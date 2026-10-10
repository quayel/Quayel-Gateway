# AI Agent Guide — Quayel Gateway

> **Audience:** LLM agents and automation. This file is the machine-oriented contract for
> generating, validating, and operating Quayel Gateway configs. Human prose lives in the
> other `docs/*.md` files; **when they disagree with this file, this file wins** (it is
> verified against `src/config/schema.rs`, `src/config/loader.rs` and the release binary).

---

## 1. What this program is

Quayel Gateway is a single-binary reverse proxy / API gateway (Rust, Pingora core).
Run: `quayel-gateway [OPTIONS] [CONFIG_PATH]`. One JSON file describes everything:
listeners, client-IP resolution, and a plugin pipeline
(`ip_intel → firewall → rate_limiting → load_balancer → cache → logging`, plus `auto_ssl`
for TLS). All IP-intelligence data is embedded in the binary. There are **no** external
services to install (no Redis/etcd/DB).

| Fact | Value |
|---|---|
| Binary | `target/release/quayel-gateway` (~153 MB, data embedded) |
| CLI | `--workers <N>` (default: all CPU cores), `--help`; positional `CONFIG_PATH` (default `config.json`) |
| Env | `RUST_LOG` (`info` default), `QUAYEL_IP_INTEL_CACHE_SIZE` (default `65536`) |
| Build | `./setup.sh` then `cargo build --release` (Linux x86_64) |
| Config reload | Automatic — the file is watched; a valid edit hot-reloads (no restart). Invalid edits are rejected and the old config keeps serving. |
| Logs | stderr = JSON tracing; access log = JSONL file (if `plugins.logging` configured) |

---

## 2. Config generation contract

When you generate a `config.json`, follow this checklist **every time**:

1. **Required top-level fields:** `gateway_id`, `gateway_name`, `server_name`, `config_version` (all strings), `listen` (object), `plugins` (object). `client_ip` is optional (defaults to `peer_ip`).
2. **At least one** of `listen.http` / `listen.https` must be set (`"host:port"` strings).
3. **Enums are snake_case strings** — see §4. A single wrong enum value makes the whole
   config fail to load (serde error at startup). Examples of wrong values seen in the wild:
   `"round-robin"`, `"HTTP"`, `"mode": "http"` (health check), `"Header_Index"`.
4. **Firewall rules must have ≥ 1 condition** (`conditions: []` is rejected).
5. **Rate limit rules:** `limit > 0` and `window_seconds > 0`.
6. **Each load balancer needs ≥ 1 target.**
7. **Auto-SSL**, if enabled, requires `email` (string) and non-empty `domains`.
8. **Rule/ordering semantics:** rules inside a plugin are evaluated **in array order,
   first match wins**. Put the most specific rules first.
9. **Rule ids** must be unique strings (they appear in logs, block responses, and
   rate-limit counters).
10. Unknown JSON fields are **ignored** by the gateway, but the provided JSON Schema
    (`docs/config.schema.json`) is strict (`additionalProperties: false`) so typos get
    caught. Validate before deploying (§7).

### Minimal valid config (proxy to one backend)

```json
{
  "gateway_id": "gw-01",
  "gateway_name": "default",
  "server_name": "api.example.com",
  "config_version": "1",
  "listen": { "http": "0.0.0.0:8080" },
  "plugins": {
    "ip_intel": { "enabled": true },
    "load_balancer": {
      "enabled": true,
      "load_balancers": [{
        "id": "default",
        "name": "Backend",
        "conditions": [],
        "algorithm": { "type": "round_robin" },
        "targets": [
          { "id": "t1", "host": "127.0.0.1", "port": 3000 }
        ],
        "host_header": { "mode": "visitor" },
        "health_check": { "mode": "off" }
      }]
    }
  }
}
```

Everything else has working defaults (see §5).

---

## 3. Full config tree (ground truth: `src/config/schema.rs`)

```
GatewayConfig
├── gateway_id: string                       (required)
├── gateway_name: string                     (required)
├── server_name: string                      (required)
├── config_version: string                   (required; bump it on every change)
├── listen
│   ├── http:  "host:port" | absent
│   └── https: "host:port" | absent          (≥1 of the two required)
├── client_ip                                (optional)
│   ├── source: peer_ip | header | header_index        (default peer_ip)
│   ├── header: string                       (required when source is header|header_index)
│   ├── index: integer ≥ 0                   (required when source is header_index)
│   └── fallback: peer_ip                    (only valid value)
└── plugins                                  (required object; every sub-plugin optional)
    ├── ip_intel       { enabled: bool = true }
    ├── firewall       { enabled = true, rules: FirewallRule[] = [] }
    ├── rate_limiting  { enabled = true, rules: RateLimitRule[] = [] }
    ├── cache          { enabled = true, max_object_size_bytes = 10485760, rules: CacheRule[] = [] }
    ├── load_balancer  { enabled = true, load_balancers: LoadBalancer[] = [] }
    ├── logging        { enabled = true, mode = "file", file?: { path, buffer_size = 8192, flush_interval_ms = 1000 } }
    └── auto_ssl       { enabled = true, email*, domains*, cert_storage_path = "/var/lib/quayel/certs", staging = false, renewal_days_before = 30 }
```

### FirewallRule
`id*`, `name*`, `enabled = true`, `conditions*: Condition[] (≥1)`, `action*: FirewallAction`

### FirewallAction
`type*: allow | block | redirect | set_request_header | set_response_header`
- `block` → `status` (default `403`), JSON body `{"error":"blocked","status":403,"rule_id":"<id>"}`
- `redirect` → `status` (default `302`), `location*` (URL). ⚠️ The field is `location`,
  **not** `url` — `url` is silently ignored and the gateway redirects to `/` instead.
- `set_request_header` / `set_response_header` → `headers*` (map of string→string)

### RateLimitRule
`id*`, `name*`, `enabled = true`, `conditions*: Condition[]` (empty = every request),
`key*: string | string[]`, `limit*: integer > 0`, `window_seconds*: integer > 0`,
`action?: { type: "block", status? }` (default `{type:"block", status:429}`)

- `key` is any condition path (§6). Array form = composite key, parts joined with `":"`.
- JWT keys: `"authorization.jwt.user_id"` → decode Bearer token from the `authorization`
  header, extract claim `user_id` (nested claims: `"authorization.jwt.data.role"`).
- Legacy template form also accepted: `"{req.client_ip}+{http.header.x-api-key}"`.
- Blocked response: `429` + `Retry-After: <window_seconds>` +
  `{"error":"rate_limited","status":429,"rule_id":"...","limit":N,"window_seconds":N}`.

### CacheRule
`id*`, `name*`, `enabled = true`, `conditions*: Condition[]` (empty = always),
`cache: "eligible" | "bypass" = "eligible"`,
`edge_ttl*: { mode: "origin" | "custom", seconds?: int }`,
`browser_ttl?: { mode: "bypass" | "origin" | "custom", seconds?: int }`,
`cache_key?: { mode: "default" | "custom", parts?: string[] }`,
`statuses?: int[] = [200, 301, 404]`,
`stale_while_revalidate?: int` , `stale_if_error?: int`

- `edge_ttl.mode = "custom"` uses `seconds` (falls back to origin CDN headers if absent).
- `edge_ttl.mode = "origin"` reads `s-maxage`, then `max-age` from upstream `Cache-Control`;
  `no-store` / `no-cache` / `private` always skip the cache.
- `cache_key.mode = "custom"` adds `parts` (condition paths, e.g. `["ip.country"]`) to the
  default key `scheme|host|path`.
- Response header `Quayel-Cache-Status: NONE|HIT|MISS|BYPASS|STALE|REVALIDATING`.

### LoadBalancer
`id*`, `name*`, `enabled = true`, `conditions*: Condition[]` (empty = matches all;
first LB in the array whose conditions match handles the request),
`algorithm*: { type*: AlgorithmType, key?: string }`,
`targets*: Target[] (≥1)`,
`host_header?: { mode: "visitor" | "custom" | "target", value?: string }` (default `visitor`;
`custom` requires `value`), `health_check?: HealthCheck`

### AlgorithmType
`round_robin | weighted_round_robin | least_connections | fast_response | sticky_session`
- `sticky_session` uses `algorithm.key` (a condition path, e.g. `"req.header.X-Session-Id"`).

### Target
`id*`, `host*`, `port*` (1–65535), `protocol: "http" | "https" = "http"` (⚠️ **lowercase**),
`weight: int = 100`, `enabled = true`, `tls?: { verify: bool = false, sni?: string }`

### HealthCheck
`mode*: "https" | "accepts_connections" | "off"` (⚠️ there is **no** `"http"` mode),
`path: string = "/"` (used by `https` mode), `interval_seconds = 5`, `timeout_ms = 1000`,
`expected_statuses?: int[]`, `healthy_threshold = 2`, `unhealthy_threshold = 3`

- `https` → HTTP(S) GET to the target's protocol/host/port at `path`.
- `accepts_connections` → TCP connect check only.
- No healthy target → `503` with `{"error":"no_healthy_upstream"}`. (With
  `health_check: {mode:"off"}` all targets are assumed healthy; a dead backend then
  yields Pingora's plain `502`.)

### Condition
`left*: string (path, §6)`, `operator*: Operator`, `value: any` (omit for
`exists`/`not_exists`), `next: "and" | "or"` (joins to the **next** condition; default `and`)

### Operator
`equals, not_equals, contains, not_contains, starts_with, ends_with, exists, not_exists,
in, not_in, greater_than, greater_than_or_equal, less_than, less_than_or_equal, regex`

---

## 4. Enum cheat-sheet (copy exactly — these strings are case- and spelling-sensitive)

| Enum | Allowed values |
|---|---|
| `client_ip.source` | `peer_ip` `header` `header_index` |
| `client_ip.fallback` | `peer_ip` |
| `action.type` (firewall) | `allow` `block` `redirect` `set_request_header` `set_response_header` |
| `action.type` (rate limit) | `block` |
| `operator` | `equals` `not_equals` `contains` `not_contains` `starts_with` `ends_with` `exists` `not_exists` `in` `not_in` `greater_than` `greater_than_or_equal` `less_than` `less_than_or_equal` `regex` |
| `next` | `and` `or` |
| `cache` (rule) | `eligible` `bypass` |
| `edge_ttl.mode` | `origin` `custom` |
| `browser_ttl.mode` | `bypass` `origin` `custom` |
| `cache_key.mode` | `default` `custom` |
| `algorithm.type` | `round_robin` `weighted_round_robin` `least_connections` `fast_response` `sticky_session` |
| `target.protocol` | `http` `https` |
| `host_header.mode` | `visitor` `custom` `target` |
| `health_check.mode` | `https` `accepts_connections` `off` |

---

## 5. Defaults reference (fields you can omit)

| Location | Field | Default |
|---|---|---|
| `client_ip` | whole object | `{ "source": "peer_ip" }` |
| every plugin | `enabled` | `true` (a plugin object that is present runs) |
| `firewall` / `rate_limiting` / `cache` / `load_balancer` | `rules` / `load_balancers` | `[]` |
| `cache` | `max_object_size_bytes` | `10485760` (10 MB) |
| cache rule | `cache` | `"eligible"` |
| cache rule | `statuses` | `[200, 301, 404]` |
| cache rule | `cache_key` | `{ "mode": "default" }` |
| rate limit rule | `action` | `{ "type": "block", "status": 429 }` |
| target | `protocol` / `weight` / `enabled` | `http` / `100` / `true` |
| target | `tls` | `{ "verify": false, "sni": null }` |
| load balancer | `host_header` | `{ "mode": "visitor" }` |
| health check | `interval_seconds` / `timeout_ms` | `5` / `1000` |
| health check | `healthy_threshold` / `unhealthy_threshold` | `2` / `3` |
| health check | `path` | `"/"` |
| logging | `mode` / `buffer_size` / `flush_interval_ms` | `file` / `8192` / `1000` |
| auto_ssl | `cert_storage_path` / `staging` / `renewal_days_before` | `/var/lib/quayel/certs` / `false` / `30` |
| firewall action `block` | `status` | `403` |
| firewall action `redirect` | `status` | `302` |

---

## 6. Condition paths (the `left` / key / cache_key `parts` vocabulary)

| Path | Type | Notes |
|---|---|---|
| `req.host` (alias `http.host`) | string | Host header |
| `req.path` (`http.path`) | string | Path **including** query string |
| `req.method` (`http.method`) | string | e.g. `"POST"` |
| `req.scheme` (`http.scheme`) | string | `http` / `https` |
| `req.ip` (`http.ip`) | string | Resolved client IP (per `client_ip` config) |
| `req.peer_ip` (`http.peer_ip`) | string | Direct TCP peer |
| `req.user_agent` (`http.user_agent`) | string | |
| `req.client_ip` | string | **Rate-limit keys only** — alias of `req.ip` |
| `ip.country` | string | ISO 3166-1 alpha-2, e.g. `"US"` |
| `ip.region` / `ip.city` | string | |
| `ip.asn` | number | |
| `ip.as_org` | string | e.g. `"AMAZON-02"` |
| `ip.provider` | string | Hosting label, e.g. `"Hostinger"` |
| `ip.is_vpn` `ip.is_tor` `ip.is_datacenter` `ip.is_proxy` `ip.is_mobile` `ip.is_residential` `ip.is_residential_proxy` | bool | may be `null` → use `equals true`, not `not_equals false` |
| `ip.network_type` | string | e.g. `"datacenter"` |
| `ip.risk_score` | number | 0–100 |
| `req.header.<name>` (`http.header.<name>`, or bare `header.<name>`) | string | case-insensitive header name |
| `req.header.<name>.jwt.<claim_path>` | any | decode JWT payload (Bearer prefix stripped), navigate dotted claim path, e.g. `req.header.authorization.jwt.data.role` |
| `req.query.<name>` (`http.query.<name>`) | string | |
| `req.cookie.<name>` (`http.cookie.<name>`) | string | |

Notes:
- `ip.*` paths need `plugins.ip_intel.enabled: true`; otherwise they resolve to nothing.
- Unresolvable paths are `null`: `exists` / `not_exists` see this; `equals`/`in` won't match.
- Coercion: string↔number compares numerically (string parsed as float); no bool coercion.
- `regex` uses Rust `regex` syntax; an invalid pattern is logged and never matches.

---

## 7. Validate before you deploy

**Step 1 — syntax + schema** (JSON Schema at [`config.schema.json`](config.schema.json)):

```bash
python3 - <<'EOF'
import json
cfg = json.load(open("config.json"))            # step 1: syntax
print("JSON OK")
EOF
```

If the environment has `jsonschema` (or `check-jsonschema` / VS Code), validate against
`docs/config.schema.json` for full enum/required checking:

```bash
check-jsonschema --schemafile docs/config.schema.json config.json   # if installed
```

**Step 2 — the gateway's own parser is the final judge.** It validates at startup and
exits with a precise error (this is the most reliable check):

```bash
timeout -k 2 3 ./target/release/quayel-gateway config.json
# exit 0 / listening logs  → config is valid
# "Failed to load config: Failed to parse config: unknown variant `X`, expected one of ..." → fix the enum
# "Failed to load config: <rule/field> ..." → fix the semantic error
```

> Use `timeout -k` — a valid config **starts a server** and will not exit on its own.

Common startup errors and their meaning:

| Message contains | Fix |
|---|---|
| `unknown variant \`x\`, expected one of \`...\`` | Wrong enum value; copy from §4 |
| `missing field \`y\`` | Required field absent; see §3 |
| `client_ip.source is header... but no header specified` | Add `client_ip.header` |
| `client_ip.source is header_index but no index specified` | Add `client_ip.index` |
| `Firewall rule '<id>' has no conditions` | Give the rule ≥1 condition |
| `Rate limit rule '<id>' has zero limit / zero window` | Use positive integers |
| `Load balancer '<id>' has no targets` | Add ≥1 target |
| `At least one of listen.http or listen.https must be specified` | Set a listener |

**Step 3 — smoke test** (with the gateway running and a backend up):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/health     # 200 from backend
curl -s -i -H 'X-Forwarded-For: 1.2.3.4' http://localhost:8080/api/x     # check firewall/rate-limit behavior
tail -1 /var/log/quayel/access.jsonl | python3 -m json.tool               # inspect the decision
```

**Step 4 — hot reload check:** edit `config_version` and save the file. Watch stderr for
`"Config hot-reloaded successfully"` (or `"Config file changed, validating..."` followed by
an error, which means the old config is still live).

---

## 8. Recipes (safe to copy)

### Block Tor/VPN/high-risk, geo-restrict the API

```json
"firewall": {
  "enabled": true,
  "rules": [
    {
      "id": "block-anon",
      "name": "Block anonymizers",
      "conditions": [
        { "left": "ip.is_tor", "operator": "equals", "value": true, "next": "or" },
        { "left": "ip.is_vpn", "operator": "equals", "value": true, "next": "or" },
        { "left": "ip.risk_score", "operator": "greater_than", "value": 60 }
      ],
      "action": { "type": "block", "status": 403 }
    },
    {
      "id": "geo-api",
      "name": "API only from US/CA/GB",
      "conditions": [
        { "left": "req.path", "operator": "starts_with", "value": "/api/" },
        { "left": "ip.country", "operator": "not_in", "value": ["US", "CA", "GB"] }
      ],
      "action": { "type": "block", "status": 403 }
    }
  ]
}
```

### Rate limit: per-IP for the API, per-API-key stricter

```json
"rate_limiting": {
  "enabled": true,
  "rules": [
    {
      "id": "api-per-ip",
      "name": "API per IP",
      "conditions": [ { "left": "req.path", "operator": "starts_with", "value": "/api/" } ],
      "key": "req.client_ip",
      "limit": 100,
      "window_seconds": 60
    },
    {
      "id": "api-per-key",
      "name": "API per key",
      "conditions": [ { "left": "req.path", "operator": "starts_with", "value": "/api/" } ],
      "key": ["req.client_ip", "req.header.X-API-Key"],
      "limit": 1000,
      "window_seconds": 60,
      "action": { "type": "block", "status": 429 }
    }
  ]
}
```

### Cache static assets 1h at edge, 5 min in browser

```json
"cache": {
  "enabled": true,
  "max_object_size_bytes": 10485760,
  "rules": [{
    "id": "static",
    "name": "Static assets",
    "conditions": [
      { "left": "req.path", "operator": "regex", "value": "\\.(css|js|png|jpg|svg|woff2)$" }
    ],
    "cache": "eligible",
    "edge_ttl": { "mode": "custom", "seconds": 3600 },
    "browser_ttl": { "mode": "custom", "seconds": 300 },
    "stale_while_revalidate": 86400,
    "stale_if_error": 604800,
    "statuses": [200, 301]
  }]
}
```

### Two backends, least-connections, TCP health checks, real Host header

```json
"load_balancer": {
  "enabled": true,
  "load_balancers": [{
    "id": "api-pool",
    "name": "API pool",
    "conditions": [],
    "algorithm": { "type": "least_connections" },
    "targets": [
      { "id": "a", "host": "10.0.0.1", "port": 3000, "protocol": "http", "weight": 100 },
      { "id": "b", "host": "10.0.0.2", "port": 3000, "protocol": "http", "weight": 100 }
    ],
    "host_header": { "mode": "visitor" },
    "health_check": {
      "mode": "accepts_connections",
      "interval_seconds": 5,
      "timeout_ms": 1000,
      "healthy_threshold": 2,
      "unhealthy_threshold": 3
    }
  }]
}
```

### HTTPS with on-demand Let's Encrypt

```json
"listen": { "http": "0.0.0.0:8080", "https": "0.0.0.0:8443" },
"plugins": {
  "auto_ssl": {
    "enabled": true,
    "email": "admin@example.com",
    "domains": ["api.example.com"],
    "staging": true
  }
}
```

Set `staging: true` first, verify issuance works, then flip to `false`. Port 80 must be
reachable for the HTTP-01 challenge. First handshake serves a self-signed fallback cert
until ACME finishes in the background.

---

## 9. What backends receive / what logs contain

Upstream requests get `X-Forwarded-For: <client_ip>` (appended to the chain),
`X-Forwarded-Proto`, `X-Forwarded-Host`. Extra headers can be injected with a firewall
`set_request_header` rule.

Access log = one JSON object per line. Useful JSON paths for automation:

| Question | Path |
|---|---|
| Who was it? | `.client_ip`, `.ip_intel.country`, `.ip_intel.asn`, `.ip_intel.provider` |
| Blocked by firewall? | `.firewall.matched`, `.firewall.rule_id`, `.firewall.action` |
| Rate limited? | `.rate_limit.blocked`, `.rate_limit.remaining` |
| Cache outcome | `.cache.status` (`HIT`/`MISS`/`BYPASS`/`STALE`/`REVALIDATING`/`NONE`) |
| Which backend? | `.load_balancer.lb_id`, `.load_balancer.target_id`, `.load_balancer.target` |
| Where was it terminated? | `.termination_phase` (`null` = proxied through) |
| Latency | `.timings_us.total_us`, `.timings_us.upstream_ttfb_us`, … |

---

## 10. Operational gotchas

- **Pipeline order matters:** `ip_intel → firewall → rate_limiting → load_balancer → cache
  → logging`. Load balancer selection runs *before* cache so cache revalidation knows the
  upstream. A firewall block never touches cache or backends.
- **Rule order matters** within each plugin: first match wins.
- **`ip.*` booleans can be `null`** (unknown). Prefer `{"operator":"equals","value":true}`.
- **Firewall rules cannot be catch-all by design** — empty `conditions` is a config error.
  To match everything use e.g. `{"left":"req.path","operator":"starts_with","value":"/"}`.
- **Rate-limit counters are in-memory** and per-process; `--workers N` does not change that
  (shared within the process). A restart clears them.
- **Cache is in-memory** and per-process too; no persistence across restarts.
- **Auto-SSL state** is in memory + `cert_storage_path` PEM files (survives restarts).
- **Config hot-reload** replaces the whole config; make edits atomic (write temp file +
  rename) so the watcher never reads a half-written file.
- **TLS targets:** `tls.verify` defaults to `false` (self-signed upstreams work out of the
  box). Set `verify: true` for production upstreams. SNI rules: `tls.sni` if set, else the
  visitor Host for IP targets, else the target hostname.
- The gateway returns `502` (empty body) when a supposedly-healthy upstream refuses the
  connection, and `503 {"error":"no_healthy_upstream"}` only when health checks have marked
  every target down.

---

## 11. Where to read more

| Need | File |
|---|---|
| Machine schema for validation | [`config.schema.json`](config.schema.json) |
| Full field-by-field prose reference | [`configuration.md`](configuration.md) |
| Condition semantics / coercion | [`conditions.md`](conditions.md) |
| Log format with full example | [`logging.md`](logging.md) |
| Headers, variables, response bodies | [`api-reference.md`](api-reference.md) |
| Plugin internals (cache singleflight, ACME flow, …) | [`plugins/`](plugins/) |
| Reusable skill package for AI tools | [`../skills/quayel-gateway/SKILL.md`](../skills/quayel-gateway/SKILL.md) |

| Reusable skill package for AI tools | [`../skills/quayel-gateway/SKILL.md`](../skills/quayel-gateway/SKILL.md) |
