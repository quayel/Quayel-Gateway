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
(`ip_intel → firewall → rate_limiting → request_transform → cache → load_balancer → logging`, plus `auto_ssl`
for TLS). HTTP/1.1, HTTP/2 and gRPC are served on the same ports. A separate
top-level `streams` list proxies raw TCP and UDP (databases, brokers, DNS), optionally
routed by TLS server name (SNI). All IP-intelligence data is embedded in the binary.
There are **no** external services to install (no Redis/etcd/DB).

Human docs: <https://docs.quayel.com/quayel-gateway> (Quickstart, install methods, guides, production).

| Fact | Value |
|---|---|
| Binary | `target/release/quayel-gateway` (~153 MB, data embedded) |
| CLI | `--workers <N>` (default: all CPU cores), `--version`/`-V`, `--help`; positional `CONFIG_PATH` (if omitted: `$QUAYEL_GATEWAY_CONFIG`, then `/etc/quayel-gateway/config.json`, then `./config.json`) |
| Env | `QUAYEL_GATEWAY_CONFIG`, `RUST_LOG` (`info` default), `QUAYEL_IP_INTEL_CACHE_SIZE` (default `65536`) |
| Build | `./setup.sh` then `cargo build --release` (Linux x86_64) |
| Config reload | Automatic — the file is watched; a valid edit hot-reloads (no restart). Invalid edits are rejected and the old config keeps serving. |
| Logs | stderr = JSON tracing; access log = JSONL file (if `plugins.logging` configured) |

---

## 2. Config generation contract

When you generate a `config.json`, follow this checklist **every time**:

1. **Required top-level fields:** `gateway_id`, `gateway_name`, `server_name`, `config_version` (all strings), `plugins` (object). `listen` is optional (defaults `0.0.0.0:80` / `0.0.0.0:443`). `client_ip` is optional (defaults to `peer_ip`).
2. `listen.http` / `listen.https` are `"host:port"` strings; set them only to change the default ports 80/443.
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
  "listen": { "http": "0.0.0.0:80" },
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
│   ├── fallback: peer_ip                    (only valid value)
│   └── trusted_proxies: string[]            (IPs/CIDRs whose header is believed; default loopback + private ranges + Cloudflare)
├── server                                   (optional) { workers?, http2 = true, timeouts{…}, limits{…}, protection{…}, request_id{…} }  (see configuration.md)
├── jwt                                      (optional) token verification keys (public_key | jwks_url | secret_env, …)
├── streams: Stream[]                        (optional; TCP/UDP proxy, see Stream below and streams.md)
├── metrics                                  (optional; startup only) { enabled = true, listen = "127.0.0.1:9464", path = "/metrics", max_hosts = 1000 }
└── plugins                                  (required object; every sub-plugin optional)
    ├── ip_intel       { enabled: bool = true }
    ├── firewall       { enabled = true, rules: FirewallRule[] = [] }
    ├── rate_limiting  { enabled = true, rules: RateLimitRule[] = [] }
    ├── cache          { enabled = true, max_object_size_bytes = 10485760, rules: CacheRule[] = [] }
    ├── load_balancer  { enabled = true, load_balancers: LoadBalancer[] = [] }
    ├── logging        { enabled = true, mode = "file", queue_size = 65536, user_field?, file?: { path, buffer_size = 8192, flush_interval_ms = 1000 }, sinks?: [{ type: stdout|http|clickhouse|datadog|otlp|loki|elasticsearch|opensearch|splunk, url?, … }] }  (see docs/logging.md#sinks)
    └── auto_ssl       { enabled = true, email*, domains*, cert_storage_path = "/var/lib/quayel/certs", staging = false, directory_url?, ca_root?, renewal_days_before = 30 }
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
  Without a top-level `jwt` section with keys, claims are NOT verified and can be forged.
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
`id*`, `host*`, `port*` (1–65535), `protocol: "http" | "https" | "h2c" | "h2" = "http"` (⚠️ **lowercase**; `h2c`/`h2` for gRPC),
`weight: int = 100`, `enabled = true`, `tls?: { verify: bool = false, sni?: string }`

### HealthCheck
`mode*: "https" | "accepts_connections" | "off"` (⚠️ there is **no** `"http"` mode),
`path: string = "/"` (used by `https` mode), `interval_seconds = 5`, `timeout_ms = 1000`,
`expected_statuses?: int[]`, `healthy_threshold = 2`, `unhealthy_threshold = 3`

- `https` → HTTP(S) GET to the target's protocol/host/port at `path`. Healthy = status in
  `expected_statuses`, or any 2xx/3xx when unset. Redirects are **not** followed.
- `accepts_connections` → TCP connect check only. Use it for gRPC (`h2c`/`h2`) targets,
  which usually reject a plain GET.
- Unhealthy targets are taken out of their pool (health is tracked per pool). A config
  reload applies `enabled`, weights and new targets at once, but changed `health_check`
  settings, and health checks for new targets, only start after a restart.
- No healthy target → `503` with `{"error":"no_healthy_upstream"}`. (With
  `health_check: {mode:"off"}` all targets are assumed healthy; a dead backend then
  yields Pingora's plain `502`.)

### Stream (top-level `streams[]`, TCP / UDP proxy)
`id*`, `name?`, `enabled = true`, `protocol: "tcp" | "udp" = "tcp"`,
`listen?: "host:port"` (omitted → shares `listen.https` and is picked by `sni`; startup only),
`sni?: string[]` (exact names or `*.example.com`), `tls?: "passthrough" | "terminate"`
(default `passthrough` when `sni` is set),
`targets*: [{ id*, host*, port*, weight = 100, enabled = true }]` (≥1),
`algorithm: "round_robin" | "weighted_round_robin" | "least_connections" | "ip_hash" = "round_robin"`
(⚠️ a **string**, not the `{type}` object HTTP load balancers use),
`health_check?` (only `accepts_connections` / `off`),
`rules?: [{ id*, enabled = true, conditions = [], action*: "allow" | "block" }]`
(first match decides; no match → allowed; conditions see `req.ip` and `ip.*` only),
`proxy_protocol: "off" | "v1" | "v2" = "off"`, `connect_timeout_secs = 5`,
`idle_secs?` (TCP: omitted/0 → never; UDP: default 30),
UDP only: `max_sessions = 100000`, `responses?` (e.g. `1` for DNS).

HTTP features (path, headers, JWT, cache, transform) don't apply to streams. Unknown fields
in a stream are a config error.

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
| `target.protocol` | `http` `https` `h2c` `h2` |
| `host_header.mode` | `visitor` `custom` `target` |
| `health_check.mode` | `https` `accepts_connections` `off` |
| `streams[].protocol` | `tcp` `udp` |
| `streams[].tls` | `passthrough` `terminate` |
| `streams[].algorithm` | `round_robin` `weighted_round_robin` `least_connections` `ip_hash` |
| `streams[].rules[].action` | `allow` `block` |
| `streams[].proxy_protocol` | `off` `v1` `v2` |

---

## 5. Defaults reference (fields you can omit)

| Location | Field | Default |
|---|---|---|
| `client_ip` | whole object | `{ "source": "peer_ip" }` |
| `client_ip` | `trusted_proxies` | loopback, private ranges, Cloudflare |
| `listen` | `http` / `https` | `0.0.0.0:80` / `0.0.0.0:443` |
| `server` | `http2` | `true` (h2c on the HTTP port, ALPN `h2` on HTTPS; startup only) |
| health check | `expected_statuses` | any 2xx/3xx |
| stream | `protocol` / `algorithm` / `proxy_protocol` / `connect_timeout_secs` | `tcp` / `round_robin` / `off` / `5` |
| stream | `idle_secs` | TCP: never · UDP: `30` |
| stream (UDP) | `max_sessions` | `100000` |
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
| `req.scheme` (`http.scheme`) | string | `https` for TLS connections, else `http`. `X-Forwarded-Proto` overrides it only from `client_ip.trusted_proxies` |
| `req.ip` (`http.ip`) | string | Resolved client IP (per `client_ip` config; the header is only read from `trusted_proxies`) |
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
| `req.header.<name>.jwt.<claim_path>` | any | JWT claim (Bearer prefix stripped), dotted path, e.g. `req.header.authorization.jwt.data.role`. With top-level `jwt` keys: only for verified tokens. Without: decoded UNCHECKED (forgeable) |
| `req.header.<name>.jwt_valid` | bool | true only for a verified token; always false without `jwt` keys |
| `req.header.<name>.jwt_error` | string | `missing`, `malformed`, `alg_not_allowed`, `unknown_kid`, `keys_unavailable`, `bad_signature`, `expired`, `not_yet_valid`, `wrong_issuer`, `wrong_audience`, `missing_claim`, `unverified` |
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
| `No config file found` | Pass a path, set `QUAYEL_GATEWAY_CONFIG`, or create `/etc/quayel-gateway/config.json` |

**Step 3 — smoke test** (with the gateway running and a backend up):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost/health     # 200 from backend
curl -s -i -H 'X-Forwarded-For: 1.2.3.4' http://localhost/api/x     # check firewall/rate-limit behavior
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
"listen": { "http": "0.0.0.0:80", "https": "0.0.0.0:443" },
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
until ACME finishes in the background. To send HTTP to HTTPS, add a firewall rule
(`req.scheme equals http` → `redirect` with `location: "https://${req.host}${req.path}"`);
ACME challenges are answered before the firewall, so it can't break issuance.

### Behind Cloudflare or a load balancer (real client IP)

```json
"client_ip": {
  "source": "header",
  "header": "X-Real-IP",
  "fallback": "peer_ip",
  "trusted_proxies": ["10.0.0.0/8"]
}
```

Behind Cloudflare use `{"source":"header","header":"CF-Connecting-IP"}` (Cloudflare ranges
are trusted by default). The header is ignored from any peer outside `trusted_proxies`, so
clients can't fake their IP. A proxy with a **public, non-Cloudflare** IP must be listed.

### gRPC backend (plain-text HTTP/2)

```json
"targets": [{ "id": "grpc-1", "host": "10.0.0.7", "port": 50051, "protocol": "h2c" }],
"health_check": { "mode": "accepts_connections" }
```

Use `"protocol": "h2"` for a TLS gRPC backend. Clients can use HTTP/2 over TLS on 443 or
h2c on port 80. Errors the gateway itself returns reach gRPC clients as gRPC statuses
(403 → `PermissionDenied`, 429 → `ResourceExhausted`, 502/503 → `Unavailable`).

### TCP proxy with an IP allowlist (PostgreSQL)

```json
"streams": [{
  "id": "postgres",
  "listen": "0.0.0.0:5432",
  "targets": [{ "id": "pg-1", "host": "10.0.0.5", "port": 5432 }],
  "health_check": { "mode": "accepts_connections" },
  "rules": [
    { "id": "office", "action": "allow",
      "conditions": [{ "left": "req.ip", "operator": "starts_with", "value": "203.0.113." }] },
    { "id": "everyone-else", "action": "block" }
  ]
}]
```

### Route TLS by server name on the shared 443

```json
"streams": [
  { "id": "redis-a", "sni": ["a.redis.example.com"], "tls": "terminate",
    "targets": [{ "id": "r", "host": "10.0.0.5", "port": 6379 }] }
]
```

No `listen` → the stream shares `listen.https`. Matching names go to the stream; every other
name stays normal HTTPS. `terminate` uses Auto-SSL certificates; `passthrough` forwards the
encrypted bytes untouched.

### DNS over UDP

```json
"streams": [{ "id": "dns", "protocol": "udp", "listen": "0.0.0.0:53", "responses": 1,
  "targets": [{ "id": "d1", "host": "10.0.0.53", "port": 53 }] }]
```

---

## 9. What backends receive / what logs contain

Upstream requests get `X-Forwarded-For: <client_ip>` (appended to the chain),
`X-Forwarded-Proto` (from the connection; an incoming value is only kept from a trusted
proxy), `X-Forwarded-Host`, `X-QG-Request-Id`. Extra headers can be injected with a firewall
`set_request_header` rule.

Access log = one JSON object per line. Useful JSON paths for automation:

| Question | Path |
|---|---|
| Who was it? | `.client_ip`, `.country`, `.asn`, `.provider`, `.datacenter`, `.vpn`, `.tor`, `.risk` |
| Blocked? | `.block.type` (`fw` / `rl` / `dos`, `""` = not blocked), `.block.rule`, `.block.key` |
| Firewall allow rule? | `.allow_rule` |
| Cache outcome | `.cache` (`HIT`/`MISS`/`BYPASS`/`STALE`/`REVALIDATING`/`NONE`) |
| Which backend? | `.upstream`, `.upstream_addr`, `.upstream_status` |
| Failed? | `.error` (`client closed` with status `499` when the client gave up) |
| gRPC status | `.grpc_status` (`-1` = not gRPC / no status) |
| Latency | `.dur_us`, `.upstream_us` |
| Stream connection? | `.method` = `TCP`/`UDP`, `.path` = stream id, `.block.type` = `stream` |

Every line has every key (`""` / `0` / `false` when not applicable), and `path`
never includes the query string.

---

## 10. Operational gotchas

- **Pipeline order matters:** `ip_intel → firewall → rate_limiting → request_transform → cache → load_balancer
  → logging`. Cache runs *before* load balancer selection, so a cache HIT never picks a
  target or counts toward least-connections. A firewall block never touches cache or backends.
  `request_transform` runs after firewall/rate limiting (they see the client's original
  request) and before cache (the key uses the rewritten request). `response_transform` is
  not a pipeline step: it runs on every origin or cached response on the way out, never on
  gateway blocks, and the cache only stores the untransformed origin response.
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
- The gateway returns `502` (empty body) when a target refuses the connection before
  health checks have noticed (there is no retry to another target), and
  `503 {"error":"no_healthy_upstream"}` once health checks have marked every target in the
  pool down. A request that matches no load balancer gets `404 {"error":"no_route"}`
  (0.6.3+; before that it was proxied to `127.0.0.1:80`).
- A target whose hostname doesn't resolve gets `502` for the requests sent to it (0.6.3+;
  before that the gateway panicked). Add an `accepts_connections` health check so the
  pool stops picking it.
- **Client IP behind a proxy:** set `client_ip` *and* make sure the proxy's IP is in
  `trusted_proxies` (the default covers private ranges, loopback and Cloudflare). Otherwise
  every request appears to come from the proxy.
- **HTTPS handshake deadline:** a TLS handshake on the HTTPS port must finish within
  `server.timeouts.header_secs` (default 10 s).
- **Ports below 1024** need root, `CAP_NET_BIND_SERVICE`
  (`sudo setcap cap_net_bind_service=+ep ./quayel-gateway`) or Docker. The `.deb` service
  already has the capability.
- **Docker + hot reload:** mount the config **directory** (`-v ./gw:/etc/quayel-gateway`),
  not the single file. Editors replace the file, and a single-file bind mount never sees it.
- **Startup-only settings:** `listen`, stream `listen`, `server.http2`, `metrics` and
  `health_check` changes need a restart; the rest hot-reloads.

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
| Request / response transforms | [`plugins/transform.md`](plugins/transform.md) |
| TCP / UDP streams, SNI routing | [`streams.md`](streams.md) |
| Task guides, install methods, production checklist | <https://docs.quayel.com/quayel-gateway> |
| Reusable skill package for AI tools | [`../skills/quayel-gateway/SKILL.md`](../skills/quayel-gateway/SKILL.md) |
