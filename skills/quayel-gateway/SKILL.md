---
name: quayel-gateway
description: >
  Generate, validate, and troubleshoot Quayel Gateway configs (config.json).
  Quayel Gateway is a single-binary Rust/Pingora API gateway with built-in IP
  intelligence (geo/ASN/VPN/Tor/datacenter/risk), firewall, sliding-window rate
  limiting, edge caching, load balancing, HTTP/2 and gRPC, TCP/UDP stream
  proxying with SNI routing, JSONL access logs, and on-demand Let's Encrypt TLS.
  Use this skill whenever a user asks to proxy/protect a service or database,
  add rate limits, firewall rules, caching or load balancing, edit a quayel
  config.json, or debug why a quayel rule does or does not fire.
---

# Quayel Gateway — Config Skill

You are configuring **Quayel Gateway**: one binary + one `config.json`. There is
nothing else to install. Plugins run in a fixed pipeline —
`ip_intel → firewall → rate_limiting → request_transform → cache → load_balancer → logging` — and any
plugin can short-circuit the request. Rules **inside** a plugin run in array
order, **first match wins** (most specific first). HTTP/1.1, HTTP/2 and gRPC
share the HTTP/HTTPS ports. Raw TCP/UDP (databases, brokers, DNS) goes in a
separate top-level `streams` list (§4b) that skips the HTTP pipeline.

Full references (when working inside the quayel-gateway repo):
`docs/ai-guide.md` (agent contract) · `docs/config.schema.json` (JSON Schema) ·
`docs/configuration.md` (prose) · `docs/conditions.md` (matching) ·
`docs/logging.md` (access log) · `docs/streams.md` (TCP/UDP). If those files
exist, **read `docs/ai-guide.md` before writing config** — it is verified against
the source and wins over other docs. Human docs, install methods and task
guides: <https://docs.quayel.com/quayel-gateway>.

## 1. Non-negotiables (get these wrong and the config will not load)

- Required top-level fields: `gateway_id`, `gateway_name`, `server_name`,
  `config_version` (strings), `listen` (≥1 of `http`/`https` as `"host:port"`),
  `plugins` (object).
- Enums are **snake_case strings** — copy them exactly:

| Field | Allowed values |
|---|---|
| `client_ip.source` | `peer_ip` `header` `header_index` |
| `client_ip.fallback` | `peer_ip` |
| firewall `action.type` | `allow` `block` `redirect` `set_request_header` `set_response_header` |
| rate-limit `action.type` | `block` |
| `operator` | `equals` `not_equals` `contains` `not_contains` `starts_with` `ends_with` `exists` `not_exists` `in` `not_in` `greater_than` `greater_than_or_equal` `less_than` `less_than_or_equal` `regex` |
| `next` | `and` `or` |
| cache rule `cache` | `eligible` `bypass` |
| `edge_ttl.mode` | `origin` `custom` |
| `browser_ttl.mode` | `bypass` `origin` `custom` |
| `cache_key.mode` | `default` `custom` |
| `algorithm.type` | `round_robin` `weighted_round_robin` `least_connections` `fast_response` `sticky_session` |
| `target.protocol` | `http` `https` `h2c` `h2` (`h2c`/`h2` for gRPC) |
| `host_header.mode` | `visitor` `custom` `target` |
| `health_check.mode` | `https` `accepts_connections` `off` |
| `streams[].protocol` | `tcp` `udp` |
| `streams[].tls` | `passthrough` `terminate` |
| `streams[].algorithm` (a plain string) | `round_robin` `weighted_round_robin` `least_connections` `ip_hash` |
| `streams[].rules[].action` (a plain string) | `allow` `block` |
| `streams[].proxy_protocol` | `off` `v1` `v2` |

- **Firewall rules need ≥1 condition.** Rate-limit, cache and load-balancer rules
  may have `conditions: []` (= match everything).
- Rate-limit `limit` and `window_seconds` must be ≥1. Each load balancer needs
  ≥1 target. `auto_ssl` needs `email` and non-empty `domains`.
- Redirect actions use **`location`** (not `url` — `url` is ignored and the
  redirect silently goes to `/`). `host_header.mode: "custom"` needs `value`.
- Condition field order is `{left, operator, value, next}`; omit `value` only for
  `exists`/`not_exists`; `in`/`not_in` take arrays.

## 2. Minimal config (proxy everything to one backend)

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
        "targets": [{ "id": "t1", "host": "127.0.0.1", "port": 3000 }],
        "host_header": { "mode": "visitor" },
        "health_check": { "mode": "off" }
      }]
    }
  }
}
```

Everything not shown has a safe default: `listen` 80/443, `server.http2: true`,
plugin `enabled: true`, target
`protocol: "http"`, `weight: 100`, `tls.verify: false`, cache `statuses:
[200,301,404]`, rate-limit action `{type:"block", status:429}`, health check
`interval_seconds: 5`, `timeout_ms: 1000`, `healthy_threshold: 2`,
`unhealthy_threshold: 3`, `expected_statuses`: any 2xx/3xx, auto_ssl `cert_storage_path: /var/lib/quayel/certs`,
`renewal_days_before: 30`, logging `buffer_size: 8192`, `flush_interval_ms: 1000`.

## 3. Condition paths (for `left`, rate-limit `key`, cache_key `parts`)

Request: `req.host` `req.path` (path + query) `req.method` `req.scheme`
(`https` on TLS connections) `req.ip` `req.peer_ip` `req.user_agent` (each also
as `http.*`).
Headers/query/cookies: `req.header.<Name>` `req.query.<name>` `req.cookie.<name>`.
JWT claims: `req.header.authorization.jwt.<claim.path>` (Bearer prefix auto-stripped;
e.g. `req.header.authorization.jwt.data.role`). Add a top-level `jwt` section with
keys (`public_key`, `jwks_url`, `secret_env`, ...) to verify tokens; without it claims
are decoded unchecked. Block bad tokens with `req.header.authorization.jwt_valid`
`not_equals` `true`; `jwt_error` gives the reason.

IP intelligence (needs `ip_intel.enabled: true`; values may be `null`):
`ip.country` `ip.region` `ip.city` `ip.asn` `ip.as_org` `ip.provider`
`ip.network_type` `ip.risk_score` (0–100) and booleans `ip.is_vpn` `ip.is_tor`
`ip.is_datacenter` `ip.is_proxy` `ip.is_mobile` `ip.is_residential`
`ip.is_residential_proxy`. Match booleans with `equals true` (not `not_equals false`).

Rate-limit `key`: a path (`"req.client_ip"`), a composite array
(`["req.client_ip", "req.header.X-API-Key"]`, joined with `:`), or a legacy
template (`"{req.client_ip}+{http.header.x-api-key}"`).

## 4. Recipes

Firewall — block anonymizers and risky IPs, geo-fence the API:

```json
"firewall": { "enabled": true, "rules": [
  { "id": "block-anon", "name": "Block anonymizers", "conditions": [
      { "left": "ip.is_tor", "operator": "equals", "value": true, "next": "or" },
      { "left": "ip.is_vpn", "operator": "equals", "value": true, "next": "or" },
      { "left": "ip.risk_score", "operator": "greater_than", "value": 60 }
    ], "action": { "type": "block", "status": 403 } },
  { "id": "geo-api", "name": "API only from US/CA/GB", "conditions": [
      { "left": "req.path", "operator": "starts_with", "value": "/api/" },
      { "left": "ip.country", "operator": "not_in", "value": ["US", "CA", "GB"] }
    ], "action": { "type": "block", "status": 403 } }
]}
```

Rate limiting — global + per-IP on the API:

```json
"rate_limiting": { "enabled": true, "rules": [
  { "id": "global", "name": "Global", "conditions": [],
    "key": "req.client_ip", "limit": 1000, "window_seconds": 60 },
  { "id": "api", "name": "API per IP", "conditions": [
      { "left": "req.path", "operator": "starts_with", "value": "/api/" }
    ], "key": "req.client_ip", "limit": 100, "window_seconds": 60,
    "action": { "type": "block", "status": 429 } }
]}
```

Cache — static assets, 1 h edge / 5 min browser, stale windows:

```json
"cache": { "enabled": true, "max_object_size_bytes": 10485760, "rules": [{
  "id": "static", "name": "Static assets",
  "conditions": [{ "left": "req.path", "operator": "regex", "value": "\\.(css|js|png|jpg|svg|woff2)$" }],
  "cache": "eligible",
  "edge_ttl": { "mode": "custom", "seconds": 3600 },
  "browser_ttl": { "mode": "custom", "seconds": 300 },
  "stale_while_revalidate": 86400, "stale_if_error": 604800,
  "statuses": [200, 301]
}]}
```

Load balancing — 2 backends, least-connections, TCP health checks:

```json
"load_balancer": { "enabled": true, "load_balancers": [{
  "id": "pool", "name": "API pool", "conditions": [],
  "algorithm": { "type": "least_connections" },
  "targets": [
    { "id": "a", "host": "10.0.0.1", "port": 3000 },
    { "id": "b", "host": "10.0.0.2", "port": 3000 }
  ],
  "host_header": { "mode": "visitor" },
  "health_check": { "mode": "accepts_connections", "interval_seconds": 5, "timeout_ms": 1000 }
}]}
```

TLS — on-demand Let's Encrypt (start with `"staging": true`):

```json
"listen": { "http": "0.0.0.0:80", "https": "0.0.0.0:443" },
"plugins": { "auto_ssl": { "enabled": true, "email": "admin@example.com",
  "domains": ["api.example.com"], "staging": true } }
```

Real client IP behind Cloudflare / a load balancer (the header is only believed
from `trusted_proxies`; default = loopback, private ranges and Cloudflare):

```json
"client_ip": { "source": "header", "header": "CF-Connecting-IP" }
"client_ip": { "source": "header", "header": "X-Real-IP", "fallback": "peer_ip",
               "trusted_proxies": ["203.0.113.10"] }
```

gRPC backend: target `"protocol": "h2c"` (plain) or `"h2"` (TLS) with
`"health_check": { "mode": "accepts_connections" }` (gRPC servers reject a plain GET).

## 4b. Streams (TCP / UDP proxy, top-level `streams`)

```json
"streams": [
  { "id": "postgres", "listen": "0.0.0.0:5432",
    "targets": [{ "id": "pg-1", "host": "10.0.0.5", "port": 5432 }],
    "algorithm": "least_connections",
    "health_check": { "mode": "accepts_connections" },
    "rules": [
      { "id": "office", "action": "allow",
        "conditions": [{ "left": "req.ip", "operator": "starts_with", "value": "203.0.113." }] },
      { "id": "everyone-else", "action": "block" } ] },
  { "id": "redis-a", "sni": ["a.redis.example.com"], "tls": "terminate",
    "targets": [{ "id": "r", "host": "10.0.0.6", "port": 6379 }] },
  { "id": "dns", "protocol": "udp", "listen": "0.0.0.0:53", "responses": 1,
    "targets": [{ "id": "d1", "host": "10.0.0.53", "port": 53 }] }
]
```

- No `listen` → the stream shares `listen.https` and is picked by `sni`; other
  names stay normal HTTPS. `tls`: `passthrough` (default with `sni`) forwards
  encrypted bytes, `terminate` uses Auto-SSL certificates.
- Rules see only `req.ip` and `ip.*`; first match decides, no match → allowed.
- Other fields: `proxy_protocol` (`v1`/`v2`), `connect_timeout_secs` (5),
  `idle_secs` (TCP never, UDP 30), UDP `max_sessions` (100000), `responses`.
- Unknown fields in a stream are a config error. Stream `listen` is startup-only.

## 5. Workflow — always validate before declaring success

1. **Generate** the config (bump `config_version` on every change).
2. **Syntax check:** `python3 -c "import json,sys; json.load(open('config.json')); print('OK')"`.
3. **Schema check** if `jsonschema` or `check-jsonschema` is available:
   `check-jsonschema --schemafile docs/config.schema.json config.json`.
4. **Authoritative check — the gateway's own parser** (it exits with a precise
   error; wrap in `timeout -k` because a valid config starts a server):
   ```bash
   timeout -k 2 3 ./target/release/quayel-gateway config.json
   ```
5. **Smoke test:** `curl -s -i http://localhost/<path>` and
   `tail -1 <access-log>.jsonl | python3 -m json.tool`.
6. **Hot reload:** the config file is watched — a valid save reloads without
   restart (log: `Config hot-reloaded successfully`). An invalid save is
   rejected and the previous config keeps serving. Edit atomically
   (write temp + rename).

Startup error → fix map:

| Error fragment | Cause |
|---|---|
| ``unknown variant `x`, expected one of `...` `` | wrong enum value (see §1) |
| ``missing field `y` `` | required field absent |
| `client_ip.source is ... but no header specified` | add `client_ip.header` |
| `client_ip.source is header_index but no index specified` | add `client_ip.index` |
| `Firewall rule '<id>' has no conditions` | add ≥1 condition |
| `Rate limit rule '<id>' has zero limit / zero window` | use values ≥1 |
| `Load balancer '<id>' has no targets` | add ≥1 target |
| `No config file found` | pass a path, set `QUAYEL_GATEWAY_CONFIG`, or create `/etc/quayel-gateway/config.json` |

## 6. Behavior notes that surprise people

- Backends receive `X-Forwarded-For` (client IP appended), `X-Forwarded-Proto`
  (from the connection; kept from the client only if it's a trusted proxy),
  `X-Forwarded-Host`, `X-QG-Request-Id`. Inject more with a firewall
  `set_request_header` action.
- Client IP comes from `client_ip` config (§4). The header is ignored unless the
  TCP peer is in `trusted_proxies`, so a proxy with a public, non-Cloudflare IP
  must be listed or every request looks like it comes from the proxy. Never use
  `X-Forwarded-For` index `0` on an internet-facing gateway: clients control it.
- HTTP → HTTPS: firewall rule `req.scheme equals http` → `redirect` with
  `location: "https://${req.host}${req.path}"`. ACME challenges are answered
  before the firewall, so this can't break certificate issuance.
- Blocked requests get JSON: firewall `{"error":"blocked",...,"rule_id":...}`,
  rate limit `429 + Retry-After` `{"error":"rate_limited",...}`, no healthy
  upstream `503 {"error":"no_healthy_upstream"}` (a dead backend with
  `health_check: off`, or one not yet detected, returns a plain `502`; there is
  no retry), no matching load balancer `404 {"error":"Not Found"}`, gRPC
  clients get a gRPC status instead (`PermissionDenied`, `Unavailable`, …).
- Health checks take failing targets out of their pool. `https` mode honours
  `expected_statuses` and does not follow redirects. Changed `health_check`
  settings need a restart; so do `listen`, `server.http2` and `metrics`.
- Cache decisions are visible in the `Quayel-Cache-Status` response header
  (`HIT`/`MISS`/`BYPASS`/`STALE`/`REVALIDATING`/`NONE`).
- Rate-limit counters and cache are in-memory per process; a restart clears them.
- Access log = one JSON object per line, same keys on every line; check
  `.block.type` / `.block.rule` / `.block.key` (what stopped it, `""` if
  nothing), `.allow_rule`, `.cache`, `.upstream`, `.upstream_status`, `.grpc_status`, `.error`,
  `.dur_us` to see why a request was handled the way it was. `path` never
  includes the query string. `grpc_status` is `-1` for non-gRPC requests. Stream
  connections log `method` `TCP`/`UDP` with `path` = stream id.
- `ip.*` fields are only populated when `ip_intel` is enabled; booleans can be
  `null` (unknown).
- Ports below 1024 need root, `sudo setcap cap_net_bind_service=+ep ./quayel-gateway`,
  or Docker. In Docker, mount the config **directory**
  (`-v ./gw:/etc/quayel-gateway`), not the single file, or hot reload never sees edits.
