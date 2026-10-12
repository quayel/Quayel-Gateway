# Configuration Reference

Complete reference for `config.json`.

## Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `gateway_id` | string | ✅ | Unique identifier for this gateway instance |
| `gateway_name` | string | ✅ | Human-readable name |
| `server_name` | string | ✅ | Server name for logging |
| `config_version` | string | ✅ | Version string for tracking config changes |
| `listen` | object | — | Listen addresses (default ports 80/443) |
| `client_ip` | object | — | Client IP resolution strategy |
| `server` | object | — | Workers, timeouts, size limits and DoS protection. Every field has a default |
| `jwt` | object | — | Keys for verifying JWTs read by `header.<name>.jwt.*` fields. Without it, tokens are decoded unchecked |
| `plugins` | object | ✅ | Plugin configurations |

## `listen`

```json
{
  "listen": {
    "http": "0.0.0.0:8080",
    "https": "0.0.0.0:8443"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `http` | string | HTTP listen address (`host:port`) |
| `https` | string | HTTPS listen address (requires TLS config) |

`listen` is optional. Defaults: `http` = `0.0.0.0:80`, `https` = `0.0.0.0:443`. The HTTPS listener only starts when Auto-SSL is enabled. Binding ports below 1024 needs root or `CAP_NET_BIND_SERVICE`.

## `client_ip`

Controls how the real client IP is determined from incoming requests.

```json
{
  "client_ip": {
    "source": "header",
    "header": "X-Forwarded-For",
    "index": 0,
    "fallback": "peer_ip"
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `source` | enum | `"peer_ip"` | How to resolve client IP |
| `header` | string | — | Header name (when source is `header` or `header_index`) |
| `index` | integer | — | Comma-separated index (0-based, when source is `header_index`) |
| `fallback` | enum | — | Fallback when header is missing |

### `source` values

| Value | Description |
|-------|-------------|
| `"peer_ip"` | Use the direct TCP connection IP |
| `"header"` | Read IP from a single-valued header |
| `"header_index"` | Read IP from a specific index in a comma-separated header |

### Example: Cloudflare

```json
{
  "client_ip": {
    "source": "header",
    "header": "CF-Connecting-IP"
  }
}
```

### Example: Nginx reverse proxy

```json
{
  "client_ip": {
    "source": "header_index",
    "header": "X-Forwarded-For",
    "index": 0,
    "fallback": "peer_ip"
  }
}
```

## `server`

Server-wide settings: worker threads, timeouts, size limits, and protection
against connection floods, Slowloris, slow POST and HTTP request floods.

`server` and every block inside it are optional. Anything you leave out uses
the default in the tables below, and any value you set overrides it. Setting
a timeout or limit to `0` switches that one check off. A misspelled field name
is rejected when the config loads.

```json
{
  "server": {
    "workers": 4,
    "timeouts": { "header_secs": 5, "upstream_read_secs": 120 },
    "limits": { "max_body_bytes": 10485760 },
    "protection": {
      "max_requests_per_ip_per_sec": 200,
      "exempt_ips": ["127.0.0.0/8", "10.0.0.0/8"]
    }
  }
}
```

Settings marked **startup only** take effect when the gateway restarts. All
the others also change on [live reload](../README.md#changing-the-config).

| Field | Default | Description |
|-------|---------|-------------|
| `workers` | all CPU cores | Worker threads. `--workers` on the command line wins. Startup only |

### `server.timeouts`

All values are in seconds.

| Field | Default | What it limits |
|-------|---------|----------------|
| `header_secs` | `10` | Time for the **whole** request header to arrive. Counted from the connection opening (first request) or from the first byte of each later keep-alive request. Stops Slowloris |
| `keepalive_secs` | `60` | How long an idle keep-alive connection waits for the next request. `0` turns keep-alive off |
| `body_read_secs` | `30` | Longest gap between two reads of a request body (slow POST / R.U.D.Y.) |
| `response_write_secs` | `60` | Longest a single write to the client may take (clients that read the response very slowly) |
| `upstream_connect_secs` | `5` | TCP connect to the upstream |
| `upstream_total_connect_secs` | `10` | TCP connect plus TLS handshake to the upstream |
| `upstream_read_secs` | `60` | Longest wait for data from the upstream |
| `upstream_write_secs` | `30` | Longest a single write to the upstream may take |
| `upstream_idle_secs` | `30` | How long an unused upstream connection stays in the pool |
| `graceful_shutdown_secs` | `5` | Time in-flight requests get to finish after `SIGTERM`. Startup only |

### `server.limits`

| Field | Default | Description |
|-------|---------|-------------|
| `max_header_bytes` | `32768` (32 KB) | Largest request header block. Larger → connection closed |
| `max_body_bytes` | `104857600` (100 MB) | Largest request body. Larger → `413`, checked from `Content-Length` and while streaming chunked bodies |
| `max_requests_per_connection` | `10000` | Requests served on one keep-alive connection before it is closed. Startup only |
| `upstream_keepalive_pool_size` | `1024` | Idle upstream connections kept per worker. Startup only |

### `server.protection`

Per-IP limits. Connection limits use the IP of the machine connecting to the
gateway; the request limit and bans also use the [resolved client IP](#client_ip).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Turns every check in this block on or off |
| `exempt_ips` | `["127.0.0.0/8", "::1/128"]` | IPs or CIDRs that skip every limit and are never banned |
| `exempt_cloudflare` | `true` | Skip the limits for [Cloudflare's edge IPs](data-sources.md), which carry many visitors over a few addresses. Set `client_ip` to `CF-Connecting-IP` so the request limit applies to real visitors |
| `max_connections_per_ip` | `256` | Open connections one IP may hold at once. Over the limit → new connection dropped |
| `max_new_connections_per_ip_per_sec` | `100` | New connections per second from one IP. Over → dropped |
| `max_requests_per_ip_per_sec` | `500` | Requests per second from one client IP across all routes. Over → `429` with `Retry-After` |

#### `server.protection.ban`

An IP that breaks the limits above (or sends a too-slow or too-large request)
`strikes` times within `window_secs` is banned for `duration_secs`. While
banned, its new connections are dropped and its requests get `429`.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Turn automatic bans on or off |
| `strikes` | `50` | Violations that trigger a ban |
| `window_secs` | `60` | Window the strikes are counted in |
| `duration_secs` | `600` | Ban length |

Requests refused by `server.protection` or `server.limits` are logged with
`termination_phase: "Protection"`, and the response carries an
`X-Quayel-Block-Reason` header (`request_rate`, `banned` or `body_too_large`).
Bans are logged to `gateway.out` as warnings. Connections dropped before any
request (connection limits, slow or oversized headers) are only logged at
`debug` level, so a flood doesn't flood the logs too.

#### What this does and doesn't cover

| Attack | Covered by |
|--------|------------|
| Slowloris (headers sent slowly) | `timeouts.header_secs`, `limits.max_header_bytes`, `protection.max_connections_per_ip` |
| Slow POST / R.U.D.Y. | `timeouts.body_read_secs`, `limits.max_body_bytes` |
| Slow read | `timeouts.response_write_secs` |
| Connection flood from few IPs | `protection.max_connections_per_ip`, `max_new_connections_per_ip_per_sec`, bans |
| HTTP request flood | `protection.max_requests_per_ip_per_sec`, bans |
| SYN flood | The kernel: keep `net.ipv4.tcp_syncookies = 1` (on by default) |
| Floods that fill the network link (UDP, amplification, large botnets) | Not possible inside any server. Use Cloudflare or your host's DDoS filtering in front |

HTTP/2 connections use the per-IP connection limits and bans, plus HTTP/2's
own stream limits; the header deadline applies to HTTP/1.x.

## `jwt`

Optional. Keys used to verify the JWTs that rules read through
`header.<name>.jwt.*` fields ([conditions](conditions.md#jwt-fields)). Without
this section, tokens are decoded without any check. With it, claims only
resolve for tokens that verify against one of the keys.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | `false` → behave as if the section weren't there |
| `leeway_secs` | `30` | Clock skew allowed for `exp` and `nbf` |
| `required_claims` | `["exp"]` | Claims a token must have: any of `exp`, `nbf`, `iss`, `aud`, `sub` |
| `keys` | — | One or more keys. A token is valid if it verifies against any of them |

Each key:

| Field | Description |
|-------|-------------|
| `id` | Unique name, used in error messages |
| `algorithms` | Required. Algorithms the key accepts: `HS256/384/512`, `RS256/384/512`, `PS256/384/512`, `ES256/384`, `EdDSA`. The token's own `alg` can only choose from this list, so an RSA key can never be used as an HMAC secret |
| `kid` | Optional. Only use this key for tokens with this `kid` header |
| `issuer` | Optional. Accepted `iss`, a string or a list |
| `audience` | Optional. Accepted `aud`, a string or a list |
| *one key source* | Exactly one of the fields below |

| Key source | For | Notes |
|------------|-----|-------|
| `secret` | HS* | Inline. Works, but logs a warning: prefer the next two |
| `secret_env` | HS* | Name of an environment variable holding the secret |
| `secret_file` | HS* | Path to a file holding the secret (trailing newline ignored) |
| `public_key` | RS*/PS*/ES*/EdDSA | Pasted public key: a PEM with `\n` line breaks, just the base64 body, a list of lines, `BEGIN RSA PUBLIC KEY`, or a `BEGIN CERTIFICATE` |
| `public_key_env` | RS*/PS*/ES*/EdDSA | Environment variable holding the PEM |
| `public_key_file` | RS*/PS*/ES*/EdDSA | Path to a normal multi-line `.pem` file |
| `jwks` | any | Inline JWKS: `{ "keys": [ ... ] }`. Matched by `kid`; keys with `use` other than `sig` are skipped |
| `jwks_url` | any | Fetched in the background and refreshed every `jwks_refresh_secs` (default 600, minimum 60; a `Cache-Control: max-age` on the response wins). HTTPS only, except `localhost` |

Checked when the config loads, so a bad key stops the gateway (or a hot
reload) with a clear error instead of failing requests:

- exactly one key source per key, and every algorithm in `algorithms` must fit it
  (a secret only with HS*, an RSA key only with RS*/PS*, and so on)
- a pasted **private** key is refused: the gateway only verifies tokens
- unknown fields are refused

A JWKS URL that fails to load keeps the last good keys and retries every 30 s.
A token with an unknown `kid` triggers an early refetch, at most once every
30 s. Until the first fetch succeeds, tokens for that key fail with
`keys_unavailable`.

```json
"jwt": {
  "keys": [
    { "id": "auth0", "algorithms": ["RS256"],
      "jwks_url": "https://example.auth0.com/.well-known/jwks.json",
      "issuer": "https://example.auth0.com/", "audience": "api" },
    { "id": "inhouse", "algorithms": ["RS256"],
      "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----" },
    { "id": "legacy", "algorithms": ["HS256"], "secret_env": "QG_LEGACY_JWT_SECRET" }
  ]
}
```

## `plugins`

```json
{
  "plugins": {
    "ip_intel": { ... },
    "firewall": { ... },
    "rate_limiting": { ... },
    "request_transform": { ... },
    "cache": { ... },
    "response_transform": { ... },
    "load_balancer": { ... },
    "logging": { ... }
  }
}
```

### `plugins.ip_intel`

IP Intelligence. All data is embedded in the binary. `enabled` is the only
required field; `forward_headers` (optional, off by default) sends the lookup
results to your backend as `X-QG-*` headers.

```json
{
  "ip_intel": {
    "enabled": true
  }
}
```

See [IP Intelligence Plugin](plugins/ip-intel.md) for details, including
[forwarding headers to the upstream](plugins/ip-intel.md#forwarding-to-the-upstream).

### `plugins.firewall`

Request firewall with allow/block/redirect rules.

```json
{
  "firewall": {
    "enabled": true,
    "rules": [
      {
        "id": "block-bad-ips",
        "name": "Block bad IPs",
        "enabled": true,
        "conditions": [
          {
            "left": "ip.is_tor",
            "operator": "equals",
            "value": true
          }
        ],
        "action": {
          "type": "block",
          "status": 403
        }
      }
    ]
  }
}
```

See [Firewall Plugin](plugins/firewall.md) for details.

### `plugins.rate_limiting`

Sliding-window rate limiting.

```json
{
  "rate_limiting": {
    "enabled": true,
    "rules": [
      {
        "id": "api-limit",
        "name": "API Rate Limit",
        "enabled": true,
        "conditions": [
          {
            "left": "req.path",
            "operator": "starts_with",
            "value": "/api/"
          }
        ],
        "key": "req.client_ip",
        "limit": 100,
        "window_seconds": 60,
        "action": {
          "type": "block",
          "status": 429
        }
      }
    ]
  }
}
```

#### Rule fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique rule identifier |
| `name` | string | ✅ | Human-readable name |
| `enabled` | bool | `true` | Enable/disable rule |
| `conditions` | array | `[]` | When to apply (**empty = every request**, e.g. a global limit) |
| `key` | string \| array | ✅ | What to count per client (see below) |
| `limit` | int > 0 | ✅ | Max requests per window |
| `window_seconds` | int > 0 | ✅ | Sliding window length |
| `action` | object | — | `{ "type": "block", "status": 429 }` (default) |

#### `key` forms

| Form | Example | Meaning |
|------|---------|---------|
| Single path | `"key": "req.client_ip"` | Count per resolved client IP |
| Composite array | `"key": ["req.client_ip", "req.header.X-API-Key"]` | Count per combination (parts joined with `:`) |
| JWT claim | `"key": "req.header.authorization.jwt.user_id"` | Count per claim. With [`jwt`](#jwt) keys, only verified tokens have the claim |
| Legacy template | `"key": "{req.client_ip}+{http.header.x-api-key}"` | Placeholders resolved and concatenated |

Any [condition path](conditions.md) can be used as a key part.

See [Rate Limiting Plugin](plugins/rate-limiting.md) for details.

### `plugins.request_transform` / `plugins.response_transform`

Rewrite the request before the cache lookup (path, query, headers) and the
response on its way to the client (headers, status). Every matching rule
applies, in array order.

```json
{
  "request_transform": {
    "enabled": true,
    "rules": [
      {
        "id": "api-v1",
        "conditions": [{ "left": "req.path", "operator": "starts_with", "value": "/api/" }],
        "actions": [{ "type": "path", "operation": "replace_prefix", "from": "/api", "to": "/v1" }]
      }
    ]
  },
  "response_transform": {
    "enabled": true,
    "rules": [
      {
        "id": "powered-by",
        "actions": [{ "type": "header", "operation": "set", "name": "X-Powered-By", "value": "Quayel" }]
      }
    ]
  }
}
```

See [Request & Response Transform](plugins/transform.md) for every action and
which headers can't be changed.

### `plugins.cache`

Edge caching with singleflight revalidation. Supports `stale-while-revalidate` and `stale-if-error` from origin's `Cache-Control` headers.

```json
{
  "cache": {
    "enabled": true,
    "max_object_size_bytes": 10485760,
    "rules": [
      {
        "id": "cache-static",
        "name": "Cache static assets",
        "enabled": true,
        "conditions": [
          {
            "left": "req.path",
            "operator": "ends_with",
            "value": ".css"
          }
        ],
        "cache": "eligible",
        "edge_ttl": {
          "mode": "custom",
          "seconds": 3600
        },
        "browser_ttl": {
          "mode": "custom",
          "seconds": 300
        },
        "cache_key": {
          "mode": "default"
        },
        "statuses": [200, 301, 404]
      }
    ]
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable cache plugin |
| `max_object_size_bytes` | int | `10485760` | Maximum response body size to cache (10 MB) |
| `rules` | array | `[]` | Cache rules (first match wins) |

#### Rule fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique rule identifier |
| `name` | string | ✅ | Human-readable name |
| `enabled` | bool | `true` | Enable/disable rule |
| `conditions` | array | `[]` | When to apply (empty = always) |
| `cache` | enum | `"eligible"` | `"eligible"` or `"bypass"` |
| `edge_ttl` | object | ✅ | Edge cache TTL configuration |
| `browser_ttl` | object | — | Browser Cache-Control header |
| `cache_key` | object | — | Cache key configuration |
| `statuses` | array | `[200, 301, 404]` | HTTP status codes to cache |
| `stale_while_revalidate` | number | — | SWR window in seconds. Overrides origin `Cache-Control` header. |
| `stale_if_error` | number | — | SIE window in seconds. Overrides origin `Cache-Control` header. |

#### `edge_ttl` modes

| Mode | Description | Extra fields |
|------|-------------|--------------|
| `"origin"` | Read TTL from upstream `Cache-Control` (`s-maxage` > `max-age`) | — |
| `"custom"` | Use fixed TTL (falls back to CDN headers if `seconds` not set) | `seconds` (optional) |

#### `browser_ttl` modes

| Mode | Description | Extra fields |
|------|-------------|--------------|
| `"bypass"` | Don't modify browser Cache-Control | — |
| `"origin"` | Forward upstream Cache-Control | — |
| `"custom"` | Set specific browser TTL | `seconds` (optional) |

#### `cache_key` modes

| Mode | Description | Extra fields |
|------|-------------|--------------|
| `"default"` | Key = `scheme\|host\|path` | — |
| `"custom"` | Add custom parts to key | `parts` (array of condition paths) |

#### CDN Cache-Control parsing

When `edge_ttl.mode` is `"origin"`, the gateway reads these directives from the upstream `Cache-Control` header:

| Directive | Used as | Priority |
|-----------|---------|----------|
| `s-maxage` | Edge TTL | 1st |
| `max-age` | Edge TTL (fallback) | 2nd |
| `stale-while-revalidate` | SWR window | Config override > origin header |
| `stale-if-error` | SIE window | Config override > origin header |
| `no-store` | Skip cache | Overrides all |
| `no-cache` | Skip cache | Overrides all |
| `private` | Skip cache | Overrides all |

> **Note:** `stale-while-revalidate` and `stale-if-error` can be set in the gateway config (recommended) or parsed from the upstream `Cache-Control` header. Gateway config takes priority over origin headers.

See [Cache Plugin](plugins/cache.md) for details.

### `plugins.load_balancer`

Upstream load balancing.

```json
{
  "load_balancer": {
    "enabled": true,
    "load_balancers": [
      {
        "id": "default",
        "name": "My Backend",
        "enabled": true,
        "conditions": [],
        "algorithm": {
          "type": "round_robin"
        },
        "targets": [
          {
            "id": "backend-1",
            "host": "10.0.0.1",
            "port": 8080,
            "protocol": "http",
            "weight": 100,
            "enabled": true,
            "tls": {
              "verify": false,
              "sni": null
            }
          },
          {
            "id": "backend-2",
            "host": "10.0.0.2",
            "port": 8080,
            "protocol": "http",
            "weight": 100,
            "enabled": true
          }
        ],
        "host_header": {
          "mode": "visitor"
        },
        "health_check": {
          "mode": "http",
          "path": "/health",
          "interval_seconds": 5,
          "timeout_ms": 1000,
          "expected_statuses": [200],
          "healthy_threshold": 2,
          "unhealthy_threshold": 3
        }
      }
    ]
  }
}
```

See [Load Balancer Plugin](plugins/load-balancer.md) for details.

#### `algorithm.type` values

| Value | Description |
|-------|-------------|
| `round_robin` | Rotate through targets |
| `weighted_round_robin` | Rotate proportionally to `weight` |
| `least_connections` | Pick the target with the fewest open connections |
| `fast_response` | Prefer targets with the fastest recent responses |
| `sticky_session` | Pin a client to a target; `algorithm.key` names the condition path to pin by (e.g. `"req.header.X-Session-Id"`) |

#### `host_header.mode` values

| Mode | Description |
|------|-------------|
| `visitor` | Forward the client's original `Host` header (default) |
| `custom` | Use the fixed `value` field (required with this mode) |
| `target` | Use each target's `host` |

#### `health_check.mode` values

| Mode | Description |
|------|-------------|
| `https` | HTTP(S) request to `path` on the target (uses the target's `protocol`) |
| `accepts_connections` | TCP connect check only |
| `off` | No health checking — all targets assumed healthy |

Other fields: `path` (default `"/"`), `interval_seconds` (5), `timeout_ms` (1000),
`expected_statuses` (array), `healthy_threshold` (2), `unhealthy_threshold` (3).
If every target is marked unhealthy the gateway returns `503` with
`{"error": "no_healthy_upstream"}`.

### `plugins.logging`

Access logging.

```json
{
  "logging": {
    "enabled": true,
    "mode": "file",
    "file": {
      "path": "/var/log/quayel/access.jsonl",
      "buffer_size": 8192,
      "flush_interval_ms": 1000
    }
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable logging |
| `mode` | string | `"file"` | Log mode (`"file"`) |
| `file.path` | string | — | Path to JSONL log file |
| `file.buffer_size` | int | `8192` | Write buffer size in bytes |
| `file.flush_interval_ms` | int | `1000` | Flush interval in milliseconds |

See [Logging](logging.md) for log format details.

### `plugins.auto_ssl`

On-demand TLS certificate provisioning using ACME (Let's Encrypt). Certificates are obtained automatically when the first HTTPS request arrives for a configured domain.

```json
{
  "auto_ssl": {
    "enabled": true,
    "email": "admin@example.com",
    "domains": [
      "example.com",
      "www.example.com",
      "api.example.com"
    ],
    "cert_storage_path": "/var/lib/quayel/certs",
    "staging": false,
    "renewal_days_before": 30
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable Auto-SSL |
| `email` | string | — | Email for Let's Encrypt account registration (required) |
| `domains` | string[] | `[]` | Domain names to provision certificates for (required) |
| `cert_storage_path` | string | `"/var/lib/quayel/certs"` | Directory to store PEM files (write-through cache) |
| `staging` | bool | `false` | Use Let's Encrypt staging environment (for testing) |
| `renewal_days_before` | int | `30` | Renew certificates this many days before expiry |

#### How it works

1. Gateway starts with a self-signed fallback cert — HTTP and HTTPS serve immediately
2. First TLS handshake for a domain in `domains` → spawns a background ACME worker
3. Worker obtains cert from Let's Encrypt via HTTP-01 challenge
4. Cert loaded into memory + persisted to disk
5. Next handshake → real cert served

#### Key behaviors

- **On-demand**: certs are only fetched when the first request arrives, not on config change
- **Deduplication**: only one ACME worker per domain (prevents duplicate provisioning)
- **Failed cert cooldown**: failed certs retry only when a new request arrives AND 24h have passed
- **Daily renewal**: background task renews certs 30 days before expiry, retries 1 failed cert per cycle
- **Non-blocking startup**: gateway serves traffic immediately, doesn't wait for certs

See [Auto-SSL Plugin](plugins/auto-ssl.md) for full documentation.

## Complete Example

```json
{
  "gateway_id": "gw-prod-01",
  "gateway_name": "production",
  "server_name": "api.example.com",
  "config_version": "2026-01-01-001",
  "listen": {
    "http": "0.0.0.0:8080"
  },
  "client_ip": {
    "source": "header_index",
    "header": "X-Forwarded-For",
    "index": 0,
    "fallback": "peer_ip"
  },
  "plugins": {
    "ip_intel": { "enabled": true },
    "firewall": {
      "enabled": true,
      "rules": [
        {
          "id": "block-tor",
          "name": "Block Tor exits",
          "enabled": true,
          "conditions": [
            { "left": "ip.is_tor", "operator": "equals", "value": true }
          ],
          "action": { "type": "block", "status": 403 }
        },
        {
          "id": "block-high-risk",
          "name": "Block high risk IPs",
          "enabled": true,
          "conditions": [
            { "left": "ip.risk_score", "operator": "greater_than", "value": 30 }
          ],
          "action": { "type": "block", "status": 403 }
        }
      ]
    },
    "rate_limiting": {
      "enabled": true,
      "rules": [
        {
          "id": "api-rate",
          "name": "API rate limit",
          "enabled": true,
          "conditions": [
            { "left": "req.path", "operator": "starts_with", "value": "/api/" }
          ],
          "key": "req.client_ip",
          "limit": 100,
          "window_seconds": 60
        }
      ]
    },
    "cache": { "enabled": false, "rules": [] },
    "load_balancer": {
      "enabled": true,
      "load_balancers": [
        {
          "id": "default",
          "name": "Backend Pool",
          "enabled": true,
          "conditions": [],
          "algorithm": { "type": "round_robin" },
          "targets": [
            {
              "id": "backend-1",
              "host": "10.0.0.1",
              "port": 8080,
              "protocol": "http",
              "weight": 100,
              "enabled": true
            }
          ],
          "host_header": { "mode": "visitor" },
          "health_check": { "mode": "off" }
        }
      ]
    },
    "logging": {
      "enabled": true,
      "mode": "file",
      "file": {
        "path": "/var/log/quayel/access.jsonl",
        "buffer_size": 8192,
        "flush_interval_ms": 1000
      }
    },
    "auto_ssl": {
      "enabled": true,
      "email": "admin@example.com",
      "domains": ["api.example.com"],
      "cert_storage_path": "/var/lib/quayel/certs",
      "staging": false,
      "renewal_days_before": 30
    }
  }
}
```

## Validation

The gateway validates config on startup and rejects:

- Missing required fields (`gateway_id`, `gateway_name`, `server_name`, `config_version`)
- Unknown fields inside `server` (typos), `server.workers: 0`, or an invalid
  IP/CIDR in `server.protection.exempt_ips`
- `client_ip.source` is `header` or `header_index` but `header` is not set
- `client_ip.source` is `header_index` but `index` is not set
- Transform rules with an unknown or wrong-phase action, an invalid regex, a
  status outside 200–599, or a protected header (`content-length`,
  `x-forwarded-for`, ...)
- Firewall rules with empty conditions
- Rate limit rules with `limit: 0` or `window_seconds: 0`
- Load balancers with no targets
- Auto-SSL: missing `email` or empty `domains`

> **Tip:** you can pre-validate generated configs against
> [`config.schema.json`](config.schema.json) (JSON Schema) before starting the
> gateway. The gateway's own parser remains authoritative. AI agents should also
> read [`ai-guide.md`](ai-guide.md).