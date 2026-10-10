# Configuration Reference

Complete reference for `config.json`.

## Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `gateway_id` | string | ✅ | Unique identifier for this gateway instance |
| `gateway_name` | string | ✅ | Human-readable name |
| `server_name` | string | ✅ | Server name for logging |
| `config_version` | string | ✅ | Version string for tracking config changes |
| `listen` | object | ✅ | Listen addresses |
| `client_ip` | object | — | Client IP resolution strategy |
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

At least one of `http` or `https` must be specified.

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

## `plugins`

```json
{
  "plugins": {
    "ip_intel": { ... },
    "firewall": { ... },
    "rate_limiting": { ... },
    "cache": { ... },
    "load_balancer": { ... },
    "logging": { ... }
  }
}
```

### `plugins.ip_intel`

IP Intelligence. All data is embedded in the binary — only `enabled` is needed.

```json
{
  "ip_intel": {
    "enabled": true
  }
}
```

See [IP Intelligence Plugin](plugins/ip-intel.md) for details.

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

See [Rate Limiting Plugin](plugins/rate-limiting.md) for details.

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
- No listen address (`http` and `https` both missing)
- `client_ip.source` is `header` or `header_index` but `header` is not set
- `client_ip.source` is `header_index` but `index` is not set
- Firewall rules with empty conditions
- Rate limit rules with `limit: 0` or `window_seconds: 0`
- Load balancers with no targets
- Auto-SSL: missing `email` or empty `domains`