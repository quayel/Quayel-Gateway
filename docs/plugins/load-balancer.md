# Load Balancer Plugin

The load balancer plugin routes requests to upstream backend servers using configurable algorithms. It supports multiple load balancer pools, weighted targets, health checks, and sticky sessions.

## Configuration

```json
{
  "plugins": {
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
            "mode": "off"
          }
        }
      ]
    }
  }
}
```

## Load Balancer Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique load balancer identifier |
| `name` | string | ✅ | Human-readable name |
| `enabled` | bool | — | Enable/disable (default: `true`) |
| `conditions` | array | — | When to use this LB (empty = always) |
| `algorithm` | object | ✅ | Load balancing algorithm |
| `targets` | array | ✅ | Upstream backend servers |
| `host_header` | object | — | Host header forwarding mode |
| `health_check` | object | — | Health check configuration |

## Algorithms

### Round Robin

Distributes requests evenly across all targets in order.

```json
{
  "algorithm": {
    "type": "round_robin"
  }
}
```

### Weighted Round Robin

Distributes requests based on target weights. A target with weight 200 receives twice as many requests as one with weight 100.

```json
{
  "algorithm": {
    "type": "weighted_round_robin"
  }
}
```

### Least Connections

Routes to the target with the fewest active connections.

```json
{
  "algorithm": {
    "type": "least_connections"
  }
}
```

### Fast Response

Routes to the target with the lowest EWMA (Exponentially Weighted Moving Average) latency.

```json
{
  "algorithm": {
    "type": "fast_response"
  }
}
```

### Sticky Session

Routes the same client to the same target based on a hash of the key.

```json
{
  "algorithm": {
    "type": "sticky_session",
    "key": "req.client_ip"
  }
}
```

The `key` field accepts any [condition path](../conditions.md#condition-paths):

| Key | Description |
|-----|-------------|
| `req.client_ip` | Sticky by client IP (default) |
| `req.header.X-API-Key` | Sticky by API key |
| `req.cookie.Session-ID` | Sticky by session cookie |
| `req.header.X-Tenant-ID` | Sticky by tenant |

## Targets

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | string | ✅ | Unique target identifier |
| `host` | string | ✅ | Backend hostname or IP |
| `port` | number | ✅ | Backend port |
| `protocol` | string | `"http"` | `"http"`, `"https"`, `"h2c"` (HTTP/2 without TLS) or `"h2"` (HTTP/2 over TLS). Use `h2c` / `h2` for gRPC servers |
| `weight` | number | `100` | Weight for weighted algorithms |
| `enabled` | bool | `true` | Enable/disable target |
| `tls.verify` | bool | `false` | Verify upstream TLS certificate |
| `tls.sni` | string | — | Custom SNI for TLS handshake |

### HTTP/2 and gRPC targets

gRPC needs HTTP/2 all the way to the server. `"h2c"` talks HTTP/2 with prior
knowledge over plain TCP; `"h2"` talks HTTP/2 over TLS (ALPN `h2`, the
`tls.*` settings apply). Up to 100 requests share one upstream connection.

```json
{ "id": "grpc", "host": "10.0.0.7", "port": 50051, "protocol": "h2c" }
```

For health checks on gRPC servers use `accepts_connections`: a gRPC server
usually answers a plain `GET` with an error status, which the `https` mode
counts as unhealthy.

### TLS configuration

```json
{
  "id": "secure-backend",
  "host": "backend.internal",
  "port": 443,
  "protocol": "https",
  "weight": 100,
  "enabled": true,
  "tls": {
    "verify": true,
    "sni": "api.example.com"
  }
}
```

When `tls.sni` is not set:
- If target host is an IP → uses the visitor's `Host` header
- If target host is a hostname → uses the target hostname

## Host Header

Controls what `Host` header is sent to the upstream.

| Mode | Description |
|------|-------------|
| `visitor` | Forward the visitor's original `Host` header |
| `custom` | Use a custom value |
| `target` | Use the target's hostname |

```json
{
  "host_header": {
    "mode": "custom",
    "value": "api.internal.example.com"
  }
}
```

## Health Checks

### Off mode

No health checks. All enabled targets are considered healthy.

```json
{
  "health_check": {
    "mode": "off"
  }
}
```

### HTTP mode

Periodic HTTP health checks.

```json
{
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
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | `"/"` | Health check endpoint |
| `interval_seconds` | int | `5` | Check interval |
| `timeout_ms` | int | `1000` | Request timeout |
| `expected_statuses` | array | any 2xx/3xx | Status codes that count as healthy. When unset or empty, any 2xx or 3xx does. Redirects are not followed |
| `healthy_threshold` | int | `2` | Consecutive successes to mark healthy |
| `unhealthy_threshold` | int | `3` | Consecutive failures to mark unhealthy |

Unhealthy targets get no traffic until they pass `healthy_threshold` checks again. Health is tracked per pool, so the same backend can be healthy in one pool and down in another with different checks.

> **Note:** health checks are started when the gateway starts. A config reload applies `enabled`, weights and new targets straight away, but new targets aren't health-checked and changed `health_check` settings don't take effect until the next restart.

### Accepts Connections mode

Simple TCP connection check.

```json
{
  "health_check": {
    "mode": "accepts_connections"
  }
}
```

## How It Works

```
Request arrives
    │
    ▼
1. Evaluate conditions for each load balancer
    │
    ├── No match → continue (no upstream selected)
    │
    └── Match:
        │
        ├── 2. Filter enabled targets
        │
        ├── No enabled targets → 503 "no_healthy_upstream"
        │
        └── 3. Select target using algorithm
            │
            ├── round_robin → atomic counter % len
            ├── weighted_round_robin → weight-based selection
            ├── least_connections → min active connections
            ├── fast_response → min EWMA latency
            └── sticky_session → hash(key + target_id)
            
            │
            ├── 4. Record selection in context
            ├── 5. Increment connection count
            │
            └── 6. Create HttpPeer → forward to upstream
```

## Examples

### Simple round-robin

```json
{
  "id": "default",
  "name": "Backend Pool",
  "enabled": true,
  "conditions": [],
  "algorithm": { "type": "round_robin" },
  "targets": [
    { "id": "b1", "host": "10.0.0.1", "port": 8080, "protocol": "http", "weight": 100, "enabled": true },
    { "id": "b2", "host": "10.0.0.2", "port": 8080, "protocol": "http", "weight": 100, "enabled": true }
  ],
  "host_header": { "mode": "visitor" },
  "health_check": { "mode": "off" }
}
```

### Weighted with health checks

```json
{
  "id": "default",
  "name": "Production Pool",
  "enabled": true,
  "conditions": [],
  "algorithm": { "type": "weighted_round_robin" },
  "targets": [
    { "id": "large", "host": "10.0.0.1", "port": 8080, "protocol": "http", "weight": 200, "enabled": true },
    { "id": "small", "host": "10.0.0.2", "port": 8080, "protocol": "http", "weight": 100, "enabled": true }
  ],
  "host_header": { "mode": "visitor" },
  "health_check": {
    "mode": "http",
    "path": "/health",
    "interval_seconds": 10,
    "timeout_ms": 2000,
    "expected_statuses": [200, 204],
    "healthy_threshold": 2,
    "unhealthy_threshold": 3
  }
}
```

### Multiple pools by path

```json
{
  "load_balancers": [
    {
      "id": "api-pool",
      "name": "API Servers",
      "enabled": true,
      "conditions": [
        { "left": "req.path", "operator": "starts_with", "value": "/api/" }
      ],
      "algorithm": { "type": "least_connections" },
      "targets": [
        { "id": "api-1", "host": "10.0.1.1", "port": 8080, "protocol": "http", "weight": 100, "enabled": true },
        { "id": "api-2", "host": "10.0.1.2", "port": 8080, "protocol": "http", "weight": 100, "enabled": true }
      ],
      "host_header": { "mode": "visitor" },
      "health_check": { "mode": "off" }
    },
    {
      "id": "static-pool",
      "name": "Static Servers",
      "enabled": true,
      "conditions": [],
      "algorithm": { "type": "round_robin" },
      "targets": [
        { "id": "static-1", "host": "10.0.2.1", "port": 80, "protocol": "http", "weight": 100, "enabled": true }
      ],
      "host_header": { "mode": "visitor" },
      "health_check": { "mode": "off" }
    }
  ]
}
```

### Sticky sessions by cookie

```json
{
  "id": "session-pool",
  "name": "Session Servers",
  "enabled": true,
  "conditions": [],
  "algorithm": {
    "type": "sticky_session",
    "key": "req.cookie.Session-ID"
  },
  "targets": [
    { "id": "app-1", "host": "10.0.0.1", "port": 8080, "protocol": "http", "weight": 100, "enabled": true },
    { "id": "app-2", "host": "10.0.0.2", "port": 8080, "protocol": "http", "weight": 100, "enabled": true }
  ],
  "host_header": { "mode": "visitor" },
  "health_check": { "mode": "off" }
}
```

### HTTPS upstream with TLS verification

```json
{
  "id": "secure-pool",
  "name": "Secure Backend",
  "enabled": true,
  "conditions": [],
  "algorithm": { "type": "round_robin" },
  "targets": [
    {
      "id": "secure-1",
      "host": "backend.internal",
      "port": 443,
      "protocol": "https",
      "weight": 100,
      "enabled": true,
      "tls": {
        "verify": true,
        "sni": "api.example.com"
      }
    }
  ],
  "host_header": { "mode": "target" },
  "health_check": { "mode": "off" }
}
```

## Upstream Headers

The gateway adds these headers to upstream requests:

| Header | Value |
|--------|-------|
| `X-Forwarded-Proto` | Original request scheme |
| `X-Forwarded-Host` | Original request host |
| `X-Forwarded-For` | Client IP (appended to existing) |

## Log Output

```json
{
  "load_balancer": {
    "lb_id": "default",
    "algorithm": "RoundRobin",
    "target_id": "backend-1",
    "target": "10.0.0.1"
  }
}
```

## Performance

| Metric | Value |
|--------|-------|
| Target selection | O(n) where n = targets |
| Connection tracking | Atomic counters |
| Latency tracking | EWMA (lock-free) |
| Sticky session hash | SHA-256 |

## Notes

- Multiple load balancers are evaluated in order — first match wins
- If no load balancer matches, the request has no upstream target (will fail)
- Connection counts are per-gateway-instance (not distributed)
- Health checks run in a background task (when enabled)
- The `503` response for no healthy upstream is: `{"error": "no_healthy_upstream"}`