# Logging

The gateway produces structured JSONL (JSON Lines) access logs — one JSON object per request.

## Configuration

```json
{
  "plugins": {
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
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable logging |
| `mode` | string | `"file"` | Log mode |
| `file.path` | string | — | Path to JSONL log file |
| `file.buffer_size` | int | `8192` | Write buffer size |
| `file.flush_interval_ms` | int | `1000` | Flush interval |

## Log Format

Each line is a complete JSON object:

```json
{
  "timestamp": "2026-01-15T10:30:45.123456789+00:00",
  "gateway_id": "gw-prod-01",
  "gateway_name": "production",
  "server_name": "api.example.com",
  "config_version": "2026-01-15-001",
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "client_ip": "203.0.113.50",
  "peer_ip": "203.0.113.50",
  "client_ip_source": "X-Forwarded-For",
  "method": "GET",
  "scheme": "https",
  "host": "api.example.com",
  "path": "/api/v1/users",
  "response_status": 200,
  "bandwidth": { ... },
  "ip_intel": { ... },
  "firewall": { ... },
  "rate_limit": { ... },
  "request_transform": { ... },
  "cache": { ... },
  "response_transform": { ... },
  "load_balancer": { ... },
  "termination_phase": null,
  "timings_us": { ... }
}
```

## Fields Reference

### Identity

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | ISO 8601 timestamp with nanoseconds |
| `gateway_id` | string | Gateway instance ID |
| `gateway_name` | string | Gateway name |
| `server_name` | string | Server name |
| `config_version` | string | Config version string |
| `request_id` | string | UUID v4 unique request ID |

### Client

| Field | Type | Description |
|-------|------|-------------|
| `client_ip` | string | Resolved real client IP |
| `peer_ip` | string | Direct TCP connection IP |
| `client_ip_source` | string | How client_ip was determined |

### HTTP

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method |
| `scheme` | string | Request scheme (http/https) |
| `host` | string | Host the client sent (a `request_transform` rewrite is in `request_transform.host`) |
| `path` | string | Path and query the client sent (a `request_transform` rewrite is in `request_transform.path`) |

### Response

| Field | Type | Description |
|-------|------|-------------|
| `response_status` | number | HTTP response status code |

### Bandwidth

```json
{
  "bandwidth": {
    "client_bytes_in": 1234,
    "client_bytes_out": 5678,
    "total_client_bytes": 6912,
    "upstream_bytes_out": 1234,
    "upstream_bytes_in": 5678,
    "total_origin_bytes": 6912
  }
}
```

| Field | Description |
|-------|-------------|
| `client_bytes_in` | Bytes received from client |
| `client_bytes_out` | Bytes sent to client |
| `total_client_bytes` | client_bytes_in + client_bytes_out |
| `upstream_bytes_out` | Bytes sent to upstream |
| `upstream_bytes_in` | Bytes received from upstream |
| `total_origin_bytes` | upstream_bytes_out + upstream_bytes_in |

### IP Intelligence

```json
{
  "ip_intel": {
    "country": "US",
    "region": "CA",
    "asn": 16509,
    "provider": "Amazon AWS",
    "network_type": "datacenter",
    "is_vpn": false,
    "is_proxy": false,
    "is_datacenter": true,
    "is_mobile": null,
    "is_tor": false,
    "risk_score": 10
  }
}
```

See [IP Intelligence](plugins/ip-intel.md) for field details.

### Firewall

```json
{
  "firewall": {
    "matched": true,
    "rule_id": "block-tor",
    "action": "Block"
  }
}
```

| Field | Description |
|-------|-------------|
| `matched` | Whether any firewall rule matched |
| `rule_id` | ID of the matched rule |
| `action` | Action taken (`Allow`, `Block`, `Redirect`, etc.) |

### Rate Limiting

```json
{
  "rate_limit": {
    "matched": true,
    "rule_id": "api-limit",
    "blocked": false,
    "remaining": 87
  }
}
```

| Field | Description |
|-------|-------------|
| `matched` | Whether any rate limit rule matched |
| `rule_id` | ID of the matched rule |
| `blocked` | Whether the request was blocked |
| `remaining` | Remaining requests in current window |

### Request Transform

```json
{
  "request_transform": {
    "rules": ["rt-api-v1"],
    "path": "/v1/users?page=2",
    "host": null
  }
}
```

| Field | Description |
|-------|-------------|
| `rules` | IDs of the `request_transform` rules that matched, in order. Empty when none matched |
| `path` | Path and query sent to the origin, when a rule rewrote them; otherwise `null` |
| `host` | Host sent to the origin, when a rule changed the `Host` header; otherwise `null` |

### Cache

```json
{
  "cache": {
    "rule_id": "cache-static",
    "status": "HIT",
    "key_hash": "a1b2c3d4..."
  }
}
```

| Field | Description |
|-------|-------------|
| `rule_id` | ID of the matched cache rule |
| `status` | Cache status (see below) |
| `key_hash` | Hash of the cache key |

#### Cache status values

| Status | Description |
|--------|-------------|
| `NONE` | No cache rule matched |
| `HIT` | Fresh cache hit — served from cache |
| `MISS` | Cache miss — fetched from upstream |
| `EXPIRED` | Entry past its stale-while-revalidate window, kept only as a stale-if-error fallback; fetched from upstream |
| `BYPASS` | Cache bypassed by rule |
| `DYNAMIC` | (Reserved for future use) |
| `STALE` | Stored copy served because the origin failed (stale-if-error) |
| `REVALIDATING` | Served stale data while another request refreshes cache |
| `REVALIDATED` | Origin answered 304; stored copy served and its TTL restarted |

### Response Transform

```json
{
  "response_transform": {
    "rules": ["rs-powered-by", "rs-cors"]
  }
}
```

| Field | Description |
|-------|-------------|
| `rules` | IDs of the `response_transform` rules that matched, in order. Always empty for gateway blocks (403, 429, ...), which aren't transformed |

### Load Balancer

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

| Field | Description |
|-------|-------------|
| `lb_id` | Load balancer pool ID |
| `algorithm` | Algorithm used |
| `target_id` | Selected target ID |
| `target` | Selected target host |

### Termination Phase

```json
{
  "termination_phase": "Firewall"
}
```

| Value | Description |
|-------|-------------|
| `null` | Request completed normally |
| `IpIntel` | Terminated by IP Intel plugin |
| `Firewall` | Terminated by Firewall (blocked/redirected) |
| `RateLimit` | Terminated by Rate Limiting (429) |
| `Cache` | Terminated by Cache (HIT served) |
| `LoadBalancer` | Terminated by Load Balancer (no upstream) |

### Timings

```json
{
  "timings_us": {
    "ip_intel_us": 42,
    "firewall_us": 3,
    "rate_limit_us": 0,
    "cache_lookup_us": null,
    "load_balancer_us": 7,
    "upstream_connect_us": null,
    "upstream_ttfb_us": null,
    "total_us": 1091
  }
}
```

All timings are in microseconds (μs).

| Field | Description |
|-------|-------------|
| `ip_intel_us` | Time spent in IP intelligence lookup |
| `firewall_us` | Time spent evaluating firewall rules |
| `rate_limit_us` | Time spent in rate limit checking |
| `cache_lookup_us` | Time spent in cache lookup |
| `load_balancer_us` | Time spent selecting upstream target |
| `upstream_connect_us` | Time to connect to upstream |
| `upstream_ttfb_us` | Upstream time to first byte |
| `total_us` | Total request processing time |

## Log Analysis Examples

### Count requests by country

```bash
cat access.jsonl | jq -r '.ip_intel.country' | sort | uniq -c | sort -rn | head -20
```

### Find blocked requests

```bash
cat access.jsonl | jq 'select(.firewall.matched == true)' | wc -l
```

### Find rate-limited requests

```bash
cat access.jsonl | jq 'select(.rate_limit.blocked == true)'
```

### Average response time

```bash
cat access.jsonl | jq '.timings_us.total_us' | awk '{sum+=$1; n++} END {print sum/n " μs"}'
```

### Requests per second

```bash
cat access.jsonl | jq -r '.timestamp' | cut -c1-19 | uniq -c | sort -rn | head
```

### Top IPs by request count

```bash
cat access.jsonl | jq -r '.client_ip' | sort | uniq -c | sort -rn | head -20
```

### VPN/Tor traffic

```bash
cat access.jsonl | jq 'select(.ip_intel.is_vpn == true or .ip_intel.is_tor == true)'
```

### High-risk requests

```bash
cat access.jsonl | jq 'select(.ip_intel.risk_score > 30)'
```

### Cache hit rate

```bash
total=$(cat access.jsonl | jq 'select(.cache.status != "NONE")' | wc -l)
hits=$(cat access.jsonl | jq 'select(.cache.status == "HIT")' | wc -l)
echo "Cache hit rate: $(echo "scale=2; $hits * 100 / $total" | bc)%"
```

### Cache revalidation events

```bash
# Count concurrent stale serving events
cat access.jsonl | jq 'select(.cache.status == "REVALIDATING")' | wc -l

# Count stale fallbacks (lock race condition)
cat access.jsonl | jq 'select(.cache.status == "STALE")' | wc -l
```

### Slow requests (>100ms)

```bash
cat access.jsonl | jq 'select(.timings_us.total_us > 100000)'
```

## Log Rotation

Use `logrotate` or similar:

```
/var/log/quayel/access.jsonl {
    daily
    rotate 30
    compress
    missingok
    notifempty
    copytruncate
}
```

## Notes

- Logs are written synchronously (one `write()` per line)
- The log file is created automatically if it doesn't exist
- Parent directories are created automatically
- Logs are appended (no rotation built-in — use external tools)
- Each gateway instance writes to its own log file