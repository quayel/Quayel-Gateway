# Logging

The gateway produces structured JSONL (JSON Lines) access logs — one JSON object per request.

## Configuration

```json
{
  "plugins": {
    "logging": {
      "enabled": true,
      "mode": "file",
      "queue_size": 65536,
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
| `mode` | string | `"file"` | Where events go. Only `"file"` today; anything else is rejected when the config loads |
| `queue_size` | int | `65536` | Events waiting to be written. When the queue is full, new events are dropped and counted (see [How events are written](#how-events-are-written)) |
| `file.path` | string | `/var/log/quayel/access.jsonl` | Path to the JSONL log file |
| `file.buffer_size` | int | `8192` | Events written per batch |
| `file.flush_interval_ms` | int | `1000` | Write at least this often, in ms. Also how often the gateway checks whether the file was rotated |

All of these settings apply on [hot reload](configuration.md): changing the
path, turning logging on or off, or changing a size starts a new writer. The
old writer finishes the events it already had, writing them to the old file.

## Request ID

Every request gets an ID, sent to the origin and returned to the client in the
`X-QG-Request-Id` header, and logged as `request_id`:

- If the request already has a well-formed `X-QG-Request-Id` (1–128
  characters from `A-Z a-z 0-9 - _ . : / + =`), that ID is reused, so one ID
  follows the request through every proxy in the chain.
- Otherwise the gateway generates a random 128-bit ID (32 hex characters).
  IDs don't repeat across restarts or between gateway instances.

```json
"server": { "request_id": { "accept_incoming": true } }
```

Set `accept_incoming` to `false` when clients talk to the gateway directly and
you don't want them choosing their own IDs. `request_transform` rules can't
change `X-QG-Request-Id`; `response_transform` rules can rename or remove it
on the way back to the client.

## Log Format

Each line is a complete JSON object:

```json
{
  "timestamp": "2026-01-15T10:30:45.123456789+00:00",
  "gateway_id": "gw-prod-01",
  "gateway_name": "production",
  "server_name": "api.example.com",
  "config_version": "2026-01-15-001",
  "request_id": "4f0c1a9e2b7d4c38a5e6f1d2c3b4a596",
  "client_ip": "203.0.113.50",
  "peer_ip": "203.0.113.50",
  "client_ip_source": "X-Forwarded-For",
  "method": "GET",
  "scheme": "https",
  "host": "api.example.com",
  "path": "/api/v1/users",
  "http_version": "HTTP/1.1",
  "user_agent": "curl/8.5.0",
  "referer": null,
  "response_status": 200,
  "upstream_status": 200,
  "error": null,
  "bandwidth": { ... },
  "ip_intel": { ... },
  "protection": null,
  "jwt": { ... },
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
| `request_id` | string | The `X-QG-Request-Id` for this request (see [Request ID](#request-id)) |

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
| `http_version` | string | `HTTP/1.0`, `HTTP/1.1` or `HTTP/2` |
| `user_agent` | string \| null | `User-Agent` the client sent |
| `referer` | string \| null | `Referer` the client sent |

### Response

| Field | Type | Description |
|-------|------|-------------|
| `response_status` | number | Status sent to the client |
| `upstream_status` | number \| null | Status the origin sent, before `response_transform`. `null` when the request never got an answer from the origin (cache hit, block, connection error) |
| `error` | string \| null | Why the request failed, e.g. the origin refused the connection or timed out. `null` on success and when a stored copy was served instead |

### Protection

`protection` names the `server.protection` / `server.limits` check that refused
the request: `banned`, `request_rate` or `body_too_large`. `null` when the
request wasn't refused. Connections refused before a request is read
(connection limits, slow or oversized headers) never produce a log line.

### JWT

```json
{
  "jwt": { "valid": true, "error": null, "sub": "user-123" }
}
```

The result for the token in the `Authorization` header. It's only present when
a rule read the token, so logging never verifies a token by itself; otherwise
`jwt` is `null`.

| Field | Description |
|-------|-------------|
| `valid` | The token passed every check against the configured `jwt` keys |
| `error` | Why it failed (`missing`, `malformed`, `expired`, `bad_signature`, ...), or `unverified` when no `jwt` keys are configured |
| `sub` | The `sub` claim, only for a valid token |

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
| `Protection` | Refused by `server.protection` / `server.limits` (see `protection`) |

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

### Follow one request across services

```bash
jq 'select(.request_id == "4f0c1a9e2b7d4c38a5e6f1d2c3b4a596")' access.jsonl
```

### Origin errors

```bash
jq 'select(.error != null) | {timestamp, path, response_status, error}' access.jsonl
```

## How events are written

- Each request's event goes onto an in-memory queue; a background task writes
  events in batches (`file.buffer_size` events, or every
  `file.flush_interval_ms`). Requests never wait for the disk.
- The queue holds at most `queue_size` events. If the disk can't keep up, new
  events are dropped rather than using more memory, and the gateway logs a
  warning with the number dropped, at most once per flush interval.
- If the file can't be opened (missing directory, permissions), the gateway
  logs the error once, drops events, and retries every flush interval.
- The log file and its parent directories are created automatically. Events
  are appended.

## Log Rotation

The gateway notices when its log file has been moved or deleted (it checks
every `flush_interval_ms`) and opens a new one at the configured path. Sending
`SIGHUP` reopens it straight away. So logrotate's default
move-and-create works without `copytruncate`, which can lose lines:

```
/var/log/quayel/access.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        pkill -HUP -x quayel-gateway || true
    endscript
}
```

`delaycompress` keeps yesterday's file uncompressed for one more cycle, so
the last few events written before the reopen land in a plain file. Without
the `postrotate` signal, the switch happens within one flush interval.

## Notes

- Each gateway instance writes to its own log file
