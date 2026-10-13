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
      },
      "user_field": "header.authorization.jwt.sub"
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
| `user_field` | string | unset | Condition field logged as `user` on every line (see [user and sample_rate](#user-and-sample_rate)) |

All of these settings apply on [hot reload](configuration.md): changing the
path, turning logging on or off, or changing a size starts a new writer. The
old writer finishes the events it already had, writing them to the old file.

## Request ID

Every request gets an ID, sent to the origin and returned to the client in the
`X-QG-Request-Id` header, and logged as `request_id`. It's created first,
before ACME challenges, DoS protection and every plugin, so blocked, refused
and failed requests (403, 429, 413, 502, …) carry one too.

- IDs are **UUIDv7** (RFC 9562), e.g. `0192d4e8-7c1a-7b3e-9f2c-4e1a7b3d5c6f`:
  48 bits of Unix milliseconds followed by random bits. They sort by time,
  don't repeat across restarts or between gateway instances, and fit
  ClickHouse's native `UUID` type. The time part equals the line's `ts`.
- If the request already has an `X-QG-Request-Id` that is a valid UUID (any
  version), it's reused, so one ID follows the request through every proxy in
  the chain. Any other value is replaced with a new ID.

```json
"server": { "request_id": { "accept_incoming": true } }
```

Set `accept_incoming` to `false` when clients talk to the gateway directly and
you don't want them choosing their own IDs. `request_transform` rules can't
change `X-QG-Request-Id`; `response_transform` rules can rename or remove it
on the way back to the client.

## Log Format

One JSON object per line. **Every line has every key, in the same order.** A
value that doesn't apply gets its typed default (`""`, `0` or `false`), never
`null` and never a missing key, so a graph or a ClickHouse column works on
every line. `schema_version` changes only when a key is added or renamed.

A request that went to the origin (pretty-printed here; one line in the file,
about 600 bytes):

```json
{
  "schema_version": 1,
  "gateway_id": "gw-1",
  "ts": 1791892991482,
  "request_id": "0192d4e8-7c1a-7b3e-9f2c-4e1a7b3d5c6f",
  "client_ip": "203.0.113.7",
  "method": "GET",
  "scheme": "https",
  "host": "api.example.com",
  "path": "/api/users",
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
  "status": 200,
  "bytes": 512,
  "req_bytes": 0,
  "dur_us": 2104,
  "country": "IN",
  "region": "MH",
  "asn": 24560,
  "provider": "",
  "datacenter": false,
  "vpn": false,
  "proxy": false,
  "tor": false,
  "risk": 5,
  "block": { "type": "", "action": "", "rule": "", "key": "" },
  "allow_rule": "",
  "cache": "MISS",
  "upstream": "origin-2",
  "upstream_addr": "10.0.0.5:8080",
  "upstream_status": 200,
  "upstream_us": 1830,
  "error": "",
  "user": "user_123",
  "sample_rate": 1
}
```

How `block` looks when something stopped the request:

```json
"block": {"type":"fw",  "action":"block",    "rule":"block-dc",     "key":"ip.is_datacenter=true"}
"block": {"type":"fw",  "action":"block",    "rule":"api-needs-jwt","key":"req.path=/api/orders&header.authorization.jwt_valid=false"}
"block": {"type":"fw",  "action":"redirect", "rule":"old-site",     "key":"req.path=/old/page"}
"block": {"type":"rl",  "action":"block",    "rule":"api-per-user", "key":"header.authorization.jwt.user_id=u_123&header.authorization.jwt.site_id=s_9"}
"block": {"type":"dos", "action":"block",    "rule":"request_rate", "key":"client_ip=5.6.7.8"}
```

## Fields Reference

### Identity and time

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | int | Line layout version (`1`) |
| `gateway_id` | string | From the config's `gateway_id` |
| `ts` | int | Arrival time, Unix milliseconds |
| `request_id` | string | UUIDv7, see [Request ID](#request-id). Never empty |

### Request

| Field | Type | Description |
|-------|------|-------------|
| `client_ip` | string | Client IP (after `client_ip` resolution) |
| `method` | string | `GET`, `POST`, … |
| `scheme` | string | `http` or `https` |
| `host` | string | `Host` the client sent (before any `request_transform`) |
| `path` | string | Path the client sent, **without the query string** |
| `user_agent` | string | Capped at 256 bytes (ends in `…` when cut) |

The query string is never written anywhere in the log: not in `path`, not in
`block.key` (query values are hashed, see below) and not in `error`.

### Result

| Field | Type | Description |
|-------|------|-------------|
| `status` | int | Status sent to the client (after `response_transform`). `499` when the client closed the connection before the response was complete; `0` when no response was sent |
| `bytes` | int | Response body bytes sent to the client |
| `req_bytes` | int | Request body bytes read from the client |
| `dur_us` | int | Total time in the gateway, microseconds |

### IP intelligence

`""` / `0` / `false` when `ip_intel` is off or has no data for the IP.

| Field | Type | Description |
|-------|------|-------------|
| `country` | string | ISO country code |
| `region` | string | Region / subdivision code |
| `asn` | int | Autonomous system number |
| `provider` | string | Hosting provider label for datacenter ranges |
| `datacenter` | bool | Datacenter / hosting range |
| `vpn` | bool | Known VPN |
| `proxy` | bool | Known proxy |
| `tor` | bool | Tor exit node |
| `risk` | int | Risk score, 0–100 |

### block and allow_rule

A request can only be stopped once, so one `block` object covers the firewall,
rate limiting and DoS protection.

| Field | Type | Description |
|-------|------|-------------|
| `block.type` | string | `""` (not blocked), `fw`, `rl` or `dos` |
| `block.action` | string | `block`, or `redirect` for a firewall redirect rule |
| `block.rule` | string | Firewall / rate-limit rule ID, or the DoS check: `banned`, `request_rate`, `body_too_large` |
| `block.key` | string | What the rule matched on, as `field=value` pairs joined by `&` |
| `allow_rule` | string | Firewall `allow` rule that let the request skip the rules after it |

`block.key`:

- **Firewall:** the conditions that made the rule match. For `A and B or C`,
  that's `A&B` when the first branch matched, or just `C`.
- **Rate limit:** the key the limiter counted on, one pair per key part.
- **DoS protection:** `client_ip=…`.
- Values from the query string (`req.query.*`, `http.query.*`) are written as
  `#` plus the first 6 hex digits of their SHA-256, e.g.
  `req.query.api_key=#a91f3c`. The same value always gives the same hash, so
  "top keys" queries still work. `req.path` values are cut at `?`.
- Capped at 256 bytes (ends in `…` when cut).

JWT has no section of its own: a token shows up through the rule that used
it (`header.authorization.jwt_valid=false` in a firewall key, a claim in a
rate-limit key), or through `user`.

Requests refused at the connection level (connection limits, slow or
oversized headers) never become an HTTP request, so they aren't in the access
log.

### Cache and upstream

| Field | Type | Description |
|-------|------|-------------|
| `cache` | string | `NONE`, `HIT`, `MISS`, `EXPIRED`, `BYPASS`, `DYNAMIC`, `STALE`, `REVALIDATING`, `REVALIDATED` (same as the `Quayel-Cache-Status` header) |
| `upstream` | string | Load balancer target ID. `""` when the request wasn't sent to an origin (cache hit, blocked) |
| `upstream_addr` | string | `host:port` it was sent to |
| `upstream_status` | int | Status the origin sent, before `response_transform`. `0` when the origin never answered |
| `upstream_us` | int | From sending the request to the origin until its response header arrived (or until it failed), microseconds |
| `error` | string | Why the request failed (connection refused, timeout, …), or `client closed` with status `499` |

### user and sample_rate

| Field | Type | Description |
|-------|------|-------------|
| `user` | string | Value of the condition field set in `plugins.logging.user_field`, e.g. `"header.authorization.jwt.sub"`. `""` when unset or empty |
| `sample_rate` | int | How many requests this line stands for. Always `1` today; count requests with `sum(sample_rate)` so queries stay right once sampling is added |

`user_field` uses the same verified-token cache as the rules: a token a rule
already checked costs nothing more. With `jwt` keys configured, `jwt.*` fields
only return claims from tokens that pass verification, so a forged token logs
`user: ""`.

## Log Analysis Examples

### What is blocking traffic

```bash
jq -r 'select(.block.type != "") | "\(.block.type) \(.block.rule)"' access.jsonl | sort | uniq -c | sort -rn
```

### Who a rate-limit rule is hitting

```bash
jq -r 'select(.block.rule == "api-per-user") | .block.key' access.jsonl | sort | uniq -c | sort -rn | head
```

### Requests by country

```bash
jq -r '.country' access.jsonl | sort | uniq -c | sort -rn
```

### Datacenter / VPN / Tor traffic

```bash
jq -c 'select(.datacenter or .vpn or .tor) | {client_ip, asn, provider, path, status}' access.jsonl
```

### Cache hit rate

```bash
jq -r 'select(.cache != "NONE") | .cache' access.jsonl | sort | uniq -c
```

### Slow requests (>100 ms) and slow origins

```bash
jq -c 'select(.dur_us > 100000) | {path, dur_us, upstream, upstream_us}' access.jsonl
```

### Origin errors and clients giving up

```bash
jq -c 'select(.error != "") | {ts, path, status, upstream_addr, error}' access.jsonl
```

### Follow one request across services

```bash
jq 'select(.request_id == "0192d4e8-7c1a-7b3e-9f2c-4e1a7b3d5c6f")' access.jsonl
```

## How events are written

- Each request's event goes onto an in-memory queue; a dedicated writer
  thread (`qg-access-log`) writes events in batches (`file.buffer_size`
  events, or every `file.flush_interval_ms`). Requests never wait for the
  disk, and a slow disk can't hold up the gateway's other background work.
- The queue is lock-free: adding an event is one atomic operation with no
  system call, and requests don't wake the writer. The writer wakes on its
  own every 5 ms and takes everything queued (or earlier, when the queue is
  half full).
- Lines are formatted on the writer thread by a hand-written JSON writer
  (fixed key bytes, integers without allocation, strings copied as they are
  unless they need escaping). The request thread only collects raw values.
- Lines go through a 1 MiB write buffer, so a batch of thousands of events
  takes a few `write()` calls. Each batch is flushed to the OS but not
  `fsync`ed: a gateway crash loses nothing already flushed, a machine crash
  can lose the last moments.
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
`SIGHUP` reopens it within 100 ms. So logrotate's default
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
