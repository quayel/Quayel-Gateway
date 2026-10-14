# API Reference — Upstream Headers, Variables & Integration

The Quayel Gateway enriches every request with IP intelligence, security decisions, and metadata. This data is available through:

1. **Upstream request headers** — forwarded to your backend servers
2. **Condition paths** — used in firewall, rate limit, cache, and LB rules
3. **JSONL log fields** — recorded in access logs
4. **Response headers** — sent back to clients

## Upstream Request Headers

These headers are automatically added to requests forwarded to backend servers.

### Standard Proxy Headers

| Header | Value | Description |
|--------|-------|-------------|
| `X-Forwarded-For` | `client_ip` | Client IP appended to existing chain |
| `X-Forwarded-Proto` | `http` / `https` | Original request scheme |
| `X-Forwarded-Host` | `host` | Original request host |
| `X-QG-Request-Id` | UUIDv7 | Request ID, also returned to the client and written to the access log |

### Client IP Resolution

The gateway resolves the real client IP based on the `client_ip` configuration:

| Config `source` | Behavior |
|------------------|----------|
| `peer_ip` | Uses direct TCP connection IP |
| `header` | Reads IP from specified header (e.g., `CF-Connecting-IP`) |
| `header_index` | Reads IP from Nth entry in comma-separated header (e.g., `X-Forwarded-For`) |

The resolved `client_ip` is used for all IP intel lookups and rate limiting.

## Condition Paths

These paths can be used in the `left` field of any condition (firewall, rate limiting, cache, load balancer).

### Request Fields

| Path | Type | Description | Example Value |
|------|------|-------------|---------------|
| `req.host` / `http.host` | string | Host header | `"api.example.com"` |
| `req.path` / `http.path` | string | Request path + query | `"/api/v1/users?page=1"` |
| `req.method` / `http.method` | string | HTTP method | `"GET"` |
| `req.scheme` / `http.scheme` | string | Request scheme | `"https"` |
| `req.ip` / `http.ip` | string | Resolved client IP | `"203.0.113.50"` |
| `req.peer_ip` / `http.peer_ip` | string | Direct connection IP | `"10.0.0.1"` |
| `req.user_agent` / `http.user_agent` | string | User-Agent header | `"Mozilla/5.0 ..."` |

### IP Intelligence Fields

| Path | Type | Description | Example Value |
|------|------|-------------|---------------|
| `ip.country` | string | ISO 3166-1 alpha-2 country code | `"US"` |
| `ip.region` | string | Region/state code | `"CA"` |
| `ip.city` | string | City name | `"San Francisco"` |
| `ip.asn` | number | Autonomous System Number | `16509` |
| `ip.as_org` | string | ASN organization name | `"AMAZON-02"` |
| `ip.provider` | string | Hosting/cloud provider label | `"Amazon AWS"` |
| `ip.is_vpn` | bool | IP is a known VPN provider | `true` |
| `ip.is_tor` | bool | IP is a Tor exit node | `false` |
| `ip.is_datacenter` | bool | IP is from datacenter/hosting | `true` |
| `ip.is_proxy` | bool | IP is a known anonymous proxy | `false` |
| `ip.is_mobile` | bool | IP is from a mobile network | `null` |
| `ip.is_residential` | bool | IP is residential | `null` |
| `ip.is_residential_proxy` | bool | IP is a residential proxy | `null` |
| `ip.network_type` | string | Network type classification | `"datacenter"` |
| `ip.risk_score` | number | Risk score (0-100) | `10` |

### Header, Query, and Cookie Access

| Path Pattern | Type | Description |
|-------------|------|-------------|
| `req.header.<name>` | string | Request header value |
| `http.header.<name>` | string | Request header value |
| `req.header.<name>.jwt.<claim.path>` | any | Claim from the JWT in the header (strips `Bearer `). With `jwt` keys: only for verified tokens; without: decoded unchecked |
| `req.header.<name>.jwt_valid` | bool | `true` only for a token that passed every check (always `false` without `jwt` keys) |
| `req.header.<name>.jwt_error` | string | Why the token failed: `missing`, `malformed`, `bad_signature`, `expired`, ... (`unverified` without keys) |
| `req.query.<name>` | string | Query parameter value |
| `http.query.<name>` | string | Query parameter value |
| `req.cookie.<name>` | string | Cookie value |
| `http.cookie.<name>` | string | Cookie value |

**Examples:**

```json
{ "left": "req.header.X-API-Key", "operator": "exists" }
{ "left": "req.header.authorization.jwt.data.role", "operator": "equals", "value": "admin" }
{ "left": "req.query.page", "operator": "greater_than", "value": 1 }
{ "left": "req.cookie.Session-ID", "operator": "exists" }
```

## Operators Reference

| Operator | Description | Left Type | Value Type |
|----------|-------------|-----------|------------|
| `equals` | Exact match | any | any |
| `not_equals` | Not equal | any | any |
| `contains` | String contains | string | string |
| `not_contains` | String does not contain | string | string |
| `starts_with` | String prefix match | string | string |
| `ends_with` | String suffix match | string | string |
| `exists` | Value is not null | any | — |
| `not_exists` | Value is null | any | — |
| `in` | Value is in array | any | array |
| `not_in` | Value is not in array | any | array |
| `greater_than` | Numeric > | number | number |
| `greater_than_or_equal` | Numeric >= | number | number |
| `less_than` | Numeric < | number | number |
| `less_than_or_equal` | Numeric <= | number | number |
| `regex` | Regular expression | string | string (regex) |

## Firewall Actions

| Action Type | Description | Extra Fields |
|-------------|-------------|--------------|
| `block` | Return error response | `status` (default: 403) |
| `allow` | Continue pipeline (skip remaining firewall rules) | — |
| `redirect` | Return redirect response | `status` (default: 302), `location` |
| `set_request_header` | Set headers on the upstream request; later rules still run | `headers` (map) |
| `set_response_header` | Set headers on the client response; later rules still run | `headers` (map) |

### Block Response Body

```json
{
  "error": "blocked",
  "status": 403,
  "rule_id": "block-tor"
}
```

### Redirect Response

```
HTTP/1.1 302 Found
Location: https://example.com/blocked
Content-Length: 0
```

## Rate Limiting

### Blocked Response Body

```json
{
  "error": "rate_limited",
  "status": 429,
  "rule_id": "api-limit",
  "limit": 100,
  "window_seconds": 60
}
```

**Response Headers:**
| Header | Value |
|--------|-------|
| `Content-Type` | `application/json` |
| `Retry-After` | Window seconds |

### Rate Limit Keys

| Key | Description |
|-----|-------------|
| `req.client_ip` | Resolved client IP |
| `req.peer_ip` | Direct connection IP |
| `req.header.<name>` | Header value (e.g., `X-API-Key`) |

## Load Balancer

### No Healthy Upstream Response

```json
{
  "error": "no_healthy_upstream"
}
```

Status: `503 Service Unavailable`

### Upstream Headers Added

| Header | Value |
|--------|-------|
| `X-Forwarded-For` | Client IP (appended to chain) |
| `X-Forwarded-Proto` | Original scheme (`http` / `https`) |
| `X-Forwarded-Host` | Original `Host` header |
| `X-QG-Request-Id` | Request ID (UUIDv7) |

### TLS / SNI Behavior

When target `protocol` is `https` or `h2`:

| Scenario | SNI used |
|----------|----------|
| `tls.sni` configured | Uses configured SNI |
| Target is IP + visitor has Host header | Uses visitor's Host |
| Target is IP + no Host header | Uses target IP as SNI |
| Target is hostname | Uses target hostname |

## Cache Response Headers

| Header | Value | Description |
|--------|-------|-------------|
| `Quayel-Cache-Status` | `NONE` / `HIT` / `MISS` / `EXPIRED` / `BYPASS` / `STALE` / `REVALIDATING` | Cache status |

### Cache Status Values

| Value | Description |
|-------|-------------|
| `NONE` | No cache rule matched |
| `HIT` | Response served from fresh cache |
| `MISS` | Cache miss, fetched from upstream |
| `EXPIRED` | (Reserved) |
| `BYPASS` | Cache bypassed by rule |
| `DYNAMIC` | (Reserved) |
| `STALE` | Served stale data (lock race fallback — another request was already revalidating) |
| `REVALIDATING` | Served stale data while another request refreshes the cache (or this request is the one refreshing) |

### Cache Revalidation

When a cached entry becomes stale, the gateway uses **singleflight revalidation** via per-key locks:

- **First request** that finds stale data acquires the lock and goes to origin like a normal cache miss
- **Concurrent requests** see the lock is held and serve stale cached data with `Quayel-Cache-Status: REVALIDATING`
- When the first request completes, the lock releases and subsequent requests see fresh cache data

This prevents **cache stampedes** — only one request per key goes to origin, regardless of how many concurrent requests arrive.

See [Cache Plugin — Singleflight Revalidation](plugins/cache.md#singleflight-revalidation) for detailed flow diagrams.

## JSONL Log Fields

See [Logging](logging.md) for the complete log format.

### Key Fields for Monitoring

| Field | Path | Description |
|-------|------|-------------|
| Client IP | `.client_ip` | Resolved real client IP |
| Country | `.country` | GeoIP country code |
| ASN | `.asn` | Autonomous System Number |
| Provider | `.provider` | Hosting/cloud provider label |
| VPN | `.vpn` | VPN detection |
| Tor | `.tor` | Tor exit detection |
| Datacenter | `.datacenter` | Datacenter detection |
| Risk Score | `.risk` | 0-100 risk score |
| Blocked | `.block.type` | `fw`, `rl`, `dos`, or `""` when not blocked |
| Blocking rule | `.block.rule`, `.block.key` | Rule ID and what it matched on |
| Cache Status | `.cache` | HIT/MISS/REVALIDATING/STALE/BYPASS/NONE |
| LB Target | `.upstream`, `.upstream_addr` | Selected upstream |
| Total Time | `.dur_us` | Total processing time (μs) |

## Plugin Pipeline Order

Plugins execute in this fixed order:

```
1. IP Intelligence     (always runs)
2. Firewall            (can short-circuit)
3. Rate Limiting       (can short-circuit)
4. Load Balancer       (can short-circuit — selects upstream target)
5. Cache               (can short-circuit — uses upstream target for revalidation)
6. Logging             (always runs)
```

### Short-circuit Behavior

| Plugin | Can Short-circuit? | When? |
|--------|-------------------|-------|
| IP Intel | No | Always continues |
| Firewall | Yes | Block, redirect, or set-header action |
| Rate Limit | Yes | Limit exceeded → 429 |
| Cache | Yes | Cache HIT → serve cached response; REVALIDATING/STALE → serve stale cached data |
| Load Balancer | Yes | No healthy upstream → 503 |

## Example: Complete Backend Integration

When your backend receives a request through Quayel, it gets:

```
GET /api/v1/users HTTP/1.1
Host: api.example.com
X-Forwarded-For: 203.0.113.50
X-Forwarded-Proto: https
X-Forwarded-Host: api.example.com
X-QG-Request-Id: 0192d4e8-7c1a-7b3e-9f2c-4e1a7b3d5c6f
User-Agent: Mozilla/5.0 ...
```

The same `X-QG-Request-Id` is returned to the client and written to the
access log, so one ID ties together the client, the gateway log and your
backend's logs.

The access log records:

```json
{
  "schema_version": 1,
  "gateway_id": "gw-prod-01",
  "ts": 1791892991482,
  "request_id": "0192d4e8-7c1a-7b3e-9f2c-4e1a7b3d5c6f",
  "client_ip": "203.0.113.50",
  "method": "GET",
  "scheme": "https",
  "host": "api.example.com",
  "path": "/api/v1/users",
  "user_agent": "Mozilla/5.0 ...",
  "status": 200,
  "bytes": 512,
  "req_bytes": 0,
  "dur_us": 2104,
  "country": "US",
  "region": "CA",
  "asn": 16509,
  "provider": "Amazon AWS",
  "datacenter": true,
  "vpn": false,
  "proxy": false,
  "tor": false,
  "risk": 10,
  "block": { "type": "", "action": "", "rule": "", "key": "" },
  "allow_rule": "",
  "cache": "MISS",
  "upstream": "backend-1",
  "upstream_addr": "10.0.0.1:8080",
  "upstream_status": 200,
  "upstream_us": 1830,
  "error": "",
  "user": "",
  "sample_rate": 1
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `QUAYEL_IP_INTEL_CACHE_SIZE` | `65536` | LRU cache size for IP lookups |ror`) |
| `QUAYEL_IP_INTEL_CACHE_SIZE` | `65536` | LRU cache size for IP lookups |