# Conditions System

Conditions are the core matching mechanism used by Firewall, Rate Limiting, Cache, and Load Balancer plugins. A condition compares a resolved value from the request context against an expected value.

## Structure

```json
{
  "left": "<path>",
  "operator": "<operator>",
  "value": <expected_value>,
  "next": "and" | "or"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `left` | string | Path to resolve from request context |
| `operator` | string | Comparison operator |
| `value` | any | Expected value (string, number, bool, array) |
| `next` | string | Logical operator to next condition (`"and"` or `"or"`, default `"and"`) |

## Condition Paths

### Request fields

| Path | Type | Description |
|------|------|-------------|
| `req.host` / `http.host` | string | Request host header |
| `req.path` / `http.path` | string | Request path (including query string) |
| `req.method` / `http.method` | string | HTTP method (GET, POST, etc.) |
| `req.scheme` / `http.scheme` | string | Request scheme (http, https) |
| `req.ip` / `http.ip` | string | Resolved client IP |
| `req.peer_ip` / `http.peer_ip` | string | Direct connection IP |
| `req.user_agent` / `http.user_agent` | string | User-Agent header |

### IP Intelligence fields

| Path | Type | Description |
|------|------|-------------|
| `ip.country` | string | Country code (ISO 3166-1 alpha-2) |
| `ip.region` | string | Region/state code |
| `ip.city` | string | City name |
| `ip.asn` | number | ASN number |
| `ip.as_org` | string | ASN organization name |
| `ip.provider` | string | Hosting/cloud provider label (e.g. `"Hostinger"`) |
| `ip.is_vpn` | bool | IP is a known VPN |
| `ip.is_tor` | bool | IP is a Tor exit node |
| `ip.is_datacenter` | bool | IP is from a datacenter/hosting |
| `ip.is_proxy` | bool | IP is a known proxy |
| `ip.is_mobile` | bool | IP is from a mobile network |
| `ip.is_residential` | bool | IP is residential |
| `ip.is_residential_proxy` | bool | IP is a residential proxy |
| `ip.network_type` | string | Network type classification |
| `ip.risk_score` | number | Risk score (0-100) |

### Headers and cookies

| Path | Type | Description |
|------|------|-------------|
| `req.header.<name>` | string | Request header value |
| `http.header.<name>` | string | Request header value |
| `req.query.<name>` | string | Query parameter value |
| `http.query.<name>` | string | Query parameter value |
| `req.cookie.<name>` | string | Cookie value |
| `http.cookie.<name>` | string | Cookie value |

### JWT claim extraction

A header path ending in `.jwt.<claim.path>` decodes the header value as a JWT
(a leading `Bearer ` is stripped), then navigates the payload by dotted claim path:

| Path | Meaning |
|------|---------|
| `req.header.authorization.jwt.user_id` | `user_id` claim of the Bearer token |
| `req.header.authorization.jwt.data.role` | nested claim `data.role` |
| `header.token.jwt.user_id` | bare `header.` prefix also works (same for rate-limit keys) |

## Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match | `"req.method"` equals `"POST"` |
| `not_equals` | Not equal | `"ip.country"` not equals `"US"` |
| `contains` | String contains | `"req.path"` contains `"/api/"` |
| `not_contains` | String does not contain | `"req.path"` not contains `"/health"` |
| `starts_with` | String starts with | `"req.path"` starts_with `"/admin/"` |
| `ends_with` | String ends with | `"req.path"` ends_with `".css"` |
| `exists` | Value exists (not null) | `"ip.is_vpn"` exists |
| `not_exists` | Value does not exist | `"ip.is_vpn"` not_exists |
| `in` | Value is in array | `"ip.country"` in `["US", "CA", "GB"]` |
| `not_in` | Value is not in array | `"ip.country"` not_in `["CN", "RU"]` |
| `greater_than` | Numeric greater than | `"ip.risk_score"` greater_than `30` |
| `greater_than_or_equal` | Numeric >= | `"ip.risk_score"` greater_than_or_equal `50` |
| `less_than` | Numeric less than | `"ip.risk_score"` less_than `10` |
| `less_than_or_equal` | Numeric <= | `"ip.asn"` less_than_or_equal `99999` |
| `regex` | Regular expression match | `"req.path"` regex `"^/api/v[0-9]+/"` |

## Logical Operators

Multiple conditions are combined with `and` (default) or `or`:

### AND (default)

All conditions must match:

```json
{
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/api/" },
    { "left": "ip.country", "operator": "not_equals", "value": "US" }
  ]
}
```

### OR

Any condition can match:

```json
{
  "conditions": [
    { "left": "ip.is_tor", "operator": "equals", "value": true, "next": "or" },
    { "left": "ip.is_vpn", "operator": "equals", "value": true, "next": "or" },
    { "left": "ip.risk_score", "operator": "greater_than", "value": 30 }
  ]
}
```

This matches if the IP is a Tor exit **or** a VPN **or** has risk score > 30.

### Mixed AND/OR

```json
{
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/api/", "next": "and" },
    { "left": "ip.is_tor", "operator": "equals", "value": true, "next": "or" },
    { "left": "ip.is_vpn", "operator": "equals", "value": true }
  ]
}
```

This matches if:
- (path starts with `/api/` **AND** is Tor) **OR** is VPN

## Examples

### Block Tor exits from specific paths

```json
{
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/admin/" },
    { "left": "ip.is_tor", "operator": "equals", "value": true }
  ]
}
```

### Allow only specific countries

```json
{
  "conditions": [
    { "left": "ip.country", "operator": "not_in", "value": ["US", "CA", "GB", "AU"] }
  ]
}
```

### Block high-risk IPs on API endpoints

```json
{
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/api/" },
    { "left": "ip.risk_score", "operator": "greater_than", "value": 50 }
  ]
}
```

### Rate limit by API key header

```json
{
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/api/" }
  ],
  "key": "req.header.X-API-Key"
}
```

### Cache by country

```json
{
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/content/" }
  ],
  "cache_key": {
    "mode": "custom",
    "parts": ["ip.country"]
  }
}
```

## Type Coercion

When comparing values of different types:

- String ↔ Number: The string is parsed as a float for comparison
- String ↔ Bool: Direct comparison (no coercion)
- Null ↔ Null: Equal
- Any ↔ Null: Not equal (unless using `exists`/`not_exists`)