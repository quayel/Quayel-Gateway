# Rate Limiting Plugin

The rate limiting plugin enforces request quotas using a sliding-window counter. Limits are per-key (IP, header, or custom value) and reset automatically when the window expires.

## Configuration

```json
{
  "plugins": {
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
}
```

## Rule Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique rule identifier |
| `name` | string | ✅ | Human-readable name |
| `enabled` | bool | — | Enable/disable rule (default: `true`) |
| `conditions` | array | — | When to apply this rule (empty = always) |
| `key` | string | ✅ | What to rate limit by |
| `limit` | number | ✅ | Maximum requests per window |
| `window_seconds` | number | ✅ | Window duration in seconds |
| `action` | object | — | Action when limit exceeded |

## Rate Limit Keys

The `key` field determines what identifier is used to track requests:

| Key | Description |
|-----|-------------|
| `req.client_ip` | Resolved client IP |
| `req.peer_ip` | Direct connection IP |
| `req.header.<name>` | Value of a specific header |
| `http.header.<name>` | Value of a specific header |

### Common key patterns

**By client IP:**
```json
{ "key": "req.client_ip" }
```

**By API key header:**
```json
{ "key": "req.header.X-API-Key" }
```

**By authorization header:**
```json
{ "key": "req.header.Authorization" }
```

**By custom header:**
```json
{ "key": "req.header.X-Tenant-ID" }
```

## How It Works

```
Request arrives
    │
    ▼
1. Evaluate conditions
    │
    ├── Conditions don't match → skip this rule
    │
    └── Conditions match:
        │
        ├── 2. Resolve rate limit key
        ├── 3. Get or create counter for (rule_id, key)
        ├── 4. Increment counter
        │
        ├── count <= limit → Continue
        │
        └── count > limit → Block (429)
```

### Window behavior

- Counter starts at 0
- Each request increments the counter
- When the window expires (elapsed >= `window_seconds`), counter resets to 1
- The window starts from the first request, not from a fixed time

### Example timeline

```
Window: 60 seconds, Limit: 5 requests

Time 0s:  Request 1 → count=1, remaining=4 → PASS
Time 1s:  Request 2 → count=2, remaining=3 → PASS
Time 2s:  Request 3 → count=3, remaining=2 → PASS
Time 3s:  Request 4 → count=4, remaining=1 → PASS
Time 4s:  Request 5 → count=5, remaining=0 → PASS
Time 5s:  Request 6 → count=6, remaining=0 → BLOCK (429)
Time 61s: Window expires, counter resets
Time 61s: Request 7 → count=1, remaining=4 → PASS
```

## Blocked Response

When rate limited, the gateway returns:

```json
{
  "error": "rate_limited",
  "status": 429,
  "rule_id": "api-limit",
  "limit": 100,
  "window_seconds": 60
}
```

Headers:
```
Content-Type: application/json
Retry-After: 60
```

## Examples

### Basic IP rate limit

```json
{
  "id": "global-ip-limit",
  "name": "Global IP Rate Limit",
  "enabled": true,
  "conditions": [],
  "key": "req.client_ip",
  "limit": 1000,
  "window_seconds": 60
}
```

### API endpoint rate limit

```json
{
  "id": "api-limit",
  "name": "API Rate Limit",
  "enabled": true,
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/api/" }
  ],
  "key": "req.client_ip",
  "limit": 100,
  "window_seconds": 60
}
```

### Per-API-key rate limit

```json
{
  "id": "per-key-limit",
  "name": "Per API Key Limit",
  "enabled": true,
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/api/" }
  ],
  "key": "req.header.X-API-Key",
  "limit": 1000,
  "window_seconds": 3600
}
```

### Strict login rate limit

```json
{
  "id": "login-limit",
  "name": "Login Rate Limit",
  "enabled": true,
  "conditions": [
    { "left": "req.path", "operator": "equals", "value": "/auth/login" },
    { "left": "req.method", "operator": "equals", "value": "POST" }
  ],
  "key": "req.client_ip",
  "limit": 5,
  "window_seconds": 300
}
```

### Multi-tier rate limiting

```json
{
  "rules": [
    {
      "id": "burst-limit",
      "name": "Burst Protection",
      "enabled": true,
      "conditions": [],
      "key": "req.client_ip",
      "limit": 50,
      "window_seconds": 10
    },
    {
      "id": "minute-limit",
      "name": "Per-Minute Limit",
      "enabled": true,
      "conditions": [],
      "key": "req.client_ip",
      "limit": 200,
      "window_seconds": 60
    },
    {
      "id": "hourly-limit",
      "name": "Hourly Limit",
      "enabled": true,
      "conditions": [],
      "key": "req.client_ip",
      "limit": 5000,
      "window_seconds": 3600
    }
  ]
}
```

### Rate limit by tenant

```json
{
  "id": "tenant-limit",
  "name": "Per-Tenant Rate Limit",
  "enabled": true,
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/api/" }
  ],
  "key": "req.header.X-Tenant-ID",
  "limit": 5000,
  "window_seconds": 60
}
```

## Log Output

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

When blocked:
```json
{
  "rate_limit": {
    "matched": true,
    "rule_id": "api-limit",
    "blocked": true,
    "remaining": 0
  }
}
```

## Performance

| Metric | Value |
|--------|-------|
| Counter lookup | O(1) — DashMap |
| Memory per counter | ~64 bytes |
| Concurrent counters | Unlimited (grows with unique keys) |

## Notes

- Counters are **in-memory only** — they reset on gateway restart
- Each gateway instance has its own counters (no distributed counting)
- For distributed rate limiting, use an external store (Redis) or a shared header
- The `action` field is optional — defaults to `block` with status `429`