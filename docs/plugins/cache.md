# Cache Plugin

The cache plugin stores and serves responses at the edge, reducing upstream load and improving latency. It supports TTL-based expiration, bypass modes, custom cache keys, and **singleflight revalidation** to prevent cache stampedes.

## Configuration

```json
{
  "plugins": {
    "cache": {
      "enabled": true,
      "max_object_size_bytes": 10485760,
      "rules": [
        {
          "id": "cache-static",
          "name": "Cache Static Assets",
          "enabled": true,
          "conditions": [
            {
              "left": "req.path",
              "operator": "regex",
              "value": "\\.(css|js|png|jpg|svg|woff2?)$"
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
          "statuses": [200, 301, 404],
          "stale_while_revalidate": 30,
          "stale_if_error": 120
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
| `cache` | enum | — | `"eligible"` or `"bypass"` (default: `"eligible"`) |
| `edge_ttl` | object | ✅ | How long to cache at the edge |
| `browser_ttl` | object | — | Browser cache TTL |
| `cache_key` | object | — | Custom cache key configuration |
| `statuses` | array | — | HTTP status codes to cache (default: `[200, 301, 404]`) |
| `stale_while_revalidate` | number | — | SWR window in seconds. Overrides origin `Cache-Control` header. |
| `stale_if_error` | number | — | SIE window in seconds. Overrides origin `Cache-Control` header. |

## Cache Modes

### Eligible

The response is eligible for caching. The plugin checks:
1. Response status is in the `statuses` list
2. Response body is within `max_object_size_bytes`
3. No `Set-Cookie` header
4. No `Cache-Control: private`, `no-store`, or `no-cache`

### Bypass

Skip the cache entirely for matching requests.

```json
{
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/api/" }
  ],
  "cache": "bypass"
}
```

## Edge TTL

Controls how long the gateway caches the response.

### Origin mode

Use the upstream's `Cache-Control` or `Expires` header:

```json
{
  "edge_ttl": {
    "mode": "origin"
  }
}
```

When mode is `origin`, the gateway reads `s-maxage` first, then `max-age` from the upstream `Cache-Control` header. If neither is present, the response is not cached.

### Custom mode

Override with a fixed TTL:

```json
{
  "edge_ttl": {
    "mode": "custom",
    "seconds": 3600
  }
}
```

## Stale-While-Revalidate and Stale-If-Error

The gateway supports `stale-while-revalidate` and `stale-if-error` directives. These can be configured in two ways:

### 1. Gateway-level configuration (recommended)

Set SWR/SIE directly in the cache rule. This overrides any origin `Cache-Control` header values:

```json
{
  "id": "cache-api",
  "name": "Cache API",
  "cache": "eligible",
  "edge_ttl": { "mode": "origin" },
  "stale_while_revalidate": 30,
  "stale_if_error": 120,
  "statuses": [200]
}
```

### 2. Origin-level (automatic)

If not configured in the gateway, SWR/SIE are parsed from the upstream `Cache-Control` header:

```
Cache-Control: s-maxage=60, stale-while-revalidate=30, stale-if-error=60
```

### Priority

| Source | Priority |
|--------|----------|
| Gateway config `stale_while_revalidate` | **Highest** — overrides origin header |
| Origin `Cache-Control: stale-while-revalidate` | Used if no gateway config |
| Neither | SWR = 0 (no revalidation window) |

Same priority applies to `stale_if_error`.

### How they're parsed

When the gateway stores a cached response, it calculates TTLs:

| Directive | Source | Stored in cache entry |
|-----------|--------|----------------------|
| `s-maxage` | Origin header | `edge_ttl` (if `mode: origin`) |
| `max-age` | Origin header | `edge_ttl` fallback (if `mode: origin`) |
| `stale-while-revalidate` | Gateway config OR origin header | `stale_while_revalidate` |
| `stale-if-error` | Gateway config OR origin header | `stale_if_error` |

### Timeline

```
edge_ttl = 60s, stale_while_revalidate = 30s, stale_if_error = 60s

max_stale = max(SWR, SIE) = max(30, 60) = 60s
fully_expired = edge_ttl + max_stale = 60 + 60 = 120s

├── 0s ────── 60s ──────────────── 120s ──────────────────────┤
│                │                        │                   │
│   FRESH        │   STALE                │  CACHE MISS       │
│   (HIT)        │   (serve stale +       │  (entry treated   │
│                │    revalidate via       │   as expired)     │
│                │    singleflight)        │                   │
│                │                        │                   │
│                ▼                        ▼                   │
│           edge_ttl              edge_ttl + max(SWR, SIE)    │
│            = 60s                      = 120s                │
│                                                             │
│  Note: entry is not physically removed from store,          │
│  but lookup() returns Miss (treated as cache miss)          │
```

### Cache states

| State | Age range | Behavior | `Quayel-Cache-Status` |
|-------|-----------|----------|------|
| **Fresh** | `age < edge_ttl` | Serve immediately | `HIT` |
| **Stale (SWR window)** | `edge_ttl ≤ age < edge_ttl + SWR` | One request revalidates (lock holder); the rest are served the stored copy | `REVALIDATING` |
| **Expired, error fallback** | `edge_ttl + SWR ≤ age < edge_ttl + SIE` | Go to origin like a miss; the stored copy is kept for a `304` or an origin error | `EXPIRED` |
| **Fully expired** | `age ≥ edge_ttl + max(SWR, SIE)` | Entry removed, normal miss | `MISS` |

Stale copies are served without asking the origin only inside the SWR window. Inside the SIE window they are used only when the origin fails (see [Revalidation outcomes](#revalidation-outcomes)).

## Singleflight Revalidation

When a cache entry becomes stale, the gateway uses **per-key locking** to ensure only one request refreshes the cache. Concurrent requests serve stale data while waiting.

### How it works

```
                    ┌──────────────┐
                    │  Cache Lookup │
                    └──────┬───────┘
                           │
             ┌─────────────┼──────────────┐
             │             │              │
          Fresh       Stale+lock      Stale+no lock
             │             │              │
          [HIT]        [HIT/STALE]    try_lock_owned()
        serve cached   serve stale    ┌────┴────┐
        status=HIT     status=        │         │
                       REVALIDATING  Ok(guard)  Err
                                      │         │
                           status=    serve stale
                           REVALIDATING  status=Stale
                           cache_should_store=true
                           return Continue
                           (go to origin normally)
                                      │
                           origin responds →
                           response_body_filter stores fresh data →
                           ctx.revalidation_guard = None (lock releases) →
                           revalidating.remove(key) →
                           next request sees fresh data → cache HIT
```

### Request flow

#### Request 1 — Stale + no lock (first request)

```
t=61s: Request arrives → cache entry is stale (age > edge_ttl)
       → No lock held for this key
       → Acquire lock (try_lock_owned)
       → Set status = REVALIDATING
       → Set cache_should_store = true
       → Return Continue (go to origin like a normal cache miss)
       → Origin responds with fresh data
       → response_body_filter stores in cache
       → Lock released (RevalidationGuard drops)
```

**Response:** `Quayel-Cache-Status: REVALIDATING` — response comes from origin.

#### Request 2 — Stale + lock held (concurrent request)

```
t=62s: Request arrives → cache entry is stale
       → Lock is held (someone else is refreshing)
       → Serve stale cached data
       → Set status = REVALIDATING
```

**Response:** `Quayel-Cache-Status: REVALIDATING` — response comes from stale cache.

#### Request 3 — After revalidation completes

```
t=63s: Request arrives → cache entry is fresh (just refreshed)
       → Serve cached data
       → Set status = HIT
```

**Response:** `Quayel-Cache-Status: HIT` — response comes from fresh cache.

### Why this is correct

| Property | Description |
|----------|-------------|
| **Lock is the mechanism** | Not a time window. Even with `stale-while-revalidate=0`, concurrent requests serve stale while someone refreshes. |
| **No background tasks** | The first request IS the refresh. It goes to origin like a normal cache miss, gets fresh data, stores it. |
| **No separate HTTP client** | Uses the normal proxy flow. Headers, middleware, TLS — everything works. |
| **Lock auto-releases** | The `RevalidationGuard` is stored in `RequestContext`. When the request completes, `ctx` drops → guard drops → lock releases. |
| **No stampedes** | Only one request per key goes to origin. All others serve stale. |

### Race condition handling

There's a small window between `lookup()` returning `Stale` and `try_lock_owned()`:

```
Thread A: lookup() → Stale
Thread B: lookup() → Stale  (concurrent)
Thread A: try_lock_owned() → Ok  → go to origin
Thread B: try_lock_owned() → Err → serve stale (status=Stale)
```

This is safe — Thread B falls back to serving stale data.

## Revalidation outcomes

The request that goes to the origin while holding a stored copy (the SWR lock holder, or an `EXPIRED` request) sends a **conditional request**. Its own `If-None-Match` / `If-Modified-Since` are replaced with the stored `ETag` / `Last-Modified`. What the client gets depends on the origin's answer:

| Origin answer | Client receives | Cache | `Quayel-Cache-Status` |
|---|---|---|---|
| `304 Not Modified` | Stored copy (status, headers, body) | Headers from the 304 merged in, TTL restarted, no body transfer | `REVALIDATED` |
| `5xx` and the entry is inside its SIE window | Stored copy | Unchanged | `STALE` |
| Connect error / timeout before any response, entry inside SIE | Stored copy | Unchanged | `STALE` |
| Cacheable response | Origin response | Replaced | `REVALIDATING` / `EXPIRED` |
| Anything else | Origin response | Unchanged | `REVALIDATING` / `EXPIRED` |

In every case the revalidation lock is released when the request ends, and the response goes through [`response_transform`](transform.md).

If a `304` carries `Cache-Control: no-store` (or anything else that makes the response uncacheable), the stored copy is served this one time and then removed.

## What gets stored

A response is stored only when **all** of these hold:

- The request is `GET` without a `Range` header. `HEAD` can be served from cache but never fills it.
- The origin status is in the rule's `statuses` (default `[200, 301, 404]`). The stored status is the origin's status, not one changed by `response_transform`.
- `Vary` is absent or lists only `Accept-Encoding`. `Vary: *`, `Vary: Cookie` and so on are not stored.
- There is no `Set-Cookie`, and `Cache-Control` / `Quayel-CDN-Cache-Control` doesn't say `no-store`, `no-cache` or `private`.
- The edge TTL is above zero and the body fits in `max_object_size_bytes`.

Client validators (`If-None-Match`, `If-Modified-Since`) are removed from requests that may be stored, so the origin always returns a full body the cache can keep.

## Stale-If-Error (SIE)

The `stale-if-error` directive extends the cache lifetime for error scenarios. When the upstream returns an error (5xx, timeout, connection failure), the gateway can serve stale data instead.

### Timeline with SIE

```
edge_ttl = 60s, stale_while_revalidate = 0s, stale_if_error = 120s

├── 0s ────── 60s ────────────── 180s ──┤
│                │                      │
│   FRESH        │   STALE (SIE)       │  FULLY EXPIRED
│   (HIT)        │                      │  (MISS)
│                │                      │
│                ▼                      ▼
│            edge_ttl            edge_ttl + SIE
│             + 0s                + 120s = 180s
```

### How SIE works

1. The entry is stored with a `stale_if_error` duration (rule setting, or the origin's `Cache-Control`).
2. The entry is kept until `edge_ttl + max(SWR, SIE)`.
3. Requests that go to the origin while the entry is inside `edge_ttl + SIE` keep it as a fallback:
   - **Origin answers normally (2xx/3xx/4xx):** the client gets the origin response, and the cache is updated if it's cacheable.
   - **Origin returns 5xx, times out or refuses the connection:** the client gets the stored copy (`STALE`) instead of the error.

### Configuration example

Origin sets the directive:

```http
HTTP/1.1 200 OK
Cache-Control: s-maxage=60, stale-while-revalidate=10, stale-if-error=120
```

The gateway automatically reads and stores these values. No gateway-side configuration needed.

## Browser TTL

Controls the `Cache-Control` header sent to the client.

### Bypass mode

Don't modify browser caching:

```json
{
  "browser_ttl": {
    "mode": "bypass"
  }
}
```

### Origin mode

Use the upstream's `Cache-Control` header:

```json
{
  "browser_ttl": {
    "mode": "origin"
  }
}
```

### Custom mode

Set a specific browser TTL:

```json
{
  "browser_ttl": {
    "mode": "custom",
    "seconds": 300
  }
}
```

## Cache Keys

### Default mode

The default cache key is: `scheme|host|path|encoding`

`path` includes the query string and is the path **after** [`request_transform`](transform.md). `encoding` is the client's `Accept-Encoding` collapsed to one of three buckets: `br` (accepts Brotli), `gzip` (accepts gzip but not Brotli) or `identity` (neither). The origin is sent the matching `Accept-Encoding` (`br, gzip`, `gzip`, or none), so a URL has at most three stored copies and a client never gets an encoding it didn't ask for.

```json
{
  "cache_key": {
    "mode": "default"
  }
}
```

### Custom mode

Add additional components to the cache key:

```json
{
  "cache_key": {
    "mode": "custom",
    "parts": [
      "ip.country",
      "req.header.Accept-Language"
    ]
  }
}
```

This creates a cache key like: `https|example.com|/page|US|en-US`

### Available cache key parts

Any [condition path](../conditions.md#condition-paths) can be used as a cache key part:

| Part | Description |
|------|-------------|
| `ip.country` | Cache by country |
| `ip.asn` | Cache by ASN |
| `req.header.<name>` | Cache by header value |
| `req.query.<name>` | Cache by query parameter |
| `req.cookie.<name>` | Cache by cookie value |

## How It Works

```
Request arrives
    │
    ▼
1. Evaluate conditions → find matching rule
    │
    ├── No match → skip cache
    │
    └── Match:
        │
        ├── cache = "bypass" → skip cache
        │
        └── cache = "eligible":
            │
            ├── 2. Generate cache key (scheme|host|path + custom parts)
            ├── 3. Hash cache key (FxHash → 16-char hex)
            │
            ├── 4. Lookup in DashMap
            │   │
            │   ├── FRESH (age < edge_ttl)
            │   │   → CacheLookup::Hit → serve cached response
            │   │   → Quayel-Cache-Status: HIT
            │   │   → Pipeline short-circuits (no upstream)
            │   │
            │   ├── STALE + lock held (someone else revalidating)
            │   │   → CacheLookup::HitRevalidating → serve stale response
            │   │   → Quayel-Cache-Status: REVALIDATING
            │   │
            │   ├── STALE + no lock
            │   │   → try_lock_owned()
            │   │   ├── Ok(guard) → become the refresh request
            │   │   │   → Quayel-Cache-Status: REVALIDATING
            │   │   │   → Continue to origin (normal proxy flow)
            │   │   │   → Origin responds → store in cache → lock releases
            │   │   │
            │   │   └── Err (race condition)
            │   │       → Serve stale response
            │   │       → Quayel-Cache-Status: STALE
            │   │
            │   ├── FULLY EXPIRED (age ≥ edge_ttl + max(SWR, SIE))
            │   │   → CacheLookup::Miss → entry removed
            │   │   → Continue to origin
            │   │
            │   └── MISS (no entry)
            │       → CacheLookup::Miss → Continue to origin
            │
            └── 5. After origin responds (response_body_filter):
                │
                ├── Parse Cache-Control headers
                │   → Extract s-maxage, max-age, stale-while-revalidate, stale-if-error
                │
                ├── Check cacheability
                │   ├── Status in statuses list?
                │   ├── Body < max_object_size?
                │   ├── No Set-Cookie?
                │   └── No no-cache/no-store/private?
                │
                ├── Calculate TTLs
                │   → edge_ttl (from mode + headers)
                │   → stale_while_revalidate (from Cache-Control)
                │   → stale_if_error (from Cache-Control)
                │
                ├── Store in cache
                │   → DashMap::insert(key, CacheEntry)
                │
                └── Release revalidation lock (if held)
                    → ctx.revalidation_guard = None
                    → revalidating.remove(key)
```

## Cache Status Values

| Status | Header Value | Meaning |
|--------|-------------|---------|
| **None** | `NONE` | No cache rule matched |
| **Hit** | `HIT` | Response served from fresh cache |
| **Miss** | `MISS` | Cache miss, fetched from upstream |
| **Expired** | `EXPIRED` | (Reserved for future use) |
| **Bypass** | `BYPASS` | Cache bypassed by rule |
| **Dynamic** | `DYNAMIC` | (Reserved for future use) |
| **Stale** | `STALE` | Serving stale data (lock race condition fallback) |
| **Revalidating** | `REVALIDATING` | Serving stale data while another request refreshes cache |

### Status in responses

The `Quayel-Cache-Status` header is added to **every** response:

```
HTTP/1.1 200 OK
Quayel-Cache-Status: HIT
Content-Type: application/json
...

HTTP/1.1 200 OK
Quayel-Cache-Status: REVALIDATING
Content-Type: application/json
...

HTTP/1.1 200 OK
Quayel-Cache-Status: MISS
Content-Type: application/json
...
```

## CDN Cache-Control Parsing

The gateway parses these directives from the upstream `Cache-Control` header:

| Directive | Effect |
|-----------|--------|
| `s-maxage` | Used as edge TTL (when `mode: origin`) |
| `max-age` | Fallback edge TTL (when `mode: origin` and no `s-maxage`) |
| `stale-while-revalidate` | SWR window duration (seconds) |
| `stale-if-error` | SIE window duration (seconds) |
| `no-store` | Response is not cached |
| `no-cache` | Response is not cached |
| `private` | Response is not cached |
| `public` | Ignored (gateway caches by default) |

### Priority order for edge TTL

When `mode: origin`:
1. `s-maxage` (if present)
2. `max-age` (if present)
3. Gateway config `seconds` (fallback)
4. Not cached (if none present)

When `mode: custom`:
1. Gateway config `seconds` (if provided)
2. CDN `s-maxage` (fallback if `seconds` missing)
3. CDN `max-age` (fallback if no `s-maxage`)
4. Not cached (if none present)

## Examples

### Cache static assets

```json
{
  "id": "cache-static",
  "name": "Cache Static Assets",
  "enabled": true,
  "conditions": [
    { "left": "req.path", "operator": "regex", "value": "\\.(css|js|png|jpg|svg|woff2?)$" }
  ],
  "cache": "eligible",
  "edge_ttl": { "mode": "custom", "seconds": 86400 },
  "browser_ttl": { "mode": "custom", "seconds": 3600 },
  "cache_key": { "mode": "default" },
  "statuses": [200]
}
```

### Cache API responses by country

```json
{
  "id": "cache-api-geo",
  "name": "Cache API by Country",
  "enabled": true,
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/api/content/" },
    { "left": "req.method", "operator": "equals", "value": "GET" }
  ],
  "cache": "eligible",
  "edge_ttl": { "mode": "custom", "seconds": 300 },
  "browser_ttl": { "mode": "custom", "seconds": 60 },
  "cache_key": {
    "mode": "custom",
    "parts": ["ip.country"]
  },
  "statuses": [200]
}
```

### Bypass cache for authenticated requests

```json
{
  "id": "bypass-auth",
  "name": "Bypass Cache for Auth",
  "enabled": true,
  "conditions": [
    { "left": "req.header.Authorization", "operator": "exists" }
  ],
  "cache": "bypass"
}
```

### Cache with origin TTL (reads from Cache-Control)

```json
{
  "id": "cache-origin-ttl",
  "name": "Cache with Origin TTL",
  "enabled": true,
  "conditions": [
    { "left": "req.method", "operator": "equals", "value": "GET" }
  ],
  "cache": "eligible",
  "edge_ttl": { "mode": "origin" },
  "browser_ttl": { "mode": "origin" },
  "cache_key": { "mode": "default" },
  "stale_while_revalidate": 30,
  "stale_if_error": 120
}
```

When the origin responds with:
```http
Cache-Control: s-maxage=120
```

The gateway:
- Caches for 120 seconds (from origin `s-maxage`)
- Serves stale for up to 30s while revalidating (from gateway config)
- Serves stale for up to 120s if origin errors (from gateway config)

**Note:** Gateway-level `stale_while_revalidate` and `stale_if_error` override origin headers. If the origin also sends these directives, the gateway config takes priority.

### Multi-rule cache strategy

```json
{
  "rules": [
    {
      "id": "bypass-api",
      "name": "Bypass API Cache",
      "enabled": true,
      "conditions": [
        { "left": "req.path", "operator": "starts_with", "value": "/api/" }
      ],
      "cache": "bypass"
    },
    {
      "id": "cache-pages",
      "name": "Cache Pages",
      "enabled": true,
      "conditions": [
        { "left": "req.method", "operator": "equals", "value": "GET" }
      ],
      "cache": "eligible",
      "edge_ttl": { "mode": "custom", "seconds": 600 },
      "browser_ttl": { "mode": "custom", "seconds": 60 },
      "cache_key": {
        "mode": "custom",
        "parts": ["ip.country"]
      },
      "statuses": [200, 404]
    }
  ]
}
```

## Log Output

```json
{
  "cache": {
    "rule_id": "cache-static",
    "status": "HIT",
    "key_hash": "a1b2c3d4e5f6..."
  }
}
```

### Status values in logs

| Status | Description |
|--------|-------------|
| `NONE` | No cache rule matched |
| `HIT` | Fresh cache hit |
| `MISS` | Cache miss — went to origin |
| `EXPIRED` | (Reserved) |
| `BYPASS` | Rule set to bypass |
| `DYNAMIC` | (Reserved) |
| `STALE` | Served stale data (lock race fallback) |
| `REVALIDATING` | Served stale data while another request refreshes |

### Monitoring revalidation

```bash
# Count revalidation events (concurrent stale serving)
cat access.jsonl | jq 'select(.cache.status == "REVALIDATING")' | wc -l

# Count stale fallbacks (lock race condition)
cat access.jsonl | jq 'select(.cache.status == "STALE")' | wc -l

# Cache hit rate (excluding NONE)
total=$(cat access.jsonl | jq 'select(.cache.status != "NONE")' | wc -l)
hits=$(cat access.jsonl | jq 'select(.cache.status == "HIT")' | wc -l)
echo "Cache hit rate: $(echo "scale=2; $hits * 100 / $total" | bc)%"
```

## Cacheability Rules

A response is cached only if ALL of these are true:

1. Response status code is in the `statuses` list
2. Response body size ≤ `max_object_size_bytes`
3. No `Set-Cookie` header present
4. No `Cache-Control: private`, `no-store`, or `no-cache`
5. Edge TTL is not zero

## Performance

| Metric | Value |
|--------|-------|
| Cache lookup | O(1) — DashMap |
| Cache store | O(1) — DashMap |
| Key hash | FxHash (fast, non-cryptographic) |
| Memory per entry | body_size + ~200 bytes overhead |
| Max entries | Unlimited (bounded by `max_object_size_bytes`) |
| Lock overhead | One `Arc<Mutex<()>>` per active revalidation |

## Notes

- Cache is **in-memory only** — entries are lost on restart
- Each gateway instance has its own cache (no shared cache)
- Rules are evaluated in order — first match wins
- The `bypass` rule should come before `eligible` rules for the same paths
- Only GET and HEAD requests are cached
- The revalidation lock is per-key — different cache keys can revalidate concurrently