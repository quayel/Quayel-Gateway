# Request & Response Transform

Two plugins rewrite traffic as it passes through the gateway:

- **`request_transform`** changes the request before the cache lookup and before it is sent to the origin: path, query parameters and headers.
- **`response_transform`** changes the response on its way to the client: headers and status code.

## Where they run

```
ip_intel → firewall → rate_limiting → request_transform → cache → load_balancer → origin
                                                            │
                                   HIT / STALE / REVALIDATED ┤
                                                            ▼
                                              response_transform → client
```

| Question | Answer |
|---|---|
| Do firewall and rate-limit rules see the rewritten request? | **No.** They run first and see what the client sent, so a rewrite can't be used to get around a firewall rule. |
| Is the cache key built from the rewritten request? | **Yes.** `/api/x` rewritten to `/v1/x` is cached as `/v1/x`. |
| Is anything transformed ever stored in the cache? | **No.** The cache stores the raw origin response. `response_transform` runs on every response sent, including cache HITs, so one client's transformed response is never served to another. |
| Do gateway blocks (firewall 403, rate-limit 429, protection 413/429) get response transforms? | **No.** Only origin responses and responses served from cache. |
| Which headers can't be changed? | `content-length`, `transfer-encoding`, `connection`, `upgrade` in both plugins, and `x-forwarded-for`, `x-forwarded-proto`, `x-forwarded-host` in `request_transform`. The config is rejected if a rule sets, adds, removes or renames one of them (including renaming another header *to* one). |

Forwarding headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-QG-*`) are built from the client's original request and set **after** request transforms, so a rule can't override them. `X-Forwarded-For` is whatever the client sent plus the client IP, and `X-Forwarded-Host` is always the host the client asked for.

## Configuration

```json
{
  "plugins": {
    "request_transform": {
      "enabled": true,
      "rules": [
        {
          "id": "api-v1",
          "conditions": [
            { "left": "req.path", "operator": "starts_with", "value": "/api/" }
          ],
          "actions": [
            { "type": "path",   "operation": "replace_prefix", "from": "/api", "to": "/v1" },
            { "type": "query",  "operation": "remove", "name": "debug" },
            { "type": "header", "operation": "set", "name": "X-Service", "value": "quayel" }
          ]
        }
      ]
    },
    "response_transform": {
      "enabled": true,
      "rules": [
        {
          "id": "powered-by",
          "actions": [
            { "type": "header", "operation": "set", "name": "X-Powered-By", "value": "Quayel" },
            { "type": "header", "operation": "remove", "name": "Server" }
          ]
        },
        {
          "id": "not-found-marker",
          "conditions": [
            { "left": "resp.status", "operator": "equals", "value": 404 }
          ],
          "actions": [
            { "type": "header", "operation": "set", "name": "X-Not-Found", "value": "1" }
          ]
        }
      ]
    }
  }
}
```

Rules run in array order, and **every** matching rule applies, unlike firewall and cache, where the first match wins. A rule with no `conditions` matches every request. Conditions use the [shared condition format](../conditions.md).

### Rule fields

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | string | required | Rule identifier, used in config errors |
| `name` | string | — | Optional label |
| `enabled` | bool | `true` | Disabled rules are skipped |
| `conditions` | array | `[]` | When the rule applies |
| `actions` | array | `[]` | What it changes, in order |

## Actions

### `header`: request and response

| `operation` | Fields | Effect |
|---|---|---|
| `set` | `name`, `value` | Replace all values of the header |
| `add` | `name`, `value` | Append another value |
| `remove` | `name` | Remove every value |
| `rename` | `name`, `to` | Move all values to a new name (replaces `to` if present) |

Changing `Host` in a request transform also changes `req.host` for the cache key and the later plugins.

### `path`: request only

| `operation` | Fields | Effect |
|---|---|---|
| `set` | `value` (must start with `/`) | Replace the path |
| `replace_prefix` | `from`, `to` | Replace a leading prefix; no change if the path doesn't start with `from` |
| `regex_replace` | `pattern`, `replacement` | Replace the first match; `$1`, `$2` refer to capture groups |

Path actions change only the path. The query string is kept.

### `query`: request only

| `operation` | Fields | Effect |
|---|---|---|
| `set` | `name`, `value` | Replace the parameter (all occurrences) or add it |
| `add` | `name`, `value` | Append another occurrence |
| `remove` | `name` | Remove every occurrence |
| `rename` | `name`, `to` | Rename, keeping the value |

Names and values you configure are percent-encoded. Parameters a rule doesn't touch are passed through byte-for-byte.

### `status`: response only

| `operation` | Fields | Effect |
|---|---|---|
| `set` | `value` (200–599) | Change the status code sent to the client |

The cache still stores the origin's status, so a `status` rule can be changed or removed without purging anything. Overriding to `204` or `304` sends no body for responses served from cache.

## Response conditions

`response_transform` conditions can use every request field, plus:

| Path | Value |
|---|---|
| `resp.status` | Status code (number) |
| `resp.header.<name>` | Response header value |

For responses served from cache, these fields come from the stored origin response.

## Access log

Each log event records which rules ran:

```json
{
  "host": "api.example.com",
  "path": "/api/users?page=2",
  "request_transform": { "rules": ["rt-api-v1"], "path": "/v1/users?page=2", "host": null },
  "response_transform": { "rules": ["rs-powered-by"] }
}
```

The top-level `host` and `path` are what the client sent. `request_transform.path` and `request_transform.host` are what went to the origin, and are `null` when no rule changed them. `response_transform.rules` is empty for gateway blocks. See [Logging](../logging.md).

## Not in this version

- JSON body field add / remove / rename and regex body replacement
- HTTP method rewrite
- Template values (`${req.ip}` and similar)
