# Firewall Plugin

The firewall plugin evaluates conditions against every request and can allow, block, redirect, or modify headers. Rules are evaluated in order — first match wins.

## Configuration

```json
{
  "plugins": {
    "firewall": {
      "enabled": true,
      "rules": [
        {
          "id": "rule-id",
          "name": "Human readable name",
          "enabled": true,
          "conditions": [
            {
              "left": "req.path",
              "operator": "starts_with",
              "value": "/admin/"
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
}
```

## Rule Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique rule identifier |
| `name` | string | ✅ | Human-readable name |
| `enabled` | bool | — | Enable/disable rule (default: `true`) |
| `conditions` | array | ✅ | Matching conditions (see [Conditions](../conditions.md)) |
| `action` | object | ✅ | Action to take when conditions match |

## Actions

### Block

Returns an error response and stops the pipeline.

```json
{
  "action": {
    "type": "block",
    "status": 403
  }
}
```

Response body:
```json
{"error": "blocked", "status": 403, "rule_id": "rule-id"}
```

### Allow

Continues the pipeline (skips remaining firewall rules). Useful for whitelisting.

```json
{
  "action": {
    "type": "allow"
  }
}
```

### Redirect

Returns a redirect response.

```json
{
  "action": {
    "type": "redirect",
    "status": 302,
    "location": "https://example.com/blocked"
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `status` | int | `302` | HTTP redirect status code |
| `location` | string | `"/"` | Redirect destination URL |

### Set Request Header

Modifies request headers before forwarding to upstream.

```json
{
  "action": {
    "type": "set_request_header",
    "headers": {
      "X-Custom-Header": "value",
      "X-Client-Country": "${ip.country}"
    }
  }
}
```

### Set Response Header

Reserved for future use.

## Rule Evaluation

Rules are evaluated **in order**. The first matching rule wins:

```
Request
  │
  ├── Rule 1: conditions match?
  │   ├── YES → execute action → DONE
  │   └── NO → continue
  │
  ├── Rule 2: conditions match?
  │   ├── YES → execute action → DONE
  │   └── NO → continue
  │
  └── No rules matched → Continue to next plugin
```

## Examples

### Block Tor exit nodes

```json
{
  "id": "block-tor",
  "name": "Block Tor Exit Nodes",
  "enabled": true,
  "conditions": [
    { "left": "ip.is_tor", "operator": "equals", "value": true }
  ],
  "action": { "type": "block", "status": 403 }
}
```

### Block VPN on login endpoints

```json
{
  "id": "block-vpn-login",
  "name": "Block VPN on Login",
  "enabled": true,
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/auth/" },
    { "left": "ip.is_vpn", "operator": "equals", "value": true }
  ],
  "action": { "type": "block", "status": 403 }
}
```

### Block high-risk IPs

```json
{
  "id": "block-high-risk",
  "name": "Block High Risk IPs",
  "enabled": true,
  "conditions": [
    { "left": "ip.risk_score", "operator": "greater_than", "value": 40 }
  ],
  "action": { "type": "block", "status": 403 }
}
```

### Geo-block countries

```json
{
  "id": "geo-block",
  "name": "Block specific countries",
  "enabled": true,
  "conditions": [
    { "left": "ip.country", "operator": "in", "value": ["CN", "RU", "KP"] }
  ],
  "action": { "type": "block", "status": 403 }
}
```

### Allow admin access from specific IPs

```json
{
  "id": "allow-admin-whitelist",
  "name": "Allow Admin Whitelist",
  "enabled": true,
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/admin/" },
    { "left": "req.ip", "operator": "not_in", "value": ["10.0.0.1", "10.0.0.2"] }
  ],
  "action": { "type": "block", "status": 403 }
}
```

### Block by User-Agent

```json
{
  "id": "block-bots",
  "name": "Block known bots",
  "enabled": true,
  "conditions": [
    { "left": "req.user_agent", "operator": "regex", "value": "(?i)(bot|crawler|spider|scraper)" }
  ],
  "action": { "type": "block", "status": 403 }
}
```

### Redirect old URLs

```json
{
  "id": "redirect-old-api",
  "name": "Redirect old API",
  "enabled": true,
  "conditions": [
    { "left": "req.path", "operator": "starts_with", "value": "/v1/" }
  ],
  "action": {
    "type": "redirect",
    "status": 301,
    "location": "https://api.example.com/v2/"
  }
}
```

### Set custom headers for upstream

```json
{
  "id": "inject-geo-headers",
  "name": "Inject Geo Headers",
  "enabled": true,
  "conditions": [],
  "action": {
    "type": "set_request_header",
    "headers": {
      "X-Client-Country": "${ip.country}",
      "X-Client-ASN": "${ip.asn}",
      "X-Client-Risk": "${ip.risk_score}"
    }
  }
}
```

### Allow specific ASN (whitelist)

```json
{
  "id": "allow-whitelist-asn",
  "name": "Allow Whitelist ASN",
  "enabled": true,
  "conditions": [
    { "left": "ip.asn", "operator": "in", "value": [13335, 16509, 15169] }
  ],
  "action": { "type": "allow" }
},
{
  "id": "block-everyone-else",
  "name": "Block Non-Whitelisted",
  "enabled": true,
  "conditions": [],
  "action": { "type": "block", "status": 403 }
}
```

## Log Output

```json
{
  "firewall": {
    "matched": true,
    "rule_id": "block-tor",
    "action": "Block"
  }
}
```

When no rule matches:
```json
{
  "firewall": {
    "matched": false,
    "rule_id": null,
    "action": null
  }
}
```