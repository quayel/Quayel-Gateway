# Streams (TCP proxy)

`streams` forwards raw TCP connections, like nginx's `stream` module. Each
stream opens a port on the gateway and copies bytes in both directions between
the client and one of its targets. Use it for anything that isn't HTTP:
databases (PostgreSQL, MySQL, Redis, MongoDB), message brokers (MQTT, AMQP),
mail, SSH, game servers, or TLS you want to pass through untouched.

The gateway doesn't read what's inside the connection, so HTTP features (path,
headers, JWT, cache, transforms) don't apply. What does apply:

| Feature | How |
|---|---|
| Load balancing | `algorithm`: round robin, weighted, least connections, IP hash |
| Failover | If a target refuses or times out, the next healthy target is tried |
| Health checks | `accepts_connections` checks mark dead targets down |
| Access rules | `rules` on the client IP and IP intel (country, VPN, Tor, ASN…) |
| DoS protection | `server.protection` per-IP connection limits and bans, shared with HTTP |
| Client IP for the backend | `proxy_protocol`: PROXY protocol v1 or v2 |
| Idle timeout | Off by default; `idle_secs` closes silent connections |
| Logging and metrics | One access-log line per connection, same schema as HTTP |

## Example

```json
"streams": [
  {
    "id": "postgres",
    "listen": "0.0.0.0:5432",
    "targets": [
      { "id": "pg-1", "host": "10.0.0.5", "port": 5432 },
      { "id": "pg-2", "host": "10.0.0.6", "port": 5432 }
    ],
    "algorithm": "least_connections",
    "health_check": { "mode": "accepts_connections", "interval_seconds": 5 },
    "rules": [
      { "id": "office", "action": "allow",
        "conditions": [{ "left": "req.ip", "operator": "starts_with", "value": "203.0.113." }] },
      { "id": "everyone-else", "action": "block" }
    ]
  }
]
```

Clients connect with their normal tools, e.g. `psql -h gateway.example.com -p 5432`.

## Fields

| Field | Default | Description |
|---|---|---|
| `id` | required | Unique name. Appears as `path` in the access log |
| `name` | `id` | Display name |
| `enabled` | `true` | `false` skips the stream |
| `protocol` | `"tcp"` | Only `tcp` for now |
| `listen` | required | `ip:port` to listen on, e.g. `"0.0.0.0:6379"`. Must not share a port with `listen.http`, `listen.https` (when Auto-SSL is on) or another stream |
| `targets` | required | `[{ "id", "host", "port", "weight": 100, "enabled": true }]`. `host` can be an IP or a DNS name (resolved on every connect) |
| `algorithm` | `"round_robin"` | `round_robin`, `weighted_round_robin`, `least_connections` (fewest open connections), `ip_hash` (same client IP → same target) |
| `health_check` | none | Same object as for HTTP load balancers, but only `mode: "accepts_connections"` (or `"off"`) is allowed. Without it every enabled target counts as healthy |
| `rules` | `[]` | Checked in order when a connection opens; the first rule whose `conditions` all match decides. `action` is `allow` or `block`. A rule with no conditions matches everyone. No match → allowed |
| `proxy_protocol` | `"off"` | `"v1"` or `"v2"`: send a PROXY protocol header to the target first, so it sees the real client IP. Only turn on if the target expects it (nginx `proxy_protocol`, HAProxy `accept-proxy`, PgBouncer, …) |
| `connect_timeout_secs` | `5` | Per target. After a timeout or refusal the next target is tried |
| `idle_secs` | `0` (never) | Close a connection after this many seconds with no data in either direction |

### Rule conditions

Rules use the same [condition syntax](conditions.md) as the firewall. The
fields that have a value on a stream connection are `req.ip`, `ip.*` (IP
intel: `ip.country`, `ip.asn`, `ip.is_vpn`, `ip.is_tor`, `ip.risk_score`, …),
`req.method` (`"TCP"`) and `req.path` (the stream id). IP intel is looked up
automatically when a rule uses an `ip.*` field, even if the `ip_intel` plugin
is off. The client IP is always the address that opened the connection;
`client_ip` header settings don't apply.

## Behaviour

- **Listeners start with the gateway.** Changing `targets`, `rules`,
  `algorithm`, timeouts or `health_check` applies on config reload. Adding a
  stream or changing a `listen` address needs a restart (the gateway logs a
  warning when it sees one). A stream removed by a reload stops accepting
  connections immediately.
- **No idle timeout by default.** Database pools and message-broker clients
  keep connections open for hours; they stay open. TCP half-close is passed
  on, so protocols that send `EOF` and then wait for a final answer work.
- **Connection limits are shared with HTTP.** `server.protection` counts
  stream and HTTP connections from the same IP together, and a ban blocks
  both. Private and loopback addresses are exempt by default.
- **Server-first protocols work.** The gateway never waits for the client to
  send first, so SMTP, MySQL and SSH banners reach the client straight away.
- **Shutdown.** On SIGTERM open stream connections are closed and logged.

## Access log

Each connection gets one line when it ends, in the normal
[log schema](logging.md):

| Field | Value on a stream line |
|---|---|
| `method` | `"TCP"` |
| `scheme` | `"tcp"` |
| `path` | The stream `id` |
| `host` | `""` |
| `status` | `200` connected · `403` blocked by a rule · `502` no target accepted · `503` every target unhealthy · `504` connecting timed out |
| `req_bytes` / `bytes` | Bytes received from / sent to the client |
| `dur_us` | Whole connection |
| `upstream`, `upstream_addr` | The target used |
| `upstream_us` | Time to connect to the target (including failed attempts) |
| `block` | `{"type":"stream","action":"block","rule":"<rule id>",…}` for a rule block |
| `error` | Why it ended early: `connect …: Connection refused`, `idle timeout`, `client: …`, `upstream: …`, `gateway shutting down` |

Connections refused by `server.protection` aren't logged, the same as for HTTP.
In `/metrics`, stream lines are counted under `method="TCP"`.
