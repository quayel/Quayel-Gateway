# Streams (TCP / UDP proxy)

`streams` forwards raw TCP connections and UDP datagrams, like nginx's
`stream` module. Each
stream opens a port on the gateway and copies bytes in both directions between
the client and one of its targets. Use it for anything that isn't HTTP:
databases (PostgreSQL, MySQL, Redis, MongoDB), message brokers (MQTT, AMQP),
mail, SSH, game servers, or TLS you want to pass through untouched; over
UDP, DNS, game traffic, VoIP, WireGuard or syslog.

The gateway doesn't read what's inside the connection, so HTTP features (path,
headers, JWT, cache, transforms) don't apply. What does apply:

| Feature | How |
|---|---|
| Routing by name | TLS connections can be routed by server name (SNI), also on the shared HTTPS port 443 |
| TLS | Pass through to the target, or terminate at the gateway with Auto-SSL certificates |
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

## Routing by server name (SNI)

A TLS client sends the host name it wants in its first message (the
ClientHello), before anything is encrypted. The gateway reads it without
consuming it, so one port can serve many backends:

```json
"streams": [
  { "id": "redis-a", "sni": ["a.redis.example.com"], "tls": "terminate",
    "targets": [{ "id": "r", "host": "10.0.0.5", "port": 6379 }] },
  { "id": "mqtt",    "sni": ["*.mqtt.example.com"],
    "targets": [{ "id": "m", "host": "10.0.0.9", "port": 8883 }] }
]
```

**Without `listen`, a stream shares the HTTPS port** (`listen.https`, 443 by
default). On that port the gateway peeks at every TLS connection: a server
name that matches a stream goes to that stream; every other name, and
clients that send no name, are handled by HTTPS exactly as before. Your websites don't
change. `redis-cli --tls -h a.redis.example.com -p 443` reaches the Redis
above.

**With `listen`, several streams can share a port** as long as they use
different names. One stream on the port may have no `sni`: it gets every
connection that matches no name, including clients that don't speak TLS.
Without such a default, an unknown name is refused (logged as `421`).

| `tls` | What happens | Certificate the client sees |
|---|---|---|
| `"passthrough"` (default with `sni`) | Encrypted bytes go to the target untouched | The target's own |
| `"terminate"` | The gateway does TLS and sends plain bytes to the target | Auto-SSL's for that name |
| omitted, no `sni` | Raw TCP, nothing is read | — |

Things to know:

- **Only TLS carries a name.** Plain Redis, MySQL, PostgreSQL (before
  `sslnegotiation=direct` in PostgreSQL 17), MQTT on 1883 or SSH send no host
  name, so they need their own port. Clients must connect with TLS
  (`redis-cli --tls`, `rediss://`, `mqtts://`, …).
- **`terminate` needs Auto-SSL.** The name must be in
  `plugins.auto_ssl.domains` to get a real certificate; until then clients
  get the self-signed fallback. Auto-SSL can't issue wildcard certificates,
  so `*.` names work with `passthrough` or with each name listed in
  `domains`.
- **Names:** exact names (case-insensitive) win over wildcards; `*.example.com`
  matches `a.example.com` but not `a.b.example.com` or `example.com`. A name
  can belong to only one stream per port.
- **A stream name wins over an HTTP site with the same name** on the HTTPS
  port, so don't give a stream the name of one of your websites.
- **Ports that route by name wait for the client to speak first** (with a
  deadline of `server.timeouts.header_secs`). Server-first protocols (SMTP,
  MySQL, SSH) belong on a port without `sni`.
- **Without Auto-SSL**, the HTTPS port opens only when a stream uses it, and
  then serves only those streams; that's read at startup.
- The ClientHello peek and the HTTPS handshake together must finish within
  `server.timeouts.header_secs` (10 s by default), so a client can't hold a
  connection open by never finishing the handshake.

## UDP

```json
"streams": [
  { "id": "dns", "protocol": "udp", "listen": "0.0.0.0:53", "responses": 1,
    "targets": [{ "id": "dns-1", "host": "10.0.0.53", "port": 53 },
                { "id": "dns-2", "host": "10.0.0.54", "port": 53 }] }
]
```

UDP has no connections, so the gateway keeps a **session per client address
and port**. The first datagram picks a target (with the stream's
`algorithm`) and opens a socket to it; the client's later datagrams go to the
same target and the target's replies go back to the client. A session ends:

- after `idle_secs` without traffic in either direction (**30 s** by default
  for UDP; `0` keeps it until shutdown),
- after `responses` replies from the target, if set (`1` suits DNS: each
  query is its own session and is logged right away),
- at shutdown.

| UDP field | Default | Description |
|---|---|---|
| `protocol` | `"tcp"` | `"udp"` |
| `listen` | required | UDP port. A TCP and a UDP stream may use the same port number (e.g. DNS on 53) |
| `idle_secs` | `30` | Seconds without traffic before the session ends |
| `responses` | none | End the session after this many replies |
| `max_sessions` | `100000` | Sessions at once on this stream; datagrams from new clients beyond it are dropped. `0` → no limit. Each session holds a socket, and UDP source addresses are easy to forge, so keep a cap |

`targets`, `algorithm`, `rules` and `server.protection` work as for TCP
(each session counts as one connection). Not available for UDP: `sni`, `tls`,
`proxy_protocol` and `health_check` (a UDP target can't be checked by
connecting). There's no failover between targets, because UDP can't tell
whether a datagram arrived; use `ip_hash` or more targets instead. A target
`host` can be a DNS name, but an IP avoids a lookup when a session starts.

A blocked client (rule or no healthy target) gets a session too, in which its
datagrams are dropped until it goes quiet; a flood from one address is
logged as one line.

## Fields

| Field | Default | Description |
|---|---|---|
| `id` | required | Unique name. Appears as `path` in the access log |
| `name` | `id` | Display name |
| `enabled` | `true` | `false` skips the stream |
| `protocol` | `"tcp"` | `"tcp"` or `"udp"` (see [UDP](#udp)) |
| `listen` | HTTPS port | `ip:port` to listen on, e.g. `"0.0.0.0:6379"`. Must not clash with `listen.http`, `listen.https` (when it's open) or another stream's port; streams with different `sni` names may share one. Omitted → shares the HTTPS port (needs `sni`) |
| `sni` | `[]` | TLS server names that pick this stream: `"db.example.com"` or `"*.example.com"` |
| `tls` | see above | `"passthrough"` or `"terminate"` |
| `targets` | required | `[{ "id", "host", "port", "weight": 100, "enabled": true }]`. `host` can be an IP or a DNS name (resolved on every connect) |
| `algorithm` | `"round_robin"` | `round_robin`, `weighted_round_robin`, `least_connections` (fewest open connections), `ip_hash` (same client IP → same target) |
| `health_check` | none | Same object as for HTTP load balancers, but only `mode: "accepts_connections"` (or `"off"`) is allowed. Without it every enabled target counts as healthy |
| `rules` | `[]` | Checked in order when a connection opens; the first rule whose `conditions` all match decides. `action` is `allow` or `block`. A rule with no conditions matches everyone. No match → allowed |
| `proxy_protocol` | `"off"` | `"v1"` or `"v2"`: send a PROXY protocol header to the target first, so it sees the real client IP. Only turn on if the target expects it (nginx `proxy_protocol`, HAProxy `accept-proxy`, PgBouncer, …) |
| `connect_timeout_secs` | `5` | Per target. After a timeout or refusal the next target is tried |
| `idle_secs` | TCP: never · UDP: `30` | Close a connection after this many seconds with no data in either direction. `0` → never |
| `max_sessions`, `responses` | | UDP only, see [UDP](#udp) |

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
  `algorithm`, `sni` names, `tls`, timeouts or `health_check` applies on
  config reload, and so does adding a stream on the HTTPS port or on a port
  that's already open. A new `listen` address needs a restart (the gateway
  logs a warning when it sees one). A stream removed by a reload stops
  accepting connections immediately.
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
| `method` | `"TCP"` or `"UDP"` (one line per UDP session) |
| `scheme` | `"tcp"`, `"udp"`, or `"tls"` for streams with `sni` or `tls` |
| `path` | The stream `id` (`""` for a refused unknown name) |
| `host` | The TLS server name, when the stream was picked by it |
| `status` | `200` connected · `400` TLS handshake failed (`terminate`) · `403` blocked by a rule · `421` no stream for the server name · `502` no target accepted · `503` every target unhealthy · `504` connecting timed out |
| `req_bytes` / `bytes` | Bytes received from / sent to the client (decrypted bytes for `terminate`) |
| `dur_us` | Whole connection |
| `upstream`, `upstream_addr` | The target used |
| `upstream_us` | Time to connect to the target (including failed attempts) |
| `block` | `{"type":"stream","action":"block","rule":"<rule id>",…}` for a rule block |
| `error` | Why it ended early: `connect …: Connection refused`, `idle timeout`, `client: …`, `upstream: …`, `gateway shutting down` |

Connections refused by `server.protection` aren't logged, the same as for HTTP.
In `/metrics`, stream lines are counted under `method="TCP"` and `method="UDP"`.
