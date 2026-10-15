# Changelog

All notable changes to Quayel Gateway are listed here, newest first.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/). Until 1.0,
a minor version bump (0.2 → 0.3) may include breaking changes; they are
always listed under **⚠️ Breaking changes**.

The text under each version becomes the GitHub release notes for that tag, so
write entries for people running the gateway, not for people reading the diff.

## [Unreleased]

### Fixed

- **Load-balancer health checks now take unhealthy targets out.** The
  checks ran and logged `Target … is now unhealthy`, but requests kept going
  to that target until it recovered. Unhealthy targets now get no traffic,
  and when every target in a pool is down the gateway answers
  `503 {"error":"no_healthy_upstream"}` as documented. Pools with
  `health_check.mode: "off"` (the default) are unchanged. Health is tracked
  per pool, so a backend used in two pools with different checks gets its
  own result in each, and the log line names the pool:
  `Target 10.0.0.21:8000 is now unhealthy (pool api)`.
- **Health checks honour `expected_statuses`.** Any 2xx or 3xx used to count
  as healthy whatever the list said. When the list is set, only those codes
  count now; when it's unset or empty, any 2xx or 3xx still does. Health
  checks no longer follow redirects, so a `301`/`302` is matched as itself.
- **`req.scheme` is `https` for HTTPS requests.** It was `http` unless the
  client sent `X-Forwarded-Proto`, so `req.scheme` conditions (such as an
  HTTP → HTTPS redirect rule) didn't work on the gateway's own HTTPS port,
  and backends received `X-Forwarded-Proto: http` for HTTPS traffic.
- **`X-Forwarded-Proto` is only believed from `client_ip.trusted_proxies`.**
  Any client could set it to change `req.scheme`, the cache key and the
  `X-Forwarded-Proto` sent upstream. From other clients the header is now
  ignored and the scheme comes from the connection.

## [0.6.0] - 2026-10-15

### Added

- **TCP proxy (`streams`).** Forward raw TCP connections from a port on the
  gateway to backends, like nginx's `stream` module: databases, MQTT, SSH,
  game servers, TLS passthrough. Each stream has load balancing
  (`round_robin`, `weighted_round_robin`, `least_connections`, `ip_hash`),
  fallback to the next target when connecting fails, `accepts_connections`
  health checks, allow/block `rules` on the client IP and IP intel, an
  optional PROXY protocol v1/v2 header, and an optional `idle_secs` (off by
  default, so pooled database connections stay open). `server.protection`
  connection limits and bans apply, shared with HTTP. Every connection
  gets one access-log line (`method: "TCP"`, `path`: the stream id,
  bytes each way, connect time). Targets, rules and timeouts follow config
  reloads; new listen addresses need a restart. See `docs/streams.md`.
- **SNI routing for streams.** TLS connections can be routed by server name:
  `sni: ["db.example.com", "*.mqtt.example.com"]`. A stream without `listen`
  shares the HTTPS port: names that match a stream go to it, everything else
  (other names, no SNI) is HTTPS as before. Several streams can also share
  their own port by name, with an optional default stream for the rest.
  `tls: "passthrough"` (default with `sni`) forwards the encrypted bytes so
  the backend keeps its own certificate; `tls: "terminate"` does TLS at the
  gateway with Auto-SSL certificates. Names can be added or changed by
  config reload.
- **UDP proxy.** `protocol: "udp"` streams forward datagrams (DNS, games,
  VoIP, WireGuard, syslog) with a session per client address: same target
  for all of a client's datagrams, replies sent back to it. Sessions end
  after `idle_secs` (30 s by default), after `responses` replies (`1` for
  DNS) or at shutdown, with one access-log line each (`method: "UDP"`).
  `max_sessions` (default 100,000) caps sessions per stream. Rules,
  balancing and `server.protection` work as for TCP. A TCP and a UDP stream
  can share a port number.
- **`grpc_status` in the access log.** The gRPC status code of each gRPC
  call: the origin's `grpc-status` (headers or trailers), or the code the
  gateway answered with (`7` for a firewall block, `14` when the origin is
  down). `-1` for requests that aren't gRPC. Existing ClickHouse tables keep
  working without the column; to store it, run
  `ALTER TABLE qg.access_log ADD COLUMN IF NOT EXISTS grpc_status Int16 DEFAULT -1 AFTER upstream_us`.

### Changed

- **HTTPS handshakes now have a deadline.** The HTTPS port is now a plain TCP
  listener and the gateway runs the TLS handshake itself (needed to read the
  server name first). Reading the ClientHello and finishing the handshake
  must take less than `server.timeouts.header_secs` (10 s by default);
  before, a client could hold a connection open indefinitely by never
  finishing the handshake. HTTPS behaviour is otherwise unchanged (same
  certificates, ALPN h2 / http/1.1, keep-alive).

## [0.5.0] - 2026-10-14

### Added

- **HTTP/2 and gRPC.** Clients can now use HTTP/2 on both ports: h2c (prior
  knowledge) on the HTTP port and ALPN `h2` on the HTTPS port. HTTP/1.1
  clients are unaffected. On by default; `server.http2: false` turns it off.
- **`h2c` and `h2` target protocols** for HTTP/2 upstreams such as gRPC
  servers, with up to 100 requests multiplexed per upstream connection.
  Health checks in `https` mode use HTTP/2 for these targets.
- **gRPC-aware handling.** Requests with `content-type: application/grpc*`
  are long-lived like WebSockets (`websocket_idle_secs` instead of the read
  timeouts), and responses the gateway makes itself (firewall block, rate
  limit, DoS refusal, unreachable origin) are sent as gRPC statuses, e.g.
  `403` → `PERMISSION_DENIED`, `429` → `RESOURCE_EXHAUSTED`, `502` →
  `UNAVAILABLE`. The access log keeps the HTTP status.
- New `grpc` test suite (needs Docker).

### Changed

- Cleartext h2c detection is done in the connection guard, with the
  `header_secs` deadline, instead of Pingora's untimed peek, so silent
  connections and short HTTP/1.0 requests are not held.

## [0.4.1] - 2026-10-14

### Security

- **Client IP headers are only believed from trusted proxies.** Before, when
  `client_ip` read the IP from a header such as `X-Forwarded-For`, anyone
  could put any IP in it and get past per-IP rate limits, DoS limits and
  bans. The new `client_ip.trusted_proxies` lists the peers whose header is
  read; from any other peer the TCP peer IP is used. The default (loopback,
  private ranges, Cloudflare) covers a load balancer or ingress in your own
  network and Cloudflare with no config. **If your proxy has another public
  IP, add it to `trusted_proxies`**, or every request will appear to come
  from the proxy. `["0.0.0.0/0", "::/0"]` restores the old behaviour.

### Added

- **`concurrency` on network sinks** (default 4, up to 64): several batches in
  flight at once, so a destination with a long round trip isn't limited to
  one batch per round trip.
- **ClickHouse table check at startup.** A ClickHouse sink sends an empty
  `INSERT` when it starts and logs an error straight away if the table or
  database is missing or the credentials are wrong.

### Changed

- **No request body limit by default.** `server.limits.max_body_bytes` now
  defaults to `0` (no limit) instead of 100 MB, so large uploads work without
  config. Set it if you want a cap; anything over it still gets `413`.
- **Looser DoS defaults, so normal traffic never hits them.** Many users
  can share one IP (office NAT, mobile carrier NAT, a load balancer), so the
  per-IP defaults are raised; a single-IP flood is still stopped:
  - `max_connections_per_ip` 256 → 4096
  - `max_new_connections_per_ip_per_sec` 100 → 1000
  - `max_requests_per_ip_per_sec` 500 → 2000
  - `ban.strikes` 50 → 1000, `ban.duration_secs` 600 → 300
  - `exempt_ips` now also covers private ranges (`10.0.0.0/8`,
    `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), so a load balancer or
    proxy in your own network isn't limited as if it were one user.
- **Longer timeouts for slow backends and uploads.** `upstream_read_secs`
  60 → 300 (slow APIs, streamed LLM output), `body_read_secs` 30 → 60.

### Fixed

- **WebSockets are no longer cut off.** Before, an idle socket was closed
  after 30 s (`body_read_secs`) or 60 s (`upstream_read_secs`), and a socket
  was killed with `413` once the client had sent `max_body_bytes` in total,
  which also counted as a DoS strike and could get the client's IP banned.
  Now traffic after the upgrade never counts against `max_body_bytes` or
  adds strikes, and an idle socket stays open. The new
  `server.timeouts.websocket_idle_secs` closes silent sockets if you want
  that (default `0`, no limit). The upgrade request itself still goes through
  the firewall, rate limits and DoS checks.
- **Network sinks no longer drop lines when they fall behind** (known issue
  in 0.4.0). With `spool_dir` set, the oldest batches now move to disk once
  memory passes 3/4 of `max_buffer_bytes` (earlier with a small buffer), so
  new lines always have room.
  Lines dropped because memory is full (no spool, or a full spool) are now
  logged as well as counted.
- **Firewall `set_request_header` and `set_response_header` work** (known
  issue in 0.4.0 and 0.3.x). Request headers reach the upstream and are
  visible to later rules; response headers are set on upstream, cached and
  blocked responses. Neither stops rule evaluation. Headers the gateway
  manages (`content-length`, `x-forwarded-*`, `x-qg-request-id`, …) are
  refused when the config loads.

## [0.4.0] - 2026-10-13

### ⚠️ Breaking changes

- **New access-log line format (`schema_version: 1`).** Each line now has the
  same 33 flat keys in the same order, with `""` / `0` / `false` instead of
  `null`, so dashboards and ClickHouse columns work on every line. Lines are
  about 600 bytes instead of about 1.4 KB. Update anything that reads the
  log:
  - Renamed: `timestamp` (RFC 3339 text) → `ts` (Unix milliseconds),
    `response_status` → `status`, `ip_intel.*` → `country`, `region`, `asn`,
    `provider`, `datacenter`, `vpn`, `proxy`, `tor`, `risk`,
    `bandwidth.client_bytes_out` → `bytes`, `client_bytes_in` → `req_bytes`,
    `timings_us.total_us` → `dur_us`, `load_balancer.target_id` → `upstream`.
  - `firewall`, `rate_limit` and `protection` are replaced by one `block`
    object: `type` (`fw`, `rl`, `dos`), `action` (`block`, `redirect`), `rule`
    and `key` (what the rule matched on, as `field=value` pairs). A firewall
    `allow` rule is logged as `allow_rule`.
  - Removed: `gateway_name`, `server_name`, `config_version`, `peer_ip`,
    `client_ip_source`, `http_version`, `referer`, `jwt`, the transform rule
    lists, `cache.rule_id` / `key_hash`, the per-plugin timings and the rest of
    `bandwidth`.
  - New: `upstream_addr`, `upstream_us`, `allow_rule`, `user`,
    `sample_rate` (always 1 for now; count with `sum(sample_rate)`).
  - **`path` no longer includes the query string**, and query values never
    appear anywhere in the log (rate-limit keys log a short hash instead).
  - A client that disconnects before the response is complete is logged as
    `status: 499`, `error: "client closed"`.
- `X-QG-Request-Id` values are UUIDv7 now, and an incoming ID is only reused
  when it's a valid UUID. Other values (any string up to 128 characters was
  accepted before) are replaced.

### Added

- **Log sinks.** `plugins.logging.sinks` sends the same lines to `stdout`,
  `clickhouse`, `datadog`, `otlp` (OpenTelemetry Collector and any OTLP/HTTP
  receiver), `loki`, `elasticsearch` / `opensearch`, `splunk` (HEC) or any
  `http` endpoint, each in its native format, alongside or instead of the
  file. Lines are formatted once on the writer thread; batches are gzipped
  and sent on the background runtime, so requests never wait on a sink.
  Failed batches are retried with backoff; with `spool_dir` they go to disk
  and are sent after an outage or a restart. ClickHouse inserts carry a
  deduplication token so a retried batch isn't stored twice. Secrets can come
  from env vars. `scripts/clickhouse/access_log.sql` creates a matching
  table. Batches default to 100,000 lines for `clickhouse` and `http` (fewer,
  larger requests to far-away endpoints), 1,000 for Datadog (its limit) and
  5,000 for the rest, whose default request limits refuse ~60 MB batches;
  each sink buffers up to 256 MiB in memory. See
  [Logging → Sinks](docs/logging.md#sinks).
- **Prometheus metrics.** A top-level `metrics` section serves `/metrics` on
  its own listener: requests by host, method and status, latency histograms,
  blocks by type and rule, upstream responses and latency, requests by
  country, cache status, and delivery counters for the log queue, file and
  every sink. Counted on the writer thread from the access-log events, so it
  adds no request-thread work beyond what logging already does. See
  [Logging → Metrics](docs/logging.md#metrics).
- **JWT verification.** A new top-level `jwt` section defines keys once:
  a shared secret (inline, env var or file), a pasted public key (PEM, `\n`
  line breaks, base64 body only, list of lines, or a certificate; also from an
  env var or file), an inline JWKS, or a JWKS URL that's fetched and refreshed
  in the background. With keys configured, the existing
  `header.<name>.jwt.<claim>` fields only return claims from tokens that pass
  the signature check and `exp` / `nbf` / `iss` / `aud`, so firewall, rate
  limiting, transform and cache rules all use verified claims. New
  `header.<name>.jwt_valid` and `header.<name>.jwt_error` fields let a firewall
  rule block missing or bad tokens. Without a `jwt` section nothing changes:
  tokens are decoded without checking, and the gateway now logs a startup
  warning when rules read JWT claims in that mode.
  Verified tokens are remembered (`verified_cache_size`, default 10,000;
  `verified_cache_ttl_secs`, default 60, never past the token's `exp`), so a
  client reusing its token pays for the signature check once rather than on
  every request.
- `scripts/test/jwt-verify.py` end-to-end test, also run by `run-all.sh`.
- **`X-QG-Request-Id`.** Every request gets a UUIDv7 ID, created before
  anything else runs, that is logged as `request_id`, sent to the origin and
  returned to the client, blocked and failed requests included. An incoming
  `X-QG-Request-Id` that is a valid UUID is reused, so one ID follows the
  request through every proxy; set `server.request_id.accept_incoming: false`
  to always generate a new one.
- `plugins.logging.user_field`: a condition field (e.g.
  `header.authorization.jwt.sub`) logged as `user` on every line.
- `plugins.logging.queue_size` (default 65,536): the most access-log events
  held in memory while waiting for the disk.

### Changed

- `request_id` in the access log is now a UUIDv7 instead of a counter that
  restarted at 0 on every restart and repeated across instances.
- Access log lines are formatted by a hand-written JSON writer on the writer
  thread instead of serde, and the request thread only collects raw values.
  Formatting a line takes about 5× less CPU (1.9 µs → 0.4 µs) and the
  request-thread part about 9× less (0.6 µs → 0.07 µs).
- The access log is written by a dedicated thread (`qg-access-log`) through a
  1 MiB write buffer, instead of a task on the background runtime with an
  8 KiB buffer. A slow disk no longer holds up JWKS refreshes, Auto-SSL or
  other background work, and a batch takes a few `write()` calls instead of
  hundreds. `SIGHUP` reopens the file within a few milliseconds.
- The access-log queue is lock-free and requests no longer wake the writer
  thread: the writer drains the queue every 5 ms (earlier when it's half
  full). Before, nearly every request cost a `futex` system call to wake it
  (about 1.8 per request under load, now about 0.04). With logging on, cache
  hits are 17–27% faster than before (paired `wrk` runs), and turning
  logging on now costs about 3–11% instead of about 27%.
- The sample `config.json` flushes the access log every second (was 60 s).

### Fixed

- On shutdown the access log now writes what's still queued. The process
  used to exit straight after Pingora stopped, losing up to one flush
  interval of lines.
- The access log queue had no size limit: with a slow or full disk, events
  piled up in memory until the process ran out of it. It's now bounded; when
  full, new events are dropped and the count is logged as a warning.
- The access log file is reopened when it's moved or deleted (checked every
  `flush_interval_ms`) and on `SIGHUP`. Before, logrotate's default
  move-and-create left the gateway writing to the rotated file, and only
  `copytruncate` worked.
- If the access log couldn't be opened at startup, logging stopped for good.
  The gateway now retries every flush interval.
- Changes to `plugins.logging` (path, on/off, sizes) now apply on hot reload.
  They used to need a restart, without any warning.
- `plugins.logging.mode` values other than `"file"` are rejected when the
  config loads instead of being silently ignored.
- Rule conditions now stop at the first result that settles the rule: in
  `A and B`, `B` isn't looked at when `A` is false, and in `A or B`, `B` isn't
  looked at when `A` is true. Before, every condition was resolved, so a rule
  like "path starts with `/api` and `jwt_valid` is not true" verified the
  token on every request, whatever the path. Results are unchanged; only
  wasted work (signature checks, regexes) is skipped.
- Origin connection errors (502s) now carry `X-QG-Request-Id` like every
  other response.
- The access log's response size (`bandwidth.client_bytes_out`, now `bytes`)
  was always 0. It's now the number of body bytes sent to the client.
- The config watcher no longer reloads an unchanged config 5 seconds after
  startup. That extra reload rebuilt every compiled rule and restarted JWKS
  fetches for nothing.

### Known issues

- **Network sinks can drop lines under sustained overload.** When a sink's
  in-memory buffer reaches `max_buffer_bytes`, new lines are dropped instead
  of being moved to `spool_dir`, and only one batch per sink is in flight at a
  time. In a 10M-request test against a distant HTTP endpoint (~300 ms round
  trip, ~16k lines/s) about 17% of lines were dropped. Drops are counted in
  `/metrics` (`qg_log_sink_lines_total{result="dropped"}`). A fix (spill before the
  limit, concurrent pushes) is planned for the next release.
- Firewall `set_request_header` and `set_response_header` actions have no
  effect on the request sent to the origin or on the response (also present
  in 0.3.x).

## [0.3.1] - 2026-10-12

### Fixed

- **Auto-SSL never issued a certificate.** The ACME client sent a placeholder
  instead of a signature and made a new account key for every request, so
  Let's Encrypt rejected the first call (`newAccount` → `400`) and HTTPS kept
  using the self-signed fallback. It's replaced with the `instant-acme` client.
  One ACME account is now registered, saved in `cert_storage_path`
  (`acme-account-*.json`, mode `0600`) and reused for every certificate and
  renewal. `key.pem` files are now written `0600` too (they were
  world-readable). Keep `cert_storage_path` on a persistent volume.
- **Auto-SSL renewal hung on its first attempt.** The renewal check held a
  lock on the domain's state while starting the renewal, which needs the same
  lock, so the renewal task deadlocked and no certificate was ever renewed.
- **A valid certificate was dropped at startup** when it was inside its
  renewal window: HTTPS served the self-signed fallback until the new
  certificate arrived, or for 24 hours if renewal failed. Stored certificates
  are now served until they actually expire, and renewal replaces them in the
  background. The renewal window is also capped at a third of the
  certificate's lifetime, so short-lived certificates aren't re-issued on
  every restart.

### Added

- **Auto-SSL: `directory_url` and `ca_root`** to use another ACME CA, such as
  a private step-ca. CAs that need External Account Binding aren't supported.
- `scripts/test/auto-ssl.py` tests Auto-SSL end to end against Pebble,
  Let's Encrypt's ACME test server. It needs Docker, so `run-all.sh` runs it
  only when Docker is available.

### ⚠️ Security note

- **JWT claims are not verified in 0.3.x.** Condition fields like
  `header.authorization.jwt.data.role` decode the token without checking its
  signature or expiry, so a client can forge any claim. Only rely on them when
  something in front of the gateway, or the origin, verifies the token.
  Verification is planned for 0.4.0. The conditions docs now say this.

## [0.3.0] - 2026-10-11

### ⚠️ Breaking changes

- **DoS protection is on by default.** New defaults that can refuse traffic
  which got through before: request headers must arrive within 10 s and be at
  most 32 KB; request bodies are capped at 100 MB (`413`); one IP may hold 256
  open connections, open 100 new ones per second and send 500 requests per
  second (`429`); IPs that keep breaking these limits are banned for 10
  minutes. Loopback and Cloudflare's edge IPs are exempt. Every value can be
  changed, or the protection turned off, in the new `server` section.

### Added

- **`server` config section.** Worker threads, every timeout (header, keep-alive,
  body read, response write, upstream connect/read/write/idle, graceful
  shutdown), size limits and the per-IP protection settings now live in one
  optional block. Every field has a built-in default; set only what you want
  to change. Most settings also apply on live reload. See
  [Configuration → `server`](docs/configuration.md#server).
- **Slowloris, slow POST and slow-read protection.** A deadline for the whole
  request header (Pingora only timed out each read), a per-read body timeout
  and a per-write response timeout.
- **`--version` / `-V` flag.** Prints the installed version and exits; the
  startup log line now includes the version too.
- **Connection and HTTP flood protection.** Per-IP limits on open connections,
  new connections per second and requests per second, with automatic temporary
  bans. Refused requests are logged with `termination_phase: "Protection"`.
- **Optional `X-QG-*` headers to the upstream.** Set
  `plugins.ip_intel.forward_headers.enabled` to `true` to send the client's
  country, region, city, ASN, provider, datacenter/VPN/proxy/Tor/mobile flags,
  network type, risk score and IP to your backend. Off by default. Client-sent
  headers with the same prefix are removed first, so they can't be spoofed. The
  prefix and the list of fields are configurable. See
  [IP Intelligence](docs/plugins/ip-intel.md#forwarding-to-the-upstream).
- **Request and response transforms.** `plugins.request_transform` rewrites the
  path, query parameters and headers after firewall and rate limiting (they
  still see the original request) and before the cache (the key uses the
  rewritten request). `plugins.response_transform` sets, adds, removes or
  renames headers and overrides the status on origin responses and on
  responses served from cache. Conditions can also use `resp.status` and
  `resp.header.<name>`. Gateway blocks are not transformed, and the cache only
  stores the untransformed origin response. Request rules can't touch
  `X-Forwarded-For`, `X-Forwarded-Proto` or `X-Forwarded-Host` (the config is
  rejected); the gateway always builds them from the client's original request.
  Access log events have `request_transform` (matched rules, rewritten path
  and host) and `response_transform` (matched rules). See
  [Request & Response Transform](docs/plugins/transform.md).
- **Conditional revalidation.** Refreshing a stale entry sends the stored
  `ETag` / `Last-Modified`. A `304` refreshes the entry without downloading the
  body again (`Quayel-Cache-Status: REVALIDATED`).
- **Stale-if-error now works.** If the origin returns a 5xx, times out or
  refuses the connection while a stored copy is inside its `stale_if_error`
  window, the client gets the stored copy (`STALE`) instead of the error.
  Between the end of `stale_while_revalidate` and the end of `stale_if_error`,
  the entry is kept only as this fallback (`EXPIRED`).

### Changed

- **Cache runs before the load balancer.** Cache HITs no longer pick a backend
  or count toward least-connections / fast-response. HITs are served even when
  no backend is healthy, and their log events have no `lb_*` / `target_*`
  fields.
- **The cache key includes the client's `Accept-Encoding`**, collapsed to `br`,
  `gzip` or `identity`, and the origin is sent the matching `Accept-Encoding`.
  Existing entries are not reused after upgrading.

### Fixed

- Cached responses were always replayed with status `200`. The origin's status
  is now stored, and only statuses in the rule's `statuses` list are stored.
- A client's `If-None-Match` / `If-Modified-Since` reached the origin on a MISS.
  They are now removed from requests whose response may be stored.
- A response compressed for one client could be served to a client that didn't
  accept that encoding. Responses with a `Vary` other than `Accept-Encoding`
  are no longer stored.
- `HEAD` and `Range` requests no longer try to fill the cache.
- Responses served from cache now carry a `Content-Length` matching the body,
  instead of the origin's framing headers.
- Log events for proxied responses now record the status sent to the client
  (it was `0`).

## [0.2.0] - 2026-10-11

The first published release. It ships as Linux binaries, `.deb` packages and a
Docker image, and changes a few defaults, so read **Breaking changes** before
upgrading an existing install.

### ⚠️ Breaking changes

- **Default ports are now 80 (HTTP) and 443 (HTTPS)**, instead of 8089 and
  8443. The `listen` section is optional and only needed to use other ports.
  Configs that already set `listen` behave exactly as before.
- **The config file is looked up in a fixed order** when no path is given on
  the command line: `$QUAYEL_GATEWAY_CONFIG`, then
  `/etc/quayel-gateway/config.json`, then `./config.json`. The startup log
  prints which file was loaded. If none exists the gateway stops with an error
  listing the paths it checked.
- **`provider-asns.txt` and `hosting-asns.txt` are replaced by one file,
  `src/data/datacenter-asns.txt`.** If you added your own ASNs to either old
  file, move them to the new one (`ASN|Label`, one per line) and rebuild.
- **Example configs moved to `examples/`** (`config.demo.json`,
  `config.all-rules.json`), and helper scripts moved to `scripts/bench/` and
  `scripts/test/`.

### Added

- **Release downloads for Linux x86_64 and aarch64:** a plain `.tar.gz`, a
  `.deb` package and a multi-arch Docker image at
  `ghcr.io/quayel/quayel-gateway`. Releases are built and published
  automatically when a version tag is pushed.
- **`.deb` package** (`sudo apt install ./quayel-gateway_<version>_<arch>.deb`)
  with a systemd service running as a dedicated `quayel` user, permission to
  bind ports 80/443 without root, a default config at
  `/etc/quayel-gateway/config.json` that upgrades never overwrite, and daily
  log rotation for `/var/log/quayel/`.
- **Datacenter detection by ASN:** visitors are flagged as datacenter traffic
  by the network (ASN) their IP belongs to, using a built-in list of 960
  hosting and cloud networks (AWS, Google Cloud, Azure, Hetzner, OVH,
  DigitalOcean, Leaseweb and more). Adding a provider is one line in
  `datacenter-asns.txt`.
- **`ip.provider` field** for firewall rules and logs, for example
  `ip.provider == "Hetzner Online GmbH"`.
- **Apache-2.0 license.** See `LICENSE` and `NOTICE`. The bundled DB-IP
  databases are CC BY 4.0.
- Docker Compose stack with persistent certificate storage and a health check.
- JSON Schema for `config.json` (`docs/config.schema.json`) and a guide for
  AI agents writing configs (`docs/ai-guide.md`).
- Live test suite covering every rule operator, action, rate-limit key, cache
  mode and load-balancer algorithm (`scripts/test/all-rules.sh`, 57 checks).

### Changed

- The README is rewritten as a step-by-step guide, with a quick start,
  copy-paste recipes and a troubleshooting table.
- Each release downloads fresh IP data (DB-IP, Tor, VPN and proxy lists) at
  build time.

### Fixed

- **Auto-SSL could freeze the gateway** while issuing a certificate during a
  TLS handshake. Certificates are now issued in the background, and plain-HTTP
  requests and clients without SNI also trigger issuance.
- **Stopping the gateway took up to 5 minutes.** `SIGTERM` now drains
  connections and exits within about 5–10 seconds, so `docker stop` and
  `systemctl stop` work as expected.
- The demo config used outdated field names (`url` on redirects, `http`
  health-check mode).

## [0.1.0] - 2026-10-10

Initial version (not published as a release): reverse proxy built on Pingora
with IP intelligence, firewall rules, rate limiting, caching, load balancing,
Auto-SSL and JSONL access logs.

[Unreleased]: https://github.com/quayel/Quayel-Gateway/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/quayel/Quayel-Gateway/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/quayel/Quayel-Gateway/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/quayel/Quayel-Gateway/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/quayel/Quayel-Gateway/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/quayel/Quayel-Gateway/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/quayel/Quayel-Gateway/releases/tag/v0.3.0
[0.2.0]: https://github.com/quayel/Quayel-Gateway/releases/tag/v0.2.0
[0.1.0]: https://github.com/quayel/Quayel-Gateway/commit/7480536
