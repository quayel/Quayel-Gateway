# Changelog

All notable changes to Quayel Gateway are listed here, newest first.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/). Until 1.0,
a minor version bump (0.2 → 0.3) may include breaking changes; they are
always listed under **⚠️ Breaking changes**.

The text under each version becomes the GitHub release notes for that tag, so
write entries for people running the gateway, not for people reading the diff.

## [Unreleased]

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

[Unreleased]: https://github.com/quayel/Quayel-Gateway/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/quayel/Quayel-Gateway/releases/tag/v0.3.0
[0.2.0]: https://github.com/quayel/Quayel-Gateway/releases/tag/v0.2.0
[0.1.0]: https://github.com/quayel/Quayel-Gateway/commit/7480536
