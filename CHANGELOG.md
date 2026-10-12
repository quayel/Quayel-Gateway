# Changelog

All notable changes to Quayel Gateway are listed here, newest first.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/). Until 1.0,
a minor version bump (0.2 → 0.3) may include breaking changes; they are
always listed under **⚠️ Breaking changes**.

The text under each version becomes the GitHub release notes for that tag, so
write entries for people running the gateway, not for people reading the diff.

## [Unreleased]

### Added

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

### Fixed

- The config watcher no longer reloads an unchanged config 5 seconds after
  startup. That extra reload rebuilt every compiled rule and restarted JWKS
  fetches for nothing.

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

[Unreleased]: https://github.com/quayel/Quayel-Gateway/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/quayel/Quayel-Gateway/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/quayel/Quayel-Gateway/releases/tag/v0.3.0
[0.2.0]: https://github.com/quayel/Quayel-Gateway/releases/tag/v0.2.0
[0.1.0]: https://github.com/quayel/Quayel-Gateway/commit/7480536
