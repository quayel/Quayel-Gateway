# Changelog

All notable changes to Quayel Gateway are listed here, newest first.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/). Until 1.0,
a minor version bump (0.2 → 0.3) may include breaking changes; they are
always listed under **⚠️ Breaking changes**.

The text under each version becomes the GitHub release notes for that tag, so
write entries for people running the gateway, not for people reading the diff.

## [Unreleased]

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

[Unreleased]: https://github.com/quayel/Quayel-Gateway/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/quayel/Quayel-Gateway/releases/tag/v0.2.0
[0.1.0]: https://github.com/quayel/Quayel-Gateway/commit/7480536
