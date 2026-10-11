# Quayel Gateway

**A fast, single-binary API gateway with IP intelligence built in.**

Quayel Gateway sits in front of your backends and handles firewall rules, rate limiting, caching, load balancing and automatic HTTPS. It is written in Rust on [Pingora](https://github.com/cloudflare/pingora), the framework behind Cloudflare's edge.

It knows who is calling: every request is tagged with country, city, ASN, hosting provider and VPN / Tor / proxy / datacenter flags. About 140 MB of IP data is compiled into the binary, so there is **nothing else to install**: no Redis, no etcd, no database, no downloads at runtime.

```
client ──▶ IP Intel ──▶ Firewall ──▶ Rate Limit ──▶ Cache ──▶ Load Balancer ──▶ your backend
                                                                     │
                                                          JSONL access log
```

---

## Contents

- [Why Quayel Gateway](#why-quayel-gateway)
- [Quick start](#quick-start)
- [Your first config](#your-first-config)
- [Common recipes](#common-recipes)
- [Features](#features)
- [Running it](#running-it)
- [Embedded IP data](#embedded-ip-data)
- [Troubleshooting](#troubleshooting)
- [How it compares](#how-it-compares)
- [Documentation](#documentation)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)

---

## Why Quayel Gateway

| | |
|---|---|
| **One file to deploy** | A single binary (~153 MB with data) plus one `config.json` |
| **Nothing to run beside it** | No Redis, etcd, database or sidecars |
| **Small footprint** | ~29 MB of memory at startup |
| **Knows every visitor** | Country / region / city, ASN and organisation, hosting provider, VPN · Tor · proxy · datacenter · Cloudflare edge, risk score. About 5 μs per lookup (LRU-cached) |
| **Rules on anything** | Match on method, path, host, headers, cookies or any IP field such as `ip.is_tor` or `ip.risk_score` |
| **HTTPS without certbot** | Let's Encrypt certificates are issued on the first request and renewed automatically |
| **Change config live** | Edit `config.json` and it is reloaded within 5 seconds. A broken file is rejected and the running config stays in place |
| **Useful logs** | One JSON line per request with IP data, the decision each plugin made and per-phase timing |

---

## Quick start

### Option 1: Docker (fastest)

The image comes with all IP data built in and a demo config that listens on ports 8080 (HTTP) and 8443 (HTTPS).

```bash
docker run --rm -p 8080:8080 -p 8443:8443 quayel/quayel-gateway
```

The same image is on Docker Hub (`quayel/quayel-gateway`) and GitHub's registry (`ghcr.io/quayel/quayel-gateway`). Use whichever you prefer.

Then use your own config by mounting it over the default:

```bash
docker run --rm -p 8080:8080 -p 8443:8443 \
  -v $PWD/config.json:/etc/quayel-gateway/config.json:ro \
  quayel/quayel-gateway
```

For a production-style setup with HTTPS (ports 80/443 and saved certificates), use Docker Compose:

```bash
docker compose up -d --build     # see docker-compose.yml
```

### Option 2: Install the .deb (Ubuntu / Debian)

Every [release](https://github.com/quayel/Quayel-Gateway/releases) has a `.deb` package for amd64 and arm64. It works on Ubuntu 22.04+ and Debian 12+.

```bash
VERSION=0.2.0                      # pick the latest from the releases page
ARCH=$(dpkg --print-architecture)  # amd64 or arm64
curl -LO https://github.com/quayel/Quayel-Gateway/releases/download/v$VERSION/quayel-gateway_${VERSION}_$ARCH.deb
sudo apt install ./quayel-gateway_${VERSION}_$ARCH.deb
```

The package sets everything up:

| What | Where |
|------|-------|
| The gateway | `/usr/bin/quayel-gateway` |
| Your config | `/etc/quayel-gateway/config.json`: listens on port 80 and forwards to `127.0.0.1:3000`. Upgrades never overwrite your edits |
| systemd service | `quayel-gateway.service`, runs as the `quayel` user and may bind ports 80/443 |
| Access log | `/var/log/quayel/access.jsonl`, rotated daily (14 days kept) |
| Certificates | `/var/lib/quayel/certs` |
| Example configs | `/usr/share/doc/quayel-gateway/examples/` |

The service is enabled but not started, so you can set your backend first:

```bash
sudo nano /etc/quayel-gateway/config.json
sudo systemctl start quayel-gateway
systemctl status quayel-gateway
journalctl -u quayel-gateway -f
```

To upgrade, install the newer `.deb` the same way. `sudo apt remove quayel-gateway` keeps your config and certificates, and `sudo apt purge quayel-gateway` deletes them too.

### Option 3: Download a Linux binary

Every [release](https://github.com/quayel/Quayel-Gateway/releases) has ready-made binaries for Linux on x86_64 and ARM64 (aarch64). They need glibc 2.35 or newer: Ubuntu 22.04+ and Debian 12+. On older systems (including RHEL/Rocky/Alma 9 and Amazon Linux 2023), use the Docker image.

```bash
VERSION=v0.2.0                     # pick the latest from the releases page
ARCH=x86_64                        # or aarch64
curl -LO https://github.com/quayel/Quayel-Gateway/releases/download/$VERSION/quayel-gateway-$VERSION-$ARCH-unknown-linux-gnu.tar.gz
tar xzf quayel-gateway-$VERSION-$ARCH-unknown-linux-gnu.tar.gz
cd quayel-gateway-$VERSION-$ARCH-unknown-linux-gnu
./quayel-gateway config.json       # config.json is the demo config; edit it first
```

Each release also lists a `SHA256SUMS` file you can check the download against with `sha256sum -c --ignore-missing SHA256SUMS`.

### Option 4: Build from source

```bash
git clone https://github.com/quayel/quayel-gateway.git
cd quayel-gateway

./setup.sh                    # 1. downloads the IP data and installs Rust + build tools
cargo build --release         # 2. builds the binary (the data is compiled in)
./target/release/quayel-gateway examples/config.demo.json   # 3. runs it
```

### Check it works

```bash
curl -v http://localhost:8080/
```

You should see the response from the backend in your config. Every response carries a `Quayel-Cache-Status` header, which is a quick way to confirm the request went through the gateway.

---

## Your first config

This sends all traffic for `api.example.com` to a backend on `127.0.0.1:3000`, with IP intelligence turned on:

```json
{
  "gateway_id": "gw-01",
  "gateway_name": "default",
  "server_name": "api.example.com",
  "config_version": "1",
  "listen": { "http": "0.0.0.0:8080" },
  "client_ip": {
    "source": "header_index",
    "header": "X-Forwarded-For",
    "index": 0,
    "fallback": "peer_ip"
  },
  "plugins": {
    "ip_intel": { "enabled": true },
    "load_balancer": {
      "enabled": true,
      "load_balancers": [{
        "id": "default",
        "name": "Backend",
        "enabled": true,
        "conditions": [],
        "algorithm": { "type": "round_robin" },
        "targets": [
          { "id": "t1", "host": "127.0.0.1", "port": 3000, "protocol": "http", "weight": 100, "enabled": true }
        ],
        "host_header": { "mode": "visitor" },
        "health_check": { "mode": "off" }
      }]
    }
  }
}
```

What each part does:

| Field | Meaning |
|-------|---------|
| `gateway_id`, `gateway_name`, `config_version` | Labels that appear in the logs. Change `config_version` whenever you edit the file so you can tell versions apart |
| `listen` | Where the gateway accepts traffic. Optional: if you leave it out, HTTP uses port 80 and HTTPS (with Auto-SSL) uses port 443. Ports below 1024 need root or `CAP_NET_BIND_SERVICE` |
| `client_ip` | How to find the real visitor IP. Use `header_index` on `X-Forwarded-For` **only** when another proxy (Cloudflare, a cloud load balancer) sits in front, because clients can fake that header. If the gateway faces the internet directly, use `{ "source": "peer_ip" }` |
| `plugins.load_balancer` | Where requests go. `conditions: []` means "match every request" |

Start it with:

```bash
./target/release/quayel-gateway config.json
```

[`examples/config.demo.json`](examples/config.demo.json) shows every plugin turned on, and [docs/configuration.md](docs/configuration.md) lists every field.

---

## Common recipes

Every firewall, rate-limit, cache and load-balancer rule uses the same **conditions**. All conditions in a rule must match:

```json
{ "left": "<field>", "operator": "<operator>", "value": <value> }
```

Fields include `req.path`, `req.method`, `req.host`, `req.headers.<name>`, `req.client_ip` and every `ip.*` field. Operators include `equals`, `starts_with`, `regex` and `greater_than`. See [docs/conditions.md](docs/conditions.md) for the full list.

<details>
<summary><b>Block Tor exit nodes and high-risk IPs</b></summary>

```json
"firewall": {
  "enabled": true,
  "rules": [
    {
      "id": "block-tor", "name": "Block Tor exit nodes", "enabled": true,
      "conditions": [{ "left": "ip.is_tor", "operator": "equals", "value": true }],
      "action": { "type": "block", "status": 403 }
    },
    {
      "id": "block-high-risk", "name": "Block risk score above 30", "enabled": true,
      "conditions": [{ "left": "ip.risk_score", "operator": "greater_than", "value": 30 }],
      "action": { "type": "block", "status": 403 }
    }
  ]
}
```
</details>

<details>
<summary><b>Rate-limit a login endpoint (10 requests per minute per IP)</b></summary>

```json
"rate_limiting": {
  "enabled": true,
  "rules": [{
    "id": "login-rate", "name": "Login rate limit", "enabled": true,
    "conditions": [
      { "left": "req.path",   "operator": "equals", "value": "/api/auth/login" },
      { "left": "req.method", "operator": "equals", "value": "POST" }
    ],
    "key": "req.client_ip",
    "limit": 10,
    "window_seconds": 60,
    "action": { "type": "block", "status": 429 }
  }]
}
```
</details>

<details>
<summary><b>Redirect <code>www</code> to the bare domain</b></summary>

```json
{
  "id": "redirect-www", "name": "Redirect www", "enabled": true,
  "conditions": [{ "left": "req.host", "operator": "equals", "value": "www.example.com" }],
  "action": { "type": "redirect", "status": 301, "location": "https://example.com" }
}
```
Add this to `plugins.firewall.rules`.
</details>

<details>
<summary><b>Cache static files for a day</b></summary>

```json
"cache": {
  "enabled": true,
  "max_object_size_bytes": 10485760,
  "rules": [{
    "id": "cache-static", "name": "Cache static assets", "enabled": true,
    "conditions": [{ "left": "req.path", "operator": "regex", "value": "\\.(css|js|woff2?|png|jpg|jpeg|gif|webp|svg|ico)$" }],
    "cache": "eligible",
    "edge_ttl":    { "mode": "custom", "seconds": 86400 },
    "browser_ttl": { "mode": "custom", "seconds": 3600 },
    "cache_key":   { "mode": "default" },
    "statuses": [200, 301]
  }]
}
```
Check the `Quayel-Cache-Status` response header: `MISS` on the first request, then `HIT`.
</details>

<details>
<summary><b>Send <code>/api/</code> to a separate pool with health checks</b></summary>

Load balancers are checked in order, and the first one whose conditions match handles the request. Put specific pools first and a catch-all (`"conditions": []`) last.

```json
{
  "id": "api-backend", "name": "API pool", "enabled": true,
  "conditions": [{ "left": "req.path", "operator": "starts_with", "value": "/api/" }],
  "algorithm": { "type": "round_robin" },
  "targets": [
    { "id": "api-1", "host": "10.0.1.10", "port": 8080, "protocol": "http", "weight": 100, "enabled": true },
    { "id": "api-2", "host": "10.0.1.11", "port": 8080, "protocol": "http", "weight": 100, "enabled": true }
  ],
  "host_header": { "mode": "visitor" },
  "health_check": {
    "mode": "https", "path": "/health", "interval_seconds": 5, "timeout_ms": 2000,
    "expected_statuses": [200], "healthy_threshold": 2, "unhealthy_threshold": 3
  }
}
```
Health-check modes are `https` (request `path` and check the status; it uses each target's own `protocol`, so it works for plain-HTTP targets too), `accepts_connections` (TCP connect only) and `off`.
</details>

---

## Features

| Plugin | What it does | Docs |
|--------|--------------|------|
| **IP Intelligence** | Adds country / region / city, ASN and organisation, hosting provider name (`Hetzner Online GmbH`, `Amazon.com, Inc.`, …), `is_vpn`, `is_tor`, `is_datacenter`, `is_proxy`, network type and risk score to every request | [ip-intel.md](docs/plugins/ip-intel.md) |
| **Firewall** | Allow, block or redirect based on any request field or IP field | [firewall.md](docs/plugins/firewall.md) |
| **Rate Limiting** | Sliding-window limits keyed by IP, header, cookie or expression | [rate-limiting.md](docs/plugins/rate-limiting.md) |
| **Cache** | Edge cache with custom TTLs, bypass rules, cache keys and stale-while-revalidate | [cache.md](docs/plugins/cache.md) |
| **Load Balancer** | Round-robin, weighted, least-connections, sticky sessions and fast-response; health checks; Host header control | [load-balancer.md](docs/plugins/load-balancer.md) |
| **Auto-SSL** | Let's Encrypt certificates issued on the first request and renewed automatically | [auto-ssl.md](docs/plugins/auto-ssl.md) |

Plugins run in this order: **IP Intel → Firewall → Rate Limit → Cache → Load Balancer → Logging**. Any plugin can stop the request early. For example, the firewall returns `403` before a backend is ever contacted.

---

## Running it

### Command line

```
quayel-gateway [--workers N] [CONFIG_PATH]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `CONFIG_PATH` | see below | Path to the config file |
| `--workers N` | all CPU cores | Number of worker threads |
| `--help` | | Show help |

If you don't pass `CONFIG_PATH`, the gateway uses the first of these that exists:

1. the file named in `$QUAYEL_GATEWAY_CONFIG`
2. `/etc/quayel-gateway/config.json` (the standard location for a server install, and the path the Docker image uses)
3. `./config.json` in the current folder

The log line `Config file: ...` at startup shows which one it picked.

### Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `QUAYEL_GATEWAY_CONFIG` | | Config file to use when no `CONFIG_PATH` is given |
| `RUST_LOG` | `info` | Log level of the gateway's own output (`debug`, `info`, `warn`, `error`) |
| `QUAYEL_IP_INTEL_CACHE_SIZE` | `65536` | How many IP lookups to keep in memory |

### Changing the config

Edit the config file while the gateway is running. It checks the file every 5 seconds:

- **Valid file:** applied right away, with no restart and no dropped connections. The log says `Config hot-reloaded successfully`.
- **Invalid file:** rejected, and the gateway keeps running on the last good config. The log shows `Config validation FAILED` or `Config compilation FAILED` with the reason.

### Logs

The gateway writes two kinds of logs:

- **Its own output** (startup, reloads, errors) goes to stdout as JSON.
- **Access logs** are one JSON line per request, written to the file set in `plugins.logging`, for example `/var/log/quayel/access.jsonl`. Turn this on with `"enabled": true`.

```bash
tail -f /var/log/quayel/access.jsonl | jq .
```

The access log has no built-in rotation, so set up `logrotate` or similar to stop it growing without limit. The field list is in [docs/logging.md](docs/logging.md).

### Auto-SSL in Docker

- **Keep your certificates.** Certificates and the ACME account key live in `cert_storage_path` (`/var/lib/quayel/certs` in the image). Mount a volume there (`-v quayel-certs:/var/lib/quayel/certs`, or use the compose file). Without it, every restart requests new certificates and you will hit Let's Encrypt rate limits.
- **Open port 80.** Let's Encrypt checks your domain over port 80 from the internet. Map `80:8080` and `443:8443` when using the demo listeners, or listen on 80/443 directly.
- **Shutdown is clean.** On `SIGTERM` the gateway finishes in-flight requests (5 s grace + 5 s drain), well inside Docker's 10 s stop timeout. `docker-compose.yml` sets `stop_grace_period: 15s` for headroom.

### Building the Docker image yourself

```bash
docker build -t quayel-gateway .
```

The build compiles the binary in `rust:1-bookworm` and runs it on `debian:bookworm-slim`. If the IP databases aren't in `src/data/`, the build downloads them automatically, so **rebuilding the image is how you refresh the IP data**. Do it about once a month to get the latest DB-IP data. Published images (`quayel/quayel-gateway` on Docker Hub and `ghcr.io/quayel/quayel-gateway`) are tagged `:latest`, `:<version>` (for example `:0.2.0`) and `:<major>.<minor>`.

### Making a release

Releases are built automatically by [`.github/workflows/release.yml`](.github/workflows/release.yml).

1. As you make changes, add a line for each user-visible one under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md), in **Breaking changes**, **Added**, **Changed** or **Fixed**.
2. When releasing, rename `## [Unreleased]` to `## [0.3.0] - YYYY-MM-DD`, add a new empty `## [Unreleased]` above it, and set `version` in `Cargo.toml` to match. Preview the notes with `scripts/release-notes.sh v0.3.0`.
3. Commit, then push a matching tag:

```bash
git tag v0.3.0
git push origin main v0.3.0
```

GitHub Actions then tests and builds the x86_64 and ARM64 binaries with fresh IP data, packages them as `.tar.gz` and `.deb` files, creates the GitHub release using that version's `CHANGELOG.md` section plus install instructions as the notes, and pushes the Docker image to `ghcr.io` and Docker Hub. The Docker Hub push needs the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repo secrets; without them it's skipped. The build stops if the tag doesn't match `Cargo.toml` or `CHANGELOG.md` has no section for that version. A tag with a suffix, such as `v0.3.0-rc.1`, is published as a pre-release and doesn't move the `latest` image tag.

---

## Embedded IP data

`./setup.sh` downloads the latest datasets into `src/data/`, and `cargo build` compiles them into the binary.

| File | Contents | Source |
|------|----------|--------|
| `dbip-city-lite.mmdb` | Country, region, city, latitude/longitude | DB-IP City Lite |
| `dbip-asn-lite.mmdb` | ASN and organisation | DB-IP ASN Lite |
| `dbip-country.mmdb` | Country (fallback) | DB-IP Country Lite |
| `cloudflare.txt` | Cloudflare edge IP ranges (IPv4 + IPv6) | Cloudflare |
| `proxy.txt` | Anonymous proxy ranges | FireHOL |
| `tor.txt` | Tor exit nodes | Tor Project |
| `vpn.txt` | VPN provider ranges | X4BNet |
| `datacenter-asns.txt` | Datacenter and hosting ASNs with provider names | **Kept in this repo, edited by hand** |

**How datacenter detection works.** The gateway looks up the visitor's ASN in the ASN database, then checks it against `datacenter-asns.txt`. If it's listed, the request gets `ip.is_datacenter = true` and the provider name. No datacenter IP ranges are shipped.

**Adding a hosting provider.** `setup.sh` never downloads or changes `datacenter-asns.txt`. Add one line in `ASN|Label` format, then rebuild:

```
24940|Hetzner Online GmbH
```

The label is the organisation registered for the ASN. Use `Unknown` when there isn't one.

`setup.sh` options:

| Command | What it does |
|---------|--------------|
| `./setup.sh` | Downloads data and installs Rust + build tools |
| `./setup.sh --data-only` | Downloads data only |
| `./setup.sh --cargo-only` | Installs Rust and fetches crates only |

> **Tip: smaller binary.** `proxy.txt` is large (~2.9M ranges, ~40 MB). If you don't need `ip.is_proxy`, empty `src/data/proxy.txt` before building.

---

## Troubleshooting

| Problem | What to check |
|---------|---------------|
| Gateway exits right after starting | Look for `Failed to load config` or `Failed to compile config` in the output. The message names the bad field. Validate against [docs/config.schema.json](docs/config.schema.json) |
| Config edits don't take effect | Look for `Config validation FAILED` in the output. The gateway keeps the last good config until the file is fixed |
| Every visitor has the same IP, or IP data looks wrong | `client_ip` doesn't match your setup. Use `peer_ip` when clients connect directly, and `header_index` / `header` only when behind a trusted proxy |
| Requests fail or hang with no backend response | Check the target `host` and `port`, and make sure no target points back at the gateway's own `listen` address. That creates a loop |
| `503` with a "no healthy upstream" body | Every target in the pool failed its health check. Check that the `health_check.path` returns one of `expected_statuses` |
| HTTPS certificate isn't issued | Port 80 must be reachable from the internet, the domain must be in `auto_ssl.domains` and its DNS must point at this server |
| Let's Encrypt rate-limit errors in Docker | Certificates aren't being kept. Mount a volume at `/var/lib/quayel/certs` |
| `localhost` / `127.0.0.1` has no country | Expected. Private and local IPs aren't in the GeoIP databases |

For more detail, run with `RUST_LOG=debug`.

---

## How it compares

| | **Nginx** | **Apache HTTP Server** | **Apache APISIX** | **Quayel Gateway** |
|---|---|---|---|---|
| Core | C, event-driven | C, process/thread MPM | Nginx + Lua (OpenResty) | **Rust on Pingora** |
| Config | `nginx.conf` + reload | `httpd.conf` / `.htaccess` | etcd + YAML / Admin API | **one JSON file, hot reload** |
| Extra services needed | — | — | etcd | **none** |
| IP intelligence (Geo / ASN / VPN / Tor / proxy) | 3rd-party modules | 3rd-party modules | plugins (partial) | **built in, data in the binary** |
| Rate limiting | `limit_req` (fixed window) | `mod_ratelimit` / ModSecurity | limit-req / limit-count | **sliding window, built in** |
| Caching | `proxy_cache` | `mod_cache` | proxy-cache plugin | **built in** |
| Load balancing | RR, hash, least_conn | `mod_proxy_balancer` | RR, chash, ewma | **RR, weighted, least-conn, sticky, fast-response** |
| HTTPS automation | certbot | certbot | plugin / external | **built in (ACME)** |
| Access logs | text | text | JSON via plugins | **JSONL with IP data and timing** |
| Deployment | binary + modules | binary + modules | OpenResty + etcd + dashboard | **one binary** |
| Maturity | very large ecosystem | very large ecosystem | large and growing | **young, batteries included** |

<details>
<summary><b>The same job in all four: proxy <code>api.example.com</code> to <code>127.0.0.1:3000</code></b></summary>

**Nginx**

```nginx
upstream backend { server 127.0.0.1:3000; }

server {
    listen 80;
    server_name api.example.com;

    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

**Apache HTTP Server**

```apache
<VirtualHost *:80>
    ServerName api.example.com

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/
</VirtualHost>
```

**Apache APISIX**

```bash
# etcd must be running first
curl -X PUT http://127.0.0.1:9180/apisix/admin/routes/1 \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -d '
{
  "uri": "/*",
  "hosts": ["api.example.com"],
  "upstream": {
    "type": "round_robin",
    "nodes": { "127.0.0.1:3000": 1 }
  }
}'
```

**Quayel Gateway:** see [Your first config](#your-first-config).
</details>

---

## Documentation

| Document | What's in it |
|----------|--------------|
| [Documentation index](docs/README.md) | Start here |
| [Getting Started](docs/getting-started.md) | Install, configure, run, systemd |
| [Configuration Reference](docs/configuration.md) | Every `config.json` field |
| [Conditions](docs/conditions.md) | Fields and operators for writing rules |
| [API Reference](docs/api-reference.md) | Headers added to requests and responses, error bodies |
| [Architecture](docs/architecture.md) | Design, plugin pipeline, data flow |
| [Data Sources](docs/data-sources.md) | Every embedded IP dataset |
| [Logging](docs/logging.md) | Access log format |

### For AI agents

| Document | What's in it |
|----------|--------------|
| [AGENTS.md](AGENTS.md) | Start here when working on or with this repo as an agent |
| [AI Guide](docs/ai-guide.md) | Schema, enums, defaults, validation loop and recipes |
| [config.schema.json](docs/config.schema.json) | JSON Schema for validating a generated `config.json` |
| [SKILL.md](skills/quayel-gateway/SKILL.md) | Portable skill package for AI tools |

---

## Repository layout

```
quayel-gateway/
├── .github/workflows/    # release.yml: builds + publishes releases on a version tag
├── config.json           # your live config (hot-reloaded; default path)
├── setup.sh              # downloads IP data, installs Rust + build tools
├── Dockerfile            # multi-stage image build
├── Dockerfile.release    # release image from prebuilt binaries (used by CI)
├── docker-compose.yml    # production-style setup with HTTPS
├── examples/
│   ├── config.demo.json       # every plugin turned on (the Docker image default)
│   └── config.all-rules.json  # every rule type, used by the rules test
├── src/
│   ├── main.rs           # entry point and CLI
│   ├── gateway/          # Pingora proxy pipeline
│   ├── plugins/          # ip_intel, firewall, rate_limit, cache, load_balancer
│   ├── lb/               # load-balancer targets and health checks
│   ├── auto_ssl/         # Let's Encrypt (ACME)
│   ├── condition/        # rule matching engine
│   ├── config/           # config loading, validation and hot reload
│   ├── logging/          # JSONL access log writer
│   ├── data/             # embedded IP datasets
│   └── utils/            # embedded data loading, CIDR sets, helpers
├── docs/
│   ├── plugins/          # one page per plugin
│   └── development/      # benchmark protocol, performance notes
├── packaging/
│   ├── build-deb.sh      # builds the .deb from a release binary (used by CI)
│   └── deb/              # systemd unit, default config, logrotate, install scripts
├── scripts/
│   ├── test/             # all-rules.sh (live rule test), check-config.sh
│   └── bench/            # wrk benchmarks, Nginx/APISIX mirrors, results/
└── skills/               # AI skill package
```

---

## Requirements

| | Minimum | Recommended |
|---|---------|-------------|
| CPU | 1 core | 2+ cores |
| RAM | 64 MB | 128 MB |
| Disk | 200 MB | 500 MB+ (for access logs) |
| OS | Linux x86_64 (Ubuntu 22.04+) | |

To build from source you need Rust stable, `build-essential`, `pkg-config`, `cmake` and `clang`. `./setup.sh` installs all of them.

## License

Quayel Gateway is open source under the [Apache License 2.0](LICENSE). You can use, modify and distribute it, including in commercial and closed-source products. If you redistribute it, include the `LICENSE` and [`NOTICE`](NOTICE) files and mark any files you changed.

The DB-IP databases built into the binary are a separate work, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): *IP Geolocation by [DB-IP](https://db-ip.com)*. Keep that attribution if you ship a binary or image that includes them.
