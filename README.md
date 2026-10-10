# Quayel Gateway

**A high-performance, single-binary API gateway built on [Pingora](https://github.com/cloudflare/pingora) (the Rust framework behind Cloudflare's edge) — with embedded IP intelligence, firewall, rate limiting, caching, load balancing and automatic TLS.**

~140 MB of IP-intelligence data (Geo/ASN MMDB databases + VPN / Tor / proxy / Cloudflare CIDR lists + a datacenter-provider ASN registry) is compiled straight into the binary. No Redis, no etcd, no external databases, no downloads at runtime.

---

## ✨ Basic Info

| | |
|---|---|
| **Language / core** | Rust on Pingora |
| **Deployment** | One binary (~153 MB incl. embedded data) + one `config.json` |
| **Runtime footprint** | ~29 MB RSS at startup |
| **External dependencies** | Zero — no Redis / etcd / DB / sidecars |
| **IP intelligence** | Geo (country / region / city), ASN + org, VPN · Tor · datacenter · proxy · Cloudflare edge, risk score |
| **TLS** | On-demand Let's Encrypt certificates (ACME) with auto-renewal |
| **Config** | Single JSON file, hot-reloaded on change |
| **Logging** | Structured JSONL access logs (IP intel, decisions, per-phase timing) |
| **Platform** | Linux x86_64 |

---

## 🔌 Plugins — What We Have

| Plugin | What it does | Docs |
|--------|--------------|------|
| **IP Intelligence** | Enriches every request with country / region / city, ASN + organization, hosting provider label (`Hostinger`, `Hetzner`, …), `is_vpn`, `is_tor`, `is_datacenter`, `is_proxy`, risk score and network classification — in ~5 μs (LRU-cached) | [docs/plugins/ip-intel.md](docs/plugins/ip-intel.md) |
| **Firewall** | Allow / block / redirect on any request attribute: method, path, headers, cookies — or any IP-intel field (`ip.is_tor`, `ip.risk_score`, …) | [docs/plugins/firewall.md](docs/plugins/firewall.md) |
| **Rate Limiting** | Sliding-window rate limits keyed by IP, header, cookie or expression | [docs/plugins/rate-limiting.md](docs/plugins/rate-limiting.md) |
| **Cache** | Edge caching with TTLs, bypass rules and custom cache keys | [docs/plugins/cache.md](docs/plugins/cache.md) |
| **Load Balancer** | Round-robin, weighted, least-connections, sticky sessions, fast-response; health checks; host-header control | [docs/plugins/load-balancer.md](docs/plugins/load-balancer.md) |
| **Auto-SSL** | On-demand Let's Encrypt certificates (ACME) obtained on first request; in-memory state, O(1) lookups, auto-renewal | [docs/plugins/auto-ssl.md](docs/plugins/auto-ssl.md) |

**Pipeline order:** `IP Intel → Firewall → Rate Limit → Cache → Load Balancer → Logging`
Every plugin can short-circuit the pipeline with its own response (e.g. firewall returns `403` before any backend is touched).

---

## 📊 Basic Chart — Nginx, Apache, APISIX vs Quayel Gateway

| | **Nginx** | **Apache HTTP Server** | **Apache APISIX** | **Quayel Gateway** |
|---|---|---|---|---|
| Core | C, event-driven | C, process/thread MPM | Nginx + Lua (OpenResty) | **Rust on Pingora** |
| Config model | `nginx.conf` + reload | `httpd.conf` / `.htaccess` | etcd + YAML / Admin API | **single JSON file, hot reload** |
| Extra services required | — | — | etcd (required) | **none** |
| IP intelligence (Geo / ASN / VPN / Tor / proxy) | 3rd-party modules | 3rd-party modules | plugins (partial) | **built-in, data embedded in binary** |
| Rate limiting | `limit_req` (fixed window) | `mod_ratelimit` / ModSecurity | limit-req / limit-count plugins | **sliding window, built-in** |
| Caching | `proxy_cache` | `mod_cache` | proxy-cache plugin | **built-in edge cache** |
| Load balancing | RR, hash, least_conn | `mod_proxy_balancer` | RR, chash, ewma | **RR, weighted, least-conn, sticky, fast-response** |
| TLS automation | external (certbot) | external (certbot) | plugin / external | **built-in Auto-SSL (ACME)** |
| Access logs | text formats | text formats | JSON via plugins | **structured JSONL + IP intel + per-phase timing** |
| Deployment | binary + modules | binary + modules | OpenResty + etcd + dashboard | **one static binary** |
| Maturity / ecosystem | very large | very large | large & growing | **young, batteries included** |

---

## 🚀 Quick Start

```bash
git clone https://github.com/quayel/quayel-gateway.git
cd quayel-gateway

./setup.sh                    # 1. datasets into src/data/ + cargo packages
cargo build --release         # 2. build (data is embedded into the binary)

./target/release/quayel-gateway config.demo.json   # 3. run
curl -v http://localhost:8080/
```

### What `setup.sh` does

1. **Downloads the embedded datasets** into `src/data/` (latest versions):
   | File | Content |
   |------|---------|
   | `dbip-city-lite.mmdb` | DB-IP City Lite — country, region, city, lat/lon |
   | `dbip-asn-lite.mmdb` | DB-IP ASN Lite — ASN + organization |
   | `dbip-country.mmdb` | DB-IP Country Lite — country fallback |
   | `cloudflare.txt` | Cloudflare edge ranges (IPv4 + IPv6) |
   | `hosting-asns.txt` | ASNs known for hosting / abuse |
   | `proxy.txt` | FireHOL anonymous proxy ranges |
   | `tor.txt` | Tor Project exit nodes |
   | `vpn.txt` | X4BNet VPN provider ranges |
   | `provider-asns.txt` | *(versioned in repo, not downloaded)* — provider ASN registry: `ASN\|Label` (e.g. `47583\|Hostinger`) |

   Datacenter/hosting detection is **ASN-based**: the ASN MMDB resolves any client IP to its ASN, and `provider-asns.txt` + `hosting-asns.txt` classify the network. No datacenter IP ranges are shipped. **Adding a provider = one line** in `src/data/provider-asns.txt`, then rebuild.
2. **Installs cargo packages** — Rust toolchain (rustup) and system build tools if missing, then fetches every crate dependency from `Cargo.toml` / `Cargo.lock`.

Flags: `./setup.sh --data-only` · `./setup.sh --asns-only` · `./setup.sh --cargo-only`

> **Note:** the FireHOL anonymous list behind `proxy.txt` is large (~2.9M ranges, ~40 MB). If you don't need `ip.is_proxy` detection, empty `src/data/proxy.txt` before `cargo build` to keep the binary smaller (the lists are embedded via `include_str!`).

---

## 🧩 Basic Configs — the Same Job in Four Servers

Proxy everything on `api.example.com` to a backend on `127.0.0.1:3000`.

### Nginx

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

### Apache HTTP Server

```apache
<VirtualHost *:80>
    ServerName api.example.com

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/
</VirtualHost>
```

### Apache APISIX

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

### Quayel Gateway

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

```bash
./target/release/quayel-gateway config.json
```

Full walk-through: [docs/getting-started.md](docs/getting-started.md) · every field: [docs/configuration.md](docs/configuration.md)

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [docs/README.md](docs/README.md) | Documentation index |
| [Getting Started](docs/getting-started.md) | Install, configure, run |
| [Architecture](docs/architecture.md) | System design, plugin pipeline, data flow |
| [Configuration Reference](docs/configuration.md) | Every `config.json` field |
| [Conditions System](docs/conditions.md) | Writing matching rules |
| [Data Sources](docs/data-sources.md) | All embedded IP-intelligence datasets |
| [API Reference](docs/api-reference.md) | Request/response headers, variables |
| [Logging](docs/logging.md) | JSONL access log format |

---

## 🗂 Repository Layout

```
quayel-gateway/
├── setup.sh              # bootstrap: datasets + cargo packages
├── Cargo.toml            # crate dependencies
├── config.demo.json      # full-featured demo config
├── src/
│   ├── main.rs           # entry point
│   ├── gateway/          # Pingora proxy pipeline
│   ├── plugins/          # ip_intel, firewall, rate_limit, cache, load_balancer
│   ├── auto_ssl/         # ACME / Let's Encrypt automation
│   ├── condition/        # request matching engine
│   ├── config/           # JSON config loader + hot reload
│   ├── data/             # embedded MMDB + CIDR datasets (setup.sh)
│   └── utils/            # embedded_data, CIDR sets, helpers
├── docs/                 # full documentation
└── scripts/              # benchmarks + nginx/APISIX mirrors
```

---

## ⚙️ Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 core | 2+ cores |
| RAM | 64 MB | 128 MB |
| Disk | 200 MB | 500 MB (logs) |
| OS | Linux x86_64 (Ubuntu 22.04+) | — |

Build: Rust stable (`rustup`), `build-essential`, `pkg-config`, `cmake`, `clang` — all installed by `./setup.sh`.

## License

Internal tool — not open source.
tool — not open source.
