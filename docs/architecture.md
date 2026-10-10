# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                    QUAYEL GATEWAY                        │
│                  (Single Rust Binary)                    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Pingora HTTP Proxy                  │   │
│  │  (Connection handling, TLS, HTTP/1.1, H2)       │   │
│  └──────────────────────┬──────────────────────────┘   │
│                         │                               │
│                         ▼                               │
│  ┌─────────────────────────────────────────────────┐   │
│  │           Request Context (per-request)          │   │
│  │  client_ip, headers, path, method, scheme, ...   │   │
│  └──────────────────────┬──────────────────────────┘   │
│                         │                               │
│                         ▼                               │
│  ┌─────────────────────────────────────────────────┐   │
│  │             PLUGIN PIPELINE (fixed order)        │   │
│  │                                                  │   │
│  │  1. IP Intelligence   ─→  country, ASN, VPN,     │   │
│  │                            Tor, DC, risk score   │   │
│  │                                                  │   │
│  │  2. Firewall          ─→  allow/block/redirect   │   │
│  │                                                  │   │
│  │  3. Rate Limiting     ─→  throttle/block         │   │
│  │                                                  │   │
│  │  4. Load Balancer     ─→  select upstream target  │   │
│  │                                                  │   │
│  │  5. Cache             ─→  HIT/MISS/REVALIDATING/STALE/BYPASS  │   │
│  └──────────────────────┬──────────────────────────┘   │
│                         │                               │
│                         ▼                               │
│  ┌─────────────────────────────────────────────────┐   │
│  │           Upstream Proxy → Backend Servers       │   │
│  └──────────────────────┬──────────────────────────┘   │
│                         │                               │
│                         ▼                               │
│  ┌─────────────────────────────────────────────────┐   │
│  │        Response Filter + Logging (JSONL)         │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │        EMBEDDED DATA (140 MB in binary)          │   │
│  │  MMDB: city, ASN, country                        │   │
│  │  CIDR: VPN, Tor, datacenter, Cloudflare, proxy   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Plugin Pipeline

Every request flows through the pipeline in this exact order:

```
Request In
    │
    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  IP Intel    │───→│  Firewall    │───→│ Rate Limit   │
│              │    │              │    │              │
│ geo, ASN,    │    │ allow/block/ │    │ throttle/    │
│ VPN, Tor, DC │    │ redirect     │    │ 429          │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       │   Any plugin can return Respond ──────┘
       │   (short-circuits remaining plugins)
       ▼
┌──────────────┐    ┌──────────────┐
│Load Balancer │───→│    Cache     │───→ Upstream
│              │    │              │
│ select target│    │ HIT → respond│
│ round-robin  │    │ MISS → fetch │
│              │    │ REVALIDATING │
│              │    │ → serve stale│
│              │    │ → first req  │
│              │    │   fetches    │
└──────────────┘    └──────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │   Logging    │
                    │   (JSONL)    │
                    └──────────────┘
```

### Short-circuit behavior

| Plugin | Can short-circuit? | When? |
|--------|-------------------|-------|
| IP Intel | No | Always continues |
| Firewall | Yes | Block, redirect, or set-header action |
| Rate Limit | Yes | Limit exceeded → 429 |
| Cache | Yes | Cache HIT → serve cached response; REVALIDATING/STALE → serve stale cached data |
| Load Balancer | Yes | No healthy upstream → 503 |

## Request Context

One `RequestContext` is created per request. All plugins read and write to the same context:

```rust
struct RequestContext {
    // Identity
    gateway_id, gateway_name, server_name, config_version,
    request_id: UUID v4,
    
    // Client
    peer_ip,          // Direct connection IP
    client_ip,        // Resolved real client IP
    client_ip_source, // How client_ip was determined
    
    // HTTP
    host, path, method, scheme, user_agent,
    headers: HashMap<String, String>,
    
    // IP Intelligence (populated by ip_intel plugin)
    ip_intel: IpIntel,
    
    // Plugin results
    firewall: FirewallResult,
    rate_limit: RateLimitResult,
    cache: CacheResult,
    load_balancer: LoadBalancerResult,
    
    // Upstream
    upstream_name, upstream_target, upstream_protocol,
    
    // Response / cache capture
    status_code: Option<u16>,
    response_headers_captured: Option<Vec<(String, String)>>,
    response_body_buffer: Vec<u8>,
    cache_should_store: bool,              // Signal to store response in cache
    revalidation_guard: Option<RevalidationGuard>, // Per-key lock for stale revalidation
    
    // Bandwidth
    client_bytes_in, client_bytes_out,
    upstream_bytes_in, upstream_bytes_out,
    
    // Timing (microseconds)
    ip_intel_latency_us, firewall_latency_us,
    rate_limit_latency_us, cache_lookup_latency_us,
    lb_latency_us, upstream_connect_latency_us,
    upstream_ttfb_us, total_latency_us,
}
```

### RevalidationGuard

The `RevalidationGuard` holds a per-key `OwnedMutexGuard<()>` for the duration of a stale cache refresh request. When the request completes and `ctx` is dropped, the guard drops → lock releases → concurrent requests see fresh cache data.

## Embedded Data Architecture

All IP intelligence data is compiled into the binary at build time using Rust's `include_bytes!()` and `include_str!()` macros. This means:

- **Zero network requests** on startup
- **Zero disk I/O** for IP intel lookups
- **Deterministic startup** — no download failures, no timeouts
- **~140 MB** added to binary size (3 MMDB files + 6 CIDR lists)

### Data files in `src/data/`

| File | Size | Format | Purpose |
|------|------|--------|---------|
| `dbip-city-lite.mmdb` | 122 MB | MMDB | Country, region, city, lat/lon |
| `dbip-asn-lite.mmdb` | 9.2 MB | MMDB | ASN number + organization |
| `dbip-country.mmdb` | 8.0 MB | MMDB | Country-only fallback |
| `datacenter.txt` | 2.0 MB | CIDR list | 118K datacenter/hosting ranges |
| `vpn.txt` | 177 KB | CIDR list | 11K VPN provider ranges |
| `tor.txt` | 19 KB | CIDR list | 1.3K Tor exit node IPs |
| `hosting-asns.txt` | 4.3 KB | ASN list | Bad/hosting ASN numbers |
| `cloudflare.txt` | 336 B | CIDR list | Cloudflare edge ranges |
| `proxy.txt` | 0 B | CIDR list | FireHOL anonymous (empty) |

> See [Data Sources](data-sources.md) for complete dataset documentation, source URLs, and update instructions.

### Update process

```bash
# 1. Copy fresh data files
cp /path/to/new/dbip-city-lite.mmdb src/data/
cp /path/to/new/dbip-asn-lite.mmdb src/data/
cp /path/to/new/vpn.txt src/data/

# 2. Rebuild
cargo build --release
strip target/release/quayel-gateway

# 3. Deploy
systemctl restart quayel-gateway
```

See [Data Sources — Updating Embedded Data](data-sources.md#updating-embedded-data) for detailed instructions.

## Concurrency Model

- **Pingora** handles connection management and HTTP parsing on Tokio
- **Plugin pipeline** is async but most operations are CPU-bound (CIDR lookups, MMDB queries)
- **LRU cache** uses `parking_lot::RwLock` for concurrent read access
- **DashMap** for rate limit counters and cache store (lock-free sharded HashMap)
- **ArcSwap** for hot-reloading config without restarts
- **Per-key Mutex** for cache revalidation singleflight (prevents stampedes)

## Memory Layout

| Component | Size | Notes |
|-----------|------|-------|
| Binary (code) | ~13 MB | Stripped release |
| Embedded data | ~140 MB | MMDB + CIDR lists |
| LRU cache | ~13 MB | 65K entries × ~200 bytes |
| Rate limit counters | ~1 MB | Grows with unique keys |
| Cache store | Variable | Bounded by `max_object_size` |
| **Total RSS** | **~29 MB** | At startup |