# Quayel Gateway Documentation

A high-performance API gateway built on [Pingora](https://github.com/cloudflare/pingora) with embedded IP intelligence, firewall, rate limiting, caching, and load balancing — all in a single Rust binary.

## Quick Links

| Document | Description |
|----------|-------------|
| [AI Agent Guide](ai-guide.md) | Machine-oriented contract for AI agents: exact schema, enums, defaults, validation loop, recipes |
| [config.schema.json](config.schema.json) | JSON Schema for validating `config.json` |
| [Getting Started](getting-started.md) | Install, configure, and run your first gateway |
| [Architecture](architecture.md) | System design, plugin pipeline, data flow |
| [Configuration Reference](configuration.md) | Every `config.json` field explained |
| [Conditions System](conditions.md) | How to write matching rules |
| [Data Sources](data-sources.md) | All 13+ embedded IP intelligence datasets |
| [Auto-SSL](plugins/auto-ssl.md) | On-demand TLS certificates via Let's Encrypt |

## Plugins

| Plugin | Description |
|--------|-------------|
| [IP Intelligence](plugins/ip-intel.md) | Geo, ASN, VPN, Tor, datacenter, proxy detection |
| [Firewall](plugins/firewall.md) | Allow/block/redirect based on any request attribute |
| [Rate Limiting](plugins/rate-limiting.md) | Sliding-window rate limits per IP, header, or key |
| [Cache](plugins/cache.md) | Edge caching with TTL, bypass, and custom keys |
| [Load Balancer](plugins/load-balancer.md) | Round-robin, weighted, least-conn, sticky, fast-response |
| [Auto-SSL](plugins/auto-ssl.md) | On-demand TLS certificates via Let's Encrypt (ACME) |

## Reference

| Document | Description |
|----------|-------------|
| [Streams](streams.md) | TCP proxy: raw ports to backends, load balancing, health checks, IP rules, PROXY protocol |
| [Logging](logging.md) | JSONL access log format, fields, sinks (ClickHouse, Datadog, OTLP, Loki, Elasticsearch, Splunk) and Prometheus metrics |
| [API Reference](api-reference.md) | Request/response headers, APISIX variables |

## Development

| Document | Description |
|----------|-------------|
| [Benchmark Protocol](development/benchmark-protocol.md) | Fixed parameters for comparable benchmark runs (`scripts/bench/`) |
| [Multithreading](development/multithreading.md) | Notes on the multi-worker performance work |

## What Makes Quayel Different

1. **Zero external dependencies** — All IP intelligence data (140 MB of MMDB + CIDR lists) is compiled directly into the binary. No Redis, no external databases, no downloads on startup.

2. **Single binary deployment** — Copy one file, write one JSON config, start serving.

3. **On-demand TLS** — Automatic certificate provisioning via Let's Encrypt ACME. Certs are obtained on first request, not on startup. All state in memory for O(1) lookups.

4. **Embedded IP intelligence** — Every request is enriched with country, ASN, VPN/Tor/datacenter/proxy detection, risk scoring, and network classification — all in ~5μs (cached).

5. **Deterministic plugin pipeline** — Plugins execute in a fixed order: IP Intel → Firewall → Rate Limit → Load Balancer → Cache → Logging. Any plugin can short-circuit the pipeline.

6. **Structured JSONL logging** — Every request produces a single JSON line with full context: IP intel, firewall decisions, rate limit state, cache status, load balancer target, and per-phase timing.

## License

Internal tool — not open source.