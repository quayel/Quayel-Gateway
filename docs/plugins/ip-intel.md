# IP Intelligence Plugin

The IP Intelligence plugin enriches every request with geolocation, ASN, and threat detection data. All data is embedded in the binary — zero external dependencies.

## Configuration

```json
{
  "plugins": {
    "ip_intel": {
      "enabled": true
    }
  }
}
```

That's it. No URLs, no storage directories, no refresh intervals. Everything is baked in.

## What It Provides

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `country` | string | DB-IP City MMDB | ISO 3166-1 alpha-2 country code |
| `region` | string | DB-IP City MMDB | Region/state code |
| `city` | string | DB-IP City MMDB | City name |
| `asn` | number | DB-IP ASN MMDB | Autonomous System Number |
| `as_org` | string | DB-IP ASN MMDB | ASN organization name |
| `provider` | string | Provider ASN registry | Hosting/cloud provider label (e.g. `"Hostinger"`, `"Hetzner"`) |
| `is_vpn` | bool | X4BNet VPN list | IP belongs to a known VPN provider |
| `is_tor` | bool | Tor Project | IP is a current Tor exit node |
| `is_datacenter` | bool | ASN-based | IP's ASN is a known datacenter/hosting provider |
| `is_proxy` | bool | FireHOL | IP is a known anonymous proxy |
| `is_mobile` | bool | — | Reserved (currently null) |
| `is_residential` | bool | — | Reserved (currently null) |
| `is_residential_proxy` | bool | — | Reserved (currently null) |
| `network_type` | string | Computed | Network classification |
| `risk_score` | number | Computed | Risk score 0-100 |

## Network Type Classification

The `network_type` field is determined by the first matching flag:

| Priority | Condition | `network_type` |
|----------|-----------|----------------|
| 1 | `is_tor` = true | `"tor"` |
| 2 | `is_vpn` = true | `"vpn"` |
| 3 | `is_datacenter` = true | `"datacenter"` |
| 4 | `is_residential_proxy` = true | `"residential_proxy"` |
| 5 | `is_proxy` = true | `"proxy"` |
| 6 | `is_mobile` = true | `"mobile"` |
| 7 | `is_residential` = true | `"residential"` |
| 8 | None match | `null` |

## Risk Score

The `risk_score` is a 0-100 integer calculated from threat flags:

| Factor | Score Added |
|--------|-------------|
| Tor exit node | +40 |
| Residential proxy | +30 |
| VPN | +25 |
| Anonymous proxy | +20 |
| Datacenter/hosting | +10 |

Scores are capped at 100. A clean residential IP gets 0.

### Risk score thresholds

| Range | Interpretation |
|-------|----------------|
| 0 | Clean residential IP |
| 10 | Datacenter/hosting |
| 20-25 | Proxy or VPN |
| 35 | VPN + datacenter |
| 40 | Tor exit node |
| 50+ | Multiple threat indicators |
| 70+ | High risk (Tor + VPN + proxy) |

## Edge Detection

The plugin detects the request edge type based on the peer IP:

| Edge Type | Detection | Description |
|-----------|-----------|-------------|
| `Cloudflare` | Peer IP in Cloudflare CIDR ranges | Request came via Cloudflare |
| `Proxy` | Peer IP is private (RFC 1918) | Behind a reverse proxy |
| `Direct` | Neither of above | Direct connection |

This is used to determine which IP headers to trust.

## How It Works

```
Request arrives
    │
    ▼
1. Check LRU cache (65,536 entries)
    │
    ├── Cache HIT → return cached result (~1μs)
    │
    └── Cache MISS → full lookup:
        │
        ├── 2. MMDB city lookup → country, region, city
        ├── 3. MMDB country fallback (if city missed)
        ├── 4. MMDB ASN lookup → asn, as_org
        ├── 5. ASN lookup: datacenter-asns.txt → is_datacenter, provider
        │        (provider = "Unknown" when the list has no name)
        ├── 6. CIDR check: vpn.txt → is_vpn
        ├── 7. CIDR check: tor.txt → is_tor
        ├── 8. CIDR check: proxy.txt → is_proxy
        ├── 9. Classify network_type
        ├── 10. Calculate risk_score
        │
        └── Cache result (~5μs total)
```

## Embedded Data Sources

### MMDB Databases (MaxMind format)

| File | Size | Records | Source |
|------|------|---------|--------|
| `dbip-city-lite.mmdb` | 122 MB | ~2.8M networks | [DB-IP](https://db-ip.com) CC-BY 4.0 |
| `dbip-asn-lite.mmdb` | 9.2 MB | ~1.1M networks | [DB-IP](https://db-ip.com) CC-BY 4.0 |
| `dbip-country.mmdb` | 8.0 MB | ~2.8M networks | [DB-IP](https://db-ip.com) CC-BY 4.0 |

### CIDR Lists

| File | Size | Entries | Source | Refresh |
|------|------|---------|--------|---------|
| `vpn.txt` | 177 KB | 11,271 CIDRs | [X4BNet](https://github.com/X4BNet/lists_vpn) | Daily |
| `tor.txt` | 19 KB | 1,358 IPs | [Tor Project](https://check.torproject.org) | Hourly |
| `cloudflare.txt` | 336 B | 22 CIDRs | [Cloudflare](https://www.cloudflare.com/ips-v4) | Daily |
| `proxy.txt` | 0 B | 0 | [FireHOL](https://github.com/firehol/blocklist-ipsets) | Weekly |

### ASN Lists (datacenter / hosting detection)

| File | Size | Entries | Source | Refresh |
|------|------|---------|--------|---------|
| `datacenter-asns.txt` | 26 KB | 960 ASNs | Maintained in-repo (`ASN\|Label`, RIR-registered names) | Edit by hand |

Datacenter detection is **ASN-based**: the ASN MMDB resolves the client IP to its ASN (already part of the ~5 μs lookup), and this list classifies the network and names the provider. No datacenter IP ranges are embedded — the ASN identifies the provider regardless of which blocks it announces.

## Performance

| Metric | Value |
|--------|-------|
| Cache hit latency | ~1 μs |
| Cache miss latency | ~5 μs |
| Cache size | 65,536 entries |
| Cache memory | ~13 MB |
| Startup time | ~200 ms |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `QUAYEL_IP_INTEL_CACHE_SIZE` | `65536` | LRU cache size for IP lookups |

## Forwarding to the Upstream

By default the lookup results stay inside the gateway: firewall rules, rate
limits and the access log use them, but your backend never sees them. Turn on
`forward_headers` to send them along with each proxied request:

```json
{
  "plugins": {
    "ip_intel": {
      "enabled": true,
      "forward_headers": {
        "enabled": true
      }
    }
  }
}
```

| Option | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turn forwarding on |
| `prefix` | `"X-QG-"` | Header name prefix. Must end with `-` and be more specific than `X-` |
| `fields` | all | Only send these fields, e.g. `["country", "is_datacenter"]` |

| Field | Header (default prefix) | Example |
|---|---|---|
| `client_ip` | `X-QG-Client-IP` | `203.0.113.7` |
| `country` | `X-QG-Country` | `DE` |
| `region` | `X-QG-Region` | `Bavaria` |
| `city` | `X-QG-City` | `M%C3%BCnchen` |
| `asn` | `X-QG-ASN` | `24940` |
| `as_org` | `X-QG-AS-Org` | `Hetzner Online GmbH` |
| `provider` | `X-QG-Provider` | `Hetzner Online GmbH` |
| `is_datacenter` | `X-QG-Datacenter` | `true` |
| `is_vpn` | `X-QG-VPN` | `false` |
| `is_proxy` | `X-QG-Proxy` | `false` |
| `is_tor` | `X-QG-Tor` | `false` |
| `is_mobile` | `X-QG-Mobile` | `false` |
| `network_type` | `X-QG-Network-Type` | `datacenter` |
| `risk_score` | `X-QG-Risk-Score` | `10` |

How values are sent:

- **Unknown values are left out**, not sent empty. Treat a missing header as
  "unknown" in the backend.
- **Flags** are `true` or `false`; numbers are plain digits.
- **Text with non-ASCII characters** (such as city names) is percent-encoded
  UTF-8, so `München` arrives as `M%C3%BCnchen`. URL-decode it in the backend.

**Spoofing protection:** when forwarding is on, the gateway first removes every
header the client sent that starts with the prefix, then adds its own, so a
client can't send `X-QG-Datacenter: false` to fool your backend. When
forwarding is off, nothing is removed, so the backend shouldn't trust `X-QG-*`
headers unless forwarding is on.

Cached responses and requests blocked by the firewall or rate limiter never
reach the upstream, so they get no headers and cost nothing extra. For proxied
requests the cost is a few microseconds and about 400 bytes per request with
every field on. Use `fields` to send only what you need.

An invalid `prefix` or an unknown field name is rejected when the config loads.
On a live reload, the previous config stays in use.

## Using in Firewall Rules

IP intel fields can be used in firewall conditions:

```json
{
  "conditions": [
    { "left": "ip.country", "operator": "in", "value": ["US", "CA"] }
  ]
}
```

```json
{
  "conditions": [
    { "left": "ip.is_tor", "operator": "equals", "value": true }
  ]
}
```

```json
{
  "conditions": [
    { "left": "ip.risk_score", "operator": "greater_than", "value": 30 }
  ]
}
```

```json
{
  "conditions": [
    { "left": "ip.asn", "operator": "in", "value": [13335, 16509] }
  ]
}
```

## Updating Data

To update the embedded data:

```bash
# 1. Copy fresh MMDB files
cp /path/to/dbip-city-lite-2026-01.mmdb src/data/dbip-city-lite.mmdb
cp /path/to/dbip-asn-lite-2026-01.mmdb src/data/dbip-asn-lite.mmdb

# 2. Copy fresh CIDR lists
cp /var/lib/quayel/ip-intel/lua/*.txt src/data/

# 3. Rebuild
cargo build --release
strip target/release/quayel-gateway

# 4. Deploy
systemctl restart quayel-gateway
```

## Log Output

Every request produces an `ip_intel` section in the JSONL log:

```json
{
  "ip_intel": {
    "country": "US",
    "region": "CA",
    "asn": 16509,
    "network_type": "datacenter",
    "is_vpn": false,
    "is_proxy": false,
    "is_datacenter": true,
    "is_mobile": null,
    "is_tor": false,
    "risk_score": 10
  }
}
```