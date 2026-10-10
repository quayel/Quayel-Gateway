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
| `is_vpn` | bool | X4BNet VPN list | IP belongs to a known VPN provider |
| `is_tor` | bool | Tor Project | IP is a current Tor exit node |
| `is_datacenter` | bool | Multi-source | IP is from a datacenter/hosting provider |
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
        ├── 5. CIDR check: vpn.txt → is_vpn
        ├── 6. CIDR check: tor.txt → is_tor
        ├── 7. CIDR check: datacenter.txt → is_datacenter
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
| `datacenter.txt` | 2.0 MB | 118,574 CIDRs | X4BNet + AWS + GCP + Oracle + Azure + DO | Daily |
| `cloudflare.txt` | 336 B | 22 CIDRs | [Cloudflare](https://www.cloudflare.com/ips-v4) | Daily |
| `hosting-asns.txt` | 4.3 KB | ASNs | [brianhama/bad-asn-list](https://github.com/brianhama/bad-asn-list) | Weekly |
| `proxy.txt` | 0 B | 0 | [FireHOL](https://github.com/firehol/blocklist-ipsets) | Weekly |

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