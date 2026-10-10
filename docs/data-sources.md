# Data Sources — All Embedded Datasets

All IP intelligence data is compiled directly into the gateway binary at build time using Rust's `include_bytes!()` and `include_str!()` macros. The gateway requires **zero downloads** at startup and works completely offline.

## Overview

| Category | Datasets | Total Size |
|----------|----------|------------|
| Geolocation | DB-IP City, Country, ASN (MMDB) | ~139 MB |
| VPN Detection | X4BNet VPN list | ~177 KB |
| Datacenter Detection | X4BNet + AWS + GCP + Oracle + Azure + DigitalOcean | ~2.0 MB |
| Tor Detection | Tor Project exit node list | ~19 KB |
| Edge Detection | Cloudflare IPv4 + IPv6 | ~336 B |
| Hosting ASNs | Bad ASN list | ~4.3 KB |
| Proxy Detection | FireHOL anonymous (empty by default) | 0 B |
| **Total** | **9 files** | **~140.3 MB** |

## Data Files (`src/data/`)

All files live in `src/data/` and are embedded via `include_bytes!()` / `include_str!()` in `src/utils/embedded_data.rs`.

### MMDB Databases (MaxMind Binary Format)

These are binary databases queried at runtime using the `maxminddb` crate.

#### `dbip-city-lite.mmdb` (122 MB)

| Field | Value |
|-------|-------|
| **Source** | [DB-IP City Lite](https://db-ip.com/db/ip/city-lite) |
| **URL** | `https://download.db-ip.com/free/dbip-city-lite-{YYYY-MM}.mmdb.gz` |
| **Format** | MMDB (MaxMind Database) |
| **Records** | ~2.8 million IPv4 + IPv6 networks |
| **License** | CC-BY 4.0 |
| **Update frequency** | Monthly (embedded at build time) |
| **Provides** | Country code, region, city name, latitude, longitude, timezone |

**Lookup struct:**
```rust
MaxMindCity {
    city: Option<MaxMindCityName>,        // city name (en)
    country: Option<MaxMindCountry>,       // iso_code: "US"
    location: Option<MaxMindLocation>,     // lat, lon, timezone
    subdivisions: Option<Vec<MaxMindSubdivision>>, // region/state code
    postal: Option<MaxMindPostal>,         // postal code
}
```

#### `dbip-asn-lite.mmdb` (9.2 MB)

| Field | Value |
|-------|-------|
| **Source** | [DB-IP ASN Lite](https://db-ip.com/db/ip/asn-lite) |
| **URL** | `https://download.db-ip.com/free/dbip-asn-lite-{YYYY-MM}.mmdb.gz` |
| **Format** | MMDB |
| **Records** | ~1.1 million IPv4 + IPv6 networks |
| **License** | CC-BY 4.0 |
| **Update frequency** | Monthly |
| **Provides** | ASN number, organization name |

**Lookup struct:**
```rust
MaxMindAsn {
    autonomous_system_number: Option<u32>,      // 16509
    autonomous_system_organization: Option<String>, // "AMAZON-02"
}
```

#### `dbip-country.mmdb` (8.0 MB)

| Field | Value |
|-------|-------|
| **Source** | [DB-IP Country Lite](https://db-ip.com/db/ip/country-lite) |
| **URL** | `https://download.db-ip.com/free/dbip-country-lite-{YYYY-MM}.mmdb.gz` |
| **Format** | MMDB |
| **Records** | ~2.8 million IPv4 + IPv6 networks |
| **License** | CC-BY 4.0 |
| **Update frequency** | Monthly |
| **Provides** | Country code only (fallback when city lookup misses) |

---

### CIDR Lists (Plain Text)

One CIDR per line. Used for IP range membership checks via binary search (O(log n)).

#### `vpn.txt` (177 KB)

| Field | Value |
|-------|-------|
| **Source** | [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) |
| **URL** | `https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt` |
| **Format** | CIDR list (one per line) |
| **Entries** | 11,271 CIDR ranges |
| **Original refresh** | Daily (24h) |
| **Provides** | Known VPN provider IP CIDRs |
| **Used for** | `ip.is_vpn` detection |

**Sample lines:**
```
1.0.1.0/24
1.0.2.0/23
1.0.8.0/21
```

#### `tor.txt` (19 KB)

| Field | Value |
|-------|-------|
| **Source** | [Tor Project](https://check.torproject.org/torbulkexitlist) |
| **URL** | `https://check.torproject.org/torbulkexitlist` |
| **Format** | IP list (one per line) |
| **Entries** | 1,358 exit node IPs |
| **Original refresh** | Hourly (1h) |
| **Provides** | Current Tor exit node IPs |
| **Used for** | `ip.is_tor` detection |

**Sample lines:**
```
2.26.97.42
5.9.47.21
17.5.12.34
```

#### `datacenter.txt` (2.0 MB)

| Field | Value |
|-------|-------|
| **Sources** | X4BNet + AWS + GCP + Oracle + Azure + DigitalOcean |
| **Entries** | 118,574 CIDR ranges |
| **Provides** | Known datacenter/hosting/cloud IP CIDRs |
| **Used for** | `ip.is_datacenter` detection |

**Source breakdown:**

| Source | URL | CIDRs |
|--------|-----|-------|
| X4BNet Datacenter | `https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt` | ~40K |
| AWS IP Ranges | `https://ip-ranges.amazonaws.com/ip-ranges.json` | ~8K |
| GCP Cloud IPs | `https://www.gstatic.com/ipranges/cloud.json` | ~3K |
| Oracle Cloud IPs | `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json` | ~5K |
| Azure Service Tags | `https://download.microsoft.com/download/...ServiceTags_Public_*.json` | ~50K |
| DigitalOcean IPs | `https://www.digitalocean.com/geo/google.csv` | ~5K |

#### `cloudflare.txt` (336 B)

| Field | Value |
|-------|-------|
| **Source** | [Cloudflare](https://www.cloudflare.com/ips-v4) |
| **URLs** | `https://www.cloudflare.com/ips-v4`, `https://www.cloudflare.com/ips-v6` |
| **Format** | CIDR list (IPv4 + IPv6) |
| **Entries** | 22 CIDR ranges |
| **Original refresh** | Daily (24h) |
| **Provides** | Cloudflare edge IP ranges |
| **Used for** | Edge detection (Cloudflare vs proxy vs direct) |

**Sample lines:**
```
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
2803:f800::/32
2a06:98c0::/29
```

#### `hosting-asns.txt` (4.3 KB)

| Field | Value |
|-------|-------|
| **Source** | [brianhama/bad-asn-list](https://github.com/brianhama/bad-asn-list) |
| **URL** | `https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv` |
| **Format** | ASN numbers (one per line) |
| **Entries** | ASN numbers known for hosting, abuse, bulletproof hosting |
| **Original refresh** | Weekly (7 days) |
| **Provides** | ASN numbers associated with hosting/abuse |
| **Used for** | `is_datacenter` fallback (ASN-based detection) |

**Sample lines:**
```
14061
16276
24940
```

#### `proxy.txt` (0 B — empty by default)

| Field | Value |
|-------|-------|
| **Source** | [FireHOL anonymous.netset](https://github.com/firehol/blocklist-ipsets) |
| **URL** | `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset` |
| **Format** | CIDR list |
| **Entries** | 0 (empty by default) |
| **Provides** | Known anonymous proxy IP ranges |
| **Used for** | `ip.is_proxy` detection |

> **Note:** FireHOL is disabled by default because the list is aggressive and may contain false positives. To use it, populate this file with the FireHOL data and rebuild.

---

## How Data Is Embedded

In `src/utils/embedded_data.rs`:

```rust
// CIDR lists
pub const VPN_CIDRS: &str = include_str!("../data/vpn.txt");
pub const TOR_CIDRS: &str = include_str!("../data/tor.txt");
pub const DATACENTER_CIDRS: &str = include_str!("../data/datacenter.txt");
pub const CLOUDFLARE_CIDRS: &str = include_str!("../data/cloudflare.txt");
pub const HOSTING_ASNS: &str = include_str!("../data/hosting-asns.txt");
pub const PROXY_CIDRS: &str = include_str!("../data/proxy.txt");

// MMDB databases
pub const DBIP_CITY_MMDB: &[u8] = include_bytes!("../data/dbip-city-lite.mmdb");
pub const DBIP_ASN_MMDB: &[u8] = include_bytes!("../data/dbip-asn-lite.mmdb");
pub const DBIP_COUNTRY_MMDB: &[u8] = include_bytes!("../data/dbip-country.mmdb");
```

These are compile-time constants. The data is part of the binary itself — no file I/O at runtime.

## Runtime Data Flow

```
Gateway starts
    │
    ▼
1. IpIntelPlugin::new()
    │
    ├── load_embedded_mmdb()
    │   ├── Reader::from_source(DBIP_CITY_MMDB)  → geo_reader
    │   ├── Reader::from_source(DBIP_ASN_MMDB)   → asn_reader
    │   └── Reader::from_source(DBIP_COUNTRY_MMDB) → country_reader
    │
    └── load_embedded_cidr_sets()
        ├── vpn.txt      → CidrSet (11,271 ranges, sorted)
        ├── tor.txt      → CidrSet (1,358 IPs, sorted)
        ├── datacenter.txt → CidrSet (118,574 ranges, sorted)
        ├── cloudflare.txt → CidrSet (22 ranges, sorted)
        ├── hosting-asns.txt → loaded as ASN numbers
        └── proxy.txt    → CidrSet (0 ranges, empty)

Per request:
    │
    ▼
1. LRU cache check (65,536 entries)
    │
    ├── HIT → return cached result (~1μs)
    │
    └── MISS:
        ├── MMDB city lookup → country, region, city
        ├── MMDB country fallback (if city missed)
        ├── MMDB ASN lookup → asn, as_org
        ├── CidrSet::contains("vpn", ip) → is_vpn
        ├── CidrSet::contains("tor", ip) → is_tor
        ├── CidrSet::contains("datacenter", ip) → is_datacenter
        ├── CidrSet::contains("proxy", ip) → is_proxy
        ├── classify_network_type()
        ├── calculate_risk_score()
        └── Cache result (~5μs total)
```

## CIDR Lookup Algorithm

Each `CidrSet` stores sorted ranges for binary search:

```rust
// Parsed CIDR: "192.168.1.0/24" → CidrRange { start, end, prefix_len }
// Sorted by start address

fn contains(&self, ip: IpAddr) -> bool {
    let ip_num = ip_to_u128(ip);
    self.ranges.binary_search_by(|r| {
        if r.end < ip_num { Ordering::Less }
        else if r.start > ip_num { Ordering::Greater }
        else { Ordering::Equal }
    }).is_ok()
}
```

**Performance:** O(log n) per lookup where n = number of ranges.

| Set | Ranges | Worst-case comparisons |
|-----|--------|----------------------|
| VPN | 11,271 | ~14 |
| Tor | 1,358 | ~11 |
| Datacenter | 118,574 | ~17 |
| Cloudflare | 22 | ~5 |

## Updating Embedded Data

To update the embedded data with fresh sources:

### 1. Update MMDB files

```bash
# Download latest DB-IP databases
wget https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz
gunzip dbip-city-lite-*.mmdb.gz

wget https://download.db-ip.com/free/dbip-asn-lite-$(date +%Y-%m).mmdb.gz
gunzip dbip-asn-lite-*.mmdb.gz

wget https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz
gunzip dbip-country-lite-*.mmdb.gz

# Copy to src/data/
cp dbip-city-lite-*.mmdb src/data/dbip-city-lite.mmdb
cp dbip-asn-lite-*.mmdb src/data/dbip-asn-lite.mmdb
cp dbip-country-lite-*.mmdb src/data/dbip-country.mmdb
```

### 2. Update CIDR lists

```bash
# VPN
curl -sL https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt \
  > src/data/vpn.txt

# Tor exits
curl -sL https://check.torproject.org/torbulkexitlist \
  > src/data/tor.txt

# Datacenter (X4BNet)
curl -sL https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt \
  > src/data/datacenter.txt

# AWS
curl -sL https://ip-ranges.amazonaws.com/ip-ranges.json | \
  jq -r '.prefixes[].ip_prefix' >> src/data/datacenter.txt

# GCP
curl -sL https://www.gstatic.com/ipranges/cloud.json | \
  jq -r '.prefixes[].ipv4Prefix // empty' >> src/data/datacenter.txt

# Oracle
curl -sL https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json | \
  jq -r '.regions[].cidrs[].cidr' >> src/data/datacenter.txt

# DigitalOcean
curl -sL https://www.digitalocean.com/geo/google.csv | \
  cut -d',' -f1 >> src/data/datacenter.txt

# Cloudflare
curl -sL https://www.cloudflare.com/ips-v4 > src/data/cloudflare.txt
curl -sL https://www.cloudflare.com/ips-v6 >> src/data/cloudflare.txt

# Hosting ASNs
curl -sL https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv | \
  tail -n +2 | cut -d',' -f1 > src/data/hosting-asns.txt
```

### 3. Rebuild

```bash
cargo build --release
strip target/release/quayel-gateway
```

### 4. Deploy

```bash
systemctl restart quayel-gateway
```

## Recommended Update Schedule

| Data | Recommended Frequency | Why |
|------|----------------------|-----|
| MMDB (city, ASN, country) | Monthly | DB-IP releases monthly |
| Tor exit list | Weekly | Exit nodes change frequently |
| VPN list | Weekly | New VPN providers appear |
| Datacenter ranges | Monthly | Cloud providers add ranges slowly |
| Cloudflare ranges | Monthly | Rarely changes |
| Hosting ASNs | Monthly | Slow-moving list |

## Binary Size Impact

| Component | Size | Percentage |
|-----------|------|------------|
| Code + dependencies | ~13 MB | 8.5% |
| DB-IP City MMDB | ~122 MB | 79.6% |
| DB-IP ASN MMDB | ~9.2 MB | 6.0% |
| DB-IP Country MMDB | ~8.0 MB | 5.2% |
| Datacenter CIDRs | ~2.0 MB | 1.3% |
| VPN CIDRs | ~177 KB | 0.1% |
| Tor CIDRs | ~19 KB | <0.1% |
| Other CIDRs | ~5 KB | <0.1% |
| **Total (stripped release)** | **~153 MB** | **100%** |

## Runtime Memory

| Component | Size | Notes |
|-----------|------|-------|
| Binary (code) | ~13 MB | Mapped from disk |
| Embedded data | ~140 MB | Mapped from binary |
| MMDB readers | ~0 MB | Memory-mapped, pages loaded on demand |
| CIDR sets (sorted) | ~5 MB | In-memory sorted arrays |
| LRU cache | ~13 MB | 65K entries × ~200 bytes |
| Rate limit counters | ~1 MB | Grows with unique keys |
| **Total RSS** | **~29 MB** | At startup |

## Data Sources Attribution

| Source | License | URL |
|--------|---------|-----|
| DB-IP | CC-BY 4.0 | https://db-ip.com |
| X4BNet lists_vpn | MIT | https://github.com/X4BNet/lists_vpn |
| Tor Project | BSD-3 | https://check.torproject.org |
| AWS IP Ranges | AWS | https://ip-ranges.amazonaws.com |
| GCP IP Ranges | Google | https://www.gstatic.com/ipranges |
| Oracle Cloud | Oracle | https://docs.oracle.com/en-us/iaas/tools |
| Azure Service Tags | Microsoft | https://www.microsoft.com/en-us/download |
| DigitalOcean | MIT | https://www.digitalocean.com/geo |
| Cloudflare | Cloudflare | https://www.cloudflare.com/ips |
| brianhama/bad-asn-list | MIT | https://github.com/brianhama/bad-asn-list |
| FireHOL | GPL v3 | https://github.com/firehol/blocklist-ipsets |