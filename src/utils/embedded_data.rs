// ── Embedded Data ───────────────────────────────────────────────────────────
// ALL IP intelligence data compiled directly into the binary via include_str!()
// and include_bytes!(). The gateway works completely offline — no downloads needed.
//
// To update: copy fresh files into src/data/ and rebuild.
//
// Data sources:
//   CIDR lists   — downloaded by setup.sh (VPN, Tor, proxy, Cloudflare ranges)
//   ASN list     — datacenter-asns.txt ('ASN|Label', maintained in-repo)
//   MMDB files   — downloaded from DB-IP free databases
//
// Datacenter/hosting detection is ASN-based: the ASN MMDB resolves any client
// IP to its ASN, and datacenter-asns.txt classifies the network. No datacenter IP
// ranges are shipped.

// ── CIDR Lists ──────────────────────────────────────────────────────────────

/// VPN provider CIDRs from X4BNet
pub const VPN_CIDRS: &str = include_str!("../data/vpn.txt");

/// Tor exit node CIDRs from Tor Project
pub const TOR_CIDRS: &str = include_str!("../data/tor.txt");

/// Cloudflare edge CIDRs (IPv4 + IPv6)
pub const CLOUDFLARE_CIDRS: &str = include_str!("../data/cloudflare.txt");

/// FireHOL anonymous proxy CIDRs (empty by default)
pub const PROXY_CIDRS: &str = include_str!("../data/proxy.txt");

// ── ASN Lists ────────────────────────────────────────────────────────────────

/// Datacenter/hosting ASNs from X4BNet/lists_vpn — 'ASN|Label' lines
/// (e.g. 47583|Hostinger International Limited), maintained by hand in the repo.
/// Sets is_datacenter and the provider label ('Unknown' when unnamed) on any
/// request whose IP resolves to one of these ASNs.
pub const DATACENTER_ASNS: &str = include_str!("../data/datacenter-asns.txt");

// ── MMDB Databases ──────────────────────────────────────────────────────────

/// DB-IP City Lite — IP → Country, Region, City, Lat/Lon
pub const DBIP_CITY_MMDB: &[u8] = include_bytes!("../data/dbip-city-lite.mmdb");

/// DB-IP ASN Lite — IP → ASN number + Organization name
pub const DBIP_ASN_MMDB: &[u8] = include_bytes!("../data/dbip-asn-lite.mmdb");

/// DB-IP Country Lite — IP → Country code (fallback if city lookup misses)
pub const DBIP_COUNTRY_MMDB: &[u8] = include_bytes!("../data/dbip-country.mmdb");

// ── Source metadata ─────────────────────────────────────────────────────────

/// Embedded CIDR source with metadata
pub struct EmbeddedCidrSource {
    pub name: &'static str,
    pub set_name: &'static str,
    pub data: &'static str,
}

/// All embedded CIDR sources
pub fn all_cidr_sources() -> Vec<EmbeddedCidrSource> {
    vec![
        EmbeddedCidrSource {
            name: "vpn.txt",
            set_name: "vpn",
            data: VPN_CIDRS,
        },
        EmbeddedCidrSource {
            name: "tor.txt",
            set_name: "tor",
            data: TOR_CIDRS,
        },
        EmbeddedCidrSource {
            name: "cloudflare.txt",
            set_name: "cloudflare",
            data: CLOUDFLARE_CIDRS,
        },
        EmbeddedCidrSource {
            name: "proxy.txt",
            set_name: "proxy",
            data: PROXY_CIDRS,
        },
    ]
}
