use crate::config::CompiledConfig;
use crate::gateway::request_context::RequestContext;
use crate::plugins::PluginFlow;
use crate::utils::cidr::CidrSet;
use crate::utils::embedded_data;
use crate::utils::sharded_lru::ShardedLruCache;
use maxminddb::Reader;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{error, info};

// ── IP Intelligence Plugin ───────────────────────────────────────────────────
// All data is embedded in the binary — zero downloads required.
//
// MMDB databases (include_bytes!):
//   dbip-city-lite.mmdb  — Country, Region, City, Lat/Lon
//   dbip-asn-lite.mmdb   — ASN number + Organization
//   dbip-country.mmdb    — Country-only (fallback)
//
// CIDR lists (include_str!):
//   vpn.txt, tor.txt, cloudflare.txt, proxy.txt
//
// ASN lists (include_str!):
//   provider-asns.txt — 'ASN|Label' registry (e.g. 47583|Hostinger)
//   hosting-asns.txt  — bare ASNs known for hosting/abuse
//
// Datacenter detection is ASN-based: the ASN MMDB resolves the client IP to its
// ASN, and the ASN lists classify the network. No datacenter IP ranges needed —
// the ASN already identifies the provider (Hostinger, Hetzner, AWS, …).

/// Default LRU cache size — 65,536 entries (2^16) for high-traffic scenarios.
/// Override via QUAYEL_IP_INTEL_CACHE_SIZE env var.
const DEFAULT_CACHE_SIZE: usize = 65_536;

#[derive(Debug)]
pub struct IpIntelPlugin {
    /// Embedded MMDB readers for geo lookups
    geo_reader: Option<Reader<&'static [u8]>>,
    /// Embedded MMDB reader for ASN lookups
    asn_reader: Option<Reader<&'static [u8]>>,
    /// Embedded MMDB reader for country fallback
    country_reader: Option<Reader<&'static [u8]>>,
    /// CIDR sets for threat detection
    cidr_sets: HashMap<String, CidrSet>,
    /// Provider registry: ASN → provider label (from provider-asns.txt)
    provider_asns: HashMap<u32, String>,
    /// ASNs known for hosting/abuse (from hosting-asns.txt)
    hosting_asns: HashSet<u32>,
    /// Sharded LRU cache for IP lookups — reduces lock contention under concurrency.
    /// 64 shards with independent RwLocks, so requests for different IPs rarely contend.
    cache: Arc<ShardedLruCache<IpAddr, Arc<IpIntel>>>,
}

/// MaxMind GeoIP City record structure
#[derive(Debug, Deserialize)]
struct MaxMindCity {
    city: Option<MaxMindCityName>,
    country: Option<MaxMindCountry>,
    location: Option<MaxMindLocation>,
    subdivisions: Option<Vec<MaxMindSubdivision>>,
    postal: Option<MaxMindPostal>,
}

#[derive(Debug, Deserialize)]
struct MaxMindCityName {
    names: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct MaxMindCountry {
    #[serde(rename = "iso_code")]
    iso_code: Option<String>,
    names: Option<HashMap<String, String>>,
    #[serde(rename = "geoname_id")]
    geoname_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct MaxMindLocation {
    latitude: Option<f64>,
    longitude: Option<f64>,
    #[serde(rename = "time_zone")]
    time_zone: Option<String>,
    #[serde(rename = "metro_code")]
    metro_code: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct MaxMindSubdivision {
    #[serde(rename = "iso_code")]
    iso_code: Option<String>,
    names: Option<HashMap<String, String>>,
    #[serde(rename = "geoname_id")]
    geoname_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct MaxMindPostal {
    code: Option<String>,
}

/// MaxMind ASN record structure
#[derive(Debug, Deserialize)]
struct MaxMindAsn {
    #[serde(rename = "autonomous_system_number")]
    autonomous_system_number: Option<u32>,
    #[serde(rename = "autonomous_system_organization")]
    autonomous_system_organization: Option<String>,
}

/// MaxMind Country-only record structure
#[derive(Debug, Deserialize)]
struct MaxMindCountryOnly {
    country: Option<MaxMindCountry>,
    registered_country: Option<MaxMindCountry>,
}

/// Edge type detected from client IP
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeType {
    /// Request came through Cloudflare
    Cloudflare,
    /// Request came through a reverse proxy
    Proxy,
    /// Direct connection
    Direct,
}

impl IpIntelPlugin {
    /// Resolve cache size from env var or fall back to DEFAULT_CACHE_SIZE
    fn resolve_cache_size() -> NonZeroUsize {
        let size = std::env::var("QUAYEL_IP_INTEL_CACHE_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_CACHE_SIZE);
        NonZeroUsize::new(size).unwrap()
    }

    pub fn new() -> Self {
        let cache_cap = Self::resolve_cache_size();
        info!("IP Intel sharded LRU cache capacity: {} entries (64 shards)", cache_cap);

        let mut plugin = Self {
            geo_reader: None,
            asn_reader: None,
            country_reader: None,
            cidr_sets: HashMap::new(),
            provider_asns: HashMap::new(),
            hosting_asns: HashSet::new(),
            cache: Arc::new(ShardedLruCache::new(cache_cap.get())),
        };

        plugin.load_embedded_mmdb();
        plugin.load_embedded_cidr_sets();
        plugin.load_embedded_asn_sets();

        plugin
    }

    /// Load MMDB readers from embedded binary data
    fn load_embedded_mmdb(&mut self) {
        // City geolocation
        match Reader::from_source(embedded_data::DBIP_CITY_MMDB) {
            Ok(reader) => {
                info!(
                    "Loaded embedded city MMDB ({} bytes, IPv{} support)",
                    embedded_data::DBIP_CITY_MMDB.len(),
                    if reader.metadata.ip_version == 6 { "4+6" } else { "4" }
                );
                self.geo_reader = Some(reader);
            }
            Err(e) => error!("Failed to load embedded city MMDB: {}", e),
        }

        // ASN lookup
        match Reader::from_source(embedded_data::DBIP_ASN_MMDB) {
            Ok(reader) => {
                info!(
                    "Loaded embedded ASN MMDB ({} bytes)",
                    embedded_data::DBIP_ASN_MMDB.len()
                );
                self.asn_reader = Some(reader);
            }
            Err(e) => error!("Failed to load embedded ASN MMDB: {}", e),
        }

        // Country fallback
        match Reader::from_source(embedded_data::DBIP_COUNTRY_MMDB) {
            Ok(reader) => {
                info!(
                    "Loaded embedded country MMDB ({} bytes)",
                    embedded_data::DBIP_COUNTRY_MMDB.len()
                );
                self.country_reader = Some(reader);
            }
            Err(e) => error!("Failed to load embedded country MMDB: {}", e),
        }
    }

    /// Load CIDR sets from embedded data
    fn load_embedded_cidr_sets(&mut self) {
        let mut loaded = 0usize;

        for source in embedded_data::all_cidr_sources() {
            let lines: Vec<String> = source
                .data
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();

            if lines.is_empty() {
                continue;
            }

            let cidr_set = CidrSet::from_lines(source.set_name, &lines);
            let count = cidr_set.len();
            if count == 0 {
                continue;
            }
            self.cidr_sets.insert(source.set_name.to_string(), cidr_set);
            info!(
                "Loaded {} CIDR ranges for '{}' (embedded, {} bytes)",
                count,
                source.set_name,
                source.data.len()
            );
            loaded += 1;
        }

        info!("Loaded {} embedded CIDR sets total", loaded);
    }

    /// Load ASN sets from embedded data.
    ///
    /// provider-asns.txt  'ASN|Label' (e.g. 47583|Hostinger) — the provider
    ///                     registry. One line per ASN; edit to add providers.
    /// hosting-asns.txt   bare ASNs known for hosting/abuse (bad-asn-list).
    fn load_embedded_asn_sets(&mut self) {
        // ── provider registry ──────────────────────────────────────────────
        let mut providers = 0usize;
        for line in embedded_data::PROVIDER_ASNS.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((asn_str, label)) = line.split_once('|') {
                if let Ok(asn) = asn_str.trim().parse::<u32>() {
                    let label = label.trim();
                    if !label.is_empty() {
                        self.provider_asns.insert(asn, label.to_string());
                        providers += 1;
                    }
                }
            }
        }
        info!(
            "Loaded {} provider ASNs ('ASN|Label' registry, embedded)",
            providers
        );

        // ── hosting/abuse ASNs ─────────────────────────────────────────────
        for line in embedded_data::HOSTING_ASNS.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(asn) = line.parse::<u32>() {
                self.hosting_asns.insert(asn);
            }
        }
        info!(
            "Loaded {} hosting ASNs for datacenter detection (embedded)",
            self.hosting_asns.len()
        );
    }

    /// Classify a network by its ASN: returns (is_datacenter, provider_label).
    /// The MMDB already resolved the IP to an ASN, and the ASN identifies the
    /// operator — no IP-range lists required.
    fn classify_asn(&self, asn: u32) -> (bool, Option<String>) {
        if let Some(label) = self.provider_asns.get(&asn) {
            return (true, Some(label.clone()));
        }
        (self.hosting_asns.contains(&asn), None)
    }

    /// Detect edge type from client IP
    pub fn detect_edge(&self, peer_ip: IpAddr) -> EdgeType {
        // Check if peer IP is in Cloudflare ranges
        if let Some(cf_set) = self.cidr_sets.get("cloudflare") {
            if cf_set.contains(peer_ip) {
                return EdgeType::Cloudflare;
            }
        }

        // Check if peer IP is private (reverse proxy)
        if crate::utils::ip::is_private_ip(peer_ip) {
            return EdgeType::Proxy;
        }

        EdgeType::Direct
    }

    pub async fn execute(
        &self,
        ctx: &mut RequestContext,
        config: &Arc<CompiledConfig>,
    ) -> PluginFlow {
        let _ip_intel_config = match &config.ip_intel {
            Some(c) if c.enabled => c,
            _ => return PluginFlow::Continue,
        };

        let client_ip = ctx.client_ip;

        let intel = self.lookup_ip(client_ip).await;

        ctx.ip_intel = Some(intel);

        PluginFlow::Continue
    }

    async fn lookup_ip(&self, ip: IpAddr) -> Arc<IpIntel> {
        // Check cache first — sharded cache uses read lock on one shard only.
        if let Some(cached) = self.cache.get(&ip) {
            return cached;
        }

        // Cache miss — perform full lookup
        let intel = self.do_lookup(ip).await;
        let intel = Arc::new(intel);

        // Insert into cache — write lock only on the target shard.
        // Other shards remain accessible during this write.
        self.cache.put(ip, intel.clone());

        intel
    }

    async fn do_lookup(&self, ip: IpAddr) -> IpIntel {
        let mut intel = IpIntel {
            country: None,
            region: None,
            city: None,
            asn: None,
            as_org: None,
            provider: None,
            is_vpn: None,
            is_proxy: None,
            is_datacenter: None,
            is_mobile: None,
            is_residential: None,
            is_residential_proxy: None,
            is_tor: None,
            network_type: None,
            risk_score: None,
            source_versions: Vec::new(),
        };

        // ── City / Geolocation lookup ──────────────────────────────────
        if let Some(reader) = &self.geo_reader {
            if let Ok(city) = reader.lookup::<MaxMindCity>(ip) {
                intel.country = city
                    .country
                    .as_ref()
                    .and_then(|c| c.iso_code.clone());
                intel.city = city
                    .city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en").cloned());
                intel.region = city
                    .subdivisions
                    .as_ref()
                    .and_then(|subs| subs.first())
                    .and_then(|s| s.iso_code.clone());
            }
        }

        // ── Country fallback lookup (if city didn't have it) ───────────
        if intel.country.is_none() {
            if let Some(reader) = &self.country_reader {
                if let Ok(rec) = reader.lookup::<MaxMindCountryOnly>(ip) {
                    intel.country = rec
                        .country
                        .as_ref()
                        .and_then(|c| c.iso_code.clone())
                        .or_else(|| {
                            rec.registered_country
                                .as_ref()
                                .and_then(|c| c.iso_code.clone())
                        });
                }
            }
        }

        // ── ASN lookup + provider classification ──────────────────────────
        // The ASN identifies the operator (Hostinger, Hetzner, AWS, …), so
        // datacenter detection needs no IP-range lists.
        if let Some(reader) = &self.asn_reader {
            if let Ok(asn_rec) = reader.lookup::<MaxMindAsn>(ip) {
                intel.asn = asn_rec.autonomous_system_number;
                intel.as_org = asn_rec.autonomous_system_organization;

                if let Some(asn) = intel.asn {
                    let (is_dc, provider) = self.classify_asn(asn);
                    intel.is_datacenter = Some(is_dc);
                    intel.provider = provider;
                }
            }
        }

        // ── CIDR-based threat detection ────────────────────────────────
        if let Some(vpn_set) = self.cidr_sets.get("vpn") {
            intel.is_vpn = Some(vpn_set.contains(ip));
        }

        if let Some(tor_set) = self.cidr_sets.get("tor") {
            intel.is_tor = Some(tor_set.contains(ip));
        }

        if let Some(proxy_set) = self.cidr_sets.get("proxy") {
            intel.is_proxy = Some(proxy_set.contains(ip));
        }

        // ── Network type classification ────────────────────────────────
        intel.network_type = classify_network_type(&intel);

        // ── Risk score calculation ─────────────────────────────────────
        intel.risk_score = Some(calculate_risk_score(&intel));

        intel
    }

    /// Clear the lookup cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Get cache stats
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.cache.len(), self.cache.capacity())
    }
}

/// Classify network type based on IP intel flags
fn classify_network_type(intel: &IpIntel) -> Option<String> {
    if intel.is_tor.unwrap_or(false) {
        return Some("tor".to_string());
    }
    if intel.is_vpn.unwrap_or(false) {
        return Some("vpn".to_string());
    }
    if intel.is_datacenter.unwrap_or(false) {
        return Some("datacenter".to_string());
    }
    if intel.is_residential_proxy.unwrap_or(false) {
        return Some("residential_proxy".to_string());
    }
    if intel.is_proxy.unwrap_or(false) {
        return Some("proxy".to_string());
    }
    if intel.is_mobile.unwrap_or(false) {
        return Some("mobile".to_string());
    }
    if intel.is_residential.unwrap_or(false) {
        return Some("residential".to_string());
    }
    None
}

/// Calculate risk score (0-100) based on IP intel flags
fn calculate_risk_score(intel: &IpIntel) -> u8 {
    let mut score: u32 = 0;

    if intel.is_tor.unwrap_or(false) {
        score += 40;
    }
    if intel.is_vpn.unwrap_or(false) {
        score += 25;
    }
    if intel.is_proxy.unwrap_or(false) {
        score += 20;
    }
    if intel.is_residential_proxy.unwrap_or(false) {
        score += 30;
    }
    if intel.is_datacenter.unwrap_or(false) {
        score += 10;
    }

    score.min(100) as u8
}

// ── IpIntel Result ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IpIntel {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    /// Hosting/cloud provider label from the ASN registry (e.g. "Hostinger")
    pub provider: Option<String>,
    pub is_vpn: Option<bool>,
    pub is_proxy: Option<bool>,
    pub is_datacenter: Option<bool>,
    pub is_mobile: Option<bool>,
    pub is_residential: Option<bool>,
    pub is_residential_proxy: Option<bool>,
    pub is_tor: Option<bool>,
    pub network_type: Option<String>,
    pub risk_score: Option<u8>,
    pub source_versions: Vec<SourceVersion>,
}

#[derive(Debug, Clone)]
pub struct SourceVersion {
    pub provider: String,
    pub dataset_id: String,
    pub version: String,
    pub loaded_at: String,
}

impl IpIntel {
    /// Get a field value by path (e.g. "country", "is_vpn", "asn")
    pub fn get_field(&self, field: &str) -> Option<Value> {
        match field {
            "country" => self.country.as_ref().map(|s| Value::String(s.clone())),
            "region" => self.region.as_ref().map(|s| Value::String(s.clone())),
            "city" => self.city.as_ref().map(|s| Value::String(s.clone())),
            "asn" => self.asn.map(|n| Value::Number(n.into())),
            "as_org" => self.as_org.as_ref().map(|s| Value::String(s.clone())),
            "provider" => self.provider.as_ref().map(|s| Value::String(s.clone())),
            "is_vpn" => self.is_vpn.map(Value::Bool),
            "is_proxy" => self.is_proxy.map(Value::Bool),
            "is_datacenter" => self.is_datacenter.map(Value::Bool),
            "is_mobile" => self.is_mobile.map(Value::Bool),
            "is_residential" => self.is_residential.map(Value::Bool),
            "is_residential_proxy" => self.is_residential_proxy.map(Value::Bool),
            "is_tor" => self.is_tor.map(Value::Bool),
            "network_type" => self.network_type.as_ref().map(|s| Value::String(s.clone())),
            "risk_score" => self.risk_score.map(|n| Value::Number(n.into())),
            _ => None,
        }
    }

    /// Check if the IP is from a specific country
    pub fn is_country(&self, country_code: &str) -> bool {
        self.country
            .as_ref()
            .map(|c| c.eq_ignore_ascii_case(country_code))
            .unwrap_or(false)
    }

    /// Get a summary string for logging
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        if let Some(country) = &self.country {
            parts.push(format!("country={}", country));
        }
        if let Some(city) = &self.city {
            parts.push(format!("city={}", city));
        }
        if let Some(asn) = self.asn {
            parts.push(format!("asn={}", asn));
        }
        if let Some(as_org) = &self.as_org {
            parts.push(format!("as_org={}", as_org));
        }
        if let Some(provider) = &self.provider {
            parts.push(format!("provider={}", provider));
        }
        if self.is_vpn.unwrap_or(false) {
            parts.push("vpn=true".to_string());
        }
        if self.is_tor.unwrap_or(false) {
            parts.push("tor=true".to_string());
        }
        if self.is_datacenter.unwrap_or(false) {
            parts.push("dc=true".to_string());
        }

        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin() -> IpIntelPlugin {
        IpIntelPlugin::new()
    }

    #[test]
    fn test_provider_registry_loaded() {
        let p = plugin();
        assert!(!p.provider_asns.is_empty(), "provider-asns.txt must parse");
        assert!(!p.hosting_asns.is_empty(), "hosting-asns.txt must parse");
    }

    #[test]
    fn test_classify_known_provider() {
        let p = plugin();
        // AS47583 = Hostinger — must be a labeled datacenter
        let (dc, label) = p.classify_asn(47583);
        assert!(dc);
        assert_eq!(label.as_deref(), Some("Hostinger"));
    }

    #[test]
    fn test_classify_cloud_giants() {
        let p = plugin();
        for (asn, name) in [
            (16509u32, "Amazon AWS"),
            (15169, "Google Cloud"),
            (8075, "Microsoft Azure"),
            (31898, "Oracle Cloud"),
        ] {
            let (dc, label) = p.classify_asn(asn);
            assert!(dc, "AS{} must be datacenter", asn);
            assert_eq!(label.as_deref(), Some(name), "AS{} label", asn);
        }
    }

    #[test]
    fn test_classify_hosting_asn_unlabeled() {
        let p = plugin();
        // 1442 is in bad-asn-list but not in the provider registry:
        // datacenter without a label
        if !p.provider_asns.contains_key(&1442) {
            let (dc, label) = p.classify_asn(1442);
            assert!(dc, "bad-asn-list ASN must be datacenter");
            assert_eq!(label, None);
        }
    }

    #[test]
    fn test_classify_clean_asn() {
        let p = plugin();
        // AS3320 (Deutsche Telekom) — residential ISP, not a provider
        let (dc, label) = p.classify_asn(3320);
        assert!(!dc);
        assert_eq!(label, None);
    }

    #[tokio::test]
    async fn test_lookup_sets_provider_and_datacenter() {
        let p = plugin();
        // Known Hostinger IP (185.28.23.0/24, AS47583) — resolved via the
        // embedded ASN MMDB
        let ip: IpAddr = "185.28.23.10".parse().unwrap();
        let intel = p.do_lookup(ip).await;
        assert_eq!(intel.asn, Some(47583));
        assert_eq!(intel.provider.as_deref(), Some("Hostinger"));
        assert_eq!(intel.is_datacenter, Some(true));
        assert_eq!(intel.network_type.as_deref(), Some("datacenter"));
    }
}