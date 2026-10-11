use crate::config::schema::ForwardHeadersConfig;
use crate::plugins::ip_intel::IpIntel;
use bytes::Bytes;
use http::HeaderValue;
use pingora_http::RequestHeader;
use std::net::IpAddr;

// ── IP-intel header forwarding ───────────────────────────────────────────────
// Optional (plugins.ip_intel.forward_headers). When enabled, every request sent
// to the upstream first has all client-sent headers with the configured prefix
// removed, so clients cannot spoof them, and then gets the gateway's own values
// (X-QG-Country, X-QG-Datacenter, ...). Fields with no value are left out.

pub const DEFAULT_PREFIX: &str = "X-QG-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardField {
    ClientIp,
    Country,
    Region,
    City,
    Asn,
    AsOrg,
    Provider,
    IsDatacenter,
    IsVpn,
    IsProxy,
    IsTor,
    IsMobile,
    NetworkType,
    RiskScore,
}

/// (config name, header suffix, field) — the order headers are sent in.
const FIELDS: &[(&str, &str, ForwardField)] = &[
    ("client_ip", "Client-IP", ForwardField::ClientIp),
    ("country", "Country", ForwardField::Country),
    ("region", "Region", ForwardField::Region),
    ("city", "City", ForwardField::City),
    ("asn", "ASN", ForwardField::Asn),
    ("as_org", "AS-Org", ForwardField::AsOrg),
    ("provider", "Provider", ForwardField::Provider),
    ("is_datacenter", "Datacenter", ForwardField::IsDatacenter),
    ("is_vpn", "VPN", ForwardField::IsVpn),
    ("is_proxy", "Proxy", ForwardField::IsProxy),
    ("is_tor", "Tor", ForwardField::IsTor),
    ("is_mobile", "Mobile", ForwardField::IsMobile),
    ("network_type", "Network-Type", ForwardField::NetworkType),
    ("risk_score", "Risk-Score", ForwardField::RiskScore),
];

#[derive(Debug, Clone)]
pub struct CompiledForwardHeaders {
    /// Lowercase prefix, used to strip client-sent copies.
    prefix_lower: String,
    /// Header names are built once at config load; cloning `Bytes` is a refcount bump.
    headers: Vec<(ForwardField, Bytes)>,
}

pub fn compile_forward_headers(cfg: &ForwardHeadersConfig) -> Result<Option<CompiledForwardHeaders>, String> {
    if !cfg.enabled {
        return Ok(None);
    }

    let prefix = cfg.prefix.trim();
    let prefix_lower = prefix.to_ascii_lowercase();
    // The prefix also decides which incoming headers get stripped, so a short
    // one like "X-" would delete X-Forwarded-For and friends.
    if !prefix.ends_with('-') || prefix_lower == "x-" || prefix.len() < 3 {
        return Err(format!(
            "ip_intel.forward_headers.prefix '{}' must end with '-' and can't be just 'X-' (e.g. \"X-QG-\")",
            cfg.prefix
        ));
    }

    let selected: Vec<ForwardField> = match &cfg.fields {
        None => FIELDS.iter().map(|(_, _, f)| *f).collect(),
        Some(names) => {
            let mut out = Vec::with_capacity(names.len());
            for name in names {
                let field = FIELDS
                    .iter()
                    .find(|(n, _, _)| *n == name.as_str())
                    .map(|(_, _, f)| *f)
                    .ok_or_else(|| {
                        let valid: Vec<&str> = FIELDS.iter().map(|(n, _, _)| *n).collect();
                        format!("ip_intel.forward_headers.fields: unknown field '{}' (valid: {})", name, valid.join(", "))
                    })?;
                if !out.contains(&field) {
                    out.push(field);
                }
            }
            out
        }
    };

    let mut headers = Vec::with_capacity(selected.len());
    for (_, suffix, field) in FIELDS {
        if !selected.contains(field) {
            continue;
        }
        let name = format!("{}{}", prefix, suffix);
        http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("ip_intel.forward_headers.prefix '{}' is not a valid header name", cfg.prefix))?;
        headers.push((*field, Bytes::from(name)));
    }

    Ok(Some(CompiledForwardHeaders { prefix_lower, headers }))
}

impl CompiledForwardHeaders {
    pub fn apply(&self, req: &mut RequestHeader, intel: Option<&IpIntel>, client_ip: IpAddr) {
        // Strip spoofed copies. Collecting into an empty Vec does not allocate,
        // which is the normal case.
        let spoofed: Vec<http::HeaderName> = req
            .headers
            .keys()
            .filter(|n| n.as_str().starts_with(self.prefix_lower.as_str()))
            .cloned()
            .collect();
        for name in &spoofed {
            req.remove_header(name);
        }

        for (field, name) in &self.headers {
            if let Some(value) = field_value(*field, intel, client_ip) {
                let _ = req.insert_header(name.clone(), value);
            }
        }
    }
}

fn field_value(field: ForwardField, intel: Option<&IpIntel>, client_ip: IpAddr) -> Option<HeaderValue> {
    if field == ForwardField::ClientIp {
        return HeaderValue::from_str(&client_ip.to_string()).ok();
    }
    let intel = intel?;
    match field {
        ForwardField::ClientIp => None,
        ForwardField::Country => text(intel.country.as_deref()),
        ForwardField::Region => text(intel.region.as_deref()),
        ForwardField::City => text(intel.city.as_deref()),
        ForwardField::Asn => intel.asn.map(HeaderValue::from),
        ForwardField::AsOrg => text(intel.as_org.as_deref()),
        ForwardField::Provider => text(intel.provider.as_deref()),
        ForwardField::IsDatacenter => flag(intel.is_datacenter),
        ForwardField::IsVpn => flag(intel.is_vpn),
        ForwardField::IsProxy => flag(intel.is_proxy),
        ForwardField::IsTor => flag(intel.is_tor),
        ForwardField::IsMobile => flag(intel.is_mobile),
        ForwardField::NetworkType => text(intel.network_type.as_deref()),
        ForwardField::RiskScore => intel.risk_score.map(|n| HeaderValue::from(u16::from(n))),
    }
}

fn flag(v: Option<bool>) -> Option<HeaderValue> {
    v.map(|b| HeaderValue::from_static(if b { "true" } else { "false" }))
}

/// Plain ASCII values are sent as-is; anything else (e.g. "Zürich") is
/// percent-encoded as UTF-8 so it is always a valid header value.
fn text(v: Option<&str>) -> Option<HeaderValue> {
    let s = v?.trim();
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| (0x20..0x7f).contains(&b) && b != b'%') {
        return HeaderValue::from_str(s).ok();
    }
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if (0x20..0x7f).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    HeaderValue::from_str(&out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(prefix: &str, fields: Option<Vec<&str>>) -> ForwardHeadersConfig {
        ForwardHeadersConfig {
            enabled: true,
            prefix: prefix.to_string(),
            fields: fields.map(|f| f.into_iter().map(String::from).collect()),
        }
    }

    fn intel() -> IpIntel {
        IpIntel {
            country: Some("CH".into()),
            region: Some("Zurich".into()),
            city: Some("Zürich".into()),
            asn: Some(16509),
            as_org: Some("Amazon.com, Inc.".into()),
            provider: Some("Amazon.com, Inc.".into()),
            is_vpn: Some(false),
            is_proxy: Some(false),
            is_datacenter: Some(true),
            is_mobile: None,
            is_residential: Some(false),
            is_residential_proxy: Some(false),
            is_tor: Some(false),
            network_type: None,
            risk_score: Some(10),
            source_versions: vec![],
        }
    }

    fn get<'a>(req: &'a RequestHeader, name: &str) -> Option<&'a str> {
        req.headers.get(name).and_then(|v| v.to_str().ok())
    }

    #[test]
    fn disabled_compiles_to_none() {
        let mut c = cfg(DEFAULT_PREFIX, None);
        c.enabled = false;
        assert!(compile_forward_headers(&c).unwrap().is_none());
    }

    #[test]
    fn strips_spoofed_and_sets_values() {
        let fh = compile_forward_headers(&cfg(DEFAULT_PREFIX, None)).unwrap().unwrap();
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-QG-Datacenter", "false").unwrap();
        req.insert_header("x-qg-made-up", "1").unwrap();
        req.insert_header("X-Forwarded-For", "1.2.3.4").unwrap();

        fh.apply(&mut req, Some(&intel()), "203.0.113.7".parse().unwrap());

        assert_eq!(get(&req, "x-qg-datacenter"), Some("true"));
        assert_eq!(get(&req, "x-qg-made-up"), None);
        assert_eq!(get(&req, "x-forwarded-for"), Some("1.2.3.4"));
        assert_eq!(get(&req, "x-qg-client-ip"), Some("203.0.113.7"));
        assert_eq!(get(&req, "x-qg-country"), Some("CH"));
        assert_eq!(get(&req, "x-qg-city"), Some("Z%C3%BCrich"));
        assert_eq!(get(&req, "x-qg-asn"), Some("16509"));
        assert_eq!(get(&req, "x-qg-risk-score"), Some("10"));
        // Unknown values are left out, not sent empty.
        assert_eq!(get(&req, "x-qg-mobile"), None);
        assert_eq!(get(&req, "x-qg-network-type"), None);
    }

    #[test]
    fn field_selection_and_custom_prefix() {
        let fh = compile_forward_headers(&cfg("X-Edge-", Some(vec!["country", "is_datacenter"]))).unwrap().unwrap();
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        fh.apply(&mut req, Some(&intel()), "203.0.113.7".parse().unwrap());
        assert_eq!(get(&req, "x-edge-country"), Some("CH"));
        assert_eq!(get(&req, "x-edge-datacenter"), Some("true"));
        assert_eq!(get(&req, "x-edge-client-ip"), None);
        assert_eq!(req.headers.len(), 2);
    }

    #[test]
    fn no_intel_still_sends_client_ip() {
        let fh = compile_forward_headers(&cfg(DEFAULT_PREFIX, None)).unwrap().unwrap();
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        fh.apply(&mut req, None, "2001:db8::1".parse().unwrap());
        assert_eq!(get(&req, "x-qg-client-ip"), Some("2001:db8::1"));
        assert_eq!(req.headers.len(), 1);
    }

    #[test]
    fn rejects_bad_config() {
        assert!(compile_forward_headers(&cfg("X-", None)).is_err());
        assert!(compile_forward_headers(&cfg("X-QG", None)).is_err());
        assert!(compile_forward_headers(&cfg("X QG-", None)).is_err());
        assert!(compile_forward_headers(&cfg(DEFAULT_PREFIX, Some(vec!["colour"]))).is_err());
    }
}
