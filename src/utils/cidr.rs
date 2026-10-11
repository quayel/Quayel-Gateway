// ── CIDR Range Checker ───────────────────────────────────────────────────────
// Fast CIDR range checking for IP classification (VPN, datacenter, tor, etc.)
// Uses binary search on sorted IP ranges for O(log n) lookups.

use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

/// A parsed CIDR range with start/end IP for fast binary search
#[derive(Debug, Clone)]
pub struct CidrRange {
    pub start: u128,
    pub end: u128,
    pub prefix_len: u8,
    pub original: String,
}

impl CidrRange {
    /// Parse a CIDR string (e.g., "192.168.1.0/24")
    pub fn parse(cidr: &str) -> Option<Self> {
        let cidr = cidr.trim();
        if cidr.is_empty() || cidr.starts_with('#') {
            return None;
        }

        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            // Try parsing as single IP
            if let Ok(ip) = cidr.parse::<IpAddr>() {
                let prefix_len = match ip {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                let num = ip_to_u128(ip);
                return Some(CidrRange {
                    start: num,
                    end: num,
                    prefix_len,
                    original: cidr.to_string(),
                });
            }
            return None;
        }

        let ip: IpAddr = parts[0].parse().ok()?;
        let prefix_len: u8 = parts[1].parse().ok()?;

        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_len > max_prefix {
            return None;
        }

        let ip_num = ip_to_u128(ip);
        let host_bits = max_prefix - prefix_len;
        let mask = if prefix_len == 0 {
            0u128
        } else {
            !0u128 << host_bits
        };

        let start = ip_num & mask;
        let end = start | ((1u128 << host_bits) - 1);

        Some(CidrRange {
            start,
            end,
            prefix_len,
            original: cidr.to_string(),
        })
    }

    /// Check if an IP is within this range
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip_num = ip_to_u128(ip);
        ip_num >= self.start && ip_num <= self.end
    }
}

/// Convert IP to u128 for comparison
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            u32::from_be_bytes(octets) as u128
        }
        IpAddr::V6(v6) => {
            let segments = v6.octets();
            u128::from_be_bytes(segments)
        }
    }
}

/// A collection of CIDR ranges optimized for fast lookups
#[derive(Debug, Clone)]
pub struct CidrSet {
    /// Sorted ranges for binary search (IPv4)
    ranges: Arc<Vec<CidrRange>>,
    /// Name/description for logging
    name: String,
}

impl CidrSet {
    /// Create a new empty CidrSet
    pub fn new(name: &str) -> Self {
        Self {
            ranges: Arc::new(Vec::new()),
            name: name.to_string(),
        }
    }

    /// Create a CidrSet from a list of CIDR strings
    pub fn from_lines(name: &str, lines: &[String]) -> Self {
        let mut ranges: Vec<CidrRange> = lines
            .iter()
            .filter_map(|line| CidrRange::parse(line))
            .collect();

        // Sort by start address for binary search
        ranges.sort_by_key(|r| r.start);

        info!("Loaded {} CIDR ranges for {}", ranges.len(), name);

        Self {
            ranges: Arc::new(ranges),
            name: name.to_string(),
        }
    }

    /// Check if an IP is in any of the ranges
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip_num = ip_to_u128(ip);

        // Binary search for the first range that could contain this IP
        let idx = self.ranges.binary_search_by(|r| {
            if r.end < ip_num {
                std::cmp::Ordering::Less
            } else if r.start > ip_num {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });

        match idx {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Get the number of ranges
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Get the name
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Parse a text file containing CIDRs (one per line)
pub fn parse_cidr_file(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Parse a CSV file with IP/CIDR in a specific column
pub fn parse_csv_cidrs(content: &str, column: usize) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        if let Some(field) = fields.get(column) {
            let field = field.trim().trim_matches('"');
            if !field.is_empty() {
                cidrs.push(field.to_string());
            }
        }
    }
    cidrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parse_ipv4() {
        let cidr = CidrRange::parse("192.168.1.0/24").unwrap();
        assert!(cidr.contains("192.168.1.1".parse().unwrap()));
        assert!(cidr.contains("192.168.1.255".parse().unwrap()));
        assert!(!cidr.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_parse_single_ip() {
        let cidr = CidrRange::parse("8.8.8.8").unwrap();
        assert!(cidr.contains("8.8.8.8".parse().unwrap()));
        assert!(!cidr.contains("8.8.8.9".parse().unwrap()));
    }

    #[test]
    fn test_cidr_set() {
        let lines = vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
            "# comment".to_string(),
            "172.16.0.0/12".to_string(),
        ];
        let set = CidrSet::from_lines("test", &lines);
        assert_eq!(set.len(), 3);
        assert!(set.contains("192.168.1.1".parse().unwrap()));
        assert!(set.contains("10.0.0.1".parse().unwrap()));
        assert!(set.contains("172.16.0.1".parse().unwrap()));
        assert!(!set.contains("8.8.8.8".parse().unwrap()));
    }
}
