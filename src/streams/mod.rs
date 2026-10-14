//! Layer 4 proxy (`streams` in config.json).
//!
//! Each stream owns a listen address. Connections to it are forwarded byte
//! for byte to one of its targets (see `tcp.rs`). Listeners are opened at
//! startup; everything else (targets, rules, timeouts) follows config reloads.
//!
//! `EdgeApp` (in `edge.rs`) sits in front of the HTTP app on the shared
//! Pingora service and sends connections on a stream port to the stream
//! proxy instead.

pub mod edge;
pub mod health;
pub mod tcp;

use crate::condition::CompiledCondition;
use crate::config::compiler::compile_conditions;
use crate::config::schema::*;
use dashmap::DashMap;
use rustc_hash::FxHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ── Compiled config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CompiledStreams {
    pub list: Vec<Arc<CompiledStream>>,
}

#[derive(Debug)]
pub struct CompiledStream {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub protocol: StreamProtocol,
    pub listen: SocketAddr,
    /// Enabled targets only.
    pub targets: Vec<CompiledStreamTarget>,
    pub algorithm: StreamAlgorithm,
    /// Some only for `accepts_connections`.
    pub health_check: Option<HealthCheckConfig>,
    pub rules: Vec<CompiledStreamRule>,
    pub proxy_protocol: ProxyProtocolVersion,
    pub connect_timeout: Duration,
    pub idle: Option<Duration>,
    /// A rule reads `ip.*`, so IP intel is looked up even when the
    /// ip_intel plugin is off.
    pub needs_intel: bool,
}

#[derive(Debug)]
pub struct CompiledStreamTarget {
    pub id: Arc<str>,
    pub host: Arc<str>,
    pub port: u16,
    pub weight: u32,
    /// "<stream id>|host:port": key for health and connection counts.
    pub key: Arc<str>,
}

#[derive(Debug)]
pub struct CompiledStreamRule {
    pub id: Arc<str>,
    pub conditions: Vec<CompiledCondition>,
    pub action: StreamRuleAction,
}

impl CompiledStreams {
    /// The stream listening on the address a connection arrived at.
    pub fn for_listener(&self, local: SocketAddr) -> Option<&Arc<CompiledStream>> {
        self.list
            .iter()
            .find(|s| s.listen == local)
            .or_else(|| self.list.iter().find(|s| listen_matches(s.listen, local)))
    }

    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        let mut v: Vec<SocketAddr> = self.list.iter().map(|s| s.listen).collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Does a connection accepted on `local` belong to a listener bound to
/// `listen`? `0.0.0.0` / `[::]` listeners take every address on their port.
pub fn listen_matches(listen: SocketAddr, local: SocketAddr) -> bool {
    listen.port() == local.port()
        && (listen.ip().is_unspecified() || canonical(listen.ip()) == canonical(local.ip()))
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Parse a listen string the way Pingora does ("ip:port" or "host:port").
pub fn parse_listen(s: &str) -> Option<SocketAddr> {
    s.parse()
        .ok()
        .or_else(|| s.to_socket_addrs().ok().and_then(|mut a| a.next()))
}

/// Do two listen addresses claim the same port (so binding both fails or
/// one would steal the other's connections)?
fn listens_overlap(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port()
        && (a.ip().is_unspecified()
            || b.ip().is_unspecified()
            || canonical(a.ip()) == canonical(b.ip()))
}

pub fn compile_streams(
    raw: &[StreamConfig],
    listen_http: &str,
    listen_https: Option<&str>,
) -> Result<CompiledStreams, String> {
    let http = parse_listen(listen_http);
    let https = listen_https.and_then(parse_listen);
    let mut ids = HashSet::new();
    let mut list: Vec<Arc<CompiledStream>> = Vec::new();

    for s in raw {
        let where_ = format!("streams[id={}]", s.id);
        if s.id.is_empty() {
            return Err("streams: every stream needs an id".into());
        }
        if !ids.insert(s.id.clone()) {
            return Err(format!("{where_}: duplicate id"));
        }
        if !s.enabled {
            continue;
        }
        let listen = s
            .listen
            .parse::<SocketAddr>()
            .map_err(|_| format!("{where_}: listen must be ip:port, got {:?}", s.listen))?;
        for (other, what) in [(http, "listen.http"), (https, "listen.https")] {
            if let Some(o) = other {
                if listens_overlap(listen, o) {
                    return Err(format!(
                        "{where_}: listen {listen} clashes with {what} ({o})"
                    ));
                }
            }
        }
        if let Some(prev) = list.iter().find(|p| listens_overlap(p.listen, listen)) {
            return Err(format!(
                "{where_}: listen {listen} clashes with stream {} ({})",
                prev.id, prev.listen
            ));
        }

        if s.targets.is_empty() {
            return Err(format!("{where_}: needs at least one target"));
        }
        if let Some(t) = s.targets.iter().find(|t| t.port == 0 || t.host.is_empty()) {
            return Err(format!("{where_}: target {} needs a host and a port", t.id));
        }
        let targets: Vec<CompiledStreamTarget> = s
            .targets
            .iter()
            .filter(|t| t.enabled)
            .map(|t| CompiledStreamTarget {
                id: Arc::from(t.id.as_str()),
                host: Arc::from(t.host.as_str()),
                port: t.port,
                weight: t.weight,
                key: Arc::from(format!("{}|{}:{}", s.id, t.host, t.port)),
            })
            .collect();

        let health_check = match &s.health_check {
            None => None,
            Some(h) => match h.mode {
                HealthCheckMode::Off => None,
                HealthCheckMode::AcceptsConnections => Some(h.clone()),
                HealthCheckMode::Https => {
                    return Err(format!(
                        "{where_}: health_check mode \"https\" isn't available for streams; \
                         use \"accepts_connections\""
                    ))
                }
            },
        };

        let rules: Vec<CompiledStreamRule> = s
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| CompiledStreamRule {
                id: Arc::from(r.id.as_str()),
                conditions: compile_conditions(&r.conditions),
                action: r.action,
            })
            .collect();
        let needs_intel = s
            .rules
            .iter()
            .flat_map(|r| r.conditions.iter())
            .any(|c| c.left.starts_with("ip."));

        list.push(Arc::new(CompiledStream {
            id: Arc::from(s.id.as_str()),
            name: Arc::from(s.name.as_deref().unwrap_or(&s.id)),
            protocol: s.protocol,
            listen,
            targets,
            algorithm: s.algorithm,
            health_check,
            rules,
            proxy_protocol: s.proxy_protocol,
            connect_timeout: Duration::from_secs(s.connect_timeout_secs.max(1)),
            idle: (s.idle_secs > 0).then(|| Duration::from_secs(s.idle_secs)),
            needs_intel,
        }));
    }
    Ok(CompiledStreams { list })
}

// ── Runtime state (balancing, health) ────────────────────────────────────────

#[derive(Debug, Default)]
pub struct StreamRuntime {
    rr: DashMap<Arc<str>, AtomicUsize>,
    /// Open connections per target key.
    active: DashMap<Arc<str>, Arc<AtomicU64>>,
    /// Health per target key; missing → healthy.
    pub health: DashMap<Arc<str>, bool>,
}

/// Counts one open connection to a target until dropped.
pub struct ActiveGuard(Arc<AtomicU64>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl StreamRuntime {
    pub fn is_healthy(&self, key: &str) -> bool {
        self.health.get(key).map(|h| *h).unwrap_or(true)
    }

    pub fn track(&self, t: &CompiledStreamTarget) -> ActiveGuard {
        let c = self
            .active
            .entry(Arc::clone(&t.key))
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone();
        c.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(c)
    }

    fn active(&self, key: &str) -> u64 {
        self.active
            .get(key)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Healthy targets in the order to try them: the algorithm's pick
    /// first, then the rest as fallbacks if connecting fails.
    pub fn order<'a>(
        &self,
        s: &'a CompiledStream,
        client_ip: IpAddr,
    ) -> Vec<&'a CompiledStreamTarget> {
        let mut up: Vec<&CompiledStreamTarget> = s
            .targets
            .iter()
            .filter(|t| self.is_healthy(&t.key))
            .collect();
        if up.len() <= 1 {
            return up;
        }
        let first = match s.algorithm {
            StreamAlgorithm::RoundRobin => self.next(&s.id) % up.len(),
            StreamAlgorithm::WeightedRoundRobin => {
                let total: u64 = up.iter().map(|t| t.weight as u64).sum();
                if total == 0 {
                    self.next(&s.id) % up.len()
                } else {
                    let mut pos = self.next(&s.id) as u64 % total;
                    let mut idx = 0;
                    for (i, t) in up.iter().enumerate() {
                        if pos < t.weight as u64 {
                            idx = i;
                            break;
                        }
                        pos -= t.weight as u64;
                    }
                    idx
                }
            }
            StreamAlgorithm::LeastConnections => {
                // Ties rotate so equal targets share new connections.
                let start = self.next(&s.id) % up.len();
                (0..up.len())
                    .map(|i| (start + i) % up.len())
                    .min_by_key(|&i| self.active(&up[i].key))
                    .unwrap_or(0)
            }
            StreamAlgorithm::IpHash => {
                // Rendezvous hashing: removing a target only moves its clients.
                up.iter()
                    .enumerate()
                    .max_by_key(|(_, t)| {
                        let mut h = FxHasher::default();
                        t.key.hash(&mut h);
                        client_ip.hash(&mut h);
                        h.finish()
                    })
                    .map(|(i, _)| i)
                    .unwrap_or(0)
            }
        };
        up.rotate_left(first);
        up
    }

    fn next(&self, stream_id: &Arc<str>) -> usize {
        if let Some(c) = self.rr.get(stream_id) {
            return c.fetch_add(1, Ordering::Relaxed);
        }
        self.rr
            .entry(Arc::clone(stream_id))
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed)
    }

    /// Forget health and counters of targets that are no longer configured.
    pub fn retain(&self, keys: &HashMap<Arc<str>, ()>) {
        self.health.retain(|k, _| keys.contains_key(k));
        self.active
            .retain(|k, c| keys.contains_key(k) || c.load(Ordering::Relaxed) > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(json: &str) -> Result<CompiledStreams, String> {
        let raw: Vec<StreamConfig> = serde_json::from_str(json).unwrap();
        compile_streams(&raw, "0.0.0.0:80", Some("0.0.0.0:443"))
    }

    const TWO: &str = r#"[{"id":"pg","listen":"0.0.0.0:5432","targets":[
        {"id":"a","host":"10.0.0.1","port":5432},
        {"id":"b","host":"10.0.0.2","port":5432,"weight":300}]}]"#;

    #[test]
    fn listener_lookup_handles_wildcard_and_mapped_addresses() {
        let c = stream(TWO).unwrap();
        assert!(c.for_listener("10.1.2.3:5432".parse().unwrap()).is_some());
        assert!(c
            .for_listener("[::ffff:10.1.2.3]:5432".parse().unwrap())
            .is_some());
        assert!(c.for_listener("10.1.2.3:5433".parse().unwrap()).is_none());
    }

    #[test]
    fn rejects_clashing_listens_and_bad_health_mode() {
        let e = stream(
            r#"[{"id":"x","listen":"127.0.0.1:443","targets":[{"id":"a","host":"h","port":1}]}]"#,
        );
        assert!(e.unwrap_err().contains("listen.https"));
        let e = stream(
            r#"[{"id":"x","listen":"0.0.0.0:9000","targets":[{"id":"a","host":"h","port":1}]},
                {"id":"y","listen":"127.0.0.1:9000","targets":[{"id":"a","host":"h","port":1}]}]"#,
        );
        assert!(e.unwrap_err().contains("clashes with stream x"));
        let e = stream(
            r#"[{"id":"x","listen":"0.0.0.0:9000","health_check":{"mode":"https"},
                 "targets":[{"id":"a","host":"h","port":1}]}]"#,
        );
        assert!(e.unwrap_err().contains("accepts_connections"));
        assert!(stream(r#"[{"id":"x","listen":"0.0.0.0:9000","targets":[]}]"#).is_err());
    }

    #[test]
    fn round_robin_rotates_and_skips_unhealthy() {
        let c = stream(TWO).unwrap();
        let s = &c.list[0];
        let rt = StreamRuntime::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let a = rt.order(s, ip)[0].id.clone();
        let b = rt.order(s, ip)[0].id.clone();
        assert_ne!(a, b);
        assert_eq!(rt.order(s, ip).len(), 2);
        rt.health.insert(Arc::clone(&s.targets[0].key), false);
        let o = rt.order(s, ip);
        assert_eq!(o.len(), 1);
        assert_eq!(&*o[0].id, "b");
    }

    #[test]
    fn weighted_and_ip_hash() {
        let raw = TWO.replace(
            r#""listen""#,
            r#""algorithm":"weighted_round_robin","listen""#,
        );
        let c = stream(&raw).unwrap();
        let rt = StreamRuntime::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let b = (0..400)
            .filter(|_| &*rt.order(&c.list[0], ip)[0].id == "b")
            .count();
        assert_eq!(b, 300);

        let raw = TWO.replace(r#""listen""#, r#""algorithm":"ip_hash","listen""#);
        let c = stream(&raw).unwrap();
        let first = rt.order(&c.list[0], ip)[0].id.clone();
        for _ in 0..10 {
            assert_eq!(rt.order(&c.list[0], ip)[0].id, first);
        }
    }

    #[test]
    fn least_connections_prefers_idle_target() {
        let raw = TWO.replace(r#""listen""#, r#""algorithm":"least_connections","listen""#);
        let c = stream(&raw).unwrap();
        let s = &c.list[0];
        let rt = StreamRuntime::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let _g1 = rt.track(&s.targets[0]);
        let _g2 = rt.track(&s.targets[0]);
        for _ in 0..4 {
            assert_eq!(&*rt.order(s, ip)[0].id, "b");
        }
    }
}
