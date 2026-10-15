//! Layer 4 proxy (`streams` in config.json).
//!
//! Each stream has a listen address, or shares the HTTPS port and is picked
//! by TLS server name (SNI). Connections are forwarded byte for byte to one
//! of its targets (see `tcp.rs`); TLS can be passed through or terminated.
//! Listeners are opened at startup; everything else (targets, rules, SNI
//! names on existing ports, timeouts) follows config reloads.
//!
//! `EdgeApp` (in `edge.rs`) sits in front of the HTTP app on the shared
//! Pingora service and sends connections on a stream port to the stream
//! proxy instead.

pub mod edge;
pub mod health;
pub mod sni;
pub mod tcp;
pub mod udp;

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
    /// Stream ports, each with the streams that share it.
    pub listeners: Vec<Arc<CompiledListener>>,
    /// Streams without `listen`: picked by SNI on the HTTPS listener.
    pub https: SniRouter,
    /// UDP streams, one per port.
    pub udp: Vec<Arc<CompiledStream>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsHandling {
    /// Bytes forwarded as they are.
    Raw,
    /// TLS from the client forwarded untouched (routed by SNI).
    Passthrough,
    /// The gateway does TLS; the target gets plain bytes.
    Terminate,
}

#[derive(Debug)]
pub struct CompiledStream {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub protocol: StreamProtocol,
    /// None → shares the HTTPS listener.
    pub listen: Option<SocketAddr>,
    pub sni: Vec<Arc<str>>,
    pub tls: TlsHandling,
    /// Enabled targets only.
    pub targets: Vec<CompiledStreamTarget>,
    pub algorithm: StreamAlgorithm,
    /// Some only for `accepts_connections`.
    pub health_check: Option<HealthCheckConfig>,
    pub rules: Vec<CompiledStreamRule>,
    pub proxy_protocol: ProxyProtocolVersion,
    pub connect_timeout: Duration,
    pub idle: Option<Duration>,
    /// UDP: session cap (0 → none) and replies per session.
    pub max_sessions: u32,
    pub responses: Option<u32>,
    /// A rule reads `ip.*`, so IP intel is looked up even when the
    /// ip_intel plugin is off.
    pub needs_intel: bool,
}

impl CompiledStream {
    /// `scheme` in the access log.
    pub fn scheme(&self) -> &'static str {
        if self.protocol == StreamProtocol::Udp {
            return "udp";
        }
        match self.tls {
            TlsHandling::Raw => "tcp",
            TlsHandling::Passthrough | TlsHandling::Terminate => "tls",
        }
    }
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

/// One stream port.
#[derive(Debug)]
pub struct CompiledListener {
    pub listen: SocketAddr,
    /// Streams on this port picked by TLS server name.
    pub sni: SniRouter,
    /// The stream for connections no `sni` entry matches (or all of them
    /// when there are no `sni` entries).
    pub default: Option<Arc<CompiledStream>>,
}

impl CompiledListener {
    /// Does a connection have to be peeked for its server name? Only then:
    /// a plain port never waits for the client to speak first.
    pub fn routes_by_sni(&self) -> bool {
        !self.sni.is_empty()
    }
}

/// Server name → stream. Exact names first, then "*.rest" wildcards that
/// cover exactly one more label.
#[derive(Debug, Clone, Default)]
pub struct SniRouter {
    exact: HashMap<Box<str>, Arc<CompiledStream>>,
    wildcard: HashMap<Box<str>, Arc<CompiledStream>>,
}

impl SniRouter {
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    pub fn route(&self, name: &str) -> Option<&Arc<CompiledStream>> {
        if let Some(s) = self.exact.get(name) {
            return Some(s);
        }
        let (_, rest) = name.split_once('.')?;
        self.wildcard.get(rest)
    }

    fn insert(&mut self, name: &str, s: &Arc<CompiledStream>) -> Result<(), String> {
        let (map, key) = match name.strip_prefix("*.") {
            Some(rest) => (&mut self.wildcard, rest),
            None => (&mut self.exact, name),
        };
        if let Some(prev) = map.get(key) {
            return Err(format!(
                "streams[id={}]: sni {name:?} is already used by stream {}",
                s.id, prev.id
            ));
        }
        map.insert(Box::from(key), Arc::clone(s));
        Ok(())
    }
}

impl CompiledStreams {
    /// The stream port a connection arrived at.
    pub fn for_listener(&self, local: SocketAddr) -> Option<&Arc<CompiledListener>> {
        self.listeners
            .iter()
            .find(|l| l.listen == local)
            .or_else(|| {
                self.listeners
                    .iter()
                    .find(|l| listen_matches(l.listen, local))
            })
    }

    /// TCP stream ports (the HTTPS listener isn't included).
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.listeners.iter().map(|l| l.listen).collect()
    }

    /// UDP stream ports.
    pub fn udp_addrs(&self) -> Vec<SocketAddr> {
        self.udp.iter().filter_map(|s| s.listen).collect()
    }

    pub fn udp_for(&self, listen: SocketAddr) -> Option<&Arc<CompiledStream>> {
        self.udp.iter().find(|s| s.listen == Some(listen))
    }

    /// Does any stream terminate TLS (and so need certificates)?
    pub fn terminates_tls(&self) -> bool {
        self.list.iter().any(|s| s.tls == TlsHandling::Terminate)
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

/// Lowercase, no trailing dot; `*` only as a whole first label.
fn normalize_sni(where_: &str, name: &str) -> Result<String, String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let body = n.strip_prefix("*.").unwrap_or(&n);
    if body.is_empty() || body.contains('*') || body.contains(':') || body.contains('/') {
        return Err(format!(
            "{where_}: sni {name:?} must be a host name or \"*.example.com\""
        ));
    }
    Ok(n)
}

/// `https_listen` is where streams without `listen` attach; `https_open`
/// says whether that listener is opened anyway (Auto-SSL on).
pub fn compile_streams(
    raw: &[StreamConfig],
    listen_http: &str,
    listen_https: &str,
    auto_ssl: bool,
) -> Result<CompiledStreams, String> {
    let http = parse_listen(listen_http);
    let uses_https = raw.iter().any(|s| s.enabled && s.listen.is_none());
    let https = if auto_ssl || uses_https {
        Some(
            parse_listen(listen_https)
                .ok_or_else(|| format!("streams: can't parse listen.https {listen_https:?}"))?,
        )
    } else {
        None
    };
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
        let udp = s.protocol == StreamProtocol::Udp;
        if udp {
            let unsupported = [
                (!s.sni.is_empty(), "sni"),
                (s.tls.is_some(), "tls"),
                (
                    s.proxy_protocol != ProxyProtocolVersion::Off,
                    "proxy_protocol",
                ),
                (
                    s.health_check
                        .as_ref()
                        .is_some_and(|h| h.mode != HealthCheckMode::Off),
                    "health_check",
                ),
                (s.listen.is_none(), "a missing listen"),
            ];
            if let Some((_, what)) = unsupported.iter().find(|(bad, _)| *bad) {
                return Err(format!("{where_}: udp streams don't support {what}"));
            }
        } else if s.max_sessions != default_udp_max_sessions() || s.responses.is_some() {
            return Err(format!(
                "{where_}: max_sessions and responses are for udp streams"
            ));
        }
        let listen = match &s.listen {
            None => None,
            Some(l) => {
                let listen = l
                    .parse::<SocketAddr>()
                    .map_err(|_| format!("{where_}: listen must be ip:port, got {l:?}"))?;
                let tcp_ports: &[(Option<SocketAddr>, &str)] = if udp {
                    &[]
                } else {
                    &[(http, "listen.http"), (https, "listen.https")]
                };
                for &(other, what) in tcp_ports {
                    if let Some(o) = other {
                        if listens_overlap(listen, o) {
                            return Err(format!(
                                "{where_}: listen {listen} clashes with {what} ({o}); \
                                 leave listen out to share the HTTPS port by sni"
                            ));
                        }
                    }
                }
                if let Some(prev) = list.iter().find(|p| {
                    p.protocol == s.protocol
                        && p.listen
                            .is_some_and(|pl| (udp || pl != listen) && listens_overlap(pl, listen))
                }) {
                    return Err(format!(
                        "{where_}: listen {listen} clashes with stream {} ({})",
                        prev.id,
                        prev.listen.unwrap()
                    ));
                }
                Some(listen)
            }
        };
        let sni = s
            .sni
            .iter()
            .map(|n| normalize_sni(&where_, n).map(|n| Arc::from(n.as_str())))
            .collect::<Result<Vec<Arc<str>>, String>>()?;
        if listen.is_none() && sni.is_empty() {
            return Err(format!(
                "{where_}: needs a listen address, or sni names to share the HTTPS port"
            ));
        }
        let tls = match (s.tls, sni.is_empty()) {
            (Some(StreamTlsMode::Terminate), _) => {
                if !auto_ssl {
                    return Err(format!(
                        "{where_}: tls \"terminate\" needs plugins.auto_ssl (its certificates \
                         are used); use \"passthrough\" to let the target do TLS"
                    ));
                }
                TlsHandling::Terminate
            }
            (_, false) => TlsHandling::Passthrough,
            (_, true) => TlsHandling::Raw,
        };

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
            sni,
            tls,
            targets,
            algorithm: s.algorithm,
            health_check,
            rules,
            proxy_protocol: s.proxy_protocol,
            connect_timeout: Duration::from_secs(s.connect_timeout_secs.max(1)),
            idle: match (s.idle_secs, udp) {
                (Some(0), _) | (None, false) => None,
                (Some(n), _) => Some(Duration::from_secs(n)),
                (None, true) => Some(Duration::from_secs(UDP_IDLE_SECS)),
            },
            max_sessions: s.max_sessions,
            responses: s.responses.filter(|n| *n > 0),
            needs_intel,
        }));
    }

    // Group by port: SNI routes plus at most one default per port.
    let mut https_router = SniRouter::default();
    let mut ports: Vec<(SocketAddr, SniRouter, Option<Arc<CompiledStream>>)> = Vec::new();
    let mut udp = Vec::new();
    for s in &list {
        if s.protocol == StreamProtocol::Udp {
            udp.push(Arc::clone(s));
            continue;
        }
        let router = match s.listen {
            None => &mut https_router,
            Some(addr) => {
                let i = match ports.iter().position(|p| p.0 == addr) {
                    Some(i) => i,
                    None => {
                        ports.push((addr, SniRouter::default(), None));
                        ports.len() - 1
                    }
                };
                if s.sni.is_empty() {
                    if let Some(prev) = &ports[i].2 {
                        return Err(format!(
                            "streams[id={}]: listen {addr} is already used by stream {}; \
                             streams sharing a port need different sni names",
                            s.id, prev.id
                        ));
                    }
                    ports[i].2 = Some(Arc::clone(s));
                    continue;
                }
                &mut ports[i].1
            }
        };
        for name in &s.sni {
            router.insert(name, s)?;
        }
    }

    Ok(CompiledStreams {
        list,
        listeners: ports
            .into_iter()
            .map(|(listen, sni, default)| {
                Arc::new(CompiledListener {
                    listen,
                    sni,
                    default,
                })
            })
            .collect(),
        https: https_router,
        udp,
    })
}

/// How long a UDP session lives without traffic when idle_secs is omitted.
pub const UDP_IDLE_SECS: u64 = 30;

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
        compile_streams(&raw, "0.0.0.0:80", "0.0.0.0:443", true)
    }

    const TWO: &str = r#"[{"id":"pg","listen":"0.0.0.0:5432","targets":[
        {"id":"a","host":"10.0.0.1","port":5432},
        {"id":"b","host":"10.0.0.2","port":5432,"weight":300}]}]"#;

    #[test]
    fn listener_lookup_handles_wildcard_and_mapped_addresses() {
        let c = stream(TWO).unwrap();
        assert!(c.for_listener("10.1.2.3:5432".parse().unwrap()).is_some());
        assert_eq!(
            c.listeners[0].default.as_ref().unwrap().tls,
            TlsHandling::Raw
        );
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

    const T: &str = r#""targets":[{"id":"a","host":"h","port":1}]"#;

    #[test]
    fn sni_routes_on_shared_and_own_ports() {
        let c = stream(&format!(
            r#"[{{"id":"r","sni":["DB1.Example.com."],{T}}},
                {{"id":"w","sni":["*.wild.example.com"],"tls":"terminate",{T}}},
                {{"id":"p1","listen":"0.0.0.0:9000","sni":["a.test"],{T}}},
                {{"id":"p2","listen":"0.0.0.0:9000","sni":["b.test"],{T}}},
                {{"id":"pd","listen":"0.0.0.0:9000",{T}}}]"#
        ))
        .unwrap();
        let id = |s: Option<&Arc<CompiledStream>>| s.map(|s| s.id.to_string());
        assert_eq!(id(c.https.route("db1.example.com")), Some("r".into()));
        assert_eq!(id(c.https.route("x.wild.example.com")), Some("w".into()));
        assert_eq!(id(c.https.route("a.b.wild.example.com")), None);
        assert_eq!(id(c.https.route("wild.example.com")), None);
        assert_eq!(
            c.https.route("db1.example.com").unwrap().tls,
            TlsHandling::Passthrough
        );
        assert_eq!(c.listen_addrs().len(), 1);
        let l = c.for_listener("10.0.0.1:9000".parse().unwrap()).unwrap();
        assert!(l.routes_by_sni());
        assert_eq!(id(l.sni.route("b.test")), Some("p2".into()));
        assert_eq!(id(l.default.as_ref()), Some("pd".into()));
        assert!(c.terminates_tls());
    }

    #[test]
    fn udp_streams() {
        let c = stream(&format!(
            r#"[{{"id":"dns","protocol":"udp","listen":"0.0.0.0:53","responses":1,{T}}},
                {{"id":"dns-tcp","listen":"0.0.0.0:53",{T}}},
                {{"id":"quic","protocol":"udp","listen":"0.0.0.0:443","idle_secs":0,{T}}}]"#
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(c.udp.len(), 2);
        assert_eq!(c.listeners.len(), 1); // TCP 53 only
        let dns = c.udp_for("0.0.0.0:53".parse().unwrap()).unwrap();
        assert_eq!(dns.idle, Some(Duration::from_secs(UDP_IDLE_SECS)));
        assert_eq!(dns.responses, Some(1));
        assert_eq!(dns.max_sessions, 100_000);
        assert_eq!(dns.scheme(), "udp");
        assert_eq!(
            c.udp_for("0.0.0.0:443".parse().unwrap()).unwrap().idle,
            None
        );
        let e = |j: String| stream(&j).unwrap_err();
        assert!(e(format!(
            r#"[{{"id":"u","protocol":"udp","sni":["a.b"],"listen":"0.0.0.0:1",{T}}}]"#
        ))
        .contains("sni"));
        assert!(e(format!(r#"[{{"id":"u","protocol":"udp",{T}}}]"#)).contains("listen"));
        assert!(e(format!(
            r#"[{{"id":"t","listen":"0.0.0.0:1","responses":1,{T}}}]"#
        ))
        .contains("udp"));
        assert!(e(format!(
            r#"[{{"id":"u","protocol":"udp","listen":"0.0.0.0:9","targets":[{{"id":"a","host":"h","port":1}}]}},
                {{"id":"v","protocol":"udp","listen":"0.0.0.0:9",{T}}}]"#
        ))
        .contains("clashes"));
    }

    #[test]
    fn sni_config_errors() {
        let e = |j: String| stream(&j).unwrap_err();
        assert!(e(format!(r#"[{{"id":"x",{T}}}]"#)).contains("needs a listen"));
        assert!(e(format!(
            r#"[{{"id":"x","sni":["a.test"],{T}}},{{"id":"y","sni":["A.test"],{T}}}]"#
        ))
        .contains("already used by stream x"));
        assert!(e(format!(
            r#"[{{"id":"x","listen":"0.0.0.0:9000",{T}}},{{"id":"y","listen":"0.0.0.0:9000",{T}}}]"#
        ))
        .contains("need different sni"));
        assert!(e(format!(r#"[{{"id":"x","sni":["a.*.test"],{T}}}]"#)).contains("host name"));
        let raw: Vec<StreamConfig> = serde_json::from_str(&format!(
            r#"[{{"id":"x","listen":"0.0.0.0:9000","tls":"terminate",{T}}}]"#
        ))
        .unwrap();
        assert!(compile_streams(&raw, "0.0.0.0:80", "0.0.0.0:443", false)
            .unwrap_err()
            .contains("auto_ssl"));
        // Without Auto-SSL the HTTPS port is free unless a stream attaches to it.
        let raw: Vec<StreamConfig> =
            serde_json::from_str(&format!(r#"[{{"id":"x","listen":"0.0.0.0:443",{T}}}]"#)).unwrap();
        assert!(compile_streams(&raw, "0.0.0.0:80", "0.0.0.0:443", false).is_ok());
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
