//! Server-level limits and per-IP flood protection (the `server` config section).
//!
//! `compile_server` turns the raw config into durations and parsed CIDRs once
//! per config load. `IpTracker` holds the live per-IP counters: open
//! connections, new connections and requests in the current second, strikes
//! and bans. It lives in `GatewayState` so counters survive config reloads.

use crate::config::schema::ServerConfig;
use crate::utils::cidr::{parse_cidr_file, CidrRange, CidrSet};
use crate::utils::embedded_data::CLOUDFLARE_CIDRS;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Compiled settings ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledServer {
    pub workers: Option<usize>,
    pub header_timeout: Option<Duration>,
    /// None → keep-alive off.
    pub keepalive_secs: Option<u64>,
    pub body_read_timeout: Option<Duration>,
    /// server.timeouts.websocket_idle_secs; None → no limit.
    pub websocket_idle_timeout: Option<Duration>,
    pub response_write_timeout: Option<Duration>,
    pub upstream_connect_timeout: Option<Duration>,
    pub upstream_total_connect_timeout: Option<Duration>,
    pub upstream_read_timeout: Option<Duration>,
    pub upstream_write_timeout: Option<Duration>,
    pub upstream_idle_timeout: Option<Duration>,
    pub graceful_shutdown_secs: u64,
    /// 0 → no limit.
    pub max_header_bytes: usize,
    /// 0 → no limit.
    pub max_body_bytes: u64,
    pub max_requests_per_connection: Option<u32>,
    pub upstream_keepalive_pool_size: usize,
    /// None when `server.protection.enabled` is false.
    pub protection: Option<Arc<CompiledProtection>>,
    /// server.request_id.accept_incoming
    pub accept_incoming_request_id: bool,
    /// server.http2
    pub http2: bool,
}

#[derive(Debug)]
pub struct CompiledProtection {
    pub exempt: CidrSet,
    pub exempt_cloudflare: bool,
    pub max_connections_per_ip: u32,
    pub max_new_connections_per_ip_per_sec: u32,
    pub max_requests_per_ip_per_sec: u32,
    pub ban: Option<CompiledBan>,
}

#[derive(Debug, Clone, Copy)]
pub struct CompiledBan {
    pub strikes: u32,
    pub window_secs: u64,
    pub duration_secs: u64,
}

impl Default for CompiledServer {
    fn default() -> Self {
        compile_server(&ServerConfig::default()).expect("default server config compiles")
    }
}

fn secs(v: u64) -> Option<Duration> {
    (v > 0).then(|| Duration::from_secs(v))
}

pub fn compile_server(raw: &ServerConfig) -> Result<CompiledServer, String> {
    if raw.workers == Some(0) {
        return Err("server.workers must be at least 1 (omit it to use all CPU cores)".to_string());
    }

    let t = &raw.timeouts;
    let l = &raw.limits;
    let p = &raw.protection;

    let protection =
        if p.enabled {
            for cidr in &p.exempt_ips {
                if CidrRange::parse(cidr).is_none() {
                    return Err(format!(
                        "server.protection.exempt_ips: '{}' is not a valid IP or CIDR",
                        cidr
                    ));
                }
            }
            let b = &p.ban;
            let ban = (b.enabled && b.strikes > 0 && b.window_secs > 0 && b.duration_secs > 0)
                .then(|| CompiledBan {
                    strikes: b.strikes,
                    window_secs: b.window_secs,
                    duration_secs: b.duration_secs,
                });
            Some(Arc::new(CompiledProtection {
                exempt: CidrSet::from_lines("server.protection.exempt_ips", &p.exempt_ips),
                exempt_cloudflare: p.exempt_cloudflare,
                max_connections_per_ip: p.max_connections_per_ip,
                max_new_connections_per_ip_per_sec: p.max_new_connections_per_ip_per_sec,
                max_requests_per_ip_per_sec: p.max_requests_per_ip_per_sec,
                ban,
            }))
        } else {
            None
        };

    Ok(CompiledServer {
        workers: raw.workers,
        header_timeout: secs(t.header_secs),
        keepalive_secs: (t.keepalive_secs > 0).then_some(t.keepalive_secs),
        body_read_timeout: secs(t.body_read_secs),
        websocket_idle_timeout: secs(t.websocket_idle_secs),
        response_write_timeout: secs(t.response_write_secs),
        upstream_connect_timeout: secs(t.upstream_connect_secs),
        upstream_total_connect_timeout: secs(t.upstream_total_connect_secs),
        upstream_read_timeout: secs(t.upstream_read_secs),
        upstream_write_timeout: secs(t.upstream_write_secs),
        upstream_idle_timeout: secs(t.upstream_idle_secs),
        graceful_shutdown_secs: t.graceful_shutdown_secs,
        max_header_bytes: l.max_header_bytes,
        max_body_bytes: l.max_body_bytes,
        max_requests_per_connection: (l.max_requests_per_connection > 0)
            .then_some(l.max_requests_per_connection),
        upstream_keepalive_pool_size: l.upstream_keepalive_pool_size,
        protection,
        accept_incoming_request_id: raw.request_id.accept_incoming,
        http2: raw.http2,
    })
}

// ── Per-IP tracking ──────────────────────────────────────────────────────────

/// Why a connection or request was refused. Used in logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    Banned,
    ConnectionLimit,
    ConnectionRate,
    RequestRate,
    SlowHeaders,
    HeaderTooLarge,
    BodyTooLarge,
}

impl Violation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Violation::Banned => "banned",
            Violation::ConnectionLimit => "conn_limit",
            Violation::ConnectionRate => "conn_rate",
            Violation::RequestRate => "request_rate",
            Violation::SlowHeaders => "slow_headers",
            Violation::HeaderTooLarge => "header_too_large",
            Violation::BodyTooLarge => "body_too_large",
        }
    }
}

#[derive(Debug, Default)]
struct IpEntry {
    active: u32,
    conn_sec: u64,
    conn_count: u32,
    req_sec: u64,
    req_count: u32,
    strike_start: u64,
    strikes: u32,
    banned_until: u64,
}

pub struct IpTracker {
    entries: DashMap<IpAddr, IpEntry>,
    epoch: Instant,
    cloudflare: CidrSet,
}

impl IpTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            epoch: Instant::now(),
            cloudflare: CidrSet::from_lines(
                "cloudflare (protection)",
                &parse_cidr_file(CLOUDFLARE_CIDRS),
            ),
        })
    }

    /// Whole seconds since the tracker started. Starts at 1 so 0 means "never".
    fn now(&self) -> u64 {
        self.epoch.elapsed().as_secs() + 1
    }

    fn is_exempt(&self, p: &CompiledProtection, ip: IpAddr) -> bool {
        p.exempt.contains(ip) || (p.exempt_cloudflare && self.cloudflare.contains(ip))
    }

    /// Called once per accepted connection. The returned permit keeps the
    /// IP's open-connection count up until it is dropped.
    pub fn open_connection(
        self: &Arc<Self>,
        p: &CompiledProtection,
        ip: IpAddr,
    ) -> Result<ConnPermit, Violation> {
        if self.is_exempt(p, ip) {
            return Ok(ConnPermit { tracker: None, ip });
        }
        let now = self.now();
        let mut e = self.entries.entry(ip).or_default();
        if e.banned_until > now {
            return Err(Violation::Banned);
        }
        if e.conn_sec != now {
            e.conn_sec = now;
            e.conn_count = 0;
        }
        e.conn_count = e.conn_count.saturating_add(1);
        let violation = if p.max_new_connections_per_ip_per_sec > 0
            && e.conn_count > p.max_new_connections_per_ip_per_sec
        {
            Some(Violation::ConnectionRate)
        } else if p.max_connections_per_ip > 0 && e.active >= p.max_connections_per_ip {
            Some(Violation::ConnectionLimit)
        } else {
            None
        };
        if let Some(v) = violation {
            add_strike(&mut e, p.ban, now, ip, v);
            return Err(v);
        }
        e.active += 1;
        Ok(ConnPermit {
            tracker: Some(self.clone()),
            ip,
        })
    }

    /// Called once per request with the resolved client IP.
    /// Err(Banned) carries the seconds left on the ban.
    pub fn check_request(
        &self,
        p: &CompiledProtection,
        ip: IpAddr,
    ) -> Result<(), (Violation, u64)> {
        if self.is_exempt(p, ip) {
            return Ok(());
        }
        let now = self.now();
        let mut e = self.entries.entry(ip).or_default();
        if e.banned_until > now {
            return Err((Violation::Banned, e.banned_until - now));
        }
        if p.max_requests_per_ip_per_sec == 0 {
            return Ok(());
        }
        if e.req_sec != now {
            e.req_sec = now;
            e.req_count = 0;
        }
        e.req_count = e.req_count.saturating_add(1);
        if e.req_count > p.max_requests_per_ip_per_sec {
            add_strike(&mut e, p.ban, now, ip, Violation::RequestRate);
            let retry = if e.banned_until > now {
                e.banned_until - now
            } else {
                1
            };
            return Err((Violation::RequestRate, retry));
        }
        Ok(())
    }

    /// Record a violation detected elsewhere (slow headers, oversized request).
    pub fn strike(&self, p: &CompiledProtection, ip: IpAddr, v: Violation) {
        if self.is_exempt(p, ip) {
            return;
        }
        let now = self.now();
        let mut e = self.entries.entry(ip).or_default();
        add_strike(&mut e, p.ban, now, ip, v);
    }

    fn close_connection(&self, ip: IpAddr) {
        if let Some(mut e) = self.entries.get_mut(&ip) {
            e.active = e.active.saturating_sub(1);
        }
    }

    /// Drop entries with no open connections, no ban and no recent activity.
    pub fn cleanup(&self) {
        let now = self.now();
        self.entries.retain(|_, e| {
            let last = e.conn_sec.max(e.req_sec).max(e.strike_start);
            e.active > 0 || e.banned_until > now || now.saturating_sub(last) < 300
        });
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn spawn_cleanup_task(self: &Arc<Self>, handle: &tokio::runtime::Handle) {
        let tracker = self.clone();
        handle.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                tracker.cleanup();
            }
        });
    }
}

fn add_strike(e: &mut IpEntry, ban: Option<CompiledBan>, now: u64, ip: IpAddr, v: Violation) {
    let Some(ban) = ban else { return };
    if e.strike_start == 0 || now >= e.strike_start + ban.window_secs {
        e.strike_start = now;
        e.strikes = 0;
    }
    e.strikes += 1;
    if e.strikes >= ban.strikes {
        e.banned_until = now + ban.duration_secs;
        e.strikes = 0;
        tracing::warn!(
            client_ip = %ip,
            reason = v.as_str(),
            ban_secs = ban.duration_secs,
            "Protection: IP banned after {} violations in {}s",
            ban.strikes,
            ban.window_secs
        );
    }
}

/// Held for the lifetime of a downstream connection.
pub struct ConnPermit {
    tracker: Option<Arc<IpTracker>>,
    ip: IpAddr,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        if let Some(t) = &self.tracker {
            t.close_connection(self.ip);
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(json: &str) -> Result<CompiledServer, String> {
        let raw: ServerConfig = serde_json::from_str(json).map_err(|e| e.to_string())?;
        compile_server(&raw)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn defaults_apply_and_config_overrides_them() {
        let d = compile("{}").unwrap();
        assert_eq!(d.header_timeout, Some(Duration::from_secs(10)));
        assert_eq!(d.keepalive_secs, Some(60));
        assert_eq!(d.max_header_bytes, 32 * 1024);
        assert_eq!(d.max_body_bytes, 0, "no body limit by default");
        assert_eq!(
            d.websocket_idle_timeout, None,
            "no WebSocket idle limit by default"
        );
        assert!(d.protection.is_some());

        let c = compile(
            r#"{"timeouts":{"header_secs":3,"keepalive_secs":0,"websocket_idle_secs":300},"limits":{"max_body_bytes":1000}}"#,
        )
        .unwrap();
        assert_eq!(c.header_timeout, Some(Duration::from_secs(3)));
        assert_eq!(c.keepalive_secs, None);
        assert_eq!(c.max_body_bytes, 1000);
        assert_eq!(c.websocket_idle_timeout, Some(Duration::from_secs(300)));
        // Untouched fields keep their defaults.
        assert_eq!(c.body_read_timeout, Some(Duration::from_secs(60)));
    }

    #[test]
    fn private_ranges_are_exempt_by_default() {
        let s = compile(r#"{"protection":{"max_connections_per_ip":1}}"#).unwrap();
        let p = s.protection.unwrap();
        let t = IpTracker::new();
        for lb in ["10.0.0.5", "172.20.1.1", "192.168.1.10", "fd00::1"] {
            for _ in 0..5 {
                std::mem::forget(t.open_connection(&p, ip(lb)).unwrap());
            }
        }
        // Public IPs still get the limit.
        let _a = t.open_connection(&p, ip("203.0.113.9")).unwrap();
        assert!(t.open_connection(&p, ip("203.0.113.9")).is_err());
    }

    #[test]
    fn rejects_bad_values() {
        assert!(compile(r#"{"workers":0}"#).is_err());
        assert!(compile(r#"{"protection":{"exempt_ips":["not-an-ip"]}}"#).is_err());
        assert!(
            compile(r#"{"timeouts":{"header_sec":3}}"#).is_err(),
            "typos are rejected"
        );
        assert!(compile(r#"{"protection":{"enabled":false}}"#)
            .unwrap()
            .protection
            .is_none());
    }

    #[test]
    fn connection_limit_and_release() {
        let s = compile(
            r#"{"protection":{"max_connections_per_ip":2,"max_new_connections_per_ip_per_sec":0}}"#,
        )
        .unwrap();
        let p = s.protection.unwrap();
        let t = IpTracker::new();
        let a = t.open_connection(&p, ip("203.0.113.5")).unwrap();
        let _b = t.open_connection(&p, ip("203.0.113.5")).unwrap();
        assert_eq!(
            t.open_connection(&p, ip("203.0.113.5")).err(),
            Some(Violation::ConnectionLimit)
        );
        drop(a);
        assert!(t.open_connection(&p, ip("203.0.113.5")).is_ok());
        // Other IPs are unaffected; exempt IPs are never limited.
        assert!(t.open_connection(&p, ip("203.0.113.6")).is_ok());
        for _ in 0..10 {
            std::mem::forget(t.open_connection(&p, ip("127.0.0.1")).unwrap());
        }
    }

    #[test]
    fn cloudflare_edges_skip_limits_when_exempt() {
        let s = compile(r#"{"protection":{"max_connections_per_ip":1}}"#).unwrap();
        let p = s.protection.unwrap();
        let t = IpTracker::new();
        let cf = ip("104.16.0.1");
        let _a = t.open_connection(&p, cf).unwrap();
        assert!(t.open_connection(&p, cf).is_ok());

        let s = compile(r#"{"protection":{"max_connections_per_ip":1,"exempt_cloudflare":false}}"#)
            .unwrap();
        let p = s.protection.unwrap();
        let _a = t.open_connection(&p, cf).unwrap();
        assert!(t.open_connection(&p, cf).is_err());
    }

    #[test]
    fn request_flood_leads_to_ban() {
        let s = compile(r#"{"protection":{"max_requests_per_ip_per_sec":5,"ban":{"strikes":3,"duration_secs":60}}}"#).unwrap();
        let p = s.protection.unwrap();
        let t = IpTracker::new();
        let a = ip("198.51.100.7");
        for _ in 0..5 {
            assert!(t.check_request(&p, a).is_ok());
        }
        assert_eq!(
            t.check_request(&p, a).unwrap_err().0,
            Violation::RequestRate
        );
        assert_eq!(
            t.check_request(&p, a).unwrap_err().0,
            Violation::RequestRate
        );
        // Third strike bans the IP for both requests and new connections.
        let (_, retry) = t.check_request(&p, a).unwrap_err();
        assert!(retry > 1);
        assert_eq!(t.check_request(&p, a).unwrap_err().0, Violation::Banned);
        assert_eq!(t.open_connection(&p, a).err(), Some(Violation::Banned));
    }

    #[test]
    fn ban_disabled_never_bans() {
        let s =
            compile(r#"{"protection":{"max_requests_per_ip_per_sec":1,"ban":{"enabled":false}}}"#)
                .unwrap();
        let p = s.protection.unwrap();
        let t = IpTracker::new();
        let a = ip("198.51.100.8");
        for _ in 0..100 {
            let _ = t.check_request(&p, a);
        }
        assert!(t.open_connection(&p, a).is_ok());
    }
}
