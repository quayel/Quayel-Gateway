//! TCP stream proxy: one accepted connection → one target connection, bytes
//! copied both ways until either side closes.
//!
//! Per connection: per-IP connection limits and bans (server.protection),
//! the stream's `rules`, target choice with fallback to the next target when
//! connecting fails, an optional PROXY protocol header, an optional idle
//! timeout, and one access-log line when the connection ends.
//!
//! Log line fields for streams: `method` is "TCP", `scheme` "tcp" (or "tls"
//! for SNI-routed / TLS-terminated streams), `host` the TLS server name,
//! `path` the stream id, `req_bytes` / `bytes` the bytes from / to the
//! client, `dur_us` the whole connection and `upstream_us` the connect time.
//! `status` is 200 once the target connection is made, 403 when a rule
//! blocks, 421 when no stream on the port matches the server name, 502 when
//! no target accepts the connection, 503 when every target is unhealthy and
//! 504 when connecting timed out.

use crate::config::compiler::CompiledConfig;
use crate::config::schema::{ProxyProtocolVersion, StreamRuleAction};
use crate::gateway::gateway::GatewayState;
use crate::gateway::protection::ConnPermit;
use crate::gateway::request_context::{BlockResult, RequestContext};
use crate::gateway::request_id;
use crate::logging::event::LogEvent;
use crate::plugins::firewall::{deciding_conditions, evaluate_conditions};
use crate::streams::sni::{peek_sni, Peeked};
use crate::streams::{CompiledStream, CompiledStreamTarget, TlsHandling};
use pingora_core::listeners::tls::Acceptor;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::Stream;
use pingora_core::server::ShutdownWatch;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// Copy buffer per direction. Database pools keep many idle connections
/// open, so this stays small.
const COPY_BUF: usize = 16 * 1024;

/// One connection on a stream port.
pub async fn serve_port(
    state: &Arc<GatewayState>,
    mut stream: Stream,
    peer: SocketAddr,
    local: SocketAddr,
    tls: Option<&Acceptor>,
    shutdown: &ShutdownWatch,
) {
    let config = state.config.load_full();
    let Some(l) = config.streams.for_listener(local).cloned() else {
        // The stream was removed by a reload; its listener stays open until
        // the next restart.
        return;
    };
    let ip = peer.ip().to_canonical();
    let Ok(permit) = admit(state, &config, ip) else {
        return;
    };
    if !l.routes_by_sni() {
        if let Some(s) = &l.default {
            serve_stream(
                state, &config, s, stream, peer, local, None, permit, tls, shutdown,
            )
            .await;
        }
        return;
    }
    let started = Instant::now();
    let name = match peek_sni(&mut stream, config.server.header_timeout).await {
        Ok(Peeked::Tls(name)) => name,
        Ok(Peeked::Other) => None,
        Err(_) => return, // closed, or nothing arrived in time
    };
    let routed = name
        .as_deref()
        .and_then(|n| l.sni.route(n))
        .or(l.default.as_ref());
    let sni = name.map(|n| Arc::from(n.as_str()));
    match routed.cloned() {
        Some(s) => {
            serve_stream(
                state, &config, &s, stream, peer, local, sni, permit, tls, shutdown,
            )
            .await
        }
        None => {
            let mut line = ConnLog::new(&config, Arc::from(""), ip, sni, "tls");
            line.ev.ts_ms =
                request_id::now_ms().saturating_sub(started.elapsed().as_millis() as u64);
            let why = if line.ev.host.is_some() {
                "no stream for this server name"
            } else {
                "no server name (SNI) sent"
            };
            line.finish(state, 421, started, Some(why.into()));
        }
    }
}

/// server.protection applies to stream connections exactly as to HTTP ones
/// (and shares the same per-IP counters). Refusals aren't logged, same as
/// for HTTP connections.
pub fn admit(
    state: &GatewayState,
    config: &CompiledConfig,
    ip: IpAddr,
) -> Result<Option<ConnPermit>, ()> {
    match &config.server.protection {
        Some(p) => match state.ip_tracker.open_connection(p, ip) {
            Ok(pm) => Ok(Some(pm)),
            Err(v) => {
                tracing::debug!(client_ip = %ip, reason = v.as_str(), "Protection: stream connection refused");
                Err(())
            }
        },
        None => Ok(None),
    }
}

/// A connection already matched to a stream: terminate TLS if the stream
/// asks for it, then proxy.
#[allow(clippy::too_many_arguments)]
pub async fn serve_stream(
    state: &Arc<GatewayState>,
    config: &Arc<CompiledConfig>,
    s: &Arc<CompiledStream>,
    stream: Stream,
    peer: SocketAddr,
    local: SocketAddr,
    sni: Option<Arc<str>>,
    permit: Option<ConnPermit>,
    tls: Option<&Acceptor>,
    shutdown: &ShutdownWatch,
) {
    let client: Stream = if s.tls == TlsHandling::Terminate {
        let started = Instant::now();
        let fail = |e: String| {
            let mut line = ConnLog::new(
                config,
                Arc::clone(&s.id),
                peer.ip().to_canonical(),
                sni.clone(),
                "tls",
            );
            line.ev.ts_ms =
                request_id::now_ms().saturating_sub(started.elapsed().as_millis() as u64);
            line.finish(state, 400, started, Some(e));
        };
        let Some(acceptor) = tls else {
            fail("tls terminate: no certificates (Auto-SSL is off)".into());
            return;
        };
        let l4 = match stream.into_any().downcast::<L4Stream>() {
            Ok(l4) => *l4,
            Err(_) => return,
        };
        let handshake = acceptor.tls_handshake(l4);
        let done = match config.server.header_timeout {
            Some(d) => tokio::time::timeout(d, handshake).await.ok(),
            None => Some(handshake.await),
        };
        match done {
            Some(Ok(tls)) => Box::new(tls),
            Some(Err(e)) => {
                fail(format!("tls handshake: {e}"));
                return;
            }
            None => {
                fail("tls handshake: timed out".into());
                return;
            }
        }
    } else {
        stream
    };
    proxy(state, config, s, client, peer, local, sni, permit, shutdown).await;
}

/// Proxy `client` to one of the stream's targets. `sni` is the TLS server
/// name when the connection was routed by it.
#[allow(clippy::too_many_arguments)]
pub async fn proxy(
    state: &Arc<GatewayState>,
    config: &Arc<CompiledConfig>,
    s: &Arc<CompiledStream>,
    client: Stream,
    peer: SocketAddr,
    local: SocketAddr,
    sni: Option<Arc<str>>,
    _permit: Option<ConnPermit>,
    shutdown: &ShutdownWatch,
) {
    let started = Instant::now();
    let ip = peer.ip().to_canonical();
    let scheme = s.scheme();

    let mut line = ConnLog::new(config, Arc::clone(&s.id), ip, sni.clone(), scheme);

    if !check_rules(state, config, s, ip, sni, &mut line).await {
        line.finish(state, 403, started, None);
        return;
    }

    // Connect: the algorithm's pick first, the other healthy targets after.
    let order = state.streams.order(s, ip);
    if order.is_empty() {
        line.finish(state, 503, started, Some("no healthy target".into()));
        return;
    }
    let connect_started = Instant::now();
    let mut last_err = String::new();
    let mut timed_out = false;
    let mut connected: Option<(TcpStream, &CompiledStreamTarget)> = None;
    for t in order {
        let addr = format!("{}:{}", t.host, t.port);
        match tokio::time::timeout(s.connect_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(c)) => {
                connected = Some((c, t));
                break;
            }
            Ok(Err(e)) => {
                timed_out = false;
                last_err = format!("connect {addr}: {e}");
            }
            Err(_) => {
                timed_out = true;
                last_err = format!("connect {addr}: timed out");
            }
        }
        tracing::debug!(stream = %s.id, error = %last_err, "Stream target connect failed, trying next");
    }
    line.ev.upstream_us = connect_started.elapsed().as_micros() as u64;
    let Some((mut upstream, target)) = connected else {
        line.finish(
            state,
            if timed_out { 504 } else { 502 },
            started,
            Some(last_err),
        );
        return;
    };
    line.ev.upstream = Some(Arc::clone(&target.id));
    line.ev.upstream_host = Some(Arc::clone(&target.host));
    line.ev.upstream_port = target.port;
    let _active = state.streams.track(target);
    let _ = upstream.set_nodelay(true);

    if s.proxy_protocol != ProxyProtocolVersion::Off {
        let header = proxy_header(s.proxy_protocol, peer, local);
        if let Err(e) = upstream.write_all(&header).await {
            line.finish(
                state,
                502,
                started,
                Some(format!("proxy protocol header: {e}")),
            );
            return;
        }
    }

    let activity = s.idle.map(|_| Arc::new(AtomicU64::new(0)));
    let mut down = Counted::new(client, activity.clone(), started);
    let mut up = Counted::new(upstream, activity.clone(), started);
    let mut shutdown = shutdown.clone();
    let end: Option<String> = tokio::select! {
        r = tokio::io::copy_bidirectional_with_sizes(&mut down, &mut up, COPY_BUF, COPY_BUF) => match r {
            Ok(_) => None,
            Err(e) => Some(if down.failed { format!("client: {e}") } else { format!("upstream: {e}") }),
        },
        _ = idle_timer(s.idle, activity.as_deref(), started) => Some("idle timeout".into()),
        _ = shutdown.changed() => Some("gateway shutting down".into()),
    };
    line.ev.req_bytes = down.read;
    line.ev.bytes = down.written;
    line.finish(state, 200, started, end);
}

/// IP intel for the log line, then the stream's rules. false → blocked
/// (`line.ev.block` says by which rule).
pub(crate) async fn check_rules(
    state: &GatewayState,
    config: &CompiledConfig,
    s: &CompiledStream,
    ip: IpAddr,
    sni: Option<Arc<str>>,
    line: &mut ConnLog,
) -> bool {
    let scheme = s.scheme();
    if !s.rules.is_empty() || s.needs_intel || config.ip_intel.is_some() {
        let mut ctx = RequestContext::new(
            Arc::clone(&config.gateway_id),
            Arc::clone(&config.gateway_name),
            Arc::clone(&config.server_name),
            Arc::clone(&config.config_version),
            ip,
            ip,
            Arc::from("peer_ip"),
            sni,
            Arc::clone(&s.id),
            Arc::from(s.protocol.as_str().to_ascii_uppercase()),
            Arc::from(scheme),
            None,
            http::HeaderMap::new(),
        );
        if s.needs_intel || config.ip_intel.is_some() {
            ctx.ip_intel = Some(state.plugin_runner.ip_intel.lookup_ip(ip).await);
            line.ev.ip_intel = ctx.ip_intel.clone();
        }
        for rule in &s.rules {
            if !rule.conditions.is_empty() && !evaluate_conditions(&mut ctx, &rule.conditions) {
                continue;
            }
            match rule.action {
                StreamRuleAction::Allow => {
                    line.ev.allow_rule = Some(Arc::clone(&rule.id));
                }
                StreamRuleAction::Block => {
                    let key = if rule.conditions.is_empty() {
                        format!("client_ip={ip}")
                    } else {
                        deciding_conditions(&mut ctx, &rule.conditions)
                    };
                    line.ev.block = BlockResult {
                        kind: "stream",
                        action: "block",
                        rule: Some(Arc::clone(&rule.id)),
                        key,
                    };
                    return false;
                }
            }
            break;
        }
    }
    true
}

/// Resolves when nothing has moved in either direction for `idle`.
async fn idle_timer(idle: Option<Duration>, activity: Option<&AtomicU64>, base: Instant) {
    let (Some(idle), Some(activity)) = (idle, activity) else {
        return std::future::pending().await;
    };
    let idle_ms = idle.as_millis() as u64;
    loop {
        let last = activity.load(Ordering::Relaxed);
        let now = base.elapsed().as_millis() as u64;
        if now >= last + idle_ms {
            return;
        }
        tokio::time::sleep(Duration::from_millis(last + idle_ms - now)).await;
    }
}

// ── PROXY protocol ───────────────────────────────────────────────────────────

const PP2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// PROXY protocol header for a connection from `src` that arrived at `dst`.
pub fn proxy_header(v: ProxyProtocolVersion, src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let (sip, dip) = (src.ip().to_canonical(), dst.ip().to_canonical());
    match v {
        ProxyProtocolVersion::Off => Vec::new(),
        ProxyProtocolVersion::V1 => match (sip, dip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                format!("PROXY TCP4 {s} {d} {} {}\r\n", src.port(), dst.port()).into_bytes()
            }
            (s, d) => {
                let (s, d) = (to_v6(s), to_v6(d));
                format!("PROXY TCP6 {s} {d} {} {}\r\n", src.port(), dst.port()).into_bytes()
            }
        },
        ProxyProtocolVersion::V2 => {
            let mut out = PP2_SIG.to_vec();
            out.push(0x21); // version 2, PROXY command
            match (sip, dip) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    out.push(0x11); // TCP over IPv4
                    out.extend_from_slice(&12u16.to_be_bytes());
                    out.extend_from_slice(&s.octets());
                    out.extend_from_slice(&d.octets());
                }
                (s, d) => {
                    out.push(0x21); // TCP over IPv6
                    out.extend_from_slice(&36u16.to_be_bytes());
                    out.extend_from_slice(&to_v6(s).octets());
                    out.extend_from_slice(&to_v6(d).octets());
                }
            }
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&dst.port().to_be_bytes());
            out
        }
    }
}

fn to_v6(ip: IpAddr) -> std::net::Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

// ── Access log line ──────────────────────────────────────────────────────────

pub(crate) struct ConnLog {
    pub(crate) ev: LogEvent,
}

impl ConnLog {
    pub(crate) fn new(
        config: &CompiledConfig,
        path: Arc<str>,
        ip: IpAddr,
        sni: Option<Arc<str>>,
        scheme: &'static str,
    ) -> Self {
        let ts_ms = request_id::now_ms();
        ConnLog {
            ev: LogEvent {
                ts_ms,
                gateway_id: Arc::clone(&config.gateway_id),
                request_id: request_id::generate_at(ts_ms),
                client_ip: ip,
                method: Arc::from("TCP"),
                scheme: Arc::from(scheme),
                host: sni,
                path,
                user_agent: None,
                status: 0,
                bytes: 0,
                req_bytes: 0,
                dur_us: 0,
                ip_intel: None,
                block: BlockResult::default(),
                allow_rule: None,
                cache: "NONE",
                upstream: None,
                upstream_host: None,
                upstream_port: 0,
                upstream_status: 0,
                upstream_us: 0,
                grpc_status: -1,
                error: None,
                user: None,
                sample_rate: 1,
            },
        }
    }

    pub(crate) fn finish(
        mut self,
        state: &GatewayState,
        status: u16,
        started: Instant,
        error: Option<String>,
    ) {
        let queue = state.log_queue.load();
        let Some(q) = queue.as_ref() else { return };
        self.ev.status = status;
        self.ev.dur_us = started.elapsed().as_micros() as u64;
        self.ev.error = error;
        q.enqueue(self.ev);
    }
}

// ── Byte counting ────────────────────────────────────────────────────────────

/// Counts bytes in each direction and records the last activity time (for
/// the idle timeout). `failed` notes which side an I/O error came from.
struct Counted<S> {
    inner: S,
    read: u64,
    written: u64,
    failed: bool,
    activity: Option<Arc<AtomicU64>>,
    base: Instant,
}

impl<S> Counted<S> {
    fn new(inner: S, activity: Option<Arc<AtomicU64>>, base: Instant) -> Self {
        Self {
            inner,
            read: 0,
            written: 0,
            failed: false,
            activity,
            base,
        }
    }

    fn touch(&self) {
        if let Some(a) = &self.activity {
            a.store(self.base.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
    }

    fn note<T>(&mut self, r: &Poll<io::Result<T>>) {
        if matches!(r, Poll::Ready(Err(_))) {
            self.failed = true;
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n > 0 {
            self.read += n;
            self.touch();
        }
        self.note(&r);
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            if n > 0 {
                self.written += n as u64;
                self.touch();
            }
        }
        self.note(&r);
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_flush(cx);
        self.note(&r);
        r
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_protocol_v1_and_v2() {
        let src: SocketAddr = "203.0.113.7:51000".parse().unwrap();
        let dst: SocketAddr = "[::ffff:10.0.0.1]:5432".parse().unwrap();
        assert_eq!(
            proxy_header(ProxyProtocolVersion::V1, src, dst),
            b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 5432\r\n".to_vec()
        );
        let v2 = proxy_header(ProxyProtocolVersion::V2, src, dst);
        assert_eq!(&v2[..12], &PP2_SIG);
        assert_eq!(&v2[12..16], &[0x21, 0x11, 0, 12]);
        assert_eq!(&v2[16..20], &[203, 0, 113, 7]);
        assert_eq!(&v2[24..28], &[0xC7, 0x38, 0x15, 0x38]);
        let six: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        let v1 = String::from_utf8(proxy_header(ProxyProtocolVersion::V1, six, dst)).unwrap();
        assert_eq!(v1, "PROXY TCP6 2001:db8::1 ::ffff:10.0.0.1 4000 5432\r\n");
        assert_eq!(
            proxy_header(ProxyProtocolVersion::V2, six, dst).len(),
            16 + 36
        );
    }
}
