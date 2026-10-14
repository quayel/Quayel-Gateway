//! TCP stream proxy: one accepted connection → one target connection, bytes
//! copied both ways until either side closes.
//!
//! Per connection: per-IP connection limits and bans (server.protection),
//! the stream's `rules`, target choice with fallback to the next target when
//! connecting fails, an optional PROXY protocol header, an optional idle
//! timeout, and one access-log line when the connection ends.
//!
//! Log line fields for streams: `method` is "TCP", `scheme` "tcp", `path` the
//! stream id, `req_bytes` / `bytes` the bytes from / to the client, `dur_us`
//! the whole connection and `upstream_us` the connect time. `status` is 200
//! once the target connection is made, 403 when a rule blocks, 502 when no
//! target accepts the connection, 503 when every target is unhealthy and 504
//! when connecting timed out.

use crate::config::compiler::CompiledConfig;
use crate::config::schema::{ProxyProtocolVersion, StreamRuleAction};
use crate::gateway::gateway::GatewayState;
use crate::gateway::request_context::{BlockResult, RequestContext};
use crate::gateway::request_id;
use crate::logging::event::LogEvent;
use crate::plugins::firewall::{deciding_conditions, evaluate_conditions};
use crate::streams::{CompiledStream, CompiledStreamTarget};
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

/// One connection on a stream listener.
pub async fn serve(
    state: &Arc<GatewayState>,
    stream: Stream,
    peer: SocketAddr,
    local: SocketAddr,
    shutdown: &ShutdownWatch,
) {
    let config = state.config.load_full();
    let Some(s) = config.streams.for_listener(local).cloned() else {
        // The stream was removed by a reload; its listener stays open until
        // the next restart.
        return;
    };
    proxy(
        state, &config, &s, stream, peer, local, None, "tcp", shutdown,
    )
    .await;
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
    scheme: &'static str,
    shutdown: &ShutdownWatch,
) {
    let started = Instant::now();
    let ts_ms = request_id::now_ms();
    let ip = peer.ip().to_canonical();

    // server.protection applies to stream connections exactly as to HTTP
    // ones (and shares the same per-IP counters). Refusals aren't logged,
    // same as for HTTP connections.
    let _permit = match &config.server.protection {
        Some(p) => match state.ip_tracker.open_connection(p, ip) {
            Ok(pm) => Some(pm),
            Err(v) => {
                tracing::debug!(client_ip = %ip, stream = %s.id, reason = v.as_str(), "Protection: stream connection refused");
                return;
            }
        },
        None => None,
    };

    let mut line = ConnLog::new(config, s, ip, ts_ms, sni.clone(), scheme);

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
                    line.finish(state, 403, started, None);
                    return;
                }
            }
            break;
        }
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

struct ConnLog {
    ev: LogEvent,
}

impl ConnLog {
    fn new(
        config: &CompiledConfig,
        s: &CompiledStream,
        ip: IpAddr,
        ts_ms: u64,
        sni: Option<Arc<str>>,
        scheme: &'static str,
    ) -> Self {
        ConnLog {
            ev: LogEvent {
                ts_ms,
                gateway_id: Arc::clone(&config.gateway_id),
                request_id: request_id::generate_at(ts_ms),
                client_ip: ip,
                method: Arc::from(s.protocol.as_str().to_ascii_uppercase()),
                scheme: Arc::from(scheme),
                host: sni,
                path: Arc::clone(&s.id),
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
                error: None,
                user: None,
                sample_rate: 1,
            },
        }
    }

    fn finish(
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
