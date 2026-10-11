//! Connection-level protection that has to run before Pingora parses HTTP.
//!
//! `GuardedApp` wraps the proxy app. For every accepted connection it applies
//! the per-IP connection limits and bans, then wraps the stream in a
//! `HeaderGuardStream`.
//!
//! Pingora only times out each individual read while waiting for a request
//! header, so a client sending one byte every few seconds can hold a
//! connection open forever (Slowloris). `HeaderGuardStream` puts a deadline
//! and a size cap on the *whole* header. The proxy hooks tell it where each
//! request starts and ends:
//!
//! - `early_request_filter` → `headers_done()`: the header was parsed, stop
//!   counting (bodies, WebSockets and slow uploads are not affected).
//! - `logging` → `request_done()`: the next bytes on this connection start a
//!   new request header, so the deadline restarts on its first byte.
//!
//! HTTP/2 connections are not wrapped; h2 has its own frame-level limits.

use crate::gateway::gateway::GatewayState;
use crate::gateway::protection::{CompiledProtection, ConnPermit, IpTracker, Violation};
use async_trait::async_trait;
use pingora_core::apps::ServerApp;
use pingora_core::protocols::raw_connect::ProxyDigest;
use pingora_core::protocols::tls::{SslDigest, TlsRef};
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl, Stream,
    TimingDigest, UniqueID, UniqueIDType, ALPN,
};
use pingora_core::server::ShutdownWatch;
use pingora_proxy::Session;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

// ── App wrapper ──────────────────────────────────────────────────────────────

pub struct GuardedApp<A> {
    inner: Arc<A>,
    state: Arc<GatewayState>,
}

impl<A> GuardedApp<A> {
    pub fn new(inner: A, state: Arc<GatewayState>) -> Self {
        Self { inner: Arc::new(inner), state }
    }
}

#[async_trait]
impl<A> ServerApp for GuardedApp<A>
where
    A: ServerApp + Send + Sync + 'static,
{
    async fn process_new(self: &Arc<Self>, stream: Stream, shutdown: &ShutdownWatch) -> Option<Stream> {
        let (header_timeout, max_header_bytes, protection) = {
            let config = self.state.config.load();
            (
                config.server.header_timeout,
                config.server.max_header_bytes,
                config.server.protection.clone(),
            )
        };
        let peer_ip = stream
            .get_socket_digest()
            .and_then(|d| d.peer_addr().and_then(|a| a.as_inet()).map(|a| a.ip()));

        let mut permit: Option<ConnPermit> = None;
        let mut strike = None;
        if let (Some(p), Some(ip)) = (protection, peer_ip) {
            match self.state.ip_tracker.open_connection(&p, ip) {
                Ok(pm) => permit = Some(pm),
                Err(v) => {
                    tracing::debug!(client_ip = %ip, reason = v.as_str(), "Protection: connection refused");
                    return None;
                }
            }
            strike = Some(StrikeCtx { tracker: self.state.ip_tracker.clone(), protection: p, ip });
        }

        let is_h2 = matches!(stream.selected_alpn_proto(), Some(ALPN::H2));
        let stream: Stream = if !is_h2 && (header_timeout.is_some() || max_header_bytes > 0) {
            Box::new(HeaderGuardStream::new(stream, header_timeout, max_header_bytes, strike))
        } else {
            stream
        };

        let reused = self.inner.process_new(stream, shutdown).await;
        drop(permit);
        reused
    }

    async fn cleanup(&self) {
        self.inner.cleanup().await
    }
}

/// The guard on this request's connection, if it has one (HTTP/1 only).
pub fn header_guard(session: &Session) -> Option<&HeaderGuardStream> {
    session.stream()?.as_any().downcast_ref::<HeaderGuardStream>()
}

// ── Header guard stream ──────────────────────────────────────────────────────

const PHASE_HEADER: u8 = 0;
const PHASE_BODY: u8 = 1;
const PHASE_IDLE: u8 = 2;
const PHASE_FAILED: u8 = 3;

struct StrikeCtx {
    tracker: Arc<IpTracker>,
    protection: Arc<CompiledProtection>,
    ip: IpAddr,
}

pub struct HeaderGuardStream {
    inner: Stream,
    /// Written by the proxy hooks through a shared reference, read in poll_read.
    phase: AtomicU8,
    timeout: Option<Duration>,
    max_bytes: usize,
    deadline: Option<Instant>,
    sleep: Option<Pin<Box<Sleep>>>,
    header_read: usize,
    strike: Option<StrikeCtx>,
}

impl HeaderGuardStream {
    fn new(inner: Stream, timeout: Option<Duration>, max_bytes: usize, strike: Option<StrikeCtx>) -> Self {
        // The first request's clock starts when the connection opens, so a
        // client that connects and sends nothing is also cut off.
        Self {
            inner,
            phase: AtomicU8::new(PHASE_HEADER),
            timeout,
            max_bytes,
            deadline: timeout.map(|t| Instant::now() + t),
            sleep: None,
            header_read: 0,
            strike,
        }
    }

    /// The current request header has been parsed.
    pub fn headers_done(&self) {
        self.phase.store(PHASE_BODY, Ordering::Relaxed);
    }

    /// The current request is finished; the next byte starts a new header.
    pub fn request_done(&self) {
        self.phase.store(PHASE_IDLE, Ordering::Relaxed);
    }

    fn fail(&mut self, v: Violation) -> io::Error {
        self.phase.store(PHASE_FAILED, Ordering::Relaxed);
        if let Some(s) = &self.strike {
            tracing::debug!(client_ip = %s.ip, reason = v.as_str(), "Protection: connection closed");
            s.tracker.strike(&s.protection, s.ip, v);
        }
        match v {
            Violation::SlowHeaders => io::Error::new(io::ErrorKind::TimedOut, "request header deadline exceeded"),
            _ => io::Error::new(io::ErrorKind::InvalidData, "request header too large"),
        }
    }
}

impl std::fmt::Debug for HeaderGuardStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderGuardStream")
            .field("inner", &self.inner)
            .field("phase", &self.phase.load(Ordering::Relaxed))
            .finish()
    }
}

impl AsyncRead for HeaderGuardStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let phase = this.phase.load(Ordering::Relaxed);

        if phase == PHASE_HEADER {
            if this.max_bytes > 0 && this.header_read > this.max_bytes {
                return Poll::Ready(Err(this.fail(Violation::HeaderTooLarge)));
            }
            if let Some(deadline) = this.deadline {
                if Instant::now() >= deadline {
                    return Poll::Ready(Err(this.fail(Violation::SlowHeaders)));
                }
            }
        }

        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before;
                if n > 0 {
                    if phase == PHASE_IDLE {
                        this.phase.store(PHASE_HEADER, Ordering::Relaxed);
                        this.header_read = n;
                        this.deadline = this.timeout.map(|t| Instant::now() + t);
                    } else if phase == PHASE_HEADER {
                        this.header_read += n;
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                if phase == PHASE_HEADER {
                    if let Some(deadline) = this.deadline {
                        let sleep = this
                            .sleep
                            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
                        if sleep.deadline() != deadline {
                            sleep.as_mut().reset(deadline);
                        }
                        if sleep.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(Err(this.fail(Violation::SlowHeaders)));
                        }
                    }
                }
                Poll::Pending
            }
            other => other,
        }
    }
}

impl AsyncWrite for HeaderGuardStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

// Everything else is passed straight through to the real connection.

#[async_trait]
impl Shutdown for HeaderGuardStream {
    async fn shutdown(&mut self) {
        self.inner.shutdown().await
    }
}

impl UniqueID for HeaderGuardStream {
    fn id(&self) -> UniqueIDType {
        self.inner.id()
    }
}

impl Ssl for HeaderGuardStream {
    fn get_ssl(&self) -> Option<&TlsRef> {
        self.inner.get_ssl()
    }
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.inner.get_ssl_digest()
    }
    fn selected_alpn_proto(&self) -> Option<ALPN> {
        self.inner.selected_alpn_proto()
    }
}

impl GetTimingDigest for HeaderGuardStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.inner.get_timing_digest()
    }
    fn get_read_pending_time(&self) -> Duration {
        self.inner.get_read_pending_time()
    }
    fn get_write_pending_time(&self) -> Duration {
        self.inner.get_write_pending_time()
    }
}

impl GetProxyDigest for HeaderGuardStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.inner.get_proxy_digest()
    }
    fn set_proxy_digest(&mut self, digest: ProxyDigest) {
        self.inner.set_proxy_digest(digest)
    }
}

impl GetSocketDigest for HeaderGuardStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.inner.get_socket_digest()
    }
    fn set_socket_digest(&mut self, digest: SocketDigest) {
        self.inner.set_socket_digest(digest)
    }
}

#[async_trait]
impl Peek for HeaderGuardStream {
    async fn try_peek(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        self.inner.try_peek(buf).await
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn guarded(timeout_ms: u64, max_bytes: usize) -> (HeaderGuardStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let stream: Stream = Box::new(pingora_core::protocols::l4::stream::Stream::from(server));
        let g = HeaderGuardStream::new(stream, Some(Duration::from_millis(timeout_ms)), max_bytes, None);
        (g, client)
    }

    #[tokio::test]
    async fn slow_header_is_cut_off() {
        let (mut g, mut client) = guarded(300, 0).await;
        let writer = tokio::spawn(async move {
            for b in b"GET / HTTP/1.1\r\n" {
                if client.write_all(&[*b]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            client
        });
        let mut buf = [0u8; 64];
        let err = loop {
            match g.read(&mut buf).await {
                Ok(0) => panic!("unexpected EOF"),
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        writer.abort();
    }

    #[tokio::test]
    async fn silent_connection_is_cut_off() {
        let (mut g, _client) = guarded(200, 0).await;
        let mut buf = [0u8; 16];
        let err = g.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn body_and_idle_phases_are_not_timed() {
        let (mut g, mut client) = guarded(200, 0).await;
        client.write_all(b"POST / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        g.read(&mut buf).await.unwrap();
        g.headers_done();
        // A slow body after the header is fine.
        tokio::time::sleep(Duration::from_millis(400)).await;
        client.write_all(b"x").await.unwrap();
        assert_eq!(g.read(&mut buf).await.unwrap(), 1);
        // Idle between requests is left to the keep-alive timeout...
        g.request_done();
        tokio::time::sleep(Duration::from_millis(400)).await;
        client.write_all(b"G").await.unwrap();
        g.read(&mut buf).await.unwrap();
        // ...but once the next header starts, its own deadline applies.
        let err = g.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn oversized_header_is_rejected() {
        let (mut g, mut client) = guarded(5_000, 100).await;
        client.write_all(&[b'a'; 300]).await.unwrap();
        let mut buf = [0u8; 64];
        let err = loop {
            match g.read(&mut buf).await {
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
