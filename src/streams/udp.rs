//! UDP stream proxy.
//!
//! UDP has no connections, so the gateway keeps a session per client
//! address: the first datagram from a client picks a target and opens a
//! socket to it; later datagrams from that client go to the same target, and
//! the target's replies go back to that client. A session ends after
//! `idle_secs` without traffic (30 s by default), after `responses` replies
//! when that is set (1 for DNS), or at shutdown; then it gets one access-log
//! line (`method` "UDP", `scheme` "udp", bytes each way).
//!
//! server.protection limits and bans apply per session like a connection.
//! `max_sessions` caps sessions per stream: UDP source addresses are easy to
//! forge, and every session holds a socket.

use crate::config::compiler::CompiledConfig;
use crate::gateway::gateway::GatewayState;
use crate::streams::tcp::{admit, check_rules, ConnLog};
use crate::streams::{CompiledStream, UDP_IDLE_SECS};
use async_trait::async_trait;
use dashmap::DashMap;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const MAX_DATAGRAM: usize = 65_535;

/// Bind every UDP stream port (at startup, so a port in use fails early).
pub fn bind(addrs: &[SocketAddr]) -> Result<Vec<(SocketAddr, std::net::UdpSocket)>, String> {
    addrs
        .iter()
        .map(|a| {
            let s = std::net::UdpSocket::bind(a).map_err(|e| format!("udp stream {a}: {e}"))?;
            s.set_nonblocking(true)
                .map_err(|e| format!("udp stream {a}: {e}"))?;
            Ok((*a, s))
        })
        .collect()
}

pub struct UdpProxy {
    state: Arc<GatewayState>,
    sockets: parking_lot::Mutex<Vec<(SocketAddr, std::net::UdpSocket)>>,
}

impl UdpProxy {
    pub fn new(state: Arc<GatewayState>, sockets: Vec<(SocketAddr, std::net::UdpSocket)>) -> Self {
        Self {
            state,
            sockets: parking_lot::Mutex::new(sockets),
        }
    }
}

#[async_trait]
impl BackgroundService for UdpProxy {
    async fn start(&self, shutdown: ShutdownWatch) {
        let sockets = std::mem::take(&mut *self.sockets.lock());
        let mut tasks = Vec::new();
        for (listen, sock) in sockets {
            let sock = match UdpSocket::from_std(sock) {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    tracing::error!(listen = %listen, error = %e, "UDP stream socket");
                    continue;
                }
            };
            tasks.push(tokio::spawn(serve_port(
                self.state.clone(),
                listen,
                sock,
                shutdown.clone(),
            )));
        }
        for t in tasks {
            let _ = t.await;
        }
    }
}

struct Session {
    /// None → the session was refused (rule block, no target); its datagrams
    /// are dropped until it goes idle, so a flood logs one line.
    up: Option<Arc<UdpSocket>>,
    started: Instant,
    /// Milliseconds after `started` of the last datagram either way.
    last: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl Session {
    fn touch(&self) {
        self.last
            .store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

type Sessions = Arc<DashMap<SocketAddr, Arc<Session>>>;

async fn serve_port(
    state: Arc<GatewayState>,
    listen: SocketAddr,
    sock: Arc<UdpSocket>,
    mut shutdown: ShutdownWatch,
) {
    let sessions: Sessions = Arc::new(DashMap::new());
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, src) = tokio::select! {
            r = sock.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(listen = %listen, error = %e, "UDP receive failed");
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };
        let data = &buf[..n];

        let existing = sessions.get(&src).map(|s| Arc::clone(&s));
        if let Some(sess) = existing {
            sess.touch();
            if let Some(up) = &sess.up {
                sess.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                send(up, data).await;
            }
            continue;
        }

        let config = state.config.load_full();
        let Some(s) = config.streams.udp_for(listen).cloned() else {
            continue; // stream removed by a reload
        };
        if s.max_sessions > 0 && sessions.len() >= s.max_sessions as usize {
            tracing::debug!(stream = %s.id, client = %src, "UDP session limit reached, datagram dropped");
            continue;
        }
        open_session(&state, &config, &s, &sock, &sessions, src, data, &shutdown).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_session(
    state: &Arc<GatewayState>,
    config: &Arc<CompiledConfig>,
    s: &Arc<CompiledStream>,
    sock: &Arc<UdpSocket>,
    sessions: &Sessions,
    src: SocketAddr,
    first: &[u8],
    shutdown: &ShutdownWatch,
) {
    let started = Instant::now();
    let ip = src.ip().to_canonical();
    let Ok(permit) = admit(state, config, ip) else {
        return;
    };
    let mut line = ConnLog::new(config, Arc::clone(&s.id), ip, None, "udp");
    line.ev.method = Arc::from("UDP");

    let mut refused: Option<(u16, Option<String>)> = None;
    let mut up = None;
    if !check_rules(state, config, s, ip, None, &mut line).await {
        refused = Some((403, None));
    } else {
        match state.streams.order(s, ip).first() {
            None => refused = Some((503, Some("no healthy target".into()))),
            Some(t) => match connect(&t.host, t.port, s.connect_timeout).await {
                Ok(u) => {
                    line.ev.upstream = Some(Arc::clone(&t.id));
                    line.ev.upstream_host = Some(Arc::clone(&t.host));
                    line.ev.upstream_port = t.port;
                    up = Some((Arc::new(u), state.streams.track(t)));
                }
                Err(e) => refused = Some((502, Some(e))),
            },
        }
    }
    line.ev.upstream_us = started.elapsed().as_micros() as u64;

    let sess = Arc::new(Session {
        up: up.as_ref().map(|(u, _)| Arc::clone(u)),
        started,
        last: AtomicU64::new(0),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
    });
    if let Some(u) = &sess.up {
        sess.bytes_in.store(first.len() as u64, Ordering::Relaxed);
        send(u, first).await;
    }
    sessions.insert(src, Arc::clone(&sess));

    let (state, s, sock, sessions) = (state.clone(), s.clone(), sock.clone(), sessions.clone());
    let mut shutdown = shutdown.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let _active = up.map(|(_, g)| g);
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut replies = 0u32;
        let mut error: Option<String> = None;
        // A refused session always expires, even with idle_secs: 0.
        let idle_after = match &sess.up {
            Some(_) => s.idle,
            None => Some(s.idle.unwrap_or(Duration::from_secs(UDP_IDLE_SECS))),
        };
        loop {
            let recv = async {
                match &sess.up {
                    Some(u) => u.recv(&mut buf).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                r = recv => match r {
                    Ok(m) => {
                        sess.touch();
                        sess.bytes_out.fetch_add(m as u64, Ordering::Relaxed);
                        let _ = sock.send_to(&buf[..m], src).await;
                        replies += 1;
                        if s.responses.is_some_and(|n| replies >= n) {
                            break;
                        }
                    }
                    // e.g. ICMP port unreachable from the target
                    Err(e) => {
                        error = Some(format!("upstream: {e}"));
                        break;
                    }
                },
                _ = idle(idle_after, &sess) => break,
                _ = shutdown.changed() => {
                    error = Some("gateway shutting down".into());
                    break;
                }
            }
        }
        sessions.remove(&src);
        line.ev.req_bytes = sess.bytes_in.load(Ordering::Relaxed);
        line.ev.bytes = sess.bytes_out.load(Ordering::Relaxed);
        let (status, refused_error) = refused.unwrap_or((200, None));
        line.finish(&state, status, started, refused_error.or(error));
    });
}

/// Send a datagram to the target without holding up the receive loop for
/// long: tokio only knows a socket is writable after its first readiness
/// event, so a fresh socket needs the awaited send. If the socket buffer
/// stays full the datagram is dropped, as the network may.
async fn send(up: &UdpSocket, data: &[u8]) {
    match up.try_send(data) {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            let _ = tokio::time::timeout(Duration::from_millis(50), up.send(data)).await;
        }
        _ => {}
    }
}

/// Resolves once the session has had no traffic for `idle`.
async fn idle(idle: Option<Duration>, sess: &Session) {
    let Some(idle) = idle else {
        return std::future::pending().await;
    };
    let idle_ms = idle.as_millis() as u64;
    loop {
        let last = sess.last.load(Ordering::Relaxed);
        let now = sess.started.elapsed().as_millis() as u64;
        if now >= last + idle_ms {
            return;
        }
        tokio::time::sleep(Duration::from_millis(last + idle_ms - now)).await;
    }
}

/// A socket connected to the target, so only its replies are received.
async fn connect(host: &str, port: u16, timeout: Duration) -> Result<UdpSocket, String> {
    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| format!("resolve {host}: timed out"))?
            .map_err(|e| format!("resolve {host}: {e}"))?
            .next()
            .ok_or_else(|| format!("resolve {host}: no address"))?,
    };
    let local: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let u = UdpSocket::bind(local)
        .await
        .map_err(|e| format!("bind for {addr}: {e}"))?;
    u.connect(addr)
        .await
        .map_err(|e| format!("connect {addr}: {e}"))?;
    Ok(u)
}
