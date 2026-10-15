//! The app behind every listener of the main Pingora service.
//!
//! - Stream ports → the TCP stream proxy.
//! - The HTTPS port is a plain TCP listener; TLS is done here instead of by
//!   Pingora's listener. When streams share the port, the ClientHello is
//!   peeked first and a matching server name goes to its stream. Everything
//!   else gets the HTTPS handshake (Auto-SSL certificates) and goes to the
//!   HTTP app exactly as before. The peek and the handshake together must
//!   finish within server.timeouts.header_secs.
//! - Everything else (the HTTP port, reused keep-alive connections) goes to
//!   the HTTP app unchanged.

use crate::gateway::gateway::GatewayState;
use crate::streams::sni::{peek_sni, Peeked};
use crate::streams::{listen_matches, tcp};
use async_trait::async_trait;
use pingora_core::apps::ServerApp;
use pingora_core::listeners::tls::Acceptor;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::Stream;
use pingora_core::server::ShutdownWatch;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

pub struct EdgeApp<H> {
    http: Arc<H>,
    state: Arc<GatewayState>,
    /// Stream ports opened at startup.
    stream_listens: Vec<SocketAddr>,
    https: Option<HttpsPort>,
    /// Certificates for streams with `tls: "terminate"` (Auto-SSL).
    stream_tls: Option<Acceptor>,
}

pub struct HttpsPort {
    pub listen: SocketAddr,
    /// None → Auto-SSL is off and the port only serves SNI streams.
    pub tls: Option<Acceptor>,
}

impl<H> EdgeApp<H> {
    pub fn new(
        http: H,
        state: Arc<GatewayState>,
        stream_listens: Vec<SocketAddr>,
        https: Option<HttpsPort>,
        stream_tls: Option<Acceptor>,
    ) -> Self {
        Self {
            http: Arc::new(http),
            state,
            stream_listens,
            https,
            stream_tls,
        }
    }
}

#[async_trait]
impl<H> ServerApp for EdgeApp<H>
where
    H: ServerApp + Send + Sync + 'static,
{
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        // A reused keep-alive connection comes back here after its first
        // request; if it is already TLS, it is HTTPS.
        if (self.stream_listens.is_empty() && self.https.is_none())
            || stream.get_ssl_digest().is_some()
        {
            return self.http.process_new(stream, shutdown).await;
        }
        let addrs = stream.get_socket_digest().and_then(|d| {
            let local = d.local_addr()?.as_inet().copied()?;
            let peer = d.peer_addr()?.as_inet().copied()?;
            Some((local, peer))
        });
        let Some((local, peer)) = addrs else {
            return self.http.process_new(stream, shutdown).await;
        };
        if self
            .stream_listens
            .iter()
            .any(|l| listen_matches(*l, local))
        {
            tcp::serve_port(
                &self.state,
                stream,
                peer,
                local,
                self.stream_tls.as_ref(),
                shutdown,
            )
            .await;
            return None;
        }
        if let Some(https) = &self.https {
            if listen_matches(https.listen, local) {
                return self.serve_https(https, stream, peer, local, shutdown).await;
            }
        }
        self.http.process_new(stream, shutdown).await
    }

    async fn cleanup(&self) {
        self.http.cleanup().await
    }
}

impl<H> EdgeApp<H>
where
    H: ServerApp + Send + Sync + 'static,
{
    async fn serve_https(
        self: &Arc<Self>,
        https: &HttpsPort,
        mut stream: Stream,
        peer: SocketAddr,
        local: SocketAddr,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let started = Instant::now();
        let config = self.state.config.load_full();
        let deadline = config.server.header_timeout;

        if !config.streams.https.is_empty() {
            match peek_sni(&mut stream, deadline).await {
                Err(_) => return None, // closed, or no ClientHello in time
                Ok(Peeked::Tls(Some(name))) => {
                    if let Some(s) = config.streams.https.route(&name).cloned() {
                        let ip = peer.ip().to_canonical();
                        let Ok(permit) = tcp::admit(&self.state, &config, ip) else {
                            return None;
                        };
                        tcp::serve_stream(
                            &self.state,
                            &config,
                            &s,
                            stream,
                            peer,
                            local,
                            Some(Arc::from(name.as_str())),
                            permit,
                            self.stream_tls.as_ref(),
                            shutdown,
                        )
                        .await;
                        return None;
                    }
                }
                Ok(_) => {}
            }
        }

        // HTTPS, as Pingora's TLS listener would do it.
        let acceptor = https.tls.as_ref()?;
        let l4 = stream.into_any().downcast::<L4Stream>().ok()?;
        let handshake = acceptor.tls_handshake(*l4);
        let tls = match deadline {
            Some(d) => tokio::time::timeout(d.saturating_sub(started.elapsed()), handshake)
                .await
                .ok()?,
            None => handshake.await,
        };
        match tls {
            Ok(tls) => self.http.process_new(Box::new(tls), shutdown).await,
            Err(e) => {
                tracing::debug!(client = %peer, error = %e, "TLS handshake failed");
                None
            }
        }
    }
}
