//! The app behind every listener of the main Pingora service. Connections
//! that arrive on a stream port go to the stream proxy; everything else goes
//! to the HTTP app unchanged.

use crate::gateway::gateway::GatewayState;
use crate::streams::{listen_matches, tcp};
use async_trait::async_trait;
use pingora_core::apps::ServerApp;
use pingora_core::protocols::Stream;
use pingora_core::server::ShutdownWatch;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct EdgeApp<H> {
    http: Arc<H>,
    state: Arc<GatewayState>,
    /// Stream listen addresses opened at startup.
    stream_listens: Vec<SocketAddr>,
}

impl<H> EdgeApp<H> {
    pub fn new(http: H, state: Arc<GatewayState>, stream_listens: Vec<SocketAddr>) -> Self {
        Self {
            http: Arc::new(http),
            state,
            stream_listens,
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
        if !self.stream_listens.is_empty() {
            let addrs = stream.get_socket_digest().and_then(|d| {
                let local = d.local_addr()?.as_inet().copied()?;
                let peer = d.peer_addr()?.as_inet().copied()?;
                Some((local, peer))
            });
            if let Some((local, peer)) = addrs {
                if self
                    .stream_listens
                    .iter()
                    .any(|l| listen_matches(*l, local))
                {
                    tcp::serve(&self.state, stream, peer, local, shutdown).await;
                    return None;
                }
            }
        }
        self.http.process_new(stream, shutdown).await
    }

    async fn cleanup(&self) {
        self.http.cleanup().await
    }
}
