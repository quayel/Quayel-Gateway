pub mod cache;
pub mod firewall;
pub mod ip_intel;
pub mod load_balancer;
pub mod rate_limit;
pub mod transform;

use bytes::Bytes;
use std::sync::Arc;

// ── Plugin Flow ──────────────────────────────────────────────────────────────
// Determines whether the plugin pipeline continues or responds early.

#[derive(Debug)]
pub enum PluginFlow {
    /// Continue to the next plugin
    Continue,
    /// Respond immediately with this response (skip remaining plugins except logging)
    Respond(GatewayResponse),
}

#[derive(Debug, Clone)]
pub struct GatewayResponse {
    pub status: u16,
    pub headers: Arc<Vec<(String, String)>>,
    pub body: Bytes,
}
