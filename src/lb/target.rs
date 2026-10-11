use crate::config::compiler::CompiledTarget;
use crate::config::schema::*;
use std::sync::Arc;

// ── Target ───────────────────────────────────────────────────────────────────
// Runtime representation of a load balancer target.

#[derive(Debug, Clone)]
pub struct Target {
    pub id: Arc<str>,
    pub host: Arc<str>,
    pub port: u16,
    pub protocol: TargetProtocol,
    pub weight: u32,
    pub enabled: bool,
    pub healthy: bool,
    /// Verify the upstream TLS certificate (`https` targets only).
    pub tls_verify: bool,
    /// Explicit SNI for the upstream TLS handshake (`https` targets only).
    pub tls_sni: Option<Arc<str>>,
}

impl Target {
    pub fn from_config(config: &CompiledTarget) -> Self {
        Self {
            id: config.id.clone(),
            host: config.host.clone(),
            port: config.port,
            protocol: config.protocol.clone(),
            weight: config.weight,
            enabled: config.enabled,
            healthy: true, // Assume healthy initially
            tls_verify: config.tls_verify,
            tls_sni: config.tls_sni.clone(),
        }
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Canonical lowercase scheme ("http" / "https") of the target.
    pub fn scheme(&self) -> &'static str {
        self.protocol.as_str()
    }

    pub fn is_available(&self) -> bool {
        self.enabled && self.healthy
    }
}
