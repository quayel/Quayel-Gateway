use crate::gateway::request_context::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── Log Event ────────────────────────────────────────────────────────────────
// Structured JSONL event capturing all gateway decisions for a request.
//
// Fields sourced from RequestContext's `Arc<str>` are stored as `Arc<str>` here
// too, enabling cheap `Arc::clone()` (atomic refcount bump) instead of
// `.to_string()` (heap allocation). This saves ~9 heap allocations per request.

#[derive(Debug, Clone, Serialize)]
pub struct LogEvent {
    pub timestamp: String,

    // Gateway identity — Arc<str> from config, cheap clone
    pub gateway_id: Arc<str>,
    pub gateway_name: Arc<str>,
    pub server_name: Arc<str>,
    pub config_version: Arc<str>,

    // Request identity
    pub request_id: String,

    // Client/network — IpAddr requires to_string() (unavoidable)
    pub client_ip: String,
    pub peer_ip: String,
    pub client_ip_source: Arc<str>,

    // HTTP — Arc<str> from request, cheap clone. host and path are what the
    // client sent; a request_transform rewrite is in request_transform.
    pub method: Arc<str>,
    pub scheme: Arc<str>,
    pub host: Arc<str>,
    pub path: Arc<str>,

    // Response
    pub response_status: u16,

    // Bandwidth
    pub bandwidth: BandwidthEvent,

    // IP intelligence
    pub ip_intel: IpIntelEvent,

    // Firewall
    pub firewall: FirewallEvent,

    // Rate limiting
    pub rate_limit: RateLimitEvent,

    // Request transform
    pub request_transform: RequestTransformEvent,

    // Cache
    pub cache: CacheEvent,

    // Response transform
    pub response_transform: ResponseTransformEvent,

    // Load balancer
    pub load_balancer: LoadBalancerEvent,

    // Termination
    pub termination_phase: Option<String>,

    // Timings
    pub timings_us: TimingsEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthEvent {
    pub client_bytes_in: u64,
    pub client_bytes_out: u64,
    pub total_client_bytes: u64,
    pub upstream_bytes_out: u64,
    pub upstream_bytes_in: u64,
    pub total_origin_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIntelEvent {
    pub country: Option<String>,
    pub region: Option<String>,
    pub asn: Option<u32>,
    pub provider: Option<String>,
    pub network_type: Option<String>,
    pub is_vpn: Option<bool>,
    pub is_proxy: Option<bool>,
    pub is_datacenter: Option<bool>,
    pub is_mobile: Option<bool>,
    pub is_tor: Option<bool>,
    pub risk_score: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallEvent {
    pub matched: bool,
    pub rule_id: Option<String>,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitEvent {
    pub matched: bool,
    pub rule_id: Option<String>,
    pub blocked: bool,
    pub remaining: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTransformEvent {
    /// IDs of the rules that matched, in order.
    pub rules: Vec<Arc<str>>,
    /// Path and query sent upstream; None when no rule rewrote them.
    pub path: Option<Arc<str>>,
    /// Host sent upstream; None when no rule touched it.
    pub host: Option<Arc<str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTransformEvent {
    /// IDs of the rules that matched, in order. Empty for gateway blocks.
    pub rules: Vec<Arc<str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEvent {
    pub rule_id: Option<String>,
    pub status: String,
    pub key_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerEvent {
    pub lb_id: Option<Arc<str>>,
    pub algorithm: Option<String>,
    pub target_id: Option<Arc<str>>,
    pub target: Option<Arc<str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingsEvent {
    pub ip_intel_us: Option<u64>,
    pub firewall_us: Option<u64>,
    pub rate_limit_us: Option<u64>,
    pub cache_lookup_us: Option<u64>,
    pub load_balancer_us: Option<u64>,
    pub upstream_connect_us: Option<u64>,
    pub upstream_ttfb_us: Option<u64>,
    pub total_us: Option<u64>,
}

impl LogEvent {
    pub fn from_context(ctx: &RequestContext) -> Self {
        LogEvent {
            // timestamp must be allocated (computed value)
            timestamp: Utc::now().to_rfc3339(),

            // ── Arc<str> fields: Arc::clone() is a single atomic increment ──
            // Previously these used .to_string() which heap-allocated each one.
            gateway_id: Arc::clone(&ctx.gateway_id),
            gateway_name: Arc::clone(&ctx.gateway_name),
            server_name: Arc::clone(&ctx.server_name),
            config_version: Arc::clone(&ctx.config_version),

            // request_id is already a String — clone is a memcpy (small, ~20 bytes)
            request_id: ctx.request_id.clone(),

            // IpAddr → String: unavoidable allocation (IpAddr is Copy, not heap)
            client_ip: ctx.client_ip.to_string(),
            peer_ip: ctx.peer_ip.to_string(),
            client_ip_source: Arc::clone(&ctx.client_ip_source),

            // ── Arc<str> fields: Arc::clone() instead of .to_string() ──
            method: Arc::clone(&ctx.method),
            scheme: Arc::clone(&ctx.scheme),
            host: match &ctx.request_transform.original_host {
                Some(original) => original.as_ref().map(Arc::clone),
                None => ctx.host.as_ref().map(Arc::clone),
            }
            .unwrap_or_else(|| Arc::from("")),
            path: Arc::clone(ctx.request_transform.original_path.as_ref().unwrap_or(&ctx.path)),

            response_status: ctx.status_code.unwrap_or(0),

            bandwidth: BandwidthEvent {
                client_bytes_in: ctx.client_bytes_in,
                client_bytes_out: ctx.client_bytes_out,
                total_client_bytes: ctx.client_bytes_in + ctx.client_bytes_out,
                upstream_bytes_out: ctx.upstream_bytes_out,
                upstream_bytes_in: ctx.upstream_bytes_in,
                total_origin_bytes: ctx.upstream_bytes_out + ctx.upstream_bytes_in,
            },

            ip_intel: IpIntelEvent {
                country: ctx.ip_intel.as_ref().and_then(|i| i.country.clone()),
                region: ctx.ip_intel.as_ref().and_then(|i| i.region.clone()),
                asn: ctx.ip_intel.as_ref().and_then(|i| i.asn),
                provider: ctx.ip_intel.as_ref().and_then(|i| i.provider.clone()),
                network_type: ctx.ip_intel.as_ref().and_then(|i| i.network_type.clone()),
                is_vpn: ctx.ip_intel.as_ref().and_then(|i| i.is_vpn),
                is_proxy: ctx.ip_intel.as_ref().and_then(|i| i.is_proxy),
                is_datacenter: ctx.ip_intel.as_ref().and_then(|i| i.is_datacenter),
                is_mobile: ctx.ip_intel.as_ref().and_then(|i| i.is_mobile),
                is_tor: ctx.ip_intel.as_ref().and_then(|i| i.is_tor),
                risk_score: ctx.ip_intel.as_ref().and_then(|i| i.risk_score),
            },

            firewall: FirewallEvent {
                matched: ctx.firewall.matched,
                rule_id: ctx.firewall.rule_id.clone(),
                action: ctx.firewall.action.as_ref().map(|a| format!("{:?}", a)),
            },

            rate_limit: RateLimitEvent {
                matched: ctx.rate_limit.matched,
                rule_id: ctx.rate_limit.rule_id.clone(),
                blocked: ctx.rate_limit.blocked,
                remaining: ctx.rate_limit.remaining,
            },

            request_transform: RequestTransformEvent {
                rules: ctx.request_transform.rules.clone(),
                path: ctx.request_transform.original_path.as_ref().map(|_| Arc::clone(&ctx.path)),
                host: ctx.request_transform.original_host.as_ref().and_then(|_| ctx.host.as_ref().map(Arc::clone)),
            },

            cache: CacheEvent {
                rule_id: ctx.cache.rule_id.clone(),
                status: ctx.cache.status.as_str().to_string(),
                key_hash: ctx.cache.key_hash.clone(),
            },

            response_transform: ResponseTransformEvent {
                rules: ctx.response_transform.rules.clone(),
            },

            load_balancer: LoadBalancerEvent {
                lb_id: ctx.load_balancer.lb_id.as_ref().map(Arc::clone),
                algorithm: ctx.load_balancer.algorithm.clone(),
                target_id: ctx.load_balancer.target_id.as_ref().map(Arc::clone),
                target: ctx.load_balancer.target_host.as_ref().map(Arc::clone),
            },

            termination_phase: ctx
                .termination_phase
                .as_ref()
                .map(|p| format!("{:?}", p)),

            timings_us: TimingsEvent {
                ip_intel_us: ctx.ip_intel_latency_us,
                firewall_us: ctx.firewall_latency_us,
                rate_limit_us: ctx.rate_limit_latency_us,
                cache_lookup_us: ctx.cache_lookup_latency_us,
                load_balancer_us: ctx.lb_latency_us,
                upstream_connect_us: ctx.upstream_connect_latency_us,
                upstream_ttfb_us: ctx.upstream_ttfb_us,
                total_us: ctx.total_latency_us,
            },
        }
    }
}