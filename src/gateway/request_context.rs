use crate::config::schema::*;
use crate::plugins::cache::CacheEntry;
use crate::plugins::ip_intel::IpIntel;
use crate::plugins::transform::{RequestTransformState, ResponseTransformState};
use http::HeaderMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::OwnedMutexGuard;

/// Revalidation lock guard — held for the duration of a stale cache refresh request.
/// When the request completes and ctx is dropped, the guard drops → lock releases.
pub struct RevalidationGuard(pub OwnedMutexGuard<()>);

impl std::fmt::Debug for RevalidationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevalidationGuard")
    }
}

// ── Request Context ──────────────────────────────────────────────────────────
// One RequestContext is created per request. All plugins read/write the same ctx.
// No RwLock needed — Pingora gives exclusive &mut access via `type CTX = RequestContext`.

#[derive(Debug)]
pub struct RequestContext {
    // Gateway identity
    pub gateway_id: Arc<str>,
    pub gateway_name: Arc<str>,
    pub server_name: Arc<str>,
    pub config_version: Arc<str>,

    // Request identity — set first thing in early_request_filter
    pub request_id: String,
    /// Arrival time, Unix milliseconds (also the time part of the UUIDv7).
    pub ts_ms: u64,
    pub started_at: Instant,

    // Client / network
    pub peer_ip: IpAddr,
    pub client_ip: IpAddr,
    pub client_ip_source: Arc<str>,

    // HTTP
    pub host: Option<Arc<str>>,
    pub path: Arc<str>,
    pub method: Arc<str>,
    pub scheme: Arc<str>,
    pub user_agent: Option<Arc<str>>,

    // Pre-parsed request headers — cloned once from raw HeaderMap.
    // Using http::HeaderMap directly avoids to_lowercase() + to_string()
    // allocations per header. HeaderMap::clone() is zero-alloc (Bytes refcount bumps).
    // Case-insensitive lookup is built-in.
    pub headers: HeaderMap,

    // Lazy parsed data (populated on first access)
    pub query_cache: Option<HashMap<String, String>>,
    pub cookie_cache: Option<HashMap<String, String>>,
    /// Per-token JWT result for this request (key: the raw token).
    pub jwt_cache: HashMap<String, crate::jwt::JwtOutcome>,
    /// JWT keys from the config snapshot this request runs under. None →
    /// tokens are decoded without checking.
    pub jwt: Option<Arc<crate::jwt::CompiledJwt>>,

    // IP intelligence
    pub ip_intel: Option<Arc<IpIntel>>,

    // Plugin results
    pub firewall: FirewallResult,
    pub request_transform: RequestTransformState,
    pub response_transform: ResponseTransformState,
    pub rate_limit: RateLimitResult,
    pub cache: CacheResult,
    pub load_balancer: LoadBalancerResult,

    // Upstream
    pub upstream_name: Option<Arc<str>>,
    pub upstream_target: Option<Arc<str>>,
    pub upstream_protocol: Option<UpstreamProtocol>,

    // Response / bandwidth
    pub status_code: Option<u16>,
    /// Status the origin sent, before response_transform (cache stores this one).
    pub upstream_status: Option<u16>,

    pub client_bytes_in: u64,
    pub client_bytes_out: u64,
    pub upstream_bytes_out: u64,
    pub upstream_bytes_in: u64,

    // Cache response capture (populated in response_filter)
    pub response_headers_captured: Option<Vec<(String, String)>>,
    pub response_body_buffer: Vec<u8>,
    pub cache_should_store: bool,

    /// Cache revalidation lock guard — held while this request refreshes a stale entry.
    /// When dropped (request completes), the lock releases and concurrent requests
    /// see fresh cache data.
    pub revalidation_guard: Option<RevalidationGuard>,

    /// Stored copy kept while this request goes to the origin (revalidation,
    /// or an expired entry still inside its stale-if-error window). Used for
    /// the conditional request, a 304 answer and stale-if-error.
    pub cache_stale: Option<CacheEntry>,
    /// Set by response_filter when the origin answer is replaced by a stored
    /// copy (304 or stale-if-error); fail_to_proxy writes it to the client.
    pub serve_from_cache: Option<CacheEntry>,

    // Timings (microseconds)
    pub ip_intel_latency_us: Option<u64>,
    pub firewall_latency_us: Option<u64>,
    pub rate_limit_latency_us: Option<u64>,
    pub cache_lookup_latency_us: Option<u64>,
    pub lb_latency_us: Option<u64>,
    pub upstream_connect_latency_us: Option<u64>,
    pub upstream_ttfb_us: Option<u64>,
    pub total_latency_us: Option<u64>,

    /// When the upstream was chosen and the connection started (upstream_peer).
    pub upstream_sent_at: Option<Instant>,
    /// Upstream chosen → response header received (or failure), microseconds.
    pub upstream_us: u64,

    // Final action
    pub termination_phase: Option<TerminationPhase>,
    /// server.protection / server.limits refusal (Violation::as_str).
    pub protection: Option<&'static str>,
    /// What stopped the request (firewall block/redirect, rate limit, DoS
    /// protection). Default (empty) when nothing did. Logged as `block`.
    pub block: BlockResult,
    /// Firewall `allow` rule that let the request skip the rules after it.
    pub allow_rule: Option<Arc<str>>,
}

// Type aliases for Arc-wrapped shared cache data
pub type SharedHeaders = Arc<Vec<(String, String)>>;
pub type SharedBody = Arc<Vec<u8>>;

impl RequestContext {
    pub fn new(
        gateway_id: Arc<str>,
        gateway_name: Arc<str>,
        server_name: Arc<str>,
        config_version: Arc<str>,
        peer_ip: IpAddr,
        client_ip: IpAddr,
        client_ip_source: Arc<str>,
        host: Option<Arc<str>>,
        path: Arc<str>,
        method: Arc<str>,
        scheme: Arc<str>,
        user_agent: Option<Arc<str>>,
        headers: HeaderMap,
    ) -> Self {
        Self {
            gateway_id,
            gateway_name,
            server_name,
            config_version,
            request_id: String::new(),
            ts_ms: 0,
            started_at: Instant::now(),
            peer_ip,
            client_ip,
            client_ip_source,
            host,
            path,
            method,
            scheme,
            user_agent,
            headers,
            query_cache: None,
            cookie_cache: None,
            jwt_cache: HashMap::new(),
            jwt: None,
            ip_intel: None,
            firewall: FirewallResult::default(),
            request_transform: RequestTransformState::default(),
            response_transform: ResponseTransformState::default(),
            rate_limit: RateLimitResult::default(),
            cache: CacheResult::default(),
            load_balancer: LoadBalancerResult::default(),
            upstream_name: None,
            upstream_target: None,
            upstream_protocol: None,
            status_code: None,
            upstream_status: None,
            client_bytes_in: 0,
            client_bytes_out: 0,
            upstream_bytes_out: 0,
            upstream_bytes_in: 0,
            response_headers_captured: None,
            response_body_buffer: Vec::new(),
            cache_should_store: false,
            revalidation_guard: None,
            cache_stale: None,
            serve_from_cache: None,
            ip_intel_latency_us: None,
            firewall_latency_us: None,
            rate_limit_latency_us: None,
            cache_lookup_latency_us: None,
            lb_latency_us: None,
            upstream_connect_latency_us: None,
            upstream_ttfb_us: None,
            total_latency_us: None,
            upstream_sent_at: None,
            upstream_us: 0,
            termination_phase: None,
            protection: None,
            block: BlockResult::default(),
            allow_rule: None,
        }
    }

    /// Get total client bandwidth
    pub fn total_client_bandwidth_bytes(&self) -> u64 {
        self.client_bytes_in + self.client_bytes_out
    }

    /// Get total origin bandwidth
    pub fn total_origin_bandwidth_bytes(&self) -> u64 {
        self.upstream_bytes_out + self.upstream_bytes_in
    }

    /// Record total latency since request started
    pub fn finalize_latency(&mut self) {
        let elapsed = self.started_at.elapsed().as_micros() as u64;
        self.total_latency_us = Some(elapsed);
    }
}

// ── Plugin Result Types ──────────────────────────────────────────────────────

/// The one thing that stopped a request. A request can only be stopped once
/// (the first refusal ends the pipeline), so a single value covers firewall,
/// rate limit and DoS protection.
#[derive(Debug, Clone, Default)]
pub struct BlockResult {
    /// "" (not blocked), "fw", "rl" or "dos".
    pub kind: &'static str,
    /// "" or "block"; "redirect" for a firewall redirect rule.
    pub action: &'static str,
    /// Firewall / rate-limit rule ID, or the DoS check (request_rate, ...).
    pub rule: Option<Arc<str>>,
    /// What the rule matched on, as `field=value` pairs joined by `&`:
    /// the firewall conditions that decided the match, the rate-limit key,
    /// or `client_ip=...` for DoS protection.
    pub key: String,
}

impl BlockResult {
    pub fn dos(violation: &'static str, client_ip: IpAddr) -> Self {
        Self {
            kind: "dos",
            action: "block",
            rule: Some(Arc::from(violation)),
            key: format!("client_ip={client_ip}"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FirewallResult {
    pub matched: bool,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub action: Option<FirewallActionType>,
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Default)]
pub struct RateLimitResult {
    pub matched: bool,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub blocked: bool,
    pub remaining: Option<u64>,
    pub limit: Option<u64>,
    pub window_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct CacheResult {
    pub rule_id: Option<String>,
    pub status: CacheStatus,
    pub key_hash: Option<String>,
    pub edge_ttl_mode: Option<&'static str>,
    pub edge_ttl_seconds: Option<u64>,
    pub browser_ttl_mode: Option<&'static str>,
    pub browser_ttl_seconds: Option<u64>,
    /// Gateway-level stale-while-revalidate override (seconds) from config.
    /// If Some, overrides origin Cache-Control header value.
    pub stale_while_revalidate_seconds: Option<u64>,
    /// Gateway-level stale-if-error override (seconds) from config.
    /// If Some, overrides origin Cache-Control header value.
    pub stale_if_error_seconds: Option<u64>,
    /// Cached max object size from config — avoids arc_swap::load() on every body chunk.
    pub max_object_size_bytes: usize,
    /// Origin statuses the matched rule allows storing.
    pub statuses: Option<Arc<[u16]>>,
    /// Normalized Accept-Encoding bucket ("br", "gzip", "identity"). Part of
    /// the cache key and sent upstream in place of the client's header.
    pub encoding: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CacheStatus {
    #[default]
    None,
    Hit,
    Miss,
    Expired,
    Bypass,
    Dynamic,
    Stale,
    Revalidating,
    /// Origin answered the conditional request with 304; stored copy served.
    Revalidated,
}

impl CacheStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CacheStatus::None => "NONE",
            CacheStatus::Hit => "HIT",
            CacheStatus::Miss => "MISS",
            CacheStatus::Expired => "EXPIRED",
            CacheStatus::Bypass => "BYPASS",
            CacheStatus::Dynamic => "DYNAMIC",
            CacheStatus::Stale => "STALE",
            CacheStatus::Revalidating => "REVALIDATING",
            CacheStatus::Revalidated => "REVALIDATED",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LoadBalancerResult {
    pub lb_id: Option<Arc<str>>,
    pub lb_name: Option<Arc<str>>,
    pub algorithm: Option<String>,
    pub target_id: Option<Arc<str>>,
    pub target_host: Option<Arc<str>>,
    pub target_port: Option<u16>,
    pub target_protocol: Option<Arc<str>>,
    pub target_tls_verify: Option<bool>,
    pub target_tls_sni: Option<Arc<str>>,
}

// ── Termination Phase ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationPhase {
    /// server.protection / server.limits (flood limit, ban, oversized body)
    Protection,
    IpIntel,
    Firewall,
    RateLimit,
    Cache,
    LoadBalancer,
    Upstream,
    Logging,
    InternalError,
}

// ── Upstream Protocol ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamProtocol {
    Http,
    Https,
}
