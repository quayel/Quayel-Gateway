use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Top-level Gateway Configuration ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub gateway_id: String,
    pub gateway_name: String,
    pub server_name: String,
    pub config_version: String,

    /// Optional: omitted → HTTP on 0.0.0.0:80, HTTPS (Auto-SSL) on 0.0.0.0:443.
    #[serde(default)]
    pub listen: ListenConfig,

    #[serde(default = "default_client_ip")]
    pub client_ip: ClientIpConfig,

    pub plugins: PluginsConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListenConfig {
    pub http: Option<String>,
    pub https: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientIpConfig {
    pub source: ClientIpSource,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub index: Option<usize>,
    #[serde(default)]
    pub fallback: Option<FallbackMode>,
}

fn default_client_ip() -> ClientIpConfig {
    ClientIpConfig {
        source: ClientIpSource::PeerIp,
        header: None,
        index: None,
        fallback: None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientIpSource {
    PeerIp,
    Header,
    HeaderIndex,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FallbackMode {
    PeerIp,
}

// ── Plugins Configuration ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginsConfig {
    #[serde(default)]
    pub ip_intel: Option<IpIntelConfig>,

    #[serde(default)]
    pub firewall: Option<FirewallConfig>,

    #[serde(default)]
    pub rate_limiting: Option<RateLimitingConfig>,

    #[serde(default)]
    pub cache: Option<CacheConfig>,

    #[serde(default)]
    pub load_balancer: Option<LoadBalancerPluginConfig>,

    #[serde(default)]
    pub logging: Option<LoggingConfig>,

    #[serde(default)]
    pub auto_ssl: Option<AutoSslConfig>,
}

// ── IP Intelligence Config ───────────────────────────────────────────────────
// All data is embedded in the binary. Only `enabled` is needed.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIntelConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

// ── Firewall Config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    pub action: FirewallAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallAction {
    #[serde(rename = "type")]
    pub action_type: FirewallActionType,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallActionType {
    Allow,
    Block,
    Redirect,
    SetRequestHeader,
    SetResponseHeader,
}

// ── Condition ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub left: String,
    pub operator: Operator,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    #[serde(default)]
    pub next: Option<LogicalOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogicalOp {
    And,
    Or,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Exists,
    NotExists,
    In,
    NotIn,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Regex,
}

// ── Rate Limiting Config ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<RateLimitRule>,
}

/// Rate limit key — accepts either a single string or an array of strings.
///
/// Single:  `"key": "req.ip"`
/// Array:   `"key": ["req.ip", "header.x-api-key"]`
///
/// Each element can use dot-notation paths including deep JWT extraction:
///   `"header.token.jwt.user_id"` → get header "token", decode JWT, extract "user_id" claim
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RateLimitKey {
    Single(String),
    Composite(Vec<String>),
}

impl RateLimitKey {
    /// Normalize to a Vec of key parts (always at least one element).
    pub fn to_parts(&self) -> Vec<String> {
        match self {
            RateLimitKey::Single(s) => vec![s.clone()],
            RateLimitKey::Composite(parts) => parts.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    pub key: RateLimitKey,
    pub limit: u64,
    pub window_seconds: u64,
    #[serde(default)]
    pub action: Option<RateLimitAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitAction {
    #[serde(rename = "type")]
    pub action_type: RateLimitActionType,
    #[serde(default)]
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitActionType {
    Block,
}

// ── Cache Config ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_object_size")]
    pub max_object_size_bytes: usize,
    #[serde(default)]
    pub rules: Vec<CacheRule>,
}

fn default_max_object_size() -> usize {
    10_485_760 // 10MB
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default = "default_cache_eligible")]
    pub cache: CacheMode,
    pub edge_ttl: EdgeTtlConfig,
    #[serde(default)]
    pub browser_ttl: Option<BrowserTtlConfig>,
    #[serde(default)]
    pub cache_key: Option<CacheKeyConfig>,
    #[serde(default)]
    pub statuses: Option<Vec<u16>>,
    /// Stale-while-revalidate window (seconds). Overrides origin Cache-Control header.
    /// During this window after edge_ttl expires, one request revalidates while others serve stale.
    #[serde(default)]
    pub stale_while_revalidate: Option<u64>,
    /// Stale-if-error window (seconds). Overrides origin Cache-Control header.
    /// Allows serving stale data when origin returns errors (5xx, timeout).
    #[serde(default)]
    pub stale_if_error: Option<u64>,
}

fn default_cache_eligible() -> CacheMode {
    CacheMode::Eligible
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    Eligible,
    Bypass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeTtlConfig {
    pub mode: EdgeTtlMode,
    #[serde(default)]
    pub seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeTtlMode {
    Origin,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserTtlConfig {
    pub mode: BrowserTtlMode,
    #[serde(default)]
    pub seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserTtlMode {
    Bypass,
    Origin,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheKeyConfig {
    pub mode: CacheKeyMode,
    #[serde(default)]
    pub parts: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheKeyMode {
    Default,
    Custom,
}

// ── Load Balancer Plugin Config ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerPluginConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub load_balancers: Vec<LoadBalancerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    pub algorithm: AlgorithmConfig,
    pub targets: Vec<TargetConfig>,
    #[serde(default)]
    pub host_header: Option<HostHeaderConfig>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmConfig {
    #[serde(rename = "type")]
    pub algorithm_type: AlgorithmType,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmType {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    FastResponse,
    StickySession,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub id: String,
    pub host: String,
    pub port: u16,
    #[serde(default = "default_target_protocol")]
    pub protocol: TargetProtocol,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub tls: TargetTlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTlsConfig {
    #[serde(default)]
    pub verify: bool,
    #[serde(default)]
    pub sni: Option<String>,
}

impl Default for TargetTlsConfig {
    fn default() -> Self {
        Self {
            verify: false,
            sni: None,
        }
    }
}

fn default_target_protocol() -> TargetProtocol {
    TargetProtocol::Http
}
fn default_weight() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TargetProtocol {
    Http,
    Https,
}

impl TargetProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetProtocol::Http => "http",
            TargetProtocol::Https => "https",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostHeaderConfig {
    pub mode: HostHeaderMode,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostHeaderMode {
    Visitor,
    Custom,
    Target,
}

// ── Health Check Config ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub mode: HealthCheckMode,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_hc_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_hc_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub expected_statuses: Option<Vec<u16>>,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_hc_interval() -> u64 {
    5
}
fn default_hc_timeout() -> u64 {
    1000
}
fn default_healthy_threshold() -> u32 {
    2
}
fn default_unhealthy_threshold() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckMode {
    Https,
    AcceptsConnections,
    Off,
}

// ── Logging Config ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_log_mode")]
    pub mode: String,
    #[serde(default)]
    pub file: Option<LogFileConfig>,
}

fn default_log_mode() -> String {
    "file".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFileConfig {
    pub path: String,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_ms: u64,
}

fn default_buffer_size() -> usize {
    8192
}
fn default_flush_interval() -> u64 {
    1000
}

// ── Auto-SSL Config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoSslConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Email for Let's Encrypt account registration
    pub email: String,
    /// Domains to provision certificates for
    pub domains: Vec<String>,
    /// Path to store PEM files (write-through cache for restart recovery)
    #[serde(default = "default_cert_storage_path")]
    pub cert_storage_path: String,
    /// Use Let's Encrypt staging environment (for testing)
    #[serde(default)]
    pub staging: bool,
    /// Renew certificates this many days before expiry
    #[serde(default = "default_renewal_days_before")]
    pub renewal_days_before: u32,
}

fn default_cert_storage_path() -> String {
    "/var/lib/quayel/certs".to_string()
}

fn default_renewal_days_before() -> u32 {
    30
}