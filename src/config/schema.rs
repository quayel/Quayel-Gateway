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

    /// Server settings: workers, timeouts, size limits and connection/flood
    /// protection. Optional; every field has a built-in default and any value
    /// set here overrides it.
    #[serde(default)]
    pub server: ServerConfig,

    /// JWT keys. Optional: without it, `header.<name>.jwt.*` fields decode
    /// tokens without checking them. With it, those fields only resolve for
    /// tokens that pass the signature and claim checks.
    #[serde(default)]
    pub jwt: Option<JwtConfig>,

    /// Prometheus `/metrics` endpoint on its own listener. Optional; omitted
    /// → no metrics. `listen` and `path` are read at startup only.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,

    pub plugins: PluginsConfig,
}

// ── Metrics Config ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Address of the metrics listener. Keep it private: it isn't behind the
    /// firewall plugin.
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
    #[serde(default = "default_metrics_path")]
    pub path: String,
    /// Distinct `host` label values kept. Hosts after this many are counted
    /// as `host="_other"`, so random Host headers can't grow memory.
    #[serde(default = "default_metrics_max_hosts")]
    pub max_hosts: usize,
}

fn default_metrics_listen() -> String {
    "127.0.0.1:9464".to_string()
}
fn default_metrics_path() -> String {
    "/metrics".to_string()
}
fn default_metrics_max_hosts() -> usize {
    1000
}

// ── JWT Config ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Clock skew allowed when checking `exp` and `nbf`.
    #[serde(default = "default_jwt_leeway_secs")]
    pub leeway_secs: u64,
    /// Claims a token must carry (any of exp, nbf, iss, aud, sub).
    #[serde(default = "default_jwt_required_claims")]
    pub required_claims: Vec<String>,
    /// A token is valid if it verifies against any one of these keys.
    pub keys: Vec<JwtKeyConfig>,
    /// How many verified tokens to remember, so a client that reuses its
    /// token skips the signature check. 0 turns the cache off.
    #[serde(default = "default_jwt_verified_cache_size")]
    pub verified_cache_size: usize,
    /// Longest a verified token is remembered. Entries also end at the
    /// token's own `exp`. Bounds how long a key removed from a JWKS keeps
    /// working for tokens it already signed.
    #[serde(default = "default_jwt_verified_cache_ttl_secs")]
    pub verified_cache_ttl_secs: u64,
}

/// One verification key. Set exactly one of the key sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtKeyConfig {
    pub id: String,
    /// Algorithms this key accepts, e.g. ["RS256"]. The token's own `alg`
    /// header can only pick from this list.
    pub algorithms: Vec<String>,
    /// Only use this key for tokens whose header `kid` matches.
    #[serde(default)]
    pub kid: Option<String>,

    // HS* shared secret
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub secret_env: Option<String>,
    #[serde(default)]
    pub secret_file: Option<String>,

    // RS* / PS* / ES* / EdDSA public key: PEM, base64 body, or a list of lines
    #[serde(default)]
    pub public_key: Option<StringOrList>,
    #[serde(default)]
    pub public_key_env: Option<String>,
    #[serde(default)]
    pub public_key_file: Option<String>,

    /// Inline JWKS document: `{ "keys": [ ... ] }`.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// JWKS URL, fetched in the background and refreshed.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Refresh interval for `jwks_url` (default 600; a `Cache-Control:
    /// max-age` on the response wins).
    #[serde(default)]
    pub jwks_refresh_secs: Option<u64>,

    /// Accepted `iss` value(s). Omitted → not checked.
    #[serde(default)]
    pub issuer: Option<StringOrList>,
    /// Accepted `aud` value(s). Omitted → not checked.
    #[serde(default)]
    pub audience: Option<StringOrList>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    One(String),
    Many(Vec<String>),
}

impl StringOrList {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            StringOrList::One(s) => vec![s.clone()],
            StringOrList::Many(v) => v.clone(),
        }
    }
}

fn default_jwt_leeway_secs() -> u64 {
    30
}

fn default_jwt_required_claims() -> Vec<String> {
    vec!["exp".to_string()]
}

fn default_jwt_verified_cache_size() -> usize {
    10_000
}

fn default_jwt_verified_cache_ttl_secs() -> u64 {
    60
}

// ── Server Config ────────────────────────────────────────────────────────────
// `server` and each of its sub-sections are optional. Any field left out uses
// the default below. For timeouts and limits, 0 switches that one check off
// (for `keepalive_secs`, 0 turns keep-alive off).
//
// Settings marked "startup only" are read once when the gateway starts; the
// rest also change on live config reload.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Worker threads. Omitted → all CPU cores. `--workers` on the command
    /// line wins. Startup only.
    #[serde(default)]
    pub workers: Option<usize>,
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub protection: ProtectionConfig,
    #[serde(default)]
    pub request_id: RequestIdConfig,
}

/// `X-QG-Request-Id`: one ID per request, logged, sent upstream and returned
/// to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestIdConfig {
    /// Reuse a well-formed `X-QG-Request-Id` sent by the client or a proxy in
    /// front. false → always generate a new one.
    #[serde(default = "default_true")]
    pub accept_incoming: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutsConfig {
    /// The whole request header must arrive within this time, counted from
    /// the connection opening (first request) or from its first byte (later
    /// keep-alive requests). Stops Slowloris.
    #[serde(default = "default_header_secs")]
    pub header_secs: u64,
    /// How long an idle keep-alive connection waits for the next request.
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    /// Longest gap allowed between two reads of a request body (slow POST).
    #[serde(default = "default_body_read_secs")]
    pub body_read_secs: u64,
    /// Longest a single write to the client may take (slow-read clients).
    #[serde(default = "default_response_write_secs")]
    pub response_write_secs: u64,
    #[serde(default = "default_upstream_connect_secs")]
    pub upstream_connect_secs: u64,
    /// TCP connect plus TLS handshake to the upstream.
    #[serde(default = "default_upstream_total_connect_secs")]
    pub upstream_total_connect_secs: u64,
    #[serde(default = "default_upstream_read_secs")]
    pub upstream_read_secs: u64,
    #[serde(default = "default_upstream_write_secs")]
    pub upstream_write_secs: u64,
    /// How long an unused upstream connection stays in the keep-alive pool.
    #[serde(default = "default_upstream_idle_secs")]
    pub upstream_idle_secs: u64,
    /// Time in-flight requests get to finish after SIGTERM. Startup only.
    #[serde(default = "default_graceful_shutdown_secs")]
    pub graceful_shutdown_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Largest request header block (request line + all headers). Larger →
    /// connection closed.
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Largest request body. Larger → 413.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u64,
    /// Requests served on one keep-alive connection before it is closed.
    /// Startup only.
    #[serde(default = "default_max_requests_per_connection")]
    pub max_requests_per_connection: u32,
    /// Idle upstream connections kept per worker. Startup only.
    #[serde(default = "default_upstream_keepalive_pool_size")]
    pub upstream_keepalive_pool_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionConfig {
    /// Master switch for the per-IP limits and bans below.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// CIDRs that skip every per-IP limit and are never banned.
    #[serde(default = "default_exempt_ips")]
    pub exempt_ips: Vec<String>,
    /// Skip the per-IP *connection* limits for Cloudflare's edge ranges, which
    /// carry many visitors over few IPs. Request limits still apply per client IP.
    #[serde(default = "default_true")]
    pub exempt_cloudflare: bool,
    /// Open connections one IP may hold at once (Slowloris, connection floods).
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_max_new_connections_per_ip_per_sec")]
    pub max_new_connections_per_ip_per_sec: u32,
    /// Requests per second from one client IP across all routes (HTTP
    /// floods). Over → 429.
    #[serde(default = "default_max_requests_per_ip_per_sec")]
    pub max_requests_per_ip_per_sec: u32,
    #[serde(default)]
    pub ban: BanConfig,
}

/// Temporary bans: an IP that breaks the limits above `strikes` times within
/// `window_secs` is refused for `duration_secs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ban_strikes")]
    pub strikes: u32,
    #[serde(default = "default_ban_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_ban_duration_secs")]
    pub duration_secs: u64,
}

// Defaults come from the serde attributes so there is one source of truth.
impl Default for ServerConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("ServerConfig defaults")
    }
}
impl Default for TimeoutsConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("TimeoutsConfig defaults")
    }
}
impl Default for LimitsConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("LimitsConfig defaults")
    }
}
impl Default for RequestIdConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("RequestIdConfig defaults")
    }
}
impl Default for ProtectionConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("ProtectionConfig defaults")
    }
}
impl Default for BanConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("BanConfig defaults")
    }
}

fn default_header_secs() -> u64 {
    10
}
fn default_keepalive_secs() -> u64 {
    60
}
fn default_body_read_secs() -> u64 {
    30
}
fn default_response_write_secs() -> u64 {
    60
}
fn default_upstream_connect_secs() -> u64 {
    5
}
fn default_upstream_total_connect_secs() -> u64 {
    10
}
fn default_upstream_read_secs() -> u64 {
    60
}
fn default_upstream_write_secs() -> u64 {
    30
}
fn default_upstream_idle_secs() -> u64 {
    30
}
fn default_graceful_shutdown_secs() -> u64 {
    5
}
fn default_max_header_bytes() -> usize {
    32 * 1024
}
fn default_max_body_bytes() -> u64 {
    100 * 1024 * 1024
}
fn default_max_requests_per_connection() -> u32 {
    10_000
}
fn default_upstream_keepalive_pool_size() -> usize {
    1024
}
fn default_exempt_ips() -> Vec<String> {
    vec!["127.0.0.0/8".to_string(), "::1/128".to_string()]
}
fn default_max_connections_per_ip() -> u32 {
    256
}
fn default_max_new_connections_per_ip_per_sec() -> u32 {
    100
}
fn default_max_requests_per_ip_per_sec() -> u32 {
    500
}
fn default_ban_strikes() -> u32 {
    50
}
fn default_ban_window_secs() -> u64 {
    60
}
fn default_ban_duration_secs() -> u64 {
    600
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
    pub request_transform: Option<TransformConfig>,

    #[serde(default)]
    pub cache: Option<CacheConfig>,

    #[serde(default)]
    pub response_transform: Option<TransformConfig>,

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
    /// Optional: send the lookup results to the upstream as X-QG-* headers.
    #[serde(default)]
    pub forward_headers: Option<ForwardHeadersConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardHeadersConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_forward_prefix")]
    pub prefix: String,
    /// Omitted → every field. See gateway::forward_headers for valid names.
    #[serde(default)]
    pub fields: Option<Vec<String>>,
}

fn default_forward_prefix() -> String {
    crate::gateway::forward_headers::DEFAULT_PREFIX.to_string()
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

// ── Transform Config ─────────────────────────────────────────────────────────
// Shared by plugins.request_transform and plugins.response_transform. Which
// action types and operations are valid depends on the plugin; the compiler
// (plugins::transform) rejects the rest.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<TransformRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformRule {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default)]
    pub actions: Vec<TransformAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformAction {
    /// header | path | query | status
    #[serde(rename = "type")]
    pub action_type: String,
    /// set | add | remove | rename | replace_prefix | regex_replace
    pub operation: String,
    /// Header or query parameter name.
    #[serde(default)]
    pub name: Option<String>,
    /// New value: header/query value, path for `path set`, status code for `status set`.
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    /// Prefix to replace (`path replace_prefix`).
    #[serde(default)]
    pub from: Option<String>,
    /// New name (`rename`) or new prefix (`path replace_prefix`).
    #[serde(default)]
    pub to: Option<String>,
    /// Regex for `path regex_replace`.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Replacement for `path regex_replace` ($1, $2 ... refer to capture groups).
    #[serde(default)]
    pub replacement: Option<String>,
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
    /// Where events go. Only "file" today.
    #[serde(default = "default_log_mode")]
    pub mode: String,
    /// Events waiting to be written. When full (disk slower than traffic),
    /// new events are dropped and counted instead of using more memory.
    #[serde(default = "default_log_queue_size")]
    pub queue_size: usize,
    #[serde(default)]
    pub file: Option<LogFileConfig>,
    /// Condition field logged as `user` on every line, e.g.
    /// "header.authorization.jwt.sub". Unset → `user` is "".
    #[serde(default)]
    pub user_field: Option<String>,
    /// Where else lines go: stdout, ClickHouse, Datadog, OpenTelemetry,
    /// Loki, Elasticsearch/OpenSearch, Splunk, or any HTTP endpoint. With
    /// sinks set and no `file` section, no file is written.
    #[serde(default)]
    pub sinks: Vec<LogSinkConfig>,
}

/// One log destination. `type` picks the format; fields that don't apply to
/// the type are refused by the config compiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSinkConfig {
    /// stdout | http | clickhouse | datadog | otlp | loki | elasticsearch | splunk
    #[serde(rename = "type")]
    pub kind: String,
    /// Name in the gateway's own logs, in metrics and for the spool
    /// directory. Default: the type.
    #[serde(default)]
    pub name: Option<String>,
    /// Base URL. Required except for stdout and datadog (which uses `site`).
    #[serde(default)]
    pub url: Option<String>,

    // ── Format-specific ──
    /// clickhouse: database (default "default")
    #[serde(default)]
    pub database: Option<String>,
    /// clickhouse: table (default "access_log")
    #[serde(default)]
    pub table: Option<String>,
    /// elasticsearch: index (default "quayel-access"); splunk: index
    #[serde(default)]
    pub index: Option<String>,
    /// datadog: site, e.g. "datadoghq.com" (default), "datadoghq.eu"
    #[serde(default)]
    pub site: Option<String>,
    /// datadog / otlp: service name (default "quayel-gateway")
    #[serde(default)]
    pub service: Option<String>,
    /// datadog: ddsource; splunk: source (default "quayel-gateway")
    #[serde(default)]
    pub source: Option<String>,
    /// datadog: ddtags, e.g. "env:prod,team:edge"
    #[serde(default)]
    pub tags: Option<String>,
    /// splunk: sourcetype (default "quayel:access")
    #[serde(default)]
    pub sourcetype: Option<String>,
    /// loki: stream labels (default {"job": "quayel-gateway"}); gateway_id
    /// is always added.
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// otlp: resource attributes added next to service.name.
    #[serde(default)]
    pub resource_attributes: HashMap<String, String>,
    /// loki: X-Scope-OrgID
    #[serde(default)]
    pub tenant_id: Option<String>,

    // ── Credentials (each secret can come from an env var instead) ──
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub password_env: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_env: Option<String>,
    /// Extra request headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Extra request headers whose values come from env vars:
    /// {"Authorization": "MY_AUTH_HEADER"}.
    #[serde(default)]
    pub headers_env: HashMap<String, String>,

    // ── Delivery ──
    /// Lines per request. Default: ClickHouse and http 100000, Datadog 1000
    /// (its limit), others 5000.
    #[serde(default)]
    pub batch_size: Option<usize>,
    /// Longest a line waits before its batch is sent. Default 1000
    /// (ClickHouse 5000).
    #[serde(default)]
    pub flush_interval_ms: Option<u64>,
    #[serde(default = "default_sink_timeout_ms")]
    pub timeout_ms: u64,
    /// "gzip" (default) or "none".
    #[serde(default = "default_sink_compression")]
    pub compression: String,
    /// Unsent lines kept in memory while the destination is down. Past this
    /// the oldest batches go to the spool, or are dropped and counted
    /// without one.
    #[serde(default = "default_sink_max_buffer_bytes")]
    pub max_buffer_bytes: usize,
    /// Directory for batches that couldn't be sent yet. They're sent first
    /// once the destination is back, also after a restart. Unset → no spool.
    #[serde(default)]
    pub spool_dir: Option<String>,
    /// Spool size limit; the oldest batches are dropped (and counted) past it.
    #[serde(default = "default_sink_spool_max_bytes")]
    pub spool_max_bytes: u64,
}

fn default_sink_timeout_ms() -> u64 {
    10_000
}
fn default_sink_compression() -> String {
    "gzip".to_string()
}
fn default_sink_max_buffer_bytes() -> usize {
    // Room for a few full 100k-line batches (~60 MB each).
    256 << 20
}
fn default_sink_spool_max_bytes() -> u64 {
    1 << 30
}

fn default_log_queue_size() -> usize {
    65_536
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
    /// Custom ACME directory URL (step-ca, Pebble, ...). Overrides `staging`.
    /// CAs that need External Account Binding aren't supported.
    #[serde(default)]
    pub directory_url: Option<String>,
    /// PEM file with the root CA of a private ACME server's HTTPS endpoint.
    #[serde(default)]
    pub ca_root: Option<String>,
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
