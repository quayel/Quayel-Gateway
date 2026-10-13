use crate::condition::CompiledCondition;
use crate::config::schema::*;
use crate::config::sinks::{compile_metrics, compile_sinks, CompiledMetrics, CompiledSink};
use crate::gateway::forward_headers::{compile_forward_headers, CompiledForwardHeaders};
use crate::gateway::protection::{compile_server, CompiledServer};
use crate::jwt::{compile_jwt, CompiledJwt};
use crate::plugins::transform::{compile_transform, CompiledTransform, TransformPhase};
use std::sync::Arc;

// ── Compiled Configuration ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledConfig {
    pub gateway_id: Arc<str>,
    pub gateway_name: Arc<str>,
    pub server_name: Arc<str>,
    pub config_version: Arc<str>,

    pub listen_http: Option<String>,
    pub listen_https: Option<String>,

    pub client_ip: CompiledClientIp,

    pub server: CompiledServer,

    /// None → JWT fields decode tokens without checking them.
    pub jwt: Option<Arc<CompiledJwt>>,

    pub ip_intel: Option<CompiledIpIntel>,
    pub firewall: Option<CompiledFirewall>,
    pub rate_limiting: Option<CompiledRateLimiting>,
    pub request_transform: Option<CompiledTransform>,
    pub cache: Option<CompiledCache>,
    pub response_transform: Option<CompiledTransform>,
    pub load_balancer: Option<CompiledLoadBalancerPlugin>,
    /// Built when logging or metrics are on: both are fed by the same
    /// event queue.
    pub logging: Option<CompiledLogging>,
    pub auto_ssl: Option<CompiledAutoSsl>,
    /// The metrics listener (startup only).
    pub metrics: Option<CompiledMetrics>,
}

#[derive(Debug, Clone)]
pub struct CompiledClientIp {
    pub source: ClientIpSource,
    pub header: Option<Arc<str>>,
    pub index: Option<usize>,
    pub fallback: Option<FallbackMode>,
}

// ── IP Intel compiled ────────────────────────────────────────────────────────
// All lookup data is embedded in the binary.

#[derive(Debug, Clone)]
pub struct CompiledIpIntel {
    pub enabled: bool,
    /// None unless forward_headers.enabled is true.
    pub forward_headers: Option<CompiledForwardHeaders>,
}

// ── Firewall compiled ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledFirewall {
    pub enabled: bool,
    pub rules: Vec<CompiledFirewallRule>,
}

#[derive(Debug, Clone)]
pub struct CompiledFirewallRule {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub enabled: bool,
    pub conditions: Vec<CompiledCondition>,
    pub action: FirewallAction,
}

// ── Rate limiting compiled ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledRateLimiting {
    pub enabled: bool,
    pub rules: Vec<CompiledRateLimitRule>,
}

#[derive(Debug, Clone)]
pub struct CompiledRateLimitRule {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub enabled: bool,
    pub conditions: Vec<CompiledCondition>,
    /// Key parts — one element for simple keys, multiple for composite keys.
    pub key: Vec<String>,
    pub limit: u64,
    pub window_seconds: u64,
    pub action: RateLimitAction,
}

// ── Cache compiled ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledCache {
    pub enabled: bool,
    pub max_object_size_bytes: usize,
    pub rules: Vec<CompiledCacheRule>,
}

#[derive(Debug, Clone)]
pub struct CompiledCacheRule {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub enabled: bool,
    pub conditions: Vec<CompiledCondition>,
    pub cache: CacheMode,
    pub edge_ttl: EdgeTtlConfig,
    pub browser_ttl: Option<BrowserTtlConfig>,
    pub cache_key: CacheKeyConfig,
    /// Origin statuses that may be stored.
    pub statuses: Arc<[u16]>,
    /// Gateway-level stale-while-revalidate override (seconds).
    /// If set, overrides origin Cache-Control header value.
    pub stale_while_revalidate: Option<u64>,
    /// Gateway-level stale-if-error override (seconds).
    /// If set, overrides origin Cache-Control header value.
    pub stale_if_error: Option<u64>,
}

// ── Load balancer compiled ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledLoadBalancerPlugin {
    pub enabled: bool,
    pub load_balancers: Vec<CompiledLoadBalancer>,
}

#[derive(Debug, Clone)]
pub struct CompiledLoadBalancer {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub enabled: bool,
    pub conditions: Vec<CompiledCondition>,
    pub algorithm: AlgorithmConfig,
    pub targets: Vec<CompiledTarget>,
    pub host_header: HostHeaderConfig,
    pub health_check: Option<HealthCheckConfig>,
}

#[derive(Debug, Clone)]
pub struct CompiledTarget {
    pub id: Arc<str>,
    pub host: Arc<str>,
    pub port: u16,
    pub protocol: TargetProtocol,
    pub weight: u32,
    pub enabled: bool,
    pub tls_verify: bool,
    pub tls_sni: Option<Arc<str>>,
}

// ── Logging compiled ─────────────────────────────────────────────────────────

/// Only built when logging or metrics are enabled. Compared on hot reload:
/// any change starts a new writer.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledLogging {
    pub mode: String,
    /// None → no file (sinks or metrics only).
    pub file_path: Option<String>,
    pub queue_size: usize,
    pub buffer_size: usize,
    pub flush_interval_ms: u64,
    /// plugins.logging.user_field
    pub user_field: Option<String>,
    pub stdout: bool,
    pub sinks: Vec<CompiledSink>,
    /// Some → events also feed the Prometheus metrics.
    pub metrics: Option<CompiledMetrics>,
}

impl CompiledLogging {
    /// True when lines are written anywhere (not only metrics).
    pub fn writes_lines(&self) -> bool {
        self.file_path.is_some() || self.stdout || !self.sinks.is_empty()
    }
}

pub const DEFAULT_LOG_PATH: &str = "/var/log/quayel/access.jsonl";

// ── Auto-SSL compiled ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledAutoSsl {
    pub enabled: bool,
    pub email: String,
    pub domains: Vec<String>,
    pub cert_storage_path: String,
    /// Resolved ACME directory: `directory_url`, else Let's Encrypt staging/production.
    pub directory_url: String,
    /// Root CA PEM for a private ACME server (None = system roots).
    pub ca_root: Option<String>,
    pub renewal_days_before: u32,
}

// ── Compiler ─────────────────────────────────────────────────────────────────

pub fn compile_config(raw: &GatewayConfig) -> Result<CompiledConfig, String> {
    let client_ip = CompiledClientIp {
        source: raw.client_ip.source.clone(),
        header: raw.client_ip.header.as_deref().map(Arc::from),
        index: raw.client_ip.index,
        fallback: raw.client_ip.fallback.clone(),
    };

    let ip_intel = match raw.plugins.ip_intel.as_ref().filter(|c| c.enabled) {
        Some(c) => Some(CompiledIpIntel {
            enabled: c.enabled,
            forward_headers: match &c.forward_headers {
                Some(fh) => compile_forward_headers(fh)?,
                None => None,
            },
        }),
        None => None,
    };

    let firewall = raw
        .plugins
        .firewall
        .as_ref()
        .filter(|c| c.enabled)
        .map(|c| compile_firewall(c));

    let rate_limiting = raw
        .plugins
        .rate_limiting
        .as_ref()
        .filter(|c| c.enabled)
        .map(|c| compile_rate_limiting(c));

    let request_transform = match &raw.plugins.request_transform {
        Some(c) => compile_transform(c, TransformPhase::Request)?,
        None => None,
    };

    let response_transform = match &raw.plugins.response_transform {
        Some(c) => compile_transform(c, TransformPhase::Response)?,
        None => None,
    };

    let cache = raw
        .plugins
        .cache
        .as_ref()
        .filter(|c| c.enabled)
        .map(|c| compile_cache(c));

    let load_balancer = raw
        .plugins
        .load_balancer
        .as_ref()
        .filter(|c| c.enabled)
        .map(|c| compile_load_balancer(c));

    let metrics = match &raw.metrics {
        Some(m) => compile_metrics(m)?,
        None => None,
    };
    let logging = match raw.plugins.logging.as_ref().filter(|c| c.enabled) {
        Some(c) => Some(compile_logging(c, metrics.clone())?),
        // Metrics only: the queue runs without writing any lines.
        None => metrics.clone().map(|m| CompiledLogging {
            mode: "file".to_string(),
            file_path: None,
            queue_size: 65_536,
            buffer_size: 8192,
            flush_interval_ms: 1000,
            user_field: None,
            stdout: false,
            sinks: Vec::new(),
            metrics: Some(m),
        }),
    };

    let auto_ssl = raw
        .plugins
        .auto_ssl
        .as_ref()
        .filter(|c| c.enabled)
        .map(|c| compile_auto_ssl(c));

    let jwt = match &raw.jwt {
        Some(c) => compile_jwt(c)?.map(Arc::new),
        None => None,
    };
    if jwt.is_none() {
        let uses_jwt_fields = serde_json::to_string(&raw.plugins)
            .map(|s| s.contains(".jwt.") || s.contains(".jwt_valid") || s.contains(".jwt_error"))
            .unwrap_or(false);
        if uses_jwt_fields {
            tracing::warn!(
                "rules read JWT claims but no `jwt` keys are configured: tokens are decoded \
                 WITHOUT checking their signature, so clients can forge any claim. Add a \
                 `jwt` section with keys to verify them."
            );
        }
    }

    Ok(CompiledConfig {
        gateway_id: Arc::from(raw.gateway_id.as_str()),
        gateway_name: Arc::from(raw.gateway_name.as_str()),
        server_name: Arc::from(raw.server_name.as_str()),
        config_version: Arc::from(raw.config_version.as_str()),
        listen_http: raw.listen.http.clone(),
        listen_https: raw.listen.https.clone(),
        client_ip,
        server: compile_server(&raw.server)?,
        jwt,
        ip_intel,
        firewall,
        rate_limiting,
        request_transform,
        cache,
        response_transform,
        load_balancer,
        logging,
        auto_ssl,
        metrics,
    })
}

fn compile_firewall(c: &FirewallConfig) -> CompiledFirewall {
    CompiledFirewall {
        enabled: c.enabled,
        rules: c
            .rules
            .iter()
            .map(|r| CompiledFirewallRule {
                id: Arc::from(r.id.as_str()),
                name: Arc::from(r.name.as_str()),
                enabled: r.enabled,
                conditions: compile_conditions(&r.conditions),
                action: r.action.clone(),
            })
            .collect(),
    }
}

fn compile_rate_limiting(c: &RateLimitingConfig) -> CompiledRateLimiting {
    CompiledRateLimiting {
        enabled: c.enabled,
        rules: c
            .rules
            .iter()
            .map(|r| CompiledRateLimitRule {
                id: Arc::from(r.id.as_str()),
                name: Arc::from(r.name.as_str()),
                enabled: r.enabled,
                conditions: compile_conditions(&r.conditions),
                key: r.key.to_parts(),
                limit: r.limit,
                window_seconds: r.window_seconds,
                action: r.action.clone().unwrap_or(RateLimitAction {
                    action_type: RateLimitActionType::Block,
                    status: Some(429),
                }),
            })
            .collect(),
    }
}

fn compile_cache(c: &CacheConfig) -> CompiledCache {
    CompiledCache {
        enabled: c.enabled,
        max_object_size_bytes: c.max_object_size_bytes,
        rules: c
            .rules
            .iter()
            .map(|r| CompiledCacheRule {
                id: Arc::from(r.id.as_str()),
                name: Arc::from(r.name.as_str()),
                enabled: r.enabled,
                conditions: compile_conditions(&r.conditions),
                cache: r.cache.clone(),
                edge_ttl: r.edge_ttl.clone(),
                browser_ttl: r.browser_ttl.clone(),
                cache_key: r.cache_key.clone().unwrap_or(CacheKeyConfig {
                    mode: CacheKeyMode::Default,
                    parts: None,
                }),
                statuses: Arc::from(r.statuses.clone().unwrap_or_else(|| vec![200, 301, 404])),
                stale_while_revalidate: r.stale_while_revalidate,
                stale_if_error: r.stale_if_error,
            })
            .collect(),
    }
}

fn compile_load_balancer(c: &LoadBalancerPluginConfig) -> CompiledLoadBalancerPlugin {
    CompiledLoadBalancerPlugin {
        enabled: c.enabled,
        load_balancers: c
            .load_balancers
            .iter()
            .map(|lb| CompiledLoadBalancer {
                id: Arc::from(lb.id.as_str()),
                name: Arc::from(lb.name.as_str()),
                enabled: lb.enabled,
                conditions: compile_conditions(&lb.conditions),
                algorithm: lb.algorithm.clone(),
                targets: lb
                    .targets
                    .iter()
                    .map(|t| CompiledTarget {
                        id: Arc::from(t.id.as_str()),
                        host: Arc::from(t.host.as_str()),
                        port: t.port,
                        protocol: t.protocol.clone(),
                        weight: t.weight,
                        enabled: t.enabled,
                        tls_verify: t.tls.verify,
                        tls_sni: t.tls.sni.as_deref().map(Arc::from),
                    })
                    .collect(),
                host_header: lb.host_header.clone().unwrap_or(HostHeaderConfig {
                    mode: HostHeaderMode::Visitor,
                    value: None,
                }),
                health_check: lb.health_check.clone(),
            })
            .collect(),
    }
}

fn compile_auto_ssl(c: &AutoSslConfig) -> CompiledAutoSsl {
    CompiledAutoSsl {
        enabled: c.enabled,
        email: c.email.clone(),
        domains: c.domains.clone(),
        cert_storage_path: c.cert_storage_path.clone(),
        directory_url: c.directory_url.clone().unwrap_or_else(|| {
            if c.staging {
                crate::auto_ssl::acme::LETS_ENCRYPT_STAGING
            } else {
                crate::auto_ssl::acme::LETS_ENCRYPT_PROD
            }
            .to_string()
        }),
        ca_root: c.ca_root.clone(),
        renewal_days_before: c.renewal_days_before,
    }
}

fn compile_logging(
    c: &LoggingConfig,
    metrics: Option<CompiledMetrics>,
) -> Result<CompiledLogging, String> {
    if c.mode != "file" {
        return Err(format!(
            "plugins.logging.mode '{}' is not supported (use \"file\")",
            c.mode
        ));
    }
    if c.queue_size == 0 {
        return Err("plugins.logging.queue_size must be at least 1".to_string());
    }
    let (stdout, sinks) = compile_sinks(&c.sinks)?;
    // No `file` section: the default file, unless sinks are set.
    let file_path = match &c.file {
        Some(f) => Some(f.path.clone()),
        None if c.sinks.is_empty() => Some(DEFAULT_LOG_PATH.to_string()),
        None => None,
    };
    if file_path.as_deref().is_some_and(|p| p.trim().is_empty()) {
        return Err("plugins.logging.file.path must not be empty".to_string());
    }
    let buffer_size = c.file.as_ref().map_or(8192, |f| f.buffer_size);
    let flush_interval_ms = c.file.as_ref().map_or(1000, |f| f.flush_interval_ms);
    if buffer_size == 0 || flush_interval_ms == 0 {
        return Err(
            "plugins.logging.file.buffer_size and flush_interval_ms must be at least 1".to_string(),
        );
    }
    Ok(CompiledLogging {
        mode: c.mode.clone(),
        file_path,
        queue_size: c.queue_size,
        buffer_size,
        flush_interval_ms,
        user_field: c
            .user_field
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(String::from),
        stdout,
        sinks,
        metrics,
    })
}

pub fn compile_conditions(conditions: &[Condition]) -> Vec<CompiledCondition> {
    conditions
        .iter()
        .map(|c| {
            // Pre-compile regex patterns at config time to avoid per-request compilation
            let compiled_regex = if c.operator == Operator::Regex {
                c.value.as_ref().and_then(|v| {
                    if let serde_json::Value::String(pattern) = v {
                        match regex::Regex::new(pattern) {
                            Ok(re) => Some(re),
                            Err(e) => {
                                tracing::warn!("Invalid regex pattern '{}': {}", pattern, e);
                                None
                            }
                        }
                    } else {
                        None
                    }
                })
            } else {
                None
            };

            CompiledCondition {
                left: c.left.clone(),
                operator: c.operator.clone(),
                value: c.value.clone(),
                next: c.next.clone(),
                compiled_regex,
            }
        })
        .collect()
}
