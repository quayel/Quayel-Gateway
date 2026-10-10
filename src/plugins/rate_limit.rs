use crate::config::compiler::CompiledConfig;
use crate::gateway::request_context::*;
use crate::plugins::firewall::{evaluate_conditions, resolve_condition_value};
use crate::plugins::{GatewayResponse, PluginFlow};
use bytes::Bytes;
use dashmap::DashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

// Rate Limiting Plugin

// Cleanup interval for the background task
const RL_CLEANUP_INTERVAL_SECS: u64 = 30;

/// Counter map key: a single "<rule_id>\u{0}<key>" String.
/// One allocation per request (vs. two for a struct-of-strings key), and the
/// map can be queried with `&str` — no owned key needs to be built for lookups.
#[derive(Debug)]
pub struct RateLimitPlugin {
    pub counters: Arc<DashMap<String, WindowCounter>>,
}

/// Fully lock-free window counter.
///
/// Both the hot-path increment and the remaining-budget read use only atomic
/// loads / fetch_add / one compare_exchange (cold path, once per window).
/// The previous design took a `parking_lot::Mutex` lock in BOTH `increment()`
/// and `remaining()` — two lock acquisitions per request on a single counter
/// shared by every request from the same client. Under 12 threads that mutex
/// cache line was a real serialization point.
#[derive(Debug)]
pub struct WindowCounter {
    /// Window start in monotonic milliseconds (relative to process start).
    /// Read with a relaxed atomic load on the hot path — no locking.
    window_start_ms: AtomicU64,
    window_seconds: u64,
    /// Atomic counter — lock-free increment via `fetch_add`.
    count: AtomicU64,
}

/// Monotonic milliseconds since process start.
/// `Instant::elapsed()` is a vDSO clock read — no syscall, no allocation.
fn monotonic_ms() -> u64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

impl WindowCounter {
    pub fn new(window_seconds: u64) -> Self {
        Self {
            window_start_ms: AtomicU64::new(monotonic_ms()),
            window_seconds,
            count: AtomicU64::new(0),
        }
    }

    #[inline]
    fn window_expired(&self, now_ms: u64) -> bool {
        let start_ms = self.window_start_ms.load(Ordering::Relaxed);
        now_ms.saturating_sub(start_ms) >= self.window_seconds * 1000
    }

    /// Lock-free increment using atomic operations.
    ///
    /// Hot path (window not expired): one relaxed load + one `fetch_add`.
    /// Cold path (window expired): the winner of a single `compare_exchange`
    /// resets the window and count; losers fall through to the fast path.
    pub fn increment(&self) -> u64 {
        let now_ms = monotonic_ms();
        let start_ms = self.window_start_ms.load(Ordering::Relaxed);

        if now_ms.saturating_sub(start_ms) >= self.window_seconds * 1000 {
            if self.window_start_ms
                .compare_exchange(start_ms, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // We claimed the reset — store 1 and return, no fetch_add race.
                self.count.store(1, Ordering::Release);
                return 1;
            }
            // Another thread claimed the reset — fall through to increment.
        }

        self.count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Read the current count and compute remaining budget.
    /// Relaxed atomic loads only — no locking on the hot path.
    pub fn remaining(&self, limit: u64) -> u64 {
        if self.window_expired(monotonic_ms()) {
            // Window expired — full budget available
            return limit;
        }
        limit.saturating_sub(self.count.load(Ordering::Relaxed))
    }

    /// True when the entry is old enough to be cleaned up.
    pub fn is_expired_for_cleanup(&self) -> bool {
        let now_ms = monotonic_ms();
        let start_ms = self.window_start_ms.load(Ordering::Relaxed);
        now_ms.saturating_sub(start_ms) >= self.window_seconds * 3 * 1000
    }
}

impl RateLimitPlugin {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(DashMap::new()),
        }
    }

    /// Remove expired counters to prevent unbounded memory growth.
    fn cleanup_expired(&self) {
        self.counters.retain(|_, counter| !counter.is_expired_for_cleanup());
    }

    /// Spawn a background tokio task that periodically cleans up expired
    /// rate limit counters. This replaces the inline cleanup that ran every
    /// 500 requests and caused latency spikes on the triggering request.
    ///
    /// The task holds an `Arc` clone of the counters map, so it's safe to
    /// run for the lifetime of the gateway.
    pub fn spawn_cleanup_task(&self, handle: &tokio::runtime::Handle) {
        let counters = Arc::clone(&self.counters);
        handle.spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(RL_CLEANUP_INTERVAL_SECS)
            );
            // Skip the first immediate tick
            interval.tick().await;
            loop {
                interval.tick().await;
                counters.retain(|_, counter| !counter.is_expired_for_cleanup());
            }
        });
    }

    pub async fn execute(
        &self,
        ctx: &mut RequestContext,
        config: &Arc<CompiledConfig>,
    ) -> PluginFlow {
        let rl_config = match &config.rate_limiting {
            Some(c) if c.enabled => c,
            _ => return PluginFlow::Continue,
        };

        for rule in &rl_config.rules {
            if !rule.enabled {
                continue;
            }

            // Fast-path: empty conditions always match
            let matched = rule.conditions.is_empty() || evaluate_conditions(ctx, &rule.conditions);

            if !matched {
                continue;
            }

            // Resolve rate limit key and build the composite map key in ONE
            // String allocation: "<rule_id>\u{0}<key>".
            let mut rl_key = String::with_capacity(rule.id.len() + 24);
            rl_key.push_str(&rule.id);
            rl_key.push('\u{0}');
            resolve_rate_limit_key_into(ctx, &rule.key, &mut rl_key);

            // ── Hot path: single DashMap lookup (borrowed &str key) ─────────
            let (count, remaining) = if let Some(counter) = self.counters.get(rl_key.as_str()) {
                let count = counter.increment();
                let remaining = counter.remaining(rule.limit);
                (count, remaining)
            } else {
                // Cold path: insert new counter (exclusive lock, but rare)
                let counter = self.counters
                    .entry(rl_key)
                    .or_insert_with(|| WindowCounter::new(rule.window_seconds));
                let count = counter.increment();
                let remaining = counter.remaining(rule.limit);
                (count, remaining)
            };

            // Record in context
            {
                ctx.rate_limit.matched = true;
                if ctx.rate_limit.rule_id.as_deref() != Some(&*rule.id) {
                    ctx.rate_limit.rule_id = Some(rule.id.to_string());
                }
                if ctx.rate_limit.rule_name.as_deref() != Some(&*rule.name) {
                    ctx.rate_limit.rule_name = Some(rule.name.to_string());
                }
                ctx.rate_limit.remaining = Some(remaining);
                ctx.rate_limit.limit = Some(rule.limit);
                ctx.rate_limit.window_seconds = Some(rule.window_seconds);
            }

            if count > rule.limit {
                {
                    ctx.rate_limit.blocked = true;
                }

                let status = rule.action.status.unwrap_or(429);
                ctx.status_code = Some(status);

                let body = format!(
                    r#"{{"error":"rate_limited","status":{},"rule_id":"{}","limit":{},"window_seconds":{}}}"#,
                    status, rule.id, rule.limit, rule.window_seconds
                );

                return PluginFlow::Respond(GatewayResponse {
                    status,
                    headers: Arc::new(vec![
                        ("content-type".to_string(), "application/json".to_string()),
                        ("content-length".to_string(), body.len().to_string()),
                        ("retry-after".to_string(), rule.window_seconds.to_string()),
                    ]),
                    body: Bytes::from(body),
                });
            }
        }

        PluginFlow::Continue
    }
}

/// Resolve a composite rate limit key from an array of path strings, appending
/// the resolved value(s) to `out` (which already contains the rule_id prefix).
///
/// Each element is resolved via `resolve_condition_value` (supports all path formats
/// including deep JWT extraction like `"header.token.jwt.user_id"`).
///
/// Single key:  `["req.ip"]`                → "127.0.0.1"
/// Composite:   `["req.ip", "header.x-api-key"]` → "127.0.0.1:abc123"
///
/// Also supports legacy template format: `"{req.client_ip}+{http.header.x-api-key}"`
fn resolve_rate_limit_key_into(ctx: &mut RequestContext, key_parts: &[String], out: &mut String) {
    // Single part — check if it's a legacy template or a simple path
    if key_parts.len() == 1 {
        let part = &key_parts[0];

        // Legacy template mode: "{placeholder}+{placeholder}"
        if part.contains('{') {
            let resolved = resolve_template_key(ctx, part);
            out.push_str(&resolved);
            return;
        }

        // Fast paths for plain scalar fields — writes directly into `out`
        // without allocating a serde_json::Value::String.
        match part.as_str() {
            "req.client_ip" | "http.ip" | "req.ip" => { let _ = write!(out, "{}", ctx.client_ip); return; }
            "req.peer_ip" | "http.peer_ip" => { let _ = write!(out, "{}", ctx.peer_ip); return; }
            "req.path" | "http.path" => { out.push_str(&ctx.path); return; }
            "req.method" | "http.method" => { out.push_str(&ctx.method); return; }
            "req.scheme" | "http.scheme" => { out.push_str(&ctx.scheme); return; }
            "req.host" | "http.host" => { out.push_str(ctx.host.as_deref().unwrap_or("unknown")); return; }
            "req.user_agent" | "http.user_agent" => { out.push_str(ctx.user_agent.as_deref().unwrap_or("unknown")); return; }
            _ => {}
        }

        // Simple single-field resolution (fast path, no separator)
        match resolve_condition_value(ctx, part) {
            Some(serde_json::Value::String(s)) => out.push_str(&s),
            Some(other) => { let _ = write!(out, "{:?}", other); }
            None => out.push_str("unknown"),
        }
        return;
    }

    // Composite key: resolve each part and join with ":"
    for (i, part) in key_parts.iter().enumerate() {
        if i > 0 { out.push(':'); }
        match resolve_condition_value(ctx, part) {
            Some(serde_json::Value::String(s)) => out.push_str(&s),
            Some(other) => { let _ = write!(out, "{:?}", other); }
            None => out.push_str("unknown"),
        }
    }
}

/// Legacy template-based key resolution (backward compatible).
/// Supports: "{req.client_ip}+{http.header.x-api-key}"
fn resolve_template_key(ctx: &mut RequestContext, key_template: &str) -> String {
    let mut result = String::new();
    let mut remaining = key_template;

    while let Some(start) = remaining.find('{') {
        result.push_str(&remaining[..start]);
        remaining = &remaining[start + 1..];

        if let Some(end) = remaining.find('}') {
            let placeholder = &remaining[..end];
            let value = resolve_condition_value(ctx, placeholder)
                .map(|v| match v {
                    serde_json::Value::String(s) => s,
                    other => format!("{:?}", other),
                })
                .unwrap_or_else(|| "unknown".to_string());
            result.push_str(&value);
            remaining = &remaining[end + 1..];
        } else {
            // No closing brace - treat as literal
            result.push('{');
        }
    }
    result.push_str(remaining);
    result
}
