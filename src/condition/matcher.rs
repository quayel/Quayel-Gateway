use crate::config::schema::{LogicalOp, Operator};
use serde_json::Value;

// ── Compiled Condition ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledCondition {
    pub left: String,
    pub operator: Operator,
    pub value: Option<Value>,
    pub next: Option<LogicalOp>,
    /// Pre-compiled regex (populated at config compile time for Operator::Regex)
    pub compiled_regex: Option<regex::Regex>,
}

// ── Path Resolution ──────────────────────────────────────────────────────────

pub fn normalize_condition_path(path: &str) -> String {
    match path {
        p if p.starts_with("req.host") => p.replacen("req.host", "http.host", 1),
        p if p.starts_with("req.path") => p.replacen("req.path", "http.path", 1),
        p if p.starts_with("req.method") => p.replacen("req.method", "http.method", 1),
        p if p.starts_with("req.scheme") => p.replacen("req.scheme", "http.scheme", 1),
        p if p.starts_with("req.ip") => p.replacen("req.ip", "http.ip", 1),
        p if p.starts_with("req.peer_ip") => p.replacen("req.peer_ip", "http.peer_ip", 1),
        p if p.starts_with("req.user_agent") => p.replacen("req.user_agent", "http.user_agent", 1),
        p if p.starts_with("req.header.") => p.replacen("req.header.", "http.header.", 1),
        p if p.starts_with("req.query.") => p.replacen("req.query.", "http.query.", 1),
        p if p.starts_with("req.cookie.") => p.replacen("req.cookie.", "http.cookie.", 1),
        other => other.to_string(),
    }
}
