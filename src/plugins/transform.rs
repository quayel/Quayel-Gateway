use crate::condition::CompiledCondition;
use crate::config::compiler::compile_conditions;
use crate::config::schema::{TransformAction, TransformConfig};
use crate::gateway::request_context::RequestContext;
use crate::plugins::firewall::{evaluate_conditions_with, resolve_condition_value};
use http::{HeaderMap, HeaderName, HeaderValue};
use pingora_http::{RequestHeader, ResponseHeader};
use serde_json::Value;
use std::sync::Arc;

// ── Request / Response Transform ─────────────────────────────────────────────
// Two plugins share this module:
//
//   request_transform   runs in the pipeline after rate_limiting and before
//                       cache. It rewrites ctx (path, query, headers, host), so
//                       the cache key and later plugins see the rewritten
//                       request. upstream_request_filter replays the same edits
//                       on the request sent to the origin.
//
//   response_transform  runs on the way out, for origin responses and for
//                       responses served from cache (HIT, STALE, REVALIDATED).
//                       The cache only ever stores the raw origin response, so
//                       nothing transformed is shared between clients.
//                       Gateway-generated blocks (403/429/...) are not
//                       transformed.
//
// Rules run in order; every matching rule applies all of its actions.

#[derive(Debug, Clone)]
pub struct CompiledTransform {
    pub rules: Vec<CompiledTransformRule>,
}

#[derive(Debug, Clone)]
pub struct CompiledTransformRule {
    pub id: Arc<str>,
    pub conditions: Vec<CompiledCondition>,
    pub ops: Vec<TransformOp>,
}

#[derive(Debug, Clone)]
pub enum TransformOp {
    Header(HeaderOp),
    PathSet(String),
    PathReplacePrefix {
        from: String,
        to: String,
    },
    PathRegexReplace {
        re: regex::Regex,
        replacement: String,
    },
    Query(QueryOp),
    Status(u16),
}

#[derive(Debug, Clone)]
pub enum HeaderOp {
    Set(HeaderName, HeaderValue),
    Add(HeaderName, HeaderValue),
    Remove(HeaderName),
    Rename(HeaderName, HeaderName),
}

#[derive(Debug, Clone)]
pub enum QueryOp {
    Set(String, String),
    Add(String, String),
    Remove(String),
    Rename(String, String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformPhase {
    Request,
    Response,
}

impl TransformPhase {
    fn plugin(self) -> &'static str {
        match self {
            TransformPhase::Request => "request_transform",
            TransformPhase::Response => "response_transform",
        }
    }
}

/// Per-request state written by request_transform, read by upstream_request_filter
/// and the access log.
#[derive(Debug, Default)]
pub struct RequestTransformState {
    /// Path and query as the client sent them; Some only when a rule changed them.
    pub original_path: Option<Arc<str>>,
    /// Host as the client sent it; Some only when a rule touched the Host header.
    pub original_host: Option<Option<Arc<str>>>,
    /// Header edits to replay on the upstream request, in order.
    pub header_edits: Vec<HeaderOp>,
    /// IDs of the rules that matched, in order (access log).
    pub rules: Vec<Arc<str>>,
}

impl RequestTransformState {
    pub fn reset(&mut self) {
        self.original_path = None;
        self.original_host = None;
        self.header_edits.clear();
        self.rules.clear();
    }

    pub fn path_rewritten(&self) -> bool {
        self.original_path.is_some()
    }
}

/// Per-request state written by response_transform (access log).
#[derive(Debug, Default)]
pub struct ResponseTransformState {
    /// IDs of the rules that matched, in order.
    pub rules: Vec<Arc<str>>,
}

impl ResponseTransformState {
    pub fn reset(&mut self) {
        self.rules.clear();
    }
}

// ── Compile ──────────────────────────────────────────────────────────────────

/// Framing headers are owned by the proxy; rewriting them would corrupt the
/// message, so the compiler rejects them.
const PROTECTED_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
];

/// Forwarding headers describe the real client and are always built by the
/// gateway from the original request, so request rules can't touch them.
/// The request ID is the one in the access log, so it can't be rewritten
/// on the way upstream either.
const FORWARDING_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    crate::gateway::request_id::HEADER,
];

pub fn compile_transform(
    c: &TransformConfig,
    phase: TransformPhase,
) -> Result<Option<CompiledTransform>, String> {
    if !c.enabled {
        return Ok(None);
    }
    let mut rules = Vec::with_capacity(c.rules.len());
    for r in c.rules.iter().filter(|r| r.enabled) {
        let ops = r
            .actions
            .iter()
            .map(|a| {
                compile_action(a, phase)
                    .map_err(|e| format!("plugins.{}: rule '{}': {}", phase.plugin(), r.id, e))
            })
            .collect::<Result<Vec<_>, _>>()?;
        rules.push(CompiledTransformRule {
            id: Arc::from(r.id.as_str()),
            conditions: compile_conditions(&r.conditions),
            ops,
        });
    }
    Ok(Some(CompiledTransform { rules }))
}

fn compile_action(a: &TransformAction, phase: TransformPhase) -> Result<TransformOp, String> {
    let op = a.operation.as_str();
    match (a.action_type.as_str(), phase) {
        ("header", _) => compile_header_op(a, op, phase).map(TransformOp::Header),
        ("path", TransformPhase::Request) => match op {
            "set" => {
                let value = value_str(a)?;
                if !value.starts_with('/') {
                    return Err(format!(
                        "path set: value must start with '/', got '{value}'"
                    ));
                }
                Ok(TransformOp::PathSet(value))
            }
            "replace_prefix" => Ok(TransformOp::PathReplacePrefix {
                from: required(&a.from, "from")?.to_string(),
                to: required(&a.to, "to")?.to_string(),
            }),
            "regex_replace" => {
                let pattern = required(&a.pattern, "pattern")?;
                let re = regex::Regex::new(pattern)
                    .map_err(|e| format!("path regex_replace: invalid pattern: {e}"))?;
                Ok(TransformOp::PathRegexReplace {
                    re,
                    replacement: required(&a.replacement, "replacement")?.to_string(),
                })
            }
            _ => Err(format!(
                "path: unknown operation '{op}' (set, replace_prefix, regex_replace)"
            )),
        },
        ("query", TransformPhase::Request) => {
            let name = required(&a.name, "name")?.to_string();
            match op {
                "set" => Ok(TransformOp::Query(QueryOp::Set(name, value_str(a)?))),
                "add" => Ok(TransformOp::Query(QueryOp::Add(name, value_str(a)?))),
                "remove" => Ok(TransformOp::Query(QueryOp::Remove(name))),
                "rename" => Ok(TransformOp::Query(QueryOp::Rename(
                    name,
                    required(&a.to, "to")?.to_string(),
                ))),
                _ => Err(format!(
                    "query: unknown operation '{op}' (set, add, remove, rename)"
                )),
            }
        }
        ("status", TransformPhase::Response) => {
            if op != "set" {
                return Err(format!("status: unknown operation '{op}' (set)"));
            }
            let code = match &a.value {
                Some(Value::Number(n)) => n.as_u64(),
                Some(Value::String(s)) => s.trim().parse::<u64>().ok(),
                _ => None,
            };
            match code {
                Some(c) if (200..=599).contains(&c) => Ok(TransformOp::Status(c as u16)),
                _ => Err("status set: value must be a status code between 200 and 599".to_string()),
            }
        }
        (t, TransformPhase::Request) => {
            Err(format!("unknown action type '{t}' (header, path, query)"))
        }
        (t, TransformPhase::Response) => Err(format!("unknown action type '{t}' (header, status)")),
    }
}

fn compile_header_op(
    a: &TransformAction,
    op: &str,
    phase: TransformPhase,
) -> Result<HeaderOp, String> {
    let name = header_name(required(&a.name, "name")?, phase)?;
    match op {
        "set" => Ok(HeaderOp::Set(name, header_value(&value_str(a)?)?)),
        "add" => Ok(HeaderOp::Add(name, header_value(&value_str(a)?)?)),
        "remove" => Ok(HeaderOp::Remove(name)),
        "rename" => Ok(HeaderOp::Rename(
            name,
            header_name(required(&a.to, "to")?, phase)?,
        )),
        _ => Err(format!(
            "header: unknown operation '{op}' (set, add, remove, rename)"
        )),
    }
}

fn header_name(s: &str, phase: TransformPhase) -> Result<HeaderName, String> {
    let name = HeaderName::from_bytes(s.trim().as_bytes())
        .map_err(|_| format!("invalid header name '{s}'"))?;
    if PROTECTED_HEADERS.contains(&name.as_str())
        || (phase == TransformPhase::Request && FORWARDING_HEADERS.contains(&name.as_str()))
    {
        return Err(format!(
            "header '{}' is managed by the gateway and cannot be transformed",
            name
        ));
    }
    Ok(name)
}

/// A header a rule sets, checked like a transform header: framing headers,
/// and on requests the forwarding headers, are refused.
pub fn check_header(
    name: &str,
    value: &str,
    phase: TransformPhase,
) -> Result<(HeaderName, HeaderValue), String> {
    Ok((header_name(name, phase)?, header_value(value)?))
}

fn header_value(s: &str) -> Result<HeaderValue, String> {
    HeaderValue::from_str(s).map_err(|_| format!("invalid header value '{s}'"))
}

fn required<'a>(v: &'a Option<String>, field: &str) -> Result<&'a str, String> {
    v.as_deref().ok_or_else(|| format!("missing '{field}'"))
}

fn value_str(a: &TransformAction) -> Result<String, String> {
    match &a.value {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        Some(Value::Bool(b)) => Ok(b.to_string()),
        _ => Err("missing 'value'".to_string()),
    }
}

// ── Request transform ────────────────────────────────────────────────────────

/// Apply request_transform rules to ctx. Header edits are recorded in
/// ctx.request_transform so upstream_request_filter can replay them.
pub fn apply_request_transform(ctx: &mut RequestContext, cfg: &CompiledTransform) {
    for rule in &cfg.rules {
        let matched = rule.conditions.is_empty()
            || evaluate_conditions_with(ctx, &rule.conditions, resolve_condition_value);
        if !matched {
            continue;
        }
        ctx.request_transform.rules.push(Arc::clone(&rule.id));
        for op in &rule.ops {
            match op {
                TransformOp::Header(h) => {
                    if header_op_touches(h, &http::header::HOST)
                        && ctx.request_transform.original_host.is_none()
                    {
                        ctx.request_transform.original_host = Some(ctx.host.clone());
                    }
                    apply_header_op_map(&mut ctx.headers, h);
                    if header_op_touches(h, &http::header::HOST) {
                        ctx.host = ctx
                            .headers
                            .get(http::header::HOST)
                            .and_then(|v| v.to_str().ok())
                            .map(Arc::from);
                    }
                    if header_op_touches(h, &http::header::USER_AGENT) {
                        ctx.user_agent = ctx
                            .headers
                            .get(http::header::USER_AGENT)
                            .and_then(|v| v.to_str().ok())
                            .map(Arc::from);
                    }
                    ctx.cookie_cache = None;
                    ctx.jwt_cache.clear();
                    ctx.request_transform.header_edits.push(h.clone());
                }
                TransformOp::PathSet(_)
                | TransformOp::PathReplacePrefix { .. }
                | TransformOp::PathRegexReplace { .. } => {
                    let current = Arc::clone(&ctx.path);
                    let (path, query) = split_path(&current);
                    let new_path = match op {
                        TransformOp::PathSet(p) => p.clone(),
                        TransformOp::PathReplacePrefix { from, to } => {
                            match path.strip_prefix(from.as_str()) {
                                Some(rest) => format!("{to}{rest}"),
                                None => continue,
                            }
                        }
                        TransformOp::PathRegexReplace { re, replacement } => {
                            re.replace(path, replacement.as_str()).into_owned()
                        }
                        _ => unreachable!(),
                    };
                    let new_path = if new_path.starts_with('/') {
                        new_path
                    } else {
                        format!("/{new_path}")
                    };
                    set_path(ctx, &new_path, query);
                }
                TransformOp::Query(q) => {
                    let current = Arc::clone(&ctx.path);
                    let (path, query) = split_path(&current);
                    let new_query = apply_query_op(query.unwrap_or(""), q);
                    set_path(
                        ctx,
                        path,
                        if new_query.is_empty() {
                            None
                        } else {
                            Some(&new_query)
                        },
                    );
                }
                TransformOp::Status(_) => {}
            }
        }
    }
}

/// Replay recorded header edits on the request sent to the origin.
pub fn replay_request_header_edits(edits: &[HeaderOp], req: &mut RequestHeader) {
    for h in edits {
        match h {
            HeaderOp::Set(n, v) => {
                let _ = req.insert_header(n.clone(), v.clone());
            }
            HeaderOp::Add(n, v) => {
                let _ = req.append_header(n.clone(), v.clone());
            }
            HeaderOp::Remove(n) => {
                req.remove_header(n);
            }
            HeaderOp::Rename(from, to) => {
                let values: Vec<HeaderValue> = req.headers.get_all(from).iter().cloned().collect();
                if values.is_empty() {
                    continue;
                }
                req.remove_header(from);
                req.remove_header(to);
                for v in values {
                    let _ = req.append_header(to.clone(), v);
                }
            }
        }
    }
}

fn header_op_touches(h: &HeaderOp, name: &HeaderName) -> bool {
    match h {
        HeaderOp::Set(n, _) | HeaderOp::Add(n, _) | HeaderOp::Remove(n) => n == name,
        HeaderOp::Rename(from, to) => from == name || to == name,
    }
}

fn apply_header_op_map(map: &mut HeaderMap, h: &HeaderOp) {
    match h {
        HeaderOp::Set(n, v) => {
            map.insert(n.clone(), v.clone());
        }
        HeaderOp::Add(n, v) => {
            map.append(n.clone(), v.clone());
        }
        HeaderOp::Remove(n) => {
            map.remove(n);
        }
        HeaderOp::Rename(from, to) => {
            let values: Vec<HeaderValue> = map.get_all(from).iter().cloned().collect();
            if values.is_empty() {
                return;
            }
            map.remove(from);
            map.remove(to);
            for v in values {
                map.append(to.clone(), v);
            }
        }
    }
}

fn split_path(path_and_query: &str) -> (&str, Option<&str>) {
    match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    }
}

fn set_path(ctx: &mut RequestContext, path: &str, query: Option<&str>) {
    let new = match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    if *ctx.path == *new {
        return;
    }
    if ctx.request_transform.original_path.is_none() {
        ctx.request_transform.original_path = Some(Arc::clone(&ctx.path));
    }
    ctx.path = Arc::from(new);
    ctx.query_cache = None;
}

/// Edit a raw query string. Existing pairs are kept byte-for-byte; only the
/// pairs this op touches are rewritten. Names match on the decoded name.
fn apply_query_op(query: &str, op: &QueryOp) -> String {
    let pairs: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
    let key_of =
        |pair: &str| -> String { decode_component(pair.split_once('=').map_or(pair, |(k, _)| k)) };
    let mut out: Vec<String> = Vec::with_capacity(pairs.len() + 1);
    match op {
        QueryOp::Set(name, value) => {
            let mut done = false;
            for p in pairs {
                if key_of(p) == *name {
                    if !done {
                        out.push(encode_pair(name, value));
                        done = true;
                    }
                } else {
                    out.push(p.to_string());
                }
            }
            if !done {
                out.push(encode_pair(name, value));
            }
        }
        QueryOp::Add(name, value) => {
            out.extend(pairs.iter().map(|p| p.to_string()));
            out.push(encode_pair(name, value));
        }
        QueryOp::Remove(name) => {
            out.extend(
                pairs
                    .iter()
                    .filter(|p| key_of(p) != *name)
                    .map(|p| p.to_string()),
            );
        }
        QueryOp::Rename(from, to) => {
            for p in pairs {
                if key_of(p) == *from {
                    match p.split_once('=') {
                        Some((_, v)) => out.push(format!("{}={}", encode_component(to), v)),
                        None => out.push(encode_component(to)),
                    }
                } else {
                    out.push(p.to_string());
                }
            }
        }
    }
    out.join("&")
}

fn encode_pair(name: &str, value: &str) -> String {
    format!("{}={}", encode_component(name), encode_component(value))
}

fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode_component(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"),
                    16,
                ) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── Response transform ───────────────────────────────────────────────────────

/// Apply response_transform rules to a response header (origin or cached).
/// Conditions may read `resp.status` and `resp.header.<name>` in addition to
/// every request field.
pub fn apply_response_transform(
    ctx: &mut RequestContext,
    cfg: &CompiledTransform,
    resp: &mut ResponseHeader,
) {
    for rule in &cfg.rules {
        let matched = rule.conditions.is_empty()
            || evaluate_conditions_with(ctx, &rule.conditions, |ctx, field| {
                resolve_response_value(ctx, resp, field)
            });
        if !matched {
            continue;
        }
        ctx.response_transform.rules.push(Arc::clone(&rule.id));
        for op in &rule.ops {
            match op {
                TransformOp::Header(h) => match h {
                    HeaderOp::Set(n, v) => {
                        let _ = resp.insert_header(n.clone(), v.clone());
                    }
                    HeaderOp::Add(n, v) => {
                        let _ = resp.append_header(n.clone(), v.clone());
                    }
                    HeaderOp::Remove(n) => {
                        resp.remove_header(n);
                    }
                    HeaderOp::Rename(from, to) => {
                        let values: Vec<HeaderValue> =
                            resp.headers.get_all(from).iter().cloned().collect();
                        if values.is_empty() {
                            continue;
                        }
                        resp.remove_header(from);
                        resp.remove_header(to);
                        for v in values {
                            let _ = resp.append_header(to.clone(), v);
                        }
                    }
                },
                TransformOp::Status(code) => {
                    let _ = resp.set_status(*code);
                }
                _ => {}
            }
        }
    }
}

fn resolve_response_value(
    ctx: &mut RequestContext,
    resp: &ResponseHeader,
    field: &str,
) -> Option<Value> {
    if field == "resp.status" {
        return Some(Value::Number(resp.status.as_u16().into()));
    }
    if let Some(name) = field.strip_prefix("resp.header.") {
        return resp
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| Value::String(v.to_string()));
    }
    resolve_condition_value(ctx, field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_ops_keep_untouched_pairs() {
        assert_eq!(
            apply_query_op("a=1&b=2", &QueryOp::Set("b".into(), "x y".into())),
            "a=1&b=x%20y"
        );
        assert_eq!(
            apply_query_op("a=1", &QueryOp::Set("c".into(), "3".into())),
            "a=1&c=3"
        );
        assert_eq!(
            apply_query_op("a=1&a=2&b=2", &QueryOp::Remove("a".into())),
            "b=2"
        );
        assert_eq!(
            apply_query_op("a=1&b=2", &QueryOp::Rename("a".into(), "z".into())),
            "z=1&b=2"
        );
        assert_eq!(
            apply_query_op("a=1", &QueryOp::Add("a".into(), "2".into())),
            "a=1&a=2"
        );
        assert_eq!(apply_query_op("", &QueryOp::Remove("a".into())), "");
    }

    #[test]
    fn decode_handles_percent_and_plus() {
        assert_eq!(decode_component("a%20b+c"), "a b c");
        assert_eq!(decode_component("bad%2"), "bad%2");
        assert_eq!(decode_component("%zz"), "%zz");
    }

    #[test]
    fn protected_headers_rejected() {
        let a = TransformAction {
            action_type: "header".into(),
            operation: "remove".into(),
            name: Some("Content-Length".into()),
            value: None,
            from: None,
            to: None,
            pattern: None,
            replacement: None,
        };
        assert!(compile_action(&a, TransformPhase::Response).is_err());
    }

    #[test]
    fn path_actions_are_request_only() {
        let a = TransformAction {
            action_type: "path".into(),
            operation: "set".into(),
            name: None,
            value: Some(Value::String("/x".into())),
            from: None,
            to: None,
            pattern: None,
            replacement: None,
        };
        assert!(compile_action(&a, TransformPhase::Request).is_ok());
        assert!(compile_action(&a, TransformPhase::Response).is_err());
    }

    fn compile(
        phase: TransformPhase,
        cfg: serde_json::Value,
    ) -> Result<Option<CompiledTransform>, String> {
        let c: TransformConfig = serde_json::from_value(cfg).expect("config parses");
        compile_transform(&c, phase)
    }

    fn compile_one(
        phase: TransformPhase,
        action: serde_json::Value,
    ) -> Result<Option<CompiledTransform>, String> {
        compile(
            phase,
            serde_json::json!({"rules": [{"id": "r", "actions": [action]}]}),
        )
    }

    fn ctx(path: &str, headers: &[(&str, &str)]) -> RequestContext {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        let host = map.get("host").and_then(|v| v.to_str().ok()).map(Arc::from);
        RequestContext::new(
            Arc::from("gw"),
            Arc::from("gw"),
            Arc::from("gw"),
            Arc::from("1"),
            ip,
            ip,
            Arc::from("peer_ip"),
            host,
            Arc::from(path),
            Arc::from("GET"),
            Arc::from("http"),
            None,
            map,
        )
    }

    fn request(rules: serde_json::Value, c: &mut RequestContext) {
        let cfg = compile(
            TransformPhase::Request,
            serde_json::json!({ "rules": rules }),
        )
        .unwrap()
        .unwrap();
        apply_request_transform(c, &cfg);
    }

    fn response(rules: serde_json::Value, c: &mut RequestContext, resp: &mut ResponseHeader) {
        let cfg = compile(
            TransformPhase::Response,
            serde_json::json!({ "rules": rules }),
        )
        .unwrap()
        .unwrap();
        apply_response_transform(c, &cfg, resp);
    }

    #[test]
    fn compile_rejects_invalid_actions() {
        use serde_json::json;
        let req = TransformPhase::Request;
        let res = TransformPhase::Response;
        let bad = [
            (
                req,
                json!({"type": "path", "operation": "regex_replace", "pattern": "([", "replacement": "x"}),
            ),
            (
                req,
                json!({"type": "path", "operation": "set", "value": "no-slash"}),
            ),
            (
                req,
                json!({"type": "path", "operation": "replace_prefix", "from": "/a"}),
            ),
            (req, json!({"type": "path", "operation": "strip"})),
            (
                req,
                json!({"type": "query", "operation": "set", "name": "a"}),
            ),
            (
                req,
                json!({"type": "query", "operation": "rename", "name": "a"}),
            ),
            (
                req,
                json!({"type": "status", "operation": "set", "value": 418}),
            ),
            (
                req,
                json!({"type": "body", "operation": "set", "value": "x"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "set", "value": "x"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "set", "name": "bad name", "value": "x"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "set", "name": "x-a", "value": "a\nb"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "append", "name": "x-a", "value": "x"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "rename", "name": "x-a", "to": "Transfer-Encoding"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "set", "name": "X-Forwarded-For", "value": "1.2.3.4"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "add", "name": "x-forwarded-for", "value": "1.2.3.4"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "remove", "name": "X-Forwarded-For"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "rename", "name": "X-Forwarded-For", "to": "x-a"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "rename", "name": "x-a", "to": "X-Forwarded-For"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "set", "name": "X-Forwarded-Proto", "value": "https"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "set", "name": "X-Forwarded-Host", "value": "x"}),
            ),
            (
                req,
                json!({"type": "header", "operation": "set", "name": "X-QG-Request-Id", "value": "x"}),
            ),
            (
                res,
                json!({"type": "query", "operation": "remove", "name": "a"}),
            ),
            (
                res,
                json!({"type": "status", "operation": "set", "value": 199}),
            ),
            (
                res,
                json!({"type": "status", "operation": "set", "value": 600}),
            ),
            (
                res,
                json!({"type": "status", "operation": "set", "value": "abc"}),
            ),
            (
                res,
                json!({"type": "status", "operation": "replace", "value": 404}),
            ),
        ];
        for (phase, action) in bad {
            assert!(
                compile_one(phase, action.clone()).is_err(),
                "{phase:?} should reject {action}"
            );
        }
        let err = compile_one(
            req,
            json!({"type": "path", "operation": "set", "value": "x"}),
        )
        .unwrap_err();
        assert!(
            err.starts_with("plugins.request_transform: rule 'r':"),
            "{err}"
        );
        assert!(compile_one(
            res,
            json!({"type": "status", "operation": "set", "value": "503"})
        )
        .is_ok());
    }

    #[test]
    fn compile_skips_disabled() {
        let off = compile(
            TransformPhase::Request,
            serde_json::json!({"enabled": false, "rules": []}),
        )
        .unwrap();
        assert!(off.is_none());
        let cfg = compile(TransformPhase::Request, serde_json::json!({"rules": [
            {"id": "on", "actions": []},
            {"id": "off", "enabled": false, "actions": [{"type": "path", "operation": "set", "value": "bad"}]},
        ]}))
        .unwrap()
        .unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(&*cfg.rules[0].id, "on");
    }

    #[test]
    fn request_path_ops() {
        use serde_json::json;
        let mut c = ctx("/api/users?x=1", &[]);
        request(
            json!([{"id": "a", "actions": [{"type": "path", "operation": "replace_prefix", "from": "/api", "to": "/v1"}]}]),
            &mut c,
        );
        assert_eq!(&*c.path, "/v1/users?x=1");
        assert_eq!(
            c.request_transform.original_path.as_deref(),
            Some("/api/users?x=1")
        );

        let mut c = ctx("/other", &[]);
        request(
            json!([{"id": "a", "actions": [{"type": "path", "operation": "replace_prefix", "from": "/api", "to": "/v1"}]}]),
            &mut c,
        );
        assert_eq!(&*c.path, "/other");
        assert!(!c.request_transform.path_rewritten());

        let mut c = ctx("/u/42/profile?q=1", &[]);
        request(
            json!([{"id": "a", "actions": [{"type": "path", "operation": "regex_replace", "pattern": "^/u/(\\d+)/", "replacement": "/users/$1/"}]}]),
            &mut c,
        );
        assert_eq!(&*c.path, "/users/42/profile?q=1");

        let mut c = ctx("/anything?q=1", &[]);
        request(
            json!([{"id": "a", "actions": [{"type": "path", "operation": "set", "value": "/fixed"}]}]),
            &mut c,
        );
        assert_eq!(&*c.path, "/fixed?q=1");

        // A rewrite that drops the leading slash is repaired.
        let mut c = ctx("/strip/me", &[]);
        request(
            json!([{"id": "a", "actions": [{"type": "path", "operation": "replace_prefix", "from": "/strip/", "to": ""}]}]),
            &mut c,
        );
        assert_eq!(&*c.path, "/me");

        // Removing the last query pair drops the '?'.
        let mut c = ctx("/p?only=1", &[]);
        request(
            json!([{"id": "a", "actions": [{"type": "query", "operation": "remove", "name": "only"}]}]),
            &mut c,
        );
        assert_eq!(&*c.path, "/p");
    }

    #[test]
    fn request_header_ops_update_ctx_and_replay() {
        use serde_json::json;
        let mut c = ctx(
            "/",
            &[
                ("host", "a.example"),
                ("x-old", "1"),
                ("x-old", "2"),
                ("x-drop", "y"),
            ],
        );
        request(
            json!([{"id": "a", "actions": [
                {"type": "header", "operation": "set", "name": "Host", "value": "b.internal"},
                {"type": "header", "operation": "add", "name": "x-multi", "value": "one"},
                {"type": "header", "operation": "add", "name": "x-multi", "value": "two"},
                {"type": "header", "operation": "rename", "name": "x-old", "to": "x-new"},
                {"type": "header", "operation": "remove", "name": "x-drop"},
                {"type": "header", "operation": "rename", "name": "x-missing", "to": "x-never"},
            ]}]),
            &mut c,
        );
        assert_eq!(c.host.as_deref(), Some("b.internal"));
        assert_eq!(c.headers.get_all("x-multi").iter().count(), 2);
        assert_eq!(
            c.headers
                .get_all("x-new")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["1", "2"]
        );
        assert!(
            c.headers.get("x-old").is_none()
                && c.headers.get("x-drop").is_none()
                && c.headers.get("x-never").is_none()
        );

        // The same edits replayed on the upstream request give the same result.
        let mut up = RequestHeader::build("GET", b"/", None).unwrap();
        for (k, v) in [
            ("host", "a.example"),
            ("x-old", "1"),
            ("x-old", "2"),
            ("x-drop", "y"),
        ] {
            up.append_header(k, v).unwrap();
        }
        replay_request_header_edits(&c.request_transform.header_edits, &mut up);
        for name in ["host", "x-multi", "x-new", "x-old", "x-drop", "x-never"] {
            let a: Vec<_> = c.headers.get_all(name).iter().collect();
            let b: Vec<_> = up.headers.get_all(name).iter().collect();
            assert_eq!(a, b, "header {name}");
        }
    }

    #[test]
    fn request_rules_conditions_and_order() {
        use serde_json::json;
        let rules = json!([
            {"id": "first", "actions": [{"type": "path", "operation": "replace_prefix", "from": "/old", "to": "/new"}]},
            // Sees the path written by the rule above.
            {"id": "second", "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/new"}],
             "actions": [{"type": "header", "operation": "set", "name": "x-chained", "value": "yes"}]},
            {"id": "no-match", "conditions": [{"left": "req.header.x-flag", "operator": "exists"}],
             "actions": [{"type": "header", "operation": "set", "name": "x-flagged", "value": "yes"}]},
            // Query condition reads the rewritten query, not a stale cache.
            {"id": "q1", "actions": [{"type": "query", "operation": "set", "name": "v", "value": "2"}]},
            {"id": "q2", "conditions": [{"left": "req.query.v", "operator": "equals", "value": "2"}],
             "actions": [{"type": "header", "operation": "set", "name": "x-v2", "value": "yes"}]},
        ]);
        let mut c = ctx("/old/a?v=1", &[]);
        request(rules, &mut c);
        assert_eq!(&*c.path, "/new/a?v=2");
        assert_eq!(c.headers.get("x-chained").unwrap(), "yes");
        assert!(c.headers.get("x-flagged").is_none());
        assert_eq!(c.headers.get("x-v2").unwrap(), "yes");
        // Matched rules are recorded for the access log, in order.
        let ids: Vec<&str> = c.request_transform.rules.iter().map(|r| &**r).collect();
        assert_eq!(ids, ["first", "second", "q1", "q2"]);
    }

    #[test]
    fn log_event_shows_the_original_request() {
        use crate::logging::event::LogEvent;
        use serde_json::json;
        let mut c = ctx("/api/a?x=1", &[("host", "public.example")]);
        request(
            json!([{"id": "rw", "actions": [
                {"type": "path", "operation": "replace_prefix", "from": "/api", "to": "/v1"},
                {"type": "header", "operation": "set", "name": "Host", "value": "internal.test"},
            ]}]),
            &mut c,
        );
        let mut resp = ResponseHeader::build(200, None).unwrap();
        response(
            json!([{"id": "rs", "actions": [{"type": "header", "operation": "set", "name": "x-a", "value": "1"}]}]),
            &mut c,
            &mut resp,
        );

        // The log shows what the client sent, not the rewrite.
        let ev = LogEvent::from_context(&c);
        assert_eq!(&*ev.path, "/api/a?x=1");
        assert_eq!(ev.host.as_deref(), Some("public.example"));

        let ev = LogEvent::from_context(&ctx("/p", &[("host", "h")]));
        assert_eq!(&*ev.path, "/p");
    }

    #[test]
    fn response_ops_and_conditions() {
        use serde_json::json;
        let rules = json!([
            {"id": "all", "actions": [
                {"type": "header", "operation": "set", "name": "X-Powered-By", "value": "Quayel"},
                {"type": "header", "operation": "remove", "name": "Server"},
                {"type": "header", "operation": "rename", "name": "X-Upstream-Id", "to": "X-Request-Ref"},
                {"type": "header", "operation": "add", "name": "Set-Cookie", "value": "b=2"},
            ]},
            {"id": "by-status", "conditions": [{"left": "resp.status", "operator": "equals", "value": 404}],
             "actions": [{"type": "status", "operation": "set", "value": 410}]},
            {"id": "by-header", "conditions": [{"left": "resp.header.content-type", "operator": "contains", "value": "json"}],
             "actions": [{"type": "header", "operation": "set", "name": "X-Json", "value": "1"}]},
            {"id": "by-request", "conditions": [{"left": "req.path", "operator": "starts_with", "value": "/admin"}],
             "actions": [{"type": "header", "operation": "set", "name": "X-Admin", "value": "1"}]},
        ]);
        let mut resp = ResponseHeader::build(404, None).unwrap();
        resp.append_header("server", "nginx").unwrap();
        resp.append_header("x-upstream-id", "abc").unwrap();
        resp.append_header("set-cookie", "a=1").unwrap();
        resp.append_header("content-type", "application/json")
            .unwrap();
        let mut c = ctx("/api", &[]);
        response(rules.clone(), &mut c, &mut resp);
        assert_eq!(resp.status.as_u16(), 410);
        assert_eq!(resp.headers.get("x-powered-by").unwrap(), "Quayel");
        assert!(resp.headers.get("server").is_none());
        assert!(resp.headers.get("x-upstream-id").is_none());
        assert_eq!(resp.headers.get("x-request-ref").unwrap(), "abc");
        assert_eq!(resp.headers.get_all("set-cookie").iter().count(), 2);
        assert_eq!(resp.headers.get("x-json").unwrap(), "1");
        assert!(resp.headers.get("x-admin").is_none());
        let ids: Vec<&str> = c.response_transform.rules.iter().map(|r| &**r).collect();
        assert_eq!(ids, ["all", "by-status", "by-header"]);

        // A later rule sees the status set by an earlier one.
        let chained = json!([
            {"id": "a", "actions": [{"type": "status", "operation": "set", "value": 503}]},
            {"id": "b", "conditions": [{"left": "resp.status", "operator": "equals", "value": 503}],
             "actions": [{"type": "header", "operation": "set", "name": "Retry-After", "value": "30"}]},
        ]);
        let mut resp = ResponseHeader::build(200, None).unwrap();
        response(chained, &mut ctx("/admin", &[]), &mut resp);
        assert_eq!(resp.status.as_u16(), 503);
        assert_eq!(resp.headers.get("retry-after").unwrap(), "30");
    }
}
