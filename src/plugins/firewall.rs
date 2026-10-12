use crate::condition::CompiledCondition;
use crate::config::compiler::CompiledConfig;
use crate::config::schema::*;
use crate::gateway::request_context::*;
use crate::plugins::{GatewayResponse, PluginFlow};
use bytes::Bytes;
use serde_json::Value;
use std::sync::Arc;

// Firewall Plugin

#[derive(Debug)]
pub struct FirewallPlugin;

impl FirewallPlugin {
    pub async fn execute(
        &self,
        ctx: &mut RequestContext,
        config: &Arc<CompiledConfig>,
    ) -> PluginFlow {
        let fw_config = match &config.firewall {
            Some(c) if c.enabled => c,
            _ => return PluginFlow::Continue,
        };

        for rule in &fw_config.rules {
            if !rule.enabled {
                continue;
            }

            // Fast-path: empty conditions always match
            let matched = rule.conditions.is_empty() || evaluate_conditions(ctx, &rule.conditions);

            if matched {
                {
                    ctx.firewall.matched = true;
                    ctx.firewall.rule_id = Some(rule.id.to_string());
                    ctx.firewall.rule_name = Some(rule.name.to_string());
                    ctx.firewall.action = Some(rule.action.action_type.clone());
                    ctx.firewall.status = rule.action.status;
                }

                match &rule.action.action_type {
                    FirewallActionType::Allow => {
                        return PluginFlow::Continue;
                    }
                    FirewallActionType::Block => {
                        let status = rule.action.status.unwrap_or(403);
                        ctx.status_code = Some(status);

                        let body = format!(
                            r#"{{"error":"blocked","status":{},"rule_id":"{}"}}"#,
                            status, rule.id
                        );

                        return PluginFlow::Respond(GatewayResponse {
                            status,
                            headers: Arc::new(vec![
                                ("content-type".to_string(), "application/json".to_string()),
                                ("content-length".to_string(), body.len().to_string()),
                            ]),
                            body: Bytes::from(body),
                        });
                    }
                    FirewallActionType::Redirect => {
                        let location = rule.action.location.as_deref().unwrap_or("/");
                        let status = rule.action.status.unwrap_or(302);

                        return PluginFlow::Respond(GatewayResponse {
                            status,
                            headers: Arc::new(vec![
                                ("location".to_string(), location.to_string()),
                                ("content-length".to_string(), "0".to_string()),
                            ]),
                            body: Bytes::new(),
                        });
                    }
                    FirewallActionType::SetRequestHeader => {
                        if let Some(hdrs) = &rule.action.headers {
                            for (k, v) in hdrs {
                                if let Ok(name) = http::HeaderName::from_bytes(k.as_bytes()) {
                                    if let Ok(val) = http::HeaderValue::from_str(v) {
                                        ctx.headers.insert(name, val);
                                    }
                                }
                            }
                        }
                        return PluginFlow::Continue;
                    }
                    FirewallActionType::SetResponseHeader => {
                        return PluginFlow::Continue;
                    }
                }
            }
        }

        PluginFlow::Continue
    }
}

/// Shared condition evaluator with correct OR/AND logic.
/// Processes conditions left-to-right with AND having higher precedence than OR.
/// Example: `A AND B OR C` evaluates as `(A AND B) OR C`.
pub fn evaluate_conditions(ctx: &mut RequestContext, conditions: &[CompiledCondition]) -> bool {
    evaluate_conditions_with(ctx, conditions, resolve_condition_value)
}

/// Same as `evaluate_conditions`, with a custom field resolver (response_transform
/// uses this to add `resp.*` fields).
pub fn evaluate_conditions_with<F>(
    ctx: &mut RequestContext,
    conditions: &[CompiledCondition],
    mut resolve: F,
) -> bool
where
    F: FnMut(&mut RequestContext, &str) -> Option<Value>,
{
    if conditions.is_empty() {
        return true;
    }

    let first_left = resolve(ctx, &conditions[0].left);
    let first_result = evaluate_single_condition(first_left, &conditions[0]);

    if conditions.len() == 1 {
        return first_result;
    }

    let mut or_result = false;
    let mut and_chain = first_result;
    let mut prev_next = conditions[0].next.as_ref().unwrap_or(&LogicalOp::And);

    for i in 1..conditions.len() {
        let cond = &conditions[i];
        let left_value = resolve(ctx, &cond.left);
        let cond_result = evaluate_single_condition(left_value, cond);
        let next_op = cond.next.as_ref().unwrap_or(&LogicalOp::And);

        match prev_next {
            LogicalOp::And => {
                and_chain = and_chain && cond_result;
            }
            LogicalOp::Or => {
                or_result = or_result || and_chain;
                and_chain = cond_result;
            }
        }

        prev_next = next_op;
    }

    or_result || and_chain
}

pub fn evaluate_single_condition(left_value: Option<Value>, condition: &CompiledCondition) -> bool {
    match &condition.operator {
        Operator::Exists => left_value.is_some(),
        Operator::NotExists => left_value.is_none(),
        Operator::Equals => match (&left_value, &condition.value) {
            (Some(left), Some(right)) => values_equal(left, right),
            (None, None) => true,
            _ => false,
        },
        Operator::NotEquals => match (&left_value, &condition.value) {
            (Some(left), Some(right)) => !values_equal(left, right),
            (None, None) => false,
            _ => true,
        },
        Operator::Contains => match (&left_value, &condition.value) {
            (Some(Value::String(s)), Some(Value::String(pattern))) => s.contains(pattern.as_str()),
            _ => false,
        },
        Operator::NotContains => match (&left_value, &condition.value) {
            (Some(Value::String(s)), Some(Value::String(pattern))) => !s.contains(pattern.as_str()),
            _ => true,
        },
        Operator::StartsWith => match (&left_value, &condition.value) {
            (Some(Value::String(s)), Some(Value::String(prefix))) => s.starts_with(prefix.as_str()),
            _ => false,
        },
        Operator::EndsWith => match (&left_value, &condition.value) {
            (Some(Value::String(s)), Some(Value::String(suffix))) => s.ends_with(suffix.as_str()),
            _ => false,
        },
        Operator::In => match (&left_value, &condition.value) {
            (Some(val), Some(Value::Array(arr))) => arr.iter().any(|item| values_equal(val, item)),
            _ => false,
        },
        Operator::NotIn => match (&left_value, &condition.value) {
            (Some(val), Some(Value::Array(arr))) => !arr.iter().any(|item| values_equal(val, item)),
            _ => true,
        },
        Operator::GreaterThan => match (&left_value, &condition.value) {
            (Some(Value::Number(l)), Some(Value::Number(r))) => {
                l.as_f64().unwrap_or(0.0) > r.as_f64().unwrap_or(0.0)
            }
            _ => false,
        },
        Operator::GreaterThanOrEqual => match (&left_value, &condition.value) {
            (Some(Value::Number(l)), Some(Value::Number(r))) => {
                l.as_f64().unwrap_or(0.0) >= r.as_f64().unwrap_or(0.0)
            }
            _ => false,
        },
        Operator::LessThan => match (&left_value, &condition.value) {
            (Some(Value::Number(l)), Some(Value::Number(r))) => {
                l.as_f64().unwrap_or(0.0) < r.as_f64().unwrap_or(0.0)
            }
            _ => false,
        },
        Operator::LessThanOrEqual => match (&left_value, &condition.value) {
            (Some(Value::Number(l)), Some(Value::Number(r))) => {
                l.as_f64().unwrap_or(0.0) <= r.as_f64().unwrap_or(0.0)
            }
            _ => false,
        },
        Operator::Regex => match (&left_value, &condition.compiled_regex) {
            (Some(Value::String(s)), Some(re)) => re.is_match(s),
            _ => false,
        },
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(s1), Value::String(s2)) => s1 == s2,
        (Value::Number(n1), Value::Number(n2)) => n1.as_f64() == n2.as_f64(),
        (Value::Bool(b1), Value::Bool(b2)) => b1 == b2,
        (Value::Null, Value::Null) => true,
        (Value::String(s), Value::Number(n)) => s
            .parse::<f64>()
            .ok()
            .map(|f| f == n.as_f64().unwrap_or(f64::NAN))
            .unwrap_or(false),
        (Value::Number(n), Value::String(s)) => s
            .parse::<f64>()
            .ok()
            .map(|f| f == n.as_f64().unwrap_or(f64::NAN))
            .unwrap_or(false),
        _ => false,
    }
}

// ── Helper Functions (defined before resolve_condition_value) ─────────────────

fn parse_query_string(path: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(query_start) = path.find('?') {
        let query = &path[query_start + 1..];
        for pair in query.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let key = &pair[..eq_pos];
                let value = &pair[eq_pos + 1..];
                map.insert(percent_decode(key), percent_decode(value));
            }
        }
    }
    map
}

fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hex1 = chars.next().unwrap_or(b'0');
            let hex2 = chars.next().unwrap_or(b'0');
            let val = u8::from_str_radix(std::str::from_utf8(&[hex1, hex2]).unwrap_or("00"), 16)
                .unwrap_or(0);
            result.push(val as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn parse_cookies(headers: &http::HeaderMap) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for pair in cookie_header.split(';') {
            let pair = pair.trim();
            if let Some(eq_pos) = pair.find('=') {
                let key = pair[..eq_pos].trim().to_string();
                let value = pair[eq_pos + 1..].trim().to_string();
                map.insert(key, value);
            }
        }
    }
    map
}

fn resolve_query_value(ctx: &mut RequestContext, query_name: &str) -> Option<Value> {
    if ctx.query_cache.is_none() {
        ctx.query_cache = Some(parse_query_string(&ctx.path));
    }
    ctx.query_cache
        .as_ref()
        .and_then(|q| q.get(query_name))
        .map(|v| Value::String(v.clone()))
}

fn resolve_cookie_value(ctx: &mut RequestContext, cookie_name: &str) -> Option<Value> {
    if ctx.cookie_cache.is_none() {
        ctx.cookie_cache = Some(parse_cookies(&ctx.headers));
    }
    ctx.cookie_cache
        .as_ref()
        .and_then(|c| c.get(cookie_name))
        .map(|v| Value::String(v.clone()))
}

/// Navigate a JSON value by a dot-separated path.
/// "user_id" → payload["user_id"]
/// "data.role" → payload["data"]["role"]
fn navigate_json_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current.clone())
}

/// Verify (or, with no `jwt` keys configured, just decode) the token in
/// `header_name`, once per request per token.
fn jwt_outcome(ctx: &mut RequestContext, header_name: &str) -> crate::jwt::JwtOutcome {
    let raw = ctx
        .headers
        .get(header_name)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing")?;
    let token = match raw.get(..7) {
        Some(p) if p.eq_ignore_ascii_case("bearer ") => raw[7..].trim(),
        _ => raw.trim(),
    };
    if token.is_empty() {
        return Err("missing");
    }
    if let Some(cached) = ctx.jwt_cache.get(token) {
        return cached.clone();
    }
    let token = token.to_string();
    let outcome = match &ctx.jwt {
        Some(keys) => keys.verify(&token),
        None => crate::jwt::decode_unverified(&token),
    };
    ctx.jwt_cache.insert(token, outcome.clone());
    outcome
}

/// Resolve a deep header path.
///
/// Format: `<header_name>` for simple header access, or one of the JWT forms:
///   "authorization.jwt.user_id"   → claim `user_id` (nested: `jwt.data.role`)
///   "authorization.jwt_valid"     → true only for a token that passed every check
///   "authorization.jwt_error"     → why it failed: missing, malformed, expired, ...
///
/// With `jwt` keys configured, claims resolve only for verified tokens. Without
/// them, tokens are decoded unchecked and `jwt_valid` is always false
/// (`jwt_error` = "unverified").
fn resolve_header_deep(ctx: &mut RequestContext, rest: &str) -> Option<Value> {
    if let Some(jwt_pos) = rest.find(".jwt.") {
        let header_name = &rest[..jwt_pos];
        let claim_path = &rest[jwt_pos + 5..]; // skip ".jwt."
        let payload = jwt_outcome(ctx, header_name).ok()?;
        navigate_json_path(&payload, claim_path)
    } else if let Some(header_name) = rest.strip_suffix(".jwt_valid") {
        let valid = ctx.jwt.is_some() && jwt_outcome(ctx, header_name).is_ok();
        Some(Value::Bool(valid))
    } else if let Some(header_name) = rest.strip_suffix(".jwt_error") {
        match jwt_outcome(ctx, header_name) {
            Err(code) => Some(Value::String(code.to_string())),
            Ok(_) if ctx.jwt.is_none() => Some(Value::String("unverified".to_string())),
            Ok(_) => None,
        }
    } else {
        // Simple header access (no JWT) — case-insensitive via HeaderMap
        ctx.headers
            .get(rest)
            .and_then(|v| v.to_str().ok())
            .map(|v| Value::String(v.to_string()))
    }
}

// ── Main Condition Value Resolver ────────────────────────────────────────────

/// Resolve a condition path value from request context.
pub fn resolve_condition_value(ctx: &mut RequestContext, path: &str) -> Option<Value> {
    match path {
        "http.host" | "req.host" => ctx.host.as_ref().map(|h| Value::String(h.to_string())),
        "http.path" | "req.path" => Some(Value::String(ctx.path.to_string())),
        "http.method" | "req.method" => Some(Value::String(ctx.method.to_string())),
        "http.scheme" | "req.scheme" => Some(Value::String(ctx.scheme.to_string())),
        "http.ip" | "req.ip" => Some(Value::String(ctx.client_ip.to_string())),
        "http.peer_ip" | "req.peer_ip" => Some(Value::String(ctx.peer_ip.to_string())),
        "http.user_agent" | "req.user_agent" => ctx
            .user_agent
            .as_ref()
            .map(|ua| Value::String(ua.to_string())),

        "ip.country" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("country")),
        "ip.region" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("region")),
        "ip.city" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("city")),
        "ip.asn" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("asn")),
        "ip.as_org" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("as_org")),
        "ip.provider" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("provider")),
        "ip.is_vpn" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("is_vpn")),
        "ip.is_proxy" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("is_proxy")),
        "ip.is_datacenter" => ctx
            .ip_intel
            .as_ref()
            .and_then(|i| i.get_field("is_datacenter")),
        "ip.is_mobile" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("is_mobile")),
        "ip.is_residential" => ctx
            .ip_intel
            .as_ref()
            .and_then(|i| i.get_field("is_residential")),
        "ip.is_residential_proxy" => ctx
            .ip_intel
            .as_ref()
            .and_then(|i| i.get_field("is_residential_proxy")),
        "ip.is_tor" => ctx.ip_intel.as_ref().and_then(|i| i.get_field("is_tor")),
        "ip.network_type" => ctx
            .ip_intel
            .as_ref()
            .and_then(|i| i.get_field("network_type")),
        "ip.risk_score" => ctx
            .ip_intel
            .as_ref()
            .and_then(|i| i.get_field("risk_score")),

        // Deep header paths — supports JWT extraction:
        //   "header.token.jwt.user_id" → header "token", decode JWT, extract claim "user_id"
        //   "header.X.jwt.a.b.c" → nested claim navigation
        p if p.starts_with("http.header.") => {
            let rest = &p[12..];
            resolve_header_deep(ctx, rest)
        }
        p if p.starts_with("req.header.") => {
            let rest = &p[11..];
            resolve_header_deep(ctx, rest)
        }
        p if p.starts_with("header.") => {
            let rest = &p[7..];
            resolve_header_deep(ctx, rest)
        }

        p if p.starts_with("http.query.") => {
            let query_name = &p[11..];
            resolve_query_value(ctx, query_name)
        }
        p if p.starts_with("req.query.") => {
            let query_name = &p[10..];
            resolve_query_value(ctx, query_name)
        }

        p if p.starts_with("http.cookie.") => {
            let cookie_name = &p[12..];
            resolve_cookie_value(ctx, cookie_name)
        }
        p if p.starts_with("req.cookie.") => {
            let cookie_name = &p[11..];
            resolve_cookie_value(ctx, cookie_name)
        }

        _ => None,
    }
}
