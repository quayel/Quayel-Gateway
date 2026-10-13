//! `block.key` for the access log: `field=value` pairs joined by `&`, so a
//! line reads on its own without the config it was written under.
//!
//! - Values from the query string (`req.query.*`, `http.query.*`) are logged
//!   as a short SHA-256 prefix (`#a91f3c`), never raw: query strings carry
//!   tokens and API keys. The same value always gives the same hash, so
//!   "top keys" graphs still work.
//! - Paths are cut at the first `?`.
//! - The whole key is capped at `MAX_KEY` bytes (ending in `…` when cut).

use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_KEY: usize = 256;

fn is_query_field(field: &str) -> bool {
    field.starts_with("req.query.") || field.starts_with("http.query.")
}

fn is_path_field(field: &str) -> bool {
    matches!(field, "req.path" | "http.path")
}

/// `#` + the first 6 hex digits of the value's SHA-256.
pub fn short_hash(value: &str) -> String {
    let d = Sha256::digest(value.as_bytes());
    format!("#{:02x}{:02x}{:02x}", d[0], d[1], d[2])
}

/// Append `field=value` (with `&` before it when `out` isn't empty).
pub fn push_pair(out: &mut String, field: &str, value: Option<&Value>) {
    let text = match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
    };
    push_text(out, field, &text);
}

/// Same as `push_pair` for a value that is already text.
pub fn push_text(out: &mut String, field: &str, text: &str) {
    if out.len() >= MAX_KEY {
        return;
    }
    if !out.is_empty() {
        out.push('&');
    }
    out.push_str(field);
    out.push('=');
    if is_query_field(field) {
        out.push_str(&short_hash(text));
    } else if is_path_field(field) {
        out.push_str(text.split('?').next().unwrap_or(""));
    } else {
        out.push_str(text);
    }
    cap(out);
}

/// Cut `s` to at most `MAX_KEY` bytes on a char boundary, ending in `…`.
pub fn cap(s: &mut String) {
    if s.len() <= MAX_KEY {
        return;
    }
    let mut end = MAX_KEY - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s.push('…');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pairs_are_joined_with_ampersand() {
        let mut k = String::new();
        push_pair(
            &mut k,
            "header.authorization.jwt.user_id",
            Some(&json!("u_123")),
        );
        push_pair(&mut k, "header.authorization.jwt.site_id", Some(&json!(9)));
        push_pair(&mut k, "ip_intel.datacenter", Some(&json!(true)));
        push_pair(&mut k, "header.x-missing", None);
        assert_eq!(
            k,
            "header.authorization.jwt.user_id=u_123&header.authorization.jwt.site_id=9\
             &ip_intel.datacenter=true&header.x-missing="
        );
    }

    #[test]
    fn query_values_are_hashed_and_paths_lose_the_query() {
        let mut k = String::new();
        push_pair(&mut k, "req.query.api_key", Some(&json!("secret-123")));
        push_text(&mut k, "req.path", "/login?token=abc");
        assert!(!k.contains("secret-123"));
        assert!(!k.contains("token"));
        assert_eq!(
            k,
            format!(
                "req.query.api_key={}&req.path=/login",
                short_hash("secret-123")
            )
        );
        assert_eq!(short_hash("x"), short_hash("x"));
        assert_eq!(short_hash("x").len(), 7);
    }

    #[test]
    fn long_keys_are_capped_on_a_char_boundary() {
        let mut k = String::new();
        push_text(&mut k, "header.x", &"é".repeat(400));
        assert!(k.len() <= MAX_KEY);
        assert!(k.ends_with('…'));
        // Nothing more is appended once the cap is reached.
        let before = k.clone();
        push_text(&mut k, "header.y", "z");
        assert_eq!(k, before);
    }
}
