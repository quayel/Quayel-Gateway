//! Access log line format (schema_version 1).
//!
//! Every line has every key, in the same order. A value that doesn't apply
//! gets its typed default (`""`, `0`, `false`), never `null` and never a
//! missing key, so every graph and ClickHouse column works on every line.
//!
//! ```text
//! {"schema_version":1,"gateway_id":"gw-1","ts":1791892991482,
//!  "request_id":"0192d4e8-7c1a-7b3e-9f2c-4e1a7b3d5c6f","client_ip":"203.0.113.7",
//!  "method":"GET","scheme":"https","host":"api.example.com","path":"/api/users",
//!  "user_agent":"curl/8.5","status":200,"bytes":512,"req_bytes":0,"dur_us":2104,
//!  "country":"IN","region":"MH","asn":24560,"provider":"","datacenter":false,
//!  "vpn":false,"proxy":false,"tor":false,"risk":5,
//!  "block":{"type":"","action":"","rule":"","key":""},"allow_rule":"",
//!  "cache":"MISS","upstream":"origin-2","upstream_addr":"10.0.0.5:8080",
//!  "upstream_status":200,"upstream_us":1830,"grpc_status":-1,"error":"","user":"","sample_rate":1}
//! ```
//!
//! The JSON is written by hand instead of through serde: key text is fixed
//! bytes, integers go through `itoa`, strings that need no escaping (nearly
//! all of them) are copied as they are, and the gateway_id prefix is built
//! once and reused.

use crate::logging::event::LogEvent;
use std::borrow::Cow;
use std::io::Write;
use std::net::IpAddr;

pub const SCHEMA_VERSION: u32 = 1;

/// Longest user_agent kept (bytes); longer ones end in `…`.
pub const MAX_USER_AGENT: usize = 256;

/// Formats events into JSON lines. Keeps the per-gateway prefix between calls.
#[derive(Default)]
pub struct LineWriter {
    prefix_gateway: Option<Box<str>>,
    prefix: Vec<u8>,
}

impl LineWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one line (ending in `\n`) to `out`.
    pub fn write(&mut self, out: &mut Vec<u8>, ev: &LogEvent) {
        if self.prefix_gateway.as_deref() != Some(&*ev.gateway_id) {
            self.prefix.clear();
            self.prefix.extend_from_slice(b"{\"schema_version\":");
            push_u64(&mut self.prefix, SCHEMA_VERSION as u64);
            self.prefix.extend_from_slice(b",\"gateway_id\":");
            push_str(&mut self.prefix, &ev.gateway_id);
            self.prefix.extend_from_slice(b",\"ts\":");
            self.prefix_gateway = Some(Box::from(&*ev.gateway_id));
        }
        out.extend_from_slice(&self.prefix);
        push_u64(out, ev.ts_ms);

        out.extend_from_slice(b",\"request_id\":");
        push_str(out, &ev.request_id);
        out.extend_from_slice(b",\"client_ip\":\"");
        push_ip(out, ev.client_ip);
        out.extend_from_slice(b"\",\"method\":");
        push_str(out, &ev.method);
        out.extend_from_slice(b",\"scheme\":");
        push_str(out, &ev.scheme);
        out.extend_from_slice(b",\"host\":");
        push_str(out, ev.host.as_deref().unwrap_or(""));
        out.extend_from_slice(b",\"path\":");
        push_str(out, without_query(&ev.path));
        out.extend_from_slice(b",\"user_agent\":");
        push_str(
            out,
            capped(ev.user_agent.as_deref().unwrap_or(""), MAX_USER_AGENT).as_ref(),
        );

        out.extend_from_slice(b",\"status\":");
        push_u64(out, ev.status as u64);
        out.extend_from_slice(b",\"bytes\":");
        push_u64(out, ev.bytes);
        out.extend_from_slice(b",\"req_bytes\":");
        push_u64(out, ev.req_bytes);
        out.extend_from_slice(b",\"dur_us\":");
        push_u64(out, ev.dur_us);

        let intel = ev.ip_intel.as_deref();
        out.extend_from_slice(b",\"country\":");
        push_str(out, intel.and_then(|i| i.country.as_deref()).unwrap_or(""));
        out.extend_from_slice(b",\"region\":");
        push_str(out, intel.and_then(|i| i.region.as_deref()).unwrap_or(""));
        out.extend_from_slice(b",\"asn\":");
        push_u64(out, intel.and_then(|i| i.asn).unwrap_or(0) as u64);
        out.extend_from_slice(b",\"provider\":");
        push_str(out, intel.and_then(|i| i.provider.as_deref()).unwrap_or(""));
        out.extend_from_slice(b",\"datacenter\":");
        push_bool(out, intel.and_then(|i| i.is_datacenter).unwrap_or(false));
        out.extend_from_slice(b",\"vpn\":");
        push_bool(out, intel.and_then(|i| i.is_vpn).unwrap_or(false));
        out.extend_from_slice(b",\"proxy\":");
        push_bool(out, intel.and_then(|i| i.is_proxy).unwrap_or(false));
        out.extend_from_slice(b",\"tor\":");
        push_bool(out, intel.and_then(|i| i.is_tor).unwrap_or(false));
        out.extend_from_slice(b",\"risk\":");
        push_u64(out, intel.and_then(|i| i.risk_score).unwrap_or(0) as u64);

        out.extend_from_slice(b",\"block\":{\"type\":");
        push_str(out, ev.block.kind);
        out.extend_from_slice(b",\"action\":");
        push_str(out, ev.block.action);
        out.extend_from_slice(b",\"rule\":");
        push_str(out, ev.block.rule.as_deref().unwrap_or(""));
        out.extend_from_slice(b",\"key\":");
        push_str(out, &ev.block.key);
        out.extend_from_slice(b"},\"allow_rule\":");
        push_str(out, ev.allow_rule.as_deref().unwrap_or(""));

        out.extend_from_slice(b",\"cache\":");
        push_str(out, ev.cache);
        out.extend_from_slice(b",\"upstream\":");
        push_str(out, ev.upstream.as_deref().unwrap_or(""));
        out.extend_from_slice(b",\"upstream_addr\":\"");
        if let Some(host) = ev.upstream_host.as_deref() {
            escape_into(out, host);
            out.push(b':');
            push_u64(out, ev.upstream_port as u64);
        }
        out.extend_from_slice(b"\",\"upstream_status\":");
        push_u64(out, ev.upstream_status as u64);
        out.extend_from_slice(b",\"upstream_us\":");
        push_u64(out, ev.upstream_us);
        out.extend_from_slice(b",\"grpc_status\":");
        if ev.grpc_status < 0 {
            out.extend_from_slice(b"-1");
        } else {
            push_u64(out, ev.grpc_status as u64);
        }

        out.extend_from_slice(b",\"error\":");
        push_str(out, ev.error.as_deref().unwrap_or(""));
        out.extend_from_slice(b",\"user\":");
        push_str(out, ev.user.as_deref().unwrap_or(""));
        out.extend_from_slice(b",\"sample_rate\":");
        push_u64(out, ev.sample_rate as u64);
        out.extend_from_slice(b"}\n");
    }
}

fn push_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(itoa::Buffer::new().format(n).as_bytes());
}

fn push_bool(out: &mut Vec<u8>, b: bool) {
    out.extend_from_slice(if b { b"true" } else { b"false" });
}

fn push_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            let mut buf = itoa::Buffer::new();
            for (i, octet) in v4.octets().iter().enumerate() {
                if i > 0 {
                    out.push(b'.');
                }
                out.extend_from_slice(buf.format(*octet).as_bytes());
            }
        }
        // IPv6 text never needs JSON escaping.
        IpAddr::V6(v6) => {
            let _ = write!(out, "{v6}");
        }
    }
}

/// A JSON string, quotes included.
fn push_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    escape_into(out, s);
    out.push(b'"');
}

/// JSON string escaping. Runs of bytes that need none are copied in one go,
/// so a plain path or header value is a single copy.
fn escape_into(out: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x00..=0x1f => b"",
            _ => continue,
        };
        out.extend_from_slice(&bytes[start..i]);
        if esc.is_empty() {
            out.extend_from_slice(b"\\u00");
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0xf) as usize]);
        } else {
            out.extend_from_slice(esc);
        }
        start = i + 1;
    }
    out.extend_from_slice(&bytes[start..]);
}

/// The path without its query string.
pub fn without_query(path: &str) -> &str {
    match path.find('?') {
        Some(i) => &path[..i],
        None => path,
    }
}

/// `s` cut to at most `max` bytes on a char boundary, ending in `…` when cut.
fn capped(s: &str, max: usize) -> Cow<'_, str> {
    if s.len() <= max {
        return Cow::Borrowed(s);
    }
    let mut end = max - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!("{}…", &s[..end]))
}

/// Remove query strings from free text such as an upstream error message:
/// each `?` and everything after it up to the next whitespace or quote.
pub fn strip_queries(text: &str) -> Cow<'_, str> {
    if !text.contains('?') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut skipping = false;
    for c in text.chars() {
        if skipping {
            if c.is_whitespace() || c == '"' || c == '\'' {
                skipping = false;
                out.push(c);
            }
        } else if c == '?' {
            skipping = true;
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::request_context::BlockResult;
    use crate::plugins::ip_intel::IpIntel;
    use serde_json::Value;
    use std::sync::Arc;

    /// Every key, in order.
    const KEYS: &[&str] = &[
        "schema_version",
        "gateway_id",
        "ts",
        "request_id",
        "client_ip",
        "method",
        "scheme",
        "host",
        "path",
        "user_agent",
        "status",
        "bytes",
        "req_bytes",
        "dur_us",
        "country",
        "region",
        "asn",
        "provider",
        "datacenter",
        "vpn",
        "proxy",
        "tor",
        "risk",
        "block",
        "allow_rule",
        "cache",
        "upstream",
        "upstream_addr",
        "upstream_status",
        "upstream_us",
        "grpc_status",
        "error",
        "user",
        "sample_rate",
    ];

    pub(crate) fn plain_event() -> LogEvent {
        let c = crate::logging::event::tests::ctx("/api/users", &[]);
        let mut ev = LogEvent::from_context(&c);
        ev.request_id = "0192d4e8-7c1a-7b3e-9f2c-4e1a7b3d5c6f".into();
        ev.ts_ms = 1_791_892_991_482;
        ev
    }

    pub(crate) fn full_event() -> LogEvent {
        let mut ev = plain_event();
        ev.client_ip = "203.0.113.7".parse().unwrap();
        ev.method = Arc::from("POST");
        ev.scheme = Arc::from("https");
        ev.host = Some(Arc::from("api.example.com"));
        ev.path = Arc::from("/login?token=secret");
        ev.user_agent = Some(Arc::from("Mozilla/5.0 (X11; Linux x86_64)"));
        ev.status = 403;
        ev.bytes = 512;
        ev.req_bytes = 64;
        ev.dur_us = 2104;
        ev.ip_intel = Some(Arc::new(IpIntel {
            country: Some("RU".into()),
            region: Some("MOW".into()),
            city: None,
            asn: Some(9009),
            as_org: None,
            provider: Some("M247".into()),
            is_vpn: Some(true),
            is_proxy: None,
            is_datacenter: Some(true),
            is_mobile: None,
            is_residential: None,
            is_residential_proxy: None,
            is_tor: Some(false),
            network_type: None,
            risk_score: Some(80),
            source_versions: vec![],
        }));
        ev.block = BlockResult {
            kind: "fw",
            action: "block",
            rule: Some(Arc::from("block-dc")),
            key: "ip.is_datacenter=true".into(),
        };
        ev.cache = "NONE";
        ev.upstream = Some(Arc::from("origin-2"));
        ev.upstream_host = Some(Arc::from("10.0.0.5"));
        ev.upstream_port = 8080;
        ev.upstream_status = 200;
        ev.upstream_us = 1830;
        ev.grpc_status = 14;
        ev.error = Some("connection refused".into());
        ev.user = Some("user_123".into());
        ev
    }

    fn line(ev: &LogEvent) -> (String, Value) {
        let mut out = Vec::new();
        LineWriter::new().write(&mut out, ev);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.ends_with('\n') && text.matches('\n').count() == 1,
            "{text}"
        );
        let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"));
        (text, v)
    }

    fn keys_in_order(text: &str) -> Vec<String> {
        // serde_json's Map is sorted unless preserve_order is on, so read the
        // top-level key order straight from the text.
        let mut keys = Vec::new();
        let mut de = serde_json::Deserializer::from_str(text);
        struct Keys<'a>(&'a mut Vec<String>);
        impl<'de> serde::de::Visitor<'de> for Keys<'_> {
            type Value = ();
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
                while let Some(k) = m.next_key::<String>()? {
                    self.0.push(k);
                    m.next_value::<serde::de::IgnoredAny>()?;
                }
                Ok(())
            }
        }
        serde::Deserializer::deserialize_map(&mut de, Keys(&mut keys)).unwrap();
        keys
    }

    #[test]
    fn plain_request_has_every_key_with_typed_defaults() {
        let (text, v) = line(&plain_event());
        assert_eq!(keys_in_order(&text), KEYS);
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["gateway_id"], "gw");
        assert_eq!(v["ts"], 1_791_892_991_482u64);
        assert_eq!(v["client_ip"], "127.0.0.1");
        assert_eq!(v["host"], "");
        assert_eq!(v["user_agent"], "");
        assert_eq!(v["status"], 0);
        assert_eq!(v["country"], "");
        assert_eq!(v["asn"], 0);
        assert_eq!(v["datacenter"], false);
        assert_eq!(v["risk"], 0);
        assert_eq!(
            v["block"],
            serde_json::json!({"type": "", "action": "", "rule": "", "key": ""})
        );
        assert_eq!(v["cache"], "NONE");
        assert_eq!(v["upstream_addr"], "");
        assert_eq!(v["upstream_status"], 0);
        assert_eq!(v["grpc_status"], -1);
        assert_eq!(v["error"], "");
        assert_eq!(v["user"], "");
        assert_eq!(v["sample_rate"], 1);
        assert!(!text.contains("null"));
    }

    #[test]
    fn full_event_values_round_trip() {
        let (text, v) = line(&full_event());
        assert_eq!(keys_in_order(&text), KEYS);
        assert_eq!(v["client_ip"], "203.0.113.7");
        assert_eq!(v["method"], "POST");
        assert_eq!(v["host"], "api.example.com");
        assert_eq!(v["path"], "/login", "query string is never logged");
        assert!(!text.contains("secret"));
        assert_eq!(v["status"], 403);
        assert_eq!(v["bytes"], 512);
        assert_eq!(v["req_bytes"], 64);
        assert_eq!(v["dur_us"], 2104);
        assert_eq!(v["country"], "RU");
        assert_eq!(v["region"], "MOW");
        assert_eq!(v["asn"], 9009);
        assert_eq!(v["provider"], "M247");
        assert_eq!(v["datacenter"], true);
        assert_eq!(v["vpn"], true);
        assert_eq!(v["proxy"], false);
        assert_eq!(v["tor"], false);
        assert_eq!(v["risk"], 80);
        assert_eq!(
            v["block"],
            serde_json::json!({"type": "fw", "action": "block", "rule": "block-dc",
                               "key": "ip.is_datacenter=true"})
        );
        assert_eq!(v["upstream"], "origin-2");
        assert_eq!(v["upstream_addr"], "10.0.0.5:8080");
        assert_eq!(v["upstream_status"], 200);
        assert_eq!(v["upstream_us"], 1830);
        assert_eq!(v["grpc_status"], 14);
        assert_eq!(v["error"], "connection refused");
        assert_eq!(v["user"], "user_123");
    }

    #[test]
    fn awkward_strings_are_escaped_and_parse_back() {
        let nasty = [
            "plain",
            "quote\" backslash\\ slash/",
            "line\nbreak\r\ttab",
            "\u{0}\u{1}\u{1f}\u{7f}",
            "ünïcødé 日本 🚀",
            "</script>",
            "",
        ];
        for s in nasty {
            let mut ev = plain_event();
            ev.host = Some(Arc::from(s));
            ev.user_agent = Some(Arc::from(s));
            ev.block.key = s.to_string();
            ev.error = Some(s.to_string());
            let (_, v) = line(&ev);
            assert_eq!(v["host"], s);
            assert_eq!(v["user_agent"], s);
            assert_eq!(v["block"]["key"], s);
            assert_eq!(v["error"], s);
        }
    }

    #[test]
    fn ipv6_and_gateway_change() {
        let mut w = LineWriter::new();
        let mut out = Vec::new();
        let mut ev = plain_event();
        ev.client_ip = "2001:db8::1".parse().unwrap();
        w.write(&mut out, &ev);
        ev.gateway_id = Arc::from("gw-\"2\"");
        w.write(&mut out, &ev);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[0]["client_ip"], "2001:db8::1");
        assert_eq!(lines[0]["gateway_id"], "gw");
        assert_eq!(
            lines[1]["gateway_id"], "gw-\"2\"",
            "prefix rebuilt on change"
        );
    }

    #[test]
    fn long_user_agent_is_capped() {
        let mut ev = plain_event();
        ev.user_agent = Some(Arc::from("é".repeat(300).as_str()));
        let (_, v) = line(&ev);
        let ua = v["user_agent"].as_str().unwrap();
        assert!(ua.len() <= MAX_USER_AGENT && ua.ends_with('…'));
    }

    #[test]
    fn queries_are_stripped_from_free_text() {
        assert_eq!(strip_queries("no query here"), "no query here");
        assert_eq!(
            strip_queries("GET http://o/x?token=abc failed: refused"),
            "GET http://o/x failed: refused"
        );
        assert_eq!(strip_queries("'/a?k=v' and \"/b?x\""), "'/a' and \"/b\"");
    }

    /// Formatting cost per line. Run with:
    /// cargo test --release writer_bench -- --ignored --nocapture
    #[test]
    #[ignore]
    fn writer_bench() {
        let mut c = crate::logging::event::tests::ctx("/api/users?page=2", &[]);
        c.request_id = "0192d4e8-7c1a-7b3e-9f2c-4e1a7b3d5c6f".into();
        c.user_agent = Some(Arc::from(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ));
        c.host = Some(Arc::from("api.example.com"));
        c.status_code = Some(200);
        c.upstream_status = Some(200);
        let n = 2_000_000;

        let t = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(LogEvent::from_context(std::hint::black_box(&c)));
        }
        let build = t.elapsed().as_nanos() as f64 / n as f64;

        let ev = LogEvent::from_context(&c);
        let mut w = LineWriter::new();
        let mut buf = Vec::with_capacity(1 << 20);
        let t = std::time::Instant::now();
        for _ in 0..n {
            buf.clear();
            w.write(&mut buf, std::hint::black_box(&ev));
            std::hint::black_box(&buf);
        }
        let fmt = t.elapsed().as_nanos() as f64 / n as f64;
        eprintln!(
            "WRITER: format {fmt:.0} ns/line, {} bytes/line; from_context {build:.0} ns",
            buf.len()
        );
    }
}
