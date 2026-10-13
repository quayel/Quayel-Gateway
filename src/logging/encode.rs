//! Request bodies for each sink type, built from a batch of access-log lines
//! (`writer.rs` format, one JSON object per line).
//!
//! ClickHouse and plain HTTP take the lines as they are. The others wrap each
//! line in the destination's envelope. Values the envelope needs (ts, status,
//! gateway_id, ...) are read straight from the line: every line has the same
//! keys in the same order, and a key like `,"ts":` can't appear inside a
//! string value because the quotes there are escaped.

use crate::config::sinks::SinkFormat;

/// One line per item, without the trailing newline.
pub fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|&b| b == b'\n').filter(|l| !l.is_empty())
}

/// Integer value of `key` (e.g. `,"ts":`).
fn int(line: &[u8], key: &[u8]) -> u64 {
    let Some(at) = find(line, key) else {
        return 0;
    };
    line[at + key.len()..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .fold(0u64, |n, &d| {
            n.saturating_mul(10).saturating_add((d - b'0') as u64)
        })
}

/// Raw (still JSON-escaped) content of string `key` (e.g. `,"host":"`).
fn raw_str<'a>(line: &'a [u8], key: &[u8]) -> &'a [u8] {
    let Some(at) = find(line, key) else {
        return b"";
    };
    let rest = &line[at + key.len()..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i] {
            b'\\' => i += 2,
            b'"' => return &rest[..i],
            _ => i += 1,
        }
    }
    rest
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn ts_ms(line: &[u8]) -> u64 {
    int(line, b",\"ts\":")
}
fn status(line: &[u8]) -> u64 {
    int(line, b",\"status\":")
}
fn gateway_id(line: &[u8]) -> &[u8] {
    raw_str(line, b",\"gateway_id\":\"")
}
fn blocked(line: &[u8]) -> bool {
    find(line, b"\"block\":{\"type\":\"\"").is_none()
}

/// info / warn (4xx or blocked) / error (5xx).
fn level(line: &[u8]) -> &'static str {
    match status(line) {
        500.. => "error",
        400.. => "warn",
        _ if blocked(line) => "warn",
        _ => "info",
    }
}

/// `GET api.example.com/path 200`, still JSON-escaped (fits in a JSON string).
fn summary(out: &mut Vec<u8>, line: &[u8]) {
    out.extend_from_slice(raw_str(line, b",\"method\":\""));
    out.push(b' ');
    out.extend_from_slice(raw_str(line, b",\"host\":\""));
    out.extend_from_slice(raw_str(line, b",\"path\":\""));
    out.push(b' ');
    out.extend_from_slice(itoa::Buffer::new().format(status(line)).as_bytes());
}

/// A JSON string literal (quotes included).
fn json_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(serde_json::to_string(s).unwrap_or_default().as_bytes());
}

/// `line` as a JSON string literal.
fn line_as_str(out: &mut Vec<u8>, line: &[u8]) {
    json_str(out, std::str::from_utf8(line).unwrap_or(""));
}

fn push_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(itoa::Buffer::new().format(n).as_bytes());
}

/// Body for a batch. `batch_id` makes Elasticsearch document IDs stable, so
/// a retried batch overwrites itself instead of adding duplicates.
/// Returns (body, content type).
pub fn encode(format: &SinkFormat, data: &[u8], batch_id: &str) -> (Vec<u8>, &'static str) {
    match format {
        SinkFormat::Http => (data.to_vec(), "application/x-ndjson"),
        SinkFormat::ClickHouse => (data.to_vec(), "application/x-ndjson"),
        SinkFormat::Datadog {
            service,
            source,
            tags,
        } => (
            datadog(data, service, source, tags.as_deref()),
            "application/json",
        ),
        SinkFormat::Otlp { service, resource } => {
            (otlp(data, service, resource), "application/json")
        }
        SinkFormat::Loki { labels } => (loki(data, labels), "application/json"),
        SinkFormat::Elasticsearch { index } => {
            (elasticsearch(data, index, batch_id), "application/x-ndjson")
        }
        SinkFormat::Splunk {
            index,
            source,
            sourcetype,
        } => (
            splunk(data, index.as_deref(), source, sourcetype),
            "application/json",
        ),
    }
}

/// Datadog logs intake v2: a JSON array. The line goes under `qg` so its
/// `status` (HTTP code) doesn't collide with Datadog's reserved `status`
/// (log level); search it as `@qg.status`, `@qg.block.rule`, ...
fn datadog(data: &[u8], service: &str, source: &str, tags: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 3 / 2);
    let mut common = Vec::new();
    common.extend_from_slice(b"{\"ddsource\":");
    json_str(&mut common, source);
    common.extend_from_slice(b",\"service\":");
    json_str(&mut common, service);
    if let Some(t) = tags {
        common.extend_from_slice(b",\"ddtags\":");
        json_str(&mut common, t);
    }
    out.push(b'[');
    for (i, line) in lines(data).enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&common);
        out.extend_from_slice(b",\"hostname\":\"");
        out.extend_from_slice(gateway_id(line));
        out.extend_from_slice(b"\",\"timestamp\":");
        push_u64(&mut out, ts_ms(line));
        out.extend_from_slice(b",\"status\":\"");
        out.extend_from_slice(level(line).as_bytes());
        out.extend_from_slice(b"\",\"message\":\"");
        summary(&mut out, line);
        out.extend_from_slice(b"\",\"qg\":");
        out.extend_from_slice(line);
        out.push(b'}');
    }
    out.push(b']');
    out
}

/// OTLP/HTTP JSON (`ExportLogsServiceRequest`). Every key of the line
/// becomes a log attribute (`block.type`, `block.rule`, ... for the nested
/// object), the body is the one-line summary.
fn otlp(data: &[u8], service: &str, resource: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 4);
    out.extend_from_slice(b"{\"resourceLogs\":[{\"resource\":{\"attributes\":[");
    attr_str(&mut out, "service.name", service);
    for (k, v) in resource {
        out.push(b',');
        attr_str(&mut out, k, v);
    }
    out.extend_from_slice(
        b"]},\"scopeLogs\":[{\"scope\":{\"name\":\"quayel-gateway.access_log\",\"version\":\"",
    );
    out.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
    out.extend_from_slice(b"\"},\"logRecords\":[");
    let mut first = true;
    for line in lines(data) {
        let Ok(obj) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(line)
        else {
            continue;
        };
        if !first {
            out.push(b',');
        }
        first = false;
        let ns = ts_ms(line).saturating_mul(1_000_000);
        let (num, text) = match level(line) {
            "error" => (17, "ERROR"),
            "warn" => (13, "WARN"),
            _ => (9, "INFO"),
        };
        out.extend_from_slice(b"{\"timeUnixNano\":\"");
        push_u64(&mut out, ns);
        out.extend_from_slice(b"\",\"observedTimeUnixNano\":\"");
        push_u64(&mut out, ns);
        out.extend_from_slice(b"\",\"severityNumber\":");
        push_u64(&mut out, num);
        out.extend_from_slice(b",\"severityText\":\"");
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(b"\",\"body\":{\"stringValue\":\"");
        summary(&mut out, line);
        out.extend_from_slice(b"\"},\"attributes\":[");
        let mut first_attr = true;
        for (k, v) in &obj {
            match v {
                serde_json::Value::Object(inner) => {
                    for (ik, iv) in inner {
                        attr(&mut out, &mut first_attr, &format!("{k}.{ik}"), iv);
                    }
                }
                _ => attr(&mut out, &mut first_attr, k, v),
            }
        }
        out.extend_from_slice(b"]}");
    }
    out.extend_from_slice(b"]}]}]}");
    out
}

fn attr_str(out: &mut Vec<u8>, k: &str, v: &str) {
    out.extend_from_slice(b"{\"key\":");
    json_str(out, k);
    out.extend_from_slice(b",\"value\":{\"stringValue\":");
    json_str(out, v);
    out.extend_from_slice(b"}}");
}

fn attr(out: &mut Vec<u8>, first: &mut bool, k: &str, v: &serde_json::Value) {
    if !*first {
        out.push(b',');
    }
    *first = false;
    out.extend_from_slice(b"{\"key\":");
    json_str(out, k);
    out.extend_from_slice(b",\"value\":{");
    match v {
        serde_json::Value::Bool(b) => out.extend_from_slice(if *b {
            b"\"boolValue\":true"
        } else {
            b"\"boolValue\":false"
        }),
        // OTLP JSON writes int64 as a string.
        serde_json::Value::Number(n) if n.is_u64() || n.is_i64() => {
            out.extend_from_slice(b"\"intValue\":\"");
            out.extend_from_slice(n.to_string().as_bytes());
            out.push(b'"');
        }
        serde_json::Value::Number(n) => {
            out.extend_from_slice(b"\"doubleValue\":");
            out.extend_from_slice(n.to_string().as_bytes());
        }
        serde_json::Value::String(s) => {
            out.extend_from_slice(b"\"stringValue\":");
            json_str(out, s);
        }
        other => {
            out.extend_from_slice(b"\"stringValue\":");
            json_str(out, &other.to_string());
        }
    }
    out.extend_from_slice(b"}}");
}

/// Loki push API: one stream per gateway_id with the configured labels; the
/// line is the entry text (query it with `| json`).
fn loki(data: &[u8], labels: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 3 / 2);
    // Consecutive lines with the same gateway_id share a stream entry.
    let mut groups: Vec<(&[u8], Vec<&[u8]>)> = Vec::new();
    for line in lines(data) {
        let gid = gateway_id(line);
        match groups.last_mut() {
            Some((g, v)) if *g == gid => v.push(line),
            _ => groups.push((gid, vec![line])),
        }
    }
    out.extend_from_slice(b"{\"streams\":[");
    for (gi, (gid, group)) in groups.iter().enumerate() {
        if gi > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"stream\":{");
        for (k, v) in labels {
            json_str(&mut out, k);
            out.push(b':');
            json_str(&mut out, v);
            out.push(b',');
        }
        out.extend_from_slice(b"\"gateway_id\":\"");
        out.extend_from_slice(gid);
        out.extend_from_slice(b"\"},\"values\":[");
        for (i, line) in group.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"[\"");
            push_u64(&mut out, ts_ms(line).saturating_mul(1_000_000));
            out.extend_from_slice(b"\",");
            line_as_str(&mut out, line);
            out.push(b']');
        }
        out.extend_from_slice(b"]}");
    }
    out.extend_from_slice(b"]}");
    out
}

/// Elasticsearch / OpenSearch `_bulk`. Each document is the line plus
/// `@timestamp` (RFC 3339, so dynamic mapping makes it a date). Document IDs
/// are `<batch id>-<line number>`: a retried batch overwrites itself, and a
/// client can't make two requests share one document by reusing a request ID.
fn elasticsearch(data: &[u8], index: &str, batch_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 3 / 2);
    for (i, line) in lines(data).enumerate() {
        out.extend_from_slice(b"{\"index\":{\"_index\":");
        json_str(&mut out, index);
        out.extend_from_slice(b",\"_id\":\"");
        out.extend_from_slice(batch_id.as_bytes());
        out.push(b'-');
        push_u64(&mut out, i as u64);
        out.extend_from_slice(b"\"}}\n{\"@timestamp\":\"");
        let ts = chrono::DateTime::from_timestamp_millis(ts_ms(line) as i64).unwrap_or_default();
        out.extend_from_slice(
            ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                .as_bytes(),
        );
        out.extend_from_slice(b"\",");
        out.extend_from_slice(&line[1..]);
        out.push(b'\n');
    }
    out
}

/// Splunk HEC `/services/collector/event`: one event object per line.
fn splunk(data: &[u8], index: Option<&str>, source: &str, sourcetype: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 3 / 2);
    let mut common = Vec::new();
    common.extend_from_slice(b",\"source\":");
    json_str(&mut common, source);
    common.extend_from_slice(b",\"sourcetype\":");
    json_str(&mut common, sourcetype);
    if let Some(i) = index {
        common.extend_from_slice(b",\"index\":");
        json_str(&mut common, i);
    }
    for line in lines(data) {
        let ms = ts_ms(line);
        out.extend_from_slice(b"{\"time\":");
        push_u64(&mut out, ms / 1000);
        out.push(b'.');
        out.extend_from_slice(format!("{:03}", ms % 1000).as_bytes());
        out.extend_from_slice(b",\"host\":\"");
        out.extend_from_slice(gateway_id(line));
        out.push(b'"');
        out.extend_from_slice(&common);
        out.extend_from_slice(b",\"event\":");
        out.extend_from_slice(line);
        out.extend_from_slice(b"}\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const LINE: &str = r#"{"schema_version":1,"gateway_id":"gw-\"1","ts":1791858593372,"request_id":"01a13318-4e5c-78ca-865a-f463596d0d6e","client_ip":"127.0.0.1","method":"GET","scheme":"http","host":"h.example","path":"/a\"b","user_agent":"x ,\"ts\":5","status":429,"bytes":88,"req_bytes":0,"dur_us":338,"country":"","region":"","asn":0,"provider":"","datacenter":false,"vpn":false,"proxy":false,"tor":false,"risk":0,"block":{"type":"rl","action":"block","rule":"per-user","key":"k"},"allow_rule":"","cache":"NONE","upstream":"","upstream_addr":"","upstream_status":0,"upstream_us":0,"error":"","user":"","sample_rate":1}"#;

    fn data() -> Vec<u8> {
        format!("{LINE}\n{LINE}\n").into_bytes()
    }

    #[test]
    fn reads_values_from_the_line() {
        let l = LINE.as_bytes();
        assert_eq!(ts_ms(l), 1791858593372);
        assert_eq!(status(l), 429);
        assert_eq!(gateway_id(l), br#"gw-\"1"#);
        assert_eq!(level(l), "warn");
    }

    #[test]
    fn datadog_is_a_valid_array() {
        let fmt = SinkFormat::Datadog {
            service: "s".into(),
            source: "src".into(),
            tags: Some("env:t".into()),
        };
        let v: Value = serde_json::from_slice(&encode(&fmt, &data(), "b").0).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert_eq!(v[0]["timestamp"], 1791858593372u64);
        assert_eq!(v[0]["hostname"], "gw-\"1");
        assert_eq!(v[0]["status"], "warn");
        assert_eq!(v[0]["message"], "GET h.example/a\"b 429");
        assert_eq!(v[0]["qg"]["block"]["rule"], "per-user");
    }

    #[test]
    fn otlp_flattens_attributes() {
        let fmt = SinkFormat::Otlp {
            service: "s".into(),
            resource: vec![("env".into(), "t".into())],
        };
        let v: Value = serde_json::from_slice(&encode(&fmt, &data(), "b").0).unwrap();
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["timeUnixNano"], "1791858593372000000");
        assert_eq!(rec["severityText"], "WARN");
        let attrs = rec["attributes"].as_array().unwrap();
        assert!(attrs
            .iter()
            .any(|a| a["key"] == "block.rule" && a["value"]["stringValue"] == "per-user"));
        assert!(attrs
            .iter()
            .any(|a| a["key"] == "status" && a["value"]["intValue"] == "429"));
        assert!(attrs
            .iter()
            .any(|a| a["key"] == "tor" && a["value"]["boolValue"] == false));
    }

    #[test]
    fn loki_elasticsearch_splunk_parse() {
        let v: Value = serde_json::from_slice(
            &encode(
                &SinkFormat::Loki {
                    labels: vec![("job".into(), "qg".into())],
                },
                &data(),
                "b",
            )
            .0,
        )
        .unwrap();
        assert_eq!(v["streams"][0]["stream"]["gateway_id"], "gw-\"1");
        assert_eq!(v["streams"][0]["values"][1][0], "1791858593372000000");
        assert_eq!(v["streams"][0]["values"][1][1], LINE);

        let es = encode(
            &SinkFormat::Elasticsearch { index: "i".into() },
            &data(),
            "B",
        )
        .0;
        let es: Vec<Value> = es
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).unwrap())
            .collect();
        assert_eq!(es.len(), 4);
        assert_eq!(es[2]["index"]["_id"], "B-1");
        assert_eq!(es[1]["@timestamp"], "2026-10-13T02:29:53.372Z");
        assert_eq!(es[1]["status"], 429);

        let sp = encode(
            &SinkFormat::Splunk {
                index: Some("main".into()),
                source: "s".into(),
                sourcetype: "t".into(),
            },
            &data(),
            "b",
        )
        .0;
        let first: Value =
            serde_json::from_slice(sp.split(|&b| b == b'\n').next().unwrap()).unwrap();
        assert_eq!(first["time"], 1791858593.372);
        assert_eq!(first["event"]["path"], "/a\"b");
    }
}
