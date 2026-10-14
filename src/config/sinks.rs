//! `plugins.logging.sinks` and `metrics`: validation and the resolved form
//! the log shipper uses (full request URL, auth headers with secrets read
//! from env vars, per-type defaults).

use crate::config::schema::{LogSinkConfig, MetricsConfig};

/// A credential or header value. Never printed by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledMetrics {
    pub listen: String,
    pub path: String,
    pub max_hosts: usize,
}

/// How a batch of JSON lines is turned into a request body.
#[derive(Debug, Clone, PartialEq)]
pub enum SinkFormat {
    /// Newline-delimited JSON, lines as they are (Vector, Fluent Bit,
    /// Logstash, any webhook).
    Http,
    /// `INSERT … FORMAT JSONEachRow`: lines as they are.
    ClickHouse,
    /// JSON array for the Datadog logs intake.
    Datadog {
        service: String,
        source: String,
        tags: Option<String>,
    },
    /// OTLP/HTTP JSON logs.
    Otlp {
        service: String,
        resource: Vec<(String, String)>,
    },
    /// Loki push API.
    Loki { labels: Vec<(String, String)> },
    /// Elasticsearch / OpenSearch `_bulk`.
    Elasticsearch { index: String },
    /// Splunk HTTP Event Collector.
    Splunk {
        index: Option<String>,
        source: String,
        sourcetype: String,
    },
}

impl SinkFormat {
    pub fn type_name(&self) -> &'static str {
        match self {
            SinkFormat::Http => "http",
            SinkFormat::ClickHouse => "clickhouse",
            SinkFormat::Datadog { .. } => "datadog",
            SinkFormat::Otlp { .. } => "otlp",
            SinkFormat::Loki { .. } => "loki",
            SinkFormat::Elasticsearch { .. } => "elasticsearch",
            SinkFormat::Splunk { .. } => "splunk",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledSink {
    pub name: String,
    pub format: SinkFormat,
    /// Full request URL (path and fixed query parameters included).
    pub url: String,
    /// Auth and extra headers.
    pub headers: Vec<(String, Secret)>,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub timeout_ms: u64,
    pub gzip: bool,
    pub max_buffer_bytes: usize,
    pub concurrency: usize,
    pub spool_dir: Option<String>,
    pub spool_max_bytes: u64,
}

/// Lines per request unless `batch_size` is set. ClickHouse and plain HTTP
/// take ~60 MB requests; Loki (4 MB/s ingest limit, 6 MB burst), the OTel
/// Collector (20 MiB body limit) and usually Elasticsearch/Splunk don't, so
/// they keep SMALL_BATCH.
const DEFAULT_BATCH: usize = 100_000;
const SMALL_BATCH: usize = 5000;
/// Datadog's intake accepts at most 1000 entries per request.
const DATADOG_MAX_BATCH: usize = 1000;
const DEFAULT_SERVICE: &str = "quayel-gateway";

pub fn compile_metrics(c: &MetricsConfig) -> Result<Option<CompiledMetrics>, String> {
    if !c.enabled {
        return Ok(None);
    }
    if c.listen.parse::<std::net::SocketAddr>().is_err() {
        return Err(format!(
            "metrics.listen '{}' must be an address like 127.0.0.1:9464",
            c.listen
        ));
    }
    if !c.path.starts_with('/') {
        return Err("metrics.path must start with '/'".to_string());
    }
    if c.max_hosts == 0 {
        return Err("metrics.max_hosts must be at least 1".to_string());
    }
    Ok(Some(CompiledMetrics {
        listen: c.listen.clone(),
        path: c.path.clone(),
        max_hosts: c.max_hosts,
    }))
}

/// Returns (stdout, network sinks).
pub fn compile_sinks(list: &[LogSinkConfig]) -> Result<(bool, Vec<CompiledSink>), String> {
    let mut stdout = false;
    let mut sinks: Vec<CompiledSink> = Vec::new();
    for (i, c) in list.iter().enumerate() {
        let at = format!("plugins.logging.sinks[{i}]");
        if c.kind == "stdout" {
            check_fields(c, &at, &[])?;
            if stdout {
                return Err(format!("{at}: only one stdout sink is allowed"));
            }
            stdout = true;
            continue;
        }
        let s = compile_sink(c, &at)?;
        if sinks.iter().any(|o| o.name == s.name) {
            return Err(format!(
                "{at}: two sinks are named '{}'; set a unique `name`",
                s.name
            ));
        }
        sinks.push(s);
    }
    Ok((stdout, sinks))
}

/// Fields every network sink accepts.
const COMMON: &[&str] = &[
    "name",
    "url",
    "headers",
    "headers_env",
    "batch_size",
    "flush_interval_ms",
    "timeout_ms",
    "compression",
    "max_buffer_bytes",
    "concurrency",
    "spool_dir",
    "spool_max_bytes",
];

fn compile_sink(c: &LogSinkConfig, at: &str) -> Result<CompiledSink, String> {
    let name = c.name.clone().unwrap_or_else(|| c.kind.clone());
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(format!(
            "{at}: name '{name}' may only use letters, digits, '-' and '_'"
        ));
    }
    let at = format!("{at} ({name})");
    let at = at.as_str();

    let mut headers: Vec<(String, Secret)> = Vec::new();
    let url_of = |c: &LogSinkConfig| -> Result<String, String> {
        let u = c
            .url
            .as_deref()
            .map(|u| u.trim().trim_end_matches('/'))
            .filter(|u| !u.is_empty())
            .ok_or_else(|| format!("{at}: `url` is required"))?;
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return Err(format!("{at}: url must start with http:// or https://"));
        }
        Ok(u.to_string())
    };

    let (format, url, default_batch, default_flush) = match c.kind.as_str() {
        "http" => {
            check_fields(
                c,
                at,
                &["user", "password", "password_env", "token", "token_env"],
            )?;
            let url = url_of(c)?;
            basic_auth(c, at, &mut headers)?;
            if let Some(t) = secret(c.token.as_deref(), c.token_env.as_deref(), "token", at)? {
                headers.push(("Authorization".into(), Secret(format!("Bearer {t}"))));
            }
            (SinkFormat::Http, url, DEFAULT_BATCH, 1000)
        }
        "clickhouse" => {
            check_fields(
                c,
                at,
                &["database", "table", "user", "password", "password_env"],
            )?;
            let base = url_of(c)?;
            let db = c.database.as_deref().unwrap_or("default");
            let table = c.table.as_deref().unwrap_or("access_log");
            for (what, v) in [("database", db), ("table", table)] {
                if v.is_empty() || !v.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
                    return Err(format!(
                        "{at}: {what} '{v}' may only use letters, digits and '_'"
                    ));
                }
            }
            let query = format!("INSERT INTO `{db}`.`{table}` FORMAT JSONEachRow");
            let url = format!(
                "{base}/?query={}&input_format_skip_unknown_fields=1&async_insert=0",
                urlencoding::encode(&query)
            );
            if let Some(u) = &c.user {
                headers.push(("X-ClickHouse-User".into(), Secret(u.clone())));
            }
            if let Some(p) = secret(
                c.password.as_deref(),
                c.password_env.as_deref(),
                "password",
                at,
            )? {
                headers.push(("X-ClickHouse-Key".into(), Secret(p)));
            }
            (SinkFormat::ClickHouse, url, DEFAULT_BATCH, 5000)
        }
        "datadog" => {
            check_fields(
                c,
                at,
                &[
                    "site",
                    "service",
                    "source",
                    "tags",
                    "api_key",
                    "api_key_env",
                ],
            )?;
            let url = match &c.url {
                Some(_) => url_of(c)?,
                None => format!(
                    "https://http-intake.logs.{}/api/v2/logs",
                    c.site.as_deref().unwrap_or("datadoghq.com")
                ),
            };
            let key = secret(
                c.api_key.as_deref(),
                c.api_key_env.as_deref(),
                "api_key",
                at,
            )?
            .ok_or_else(|| format!("{at}: `api_key` or `api_key_env` is required"))?;
            headers.push(("DD-API-KEY".into(), Secret(key)));
            if c.batch_size.is_some_and(|b| b > DATADOG_MAX_BATCH) {
                return Err(format!(
                    "{at}: batch_size can be at most {DATADOG_MAX_BATCH} (Datadog's limit)"
                ));
            }
            (
                SinkFormat::Datadog {
                    service: c.service.clone().unwrap_or_else(|| DEFAULT_SERVICE.into()),
                    source: c.source.clone().unwrap_or_else(|| DEFAULT_SERVICE.into()),
                    tags: c.tags.clone().filter(|t| !t.is_empty()),
                },
                url,
                DATADOG_MAX_BATCH,
                1000,
            )
        }
        "otlp" => {
            check_fields(c, at, &["service", "resource_attributes"])?;
            let base = url_of(c)?;
            let url = if base.ends_with("/v1/logs") {
                base
            } else {
                format!("{base}/v1/logs")
            };
            let mut resource: Vec<(String, String)> = c
                .resource_attributes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            resource.sort();
            (
                SinkFormat::Otlp {
                    service: c.service.clone().unwrap_or_else(|| DEFAULT_SERVICE.into()),
                    resource,
                },
                url,
                SMALL_BATCH,
                1000,
            )
        }
        "loki" => {
            check_fields(
                c,
                at,
                &["labels", "tenant_id", "user", "password", "password_env"],
            )?;
            let base = url_of(c)?;
            let url = if base.ends_with("/loki/api/v1/push") {
                base
            } else {
                format!("{base}/loki/api/v1/push")
            };
            basic_auth(c, at, &mut headers)?;
            if let Some(t) = &c.tenant_id {
                headers.push(("X-Scope-OrgID".into(), Secret(t.clone())));
            }
            let mut labels: Vec<(String, String)> = if c.labels.is_empty() {
                vec![("job".into(), DEFAULT_SERVICE.into())]
            } else {
                c.labels
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            };
            for (k, _) in &labels {
                let ok = k
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
                    && k.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
                if !ok || k == "gateway_id" {
                    return Err(format!(
                        "{at}: label '{k}' must match [a-zA-Z_][a-zA-Z0-9_]* and isn't \
                         gateway_id (added automatically)"
                    ));
                }
            }
            labels.sort();
            (SinkFormat::Loki { labels }, url, SMALL_BATCH, 1000)
        }
        "elasticsearch" | "opensearch" => {
            check_fields(
                c,
                at,
                &[
                    "index",
                    "user",
                    "password",
                    "password_env",
                    "api_key",
                    "api_key_env",
                ],
            )?;
            let base = url_of(c)?;
            basic_auth(c, at, &mut headers)?;
            if let Some(k) = secret(
                c.api_key.as_deref(),
                c.api_key_env.as_deref(),
                "api_key",
                at,
            )? {
                headers.push(("Authorization".into(), Secret(format!("ApiKey {k}"))));
            }
            let index = c.index.clone().unwrap_or_else(|| "quayel-access".into());
            if index.is_empty() || index.contains(['"', '\\', '/', ' ']) {
                return Err(format!("{at}: index '{index}' isn't a valid index name"));
            }
            (
                SinkFormat::Elasticsearch { index },
                format!("{base}/_bulk"),
                SMALL_BATCH,
                1000,
            )
        }
        "splunk" => {
            check_fields(
                c,
                at,
                &["index", "source", "sourcetype", "token", "token_env"],
            )?;
            let base = url_of(c)?;
            let url = if base.contains("/services/collector") {
                base
            } else {
                format!("{base}/services/collector/event")
            };
            let token = secret(c.token.as_deref(), c.token_env.as_deref(), "token", at)?
                .ok_or_else(|| format!("{at}: `token` or `token_env` is required"))?;
            headers.push(("Authorization".into(), Secret(format!("Splunk {token}"))));
            (
                SinkFormat::Splunk {
                    index: c.index.clone(),
                    source: c.source.clone().unwrap_or_else(|| DEFAULT_SERVICE.into()),
                    sourcetype: c
                        .sourcetype
                        .clone()
                        .unwrap_or_else(|| "quayel:access".into()),
                },
                url,
                SMALL_BATCH,
                1000,
            )
        }
        other => {
            return Err(format!(
                "{at}: unknown sink type '{other}' (use stdout, http, clickhouse, datadog, \
                 otlp, loki, elasticsearch or splunk)"
            ))
        }
    };

    for (k, v) in &c.headers {
        headers.push((k.clone(), Secret(v.clone())));
    }
    for (k, env) in &c.headers_env {
        let v = std::env::var(env)
            .map_err(|_| format!("{at}: headers_env.{k}: env var {env} is not set"))?;
        headers.push((k.clone(), Secret(v)));
    }
    for (k, v) in &headers {
        if http::HeaderName::from_bytes(k.as_bytes()).is_err()
            || http::HeaderValue::from_str(&v.0).is_err()
        {
            return Err(format!("{at}: header '{k}' has an invalid name or value"));
        }
    }

    let batch_size = c.batch_size.unwrap_or(default_batch);
    let flush_interval_ms = c.flush_interval_ms.unwrap_or(default_flush);
    if batch_size == 0 || flush_interval_ms == 0 || c.timeout_ms == 0 {
        return Err(format!(
            "{at}: batch_size, flush_interval_ms and timeout_ms must be at least 1"
        ));
    }
    let gzip = match c.compression.as_str() {
        "gzip" => true,
        "none" => false,
        o => {
            return Err(format!(
                "{at}: compression '{o}' (use \"gzip\" or \"none\")"
            ))
        }
    };
    if c.concurrency == 0 || c.concurrency > 64 {
        return Err(format!("{at}: concurrency must be between 1 and 64"));
    }
    if c.max_buffer_bytes < (1 << 20) {
        return Err(format!(
            "{at}: max_buffer_bytes must be at least 1048576 (1 MiB)"
        ));
    }

    Ok(CompiledSink {
        name,
        format,
        url,
        headers,
        batch_size,
        flush_interval_ms,
        timeout_ms: c.timeout_ms,
        gzip,
        max_buffer_bytes: c.max_buffer_bytes,
        concurrency: c.concurrency,
        spool_dir: c.spool_dir.clone().filter(|d| !d.trim().is_empty()),
        spool_max_bytes: c.spool_max_bytes,
    })
}

/// Refuse fields that don't apply to this sink type, so a typo or a field
/// meant for another type isn't silently ignored.
fn check_fields(c: &LogSinkConfig, at: &str, own: &[&str]) -> Result<(), String> {
    let set = [
        ("name", c.name.is_some()),
        ("url", c.url.is_some()),
        ("database", c.database.is_some()),
        ("table", c.table.is_some()),
        ("index", c.index.is_some()),
        ("site", c.site.is_some()),
        ("service", c.service.is_some()),
        ("source", c.source.is_some()),
        ("tags", c.tags.is_some()),
        ("sourcetype", c.sourcetype.is_some()),
        ("labels", !c.labels.is_empty()),
        ("resource_attributes", !c.resource_attributes.is_empty()),
        ("tenant_id", c.tenant_id.is_some()),
        ("user", c.user.is_some()),
        ("password", c.password.is_some()),
        ("password_env", c.password_env.is_some()),
        ("api_key", c.api_key.is_some()),
        ("api_key_env", c.api_key_env.is_some()),
        ("token", c.token.is_some()),
        ("token_env", c.token_env.is_some()),
        ("headers", !c.headers.is_empty()),
        ("headers_env", !c.headers_env.is_empty()),
        ("batch_size", c.batch_size.is_some()),
        ("flush_interval_ms", c.flush_interval_ms.is_some()),
        ("timeout_ms", c.timeout_ms != 10_000),
        ("compression", c.compression != "gzip"),
        ("max_buffer_bytes", c.max_buffer_bytes != 256 << 20),
        ("concurrency", c.concurrency != 4),
        ("spool_dir", c.spool_dir.is_some()),
        ("spool_max_bytes", c.spool_max_bytes != 1 << 30),
    ];
    // stdout takes nothing, not even a name.
    let network = c.kind != "stdout";
    for (field, is_set) in set {
        if is_set && !own.contains(&field) && !(network && COMMON.contains(&field)) {
            return Err(format!(
                "{at}: `{field}` doesn't apply to a {} sink",
                c.kind
            ));
        }
    }
    Ok(())
}

/// The value itself, or the env var it names. Setting both is an error.
fn secret(
    value: Option<&str>,
    env: Option<&str>,
    what: &str,
    at: &str,
) -> Result<Option<String>, String> {
    match (value, env) {
        (Some(_), Some(_)) => Err(format!("{at}: set `{what}` or `{what}_env`, not both")),
        (Some(v), None) => Ok(Some(v.to_string())),
        (None, Some(e)) => std::env::var(e)
            .map(Some)
            .map_err(|_| format!("{at}: {what}_env: env var {e} is not set")),
        (None, None) => Ok(None),
    }
}

fn basic_auth(
    c: &LogSinkConfig,
    at: &str,
    headers: &mut Vec<(String, Secret)>,
) -> Result<(), String> {
    use base64::Engine;
    let password = secret(
        c.password.as_deref(),
        c.password_env.as_deref(),
        "password",
        at,
    )?;
    match (&c.user, password) {
        (Some(u), p) => {
            let raw = format!("{u}:{}", p.unwrap_or_default());
            let enc = base64::engine::general_purpose::STANDARD.encode(raw);
            headers.push(("Authorization".into(), Secret(format!("Basic {enc}"))));
            Ok(())
        }
        (None, Some(_)) => Err(format!("{at}: `password` needs `user`")),
        (None, None) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sink(json: serde_json::Value) -> Result<(bool, Vec<CompiledSink>), String> {
        let c: LogSinkConfig = serde_json::from_value(json).unwrap();
        compile_sinks(&[c])
    }

    #[test]
    fn clickhouse_url_and_auth() {
        let (_, s) = sink(serde_json::json!({
            "type": "clickhouse", "url": "http://ch:8123/", "database": "qg",
            "user": "w", "password": "p"
        }))
        .unwrap();
        assert!(s[0]
            .url
            .starts_with("http://ch:8123/?query=INSERT%20INTO%20%60qg%60.%60access_log%60"));
        assert_eq!(s[0].batch_size, 100_000);
        assert!(s[0]
            .headers
            .iter()
            .any(|(k, v)| k == "X-ClickHouse-Key" && v.0 == "p"));
        assert!(
            !format!("{:?}", s[0]).contains("\"p\""),
            "secrets aren't printed"
        );
    }

    #[test]
    fn refuses_fields_of_other_types() {
        let e =
            sink(serde_json::json!({"type": "loki", "url": "http://l", "table": "x"})).unwrap_err();
        assert!(e.contains("`table` doesn't apply to a loki sink"), "{e}");
        let e = sink(serde_json::json!({"type": "stdout", "batch_size": 5})).unwrap_err();
        assert!(e.contains("batch_size"), "{e}");
    }

    #[test]
    fn datadog_needs_a_key_and_caps_batch() {
        assert!(sink(serde_json::json!({"type": "datadog"})).is_err());
        assert!(
            sink(serde_json::json!({"type": "datadog", "api_key": "k", "batch_size": 5000}))
                .is_err()
        );
        let (_, s) =
            sink(serde_json::json!({"type": "datadog", "api_key": "k", "site": "datadoghq.eu"}))
                .unwrap();
        assert_eq!(
            s[0].url,
            "https://http-intake.logs.datadoghq.eu/api/v2/logs"
        );
    }

    #[test]
    fn env_secrets_and_duplicate_names() {
        let e = sink(serde_json::json!({"type": "splunk", "url": "http://s", "token_env": "QG_TEST_UNSET_VAR"}))
            .unwrap_err();
        assert!(e.contains("QG_TEST_UNSET_VAR"), "{e}");
        let a: LogSinkConfig =
            serde_json::from_value(serde_json::json!({"type": "http", "url": "http://a"})).unwrap();
        assert!(compile_sinks(&[a.clone(), a]).is_err());
    }
}
