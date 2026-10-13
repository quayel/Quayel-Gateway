//! Prometheus metrics, built from access-log events on the writer thread.
//!
//! Request threads do nothing extra for metrics: the same `LogEvent` that
//! becomes a log line is counted here, once per drained batch under one lock.
//! A scrape takes the same lock and renders the text format.
//!
//! Label values come from the request (host, upstream ID, rule ID, country),
//! so they're bounded: `host` keeps `metrics.max_hosts` distinct values and
//! counts the rest as `_other`; upstreams, rules and countries are bounded by
//! the config and the IP data.

use crate::logging::event::LogEvent;
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// Histogram bucket bounds, microseconds (rendered as seconds).
const BUCKETS_US: [u64; 13] = [
    1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000,
    5_000_000, 10_000_000,
];
const OTHER_HOST: &str = "_other";
/// Bound for the other label sets, in case a config has a huge number of
/// rules or upstreams.
const MAX_SERIES: usize = 10_000;

#[derive(Default, Clone)]
struct Histogram {
    buckets: [u64; BUCKETS_US.len()],
    count: u64,
    sum_us: u64,
}

impl Histogram {
    fn observe(&mut self, us: u64, n: u64) {
        if let Some(i) = BUCKETS_US.iter().position(|&b| us <= b) {
            self.buckets[i] += n;
        }
        self.count += n;
        self.sum_us += us * n;
    }

    fn render(&self, out: &mut String, name: &str, labels: &str) {
        let sep = if labels.is_empty() { "" } else { "," };
        let mut cum = 0;
        for (i, b) in BUCKETS_US.iter().enumerate() {
            cum += self.buckets[i];
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels}{sep}le=\"{}\"}} {cum}",
                *b as f64 / 1e6
            );
        }
        let _ = writeln!(
            out,
            "{name}_bucket{{{labels}{sep}le=\"+Inf\"}} {}",
            self.count
        );
        let _ = writeln!(out, "{name}_sum{{{labels}}} {}", self.sum_us as f64 / 1e6);
        let _ = writeln!(out, "{name}_count{{{labels}}} {}", self.count);
    }
}

#[derive(Default)]
struct HostStats {
    /// (method, status) → requests
    requests: HashMap<(&'static str, u16), u64>,
    duration: Histogram,
    bytes_out: u64,
    bytes_in: u64,
    /// cache status → requests (NONE not counted)
    cache: HashMap<&'static str, u64>,
}

#[derive(Default)]
struct UpstreamStats {
    /// status → responses (0 = no answer)
    responses: HashMap<u16, u64>,
    duration: Histogram,
}

#[derive(Default)]
struct State {
    max_hosts: usize,
    hosts: HashMap<Arc<str>, HostStats>,
    blocks: HashMap<(&'static str, Arc<str>), u64>,
    upstreams: HashMap<Arc<str>, UpstreamStats>,
    countries: HashMap<String, u64>,
}

/// Delivery counters for one log sink. Shared with its shipper task.
#[derive(Default, Debug)]
pub struct SinkStats {
    /// Lines the destination accepted.
    pub sent_lines: AtomicU64,
    /// Lines given up on: buffer/spool full, refused by the destination.
    pub dropped_lines: AtomicU64,
    pub requests_ok: AtomicU64,
    pub requests_failed: AtomicU64,
    /// Bytes waiting in memory.
    pub buffered_bytes: AtomicU64,
    /// Bytes waiting in the spool directory.
    pub spool_bytes: AtomicU64,
}

pub struct Registry {
    state: Mutex<State>,
    /// Events dropped because the queue was full (not in any other metric).
    pub queue_dropped: AtomicU64,
    /// Lines that couldn't be written to the log file.
    pub file_failed: AtomicU64,
    sinks: Mutex<BTreeMap<String, Arc<SinkStats>>>,
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();

pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| Registry {
        state: Mutex::new(State {
            max_hosts: 1000,
            ..Default::default()
        }),
        queue_dropped: AtomicU64::new(0),
        file_failed: AtomicU64::new(0),
        sinks: Mutex::new(BTreeMap::new()),
    })
}

fn method_label(m: &str) -> &'static str {
    match m {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "OPTIONS" => "OPTIONS",
        "CONNECT" => "CONNECT",
        "TRACE" => "TRACE",
        _ => "OTHER",
    }
}

impl Registry {
    pub fn set_max_hosts(&self, n: usize) {
        self.state.lock().max_hosts = n;
    }

    /// Counters for sink `name`. The same counters are reused when a config
    /// reload restarts the sink, so totals don't reset.
    pub fn sink(&self, name: &str) -> Arc<SinkStats> {
        Arc::clone(self.sinks.lock().entry(name.to_string()).or_default())
    }

    /// Count a batch of events.
    pub fn record(&self, events: &[LogEvent]) {
        if events.is_empty() {
            return;
        }
        let mut s = self.state.lock();
        let s = &mut *s;
        for ev in events {
            let n = ev.sample_rate.max(1) as u64;
            let host: Arc<str> = ev.host.clone().unwrap_or_else(|| Arc::from(""));
            let host = if s.hosts.contains_key(&host) || s.hosts.len() < s.max_hosts {
                host
            } else {
                Arc::from(OTHER_HOST)
            };
            let h = s.hosts.entry(host).or_default();
            *h.requests
                .entry((method_label(&ev.method), ev.status))
                .or_default() += n;
            h.duration.observe(ev.dur_us, n);
            h.bytes_out += ev.bytes * n;
            h.bytes_in += ev.req_bytes * n;
            if ev.cache != "NONE" {
                *h.cache.entry(ev.cache).or_default() += n;
            }

            if !ev.block.kind.is_empty() {
                let rule: Arc<str> = ev.block.rule.clone().unwrap_or_else(|| Arc::from(""));
                let key = (ev.block.kind, rule);
                if s.blocks.contains_key(&key) || s.blocks.len() < MAX_SERIES {
                    *s.blocks.entry(key).or_default() += n;
                }
            }

            if let Some(up) = &ev.upstream {
                if s.upstreams.contains_key(up) || s.upstreams.len() < MAX_SERIES {
                    let u = s.upstreams.entry(Arc::clone(up)).or_default();
                    *u.responses.entry(ev.upstream_status).or_default() += n;
                    u.duration.observe(ev.upstream_us, n);
                }
            }

            let country = ev
                .ip_intel
                .as_deref()
                .and_then(|i| i.country.as_deref())
                .unwrap_or("");
            if let Some(c) = s.countries.get_mut(country) {
                *c += n;
            } else if s.countries.len() < MAX_SERIES {
                s.countries.insert(country.to_string(), n);
            }
        }
    }

    /// Prometheus text format (version 0.0.4).
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(16 * 1024);
        {
            let s = self.state.lock();
            let mut hosts: Vec<_> = s.hosts.iter().collect();
            hosts.sort_by(|a, b| a.0.cmp(b.0));

            header(
                &mut out,
                "qg_http_requests_total",
                "counter",
                "Requests by host, method and status sent to the client.",
            );
            for (host, h) in &hosts {
                let mut rows: Vec<_> = h.requests.iter().collect();
                rows.sort();
                for ((method, code), v) in rows {
                    let _ = writeln!(
                        out,
                        "qg_http_requests_total{{host=\"{}\",method=\"{method}\",code=\"{code}\"}} {v}",
                        esc(host)
                    );
                }
            }
            header(
                &mut out,
                "qg_http_request_duration_seconds",
                "histogram",
                "Time from request arrival to the end of the response.",
            );
            for (host, h) in &hosts {
                h.duration.render(
                    &mut out,
                    "qg_http_request_duration_seconds",
                    &format!("host=\"{}\"", esc(host)),
                );
            }
            header(
                &mut out,
                "qg_http_response_bytes_total",
                "counter",
                "Response body bytes sent to clients.",
            );
            for (host, h) in &hosts {
                let _ = writeln!(
                    out,
                    "qg_http_response_bytes_total{{host=\"{}\"}} {}",
                    esc(host),
                    h.bytes_out
                );
            }
            header(
                &mut out,
                "qg_http_request_bytes_total",
                "counter",
                "Request body bytes read from clients.",
            );
            for (host, h) in &hosts {
                let _ = writeln!(
                    out,
                    "qg_http_request_bytes_total{{host=\"{}\"}} {}",
                    esc(host),
                    h.bytes_in
                );
            }
            header(
                &mut out,
                "qg_cache_requests_total",
                "counter",
                "Requests the cache rule handled, by cache status.",
            );
            for (host, h) in &hosts {
                let mut rows: Vec<_> = h.cache.iter().collect();
                rows.sort();
                for (status, v) in rows {
                    let _ = writeln!(
                        out,
                        "qg_cache_requests_total{{host=\"{}\",cache=\"{status}\"}} {v}",
                        esc(host)
                    );
                }
            }

            header(&mut out, "qg_blocks_total", "counter", "Requests stopped by a firewall rule (fw), rate-limit rule (rl) or DoS protection (dos).");
            let mut blocks: Vec<_> = s.blocks.iter().collect();
            blocks.sort();
            for ((kind, rule), v) in blocks {
                let _ = writeln!(
                    out,
                    "qg_blocks_total{{type=\"{kind}\",rule=\"{}\"}} {v}",
                    esc(rule)
                );
            }

            let mut ups: Vec<_> = s.upstreams.iter().collect();
            ups.sort_by(|a, b| a.0.cmp(b.0));
            header(
                &mut out,
                "qg_upstream_responses_total",
                "counter",
                "Requests sent to each upstream target by the status it answered (0 = no answer).",
            );
            for (up, u) in &ups {
                let mut rows: Vec<_> = u.responses.iter().collect();
                rows.sort();
                for (code, v) in rows {
                    let _ = writeln!(
                        out,
                        "qg_upstream_responses_total{{upstream=\"{}\",code=\"{code}\"}} {v}",
                        esc(up)
                    );
                }
            }
            header(
                &mut out,
                "qg_upstream_duration_seconds",
                "histogram",
                "Time waiting on each upstream target.",
            );
            for (up, u) in &ups {
                u.duration.render(
                    &mut out,
                    "qg_upstream_duration_seconds",
                    &format!("upstream=\"{}\"", esc(up)),
                );
            }

            header(
                &mut out,
                "qg_requests_by_country_total",
                "counter",
                "Requests by client country (\"\" = unknown or IP intel off).",
            );
            let mut countries: Vec<_> = s.countries.iter().collect();
            countries.sort();
            for (c, v) in countries {
                let _ = writeln!(
                    out,
                    "qg_requests_by_country_total{{country=\"{}\"}} {v}",
                    esc(c)
                );
            }
        }

        header(&mut out, "qg_log_queue_dropped_total", "counter", "Events dropped because the event queue was full. They're missing from the logs and from every other metric.");
        let _ = writeln!(
            out,
            "qg_log_queue_dropped_total {}",
            self.queue_dropped.load(Ordering::Relaxed)
        );
        header(
            &mut out,
            "qg_log_file_failed_total",
            "counter",
            "Lines that couldn't be written to the log file.",
        );
        let _ = writeln!(
            out,
            "qg_log_file_failed_total {}",
            self.file_failed.load(Ordering::Relaxed)
        );

        let sinks = self.sinks.lock();
        header(
            &mut out,
            "qg_log_sink_lines_total",
            "counter",
            "Log lines per sink: sent (accepted by the destination) or dropped.",
        );
        for (name, st) in sinks.iter() {
            let _ = writeln!(
                out,
                "qg_log_sink_lines_total{{sink=\"{}\",result=\"sent\"}} {}",
                esc(name),
                st.sent_lines.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "qg_log_sink_lines_total{{sink=\"{}\",result=\"dropped\"}} {}",
                esc(name),
                st.dropped_lines.load(Ordering::Relaxed)
            );
        }
        header(
            &mut out,
            "qg_log_sink_requests_total",
            "counter",
            "Requests to each sink's destination: ok or failed (failed batches are retried).",
        );
        for (name, st) in sinks.iter() {
            let _ = writeln!(
                out,
                "qg_log_sink_requests_total{{sink=\"{}\",result=\"ok\"}} {}",
                esc(name),
                st.requests_ok.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "qg_log_sink_requests_total{{sink=\"{}\",result=\"failed\"}} {}",
                esc(name),
                st.requests_failed.load(Ordering::Relaxed)
            );
        }
        header(
            &mut out,
            "qg_log_sink_buffered_bytes",
            "gauge",
            "Unsent log bytes held in memory per sink.",
        );
        for (name, st) in sinks.iter() {
            let _ = writeln!(
                out,
                "qg_log_sink_buffered_bytes{{sink=\"{}\"}} {}",
                esc(name),
                st.buffered_bytes.load(Ordering::Relaxed)
            );
        }
        header(
            &mut out,
            "qg_log_sink_spool_bytes",
            "gauge",
            "Unsent log bytes in each sink's spool directory.",
        );
        for (name, st) in sinks.iter() {
            let _ = writeln!(
                out,
                "qg_log_sink_spool_bytes{{sink=\"{}\"}} {}",
                esc(name),
                st.spool_bytes.load(Ordering::Relaxed)
            );
        }

        header(&mut out, "qg_build_info", "gauge", "Gateway version.");
        let _ = writeln!(
            out,
            "qg_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        out
    }
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Label value escaping: backslash, double quote and newline.
fn esc(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains(['\\', '"', '\n']) {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n"),
    )
}

// ── Listener ─────────────────────────────────────────────────────────────────

/// Serve `GET <path>` on `listen`. Anything else gets 404. A tiny HTTP/1.1
/// responder: one request per connection, then close.
pub async fn serve(listen: String, path: String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Metrics listener: can't bind {}: {}", listen, e);
            return;
        }
    };
    tracing::info!("Metrics on http://{}{}", listen, path);
    let path: Arc<str> = Arc::from(path);
    loop {
        let Ok((mut conn, _)) = listener.accept().await else {
            continue;
        };
        let path = Arc::clone(&path);
        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(1024);
            let read = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 8192 {
                    match conn.read(&mut chunk).await {
                        Ok(0) | Err(_) => return false,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                true
            })
            .await;
            if !matches!(read, Ok(true)) {
                return;
            }
            let line = buf.split(|&b| b == b'\r').next().unwrap_or_default();
            let mut parts = line.split(|&b| b == b' ');
            let method = parts.next().unwrap_or_default();
            let target = parts.next().unwrap_or_default();
            let target = target.split(|&b| b == b'?').next().unwrap_or_default();
            let (status, ctype, body) =
                if (method == b"GET" || method == b"HEAD") && target == path.as_bytes() {
                    let body = registry().render();
                    (
                        "200 OK",
                        "text/plain; version=0.0.4; charset=utf-8",
                        if method == b"HEAD" {
                            String::new()
                        } else {
                            body
                        },
                    )
                } else {
                    ("404 Not Found", "text/plain", "not found\n".to_string())
                };
            let head = format!(
                "HTTP/1.1 {status}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = conn.write_all(head.as_bytes()).await;
            let _ = conn.write_all(body.as_bytes()).await;
            let _ = conn.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_caps_hosts() {
        let r = Registry {
            state: Mutex::new(State {
                max_hosts: 1,
                ..Default::default()
            }),
            queue_dropped: AtomicU64::new(0),
            file_failed: AtomicU64::new(0),
            sinks: Mutex::new(BTreeMap::new()),
        };
        let c = crate::logging::event::tests::ctx("/p", &[]);
        let mut a = LogEvent::from_context(&c);
        a.host = Some(Arc::from("a.example"));
        a.status = 200;
        a.dur_us = 3_000;
        let mut b = a.clone();
        b.host = Some(Arc::from("b.example"));
        r.record(&[a.clone(), a, b]);
        let text = r.render();
        assert!(
            text.contains(
                "qg_http_requests_total{host=\"a.example\",method=\"GET\",code=\"200\"} 2"
            ),
            "{text}"
        );
        assert!(text.contains("host=\"_other\""), "{text}");
        assert!(
            text.contains(
                "qg_http_request_duration_seconds_bucket{host=\"a.example\",le=\"0.005\"} 2"
            ),
            "{text}"
        );
    }
}
