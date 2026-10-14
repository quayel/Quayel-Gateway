//! Network log sinks: one task per sink on the background runtime.
//!
//! The writer thread formats each batch of events once and hands the same
//! bytes to every sink (`SinkHandle::push`: append under a short lock, no
//! I/O). The sink's task cuts them into batches of `batch_size` lines, encodes
//! them for the destination (`encode.rs`), gzips and POSTs them.
//!
//! - Requests never wait on a sink: a slow or failing destination only grows
//!   this sink's buffer, which is capped at `max_buffer_bytes`.
//! - Failed batches (network error, timeout, 408, 429, 5xx) are retried with
//!   backoff (0.5 s doubling to 30 s), oldest first. A 4xx other than 408/429
//!   means the destination refuses the data: the batch is dropped and counted
//!   rather than retried forever.
//! - Up to `concurrency` batches are in flight at once, so a destination with
//!   long round trips doesn't cap throughput at one batch per round trip.
//! - With a spool, the oldest batches go to disk once memory passes 3/4 of
//!   `max_buffer_bytes` (lower if the writer's hand-overs are big: room for
//!   two of them is always kept), so `push()` doesn't have to drop new
//!   lines. Spooled batches are sent first once the destination answers
//!   again, also after a restart. Without a spool, lines past
//!   `max_buffer_bytes` are dropped, counted and logged.
//! - Every batch has a UUIDv7 ID that survives retries and the spool: it's
//!   ClickHouse's `insert_deduplication_token` and the Elasticsearch document
//!   ID prefix, so a retried batch that had actually landed isn't stored twice.

use crate::config::sinks::{CompiledSink, SinkFormat};
use crate::logging::encode;
use crate::logging::metrics::{registry, SinkStats};
use crate::logging::spool::Spool;
use parking_lot::Mutex;
use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How long a sink without a spool keeps trying to send what's left when it
/// stops (shutdown or config reload).
const STOP_DEADLINE: Duration = Duration::from_secs(3);
/// At most one failure warning per sink per this interval.
const WARN_EVERY: Duration = Duration::from_secs(30);
/// How often an empty spool is re-read for batches another run left.
const RESCAN_EVERY: Duration = Duration::from_secs(30);

/// Lines handed over by the writer thread, not cut into batches yet.
#[derive(Default)]
struct Inbox {
    data: Vec<u8>,
    lines: usize,
    closed: bool,
}

struct Shared {
    inbox: Mutex<Inbox>,
    notify: Notify,
    stats: Arc<SinkStats>,
    /// Lines push() dropped since the task last logged it.
    backstop_dropped: AtomicU64,
    /// Largest single hand-over from the writer, in bytes. The spool keeps
    /// room for two of them so a whole hand-over is never dropped.
    largest_push: AtomicU64,
    /// Set when the task has stopped (everything sent, spooled or counted).
    done: Arc<AtomicBool>,
}

/// The writer thread's end of a sink. Dropping it stops the sink: what's
/// buffered is spooled, or sent within a few seconds without a spool.
pub struct SinkHandle {
    shared: Arc<Shared>,
    batch_size: usize,
    max_buffer_bytes: usize,
}

impl SinkHandle {
    pub fn start(sink: CompiledSink, handle: &tokio::runtime::Handle) -> Self {
        let shared = Arc::new(Shared {
            inbox: Mutex::new(Inbox::default()),
            notify: Notify::new(),
            stats: registry().sink(&sink.name),
            backstop_dropped: AtomicU64::new(0),
            largest_push: AtomicU64::new(0),
            done: Arc::new(AtomicBool::new(false)),
        });
        let h = Self {
            shared: Arc::clone(&shared),
            batch_size: sink.batch_size,
            max_buffer_bytes: sink.max_buffer_bytes,
        };
        info!(
            "Log sink {} ({}) started: batch_size={}, flush_interval_ms={}, concurrency={}, spool={}",
            sink.name,
            sink.format.type_name(),
            sink.batch_size,
            sink.flush_interval_ms,
            sink.concurrency,
            sink.spool_dir.as_deref().unwrap_or("off")
        );
        handle.spawn(Shipper::new(sink, shared).run());
        h
    }

    /// Set once the sink has stopped after this handle was dropped.
    pub fn done_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shared.done)
    }

    /// Hand over whole lines (each ending in '\n'). Never blocks on I/O.
    pub fn push(&self, data: &[u8], lines: usize) {
        if lines == 0 {
            return;
        }
        let stats = &self.shared.stats;
        self.shared
            .largest_push
            .fetch_max(data.len() as u64, Ordering::Relaxed);
        // The task moves batches out of memory (to the spool) well before
        // this; it's the backstop for no spool, or a spool that can't keep up.
        if stats.buffered_bytes.load(Ordering::Relaxed) as usize + data.len()
            > self.max_buffer_bytes
        {
            stats
                .dropped_lines
                .fetch_add(lines as u64, Ordering::Relaxed);
            self.shared
                .backstop_dropped
                .fetch_add(lines as u64, Ordering::Relaxed);
            self.shared.notify.notify_one();
            return;
        }
        let wake = {
            let mut inbox = self.shared.inbox.lock();
            inbox.data.extend_from_slice(data);
            inbox.lines += lines;
            inbox.lines >= self.batch_size
        };
        stats
            .buffered_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        if wake {
            self.shared.notify.notify_one();
        }
    }
}

impl Drop for SinkHandle {
    fn drop(&mut self) {
        self.shared.inbox.lock().closed = true;
        self.shared.notify.notify_one();
    }
}

struct Batch {
    id: String,
    data: Vec<u8>,
    lines: usize,
    /// Read from the spool: removed from there once sent.
    spooled: bool,
}

enum Outcome {
    Sent { rejected: usize },
    Retry(String),
    Refused(String),
}

struct Shipper {
    sink: Arc<CompiledSink>,
    shared: Arc<Shared>,
    client: reqwest::Client,
    /// Cut batches waiting to be sent, oldest first.
    queue: VecDeque<Batch>,
    queue_bytes: usize,
    spool: Option<Spool>,
    /// When the oldest uncut line arrived.
    pending_since: Option<Instant>,
    backoff: Duration,
    retry_at: Option<Instant>,
    last_warn: Option<Instant>,
    failures_since_warn: u64,
    failing: bool,
    last_rescan: Instant,
    /// IDs of spooled batches in flight, so they aren't sent twice.
    inflight_spooled: HashSet<String>,
}

impl Shipper {
    fn new(sink: CompiledSink, shared: Arc<Shared>) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("quayel-gateway/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_millis(sink.timeout_ms))
            .build()
            .unwrap_or_default();
        let spool = sink.spool_dir.as_ref().and_then(|dir| {
            let path = std::path::Path::new(dir).join(&sink.name);
            match Spool::open(&path, sink.spool_max_bytes) {
                Ok(s) => {
                    if !s.is_empty() {
                        info!(
                            "Log sink {}: {} bytes waiting in spool {}",
                            sink.name,
                            s.bytes(),
                            path.display()
                        );
                    }
                    Some(s)
                }
                Err(e) => {
                    error!(
                        "Log sink {}: can't open spool {}: {} (continuing without one)",
                        sink.name,
                        path.display(),
                        e
                    );
                    None
                }
            }
        });
        if let Some(s) = &spool {
            shared.stats.spool_bytes.store(s.bytes(), Ordering::Relaxed);
        }
        Self {
            sink: Arc::new(sink),
            shared,
            client,
            queue: VecDeque::new(),
            queue_bytes: 0,
            spool,
            pending_since: None,
            backoff: BACKOFF_MIN,
            retry_at: None,
            last_warn: None,
            failures_since_warn: 0,
            failing: false,
            last_rescan: Instant::now(),
            inflight_spooled: HashSet::new(),
        }
    }

    async fn run(mut self) {
        let flush = Duration::from_millis(self.sink.flush_interval_ms);
        let tick = (flush / 4).clamp(Duration::from_millis(10), Duration::from_millis(250));
        let mut inflight: JoinSet<(Batch, Outcome)> = JoinSet::new();
        if matches!(self.sink.format, SinkFormat::ClickHouse) {
            let (client, sink) = (self.client.clone(), Arc::clone(&self.sink));
            tokio::spawn(async move { check_clickhouse(&client, &sink).await });
        }
        loop {
            let closed = self.cut(flush);
            self.enforce_limit();
            self.report_backstop();

            if closed {
                while let Some(r) = inflight.join_next().await {
                    self.joined(r);
                }
                self.stop().await;
                self.shared.done.store(true, Ordering::Release);
                return;
            }

            // Fill the free send slots. Cutting and spilling carry on while
            // requests are in flight, so a slow destination fills the spool
            // rather than the memory backstop in push().
            while inflight.len() < self.sink.concurrency
                && self.retry_at.is_none_or(|t| Instant::now() >= t)
            {
                let Some(batch) = self.next_batch() else { break };
                if batch.spooled {
                    self.inflight_spooled.insert(batch.id.clone());
                }
                let client = self.client.clone();
                let sink = Arc::clone(&self.sink);
                inflight.spawn(async move {
                    let o = send(&client, &sink, &batch).await;
                    (batch, o)
                });
            }

            let wait = match self.retry_at {
                Some(t) => t.saturating_duration_since(Instant::now()).min(tick),
                None => tick,
            };
            tokio::select! {
                Some(r) = inflight.join_next(), if !inflight.is_empty() => self.joined(r),
                _ = self.shared.notify.notified() => {}
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    fn joined(&mut self, r: Result<(Batch, Outcome), tokio::task::JoinError>) {
        match r {
            Ok((batch, outcome)) => {
                self.inflight_spooled.remove(&batch.id);
                self.settle(batch, outcome);
            }
            // A send task panicked: its batch is gone. Spooled batches are
            // still on disk and get picked up again by ID.
            Err(e) => {
                self.inflight_spooled.clear();
                error!("Log sink {}: send task failed: {}", self.sink.name, e);
            }
        }
    }

    /// Log lines push() dropped because memory was full.
    fn report_backstop(&mut self) {
        let n = self.shared.backstop_dropped.swap(0, Ordering::Relaxed);
        if n > 0 {
            let hint = if self.spool.is_some() {
                "spool can't keep up"
            } else {
                "set spool_dir or raise concurrency"
            };
            self.warn(&format!(
                "dropped {n} new lines: memory buffer full ({} bytes, {hint})",
                self.sink.max_buffer_bytes
            ));
        }
    }

    /// Move inbox lines into batches when there are `batch_size` of them,
    /// the oldest has waited `flush`, or the sink is stopping. Returns
    /// whether the sink is stopping.
    fn cut(&mut self, flush: Duration) -> bool {
        let (data, lines, closed) = {
            let mut inbox = self.shared.inbox.lock();
            if inbox.lines == 0 {
                self.pending_since = None;
                return inbox.closed;
            }
            let since = *self.pending_since.get_or_insert_with(Instant::now);
            if inbox.lines < self.sink.batch_size && since.elapsed() < flush && !inbox.closed {
                return false;
            }
            let lines = std::mem::take(&mut inbox.lines);
            (std::mem::take(&mut inbox.data), lines, inbox.closed)
        };
        self.pending_since = None;
        // Moving from the inbox to the queue: still in memory, so
        // buffered_bytes doesn't change.
        if lines <= self.sink.batch_size {
            self.enqueue(data, lines);
        } else {
            let mut start = 0;
            let mut n = 0;
            for (i, &b) in data.iter().enumerate() {
                if b == b'\n' {
                    n += 1;
                    if n == self.sink.batch_size {
                        self.enqueue(data[start..=i].to_vec(), n);
                        start = i + 1;
                        n = 0;
                    }
                }
            }
            if n > 0 {
                self.enqueue(data[start..].to_vec(), n);
            }
        }
        closed
    }

    fn enqueue(&mut self, data: Vec<u8>, lines: usize) {
        self.queue_bytes += data.len();
        self.queue.push_back(Batch {
            id: crate::gateway::request_id::generate(),
            data,
            lines,
            spooled: false,
        });
    }

    fn pop_front(&mut self) -> Option<Batch> {
        let b = self.queue.pop_front()?;
        self.queue_bytes -= b.data.len();
        self.shared
            .stats
            .buffered_bytes
            .fetch_sub(b.data.len() as u64, Ordering::Relaxed);
        Some(b)
    }

    fn push_front(&mut self, b: Batch) {
        self.queue_bytes += b.data.len();
        self.shared
            .stats
            .buffered_bytes
            .fetch_add(b.data.len() as u64, Ordering::Relaxed);
        self.queue.push_front(b);
    }

    /// Keep memory under max_buffer_bytes. With a spool, oldest batches go
    /// to disk early enough that push() keeps room for new lines: the larger
    /// of 1/4 of the buffer and two of the biggest hand-overs stays free.
    /// Without one they're dropped past the limit. The newest batch always
    /// stays in memory.
    fn enforce_limit(&mut self) {
        let max = self.sink.max_buffer_bytes;
        let limit = if self.spool.is_some() {
            let largest = self.shared.largest_push.load(Ordering::Relaxed) as usize;
            max.saturating_sub((max / 4).max(largest.saturating_mul(2)))
        } else {
            max
        };
        while self.queue.len() > 1
            && self.shared.stats.buffered_bytes.load(Ordering::Relaxed) as usize > limit
        {
            let Some(b) = self.pop_front() else { break };
            self.spill(b, "memory buffer full");
        }
    }

    fn spill(&mut self, b: Batch, why: &str) {
        let dropped = match self.spool.as_mut() {
            Some(s) => match s.push(&b.id, &b.data, b.lines) {
                Ok(d) => d,
                Err(e) => {
                    error!("Log sink {}: can't write spool: {}", self.sink.name, e);
                    b.lines
                }
            },
            None => b.lines,
        };
        if let Some(s) = &self.spool {
            self.shared
                .stats
                .spool_bytes
                .store(s.bytes(), Ordering::Relaxed);
        }
        if dropped > 0 {
            self.shared
                .stats
                .dropped_lines
                .fetch_add(dropped as u64, Ordering::Relaxed);
            self.warn(&format!("dropped {dropped} lines ({why})"));
        }
    }

    /// Spooled batches first (they're older), then memory.
    fn next_batch(&mut self) -> Option<Batch> {
        if let Some(s) = self.spool.as_mut() {
            if s.is_empty() && self.last_rescan.elapsed() >= RESCAN_EVERY {
                s.rescan();
                self.last_rescan = Instant::now();
            }
            while let Some(e) = s.oldest_except(&self.inflight_spooled) {
                match s.read(&e) {
                    Ok(data) => {
                        return Some(Batch {
                            id: e.id,
                            data,
                            lines: e.lines,
                            spooled: true,
                        })
                    }
                    Err(err) => {
                        // Removed by hand, or unreadable: skip it.
                        warn!(
                            "Log sink {}: skipping spooled batch {}: {}",
                            self.sink.name, e.id, err
                        );
                        s.remove(&e.id);
                    }
                }
            }
        }
        self.pop_front()
    }

    fn settle(&mut self, b: Batch, outcome: Outcome) {
        let stats = Arc::clone(&self.shared.stats);
        match outcome {
            Outcome::Sent { rejected } => {
                stats.requests_ok.fetch_add(1, Ordering::Relaxed);
                stats
                    .sent_lines
                    .fetch_add((b.lines - rejected.min(b.lines)) as u64, Ordering::Relaxed);
                if rejected > 0 {
                    stats
                        .dropped_lines
                        .fetch_add(rejected as u64, Ordering::Relaxed);
                    self.warn(&format!(
                        "destination rejected {rejected} of {} lines",
                        b.lines
                    ));
                }
                self.forget(&b);
                if self.failing {
                    info!(
                        "Log sink {}: delivering again ({} failed requests before this)",
                        self.sink.name,
                        stats.requests_failed.load(Ordering::Relaxed)
                    );
                    self.failing = false;
                }
                self.backoff = BACKOFF_MIN;
                self.retry_at = None;
            }
            Outcome::Refused(msg) => {
                stats.requests_failed.fetch_add(1, Ordering::Relaxed);
                stats
                    .dropped_lines
                    .fetch_add(b.lines as u64, Ordering::Relaxed);
                self.warn(&format!(
                    "destination refused a batch of {} lines: {msg}",
                    b.lines
                ));
                self.forget(&b);
            }
            Outcome::Retry(msg) => {
                stats.requests_failed.fetch_add(1, Ordering::Relaxed);
                self.failing = true;
                self.warn(&format!(
                    "send failed, retrying in {:.1}s: {msg}",
                    self.backoff.as_secs_f64()
                ));
                // Batches in flight together fail together: back off once.
                if self.retry_at.is_none_or(|t| Instant::now() >= t) {
                    self.retry_at = Some(Instant::now() + self.backoff);
                    self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
                }
                if b.spooled {
                    // Still in the spool; retried from there.
                } else if self.spool.is_some() {
                    // On disk now, so a crash during the outage doesn't
                    // lose it. Retried from the spool, oldest first.
                    self.spill(b, "spool full");
                } else {
                    self.push_front(b);
                }
            }
        }
    }

    fn forget(&mut self, b: &Batch) {
        if b.spooled {
            if let Some(s) = self.spool.as_mut() {
                s.remove(&b.id);
                self.shared
                    .stats
                    .spool_bytes
                    .store(s.bytes(), Ordering::Relaxed);
            }
        }
    }

    fn warn(&mut self, msg: &str) {
        self.failures_since_warn += 1;
        if self.last_warn.is_some_and(|t| t.elapsed() < WARN_EVERY) {
            return;
        }
        let more = self.failures_since_warn - 1;
        self.failures_since_warn = 0;
        self.last_warn = Some(Instant::now());
        if more > 0 {
            warn!(
                "Log sink {}: {} (+{} more since last report)",
                self.sink.name, msg, more
            );
        } else {
            warn!("Log sink {}: {}", self.sink.name, msg);
        }
    }

    /// Shutdown or reload. With a spool everything in memory goes there (the
    /// next run, or the sink that replaced this one, sends it). Without one,
    /// keep sending for up to STOP_DEADLINE.
    async fn stop(&mut self) {
        if self.spool.is_some() {
            let n = self.queue.len();
            while let Some(b) = self.pop_front() {
                self.spill(b, "spool full at shutdown");
            }
            info!(
                "Log sink {} stopped ({} batches spooled)",
                self.sink.name, n
            );
            return;
        }
        let deadline = Instant::now() + STOP_DEADLINE;
        while Instant::now() < deadline {
            let Some(b) = self.pop_front() else { break };
            let left = deadline.saturating_duration_since(Instant::now());
            let outcome = match tokio::time::timeout(left, send(&self.client, &self.sink, &b)).await
            {
                Ok(o) => o,
                Err(_) => Outcome::Retry("stop deadline".into()),
            };
            let retry = matches!(outcome, Outcome::Retry(_));
            self.settle(b, outcome);
            if retry {
                tokio::time::sleep(
                    BACKOFF_MIN.min(deadline.saturating_duration_since(Instant::now())),
                )
                .await;
            }
        }
        let mut lost = 0;
        while let Some(b) = self.pop_front() {
            lost += b.lines;
        }
        if lost > 0 {
            self.shared
                .stats
                .dropped_lines
                .fetch_add(lost as u64, Ordering::Relaxed);
            warn!(
                "Log sink {} stopped: {} lines not delivered (set spool_dir to keep them)",
                self.sink.name, lost
            );
        } else {
            info!("Log sink {} stopped", self.sink.name);
        }
    }
}

async fn send(client: &reqwest::Client, sink: &CompiledSink, b: &Batch) -> Outcome {
    let (body, ctype) = encode::encode(&sink.format, &b.data, &b.id);
    let mut url = sink.url.clone();
    if matches!(sink.format, SinkFormat::ClickHouse) {
        url.push_str("&insert_deduplication_token=");
        url.push_str(&b.id);
    }
    let body = if sink.gzip {
        let mut gz = flate2::write::GzEncoder::new(
            Vec::with_capacity(body.len() / 6),
            flate2::Compression::fast(),
        );
        if gz.write_all(&body).is_err() {
            return Outcome::Retry("gzip failed".into());
        }
        match gz.finish() {
            Ok(v) => v,
            Err(e) => return Outcome::Retry(format!("gzip failed: {e}")),
        }
    } else {
        body
    };
    let mut req = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, ctype)
        .body(body);
    if sink.gzip {
        req = req.header(reqwest::header::CONTENT_ENCODING, "gzip");
    }
    for (k, v) in &sink.headers {
        req = req.header(k.as_str(), v.0.as_str());
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return Outcome::Retry(describe(&e)),
    };
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if status.is_success() {
        let rejected = match sink.format {
            SinkFormat::Elasticsearch { .. } => bulk_errors(&text),
            _ => 0,
        };
        return Outcome::Sent { rejected };
    }
    let msg = format!("HTTP {}: {}", status.as_u16(), snippet(&text));
    if status.as_u16() == 408 || status.as_u16() == 429 || status.is_server_error() {
        Outcome::Retry(msg)
    } else {
        Outcome::Refused(msg)
    }
}

/// An empty INSERT on the sink's own URL: checks the address, credentials,
/// database and table without writing a row, so a missing table is a clear
/// error at startup instead of only a drop counter. Lines are still queued
/// either way; an unreachable server is just retried like any outage.
async fn check_clickhouse(client: &reqwest::Client, sink: &CompiledSink) {
    // ClickHouse answers 411 to a POST without Content-Length.
    let mut req = client
        .post(&sink.url)
        .header(reqwest::header::CONTENT_LENGTH, "0")
        .body(Vec::new());
    for (k, v) in &sink.headers {
        req = req.header(k.as_str(), v.0.as_str());
    }
    match req.send().await {
        Ok(r) if r.status().is_success() => {
            info!("Log sink {}: ClickHouse table check ok", sink.name)
        }
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            error!(
                "Log sink {}: ClickHouse refuses inserts (HTTP {}): {} \
                 (create the table with scripts/clickhouse/access_log.sql; \
                 lines are dropped until then)",
                sink.name,
                status,
                snippet(&text)
            );
        }
        Err(e) => warn!(
            "Log sink {}: ClickHouse table check failed: {} (will keep retrying)",
            sink.name,
            describe(&e)
        ),
    }
}

/// reqwest errors print the URL, which can hold the ClickHouse query and
/// tokens; describe them without it.
fn describe(e: &reqwest::Error) -> String {
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connection failed"
    } else {
        "request failed"
    };
    let mut src = std::error::Error::source(e);
    let mut detail = String::new();
    while let Some(s) = src {
        detail = s.to_string();
        src = s.source();
    }
    if detail.is_empty() {
        kind.to_string()
    } else {
        format!("{kind}: {detail}")
    }
}

fn snippet(text: &str) -> String {
    let t = text.trim();
    let mut end = t.len().min(300);
    while !t.is_char_boundary(end) {
        end -= 1;
    }
    t[..end].replace('\n', " ")
}

/// Items an Elasticsearch `_bulk` response reports as failed.
fn bulk_errors(text: &str) -> usize {
    if !text.contains("\"errors\":true") {
        return 0;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return 0;
    };
    v["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|i| {
                    i.as_object()
                        .and_then(|o| o.values().next())
                        .is_some_and(|r| r.get("error").is_some())
                })
                .count()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_bulk_item_errors() {
        let t = r#"{"errors":true,"items":[{"index":{"status":201}},{"index":{"status":400,"error":{"type":"x"}}}]}"#;
        assert_eq!(bulk_errors(t), 1);
        assert_eq!(bulk_errors(r#"{"errors":false,"items":[]}"#), 0);
    }

    #[test]
    fn snippet_cuts_on_char_boundary() {
        let s = "é".repeat(400);
        assert!(snippet(&s).len() <= 300);
    }
}
