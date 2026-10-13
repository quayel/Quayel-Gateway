use crate::config::compiler::CompiledLogging;
use crate::logging::event::LogEvent;
use crate::logging::writer::LineWriter;
use crossbeam_queue::ArrayQueue;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::Thread;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{error, info, warn};

// ── Async Log Queue ──────────────────────────────────────────────────────────
// Non-blocking enqueue into a bounded lock-free queue. A dedicated OS thread
// drains it and writes events in batches to a JSONL file, so serialization and
// disk writes never occupy a tokio worker (a slow disk can't stall JWKS
// refreshes, Auto-SSL or the other background tasks).
//
// - No wake-up per event: enqueue is one atomic push, with no syscall. The
//   writer wakes on its own every DRAIN_INTERVAL and takes everything queued.
//   (A channel woke the writer through a futex on nearly every request, which
//   cost more request-thread CPU than formatting the line.) Requests only wake
//   the writer early when the queue is half full, so a burst can't overflow it
//   between two drains.
// - Bounded: when the writer can't keep up (slow or full disk), new events are
//   dropped and counted instead of growing memory without limit. Logging never
//   slows requests down. The writer reports the count every flush interval.
// - Rotation: the file is reopened when its path no longer points at the open
//   file (logrotate's default move-and-create, `mv`, `rm`), checked every
//   flush interval, or on SIGHUP (within DRAIN_INTERVAL). `copytruncate` isn't needed.
// - Lines are formatted by `LineWriter` (hand-written JSON, fixed schema) into
//   one reused buffer per batch, then written through a large BufWriter
//   (WRITE_BUFFER bytes), so a batch of thousands of lines costs a handful of
//   write() calls.

/// Size of the file write buffer. Lines are ~600 bytes, so 1 MiB holds
/// ~1,700 lines per write() instead of ~13 with the 8 KiB default.
const WRITE_BUFFER: usize = 1 << 20;

/// How often the writer thread wakes to drain the queue. At 60k events/s
/// that's ~300 events per wake-up; lines sit in the batch for up to
/// flush_interval_ms anyway, so this adds no visible delay.
const DRAIN_INTERVAL: Duration = Duration::from_millis(5);

/// State shared by the request threads and the writer thread.
#[derive(Debug)]
struct Shared {
    queue: ArrayQueue<LogEvent>,
    /// Events the queue refused because it was full.
    dropped: AtomicU64,
    /// Set when the LogQueue is dropped (shutdown or config reload): the
    /// writer drains what's left and stops.
    closed: AtomicBool,
    /// Set by the SIGHUP listener.
    reopen: AtomicBool,
    /// Queue length at which enqueue wakes the writer early.
    wake_at: usize,
}

#[derive(Debug)]
pub struct LogQueue {
    shared: Arc<Shared>,
    /// The writer thread, for early wake-ups. None in tests without a writer.
    writer: Option<Thread>,
    /// Dropped with the queue: stops the SIGHUP listener task.
    _stop: oneshot::Sender<()>,
    /// The settings this queue was built from; hot reload compares them.
    pub settings: CompiledLogging,
}

impl LogQueue {
    /// Create the queue, start its writer thread, and listen for SIGHUP on
    /// `handle`.
    pub fn new(settings: CompiledLogging, handle: &tokio::runtime::Handle) -> Self {
        Self::build(settings, handle, true)
    }

    fn build(settings: CompiledLogging, handle: &tokio::runtime::Handle, start: bool) -> Self {
        let path = PathBuf::from(&settings.file_path);
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                error!("Failed to create log directory {:?}: {}", parent, e);
            }
        }

        let shared = Arc::new(Shared {
            // queue_size >= 1 is enforced by the config compiler.
            queue: ArrayQueue::new(settings.queue_size.max(1)),
            dropped: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            reopen: AtomicBool::new(false),
            wake_at: (settings.queue_size / 2).max(1),
        });
        let (stop_tx, stop_rx) = oneshot::channel::<()>();

        let mut thread = None;
        if start {
            let writer = Writer {
                shared: Arc::clone(&shared),
                path,
                buffer_size: settings.buffer_size,
                flush_interval: Duration::from_millis(settings.flush_interval_ms),
                open_failed: false,
                lines: LineWriter::new(),
                scratch: Vec::with_capacity(WRITE_BUFFER),
            };
            match std::thread::Builder::new()
                .name("qg-access-log".into())
                .spawn(move || writer.run())
            {
                Ok(h) => thread = Some(h.thread().clone()),
                Err(e) => error!("Failed to start access log writer thread: {}", e),
            }
            handle.spawn(listen_for_hangup(Arc::clone(&shared), stop_rx));
        }

        info!(
            "Access log started: file={}, queue_size={}, buffer_size={}, flush_interval_ms={}",
            settings.file_path,
            settings.queue_size,
            settings.buffer_size,
            settings.flush_interval_ms
        );

        Self {
            shared,
            writer: thread,
            _stop: stop_tx,
            settings,
        }
    }

    /// Enqueue a log event. Never blocks: when the queue is full the event is
    /// dropped and counted.
    pub fn enqueue(&self, event: LogEvent) {
        if self.shared.queue.push(event).is_err() {
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        } else if self.shared.queue.len() >= self.shared.wake_at {
            self.wake_writer();
        }
    }

    fn wake_writer(&self) {
        if let Some(t) = &self.writer {
            t.unpark();
        }
    }
}

impl Drop for LogQueue {
    /// Shutdown or config reload: the writer drains what's queued, writes it
    /// and stops. Every push happened before this, so nothing is left behind.
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        self.wake_writer();
    }
}

/// Sets `reopen` on every SIGHUP until the owning queue is dropped.
async fn listen_for_hangup(shared: Arc<Shared>, mut stop: oneshot::Receiver<()>) {
    let Ok(mut hangup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
    else {
        return;
    };
    loop {
        tokio::select! {
            _ = &mut stop => return,
            r = hangup.recv() => match r {
                Some(()) => shared.reopen.store(true, Ordering::Relaxed),
                None => return,
            },
        }
    }
}

// ── Writer thread ────────────────────────────────────────────────────────────

struct Writer {
    shared: Arc<Shared>,
    path: PathBuf,
    buffer_size: usize,
    flush_interval: Duration,
    /// The last open attempt failed (log the error once, not every retry).
    open_failed: bool,
    lines: LineWriter,
    /// Formatted lines of the current batch.
    scratch: Vec<u8>,
}

/// The open log file plus the identity of the file it was opened as.
struct OpenLog {
    writer: BufWriter<File>,
    dev: u64,
    ino: u64,
}

impl OpenLog {
    fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let meta = file.metadata()?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            writer: BufWriter::with_capacity(WRITE_BUFFER, file),
        })
    }

    /// True when `path` no longer names this file (moved, deleted, replaced).
    fn is_stale(&self, path: &Path) -> bool {
        match std::fs::metadata(path) {
            Ok(m) => m.dev() != self.dev || m.ino() != self.ino,
            Err(_) => true,
        }
    }
}

impl Writer {
    fn run(mut self) {
        let mut log = self.open();
        let mut buffer: Vec<LogEvent> = Vec::with_capacity(self.buffer_size.min(65_536));
        // Lines lost because the file couldn't be opened or written.
        let mut failed: u64 = 0;
        let mut next_tick = Instant::now() + self.flush_interval;

        loop {
            // Read before draining: once closed is seen, every event pushed
            // before the LogQueue was dropped is in the queue.
            let closed = self.shared.closed.load(Ordering::Acquire);
            while let Some(event) = self.shared.queue.pop() {
                buffer.push(event);
                if buffer.len() >= self.buffer_size {
                    failed += self.flush(&mut log, &mut buffer);
                }
            }
            if closed {
                // Shutdown, or a config reload replaced this queue. Write
                // what's left and stop.
                failed += self.flush(&mut log, &mut buffer);
                self.report(&mut failed);
                info!("Access log writer stopped: file={}", self.path.display());
                return;
            }

            if self.shared.reopen.swap(false, Ordering::Relaxed) {
                failed += self.flush(&mut log, &mut buffer);
                info!("SIGHUP: reopening access log {}", self.path.display());
                log = self.reopen(log);
            }

            if Instant::now() >= next_tick {
                failed += self.flush(&mut log, &mut buffer);
                if log.as_ref().map_or(true, |l| l.is_stale(&self.path)) {
                    log = self.reopen(log);
                }
                self.report(&mut failed);
                next_tick = Instant::now() + self.flush_interval;
            }

            // Nothing wakes this thread per event: enqueue only unparks it
            // when the queue is half full, and Drop unparks it to stop.
            std::thread::park_timeout(DRAIN_INTERVAL);
        }
    }

    fn open(&mut self) -> Option<OpenLog> {
        match OpenLog::open(&self.path) {
            Ok(l) => {
                if std::mem::take(&mut self.open_failed) {
                    info!("Access log opened: {}", self.path.display());
                }
                Some(l)
            }
            Err(e) => {
                if !std::mem::replace(&mut self.open_failed, true) {
                    error!(
                        "Failed to open access log {}: {} (retrying every flush interval; \
                         events are dropped until it opens)",
                        self.path.display(),
                        e
                    );
                }
                None
            }
        }
    }

    fn reopen(&mut self, old: Option<OpenLog>) -> Option<OpenLog> {
        let had_file = old.is_some();
        drop(old);
        let new = self.open();
        if new.is_some() && had_file {
            info!("Access log reopened: {}", self.path.display());
        }
        new
    }

    /// Write and flush the batch. Returns how many events were lost.
    fn flush(&mut self, log: &mut Option<OpenLog>, buffer: &mut Vec<LogEvent>) -> u64 {
        if buffer.is_empty() {
            return 0;
        }
        let n = buffer.len() as u64;
        let Some(l) = log.as_mut() else {
            buffer.clear();
            return n;
        };
        self.scratch.clear();
        for event in buffer.drain(..) {
            self.lines.write(&mut self.scratch, &event);
        }
        let result = l
            .writer
            .write_all(&self.scratch)
            .and_then(|_| l.writer.flush());
        // Don't keep a huge buffer around after one unusually large batch.
        if self.scratch.capacity() > 4 * WRITE_BUFFER {
            self.scratch = Vec::with_capacity(WRITE_BUFFER);
        }
        match result {
            Ok(()) => 0,
            Err(e) => {
                error!("Failed to write access log {}: {}", self.path.display(), e);
                n
            }
        }
    }

    /// One warning per interval instead of one per event.
    fn report(&self, failed: &mut u64) {
        let dropped = self.shared.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            warn!(
                dropped,
                "Access log queue full: dropped {} events (disk too slow? raise logging.queue_size)",
                dropped
            );
        }
        if *failed > 0 {
            warn!(
                failed = *failed,
                "Access log: {} events could not be written to {}",
                *failed,
                self.path.display()
            );
            *failed = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(path: &Path, queue_size: usize) -> CompiledLogging {
        CompiledLogging {
            mode: "file".into(),
            file_path: path.to_string_lossy().into_owned(),
            queue_size,
            buffer_size: 1,
            flush_interval_ms: 50,
            user_field: None,
        }
    }

    fn event(id: &str) -> LogEvent {
        let mut c = crate::logging::event::tests::ctx("/p", &[]);
        c.request_id = id.to_string();
        LogEvent::from_context(&c)
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    async fn wait_for(path: &Path, n: usize) -> Vec<String> {
        for _ in 0..100 {
            let l = lines(path);
            if l.len() >= n {
                return l;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        lines(path)
    }

    #[tokio::test]
    async fn full_queue_drops_and_counts_instead_of_growing() {
        let dir = tempdir();
        let path = dir.join("access.jsonl");
        // No writer thread: nothing drains the queue.
        let q = LogQueue::build(
            settings(&path, 4),
            &tokio::runtime::Handle::current(),
            false,
        );
        for i in 0..10 {
            q.enqueue(event(&i.to_string()));
        }
        assert_eq!(q.shared.dropped.load(Ordering::Relaxed), 6);
    }

    #[tokio::test]
    async fn writes_every_event_in_order_with_large_batches() {
        let dir = tempdir();
        let path = dir.join("access.jsonl");
        let mut s = settings(&path, 10_000);
        s.buffer_size = 4096;
        s.flush_interval_ms = 1000;
        let q = LogQueue::new(s, &tokio::runtime::Handle::current());
        for i in 0..5000 {
            q.enqueue(event(&format!("e{i}")));
        }
        // Dropping the queue disconnects the writer, which flushes the rest.
        drop(q);
        let l = wait_for(&path, 5000).await;
        assert_eq!(l.len(), 5000);
        assert!(l[0].contains("\"e0\""));
        assert!(l[4999].contains("\"e4999\""));
    }

    #[tokio::test]
    async fn reopens_after_the_file_is_moved() {
        let dir = tempdir();
        let path = dir.join("access.jsonl");
        let rotated = dir.join("access.jsonl.1");
        let q = LogQueue::new(settings(&path, 64), &tokio::runtime::Handle::current());

        q.enqueue(event("before"));
        assert_eq!(wait_for(&path, 1).await.len(), 1);

        std::fs::rename(&path, &rotated).unwrap();
        // Give the writer a flush interval to notice the move.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        q.enqueue(event("after"));

        let new = wait_for(&path, 1).await;
        assert_eq!(new.len(), 1, "new file gets the next event");
        assert!(new[0].contains("\"after\""));
        let old = lines(&rotated);
        assert_eq!(old.len(), 1);
        assert!(old[0].contains("\"before\""));
    }

    #[tokio::test]
    async fn retries_when_the_directory_appears_later() {
        let dir = tempdir();
        let sub = dir.join("later");
        let path = sub.join("access.jsonl");
        let q = LogQueue::new(settings(&path, 64), &tokio::runtime::Handle::current());
        std::fs::remove_dir_all(&sub).unwrap(); // LogQueue::new created it
        q.enqueue(event("lost"));
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        std::fs::create_dir_all(&sub).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        q.enqueue(event("kept"));
        let l = wait_for(&path, 1).await;
        assert_eq!(l.len(), 1);
        assert!(l[0].contains("\"kept\""));
    }

    fn tempdir() -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("qg-log-{}", crate::gateway::request_id::generate()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
