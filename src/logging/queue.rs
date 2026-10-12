use crate::config::compiler::CompiledLogging;
use crate::logging::event::LogEvent;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

// ── Async Log Queue ──────────────────────────────────────────────────────────
// Non-blocking enqueue via a bounded mpsc channel. A background tokio task
// drains the channel and writes events in batches to a JSONL file.
//
// - Bounded: when the writer can't keep up (slow or full disk), new events are
//   dropped and counted instead of growing memory without limit. Logging never
//   slows requests down. The writer reports the count every flush interval.
// - Rotation: the file is reopened when its path no longer points at the open
//   file (logrotate's default move-and-create, `mv`, `rm`), checked every
//   flush interval, or straight away on SIGHUP. `copytruncate` isn't needed.
// - Serialization happens in the background task, straight into the
//   BufWriter with serde_json::to_writer().

#[derive(Debug)]
pub struct LogQueue {
    tx: mpsc::Sender<LogEvent>,
    dropped: Arc<AtomicU64>,
    /// The settings this queue was built from; hot reload compares them.
    pub settings: CompiledLogging,
}

impl LogQueue {
    /// Create the queue and spawn its writer task on `handle`.
    pub fn new(settings: CompiledLogging, handle: &tokio::runtime::Handle) -> Self {
        let path = PathBuf::from(&settings.file_path);
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                error!("Failed to create log directory {:?}: {}", parent, e);
            }
        }

        let (tx, rx) = mpsc::channel::<LogEvent>(settings.queue_size);
        let dropped = Arc::new(AtomicU64::new(0));

        let writer = Writer {
            rx,
            path,
            buffer_size: settings.buffer_size,
            flush_interval_ms: settings.flush_interval_ms,
            dropped: Arc::clone(&dropped),
            open_failed: false,
        };
        handle.spawn(writer.run());

        info!(
            "Access log started: file={}, queue_size={}, buffer_size={}, flush_interval_ms={}",
            settings.file_path,
            settings.queue_size,
            settings.buffer_size,
            settings.flush_interval_ms
        );

        Self {
            tx,
            dropped,
            settings,
        }
    }

    /// Enqueue a log event. Never blocks: when the queue is full the event is
    /// dropped and counted.
    pub fn enqueue(&self, event: LogEvent) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(event) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ── Background writer task ───────────────────────────────────────────────────

struct Writer {
    rx: mpsc::Receiver<LogEvent>,
    path: PathBuf,
    buffer_size: usize,
    flush_interval_ms: u64,
    /// Events the queue refused because it was full.
    dropped: Arc<AtomicU64>,
    /// The last open attempt failed (log the error once, not every retry).
    open_failed: bool,
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
            writer: BufWriter::new(file),
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
    async fn run(mut self) {
        let mut log = self.open();
        let mut buffer: Vec<LogEvent> = Vec::with_capacity(self.buffer_size.min(65_536));
        // Lines lost because the file couldn't be opened or written.
        let mut failed: u64 = 0;

        let mut tick =
            tokio::time::interval(std::time::Duration::from_millis(self.flush_interval_ms));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick fires immediately

        let mut hangup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

        loop {
            tokio::select! {
                msg = self.rx.recv() => match msg {
                    Some(event) => {
                        buffer.push(event);
                        if buffer.len() >= self.buffer_size {
                            failed += self.flush(&mut log, &mut buffer);
                        }
                    }
                    None => {
                        // Every sender is gone: shutdown, or a config reload
                        // replaced this queue. Write what's left and stop.
                        failed += self.flush(&mut log, &mut buffer);
                        self.report(&mut failed);
                        info!("Access log writer stopped: file={}", self.path.display());
                        return;
                    }
                },
                _ = tick.tick() => {
                    failed += self.flush(&mut log, &mut buffer);
                    if log.as_ref().map_or(true, |l| l.is_stale(&self.path)) {
                        log = self.reopen(log);
                    }
                    self.report(&mut failed);
                }
                Some(()) = recv_signal(&mut hangup) => {
                    failed += self.flush(&mut log, &mut buffer);
                    info!("SIGHUP: reopening access log {}", self.path.display());
                    log = self.reopen(log);
                }
            }
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
    fn flush(&self, log: &mut Option<OpenLog>, buffer: &mut Vec<LogEvent>) -> u64 {
        if buffer.is_empty() {
            return 0;
        }
        let Some(l) = log.as_mut() else {
            let n = buffer.len() as u64;
            buffer.clear();
            return n;
        };
        let mut lost = 0;
        for event in buffer.drain(..) {
            let ok = serde_json::to_writer(l.writer.by_ref(), &event).is_ok()
                && l.writer.write_all(b"\n").is_ok();
            if !ok {
                lost += 1;
            }
        }
        if let Err(e) = l.writer.flush() {
            error!("Failed to write access log {}: {}", self.path.display(), e);
        }
        lost
    }

    /// One warning per interval instead of one per event.
    fn report(&self, failed: &mut u64) {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
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

/// Waits for the next SIGHUP, or forever when no handler could be installed.
async fn recv_signal(sig: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    match sig {
        Some(s) => s.recv().await,
        None => std::future::pending().await,
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

    #[test]
    fn full_queue_drops_and_counts_instead_of_growing() {
        let dir = tempdir();
        let path = dir.join("access.jsonl");
        // A current-thread runtime that never runs the writer: nothing drains.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let q = LogQueue::new(settings(&path, 4), rt.handle());
        for i in 0..10 {
            q.enqueue(event(&i.to_string()));
        }
        assert_eq!(q.dropped.load(Ordering::Relaxed), 6);
        drop(q);
        drop(rt);
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
