use crate::logging::event::LogEvent;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info};

// ── Async Log Queue ──────────────────────────────────────────────────────────
// Non-blocking enqueue via mpsc channel. A background tokio task drains the
// channel and writes events in batches to a JSONL file.
//
// Optimization: Serialization is moved to the background task to avoid
// blocking the request hot path. The LogEvent is sent through the channel
// and serialized directly to the BufWriter using serde_json::to_writer().

#[derive(Debug, Clone)]
pub struct LogQueue {
    tx: mpsc::UnboundedSender<LogEvent>,
}

impl LogQueue {
    /// Create an async log queue that spawns a background writer task.
    ///
    /// * `file_path`   – path to the JSONL log file
    /// * `buffer_size` – flush after this many events accumulate
    /// * `flush_interval_ms` – flush at least this often (timer)
    /// * `handle`      – tokio runtime handle to spawn the task on
    pub fn new(
        file_path: String,
        buffer_size: usize,
        flush_interval_ms: u64,
        handle: tokio::runtime::Handle,
    ) -> Self {
        let path = PathBuf::from(&file_path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                error!("Failed to create log directory {:?}: {}", parent, e);
            }
        }

        let (tx, rx) = mpsc::unbounded_channel::<LogEvent>();

        let _join: JoinHandle<()> = handle.spawn(async move {
            writer_task(rx, path, buffer_size, flush_interval_ms).await;
        });

        info!(
            "Log queue started: file={}, buffer_size={}, flush_interval_ms={}",
            file_path, buffer_size, flush_interval_ms
        );

        Self { tx }
    }

    /// Enqueue a log event. This is non-blocking — the event is sent through
    /// the channel for background serialization. Returns immediately.
    pub fn enqueue(&self, event: LogEvent) {
        // Send is infallible for unbounded channels unless the receiver
        // was dropped (which only happens on shutdown).
        let _ = self.tx.send(event);
    }
}

// ── Background writer task ───────────────────────────────────────────────────

async fn writer_task(
    mut rx: mpsc::UnboundedReceiver<LogEvent>,
    path: PathBuf,
    buffer_size: usize,
    flush_interval_ms: u64,
) {
    // Open the file once and keep it for the lifetime of the task.
    let file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open log file {:?}: {}", path, e);
            return;
        }
    };

    let mut writer = BufWriter::new(file);
    let mut buffer: Vec<LogEvent> = Vec::with_capacity(buffer_size);
    let mut flush_interval =
        tokio::time::interval(std::time::Duration::from_millis(flush_interval_ms));

    // The interval fires immediately on the first tick — skip that.
    flush_interval.tick().await;

    loop {
        tokio::select! {
            // Receive the next LogEvent from the channel
            msg = rx.recv() => {
                match msg {
                    Some(event) => {
                        buffer.push(event);
                        // Flush when the batch is full
                        if buffer.len() >= buffer_size {
                            flush_batch(&mut writer, &mut buffer);
                        }
                    }
                    None => {
                        // Channel closed — drain remaining and exit
                        if !buffer.is_empty() {
                            flush_batch(&mut writer, &mut buffer);
                        }
                        let _ = writer.flush();
                        info!("Log writer shutting down (channel closed)");
                        return;
                    }
                }
            }
            // Timer fired — flush whatever we have
            _ = flush_interval.tick() => {
                if !buffer.is_empty() {
                    flush_batch(&mut writer, &mut buffer);
                }
            }
        }
    }
}

/// Write all buffered events at once using serde_json::to_writer() directly
/// into the BufWriter, avoiding intermediate String allocation.
fn flush_batch(writer: &mut BufWriter<File>, buffer: &mut Vec<LogEvent>) {
    for event in buffer.drain(..) {
        // Serialize directly to writer — no intermediate String allocation
        if serde_json::to_writer(writer.by_ref(), &event).is_err() {
            error!("Failed to serialize log event");
            continue;
        }
        // Write newline separator
        if writeln!(writer).is_err() {
            error!("Failed to write log line");
        }
    }
    if let Err(e) = writer.flush() {
        error!("Failed to flush log file: {}", e);
    }
}