//! On-disk queue of batches a sink couldn't send yet.
//!
//! One file per batch, named `<batch id>-<lines>.jsonl` and holding the raw
//! lines. Batch IDs are UUIDv7, so names sort oldest first. Files are written
//! to `.tmp` and renamed, so a crash never leaves half a batch behind. The
//! batch ID survives restarts, which keeps ClickHouse's dedup token and
//! Elasticsearch's document IDs stable when a spooled batch is retried.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SpoolEntry {
    pub id: String,
    pub lines: usize,
    pub bytes: u64,
}

pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    entries: VecDeque<SpoolEntry>,
    bytes: u64,
}

impl Spool {
    pub fn open(dir: &Path, max_bytes: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut s = Self {
            dir: dir.to_path_buf(),
            max_bytes,
            entries: VecDeque::new(),
            bytes: 0,
        };
        s.rescan();
        Ok(s)
    }

    /// Re-read the directory (picks up batches a previous run, or the sink
    /// this one replaced on reload, left behind).
    pub fn rescan(&mut self) {
        let mut found: Vec<SpoolEntry> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let Some(stem) = name.strip_suffix(".jsonl") else {
                    continue;
                };
                let Some((id, lines)) = stem.rsplit_once('-') else {
                    continue;
                };
                let Ok(lines) = lines.parse::<usize>() else {
                    continue;
                };
                let bytes = e.metadata().map(|m| m.len()).unwrap_or(0);
                found.push(SpoolEntry {
                    id: id.to_string(),
                    lines,
                    bytes,
                });
            }
        }
        found.sort_by(|a, b| a.id.cmp(&b.id));
        self.bytes = found.iter().map(|e| e.bytes).sum();
        self.entries = found.into();
    }

    fn path(&self, id: &str, lines: usize) -> PathBuf {
        self.dir.join(format!("{id}-{lines}.jsonl"))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn oldest(&self) -> Option<SpoolEntry> {
        self.entries.front().cloned()
    }
    /// The oldest entry whose ID isn't in `skip` (batches already in flight).
    pub fn oldest_except(&self, skip: &HashSet<String>) -> Option<SpoolEntry> {
        self.entries.iter().find(|e| !skip.contains(&e.id)).cloned()
    }

    /// Store a batch. Returns how many lines were dropped to stay under
    /// `max_bytes` (oldest batches first, possibly this one).
    pub fn push(&mut self, id: &str, data: &[u8], lines: usize) -> std::io::Result<usize> {
        let final_path = self.path(id, lines);
        let tmp = self.dir.join(format!("{id}.tmp"));
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &final_path)?;
        let entry = SpoolEntry {
            id: id.to_string(),
            lines,
            bytes: data.len() as u64,
        };
        // Keep the queue sorted (an older batch can arrive after a newer one
        // when the in-memory buffer overflows into the spool).
        let pos = self
            .entries
            .iter()
            .position(|e| e.id > entry.id)
            .unwrap_or(self.entries.len());
        self.bytes += entry.bytes;
        self.entries.insert(pos, entry);
        let mut dropped = 0;
        while self.bytes > self.max_bytes {
            let Some(old) = self.entries.pop_front() else {
                break;
            };
            let _ = std::fs::remove_file(self.path(&old.id, old.lines));
            self.bytes -= old.bytes;
            dropped += old.lines;
        }
        Ok(dropped)
    }

    pub fn read(&self, e: &SpoolEntry) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.path(&e.id, e.lines))
    }

    /// Forget and delete batch `id` (sent, or given up on). False when it
    /// isn't in the spool.
    pub fn remove(&mut self, id: &str) -> bool {
        let Some(pos) = self.entries.iter().position(|e| e.id == id) else {
            return false;
        };
        let e = self.entries.remove(pos).expect("position is in range");
        let _ = std::fs::remove_file(self.path(&e.id, e.lines));
        self.bytes -= e.bytes;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_order_caps_size_and_survives_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "qg-spool-{}",
            crate::gateway::request_id::generate()
        ));
        let mut s = Spool::open(&dir, 25).unwrap();
        assert_eq!(s.push("b", b"0123456789", 2).unwrap(), 0);
        assert_eq!(s.push("a", b"0123456789", 3).unwrap(), 0);
        assert_eq!(s.oldest().unwrap().id, "a");
        // Over 25 bytes: the oldest ("a", 3 lines) goes.
        assert_eq!(s.push("c", b"0123456789", 1).unwrap(), 3);
        assert_eq!(s.oldest().unwrap().id, "b");
        let again = Spool::open(&dir, 25).unwrap();
        assert_eq!(again.bytes(), 20);
        assert_eq!(again.oldest().unwrap().lines, 2);
        assert_eq!(again.read(&again.oldest().unwrap()).unwrap(), b"0123456789");
        assert!(s.remove("b"));
        assert!(!s.remove("b"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
