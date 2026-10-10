use lru::LruCache;
use parking_lot::RwLock;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use rustc_hash::FxHasher;

// ── Sharded LRU Cache ────────────────────────────────────────────────────────
// A lock-striped LRU cache that reduces contention under high concurrency.
//
// Instead of a single RwLock protecting the entire cache, we split the cache
// into N shards (default 64). Each shard has its own RwLock, so requests for
// different keys rarely contend.
//
// The shard is selected by hashing the key and taking modulo N.
// For IpAddr keys, the hash is very fast (FxHash).

const DEFAULT_NUM_SHARDS: usize = 64;

pub struct ShardedLruCache<K: Eq + Hash + Clone, V: Clone> {
    shards: Vec<RwLock<LruCache<K, V>>>,
    per_shard_cap: NonZeroUsize,
}

impl<K: Eq + Hash + Clone + std::fmt::Debug, V: Clone + std::fmt::Debug> std::fmt::Debug for ShardedLruCache<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardedLruCache")
            .field("num_shards", &self.shards.len())
            .field("per_shard_cap", &self.per_shard_cap)
            .finish()
    }
}

impl<K: Eq + Hash + Clone, V: Clone> ShardedLruCache<K, V> {
    pub fn new(total_capacity: usize) -> Self {
        let num_shards = DEFAULT_NUM_SHARDS;
        let per_shard_cap = NonZeroUsize::new(
            (total_capacity / num_shards).max(1)
        ).unwrap();
        
        let mut shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(RwLock::new(LruCache::new(per_shard_cap)));
        }
        
        Self { shards, per_shard_cap }
    }

    fn shard_index(&self, key: &K) -> usize {
        let mut hasher = FxHasher::default();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }

    /// Get a value from the cache. Uses read lock (shared).
    pub fn get(&self, key: &K) -> Option<V> {
        let idx = self.shard_index(key);
        self.shards[idx].read().peek(key).cloned()
    }

    /// Insert a value into the cache. Uses write lock (exclusive) on one shard.
    pub fn put(&self, key: K, value: V) {
        let idx = self.shard_index(&key);
        self.shards[idx].write().put(key, value);
    }

    /// Clear all shards.
    pub fn clear(&self) {
        for shard in &self.shards {
            shard.write().clear();
        }
    }

    /// Get total capacity.
    pub fn capacity(&self) -> usize {
        self.per_shard_cap.get() * self.shards.len()
    }

    /// Get approximate total length (sum of all shards).
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().len()).sum()
    }
}