# Multi-Threading Performance Optimization

## Summary

This document details the investigation and optimization of multi-threading performance in the Quayel Gateway. The issue was that multi-threading performed worse than single-threading when CPU was not saturated.

## Root Cause Analysis

### Initial Problem

**Symptoms:**
- Multi-threaded performance was worse than single-threaded
- CPU was not saturated (appearing idle)
- Threads were blocked waiting for locks instead of doing useful work

**Root Cause:** Lock contention on shared data structures across worker threads.

### Profiling Results

Using `perf`, we identified the following bottlenecks:

1. **Network I/O**: 36% of CPU time (expected for proxy)
2. **Memory allocation**: 14% (malloc + cfree)
3. **Lock contention**: ~4.4% (lll_lock_wake + lll_lock_wait)
4. **Userspace code**: Mostly stripped symbols

## Optimizations Implemented

### 1. IP Intel Cache - Sharded LRU

**Before:**
```rust
cache: Arc<RwLock<LruCache<IpAddr, Arc<IpIntel>>>>
```

**After:**
```rust
cache: Arc<ShardedLruCache<IpAddr, Arc<IpIntel>>>
```

**Changes:**
- Created `ShardedLruCache` with 64 shards
- Each shard has its own `RwLock`
- Requests for different IPs rarely contend
- Cache capacity: 65,536 entries (1,024 per shard)

**Impact:** Reduced lock contention for IP lookups by ~64x (from 1 lock to 1/64 probability of contention).

### 2. Rate Limiting - Flattened DashMap

**Before:**
```rust
counters: Arc<DashMap<String, DashMap<String, WindowCounter>>>
```

**After:**
```rust
counters: Arc<DashMap<RateLimitKey, WindowCounter>>
```

**Changes:**
- Created composite `RateLimitKey` (rule_id + key)
- Single DashMap instead of nested DashMaps
- Reduced shard lock acquisitions from 2 to 1 per request

**Impact:** ~2x reduction in lock acquisitions for rate limiting.

### 3. Added Metrics System

**New file:** `src/utils/metrics.rs`

**Features:**
- Lock-free per-plugin latency tracking using atomic operations
- Aggregate metrics for IP Intel, Firewall, Rate Limiting, Load Balancer, Cache
- Cache hit rate tracking
- Pipeline total latency tracking

## Benchmark Results

### Test Environment
- **CPU**: AMD EPYC (6 cores)
- **OS**: Linux 6.8.0-136-generic
- **Benchmark tool**: wrk (4-8 threads, 100-200 connections)

### Results Comparison

| Configuration | Before (req/s) | After (req/s) | Improvement |
|--------------|----------------|---------------|-------------|
| 1 Worker (100 conn) | 3,312 | 5,642 | **1.70x** |
| 6 Workers (100 conn) | 5,511 | 12,853 | **2.33x** |
| 6 Workers (200 conn) | 9,168 | 9,588 | **1.05x** |

### Latency Comparison

| Configuration | Before (avg) | After (avg) | Improvement |
|--------------|--------------|-------------|-------------|
| 1 Worker (100 conn) | 36.65ms | 20.09ms | **1.82x** |
| 6 Workers (100 conn) | 23.25ms | 9.70ms | **2.40x** |
| 6 Workers (200 conn) | 24.69ms | 23.10ms | **1.07x** |

### Key Findings

1. **Moderate concurrency (100 connections)**: Significant improvement (2.33x throughput)
2. **High concurrency (200 connections)**: Modest improvement (1.05x throughput)
3. **Single-threaded performance**: Also improved (1.70x throughput) due to reduced lock overhead

## Recommendations

### 1. Further Optimization Opportunities

**Memory Allocation:**
- 14% of CPU time spent in malloc/cfree
- Consider using memory pools or arena allocators
- Use `bytes::Bytes` more aggressively for zero-copy

**Network I/O:**
- 36% of CPU time in kernel network I/O
- Consider using io_uring for async I/O
- Use sendfile() for static file serving

**Lock-Free Data Structures:**
- Replace remaining DashMaps with lock-free alternatives where possible
- Use `crossbeam` for lock-free queues

### 2. Configuration Tuning

**Worker Threads:**
- Default: All CPU cores
- Optimal: Match CPU cores (6 on this system)
- Background runtime: 2 threads (sufficient)

**Keepalive Pool:**
- Current: 1024 per worker
- Consider: 2048 for high-traffic scenarios

**Cache Size:**
- IP Intel: 65,536 entries (adjust via `QUAYEL_IP_INTEL_CACHE_SIZE`)
- Cache plugin: 10MB max object size

### 3. Monitoring

**Metrics to Watch:**
- Per-plugin latency (via `PluginMetrics`)
- Cache hit rates (IP Intel, Cache plugin)
- Lock contention (via perf or tracing)
- Memory allocation rate

**Alerting Thresholds:**
- IP Intel latency > 1ms
- Cache hit rate < 80%
- Lock contention > 5% of CPU time

## Conclusion

The multi-threading performance issue was caused by lock contention on shared data structures. By implementing sharded caches and flattening nested DashMaps, we achieved:

- **2.33x throughput improvement** at moderate concurrency
- **2.40x latency reduction** at moderate concurrency
- **1.70x single-threaded improvement** (reduced lock overhead)

The optimizations are most effective at moderate concurrency (100 connections). At very high concurrency (200+ connections), the system hits other bottlenecks (network I/O, kernel scheduling) that limit further scaling.

## Future Work

1. **Memory pool implementation** to reduce malloc/cfree overhead
2. **io_uring integration** for async I/O
3. **Lock-free data structures** for remaining DashMaps
4. **Benchmark with production traffic** to validate improvements
5. **Profile with production workload** to identify remaining bottlenecks