use std::sync::atomic::{AtomicU64, Ordering};

// ── Aggregate Metrics ────────────────────────────────────────────────────────
// Lock-free per-plugin latency tracking using atomic operations.
// Each plugin records its latency via record_*() methods.
// Query with snapshot() to get current aggregates.

#[derive(Debug)]
pub struct PluginMetrics {
    // IP Intel
    pub ip_intel_total_us: AtomicU64,
    pub ip_intel_count: AtomicU64,
    pub ip_intel_cache_hits: AtomicU64,
    pub ip_intel_cache_misses: AtomicU64,

    // Firewall
    pub firewall_total_us: AtomicU64,
    pub firewall_count: AtomicU64,

    // Rate Limiting
    pub rate_limit_total_us: AtomicU64,
    pub rate_limit_count: AtomicU64,

    // Load Balancer
    pub lb_total_us: AtomicU64,
    pub lb_count: AtomicU64,

    // Cache
    pub cache_total_us: AtomicU64,
    pub cache_count: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,

    // Total pipeline
    pub pipeline_total_us: AtomicU64,
    pub pipeline_count: AtomicU64,

    // Requests
    pub total_requests: AtomicU64,
}

impl PluginMetrics {
    pub fn new() -> Self {
        Self {
            ip_intel_total_us: AtomicU64::new(0),
            ip_intel_count: AtomicU64::new(0),
            ip_intel_cache_hits: AtomicU64::new(0),
            ip_intel_cache_misses: AtomicU64::new(0),
            firewall_total_us: AtomicU64::new(0),
            firewall_count: AtomicU64::new(0),
            rate_limit_total_us: AtomicU64::new(0),
            rate_limit_count: AtomicU64::new(0),
            lb_total_us: AtomicU64::new(0),
            lb_count: AtomicU64::new(0),
            cache_total_us: AtomicU64::new(0),
            cache_count: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            pipeline_total_us: AtomicU64::new(0),
            pipeline_count: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
        }
    }

    pub fn record_ip_intel(&self, latency_us: u64, cache_hit: bool) {
        self.ip_intel_total_us.fetch_add(latency_us, Ordering::Relaxed);
        self.ip_intel_count.fetch_add(1, Ordering::Relaxed);
        if cache_hit {
            self.ip_intel_cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.ip_intel_cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_firewall(&self, latency_us: u64) {
        self.firewall_total_us.fetch_add(latency_us, Ordering::Relaxed);
        self.firewall_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rate_limit(&self, latency_us: u64) {
        self.rate_limit_total_us.fetch_add(latency_us, Ordering::Relaxed);
        self.rate_limit_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_lb(&self, latency_us: u64) {
        self.lb_total_us.fetch_add(latency_us, Ordering::Relaxed);
        self.lb_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache(&self, latency_us: u64, hit: bool) {
        self.cache_total_us.fetch_add(latency_us, Ordering::Relaxed);
        self.cache_count.fetch_add(1, Ordering::Relaxed);
        if hit {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_pipeline(&self, latency_us: u64) {
        self.pipeline_total_us.fetch_add(latency_us, Ordering::Relaxed);
        self.pipeline_count.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            ip_intel_avg_us: avg(&self.ip_intel_total_us, &self.ip_intel_count),
            ip_intel_count: self.ip_intel_count.load(Ordering::Relaxed),
            ip_intel_cache_hit_rate: rate(&self.ip_intel_cache_hits, &self.ip_intel_count),
            firewall_avg_us: avg(&self.firewall_total_us, &self.firewall_count),
            firewall_count: self.firewall_count.load(Ordering::Relaxed),
            rate_limit_avg_us: avg(&self.rate_limit_total_us, &self.rate_limit_count),
            rate_limit_count: self.rate_limit_count.load(Ordering::Relaxed),
            lb_avg_us: avg(&self.lb_total_us, &self.lb_count),
            lb_count: self.lb_count.load(Ordering::Relaxed),
            cache_avg_us: avg(&self.cache_total_us, &self.cache_count),
            cache_count: self.cache_count.load(Ordering::Relaxed),
            cache_hit_rate: rate(&self.cache_hits, &self.cache_count),
            pipeline_avg_us: avg(&self.pipeline_total_us, &self.pipeline_count),
            total_requests: self.total_requests.load(Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        self.ip_intel_total_us.store(0, Ordering::Relaxed);
        self.ip_intel_count.store(0, Ordering::Relaxed);
        self.ip_intel_cache_hits.store(0, Ordering::Relaxed);
        self.ip_intel_cache_misses.store(0, Ordering::Relaxed);
        self.firewall_total_us.store(0, Ordering::Relaxed);
        self.firewall_count.store(0, Ordering::Relaxed);
        self.rate_limit_total_us.store(0, Ordering::Relaxed);
        self.rate_limit_count.store(0, Ordering::Relaxed);
        self.lb_total_us.store(0, Ordering::Relaxed);
        self.lb_count.store(0, Ordering::Relaxed);
        self.cache_total_us.store(0, Ordering::Relaxed);
        self.cache_count.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.pipeline_total_us.store(0, Ordering::Relaxed);
        self.pipeline_count.store(0, Ordering::Relaxed);
        self.total_requests.store(0, Ordering::Relaxed);
    }
}

fn avg(total: &AtomicU64, count: &AtomicU64) -> u64 {
    let t = total.load(Ordering::Relaxed);
    let c = count.load(Ordering::Relaxed);
    if c == 0 { 0 } else { t / c }
}

fn rate(numerator: &AtomicU64, denominator: &AtomicU64) -> f64 {
    let n = numerator.load(Ordering::Relaxed);
    let d = denominator.load(Ordering::Relaxed);
    if d == 0 { 0.0 } else { n as f64 / d as f64 }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub ip_intel_avg_us: u64,
    pub ip_intel_count: u64,
    pub ip_intel_cache_hit_rate: f64,
    pub firewall_avg_us: u64,
    pub firewall_count: u64,
    pub rate_limit_avg_us: u64,
    pub rate_limit_count: u64,
    pub lb_avg_us: u64,
    pub lb_count: u64,
    pub cache_avg_us: u64,
    pub cache_count: u64,
    pub cache_hit_rate: f64,
    pub pipeline_avg_us: u64,
    pub total_requests: u64,
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Plugin Metrics (avg μs) ===")?;
        writeln!(f, "Total requests: {}", self.total_requests)?;
        writeln!(f, "Pipeline avg: {} μs", self.pipeline_avg_us)?;
        writeln!(f, "---")?;
        writeln!(f, "IP Intel:  {} μs ({} calls, {:.1}% cache hit)", 
            self.ip_intel_avg_us, self.ip_intel_count, self.ip_intel_cache_hit_rate * 100.0)?;
        writeln!(f, "Firewall:  {} μs ({} calls)", self.firewall_avg_us, self.firewall_count)?;
        writeln!(f, "Rate Limit:{} μs ({} calls)", self.rate_limit_avg_us, self.rate_limit_count)?;
        writeln!(f, "LB:        {} μs ({} calls)", self.lb_avg_us, self.lb_count)?;
        writeln!(f, "Cache:     {} μs ({} calls, {:.1}% hit rate)", 
            self.cache_avg_us, self.cache_count, self.cache_hit_rate * 100.0)?;
        Ok(())
    }
}