use crate::config::compiler::CompiledConfig;
use crate::config::schema::*;
use crate::gateway::request_context::*;
use crate::plugins::firewall::{evaluate_conditions, resolve_condition_value};
use crate::plugins::{GatewayResponse, PluginFlow};
use bytes::Bytes;
use dashmap::DashMap;
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Singleflight coalescing for cache revalidation.
///
/// When a cache entry becomes stale, the first request acquires a per-key lock
/// and goes to origin like a normal cache miss (PluginFlow::Continue).
/// Concurrent requests for the same key see the lock is held and serve stale.
///
/// When the first request completes:
/// 1. `response_body_filter` stores the fresh response in cache
/// 2. The lock guard (stored in RequestContext) is dropped → lock released
/// 3. Subsequent requests see fresh data → cache hit
///
/// No background tasks. No separate HTTP client. The normal proxy flow IS the refresh.
///
/// The refresh request carries the stored validators (If-None-Match /
/// If-Modified-Since). A 304 refreshes the stored copy without a body
/// transfer; a 5xx or connect error inside the stale-if-error window serves
/// the stored copy instead of the error. Both are handled in gateway.rs
/// (response_filter → fail_to_proxy).
#[derive(Debug)]
pub struct CachePlugin {
    pub store: DashMap<String, CacheEntry>,
    pub revalidating: DashMap<String, Arc<Mutex<()>>>,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub status: u16,
    pub headers: Arc<Vec<(String, String)>>,
    pub body: Bytes,
    pub stored_at: Instant,
    pub edge_ttl: Duration,
    pub stale_while_revalidate: Duration,
    pub stale_if_error: Duration,
}

impl CacheEntry {
    pub fn is_fresh(&self) -> bool {
        self.stored_at.elapsed() < self.edge_ttl
    }
    pub fn is_fully_expired(&self) -> bool {
        // Fully expired = past edge_ttl + the longer of the two stale windows.
        // Between the end of SWR and the end of SIE the entry is kept only as
        // an error fallback (CacheLookup::Expired).
        self.stored_at.elapsed()
            >= self.edge_ttl + self.stale_while_revalidate.max(self.stale_if_error)
    }
    pub fn is_stale_if_error(&self) -> bool {
        if self.stale_if_error.is_zero() {
            return false;
        }
        let age = self.stored_at.elapsed();
        age >= self.edge_ttl && age < self.edge_ttl + self.stale_if_error
    }

    /// Check if entry is within the stale-while-revalidate window.
    /// This is where revalidation (lock mechanism) is allowed.
    /// Header value from the stored response (names are stored lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn is_stale_revalidatable(&self) -> bool {
        if self.stale_while_revalidate.is_zero() {
            return false;
        }
        let age = self.stored_at.elapsed();
        age >= self.edge_ttl && age < self.edge_ttl + self.stale_while_revalidate
    }
}

enum CacheLookup {
    Hit(CacheEntry),
    HitRevalidating(CacheEntry),
    Stale(CacheEntry),
    /// Past the SWR window but inside stale-if-error: go to origin like a
    /// miss, keep the entry for a 304 or an error fallback.
    Expired(CacheEntry),
    Miss,
    Bypass,
}

impl CachePlugin {
    pub fn new() -> Self {
        Self {
            store: DashMap::new(),
            revalidating: DashMap::new(),
        }
    }

    pub async fn execute(
        &self,
        ctx: &mut RequestContext,
        config: &Arc<CompiledConfig>,
    ) -> PluginFlow {
        let cache_config = match &config.cache {
            Some(c) if c.enabled => c,
            _ => return PluginFlow::Continue,
        };

        if ctx.method.as_ref() != "GET" && ctx.method.as_ref() != "HEAD" {
            ctx.cache.status = CacheStatus::Bypass;
            return PluginFlow::Continue;
        }
        // HEAD can be served from cache but never fills it (no body to store).
        // Range requests are passed through and not stored either.
        let can_store =
            ctx.method.as_ref() == "GET" && !ctx.headers.contains_key(http::header::RANGE);

        for rule in &cache_config.rules {
            if !rule.enabled {
                continue;
            }

            // Fast-path: empty conditions always match (skip evaluate_conditions overhead)
            let matched = rule.conditions.is_empty() || evaluate_conditions(ctx, &rule.conditions);
            if !matched {
                continue;
            }

            // Reuse the rule_id String allocation across requests (same rule matches
            // every request) — comparison instead of a heap allocation.
            if ctx.cache.rule_id.as_deref() != Some(rule.id.as_ref()) {
                ctx.cache.rule_id = Some(rule.id.to_string());
            }

            if rule.cache == CacheMode::Bypass {
                ctx.cache.status = CacheStatus::Bypass;
                return PluginFlow::Continue;
            }

            // Generate cache key hash directly into the ctx-held String buffer.
            // take() is a pointer swap: the previous request's buffer is reused,
            // so steady-state requests allocate nothing here.
            ctx.cache.encoding = accept_encoding_bucket(&ctx.headers);
            let mut kh = ctx.cache.key_hash.take().unwrap_or_default();
            make_cache_key_hash(ctx, &rule.cache_key, &mut kh);

            {
                ctx.cache.edge_ttl_mode = Some(edge_ttl_mode_str(&rule.edge_ttl.mode));
                ctx.cache.edge_ttl_seconds = rule.edge_ttl.seconds;
                if let Some(bt) = &rule.browser_ttl {
                    ctx.cache.browser_ttl_mode = Some(browser_ttl_mode_str(&bt.mode));
                    ctx.cache.browser_ttl_seconds = bt.seconds;
                }
                ctx.cache.stale_while_revalidate_seconds = rule.stale_while_revalidate;
                ctx.cache.stale_if_error_seconds = rule.stale_if_error;
                // Cache max_object_size_bytes once — avoids arc_swap::load() per body chunk
                ctx.cache.max_object_size_bytes = config
                    .cache
                    .as_ref()
                    .map(|c| c.max_object_size_bytes)
                    .unwrap_or(10 * 1024 * 1024);
                ctx.cache.statuses = Some(Arc::clone(&rule.statuses));
            }

            match self.lookup(&kh) {
                CacheLookup::Hit(entry) => {
                    // Fresh entry — serve cached response.
                    ctx.cache.status = CacheStatus::Hit;
                    ctx.cache.key_hash = Some(kh);
                    return PluginFlow::Respond(GatewayResponse {
                        status: entry.status,
                        headers: entry.headers.clone(),
                        body: entry.body.clone(),
                    });
                }
                CacheLookup::HitRevalidating(entry) => {
                    // Stale entry, but someone else is actively refreshing it.
                    // Serve stale data with Revalidating status.
                    ctx.cache.status = CacheStatus::Revalidating;
                    ctx.cache.key_hash = Some(kh);
                    return PluginFlow::Respond(GatewayResponse {
                        status: entry.status,
                        headers: entry.headers.clone(),
                        body: entry.body.clone(),
                    });
                }
                CacheLookup::Stale(entry) => {
                    // Entry is stale and nobody is refreshing. Try to become the refresh request.
                    let lock_arc = self
                        .revalidating
                        .entry(kh.clone())
                        .or_insert_with(|| Arc::new(Mutex::new(())))
                        .value()
                        .clone();

                    match lock_arc.try_lock_owned() {
                        Ok(guard) => {
                            // We got the lock — this request goes to origin like a normal miss.
                            // The guard lives in ctx — when the request completes, it drops
                            // and releases the lock automatically.
                            ctx.revalidation_guard = Some(RevalidationGuard(guard));
                            ctx.cache.status = CacheStatus::Revalidating;
                            ctx.cache.key_hash = Some(kh);
                            ctx.cache_should_store = can_store;
                            ctx.cache_stale = Some(entry);
                            return PluginFlow::Continue;
                        }
                        Err(_) => {
                            // Race: someone else took the lock between lookup() and here.
                            // Serve stale data.
                            ctx.cache.status = CacheStatus::Stale;
                            ctx.cache.key_hash = Some(kh);
                            return PluginFlow::Respond(GatewayResponse {
                                status: entry.status,
                                headers: entry.headers.clone(),
                                body: entry.body.clone(),
                            });
                        }
                    }
                }
                CacheLookup::Expired(entry) => {
                    ctx.cache.status = CacheStatus::Expired;
                    ctx.cache.key_hash = Some(kh);
                    ctx.cache_should_store = can_store;
                    ctx.cache_stale = Some(entry);
                }
                CacheLookup::Miss => {
                    ctx.cache.status = CacheStatus::Miss;
                    ctx.cache.key_hash = Some(kh);
                    // Signal response_body_filter to capture and store the upstream response
                    ctx.cache_should_store = can_store;
                }
                CacheLookup::Bypass => {
                    ctx.cache.status = CacheStatus::Bypass;
                    ctx.cache.key_hash = Some(kh);
                }
            }
            return PluginFlow::Continue;
        }
        PluginFlow::Continue
    }

    fn lookup(&self, kh: &str) -> CacheLookup {
        let entry = match self.store.get(kh) {
            Some(e) => e.clone(),
            None => return CacheLookup::Miss,
        };

        // Fresh → cache hit
        if entry.is_fresh() {
            return CacheLookup::Hit(entry);
        }

        // Entry is stale (past edge_ttl). Check if it's fully expired first.
        // Fully expired = past edge_ttl + stale_while_revalidate
        if entry.is_fully_expired() {
            // Fully expired — remove from cache, treat as miss.
            drop(entry);
            self.store.remove(kh);
            self.revalidating.remove(kh);
            return CacheLookup::Miss;
        }

        // Past SWR but still inside stale-if-error: origin fetch with fallback.
        if !entry.is_stale_revalidatable() {
            return CacheLookup::Expired(entry);
        }

        // Entry is stale but NOT fully expired (within SWR window).
        // Check if someone is actively revalidating.
        if self.revalidating.contains_key(kh) {
            // Lock held — serve stale with Revalidating status.
            return CacheLookup::HitRevalidating(entry);
        }

        // Stale within SWR window, nobody refreshing — caller can try to take lock
        CacheLookup::Stale(entry)
    }

    pub fn get_stale_if_error(&self, kh: &str) -> Option<CacheEntry> {
        let entry = self.store.get(kh)?.clone();
        if entry.is_fully_expired() {
            return None;
        }
        if entry.is_stale_if_error() {
            return Some(entry);
        }
        None
    }

    pub fn store(
        &self,
        kh: &str,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
        edge_ttl: Duration,
        swr: Duration,
        sie: Duration,
        max_object_size_bytes: usize,
    ) -> bool {
        if body.is_empty() {
            return false;
        }
        if body.len() > max_object_size_bytes {
            return false;
        }
        if headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        {
            return false;
        }
        if let Some(cc) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
        {
            let v = cc.1.to_lowercase();
            if v.contains("no-store") || v.contains("private") {
                return false;
            }
        }
        if edge_ttl.is_zero() {
            return false;
        }
        self.store.insert(
            kh.to_string(),
            CacheEntry {
                status,
                headers: Arc::new(headers.to_vec()),
                body: Bytes::copy_from_slice(body),
                stored_at: Instant::now(),
                edge_ttl,
                stale_while_revalidate: swr,
                stale_if_error: sie,
            },
        );
        true
    }

    /// Replace an entry after a 304: same body, merged headers, new TTLs.
    pub fn store_revalidated(&self, kh: &str, entry: CacheEntry) {
        self.store.insert(kh.to_string(), entry);
    }
}

// CDN Cache-Control Parsing

#[derive(Debug, Clone, Default)]
pub struct CdnCacheControl {
    pub s_maxage: Option<u64>,
    pub max_age: Option<u64>,
    pub stale_while_revalidate: Option<u64>,
    pub stale_if_error: Option<u64>,
    pub no_store: bool,
    pub no_cache: bool,
    pub private: bool,
}

pub fn parse_cdn_cache_control(headers: &[(String, String)]) -> CdnCacheControl {
    let mut cdn = CdnCacheControl::default();
    let mut found_cdn_header = false;

    // Priority 1: CDN-specific header (quayel-cdn-cache-control)
    // This header is set by the CDN layer and has higher priority than cache-control.
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("quayel-cdn-cache-control") {
            parse_cc_value(v, &mut cdn);
            found_cdn_header = true;
            break;
        }
    }

    // Priority 2: Standard cache-control (only if no CDN header found)
    if !found_cdn_header {
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("cache-control") {
                parse_cc_value(v, &mut cdn);
                break;
            }
        }
    }

    cdn
}

/// Parse CDN cache-control directly from the upstream response HeaderMap.
/// Used in `response_filter` for early cacheability rejection — avoids
/// first capturing all headers into a Vec<(String,String)> only to find
/// out the response isn't cacheable.
pub fn parse_upstream_cdn_cache_control(headers: &http::HeaderMap) -> CdnCacheControl {
    let mut cdn = CdnCacheControl::default();

    // Priority 1: CDN-specific header (quayel-cdn-cache-control)
    if let Some(value) = headers
        .get("quayel-cdn-cache-control")
        .and_then(|v| v.to_str().ok())
    {
        parse_cc_value(value, &mut cdn);
        return cdn;
    }

    // Priority 2: Standard cache-control
    if let Some(value) = headers.get("cache-control").and_then(|v| v.to_str().ok()) {
        parse_cc_value(value, &mut cdn);
    }

    cdn
}

fn parse_cc_value(value: &str, cdn: &mut CdnCacheControl) {
    for part in value.split(',') {
        let part = part.trim().to_lowercase();
        if part == "no-store" {
            cdn.no_store = true;
        } else if part == "no-cache" {
            cdn.no_cache = true;
        } else if part == "private" {
            cdn.private = true;
        } else if part == "public" {
        } else if let Some(v) = parse_directive(&part, "s-maxage") {
            cdn.s_maxage = Some(v);
        } else if let Some(v) = parse_directive(&part, "max-age") {
            cdn.max_age = Some(v);
        } else if let Some(v) = parse_directive(&part, "stale-while-revalidate") {
            cdn.stale_while_revalidate = Some(v);
        } else if let Some(v) = parse_directive(&part, "stale-if-error") {
            cdn.stale_if_error = Some(v);
        }
    }
}

pub fn calculate_edge_ttl(cdn: &CdnCacheControl, mode: &str, seconds: Option<u64>) -> Duration {
    if mode == "custom" {
        if let Some(s) = seconds {
            return Duration::from_secs(s);
        }
    }
    if let Some(s) = cdn.s_maxage {
        return Duration::from_secs(s);
    }
    if let Some(s) = cdn.max_age {
        return Duration::from_secs(s);
    }
    if let Some(s) = seconds {
        return Duration::from_secs(s);
    }
    Duration::ZERO
}

pub fn calculate_stale_while_revalidate(cdn: &CdnCacheControl) -> Duration {
    cdn.stale_while_revalidate
        .map(Duration::from_secs)
        .unwrap_or(Duration::ZERO)
}

pub fn calculate_stale_if_error(cdn: &CdnCacheControl) -> Duration {
    cdn.stale_if_error
        .map(Duration::from_secs)
        .unwrap_or(Duration::ZERO)
}

pub fn parse_origin_ttl(headers: &[(String, String)]) -> Option<Duration> {
    let cdn = parse_cdn_cache_control(headers);
    if cdn.no_store || cdn.no_cache || cdn.private {
        return Some(Duration::ZERO);
    }
    if let Some(s) = cdn.s_maxage {
        return Some(Duration::from_secs(s));
    }
    if let Some(s) = cdn.max_age {
        return Some(Duration::from_secs(s));
    }
    None
}

fn parse_directive(value: &str, directive: &str) -> Option<u64> {
    for part in value.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(directive) {
            let rest = rest.trim().strip_prefix('=').unwrap_or("").trim();
            if let Ok(secs) = rest.parse::<u64>() {
                return Some(secs);
            }
        }
    }
    None
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Combined cache key generation + hashing — zero intermediate String allocations.
///
/// Hashes directly from Arc<str> references (scheme, host, path) without
/// creating intermediate Strings. Produces the hex key directly into `out`,
/// reusing its heap buffer across requests on the same connection.
fn make_cache_key_hash(ctx: &mut RequestContext, kc: &CacheKeyConfig, out: &mut String) {
    out.clear();
    let mut hasher = FxHasher::default();

    // Hash directly from Arc<str> references — no String allocation
    ctx.scheme.hash(&mut hasher);
    "|".hash(&mut hasher);
    if let Some(host) = &ctx.host {
        host.hash(&mut hasher);
        "|".hash(&mut hasher);
    }
    ctx.path.hash(&mut hasher);
    "|".hash(&mut hasher);
    ctx.cache.encoding.hash(&mut hasher);

    if kc.mode == CacheKeyMode::Custom {
        if let Some(cp) = &kc.parts {
            for p in cp {
                // Fast path for plain scalar fields — hashes the underlying value
                // directly instead of allocating a serde_json::Value::String.
                match p.as_str() {
                    "req.path" | "http.path" => {
                        "|".hash(&mut hasher);
                        ctx.path.hash(&mut hasher);
                        continue;
                    }
                    "req.host" | "http.host" => {
                        if let Some(h) = &ctx.host {
                            "|".hash(&mut hasher);
                            h.hash(&mut hasher);
                        }
                        continue;
                    }
                    "req.method" | "http.method" => {
                        "|".hash(&mut hasher);
                        ctx.method.hash(&mut hasher);
                        continue;
                    }
                    "req.scheme" | "http.scheme" => {
                        "|".hash(&mut hasher);
                        ctx.scheme.hash(&mut hasher);
                        continue;
                    }
                    "req.ip" | "http.ip" => {
                        "|".hash(&mut hasher);
                        ctx.client_ip.hash(&mut hasher);
                        continue;
                    }
                    "req.peer_ip" | "http.peer_ip" => {
                        "|".hash(&mut hasher);
                        ctx.peer_ip.hash(&mut hasher);
                        continue;
                    }
                    "req.user_agent" | "http.user_agent" => {
                        if let Some(ua) = &ctx.user_agent {
                            "|".hash(&mut hasher);
                            ua.hash(&mut hasher);
                        }
                        continue;
                    }
                    _ => {}
                }
                if let Some(value) = resolve_condition_value(ctx, p) {
                    match value {
                        serde_json::Value::String(s) => {
                            "|".hash(&mut hasher);
                            s.hash(&mut hasher);
                        }
                        serde_json::Value::Number(n) => {
                            "|".hash(&mut hasher);
                            n.to_string().hash(&mut hasher);
                        }
                        serde_json::Value::Bool(b) => {
                            "|".hash(&mut hasher);
                            b.hash(&mut hasher);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Produce hex key directly into `out` — no format!/to_vec allocation
    let hash = hasher.finish();
    out.reserve(16);
    for i in 0..8 {
        let byte = (hash >> (56 - i * 8)) as u8;
        out.push(HEX_CHARS[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
}

/// Collapse Accept-Encoding into the three variants the cache stores.
/// Keeps the number of stored copies per URL at most three, and guarantees a
/// client never receives an encoding it did not ask for.
pub fn accept_encoding_bucket(headers: &http::HeaderMap) -> &'static str {
    let mut gzip = false;
    for value in headers.get_all(http::header::ACCEPT_ENCODING) {
        let Ok(v) = value.to_str() else { continue };
        for part in v.split(',') {
            let mut it = part.split(';');
            let coding = it.next().unwrap_or("").trim();
            let refused = it.any(|p| matches!(p.trim().strip_prefix("q="), Some(q) if q.trim().parse::<f32>().map_or(false, |q| q == 0.0)));
            if refused {
                continue;
            }
            if coding.eq_ignore_ascii_case("br") {
                return "br";
            }
            if coding.eq_ignore_ascii_case("gzip") {
                gzip = true;
            }
        }
    }
    if gzip {
        "gzip"
    } else {
        "identity"
    }
}

/// Accept-Encoding sent to the origin for a bucket (None = remove the header).
pub fn bucket_accept_encoding(bucket: &str) -> Option<&'static str> {
    match bucket {
        "br" => Some("br, gzip"),
        "gzip" => Some("gzip"),
        _ => None,
    }
}

/// True when the response varies only on headers the cache key already covers.
pub fn vary_is_cacheable(headers: &http::HeaderMap) -> bool {
    headers.get_all(http::header::VARY).iter().all(|v| {
        v.to_str().map_or(false, |v| {
            v.split(',')
                .map(str::trim)
                .all(|f| f.is_empty() || f.eq_ignore_ascii_case("accept-encoding"))
        })
    })
}

fn browser_ttl_mode_str(mode: &BrowserTtlMode) -> &'static str {
    match mode {
        BrowserTtlMode::Bypass => "bypass",
        BrowserTtlMode::Origin => "origin",
        BrowserTtlMode::Custom => "custom",
    }
}

fn edge_ttl_mode_str(mode: &EdgeTtlMode) -> &'static str {
    match mode {
        EdgeTtlMode::Origin => "origin",
        EdgeTtlMode::Custom => "custom",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ae(v: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::ACCEPT_ENCODING, v.parse().unwrap());
        h
    }

    #[test]
    fn encoding_buckets() {
        assert_eq!(accept_encoding_bucket(&ae("gzip, deflate, br")), "br");
        assert_eq!(accept_encoding_bucket(&ae("gzip;q=0.5")), "gzip");
        assert_eq!(accept_encoding_bucket(&ae("br;q=0, gzip")), "gzip");
        assert_eq!(accept_encoding_bucket(&ae("deflate")), "identity");
        assert_eq!(accept_encoding_bucket(&http::HeaderMap::new()), "identity");
    }

    #[test]
    fn vary_rules() {
        let mut h = http::HeaderMap::new();
        assert!(vary_is_cacheable(&h));
        h.insert(http::header::VARY, "Accept-Encoding".parse().unwrap());
        assert!(vary_is_cacheable(&h));
        h.insert(
            http::header::VARY,
            "Accept-Encoding, Cookie".parse().unwrap(),
        );
        assert!(!vary_is_cacheable(&h));
        h.insert(http::header::VARY, "*".parse().unwrap());
        assert!(!vary_is_cacheable(&h));
    }

    fn entry(age: u64, ttl: u64, swr: u64, sie: u64) -> CacheEntry {
        CacheEntry {
            status: 200,
            headers: Arc::new(vec![]),
            body: Bytes::from_static(b"x"),
            stored_at: Instant::now() - Duration::from_secs(age),
            edge_ttl: Duration::from_secs(ttl),
            stale_while_revalidate: Duration::from_secs(swr),
            stale_if_error: Duration::from_secs(sie),
        }
    }

    #[test]
    fn lookup_states() {
        let c = CachePlugin::new();
        c.store.insert("fresh".into(), entry(1, 10, 0, 0));
        c.store.insert("swr".into(), entry(15, 10, 10, 0));
        c.store.insert("sie".into(), entry(25, 10, 10, 60));
        c.store.insert("gone".into(), entry(100, 10, 10, 60));
        assert!(matches!(c.lookup("fresh"), CacheLookup::Hit(_)));
        assert!(matches!(c.lookup("swr"), CacheLookup::Stale(_)));
        assert!(matches!(c.lookup("sie"), CacheLookup::Expired(_)));
        assert!(matches!(c.lookup("gone"), CacheLookup::Miss));
        assert!(c.store.get("gone").is_none());
    }
}
