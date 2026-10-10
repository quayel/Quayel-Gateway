use crate::auto_ssl::AutoSslManager;
use crate::config::compiler::CompiledConfig;
use crate::config::schema::ClientIpSource;
use crate::gateway::plugin_runner::PluginRunner;
use crate::gateway::request_context::*;
use crate::logging::event::LogEvent;
use crate::logging::queue::LogQueue;
use crate::plugins::cache::{parse_cdn_cache_control, calculate_edge_ttl, calculate_stale_while_revalidate, calculate_stale_if_error, parse_upstream_cdn_cache_control};
use crate::plugins::{GatewayResponse, PluginFlow};
use arc_swap::ArcSwap;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use std::time::Duration;

// Upstream timeout configuration

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_TOTAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_READ_TIMEOUT: Duration = Duration::from_secs(60);
const UPSTREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct GatewayState {
    pub config: ArcSwap<CompiledConfig>,
    pub plugin_runner: PluginRunner,
    pub log_queue: Option<LogQueue>,
    pub auto_ssl: Option<Arc<AutoSslManager>>,
    pub metrics: Arc<crate::utils::metrics::PluginMetrics>,
}

impl GatewayState {
    pub fn new(config: CompiledConfig, log_queue: Option<LogQueue>, handle: Option<tokio::runtime::Handle>) -> Self {
        let plugin_runner = PluginRunner::new(&config);
        // Spawn background rate limiter cleanup task if handle provided
        if let Some(h) = &handle {
            plugin_runner.rate_limiting.spawn_cleanup_task(h);
        }

        // Initialize Auto-SSL manager if configured
        let auto_ssl = config.auto_ssl.as_ref().map(|ssl_config| {
            Arc::new(AutoSslManager::new(
                &ssl_config.email,
                &ssl_config.domains,
                &ssl_config.cert_storage_path,
                ssl_config.staging,
                ssl_config.renewal_days_before,
            ))
        });

        Self { 
            config: ArcSwap::from_pointee(config), 
            plugin_runner, 
            log_queue, 
            auto_ssl,
            metrics: Arc::new(crate::utils::metrics::PluginMetrics::new()),
        }
    }
}

pub struct QuayelGateway {
    pub state: Arc<GatewayState>,
}

#[cfg_attr(not(doc_async_trait), async_trait::async_trait)]
impl ProxyHttp for QuayelGateway {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        let peer_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        RequestContext::new(
            Arc::from(""), Arc::from(""), Arc::from(""), Arc::from(""),
            peer_ip, peer_ip, Arc::from(""), None,
            Arc::from("/"), Arc::from("GET"), Arc::from("http"), None, http::HeaderMap::new(),
        )
    }

    // request_filter: pipeline + short-circuit response

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> pingora_core::Result<bool> {
        // Check for ACME HTTP-01 challenge requests first
        // This must happen before any other processing
        let path_str = session.req_header().uri.path();
        if let Some(ref auto_ssl) = self.state.auto_ssl {
            if let Some(response) = auto_ssl.get_challenge_response(path_str) {
                // Serve the challenge token
                let mut header = ResponseHeader::build(200, None)?;
                header.insert_header("Content-Type", "text/plain")?;
                header.insert_header("Content-Length", response.len().to_string())?;
                session.write_response_header(Box::new(header), false).await?;
                session.write_response_body(Some(Bytes::from(response)), true).await?;
                return Ok(true); // Short-circuit — don't proxy to upstream
            }
        }

        // Load config once (Guard<Arc> — cheap clone of Arc pointer)
        let config = self.state.config.load();

        // Extract client IP early — needed by all plugins
        let peer_addr = session.client_addr()
            .and_then(|a| a.as_inet())
            .map(|inet| inet.ip())
            .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
        let raw_headers = &session.req_header().headers;
        let client_ip = resolve_client_ip_from_raw(&config, raw_headers, peer_addr);

        // Reuse the RequestContext fields in-place to avoid full struct re-creation.
        // Only update fields that change per-request; keep the default() initialized ones.
        ctx.gateway_id = Arc::clone(&config.gateway_id);
        ctx.gateway_name = Arc::clone(&config.gateway_name);
        ctx.server_name = Arc::clone(&config.server_name);
        ctx.config_version = Arc::clone(&config.config_version);
        ctx.request_id = {
            use std::sync::atomic::Ordering;
            REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed).to_string()
        };
        ctx.started_at = std::time::Instant::now();
        ctx.peer_ip = peer_addr;
        ctx.client_ip = client_ip;
        // Reuse Arc<str> allocations across keep-alive requests: when the value
        // is unchanged (the common case — same client requesting the same URL),
        // this is just a comparison instead of a heap allocation.
        set_arc_str(&mut ctx.client_ip_source, config.client_ip.header.as_deref().unwrap_or("peer_ip"));
        set_opt_arc_str(&mut ctx.host, raw_headers.get("host").and_then(|v| v.to_str().ok()));
        set_arc_str(&mut ctx.path, session.req_header().uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/"));
        set_arc_str(&mut ctx.method, session.req_header().method.as_str());
        set_arc_str(&mut ctx.scheme, resolve_scheme_from_raw(&session.req_header().uri, raw_headers));
        set_opt_arc_str(&mut ctx.user_agent, raw_headers.get("user-agent").and_then(|v| v.to_str().ok()));
        ctx.headers = raw_headers.clone();

        // Reset per-request plugin state (avoid re-allocating new struct)
        ctx.query_cache = None;
        ctx.cookie_cache = None;
        ctx.jwt_cache.clear();
        ctx.ip_intel = None;
        ctx.firewall = FirewallResult::default();
        ctx.rate_limit = RateLimitResult::default();
        ctx.cache = CacheResult::default();
        ctx.load_balancer = LoadBalancerResult::default();
        ctx.upstream_name = None;
        ctx.upstream_target = None;
        ctx.upstream_protocol = None;
        ctx.status_code = None;
        ctx.client_bytes_in = 0;
        ctx.client_bytes_out = 0;
        ctx.upstream_bytes_out = 0;
        ctx.upstream_bytes_in = 0;
        ctx.response_headers_captured = None;
        ctx.response_body_buffer.clear();
        ctx.cache_should_store = false;
        ctx.revalidation_guard = None;
        ctx.ip_intel_latency_us = None;
        ctx.firewall_latency_us = None;
        ctx.rate_limit_latency_us = None;
        ctx.cache_lookup_latency_us = None;
        ctx.lb_latency_us = None;
        ctx.upstream_connect_latency_us = None;
        ctx.upstream_ttfb_us = None;
        ctx.total_latency_us = None;
        ctx.termination_phase = None;

        let flow = self.state.plugin_runner.execute_pipeline(ctx, &config, &self.state.metrics).await;

        match flow {
            PluginFlow::Respond(resp) => {
                send_gateway_response(session, &resp, ctx).await?;
                Ok(true)
            }
            PluginFlow::Continue => Ok(false),
        }
    }

    // upstream_peer: select target from LB result

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> pingora_core::Result<Box<HttpPeer>> {
        let target_host = ctx.load_balancer.target_host.clone().unwrap_or_else(|| Arc::from("127.0.0.1"));
        let target_port = ctx.load_balancer.target_port.unwrap_or(80);
        let target_protocol = ctx.load_balancer.target_protocol.clone().unwrap_or_else(|| Arc::from("http"));
        let tls_verify = ctx.load_balancer.target_tls_verify.unwrap_or(false);
        let tls_sni = ctx.load_balancer.target_tls_sni.clone();

        let peer: Box<HttpPeer> = if target_protocol.eq_ignore_ascii_case("https") {
            let sni = resolve_upstream_sni(&target_host, tls_sni.as_deref(), ctx.host.as_deref());
            let mut peer = HttpPeer::new((target_host.as_ref(), target_port), true, sni);
            peer.options.verify_cert = tls_verify;
            peer.options.connection_timeout = Some(UPSTREAM_CONNECT_TIMEOUT);
            peer.options.total_connection_timeout = Some(UPSTREAM_TOTAL_CONNECT_TIMEOUT);
            peer.options.read_timeout = Some(UPSTREAM_READ_TIMEOUT);
            peer.options.write_timeout = Some(UPSTREAM_WRITE_TIMEOUT);
            peer.options.idle_timeout = Some(UPSTREAM_IDLE_TIMEOUT);
            Box::new(peer)
        } else {
            let mut peer = HttpPeer::new((target_host.as_ref(), target_port), false, String::new());
            peer.options.connection_timeout = Some(UPSTREAM_CONNECT_TIMEOUT);
            peer.options.total_connection_timeout = Some(UPSTREAM_TOTAL_CONNECT_TIMEOUT);
            peer.options.read_timeout = Some(UPSTREAM_READ_TIMEOUT);
            peer.options.write_timeout = Some(UPSTREAM_WRITE_TIMEOUT);
            peer.options.idle_timeout = Some(UPSTREAM_IDLE_TIMEOUT);
            Box::new(peer)
        };
        Ok(peer)
    }

    // upstream_request_filter: set forwarding headers

    async fn upstream_request_filter(&self, _session: &mut Session, upstream_request: &mut pingora_http::RequestHeader, ctx: &mut Self::CTX) -> pingora_core::Result<()> {
        let _ = upstream_request.insert_header("X-Forwarded-Proto", ctx.scheme.as_ref());
        if let Some(host) = ctx.host.as_deref() {
            if !host.is_empty() { let _ = upstream_request.insert_header("X-Forwarded-Host", host); }
        }
        let client_ip = ctx.client_ip.to_string();
        let xff = match upstream_request.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(existing) if !existing.trim().is_empty() => format!("{}, {}", existing.trim(), client_ip),
            _ => client_ip,
        };
        let _ = upstream_request.insert_header("X-Forwarded-For", xff);
        Ok(())
    }

    // response_filter: capture upstream response headers for cache

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        // Only capture upstream response headers when caching is active.
        // This avoids Vec + N header clones (to_lowercase + to_string) on
        // every non-cacheable request (firewall block, rate limit, bypass, etc.)
        if ctx.cache_should_store {
            // ── Early cacheability check ──────────────────────────────────
            // Parse CDN cache-control directly from the upstream HeaderMap to
            // reject non-cacheable responses BEFORE capturing all headers into
            // a Vec.  For /no-cache (origin sends no cache-control → TTL = 0)
            // this saves ~16 String allocations + body buffering per request.
            let cdn_cc = parse_upstream_cdn_cache_control(&upstream_response.headers);

            if cdn_cc.no_store || cdn_cc.no_cache || cdn_cc.private {
                ctx.cache_should_store = false;
            } else {
                let edge_ttl = calculate_edge_ttl(
                    &cdn_cc,
                    ctx.cache.edge_ttl_mode.unwrap_or(""),
                    ctx.cache.edge_ttl_seconds,
                );
                if edge_ttl.is_zero() {
                    ctx.cache_should_store = false;
                }
            }

            // Only capture headers if the response is still cacheable.
            if ctx.cache_should_store {
                let mut headers_vec = Vec::new();
                for (name, value) in upstream_response.headers.iter() {
                    if let Ok(v) = value.to_str() {
                        headers_vec.push((name.as_str().to_lowercase(), v.to_string()));
                    }
                }
                ctx.response_headers_captured = Some(headers_vec);
            }
        }

        upstream_response.insert_header("Quayel-Cache-Status", ctx.cache.status.as_str()).unwrap_or(());
        Ok(())
    }

    // response_body_filter: buffer body + store in cache

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Option<Duration>> {
        // Buffer body chunks only when caching is active.
        // When cache_should_store is false, skip buffering entirely —
        // this avoids memory allocation for non-cacheable responses.
        if ctx.cache_should_store {
            if let Some(chunk) = body {
                // Early size check: stop buffering if we've exceeded max object size.
                // Without this, a 2GB response would allocate 2GB before the
                // end_of_stream check rejects it.
                // Uses cached value from ctx — no arc_swap::load() per chunk.
                let max_size = ctx.cache.max_object_size_bytes;
                if ctx.response_body_buffer.len() + chunk.len() > max_size {
                    ctx.cache_should_store = false; // Too large — don't store
                } else {
                    ctx.response_body_buffer.extend_from_slice(chunk);
                }
            }
        }

        // On last chunk, store in cache
        if end_of_stream && ctx.cache_should_store {
            let rule_id = ctx.cache.rule_id.clone();
            let key_hash = ctx.cache.key_hash.clone();
            let edge_ttl_mode = ctx.cache.edge_ttl_mode.clone().unwrap_or_default();
            let edge_ttl_seconds = ctx.cache.edge_ttl_seconds;

            if let (Some(_rule_id), Some(key_hash)) = (rule_id, key_hash) {
                let headers = ctx.response_headers_captured.clone().unwrap_or_default();
                let body_buf = &ctx.response_body_buffer;

                // Parse Cache-Control headers
                let cdn_cc = parse_cdn_cache_control(&headers);

                // Check if origin says don't cache
                if cdn_cc.no_store || cdn_cc.no_cache || cdn_cc.private {
                    ctx.cache_should_store = false;
                    return Ok(None);
                }

                // Calculate TTLs from CDN cache control headers
                let cdn_edge_ttl = calculate_edge_ttl(&cdn_cc, &edge_ttl_mode, edge_ttl_seconds);

                // SWR/SIE: config overrides origin headers
                let swr_config = ctx.cache.stale_while_revalidate_seconds;
                let sie_config = ctx.cache.stale_if_error_seconds;
                let stale_while_revalidate = swr_config
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| calculate_stale_while_revalidate(&cdn_cc));
                let stale_if_error = sie_config
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| calculate_stale_if_error(&cdn_cc));

                // Edge TTL: if config provides SWR but not edge_ttl, ensure edge_ttl is non-zero
                // Use cdn_edge_ttl as-is; if it's zero and we have SWR, that's a misconfiguration
                let edge_ttl = cdn_edge_ttl;

                let status = ctx.status_code.unwrap_or(200);

                if edge_ttl.is_zero() {
                    ctx.cache_should_store = false;
                    return Ok(None);
                }

                let max_object_size = ctx.cache.max_object_size_bytes;

                self.state.plugin_runner.cache.store(
                    &key_hash,
                    status,
                    &headers,
                    body_buf,
                    edge_ttl,
                    stale_while_revalidate,
                    stale_if_error,
                    max_object_size,
                );

                // Release revalidation lock early — cache is now fresh.
                // The guard drops → lock releases → concurrent requests see fresh data.
                ctx.revalidation_guard = None;
                // Clean up the revalidating map entry for this key.
                self.state.plugin_runner.cache.revalidating.remove(&key_hash);

                ctx.cache_should_store = false;
            }
        }

        Ok(None)
    }

    // logging: SINGLE log point

    async fn logging(&self, _session: &mut Session, _upstream_response: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        // Clean up revalidation state if this request was revalidating
        // but failed to store (origin error, timeout, filtered response).
        // Without this cleanup, revalidating map entries leak →
        // subsequent requests see HitRevalidating and serve stale forever.
        if ctx.revalidation_guard.is_some() {
            if let Some(key_hash) = &ctx.cache.key_hash {
                self.state.plugin_runner.cache.revalidating.remove(key_hash);
            }
            ctx.revalidation_guard = None;
        }

        // Always release LB connection — correctness required even when logging is off.
        // Moved before log_queue check to prevent connection count leak.
        if let (Some(host), Some(port)) = (&ctx.load_balancer.target_host, ctx.load_balancer.target_port) {
            self.state.plugin_runner.load_balancer.release_connection(host, port);
        }

        let queue = match self.state.log_queue {
            Some(ref q) => q,
            None => return,
        };

        ctx.finalize_latency();

        let event = LogEvent::from_context(ctx);
        let _ = queue.enqueue(event);
    }
}

// Send a GatewayResponse via Pingora session

async fn send_gateway_response(
    session: &mut Session,
    resp: &GatewayResponse,
    ctx: &mut RequestContext,
) -> pingora_core::Result<()> {
    ctx.status_code = Some(resp.status);

    let mut header = ResponseHeader::build(resp.status, None)?;
    for (name, value) in resp.headers.iter() {
        let hname = http::header::HeaderName::from_bytes(name.as_bytes())
            .unwrap_or(http::header::HeaderName::from_static("x-quayel"));
        let hval = http::HeaderValue::from_str(value)
            .unwrap_or(http::HeaderValue::from_static(""));
        header.insert_header(hname, hval)?;
    }

    // Always add Quayel-Cache-Status header to every response
    // Short ASCII strings ("HIT", "MISS", etc.) — no heap allocation for <= 14 bytes
    let cache_status = ctx.cache.status.as_str();
    header.insert_header(
        http::header::HeaderName::from_static("quayel-cache-status"),
        http::HeaderValue::from_str(cache_status).unwrap_or(http::HeaderValue::from_static("")),
    )?;

    session.write_response_header(Box::new(header), false).await?;

    if resp.body.is_empty() {
        session.write_response_body(Some(Bytes::new()), true).await?;
    } else {
        session.write_response_body(Some(resp.body.clone()), true).await?;
    }

    Ok(())
}

// Helpers

fn resolve_upstream_sni(target_host: &str, configured: Option<&str>, visitor_host: Option<&str>) -> String {
    if let Some(sni) = configured { let sni = sni.trim(); if !sni.is_empty() { return sni.to_string(); } }
    if target_host.parse::<std::net::IpAddr>().is_ok() {
        if let Some(host) = visitor_host { let host = host.trim(); if !host.is_empty() { return host.split(':').next().unwrap_or(host).to_string(); } }
    }
    target_host.to_string()
}

/// Reuse an existing Arc<str> allocation when the value is unchanged.
/// On keep-alive connections clients repeat the same request target, so this
/// turns a per-request heap allocation into a short string comparison.
#[inline]
fn set_arc_str(slot: &mut Arc<str>, value: &str) {
    if &**slot != value {
        *slot = Arc::from(value);
    }
}

/// Like `set_arc_str`, for optional fields.
#[inline]
fn set_opt_arc_str(slot: &mut Option<Arc<str>>, value: Option<&str>) {
    match (slot.as_deref(), value) {
        (Some(cur), Some(new)) if cur == new => {}
        _ => *slot = value.map(Arc::from),
    }
}

/// Resolve scheme directly from raw HeaderMap — avoids full header extraction.
/// Returns a `&'static str` ("http" / "https" are the only two possible values),
/// so the common case allocates nothing at all.
fn resolve_scheme_from_raw(uri: &http::Uri, headers: &http::HeaderMap) -> &'static str {
    for hdr_name in &["x-forwarded-proto", "x-forwarded-protocol", "x-scheme"] {
        if let Some(value) = headers.get(*hdr_name).and_then(|v| v.to_str().ok()) {
            if let Some(proto) = value.split(',').next() {
                let proto = proto.trim();
                if proto.eq_ignore_ascii_case("http") { return "http"; }
                if proto.eq_ignore_ascii_case("https") { return "https"; }
            }
        }
    }
    if let Some(scheme) = uri.scheme_str() {
        return if scheme.eq_ignore_ascii_case("https") { "https" } else { "http" };
    }
    "http"
}

/// Resolve client IP directly from raw HeaderMap — avoids full header extraction.
fn resolve_client_ip_from_raw(config: &CompiledConfig, headers: &http::HeaderMap, peer_ip: std::net::IpAddr) -> std::net::IpAddr {
    match &config.client_ip.source {
        ClientIpSource::PeerIp => peer_ip,
        ClientIpSource::Header => {
            if let Some(header_name) = &config.client_ip.header {
                if let Some(value) = headers.get(header_name.as_ref()).and_then(|v| v.to_str().ok()) {
                    if let Ok(ip) = value.trim().parse::<std::net::IpAddr>() { return ip; }
                }
            }
            peer_ip
        }
        ClientIpSource::HeaderIndex => {
            if let (Some(header_name), Some(index)) = (&config.client_ip.header, config.client_ip.index) {
                if let Some(value) = headers.get(header_name.as_ref()).and_then(|v| v.to_str().ok()) {
                    // nth() over the split iterator — no Vec allocation per request
                    if let Some(part) = value.split(',').nth(index) {
                        if let Ok(ip) = part.trim().parse::<std::net::IpAddr>() { return ip; }
                    }
                }
            }
            peer_ip
        }
    }
}
