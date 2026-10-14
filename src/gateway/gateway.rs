use crate::auto_ssl::AutoSslManager;
use crate::config::compiler::CompiledConfig;
use crate::config::schema::ClientIpSource;
use crate::gateway::conn_guard::header_guard;
use crate::gateway::plugin_runner::PluginRunner;
use crate::gateway::protection::{IpTracker, Violation};
use crate::gateway::request_context::*;
use crate::gateway::request_id;
use crate::logging::event::LogEvent;
use crate::logging::queue::LogQueue;
use crate::logging::writer::strip_queries;
use crate::plugins::cache::{
    bucket_accept_encoding, calculate_edge_ttl, calculate_stale_if_error,
    calculate_stale_while_revalidate, parse_cdn_cache_control, parse_upstream_cdn_cache_control,
    vary_is_cacheable, CacheEntry,
};
use crate::plugins::firewall::resolve_condition_value;
use crate::plugins::transform::{
    apply_response_transform, replay_request_header_edits, CompiledTransform,
};
use crate::plugins::{GatewayResponse, PluginFlow};
use arc_swap::{ArcSwap, ArcSwapOption};
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::FailToProxy;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use std::time::Duration;

pub struct GatewayState {
    pub config: ArcSwap<CompiledConfig>,
    pub plugin_runner: PluginRunner,
    /// None when logging is off. Swapped on config reload when the logging
    /// settings change; the old writer finishes its queue and stops.
    pub log_queue: ArcSwapOption<LogQueue>,
    pub auto_ssl: Option<Arc<AutoSslManager>>,
    pub metrics: Arc<crate::utils::metrics::PluginMetrics>,
    /// Per-IP connection/request counters and bans (server.protection).
    pub ip_tracker: Arc<IpTracker>,
}

impl GatewayState {
    pub fn new(
        config: CompiledConfig,
        log_queue: Option<LogQueue>,
        handle: Option<tokio::runtime::Handle>,
    ) -> Self {
        let plugin_runner = PluginRunner::new(&config);
        // Spawn background rate limiter cleanup task if handle provided
        if let Some(h) = &handle {
            plugin_runner.rate_limiting.spawn_cleanup_task(h);
        }

        // Initialize Auto-SSL manager if configured
        let auto_ssl = config.auto_ssl.as_ref().map(|ssl_config| {
            let manager = Arc::new(AutoSslManager::new(ssl_config));
            // Give it the background runtime handle so the sync SNI callback can
            // spawn ACME workers (it runs on a tokio worker and cannot block/spawn
            // on its own runtime).
            if let Some(h) = &handle {
                manager.set_bg_handle(h.clone());
            }
            manager
        });

        let ip_tracker = IpTracker::new();
        if let Some(h) = &handle {
            ip_tracker.spawn_cleanup_task(h);
        }

        Self {
            config: ArcSwap::from_pointee(config),
            plugin_runner,
            log_queue: ArcSwapOption::from(log_queue.map(Arc::new)),
            auto_ssl,
            metrics: Arc::new(crate::utils::metrics::PluginMetrics::new()),
            ip_tracker,
        }
    }
}

impl GatewayState {
    /// Apply new logging settings after a config reload. Unchanged settings
    /// keep the running writer.
    pub fn reload_logging(
        &self,
        settings: Option<&crate::config::compiler::CompiledLogging>,
        handle: &tokio::runtime::Handle,
    ) {
        let current = self.log_queue.load();
        if current.as_deref().map(|q| &q.settings) == settings {
            return;
        }
        let next = settings.map(|s| Arc::new(LogQueue::new(s.clone(), handle)));
        if next.is_none() {
            tracing::info!("Access log disabled by config reload");
        }
        self.log_queue.store(next);
    }
}

pub struct QuayelGateway {
    pub state: Arc<GatewayState>,
}

impl QuayelGateway {
    /// Origin answered the conditional request with 304: merge its headers
    /// into the stored copy, restart the TTL and store it again. Returns the
    /// entry to serve.
    fn refresh_after_304(
        &self,
        ctx: &RequestContext,
        stale: &CacheEntry,
        not_modified: &ResponseHeader,
    ) -> CacheEntry {
        // RFC 9111 §4.3.4: headers in the 304 replace the stored ones, except
        // those describing the body/framing.
        const KEEP_STORED: &[&str] = &[
            "content-length",
            "content-encoding",
            "content-type",
            "content-range",
            "transfer-encoding",
            "connection",
            "keep-alive",
        ];
        let mut headers: Vec<(String, String)> = stale
            .headers
            .iter()
            .filter(|(k, _)| {
                KEEP_STORED.contains(&k.as_str()) || !not_modified.headers.contains_key(k.as_str())
            })
            .cloned()
            .collect();
        for (name, value) in not_modified.headers.iter() {
            if KEEP_STORED.contains(&name.as_str()) {
                continue;
            }
            if let Ok(v) = value.to_str() {
                headers.push((name.as_str().to_string(), v.to_string()));
            }
        }

        let mut entry = CacheEntry {
            status: stale.status,
            headers: Arc::new(headers),
            body: stale.body.clone(),
            stored_at: std::time::Instant::now(),
            edge_ttl: stale.edge_ttl,
            stale_while_revalidate: stale.stale_while_revalidate,
            stale_if_error: stale.stale_if_error,
        };
        if let Some(key_hash) = &ctx.cache.key_hash {
            match cache_ttls(&ctx.cache, &entry.headers) {
                Some((edge, swr, sie)) => {
                    entry.edge_ttl = edge;
                    entry.stale_while_revalidate = swr;
                    entry.stale_if_error = sie;
                    self.state
                        .plugin_runner
                        .cache
                        .store_revalidated(key_hash, entry.clone());
                }
                // Origin no longer allows caching: serve this once, then drop it.
                None => {
                    self.state.plugin_runner.cache.store.remove(key_hash);
                }
            }
        }
        entry
    }
}

/// Error used by response_filter to hand the response over to fail_to_proxy.
fn serve_from_cache_error() -> Box<pingora_error::Error> {
    pingora_error::Error::explain(
        pingora_error::ErrorType::Custom("serve_from_cache"),
        "origin answer replaced by stored copy",
    )
}

/// Edge TTL, stale-while-revalidate and stale-if-error for a response, or
/// None when it must not be stored. Rule settings override origin headers.
fn cache_ttls(
    cache: &CacheResult,
    headers: &[(String, String)],
) -> Option<(Duration, Duration, Duration)> {
    let cdn_cc = parse_cdn_cache_control(headers);
    if cdn_cc.no_store || cdn_cc.no_cache || cdn_cc.private {
        return None;
    }
    let edge_ttl = calculate_edge_ttl(
        &cdn_cc,
        cache.edge_ttl_mode.unwrap_or(""),
        cache.edge_ttl_seconds,
    );
    if edge_ttl.is_zero() {
        return None;
    }
    let swr = cache
        .stale_while_revalidate_seconds
        .map(Duration::from_secs)
        .unwrap_or_else(|| calculate_stale_while_revalidate(&cdn_cc));
    let sie = cache
        .stale_if_error_seconds
        .map(Duration::from_secs)
        .unwrap_or_else(|| calculate_stale_if_error(&cdn_cc));
    Some((edge_ttl, swr, sie))
}

#[cfg_attr(not(doc_async_trait), async_trait::async_trait)]
impl ProxyHttp for QuayelGateway {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        let peer_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        RequestContext::new(
            Arc::from(""),
            Arc::from(""),
            Arc::from(""),
            Arc::from(""),
            peer_ip,
            peer_ip,
            Arc::from(""),
            None,
            Arc::from("/"),
            Arc::from("GET"),
            Arc::from("http"),
            None,
            http::HeaderMap::new(),
        )
    }

    // early_request_filter: header is parsed — request ID, then server.timeouts

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        // First thing for every request, before ACME, protection and the
        // plugins, so every response and log line has an ID. ts_ms is also the
        // time part of a generated UUIDv7.
        let config = self.state.config.load();
        ctx.ts_ms = request_id::now_ms();
        ctx.started_at = std::time::Instant::now();
        ctx.request_id = request_id::resolve(
            &session.req_header().headers,
            config.server.accept_incoming_request_id,
            ctx.ts_ms,
        );

        if let Some(guard) = header_guard(session) {
            guard.headers_done();
        }
        let server = &config.server;
        session.set_keepalive(server.keepalive_secs);
        // After a 101 the request "body" is the WebSocket client stream, read
        // with the same timeout, so it gets the idle limit instead.
        ctx.upgrade = session.is_upgrade_req();
        // gRPC streams can stay open and quiet for a long time, like a WebSocket.
        ctx.grpc = is_grpc(session.req_header());
        session.set_read_timeout(if ctx.upgrade || ctx.grpc {
            server.websocket_idle_timeout
        } else {
            server.body_read_timeout
        });
        session.set_write_timeout(server.response_write_timeout);
        Ok(())
    }

    // request_filter: pipeline + short-circuit response

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        // Check for ACME HTTP-01 challenge requests first
        // This must happen before any other processing
        let path_str = session.req_header().uri.path();
        if let Some(ref auto_ssl) = self.state.auto_ssl {
            if let Some(response) = auto_ssl.get_challenge_response(path_str) {
                // Serve the challenge token
                let mut header = ResponseHeader::build(200, None)?;
                header.insert_header("Content-Type", "text/plain")?;
                header.insert_header("Content-Length", response.len().to_string())?;
                insert_request_id(
                    header.insert_header(request_id::HEADER, ctx.request_id.as_str()),
                );
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(Bytes::from(response)), true)
                    .await?;
                return Ok(true); // Short-circuit — don't proxy to upstream
            }
        }

        // Trigger on-demand Auto-SSL provisioning for the request's host
        // (fire-and-forget, dedup-guarded). For HTTPS this normally already fired
        // at handshake time via the SNI resolver; this also covers plain-HTTP
        // requests and clients that omit SNI.
        if let Some(ref auto_ssl) = self.state.auto_ssl {
            let host = session
                .req_header()
                .uri
                .host()
                .map(|h| h.to_string())
                .or_else(|| {
                    session
                        .req_header()
                        .headers
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .map(|h| h.to_string())
                })
                .map(|h| {
                    // Strip :port if present
                    let host = h.split(':').next().unwrap_or(&h);
                    host.trim().to_ascii_lowercase()
                });
            if let Some(host) = host {
                auto_ssl.trigger_provision_if_needed(&host);
            }
        }

        // Load config once (Guard<Arc> — cheap clone of Arc pointer)
        let config = self.state.config.load();

        // Extract client IP early — needed by all plugins
        let peer_addr = session
            .client_addr()
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
        ctx.jwt = config.jwt.clone();
        ctx.peer_ip = peer_addr;
        ctx.client_ip = client_ip;
        // Reuse Arc<str> allocations across keep-alive requests: when the value
        // is unchanged (the common case — same client requesting the same URL),
        // this is just a comparison instead of a heap allocation.
        set_arc_str(
            &mut ctx.client_ip_source,
            config.client_ip.header.as_deref().unwrap_or("peer_ip"),
        );
        set_opt_arc_str(
            &mut ctx.host,
            raw_headers.get("host").and_then(|v| v.to_str().ok()),
        );
        set_arc_str(
            &mut ctx.path,
            session
                .req_header()
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
        );
        set_arc_str(&mut ctx.method, session.req_header().method.as_str());
        set_arc_str(
            &mut ctx.scheme,
            resolve_scheme_from_raw(&session.req_header().uri, raw_headers),
        );
        set_opt_arc_str(
            &mut ctx.user_agent,
            raw_headers.get("user-agent").and_then(|v| v.to_str().ok()),
        );
        ctx.headers = raw_headers.clone();

        // Reset per-request plugin state (avoid re-allocating new struct)
        ctx.query_cache = None;
        ctx.cookie_cache = None;
        ctx.jwt_cache.clear();
        ctx.ip_intel = None;
        ctx.firewall = FirewallResult::default();
        ctx.request_transform.reset();
        ctx.response_transform.reset();
        ctx.rate_limit = RateLimitResult::default();
        ctx.cache = CacheResult::default();
        ctx.load_balancer = LoadBalancerResult::default();
        ctx.upstream_name = None;
        ctx.upstream_target = None;
        ctx.upstream_protocol = None;
        ctx.status_code = None;
        ctx.upstream_status = None;
        ctx.client_bytes_in = 0;
        ctx.client_bytes_out = 0;
        ctx.upstream_bytes_out = 0;
        ctx.upstream_bytes_in = 0;
        ctx.response_headers_captured = None;
        ctx.response_body_buffer.clear();
        ctx.cache_should_store = false;
        ctx.revalidation_guard = None;
        ctx.cache_stale = None;
        ctx.serve_from_cache = None;
        ctx.ip_intel_latency_us = None;
        ctx.firewall_latency_us = None;
        ctx.rate_limit_latency_us = None;
        ctx.cache_lookup_latency_us = None;
        ctx.lb_latency_us = None;
        ctx.upstream_connect_latency_us = None;
        ctx.upstream_ttfb_us = None;
        ctx.total_latency_us = None;
        ctx.upstream_sent_at = None;
        ctx.upstream_us = 0;
        ctx.termination_phase = None;
        ctx.protection = None;
        ctx.block = BlockResult::default();
        ctx.allow_rule = None;

        // server.protection: bans and the per-IP request flood limit
        if let Some(protection) = &config.server.protection {
            if let Err((violation, retry_after)) =
                self.state.ip_tracker.check_request(protection, client_ip)
            {
                ctx.termination_phase = Some(TerminationPhase::Protection);
                ctx.protection = Some(violation.as_str());
                ctx.block = BlockResult::dos(violation.as_str(), client_ip);
                session.set_keepalive(None);
                let resp = protection_response(429, violation, Some(retry_after));
                send_gateway_response(session, &resp, ctx, None).await?;
                return Ok(true);
            }
        }

        // server.limits.max_body_bytes: reject a declared oversized body up front.
        // Chunked bodies are counted in request_body_filter.
        let max_body = config.server.max_body_bytes;
        if max_body > 0 && !ctx.upgrade {
            let declared = session
                .req_header()
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            if declared.is_some_and(|len| len > max_body) {
                if let Some(protection) = &config.server.protection {
                    self.state
                        .ip_tracker
                        .strike(protection, client_ip, Violation::BodyTooLarge);
                }
                ctx.termination_phase = Some(TerminationPhase::Protection);
                ctx.protection = Some(Violation::BodyTooLarge.as_str());
                ctx.block = BlockResult::dos(Violation::BodyTooLarge.as_str(), client_ip);
                session.set_keepalive(None);
                let resp = protection_response(413, Violation::BodyTooLarge, None);
                send_gateway_response(session, &resp, ctx, None).await?;
                return Ok(true);
            }
        }

        let flow = self
            .state
            .plugin_runner
            .execute_pipeline(ctx, &config, &self.state.metrics)
            .await;

        match flow {
            PluginFlow::Respond(resp) => {
                // Cache HIT / STALE / REVALIDATING get response_transform;
                // gateway-generated blocks (firewall, rate limit, ...) do not.
                let transform = if ctx.termination_phase == Some(TerminationPhase::Cache) {
                    config.response_transform.as_ref()
                } else {
                    None
                };
                send_gateway_response(session, &resp, ctx, transform).await?;
                Ok(true)
            }
            PluginFlow::Continue => Ok(false),
        }
    }

    // request_body_filter: enforce server.limits.max_body_bytes on streamed
    // bodies (not WebSocket traffic after an upgrade)

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        if let Some(chunk) = body {
            ctx.client_bytes_in += chunk.len() as u64;
            let config = self.state.config.load();
            let max_body = config.server.max_body_bytes;
            if max_body > 0 && !ctx.upgrade && ctx.client_bytes_in > max_body {
                if let Some(protection) = &config.server.protection {
                    self.state.ip_tracker.strike(
                        protection,
                        ctx.client_ip,
                        Violation::BodyTooLarge,
                    );
                }
                ctx.termination_phase = Some(TerminationPhase::Protection);
                ctx.protection = Some(Violation::BodyTooLarge.as_str());
                ctx.block = BlockResult::dos(Violation::BodyTooLarge.as_str(), ctx.client_ip);
                return Err(pingora_error::Error::explain(
                    pingora_error::ErrorType::HTTPStatus(413),
                    "request body larger than server.limits.max_body_bytes",
                ));
            }
        }
        Ok(())
    }

    // upstream_peer: select target from LB result

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        let target_host = ctx
            .load_balancer
            .target_host
            .clone()
            .unwrap_or_else(|| Arc::from("127.0.0.1"));
        let target_port = ctx.load_balancer.target_port.unwrap_or(80);
        let target_protocol = ctx
            .load_balancer
            .target_protocol
            .clone()
            .unwrap_or_else(|| Arc::from("http"));
        let tls_verify = ctx.load_balancer.target_tls_verify.unwrap_or(false);
        let tls_sni = ctx.load_balancer.target_tls_sni.clone();

        let tls = matches!(target_protocol.as_ref(), "https" | "h2");
        let mut peer = if tls {
            let sni = resolve_upstream_sni(&target_host, tls_sni.as_deref(), ctx.host.as_deref());
            let mut peer = HttpPeer::new((target_host.as_ref(), target_port), true, sni);
            peer.options.verify_cert = tls_verify;
            peer
        } else {
            HttpPeer::new((target_host.as_ref(), target_port), false, String::new())
        };
        // h2c / h2 targets: HTTP/2 only (prior knowledge without TLS, ALPN h2
        // with it), with many requests multiplexed on one connection.
        if matches!(target_protocol.as_ref(), "h2c" | "h2") {
            peer.options.set_http_version(2, 2);
            peer.options.max_h2_streams = H2_UPSTREAM_STREAMS;
        }
        // server.timeouts.upstream_*
        let config = self.state.config.load();
        let server = &config.server;
        peer.options.connection_timeout = server.upstream_connect_timeout;
        peer.options.total_connection_timeout = server.upstream_total_connect_timeout;
        peer.options.read_timeout = if ctx.upgrade || ctx.grpc {
            server.websocket_idle_timeout
        } else {
            server.upstream_read_timeout
        };
        peer.options.write_timeout = server.upstream_write_timeout;
        peer.options.idle_timeout = server.upstream_idle_timeout;
        // From here on the request belongs to this upstream: logged as
        // upstream/upstream_addr, and upstream_us counts connect time too.
        ctx.upstream_sent_at = Some(std::time::Instant::now());
        Ok(Box::new(peer))
    }

    // upstream_request_filter: set forwarding headers

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        // 1. request_transform: replay the rewrite made in the pipeline
        if ctx.request_transform.path_rewritten() {
            match ctx.path.parse::<http::Uri>() {
                Ok(uri) => upstream_request.set_uri(uri),
                Err(e) => {
                    return Err(pingora_error::Error::explain(
                        pingora_error::ErrorType::InternalError,
                        format!(
                            "request_transform produced an invalid path '{}': {e}",
                            ctx.path
                        ),
                    ));
                }
            }
        }
        // Firewall set_request_header first, so request_transform rules
        // (which run after the firewall) win on the same header.
        for (name, val) in &ctx.firewall.request_headers {
            let _ = upstream_request.insert_header(name.clone(), val.clone());
        }
        replay_request_header_edits(&ctx.request_transform.header_edits, upstream_request);

        // 2. Cache: the origin answer may be stored, so it must not depend on
        // the client's own validators, and its encoding must match the key.
        if ctx.cache_should_store || ctx.cache_stale.is_some() {
            upstream_request.remove_header(&http::header::IF_NONE_MATCH);
            upstream_request.remove_header(&http::header::IF_MODIFIED_SINCE);
            match bucket_accept_encoding(ctx.cache.encoding) {
                Some(ae) => {
                    let _ = upstream_request.insert_header(http::header::ACCEPT_ENCODING, ae);
                }
                None => {
                    upstream_request.remove_header(&http::header::ACCEPT_ENCODING);
                }
            }
            // Revalidation: ask the origin whether the stored copy is still good.
            if let Some(stale) = &ctx.cache_stale {
                if let Some(etag) = stale.header("etag") {
                    let _ = upstream_request.insert_header(http::header::IF_NONE_MATCH, etag);
                }
                if let Some(lm) = stale.header("last-modified") {
                    let _ = upstream_request.insert_header(http::header::IF_MODIFIED_SINCE, lm);
                }
            }
        }

        // 3. Forwarding headers last, built from the client's original request,
        // so a transform rule cannot override them. X-Forwarded-Host is the
        // host the client asked for, not a rewritten one.
        let original = session.req_header();
        let _ = upstream_request.insert_header("X-Forwarded-Proto", ctx.scheme.as_ref());
        if let Some(host) = original
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
        {
            if !host.is_empty() {
                let _ = upstream_request.insert_header("X-Forwarded-Host", host);
            }
        }
        let client_ip = ctx.client_ip.to_string();
        let xff = match original
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            Some(existing) if !existing.trim().is_empty() => {
                format!("{}, {}", existing.trim(), client_ip)
            }
            _ => client_ip,
        };
        let _ = upstream_request.insert_header("X-Forwarded-For", xff);

        // Optional X-QG-* headers (plugins.ip_intel.forward_headers). Off by default.
        let config = self.state.config.load();
        if let Some(fh) = config
            .ip_intel
            .as_ref()
            .and_then(|i| i.forward_headers.as_ref())
        {
            fh.apply(upstream_request, ctx.ip_intel.as_deref(), ctx.client_ip);
        }

        // Last, so neither a transform rule nor the X-QG-* stripping above
        // can change or drop it.
        insert_request_id(
            upstream_request.insert_header(request_id::HEADER, ctx.request_id.as_str()),
        );
        Ok(())
    }

    // response_filter: capture upstream response headers for cache

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        let status = upstream_response.status.as_u16();
        ctx.upstream_status = Some(status);
        if let Some(sent) = ctx.upstream_sent_at {
            ctx.upstream_us = sent.elapsed().as_micros() as u64;
        }

        // ── Revalidation outcome ─────────────────────────────────────────
        // A stored copy is held when this request is the revalidation lock
        // holder or an expired entry is inside its stale-if-error window.
        // To answer from it, stop proxying here: fail_to_proxy writes the
        // stored copy (with response_transform) to the client.
        if let Some(stale) = ctx.cache_stale.as_ref() {
            if status == 304 {
                let refreshed = self.refresh_after_304(ctx, stale, upstream_response);
                ctx.cache.status = CacheStatus::Revalidated;
                ctx.serve_from_cache = Some(refreshed);
                ctx.cache_should_store = false;
                return Err(serve_from_cache_error());
            }
            if status >= 500 && stale.is_stale_if_error() {
                ctx.cache.status = CacheStatus::Stale;
                ctx.serve_from_cache = Some(stale.clone());
                ctx.cache_should_store = false;
                return Err(serve_from_cache_error());
            }
        }

        // Only capture upstream response headers when caching is active.
        // This avoids Vec + N header clones (to_lowercase + to_string) on
        // every non-cacheable request (firewall block, rate limit, bypass, etc.)
        if ctx.cache_should_store {
            // Status allowed by the rule, and no Vary the key doesn't cover.
            let status_ok = ctx
                .cache
                .statuses
                .as_ref()
                .map_or(true, |s| s.contains(&status));
            if !status_ok || !vary_is_cacheable(&upstream_response.headers) {
                ctx.cache_should_store = false;
            }
        }

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

        // Everything below happens after the cache captured the origin
        // headers, so none of it is ever stored.
        upstream_response
            .insert_header("Quayel-Cache-Status", ctx.cache.status.as_str())
            .unwrap_or(());
        insert_request_id(
            upstream_response.insert_header(request_id::HEADER, ctx.request_id.as_str()),
        );
        for (name, val) in &ctx.firewall.response_headers {
            let _ = upstream_response.insert_header(name.clone(), val.clone());
        }
        let config = self.state.config.load();
        if let Some(rt) = &config.response_transform {
            apply_response_transform(ctx, rt, upstream_response);
        }
        ctx.status_code = Some(upstream_response.status.as_u16());
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

            if let (Some(_rule_id), Some(key_hash)) = (rule_id, key_hash) {
                let headers = ctx.response_headers_captured.clone().unwrap_or_default();
                let body_buf = &ctx.response_body_buffer;

                let Some((edge_ttl, stale_while_revalidate, stale_if_error)) =
                    cache_ttls(&ctx.cache, &headers)
                else {
                    ctx.cache_should_store = false;
                    return Ok(None);
                };

                // The origin's status, not the transformed one sent to the client.
                let status = ctx.upstream_status.unwrap_or(200);

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
                self.state
                    .plugin_runner
                    .cache
                    .revalidating
                    .remove(&key_hash);

                ctx.cache_should_store = false;
            }
        }

        Ok(None)
    }

    // fail_to_proxy: answer from cache (304 / stale-if-error), else error page

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_error::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        // response_filter chose a stored copy (304 or 5xx inside stale-if-error),
        // or the origin could not be reached at all (connect error, timeout)
        // while an entry inside its stale-if-error window is held.
        let entry = ctx.serve_from_cache.take().or_else(|| {
            let usable = session.response_written().is_none()
                && *e.esource() == pingora_error::ErrorSource::Upstream
                && ctx
                    .cache_stale
                    .as_ref()
                    .is_some_and(|s| s.is_stale_if_error());
            if usable {
                ctx.cache.status = CacheStatus::Stale;
                ctx.cache_stale.clone()
            } else {
                None
            }
        });

        if let Some(entry) = entry {
            ctx.termination_phase = Some(TerminationPhase::Cache);
            let resp = GatewayResponse {
                status: entry.status,
                headers: entry.headers.clone(),
                body: entry.body.clone(),
            };
            let config = self.state.config.load();
            return match send_gateway_response(
                session,
                &resp,
                ctx,
                config.response_transform.as_ref(),
            )
            .await
            {
                Ok(()) => FailToProxy {
                    error_code: ctx.status_code.unwrap_or(resp.status),
                    can_reuse_downstream: session.is_body_done(),
                },
                Err(_) => FailToProxy {
                    error_code: 0,
                    can_reuse_downstream: false,
                },
            };
        }

        // Default Pingora behaviour.
        use pingora_error::{ErrorSource, ErrorType};
        let code = match e.etype() {
            ErrorType::HTTPStatus(code) => *code,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };
        if code > 0 {
            ctx.status_code = Some(code);
            if ctx.grpc && session.response_written().is_none() {
                let message = grpc_message(code, &[]);
                let _ = send_grpc_error(session, ctx, code, &message, &[]).await;
            } else {
                let _ = respond_error_with_id(session, code, &ctx.request_id).await;
            }
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    fn suppress_error_log(
        &self,
        _session: &Session,
        ctx: &Self::CTX,
        error: &pingora_error::Error,
    ) -> bool {
        // Answered from cache, or a gRPC stream the client ended normally:
        // not a failure from the client's point of view.
        ctx.termination_phase == Some(TerminationPhase::Cache)
            || (ctx.grpc && h2_finished_reset(error))
    }

    // logging: SINGLE log point

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        // The next bytes on this connection start a new request header. If
        // the body wasn't fully read (blocked/rejected request), close the
        // connection instead of draining an unknown amount of data.
        if header_guard(session).is_some() {
            if session.is_body_done() {
                if let Some(guard) = header_guard(session) {
                    guard.request_done();
                }
            } else {
                session.set_keepalive(None);
            }
        }

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
        if let (Some(host), Some(port)) = (
            &ctx.load_balancer.target_host,
            ctx.load_balancer.target_port,
        ) {
            self.state
                .plugin_runner
                .load_balancer
                .release_connection(host, port);
        }

        let queue = self.state.log_queue.load();
        let Some(queue) = queue.as_deref() else {
            return;
        };

        ctx.finalize_latency();
        ctx.client_bytes_out = session.body_bytes_sent() as u64;
        // Failed before early_request_filter (e.g. a malformed header).
        if ctx.request_id.is_empty() {
            ctx.ts_ms = request_id::now_ms();
            ctx.request_id = request_id::generate_at(ctx.ts_ms);
        }
        // The origin never answered: time spent waiting on it.
        if ctx.upstream_us == 0 {
            if let Some(sent) = ctx.upstream_sent_at {
                ctx.upstream_us = sent.elapsed().as_micros() as u64;
            }
        }

        let mut event = LogEvent::from_context(ctx);
        if let Some(field) = &queue.settings.user_field {
            event.user = match resolve_condition_value(ctx, field) {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(s)) => Some(s),
                Some(v) => Some(v.to_string()),
            };
        }
        // Answered from a stored copy: the internal error that stopped
        // proxying isn't a failure.
        if ctx.termination_phase != Some(TerminationPhase::Cache) {
            if let Some(e) = error {
                if ctx.grpc && h2_finished_reset(e) {
                    // The client ended the stream after the response with
                    // RST_STREAM(NO_ERROR): normal for gRPC, not a failure.
                } else if client_closed(e) {
                    // Nginx's convention: the client gave up before the
                    // response was complete.
                    event.status = 499;
                    event.error = Some("client closed".to_string());
                } else {
                    event.error = Some(strip_queries(&e.to_string()).into_owned());
                }
            }
        }
        queue.enqueue(event);
    }
}

// Send a GatewayResponse via Pingora session

async fn send_gateway_response(
    session: &mut Session,
    resp: &GatewayResponse,
    ctx: &mut RequestContext,
    transform: Option<&CompiledTransform>,
) -> pingora_core::Result<()> {
    // A gRPC client can't read an HTTP error page: answer with a gRPC status
    // instead. Cached copies are never gRPC (only GET/HEAD are cached).
    if ctx.grpc && ctx.termination_phase != Some(TerminationPhase::Cache) {
        let message = grpc_message(resp.status, &resp.body);
        return send_grpc_error(session, ctx, resp.status, &message, &resp.headers).await;
    }
    let mut header = ResponseHeader::build(resp.status, None)?;
    for (name, value) in resp.headers.iter() {
        // Framing comes from the body we send, not from the stored headers.
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let hname = http::header::HeaderName::from_bytes(name.as_bytes())
            .unwrap_or(http::header::HeaderName::from_static("x-quayel"));
        let hval = http::HeaderValue::from_str(value).unwrap_or(http::HeaderValue::from_static(""));
        // append, not insert: stored responses may repeat a header (e.g. Link)
        header.append_header(hname, hval)?;
    }
    header.insert_header(http::header::CONTENT_LENGTH, resp.body.len())?;

    // Always add Quayel-Cache-Status header to every response
    // Short ASCII strings ("HIT", "MISS", etc.) — no heap allocation for <= 14 bytes
    let cache_status = ctx.cache.status.as_str();
    header.insert_header(
        http::header::HeaderName::from_static("quayel-cache-status"),
        http::HeaderValue::from_str(cache_status).unwrap_or(http::HeaderValue::from_static("")),
    )?;
    insert_request_id(header.insert_header(request_id::HEADER, ctx.request_id.as_str()));
    for (name, val) in &ctx.firewall.response_headers {
        let _ = header.insert_header(name.clone(), val.clone());
    }

    if let Some(rt) = transform {
        apply_response_transform(ctx, rt, &mut header);
    }
    let status = header.status.as_u16();
    ctx.status_code = Some(status);

    // A status override to 204/304 means no body.
    let body = if matches!(status, 204 | 304) {
        header.remove_header(&http::header::CONTENT_LENGTH);
        Bytes::new()
    } else {
        resp.body.clone()
    };

    session
        .write_response_header(Box::new(header), false)
        .await?;
    session.write_response_body(Some(body), true).await?;

    Ok(())
}

/// Upstream HTTP/2 streams multiplexed on one connection (h2c / h2 targets).
const H2_UPSTREAM_STREAMS: usize = 100;

/// `application/grpc`, `application/grpc+proto`, `application/grpc-web`, ...
fn is_grpc(req: &pingora_http::RequestHeader) -> bool {
    req.headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.len() >= 16 && ct.as_bytes()[..16].eq_ignore_ascii_case(b"application/grpc")
        })
}

/// gRPC status for an HTTP status the gateway decided on. Follows gRPC's
/// HTTP-to-status mapping, except 413 and 429 which are RESOURCE_EXHAUSTED.
fn grpc_code(status: u16) -> u8 {
    match status {
        400 => 13,             // INTERNAL
        401 => 16,             // UNAUTHENTICATED
        403 => 7,              // PERMISSION_DENIED
        404 => 12,             // UNIMPLEMENTED
        413 | 429 => 8,        // RESOURCE_EXHAUSTED
        502 | 503 | 504 => 14, // UNAVAILABLE
        _ => 2,                // UNKNOWN
    }
}

/// `grpc-message`: the gateway's text body if it is one short line, else the
/// HTTP reason phrase. Percent-encoded as the gRPC spec requires.
fn grpc_message(status: u16, body: &[u8]) -> String {
    // Gateway blocks are JSON like {"error":"blocked","rule_id":"x",...}.
    let from_json = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let error = v.get("error")?.as_str()?.to_string();
            Some(match v.get("rule_id").and_then(|r| r.as_str()) {
                Some(rule) => format!("{error} (rule {rule})"),
                None => error,
            })
        });
    let text = from_json
        .or_else(|| std::str::from_utf8(body).ok().map(str::to_string))
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.len() <= 200 && !t.contains('\n'))
        .map(str::to_string)
        .unwrap_or_else(|| {
            http::StatusCode::from_u16(status)
                .ok()
                .and_then(|s| s.canonical_reason())
                .unwrap_or("gateway error")
                .to_string()
        });
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if (0x20..=0x7e).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// A gRPC error response: HTTP 200 with no body and the status in
/// grpc-status / grpc-message. The log keeps the HTTP status the gateway
/// decided on.
async fn send_grpc_error(
    session: &mut Session,
    ctx: &mut RequestContext,
    status: u16,
    message: &str,
    extra_headers: &[(String, String)],
) -> pingora_core::Result<()> {
    let mut status_fields = http::HeaderMap::new();
    status_fields.insert(
        "grpc-status",
        http::HeaderValue::from(grpc_code(status) as u16),
    );
    status_fields.insert(
        "grpc-message",
        http::HeaderValue::from_str(message)
            .unwrap_or(http::HeaderValue::from_static("gateway error")),
    );
    // Pingora can't end an h2 stream on the HEADERS frame (a "trailers-only"
    // response), so over HTTP/2 the status goes in a trailers frame after
    // the headers. HTTP/1.1 (grpc-web) carries it in the headers.
    let h2 = session.as_http2().is_some();
    let mut header = ResponseHeader::build(200, None)?;
    header.insert_header(http::header::CONTENT_TYPE, "application/grpc")?;
    if !h2 {
        for (name, value) in &status_fields {
            header.insert_header(name.clone(), value.clone())?;
        }
        header.insert_header(http::header::CONTENT_LENGTH, "0")?;
    }
    for (name, value) in extra_headers {
        if name.eq_ignore_ascii_case("retry-after") {
            let _ = header.insert_header("retry-after", value.as_str());
        }
    }
    insert_request_id(header.insert_header(request_id::HEADER, ctx.request_id.as_str()));
    for (name, val) in &ctx.firewall.response_headers {
        let _ = header.insert_header(name.clone(), val.clone());
    }
    ctx.status_code = Some(status);
    if h2 {
        session.write_response_header(Box::new(header), false).await?;
        session.write_response_trailers(status_fields).await
    } else {
        session.write_response_header(Box::new(header), false).await?;
        session.write_response_body(Some(Bytes::new()), true).await
    }
}

/// The request ID is always a valid header value (generated hex or a checked
/// incoming one); this only exists to make the `Result` explicit.
fn insert_request_id(r: pingora_core::Result<()>) {
    debug_assert!(r.is_ok(), "request id is a valid header value");
}

/// The client closed the connection (or stopped reading) before the
/// response was complete.
fn client_closed(e: &pingora_core::Error) -> bool {
    use pingora_error::{ErrorSource, ErrorType};
    *e.esource() == ErrorSource::Downstream
        && matches!(
            e.etype(),
            ErrorType::ConnectionClosed | ErrorType::ReadError | ErrorType::WriteError
        )
}

/// An HTTP/2 client reset the stream with NO_ERROR ("done, nothing wrong").
/// gRPC clients do this when the server finishes before they half-close;
/// a real cancel uses CANCEL.
fn h2_finished_reset(e: &pingora_core::Error) -> bool {
    e.root_cause()
        .downcast_ref::<h2::Error>()
        .is_some_and(|h| h.reason() == Some(h2::Reason::NO_ERROR))
}

/// Pingora's `respond_error`, plus `X-QG-Request-Id`.
async fn respond_error_with_id(
    session: &mut Session,
    code: u16,
    request_id: &str,
) -> pingora_core::Result<()> {
    let mut header = pingora_core::protocols::http::ServerSession::generate_error(code);
    header.insert_header(request_id::HEADER, request_id)?;
    session.write_error_response(header, Bytes::new()).await
}

/// Short plain-text response for server.protection / server.limits refusals.
fn protection_response(
    status: u16,
    violation: Violation,
    retry_after: Option<u64>,
) -> GatewayResponse {
    let mut headers = vec![
        ("content-type".to_string(), "text/plain".to_string()),
        ("connection".to_string(), "close".to_string()),
    ];
    if let Some(secs) = retry_after {
        headers.push(("retry-after".to_string(), secs.to_string()));
    }
    let body = match status {
        413 => "Request body too large\n",
        _ => "Too many requests\n",
    };
    headers.push((
        "x-quayel-block-reason".to_string(),
        violation.as_str().to_string(),
    ));
    GatewayResponse {
        status,
        headers: Arc::new(headers),
        body: Bytes::from_static(body.as_bytes()),
    }
}

// Helpers

fn resolve_upstream_sni(
    target_host: &str,
    configured: Option<&str>,
    visitor_host: Option<&str>,
) -> String {
    if let Some(sni) = configured {
        let sni = sni.trim();
        if !sni.is_empty() {
            return sni.to_string();
        }
    }
    if target_host.parse::<std::net::IpAddr>().is_ok() {
        if let Some(host) = visitor_host {
            let host = host.trim();
            if !host.is_empty() {
                return host.split(':').next().unwrap_or(host).to_string();
            }
        }
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
                if proto.eq_ignore_ascii_case("http") {
                    return "http";
                }
                if proto.eq_ignore_ascii_case("https") {
                    return "https";
                }
            }
        }
    }
    if let Some(scheme) = uri.scheme_str() {
        return if scheme.eq_ignore_ascii_case("https") {
            "https"
        } else {
            "http"
        };
    }
    "http"
}

/// Resolve client IP directly from raw HeaderMap — avoids full header extraction.
fn resolve_client_ip_from_raw(
    config: &CompiledConfig,
    headers: &http::HeaderMap,
    peer_ip: std::net::IpAddr,
) -> std::net::IpAddr {
    if config.client_ip.source != ClientIpSource::PeerIp
        && !config.client_ip.trusted_proxies.contains(peer_ip)
    {
        return peer_ip;
    }
    match &config.client_ip.source {
        ClientIpSource::PeerIp => peer_ip,
        ClientIpSource::Header => {
            if let Some(header_name) = &config.client_ip.header {
                if let Some(value) = headers
                    .get(header_name.as_ref())
                    .and_then(|v| v.to_str().ok())
                {
                    if let Ok(ip) = value.trim().parse::<std::net::IpAddr>() {
                        return ip;
                    }
                }
            }
            peer_ip
        }
        ClientIpSource::HeaderIndex => {
            if let (Some(header_name), Some(index)) =
                (&config.client_ip.header, config.client_ip.index)
            {
                if let Some(value) = headers
                    .get(header_name.as_ref())
                    .and_then(|v| v.to_str().ok())
                {
                    // nth() over the split iterator — no Vec allocation per request
                    if let Some(part) = value.split(',').nth(index) {
                        if let Ok(ip) = part.trim().parse::<std::net::IpAddr>() {
                            return ip;
                        }
                    }
                }
            }
            peer_ip
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_content_types() {
        let req = |ct: &str| {
            let mut r = pingora_http::RequestHeader::build("POST", b"/s/M", None).unwrap();
            r.insert_header("content-type", ct).unwrap();
            r
        };
        assert!(is_grpc(&req("application/grpc")));
        assert!(is_grpc(&req("application/grpc+proto")));
        assert!(is_grpc(&req("Application/GRPC-web")));
        assert!(!is_grpc(&req("application/json")));
        assert!(!is_grpc(&req("application/gr")));
    }

    #[test]
    fn grpc_status_and_message() {
        assert_eq!(grpc_code(403), 7);
        assert_eq!(grpc_code(429), 8);
        assert_eq!(grpc_code(502), 14);
        assert_eq!(grpc_code(418), 2);
        assert_eq!(
            grpc_message(403, br#"{"error":"blocked","status":403,"rule_id":"r1"}"#),
            "blocked (rule r1)"
        );
        assert_eq!(grpc_message(429, b"Too many requests\n"), "Too many requests");
        assert_eq!(grpc_message(502, b""), "Bad Gateway");
        // Non-ASCII and '%' are percent-encoded.
        assert_eq!(grpc_message(400, "100% caf\u{e9}".as_bytes()), "100%25 caf%C3%A9");
    }

    fn compiled(client_ip: &str) -> CompiledConfig {
        let raw: crate::config::schema::GatewayConfig = serde_json::from_str(&format!(
            r#"{{"gateway_id":"t","gateway_name":"t","server_name":"t","config_version":"1",
                "client_ip":{},"plugins":{{}}}}"#,
            client_ip
        ))
        .unwrap();
        crate::config::compiler::compile_config(&raw).unwrap()
    }

    fn resolve(c: &CompiledConfig, xff: &str, peer: &str) -> String {
        let mut h = http::HeaderMap::new();
        h.insert("x-forwarded-for", xff.parse().unwrap());
        resolve_client_ip_from_raw(c, &h, peer.parse().unwrap()).to_string()
    }

    #[test]
    fn header_only_believed_from_trusted_proxies() {
        let c = compiled(r#"{"source":"header_index","header":"X-Forwarded-For","index":0}"#);
        // Default trust: private ranges and Cloudflare.
        assert_eq!(resolve(&c, "8.8.8.8", "10.1.2.3"), "8.8.8.8");
        assert_eq!(resolve(&c, "8.8.8.8", "173.245.48.1"), "8.8.8.8");
        // A public client sending the header itself is ignored.
        assert_eq!(resolve(&c, "10.0.0.1", "203.0.113.9"), "203.0.113.9");

        let c = compiled(
            r#"{"source":"header","header":"X-Forwarded-For","trusted_proxies":["203.0.113.0/24"]}"#,
        );
        assert_eq!(resolve(&c, "8.8.8.8", "203.0.113.9"), "8.8.8.8");
        assert_eq!(resolve(&c, "8.8.8.8", "10.1.2.3"), "10.1.2.3");
    }

    #[test]
    fn invalid_trusted_proxy_is_rejected() {
        let raw: crate::config::schema::GatewayConfig = serde_json::from_str(
            r#"{"gateway_id":"t","gateway_name":"t","server_name":"t","config_version":"1",
                "client_ip":{"source":"header","header":"X","trusted_proxies":["nope"]},"plugins":{}}"#,
        )
        .unwrap();
        assert!(crate::config::compiler::compile_config(&raw).is_err());
    }
}
