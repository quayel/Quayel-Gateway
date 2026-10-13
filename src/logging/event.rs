use crate::gateway::request_context::*;
use crate::plugins::ip_intel::IpIntel;
use std::net::IpAddr;
use std::sync::Arc;

// ── Log Event ────────────────────────────────────────────────────────────────
// One access log line, as raw values. Building it on the request thread is
// only refcount bumps and copies of small integers: every string is either an
// `Arc<str>` clone or (for request_id and the rare block key / error) a short
// copy. All formatting — IPs, escaping, JSON — happens on the writer thread
// (see `writer.rs`), which also defines the line's fixed schema.

#[derive(Debug, Clone)]
pub struct LogEvent {
    /// Arrival time, Unix milliseconds.
    pub ts_ms: u64,
    pub gateway_id: Arc<str>,
    pub request_id: String,

    pub client_ip: IpAddr,
    pub method: Arc<str>,
    pub scheme: Arc<str>,
    /// Host and path the client sent (before any request_transform). The
    /// writer drops the query string from the path.
    pub host: Option<Arc<str>>,
    pub path: Arc<str>,
    pub user_agent: Option<Arc<str>>,

    /// Status sent to the client; 499 when the client closed the connection.
    pub status: u16,
    /// Response body bytes sent to the client.
    pub bytes: u64,
    /// Request body bytes read from the client.
    pub req_bytes: u64,
    pub dur_us: u64,

    pub ip_intel: Option<Arc<IpIntel>>,

    pub block: BlockResult,
    pub allow_rule: Option<Arc<str>>,

    pub cache: &'static str,

    /// Load balancer target ID and address, only when the request was sent
    /// to the upstream.
    pub upstream: Option<Arc<str>>,
    pub upstream_host: Option<Arc<str>>,
    pub upstream_port: u16,
    /// Status the origin sent, before response_transform. 0 when the
    /// request never got an answer from the origin.
    pub upstream_status: u16,
    pub upstream_us: u64,

    /// Why the request failed. Query strings are already removed.
    pub error: Option<String>,
    /// Value of plugins.logging.user_field.
    pub user: Option<String>,
    /// How many requests this line stands for (sampling; always 1 today).
    pub sample_rate: u32,
}

impl LogEvent {
    pub fn from_context(ctx: &RequestContext) -> Self {
        let sent_upstream = ctx.upstream_sent_at.is_some();
        LogEvent {
            ts_ms: ctx.ts_ms,
            gateway_id: Arc::clone(&ctx.gateway_id),
            request_id: ctx.request_id.clone(),

            client_ip: ctx.client_ip,
            method: Arc::clone(&ctx.method),
            scheme: Arc::clone(&ctx.scheme),
            host: match &ctx.request_transform.original_host {
                Some(original) => original.clone(),
                None => ctx.host.clone(),
            },
            path: Arc::clone(
                ctx.request_transform
                    .original_path
                    .as_ref()
                    .unwrap_or(&ctx.path),
            ),
            user_agent: ctx.user_agent.clone(),

            status: ctx.status_code.unwrap_or(0),
            bytes: ctx.client_bytes_out,
            req_bytes: ctx.client_bytes_in,
            dur_us: ctx.total_latency_us.unwrap_or(0),

            ip_intel: ctx.ip_intel.clone(),

            block: ctx.block.clone(),
            allow_rule: ctx.allow_rule.clone(),

            cache: ctx.cache.status.as_str(),

            upstream: sent_upstream
                .then(|| ctx.load_balancer.target_id.clone())
                .flatten(),
            upstream_host: sent_upstream
                .then(|| ctx.load_balancer.target_host.clone())
                .flatten(),
            upstream_port: if sent_upstream {
                ctx.load_balancer.target_port.unwrap_or(0)
            } else {
                0
            },
            upstream_status: ctx.upstream_status.unwrap_or(0),
            upstream_us: ctx.upstream_us,

            error: None,
            user: None,
            sample_rate: 1,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use http::{HeaderMap, HeaderName, HeaderValue};

    pub(crate) fn ctx(path: &str, headers: &[(&str, &str)]) -> RequestContext {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        RequestContext::new(
            Arc::from("gw"),
            Arc::from("gw"),
            Arc::from("gw"),
            Arc::from("1"),
            ip,
            ip,
            Arc::from("peer_ip"),
            None,
            Arc::from(path),
            Arc::from("GET"),
            Arc::from("http"),
            None,
            map,
        )
    }

    #[test]
    fn upstream_is_only_logged_when_the_request_was_sent_there() {
        let mut c = ctx("/p", &[]);
        c.load_balancer.target_id = Some(Arc::from("origin-2"));
        c.load_balancer.target_host = Some(Arc::from("10.0.0.5"));
        c.load_balancer.target_port = Some(8080);
        let ev = LogEvent::from_context(&c);
        assert!(ev.upstream.is_none() && ev.upstream_host.is_none());
        assert_eq!(ev.upstream_port, 0);

        c.upstream_sent_at = Some(std::time::Instant::now());
        let ev = LogEvent::from_context(&c);
        assert_eq!(ev.upstream.as_deref(), Some("origin-2"));
        assert_eq!(ev.upstream_host.as_deref(), Some("10.0.0.5"));
        assert_eq!(ev.upstream_port, 8080);
    }

    #[test]
    fn logs_the_host_and_path_the_client_sent() {
        let mut c = ctx("/rewritten", &[]);
        c.host = Some(Arc::from("internal.svc"));
        c.request_transform.original_path = Some(Arc::from("/original?x=1"));
        c.request_transform.original_host = Some(Some(Arc::from("api.example.com")));
        let ev = LogEvent::from_context(&c);
        assert_eq!(&*ev.path, "/original?x=1");
        assert_eq!(ev.host.as_deref(), Some("api.example.com"));
    }
}
