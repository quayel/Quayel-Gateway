use crate::config::compiler::CompiledLoadBalancer;
use crate::config::schema::*;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};

// ── Health Checker ───────────────────────────────────────────────────────────
// Background health check tasks for load balancer targets.

#[derive(Debug)]
pub struct HealthChecker {
    /// Target health status: "<pool id>/<host>:<port>" -> is_healthy. Keyed
    /// per pool, since the same backend can have different checks in two pools.
    pub status: DashMap<String, bool>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            status: DashMap::new(),
        }
    }

    /// Start background health check tasks for all load balancers
    pub fn start_background_checks(self: &Arc<Self>, lb_configs: &[CompiledLoadBalancer]) {
        for lb in lb_configs {
            if let Some(hc_config) = &lb.health_check {
                if hc_config.mode == HealthCheckMode::Off {
                    continue;
                }

                for target in &lb.targets {
                    let checker = Arc::clone(self);
                    let _target_id = target.id.to_string();
                    let target_host = target.host.to_string();
                    let target_port = target.port;
                    let target_protocol = target.protocol.clone();
                    let tls_verify = target.tls_verify;
                    let hc_config = hc_config.clone();
                    let key = health_key(&lb.id, &target_host, target_port);

                    // Initialize as healthy
                    checker.status.insert(key.clone(), true);

                    tokio::spawn(async move {
                        checker
                            .run_health_check_loop(
                                &key,
                                &target_host,
                                target_port,
                                &target_protocol,
                                tls_verify,
                                &hc_config,
                            )
                            .await;
                    });
                }
            }
        }
    }

    async fn run_health_check_loop(
        &self,
        key: &str,
        host: &str,
        port: u16,
        protocol: &TargetProtocol,
        tls_verify: bool,
        config: &HealthCheckConfig,
    ) {
        let interval = Duration::from_secs(config.interval_seconds);
        let timeout = Duration::from_millis(config.timeout_ms);
        let mut consecutive_failures = 0u32;
        let mut consecutive_successes = 0u32;

        loop {
            time::sleep(interval).await;

            let success = match &config.mode {
                HealthCheckMode::Https => {
                    self.check_http(
                        host,
                        port,
                        config.path.as_deref().unwrap_or("/"),
                        timeout,
                        protocol,
                        tls_verify,
                        config.expected_statuses.as_deref(),
                    )
                    .await
                }
                HealthCheckMode::AcceptsConnections => {
                    self.check_tcp_connection(host, port, timeout).await
                }
                HealthCheckMode::Off => true,
            };

            if success {
                consecutive_failures = 0;
                consecutive_successes += 1;

                if consecutive_successes >= config.healthy_threshold {
                    if let Some(mut status) = self.status.get_mut(key) {
                        if !*status {
                            info!("Target {}:{} is now healthy (pool {})", host, port, pool_id(key));
                        }
                        *status = true;
                    }
                }
            } else {
                consecutive_successes = 0;
                consecutive_failures += 1;

                if consecutive_failures >= config.unhealthy_threshold {
                    if let Some(mut status) = self.status.get_mut(key) {
                        if *status {
                            warn!("Target {}:{} is now unhealthy (pool {})", host, port, pool_id(key));
                        }
                        *status = false;
                    }
                }
            }
        }
    }

    /// HTTP(S) health check. The target is healthy when the status is in
    /// `expected_statuses`, or any 2xx/3xx when that list is unset or empty.
    /// Honors the target protocol and its TLS verify setting so
    /// self-signed/expired upstream certificates do not mark `https` targets
    /// unhealthy.
    async fn check_http(
        &self,
        host: &str,
        port: u16,
        path: &str,
        timeout: Duration,
        protocol: &TargetProtocol,
        tls_verify: bool,
        expected_statuses: Option<&[u16]>,
    ) -> bool {
        let scheme = if protocol.is_tls() { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", scheme, host, port, path);

        // Redirects aren't followed: a 301/302 is the health endpoint's own
        // answer, matched against `expected_statuses` like any other status.
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(!tls_verify)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout);
        // h2c / h2 targets may not speak HTTP/1.1 at all (gRPC servers).
        if protocol.is_http2() {
            builder = builder.http2_prior_knowledge();
        }
        let client = match builder.build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        match tokio::time::timeout(timeout, client.get(&url).send()).await {
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                status_is_healthy(status, expected_statuses)
            }
            _ => false,
        }
    }

    async fn check_tcp_connection(&self, host: &str, port: u16, timeout: Duration) -> bool {
        let addr = format!("{}:{}", host, port);

        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    pub fn is_healthy(&self, pool: &str, host: &str, port: u16) -> bool {
        let key = health_key(pool, host, port);
        self.status.get(&key).map(|s| *s).unwrap_or(true) // Default to healthy if not tracked
    }
}

fn health_key(pool: &str, host: &str, port: u16) -> String {
    format!("{}/{}:{}", pool, host, port)
}

fn pool_id(key: &str) -> &str {
    key.split('/').next().unwrap_or(key)
}

fn status_is_healthy(status: u16, expected: Option<&[u16]>) -> bool {
    match expected {
        Some(list) if !list.is_empty() => list.contains(&status),
        _ => (200..400).contains(&status),
    }
}

#[cfg(test)]
mod tests {
    use super::status_is_healthy;

    #[test]
    fn expected_statuses_decide_health() {
        assert!(status_is_healthy(204, None));
        assert!(status_is_healthy(302, Some(&[])));
        assert!(!status_is_healthy(404, None));
        assert!(status_is_healthy(200, Some(&[200])));
        assert!(!status_is_healthy(302, Some(&[200])));
        assert!(status_is_healthy(404, Some(&[200, 404])));
    }
}
