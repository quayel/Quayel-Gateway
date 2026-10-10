use crate::config::schema::*;
use crate::config::compiler::CompiledLoadBalancer;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};

// ── Health Checker ───────────────────────────────────────────────────────────
// Background health check tasks for load balancer targets.

#[derive(Debug)]
pub struct HealthChecker {
    /// Target health status: target_key -> is_healthy
    pub status: DashMap<String, bool>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            status: DashMap::new(),
        }
    }

    /// Start background health check tasks for all load balancers
    pub fn start_background_checks(
        self: &Arc<Self>,
        lb_configs: &[CompiledLoadBalancer],
    ) {
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
                    let key = format!("{}:{}", target_host, target_port);

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
                            info!("Target {} is now healthy", key);
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
                            warn!("Target {} is now unhealthy", key);
                        }
                        *status = false;
                    }
                }
            }
        }
    }

    /// HTTP(S) health check. Honors the target protocol and its TLS verify
    /// setting so self-signed/expired upstream certificates do not mark
    /// `https` targets unhealthy.
    async fn check_http(
        &self,
        host: &str,
        port: u16,
        path: &str,
        timeout: Duration,
        protocol: &TargetProtocol,
        tls_verify: bool,
    ) -> bool {
        let url = format!("{}://{}:{}{}", protocol.as_str(), host, port, path);

        let client = match reqwest::Client::builder()
            .danger_accept_invalid_certs(!tls_verify)
            .timeout(timeout)
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        match tokio::time::timeout(timeout, client.get(&url).send()).await {
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                status >= 200 && status < 400
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

    pub fn is_healthy(&self, host: &str, port: u16) -> bool {
        let key = format!("{}:{}", host, port);
        self.status
            .get(&key)
            .map(|s| *s)
            .unwrap_or(true) // Default to healthy if not tracked
    }
}