#![allow(dead_code, unexpected_cfgs)]

mod auto_ssl;
mod condition;
mod config;
mod gateway;
mod lb;
mod logging;
mod plugins;
mod utils;

// Use jemalloc as the global allocator for better performance under high concurrency
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use crate::auto_ssl::AutoSslManager;
use crate::config::{compile_config, load_config, ConfigWatcher};
use crate::gateway::gateway::{GatewayState, QuayelGateway};
use crate::logging::queue::LogQueue;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_proxy::http_proxy_service;
use std::sync::Arc;

/// Parse `--workers N` from the raw CLI args, returning (worker_count, remaining_args).
/// If `--workers` is not provided, defaults to all available CPU cores.
fn parse_workers_from_args() -> (usize, Vec<String>) {
    let args: Vec<String> = std::env::args().collect();
    let mut workers: Option<usize> = None;
    let mut remaining: Vec<String> = Vec::new();

    let mut i = 1; // skip args[0] which is the binary path
    while i < args.len() {
        if args[i] == "--help" || args[i] == "-h" {
            println!("Usage: {} [OPTIONS] [CONFIG_PATH]", args[0]);
            println!();
            println!("Options:");
            println!("  --workers <N>   Number of worker threads (default: all CPU cores)");
            println!("  --help, -h      Show this help message");
            println!();
            println!("Arguments:");
            println!("  CONFIG_PATH     Path to config.json (default: config.json)");
            std::process::exit(0);
        }
        if args[i] == "--workers" {
            if i + 1 < args.len() {
                match args[i + 1].parse::<usize>() {
                    Ok(n) if n > 0 => workers = Some(n),
                    _ => {
                        eprintln!("Error: --workers requires a positive integer");
                        std::process::exit(1);
                    }
                }
                i += 2;
                continue;
            } else {
                eprintln!("Error: --workers requires a value");
                std::process::exit(1);
            }
        }
        remaining.push(args[i].clone());
        i += 1;
    }

    let count = workers.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    (count, remaining)
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    tracing::info!("Starting Quayel Gateway...");

    // Parse worker count from CLI (--workers N) or default to all CPUs
    let (worker_count, remaining_args) = parse_workers_from_args();
    let workers_from_cli = std::env::args().any(|a| a == "--workers");
    tracing::info!(
        "Worker threads: {}{}",
        worker_count,
        if workers_from_cli { " (from --workers)" } else { " (auto-detected)" }
    );

    // Load configuration — positional arg or default to "config.json"
    let config_path = remaining_args
        .into_iter()
        .find(|a| !a.starts_with("--"))
        .unwrap_or_else(|| "config.json".to_string());

    let raw_config = match load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    tracing::info!(
        "Loaded config: gateway_id={}, version={}",
        raw_config.gateway_id,
        raw_config.config_version
    );

    // Compile config
    let compiled = match compile_config(&raw_config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to compile config: {}", e);
            std::process::exit(1);
        }
    };

    // ── Background Tokio runtime ──────────────────────────────────────────
    // Pingora's run_forever() creates its OWN Tokio runtime internally, so we
    // cannot call tokio::spawn or Handle::current() before it starts.
    // Solution: create a small dedicated runtime here for health checks and
    // the log queue writer. It lives for the entire process lifetime.
    let bg_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("quayel-bg")
        .build()
        .expect("Failed to create background Tokio runtime");
    let bg_handle = bg_runtime.handle().clone();
    // Leak the runtime so its threads stay alive until process exit.
    // (server.run_forever() blocks until SIGTERM anyway.)
    std::mem::forget(bg_runtime);

    // Initialize Pingora server with tuned upstream keepalive pool
    let opt = Opt::default();
    let mut conf = pingora_core::server::configuration::ServerConf::default();
    // Set worker threads — this is the Pingora ServerConf field that controls
    // how many Tokio service runtimes are created (default was 1!)
    conf.threads = worker_count;
    // Increase upstream keepalive pool size to handle concurrent connections
    // Default is 128 per worker thread; bump to 1024 for high-traffic gateways
    conf.upstream_keepalive_pool_size = 1024;
    // Graceful shutdown timing. Without these, pingora uses EXIT_TIMEOUT = 300s
    // as the grace period after SIGTERM — the process looks dead for 5 minutes
    // and container runtimes resort to SIGKILL. 5s grace + 5s runtime shutdown
    // fits Docker's default 10s stop timeout while still draining in-flight
    // requests.
    conf.grace_period_seconds = Some(5);
    conf.graceful_shutdown_timeout_seconds = Some(5);
    let mut server = Server::new_with_opt_and_conf(opt, conf);
    server.bootstrap();

    tracing::info!("Pingora server initialized with {} workers", worker_count);

    // Get listen address
    let listen_addr = compiled
        .listen_http
        .clone()
        .unwrap_or_else(|| "0.0.0.0:8089".to_string());

    // Initialize log queue ONLY when logging is enabled
    // When logging.enabled = false, log_queue = None → no file opened, no LogEvent built per request
    let log_queue = if let Some(ref logging_config) = compiled.logging {
        if logging_config.enabled {
            let log_path = logging_config.file_path.clone()
                .unwrap_or_else(|| "/var/log/quayel/access.jsonl".to_string());
            let buffer_size = logging_config.buffer_size;
            let flush_interval_ms = logging_config.flush_interval_ms;

            tracing::info!("Logging enabled: file={}, buffer={}, flush_ms={}", log_path, buffer_size, flush_interval_ms);

            Some(LogQueue::new(
                log_path,
                buffer_size,
                flush_interval_ms,
                bg_handle.clone(),
            ))
        } else {
            tracing::info!("Logging disabled — skipping log queue creation");
            None
        }
    } else {
        tracing::info!("Logging not configured — skipping log queue creation");
        None
    };

    // Create gateway state — IP intel data is embedded in the binary
    let state = Arc::new(GatewayState::new(compiled, log_queue, Some(bg_handle.clone())));

    // Create HTTP proxy service
    tracing::info!("Listening on {}", listen_addr);

    let mut proxy_service = http_proxy_service(
        &server.configuration,
        QuayelGateway { state: state.clone() },
    );

    proxy_service.add_tcp(&listen_addr);

    // Start HTTPS listener with Auto-SSL if configured
    if let Some(ref auto_ssl_manager) = state.auto_ssl {
        let https_addr = state.config.load().listen_https.clone()
            .unwrap_or_else(|| "0.0.0.0:8443".to_string());

        tracing::info!("Auto-SSL enabled — HTTPS listening on {}", https_addr);

        // Create SNI cert resolver
        let sni_resolver = Arc::new(SniCertResolver::new(auto_ssl_manager.clone()));

        // Create TLS settings with SNI resolver
        let mut tls_settings = pingora_core::listeners::tls::TlsSettings::intermediate("", "")
            .unwrap_or_else(|_| {
                // Fallback: create minimal settings
                pingora_core::listeners::tls::TlsSettings::intermediate(
                    "/dev/null", "/dev/null"
                ).unwrap()
            });
        tls_settings.set_cert_resolver(sni_resolver);

        // Add TLS listener
        proxy_service.add_tls_with_settings(&https_addr, None, tls_settings);

        // Start daily renewal task
        let auto_ssl_clone = auto_ssl_manager.clone();
        let bg_handle_clone = bg_handle.clone();
        bg_handle.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
            loop {
                interval.tick().await;
                auto_ssl_clone.daily_renewal_check(&bg_handle_clone).await;
            }
        });
    } else {
        tracing::info!("Auto-SSL disabled — no HTTPS listener");
    }

    // Start background tasks (health checks, etc.) on the background runtime
    start_background_tasks(&state, &bg_handle);

    // Start config file watcher — checks every 5 seconds for changes
    let config_path_clone = config_path.clone();
    let watcher = ConfigWatcher::new(config_path_clone);
    watcher.start(state.clone(), bg_handle.clone());

    // Add service and run
    server.add_service(proxy_service);

    tracing::info!("Quayel Gateway starting...");
    server.run_forever();
}

fn start_background_tasks(state: &Arc<GatewayState>, bg_handle: &tokio::runtime::Handle) {
    // Start health checks if load balancer is configured
    let config = state.config.load();
    if let Some(lb_config) = &config.load_balancer {
        if lb_config.enabled {
            let health_checker = Arc::new(crate::lb::health::HealthChecker::new());
            // Clone the configs so we can move them into the spawned task
            let lb_configs = lb_config.load_balancers.clone();
            let checker = health_checker.clone();
            bg_handle.spawn(async move {
                checker.start_background_checks(&lb_configs);
            });
        }
    }

    tracing::info!("Background tasks started (no dataset downloads needed — all data embedded)");
}

/// SNI-based certificate resolver for Auto-SSL.
///
/// When a TLS ClientHello arrives with an SNI hostname, this resolver:
/// 1. Checks the in-memory cert_map for a real cert → serve it
/// 2. If not found, checks if the domain should be provisioned
/// 3. If yes, spawns a background ACME worker (dedup guarded)
/// 4. Returns the fallback self-signed cert for now
///
/// Next handshake for the same domain will get the real cert.
#[derive(Debug)]
struct SniCertResolver {
    auto_ssl: Arc<AutoSslManager>,
    /// Default fallback cert for unknown domains
    fallback_cert: rustls::sign::CertifiedKey,
}

impl SniCertResolver {
    fn new(auto_ssl: Arc<AutoSslManager>) -> Self {
        let fallback_cert = auto_ssl.generate_fallback_cert()
            .expect("Failed to generate fallback certificate");
        Self { auto_ssl, fallback_cert }
    }
}

impl rustls::server::ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // Get the SNI hostname
        let server_name = client_hello.server_name()?;
        let domain = server_name.to_string();

        // 1. Check if we have a real cert for this domain
        if let Some(cert) = self.auto_ssl.get_cert(&domain) {
            return Some(cert);
        }

        // 2. + 3. On-demand provisioning: if this domain needs a cert, spawn the
        // background ACME worker (dedup-guarded, non-blocking) via the manager's
        // stored runtime handle. This MUST happen here — while only the self-signed
        // fallback cert is available, HTTPS clients abort the handshake
        // (CertificateUnknown) and the request never reaches request_filter.
        self.auto_ssl.trigger_provision_if_needed(&domain);

        // 4. Return fallback cert (next handshake gets the real cert)
        Some(Arc::new(self.fallback_cert.clone()))
    }
}