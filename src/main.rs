#![allow(dead_code, unexpected_cfgs)]

mod auto_ssl;
mod condition;
mod config;
mod gateway;
mod jwt;
mod lb;
mod logging;
mod plugins;
mod streams;
mod utils;

// Use jemalloc as the global allocator for better performance under high concurrency
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use crate::auto_ssl::AutoSslManager;
use crate::config::{compile_config, load_config, ConfigWatcher};
use crate::gateway::conn_guard::GuardedApp;
use crate::gateway::gateway::{GatewayState, QuayelGateway};
use crate::logging::queue::LogQueue;
use crate::streams::edge::EdgeApp;
use pingora_core::apps::HttpServerOptions;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::services::listening::Service;
use pingora_proxy::http_proxy;
use std::sync::Arc;

/// Parse `--workers N` from the raw CLI args, returning (workers, remaining_args).
fn parse_workers_from_args() -> (Option<usize>, Vec<String>) {
    let args: Vec<String> = std::env::args().collect();
    let mut workers: Option<usize> = None;
    let mut remaining: Vec<String> = Vec::new();

    let mut i = 1; // skip args[0] which is the binary path
    while i < args.len() {
        if args[i] == "--help" || args[i] == "-h" {
            println!("Usage: {} [OPTIONS] [CONFIG_PATH]", args[0]);
            println!();
            println!("Options:");
            println!("  --workers <N>   Number of worker threads (default: server.workers, else all CPU cores)");
            println!("  --version, -V   Print the version and exit");
            println!("  --help, -h      Show this help message");
            println!();
            println!("Arguments:");
            println!(
                "  CONFIG_PATH     Path to the config file. If omitted, the first that exists of:"
            );
            println!(
                "                    $QUAYEL_GATEWAY_CONFIG, {}, ./config.json",
                DEFAULT_CONFIG_PATH
            );
            std::process::exit(0);
        }
        if args[i] == "--version" || args[i] == "-V" {
            println!("quayel-gateway {}", env!("CARGO_PKG_VERSION"));
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

    (workers, remaining)
}

/// System-wide config location (same path the Docker image uses).
const DEFAULT_CONFIG_PATH: &str = "/etc/quayel-gateway/config.json";
const DEFAULT_HTTP_LISTEN: &str = "0.0.0.0:80";
const DEFAULT_HTTPS_LISTEN: &str = "0.0.0.0:443";

/// Pick the config file: CLI argument, then $QUAYEL_GATEWAY_CONFIG, then the
/// system path, then ./config.json (kept so existing setups keep working).
fn resolve_config_path(cli_arg: Option<String>) -> Result<String, String> {
    if let Some(path) = cli_arg {
        return Ok(path);
    }
    if let Ok(path) = std::env::var("QUAYEL_GATEWAY_CONFIG") {
        if !path.is_empty() {
            return Ok(path);
        }
    }
    for candidate in [DEFAULT_CONFIG_PATH, "config.json"] {
        if std::path::Path::new(candidate).is_file() {
            return Ok(candidate.to_string());
        }
    }
    Err(format!(
        "No config file found. Looked for {} and ./config.json; pass a path or set QUAYEL_GATEWAY_CONFIG",
        DEFAULT_CONFIG_PATH
    ))
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

    // Parse args first so --help / --version print without a startup log line
    let (cli_workers, remaining_args) = parse_workers_from_args();

    tracing::info!("Starting Quayel Gateway {}...", env!("CARGO_PKG_VERSION"));

    // Load configuration — positional arg, $QUAYEL_GATEWAY_CONFIG, system path, ./config.json
    let config_path =
        match resolve_config_path(remaining_args.into_iter().find(|a| !a.starts_with("--"))) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("{}", e);
                std::process::exit(1);
            }
        };
    tracing::info!("Config file: {}", config_path);

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

    // Worker threads: --workers, then server.workers, then all CPU cores
    let (worker_count, workers_source) = match (cli_workers, compiled.server.workers) {
        (Some(n), _) => (n, "from --workers"),
        (None, Some(n)) => (n, "from server.workers"),
        (None, None) => (
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            "auto-detected",
        ),
    };
    tracing::info!("Worker threads: {} ({})", worker_count, workers_source);

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
    // Upstream keepalive pool (server.limits.upstream_keepalive_pool_size,
    // default 1024; Pingora's own default is 128 per worker thread)
    conf.upstream_keepalive_pool_size = compiled.server.upstream_keepalive_pool_size;
    // Graceful shutdown timing. Without these, pingora uses EXIT_TIMEOUT = 300s
    // as the grace period after SIGTERM — the process looks dead for 5 minutes
    // and container runtimes resort to SIGKILL. The default 5s grace
    // (server.timeouts.graceful_shutdown_secs) + 5s runtime shutdown fits
    // Docker's default 10s stop timeout while still draining in-flight requests.
    conf.grace_period_seconds = Some(compiled.server.graceful_shutdown_secs);
    conf.graceful_shutdown_timeout_seconds = Some(5);
    let mut server = Server::new_with_opt_and_conf(opt, conf);
    server.bootstrap();

    tracing::info!("Pingora server initialized with {} workers", worker_count);

    // Get listen address
    let listen_addr = compiled
        .listen_http
        .clone()
        .unwrap_or_else(|| DEFAULT_HTTP_LISTEN.to_string());

    // Prometheus listener. Its address is read at startup only; the counters
    // are fed by the log queue's writer thread.
    if let Some(m) = compiled.metrics.clone() {
        bg_handle.spawn(crate::logging::metrics::serve(m.listen, m.path));
    }

    // Log queue only when logging or metrics are enabled: otherwise no file
    // is opened and no LogEvent is built per request. Config reloads can turn
    // it on/off.
    let log_queue = match compiled.logging.clone() {
        Some(settings) => Some(LogQueue::new(settings, &bg_handle)),
        None => {
            tracing::info!("Access log off (plugins.logging missing or disabled)");
            None
        }
    };

    // Create gateway state — IP intel data is embedded in the binary
    let state = Arc::new(GatewayState::new(
        compiled,
        log_queue,
        Some(bg_handle.clone()),
    ));

    // Create HTTP proxy service
    tracing::info!("Listening on {}", listen_addr);

    let mut proxy = http_proxy(
        &server.configuration,
        QuayelGateway {
            state: state.clone(),
        },
    );
    let mut server_options = HttpServerOptions::default();
    server_options.keepalive_request_limit = state.config.load().server.max_requests_per_connection;
    proxy.server_options = Some(server_options);
    // GuardedApp applies server.protection connection limits and the
    // request-header deadline before Pingora parses each request. EdgeApp
    // sends connections on stream ports to the TCP proxy instead.
    let stream_listens = state.config.load().streams.listen_addrs();
    let https_addr = state
        .config
        .load()
        .listen_https
        .clone()
        .unwrap_or_else(|| DEFAULT_HTTPS_LISTEN.to_string());

    // TLS for HTTPS (ALPN h2 + http/1.1) and for streams with
    // `tls: "terminate"` (no ALPN), both with Auto-SSL certificates.
    let tls_acceptor = |h2: bool| {
        let manager = state.auto_ssl.as_ref()?;
        let mut tls_settings = pingora_core::listeners::tls::TlsSettings::intermediate("", "")
            .unwrap_or_else(|_| {
                pingora_core::listeners::tls::TlsSettings::intermediate("/dev/null", "/dev/null")
                    .unwrap()
            });
        tls_settings.set_cert_resolver(Arc::new(SniCertResolver::new(manager.clone())));
        if h2 {
            tls_settings.enable_h2();
        }
        Some(tls_settings.build())
    };
    let http_tls = tls_acceptor(state.config.load().server.http2);
    let stream_tls = tls_acceptor(false);

    // The HTTPS port is a plain TCP listener: EdgeApp reads the server name
    // first (for streams that share the port) and then does the TLS
    // handshake itself. It opens with Auto-SSL, or without it when a stream
    // uses the port.
    let https_port = if http_tls.is_some() || !state.config.load().streams.https.is_empty() {
        match crate::streams::parse_listen(&https_addr) {
            Some(listen) => Some(crate::streams::edge::HttpsPort {
                listen,
                tls: http_tls,
            }),
            None => {
                tracing::error!("listen.https {:?} is not an ip:port address", https_addr);
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    match (&state.auto_ssl, &https_port) {
        (Some(_), _) => tracing::info!("Auto-SSL enabled — HTTPS listening on {}", https_addr),
        (None, Some(_)) => tracing::info!(
            "Auto-SSL disabled — {} serves SNI-routed streams only",
            https_addr
        ),
        (None, None) => tracing::info!("Auto-SSL disabled — no HTTPS listener"),
    }

    let mut proxy_service = Service::new(
        "Quayel Gateway".to_string(),
        EdgeApp::new(
            GuardedApp::new(proxy, state.clone()),
            state.clone(),
            stream_listens.clone(),
            https_port,
            stream_tls,
        ),
    );

    proxy_service.add_tcp(&listen_addr);
    if state.auto_ssl.is_some() || !state.config.load().streams.https.is_empty() {
        proxy_service.add_tcp(&https_addr);
    }
    for s in &state.config.load().streams.list {
        match s.listen {
            Some(addr) => tracing::info!(stream = %s.id, listen = %addr, sni = ?s.sni, "TCP stream listening"),
            None => tracing::info!(stream = %s.id, listen = %https_addr, sni = ?s.sni, "TCP stream on the HTTPS port"),
        }
    }
    for addr in &stream_listens {
        proxy_service.add_tcp(&addr.to_string());
    }
    crate::streams::health::spawn(state.clone(), &bg_handle);

    // UDP streams: bound now so a port in use stops startup with a clear
    // error; served by their own background service.
    let udp_addrs = state.config.load().streams.udp_addrs();
    let udp_service = if udp_addrs.is_empty() {
        None
    } else {
        let sockets = match crate::streams::udp::bind(&udp_addrs) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{}", e);
                std::process::exit(1);
            }
        };
        for s in &state.config.load().streams.udp {
            tracing::info!(stream = %s.id, listen = ?s.listen, "UDP stream listening");
        }
        let mut svc = pingora_core::services::background::background_service(
            "Quayel UDP streams",
            crate::streams::udp::UdpProxy::new(state.clone(), sockets),
        );
        svc.threads = Some(worker_count);
        Some(svc)
    };

    // Daily Auto-SSL renewal
    if let Some(ref auto_ssl_manager) = state.auto_ssl {
        let auto_ssl_clone = auto_ssl_manager.clone();
        let bg_handle_clone = bg_handle.clone();
        bg_handle.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
            loop {
                interval.tick().await;
                auto_ssl_clone.daily_renewal_check(&bg_handle_clone).await;
            }
        });
    }

    // Start background tasks (health checks, etc.) on the background runtime
    start_background_tasks(&state, &bg_handle);

    // Start config file watcher — checks every 5 seconds for changes
    let config_path_clone = config_path.clone();
    let watcher = ConfigWatcher::new(config_path_clone);
    watcher.start(state.clone(), bg_handle.clone());

    // Add service and run
    server.add_service(proxy_service);
    if let Some(svc) = udp_service {
        server.add_service(svc);
    }

    tracing::info!("Quayel Gateway starting...");
    // run() returns once Pingora has shut down (run_forever() would exit the
    // process right there, with access-log lines still in memory).
    server.run(pingora_core::server::RunArgs::default());
    if let Some(queue) = state.log_queue.swap(None) {
        queue.shutdown(std::time::Duration::from_secs(4));
    }
    tracing::info!("Quayel Gateway stopped");
    std::process::exit(0)
}

fn start_background_tasks(state: &Arc<GatewayState>, bg_handle: &tokio::runtime::Handle) {
    // Start health checks if load balancer is configured
    let config = state.config.load();
    if let Some(lb_config) = &config.load_balancer {
        if lb_config.enabled {
            // Shared with the load balancer, which skips unhealthy targets.
            let health_checker = state.plugin_runner.load_balancer.health.clone();
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
        let fallback_cert = auto_ssl
            .generate_fallback_cert()
            .expect("Failed to generate fallback certificate");
        Self {
            auto_ssl,
            fallback_cert,
        }
    }
}

impl rustls::server::ResolvesServerCert for SniCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
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
