use crate::config::compiler::compile_config;
use crate::config::loader::load_config;
use crate::gateway::gateway::GatewayState;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

const CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Background config watcher.
/// Reads config.json every 5 seconds, checks if the SHA-256 hash changed.
/// If changed: validates and compiles the new config.
/// If valid: atomically swaps it into the running gateway.
/// If invalid: logs error, keeps old config, retries next cycle.
pub struct ConfigWatcher {
    config_path: String,
}

impl ConfigWatcher {
    pub fn new(config_path: String) -> Self {
        Self { config_path }
    }

    /// Start the watcher loop on the given Tokio runtime handle.
    pub fn start(self, state: Arc<GatewayState>, handle: tokio::runtime::Handle) {
        let handle_clone = handle.clone();
        handle.spawn(async move {
            // Seed with the file the gateway just started from, so the first
            // check doesn't recompile (and refetch JWKS for) an unchanged config.
            let mut last_hash: Option<Vec<u8>> = std::fs::read_to_string(&self.config_path)
                .ok()
                .map(|c| Sha256::digest(c.as_bytes()).to_vec());

            tracing::info!(
                path = %self.config_path,
                interval_secs = CHECK_INTERVAL.as_secs(),
                "Config watcher started"
            );

            loop {
                tokio::time::sleep(CHECK_INTERVAL).await;

                // Read file
                let content = match std::fs::read_to_string(&self.config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(
                            path = %self.config_path,
                            error = %e,
                            "Config watcher: cannot read file, will retry"
                        );
                        continue;
                    }
                };

                // Compute SHA-256 hash
                let mut hasher = Sha256::new();
                hasher.update(content.as_bytes());
                let hash = hasher.finalize().to_vec();

                if last_hash.as_deref() == Some(&hash) {
                    continue; // No change
                }

                tracing::info!(path = %self.config_path, "Config file changed, validating...");

                // Validate (parse + schema checks)
                let raw_config = match load_config(&self.config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(
                            path = %self.config_path,
                            error = %e,
                            "Config validation FAILED — keeping current config, will retry next cycle"
                        );
                        // Do NOT update last_hash so we retry next cycle
                        continue;
                    }
                };

                // Compile (conditions, regex, etc.)
                let compiled = match compile_config(&raw_config) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(
                            path = %self.config_path,
                            error = %e,
                            "Config compilation FAILED — keeping current config, will retry next cycle"
                        );
                        continue;
                    }
                };

                // Atomic swap
                let old_version = state.config.load().config_version.to_string();
                let new_version = compiled.config_version.to_string();

                // Update Auto-SSL allowed domains if configured
                if let Some(ref auto_ssl) = state.auto_ssl {
                    if let Some(ref ssl_config) = compiled.auto_ssl {
                        let domains = ssl_config.domains.clone();
                        let auto_ssl_clone = auto_ssl.clone();
                        handle_clone.spawn(async move {
                            auto_ssl_clone.update_allowed_domains(domains).await;
                        });
                    }
                }

                if compiled.streams.listen_addrs() != state.config.load().streams.listen_addrs() {
                    tracing::warn!(
                        "streams: listen addresses changed; new or moved listeners open after \
                         a restart (targets, rules and timeouts apply now)"
                    );
                }
                state.reload_logging(compiled.logging.as_ref(), &handle_clone);
                state.config.store(Arc::new(compiled));
                last_hash = Some(hash);

                tracing::info!(
                    path = %self.config_path,
                    old_version = %old_version,
                    new_version = %new_version,
                    "Config hot-reloaded successfully"
                );
            }
        });
    }
}
