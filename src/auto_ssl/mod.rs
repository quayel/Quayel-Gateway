pub mod acme;
pub mod certificate;
pub mod challenge;

use acme::AcmeClient;
use certificate::{CertExpiryStatus, CertificateManager, CertMap};
use challenge::ChallengeStore;
use dashmap::{DashMap, DashSet};
use rustls::sign::CertifiedKey;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{info, error};

/// Certificate provisioning state
#[derive(Debug, Clone)]
pub enum CertState {
    /// Certificate is valid and loaded
    Valid {
        expires_at: time::OffsetDateTime,
    },
    /// ACME provisioning in progress
    Pending,
    /// Provisioning failed
    Failed {
        error: String,
        failed_at: Instant,
        attempts: u32,
    },
    /// Certificate has expired
    Expired,
}

/// On-demand TLS certificate manager.
///
/// All runtime state lives in memory for fast lookups.
/// Disk is write-through cache for restart recovery only.
pub struct AutoSslManager {
    /// Domain → CertifiedKey (for SNI lookup, O(1))
    pub cert_map: CertMap,
    /// Domain → provisioning state
    pub cert_state: DashMap<String, CertState>,
    /// Allowed domains from config (whitelist)
    pub allowed_domains: RwLock<std::collections::HashSet<String>>,
    /// Dedup guard — one ACME worker per domain
    pub provisioning_set: DashSet<String>,
    /// HTTP-01 challenge token store
    pub challenge_store: Arc<ChallengeStore>,
    /// Certificate manager for PEM I/O
    pub cert_manager: CertificateManager,
    /// ACME email
    pub email: String,
    /// Use staging environment
    pub staging: bool,
    /// Renewal days before expiry
    pub renewal_days_before: u32,
    /// Background runtime handle for spawning ACME workers from sync contexts
    /// (the rustls SNI callback). Set once at startup via `set_bg_handle`.
    bg_handle: RwLock<Option<tokio::runtime::Handle>>,
}

impl std::fmt::Debug for AutoSslManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoSslManager")
            .field("email", &self.email)
            .field("staging", &self.staging)
            .field("renewal_days_before", &self.renewal_days_before)
            .field("cert_count", &self.cert_map.len())
            .field(
                "allowed_domains_count",
                &self.allowed_domains.read().map(|d| d.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl AutoSslManager {
    /// Create a new AutoSslManager from config
    pub fn new(
        email: &str,
        domains: &[String],
        cert_storage_path: &str,
        staging: bool,
        renewal_days_before: u32,
    ) -> Self {
        let cert_manager = CertificateManager::new(cert_storage_path);
        
        // Load cached certs from disk on startup
        let cert_map = cert_manager.load_all_cached_certs(domains);
        let loaded_count = cert_map.len();
        
        // Initialize cert states for loaded certs
        let cert_state = DashMap::new();
        for domain in domains {
            if cert_map.contains_key(domain) {
                // Check expiry of loaded cert
                if let Some((cert_pem, _)) = cert_manager.load_cert_from_disk(domain) {
                    match CertificateManager::check_expiry(&cert_pem, renewal_days_before) {
                        CertExpiryStatus::Valid { expires_at, .. } => {
                            cert_state.insert(domain.clone(), CertState::Valid { expires_at });
                        }
                        CertExpiryStatus::ExpiringSoon { .. } | CertExpiryStatus::Expired => {
                            cert_state.insert(domain.clone(), CertState::Expired);
                            // Remove from cert_map so it gets re-provisioned
                            cert_map.remove(domain);
                        }
                        CertExpiryStatus::ParseError => {
                            cert_state.insert(domain.clone(), CertState::Expired);
                            cert_map.remove(domain);
                        }
                    }
                }
            }
        }

        let allowed_domains: std::collections::HashSet<String> = domains.iter().cloned().collect();

        info!(
            loaded_certs = loaded_count,
            total_domains = domains.len(),
            "Auto-SSL manager initialized"
        );

        Self {
            cert_map,
            cert_state,
            allowed_domains: RwLock::new(allowed_domains),
            provisioning_set: DashSet::new(),
            challenge_store: Arc::new(ChallengeStore::new()),
            cert_manager,
            email: email.to_string(),
            staging,
            renewal_days_before,
            bg_handle: RwLock::new(None),
        }
    }

    /// Set the background runtime handle used to spawn ACME workers from sync
    /// contexts (the rustls SNI callback, which cannot call `tokio::spawn`).
    pub fn set_bg_handle(&self, handle: tokio::runtime::Handle) {
        *self
            .bg_handle
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(handle);
    }

    /// Get a certificate for a domain (for SNI callback).
    /// Returns the real cert if available, otherwise the fallback.
    pub fn get_cert(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.cert_map.get(domain).map(|v| v.clone())
    }

    /// Check if a domain should trigger on-demand provisioning.
    /// Returns true if the domain is in the allowed list and needs provisioning.
    pub fn should_provision(&self, domain: &str) -> bool {
        // Check if domain is in allowed list.
        // NOTE: this runs inside the tokio runtime (rustls SNI callback) — must never
        // use tokio's blocking_* APIs here. A std RwLock is safe: the critical section
        // is a hash-set lookup and is never held across an await point.
        {
            let allowed = self
                .allowed_domains
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if !allowed.contains(domain) {
                return false;
            }
        }

        // Check if already provisioning
        if self.provisioning_set.contains(domain) {
            return false;
        }

        // Check current state
        match self.cert_state.get(domain) {
            Some(state) => match state.value() {
                CertState::Valid { .. } => false, // Already have a valid cert
                CertState::Pending => false,      // Already being provisioned
                CertState::Failed { failed_at, .. } => {
                    // Only retry if 24h have passed
                    failed_at.elapsed() >= std::time::Duration::from_secs(24 * 60 * 60)
                }
                CertState::Expired => true, // Expired certs should be re-provisioned
            },
            None => true, // No state yet — need to provision
        }
    }

    /// Trigger on-demand provisioning for a domain (async entry point).
    /// Called from the daily renewal check. Uses dedup guard — one worker per domain.
    pub async fn provision_if_needed(
        self: &Arc<Self>,
        domain: String,
        bg_handle: &tokio::runtime::Handle,
    ) {
        self.start_provision(domain, bg_handle);
    }

    /// Sync entry point for on-demand provisioning, callable from the rustls SNI
    /// callback and `request_filter`. Checks `should_provision` first (cheap), then
    /// spawns the ACME worker on the background runtime. Never blocks the caller —
    /// the SNI callback runs on a tokio worker thread and must not block.
    pub fn trigger_provision_if_needed(self: &Arc<Self>, domain: &str) {
        if !self.should_provision(domain) {
            return;
        }
        let handle = self
            .bg_handle
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match handle {
            Some(h) => {
                info!(domain = %domain, "Domain needs cert provisioning — starting on-demand ACME worker");
                self.start_provision(domain.to_string(), &h);
            }
            None => {
                tracing::warn!(
                    domain = %domain,
                    "Cert provisioning needed but no background runtime handle is set — skipping"
                );
            }
        }
    }

    /// Dedup-guarded spawn of the ACME worker on `bg_handle`.
    fn start_provision(self: &Arc<Self>, domain: String, bg_handle: &tokio::runtime::Handle) {
        // Dedup check
        if !self.provisioning_set.insert(domain.clone()) {
            return; // Already provisioning
        }

        // Mark as pending
        self.cert_state.insert(domain.clone(), CertState::Pending);

        let manager = Arc::clone(self);
        let domain_clone = domain.clone();

        bg_handle.spawn(async move {
            info!(domain = %domain_clone, "Starting on-demand cert provisioning");

            let mut acme_client = AcmeClient::new(&manager.email, manager.staging);

            match acme_client.provision_certificate(&domain_clone, &manager.challenge_store).await {
                Ok(result) => {
                    // Parse and load the cert
                    match certificate::parse_pem_to_certified_key(&result.cert_pem, &result.key_pem) {
                        Ok(certified_key) => {
                            // Store in memory
                            let expires_at = match CertificateManager::check_expiry(&result.cert_pem, 0) {
                                CertExpiryStatus::Valid { expires_at, .. } => expires_at,
                                _ => time::OffsetDateTime::now_utc() + time::Duration::days(90),
                            };

                            manager.cert_map.insert(domain_clone.clone(), Arc::new(certified_key));
                            manager.cert_state.insert(domain_clone.clone(), CertState::Valid { expires_at });

                            // Write-through to disk (fire-and-forget)
                            let storage_domain = domain_clone.clone();
                            let cert_pem = result.cert_pem.clone();
                            let key_pem = result.key_pem.clone();
                            let storage_path = manager.cert_manager.storage_path.clone();
                            tokio::spawn(async move {
                                let cert_manager = CertificateManager::new(&storage_path.to_string_lossy());
                                if let Err(e) = cert_manager.save_cert(&storage_domain, &cert_pem, &key_pem) {
                                    error!(domain = %storage_domain, error = %e, "Failed to save cert to disk");
                                }
                            });

                            info!(domain = %domain_clone, "Cert provisioned and loaded successfully");
                        }
                        Err(e) => {
                            error!(domain = %domain_clone, error = %e, "Failed to parse provisioned cert");
                            manager.cert_state.insert(domain_clone.clone(), CertState::Failed {
                                error: e,
                                failed_at: Instant::now(),
                                attempts: 1,
                            });
                        }
                    }
                }
                Err(e) => {
                    error!(domain = %domain_clone, error = %e, "ACME provisioning failed");
                    manager.cert_state.insert(domain_clone.clone(), CertState::Failed {
                        error: e.to_string(),
                        failed_at: Instant::now(),
                        attempts: 1,
                    });
                }
            }

            // Remove from provisioning set
            manager.provisioning_set.remove(&domain_clone);
        });
    }

    /// Update the allowed domains list (called on config change).
    /// Does NOT trigger cert provisioning — that happens on first request.
    pub async fn update_allowed_domains(&self, new_domains: Vec<String>) {
        {
            let mut allowed = self
                .allowed_domains
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *allowed = new_domains.into_iter().collect();
            info!(count = allowed.len(), "Updated allowed domains list");
        }
    }

    /// Daily renewal check — renew expiring certs, retry one failed cert.
    pub async fn daily_renewal_check(
        self: &Arc<Self>,
        bg_handle: &tokio::runtime::Handle,
    ) {
        info!("Running daily cert renewal check");

        let domains: Vec<String> = {
            let allowed = self
                .allowed_domains
                .read()
                .unwrap_or_else(|e| e.into_inner());
            allowed.iter().cloned().collect()
        };

        let mut retried_failed = false;

        for domain in domains {
            // Check if cert needs renewal
            if let Some(state) = self.cert_state.get(&domain) {
                match state.value() {
                    CertState::Valid { expires_at } => {
                        let now = time::OffsetDateTime::now_utc();
                        let days_until_expiry = (*expires_at - now).whole_days();
                        if days_until_expiry <= self.renewal_days_before as i64 {
                            info!(domain = %domain, days_left = days_until_expiry, "Cert expiring soon, triggering renewal");
                            self.provision_if_needed(domain.clone(), bg_handle).await;
                        }
                    }
                    CertState::Expired => {
                        info!(domain = %domain, "Cert expired, triggering renewal");
                        self.provision_if_needed(domain.clone(), bg_handle).await;
                    }
                    CertState::Failed { failed_at, attempts, .. } => {
                        // Retry one failed cert per daily cycle
                        if !retried_failed && failed_at.elapsed() >= std::time::Duration::from_secs(24 * 60 * 60) {
                            info!(domain = %domain, attempts = attempts, "Retrying failed cert (daily cycle)");
                            self.provision_if_needed(domain.clone(), bg_handle).await;
                            retried_failed = true;
                        }
                    }
                    CertState::Pending => {
                        // Already being provisioned, skip
                    }
                }
            }
        }
    }

    /// Get the challenge store for HTTP-01 intercept
    pub fn get_challenge_store(&self) -> &Arc<ChallengeStore> {
        &self.challenge_store
    }

    /// Generate a default fallback cert for unknown domains
    pub fn generate_fallback_cert(&self) -> Result<CertifiedKey, String> {
        CertificateManager::generate_default_fallback()
    }

    /// Check if a path is an ACME challenge request
    pub fn is_challenge_request(path: &str) -> bool {
        ChallengeStore::is_challenge_path(path)
    }

    /// Get challenge response for a path
    pub fn get_challenge_response(&self, path: &str) -> Option<String> {
        ChallengeStore::extract_token(path)
            .and_then(|token| self.challenge_store.get_response(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the SNI-callback panic:
    /// `should_provision` runs inside the tokio runtime (rustls `ResolvesServerCert`
    /// is invoked during the TLS handshake on a runtime worker thread). It must not
    /// use tokio's blocking lock APIs — `blocking_read()` there aborts the process
    /// with "Cannot block the current thread from within a runtime".
    #[test]
    fn should_provision_works_inside_tokio_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");

        let manager = AutoSslManager::new(
            "test@example.com",
            &["example.com".to_string()],
            "/tmp/quayel-gateway-test-certs",
            true,
            30,
        );

        rt.block_on(async {
            // Before the fix: tokio::sync::RwLock::blocking_read() panicked here.
            assert!(manager.should_provision("example.com"));
            assert!(!manager.should_provision("not-allowed.example"));

            // And the Debug impl must be safe in runtime context too.
            let _ = format!("{:?}", manager);
        });
    }
}
