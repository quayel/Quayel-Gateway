pub mod acme;
pub mod certificate;
pub mod challenge;

use acme::AcmeClient;
use certificate::{CertExpiryStatus, CertificateManager, CertMap};
use challenge::ChallengeStore;
use dashmap::{DashMap, DashSet};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
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
}

impl std::fmt::Debug for AutoSslManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoSslManager")
            .field("email", &self.email)
            .field("staging", &self.staging)
            .field("renewal_days_before", &self.renewal_days_before)
            .field("cert_count", &self.cert_map.len())
            .field("allowed_domains_count", &self.allowed_domains.blocking_read().len())
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
        }
    }

    /// Get a certificate for a domain (for SNI callback).
    /// Returns the real cert if available, otherwise the fallback.
    pub fn get_cert(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.cert_map.get(domain).map(|v| v.clone())
    }

    /// Check if a domain should trigger on-demand provisioning.
    /// Returns true if the domain is in the allowed list and needs provisioning.
    pub fn should_provision(&self, domain: &str) -> bool {
        // Check if domain is in allowed list
        {
            let allowed = self.allowed_domains.blocking_read();
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

    /// Trigger on-demand provisioning for a domain.
    /// This is called from the SNI callback when a TLS handshake arrives for an unknown domain.
    /// Uses dedup guard to ensure only one worker per domain.
    pub async fn provision_if_needed(
        self: &Arc<Self>,
        domain: String,
        bg_handle: &tokio::runtime::Handle,
    ) {
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
        let mut allowed = self.allowed_domains.write().await;
        *allowed = new_domains.into_iter().collect();
        info!(count = allowed.len(), "Updated allowed domains list");
    }

    /// Daily renewal check — renew expiring certs, retry one failed cert.
    pub async fn daily_renewal_check(
        self: &Arc<Self>,
        bg_handle: &tokio::runtime::Handle,
    ) {
        info!("Running daily cert renewal check");

        let allowed = self.allowed_domains.read().await;
        let domains: Vec<String> = allowed.iter().cloned().collect();
        drop(allowed);

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