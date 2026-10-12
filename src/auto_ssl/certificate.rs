use dashmap::DashMap;
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

/// In-memory certificate store — domain → CertifiedKey (for SNI lookup)
pub type CertMap = DashMap<String, Arc<CertifiedKey>>;

/// Certificate manager: handles self-signed fallback, PEM I/O, and expiry parsing
pub struct CertificateManager {
    /// Storage path for PEM files on disk
    pub storage_path: PathBuf,
}

impl CertificateManager {
    pub fn new(storage_path: &str) -> Self {
        let path = PathBuf::from(storage_path);
        // Create directory if it doesn't exist
        if !path.exists() {
            if let Err(e) = std::fs::create_dir_all(&path) {
                error!("Failed to create cert storage directory {:?}: {}", path, e);
            } else {
                info!("Created cert storage directory: {:?}", path);
            }
        }
        Self { storage_path: path }
    }

    /// Generate a self-signed fallback certificate for a domain.
    /// Used when the real cert is not yet provisioned.
    pub fn generate_self_signed(domain: &str) -> Result<CertifiedKey, String> {
        let mut params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| format!("Failed to create cert params: {}", e))?;

        // Add SAN
        params.subject_alt_names = vec![SanType::DnsName(
            domain
                .try_into()
                .map_err(|e| format!("Invalid domain: {}", e))?,
        )];

        let key_pair =
            KeyPair::generate().map_err(|e| format!("Failed to generate key pair: {}", e))?;

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("Failed to self-sign cert: {}", e))?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let signing_key = rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(key_der)
            .map_err(|e| format!("Failed to load private key: {}", e))?;

        Ok(CertifiedKey::new(vec![cert_der], signing_key))
    }

    /// Generate a default self-signed certificate for unknown domains.
    /// This is the fallback served when a domain is not in the config.
    pub fn generate_default_fallback() -> Result<CertifiedKey, String> {
        Self::generate_self_signed("localhost")
    }

    /// Save certificate PEM files to disk (write-through cache).
    /// This is fire-and-forget — called after ACME provisioning succeeds.
    pub fn save_cert(&self, domain: &str, cert_pem: &str, key_pem: &str) -> Result<(), String> {
        let domain_dir = self.storage_path.join(sanitize_domain(domain));
        std::fs::create_dir_all(&domain_dir)
            .map_err(|e| format!("Failed to create domain dir: {}", e))?;

        let cert_path = domain_dir.join("cert.pem");
        let key_path = domain_dir.join("key.pem");

        std::fs::write(&cert_path, cert_pem)
            .map_err(|e| format!("Failed to write cert PEM: {}", e))?;
        // The private key must not be readable by other users.
        crate::auto_ssl::acme::write_private(&key_path, key_pem.as_bytes())
            .map_err(|e| format!("Failed to write key PEM: {}", e))?;

        info!("Saved cert for domain '{}' to {:?}", domain, domain_dir);
        Ok(())
    }

    /// Load a certificate from disk (startup only).
    /// Returns (cert_pem, key_pem) if the files exist.
    pub fn load_cert_from_disk(&self, domain: &str) -> Option<(String, String)> {
        let domain_dir = self.storage_path.join(sanitize_domain(domain));
        let cert_path = domain_dir.join("cert.pem");
        let key_path = domain_dir.join("key.pem");

        if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path).ok()?;
            let key_pem = std::fs::read_to_string(&key_path).ok()?;
            Some((cert_pem, key_pem))
        } else {
            None
        }
    }

    /// Load all cached certificates from disk into a CertMap.
    /// Called on startup to restore state from the write-through cache.
    pub fn load_all_cached_certs(&self, allowed_domains: &[String]) -> CertMap {
        let cert_map = CertMap::new();

        for domain in allowed_domains {
            if let Some((cert_pem, key_pem)) = self.load_cert_from_disk(domain) {
                match parse_pem_to_certified_key(&cert_pem, &key_pem) {
                    Ok(certified_key) => {
                        cert_map.insert(domain.clone(), Arc::new(certified_key));
                        info!("Loaded cached cert for domain '{}'", domain);
                    }
                    Err(e) => {
                        warn!("Failed to parse cached cert for '{}': {}", domain, e);
                    }
                }
            }
        }

        cert_map
    }

    /// Check if a certificate is expired or due for renewal. The renewal window is
    /// `days_before`, capped at a third of the cert's lifetime so short-lived certs
    /// (e.g. 6 days) aren't re-issued on every check.
    pub fn check_expiry(cert_pem: &str, days_before: u32) -> CertExpiryStatus {
        match x509_parser::pem::Pem::iter_from_buffer(cert_pem.as_bytes()).next() {
            Some(Ok(pem)) => match pem.parse_x509() {
                Ok(cert) => {
                    let not_before = cert.validity().not_before.to_datetime();
                    let not_after = cert.validity().not_after.to_datetime();
                    let now = time::OffsetDateTime::now_utc();
                    let renew_at = renewal_time(not_before, not_after, days_before);
                    let days_left = (not_after - now).whole_days().max(0) as u32;

                    if now >= not_after {
                        CertExpiryStatus::Expired
                    } else if now >= renew_at {
                        CertExpiryStatus::ExpiringSoon {
                            days_left,
                            expires_at: not_after,
                            renew_at,
                        }
                    } else {
                        CertExpiryStatus::Valid {
                            days_left,
                            expires_at: not_after,
                            renew_at,
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to parse x509 cert: {}", e);
                    CertExpiryStatus::ParseError
                }
            },
            _ => CertExpiryStatus::ParseError,
        }
    }
}

/// Parse PEM-encoded cert + key into a rustls CertifiedKey
pub fn parse_pem_to_certified_key(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey, String> {
    // Parse certificates
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse cert PEM: {}", e))?;

    if certs.is_empty() {
        return Err("No certificates found in PEM".to_string());
    }

    // Parse private key
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("Failed to parse key PEM: {}", e))?
        .ok_or("No private key found in PEM")?;

    let signing_key = rustls::crypto::ring::default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("Failed to load private key: {}", e))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

/// When to renew: `days_before` before expiry, but never earlier than two
/// thirds into the cert's lifetime (90-day cert → 30 days, 6-day cert → 2 days).
pub fn renewal_time(
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
    days_before: u32,
) -> time::OffsetDateTime {
    let window = time::Duration::days(days_before as i64).min((not_after - not_before) / 3);
    not_after - window
}

/// Sanitize domain name for use as a directory name
fn sanitize_domain(domain: &str) -> String {
    domain.replace('*', "_wildcard")
}

/// Certificate expiry status
#[derive(Debug, Clone)]
pub enum CertExpiryStatus {
    Valid {
        days_left: u32,
        expires_at: time::OffsetDateTime,
        renew_at: time::OffsetDateTime,
    },
    ExpiringSoon {
        days_left: u32,
        expires_at: time::OffsetDateTime,
        renew_at: time::OffsetDateTime,
    },
    Expired,
    ParseError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Duration, OffsetDateTime};

    #[test]
    fn renewal_window_is_capped_at_a_third_of_the_lifetime() {
        let start = OffsetDateTime::UNIX_EPOCH;
        // 90-day cert, 30-day setting: renew 30 days before expiry.
        let end = start + Duration::days(90);
        assert_eq!(renewal_time(start, end, 30), end - Duration::days(30));
        // 6-day cert, 30-day setting: renew 2 days before expiry, not immediately.
        let end = start + Duration::days(6);
        assert_eq!(renewal_time(start, end, 30), end - Duration::days(2));
        // A smaller setting wins.
        let end = start + Duration::days(90);
        assert_eq!(renewal_time(start, end, 7), end - Duration::days(7));
    }
}
