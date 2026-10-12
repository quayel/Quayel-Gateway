use crate::auto_ssl::challenge::ChallengeStore;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tracing::{info, warn};

/// ACME v2 directory URLs
pub const LETS_ENCRYPT_PROD: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// How long to wait for the CA to validate challenges and to issue the cert.
const VALIDATION_POLICY: RetryPolicy = RetryPolicy::new()
    .initial_delay(Duration::from_secs(1))
    .backoff(1.5)
    .timeout(Duration::from_secs(120));

/// Error type for ACME operations
#[derive(Debug)]
pub enum AcmeError {
    Account(String),
    Protocol(String),
    ChallengeFailed(String),
    OrderFailed(String),
    CertificateFailed(String),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Account(e) => write!(f, "ACME account error: {}", e),
            AcmeError::Protocol(e) => write!(f, "ACME protocol error: {}", e),
            AcmeError::ChallengeFailed(e) => write!(f, "ACME challenge failed: {}", e),
            AcmeError::OrderFailed(e) => write!(f, "ACME order failed: {}", e),
            AcmeError::CertificateFailed(e) => write!(f, "ACME certificate error: {}", e),
        }
    }
}

impl From<instant_acme::Error> for AcmeError {
    fn from(e: instant_acme::Error) -> Self {
        AcmeError::Protocol(e.to_string())
    }
}

/// Result of a successful ACME provisioning
pub struct AcmeResult {
    pub cert_pem: String,
    pub key_pem: String,
}

/// ACME v2 client. One per `AutoSslManager`: the account is registered (or
/// loaded from disk) once and reused for every domain and renewal.
pub struct AcmeClient {
    directory_url: String,
    email: String,
    /// PEM file with the root CA of a private ACME server (e.g. Pebble, step-ca).
    /// `None` uses the system roots.
    ca_root: Option<PathBuf>,
    /// Where the account key and URL are persisted (0600).
    account_path: PathBuf,
    account: OnceCell<Account>,
}

impl AcmeClient {
    pub fn new(
        directory_url: &str,
        email: &str,
        ca_root: Option<&str>,
        storage_path: &Path,
    ) -> Self {
        Self {
            directory_url: directory_url.to_string(),
            email: email.to_string(),
            ca_root: ca_root.map(PathBuf::from),
            account_path: account_file(storage_path, directory_url),
            account: OnceCell::new(),
        }
    }

    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    fn builder(&self) -> Result<instant_acme::AccountBuilder, AcmeError> {
        // rustls has both ring and aws-lc-rs compiled in, so it won't pick a
        // provider by itself. Pingora installs one at server start; don't rely
        // on that ordering. Err just means one is already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        match &self.ca_root {
            Some(p) => Account::builder_with_root(p),
            None => Account::builder(),
        }
        .map_err(|e| AcmeError::Account(format!("HTTP client: {}", e)))
    }

    /// The ACME account: loaded from disk if present, otherwise registered
    /// once and saved, so every order and renewal uses the same key.
    async fn account(&self) -> Result<&Account, AcmeError> {
        self.account
            .get_or_try_init(|| async {
                if let Some(creds) = self.load_credentials() {
                    match self.builder()?.from_credentials(creds).await {
                        Ok(a) => {
                            info!(path = ?self.account_path, "Loaded ACME account");
                            return Ok(a);
                        }
                        Err(e) => {
                            warn!(error = %e, path = ?self.account_path,
                                "Stored ACME account unusable, registering a new one")
                        }
                    }
                }
                let contact = format!("mailto:{}", self.email);
                let contacts = [contact.as_str()];
                let (account, creds) = self
                    .builder()?
                    .create(
                        &NewAccount {
                            contact: if self.email.is_empty() {
                                &[]
                            } else {
                                &contacts
                            },
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        self.directory_url.clone(),
                        None,
                    )
                    .await
                    .map_err(|e| AcmeError::Account(e.to_string()))?;
                if let Err(e) = self.save_credentials(&creds) {
                    // Not fatal: we can still issue, we'll just register again next start.
                    warn!(error = %e, path = ?self.account_path, "Failed to save ACME account");
                }
                info!(email = %self.email, directory = %self.directory_url, "ACME account registered");
                Ok(account)
            })
            .await
    }

    fn load_credentials(&self) -> Option<AccountCredentials> {
        let data = std::fs::read(&self.account_path).ok()?;
        match serde_json::from_slice(&data) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(error = %e, path = ?self.account_path, "Ignoring unreadable ACME account file");
                None
            }
        }
    }

    fn save_credentials(&self, creds: &AccountCredentials) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(creds).map_err(|e| e.to_string())?;
        write_private(&self.account_path, &json)
    }

    /// Provision a certificate for one domain via HTTP-01.
    pub async fn provision_certificate(
        &self,
        domain: &str,
        challenge_store: &Arc<ChallengeStore>,
    ) -> Result<AcmeResult, AcmeError> {
        info!(domain = %domain, "Starting ACME certificate provisioning");
        let account = self.account().await?;

        let identifiers = [Identifier::Dns(domain.to_string())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| AcmeError::OrderFailed(e.to_string()))?;

        // Publish every pending HTTP-01 token, then tell the CA we're ready.
        let mut tokens = Vec::new();
        let ready = async {
            let mut authorizations = order.authorizations();
            while let Some(authz) = authorizations.next().await {
                let mut authz = authz?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => {
                        return Err(AcmeError::ChallengeFailed(format!(
                            "authorization is {:?}",
                            other
                        )))
                    }
                }
                let mut challenge = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                    AcmeError::ChallengeFailed("CA offered no http-01 challenge".to_string())
                })?;
                challenge_store.set_token(
                    challenge.token.clone(),
                    challenge.key_authorization().as_str().to_string(),
                );
                tokens.push(challenge.token.clone());
                challenge.set_ready().await?;
            }
            Ok(())
        }
        .await;

        let result = match ready {
            Ok(()) => self.finish_order(domain, &mut order).await,
            Err(e) => Err(e),
        };

        for token in &tokens {
            challenge_store.remove_token(token);
        }
        if result.is_ok() {
            info!(domain = %domain, "ACME certificate provisioned successfully");
        }
        result
    }

    async fn finish_order(
        &self,
        domain: &str,
        order: &mut instant_acme::Order,
    ) -> Result<AcmeResult, AcmeError> {
        let status = order
            .poll_ready(&VALIDATION_POLICY)
            .await
            .map_err(|e| AcmeError::ChallengeFailed(e.to_string()))?;
        if status != OrderStatus::Ready {
            return Err(AcmeError::ChallengeFailed(format!(
                "order is {:?} after validation",
                status
            )));
        }

        // Fresh ECDSA P-256 key per certificate; the CSR names only this domain.
        let key = rcgen::KeyPair::generate()
            .map_err(|e| AcmeError::CertificateFailed(format!("key generation: {}", e)))?;
        let params = rcgen::CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| AcmeError::CertificateFailed(format!("invalid domain: {}", e)))?;
        let csr = params
            .serialize_request(&key)
            .map_err(|e| AcmeError::CertificateFailed(format!("CSR: {}", e)))?;

        order
            .finalize_csr(csr.der())
            .await
            .map_err(|e| AcmeError::OrderFailed(format!("finalize: {}", e)))?;
        let cert_pem = order
            .poll_certificate(&VALIDATION_POLICY)
            .await
            .map_err(|e| AcmeError::CertificateFailed(e.to_string()))?;

        Ok(AcmeResult {
            cert_pem,
            key_pem: key.serialize_pem(),
        })
    }
}

/// One account file per ACME directory, so switching between staging,
/// production or a private CA never reuses the wrong account.
fn account_file(storage_path: &Path, directory_url: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(directory_url.as_bytes());
    let short: String = hash[..6].iter().map(|b| format!("{:02x}", b)).collect();
    storage_path.join(format!("acme-account-{}.json", short))
}

/// Write a file readable only by the owner (private keys, account credentials).
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {:?}: {}", dir, e))?;
    }
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("open {:?}: {}", tmp, e))?;
    f.write_all(data)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("write {:?}: {}", tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {:?}: {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_file_is_per_directory() {
        let dir = Path::new("/tmp/x");
        let a = account_file(dir, LETS_ENCRYPT_PROD);
        let b = account_file(dir, LETS_ENCRYPT_STAGING);
        assert_ne!(a, b);
        assert_eq!(a, account_file(dir, LETS_ENCRYPT_PROD));
        assert!(a.to_string_lossy().starts_with("/tmp/x/acme-account-"));
    }

    /// Talks to the real Let's Encrypt staging server, so it's opt-in:
    /// `cargo test le_staging -- --ignored`. Registers an account with no
    /// contact, then loads it back from disk.
    #[tokio::test]
    #[ignore]
    async fn le_staging_account_register_and_reload() {
        let dir = std::env::temp_dir().join(format!("qg-le-{}", std::process::id()));
        let client = AcmeClient::new(LETS_ENCRYPT_STAGING, "", None, &dir);
        let id = client.account().await.expect("register").id().to_string();
        assert!(id.starts_with("https://acme-staging-v02.api.letsencrypt.org/"));
        let again = AcmeClient::new(LETS_ENCRYPT_STAGING, "", None, &dir);
        assert_eq!(again.account().await.expect("reload").id(), id);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_private_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("qg-acme-{}", std::process::id()));
        let path = dir.join("secret.json");
        write_private(&path, b"{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
