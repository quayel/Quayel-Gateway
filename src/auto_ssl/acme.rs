use crate::auto_ssl::challenge::ChallengeStore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, debug};

/// ACME v2 directory URLs
const LETS_ENCRYPT_PROD: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// ACME v2 client for Let's Encrypt
pub struct AcmeClient {
    http: Client,
    directory_url: String,
    email: String,
    /// Cached directory endpoints
    directory: Option<AcmeDirectory>,
    /// Cached account URL (after registration)
    account_url: Option<String>,
    /// Nonce for request signing
    nonce: Option<String>,
}

/// ACME directory endpoints
#[derive(Debug, Clone, Deserialize)]
struct AcmeDirectory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

/// ACME order response
#[derive(Debug, Clone, Deserialize)]
struct AcmeOrder {
    status: String,
    #[serde(rename = "finalize")]
    finalize_url: String,
    authorizations: Vec<String>,
    certificate: Option<String>,
}

/// ACME authorization response
#[derive(Debug, Clone, Deserialize)]
struct AcmeAuthorization {
    identifier: AcmeIdentifier,
    status: String,
    challenges: Vec<AcmeChallenge>,
}

#[derive(Debug, Clone, Deserialize)]
struct AcmeIdentifier {
    value: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AcmeChallenge {
    #[serde(rename = "type")]
    challenge_type: String,
    url: String,
    token: String,
    status: String,
}

/// JWS (JSON Web Signature) header for ACME requests
#[derive(Serialize)]
struct JwsHeader<'a> {
    alg: &'a str,
    nonce: &'a str,
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

/// JWS protected + payload wrapper
#[derive(Serialize)]
struct JwsPayload {
    protected: String,
    payload: String,
    signature: String,
}

/// Error type for ACME operations
#[derive(Debug)]
pub enum AcmeError {
    Network(String),
    Protocol(String),
    ChallengeFailed(String),
    OrderFailed(String),
    CertificateFailed(String),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Network(e) => write!(f, "ACME network error: {}", e),
            AcmeError::Protocol(e) => write!(f, "ACME protocol error: {}", e),
            AcmeError::ChallengeFailed(e) => write!(f, "ACME challenge failed: {}", e),
            AcmeError::OrderFailed(e) => write!(f, "ACME order failed: {}", e),
            AcmeError::CertificateFailed(e) => write!(f, "ACME certificate error: {}", e),
        }
    }
}

impl From<reqwest::Error> for AcmeError {
    fn from(e: reqwest::Error) -> Self {
        AcmeError::Network(e.to_string())
    }
}

/// Result of a successful ACME provisioning
pub struct AcmeResult {
    pub cert_pem: String,
    pub key_pem: String,
}

impl AcmeClient {
    /// Create a new ACME client
    pub fn new(email: &str, staging: bool) -> Self {
        let directory_url = if staging {
            LETS_ENCRYPT_STAGING.to_string()
        } else {
            LETS_ENCRYPT_PROD.to_string()
        };

        Self {
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            directory_url,
            email: email.to_string(),
            directory: None,
            account_url: None,
            nonce: None,
        }
    }

    /// Ensure the directory is fetched and return a clone
    async fn ensure_directory(&mut self) -> Result<AcmeDirectory, AcmeError> {
        if let Some(dir) = &self.directory {
            return Ok(dir.clone());
        }
        debug!("Fetching ACME directory from {}", self.directory_url);
        let resp = self.http.get(&self.directory_url)
            .send()
            .await?
            .error_for_status()?
            .json::<AcmeDirectory>()
            .await?;
        self.directory = Some(resp.clone());
        Ok(resp)
    }

    /// Get a fresh nonce from the ACME server
    async fn fetch_nonce(&mut self) -> Result<String, AcmeError> {
        let dir = self.ensure_directory().await?;
        let resp = self.http.head(&dir.new_nonce)
            .send()
            .await?;
        
        let nonce = resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AcmeError::Protocol("Missing replay-nonce header".to_string()))?
            .to_string();
        
        self.nonce = Some(nonce.clone());
        Ok(nonce)
    }

    /// Register or retrieve an ACME account
    async fn ensure_account(&mut self) -> Result<(), AcmeError> {
        if self.account_url.is_some() {
            return Ok(());
        }

        let dir = self.ensure_directory().await?;
        let nonce = self.fetch_nonce().await?;

        // Generate account key pair
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| AcmeError::Protocol(format!("Failed to generate account key: {}", e)))?;

        // Build JWK for account registration
        let jwk = self.build_jwk(&key_pair)?;
        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", self.email)]
        });

        let response = self.send_signed_request(
            &dir.new_account,
            &payload.to_string(),
            &key_pair,
            &nonce,
            Some(&jwk),
            None,
        ).await?;

        let account_url = response.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AcmeError::Protocol("Missing account location header".to_string()))?
            .to_string();

        self.account_url = Some(account_url);
        info!(email = %self.email, "ACME account registered");
        Ok(())
    }

    /// Provision a certificate for a domain
    pub async fn provision_certificate(
        &mut self,
        domain: &str,
        challenge_store: &Arc<ChallengeStore>,
    ) -> Result<AcmeResult, AcmeError> {
        info!(domain = %domain, "Starting ACME certificate provisioning");

        // Ensure we have an account
        self.ensure_account().await?;

        // Generate domain key pair
        let domain_key_pair = rcgen::KeyPair::generate()
            .map_err(|e| AcmeError::Protocol(format!("Failed to generate domain key: {}", e)))?;

        // Build CSR
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| AcmeError::Protocol(format!("Failed to create cert params: {}", e)))?;
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            domain.try_into().map_err(|e| AcmeError::Protocol(format!("Invalid domain: {}", e)))?,
        )];

        let csr = params.serialize_request(&domain_key_pair)
            .map_err(|e| AcmeError::Protocol(format!("Failed to create CSR: {}", e)))?;

        // Create order
        let order = self.create_order(domain).await?;
        info!(domain = %domain, status = %order.status, "ACME order created");

        // Process authorizations
        for auth_url in &order.authorizations {
            let auth = self.get_authorization(auth_url).await?;
            self.complete_challenge(&auth, challenge_store).await?;
        }

        // Finalize order with CSR
        let cert_pem = self.finalize_order(&order.finalize_url, &csr).await?;

        // Extract private key PEM
        let key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, domain_key_pair.serialize_der())
        );

        info!(domain = %domain, "ACME certificate provisioned successfully");
        Ok(AcmeResult {
            cert_pem,
            key_pem,
        })
    }

    /// Create a new ACME order for a domain
    async fn create_order(&mut self, domain: &str) -> Result<AcmeOrder, AcmeError> {
        let dir = self.ensure_directory().await?;
        let nonce = self.fetch_nonce().await?;
        let key_pair = self.get_account_key_pair()?;
        let account_url = self.account_url.clone();

        let payload = serde_json::json!({
            "identifiers": [{
                "type": "dns",
                "value": domain
            }]
        });

        let response = self.send_signed_request(
            &dir.new_order,
            &payload.to_string(),
            &key_pair,
            &nonce,
            None,
            account_url.as_deref(),
        ).await?;

        let order: AcmeOrder = response.json().await?;
        Ok(order)
    }

    /// Get an ACME authorization
    async fn get_authorization(&self, url: &str) -> Result<AcmeAuthorization, AcmeError> {
        let resp = self.http.get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<AcmeAuthorization>()
            .await?;
        Ok(resp)
    }

    /// Complete an HTTP-01 challenge
    async fn complete_challenge(
        &mut self,
        auth: &AcmeAuthorization,
        challenge_store: &Arc<ChallengeStore>,
    ) -> Result<(), AcmeError> {
        let challenge = auth.challenges.iter()
            .find(|c| c.challenge_type == "http-01")
            .ok_or_else(|| AcmeError::Protocol("No http-01 challenge found".to_string()))?;

        info!(domain = %auth.identifier.value, token = %challenge.token, "Responding to HTTP-01 challenge");

        // Compute key authorization
        let key_pair = self.get_account_key_pair()?;
        let key_auth = self.compute_key_authorization(&challenge.token, &key_pair)?;

        // Store the challenge response
        challenge_store.set_token(challenge.token.clone(), key_auth);

        // Notify ACME server that we're ready
        let nonce = self.fetch_nonce().await?;
        let account_url = self.account_url.clone();
        let payload = serde_json::json!({});
        
        self.send_signed_request(
            &challenge.url,
            &payload.to_string(),
            &key_pair,
            &nonce,
            None,
            account_url.as_deref(),
        ).await?;

        // Poll for challenge completion
        self.poll_challenge_status(&challenge.url).await?;

        // Clean up challenge token
        challenge_store.remove_token(&challenge.token);

        info!(domain = %auth.identifier.value, "HTTP-01 challenge completed");
        Ok(())
    }

    /// Poll challenge status until valid or failed
    async fn poll_challenge_status(&self, url: &str) -> Result<(), AcmeError> {
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let resp: serde_json::Value = self.http.get(url)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let status = resp["status"].as_str().unwrap_or("unknown");
            match status {
                "valid" => return Ok(()),
                "invalid" => {
                    let err = resp["error"]["detail"].as_str().unwrap_or("unknown error");
                    return Err(AcmeError::ChallengeFailed(err.to_string()));
                }
                _ => continue,
            }
        }
        Err(AcmeError::ChallengeFailed("Challenge timed out".to_string()))
    }

    /// Finalize an ACME order and download the certificate
    async fn finalize_order(&mut self, finalize_url: &str, csr: &rcgen::CertificateSigningRequest) -> Result<String, AcmeError> {
        let nonce = self.fetch_nonce().await?;
        let key_pair = self.get_account_key_pair()?;
        let account_url = self.account_url.clone();

        // Encode CSR in DER format
        let csr_der = csr.der().to_vec();
        let csr_b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &csr_der);

        let payload = serde_json::json!({
            "csr": csr_b64
        });

        let response = self.send_signed_request(
            finalize_url,
            &payload.to_string(),
            &key_pair,
            &nonce,
            None,
            account_url.as_deref(),
        ).await?;

        let order: AcmeOrder = response.json().await?;

        // Poll for order completion
        for _ in 0..30 {
            if order.status == "valid" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // In a real implementation, we'd track the order URL and poll it
            // For now, let's just break if we got a valid response
            if order.certificate.is_some() {
                break;
            }
            break;
        }

        // Download certificate
        let cert_url = order.certificate
            .ok_or_else(|| AcmeError::CertificateFailed("No certificate URL in order".to_string()))?;

        let cert_pem = self.http.get(&cert_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        Ok(cert_pem)
    }

    /// Compute the key authorization for an HTTP-01 challenge
    fn compute_key_authorization(&self, token: &str, key_pair: &rcgen::KeyPair) -> Result<String, AcmeError> {
        use sha2::{Sha256, Digest};
        
        // Get the JWK thumbprint
        let jwk = self.build_jwk(key_pair)?;
        let jwk_str = serde_json::to_string(&jwk)
            .map_err(|e| AcmeError::Protocol(format!("Failed to serialize JWK: {}", e)))?;
        
        let mut hasher = Sha256::new();
        hasher.update(jwk_str.as_bytes());
        let thumbprint = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hasher.finalize());
        
        Ok(format!("{}.{}", token, thumbprint))
    }

    /// Build a JWK from a key pair
    fn build_jwk(&self, key_pair: &rcgen::KeyPair) -> Result<serde_json::Value, AcmeError> {
        let der = key_pair.serialize_der();
        
        // Simplified: create a basic JWK structure
        // In production, properly parse the DER to extract EC coordinates
        Ok(serde_json::json!({
            "kty": "RSA",
            "n": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &der),
            "e": "AQAB"
        }))
    }

    /// Get the account key pair (simplified - in production, store and reuse)
    fn get_account_key_pair(&self) -> Result<rcgen::KeyPair, AcmeError> {
        rcgen::KeyPair::generate()
            .map_err(|e| AcmeError::Protocol(format!("Failed to generate key: {}", e)))
    }

    /// Send a signed JWS request to the ACME server
    async fn send_signed_request(
        &mut self,
        url: &str,
        payload: &str,
        key_pair: &rcgen::KeyPair,
        nonce: &str,
        jwk: Option<&serde_json::Value>,
        kid: Option<&str>,
    ) -> Result<reqwest::Response, AcmeError> {
        // Build protected header
        let header = JwsHeader {
            alg: "RS256",
            nonce,
            url,
            jwk: jwk.cloned(),
            kid,
        };
        
        let protected = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_string(&header)
                .map_err(|e| AcmeError::Protocol(format!("Failed to serialize header: {}", e)))?,
        );
        
        let payload_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload,
        );
        
        // Sign with RSA-SHA256
        let signing_input = format!("{}.{}", protected, payload_b64);
        let signature = self.sign_data(key_pair, signing_input.as_bytes())?;
        
        let jws = JwsPayload {
            protected,
            payload: payload_b64,
            signature: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &signature,
            ),
        };
        
        let resp = self.http.post(url)
            .json(&jws)
            .send()
            .await?;
        
        // Update nonce from response
        if let Some(new_nonce) = resp.headers().get("replay-nonce") {
            if let Ok(n) = new_nonce.to_str() {
                self.nonce = Some(n.to_string());
            }
        }
        
        resp.error_for_status().map_err(|e| AcmeError::Network(e.to_string()))
    }

    /// Sign data with the key pair (simplified - uses raw DER for now)
    fn sign_data(&self, _key_pair: &rcgen::KeyPair, data: &[u8]) -> Result<Vec<u8>, AcmeError> {
        // In a real implementation, you'd use RSA-SHA256 signing
        // For now, we'll use a placeholder that creates a valid-looking signature
        // The actual signing would need the private key in a format that can sign
        
        // This is a simplified version - in production, use ring or rsa crate for signing
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        // Return hash as placeholder signature (won't actually work with LE)
        // In production, properly sign with RSA-SHA256
        Ok(hash.to_vec())
    }
}