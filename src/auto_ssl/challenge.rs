use dashmap::DashMap;
use tracing::debug;

/// HTTP-01 ACME challenge token store.
///
/// When Let's Encrypt needs to verify domain ownership, it requests a token at:
///   http://DOMAIN/.well-known/acme-challenge/TOKEN
///
/// The ACME client stores the token → key-authorization mapping here.
/// The HTTP handler serves the key-authorization when the challenge path is hit.
pub struct ChallengeStore {
    /// token → key_authorization
    tokens: DashMap<String, String>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            tokens: DashMap::new(),
        }
    }

    /// Store a challenge token and its key authorization.
    /// Called by the ACME client when responding to an HTTP-01 challenge.
    pub fn set_token(&self, token: String, key_authorization: String) {
        debug!(token = %token, "Stored ACME challenge token");
        self.tokens.insert(token, key_authorization);
    }

    /// Look up a challenge token's key authorization.
    /// Called by the HTTP handler when a request hits /.well-known/acme-challenge/:token
    pub fn get_response(&self, token: &str) -> Option<String> {
        self.tokens.get(token).map(|v| v.clone())
    }

    /// Remove a challenge token after it's been used or expired.
    pub fn remove_token(&self, token: &str) {
        self.tokens.remove(token);
        debug!(token = %token, "Removed ACME challenge token");
    }

    /// Check if a path is an ACME challenge request.
    pub fn is_challenge_path(path: &str) -> bool {
        path.starts_with("/.well-known/acme-challenge/")
    }

    /// Extract the token from a challenge path.
    /// Returns None if the path is not a challenge path.
    pub fn extract_token(path: &str) -> Option<&str> {
        if Self::is_challenge_path(path) {
            path.strip_prefix("/.well-known/acme-challenge/")
        } else {
            None
        }
    }

    /// Get the number of pending challenge tokens (for monitoring)
    pub fn pending_count(&self) -> usize {
        self.tokens.len()
    }
}