//! JWT verification for the `header.<name>.jwt.*` condition fields.
//!
//! Keys are defined once in the top-level `jwt` section. With no `jwt`
//! section, tokens are decoded without any check (the original behaviour).
//! With keys configured, claim fields only resolve for tokens that pass the
//! signature check plus `exp` / `nbf` / `iss` / `aud`; the
//! `jwt_valid` / `jwt_error` fields say why a token failed.
//!
//! Each key takes its material from exactly one source: a shared secret
//! (inline, env, file), a public key (inline PEM / base64 / list of lines,
//! env, file), an inline JWKS, or a JWKS URL that is fetched and refreshed in
//! the background.

use crate::config::schema::{JwtConfig, JwtKeyConfig, StringOrList};
use arc_swap::ArcSwap;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use parking_lot::{Condvar, Mutex};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Cached result of one token on one request: the verified (or, with no keys
/// configured, merely decoded) payload, or an error code.
pub type JwtOutcome = Result<Arc<Value>, &'static str>;

/// Minimum gap between refetches of a JWKS URL triggered by an unknown `kid`.
const FORCED_REFRESH_MIN_SECS: u64 = 30;
/// Retry delay while a JWKS URL has never loaded or its last fetch failed.
const RETRY_SECS: u64 = 30;
const DEFAULT_JWKS_REFRESH_SECS: u64 = 600;

// ── Compiled config ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct CompiledJwt {
    keys: Vec<CompiledJwtKey>,
}

impl std::fmt::Debug for CompiledJwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<&str> = self.keys.iter().map(|k| &*k.id).collect();
        f.debug_struct("CompiledJwt").field("keys", &ids).finish()
    }
}

#[derive(Clone)]
struct CompiledJwtKey {
    id: Arc<str>,
    /// Only tokens whose header `kid` equals this use the key.
    kid: Option<String>,
    /// One validation per allowed algorithm (jsonwebtoken checks every listed
    /// algorithm against the key's family, so they can't share one).
    validations: Vec<(Algorithm, Validation)>,
    source: KeySource,
}

#[derive(Clone)]
enum KeySource {
    Static(Arc<Vec<KeyEntry>>),
    Remote(Arc<JwksHandle>),
}

#[derive(Clone)]
struct KeyEntry {
    kid: Option<String>,
    /// Algorithm pinned by a JWK's `alg`, if it gave one.
    alg: Option<Algorithm>,
    family: Family,
    key: DecodingKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Hmac,
    Rsa,
    Ec,
    Ed,
}

fn family(alg: Algorithm) -> Family {
    use Algorithm::*;
    match alg {
        HS256 | HS384 | HS512 => Family::Hmac,
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => Family::Rsa,
        ES256 | ES384 => Family::Ec,
        EdDSA => Family::Ed,
    }
}

// ── Verification ─────────────────────────────────────────────────────────────

impl CompiledJwt {
    /// Verify a token against every configured key.
    ///
    /// The token's `alg` header only selects among the algorithms a key was
    /// configured with; it can never switch a key to another family (the
    /// HS256-with-an-RSA-public-key attack).
    pub fn verify(&self, token: &str) -> JwtOutcome {
        let header = jsonwebtoken::decode_header(token).map_err(|_| "malformed")?;
        let token_kid = header.kid.as_deref();

        let mut alg_allowed = false;
        let mut keys_unavailable = false;
        let mut tried_signature = false;
        let mut claim_error: Option<&'static str> = None;

        for key in &self.keys {
            let Some((_, validation)) = key.validations.iter().find(|(a, _)| *a == header.alg)
            else {
                continue;
            };
            alg_allowed = true;
            if let Some(kid) = &key.kid {
                if token_kid != Some(kid.as_str()) {
                    continue;
                }
            }

            let entries = match &key.source {
                KeySource::Static(e) => Arc::clone(e),
                KeySource::Remote(h) => match h.snapshot() {
                    Some(e) => e,
                    None => {
                        keys_unavailable = true;
                        continue;
                    }
                },
            };

            let mut matched_entry = false;
            for entry in entries.iter() {
                if entry.family != family(header.alg) {
                    continue;
                }
                if entry.alg.is_some_and(|a| a != header.alg) {
                    continue;
                }
                if let (Some(want), Some(have)) = (token_kid, entry.kid.as_deref()) {
                    if want != have {
                        continue;
                    }
                }
                matched_entry = true;
                tried_signature = true;
                match jsonwebtoken::decode::<Value>(token, &entry.key, validation) {
                    Ok(data) => return Ok(Arc::new(data.claims)),
                    // Signature didn't verify with this key: try the next one.
                    Err(e)
                        if matches!(
                            e.kind(),
                            jsonwebtoken::errors::ErrorKind::InvalidSignature
                        ) => {}
                    // Signature verified but a claim check failed. Keep looking
                    // (another key may have a different issuer/audience), but
                    // remember the most specific reason.
                    Err(e) => {
                        claim_error.get_or_insert(error_code(e.kind()));
                    }
                }
            }

            if !matched_entry {
                if let KeySource::Remote(h) = &key.source {
                    // Possibly a rotated key: ask for an early refetch.
                    h.request_refresh();
                }
            }
        }

        Err(if let Some(e) = claim_error {
            e
        } else if tried_signature {
            "bad_signature"
        } else if !alg_allowed {
            "alg_not_allowed"
        } else if keys_unavailable {
            "keys_unavailable"
        } else {
            "unknown_kid"
        })
    }
}

fn error_code(kind: &jsonwebtoken::errors::ErrorKind) -> &'static str {
    use jsonwebtoken::errors::ErrorKind::*;
    match kind {
        InvalidSignature => "bad_signature",
        ExpiredSignature => "expired",
        ImmatureSignature => "not_yet_valid",
        InvalidIssuer => "wrong_issuer",
        InvalidAudience => "wrong_audience",
        InvalidSubject => "wrong_subject",
        MissingRequiredClaim(_) => "missing_claim",
        InvalidAlgorithm | InvalidAlgorithmName => "alg_not_allowed",
        InvalidToken | Base64(_) | Json(_) | Utf8(_) => "malformed",
        _ => "invalid",
    }
}

/// Decode the payload without any check (used when no keys are configured).
pub fn decode_unverified(token: &str) -> JwtOutcome {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload_b64 = token.split('.').nth(1).ok_or("malformed")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload_b64.trim_end_matches('='))
        .map_err(|_| "malformed")?;
    let payload: Value = serde_json::from_slice(&bytes).map_err(|_| "malformed")?;
    Ok(Arc::new(payload))
}

// ── Compiler ─────────────────────────────────────────────────────────────────

const ALLOWED_REQUIRED_CLAIMS: &[&str] = &["exp", "nbf", "iss", "aud", "sub"];

pub fn compile_jwt(c: &JwtConfig) -> Result<Option<CompiledJwt>, String> {
    if !c.enabled {
        return Ok(None);
    }
    if c.keys.is_empty() {
        return Err("jwt: `keys` is empty (remove the `jwt` section to decode tokens without checking them)".into());
    }
    for claim in &c.required_claims {
        if !ALLOWED_REQUIRED_CLAIMS.contains(&claim.as_str()) {
            return Err(format!(
                "jwt.required_claims: unknown claim `{}` (allowed: {})",
                claim,
                ALLOWED_REQUIRED_CLAIMS.join(", ")
            ));
        }
    }

    let mut seen = std::collections::HashSet::new();
    let mut keys = Vec::with_capacity(c.keys.len());
    for k in &c.keys {
        if k.id.trim().is_empty() {
            return Err("jwt.keys: every key needs a non-empty `id`".into());
        }
        if !seen.insert(k.id.as_str()) {
            return Err(format!("jwt.keys: duplicate id `{}`", k.id));
        }
        keys.push(compile_key(k, c).map_err(|e| format!("jwt key `{}`: {}", k.id, e))?);
    }
    Ok(Some(CompiledJwt { keys }))
}

fn compile_key(k: &JwtKeyConfig, c: &JwtConfig) -> Result<CompiledJwtKey, String> {
    if k.algorithms.is_empty() {
        return Err("`algorithms` is required (e.g. [\"RS256\"])".into());
    }
    let mut algorithms = Vec::new();
    for a in &k.algorithms {
        let alg = Algorithm::from_str(a).map_err(|_| {
            format!("unknown algorithm `{a}` (use HS256/384/512, RS256/384/512, PS256/384/512, ES256/384 or EdDSA)")
        })?;
        if !algorithms.contains(&alg) {
            algorithms.push(alg);
        }
    }

    let sources = [
        ("secret", k.secret.is_some()),
        ("secret_env", k.secret_env.is_some()),
        ("secret_file", k.secret_file.is_some()),
        ("public_key", k.public_key.is_some()),
        ("public_key_env", k.public_key_env.is_some()),
        ("public_key_file", k.public_key_file.is_some()),
        ("jwks", k.jwks.is_some()),
        ("jwks_url", k.jwks_url.is_some()),
    ];
    let set: Vec<&str> = sources
        .iter()
        .filter(|(_, s)| *s)
        .map(|(n, _)| *n)
        .collect();
    match set.len() {
        0 => return Err("no key source; set one of secret, secret_env, secret_file, public_key, public_key_env, public_key_file, jwks, jwks_url".into()),
        1 => {}
        _ => return Err(format!("set exactly one key source, found: {}", set.join(", "))),
    }
    if k.jwks_refresh_secs.is_some() && k.jwks_url.is_none() {
        return Err("`jwks_refresh_secs` only applies to `jwks_url`".into());
    }

    let families: Vec<Family> = algorithms.iter().map(|a| family(*a)).collect();
    let single_family = || -> Result<Family, String> {
        let f = families[0];
        if families.iter().any(|x| *x != f) {
            return Err("all `algorithms` of a secret or public key must be the same kind (HS*, RS*/PS*, ES* or EdDSA)".into());
        }
        Ok(f)
    };

    let source = if k.secret.is_some() || k.secret_env.is_some() || k.secret_file.is_some() {
        if single_family()? != Family::Hmac {
            return Err(
                "a secret only works with HS256/HS384/HS512; RS/PS/ES/EdDSA need a public key"
                    .into(),
            );
        }
        let secret = if let Some(s) = &k.secret {
            tracing::warn!(
                key = %k.id,
                "jwt key has an inline `secret` in the config file; prefer `secret_env` or `secret_file`"
            );
            s.clone()
        } else if let Some(var) = &k.secret_env {
            read_env(var)?
        } else {
            read_file(k.secret_file.as_deref().unwrap())?
                .trim_end_matches(['\r', '\n'])
                .to_string()
        };
        if secret.is_empty() {
            return Err("secret is empty".into());
        }
        KeySource::Static(Arc::new(vec![KeyEntry {
            kid: None,
            alg: None,
            family: Family::Hmac,
            key: DecodingKey::from_secret(secret.as_bytes()),
        }]))
    } else if k.public_key.is_some() || k.public_key_env.is_some() || k.public_key_file.is_some() {
        let raw = if let Some(p) = &k.public_key {
            match p {
                StringOrList::One(s) => s.clone(),
                StringOrList::Many(lines) => lines.join("\n"),
            }
        } else if let Some(var) = &k.public_key_env {
            read_env(var)?
        } else {
            read_file(k.public_key_file.as_deref().unwrap())?
        };
        let f = single_family()?;
        if f == Family::Hmac {
            return Err("HS256/HS384/HS512 need a secret, not a public key".into());
        }
        let key = parse_public_key(&raw, f)?;
        KeySource::Static(Arc::new(vec![KeyEntry {
            kid: None,
            alg: None,
            family: f,
            key,
        }]))
    } else if let Some(jwks) = &k.jwks {
        let entries = parse_jwks(jwks)?;
        if entries.is_empty() {
            return Err("`jwks` has no usable keys".into());
        }
        KeySource::Static(Arc::new(entries))
    } else {
        let url = k.jwks_url.as_deref().unwrap();
        check_jwks_url(url)?;
        let refresh = k.jwks_refresh_secs.unwrap_or(DEFAULT_JWKS_REFRESH_SECS);
        if refresh < 60 {
            return Err("`jwks_refresh_secs` must be at least 60".into());
        }
        KeySource::Remote(JwksHandle::get_or_start(url, refresh))
    };

    let issuers: Option<Vec<String>> = k.issuer.as_ref().map(|i| i.to_vec());
    let audiences: Option<Vec<String>> = k.audience.as_ref().map(|a| a.to_vec());
    let validations = algorithms
        .iter()
        .map(|alg| {
            let mut v = Validation::new(*alg);
            v.leeway = c.leeway_secs;
            v.validate_exp = true;
            v.validate_nbf = true;
            v.set_required_spec_claims(&c.required_claims);
            if let Some(i) = &issuers {
                v.set_issuer(i);
            }
            match &audiences {
                Some(a) => v.set_audience(a),
                None => v.validate_aud = false,
            }
            (*alg, v)
        })
        .collect();

    Ok(CompiledJwtKey {
        id: Arc::from(k.id.as_str()),
        kid: k.kid.clone(),
        validations,
        source,
    })
}

fn read_env(var: &str) -> Result<String, String> {
    std::env::var(var).map_err(|_| format!("environment variable `{var}` is not set"))
}

fn read_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("can't read `{path}`: {e}"))
}

/// Accept a pasted public key in any of the forms people actually paste:
/// a full PEM (with real or `\n`-escaped line breaks), only the base64 body,
/// or a certificate. Private keys are refused.
fn parse_public_key(raw: &str, f: Family) -> Result<DecodingKey, String> {
    let mut text = raw.trim().replace("\\n", "\n").replace("\r\n", "\n");
    if text.contains("PRIVATE KEY") {
        return Err("this is a PRIVATE key; paste the PUBLIC key (the gateway only verifies tokens and must never hold the signing key)".into());
    }
    if !text.contains("-----BEGIN") {
        let body: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if body.is_empty() {
            return Err("public key is empty".into());
        }
        let lines: Vec<String> = body
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        text = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            lines.join("\n")
        );
    }
    let res = match f {
        Family::Rsa => DecodingKey::from_rsa_pem(text.as_bytes()),
        Family::Ec => DecodingKey::from_ec_pem(text.as_bytes()),
        Family::Ed => DecodingKey::from_ed_pem(text.as_bytes()),
        Family::Hmac => return Err("HS256/HS384/HS512 need a secret, not a public key".into()),
    };
    res.map_err(|e| {
        let want = match f {
            Family::Rsa => "an RSA public key (RS*/PS*)",
            Family::Ec => "an EC public key (ES*)",
            Family::Ed => "an Ed25519 public key (EdDSA)",
            Family::Hmac => "",
        };
        format!("can't read public key as {want}: {e}")
    })
}

/// Parse a JWKS document. Keys that can't be used for verification
/// (encryption keys, unsupported types) are skipped with a warning rather
/// than failing the whole set, as identity providers often publish extras.
fn parse_jwks(doc: &Value) -> Result<Vec<KeyEntry>, String> {
    let keys = doc
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or("JWKS must be an object with a `keys` array")?;
    let mut out = Vec::new();
    for (i, raw) in keys.iter().enumerate() {
        if raw
            .get("use")
            .and_then(|u| u.as_str())
            .is_some_and(|u| u != "sig")
        {
            continue;
        }
        let jwk: Jwk = match serde_json::from_value(raw.clone()) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(index = i, error = %e, "skipping unreadable JWKS key");
                continue;
            }
        };
        let fam = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => Family::Rsa,
            AlgorithmParameters::EllipticCurve(_) => Family::Ec,
            AlgorithmParameters::OctetKeyPair(_) => Family::Ed,
            AlgorithmParameters::OctetKey(_) => Family::Hmac,
        };
        let alg = match &jwk.common.key_algorithm {
            Some(ka) => match Algorithm::from_str(&ka.to_string()) {
                Ok(a) => Some(a),
                // An encryption algorithm (RSA-OAEP etc.): not a signing key.
                Err(_) => continue,
            },
            None => None,
        };
        match DecodingKey::from_jwk(&jwk) {
            Ok(key) => out.push(KeyEntry {
                kid: jwk.common.key_id.clone(),
                alg,
                family: fam,
                key,
            }),
            Err(e) => tracing::warn!(index = i, error = %e, "skipping unusable JWKS key"),
        }
    }
    Ok(out)
}

fn check_jwks_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = lower.strip_prefix("http://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
        if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
            return Ok(());
        }
    }
    Err(format!(
        "`jwks_url` must use https:// (plain http is only allowed for localhost): {url}"
    ))
}

// ── JWKS URL fetcher ─────────────────────────────────────────────────────────
// One background thread per URL. Configs hold strong references to the
// handle; the registry and the thread hold weak ones, so a URL that a config
// reload drops stops being fetched. A reload that keeps the URL reuses the
// already-loaded keys.

pub struct JwksHandle {
    url: String,
    keys: ArcSwap<Option<Arc<Vec<KeyEntry>>>>,
    signal: Arc<RefreshSignal>,
    last_forced: AtomicU64,
}

#[derive(Default)]
struct RefreshSignal {
    wake: Mutex<bool>,
    cv: Condvar,
}

static JWKS_REGISTRY: OnceLock<Mutex<HashMap<String, Weak<JwksHandle>>>> = OnceLock::new();

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl JwksHandle {
    fn get_or_start(url: &str, refresh_secs: u64) -> Arc<JwksHandle> {
        let registry = JWKS_REGISTRY.get_or_init(Default::default);
        let mut map = registry.lock();
        map.retain(|_, w| w.strong_count() > 0);
        let reg_key = format!("{refresh_secs} {url}");
        if let Some(h) = map.get(&reg_key).and_then(|w| w.upgrade()) {
            return h;
        }
        let handle = Arc::new(JwksHandle {
            url: url.to_string(),
            keys: ArcSwap::from_pointee(None),
            signal: Arc::new(RefreshSignal::default()),
            last_forced: AtomicU64::new(0),
        });
        map.insert(reg_key, Arc::downgrade(&handle));
        spawn_fetcher(
            Arc::downgrade(&handle),
            Arc::clone(&handle.signal),
            url.to_string(),
            refresh_secs,
        );
        handle
    }

    fn snapshot(&self) -> Option<Arc<Vec<KeyEntry>>> {
        self.keys.load().as_ref().clone()
    }

    /// Wake the fetcher early (unknown `kid`), at most once every 30 s so
    /// junk tokens can't flood the identity provider.
    fn request_refresh(&self) {
        let now = now_secs();
        let last = self.last_forced.load(Ordering::Relaxed);
        if now.saturating_sub(last) < FORCED_REFRESH_MIN_SECS {
            return;
        }
        if self
            .last_forced
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            *self.signal.wake.lock() = true;
            self.signal.cv.notify_one();
        }
    }
}

fn spawn_fetcher(
    handle: Weak<JwksHandle>,
    signal: Arc<RefreshSignal>,
    url: String,
    refresh_secs: u64,
) {
    let spawned = std::thread::Builder::new()
        .name("quayel-jwks".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(url = %url, error = %e, "jwks: can't start fetcher runtime");
                    return;
                }
            };
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent(concat!("quayel-gateway/", env!("CARGO_PKG_VERSION")))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(url = %url, error = %e, "jwks: can't build HTTP client");
                    return;
                }
            };
            loop {
                if handle.strong_count() == 0 {
                    return;
                }
                let wait = match rt.block_on(fetch_jwks(&client, &url)) {
                    Ok((entries, max_age)) => {
                        let Some(h) = handle.upgrade() else { return };
                        tracing::info!(url = %url, keys = entries.len(), "jwks: loaded");
                        h.keys.store(Arc::new(Some(Arc::new(entries))));
                        max_age.map(|m| m.clamp(60, 86_400)).unwrap_or(refresh_secs)
                    }
                    Err(e) => {
                        // Keep the last good key set; retry sooner.
                        tracing::warn!(url = %url, error = %e, "jwks: fetch failed, keeping previous keys");
                        RETRY_SECS.min(refresh_secs)
                    }
                };
                let mut woken = signal.wake.lock();
                if !*woken {
                    signal.cv.wait_for(&mut woken, Duration::from_secs(wait));
                }
                *woken = false;
            }
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "jwks: can't spawn fetcher thread");
    }
}

async fn fetch_jwks(
    client: &reqwest::Client,
    url: &str,
) -> Result<(Vec<KeyEntry>, Option<u64>), String> {
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let max_age = resp
        .headers()
        .get(http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .and_then(|cc| {
            cc.split(',')
                .filter_map(|d| d.trim().strip_prefix("max-age="))
                .next()
                .and_then(|n| n.parse::<u64>().ok())
        });
    let doc: Value = resp.json().await.map_err(|e| format!("not JSON: {e}"))?;
    let entries = parse_jwks(&doc)?;
    if entries.is_empty() {
        return Err("JWKS has no usable signing keys".into());
    }
    Ok((entries, max_age))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::request_context::RequestContext;
    use crate::plugins::firewall::resolve_condition_value;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    const RSA_PRIV: &str = include_str!("../tests/fixtures/jwt/rsa_private.pem");
    const RSA_PUB: &str = include_str!("../tests/fixtures/jwt/rsa_public.pem");
    const RSA_PUB_PKCS1: &str = include_str!("../tests/fixtures/jwt/rsa_public_pkcs1.pem");
    const RSA_CERT: &str = include_str!("../tests/fixtures/jwt/rsa_cert.pem");
    const RSA2_PRIV: &str = include_str!("../tests/fixtures/jwt/rsa2_private.pem");
    const EC_PRIV: &str = include_str!("../tests/fixtures/jwt/ec_private.pem");
    const EC_PUB: &str = include_str!("../tests/fixtures/jwt/ec_public.pem");
    const ED_PRIV: &str = include_str!("../tests/fixtures/jwt/ed_private.pem");
    const ED_PUB: &str = include_str!("../tests/fixtures/jwt/ed_public.pem");

    fn now() -> i64 {
        now_secs() as i64
    }

    fn compile(cfg: Value) -> Result<CompiledJwt, String> {
        let c: JwtConfig = serde_json::from_value(cfg).map_err(|e| e.to_string())?;
        compile_jwt(&c).map(|o| o.expect("enabled"))
    }

    fn rs_token(priv_pem: &str, alg: Algorithm, kid: Option<&str>, claims: Value) -> String {
        let mut h = Header::new(alg);
        h.kid = kid.map(String::from);
        encode(
            &h,
            &claims,
            &EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn hs_token(secret: &str, claims: Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn good_claims() -> Value {
        json!({ "sub": "u1", "exp": now() + 600, "data": { "role": "admin" } })
    }

    fn rsa_cfg(public_key: Value) -> Value {
        json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "public_key": public_key }] })
    }

    // ── Key sources and pasting formats ──────────────────────────────────

    #[test]
    fn rs256_accepts_every_paste_format() {
        let token = rs_token(RSA_PRIV, Algorithm::RS256, None, good_claims());
        let body: String = RSA_PUB
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let escaped = RSA_PUB.trim().replace('\n', "\\n");
        let lines: Vec<&str> = RSA_PUB.lines().collect();
        for (name, pk) in [
            ("pem", json!(RSA_PUB)),
            ("escaped newlines", json!(escaped)),
            ("base64 body only", json!(body)),
            ("list of lines", json!(lines)),
            ("pkcs1 RSA PUBLIC KEY", json!(RSA_PUB_PKCS1)),
            ("certificate", json!(RSA_CERT)),
        ] {
            let jwt = compile(rsa_cfg(pk)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(jwt.verify(&token).is_ok(), "{name} should verify");
        }
    }

    #[test]
    fn public_key_from_env_and_file() {
        let token = rs_token(RSA_PRIV, Algorithm::RS256, None, good_claims());
        std::env::set_var("QG_TEST_JWT_PUB", RSA_PUB);
        let jwt = compile(json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "public_key_env": "QG_TEST_JWT_PUB" }] })).unwrap();
        assert!(jwt.verify(&token).is_ok());
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/jwt/rsa_public.pem"
        );
        let jwt = compile(
            json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "public_key_file": path }] }),
        )
        .unwrap();
        assert!(jwt.verify(&token).is_ok());
    }

    #[test]
    fn hs256_secret_inline_env_file() {
        let token = hs_token("s3cret", good_claims());
        let jwt = compile(
            json!({ "keys": [{ "id": "k", "algorithms": ["HS256"], "secret": "s3cret" }] }),
        )
        .unwrap();
        assert!(jwt.verify(&token).is_ok());
        std::env::set_var("QG_TEST_JWT_SECRET", "s3cret");
        let jwt = compile(json!({ "keys": [{ "id": "k", "algorithms": ["HS256"], "secret_env": "QG_TEST_JWT_SECRET" }] })).unwrap();
        assert!(jwt.verify(&token).is_ok());
        let dir = std::env::temp_dir().join("qg-jwt-secret-test");
        std::fs::write(&dir, "s3cret\n").unwrap();
        let jwt = compile(json!({ "keys": [{ "id": "k", "algorithms": ["HS256"], "secret_file": dir.to_str().unwrap() }] })).unwrap();
        assert!(
            jwt.verify(&token).is_ok(),
            "trailing newline in a secret file is ignored"
        );
        assert_eq!(
            jwt.verify(&hs_token("other", good_claims())).unwrap_err(),
            "bad_signature"
        );
    }

    #[test]
    fn es256_and_eddsa() {
        let claims = good_claims();
        let es = encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &EncodingKey::from_ec_pem(EC_PRIV.as_bytes()).unwrap(),
        )
        .unwrap();
        let jwt = compile(
            json!({ "keys": [{ "id": "k", "algorithms": ["ES256"], "public_key": EC_PUB }] }),
        )
        .unwrap();
        assert!(jwt.verify(&es).is_ok());
        let ed = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(ED_PRIV.as_bytes()).unwrap(),
        )
        .unwrap();
        let jwt = compile(
            json!({ "keys": [{ "id": "k", "algorithms": ["EdDSA"], "public_key": ED_PUB }] }),
        )
        .unwrap();
        assert!(jwt.verify(&ed).is_ok());
    }

    #[test]
    fn inline_jwks_matches_kid() {
        let token = rs_token(RSA_PRIV, Algorithm::RS256, Some("k1"), good_claims());
        let jwks = rsa_jwks("k1");
        let jwt =
            compile(json!({ "keys": [{ "id": "set", "algorithms": ["RS256"], "jwks": jwks }] }))
                .unwrap();
        assert!(jwt.verify(&token).is_ok());
        let other_kid = rs_token(RSA_PRIV, Algorithm::RS256, Some("k9"), good_claims());
        assert_eq!(jwt.verify(&other_kid).unwrap_err(), "unknown_kid");
    }

    /// JWKS for the fixture RSA key: `n` and `e` read from the PKCS#1 DER.
    /// The first entry is an encryption key that must be skipped.
    fn rsa_jwks(kid: &str) -> Value {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use base64::Engine;
        let b64: String = RSA_PUB_PKCS1
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = STANDARD.decode(b64).unwrap();
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let (n, rest) = read_der_int(&der[seq_body_offset(&der)..]);
        let (e, _) = read_der_int(rest);
        let strip = |b: &[u8]| {
            b.iter()
                .skip_while(|x| **x == 0)
                .copied()
                .collect::<Vec<u8>>()
        };
        json!({ "keys": [
            { "kty": "RSA", "use": "enc", "kid": "enc-key", "n": URL_SAFE_NO_PAD.encode(strip(n)), "e": URL_SAFE_NO_PAD.encode(strip(e)) },
            { "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": URL_SAFE_NO_PAD.encode(strip(n)), "e": URL_SAFE_NO_PAD.encode(strip(e)) }
        ]})
    }

    fn der_len(b: &[u8]) -> (usize, usize) {
        if b[0] & 0x80 == 0 {
            (b[0] as usize, 1)
        } else {
            let n = (b[0] & 0x7f) as usize;
            (
                b[1..=n].iter().fold(0usize, |a, x| (a << 8) | *x as usize),
                1 + n,
            )
        }
    }

    fn seq_body_offset(der: &[u8]) -> usize {
        1 + der_len(&der[1..]).1
    }

    fn read_der_int(b: &[u8]) -> (&[u8], &[u8]) {
        assert_eq!(b[0], 0x02);
        let (len, hdr) = der_len(&b[1..]);
        let start = 1 + hdr;
        (&b[start..start + len], &b[start + len..])
    }

    // ── Claim checks ─────────────────────────────────────────────────────

    #[test]
    fn claim_checks() {
        let jwt = compile(json!({ "leeway_secs": 0, "keys": [{
            "id": "k", "algorithms": ["HS256"], "secret": "s",
            "issuer": ["https://a.example", "https://b.example"], "audience": "api" }] }))
        .unwrap();
        let ok = json!({ "exp": now() + 60, "iss": "https://b.example", "aud": "api" });
        assert!(jwt.verify(&hs_token("s", ok)).is_ok());
        let cases = [
            (
                json!({ "exp": now() - 60, "iss": "https://a.example", "aud": "api" }),
                "expired",
            ),
            (
                json!({ "exp": now() + 60, "nbf": now() + 600, "iss": "https://a.example", "aud": "api" }),
                "not_yet_valid",
            ),
            (
                json!({ "exp": now() + 60, "iss": "https://evil.example", "aud": "api" }),
                "wrong_issuer",
            ),
            (
                json!({ "exp": now() + 60, "iss": "https://a.example", "aud": "other" }),
                "wrong_audience",
            ),
            (
                json!({ "iss": "https://a.example", "aud": "api" }),
                "missing_claim",
            ),
        ];
        for (claims, want) in cases {
            assert_eq!(
                jwt.verify(&hs_token("s", claims.clone())).unwrap_err(),
                want,
                "{claims}"
            );
        }
    }

    #[test]
    fn leeway_and_required_claims() {
        let jwt = compile(json!({ "leeway_secs": 120, "required_claims": [], "keys": [{ "id": "k", "algorithms": ["HS256"], "secret": "s" }] })).unwrap();
        assert!(
            jwt.verify(&hs_token("s", json!({ "exp": now() - 60 })))
                .is_ok(),
            "within leeway"
        );
        assert!(
            jwt.verify(&hs_token("s", json!({ "sub": "x" }))).is_ok(),
            "exp not required"
        );
        // Not requiring exp must never disable the expiry check itself.
        assert_eq!(
            jwt.verify(&hs_token("s", json!({ "exp": now() - 600 })))
                .unwrap_err(),
            "expired",
            "expired beyond leeway"
        );
        // Same for nbf: a token that isn't valid yet is still rejected.
        assert_eq!(
            jwt.verify(&hs_token("s", json!({ "nbf": now() + 600 })))
                .unwrap_err(),
            "not_yet_valid",
            "nbf in the future"
        );
    }

    #[test]
    fn audience_in_token_without_audience_config_is_fine() {
        let jwt =
            compile(json!({ "keys": [{ "id": "k", "algorithms": ["HS256"], "secret": "s" }] }))
                .unwrap();
        assert!(jwt
            .verify(&hs_token(
                "s",
                json!({ "exp": now() + 60, "aud": "whatever" })
            ))
            .is_ok());
    }

    // ── Attacks ──────────────────────────────────────────────────────────

    #[test]
    fn forged_and_confused_tokens_rejected() {
        let jwt = compile(rsa_cfg(json!(RSA_PUB))).unwrap();
        // Signed by a different RSA key.
        let other = rs_token(RSA2_PRIV, Algorithm::RS256, None, good_claims());
        assert_eq!(jwt.verify(&other).unwrap_err(), "bad_signature");
        // HS256 using the public key as the HMAC secret.
        let confused = hs_token(RSA_PUB, good_claims());
        assert_eq!(jwt.verify(&confused).unwrap_err(), "alg_not_allowed");
        // alg: none.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(good_claims().to_string())
        );
        assert_eq!(jwt.verify(&none).unwrap_err(), "malformed");
        // Payload edited after signing.
        let good = rs_token(RSA_PRIV, Algorithm::RS256, None, good_claims());
        let mut parts: Vec<String> = good.split('.').map(String::from).collect();
        parts[1] = URL_SAFE_NO_PAD.encode(
            json!({ "sub": "u1", "exp": now() + 600, "data": { "role": "root" } }).to_string(),
        );
        assert_eq!(jwt.verify(&parts.join(".")).unwrap_err(), "bad_signature");
        assert_eq!(jwt.verify("not-a-token").unwrap_err(), "malformed");
    }

    #[test]
    fn multiple_keys_any_one_passes_and_kid_pin() {
        let jwt = compile(json!({ "keys": [
            { "id": "a", "algorithms": ["RS256"], "public_key": RSA_PUB, "kid": "a" },
            { "id": "b", "algorithms": ["HS256"], "secret": "s" }
        ] }))
        .unwrap();
        assert!(jwt
            .verify(&rs_token(
                RSA_PRIV,
                Algorithm::RS256,
                Some("a"),
                good_claims()
            ))
            .is_ok());
        assert_eq!(
            jwt.verify(&rs_token(
                RSA_PRIV,
                Algorithm::RS256,
                Some("zzz"),
                good_claims()
            ))
            .unwrap_err(),
            "unknown_kid"
        );
        assert!(jwt.verify(&hs_token("s", good_claims())).is_ok());
    }

    // ── Config errors ────────────────────────────────────────────────────

    #[test]
    fn config_errors() {
        let bad = [
            (json!({ "keys": [] }), "empty"),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256"] }] }),
                "no key source",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "public_key": RSA_PUB, "jwks_url": "https://x/jwks" }] }),
                "exactly one",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "secret": "s" }] }),
                "only works with HS",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["HS256"], "public_key": RSA_PUB }] }),
                "need a secret",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256", "ES256"], "public_key": RSA_PUB }] }),
                "same kind",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["XX256"], "secret": "s" }] }),
                "unknown algorithm",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": [], "secret": "s" }] }),
                "`algorithms` is required",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "public_key": RSA_PRIV }] }),
                "PRIVATE key",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["ES256"], "public_key": RSA_PUB }] }),
                "EC public key",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "public_key": "bm90IGEga2V5" }] }),
                "RSA public key",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "jwks_url": "http://idp.example/jwks" }] }),
                "https://",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "jwks_url": "https://idp.example/jwks", "jwks_refresh_secs": 5 }] }),
                "at least 60",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "public_key": RSA_PUB, "jwks_refresh_secs": 600 }] }),
                "only applies",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["HS256"], "secret_env": "QG_TEST_UNSET_VAR_XYZ" }] }),
                "not set",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["HS256"], "secret": "s" }, { "id": "k", "algorithms": ["HS256"], "secret": "t" }] }),
                "duplicate id",
            ),
            (
                json!({ "required_claims": ["jti"], "keys": [{ "id": "k", "algorithms": ["HS256"], "secret": "s" }] }),
                "unknown claim",
            ),
            (
                json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "jwks": { "keys": [] } }] }),
                "no usable keys",
            ),
        ];
        for (cfg, want) in bad {
            let err = compile(cfg.clone())
                .err()
                .unwrap_or_else(|| panic!("should fail: {cfg}"));
            assert!(err.contains(want), "{cfg}\n  got: {err}\n  want: {want}");
        }
        // Unknown fields are rejected by serde.
        assert!(compile(
            json!({ "keys": [{ "id": "k", "algorithms": ["HS256"], "secret": "s", "scret": 1 }] })
        )
        .is_err());
        // Plain http is fine for localhost (tests, sidecars).
        assert!(compile(json!({ "keys": [{ "id": "k", "algorithms": ["RS256"], "jwks_url": "http://127.0.0.1:1/jwks" }] })).is_ok());
    }

    // ── Condition fields ─────────────────────────────────────────────────

    fn ctx_with(auth: Option<&str>, jwt: Option<CompiledJwt>) -> RequestContext {
        let mut map = http::HeaderMap::new();
        if let Some(a) = auth {
            map.insert("authorization", a.parse().unwrap());
        }
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let mut ctx = RequestContext::new(
            Arc::from("gw"),
            Arc::from("gw"),
            Arc::from("gw"),
            Arc::from("1"),
            ip,
            ip,
            Arc::from("peer_ip"),
            None,
            Arc::from("/"),
            Arc::from("GET"),
            Arc::from("http"),
            None,
            map,
        );
        ctx.jwt = jwt.map(Arc::new);
        ctx
    }

    #[test]
    fn fields_without_keys_decode_unchecked() {
        let forged = hs_token("anything", good_claims());
        let mut ctx = ctx_with(Some(&format!("Bearer {forged}")), None);
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt.data.role"),
            Some(json!("admin"))
        );
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt_valid"),
            Some(json!(false))
        );
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt_error"),
            Some(json!("unverified"))
        );
    }

    #[test]
    fn fields_with_keys_only_resolve_verified_claims() {
        let jwt = || compile(rsa_cfg(json!(RSA_PUB))).unwrap();
        let good = rs_token(RSA_PRIV, Algorithm::RS256, None, good_claims());
        let mut ctx = ctx_with(Some(&format!("Bearer {good}")), Some(jwt()));
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt.data.role"),
            Some(json!("admin"))
        );
        assert_eq!(
            resolve_condition_value(&mut ctx, "req.header.authorization.jwt.sub"),
            Some(json!("u1"))
        );
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt_valid"),
            Some(json!(true))
        );
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt_error"),
            None
        );

        let forged = rs_token(RSA2_PRIV, Algorithm::RS256, None, good_claims());
        let mut ctx = ctx_with(Some(&format!("bearer {forged}")), Some(jwt()));
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt.data.role"),
            None
        );
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt_valid"),
            Some(json!(false))
        );
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt_error"),
            Some(json!("bad_signature"))
        );

        let mut ctx = ctx_with(None, Some(jwt()));
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt_valid"),
            Some(json!(false))
        );
        assert_eq!(
            resolve_condition_value(&mut ctx, "header.authorization.jwt_error"),
            Some(json!("missing"))
        );

        // Raw token without the Bearer prefix, in a custom header.
        let mut map_ctx = ctx_with(None, Some(jwt()));
        map_ctx.headers.insert("x-token", good.parse().unwrap());
        assert_eq!(
            resolve_condition_value(&mut map_ctx, "header.x-token.jwt.sub"),
            Some(json!("u1"))
        );
    }

    #[test]
    fn token_is_verified_once_per_request() {
        let good = hs_token("s", good_claims());
        let jwt =
            compile(json!({ "keys": [{ "id": "k", "algorithms": ["HS256"], "secret": "s" }] }))
                .unwrap();
        let mut ctx = ctx_with(Some(&format!("Bearer {good}")), Some(jwt));
        resolve_condition_value(&mut ctx, "header.authorization.jwt.sub");
        assert_eq!(ctx.jwt_cache.len(), 1);
        resolve_condition_value(&mut ctx, "header.authorization.jwt_valid");
        resolve_condition_value(&mut ctx, "header.authorization.jwt.data.role");
        assert_eq!(ctx.jwt_cache.len(), 1);
    }
}
