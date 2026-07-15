//! Ingest bearer-token authentication for `POST /events`.
//!
//! `Authorization: Bearer <AUDIT_INGEST_TOKEN>`, compared in constant time so a timing
//! side-channel can't recover the token byte by byte. Read endpoints (`/api/verify`,
//! `/api/events`, `/healthz`) and the SSO dashboard do NOT call this — the dashboard is
//! authenticated at the gateway (Sluice injects `X-Auth-*`).
//!
//! `POST /api/checkpoint` is the lone gateway-SSO-gated write: [`require_admin_sso`] confirms a
//! Sluice-injected identity (optionally restricted to an admin allowlist), and a CSRF token
//! ([`csrf_token`]/[`require_csrf`]) — keyed by the existing ingest secret and bound to that
//! identity — blocks cross-site form posts. Both use constant-time comparison via [`ct_eq`].

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// Verify the request carries the configured ingest bearer token. Returns `Unauthorized`
/// (401 + `WWW-Authenticate: Bearer`) when the header is missing, malformed, or mismatched.
pub fn require_ingest(headers: &HeaderMap, expected_token: &str) -> Result<(), AppError> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);

    match presented {
        Some(token) if ct_eq(token.as_bytes(), expected_token.as_bytes()) => Ok(()),
        _ => Err(AppError::Unauthorized(
            "missing or invalid ingest bearer token".to_string(),
        )),
    }
}

/// Require the request is gateway-SSO-authenticated and, when `admins` is non-empty, that the
/// Sluice-injected `X-Auth-Email` is a member (case-insensitive). Returns the authenticated
/// email. An empty `admins` list means "any authenticated SSO user" — the graceful default that
/// matches the `auth=sso` gateway route, never a 500.
pub fn require_admin_sso(headers: &HeaderMap, admins: &[String]) -> Result<String, AppError> {
    let email = headers
        .get("x-auth-email")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let email = match email {
        Some(e) => e.to_string(),
        None => {
            return Err(AppError::Unauthorized(
                "gateway SSO session required".to_string(),
            ))
        }
    };
    if !admins.is_empty() && !admins.iter().any(|a| a.eq_ignore_ascii_case(&email)) {
        return Err(AppError::Forbidden(
            "admin privilege required to seal a checkpoint".to_string(),
        ));
    }
    Ok(email)
}

/// Deterministic CSRF token bound to the SSO identity: `hex(HMAC-SHA256(secret, email))`. The
/// dashboard embeds it as a hidden field; a cross-site attacker can't forge it without the
/// server secret, so a stray form post is rejected. The secret reuses the existing ingest token
/// (no new configuration).
pub fn csrf_token(secret: &str, email: &str) -> String {
    hex::encode(hmac_sha256(secret.as_bytes(), email.as_bytes()))
}

/// Validate a presented CSRF token against the expected one for `email`, in constant time.
pub fn require_csrf(presented: Option<&str>, secret: &str, email: &str) -> Result<(), AppError> {
    let expected = csrf_token(secret, email);
    match presented {
        Some(tok) if ct_eq(tok.trim().as_bytes(), expected.as_bytes()) => Ok(()),
        _ => Err(AppError::Forbidden(
            "missing or invalid CSRF token".to_string(),
        )),
    }
}

/// HMAC-SHA256 (RFC2104) over `msg` keyed by `key`. Self-contained on the existing `sha2`
/// dependency — no extra crate, no OpenSSL.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// Constant-time byte equality. Folds the length difference into the accumulator so
/// neither the comparison time nor an early return reveals where two values diverge.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().min(b.len());
    for i in 0..n {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_and_rejects() {
        assert!(ct_eq(b"token", b"token"));
        assert!(!ct_eq(b"token", b"tokeN"));
        assert!(!ct_eq(b"token", b"token-longer"));
        assert!(!ct_eq(b"", b"x"));
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_vector() {
        // RFC4231 test case 2: key = "Jefe", data = "what do ya want for nothing?".
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn csrf_token_is_identity_bound_and_validates() {
        let secret = "ingest-secret";
        let tok = csrf_token(secret, "admin@steadholme.local");
        // Round-trips for the same identity...
        assert!(require_csrf(Some(&tok), secret, "admin@steadholme.local").is_ok());
        // ...but is bound to that identity and secret.
        assert!(require_csrf(Some(&tok), secret, "mallory@evil.example").is_err());
        assert!(require_csrf(Some(&tok), "other-secret", "admin@steadholme.local").is_err());
        assert!(require_csrf(None, secret, "admin@steadholme.local").is_err());
        assert!(require_csrf(Some("deadbeef"), secret, "admin@steadholme.local").is_err());
    }

    #[test]
    fn require_admin_sso_honors_allowlist() {
        let mut headers = HeaderMap::new();
        // No identity -> unauthorized.
        assert!(require_admin_sso(&headers, &[]).is_err());

        headers.insert("x-auth-email", "user@steadholme.local".parse().unwrap());
        // Empty allowlist -> any SSO user passes.
        assert_eq!(
            require_admin_sso(&headers, &[]).unwrap(),
            "user@steadholme.local"
        );
        // Non-empty allowlist excluding the user -> forbidden.
        assert!(require_admin_sso(&headers, &["admin@steadholme.local".to_string()]).is_err());
        // Allowlist including the user (case-insensitive) -> ok.
        assert!(require_admin_sso(&headers, &["USER@steadholme.local".to_string()]).is_ok());
    }
}
