//! Merkle checkpoint APIs (ADDED tamper-evidence summary; the chain stays the spine).
//!
//! - `POST /api/checkpoint`  — seal a checkpoint over the current head (gateway SSO + CSRF;
//!   optionally restricted to `WATCHTOWER_ADMIN_EMAILS`). A browser form post is answered with
//!   a 303 redirect back to the dashboard; an API/JSON post gets the sealed checkpoint as JSON.
//! - `GET  /api/checkpoints` — list every checkpoint, each re-verified against the live log:
//!   recompute the Merkle root up to its `seq_hi` and report whether it still matches.
//!
//! The existing append/verify/ingest paths are not touched — this module only reads
//! `all_events`, plus reads/writes the separate `checkpoints` store.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::auth::{require_admin_sso, require_csrf};
use crate::error::AppError;
use crate::merkle::{make_checkpoint, merkle_root_upto, Checkpoint};
use crate::{now_ms, AppState};

/// One checkpoint as rendered by `GET /api/checkpoints`: the stored fields plus a live
/// re-verification (`valid` + the `current_root` recomputed over the log up to `seq_hi`).
#[derive(Serialize)]
pub struct CheckpointView {
    pub id: String,
    pub seq_hi: i64,
    pub merkle_root: String,
    pub created_at: i64,
    /// True when the stored root still equals the root recomputed over the current log prefix.
    pub valid: bool,
    /// The root recomputed now over events `1..=seq_hi` (differs from `merkle_root` on tamper).
    pub current_root: String,
}

impl CheckpointView {
    /// Re-verify a stored checkpoint against the current event log.
    fn verify(cp: &Checkpoint, events: &[crate::chain::AuditEvent]) -> Self {
        let current_root = merkle_root_upto(events, cp.seq_hi);
        CheckpointView {
            valid: current_root == cp.merkle_root,
            current_root,
            id: cp.id.clone(),
            seq_hi: cp.seq_hi,
            merkle_root: cp.merkle_root.clone(),
            created_at: cp.created_at,
        }
    }
}

/// `GET /api/checkpoints` -> every checkpoint, newest-first, each re-verified against the live
/// chain. Public read (same posture as `/api/verify`).
pub async fn list(State(state): State<AppState>) -> Result<Json<Vec<CheckpointView>>, AppError> {
    let events = state.store.all_events().await?;
    let mut checkpoints = state.store.all_checkpoints().await?;
    checkpoints.sort_by(|a, b| b.seq_hi.cmp(&a.seq_hi)); // newest-first, like the event timeline
    let views = checkpoints
        .iter()
        .map(|cp| CheckpointView::verify(cp, &events))
        .collect();
    Ok(Json(views))
}

/// `POST /api/checkpoint` -> seal a checkpoint over the current head.
///
/// Auth: a gateway-SSO identity (optionally on the admin allowlist) plus a valid CSRF token. The
/// token may arrive as the `X-CSRF-Token` header (API clients) or a `csrf` form/JSON field
/// (the dashboard's hidden field). Returns JSON for an API post, or a 303 back to the dashboard
/// for a browser form post.
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let email = require_admin_sso(&headers, &state.config.admin_emails)?;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_form = content_type.starts_with("application/x-www-form-urlencoded");

    let presented = header_csrf(&headers).or_else(|| extract_csrf(&body, is_form));
    require_csrf(presented.as_deref(), &state.config.ingest_token, &email)?;

    let events = state.store.all_events().await?;
    let checkpoint = make_checkpoint(&events, now_ms());
    state.store.insert_checkpoint(checkpoint.clone()).await?;

    if is_form {
        // Browser form post: bounce back to the page the user came from (the dashboard), or "/".
        let location = headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .unwrap_or("/")
            .to_string();
        return Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response());
    }

    // API post: return the sealed checkpoint (always self-valid at seal time).
    Ok(Json(CheckpointView::verify(&checkpoint, &events)).into_response())
}

/// CSRF token from the `X-CSRF-Token` header (trimmed, non-empty), if present.
fn header_csrf(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// CSRF token from the body: a `csrf` field of a urlencoded form, or a `"csrf"` JSON string.
fn extract_csrf(body: &Bytes, is_form: bool) -> Option<String> {
    if is_form {
        form_field(body, "csrf")
    } else {
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("csrf").and_then(|c| c.as_str()).map(str::to_string))
    }
}

/// Pull one field out of an `application/x-www-form-urlencoded` body (minimal `%`/`+` decode).
fn form_field(body: &Bytes, key: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    for pair in text.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        if form_decode(k) == key {
            return Some(form_decode(it.next().unwrap_or("")));
        }
    }
    None
}

/// Decode a urlencoded form token: `+` -> space and `%XX` -> byte.
fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_field_extracts_and_decodes() {
        let body = Bytes::from_static(b"csrf=ab%20cd&other=x");
        assert_eq!(form_field(&body, "csrf").as_deref(), Some("ab cd"));
        assert_eq!(form_field(&body, "missing"), None);
        let plus = Bytes::from_static(b"csrf=a+b");
        assert_eq!(form_field(&plus, "csrf").as_deref(), Some("a b"));
    }

    #[test]
    fn extract_csrf_reads_json_field() {
        let body = Bytes::from_static(br#"{"csrf":"deadbeef"}"#);
        assert_eq!(extract_csrf(&body, false).as_deref(), Some("deadbeef"));
        assert_eq!(extract_csrf(&Bytes::from_static(b"{}"), false), None);
    }
}
