//! Alert rule APIs.
//!
//! - `GET  /api/alert-rules`  - list configured rules.
//! - `POST /api/alert-rules`  - create a rule (gateway SSO + CSRF) and mirror-audit it.
//! - `GET  /api/alerts`       - recent append-only alert match markers.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::alerts::{make_alert_rule, AlertMatch, AlertRule};
use crate::auth::{require_admin_sso, require_csrf};
use crate::chain::EventInput;
use crate::config::QUERY_LIMIT;
use crate::error::AppError;
use crate::{now_ms, AppState};

/// `GET /api/alert-rules` -> every rule, newest-first.
pub async fn list_rules(State(state): State<AppState>) -> Result<Json<Vec<AlertRule>>, AppError> {
    Ok(Json(state.store.all_alert_rules().await?))
}

/// Query string for `GET /api/alerts`.
#[derive(Deserialize, Default)]
pub struct AlertMatchesQuery {
    pub limit: Option<usize>,
}

/// `GET /api/alerts?limit=` -> recent alert match markers.
pub async fn list_matches(
    State(state): State<AppState>,
    Query(query): Query<AlertMatchesQuery>,
) -> Result<Json<Vec<AlertMatch>>, AppError> {
    let limit = query.limit.unwrap_or(50).clamp(1, QUERY_LIMIT);
    Ok(Json(state.store.recent_alert_matches(limit).await?))
}

/// Body accepted by `POST /api/alert-rules` in JSON or urlencoded form shape.
#[derive(Deserialize, Default)]
pub struct AlertRuleBody {
    pub csrf: Option<String>,
    pub name: Option<String>,
    pub actor: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub severity: Option<String>,
}

/// `POST /api/alert-rules` -> create one exact-match alert rule.
pub async fn create_rule(
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
    let body_fields = parse_body(&body, is_form)?;

    let presented = header_csrf(&headers).or(body_fields.csrf.as_deref());
    require_csrf(presented, &state.config.ingest_token, &email)?;

    let created_at = now_ms();
    let name = clean(body_fields.name).unwrap_or_else(|| "Alert rule".to_string());
    let rule = make_alert_rule(
        name,
        clean(body_fields.actor),
        clean(body_fields.action),
        clean(body_fields.source),
        clean(body_fields.severity),
        email.clone(),
        created_at,
    );
    if !rule.has_predicate() {
        return Err(AppError::InvalidRequest(
            "alert rule requires at least one actor/action/source/severity predicate".to_string(),
        ));
    }

    state.store.insert_alert_rule(rule.clone()).await?;
    state
        .store
        .append(EventInput {
            ts: now_ms(),
            actor: email,
            action: "watchtower.alert_rule.create".to_string(),
            target: rule.id.clone(),
            severity: "notice".to_string(),
            detail: format!(
                "created alert rule name={} actor={} action={} source={} severity={}",
                rule.name,
                display_predicate(&rule.actor),
                display_predicate(&rule.action),
                display_predicate(&rule.source),
                display_predicate(&rule.severity),
            ),
            source: "watchtower".to_string(),
        })
        .await?;

    if is_form {
        let location = headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .unwrap_or("/")
            .to_string();
        return Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response());
    }

    Ok(Json(rule).into_response())
}

fn parse_body(body: &Bytes, is_form: bool) -> Result<AlertRuleBody, AppError> {
    if is_form {
        return Ok(AlertRuleBody {
            csrf: form_field(body, "csrf"),
            name: form_field(body, "name"),
            actor: form_field(body, "actor"),
            action: form_field(body, "action"),
            source: form_field(body, "source"),
            severity: form_field(body, "severity"),
        });
    }
    serde_json::from_slice::<AlertRuleBody>(body)
        .map_err(|e| AppError::InvalidRequest(format!("invalid alert rule JSON: {e}")))
}

fn header_csrf(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn clean(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn display_predicate(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("*")
}

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
    fn form_field_extracts_alert_rule_fields() {
        let body = Bytes::from_static(
            b"csrf=tok&name=Login+failures&action=login.failure&severity=warn%20high",
        );
        assert_eq!(form_field(&body, "name").as_deref(), Some("Login failures"));
        assert_eq!(
            form_field(&body, "action").as_deref(),
            Some("login.failure")
        );
        assert_eq!(form_field(&body, "severity").as_deref(), Some("warn high"));
        assert_eq!(form_field(&body, "missing"), None);
    }

    #[test]
    fn clean_drops_empty_values() {
        assert_eq!(
            clean(Some("  actor  ".to_string())).as_deref(),
            Some("actor")
        );
        assert_eq!(clean(Some("   ".to_string())), None);
        assert_eq!(clean(None), None);
    }
}
