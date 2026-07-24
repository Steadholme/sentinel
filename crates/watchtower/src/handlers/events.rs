//! Ingest + read APIs.
//!
//! - `POST /events`     — append one event (bearer `AUDIT_INGEST_TOKEN`). The server assigns
//!   `ts`, `seq`, `prev_hash`, and the committed `hash`; an optional `Idempotency-Key` makes a
//!   producer/source-scoped retry return the original event without extending the chain.
//! - `GET  /api/verify` — recompute the whole chain -> summary plus detailed issue scan.
//! - `GET  /api/events` — filtered, newest-first list (`?actor=&action=&source=&severity=...`).
//! - `GET  /api/events/search` — the same list with pagination metadata.
//! - `GET  /api/events/export` — filtered CSV or JSON export.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::require_ingest;
use crate::chain::{verify_chain, verify_chain_issues, AuditEvent, EventInput, VerifyIssue};
use crate::config::QUERY_LIMIT;
use crate::error::AppError;
use crate::store::EventFilter;
use crate::{now_ms, AppState};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const IDEMPOTENCY_KEY_BYTES: usize = 64;

/// `POST /events` request body. Every field defaults to empty so a producer can omit any of
/// them; the entry is still a valid, hash-chained link. `ts`/`seq`/`hash` are NOT accepted
/// from the caller — the server owns them.
#[derive(Deserialize)]
pub struct IngestBody {
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub source: String,
}

/// `POST /events` -> the sealed [`AuditEvent`] (seq, ts, prev_hash, hash, ...).
pub async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<IngestBody>,
) -> Result<Json<AuditEvent>, AppError> {
    require_ingest(&headers, &state.config.ingest_token)?;
    let idempotency_key = parse_idempotency_key(&headers)?;

    let input = EventInput {
        ts: now_ms(),
        actor: body.actor,
        action: body.action,
        target: body.target,
        severity: body.severity,
        detail: body.detail,
        source: body.source,
    };
    let (event, appended) = match idempotency_key {
        Some(key) => {
            let outcome = state.store.append_idempotent(input, key).await?;
            (outcome.event, outcome.appended)
        }
        None => (state.store.append(input).await?, true),
    };
    if appended {
        if let Err(e) = state.store.record_alert_matches(&event, now_ms()).await {
            tracing::warn!(error = %e, seq = event.seq, "alert match recording failed");
        }
    }
    Ok(Json(event))
}

fn parse_idempotency_key(headers: &HeaderMap) -> Result<Option<String>, AppError> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AppError::InvalidRequest(
            "Idempotency-Key must be sent exactly once".to_string(),
        ));
    }
    let key = value.to_str().map_err(|_| {
        AppError::InvalidRequest("Idempotency-Key must contain visible ASCII".to_string())
    })?;
    let valid = key.len() == IDEMPOTENCY_KEY_BYTES
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(AppError::InvalidRequest(
            "Idempotency-Key must be exactly 64 lowercase hexadecimal characters".to_string(),
        ));
    }
    Ok(Some(key.to_string()))
}

/// `GET /api/verify` response — `first_broken_seq` is omitted when the chain is intact.
#[derive(Serialize)]
pub struct VerifyResponse {
    pub ok: bool,
    pub count: usize,
    pub head_hash: String,
    pub checked_at: i64,
    pub issues: Vec<VerifyIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_broken_seq: Option<i64>,
}

/// `GET /api/verify` -> recompute the entire chain and report integrity.
pub async fn verify(State(state): State<AppState>) -> Result<Json<VerifyResponse>, AppError> {
    let events = state.store.all_events().await?;
    let report = verify_chain(&events);
    let issues = verify_chain_issues(&events);
    Ok(Json(VerifyResponse {
        ok: report.ok,
        count: report.count,
        head_hash: report.head_hash,
        checked_at: now_ms(),
        issues,
        first_broken_seq: report.first_broken_seq,
    }))
}

/// Query string for `GET /api/events` and the dashboard. Blank params are treated as absent.
#[derive(Deserialize, Default)]
pub struct EventsQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub severity: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub q: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl EventsQuery {
    /// Convert the raw query into a [`EventFilter`], dropping empty strings so `?actor=`
    /// (no value) is the same as omitting it.
    pub fn into_filter(self) -> EventFilter {
        fn clean(v: Option<String>) -> Option<String> {
            v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        }
        EventFilter {
            actor: clean(self.actor),
            action: clean(self.action),
            source: clean(self.source),
            severity: clean(self.severity),
            since: self.since,
            until: self.until,
            q: clean(self.q),
            limit: self.limit.unwrap_or(QUERY_LIMIT).clamp(1, QUERY_LIMIT),
            offset: self.offset.unwrap_or(0),
            ..EventFilter::new()
        }
    }
}

/// `GET /api/events?actor=&action=&source=&severity=&since=&until=&q=&limit=&offset=`
/// -> filtered, newest-first list. The response stays a raw array for backward compatibility.
pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<Vec<AuditEvent>>, AppError> {
    let filter = query.into_filter();
    let events = state.store.query(&filter).await?;
    Ok(Json(events))
}

/// Paged search response for clients that need count/next-offset metadata.
#[derive(Serialize)]
pub struct EventsPage {
    pub items: Vec<AuditEvent>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// `GET /api/events/search?...` -> filtered events plus pagination metadata.
pub async fn search(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<EventsPage>, AppError> {
    let filter = query.into_filter();
    let total = state.store.count(&filter).await?;
    let items = state.store.query(&filter).await?;
    let next = filter.offset + items.len();
    Ok(Json(EventsPage {
        next_offset: (next < total).then_some(next),
        items,
        total,
        limit: filter.limit,
        offset: filter.offset,
    }))
}

/// Query string for `GET /api/events/export`.
#[derive(Deserialize, Default)]
pub struct ExportQuery {
    #[serde(flatten)]
    pub events: EventsQuery,
    pub format: Option<String>,
}

/// `GET /api/events/export?format=csv|json&...` -> filtered export.
pub async fn export(
    State(state): State<AppState>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, AppError> {
    let format = query
        .format
        .as_deref()
        .unwrap_or("csv")
        .trim()
        .to_lowercase();
    let filter = query.events.into_filter();
    let events = state.store.query(&filter).await?;

    if format == "json" {
        return Ok(Json(events).into_response());
    }
    if format != "csv" {
        return Ok((
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            Json(serde_json::json!({
                "error": "bad_request",
                "message": "format must be csv or json"
            })),
        )
            .into_response());
    }

    let csv = events_csv(&events);
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"watchtower-events.csv\"",
            ),
        ],
        csv,
    )
        .into_response())
}

fn events_csv(events: &[AuditEvent]) -> String {
    let mut out = "seq,ts,actor,action,target,severity,detail,source,prev_hash,hash\n".to_string();
    for e in events {
        csv_row(
            &mut out,
            &[
                e.seq.to_string(),
                e.ts.to_string(),
                e.actor.clone(),
                e.action.clone(),
                e.target.clone(),
                e.severity.clone(),
                e.detail.clone(),
                e.source.clone(),
                e.prev_hash.clone(),
                e.hash.clone(),
            ],
        );
    }
    out
}

fn csv_row(out: &mut String, fields: &[String]) {
    for (idx, field) in fields.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        for c in field.chars() {
            if c == '"' {
                out.push('"');
            }
            out.push(c);
        }
        out.push('"');
    }
    out.push('\n');
}
