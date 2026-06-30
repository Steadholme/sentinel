//! Ingest + read APIs.
//!
//! - `POST /events`     — append one event (bearer `AUDIT_INGEST_TOKEN`). The server assigns
//!   `ts`, `seq`, `prev_hash`, and the committed `hash`; the producer only supplies content.
//! - `GET  /api/verify` — recompute the whole chain -> `{ ok, count, head_hash, first_broken_seq? }`.
//! - `GET  /api/events` — filtered, newest-first list (`?actor=&action=&since=&q=`).

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::require_ingest;
use crate::chain::{verify_chain, AuditEvent, EventInput};
use crate::error::AppError;
use crate::store::EventFilter;
use crate::{now_ms, AppState};

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

    let input = EventInput {
        ts: now_ms(),
        actor: body.actor,
        action: body.action,
        target: body.target,
        severity: body.severity,
        detail: body.detail,
        source: body.source,
    };
    let event = state.store.append(input).await?;
    Ok(Json(event))
}

/// `GET /api/verify` response — `first_broken_seq` is omitted when the chain is intact.
#[derive(Serialize)]
pub struct VerifyResponse {
    pub ok: bool,
    pub count: usize,
    pub head_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_broken_seq: Option<i64>,
}

/// `GET /api/verify` -> recompute the entire chain and report integrity.
pub async fn verify(State(state): State<AppState>) -> Result<Json<VerifyResponse>, AppError> {
    let events = state.store.all_events().await?;
    let report = verify_chain(&events);
    Ok(Json(VerifyResponse {
        ok: report.ok,
        count: report.count,
        head_hash: report.head_hash,
        first_broken_seq: report.first_broken_seq,
    }))
}

/// Query string for `GET /api/events` and the dashboard. Blank params are treated as absent.
#[derive(Deserialize, Default)]
pub struct EventsQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub since: Option<i64>,
    pub q: Option<String>,
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
            since: self.since,
            q: clean(self.q),
            ..EventFilter::new()
        }
    }
}

/// `GET /api/events?actor=&action=&since=&q=` -> filtered, newest-first list.
pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<Vec<AuditEvent>>, AppError> {
    let filter = query.into_filter();
    let events = state.store.query(&filter).await?;
    Ok(Json(events))
}
