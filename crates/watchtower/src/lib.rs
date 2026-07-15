//! Watchtower — tamper-evident audit spine + mini-SIEM dashboard for the Steadholme stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store) and [`build_state_from_env`] (env-selected store).
//! Integration tests consume [`app`] directly via `tower::oneshot`, exactly like keystone /
//! keyward.
//!
//! Endpoints:
//! - `GET /healthz` — liveness (public)
//! - `POST /events` — append one event (bearer `AUDIT_INGEST_TOKEN`)
//! - `GET /api/verify` — recompute the chain (public read)
//! - `GET /api/events` — filtered list (public read)
//! - `GET /api/events/search` / `GET /api/events/export` — paged search + CSV/JSON export
//! - `GET /api/alert-rules` / `POST /api/alert-rules` — alert rules (create is SSO + CSRF)
//! - `GET /api/alerts` — append-only alert match markers
//! - `GET /` — SSO dashboard (gateway-authenticated; registered as the fallback so the
//!   gateway-prefixed `/watchtower` path renders it too)

pub mod alerts;
pub mod auth;
pub mod chain;
pub mod config;
pub mod error;
pub mod handlers;
pub mod merkle;
pub mod store;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::config::Config;
use crate::merkle::make_checkpoint;
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
}

/// Build the router wiring all endpoints onto `state`.
///
/// The dashboard is registered as the fallback (not just `GET /`): Sluice forwards the
/// gateway route prefix unmodified, so an `auth=sso` route at `/watchtower` arrives here as
/// `GET /watchtower`. Routing it through the fallback means the dashboard renders regardless
/// of the public prefix, with no per-deployment path config. The explicit API/health/ingest
/// routes still match first.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/events", post(handlers::events::ingest))
        .route("/api/verify", get(handlers::events::verify))
        .route("/api/events", get(handlers::events::list))
        .route("/api/events/search", get(handlers::events::search))
        .route("/api/events/export", get(handlers::events::export))
        .route("/api/checkpoint", post(handlers::checkpoints::create))
        .route("/api/checkpoints", get(handlers::checkpoints::list))
        .route(
            "/api/alert-rules",
            get(handlers::alerts::list_rules).post(handlers::alerts::create_rule),
        )
        .route("/api/alerts", get(handlers::alerts::list_matches))
        .fallback(get(handlers::dashboard::dashboard))
        .with_state(state)
}

/// Spawn the background Merkle checkpointer when `checkpoint_interval_secs > 0`.
///
/// Every interval it reads the current head and, if it has advanced past the latest stored
/// checkpoint's `seq_hi`, seals a fresh Merkle root over the whole chain prefix. It NEVER
/// touches the append-only chain and swallows transient store errors (a slow/unavailable
/// backend just skips that tick) so it can never wedge or crash the service. Disabled by
/// default, so dev/test runs and `app()`-driven tests are unaffected.
pub fn spawn_checkpointer(state: AppState) {
    let secs = state.config.checkpoint_interval_secs;
    if secs == 0 {
        return;
    }
    let interval = Duration::from_secs(secs);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let events = match state.store.all_events().await {
                Ok(e) if !e.is_empty() => e,
                _ => continue, // empty log or transient error -> skip this tick
            };
            let head_seq = events.last().map(|e| e.seq).unwrap_or(0);
            let last_hi = state
                .store
                .all_checkpoints()
                .await
                .unwrap_or_default()
                .iter()
                .map(|c| c.seq_hi)
                .max()
                .unwrap_or(0);
            if head_seq > last_hi {
                let cp = make_checkpoint(&events, now_ms());
                if let Err(e) = state.store.insert_checkpoint(cp).await {
                    tracing::warn!(error = %e, "periodic checkpoint seal failed (will retry)");
                } else {
                    tracing::info!(seq_hi = head_seq, "sealed periodic Merkle checkpoint");
                }
            }
        }
    });
}

/// Construct dev state: dev [`Config`] + an empty [`InMemoryStore`]. Used by `main`'s memory
/// mode and by the integration tests, so they need no database.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `WATCHTOWER_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = std::env::var("WATCHTOWER_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "WATCHTOWER_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("WATCHTOWER_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => {
            return Err(format!(
                "unknown WATCHTOWER_STORE={other} (use memory|postgres)"
            ))
        }
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
    })
}

/// Current wall-clock time in epoch milliseconds (the audit `ts`). `seq` — not `ts` — is the
/// ordering authority, so millisecond precision is purely for human-readable timelines.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as i64
}
