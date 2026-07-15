//! Hindsight — incident timeline / RCA correlator for the Steadholme stack.
//!
//! The observability capstone over Vitals / Sift / Watchtower: it correlates metrics + logs +
//! audit into one queryable, time-ordered incident timeline, and lets operators open incidents
//! over a window and thread notes onto them.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store + empty feeds — DB-free) and [`build_state_from_env`]
//! (env-selected store, read-only Sift pool, audit emitter). Integration tests consume [`app`]
//! directly via `tower::oneshot`, exactly like the rest of the estate.
//!
//! Hindsight sits behind a Sluice `auth=sso` route at the subdomain ROOT (`rca.w33d.xyz`); the
//! gateway forwards the path UNMODIFIED, so the routes below are the real paths.
//!
//! Endpoints:
//! - `GET  /healthz`                    liveness (container HEALTHCHECK, no auth)
//! - `GET  /`                           dashboard: merged timeline over a window + incidents list
//! - `GET  /incident/{id}`              one incident + its merged evidence window + notes
//! - `POST /api/incidents`              open an incident over a time window (CSRF)
//! - `POST /api/incidents/{id}/notes`   thread a note onto an incident (CSRF)
//! - `GET  /api/timeline?from=&to=`     JSON merged timeline

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod feeds;
pub mod handlers;
pub mod http;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, Config};
use crate::feeds::sift::{InMemoryLogReader, LogReader, PgLogReader};
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub logs: Arc<dyn LogReader>,
    pub audit: AuditSink,
}

/// Build the router wiring all endpoints onto `state`.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::timeline::dashboard))
        .route("/incident/{id}", get(handlers::timeline::incident))
        .route("/api/incidents", post(handlers::timeline::open_incident))
        .route(
            "/api/incidents/{id}/notes",
            post(handlers::timeline::add_note),
        )
        .route("/api/timeline", get(handlers::timeline::timeline_json))
        .with_state(state)
}

/// Construct dev state: dev [`Config`] + an empty [`InMemoryStore`] + empty Sift reader + a
/// disabled audit sink. Used by `main`'s memory mode and the integration tests, so they need no
/// database and no Watchtower.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        logs: Arc::new(InMemoryLogReader::empty()),
        audit: AuditSink::disabled(),
    }
}

/// Build a dev state around a pre-built store + log reader (used by handler tests that seed feeds).
pub fn build_state_with(store: Arc<dyn Store>, logs: Arc<dyn LogReader>) -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store,
        logs,
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The OWN store is selected by `HINDSIGHT_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// The Sift logs feed is wired from `SIFT_DATABASE_URL` (a READ-ONLY, lazily-connected pool) when
/// set; otherwise the feed is empty (but reached). The audit emitter is wired from
/// `AUDIT_ENABLED` / `WATCHTOWER_URL` / `AUDIT_INGEST_TOKEN`.
///
/// Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = env_nonempty("HINDSIGHT_STORE").unwrap_or_else(|| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("DATABASE_URL")
                .ok_or_else(|| "HINDSIGHT_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("HINDSIGHT_STORE=postgres — connecting to database");
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
                "unknown HINDSIGHT_STORE={other} (use memory|postgres)"
            ))
        }
    };

    // Read-only Sift logs feed (lazily connected — a down Sift DB never blocks startup).
    let logs: Arc<dyn LogReader> = match env_nonempty("SIFT_DATABASE_URL") {
        Some(dsn) => {
            let reader =
                PgLogReader::connect_lazy(&dsn).map_err(|e| format!("SIFT_DATABASE_URL: {e}"))?;
            tracing::info!("Sift logs feed wired (read-only pool)");
            Arc::new(reader)
        }
        None => {
            tracing::warn!(
                "SIFT_DATABASE_URL unset — the Sift logs feed will be empty. Set it to correlate logs."
            );
            Arc::new(InMemoryLogReader::empty())
        }
    };

    // Non-blocking audit emitter -> Watchtower (disabled unless AUDIT_ENABLED + token set).
    let audit_enabled = env_nonempty("AUDIT_ENABLED")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let audit = AuditSink::start(
        audit_enabled,
        &config.watchtower_url,
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        logs,
        audit,
    })
}

/// Current wall-clock time in epoch seconds (incident timestamps + window math).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Monotonic-ish nanosecond counter for incident/note ids.
pub fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos()
}
