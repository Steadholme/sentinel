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
//! - `POST /api/incidents/{id}/resolve` atomically resolve an incident (CSRF)
//! - `GET  /api/timeline`               JSON v2 comparison + legacy seconds fields

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod feeds;
pub mod handlers;
pub mod http;
pub mod store;
pub mod view_contract;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::{header, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::Response;
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
    handlers::validate_templates().expect("Hindsight static template contract invalid");
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/", get(handlers::timeline::dashboard))
        .route("/incident/{id}", get(handlers::timeline::incident))
        .route("/api/incidents", post(handlers::timeline::open_incident))
        .route(
            "/api/incidents/{id}/notes",
            post(handlers::timeline::add_note),
        )
        .route(
            "/api/incidents/{id}/resolve",
            post(handlers::timeline::resolve_incident),
        )
        .route("/api/timeline", get(handlers::timeline::timeline_json))
        .method_not_allowed_fallback(handlers::timeline::method_not_allowed)
        .fallback(handlers::timeline::route_not_found)
        .layer(middleware::from_fn(response_security))
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
/// set; otherwise that channel is explicitly unconfigured. The audit emitter is wired from
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
                .map_err(|_| "connect postgres failed".to_string())?;
            pg.migrate()
                .await
                .map_err(|_| "Hindsight migration or preflight failed".to_string())?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        _ => return Err("unknown HINDSIGHT_STORE (use memory|postgres)".to_string()),
    };

    // Read-only Sift logs feed (lazily connected — a down Sift DB never blocks startup).
    let logs: Arc<dyn LogReader> = match env_nonempty("SIFT_DATABASE_URL") {
        Some(dsn) => match PgLogReader::connect_lazy(&dsn) {
            Ok(reader) => {
                tracing::info!("Sift logs feed wired (read-only pool)");
                Arc::new(reader)
            }
            Err(_) => {
                tracing::warn!("Sift logs feed configuration invalid");
                Arc::new(InMemoryLogReader::unconfigured())
            }
        },
        None => {
            tracing::warn!("SIFT_DATABASE_URL unset — the log channel is configuration-absent");
            Arc::new(InMemoryLogReader::unconfigured())
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

/// Current wall-clock time in epoch milliseconds, resolved once per request.
pub fn now_millis() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis();
    i64::try_from(millis).expect("system clock outside signed millisecond range")
}

/// Current wall-clock time in epoch seconds.
pub fn now_secs() -> i64 {
    now_millis().div_euclid(1_000)
}

async fn response_security(request: Request, next: Next) -> Response {
    let health_candidate = request.uri().path() == "/healthz"
        && matches!(
            *request.method(),
            axum::http::Method::GET | axum::http::Method::HEAD
        );
    let mut response = next.run(request).await;
    let health = health_candidate && response.status().is_success();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if health {
            "no-store"
        } else {
            "private, no-store"
        }),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if !health {
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            ),
        );
    }
    response
}
