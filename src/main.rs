//! Sentinel — one container hosting the HOLDFAST audit + RCA surfaces behind a Host-based demux.
//!
//! Two vendored crates, reused verbatim:
//! - **Watchtower** (audit spine): the tamper-evident audit log / SIEM. EVERY estate service POSTs
//!   audit events to `http://watchtower:8500/events`, and the gateway fronts the console at
//!   `audit.w33d.xyz`. The compose service is kept named `watchtower` and this binds :8500, so that
//!   estate-wide address is UNCHANGED.
//! - **Hindsight** (RCA): a READ-ONLY root-cause correlator at `rca.w33d.xyz` that consumes
//!   Watchtower audit + Sift logs + Vitals metrics and writes only its own incidents/notes.
//!
//! Dispatch is by `Host` leading label: `watchtower` (internal :8500 audit POSTs) OR `audit`
//! (gateway console) → Watchtower; `rca` → Hindsight. The full request (headers + body) is forwarded
//! via `oneshot`, so Watchtower's `/events` ingest + verify/checkpoint paths are evaluated exactly as
//! standalone. Each surface keeps its OWN database. `healthcheck` subcommand is a dependency-free
//! host-agnostic loopback `GET /healthz`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

/// Default listen address — Watchtower's port, kept so `watchtower:8500` is unchanged estate-wide.
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8500";

#[derive(Clone)]
struct Vhosts {
    watchtower: Router,
    rca: Router,
}

#[tokio::main]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(run_healthcheck());
    }

    tracing_subscriber::fmt::init();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());

    let watchtower = build_watchtower()
        .await
        .unwrap_or_else(|e| fatal("watchtower (audit spine)", e));
    let rca = build_rca().await.unwrap_or_else(|e| fatal("rca (hindsight)", e));

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .fallback(dispatch)
        .with_state(Vhosts { watchtower, rca });

    let addr: SocketAddr = bind_addr.parse().expect("invalid BIND_ADDR");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    tracing::info!(%addr, "Sentinel listening (watchtower audit + hindsight RCA vhost demux)");
    axum::serve(listener, app).await.expect("server error");
}

/// Dispatch by `Host` leading label. `watchtower` (internal audit POSTs) + `audit` (gateway console)
/// → Watchtower; `rca` → Hindsight; unknown → 404.
async fn dispatch(State(v): State<Vhosts>, req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let label = host
        .split(':')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    let router = match label {
        // The audit spine is reached BOTH internally (http://watchtower:8500, Host "watchtower")
        // and via the gateway console (audit.w33d.xyz, Host "audit"). Both → Watchtower.
        "watchtower" | "audit" => v.watchtower,
        "rca" => v.rca,
        _ => return (StatusCode::NOT_FOUND, "unknown sentinel host").into_response(),
    };
    match router.oneshot(req).await {
        Ok(resp) => resp,
        Err(e) => match e {},
    }
}

/// Build the Watchtower (audit spine) surface. Store from `WATCHTOWER_DATABASE_URL` (legacy
/// `DATABASE_URL` accepted), migrated idempotently.
async fn build_watchtower() -> Result<Router, String> {
    let dsn = require_env_any(&["WATCHTOWER_DATABASE_URL", "DATABASE_URL"])?;
    let pg = watchtower::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("watchtower (audit spine) store ready");
    let state = watchtower::AppState {
        config: Arc::new(watchtower::config::Config::from_env()),
        store: Arc::new(pg),
    };
    Ok(watchtower::app(state))
}

/// Build the Hindsight (RCA) surface. Store from `HINDSIGHT_DATABASE_URL` (its OWN DB — NOT the
/// shared `DATABASE_URL`, which is Watchtower's in this process), a lazily-connected read-only Sift
/// logs feed from `SIFT_DATABASE_URL`, and a non-blocking audit emitter back to Watchtower.
async fn build_rca() -> Result<Router, String> {
    let dsn = require_env("HINDSIGHT_DATABASE_URL")?;
    let pg = hindsight::store::PgStore::connect(&dsn)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    pg.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    tracing::info!("rca (hindsight) store ready");

    // Read-only Sift logs feed (lazily connected — a down Sift DB never blocks startup).
    let logs: Arc<dyn hindsight::feeds::sift::LogReader> =
        match std::env::var("SIFT_DATABASE_URL").ok().filter(|v| !v.is_empty()) {
            Some(sift_dsn) => match hindsight::feeds::sift::PgLogReader::connect_lazy(&sift_dsn) {
                Ok(r) => {
                    tracing::info!("hindsight Sift logs feed wired (read-only pool)");
                    Arc::new(r)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "invalid SIFT_DATABASE_URL — logs feed empty");
                    Arc::new(hindsight::feeds::sift::InMemoryLogReader::empty())
                }
            },
            None => Arc::new(hindsight::feeds::sift::InMemoryLogReader::empty()),
        };

    let config = hindsight::config::Config::from_env();
    let audit_enabled = std::env::var("AUDIT_ENABLED")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let audit = hindsight::audit::AuditSink::start(
        audit_enabled,
        &config.watchtower_url,
        std::env::var("AUDIT_INGEST_TOKEN").ok().as_deref(),
    );

    let state = hindsight::AppState {
        config: Arc::new(config),
        store: Arc::new(pg),
        logs,
        audit,
    };
    Ok(hindsight::app(state))
}

/// Read a required env var, error when unset/empty.
fn require_env(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{key} is required")),
    }
}

/// Read the first set+non-empty of `keys`, error when none are set.
fn require_env_any(keys: &[&str]) -> Result<String, String> {
    for k in keys {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
    }
    Err(format!("one of {keys:?} is required"))
}

fn fatal(surface: &str, err: String) -> ! {
    tracing::error!(surface, error = %err, "failed to build sentinel surface");
    std::process::exit(1);
}

/// GET `/healthz` over a raw TCP socket on the loopback. Returns the process exit code.
fn run_healthcheck() -> i32 {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let port = bind_addr.rsplit(':').next().unwrap_or("8500");
    let target = format!("127.0.0.1:{port}");
    match healthcheck_once(&target) {
        Ok(true) => 0,
        Ok(false) => {
            eprintln!("healthcheck: {target} did not return 200");
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {target} error: {e}");
            1
        }
    }
}

fn healthcheck_once(target: &str) -> std::io::Result<bool> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf.lines().next().unwrap_or("").contains("200"))
}
