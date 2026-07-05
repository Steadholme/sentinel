//! Concurrency STRESS test for the PostgreSQL store (liveness / no-wedge guarantee).
//!
//! Runs ONLY when `STRESS_DATABASE_URL` is set (it needs an external Postgres). When unset the
//! test prints a note and returns early — it never fails the default `cargo test` run, which
//! stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name wt-stresspg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=watchtower \
//!   -p 127.0.0.1:55443:5432 postgres:18-alpine
//! STRESS_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55443/watchtower \
//!   cargo test --test pg_stress -- --nocapture
//! docker rm -f wt-stresspg
//! ```
//!
//! WHAT IT PROVES: full-chain READS (`/api/verify`, which calls `all_events` + recomputes the
//! whole chain) interleaved with append BURSTS (`POST /events`) plus a constant stream of
//! `/healthz` probes must NEVER wedge the serving runtime. Every request completes inside a
//! tight deadline, `/healthz` (which touches no store) stays fast throughout, and the chain
//! still verifies with the exact expected count at the end.
//!
//! The runtime is deliberately small (`worker_threads = 4`) and the offered concurrency is much
//! larger, so the PRE-FIX path (synchronous `Store` driven by `block_in_place` +
//! `Handle::block_on` on the serving runtime, append serialized by a std `Mutex` held across the
//! block) deadlocks here: more concurrent `block_in_place` calls than worker threads leaves no
//! thread to drive the IO driver, so even `/healthz` stops responding and the deadlines trip.
//! The async-store fix never blocks a worker, so it passes comfortably.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use watchtower::config::DEFAULT_INGEST_TOKEN;
use watchtower::store::PgStore;
use watchtower::{app, build_dev_state, AppState};

// --- load shape -------------------------------------------------------------------------
const SEED_EVENTS: usize = 60; // pre-load so every full-chain read has real work to do
const READERS: usize = 24; // concurrent full-chain readers (/api/verify)
const READS_EACH: usize = 12;
const APPENDERS: usize = 24; // concurrent append bursts (POST /events)
const APPENDS_EACH: usize = 12;
const HEALTH_PROBERS: usize = 8; // concurrent /healthz probers (touch no store)
const HEALTH_EACH: usize = 60;

// --- deadlines --------------------------------------------------------------------------
/// Any single request taking longer than this counts as a wedge.
const PER_OP_DEADLINE: Duration = Duration::from_secs(5);
/// `/healthz` touches no store — it must stay snappy even under full read+append pressure.
const HEALTH_DEADLINE: Duration = Duration::from_secs(2);
/// The whole interleaved storm must finish well within this bound.
const TOTAL_DEADLINE: Duration = Duration::from_secs(45);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reads_appends_and_healthz_never_wedge() {
    let Ok(url) = std::env::var("STRESS_DATABASE_URL") else {
        eprintln!(
            "NOTE: STRESS_DATABASE_URL not set — skipping Postgres concurrency stress test (needs \
             external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate / clean slate -----------------------------------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect to STRESS_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    let raw = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("DELETE FROM audit_events")
        .execute(&raw)
        .await
        .unwrap();

    let mut state = build_dev_state();
    state.store = Arc::new(pg);

    // --- seed a non-trivial chain ------------------------------------------
    for i in 1..=SEED_EVENTS {
        let v = ingest_one(
            &state,
            &format!("seed_{i}"),
            "seed.event",
            "info",
            &format!("seed {i}"),
        )
        .await;
        assert_eq!(
            v["seq"], i as i64,
            "seed appends are serialized + monotonic"
        );
    }

    // Shared counters so the summary proves real work happened (not a no-op pass).
    let reads_done = Arc::new(AtomicU64::new(0));
    let appends_done = Arc::new(AtomicU64::new(0));
    let health_done = Arc::new(AtomicU64::new(0));
    let max_health_us = Arc::new(AtomicU64::new(0));

    let started = Instant::now();
    let mut handles = Vec::new();

    // Full-chain READ storm: GET /api/verify recomputes the entire chain every call.
    for r in 0..READERS {
        let state = state.clone();
        let reads_done = reads_done.clone();
        handles.push(tokio::spawn(async move {
            for k in 0..READS_EACH {
                let (status, body) = oneshot_json(&state, get("/api/verify"), PER_OP_DEADLINE)
                    .await
                    .unwrap_or_else(|| {
                        panic!("reader {r} verify #{k} WEDGED (> {PER_OP_DEADLINE:?})")
                    });
                assert_eq!(status, StatusCode::OK, "verify status");
                assert_eq!(body["ok"], true, "chain stays valid under concurrency");
                reads_done.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Append BURSTS: POST /events. The store serializes these; the chain must stay monotonic.
    for a in 0..APPENDERS {
        let state = state.clone();
        let appends_done = appends_done.clone();
        handles.push(tokio::spawn(async move {
            for k in 0..APPENDS_EACH {
                let req = post_event(
                    &format!("worker_{a}"),
                    "burst.append",
                    "info",
                    &format!("a{a}-k{k}"),
                );
                let (status, body) = oneshot_json(&state, req, PER_OP_DEADLINE)
                    .await
                    .unwrap_or_else(|| {
                        panic!("appender {a} append #{k} WEDGED (> {PER_OP_DEADLINE:?})")
                    });
                assert_eq!(status, StatusCode::OK, "append status: {body}");
                appends_done.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // /healthz storm: touches NO store, so it must answer near-instantly the whole time.
    for h in 0..HEALTH_PROBERS {
        let state = state.clone();
        let health_done = health_done.clone();
        let max_health_us = max_health_us.clone();
        handles.push(tokio::spawn(async move {
            for k in 0..HEALTH_EACH {
                let t0 = Instant::now();
                let (status, _) = oneshot_bytes(&state, get("/healthz"), HEALTH_DEADLINE)
                    .await
                    .unwrap_or_else(|| {
                        panic!("/healthz prober {h} hit #{k} WEDGED (> {HEALTH_DEADLINE:?}) — runtime starved")
                    });
                assert_eq!(status, StatusCode::OK, "healthz status");
                let us = t0.elapsed().as_micros() as u64;
                max_health_us.fetch_max(us, Ordering::Relaxed);
                health_done.fetch_add(1, Ordering::Relaxed);
                // Brief yield so probes spread across the whole load window.
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }));
    }

    // Whole storm must finish well within the total deadline (catches a soft wedge too).
    let all = futures_join_all(handles);
    tokio::time::timeout(TOTAL_DEADLINE, all)
        .await
        .expect("concurrent read+append+healthz storm exceeded TOTAL_DEADLINE — runtime wedged");

    let elapsed = started.elapsed();

    // --- final chain integrity ---------------------------------------------
    let (status, v) = oneshot_json(&state, get("/api/verify"), PER_OP_DEADLINE)
        .await
        .expect("final verify wedged");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["ok"], true, "chain verifies after the storm");
    let expected = (SEED_EVENTS + APPENDERS * APPENDS_EACH) as i64;
    assert_eq!(
        v["count"], expected,
        "every append landed exactly once, chain intact"
    );

    let max_health_ms = max_health_us.load(Ordering::Relaxed) as f64 / 1000.0;
    println!(
        "PG STRESS OK: {} reads + {} appends + {} healthz in {:?} (worker_threads=4); \
         final chain count={} ok=true; max /healthz latency={:.1}ms (deadline {}ms)",
        reads_done.load(Ordering::Relaxed),
        appends_done.load(Ordering::Relaxed),
        health_done.load(Ordering::Relaxed),
        elapsed,
        expected,
        max_health_ms,
        HEALTH_DEADLINE.as_millis(),
    );

    sqlx::query("DELETE FROM audit_events")
        .execute(&raw)
        .await
        .unwrap();
}

// --- helpers ----------------------------------------------------------------------------

/// Await every handle, panicking if any task panicked (carries the inner assert message).
async fn futures_join_all(handles: Vec<tokio::task::JoinHandle<()>>) {
    for h in handles {
        h.await.expect("a stress task panicked");
    }
}

/// Drive one request through the real router with a per-op timeout. `None` == timed out.
async fn oneshot_bytes(
    state: &AppState,
    req: Request<Body>,
    deadline: Duration,
) -> Option<(StatusCode, Vec<u8>)> {
    let fut = async {
        let resp = app(state.clone()).oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    };
    tokio::time::timeout(deadline, fut).await.ok()
}

async fn oneshot_json(
    state: &AppState,
    req: Request<Body>,
    deadline: Duration,
) -> Option<(StatusCode, Value)> {
    let (status, bytes) = oneshot_bytes(state, req, deadline).await?;
    Some((status, serde_json::from_slice(&bytes).unwrap()))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post_event(actor: &str, action: &str, severity: &str, detail: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/events")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {DEFAULT_INGEST_TOKEN}"),
        )
        .body(Body::from(
            serde_json::json!({
                "actor": actor, "action": action, "target": "keystone",
                "severity": severity, "detail": detail, "source": "stress"
            })
            .to_string(),
        ))
        .unwrap()
}

async fn ingest_one(
    state: &AppState,
    actor: &str,
    action: &str,
    severity: &str,
    detail: &str,
) -> Value {
    let (status, v) = oneshot_json(
        state,
        post_event(actor, action, severity, detail),
        PER_OP_DEADLINE,
    )
    .await
    .expect("seed ingest wedged");
    assert_eq!(status, StatusCode::OK, "seed ingest ok: {v}");
    v
}
