//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the
//! test prints a note and returns early — it never fails the default `cargo test` run, which
//! stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name wt-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=watchtower \
//!   -p 127.0.0.1:55442:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55442/watchtower \
//!   cargo test --test pg_store -- --nocapture
//! docker rm -f wt-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use watchtower::config::DEFAULT_INGEST_TOKEN;
use watchtower::store::PgStore;
use watchtower::{app, build_dev_state, AppState};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test (needs external \
             Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url).await.expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // Wire the PG store behind Arc<dyn Store> in an otherwise-dev AppState.
    let mut state = build_dev_state();
    state.store = Arc::new(pg);

    // Separate raw pool to (a) reset the table for a clean run and (b) later simulate a
    // raw-DB tamper that the app's append-only API can never perform.
    let raw = PgPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
    sqlx::query("DELETE FROM audit_events").execute(&raw).await.unwrap();

    // --- append N via HTTP, confirm chain links ----------------------------
    let mut prev =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    for i in 1..=12 {
        let ev = ingest(&state, &format!("u_{i}"), "login.success", "info", &format!("pg entry {i}")).await;
        assert_eq!(ev["seq"], i);
        assert_eq!(ev["prev_hash"], prev);
        prev = ev["hash"].as_str().unwrap().to_string();
    }

    // Whole chain verifies; head_hash persisted = last hash (the externally-anchorable head).
    let (_, v) = json(&state, get("/api/verify")).await;
    assert_eq!(v["ok"], true);
    assert_eq!(v["count"], 12);
    assert_eq!(v["head_hash"], prev, "persisted head hash is anchorable");

    // LIKE filter round-trips through Postgres lower(..) LIKE ..
    let (_, v) = json(&state, get("/api/events?q=ENTRY%207")).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    let (_, v) = json(&state, get("/api/events?actor=u_3")).await;
    assert_eq!(v.as_array().unwrap().len(), 1);

    // --- simulate raw-storage tamper of a MIDDLE event's detail ------------
    // The service has no update path; an attacker with direct DB access rewrites the detail of
    // seq 6 but cannot recompute the whole forward chain. verify() must pinpoint seq 6.
    sqlx::query("UPDATE audit_events SET detail = $1 WHERE seq = $2")
        .bind("TAMPERED OUT OF BAND")
        .bind(6_i64)
        .execute(&raw)
        .await
        .unwrap();

    let (_, v) = json(&state, get("/api/verify")).await;
    assert_eq!(v["ok"], false, "tamper detected");
    assert_eq!(v["first_broken_seq"], 6, "exact first broken seq");
    assert_eq!(v["count"], 12);

    // The dashboard reflects the tamper with the red badge.
    let req = Request::builder()
        .uri("/watchtower")
        .header("x-auth-email", "auditor@holdfast.local")
        .body(Body::empty())
        .unwrap();
    let (status, bytes) = call(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(bytes).unwrap();
    assert!(html.contains("integ-bad"), "red badge on tamper");
    assert!(html.contains("TAMPERED at seq 6"));

    // Cleanup the throwaway table state.
    sqlx::query("DELETE FROM audit_events").execute(&raw).await.unwrap();
    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + serialized append + verify + LIKE/actor \
         filters + out-of-band tamper detected at exact seq"
    );
}

// --- helpers ---------------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
    (status, bytes)
}

async fn json(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let (status, bytes) = call(state, req).await;
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

async fn ingest(state: &AppState, actor: &str, action: &str, severity: &str, detail: &str) -> Value {
    let req = Request::builder()
        .method("POST")
        .uri("/events")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {DEFAULT_INGEST_TOKEN}"))
        .body(Body::from(
            serde_json::json!({
                "actor": actor, "action": action, "target": "keystone",
                "severity": severity, "detail": detail, "source": "test"
            })
            .to_string(),
        ))
        .unwrap();
    let (status, v) = json(state, req).await;
    assert_eq!(status, StatusCode::OK, "ingest ok: {v}");
    v
}
