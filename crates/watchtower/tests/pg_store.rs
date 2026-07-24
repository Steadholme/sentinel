//! PostgreSQL `Store` integration test.
//!
//! Explicitly ignored by the default database-free test run. Spin up a throwaway Postgres and
//! run the ignored gate with `TEST_DATABASE_URL`:
//!
//! ```text
//! docker run --rm -d --name wt-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=watchtower \
//!   -p 127.0.0.1:55442:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55442/watchtower \
//!   cargo test --test pg_store -- --ignored --nocapture
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
use sqlx::Row;
use tower::ServiceExt;
use watchtower::alerts::make_alert_rule;
use watchtower::config::DEFAULT_INGEST_TOKEN;
use watchtower::store::PgStore;
use watchtower::{app, build_dev_state, AppState};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; run this PostgreSQL gate explicitly with --ignored"]
async fn pg_store_full_integration() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set for the explicit PostgreSQL gate");

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // Wire the PG store behind Arc<dyn Store> in an otherwise-dev AppState.
    let mut state = build_dev_state();
    state.store = Arc::new(pg);

    // Separate raw pool to (a) reset the table for a clean run and (b) later simulate a
    // raw-DB tamper that the app's append-only API can never perform.
    let raw = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query("DELETE FROM alert_matches")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM alert_rules")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM audit_idempotency_keys")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM audit_events")
        .execute(&raw)
        .await
        .unwrap();

    // --- cross-process idempotency + chain serialization ------------------
    // A second PgStore has a distinct in-process mutex, so only the database transaction lock
    // can make these requests one global writer.
    let mut peer_state = build_dev_state();
    peer_state.store = Arc::new(
        PgStore::connect(&url)
            .await
            .expect("connect independent PgStore"),
    );
    state
        .store
        .insert_alert_rule(make_alert_rule(
            "Murmur sends".to_string(),
            None,
            Some("message.send".to_string()),
            Some("murmur".to_string()),
            None,
            "test".to_string(),
            1,
        ))
        .await
        .unwrap();

    const STABLE_KEY: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let (first, retry) = tokio::join!(
        ingest_with_key(
            &state,
            "u_1",
            "message.send",
            "info",
            "m_1",
            "murmur",
            STABLE_KEY,
        ),
        ingest_with_key(
            &peer_state,
            "u_1",
            "message.send",
            "info",
            "m_1",
            "murmur",
            STABLE_KEY,
        )
    );
    assert_eq!(retry, first, "lost-2xx retry returns original AuditEvent");
    assert_eq!(first["seq"], 1);

    let event_count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM audit_events")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
    let key_count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM audit_idempotency_keys")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
    let match_count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM alert_matches")
        .fetch_one(&raw)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
    assert_eq!(event_count, 1, "one authoritative audit row");
    assert_eq!(key_count, 1, "event and key claim committed together");
    assert_eq!(
        match_count, 1,
        "replay does not record an alert match again"
    );

    let digest_row =
        sqlx::query("SELECT key_hash, request_hash, event_seq FROM audit_idempotency_keys")
            .fetch_one(&raw)
            .await
            .unwrap();
    let key_hash: String = digest_row.try_get("key_hash").unwrap();
    let request_hash: String = digest_row.try_get("request_hash").unwrap();
    assert_eq!(key_hash.len(), 64);
    assert_eq!(request_hash.len(), 64);
    assert_ne!(
        key_hash, STABLE_KEY,
        "producer key is not stored in plaintext"
    );
    assert_eq!(digest_row.try_get::<i64, _>("event_seq").unwrap(), 1);

    let (status, conflict) = json(
        &state,
        event_request(
            "u_1",
            "message.send",
            "info",
            "different payload",
            "murmur",
            Some(STABLE_KEY),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["error"], "idempotency_conflict");

    // The same opaque key belongs to an independent namespace for another producer/source.
    let other_source = ingest_with_key(
        &state,
        "u_1",
        "gateway.allow",
        "info",
        "m_1",
        "sluice",
        STABLE_KEY,
    )
    .await;
    assert_eq!(other_source["seq"], 2);

    // Two distinct claims through independent PgStore instances must still observe consecutive
    // heads and leave a valid chain.
    const KEY_TWO: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const KEY_THREE: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let (unique_a, unique_b) = tokio::join!(
        ingest_with_key(&state, "u_2", "token.issue", "info", "a", "murmur", KEY_TWO,),
        ingest_with_key(
            &peer_state,
            "u_3",
            "token.issue",
            "info",
            "b",
            "murmur",
            KEY_THREE,
        )
    );
    let mut seqs = [
        unique_a["seq"].as_i64().unwrap(),
        unique_b["seq"].as_i64().unwrap(),
    ];
    seqs.sort_unstable();
    assert_eq!(seqs, [3, 4]);
    let (_, verified) = json(&state, get("/api/verify")).await;
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["count"], 4);

    // Reset before the existing append/tamper scenario.
    sqlx::query("DELETE FROM alert_matches")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM alert_rules")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM audit_idempotency_keys")
        .execute(&raw)
        .await
        .unwrap();
    sqlx::query("DELETE FROM audit_events")
        .execute(&raw)
        .await
        .unwrap();

    // --- append N via HTTP, confirm chain links ----------------------------
    let mut prev = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    for i in 1..=12 {
        let ev = ingest(
            &state,
            &format!("u_{i}"),
            "login.success",
            "info",
            &format!("pg entry {i}"),
        )
        .await;
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
        .header("x-auth-email", "auditor@steadholme.local")
        .body(Body::empty())
        .unwrap();
    let (status, bytes) = call(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(bytes).unwrap();
    assert!(html.contains("integ-bad"), "red badge on tamper");
    assert!(html.contains("TAMPERED at seq 6"));

    // Cleanup the throwaway table state.
    sqlx::query("DELETE FROM audit_events")
        .execute(&raw)
        .await
        .unwrap();
    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + serialized append + verify + LIKE/actor \
         filters + out-of-band tamper detected at exact seq"
    );
}

// --- helpers ---------------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

async fn json(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let (status, bytes) = call(state, req).await;
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

async fn ingest(
    state: &AppState,
    actor: &str,
    action: &str,
    severity: &str,
    detail: &str,
) -> Value {
    let req = event_request(actor, action, severity, detail, "test", None);
    let (status, v) = json(state, req).await;
    assert_eq!(status, StatusCode::OK, "ingest ok: {v}");
    v
}

#[allow(clippy::too_many_arguments)]
async fn ingest_with_key(
    state: &AppState,
    actor: &str,
    action: &str,
    severity: &str,
    detail: &str,
    source: &str,
    key: &str,
) -> Value {
    let (status, value) = json(
        state,
        event_request(actor, action, severity, detail, source, Some(key)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "idempotent ingest ok: {value}");
    value
}

fn event_request(
    actor: &str,
    action: &str,
    severity: &str,
    detail: &str,
    source: &str,
    key: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/events")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {DEFAULT_INGEST_TOKEN}"),
        );
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key);
    }
    builder
        .body(Body::from(
            serde_json::json!({
                "actor": actor, "action": action, "target": "keystone",
                "severity": severity, "detail": detail, "source": source
            })
            .to_string(),
        ))
        .unwrap()
}
