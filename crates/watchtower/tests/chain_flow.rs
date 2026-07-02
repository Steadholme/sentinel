//! End-to-end contract test against the in-memory store (NO database).
//!
//! Drives the real Router in-process via `tower::oneshot` and exercises the full surface:
//! ingest auth, chain building + verification, the LIKE/actor/since filters, and the
//! server-rendered SSO dashboard (incl. the X-Auth-Email read + the integrity badge).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use watchtower::config::DEFAULT_INGEST_TOKEN;
use watchtower::{app, build_dev_state, AppState};

// --- HTTP helpers ----------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

async fn json_call(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let (status, bytes) = call(state, req).await;
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("non-JSON body: {}", String::from_utf8_lossy(&bytes)));
    (status, value)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post_event(token: Option<&str>, json: Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/events")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(json.to_string())).unwrap()
}

async fn ingest_ok(
    state: &AppState,
    action: &str,
    actor: &str,
    severity: &str,
    detail: &str,
) -> Value {
    let (status, v) = json_call(
        state,
        post_event(
            Some(DEFAULT_INGEST_TOKEN),
            serde_json::json!({
                "actor": actor, "action": action, "target": "keystone",
                "severity": severity, "detail": detail, "source": "test"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ingest should succeed: {v}");
    v
}

async fn ingest_full(
    state: &AppState,
    action: &str,
    actor: &str,
    severity: &str,
    detail: &str,
    source: &str,
) -> Value {
    let (status, v) = json_call(
        state,
        post_event(
            Some(DEFAULT_INGEST_TOKEN),
            serde_json::json!({
                "actor": actor, "action": action, "target": "keystone",
                "severity": severity, "detail": detail, "source": source
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ingest should succeed: {v}");
    v
}

// --- tests -----------------------------------------------------------------------------

#[tokio::test]
async fn appending_events_builds_a_verifiable_chain() {
    let state = build_dev_state();

    // Empty chain verifies (genesis head).
    let (status, v) = json_call(&state, get("/api/verify")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["ok"], true);
    assert_eq!(v["count"], 0);
    assert!(v["checked_at"].as_i64().unwrap() > 0);
    assert!(v["issues"].as_array().unwrap().is_empty());
    assert_eq!(
        v["head_hash"],
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert!(v.get("first_broken_seq").is_none(), "omitted when ok");

    // Append N and confirm seq/prev_hash linkage as returned by the ingest endpoint.
    let mut prev = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    for i in 1..=25 {
        let ev = ingest_ok(
            &state,
            "login.success",
            &format!("u_{i}"),
            "info",
            &format!("entry {i}"),
        )
        .await;
        assert_eq!(ev["seq"], i, "monotonic seq");
        assert_eq!(ev["prev_hash"], prev, "each event links the previous head");
        assert!(ev["ts"].as_i64().unwrap() > 0, "server-assigned ts");
        assert_eq!(ev["hash"].as_str().unwrap().len(), 64, "sha256 hex hash");
        prev = ev["hash"].as_str().unwrap().to_string();
    }

    // Whole chain verifies; head_hash is the last event's hash.
    let (_, v) = json_call(&state, get("/api/verify")).await;
    assert_eq!(v["ok"], true);
    assert_eq!(v["count"], 25);
    assert_eq!(v["head_hash"], prev);
    assert!(v.get("first_broken_seq").is_none());
}

#[tokio::test]
async fn ingest_requires_the_bearer_token() {
    let state = build_dev_state();

    // No token -> 401 + WWW-Authenticate.
    let resp = app(state.clone())
        .oneshot(post_event(None, serde_json::json!({ "action": "x" })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer"
    );

    // Wrong token -> 401.
    let (status, _) = call(
        &state,
        post_event(Some("not-the-token"), serde_json::json!({ "action": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Nothing was appended.
    let (_, v) = json_call(&state, get("/api/verify")).await;
    assert_eq!(v["count"], 0);

    // Correct token -> 200.
    let (status, _) = call(
        &state,
        post_event(
            Some(DEFAULT_INGEST_TOKEN),
            serde_json::json!({ "action": "x" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn list_filters_by_q_actor_and_since() {
    let state = build_dev_state();
    ingest_full(
        &state,
        "login.success",
        "u_admin",
        "info",
        "password login from 10.0.0.4",
        "keystone",
    )
    .await;
    ingest_full(
        &state,
        "login.failure",
        "u_bob",
        "warning",
        "bad \"password\", check",
        "keystone",
    )
    .await;
    ingest_full(
        &state,
        "token.issue",
        "u_admin",
        "info",
        "issued access token",
        "keyward",
    )
    .await;
    ingest_full(
        &state,
        "cert.revoke",
        "u_admin",
        "critical",
        "revoked leaf serial 0badc0de",
        "hindsight",
    )
    .await;

    // q = case-insensitive LIKE over action/target/detail.
    let (status, v) = json_call(&state, get("/api/events?q=PASSWORD")).await;
    assert_eq!(status, StatusCode::OK);
    let arr = v.as_array().unwrap();
    assert_eq!(
        arr.len(),
        2,
        "two events mention 'password' (case-insensitive)"
    );

    // q matches the action text too.
    let (_, v) = json_call(&state, get("/api/events?q=revoke")).await;
    assert_eq!(v.as_array().unwrap().len(), 1);

    // actor exact match (newest-first ordering).
    let (_, v) = json_call(&state, get("/api/events?actor=u_admin")).await;
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["action"], "cert.revoke", "newest first");

    // source and severity exact filters.
    let (_, v) = json_call(&state, get("/api/events?source=keystone")).await;
    assert_eq!(v.as_array().unwrap().len(), 2);
    let (_, v) = json_call(&state, get("/api/events?severity=critical")).await;
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["action"], "cert.revoke");

    // combined actor + q.
    let (_, v) = json_call(&state, get("/api/events?actor=u_admin&q=token")).await;
    assert_eq!(v.as_array().unwrap().len(), 1);

    // since = ts lower bound; a far-future bound excludes everything.
    let (_, v) = json_call(&state, get("/api/events?since=99999999999999")).await;
    assert_eq!(v.as_array().unwrap().len(), 0);
    // a zero bound includes everything.
    let (_, v) = json_call(&state, get("/api/events?since=0")).await;
    assert_eq!(v.as_array().unwrap().len(), 4);
    // until = ts upper bound; zero excludes every normal event timestamp.
    let (_, v) = json_call(&state, get("/api/events?until=0")).await;
    assert_eq!(v.as_array().unwrap().len(), 0);

    // limit/offset page the backward-compatible array response.
    let (_, v) = json_call(&state, get("/api/events?limit=2&offset=1")).await;
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["action"], "token.issue");
    assert_eq!(arr[1]["action"], "login.failure");

    // /api/events/search adds total/next metadata without changing /api/events shape.
    let (_, v) = json_call(&state, get("/api/events/search?actor=u_admin&limit=2")).await;
    assert_eq!(v["total"], 3);
    assert_eq!(v["limit"], 2);
    assert_eq!(v["offset"], 0);
    assert_eq!(v["next_offset"], 2);
    assert_eq!(v["items"].as_array().unwrap().len(), 2);

    // CSV export uses the same filters and escapes quotes/commas.
    let (status, bytes) = call(&state, get("/api/events/export?format=csv&q=PASSWORD")).await;
    assert_eq!(status, StatusCode::OK);
    let csv = String::from_utf8(bytes).unwrap();
    assert!(csv.starts_with("seq,ts,actor,action,target,severity,detail,source,prev_hash,hash"));
    assert!(csv.contains("\"bad \"\"password\"\", check\""));

    let (status, v) = json_call(
        &state,
        get("/api/events/export?format=json&source=hindsight"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 1);

    // empty params behave as absent (?actor= returns all).
    let (_, v) = json_call(&state, get("/api/events?actor=")).await;
    assert_eq!(v.as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn dashboard_renders_with_identity_and_integrity_badge() {
    let state = build_dev_state();
    ingest_ok(&state, "login.success", "u_admin", "info", "hello <world>").await;
    ingest_ok(&state, "cert.revoke", "u_admin", "critical", "revoked").await;

    // GET / with the Sluice-injected X-Auth-Email -> server-rendered HTML.
    let req = Request::builder()
        .uri("/")
        .header("x-auth-email", "admin@holdfast.local")
        .body(Body::empty())
        .unwrap();
    let (status, bytes) = call(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(bytes).unwrap();
    assert!(
        html.contains("admin@holdfast.local"),
        "shows signed-in email"
    );
    assert!(
        html.contains("/_gw/auth/logout"),
        "logout points at the gateway"
    );
    assert!(
        html.contains("integ-ok"),
        "green integrity badge for a valid chain"
    );
    assert!(html.contains("Verified"), "badge text");
    assert!(html.contains("login.success"), "timeline shows events");
    assert!(html.contains("Alert rules"), "alert section rendered");
    assert!(
        html.contains("/api/events/export?"),
        "export links rendered"
    );
    // Producer-supplied text is HTML-escaped (no raw angle brackets in detail).
    assert!(html.contains("hello &lt;world&gt;"), "detail is escaped");
    assert!(!html.contains("hello <world>"), "no unescaped detail leaks");

    // The gateway forwards its route prefix unmodified -> the dashboard still renders.
    let req = Request::builder()
        .uri("/watchtower")
        .header("x-auth-email", "admin@holdfast.local")
        .body(Body::empty())
        .unwrap();
    let (status, bytes) = call(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(bytes).unwrap().contains("Audit timeline"));
}

#[tokio::test]
async fn healthz_is_public() {
    let state = build_dev_state();
    let (status, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ok");
}
