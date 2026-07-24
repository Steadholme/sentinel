//! End-to-end alert-rule contract test (NO database).
//!
//! Covers SSO + CSRF creation, mirror auditing of the rule write, append-only match markers, and
//! the dashboard alert section. Existing ingest remains a single sealed event response.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use watchtower::auth::csrf_token;
use watchtower::config::DEFAULT_INGEST_TOKEN;
use watchtower::{app, build_dev_state, AppState};

const ADMIN: &str = "admin@steadholme.local";

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

fn token_for(email: &str) -> String {
    csrf_token(DEFAULT_INGEST_TOKEN, email)
}

fn post_rule_json(
    email: Option<&str>,
    csrf: Option<&str>,
    action: Option<&str>,
    severity: Option<&str>,
) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/api/alert-rules")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(email) = email {
        b = b.header("x-auth-email", email);
    }
    b.body(Body::from(
        serde_json::json!({
            "csrf": csrf,
            "name": "Login failures",
            "action": action,
            "severity": severity
        })
        .to_string(),
    ))
    .unwrap()
}

fn post_event(action: &str, actor: &str, severity: &str) -> Request<Body> {
    post_event_with_key(action, actor, severity, None)
}

fn post_event_with_key(
    action: &str,
    actor: &str,
    severity: &str,
    idempotency_key: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/events")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {DEFAULT_INGEST_TOKEN}"),
        );
    if let Some(key) = idempotency_key {
        builder = builder.header("idempotency-key", key);
    }
    builder
        .body(Body::from(
            serde_json::json!({
                "actor": actor,
                "action": action,
                "target": "keystone",
                "severity": severity,
                "detail": "from test",
                "source": "keystone"
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn alert_rules_mark_future_matching_events() {
    let state = build_dev_state();

    let (status, _) = call(
        &state,
        post_rule_json(None, Some("x"), Some("login.failure"), Some("warning")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(
        &state,
        post_rule_json(Some(ADMIN), None, Some("login.failure"), Some("warning")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let tok = token_for(ADMIN);
    let (status, rule) = json_call(
        &state,
        post_rule_json(
            Some(ADMIN),
            Some(&tok),
            Some("login.failure"),
            Some("warning"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rule["name"], "Login failures");
    assert_eq!(rule["action"], "login.failure");

    // Rule creation is mirror-audited into the hash chain.
    let (_, verify) = json_call(&state, get("/api/verify")).await;
    assert_eq!(verify["ok"], true);
    assert_eq!(verify["count"], 1);

    let (status, rules) = json_call(&state, get("/api/alert-rules")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rules.as_array().unwrap().len(), 1);

    const STABLE_KEY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (status, event) = json_call(
        &state,
        post_event_with_key("login.failure", "u_bob", "warning", Some(STABLE_KEY)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event["action"], "login.failure");
    let matching_seq = event["seq"].as_i64().unwrap();

    let (status, replay) = json_call(
        &state,
        post_event_with_key("login.failure", "u_bob", "warning", Some(STABLE_KEY)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        replay, event,
        "idempotent replay returns the original event"
    );

    let (status, _) = json_call(&state, post_event("login.success", "u_bob", "info")).await;
    assert_eq!(status, StatusCode::OK);

    let (status, hits) = json_call(&state, get("/api/alerts")).await;
    assert_eq!(status, StatusCode::OK);
    let hits = hits.as_array().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["rule_name"], "Login failures");
    assert_eq!(hits[0]["event_seq"], matching_seq);
    assert_eq!(hits[0]["action"], "login.failure");

    let (_, verify) = json_call(&state, get("/api/verify")).await;
    assert_eq!(verify["ok"], true);
    assert_eq!(verify["count"], 3);

    let req = Request::builder()
        .uri("/")
        .header("x-auth-email", ADMIN)
        .body(Body::empty())
        .unwrap();
    let (status, bytes) = call(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(bytes).unwrap();
    assert!(html.contains("Login failures"));
    assert!(html.contains("Recent matches"));
    assert!(html.contains("/api/alert-rules"));
}

#[tokio::test]
async fn alert_rule_requires_a_predicate() {
    let state = build_dev_state();
    let tok = token_for(ADMIN);
    let (status, body) =
        json_call(&state, post_rule_json(Some(ADMIN), Some(&tok), None, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}
