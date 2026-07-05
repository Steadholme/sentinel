//! End-to-end HTTP flow over the in-memory store + seeded Sift reader (NO database, NO network).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate.
//! Covers: health, empty dashboard, the SSO/CSRF guards on opening incidents + adding notes,
//! the open/view/note flow, the JSON timeline merge over a seeded Sift feed, and feed-down
//! resilience (the HTTP feeds point at a dead port and degrade to "unavailable").

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use hindsight::feeds::sift::{InMemoryLogReader, LogRow};
use hindsight::store::InMemoryStore;
use hindsight::{app, build_state_with, AppState};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

fn seeded_state() -> AppState {
    let now = hindsight::now_secs();
    let logs = InMemoryLogReader::with_rows(vec![
        LogRow {
            id: "l1".to_string(),
            ts: now - 600,
            host: "web-1".to_string(),
            app: "gateway".to_string(),
            severity: "error".to_string(),
            message: "upstream 502 from sluice".to_string(),
            template_id: "t1".to_string(),
        },
        LogRow {
            id: "l2".to_string(),
            ts: now - 300,
            host: "db-1".to_string(),
            app: "fusiondb".to_string(),
            severity: "warn".to_string(),
            message: "slow query 1200ms".to_string(),
            template_id: "t2".to_string(),
        },
        LogRow {
            id: "l3".to_string(),
            ts: now - 120,
            host: "web-1".to_string(),
            app: "gateway".to_string(),
            severity: "info".to_string(), // dropped: not error/warn
            message: "request served".to_string(),
            template_id: "t3".to_string(),
        },
    ]);
    build_state_with(Arc::new(InMemoryStore::new()), Arc::new(logs))
}

#[tokio::test]
async fn full_incident_flow_in_memory() {
    let state = seeded_state();

    // --- health ------------------------------------------------------------
    let (status, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    // --- dashboard renders, mints CSRF cookie, merges the seeded Sift feed --
    let resp = app(state.clone()).oneshot(get("/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        set_cookie.contains("__Host-csrf="),
        "GET / mints CSRF cookie"
    );
    let body = body_of(resp).await;
    assert!(body.contains("Incident Timeline"));
    assert!(
        body.contains("upstream 502 from sluice"),
        "error log on timeline"
    );
    assert!(body.contains("slow query 1200ms"), "warn log on timeline");
    assert!(
        !body.contains("request served"),
        "info log excluded from timeline"
    );
    // HTTP feeds (dead default URLs) are unavailable; the seeded Sift feed is live.
    assert!(body.contains("Sift · live"));
    assert!(body.contains("Watchtower · unavailable"));
    assert!(body.contains("No incidents yet"));

    // --- POST /api/incidents without identity -> 401 -----------------------
    let form_b = form(&[
        ("title", "Nope"),
        ("window_hours", "24"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(&state, post_csrf("/api/incidents", &form_b, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // --- POST /api/incidents with bad CSRF -> 401 --------------------------
    let form_b = form(&[
        ("title", "Nope"),
        ("window_hours", "24"),
        ("csrf_token", "WRONG"),
    ]);
    let (status, _) = call(
        &state,
        post_csrf("/api/incidents", &form_b, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- open a real incident ----------------------------------------------
    let form_b = form(&[
        ("title", "Gateway 502 storm"),
        ("window_hours", "6"),
        ("csrf_token", CSRF),
    ]);
    let resp = app(state.clone())
        .oneshot(post_csrf(
            "/api/incidents",
            &form_b,
            Some(("u_alice", "alice@hf")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert!(
        location.starts_with("/incident/inc_"),
        "redirect to the new incident"
    );

    // --- dashboard now lists it --------------------------------------------
    let (_, body) = call(&state, get("/")).await;
    assert!(body.contains("Gateway 502 storm"));

    // --- incident view shows the evidence window + the seeded logs ---------
    let (status, body) = call(&state, get(&location)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Gateway 502 storm"));
    assert!(body.contains("Evidence window"));
    assert!(
        body.contains("upstream 502 from sluice"),
        "log evidence in incident window"
    );
    assert!(body.contains("No notes yet"));

    // --- add a note: missing identity -> 401 -------------------------------
    let inc_id = location.strip_prefix("/incident/").unwrap();
    let notes_path = format!("/api/incidents/{inc_id}/notes");
    let form_b = form(&[("body", "looking into it"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf(&notes_path, &form_b, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- add a note: owner succeeds ----------------------------------------
    let form_b = form(&[
        ("body", "Correlated to a sluice restart."),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf(&notes_path, &form_b, Some(("u_alice", "alice@hf"))),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, body) = call(&state, get(&location)).await;
    assert!(
        body.contains("Correlated to a sluice restart."),
        "note rendered"
    );

    // --- note on a missing incident -> 404 ---------------------------------
    let form_b = form(&[("body", "x"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf(
            "/api/incidents/inc_missing/notes",
            &form_b,
            Some(("u_alice", "alice@hf")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- a missing incident view -> 404 ------------------------------------
    let (status, _) = call(&state, get("/incident/inc_missing")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn json_timeline_merges_and_reports_feed_status() {
    let state = seeded_state();
    let now = hindsight::now_secs();
    let from = now - 3600;

    let (status, body) = call(&state, get(&format!("/api/timeline?from={from}&to=0"))).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();

    // The two error/warn logs are present; the info log is filtered out.
    let events = v["events"].as_array().unwrap();
    assert_eq!(events.len(), 2, "two error/warn logs merged");
    assert!(events.iter().all(|e| e["source"] == "sift"));
    // Newest-first ordering.
    assert_eq!(events[0]["title"], "slow query 1200ms");
    assert_eq!(events[1]["title"], "upstream 502 from sluice");

    // Feed status: Sift reached, the HTTP feeds (dead default URLs) unavailable.
    assert_eq!(v["status"]["sift"], true);
    assert_eq!(v["status"]["watchtower"], false);
    assert_eq!(v["status"]["vitals"], false);
    // The open window resolved `to=0` to "now".
    assert!(v["to"].as_i64().unwrap() >= from);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_of(resp).await)
}

async fn body_of(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

/// Build a urlencoded POST carrying the test CSRF cookie + (optionally) gateway identity.
fn post_csrf(uri: &str, body: &str, ident: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b
            .header("x-auth-subject", sub)
            .header("x-auth-email", email);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Minimal application/x-www-form-urlencoded value encoder.
fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}
