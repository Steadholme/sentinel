//! Contract-level HTTP tests for the authenticated Hindsight comparator.
//!
//! These tests drive the real Axum router in process. They deliberately use
//! invalid upstream URLs so evidence degradation is deterministic and no
//! network or database is required.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Method, Request, Response, StatusCode};
use hindsight::audit::AuditSink;
use hindsight::config::Config;
use hindsight::feeds::sift::{InMemoryLogReader, LogReader, LogRow};
use hindsight::store::{
    InMemoryStore, IncidentCase, NewIncident, NewNote, OperatorNote, ResolveCommand, ResolveResult,
    Store, StoreError, StoreFailureKind,
};
use hindsight::view_contract::{
    ActorTruth, BoundedDisplayEmail, BoundedRows, BoundedSubject, BoundedTitle, IncidentId,
    IncidentLifecycle,
};
use hindsight::{app, AppState};
use serde_json::Value;
use tower::ServiceExt;

const CSRF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const COMMAND_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const COMMAND_B: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SUBJECT: &str = "operator-subject";
const EMAIL: &str = "operator@example.invalid";

fn test_state(store: Arc<dyn Store>, logs: Arc<dyn LogReader>) -> AppState {
    AppState {
        config: Arc::new(Config {
            bind_addr: "127.0.0.1:0".to_string(),
            vitals_url: "invalid".to_string(),
            watchtower_url: "invalid".to_string(),
        }),
        store,
        logs,
        audit: AuditSink::disabled(),
    }
}

fn empty_state() -> (AppState, Arc<InMemoryStore>) {
    let store = Arc::new(InMemoryStore::new());
    (
        test_state(store.clone(), Arc::new(InMemoryLogReader::empty())),
        store,
    )
}

fn seeded_state() -> (AppState, Arc<InMemoryStore>) {
    let store = Arc::new(InMemoryStore::new());
    let now = hindsight::now_secs();
    let logs = InMemoryLogReader::with_rows(vec![
        LogRow {
            id: "log_error".to_string(),
            ts: now - 600,
            host: "edge-1".to_string(),
            app: "sluice".to_string(),
            severity: "error".to_string(),
            message: "upstream 502 from sluice".to_string(),
            template_id: "gateway-upstream".to_string(),
        },
        LogRow {
            id: "log_warn".to_string(),
            ts: now - 300,
            host: "db-1".to_string(),
            app: "fusiondb".to_string(),
            severity: "warn".to_string(),
            message: "slow query 1200ms".to_string(),
            template_id: "database-slow-query".to_string(),
        },
        LogRow {
            id: "log_info".to_string(),
            ts: now - 120,
            host: "edge-1".to_string(),
            app: "sluice".to_string(),
            severity: "info".to_string(),
            message: "request served".to_string(),
            template_id: "request-ok".to_string(),
        },
    ]);
    (test_state(store.clone(), Arc::new(logs)), store)
}

async fn seed_incident(store: &InMemoryStore, id: &str, title: &str) -> IncidentCase {
    let now = hindsight::now_secs();
    store
        .create_incident(NewIncident {
            id: IncidentId::parse(id).unwrap(),
            title: BoundedTitle::parse(title).unwrap(),
            from_ts_s: now - 3_600,
            actor_sub: BoundedSubject::parse(SUBJECT).unwrap(),
            display_email: Some(BoundedDisplayEmail::parse(EMAIL).unwrap()),
            created_at_s: now,
        })
        .await
        .unwrap()
}

async fn send(state: &AppState, request: Request<Body>) -> Response<Body> {
    app(state.clone()).oneshot(request).await.unwrap()
}

async fn body(response: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, String) {
    let response = send(state, request).await;
    let status = response.status();
    (status, body(response).await)
}

fn request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn authenticated(mut request: Request<Body>) -> Request<Body> {
    request
        .headers_mut()
        .insert("x-auth-subject", SUBJECT.parse().unwrap());
    request
        .headers_mut()
        .insert("x-auth-email", EMAIL.parse().unwrap());
    request
}

fn get(uri: &str) -> Request<Body> {
    request(Method::GET, uri)
}

fn get_auth(uri: &str) -> Request<Body> {
    authenticated(get(uri))
}

fn post_form(
    uri: &str,
    pairs: &[(&str, &str)],
    identity: Option<(&str, &str)>,
    cookie: Option<&str>,
) -> Request<Body> {
    let encoded = form(pairs);
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        .header(header::CONTENT_LENGTH, encoded.len().to_string());
    if let Some((subject, email)) = identity {
        builder = builder
            .header("x-auth-subject", subject)
            .header("x-auth-email", email);
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::from(encoded)).unwrap()
}

fn valid_post(uri: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    post_form(
        uri,
        pairs,
        Some((SUBJECT, EMAIL)),
        Some(&format!("__Host-csrf={CSRF}")),
    )
}

#[tokio::test]
async fn versioned_stylesheet_is_immutable_and_linked() {
    let (state, _) = empty_state();
    let response = send(&state, get("/assets/hindsight-20260909.css")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/css; charset=utf-8"
    );
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );

    let response = send(&state, get_auth("/")).await;
    let html = body(response).await;
    assert!(html.contains("/assets/hindsight-20260909.css"));
    assert!(!html.contains("<style"));
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", enc(key), enc(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn enc(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(char::from(byte));
            }
            b' ' => output.push('+'),
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

fn location(response: &Response<Body>) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn incident_id_from_location(value: &str) -> IncidentId {
    let path = value.split('#').next().unwrap();
    IncidentId::parse(path.strip_prefix("/incident/").unwrap()).unwrap()
}

fn assert_private_security(response: &Response<Body>) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    assert_eq!(
        response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
        "DENY"
    );
    assert!(response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));
    assert!(response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("font-src data:"));
}

#[derive(Default)]
struct UnavailableStore;

fn unavailable() -> StoreError {
    StoreError::Unavailable(StoreFailureKind::Query)
}

#[async_trait]
impl Store for UnavailableStore {
    async fn list_incidents_bounded(
        &self,
        _: usize,
    ) -> Result<BoundedRows<IncidentCase>, StoreError> {
        Err(unavailable())
    }

    async fn get_incident_case(&self, _: &IncidentId) -> Result<Option<IncidentCase>, StoreError> {
        Err(unavailable())
    }

    async fn create_incident(&self, _: NewIncident) -> Result<IncidentCase, StoreError> {
        Err(unavailable())
    }

    async fn list_notes_bounded(
        &self,
        _: &IncidentId,
        _: usize,
    ) -> Result<BoundedRows<OperatorNote>, StoreError> {
        Err(unavailable())
    }

    async fn add_note(&self, _: NewNote) -> Result<OperatorNote, StoreError> {
        Err(unavailable())
    }

    async fn resolve_incident(&self, _: ResolveCommand) -> Result<ResolveResult, StoreError> {
        Err(unavailable())
    }
}

struct NotesUnavailableStore {
    inner: Arc<InMemoryStore>,
}

#[async_trait]
impl Store for NotesUnavailableStore {
    async fn list_incidents_bounded(
        &self,
        limit_plus_one: usize,
    ) -> Result<BoundedRows<IncidentCase>, StoreError> {
        self.inner.list_incidents_bounded(limit_plus_one).await
    }

    async fn get_incident_case(&self, id: &IncidentId) -> Result<Option<IncidentCase>, StoreError> {
        self.inner.get_incident_case(id).await
    }

    async fn create_incident(&self, new: NewIncident) -> Result<IncidentCase, StoreError> {
        self.inner.create_incident(new).await
    }

    async fn list_notes_bounded(
        &self,
        _: &IncidentId,
        _: usize,
    ) -> Result<BoundedRows<OperatorNote>, StoreError> {
        Err(unavailable())
    }

    async fn add_note(&self, new: NewNote) -> Result<OperatorNote, StoreError> {
        self.inner.add_note(new).await
    }

    async fn resolve_incident(&self, command: ResolveCommand) -> Result<ResolveResult, StoreError> {
        self.inner.resolve_incident(command).await
    }
}

#[tokio::test]
async fn health_is_open_and_not_readiness() {
    let state = test_state(
        Arc::new(UnavailableStore),
        Arc::new(InMemoryLogReader::down()),
    );
    let response = send(&state, get("/healthz")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );
    assert!(response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .is_none());
    assert_eq!(body(response).await, "ok");
}

#[tokio::test]
async fn anonymous_read_routes_are_401() {
    let (state, _) = empty_state();
    for uri in ["/", "/incident/inc_missing"] {
        let response = send(&state, get(uri)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer"
        );
        assert_private_security(&response);
        let rendered = body(response).await;
        assert!(
            rendered.to_ascii_lowercase().starts_with("<!doctype html>"),
            "{uri}: {rendered}"
        );
        assert!(!rendered.contains("x-auth-subject"));
        assert!(rendered.contains("data-gateway-context=\"unavailable\""));
    }
    let response = send(&state, get("/api/timeline")).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer"
    );
    let rendered = body(response).await;
    let value: Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["error"]["code"], "unauthorized");
    assert!(!rendered.contains("<!doctype"));
}

#[tokio::test]
async fn dashboard_query_rejects_unknown_duplicate_and_unsupported() {
    let (state, _) = empty_state();
    for uri in [
        "/?unknown=1",
        "/?window=1&window=6",
        "/?window=2",
        "/?window=01",
        "/?window=%GG",
    ] {
        let (status, rendered) = call(&state, get_auth(uri)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {rendered}");
        assert!(rendered.contains("Window request rejected"));
        assert!(!rendered.contains("Effective window:"));
    }
}

#[tokio::test]
async fn incident_get_rejects_query_and_malformed_id_safely() {
    let (state, _) = empty_state();
    let (status, rendered) = call(&state, get_auth("/incident/inc_missing?x=1")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(rendered.contains("Window request rejected"));

    let (status, rendered) = call(&state, get_auth("/incident/not-an-incident")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(rendered.contains("Incident not found"));
    assert!(!rendered.contains("not-an-incident"));
}

#[tokio::test]
async fn authenticated_dashboard_preserves_feed_degradation() {
    let (state, _) = seeded_state();
    let (status, rendered) = call(&state, get_auth("/?window=24")).await;
    assert_eq!(status, StatusCode::OK, "{rendered}");
    assert!(rendered.contains("upstream 502 from sluice"));
    assert!(rendered.contains("slow query 1200ms"));
    assert!(!rendered.contains("request served"));
    assert!(rendered.contains("Configuration absent or invalid"));
    assert!(rendered.contains("Loaded evidence"));
    assert!(rendered.contains("data-channel=\"audit\""));
    assert!(rendered.contains("data-channel=\"log\""));
    assert!(rendered.contains("data-channel=\"metric\""));
}

#[tokio::test]
async fn authenticated_incident_missing_is_404() {
    let (state, _) = empty_state();
    let response = send(&state, get_auth("/incident/inc_missing")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_private_security(&response);
    let rendered = body(response).await;
    assert!(rendered.contains("Incident not found"));
    assert!(rendered.contains("data-gateway-context=\"authenticated\""));
}

#[tokio::test]
async fn primary_store_failure_is_503_not_404() {
    let state = test_state(
        Arc::new(UnavailableStore),
        Arc::new(InMemoryLogReader::empty()),
    );
    let response = send(&state, get_auth("/incident/inc_missing")).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(body(response)
        .await
        .contains("Hindsight data is temporarily unavailable"));

    // The dashboard's incident index is a bounded sibling section, not the
    // primary object of an incident route, so its failure remains a truthful
    // successful page rather than being confused with an empty index.
    let response = send(&state, get_auth("/")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body(response).await.contains("Section unavailable"));
}

#[tokio::test]
async fn section_store_failure_preserves_successful_siblings() {
    let inner = Arc::new(InMemoryStore::new());
    let case = seed_incident(&inner, "inc_section", "Section failure").await;
    let state = test_state(
        Arc::new(NotesUnavailableStore {
            inner: inner.clone(),
        }),
        Arc::new(InMemoryLogReader::with_rows(vec![LogRow {
            id: "visible-log".to_string(),
            ts: hindsight::now_secs() - 60,
            host: "host".to_string(),
            app: "app".to_string(),
            severity: "error".to_string(),
            message: "successful sibling evidence".to_string(),
            template_id: "template".to_string(),
        }])),
    );
    let (status, rendered) =
        call(&state, get_auth(&format!("/incident/{}", case.id.as_str()))).await;
    assert_eq!(status, StatusCode::OK, "{rendered}");
    assert!(rendered.contains("successful sibling evidence"));
    assert!(rendered.contains("Section unavailable"));
    assert!(rendered.contains("Incident opened"));
}

#[tokio::test]
async fn open_incident_native_flow_records_verified_subject() {
    let (state, store) = empty_state();
    let response = send(
        &state,
        valid_post(
            "/api/incidents",
            &[
                ("title", "Gateway 502 storm"),
                ("window_hours", "6"),
                ("csrf_token", CSRF),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_private_security(&response);
    let id = incident_id_from_location(&location(&response));
    let case = store.get_incident_case(&id).await.unwrap().unwrap();
    assert_eq!(case.title.as_str(), "Gateway 502 storm");
    assert_eq!(case.lifecycle, IncidentLifecycle::Open);
    match case.actor {
        ActorTruth::Verified {
            subject,
            display_email,
        } => {
            assert_eq!(subject.as_str(), SUBJECT);
            assert_eq!(display_email.unwrap().as_str(), EMAIL);
        }
        ActorTruth::LegacyUnclassified { .. } => panic!("new actor must be verified"),
    }
}

#[tokio::test]
async fn open_incident_invalid_form_rerenders_without_mutation() {
    let (state, store) = empty_state();
    let response = send(
        &state,
        valid_post(
            "/api/incidents",
            &[
                ("title", " \t "),
                ("window_hours", "2"),
                ("csrf_token", CSRF),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let rendered = body(response).await;
    assert!(rendered.contains("Enter an incident title"));
    assert!(rendered.contains("Choose 1, 6, 24, 72, or 168 hours"));
    assert!(rendered.contains("aria-invalid=\"true\""));
    let rows = store.list_incidents_bounded(201).await.unwrap();
    assert!(rows.rows.is_empty());

    let response = send(
        &state,
        valid_post(
            "/api/incidents",
            &[
                ("title", "Leading-zero window"),
                ("window_hours", "024"),
                ("csrf_token", CSRF),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body(response)
        .await
        .contains("Choose 1, 6, 24, 72, or 168 hours"));
    assert!(store
        .list_incidents_bounded(201)
        .await
        .unwrap()
        .rows
        .is_empty());

    let encoded = form(&[
        ("title", "Malformed charset"),
        ("window_hours", "24"),
        ("csrf_token", CSRF),
    ]);
    for content_type in [
        "application/x-www-form-urlencoded; charset=\"utf-8",
        "application/x-www-form-urlencoded; charset=utf-8\"",
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/incidents")
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, encoded.len().to_string())
            .header("x-auth-subject", SUBJECT)
            .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
            .body(Body::from(encoded.clone()))
            .unwrap();
        let response = send(&state, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{content_type}");
        let rendered = body(response).await;
        assert!(rendered.contains("Request form was rejected"));
        assert!(rendered.contains("data-gateway-context=\"unavailable\""));
    }
    let signed_length = Request::builder()
        .method(Method::POST)
        .uri("/api/incidents")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::CONTENT_LENGTH, format!("+{}", encoded.len()))
        .header("x-auth-subject", SUBJECT)
        .body(Body::from(encoded))
        .unwrap();
    assert_eq!(
        send(&state, signed_length).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn add_note_native_flow_binds_body_id_to_path() {
    let (state, store) = empty_state();
    let case = seed_incident(&store, "inc_note", "Note binding").await;
    let path = format!("/api/incidents/{}/notes", case.id.as_str());
    let response = send(
        &state,
        valid_post(
            &path,
            &[
                ("incident_id", case.id.as_str()),
                ("body", "Correlated to a Sluice restart."),
                ("csrf_token", CSRF),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(location(&response).starts_with(&format!("/incident/{}#note_", case.id)));
    let notes = store.list_notes_bounded(&case.id, 201).await.unwrap();
    assert_eq!(notes.rows.len(), 1);
    assert_eq!(notes.rows[0].incident_id, case.id);
    assert_eq!(
        notes.rows[0].body.as_str(),
        "Correlated to a Sluice restart."
    );
    assert!(matches!(notes.rows[0].actor, ActorTruth::Verified { .. }));
}

#[tokio::test]
async fn add_note_rejects_id_mismatch_unknown_and_actor_fields() {
    let (state, store) = empty_state();
    let case = seed_incident(&store, "inc_note_schema", "Strict notes").await;
    let path = format!("/api/incidents/{}/notes", case.id.as_str());
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![
            ("incident_id", "inc_other"),
            ("body", "mismatch"),
            ("csrf_token", CSRF),
        ],
        vec![
            ("incident_id", case.id.as_str()),
            ("body", "unknown"),
            ("csrf_token", CSRF),
            ("extra", "forbidden"),
        ],
        vec![
            ("incident_id", case.id.as_str()),
            ("body", "actor injection"),
            ("csrf_token", CSRF),
            ("actor_sub", "attacker"),
        ],
    ];
    for fields in cases {
        let (status, rendered) = call(&state, valid_post(&path, &fields)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rendered}");
        assert!(rendered.contains("Request form was rejected"));
        assert!(!rendered.contains("attacker"));
    }
    assert!(store
        .list_notes_bounded(&case.id, 201)
        .await
        .unwrap()
        .rows
        .is_empty());
}

#[tokio::test]
async fn first_resolve_freezes_one_instant_and_one_public_mark() {
    let (state, store) = empty_state();
    let case = seed_incident(&store, "inc_resolve", "Resolve once").await;
    let path = format!("/api/incidents/{}/resolve", case.id);
    let response = send(
        &state,
        valid_post(
            &path,
            &[
                ("incident_id", case.id.as_str()),
                ("expected_lifecycle", "open"),
                ("command_id", COMMAND_A),
                ("csrf_token", CSRF),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let redirect = location(&response);
    assert!(redirect.starts_with(&format!("/incident/{}#rm_", case.id)));
    let stored = store.get_incident_case(&case.id).await.unwrap().unwrap();
    assert_eq!(stored.lifecycle, IncidentLifecycle::Resolved);
    let mark = stored.resolution.unwrap();
    assert!(mark.mark_ref.as_str().starts_with("rm_"));
    assert!(!mark.mark_ref.as_str().contains(COMMAND_A));
    assert_eq!(stored.to_ts_s_compat, mark.resolved_at_ms.div_euclid(1_000));
}

#[tokio::test]
async fn same_command_retry_preserves_time_actor_and_mark() {
    let (state, store) = empty_state();
    let case = seed_incident(&store, "inc_retry", "Retry resolve").await;
    let path = format!("/api/incidents/{}/resolve", case.id);
    let fields = [
        ("incident_id", case.id.as_str()),
        ("expected_lifecycle", "open"),
        ("command_id", COMMAND_A),
        ("csrf_token", CSRF),
    ];
    let first = send(&state, valid_post(&path, &fields)).await;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    let first_location = location(&first);
    let first_mark = store
        .get_incident_case(&case.id)
        .await
        .unwrap()
        .unwrap()
        .resolution
        .unwrap();

    let second = send(
        &state,
        post_form(
            &path,
            &fields,
            Some(("different-operator", "different@example.invalid")),
            Some(&format!("__Host-csrf={CSRF}")),
        ),
    )
    .await;
    assert_eq!(second.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&second), first_location);
    let second_mark = store
        .get_incident_case(&case.id)
        .await
        .unwrap()
        .unwrap()
        .resolution
        .unwrap();
    assert_eq!(second_mark, first_mark);
}

#[tokio::test]
async fn different_command_retry_returns_safe_409() {
    let (state, store) = empty_state();
    let case = seed_incident(&store, "inc_conflict", "Resolve conflict").await;
    let path = format!("/api/incidents/{}/resolve", case.id);
    for (command, expected) in [
        (COMMAND_A, StatusCode::SEE_OTHER),
        (COMMAND_B, StatusCode::CONFLICT),
    ] {
        let response = send(
            &state,
            valid_post(
                &path,
                &[
                    ("incident_id", case.id.as_str()),
                    ("expected_lifecycle", "open"),
                    ("command_id", command),
                    ("csrf_token", CSRF),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), expected);
        if expected == StatusCode::CONFLICT {
            let rendered = body(response).await;
            assert!(rendered.contains("Incident already resolved"));
            assert!(rendered.contains("different command"));
            assert!(!rendered.contains(COMMAND_A));
            assert!(!rendered.contains(COMMAND_B));
        }
    }
}

#[tokio::test]
async fn resolve_rejects_bad_csrf_lifecycle_id_and_command() {
    let (state, store) = empty_state();
    let case = seed_incident(&store, "inc_reject", "Reject resolve").await;
    let path = format!("/api/incidents/{}/resolve", case.id);
    let bad_csrf = post_form(
        &path,
        &[
            ("incident_id", case.id.as_str()),
            ("expected_lifecycle", "open"),
            ("command_id", COMMAND_A),
            ("csrf_token", COMMAND_B),
        ],
        Some((SUBJECT, EMAIL)),
        Some(&format!("__Host-csrf={CSRF}")),
    );
    assert_eq!(
        send(&state, bad_csrf).await.status(),
        StatusCode::UNAUTHORIZED
    );

    for fields in [
        vec![
            ("incident_id", case.id.as_str()),
            ("expected_lifecycle", "resolved"),
            ("command_id", COMMAND_A),
            ("csrf_token", CSRF),
        ],
        vec![
            ("incident_id", "inc_other"),
            ("expected_lifecycle", "open"),
            ("command_id", COMMAND_A),
            ("csrf_token", CSRF),
        ],
        vec![
            ("incident_id", case.id.as_str()),
            ("expected_lifecycle", "open"),
            ("command_id", "not-a-command"),
            ("csrf_token", CSRF),
        ],
    ] {
        assert_eq!(
            send(&state, valid_post(&path, &fields)).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        store
            .get_incident_case(&case.id)
            .await
            .unwrap()
            .unwrap()
            .lifecycle,
        IncidentLifecycle::Open
    );
}

#[tokio::test]
async fn csrf_get_replaces_malformed_or_duplicate_cookie() {
    let (state, _) = empty_state();
    for cookie in [
        "__Host-csrf=malformed".to_string(),
        format!("__Host-csrf={CSRF}; __Host-csrf={COMMAND_A}"),
        format!("__Host-csrf ={CSRF}"),
        format!("__Host-csrf= {CSRF}"),
    ] {
        let mut request = get_auth("/");
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
        let response = send(&state, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let replacement = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(replacement.starts_with("__Host-csrf="));
        assert!(replacement.contains("; Secure;"));
        assert!(!replacement.contains("malformed"));
    }

    let mut request = get_auth("/");
    request.headers_mut().insert(
        header::COOKIE,
        format!("__Host-csrf={CSRF}").parse().unwrap(),
    );
    let response = send(&state, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn resolved_incident_has_no_resolve_form() {
    let (state, store) = empty_state();
    let case = seed_incident(&store, "inc_no_form", "Resolved form").await;
    let result = store
        .resolve_incident(ResolveCommand {
            incident_id: case.id.clone(),
            command_id: hindsight::view_contract::ResolveCommandId::parse(COMMAND_A).unwrap(),
            expected_lifecycle: hindsight::view_contract::ExpectedOpen,
            actor_sub: BoundedSubject::parse(SUBJECT).unwrap(),
            display_email: None,
            observed_at_ms: hindsight::now_millis(),
        })
        .await
        .unwrap();
    assert!(matches!(result, ResolveResult::Resolved { .. }));
    let (status, rendered) =
        call(&state, get_auth(&format!("/incident/{}", case.id.as_str()))).await;
    assert_eq!(status, StatusCode::OK, "{rendered}");
    assert!(!rendered.contains(&format!("/api/incidents/{}/resolve", case.id)));
    assert!(!rendered.contains("name=\"command_id\""));
    assert!(rendered.contains("Incident resolved"));
}

#[tokio::test]
async fn json_legacy_query_and_response_remain_seconds_compatible() {
    let (state, _) = seeded_state();
    let now = hindsight::now_secs();
    let from = now - 3_600;
    let response = send(&state, get_auth(&format!("/api/timeline?from={from}&to=0"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_private_security(&response);
    assert!(response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let value: Value = serde_json::from_str(&body(response).await).unwrap();
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["from"], from);
    assert!(value["to"].as_i64().unwrap() >= from);
    assert_eq!(
        value["requested_window_ms"]["from_inclusive_ms"],
        from * 1_000
    );
    assert_eq!(value["requested_window_ms"]["to_inclusive_ms"], Value::Null);
    assert_eq!(value["requested_window_ms"]["moving"], true);
    assert!(value["status"]["sift"].as_bool().unwrap());
    assert!(value["events"].as_array().unwrap().iter().all(|event| {
        event["ts"].is_i64()
            && event["source"].is_string()
            && event["severity"].is_string()
            && event["title"].is_string()
            && event["detail"].is_string()
    }));
}

#[tokio::test]
async fn json_exact_query_returns_millisecond_truth() {
    let (state, _) = seeded_state();
    let now_ms = hindsight::now_millis();
    let from_ms = now_ms - 3_600_000;
    let to_ms = now_ms - 1;
    let (status, rendered) = call(
        &state,
        get_auth(&format!("/api/timeline?from_ms={from_ms}&to_ms={to_ms}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rendered}");
    let value: Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["requested_window_ms"]["from_inclusive_ms"], from_ms);
    assert_eq!(value["requested_window_ms"]["to_inclusive_ms"], to_ms);
    assert_eq!(value["requested_window_ms"]["moving"], false);
    assert_eq!(value["effective_window_ms"]["from_inclusive_ms"], from_ms);
    assert_eq!(value["effective_window_ms"]["to_inclusive_ms"], to_ms);
    assert!(value["observed_at_ms"].as_i64().unwrap() >= to_ms);
    assert_eq!(value["from"], from_ms.div_euclid(1_000));
    assert_eq!(value["to"], to_ms.div_euclid(1_000));
}

#[tokio::test]
async fn json_errors_never_fall_back_to_html() {
    let (state, _) = empty_state();
    for request in [
        get("/api/timeline"),
        get_auth("/api/timeline?from=1&from_ms=1000"),
        get_auth("/api/missing"),
        authenticated(request(Method::POST, "/api/timeline")),
    ] {
        let response = send(&state, request).await;
        assert!(response.status().is_client_error());
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            content_type.starts_with("application/json"),
            "{content_type}"
        );
        let rendered = body(response).await;
        let value: Value = serde_json::from_str(&rendered).unwrap();
        assert!(value["error"]["code"].is_string());
        assert!(!rendered.contains("<html"));
    }
}

#[tokio::test]
async fn redirect_fallback_extractor_and_error_headers_match_matrix() {
    let (state, store) = empty_state();
    let case = seed_incident(&store, "inc_matrix", "Header matrix").await;

    let open = send(
        &state,
        valid_post(
            "/api/incidents",
            &[
                ("title", "Native redirect"),
                ("window_hours", "24"),
                ("csrf_token", CSRF),
            ],
        ),
    )
    .await;
    assert_eq!(open.status(), StatusCode::SEE_OTHER);
    assert!(open.headers().get(header::LOCATION).is_some());
    assert_private_security(&open);

    let html_method = send(&state, authenticated(request(Method::PUT, "/"))).await;
    assert_eq!(html_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        html_method.headers().get(header::ALLOW).unwrap(),
        "GET, HEAD"
    );
    assert!(body(html_method)
        .await
        .to_ascii_lowercase()
        .starts_with("<!doctype html>"));

    let json_method = send(
        &state,
        authenticated(request(Method::POST, "/api/timeline")),
    )
    .await;
    assert_eq!(json_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        json_method.headers().get(header::ALLOW).unwrap(),
        "GET, HEAD"
    );
    assert!(json_method
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("application/json"));

    let html_missing = send(&state, get_auth("/missing")).await;
    assert_eq!(html_missing.status(), StatusCode::NOT_FOUND);
    assert!(body(html_missing)
        .await
        .to_ascii_lowercase()
        .starts_with("<!doctype html>"));

    let malformed_path = send(
        &state,
        valid_post(
            &format!("/api/incidents/{}/notes", case.id),
            &[("incident_id", "bad"), ("body", "x"), ("csrf_token", CSRF)],
        ),
    )
    .await;
    assert_eq!(malformed_path.status(), StatusCode::BAD_REQUEST);
    assert_private_security(&malformed_path);
}

#[tokio::test]
async fn marker_shaped_operator_text_is_inert_end_to_end() {
    let (state, store) = empty_state();
    let title = "Marker [[W33D:TOPBAR_FRAGMENT]] <script>alert(1)</script>";
    let response = send(
        &state,
        valid_post(
            "/api/incidents",
            &[
                ("title", title),
                ("window_hours", "24"),
                ("csrf_token", CSRF),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let id = incident_id_from_location(&location(&response));
    let path = format!("/api/incidents/{}/notes", id);
    let note = "Note [[W33D:STATIC_CSS]] <img src=x onerror=alert(2)>";
    let response = send(
        &state,
        valid_post(
            &path,
            &[
                ("incident_id", id.as_str()),
                ("body", note),
                ("csrf_token", CSRF),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        store.list_notes_bounded(&id, 201).await.unwrap().rows.len(),
        1
    );

    let (status, rendered) = call(&state, get_auth(&format!("/incident/{id}"))).await;
    assert_eq!(status, StatusCode::OK, "{rendered}");
    assert!(rendered.contains("[[W33D:TOPBAR_FRAGMENT]]"));
    assert!(rendered.contains("[[W33D:STATIC_CSS]]"));
    assert!(rendered.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(rendered.contains("&lt;img src=x onerror=alert(2)&gt;"));
    assert!(!rendered.contains("<script>alert(1)</script>"));
    assert!(!rendered.contains("<img src=x"));
}

#[tokio::test]
async fn audit_open_is_attempt_only_and_note_resolve_do_not_emit() {
    let (state, store) = empty_state();
    let open = send(
        &state,
        valid_post(
            "/api/incidents",
            &[
                ("title", "Audit truth"),
                ("window_hours", "24"),
                ("csrf_token", CSRF),
            ],
        ),
    )
    .await;
    let id = incident_id_from_location(&location(&open));
    let note_path = format!("/api/incidents/{id}/notes");
    assert_eq!(
        send(
            &state,
            valid_post(
                &note_path,
                &[
                    ("incident_id", id.as_str()),
                    ("body", "One note"),
                    ("csrf_token", CSRF),
                ],
            ),
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    let resolve_path = format!("/api/incidents/{id}/resolve");
    assert_eq!(
        send(
            &state,
            valid_post(
                &resolve_path,
                &[
                    ("incident_id", id.as_str()),
                    ("expected_lifecycle", "open"),
                    ("command_id", COMMAND_A),
                    ("csrf_token", CSRF),
                ],
            ),
        )
        .await
        .status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        store
            .get_incident_case(&id)
            .await
            .unwrap()
            .unwrap()
            .lifecycle,
        IncidentLifecycle::Resolved
    );
    let (status, rendered) = call(&state, get_auth(&format!("/incident/{id}"))).await;
    assert_eq!(status, StatusCode::OK, "{rendered}");
    assert!(rendered.contains("Audit enqueue attempted — no enqueue or delivery receipt is stored"));
    assert!(rendered.contains("No audit enqueue is attempted for note marks"));
    assert!(rendered.contains("No audit enqueue is attempted for resolution marks"));
    assert!(!rendered.contains("Audit delivered"));
    assert!(!rendered.contains("Audit enqueued successfully"));
}
