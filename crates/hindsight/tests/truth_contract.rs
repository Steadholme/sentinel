//! Frozen truth, composition, transport, and persistence contract for Hindsight.
//!
//! The ordinary tests are hermetic. PostgreSQL tests return early unless a
//! dedicated `HINDSIGHT_TEST_DATABASE_URL` (or `HINDSIGHT_TEST_DSN`) is
//! supplied; the database name must contain `test` before the fixture may
//! reset Hindsight's three owned tables.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, Response, StatusCode};
use axum::response::IntoResponse;
use hindsight::audit::{AuditEvent, AuditSink};
use hindsight::config::Config;
use hindsight::error::{AppError, ErrorCondition};
use hindsight::feeds::sift::{InMemoryLogReader, LogAcquisition, LogReader, LogRow};
use hindsight::feeds::vitals::{self, MetricAcquisition};
use hindsight::feeds::watchtower::{self, AuditAcquisition};
use hindsight::feeds::{ComparisonSnapshot, LegacySource};
use hindsight::handlers;
use hindsight::store::{
    InMemoryStore, NewIncident, NewNote, PgStore, ResolveCommand, ResolveInvariant, ResolveResult,
    Store,
};
use hindsight::view_contract::{
    allocate_display, ceil_millis_to_seconds, collapse_records, emergency_html, emergency_json,
    floor_millis_to_seconds, token, ActorTruth, AuditRecord, BoundedDisplayEmail,
    BoundedDisplayText, BoundedNote, BoundedRows, BoundedSubject, BoundedTitle, Boundedness,
    ChannelId, ChannelState, ChannelView, ComposeError, Composer, Coverage, CoverageKind,
    CsrfToken, EscapedAttribute, EscapedText, EvidenceItem, EvidenceRecord, ExpectedOpen, GapTruth,
    IncidentId, IncidentLifecycle, LogRecord, MetricClassification, MetricRecord, NoteId,
    ProductRelativePath, PublicMarkRef, RenderedFragment, RequestedWindowMs, ResolveCommandId,
    SectionState, Slot, SlotValue, SourceKey, TemplateId, TokenDomain, TrustedStaticUrl,
    TruthError, TypedBooleanAttribute, TypedHiddenValue, ValidationError, WindowGate,
    WindowLifecycle, ACQUISITION_CAP_BYTES, MAX_WINDOW_MS,
};
use serde_json::{json, Value};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use tower::ServiceExt;

const CSRF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const COMMAND_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const COMMAND_B: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn coverage(kind: CoverageKind) -> Coverage {
    Coverage {
        kind,
        requested_from_ms: 1_000,
        requested_to_ms: Some(9_000),
        effective_from_ms: 1_000,
        effective_to_ms: 9_000,
        acquired_from_ms: Some(2_000),
        acquired_to_ms: Some(8_000),
        gap_before_window: GapTruth::NotObserved,
        gap_after_window: GapTruth::Unknown,
    }
}

fn audit_record(sequence: i64, instant_ms: i64, detail: &str) -> EvidenceRecord {
    EvidenceRecord::Audit(AuditRecord {
        sequence,
        hash: format!("{sequence:064x}"),
        previous_hash: format!("{:064x}", sequence.saturating_sub(1)),
        recorded_at_ms: instant_ms,
        actor: "subject".to_string(),
        action: "action".to_string(),
        target: "target".to_string(),
        severity: "notice".to_string(),
        detail: detail.to_string(),
        source: "watchtower".to_string(),
    })
}

fn log_record(id: &str, second: i64, message: &str) -> EvidenceRecord {
    EvidenceRecord::Log(LogRecord {
        id: id.to_string(),
        template_id: "template".to_string(),
        recorded_at_s: second,
        host: "host".to_string(),
        app: "app".to_string(),
        severity: "error".to_string(),
        message: message.to_string(),
    })
}

fn metric_record(host: &str, second: i64, value: f64) -> EvidenceRecord {
    EvidenceRecord::Metric(MetricRecord {
        host: host.to_string(),
        metric_name: "cpu_pct".to_string(),
        raw_value_bits: value.to_bits(),
        unit: "percent".to_string(),
        recorded_at_s: second,
        classification: MetricClassification::CpuHigh,
        derivation: "cpu_pct >= 90.0".to_string(),
    })
}

fn loaded_channel(
    id: ChannelId,
    records: Vec<EvidenceRecord>,
    boundedness: Boundedness,
) -> ChannelView {
    ChannelView::loaded(
        id,
        boundedness,
        coverage(CoverageKind::ExactWindowLimitPlusOne),
        records.len(),
        records,
    )
    .unwrap()
}

fn gate() -> WindowGate {
    WindowGate::validate(
        RequestedWindowMs {
            from_inclusive: 1_000,
            to_inclusive: Some(9_000),
        },
        10_000,
        WindowLifecycle::Frozen,
    )
    .unwrap()
}

fn text(value: impl Into<String>) -> SlotValue {
    SlotValue::Text(EscapedText::new(value))
}

fn attr(value: impl Into<String>) -> SlotValue {
    SlotValue::Attribute(EscapedAttribute::new(value))
}

fn topbar_values(title: &str) -> Vec<(Slot, SlotValue)> {
    vec![
        (Slot::TopbarPageTitleText, text(title)),
        (Slot::GatewayContextText, text("Verified operator")),
        (
            Slot::GatewayContextToken,
            token(TokenDomain::GatewayContext, "authenticated"),
        ),
        (
            Slot::PortalUrl,
            SlotValue::TrustedStaticUrl(TrustedStaticUrl::Portal),
        ),
        (
            Slot::LogoutUrl,
            SlotValue::TrustedStaticUrl(TrustedStaticUrl::Logout),
        ),
    ]
}

fn notice_empty() -> RenderedFragment {
    RenderedFragment::typed_empty(TemplateId::InlineNotice)
}

fn open_form_values(
    checked_hours: &[i64],
    title_invalid: bool,
    window_invalid: bool,
) -> Vec<(Slot, SlotValue)> {
    let csrf = CsrfToken::parse(CSRF).unwrap();
    let checked = |hours| checked_hours.contains(&hours);
    vec![
        (
            Slot::OpenActionPath,
            SlotValue::ProductPath(ProductRelativePath::OpenIncident),
        ),
        (
            Slot::CsrfValueAttribute,
            SlotValue::HiddenValue(TypedHiddenValue::csrf(&csrf)),
        ),
        (Slot::OpenTitleValueAttribute, attr("title")),
        (
            Slot::OpenTitleInvalidToken,
            token(
                TokenDomain::AriaInvalid,
                if title_invalid { "true" } else { "false" },
            ),
        ),
        (
            Slot::OpenWindow1CheckedAttribute,
            SlotValue::BooleanAttribute(TypedBooleanAttribute::checked(checked(1))),
        ),
        (
            Slot::OpenWindow6CheckedAttribute,
            SlotValue::BooleanAttribute(TypedBooleanAttribute::checked(checked(6))),
        ),
        (
            Slot::OpenWindow24CheckedAttribute,
            SlotValue::BooleanAttribute(TypedBooleanAttribute::checked(checked(24))),
        ),
        (
            Slot::OpenWindow72CheckedAttribute,
            SlotValue::BooleanAttribute(TypedBooleanAttribute::checked(checked(72))),
        ),
        (
            Slot::OpenWindow168CheckedAttribute,
            SlotValue::BooleanAttribute(TypedBooleanAttribute::checked(checked(168))),
        ),
        (
            Slot::OpenWindowInvalidToken,
            token(
                TokenDomain::AriaInvalid,
                if window_invalid { "true" } else { "false" },
            ),
        ),
        (
            Slot::OpenErrorSummaryFragment,
            SlotValue::Fragment(notice_empty()),
        ),
        (
            Slot::OpenTitleErrorText,
            text(if title_invalid { "title error" } else { "" }),
        ),
        (
            Slot::OpenTitleErrorHiddenAttribute,
            SlotValue::BooleanAttribute(TypedBooleanAttribute::hidden(!title_invalid)),
        ),
        (
            Slot::OpenWindowErrorText,
            text(if window_invalid { "window error" } else { "" }),
        ),
        (
            Slot::OpenWindowErrorHiddenAttribute,
            SlotValue::BooleanAttribute(TypedBooleanAttribute::hidden(!window_invalid)),
        ),
    ]
}

fn note_form_values(body_invalid: bool) -> Vec<(Slot, SlotValue)> {
    let csrf = CsrfToken::parse(CSRF).unwrap();
    let incident = IncidentId::parse("inc_composer").unwrap();
    vec![
        (
            Slot::NoteActionPath,
            SlotValue::ProductPath(ProductRelativePath::AddNote(incident.clone())),
        ),
        (
            Slot::CsrfValueAttribute,
            SlotValue::HiddenValue(TypedHiddenValue::csrf(&csrf)),
        ),
        (
            Slot::MutationIncidentIdValueAttribute,
            SlotValue::HiddenValue(TypedHiddenValue::incident_id(&incident)),
        ),
        (Slot::NoteBodyText, text("body")),
        (
            Slot::NoteBodyInvalidToken,
            token(
                TokenDomain::AriaInvalid,
                if body_invalid { "true" } else { "false" },
            ),
        ),
        (
            Slot::NoteErrorSummaryFragment,
            SlotValue::Fragment(notice_empty()),
        ),
        (
            Slot::NoteBodyErrorText,
            text(if body_invalid { "body error" } else { "" }),
        ),
        (
            Slot::NoteBodyErrorHiddenAttribute,
            SlotValue::BooleanAttribute(TypedBooleanAttribute::hidden(!body_invalid)),
        ),
    ]
}

fn test_state(store: Arc<dyn Store>, logs: Arc<dyn LogReader>) -> hindsight::AppState {
    hindsight::AppState {
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

fn authenticated(mut request: Request<Body>) -> Request<Body> {
    request
        .headers_mut()
        .insert("x-auth-subject", "operator".parse().unwrap());
    request
}

async fn send(state: &hindsight::AppState, request: Request<Body>) -> Response<Body> {
    hindsight::app(state.clone())
        .oneshot(request)
        .await
        .unwrap()
}

async fn response_body(response: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn request(method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .unwrap()
}

#[test]
fn channel_state_zero_event_invariants() {
    for state in [
        ChannelState::ConfigurationAbsentOrInvalid,
        ChannelState::Unavailable,
        ChannelState::NonSuccess,
        ChannelState::OversizeTruncated,
        ChannelState::InvalidSchema,
    ] {
        let channel = ChannelView::failed(ChannelId::Audit, state).unwrap();
        assert!(channel.items.is_empty());
        assert_eq!(channel.coverage, None);
        assert_eq!(channel.acquired_count, None);
        assert_eq!(channel.eligible_distinct_count, None);
        assert_eq!(channel.displayed_distinct_count, None);
        assert_eq!(channel.validate(), Ok(()));
    }
    let invalid = ChannelView {
        id: ChannelId::Audit,
        state: ChannelState::Unavailable,
        coverage: None,
        acquired_count: Some(0),
        eligible_distinct_count: None,
        displayed_distinct_count: None,
        items: Vec::new(),
    };
    assert_eq!(invalid.validate(), Err(TruthError::InvalidChannel));
}

#[test]
fn loaded_state_requires_items_and_exact_bound() {
    let empty = loaded_channel(ChannelId::Log, Vec::new(), Boundedness::ProvenEnd);
    assert_eq!(empty.state, ChannelState::LoadedEmpty);
    assert_eq!(empty.acquired_count, Some(0));
    assert_eq!(empty.eligible_distinct_count, Some(0));
    assert_eq!(empty.displayed_distinct_count, Some(0));
    assert!(empty.items.is_empty());

    let nonempty = loaded_channel(
        ChannelId::Log,
        vec![log_record("log-1", 2, "message")],
        Boundedness::KnownMore,
    );
    assert_eq!(
        nonempty.state,
        ChannelState::LoadedNonEmpty(Boundedness::KnownMore)
    );
    assert_eq!(nonempty.items.len(), 1);
    assert_eq!(nonempty.validate(), Ok(()));
    assert_eq!(
        ChannelView::loaded(
            ChannelId::Audit,
            Boundedness::ProvenEnd,
            coverage(CoverageKind::RecentCountBounded),
            1,
            vec![log_record("wrong", 2, "wrong channel")]
        ),
        Err(TruthError::InvalidChannel)
    );
}

#[test]
fn section_state_row_invariants() {
    let bounded = BoundedRows::from_limit_plus_one(vec![1, 2, 3], 2).unwrap();
    assert_eq!(bounded.rows, vec![1, 2]);
    assert_eq!(bounded.boundedness, Boundedness::KnownMore);
    assert_eq!(bounded.acquired_count, 2);

    assert_eq!(
        serde_json::to_value(SectionState::Loaded {
            bounded: Boundedness::ProvenEnd
        })
        .unwrap(),
        json!({"kind":"loaded","bounded":"proven_end"})
    );
    assert_eq!(
        serde_json::to_value(SectionState::LoadedEmpty).unwrap(),
        json!({"kind":"loaded_empty"})
    );
    assert_eq!(
        serde_json::to_value(SectionState::Unavailable).unwrap(),
        json!({"kind":"unavailable"})
    );
}

#[tokio::test]
async fn acquisition_outcomes_remain_distinct() {
    assert!(matches!(
        InMemoryLogReader::unconfigured()
            .recent_errors(1, 2, 2)
            .await,
        LogAcquisition::ConfigurationAbsentOrInvalid
    ));
    assert!(matches!(
        InMemoryLogReader::down().recent_errors(1, 2, 2).await,
        LogAcquisition::Unavailable
    ));
    assert!(matches!(
        InMemoryLogReader::empty().recent_errors(1, 2, 2).await,
        LogAcquisition::Loaded { .. }
    ));
    assert!(matches!(
        watchtower::parse(b"{}"),
        AuditAcquisition::InvalidSchema
    ));
    assert!(matches!(
        vitals::parse(b"{}"),
        MetricAcquisition::InvalidSchema
    ));
}

#[tokio::test]
async fn oversize_and_invalid_schema_emit_zero_events() {
    let oversize = InMemoryLogReader::with_rows(vec![LogRow {
        id: "oversize".to_string(),
        ts: 10,
        host: "host".to_string(),
        app: "app".to_string(),
        severity: "error".to_string(),
        message: "x".repeat(ACQUISITION_CAP_BYTES + 1),
        template_id: "template".to_string(),
    }]);
    assert!(matches!(
        oversize.recent_errors(1, 20, 2).await,
        LogAcquisition::OversizeTruncated
    ));
    let invalid = InMemoryLogReader::with_rows(vec![LogRow {
        id: String::new(),
        ts: 10,
        host: "host".to_string(),
        app: "app".to_string(),
        severity: "error".to_string(),
        message: "message".to_string(),
        template_id: "template".to_string(),
    }]);
    assert!(matches!(
        invalid.recent_errors(1, 20, 2).await,
        LogAcquisition::InvalidSchema
    ));
    assert!(matches!(
        watchtower::parse(b"not-json"),
        AuditAcquisition::InvalidSchema
    ));
    assert!(matches!(
        vitals::parse(br#"{"samples":[{"host":"","metric":"cpu_pct","value":91,"ts":1}]}"#),
        MetricAcquisition::InvalidSchema
    ));
}

#[tokio::test]
async fn coverage_gap_truth_is_source_specific() {
    let logs = InMemoryLogReader::with_rows(vec![LogRow {
        id: "log".to_string(),
        ts: 5,
        host: "host".to_string(),
        app: "app".to_string(),
        severity: "error".to_string(),
        message: "message".to_string(),
        template_id: "template".to_string(),
    }]);
    let snapshot = hindsight::feeds::gather(
        &Config {
            bind_addr: "127.0.0.1:0".to_string(),
            vitals_url: "invalid".to_string(),
            watchtower_url: "invalid".to_string(),
        },
        &logs,
        gate(),
    )
    .await
    .unwrap();
    assert_eq!(snapshot.channels[0].coverage, None);
    assert_eq!(snapshot.channels[2].coverage, None);
    let log_coverage = snapshot.channels[1].coverage.as_ref().unwrap();
    assert_eq!(log_coverage.kind, CoverageKind::ExactWindowLimitPlusOne);
    assert_eq!(log_coverage.gap_before_window, GapTruth::NotObserved);
    assert_eq!(log_coverage.gap_after_window, GapTruth::NotObserved);
}

#[test]
fn metric_classification_thresholds_are_exact() {
    assert_eq!(vitals::classify("cpu_pct", 89.999), None);
    assert_eq!(
        vitals::classify("cpu_pct", 90.0).unwrap().0,
        MetricClassification::CpuHigh
    );
    assert_eq!(vitals::classify("mem_pct", 89.999), None);
    assert_eq!(
        vitals::classify("mem_pct", 90.0).unwrap().0,
        MetricClassification::MemoryHigh
    );
    assert_eq!(vitals::classify("load1", 3.999), None);
    assert_eq!(
        vitals::classify("load1", 4.0).unwrap().0,
        MetricClassification::LoadElevated
    );
    assert_eq!(
        vitals::classify("load1", 8.0).unwrap().0,
        MetricClassification::LoadCritical
    );
    assert_eq!(vitals::classify("other", 999.0), None);
}

#[test]
fn source_keys_and_payload_tuples_are_lossless() {
    let audit = audit_record(7, 7_123, "detail");
    assert_eq!(
        audit.source_key(),
        SourceKey::Audit {
            sequence: 7,
            hash: format!("{:064x}", 7)
        }
    );
    let audit_payload = audit.payload_tuple();
    assert!(format!("{audit_payload:?}").contains("detail"));
    assert!(format!("{audit_payload:?}").contains("7123"));

    let log = log_record("log-7", 7, "exact message");
    assert_eq!(
        log.source_key(),
        SourceKey::Log {
            id: "log-7".to_string()
        }
    );
    let log_payload = format!("{:?}", log.payload_tuple());
    assert!(log_payload.contains("exact message"));
    assert!(log_payload.contains("template"));

    let metric = metric_record("host-7", 7, 91.125);
    assert_eq!(
        metric.source_key(),
        SourceKey::Metric {
            host: "host-7".to_string(),
            metric_name: "cpu_pct".to_string(),
            recorded_at_s: 7
        }
    );
    assert!(format!("{:?}", metric.payload_tuple()).contains(&91.125f64.to_bits().to_string()));
}

#[test]
fn duplicates_collapse_and_conflicts_keep_all_variants() {
    let duplicate = log_record("same", 4, "same payload");
    let conflict = log_record("same", 5, "different payload");
    let items = collapse_records(vec![duplicate.clone(), duplicate, conflict]).unwrap();
    assert_eq!(items.len(), 1);
    let EvidenceItem::Conflict {
        source_key,
        variants,
    } = &items[0]
    else {
        panic!("different payloads for one key must remain a conflict");
    };
    assert_eq!(
        source_key,
        &SourceKey::Log {
            id: "same".to_string()
        }
    );
    assert_eq!(variants.len(), 2);
    let payloads = variants
        .iter()
        .map(EvidenceRecord::payload_tuple)
        .collect::<BTreeSet<_>>();
    assert_eq!(payloads.len(), 2);
}

#[test]
fn evidence_order_preserves_precision_and_exact_tiebreaks() {
    let items = collapse_records(vec![
        log_record("b", 2, "b"),
        log_record("a", 2, "a"),
        audit_record(3, 2_001, "millisecond winner"),
        metric_record("host", 2, 95.0),
    ])
    .unwrap();
    assert!(matches!(
        &items[0],
        EvidenceItem::Event {
            record: EvidenceRecord::Audit(_)
        }
    ));
    assert!(matches!(
        &items[1],
        EvidenceItem::Event {
            record: EvidenceRecord::Log(LogRecord { id, .. })
        } if id == "a"
    ));
    assert!(matches!(
        &items[2],
        EvidenceItem::Event {
            record: EvidenceRecord::Log(LogRecord { id, .. })
        } if id == "b"
    ));
    assert!(matches!(
        &items[3],
        EvidenceItem::Event {
            record: EvidenceRecord::Metric(_)
        }
    ));
}

#[test]
fn cross_channel_display_allocation_is_global_deterministic_and_explicit() {
    let mut channels = [
        loaded_channel(
            ChannelId::Audit,
            vec![
                audit_record(1, 9_000, "audit newest"),
                audit_record(2, 6_000, "audit second"),
            ],
            Boundedness::CompletenessUnknown,
        ),
        loaded_channel(
            ChannelId::Log,
            vec![
                log_record("log-new", 8, "new"),
                log_record("log-old", 5, "old"),
            ],
            Boundedness::ProvenEnd,
        ),
        loaded_channel(
            ChannelId::Metric,
            vec![
                metric_record("metric-new", 7, 95.0),
                metric_record("metric-old", 4, 96.0),
            ],
            Boundedness::CompletenessUnknown,
        ),
    ];
    allocate_display(&mut channels, 4).unwrap();
    assert_eq!(
        channels
            .iter()
            .map(|channel| channel.items.len())
            .sum::<usize>(),
        4
    );
    assert!(channels.iter().all(|channel| !channel.items.is_empty()));
    assert_eq!(channels[0].items.len(), 2);
    for channel in &channels {
        assert_eq!(channel.displayed_distinct_count, Some(channel.items.len()));
        assert_eq!(channel.eligible_distinct_count, Some(2));
        channel.validate().unwrap();
    }
}

#[test]
fn failure_counts_and_coverage_are_null_not_zero() {
    let value = serde_json::to_value(
        ChannelView::failed(ChannelId::Metric, ChannelState::Unavailable).unwrap(),
    )
    .unwrap();
    assert_eq!(value["coverage"], Value::Null);
    assert_eq!(value["acquired_count"], Value::Null);
    assert_eq!(value["eligible_distinct_count"], Value::Null);
    assert_eq!(value["displayed_distinct_count"], Value::Null);
    assert_eq!(value["items"], json!([]));
    assert_ne!(value["acquired_count"], json!(0));
}

#[test]
fn window_validation_rejects_without_clamp() {
    let observed = 1_000_000;
    for requested in [
        RequestedWindowMs {
            from_inclusive: 0,
            to_inclusive: Some(observed),
        },
        RequestedWindowMs {
            from_inclusive: observed,
            to_inclusive: Some(observed - 1),
        },
        RequestedWindowMs {
            from_inclusive: 1,
            to_inclusive: Some(observed + 1),
        },
        RequestedWindowMs {
            from_inclusive: observed - MAX_WINDOW_MS - 1,
            to_inclusive: Some(observed),
        },
    ] {
        assert_eq!(
            WindowGate::validate(requested, observed, WindowLifecycle::Frozen),
            Err(ValidationError::InvalidWindow)
        );
    }
    assert_eq!(
        WindowGate::validate(
            RequestedWindowMs {
                from_inclusive: observed - 1,
                to_inclusive: None
            },
            observed,
            WindowLifecycle::Frozen
        ),
        Err(ValidationError::InvalidWindow)
    );
}

#[test]
fn second_millisecond_rounding_is_inclusive_and_checked() {
    assert_eq!(ceil_millis_to_seconds(1).unwrap(), 1);
    assert_eq!(ceil_millis_to_seconds(1_000).unwrap(), 1);
    assert_eq!(ceil_millis_to_seconds(1_001).unwrap(), 2);
    assert_eq!(floor_millis_to_seconds(1).unwrap(), 0);
    assert_eq!(floor_millis_to_seconds(1_999).unwrap(), 1);
    assert_eq!(floor_millis_to_seconds(2_000).unwrap(), 2);
    assert_eq!(
        ceil_millis_to_seconds(i64::MAX),
        Err(ValidationError::Overflow)
    );
    assert_eq!(
        floor_millis_to_seconds(0),
        Err(ValidationError::InvalidWindow)
    );
}

#[test]
fn one_observation_instant_drives_every_channel() {
    let gate = gate();
    let channels = [
        loaded_channel(
            ChannelId::Audit,
            vec![audit_record(1, 5_001, "audit")],
            Boundedness::CompletenessUnknown,
        ),
        loaded_channel(
            ChannelId::Log,
            vec![log_record("log", 5, "log")],
            Boundedness::ProvenEnd,
        ),
        loaded_channel(
            ChannelId::Metric,
            vec![metric_record("metric", 5, 95.0)],
            Boundedness::CompletenessUnknown,
        ),
    ];
    let snapshot = ComparisonSnapshot { gate, channels };
    assert_eq!(snapshot.gate.observed_at_ms, 10_000);
    for channel in &snapshot.channels {
        let coverage = channel.coverage.as_ref().unwrap();
        assert_eq!(
            coverage.effective_from_ms,
            snapshot.gate.effective.from_inclusive
        );
        assert_eq!(
            coverage.effective_to_ms,
            snapshot.gate.effective.to_inclusive
        );
    }
}

#[test]
fn bounded_rows_limit_plus_one_invariants() {
    let exact = BoundedRows::from_limit_plus_one(vec![1, 2], 2).unwrap();
    assert_eq!(exact.rows, vec![1, 2]);
    assert_eq!(exact.boundedness, Boundedness::ProvenEnd);
    assert_eq!(exact.acquired_count, 2);
    let more = BoundedRows::from_limit_plus_one(vec![1, 2, 3], 2).unwrap();
    assert_eq!(more.rows, vec![1, 2]);
    assert_eq!(more.boundedness, Boundedness::KnownMore);
    assert_eq!(more.acquired_count, 2);
    assert_eq!(
        BoundedRows::from_limit_plus_one(vec![1, 2, 3, 4], 2),
        Err(TruthError::InvalidBound)
    );
}

#[tokio::test]
async fn incident_note_and_mark_order_and_cardinality() {
    let store = InMemoryStore::new();
    let incident = store
        .create_incident(new_incident("inc_order", 100))
        .await
        .unwrap();
    for (id, body, created_at_s) in [
        ("note_later", "later", 103),
        ("note_earlier", "earlier", 102),
    ] {
        store
            .add_note(NewNote {
                id: NoteId::parse(id).unwrap(),
                incident_id: incident.id.clone(),
                body: BoundedNote::parse(body).unwrap(),
                actor_sub: BoundedSubject::parse("subject").unwrap(),
                display_email: None,
                created_at_s,
            })
            .await
            .unwrap();
    }
    let notes = store.list_notes_bounded(&incident.id, 201).await.unwrap();
    assert_eq!(
        notes
            .rows
            .iter()
            .map(|note| note.id.as_str())
            .collect::<Vec<_>>(),
        vec!["note_earlier", "note_later"]
    );
    let result = store
        .resolve_incident(resolve_command(&incident.id, COMMAND_A, 104_999))
        .await
        .unwrap();
    let ResolveResult::Resolved { incident, mark } = result else {
        panic!("first resolve must win");
    };
    assert_eq!(incident.resolution.as_ref(), Some(&mark));
    assert_eq!(incident.to_ts_s_compat, 104);
    let retry = store
        .resolve_incident(resolve_command(&incident.id, COMMAND_A, 999_999))
        .await
        .unwrap();
    assert!(matches!(
        retry,
        ResolveResult::AlreadyResolved { ref mark, .. }
            if mark.resolved_at_ms == 104_999
    ));
}

#[test]
fn legacy_actor_value_never_becomes_verified_subject() {
    let legacy = BoundedDisplayText::project("legacy@example.invalid");
    let actor = ActorTruth::LegacyUnclassified {
        legacy_display: legacy,
    };
    assert!(matches!(
        actor,
        ActorTruth::LegacyUnclassified { ref legacy_display }
            if legacy_display.visible() == "legacy@example.invalid"
    ));
    let unsafe_legacy = BoundedDisplayText::project("legacy\nsubject");
    assert!(!unsafe_legacy.is_safe());
    assert_eq!(
        unsafe_legacy.visible(),
        "Legacy value not safely displayable (unclassified)"
    );
}

#[tokio::test]
async fn missing_display_email_is_truthful() {
    let store = InMemoryStore::new();
    let incident = store
        .create_incident(NewIncident {
            display_email: None,
            ..new_incident("inc_no_email", 100)
        })
        .await
        .unwrap();
    assert!(matches!(
        incident.actor,
        ActorTruth::Verified {
            display_email: None,
            ..
        }
    ));
}

#[test]
fn public_mark_ref_never_contains_command_id() {
    let command = ResolveCommandId::parse(COMMAND_A).unwrap();
    let mark = PublicMarkRef::generate();
    assert!(mark.as_str().starts_with("rm_"));
    assert_eq!(mark.as_str().len(), 35);
    assert!(!mark.as_str().contains(command.as_str()));
    let path =
        ProductRelativePath::Resolved(IncidentId::parse("inc_public").unwrap(), mark.clone())
            .as_string()
            .unwrap();
    assert!(path.ends_with(mark.as_str()));
    assert!(!path.contains(COMMAND_A));
}

#[test]
fn strict_open_form_schema_and_bounds() {
    assert_eq!(
        BoundedTitle::parse("   title   ").unwrap().as_str(),
        "title"
    );
    assert!(BoundedTitle::parse("").is_err());
    assert!(BoundedTitle::parse(&"a".repeat(161)).is_err());
    assert!(BoundedTitle::parse(&"é".repeat(161)).is_err());
    assert!(BoundedTitle::parse("line\nbreak").is_err());
    assert!(CsrfToken::parse(CSRF).is_ok());
    assert!(CsrfToken::parse("AA").is_err());
    assert!(Composer::render(
        TemplateId::OpenIncidentForm,
        open_form_values(&[24], false, false)
    )
    .is_ok());
}

#[test]
fn strict_note_form_schema_and_bounds() {
    assert_eq!(
        BoundedNote::parse(" a\r\nb\rc ").unwrap().as_str(),
        "a\nb\nc"
    );
    assert!(BoundedNote::parse("").is_err());
    assert!(BoundedNote::parse(&"n".repeat(4_001)).is_err());
    assert!(BoundedNote::parse("bad\u{0}note").is_err());
    assert!(Composer::render(TemplateId::NoteForm, note_form_values(false)).is_ok());
}

#[test]
fn strict_resolve_form_schema_and_bounds() {
    assert!(IncidentId::parse("inc_valid-1").is_ok());
    assert!(IncidentId::parse("invalid").is_err());
    assert!(ExpectedOpen::parse("open").is_ok());
    assert!(ExpectedOpen::parse("resolved").is_err());
    assert!(ResolveCommandId::parse(COMMAND_A).is_ok());
    assert!(ResolveCommandId::parse(&"A".repeat(64)).is_err());
    assert!(ResolveCommandId::parse(&"a".repeat(63)).is_err());
}

#[tokio::test]
async fn strict_forms_reject_duplicate_unknown_actor_and_oversize() {
    let store = Arc::new(InMemoryStore::new());
    let state = test_state(store.clone(), Arc::new(InMemoryLogReader::empty()));
    let cookie = format!("__Host-csrf={CSRF}");
    let cases = [
        format!("title=a&title=b&window_hours=24&csrf_token={CSRF}"),
        format!("title=a&window_hours=24&csrf_token={CSRF}&actor_sub=attacker"),
        format!("title=a&window_hours=24&csrf_token={CSRF}&unknown=x"),
        format!(
            "title={}&window_hours=24&csrf_token={CSRF}",
            "x".repeat(33_000)
        ),
    ];
    for encoded in cases {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/incidents")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &cookie)
            .header("x-auth-subject", "operator")
            .body(Body::from(encoded))
            .unwrap();
        let response = send(&state, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response_body(response).await.contains("attacker"));
    }
    assert!(store
        .list_incidents_bounded(201)
        .await
        .unwrap()
        .rows
        .is_empty());
}

#[test]
fn json_legacy_fields_preserve_names_types_units_and_sources() {
    let snapshot = ComparisonSnapshot {
        gate: gate(),
        channels: [
            loaded_channel(
                ChannelId::Audit,
                vec![audit_record(1, 8_999, "audit")],
                Boundedness::CompletenessUnknown,
            ),
            loaded_channel(
                ChannelId::Log,
                vec![log_record("log", 7, "log")],
                Boundedness::ProvenEnd,
            ),
            loaded_channel(
                ChannelId::Metric,
                vec![metric_record("metric", 6, 95.0)],
                Boundedness::CompletenessUnknown,
            ),
        ],
    };
    let encoded = serde_json::to_value(snapshot.timeline_json_v2()).unwrap();
    for field in ["from", "to", "status", "events"] {
        assert!(encoded.get(field).is_some(), "{field}");
    }
    assert!(encoded["from"].is_i64());
    assert!(encoded["to"].is_i64());
    let sources = encoded["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["source"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(sources, BTreeSet::from(["watchtower", "sift", "vitals"]));
    assert_eq!(
        serde_json::to_value(LegacySource::Watchtower).unwrap(),
        json!("watchtower")
    );
}

#[test]
fn json_v2_exact_fields_states_and_conflicts() {
    let conflicting = loaded_channel(
        ChannelId::Log,
        vec![
            log_record("same", 7, "variant a"),
            log_record("same", 8, "variant b"),
        ],
        Boundedness::ProvenEnd,
    );
    let snapshot = ComparisonSnapshot {
        gate: gate(),
        channels: [
            ChannelView::failed(ChannelId::Audit, ChannelState::Unavailable).unwrap(),
            conflicting,
            loaded_channel(
                ChannelId::Metric,
                Vec::new(),
                Boundedness::CompletenessUnknown,
            ),
        ],
    };
    let value = serde_json::to_value(snapshot.timeline_json_v2()).unwrap();
    let keys = value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from([
            "channels".to_string(),
            "effective_window_ms".to_string(),
            "events".to_string(),
            "from".to_string(),
            "observed_at_ms".to_string(),
            "requested_window_ms".to_string(),
            "schema_version".to_string(),
            "status".to_string(),
            "to".to_string(),
        ])
    );
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["channels"][0]["state"]["kind"], "unavailable");
    assert_eq!(value["channels"][1]["items"][0]["kind"], "conflict");
    assert_eq!(
        value["channels"][1]["items"][0]["variants"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(value["channels"][2]["state"]["kind"], "loaded_empty");
}

#[tokio::test]
async fn json_query_families_reject_mixed_duplicate_and_unknown() {
    let state = test_state(
        Arc::new(InMemoryStore::new()),
        Arc::new(InMemoryLogReader::empty()),
    );
    for uri in [
        "/api/timeline?from=1&from_ms=1000",
        "/api/timeline?from=1&from=2",
        "/api/timeline?from_ms=1&unknown=2",
        "/api/timeline?to=2",
        "/api/timeline?from=-1",
        "/api/timeline?from_ms=0",
    ] {
        let response = send(
            &state,
            authenticated(request(Method::GET, uri, Body::empty())),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert!(response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("application/json"));
        let value: Value = serde_json::from_str(&response_body(response).await).unwrap();
        assert_eq!(value["error"]["code"], "invalid_request");
    }
}

#[test]
fn composer_all_templates_match_exact_specs() {
    Composer::validate_all_templates().unwrap();
    handlers::validate_templates().unwrap();
}

#[test]
fn composer_rejects_missing_duplicate_unknown_and_unexpected() {
    assert_eq!(
        Composer::render(TemplateId::Topbar, Vec::new()).unwrap_err(),
        ComposeError::MissingSlot
    );
    let mut duplicate = topbar_values("title");
    duplicate.push((Slot::TopbarPageTitleText, text("duplicate")));
    assert_eq!(
        Composer::render(TemplateId::Topbar, duplicate).unwrap_err(),
        ComposeError::DuplicateSlot
    );
    let mut unexpected = topbar_values("title");
    unexpected.pop();
    unexpected.push((Slot::NoticeHeadingText, text("unexpected")));
    assert!(matches!(
        Composer::render(TemplateId::Topbar, unexpected),
        Err(ComposeError::MissingSlot | ComposeError::UnexpectedSlot)
    ));
    // Unknown marker names are rejected by the immutable template inventory.
    Composer::validate_all_templates().unwrap();
}

#[test]
fn composer_rejects_wrong_kind_illegal_empty_path_url_and_token() {
    let mut wrong_kind = topbar_values("title");
    wrong_kind[0] = (
        Slot::TopbarPageTitleText,
        SlotValue::ProductPath(ProductRelativePath::Root),
    );
    assert_eq!(
        Composer::render(TemplateId::Topbar, wrong_kind).unwrap_err(),
        ComposeError::WrongValueKind
    );

    let mut empty = topbar_values("");
    assert_eq!(
        Composer::render(TemplateId::Topbar, std::mem::take(&mut empty)).unwrap_err(),
        ComposeError::EmptyValueForbidden
    );

    let window_values = vec![
        (
            Slot::WindowChoicePath,
            SlotValue::ProductPath(ProductRelativePath::DashboardWindow(2)),
        ),
        (Slot::WindowChoiceText, text("invalid")),
        (
            Slot::WindowChoiceCurrentToken,
            token(TokenDomain::Current, "not-current"),
        ),
        (Slot::WindowChoiceAriaCurrentAttribute, attr("false")),
    ];
    assert_eq!(
        Composer::render(TemplateId::WindowChoice, window_values).unwrap_err(),
        ComposeError::InvalidProductPath
    );
    assert_eq!(
        hindsight::view_contract::ClosedToken::new(TokenDomain::Current, "maybe").unwrap_err(),
        ComposeError::InvalidClosedToken
    );
    // Trusted URLs are closed variants; arbitrary URL construction is impossible.
    assert!(matches!(TrustedStaticUrl::Portal, TrustedStaticUrl::Portal));
}

#[test]
fn composer_does_not_rescan_marker_shaped_values() {
    let rendered = Composer::render(
        TemplateId::Topbar,
        topbar_values("[[W33D:LOGOUT_URL]] <script>x</script>"),
    )
    .unwrap()
    .into_string();
    assert!(rendered.contains("[[W33D:LOGOUT_URL]]"));
    assert!(rendered.contains("&lt;script&gt;x&lt;/script&gt;"));
    assert!(!rendered.contains("<script>x</script>"));
}

#[test]
fn composer_hidden_values_never_construct_form_markup() {
    let rendered = Composer::render(TemplateId::NoteForm, note_form_values(false))
        .unwrap()
        .into_string();
    assert_eq!(rendered.matches("name=\"csrf_token\"").count(), 1);
    assert_eq!(rendered.matches("name=\"incident_id\"").count(), 1);
    assert!(rendered.contains(&format!("value=\"{CSRF}\"")));
    assert!(rendered.contains("value=\"inc_composer\""));
    assert_eq!(rendered.matches("<form").count(), 1);
}

#[test]
fn composer_rejects_form_cross_slot_invariants() {
    assert_eq!(
        Composer::render(
            TemplateId::OpenIncidentForm,
            open_form_values(&[], false, false)
        )
        .unwrap_err(),
        ComposeError::CrossSlotInvariant
    );
    assert_eq!(
        Composer::render(
            TemplateId::OpenIncidentForm,
            open_form_values(&[1, 24], false, false)
        )
        .unwrap_err(),
        ComposeError::CrossSlotInvariant
    );
    let mut inconsistent = note_form_values(false);
    inconsistent
        .iter_mut()
        .find(|(slot, _)| *slot == Slot::NoteBodyInvalidToken)
        .unwrap()
        .1 = token(TokenDomain::AriaInvalid, "true");
    assert_eq!(
        Composer::render(TemplateId::NoteForm, inconsistent).unwrap_err(),
        ComposeError::CrossSlotInvariant
    );
}

#[test]
fn product_relative_paths_are_closed_variants() {
    let incident = IncidentId::parse("inc_paths").unwrap();
    let note = NoteId::parse("note_paths").unwrap();
    let mark = PublicMarkRef::parse("rm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    assert_eq!(ProductRelativePath::Root.as_string().unwrap(), "/");
    assert_eq!(
        ProductRelativePath::DashboardWindow(24)
            .as_string()
            .unwrap(),
        "/?window=24"
    );
    assert_eq!(
        ProductRelativePath::Incident(incident.clone())
            .as_string()
            .unwrap(),
        "/incident/inc_paths"
    );
    assert_eq!(
        ProductRelativePath::AddNote(incident.clone())
            .as_string()
            .unwrap(),
        "/api/incidents/inc_paths/notes"
    );
    assert_eq!(
        ProductRelativePath::Resolve(incident.clone())
            .as_string()
            .unwrap(),
        "/api/incidents/inc_paths/resolve"
    );
    assert_eq!(
        ProductRelativePath::NoteAdded(incident.clone(), note)
            .as_string()
            .unwrap(),
        "/incident/inc_paths#note_paths"
    );
    assert_eq!(
        ProductRelativePath::Resolved(incident, mark)
            .as_string()
            .unwrap(),
        "/incident/inc_paths#rm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        ProductRelativePath::DashboardWindow(2).as_string(),
        Err(ComposeError::InvalidProductPath)
    );
}

#[test]
fn composer_emergency_fallback_is_constant_and_safe() {
    assert_eq!(emergency_html(), emergency_html());
    assert!(emergency_html().starts_with("<!doctype html>"));
    assert!(emergency_html().contains("href=\"/\""));
    assert!(!emergency_html().contains("<script"));
    assert_eq!(
        serde_json::from_str::<Value>(emergency_json()).unwrap(),
        json!({
            "error": {
                "code": "internal_error",
                "message": "Hindsight could not complete the request"
            }
        })
    );
}

#[tokio::test]
async fn safe_error_copy_is_closed_and_redacted() {
    let secret = "postgres://secret@internal/db";
    for error in [
        AppError::InvalidRequest(secret.to_string()),
        AppError::Unauthorized(secret.to_string()),
        AppError::NotFound(secret.to_string()),
        AppError::Internal(secret.to_string()),
        AppError::html(ErrorCondition::PrimaryUnavailable),
        AppError::json(ErrorCondition::Internal),
    ] {
        let response = error.into_response();
        let rendered = response_body(response).await;
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("internal/db"));
    }
}

#[tokio::test]
async fn response_security_matrix_covers_every_response_class() {
    let state = test_state(
        Arc::new(InMemoryStore::new()),
        Arc::new(InMemoryLogReader::empty()),
    );
    let requests = [
        request(Method::GET, "/healthz", Body::empty()),
        request(Method::POST, "/healthz", Body::empty()),
        authenticated(request(Method::GET, "/", Body::empty())),
        authenticated(request(Method::GET, "/api/timeline", Body::empty())),
        request(Method::GET, "/missing", Body::empty()),
        authenticated(request(Method::POST, "/api/timeline", Body::empty())),
    ];
    for request in requests {
        let health = request.uri().path() == "/healthz"
            && matches!(*request.method(), Method::GET | Method::HEAD);
        let response = send(&state, request).await;
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            if health {
                "no-store"
            } else {
                "private, no-store"
            }
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        if health {
            assert!(response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_none());
        } else {
            assert_eq!(
                response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
                "DENY"
            );
            assert_eq!(
                response.headers().get(header::REFERRER_POLICY).unwrap(),
                "no-referrer"
            );
            assert!(response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_some());
        }
    }
}

#[tokio::test]
async fn audit_attempt_copy_never_claims_enqueue_or_delivery() {
    let store = Arc::new(InMemoryStore::new());
    let incident = store
        .create_incident(new_incident("inc_audit_copy", hindsight::now_secs()))
        .await
        .unwrap();
    let state = test_state(store, Arc::new(InMemoryLogReader::empty()));
    let response = send(
        &state,
        authenticated(request(
            Method::GET,
            &format!("/incident/{}", incident.id),
            Body::empty(),
        )),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let rendered = response_body(response).await;
    assert!(rendered.contains("Audit enqueue attempted"));
    assert!(rendered.contains("no enqueue or delivery receipt is stored"));
    assert!(!rendered.contains("Audit delivered"));
    assert!(!rendered.contains("Audit enqueue succeeded"));
}

#[test]
fn telemetry_fields_are_locator_and_secret_free() {
    let event = AuditEvent::notice("hindsight.incident.open", "subject", "inc_public", "24");
    let encoded = serde_json::to_value(event).unwrap();
    assert_eq!(
        encoded
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "action".to_string(),
            "actor".to_string(),
            "detail".to_string(),
            "severity".to_string(),
            "source".to_string(),
            "target".to_string(),
        ])
    );
    let source = include_str!("../src/audit.rs");
    assert!(!source.contains("raw_error ="));
    assert!(!source.contains("locator ="));
    assert!(!source.contains("endpoint ="));
    assert!(!source.contains("credential ="));
}

fn new_incident(id: &str, created_at_s: i64) -> NewIncident {
    NewIncident {
        id: IncidentId::parse(id).unwrap(),
        title: BoundedTitle::parse(&format!("Incident {id}")).unwrap(),
        from_ts_s: created_at_s - 60,
        actor_sub: BoundedSubject::parse("subject").unwrap(),
        display_email: None,
        created_at_s,
    }
}

fn resolve_command(id: &IncidentId, command: &str, observed_at_ms: i64) -> ResolveCommand {
    ResolveCommand {
        incident_id: id.clone(),
        command_id: ResolveCommandId::parse(command).unwrap(),
        expected_lifecycle: ExpectedOpen,
        actor_sub: BoundedSubject::parse("resolver").unwrap(),
        display_email: Some(BoundedDisplayEmail::parse("resolver@example.invalid").unwrap()),
        observed_at_ms,
    }
}

// ---------------------------------------------------------------------------
// Dedicated PostgreSQL contract. Tests return early unless a test DSN exists.
// ---------------------------------------------------------------------------

static PG_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn pg_test_dsn() -> Option<String> {
    std::env::var("HINDSIGHT_TEST_DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("HINDSIGHT_TEST_DSN").ok())
        .filter(|value| !value.trim().is_empty())
}

async fn pg_pool(dsn: &str) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(dsn)
        .await
        .expect("connect dedicated Hindsight test database");
    let database: String = sqlx::query("SELECT current_database() AS database")
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("database")
        .unwrap();
    assert!(
        database.to_ascii_lowercase().contains("test"),
        "refusing to reset non-test database {database:?}"
    );
    pool
}

async fn reset_pg(pool: &PgPool) {
    for statement in [
        "DROP TABLE IF EXISTS resolution_marks",
        "DROP TABLE IF EXISTS notes",
        "DROP TABLE IF EXISTS incidents",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}

async fn legacy_schema(pool: &PgPool) {
    sqlx::query(
        "CREATE TABLE incidents (\
           id TEXT PRIMARY KEY, title TEXT NOT NULL, \
           status TEXT NOT NULL DEFAULT 'open', from_ts BIGINT, \
           to_ts BIGINT NOT NULL DEFAULT 0, \
           created_by TEXT NOT NULL DEFAULT '', created_at BIGINT\
         )",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE notes (\
           id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, \
           body TEXT NOT NULL, author_sub TEXT NOT NULL DEFAULT '', \
           created_at BIGINT\
         )",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn migrated_pg(dsn: &str) -> (PgPool, PgStore) {
    let pool = pg_pool(dsn).await;
    reset_pg(&pool).await;
    let store = PgStore::from_pool(pool.clone());
    store.migrate().await.unwrap();
    (pool, store)
}

#[tokio::test]
async fn pg_migration_is_idempotent_and_fingerprinted() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let (pool, store) = migrated_pg(&dsn).await;
    let before = store.schema_fingerprint().await.unwrap();

    let incident = store
        .create_incident(new_incident("inc_pg_restart", 100))
        .await
        .unwrap();
    let ResolveResult::Resolved {
        incident: resolved,
        mark: mark_before_restart,
    } = store
        .resolve_incident(resolve_command(&incident.id, COMMAND_A, 101_987))
        .await
        .unwrap()
    else {
        panic!("first resolve must persist one resolution mark");
    };
    assert_eq!(resolved.resolution.as_ref(), Some(&mark_before_restart));

    let restart_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&dsn)
        .await
        .unwrap();
    let restarted = PgStore::from_pool(restart_pool.clone());
    restarted.migrate().await.unwrap();
    let after = restarted.schema_fingerprint().await.unwrap();
    assert_eq!(before, after);
    assert_eq!(before.len(), 16);
    assert_ne!(before, "0000000000000000");

    let reloaded = restarted
        .get_incident_case(&incident.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.lifecycle, IncidentLifecycle::Resolved);
    assert_eq!(reloaded.resolution.as_ref(), Some(&mark_before_restart));
    assert_eq!(
        reloaded.to_ts_s_compat,
        mark_before_restart.resolved_at_ms.div_euclid(1_000)
    );

    restart_pool.close().await;
    pool.close().await;
}

#[tokio::test]
async fn pg_migration_preflight_rejects_legacy_lifecycle() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let pool = pg_pool(&dsn).await;
    reset_pg(&pool).await;
    legacy_schema(&pool).await;
    sqlx::query(
        "INSERT INTO incidents \
         (id,title,status,from_ts,to_ts,created_by,created_at) \
         VALUES ('inc_legacy_bad','Bad legacy','resolved',1,2,'legacy',3)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let store = PgStore::from_pool(pool.clone());
    assert!(store.migrate().await.is_err());
    let actor_column: i64 = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS count FROM information_schema.columns \
         WHERE table_schema='public' AND table_name='incidents' AND column_name='actor_sub'",
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(actor_column, 0);
    pool.close().await;
}

#[tokio::test]
async fn pg_fallible_reads_distinguish_empty_missing_and_failure() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let (pool, store) = migrated_pg(&dsn).await;
    assert!(store
        .list_incidents_bounded(201)
        .await
        .unwrap()
        .rows
        .is_empty());
    assert!(store
        .get_incident_case(&IncidentId::parse("inc_absent").unwrap())
        .await
        .unwrap()
        .is_none());
    pool.close().await;
    assert!(store.list_incidents_bounded(201).await.is_err());
}

#[tokio::test]
async fn pg_limit_plus_one_proves_incident_and_note_bounds() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let (pool, store) = migrated_pg(&dsn).await;
    for index in 1..=201 {
        store
            .create_incident(new_incident(
                &format!("inc_bound_{index:03}"),
                1_000 + index,
            ))
            .await
            .unwrap();
    }
    let incidents = store.list_incidents_bounded(201).await.unwrap();
    assert_eq!(incidents.rows.len(), 200);
    assert_eq!(incidents.acquired_count, 200);
    assert_eq!(incidents.boundedness, Boundedness::KnownMore);

    let incident_id = IncidentId::parse("inc_bound_001").unwrap();
    for index in 1..=201 {
        store
            .add_note(NewNote {
                id: NoteId::parse(&format!("note_bound_{index:03}")).unwrap(),
                incident_id: incident_id.clone(),
                body: BoundedNote::parse(&format!("note {index}")).unwrap(),
                actor_sub: BoundedSubject::parse("subject").unwrap(),
                display_email: None,
                created_at_s: 2_000 + index,
            })
            .await
            .unwrap();
    }
    let notes = store.list_notes_bounded(&incident_id, 201).await.unwrap();
    assert_eq!(notes.rows.len(), 200);
    assert_eq!(notes.acquired_count, 200);
    assert_eq!(notes.boundedness, Boundedness::KnownMore);
    pool.close().await;
}

#[tokio::test]
async fn pg_same_command_concurrency_commits_exactly_one_mark() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let (pool, store) = migrated_pg(&dsn).await;
    let incident = store
        .create_incident(new_incident("inc_pg_same", 100))
        .await
        .unwrap();
    let pool_two = PgPoolOptions::new()
        .max_connections(2)
        .connect(&dsn)
        .await
        .unwrap();
    let one = PgStore::from_pool(pool.clone());
    let two = PgStore::from_pool(pool_two.clone());
    let command_one = resolve_command(&incident.id, COMMAND_A, 101_123);
    let command_two = command_one.clone();
    let (left, right) = tokio::join!(
        one.resolve_incident(command_one),
        two.resolve_incident(command_two)
    );
    let results = [left.unwrap(), right.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ResolveResult::Resolved { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ResolveResult::AlreadyResolved { .. }))
            .count(),
        1
    );
    let marks: i64 = sqlx::query("SELECT COUNT(*)::BIGINT AS count FROM resolution_marks")
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
    assert_eq!(marks, 1);
    pool_two.close().await;
    pool.close().await;
}

#[tokio::test]
async fn pg_different_command_concurrency_has_one_winner_one_conflict() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let (pool, store) = migrated_pg(&dsn).await;
    let incident = store
        .create_incident(new_incident("inc_pg_different", 100))
        .await
        .unwrap();
    let pool_two = PgPoolOptions::new()
        .max_connections(2)
        .connect(&dsn)
        .await
        .unwrap();
    let one = PgStore::from_pool(pool.clone());
    let two = PgStore::from_pool(pool_two.clone());
    let (left, right) = tokio::join!(
        one.resolve_incident(resolve_command(&incident.id, COMMAND_A, 101_111)),
        two.resolve_incident(resolve_command(&incident.id, COMMAND_B, 101_222))
    );
    let results = [left.unwrap(), right.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ResolveResult::Resolved { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ResolveResult::StaleConflict { .. }))
            .count(),
        1
    );
    pool_two.close().await;
    pool.close().await;
}

#[tokio::test]
async fn pg_resolution_rollback_leaves_neither_half() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let (pool, store) = migrated_pg(&dsn).await;
    let incident = store
        .create_incident(new_incident("inc_pg_rollback", 100))
        .await
        .unwrap();
    sqlx::query(
        "CREATE OR REPLACE FUNCTION hindsight_test_reject_update() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test rollback'; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER hindsight_test_reject_update \
         BEFORE UPDATE ON incidents FOR EACH ROW EXECUTE FUNCTION hindsight_test_reject_update()",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(store
        .resolve_incident(resolve_command(&incident.id, COMMAND_A, 101_999))
        .await
        .is_err());
    let row = sqlx::query(
        "SELECT i.status, i.to_ts, COUNT(r.incident_id)::BIGINT AS marks \
         FROM incidents i LEFT JOIN resolution_marks r ON r.incident_id=i.id \
         WHERE i.id=$1 GROUP BY i.status,i.to_ts",
    )
    .bind(incident.id.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.try_get::<String, _>("status").unwrap(), "open");
    assert_eq!(row.try_get::<i64, _>("to_ts").unwrap(), 0);
    assert_eq!(row.try_get::<i64, _>("marks").unwrap(), 0);
    pool.close().await;
}

#[tokio::test]
async fn pg_command_collision_on_other_incident_fails_closed() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let (pool, store) = migrated_pg(&dsn).await;
    let first = store
        .create_incident(new_incident("inc_pg_command_a", 100))
        .await
        .unwrap();
    let second = store
        .create_incident(new_incident("inc_pg_command_b", 101))
        .await
        .unwrap();
    assert!(matches!(
        store
            .resolve_incident(resolve_command(&first.id, COMMAND_A, 102_001))
            .await
            .unwrap(),
        ResolveResult::Resolved { .. }
    ));
    assert!(matches!(
        store
            .resolve_incident(resolve_command(&second.id, COMMAND_A, 103_001))
            .await
            .unwrap(),
        ResolveResult::InvariantFailure(ResolveInvariant::CommandIdentityCollision)
    ));
    assert_eq!(
        store
            .get_incident_case(&second.id)
            .await
            .unwrap()
            .unwrap()
            .lifecycle,
        IncidentLifecycle::Open
    );
    pool.close().await;
}

#[tokio::test]
async fn pg_public_mark_ref_collision_rolls_back() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let (pool, store) = migrated_pg(&dsn).await;
    sqlx::query(
        "CREATE OR REPLACE FUNCTION hindsight_test_force_mark_ref() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN NEW.mark_ref='rm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; RETURN NEW; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER hindsight_test_force_mark_ref \
         BEFORE INSERT ON resolution_marks FOR EACH ROW EXECUTE FUNCTION hindsight_test_force_mark_ref()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let first = store
        .create_incident(new_incident("inc_pg_mark_a", 100))
        .await
        .unwrap();
    let second = store
        .create_incident(new_incident("inc_pg_mark_b", 101))
        .await
        .unwrap();
    assert!(matches!(
        store
            .resolve_incident(resolve_command(&first.id, COMMAND_A, 102_001))
            .await
            .unwrap(),
        ResolveResult::Resolved { .. }
    ));
    assert!(matches!(
        store
            .resolve_incident(resolve_command(&second.id, COMMAND_B, 103_001))
            .await
            .unwrap(),
        ResolveResult::InvariantFailure(ResolveInvariant::PublicMarkRefCollision)
    ));
    assert_eq!(
        store
            .get_incident_case(&second.id)
            .await
            .unwrap()
            .unwrap()
            .lifecycle,
        IncidentLifecycle::Open
    );
    pool.close().await;
}

#[tokio::test]
async fn pg_legacy_actor_columns_preserve_unclassified_truth() {
    let Some(dsn) = pg_test_dsn() else { return };
    let _guard = PG_TEST_LOCK.lock().await;
    let pool = pg_pool(&dsn).await;
    reset_pg(&pool).await;
    legacy_schema(&pool).await;
    sqlx::query(
        "INSERT INTO incidents \
         (id,title,status,from_ts,to_ts,created_by,created_at) \
         VALUES ('inc_pg_legacy','Legacy','open',1,0,'legacy display',2)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO notes (id,incident_id,body,author_sub,created_at) \
         VALUES ('note_pg_legacy','inc_pg_legacy','Legacy note','verified-note-subject',3)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let store = PgStore::from_pool(pool.clone());
    store.migrate().await.unwrap();
    let incident = store
        .get_incident_case(&IncidentId::parse("inc_pg_legacy").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        incident.actor,
        ActorTruth::LegacyUnclassified { ref legacy_display }
            if legacy_display.visible() == "legacy display"
    ));
    let notes = store.list_notes_bounded(&incident.id, 201).await.unwrap();
    assert!(matches!(
        notes.rows[0].actor,
        ActorTruth::Verified {
            ref subject,
            display_email: None
        } if subject.as_str() == "verified-note-subject"
    ));
    pool.close().await;
}
