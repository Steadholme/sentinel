//! Authenticated HTML and JSON Hindsight routes.

use std::collections::BTreeMap;

use axum::body::{to_bytes, Body};
use axum::extract::{OriginalUri, RawQuery, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::{DEFAULT_WINDOW_HOURS, FORM_BODY_CAP, LIST_LIMIT, NOTE_LIMIT, WINDOW_CHOICES};
use crate::error::{AppError, ErrorCondition, ErrorSurface, RouteAllow};
use crate::feeds::{self, ComparisonSnapshot};
use crate::handlers::{datetime_attribute_ms, fmt_datetime_ms, fmt_datetime_s, render_topbar};
use crate::store::{
    IncidentCase, NewIncident, NewNote, OperatorNote, ResolveCommand, ResolveResult,
};
use crate::view_contract::{
    token, ActorTruth, AuditReceiptTruth, BoundedDisplayEmail, BoundedNote, BoundedRows,
    BoundedSubject, BoundedTitle, Boundedness, ChannelId, ChannelState, ComposeError, Composer,
    CsrfToken, EscapedAttribute, EscapedText, EvidenceItem, EvidenceRecord, ExpectedOpen,
    IncidentId, IncidentLifecycle, MarkKind, NoteId, ProductRelativePath, RenderedFragment,
    RequestedWindowMs, ResolveCommandId, SectionState, Slot, SlotValue, StaticCssValue, TemplateId,
    TokenDomain, TypedBooleanAttribute, TypedHiddenValue, ValidationError, WindowGate,
    WindowLifecycle,
};
use crate::{now_millis, AppState};

const TITLE_EMPTY: &str = "Enter an incident title";
const TITLE_INVALID: &str =
    "Title must be 1–160 characters, at most 1,024 bytes, and contain no control characters";
const WINDOW_INVALID: &str = "Choose 1, 6, 24, 72, or 168 hours";
const NOTE_EMPTY: &str = "Enter an operator note";
const NOTE_INVALID: &str =
    "Note must be 1–4,000 characters, at most 16,384 bytes, and contain no unsupported control characters";

#[derive(Clone)]
struct Identity {
    subject: BoundedSubject,
    display_email: Option<BoundedDisplayEmail>,
}

#[derive(Clone, Debug)]
struct OpenFormRender {
    title: String,
    window_hours: i64,
    title_error: Option<&'static str>,
    window_error: Option<&'static str>,
}

impl OpenFormRender {
    fn pristine(window_hours: i64) -> Self {
        Self {
            title: String::new(),
            window_hours,
            title_error: None,
            window_error: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct NoteFormRender {
    body: String,
    body_error: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// GET routes
// ---------------------------------------------------------------------------

pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, AppError> {
    let window_hours = parse_dashboard_query(raw_query.as_deref())?;
    let identity = require_identity(&headers)?;
    let (csrf, set_cookie) = csrf_for_get(&headers);
    render_dashboard(
        &state,
        &identity,
        &csrf,
        set_cookie,
        window_hours,
        OpenFormRender::pristine(window_hours),
        None,
        StatusCode::OK,
    )
    .await
    .map_err(AppError::authenticated)
}

pub async fn incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, AppError> {
    reject_any_query(raw_query.as_deref())?;
    let identity = require_identity(&headers)?;
    let result: Result<Response, AppError> = async {
        let raw_id = route_incident_id(&uri, "/incident/", "")
            .ok_or_else(|| AppError::html(ErrorCondition::IncidentAbsent))?;
        let id = IncidentId::parse(raw_id)
            .map_err(|_| AppError::html(ErrorCondition::IncidentAbsent))?;
        let case = state
            .store
            .get_incident_case(&id)
            .await
            .map_err(|_| AppError::html(ErrorCondition::PrimaryUnavailable))?
            .ok_or_else(|| AppError::html(ErrorCondition::IncidentAbsent))?;
        let observed_at_ms = now_millis();
        let (csrf, set_cookie) = csrf_for_get(&headers);
        render_incident(
            &state,
            &identity,
            &csrf,
            set_cookie,
            case,
            NoteFormRender::default(),
            None,
            StatusCode::OK,
            observed_at_ms,
        )
        .await
    }
    .await;
    result.map_err(AppError::authenticated)
}

pub async fn timeline_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, AppError> {
    let _identity = require_identity_json(&headers)?;
    let observed_at_ms = now_millis();
    let requested = parse_timeline_query(raw_query.as_deref(), observed_at_ms)?;
    let gate = WindowGate::validate(
        requested,
        observed_at_ms,
        if requested.to_inclusive.is_some() {
            WindowLifecycle::Frozen
        } else {
            WindowLifecycle::Moving
        },
    )
    .map_err(|_| AppError::json(ErrorCondition::InvalidWindow))?;
    let snapshot = feeds::gather(&state.config, state.logs.as_ref(), gate)
        .await
        .map_err(|_| AppError::json(ErrorCondition::Internal))?;
    Ok(Json(snapshot.timeline_json_v2()).into_response())
}

// ---------------------------------------------------------------------------
// Native form mutations
// ---------------------------------------------------------------------------

pub async fn open_incident(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let headers = request.headers().clone();
    let form = strict_form(request, &["title", "window_hours", "csrf_token"]).await?;
    let identity = require_identity(&headers)?;
    let result: Result<Response, AppError> = async {
        let csrf = parse_form_csrf(&form)?;
        verify_csrf(&headers, &csrf)?;

        let raw_title = form.get("title").expect("strict field");
        let raw_window = form.get("window_hours").expect("strict field");
        let window_hours = parse_window_choice(raw_window);
        let title = BoundedTitle::parse(raw_title);
        let render = OpenFormRender {
            title: title
                .as_ref()
                .map(|value| value.as_str().to_string())
                .unwrap_or_default(),
            window_hours: window_hours
                .filter(|value| WINDOW_CHOICES.contains(value))
                .unwrap_or(DEFAULT_WINDOW_HOURS),
            title_error: match &title {
                Err(ValidationError::Empty) => Some(TITLE_EMPTY),
                Err(_) => Some(TITLE_INVALID),
                Ok(_) => None,
            },
            window_error: if window_hours.is_some() {
                None
            } else {
                Some(WINDOW_INVALID)
            },
        };
        if render.title_error.is_some() || render.window_error.is_some() {
            return render_dashboard(
                &state,
                &identity,
                &csrf,
                None,
                render.window_hours,
                render,
                None,
                StatusCode::BAD_REQUEST,
            )
            .await;
        }

        let observed_at_ms = now_millis();
        let created_at_s = observed_at_ms.div_euclid(1_000);
        let window_seconds = render
            .window_hours
            .checked_mul(3_600)
            .ok_or_else(|| AppError::html(ErrorCondition::Internal))?;
        let from_ts_s = created_at_s
            .checked_sub(window_seconds)
            .ok_or_else(|| AppError::html(ErrorCondition::Internal))?;
        let id = IncidentId::generate();
        let created = state
            .store
            .create_incident(NewIncident {
                id: id.clone(),
                title: title.expect("validated title"),
                from_ts_s,
                actor_sub: identity.subject.clone(),
                display_email: identity.display_email.clone(),
                created_at_s,
            })
            .await
            .map_err(|_| AppError::html(ErrorCondition::Internal))?;
        let outcome = state.audit.emit(AuditEvent::notice(
            "hindsight.incident.open",
            identity.subject.as_str(),
            created.id.as_str(),
            &render.window_hours.to_string(),
        ));
        tracing::info!(
            audit_outcome = audit_outcome_token(outcome),
            "incident-open audit enqueue attempted"
        );
        redirect(ProductRelativePath::IncidentOpened(id))
    }
    .await;
    result.map_err(AppError::authenticated)
}

pub async fn add_note(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Result<Response, AppError> {
    let headers = request.headers().clone();
    let form = strict_form(request, &["incident_id", "body", "csrf_token"]).await?;
    let identity = require_identity(&headers)?;
    let result: Result<Response, AppError> = async {
        let csrf = parse_form_csrf(&form)?;
        verify_csrf(&headers, &csrf)?;
        let raw_path_id = route_incident_id(&uri, "/api/incidents/", "/notes")
            .ok_or_else(|| AppError::html(ErrorCondition::StructuralForm))?;
        let path_id = IncidentId::parse(raw_path_id)
            .map_err(|_| AppError::html(ErrorCondition::StructuralForm))?;
        let body_id = IncidentId::parse(form.get("incident_id").expect("strict field"))
            .map_err(|_| AppError::html(ErrorCondition::StructuralForm))?;
        if !constant_time_equal(path_id.as_str(), body_id.as_str()) {
            return Err(AppError::html(ErrorCondition::StructuralForm));
        }
        let case = state
            .store
            .get_incident_case(&path_id)
            .await
            .map_err(|_| AppError::html(ErrorCondition::PrimaryUnavailable))?
            .ok_or_else(|| AppError::html(ErrorCondition::IncidentAbsent))?;
        let raw_body = form.get("body").expect("strict field");
        let body = BoundedNote::parse(raw_body);
        if let Err(error) = body {
            let body_error = match error {
                ValidationError::Empty => NOTE_EMPTY,
                _ => NOTE_INVALID,
            };
            let safe_body = BoundedNote::parse(raw_body)
                .map(|value| value.as_str().to_string())
                .unwrap_or_default();
            return render_incident(
                &state,
                &identity,
                &csrf,
                None,
                case,
                NoteFormRender {
                    body: safe_body,
                    body_error: Some(body_error),
                },
                None,
                StatusCode::BAD_REQUEST,
                now_millis(),
            )
            .await;
        }
        let note = state
            .store
            .add_note(NewNote {
                id: NoteId::generate(),
                incident_id: path_id.clone(),
                body: body.expect("validated note"),
                actor_sub: identity.subject,
                display_email: identity.display_email,
                created_at_s: now_millis().div_euclid(1_000),
            })
            .await
            .map_err(|_| AppError::html(ErrorCondition::Internal))?;
        redirect(ProductRelativePath::NoteAdded(path_id, note.id))
    }
    .await;
    result.map_err(AppError::authenticated)
}

pub async fn resolve_incident(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Result<Response, AppError> {
    let headers = request.headers().clone();
    let form = strict_form(
        request,
        &[
            "incident_id",
            "expected_lifecycle",
            "command_id",
            "csrf_token",
        ],
    )
    .await?;
    let identity = require_identity(&headers)?;
    let result: Result<Response, AppError> = async {
        let csrf = parse_form_csrf(&form)?;
        verify_csrf(&headers, &csrf)?;
        let raw_path_id = route_incident_id(&uri, "/api/incidents/", "/resolve")
            .ok_or_else(|| AppError::html(ErrorCondition::StructuralForm))?;
        let path_id = IncidentId::parse(raw_path_id)
            .map_err(|_| AppError::html(ErrorCondition::StructuralForm))?;
        let body_id = IncidentId::parse(form.get("incident_id").expect("strict field"))
            .map_err(|_| AppError::html(ErrorCondition::StructuralForm))?;
        if !constant_time_equal(path_id.as_str(), body_id.as_str()) {
            return Err(AppError::html(ErrorCondition::StructuralForm));
        }
        let expected = ExpectedOpen::parse(form.get("expected_lifecycle").expect("strict field"))
            .map_err(|_| AppError::html(ErrorCondition::StructuralForm))?;
        let command_id = ResolveCommandId::parse(form.get("command_id").expect("strict field"))
            .map_err(|_| AppError::html(ErrorCondition::StructuralForm))?;
        let observed_at_ms = now_millis();
        let outcome = state
            .store
            .resolve_incident(ResolveCommand {
                incident_id: path_id.clone(),
                command_id,
                expected_lifecycle: expected,
                actor_sub: identity.subject.clone(),
                display_email: identity.display_email.clone(),
                observed_at_ms,
            })
            .await
            .map_err(|_| AppError::html(ErrorCondition::Internal))?;
        match outcome {
            ResolveResult::Resolved { mark, .. } | ResolveResult::AlreadyResolved { mark, .. } => {
                redirect(ProductRelativePath::Resolved(path_id, mark.mark_ref))
            }
            ResolveResult::StaleConflict { incident, mark } => {
                render_incident(
                    &state,
                    &identity,
                    &csrf,
                    None,
                    incident,
                    NoteFormRender::default(),
                    Some(render_notice(
                        "resolve-errors",
                        "stale-conflict",
                        "Incident already resolved",
                        ErrorCondition::StaleResolve.message(),
                    )?),
                    StatusCode::CONFLICT,
                    observed_at_ms.max(mark.resolved_at_ms),
                )
                .await
            }
            ResolveResult::NotFound => Err(AppError::html(ErrorCondition::IncidentAbsent)),
            ResolveResult::InvariantFailure(_) => Err(AppError::html(ErrorCondition::Internal)),
        }
    }
    .await;
    result.map_err(AppError::authenticated)
}

// ---------------------------------------------------------------------------
// Router fallbacks
// ---------------------------------------------------------------------------

pub async fn method_not_allowed(OriginalUri(uri): OriginalUri, method: Method) -> Response {
    let path = uri.path();
    let (surface, allow) = if path == "/api/timeline" {
        (ErrorSurface::Json, RouteAllow::GetHead)
    } else if is_native_form_path(path) {
        (ErrorSurface::Html, RouteAllow::Post)
    } else if path == "/healthz" || path == "/" || is_incident_path(path) {
        (ErrorSurface::Html, RouteAllow::GetHead)
    } else if path.starts_with("/api/") {
        (
            ErrorSurface::Json,
            if method == Method::GET {
                RouteAllow::Get
            } else {
                RouteAllow::Post
            },
        )
    } else {
        (ErrorSurface::Html, RouteAllow::Get)
    };
    AppError::method(surface, allow).into_response()
}

pub async fn route_not_found(OriginalUri(uri): OriginalUri) -> Response {
    if uri.path().starts_with("/api/") {
        AppError::json(ErrorCondition::RouteAbsent).into_response()
    } else {
        AppError::html(ErrorCondition::RouteAbsent).into_response()
    }
}

// ---------------------------------------------------------------------------
// Page composition
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn render_dashboard(
    state: &AppState,
    identity: &Identity,
    csrf: &CsrfToken,
    set_cookie: Option<String>,
    window_hours: i64,
    open_state: OpenFormRender,
    notice: Option<RenderedFragment>,
    status: StatusCode,
) -> Result<Response, AppError> {
    let observed_at_ms = now_millis();
    let from_ms = observed_at_ms
        .checked_sub(
            window_hours
                .checked_mul(3_600_000)
                .ok_or_else(|| AppError::html(ErrorCondition::Internal))?,
        )
        .ok_or_else(|| AppError::html(ErrorCondition::Internal))?;
    let gate = WindowGate::validate(
        RequestedWindowMs {
            from_inclusive: from_ms,
            to_inclusive: None,
        },
        observed_at_ms,
        WindowLifecycle::Moving,
    )
    .map_err(|_| AppError::html(ErrorCondition::InvalidWindow))?;
    let snapshot = feeds::gather(&state.config, state.logs.as_ref(), gate)
        .await
        .map_err(|_| AppError::html(ErrorCondition::Internal))?;
    let incidents = state.store.list_incidents_bounded(LIST_LIMIT + 1).await;
    let (incident_state, incident_rows) = match incidents {
        Ok(rows) => {
            let state = section_state(&rows);
            let rendered = rows
                .rows
                .iter()
                .map(|case| render_incident_row(case, None))
                .collect::<Result<Vec<_>, _>>()?;
            (state, rendered)
        }
        Err(_) => (SectionState::Unavailable, Vec::new()),
    };
    let topbar = render_topbar("Hindsight", &display_identity(identity), true)?;
    let choices = WINDOW_CHOICES
        .iter()
        .map(|hours| render_window_choice(*hours, *hours == window_hours))
        .collect::<Result<Vec<_>, _>>()?;
    let channels = render_channels(&snapshot)?;
    let open_form = render_open_form(csrf, &open_state)?;
    let page = Composer::render(
        TemplateId::Dashboard,
        vec![
            (
                Slot::StaticCss,
                SlotValue::StaticCss(StaticCssValue::application()),
            ),
            (Slot::TopbarFragment, SlotValue::Fragment(topbar)),
            (
                Slot::DocumentTitleText,
                text("Incident comparator · Hindsight"),
            ),
            (Slot::HeadingTitleText, text("Incident comparator")),
            (
                Slot::PageNoticeFragment,
                SlotValue::Fragment(
                    notice
                        .unwrap_or_else(|| RenderedFragment::typed_empty(TemplateId::InlineNotice)),
                ),
            ),
            (
                Slot::WindowRequestedText,
                text(format!("Requested window: last {window_hours} hours")),
            ),
            (
                Slot::WindowEffectiveText,
                text(format!(
                    "Effective window: {} to {}",
                    fmt_datetime_ms(gate.effective.from_inclusive),
                    fmt_datetime_ms(gate.effective.to_inclusive)
                )),
            ),
            (
                Slot::WindowObservedText,
                text(format!(
                    "Observed at {}",
                    fmt_datetime_ms(gate.observed_at_ms)
                )),
            ),
            (
                Slot::WindowObservedDatetimeAttribute,
                attr(datetime_attribute_ms(gate.observed_at_ms)),
            ),
            (Slot::WindowLifecycleText, text("Moving window")),
            (
                Slot::WindowLifecycleToken,
                token(TokenDomain::WindowLifecycle, "moving"),
            ),
            (
                Slot::WindowChoicesFragment,
                SlotValue::FragmentList(choices),
            ),
            (
                Slot::AuditChannelFragment,
                SlotValue::Fragment(channels[0].clone()),
            ),
            (
                Slot::LogChannelFragment,
                SlotValue::Fragment(channels[1].clone()),
            ),
            (
                Slot::MetricChannelFragment,
                SlotValue::Fragment(channels[2].clone()),
            ),
            (
                Slot::IncidentSectionStateText,
                text(section_state_text(incident_state)),
            ),
            (
                Slot::IncidentSectionStateToken,
                section_state_token(incident_state),
            ),
            (
                Slot::IncidentRowsFragmentList,
                SlotValue::FragmentList(incident_rows),
            ),
            (
                Slot::OpenIncidentFormFragment,
                SlotValue::Fragment(open_form),
            ),
        ],
    )?
    .into_string();
    Ok(html_response(status, page, set_cookie))
}

#[allow(clippy::too_many_arguments)]
async fn render_incident(
    state: &AppState,
    identity: &Identity,
    csrf: &CsrfToken,
    set_cookie: Option<String>,
    case: IncidentCase,
    note_state: NoteFormRender,
    notice: Option<RenderedFragment>,
    status: StatusCode,
    observed_at_ms: i64,
) -> Result<Response, AppError> {
    let from_ms = case
        .from_ts_s
        .checked_mul(1_000)
        .ok_or_else(|| AppError::html(ErrorCondition::Internal))?;
    let (requested_to, lifecycle) = match (&case.lifecycle, &case.resolution) {
        (IncidentLifecycle::Open, None) => (None, WindowLifecycle::Moving),
        (IncidentLifecycle::Resolved, Some(mark)) => {
            (Some(mark.resolved_at_ms), WindowLifecycle::Frozen)
        }
        _ => return Err(AppError::html(ErrorCondition::Internal)),
    };
    let gate = WindowGate::validate(
        RequestedWindowMs {
            from_inclusive: from_ms,
            to_inclusive: requested_to,
        },
        observed_at_ms,
        lifecycle,
    )
    .map_err(|_| AppError::html(ErrorCondition::Internal))?;
    let snapshot = feeds::gather(&state.config, state.logs.as_ref(), gate)
        .await
        .map_err(|_| AppError::html(ErrorCondition::Internal))?;
    let notes = state
        .store
        .list_notes_bounded(&case.id, NOTE_LIMIT + 1)
        .await;
    let (operator_state, note_rows) = match notes {
        Ok(rows) => (section_state(&rows), rows.rows),
        Err(_) => (SectionState::Unavailable, Vec::new()),
    };
    let marks = render_operator_marks(&case, &note_rows)?;
    let topbar = render_topbar("Hindsight", &display_identity(identity), true)?;
    let channels = render_channels(&snapshot)?;
    let note_form = render_note_form(&case.id, csrf, &note_state)?;
    let resolve_form = if case.lifecycle == IncidentLifecycle::Open {
        render_resolve_form(&case.id, csrf, &ResolveCommandId::generate(), None)?
    } else {
        RenderedFragment::typed_empty(TemplateId::ResolveForm)
    };
    let lifecycle_text = match case.lifecycle {
        IncidentLifecycle::Open => "Open",
        IncidentLifecycle::Resolved => "Resolved",
    };
    let page = Composer::render(
        TemplateId::Incident,
        vec![
            (
                Slot::StaticCss,
                SlotValue::StaticCss(StaticCssValue::application()),
            ),
            (Slot::TopbarFragment, SlotValue::Fragment(topbar)),
            (
                Slot::DocumentTitleText,
                text(format!("{} · Hindsight", case.title.as_str())),
            ),
            (Slot::HeadingTitleText, text(case.title.as_str())),
            (Slot::IncidentLifecycleText, text(lifecycle_text)),
            (
                Slot::IncidentLifecycleToken,
                lifecycle_token(case.lifecycle),
            ),
            (
                Slot::PageNoticeFragment,
                SlotValue::Fragment(
                    notice
                        .unwrap_or_else(|| RenderedFragment::typed_empty(TemplateId::InlineNotice)),
                ),
            ),
            (
                Slot::WindowRequestedText,
                text(match gate.requested.to_inclusive {
                    Some(to) => format!(
                        "Requested frozen window: {} to {}",
                        fmt_datetime_ms(gate.requested.from_inclusive),
                        fmt_datetime_ms(to)
                    ),
                    None => format!(
                        "Requested moving window from {}",
                        fmt_datetime_ms(gate.requested.from_inclusive)
                    ),
                }),
            ),
            (
                Slot::WindowEffectiveText,
                text(format!(
                    "Effective window: {} to {}",
                    fmt_datetime_ms(gate.effective.from_inclusive),
                    fmt_datetime_ms(gate.effective.to_inclusive)
                )),
            ),
            (
                Slot::WindowObservedText,
                text(format!(
                    "Observed at {}",
                    fmt_datetime_ms(gate.observed_at_ms)
                )),
            ),
            (
                Slot::WindowObservedDatetimeAttribute,
                attr(datetime_attribute_ms(gate.observed_at_ms)),
            ),
            (
                Slot::WindowLifecycleText,
                text(match lifecycle {
                    WindowLifecycle::Moving => "Moving window",
                    WindowLifecycle::Frozen => "Frozen window",
                }),
            ),
            (
                Slot::WindowLifecycleToken,
                token(
                    TokenDomain::WindowLifecycle,
                    match lifecycle {
                        WindowLifecycle::Moving => "moving",
                        WindowLifecycle::Frozen => "frozen",
                    },
                ),
            ),
            (
                Slot::AuditChannelFragment,
                SlotValue::Fragment(channels[0].clone()),
            ),
            (
                Slot::LogChannelFragment,
                SlotValue::Fragment(channels[1].clone()),
            ),
            (
                Slot::MetricChannelFragment,
                SlotValue::Fragment(channels[2].clone()),
            ),
            (
                Slot::OperatorSectionStateText,
                text(section_state_text(operator_state)),
            ),
            (
                Slot::OperatorSectionStateToken,
                section_state_token(operator_state),
            ),
            (
                Slot::OperatorMarksFragmentList,
                SlotValue::FragmentList(marks),
            ),
            (Slot::NoteFormFragment, SlotValue::Fragment(note_form)),
            (Slot::ResolveFormFragment, SlotValue::Fragment(resolve_form)),
            (
                Slot::ReturnPath,
                SlotValue::ProductPath(ProductRelativePath::Root),
            ),
        ],
    )?
    .into_string();
    Ok(html_response(status, page, set_cookie))
}

fn render_channels(snapshot: &ComparisonSnapshot) -> Result<[RenderedFragment; 3], ComposeError> {
    Ok([
        render_channel(&snapshot.channels[0])?,
        render_channel(&snapshot.channels[1])?,
        render_channel(&snapshot.channels[2])?,
    ])
}

fn render_channel(
    channel: &crate::view_contract::ChannelView,
) -> Result<RenderedFragment, ComposeError> {
    let items = channel
        .items
        .iter()
        .map(render_evidence_item)
        .collect::<Result<Vec<_>, _>>()?;
    let loaded = matches!(
        channel.state,
        ChannelState::LoadedEmpty | ChannelState::LoadedNonEmpty(_)
    );
    let coverage_text = if loaded {
        let coverage = channel.coverage.as_ref().expect("loaded coverage");
        format!(
            "Coverage {} to {}; before-window gap {}; after-window gap {}",
            fmt_datetime_ms(coverage.effective_from_ms),
            fmt_datetime_ms(coverage.effective_to_ms),
            gap_text(coverage.gap_before_window),
            gap_text(coverage.gap_after_window)
        )
    } else {
        "Coverage unavailable — acquisition did not produce valid records".to_string()
    };
    let acquired_text = channel
        .acquired_count
        .map(|count| format!("Acquired rows: {count}"))
        .unwrap_or_else(|| "Acquired count unavailable".to_string());
    let eligible_text = channel
        .eligible_distinct_count
        .map(|count| format!("Eligible distinct items: {count}"))
        .unwrap_or_else(|| "No decoded events".to_string());
    let displayed_text = channel
        .displayed_distinct_count
        .map(|count| format!("Displayed distinct items: {count}"))
        .unwrap_or_else(|| "Displayed count unavailable".to_string());
    let allocation_text = match (
        channel.eligible_distinct_count,
        channel.displayed_distinct_count,
    ) {
        (Some(eligible), Some(displayed)) => {
            let omitted = eligible
                .checked_sub(displayed)
                .ok_or(ComposeError::CrossSlotInvariant)?;
            if omitted == 0 {
                "No distinct item omitted by the 300-item display allocation".to_string()
            } else {
                format!(
                    "{omitted} distinct items omitted by the 300-item cross-channel display allocation"
                )
            }
        }
        _ => "Display allocation unavailable".to_string(),
    };
    let (boundedness_text, boundedness_token) = match channel.state {
        ChannelState::LoadedNonEmpty(Boundedness::KnownMore) => {
            ("More known beyond this view", "known-more")
        }
        ChannelState::LoadedNonEmpty(Boundedness::ProvenEnd) => {
            ("End of selected window proven", "proven-end")
        }
        ChannelState::LoadedNonEmpty(Boundedness::CompletenessUnknown) => {
            ("Completeness unknown", "completeness-unknown")
        }
        _ => (
            "Boundedness not applicable — no decoded events",
            "not-applicable",
        ),
    };
    Composer::render(
        TemplateId::FeedChannel,
        vec![
            (Slot::ChannelToken, channel_token(channel.id)),
            (Slot::SourceLabelText, text(channel_label(channel.id))),
            (Slot::StateText, text(channel_state_label(&channel.state))),
            (Slot::StateToken, channel_state_token(&channel.state)),
            (
                Slot::StateDescriptionText,
                text(channel_state_description(&channel.state)),
            ),
            (Slot::CoverageText, text(coverage_text)),
            (Slot::AcquiredCountText, text(acquired_text)),
            (Slot::EligibleDistinctCountText, text(eligible_text)),
            (Slot::DisplayedCountText, text(displayed_text)),
            (Slot::DisplayAllocationText, text(allocation_text)),
            (Slot::BoundednessText, text(boundedness_text)),
            (
                Slot::BoundednessToken,
                token(TokenDomain::Boundedness, boundedness_token),
            ),
            (Slot::EventItemsFragmentList, SlotValue::FragmentList(items)),
        ],
    )
}

fn render_evidence_item(item: &EvidenceItem) -> Result<RenderedFragment, ComposeError> {
    match item {
        EvidenceItem::Event { record } => render_record(record, Vec::new()),
        EvidenceItem::Conflict {
            source_key,
            variants,
        } => {
            let rendered = variants
                .iter()
                .take(300)
                .map(|variant| render_record(variant, Vec::new()))
                .collect::<Result<Vec<_>, _>>()?;
            let max_ms = variants
                .iter()
                .filter_map(EvidenceRecord::instant_ms)
                .max()
                .unwrap_or(0);
            let min_ms = variants
                .iter()
                .filter_map(EvidenceRecord::instant_ms)
                .min()
                .unwrap_or(0);
            let omitted = variants
                .len()
                .checked_sub(rendered.len())
                .ok_or(ComposeError::CrossSlotInvariant)?;
            Composer::render(
                TemplateId::Event,
                vec![
                    (Slot::ChannelToken, channel_token(item.channel())),
                    (
                        Slot::RecordedText,
                        text(format!(
                            "{} to {} · Ordering anchor only",
                            fmt_datetime_ms(min_ms),
                            fmt_datetime_ms(max_ms)
                        )),
                    ),
                    (
                        Slot::RecordedDatetimeAttribute,
                        attr(datetime_attribute_ms(max_ms)),
                    ),
                    (Slot::SeverityText, text("Unknown producer severity")),
                    (Slot::SeverityToken, token(TokenDomain::Severity, "unknown")),
                    (Slot::TitleText, text("Conflicting source assertions")),
                    (
                        Slot::DetailPreviewText,
                        text(format!(
                            "{} variants; {} omitted from HTML",
                            variants.len(),
                            omitted
                        )),
                    ),
                    (Slot::MachineValueText, text("")),
                    (
                        Slot::ProvenanceText,
                        text(bounded_presentation(
                            &source_key_text(source_key),
                            512,
                            2_048,
                        )),
                    ),
                    (
                        Slot::DisclosureFragment,
                        SlotValue::Fragment(RenderedFragment::typed_empty(TemplateId::Disclosure)),
                    ),
                    (Slot::ConflictFragment, SlotValue::FragmentList(rendered)),
                ],
            )
        }
    }
}

fn render_record(
    record: &EvidenceRecord,
    conflicts: Vec<RenderedFragment>,
) -> Result<RenderedFragment, ComposeError> {
    let instant = record.instant_ms().unwrap_or(0);
    let (severity_text, severity_token_value) = severity(record);
    let (title, detail, machine, provenance, disclosure_summary, disclosure_body) =
        record_presentation(record);
    let disclosure = if disclosure_body.is_empty() {
        RenderedFragment::typed_empty(TemplateId::Disclosure)
    } else {
        Composer::render(
            TemplateId::Disclosure,
            vec![
                (Slot::DisclosureSummaryText, text(disclosure_summary)),
                (Slot::DisclosureBodyText, text(disclosure_body)),
            ],
        )?
    };
    Composer::render(
        TemplateId::Event,
        vec![
            (Slot::ChannelToken, channel_token(record.channel())),
            (Slot::RecordedText, text(fmt_datetime_ms(instant))),
            (
                Slot::RecordedDatetimeAttribute,
                attr(datetime_attribute_ms(instant)),
            ),
            (Slot::SeverityText, text(severity_text)),
            (
                Slot::SeverityToken,
                token(TokenDomain::Severity, severity_token_value),
            ),
            (Slot::TitleText, text(title)),
            (Slot::DetailPreviewText, text(detail)),
            (Slot::MachineValueText, text(machine)),
            (Slot::ProvenanceText, text(provenance)),
            (Slot::DisclosureFragment, SlotValue::Fragment(disclosure)),
            (Slot::ConflictFragment, SlotValue::FragmentList(conflicts)),
        ],
    )?
    .with_evidence_record(record)
}

fn record_presentation(
    record: &EvidenceRecord,
) -> (String, String, String, String, String, String) {
    match record {
        EvidenceRecord::Audit(record) => {
            let title = source_title(&record.action);
            (
                title,
                bounded_presentation(&record.detail, 512, 2_048),
                String::new(),
                bounded_presentation(
                    &format!("Audit sequence {} · hash {}", record.sequence, record.hash),
                    512,
                    2_048,
                ),
                "Audit source fields".to_string(),
                bounded_presentation(
                    &format!(
                        "Actor: {}\nTarget: {}\nSource: {}\nPrevious hash: {}",
                        record.actor, record.target, record.source, record.previous_hash
                    ),
                    4_096,
                    16_384,
                ),
            )
        }
        EvidenceRecord::Log(record) => {
            let detail =
                bounded_presentation(&format!("{} · {}", record.host, record.app), 512, 2_048);
            (
                source_title(&record.message),
                detail,
                String::new(),
                bounded_presentation(
                    &format!(
                        "Log id {} · template {}",
                        record.id,
                        if record.template_id.is_empty() {
                            "not recorded"
                        } else {
                            &record.template_id
                        }
                    ),
                    512,
                    2_048,
                ),
                "Retained log message".to_string(),
                bounded_presentation(&record.message, 4_096, 16_384),
            )
        }
        EvidenceRecord::Metric(record) => (
            record.derivation.clone(),
            bounded_presentation(&record.host, 512, 2_048),
            f64::from_bits(record.raw_value_bits).to_string(),
            bounded_presentation(
                &format!(
                    "Metric {} · {} · {}",
                    record.host, record.metric_name, record.recorded_at_s
                ),
                512,
                2_048,
            ),
            "Metric derivation".to_string(),
            bounded_presentation(
                &format!("{} · {}", record.unit, record.derivation),
                4_096,
                16_384,
            ),
        ),
    }
}

fn render_window_choice(hours: i64, current: bool) -> Result<RenderedFragment, ComposeError> {
    Composer::render(
        TemplateId::WindowChoice,
        vec![
            (
                Slot::WindowChoicePath,
                SlotValue::ProductPath(ProductRelativePath::DashboardWindow(hours)),
            ),
            (
                Slot::WindowChoiceText,
                text(match hours {
                    1 => "1 hour".to_string(),
                    24 => "24 hours".to_string(),
                    72 => "3 days".to_string(),
                    168 => "7 days".to_string(),
                    value => format!("{value} hours"),
                }),
            ),
            (
                Slot::WindowChoiceCurrentToken,
                token(
                    TokenDomain::Current,
                    if current { "current" } else { "not-current" },
                ),
            ),
            (
                Slot::WindowChoiceAriaCurrentAttribute,
                attr(if current { "page" } else { "false" }),
            ),
        ],
    )
}

fn render_incident_row(
    case: &IncidentCase,
    current: Option<&IncidentId>,
) -> Result<RenderedFragment, ComposeError> {
    let (subject, display, truth_token) = actor_presentation(&case.actor);
    let is_current = current.is_some_and(|id| id == &case.id);
    Composer::render(
        TemplateId::IncidentRow,
        vec![
            (
                Slot::IncidentPath,
                SlotValue::ProductPath(ProductRelativePath::Incident(case.id.clone())),
            ),
            (Slot::TitleText, text(case.title.as_str())),
            (Slot::OpenedText, text(fmt_datetime_s(case.created_at_s))),
            (
                Slot::OpenedDatetimeAttribute,
                attr(datetime_attribute_ms(
                    case.created_at_s
                        .checked_mul(1_000)
                        .ok_or(ComposeError::CrossSlotInvariant)?,
                )),
            ),
            (Slot::ActorSubjectText, text(subject)),
            (Slot::DisplayIdentityText, text(display)),
            (
                Slot::ActorTruthToken,
                token(TokenDomain::ActorTruth, truth_token),
            ),
            (
                Slot::LifecycleText,
                text(match case.lifecycle {
                    IncidentLifecycle::Open => "Open",
                    IncidentLifecycle::Resolved => "Resolved",
                }),
            ),
            (Slot::LifecycleToken, lifecycle_token(case.lifecycle)),
            (
                Slot::CurrentText,
                text(if is_current { "Current" } else { "" }),
            ),
            (
                Slot::CurrentToken,
                token(
                    TokenDomain::Current,
                    if is_current { "current" } else { "not-current" },
                ),
            ),
        ],
    )
}

fn render_operator_marks(
    case: &IncidentCase,
    notes: &[OperatorNote],
) -> Result<Vec<RenderedFragment>, ComposeError> {
    let mut marks = Vec::with_capacity(notes.len() + 2);
    marks.push(render_operator_mark(
        "incident-opened",
        MarkKind::IncidentOpened,
        &case.actor,
        case.created_at_s
            .checked_mul(1_000)
            .ok_or(ComposeError::CrossSlotInvariant)?,
        case.title.as_str(),
        "Open",
        "",
        AuditReceiptTruth::OpenAttemptedNoStoredReceipt,
    )?);
    for note in notes {
        marks.push(render_operator_mark(
            note.id.as_str(),
            MarkKind::NoteAdded,
            &note.actor,
            note.created_at_s
                .checked_mul(1_000)
                .ok_or(ComposeError::CrossSlotInvariant)?,
            note.body.as_str(),
            "",
            "",
            AuditReceiptTruth::NotAttemptedForNote,
        )?);
    }
    if let Some(resolution) = &case.resolution {
        marks.push(render_operator_mark(
            resolution.mark_ref.as_str(),
            MarkKind::IncidentResolved,
            &resolution.actor,
            resolution.resolved_at_ms,
            "Incident resolved",
            "Resolved",
            resolution.mark_ref.as_str(),
            AuditReceiptTruth::NotAttemptedForResolve,
        )?);
    }
    Ok(marks)
}

#[allow(clippy::too_many_arguments)]
fn render_operator_mark(
    id: &str,
    kind: MarkKind,
    actor: &ActorTruth,
    recorded_at_ms: i64,
    body: &str,
    lifecycle: &str,
    public_ref: &str,
    audit_truth: AuditReceiptTruth,
) -> Result<RenderedFragment, ComposeError> {
    let (subject, display, truth_token) = actor_presentation(actor);
    let (kind_text, kind_token) = match kind {
        MarkKind::IncidentOpened => ("Incident opened", "incident-opened"),
        MarkKind::NoteAdded => ("Note added", "note-added"),
        MarkKind::IncidentResolved => ("Incident resolved", "incident-resolved"),
    };
    Composer::render(
        TemplateId::OperatorMark,
        vec![
            (Slot::MarkIdAttribute, attr(id)),
            (Slot::MarkTypeText, text(kind_text)),
            (
                Slot::MarkTypeToken,
                token(TokenDomain::MarkKind, kind_token),
            ),
            (Slot::ActorSubjectText, text(subject)),
            (Slot::DisplayIdentityText, text(display)),
            (
                Slot::ActorTruthToken,
                token(TokenDomain::ActorTruth, truth_token),
            ),
            (Slot::RecordedText, text(fmt_datetime_ms(recorded_at_ms))),
            (
                Slot::RecordedDatetimeAttribute,
                attr(datetime_attribute_ms(recorded_at_ms)),
            ),
            (Slot::BodyText, text(body)),
            (Slot::LifecycleText, text(lifecycle)),
            (Slot::PublicMarkRefText, text(public_ref)),
            (
                Slot::AuditTruthText,
                text(match audit_truth {
                    AuditReceiptTruth::OpenAttemptedNoStoredReceipt => {
                        "Audit enqueue attempted — no enqueue or delivery receipt is stored"
                    }
                    AuditReceiptTruth::NotAttemptedForNote => {
                        "No audit enqueue is attempted for note marks"
                    }
                    AuditReceiptTruth::NotAttemptedForResolve => {
                        "No audit enqueue is attempted for resolution marks"
                    }
                }),
            ),
        ],
    )
}

fn render_open_form(
    csrf: &CsrfToken,
    state: &OpenFormRender,
) -> Result<RenderedFragment, ComposeError> {
    let has_errors = state.title_error.is_some() || state.window_error.is_some();
    let summary = if has_errors {
        render_notice(
            "open-errors",
            "validation-error",
            "Check the open incident form",
            ErrorCondition::VisibleForm.message(),
        )?
    } else {
        RenderedFragment::typed_empty(TemplateId::InlineNotice)
    };
    Composer::render(
        TemplateId::OpenIncidentForm,
        vec![
            (
                Slot::OpenActionPath,
                SlotValue::ProductPath(ProductRelativePath::OpenIncident),
            ),
            (
                Slot::CsrfValueAttribute,
                SlotValue::HiddenValue(TypedHiddenValue::csrf(csrf)),
            ),
            (Slot::OpenTitleValueAttribute, attr(&state.title)),
            (
                Slot::OpenTitleInvalidToken,
                aria_invalid(state.title_error.is_some()),
            ),
            checked_slot(Slot::OpenWindow1CheckedAttribute, state.window_hours == 1),
            checked_slot(Slot::OpenWindow6CheckedAttribute, state.window_hours == 6),
            checked_slot(Slot::OpenWindow24CheckedAttribute, state.window_hours == 24),
            checked_slot(Slot::OpenWindow72CheckedAttribute, state.window_hours == 72),
            checked_slot(
                Slot::OpenWindow168CheckedAttribute,
                state.window_hours == 168,
            ),
            (
                Slot::OpenWindowInvalidToken,
                aria_invalid(state.window_error.is_some()),
            ),
            (Slot::OpenErrorSummaryFragment, SlotValue::Fragment(summary)),
            (
                Slot::OpenTitleErrorText,
                text(state.title_error.unwrap_or("")),
            ),
            (
                Slot::OpenTitleErrorHiddenAttribute,
                SlotValue::BooleanAttribute(TypedBooleanAttribute::hidden(
                    state.title_error.is_none(),
                )),
            ),
            (
                Slot::OpenWindowErrorText,
                text(state.window_error.unwrap_or("")),
            ),
            (
                Slot::OpenWindowErrorHiddenAttribute,
                SlotValue::BooleanAttribute(TypedBooleanAttribute::hidden(
                    state.window_error.is_none(),
                )),
            ),
        ],
    )
}

fn render_note_form(
    incident_id: &IncidentId,
    csrf: &CsrfToken,
    state: &NoteFormRender,
) -> Result<RenderedFragment, ComposeError> {
    let summary = if state.body_error.is_some() {
        render_notice(
            "note-errors",
            "validation-error",
            "Check the operator note",
            ErrorCondition::VisibleForm.message(),
        )?
    } else {
        RenderedFragment::typed_empty(TemplateId::InlineNotice)
    };
    Composer::render(
        TemplateId::NoteForm,
        vec![
            (
                Slot::NoteActionPath,
                SlotValue::ProductPath(ProductRelativePath::AddNote(incident_id.clone())),
            ),
            (
                Slot::CsrfValueAttribute,
                SlotValue::HiddenValue(TypedHiddenValue::csrf(csrf)),
            ),
            (
                Slot::MutationIncidentIdValueAttribute,
                SlotValue::HiddenValue(TypedHiddenValue::incident_id(incident_id)),
            ),
            (Slot::NoteBodyText, text(&state.body)),
            (
                Slot::NoteBodyInvalidToken,
                aria_invalid(state.body_error.is_some()),
            ),
            (Slot::NoteErrorSummaryFragment, SlotValue::Fragment(summary)),
            (
                Slot::NoteBodyErrorText,
                text(state.body_error.unwrap_or("")),
            ),
            (
                Slot::NoteBodyErrorHiddenAttribute,
                SlotValue::BooleanAttribute(TypedBooleanAttribute::hidden(
                    state.body_error.is_none(),
                )),
            ),
        ],
    )
}

fn render_resolve_form(
    incident_id: &IncidentId,
    csrf: &CsrfToken,
    command_id: &ResolveCommandId,
    notice: Option<RenderedFragment>,
) -> Result<RenderedFragment, ComposeError> {
    Composer::render(
        TemplateId::ResolveForm,
        vec![
            (
                Slot::ResolveActionPath,
                SlotValue::ProductPath(ProductRelativePath::Resolve(incident_id.clone())),
            ),
            (
                Slot::CsrfValueAttribute,
                SlotValue::HiddenValue(TypedHiddenValue::csrf(csrf)),
            ),
            (
                Slot::MutationIncidentIdValueAttribute,
                SlotValue::HiddenValue(TypedHiddenValue::incident_id(incident_id)),
            ),
            (
                Slot::ResolveExpectedLifecycleValueAttribute,
                SlotValue::HiddenValue(TypedHiddenValue::expected_open(ExpectedOpen)),
            ),
            (
                Slot::ResolveCommandIdValueAttribute,
                SlotValue::HiddenValue(TypedHiddenValue::resolve_command_id(command_id)),
            ),
            (
                Slot::ResolveErrorSummaryFragment,
                SlotValue::Fragment(
                    notice
                        .unwrap_or_else(|| RenderedFragment::typed_empty(TemplateId::InlineNotice)),
                ),
            ),
        ],
    )
}

fn render_notice(
    id: &str,
    kind: &'static str,
    heading: &str,
    message: &str,
) -> Result<RenderedFragment, ComposeError> {
    Composer::render(
        TemplateId::InlineNotice,
        vec![
            (Slot::NoticeIdAttribute, attr(id)),
            (Slot::NoticeKindToken, token(TokenDomain::NoticeKind, kind)),
            (Slot::NoticeHeadingText, text(heading)),
            (Slot::NoticeMessageText, text(message)),
        ],
    )
}

// ---------------------------------------------------------------------------
// Strict query/form/identity/CSRF parsing
// ---------------------------------------------------------------------------

fn route_incident_id<'a>(uri: &'a axum::http::Uri, prefix: &str, suffix: &str) -> Option<&'a str> {
    let id = uri.path().strip_prefix(prefix)?.strip_suffix(suffix)?;
    (!id.is_empty() && !id.contains('/')).then_some(id)
}

fn parse_dashboard_query(raw: Option<&str>) -> Result<i64, AppError> {
    let pairs = parse_pairs(raw.unwrap_or(""), FORM_BODY_CAP)
        .map_err(|_| AppError::html(ErrorCondition::InvalidWindow))?;
    if pairs.is_empty() {
        return Ok(DEFAULT_WINDOW_HOURS);
    }
    if pairs.len() != 1 || pairs[0].0 != "window" {
        return Err(AppError::html(ErrorCondition::InvalidWindow));
    }
    parse_window_choice(&pairs[0].1).ok_or_else(|| AppError::html(ErrorCondition::InvalidWindow))
}

fn parse_window_choice(raw: &str) -> Option<i64> {
    match raw {
        "1" => Some(1),
        "6" => Some(6),
        "24" => Some(24),
        "72" => Some(72),
        "168" => Some(168),
        _ => None,
    }
}

fn reject_any_query(raw: Option<&str>) -> Result<(), AppError> {
    let pairs = parse_pairs(raw.unwrap_or(""), FORM_BODY_CAP)
        .map_err(|_| AppError::html(ErrorCondition::InvalidWindow))?;
    if pairs.is_empty() {
        Ok(())
    } else {
        Err(AppError::html(ErrorCondition::InvalidWindow))
    }
}

fn parse_timeline_query(
    raw: Option<&str>,
    observed_at_ms: i64,
) -> Result<RequestedWindowMs, AppError> {
    let pairs = parse_pairs(raw.unwrap_or(""), FORM_BODY_CAP)
        .map_err(|_| AppError::json(ErrorCondition::InvalidWindow))?;
    if pairs.is_empty() {
        return Ok(RequestedWindowMs {
            from_inclusive: observed_at_ms
                .checked_sub(DEFAULT_WINDOW_HOURS * 3_600_000)
                .ok_or_else(|| AppError::json(ErrorCondition::InvalidWindow))?,
            to_inclusive: None,
        });
    }
    let mut values = BTreeMap::new();
    for (key, value) in pairs {
        if values.insert(key.clone(), value).is_some()
            || !matches!(key.as_str(), "from" | "to" | "from_ms" | "to_ms")
        {
            return Err(AppError::json(ErrorCondition::InvalidWindow));
        }
    }
    let legacy = values.contains_key("from") || values.contains_key("to");
    let exact = values.contains_key("from_ms") || values.contains_key("to_ms");
    if legacy == exact {
        return Err(AppError::json(ErrorCondition::InvalidWindow));
    }
    if legacy {
        let from = parse_positive_i64(values.get("from"))?
            .checked_mul(1_000)
            .ok_or_else(|| AppError::json(ErrorCondition::InvalidWindow))?;
        let to = match parse_optional_upper(values.get("to"))? {
            Some(value) => Some(
                value
                    .checked_mul(1_000)
                    .ok_or_else(|| AppError::json(ErrorCondition::InvalidWindow))?,
            ),
            None => None,
        };
        Ok(RequestedWindowMs {
            from_inclusive: from,
            to_inclusive: to,
        })
    } else {
        Ok(RequestedWindowMs {
            from_inclusive: parse_positive_i64(values.get("from_ms"))?,
            to_inclusive: parse_optional_upper(values.get("to_ms"))?,
        })
    }
}

fn parse_positive_i64(value: Option<&String>) -> Result<i64, AppError> {
    let value = value
        .ok_or_else(|| AppError::json(ErrorCondition::InvalidWindow))?
        .parse::<i64>()
        .map_err(|_| AppError::json(ErrorCondition::InvalidWindow))?;
    (value > 0)
        .then_some(value)
        .ok_or_else(|| AppError::json(ErrorCondition::InvalidWindow))
}

fn parse_optional_upper(value: Option<&String>) -> Result<Option<i64>, AppError> {
    match value {
        None => Ok(None),
        Some(value) => {
            let parsed = value
                .parse::<i64>()
                .map_err(|_| AppError::json(ErrorCondition::InvalidWindow))?;
            if parsed == 0 {
                Ok(None)
            } else if parsed > 0 {
                Ok(Some(parsed))
            } else {
                Err(AppError::json(ErrorCondition::InvalidWindow))
            }
        }
    }
}

async fn strict_form(
    request: Request,
    expected: &[&str],
) -> Result<BTreeMap<String, String>, AppError> {
    if !valid_form_content_type(request.headers()) {
        return Err(AppError::html(ErrorCondition::StructuralForm));
    }
    let content_lengths = request
        .headers()
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .collect::<Vec<_>>();
    if content_lengths.len() > 1
        || content_lengths.first().is_some_and(|value| {
            value
                .to_str()
                .ok()
                .and_then(parse_content_length)
                .is_none_or(|length| length > FORM_BODY_CAP)
        })
    {
        return Err(AppError::html(ErrorCondition::StructuralForm));
    }
    let bytes = to_bytes(request.into_body(), FORM_BODY_CAP)
        .await
        .map_err(|_| AppError::html(ErrorCondition::StructuralForm))?;
    let raw =
        std::str::from_utf8(&bytes).map_err(|_| AppError::html(ErrorCondition::StructuralForm))?;
    let pairs = parse_pairs(raw, FORM_BODY_CAP)
        .map_err(|_| AppError::html(ErrorCondition::StructuralForm))?;
    let expected_set = expected
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let mut values = BTreeMap::new();
    for (key, value) in pairs {
        if !expected_set.contains(key.as_str()) || values.insert(key, value).is_some() {
            return Err(AppError::html(ErrorCondition::StructuralForm));
        }
    }
    if values.len() != expected.len() || expected.iter().any(|key| !values.contains_key(*key)) {
        return Err(AppError::html(ErrorCondition::StructuralForm));
    }
    Ok(values)
}

fn parse_content_length(raw: &str) -> Option<usize> {
    let raw = raw.trim();
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse::<usize>().ok()
}

fn valid_form_content_type(headers: &HeaderMap) -> bool {
    let values = headers
        .get_all(header::CONTENT_TYPE)
        .iter()
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return false;
    }
    let Ok(raw) = values[0].to_str() else {
        return false;
    };
    let mut parts = raw.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
    {
        return false;
    }
    let parameters = parts.collect::<Vec<_>>();
    parameters.is_empty()
        || (parameters.len() == 1
            && parameters[0].split_once('=').is_some_and(|(name, value)| {
                let value = value.trim();
                let utf8 = value.eq_ignore_ascii_case("utf-8")
                    || (value.len() >= 2
                        && value.starts_with('"')
                        && value.ends_with('"')
                        && value[1..value.len() - 1].eq_ignore_ascii_case("utf-8"));
                name.trim().eq_ignore_ascii_case("charset") && utf8
            }))
}

fn parse_pairs(raw: &str, cap: usize) -> Result<Vec<(String, String)>, ()> {
    if raw.len() > cap {
        return Err(());
    }
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split('&')
        .map(|pair| {
            let (key, value) = pair.split_once('=').ok_or(())?;
            Ok((percent_decode(key)?, percent_decode(value)?))
        })
        .collect()
}

fn percent_decode(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(());
                }
                let high = hex_digit(bytes[index + 1]).ok_or(())?;
                let low = hex_digit(bytes[index + 2]).ok_or(())?;
                output.push((high << 4) | low);
                index += 3;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output).map_err(|_| ())
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn require_identity(headers: &HeaderMap) -> Result<Identity, AppError> {
    identity(headers).map_err(|_| AppError::html(ErrorCondition::MissingIdentity))
}

fn require_identity_json(headers: &HeaderMap) -> Result<Identity, AppError> {
    identity(headers).map_err(|_| AppError::json(ErrorCondition::MissingIdentity))
}

fn identity(headers: &HeaderMap) -> Result<Identity, ()> {
    let subjects = headers
        .get_all(auth::HEADER_SUBJECT)
        .iter()
        .collect::<Vec<_>>();
    if subjects.len() != 1 {
        return Err(());
    }
    let subject = BoundedSubject::parse(subjects[0].to_str().map_err(|_| ())?).map_err(|_| ())?;
    let emails = headers
        .get_all(auth::HEADER_EMAIL)
        .iter()
        .collect::<Vec<_>>();
    let display_email = if emails.len() == 1 {
        emails[0]
            .to_str()
            .ok()
            .and_then(|value| BoundedDisplayEmail::parse(value).ok())
    } else {
        None
    };
    Ok(Identity {
        subject,
        display_email,
    })
}

fn csrf_for_get(headers: &HeaderMap) -> (CsrfToken, Option<String>) {
    match csrf_cookie_values(headers).as_slice() {
        [value] => match CsrfToken::parse(value) {
            Ok(token) => (token, None),
            Err(_) => mint_csrf(),
        },
        _ => mint_csrf(),
    }
}

fn mint_csrf() -> (CsrfToken, Option<String>) {
    let token = CsrfToken::generate();
    let cookie = auth::csrf_cookie(token.as_str());
    (token, Some(cookie))
}

fn parse_form_csrf(form: &BTreeMap<String, String>) -> Result<CsrfToken, AppError> {
    CsrfToken::parse(form.get("csrf_token").expect("strict field"))
        .map_err(|_| AppError::html(ErrorCondition::StructuralForm))
}

fn verify_csrf(headers: &HeaderMap, submitted: &CsrfToken) -> Result<(), AppError> {
    let values = csrf_cookie_values(headers);
    if values.len() == 1
        && CsrfToken::parse(&values[0])
            .ok()
            .is_some_and(|cookie| constant_time_equal(cookie.as_str(), submitted.as_str()))
    {
        Ok(())
    } else {
        Err(AppError::html(ErrorCondition::BadCsrf))
    }
}

fn csrf_cookie_values(headers: &HeaderMap) -> Vec<String> {
    let mut values = Vec::new();
    for header_value in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = header_value.to_str() else {
            continue;
        };
        for (index, raw_pair) in raw.split(';').enumerate() {
            let pair = if index == 0 {
                raw_pair
            } else {
                raw_pair.strip_prefix(' ').unwrap_or(raw_pair)
            };
            let Some((name, value)) = pair.split_once('=') else {
                if pair.trim_matches([' ', '\t']) == auth::CSRF_COOKIE {
                    values.push(String::new());
                }
                continue;
            };
            if name == auth::CSRF_COOKIE {
                values.push(value.to_string());
            } else if name.trim_matches([' ', '\t']) == auth::CSRF_COOKIE {
                values.push(String::new());
            }
        }
    }
    values
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    const COMPARISON_CAP: usize = 128;
    let mut difference = left.len() ^ right.len();
    difference |= usize::from(left.len() > COMPARISON_CAP || right.len() > COMPARISON_CAP);
    for index in 0..COMPARISON_CAP {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

// ---------------------------------------------------------------------------
// Small closed presentation helpers
// ---------------------------------------------------------------------------

fn text(value: impl Into<String>) -> SlotValue {
    SlotValue::Text(EscapedText::new(value))
}

fn attr(value: impl Into<String>) -> SlotValue {
    SlotValue::Attribute(EscapedAttribute::new(value))
}

fn checked_slot(slot: Slot, checked: bool) -> (Slot, SlotValue) {
    (
        slot,
        SlotValue::BooleanAttribute(TypedBooleanAttribute::checked(checked)),
    )
}

fn aria_invalid(invalid: bool) -> SlotValue {
    token(
        TokenDomain::AriaInvalid,
        if invalid { "true" } else { "false" },
    )
}

fn lifecycle_token(lifecycle: IncidentLifecycle) -> SlotValue {
    token(
        TokenDomain::IncidentLifecycle,
        match lifecycle {
            IncidentLifecycle::Open => "open",
            IncidentLifecycle::Resolved => "resolved",
        },
    )
}

fn section_state<T>(rows: &BoundedRows<T>) -> SectionState {
    if rows.rows.is_empty() {
        SectionState::LoadedEmpty
    } else {
        SectionState::Loaded {
            bounded: rows.boundedness,
        }
    }
}

fn section_state_text(state: SectionState) -> &'static str {
    match state {
        SectionState::Loaded {
            bounded: Boundedness::KnownMore,
        } => "Loaded with additional rows known beyond this view",
        SectionState::Loaded {
            bounded: Boundedness::ProvenEnd,
        } => "Loaded — end of section proven",
        SectionState::Loaded {
            bounded: Boundedness::CompletenessUnknown,
        } => "Section invariant rejected",
        SectionState::LoadedEmpty => "Loaded successfully — no rows",
        SectionState::Unavailable => "Section unavailable",
    }
}

fn section_state_token(state: SectionState) -> SlotValue {
    token(
        TokenDomain::SectionState,
        match state {
            SectionState::Loaded {
                bounded: Boundedness::KnownMore,
            } => "loaded-known-more",
            SectionState::Loaded {
                bounded: Boundedness::ProvenEnd,
            } => "loaded-proven-end",
            SectionState::Loaded {
                bounded: Boundedness::CompletenessUnknown,
            } => "unavailable",
            SectionState::LoadedEmpty => "loaded-empty",
            SectionState::Unavailable => "unavailable",
        },
    )
}

fn channel_token(channel: ChannelId) -> SlotValue {
    token(
        TokenDomain::Channel,
        match channel {
            ChannelId::Audit => "audit",
            ChannelId::Log => "log",
            ChannelId::Metric => "metric",
        },
    )
}

fn channel_label(channel: ChannelId) -> &'static str {
    match channel {
        ChannelId::Audit => "Audit register",
        ChannelId::Log => "Log register",
        ChannelId::Metric => "Metric register",
    }
}

fn channel_state_label(state: &ChannelState) -> &'static str {
    match state {
        ChannelState::ConfigurationAbsentOrInvalid => "Configuration absent or invalid",
        ChannelState::Unavailable => "Source unavailable",
        ChannelState::NonSuccess => "Source returned non-success",
        ChannelState::OversizeTruncated => "Acquisition exceeded size limit",
        ChannelState::InvalidSchema => "Response schema invalid",
        ChannelState::LoadedEmpty => "Loaded empty",
        ChannelState::LoadedNonEmpty(_) => "Loaded evidence",
    }
}

fn channel_state_description(state: &ChannelState) -> &'static str {
    match state {
        ChannelState::ConfigurationAbsentOrInvalid => {
            "Source configuration did not produce a valid acquisition target"
        }
        ChannelState::Unavailable => "Source unavailable",
        ChannelState::NonSuccess => {
            "Source returned a non-success response — events were not decoded"
        }
        ChannelState::OversizeTruncated => {
            "Acquisition exceeded the size limit — events were not decoded; completeness unavailable"
        }
        ChannelState::InvalidSchema => {
            "Response schema invalid — events were not decoded"
        }
        ChannelState::LoadedEmpty => {
            "Loaded successfully — no events in this window"
        }
        ChannelState::LoadedNonEmpty(_) => {
            "Decoded evidence retained under the stated boundedness"
        }
    }
}

fn channel_state_token(state: &ChannelState) -> SlotValue {
    token(
        TokenDomain::ChannelState,
        match state {
            ChannelState::ConfigurationAbsentOrInvalid => "configuration-absent-or-invalid",
            ChannelState::Unavailable => "unavailable",
            ChannelState::NonSuccess => "non-success",
            ChannelState::OversizeTruncated => "oversize-truncated",
            ChannelState::InvalidSchema => "invalid-schema",
            ChannelState::LoadedEmpty => "loaded-empty",
            ChannelState::LoadedNonEmpty(_) => "loaded-non-empty",
        },
    )
}

fn gap_text(gap: crate::view_contract::GapTruth) -> &'static str {
    match gap {
        crate::view_contract::GapTruth::Observed => "observed",
        crate::view_contract::GapTruth::NotObserved => "not observed",
        crate::view_contract::GapTruth::Unknown => "unknown",
    }
}

fn severity(record: &EvidenceRecord) -> (String, &'static str) {
    match record {
        EvidenceRecord::Metric(record) => match record.classification {
            crate::view_contract::MetricClassification::LoadElevated => {
                (record.derivation.clone(), "derived-notice")
            }
            _ => (record.derivation.clone(), "derived-warning"),
        },
        EvidenceRecord::Audit(record) => producer_severity(&record.severity),
        EvidenceRecord::Log(record) => producer_severity(&record.severity),
    }
}

fn producer_severity(value: &str) -> (String, &'static str) {
    let normalized = value
        .trim_matches(|character: char| character.is_ascii_whitespace())
        .to_ascii_lowercase();
    let token = match normalized.as_str() {
        "info" => "producer-info",
        "notice" => "producer-notice",
        "warn" | "warning" => "producer-warning",
        "error" | "err" | "crit" | "critical" | "fatal" | "alert" | "emerg" => "producer-error",
        _ => "unknown",
    };
    let text = if token == "unknown" {
        "Unknown producer severity".to_string()
    } else {
        bounded_presentation(value, 256, 1_024)
    };
    (text, token)
}

fn source_key_text(key: &crate::view_contract::SourceKey) -> String {
    match key {
        crate::view_contract::SourceKey::Audit { sequence, hash } => {
            format!("Audit sequence {sequence} · hash {hash}")
        }
        crate::view_contract::SourceKey::Log { id } => {
            format!("Log id {id}")
        }
        crate::view_contract::SourceKey::Metric {
            host,
            metric_name,
            recorded_at_s,
        } => format!("Metric {host} · {metric_name} · {recorded_at_s}"),
    }
}

fn source_title(value: &str) -> String {
    if value.is_empty() {
        "Source title not recorded".to_string()
    } else {
        bounded_presentation(value, 256, 1_024)
    }
}

fn bounded_presentation(value: &str, max_scalars: usize, max_bytes: usize) -> String {
    let scalar_count = value.chars().count();
    if scalar_count <= max_scalars && value.len() <= max_bytes {
        return value.to_string();
    }
    const TRUNCATION_FACT: &str = " · Preview truncated";
    let scalar_budget = max_scalars
        .checked_sub(TRUNCATION_FACT.chars().count())
        .expect("presentation bound accommodates truncation fact");
    let byte_budget = max_bytes
        .checked_sub(TRUNCATION_FACT.len())
        .expect("presentation byte bound accommodates truncation fact");
    let mut output = String::new();
    for (index, character) in value.chars().enumerate() {
        if index >= scalar_budget || output.len() + character.len_utf8() > byte_budget {
            break;
        }
        output.push(character);
    }
    output.push_str(TRUNCATION_FACT);
    output
}

fn actor_presentation(actor: &ActorTruth) -> (String, String, &'static str) {
    match actor {
        ActorTruth::Verified {
            subject,
            display_email,
        } => (
            subject.as_str().to_string(),
            display_email
                .as_ref()
                .map(|value| value.as_str().to_string())
                .unwrap_or_else(|| "Display email not recorded".to_string()),
            "verified",
        ),
        ActorTruth::LegacyUnclassified { legacy_display } => {
            let visible = legacy_display.visible();
            (
                "Stable subject not recorded".to_string(),
                if legacy_display.has_recorded_value() {
                    format!("Legacy value (unclassified): {visible}")
                } else {
                    visible
                },
                "legacy-unclassified",
            )
        }
    }
}

fn display_identity(identity: &Identity) -> String {
    identity
        .display_email
        .as_ref()
        .map(|email| email.as_str().to_string())
        .unwrap_or_else(|| identity.subject.as_str().to_string())
}

fn html_response(status: StatusCode, body: String, set_cookie: Option<String>) -> Response {
    let mut response = (status, Html(body)).into_response();
    if let Some(cookie) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    response
}

fn redirect(path: ProductRelativePath) -> Result<Response, AppError> {
    let location = path
        .as_string()
        .map_err(|_| AppError::html(ErrorCondition::Internal))?;
    let location =
        HeaderValue::from_str(&location).map_err(|_| AppError::html(ErrorCondition::Internal))?;
    let mut response = (StatusCode::SEE_OTHER, Body::empty()).into_response();
    response.headers_mut().insert(header::LOCATION, location);
    Ok(response)
}

fn is_incident_path(path: &str) -> bool {
    path.strip_prefix("/incident/")
        .is_some_and(|suffix| !suffix.is_empty() && !suffix.contains('/'))
}

fn is_native_form_path(path: &str) -> bool {
    if path == "/api/incidents" {
        return true;
    }
    let Some(rest) = path.strip_prefix("/api/incidents/") else {
        return false;
    };
    let Some((id, suffix)) = rest.split_once('/') else {
        return false;
    };
    !id.is_empty() && matches!(suffix, "notes" | "resolve")
}

fn audit_outcome_token(outcome: crate::view_contract::AuditEnqueueOutcome) -> &'static str {
    match outcome {
        crate::view_contract::AuditEnqueueOutcome::Disabled => "disabled",
        crate::view_contract::AuditEnqueueOutcome::Enqueued => "enqueued",
        crate::view_contract::AuditEnqueueOutcome::DroppedFull => "dropped-full",
        crate::view_contract::AuditEnqueueOutcome::DroppedClosed => "dropped-closed",
    }
}

impl From<ComposeError> for AppError {
    fn from(_: ComposeError) -> Self {
        AppError::html(ErrorCondition::Internal)
    }
}
