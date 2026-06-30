//! The SSO dashboard, the incident view, and the incident/note/timeline API.
//!
//! `GET /` renders the unified, time-ordered timeline (merged Watchtower audit + Sift error/warn
//! logs + Vitals anomalies) over a selectable window, alongside the incidents list and an
//! "open incident" form. `GET /incident/{id}` renders one incident with the SAME merge clipped to
//! its evidence window, plus its note thread. The POST routes (open an incident / add a note) are
//! double-submit CSRF protected and take their actor from the gateway-injected `X-Auth-*`
//! (never a client field). `GET /api/timeline` returns the merged timeline as JSON.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::{DEFAULT_WINDOW_HOURS, TIMELINE_LIMIT};
use crate::error::AppError;
use crate::feeds::{self, Timeline, TimelineEvent};
use crate::handlers::{
    esc, fmt_date, fmt_datetime, severity_class, source_label, topbar, APP_CSS,
};
use crate::store::{Incident, Note};
use crate::{now_nanos, now_secs, AppState};

const DASHBOARD_HTML: &str = include_str!("../../templates/dashboard.html");
const INCIDENT_HTML: &str = include_str!("../../templates/incident.html");

/// The window selector choices, in hours. `DEFAULT_WINDOW_HOURS` is the default.
const WINDOW_CHOICES: &[i64] = &[1, 6, 24, 72, 168];
/// Hard cap on a requested window (30 days) so a hostile `?window=` can't widen the scan forever.
const MAX_WINDOW_HOURS: i64 = 720;

// ---------------------------------------------------------------------------
// Query / form bodies
// ---------------------------------------------------------------------------

/// Dashboard query: `?window=<hours>` selects the timeline window (default 24h).
#[derive(Debug, Deserialize)]
pub struct DashQuery {
    #[serde(default)]
    pub window: Option<i64>,
}

/// `GET /api/timeline?from=&to=` query (epoch seconds; `to=0`/omitted means "now").
#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    #[serde(default)]
    pub from: Option<i64>,
    #[serde(default)]
    pub to: Option<i64>,
}

/// Open-incident form. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct OpenForm {
    #[serde(default)]
    pub title: String,
    /// Window length in hours; `from_ts = now - window_hours*3600`, `to_ts = 0` (ongoing).
    #[serde(default)]
    pub window_hours: Option<i64>,
    #[serde(default)]
    pub csrf_token: String,
}

/// Add-note form.
#[derive(Debug, Deserialize)]
pub struct NoteForm {
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub csrf_token: String,
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

/// `GET /` — the command-center timeline over a selectable window + the incidents list.
pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DashQuery>,
) -> Response {
    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let window_hours = clamp_window(q.window.unwrap_or(DEFAULT_WINDOW_HOURS));
    let now = now_secs();
    let from = now - window_hours * 3600;

    let tl = feeds::gather(
        &state.config,
        state.logs.as_ref(),
        from,
        0, // up to now
        now,
        TIMELINE_LIMIT,
    )
    .await;

    let incidents = state.store.list_incidents().await;

    let page = DASHBOARD_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Incident Timeline", &email))
        .replace("{{WINDOW_LABEL}}", &esc(&window_label(window_hours)))
        .replace("{{WINDOW_TABS}}", &render_window_tabs(window_hours))
        .replace("{{STATUS_CHIPS}}", &render_status_chips(&tl))
        .replace("{{OPEN_FORM}}", &render_open_form(&csrf, window_hours))
        .replace("{{INCIDENTS}}", &render_incident_list(&incidents))
        .replace("{{TIMELINE}}", &render_timeline(&tl));

    html_with_cookie(page, set_cookie)
}

// ---------------------------------------------------------------------------
// Incident view
// ---------------------------------------------------------------------------

/// `GET /incident/{id}` — one incident, its merged evidence window, and its note thread.
pub async fn incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let email = auth::display_email(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    let inc = state
        .store
        .get_incident(&id)
        .await
        .ok_or_else(|| AppError::NotFound("no such incident".to_string()))?;

    let now = now_secs();
    let tl = feeds::gather(
        &state.config,
        state.logs.as_ref(),
        inc.from_ts,
        inc.to_ts,
        now,
        TIMELINE_LIMIT,
    )
    .await;

    let notes = state.store.list_notes(&inc.id).await;

    let window_meta = format!(
        "Evidence window {} → {}",
        fmt_datetime(inc.from_ts),
        if inc.to_ts <= 0 {
            "now (open)".to_string()
        } else {
            fmt_datetime(inc.to_ts)
        },
    );
    let meta = format!(
        "Opened {} · {} · {}",
        fmt_datetime(inc.created_at),
        if inc.created_by.is_empty() {
            "—".to_string()
        } else {
            inc.created_by.clone()
        },
        window_meta,
    );

    let page = INCIDENT_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Incident", &email))
        .replace("{{INCIDENT_ID}}", &esc(&inc.id))
        .replace("{{TITLE}}", &esc(&inc.title))
        .replace("{{STATUS_BADGE}}", &render_status_badge(&inc.status))
        .replace("{{META}}", &esc(&meta))
        .replace("{{STATUS_CHIPS}}", &render_status_chips(&tl))
        .replace("{{TIMELINE}}", &render_timeline(&tl))
        .replace("{{NOTES}}", &render_notes(&notes))
        .replace("{{NOTE_FORM}}", &render_note_form(&inc.id, &csrf));

    Ok(html_with_cookie(page, set_cookie))
}

// ---------------------------------------------------------------------------
// Open an incident
// ---------------------------------------------------------------------------

/// `POST /api/incidents` — open an incident over a time window (CSRF + SSO).
pub async fn open_incident(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<OpenForm>,
) -> Result<Response, AppError> {
    let (sub, email) = auth::require_operator(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::InvalidRequest("title is required".to_string()));
    }
    let window_hours = clamp_window(form.window_hours.unwrap_or(DEFAULT_WINDOW_HOURS));
    let now = now_secs();
    let id = format!("inc_{}", now_nanos());
    let created_by = if email.is_empty() { sub.clone() } else { email.clone() };

    let incident = Incident {
        id: id.clone(),
        title: title.to_string(),
        status: "open".to_string(),
        from_ts: now - window_hours * 3600,
        to_ts: 0, // ongoing
        created_by,
        created_at: now,
    };
    state.store.create_incident(&incident).await?;
    tracing::info!(id = %id, "incident opened");

    // Notable event: emit to Watchtower (non-blocking; a down Watchtower never blocks this).
    state.audit.emit(AuditEvent::notice(
        "hindsight.incident.open",
        &email,
        &id,
        &format!("window {window_hours}h"),
    ));

    Ok(redirect(&format!("/incident/{id}")))
}

// ---------------------------------------------------------------------------
// Add a note
// ---------------------------------------------------------------------------

/// `POST /api/incidents/{id}/notes` — thread a note onto an incident (CSRF + SSO).
pub async fn add_note(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<NoteForm>,
) -> Result<Response, AppError> {
    let (sub, _email) = auth::require_operator(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    // The incident must exist before a note can attach to it.
    let inc = state
        .store
        .get_incident(&id)
        .await
        .ok_or_else(|| AppError::NotFound("no such incident".to_string()))?;

    let body = form.body.trim();
    if body.is_empty() {
        return Err(AppError::InvalidRequest("note body is required".to_string()));
    }
    let now = now_secs();
    let note = Note {
        id: format!("note_{}", now_nanos()),
        incident_id: inc.id.clone(),
        body: body.to_string(),
        author_sub: sub,
        created_at: now,
    };
    state.store.add_note(&note).await?;
    tracing::info!(incident = %inc.id, "note added");

    Ok(redirect(&format!("/incident/{}", inc.id)))
}

// ---------------------------------------------------------------------------
// JSON timeline API
// ---------------------------------------------------------------------------

/// `GET /api/timeline?from=&to=` — the merged timeline as JSON (SSO-gated, read-only).
pub async fn timeline_json(
    State(state): State<AppState>,
    Query(q): Query<TimelineQuery>,
) -> Json<Timeline> {
    let now = now_secs();
    // Default window: the last DEFAULT_WINDOW_HOURS hours when no `from` is given.
    let from = q.from.unwrap_or_else(|| now - DEFAULT_WINDOW_HOURS * 3600);
    let to = q.to.unwrap_or(0);
    let tl = feeds::gather(
        &state.config,
        state.logs.as_ref(),
        from,
        to,
        now,
        TIMELINE_LIMIT,
    )
    .await;
    Json(tl)
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// Clamp a requested window (hours) into `[1, MAX_WINDOW_HOURS]`.
fn clamp_window(hours: i64) -> i64 {
    hours.clamp(1, MAX_WINDOW_HOURS)
}

/// Human label for a window length.
fn window_label(hours: i64) -> String {
    match hours {
        1 => "last hour".to_string(),
        h if h % 24 == 0 => format!("last {} days", h / 24),
        h => format!("last {h} hours"),
    }
}

/// Render the window-selector tabs; the active one is highlighted.
fn render_window_tabs(active: i64) -> String {
    let mut out = String::new();
    for &h in WINDOW_CHOICES {
        let cls = if h == active {
            "wtab wtab--active"
        } else {
            "wtab"
        };
        let label = match h {
            1 => "1h".to_string(),
            h if h % 24 == 0 => format!("{}d", h / 24),
            h => format!("{h}h"),
        };
        out.push_str(&format!(
            r#"<a class="{cls}" href="/?window={h}">{label}</a>"#,
            cls = cls,
            h = h,
            label = esc(&label),
        ));
    }
    out
}

/// Render the per-source availability chips (reached vs. unavailable).
fn render_status_chips(tl: &Timeline) -> String {
    let chip = |label: &str, ok: bool| {
        let (cls, state) = if ok {
            ("chip chip--ok", "live")
        } else {
            ("chip chip--down", "unavailable")
        };
        format!(
            r#"<span class="{cls}"><span class="chip__dot" aria-hidden="true"></span>{label} · {state}</span>"#,
            cls = cls,
            label = esc(label),
            state = state,
        )
    };
    format!(
        r#"<div class="chips">{wt}{sift}{vitals}</div>"#,
        wt = chip("Watchtower", tl.status.watchtower),
        sift = chip("Sift", tl.status.sift),
        vitals = chip("Vitals", tl.status.vitals),
    )
}

/// Render the open-incident form.
fn render_open_form(csrf: &str, window_hours: i64) -> String {
    let mut opts = String::new();
    for &h in WINDOW_CHOICES {
        let sel = if h == window_hours { " selected" } else { "" };
        let label = match h {
            1 => "Last hour".to_string(),
            h if h % 24 == 0 => format!("Last {} days", h / 24),
            h => format!("Last {h} hours"),
        };
        opts.push_str(&format!(
            r#"<option value="{h}"{sel}>{label}</option>"#,
            h = h,
            sel = sel,
            label = esc(&label),
        ));
    }
    format!(
        r#"<form class="open-form" method="post" action="/api/incidents">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <div class="field">
    <label for="inc-title">Title</label>
    <input id="inc-title" type="text" name="title" placeholder="e.g. API latency spike" maxlength="200" required>
  </div>
  <div class="field">
    <label for="inc-window">Evidence window</label>
    <select id="inc-window" name="window_hours">{opts}</select>
  </div>
  <button class="btn btn-primary" type="submit">Open incident</button>
</form>"#,
        csrf = esc(csrf),
        opts = opts,
    )
}

/// Render the incidents list (newest-first), or a calm empty state.
fn render_incident_list(incidents: &[Incident]) -> String {
    if incidents.is_empty() {
        return r#"<div class="empty-state empty-state--sm"><p>No incidents yet. Open one over a window to start correlating.</p></div>"#.to_string();
    }
    let mut out = String::new();
    for i in incidents {
        out.push_str(&format!(
            r#"<a class="inc-row" href="/incident/{id}">
  <div class="inc-row__main">
    <span class="inc-row__title">{title}</span>
    <span class="inc-row__meta">{date} · {by}</span>
  </div>
  {badge}
</a>"#,
            id = esc(&i.id),
            title = esc(&i.title),
            date = esc(&fmt_date(i.created_at)),
            by = esc(if i.created_by.is_empty() { "—" } else { &i.created_by }),
            badge = render_status_badge(&i.status),
        ));
    }
    out
}

/// Render a status badge for an incident (`open`/`resolved`/other).
fn render_status_badge(status: &str) -> String {
    let s = status.trim().to_ascii_lowercase();
    let cls = match s.as_str() {
        "resolved" | "closed" => "badge badge--resolved",
        "open" | "" => "badge badge--open",
        _ => "badge badge--open",
    };
    let label = if s.is_empty() { "open".to_string() } else { s };
    format!(
        r#"<span class="{cls}">{label}</span>"#,
        cls = cls,
        label = esc(&label),
    )
}

/// Render the merged timeline as a vertical, time-ordered rail.
fn render_timeline(tl: &Timeline) -> String {
    if tl.events.is_empty() {
        return r#"<div class="empty-state"><h2>No events in this window</h2><p>Nothing notable correlated from Watchtower, Sift, or Vitals over the selected window.</p></div>"#.to_string();
    }
    let mut out = String::new();
    for e in &tl.events {
        out.push_str(&render_event(e));
    }
    out
}

/// One timeline entry: severity dot, source tag, time, title, and detail.
fn render_event(e: &TimelineEvent) -> String {
    let detail = if e.detail.trim().is_empty() {
        String::new()
    } else {
        format!(r#"<span class="tl__detail">{}</span>"#, esc(&e.detail))
    };
    format!(
        r#"<div class="tl__item">
  <span class="tl__dot {sev}" aria-hidden="true"></span>
  <div class="tl__body">
    <div class="tl__line">
      <span class="tl__src tl__src--{src}">{src_label}</span>
      <span class="tl__title">{title}</span>
    </div>
    <div class="tl__meta">{when}{sep}{detail}</div>
  </div>
</div>"#,
        sev = severity_class(&e.severity),
        src = e.source,
        src_label = esc(source_label(e.source)),
        title = esc(&e.title),
        when = esc(&fmt_datetime(e.ts)),
        sep = if e.detail.trim().is_empty() { "" } else { " · " },
        detail = detail,
    )
}

/// Render the incident's note thread, oldest-first.
fn render_notes(notes: &[Note]) -> String {
    if notes.is_empty() {
        return r#"<div class="empty-state empty-state--sm"><p>No notes yet. Add the first observation below.</p></div>"#.to_string();
    }
    let mut out = String::new();
    for n in notes {
        out.push_str(&format!(
            r#"<div class="note">
  <div class="note__meta">{author} · {when}</div>
  <div class="note__body">{body}</div>
</div>"#,
            author = esc(if n.author_sub.is_empty() { "—" } else { &n.author_sub }),
            when = esc(&fmt_datetime(n.created_at)),
            body = esc(&n.body),
        ));
    }
    out
}

/// Render the add-note form for an incident.
fn render_note_form(incident_id: &str, csrf: &str) -> String {
    format!(
        r#"<form class="note-form" method="post" action="/api/incidents/{id}/notes">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <div class="field">
    <label for="note-body">Add a note</label>
    <textarea id="note-body" name="body" rows="3" placeholder="What did you observe or do?" required></textarea>
  </div>
  <button class="btn btn-primary" type="submit">Add note</button>
</form>"#,
        id = esc(incident_id),
        csrf = esc(csrf),
    )
}

/// A 303 redirect (post/redirect/get).
fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(location).expect("valid location"),
        )],
    )
        .into_response()
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}
