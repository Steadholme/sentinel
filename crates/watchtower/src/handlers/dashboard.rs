//! The server-rendered SSO dashboard (mini-SIEM) — v2 (2026-09-08, Figma uf3oBCl3MUWyxGmD5tFn8t).
//!
//! `GET /` (and, because Sluice forwards the gateway prefix unmodified, any other path) renders
//! the audit timeline: a chain-INTEGRITY band (from a live `verify`), the event count with
//! severity pills, the hash chain itself as linked blocks, Merkle checkpoints, alert rules with
//! their recent matches, and the filtered event table. `GET /event/{seq}` renders one record
//! with its chain position and verification. It does NO login of its own — it reads the
//! Sluice-injected `X-Auth-Email` to show "signed in as", and Logout points at the gateway.
//!
//! Odyssey CSS plus Watchtower service CSS are embedded in the binary and served from a
//! content-versioned asset path. All producer-supplied fields are HTML-escaped on render
//! (defense-in-depth against stored XSS).

use std::sync::OnceLock;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use crate::alerts::{AlertMatch, AlertRule};
use crate::auth::csrf_token;
use crate::chain::{verify_chain, AuditEvent, VerifyReport, GENESIS_HASH_HEX};
use crate::error::AppError;
use crate::handlers::events::EventsQuery;
use crate::merkle::{merkle_root_upto, Checkpoint};
use crate::store::EventFilter;
use crate::AppState;

/// Watchtower-only CSS layered after Odyssey's canonical font, tokens, and components.
const SERVICE_CSS: &str = include_str!("../../static/service.css");
pub const APP_CSS_PATH: &str = "/assets/watchtower-20260909.css";
static APP_CSS: OnceLock<String> = OnceLock::new();

/// Embedded design system served from [`APP_CSS_PATH`].
fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

/// Long-lived, content-versioned Watchtower stylesheet.
pub async fn app_css_asset() -> Response {
    let mut response = app_css().into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Page shells with `{{PLACEHOLDER}}` slots filled in below.
const TEMPLATE: &str = include_str!("../../templates/dashboard.html");
const EVENT_TEMPLATE: &str = include_str!("../../templates/event.html");
const ERROR_TEMPLATE: &str = include_str!("../../templates/error.html");

// ---- icons (24px stroke set, matching the Figma Icon/UI sheet) -------------------------------

const fn svg(body: &'static str) -> &'static str {
    body
}
const ICON_TOWER: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M7 22V9h10v13\"/><path d=\"M5 9h14M8 9V5h8v4M12 5V3\"/><path d=\"M10 22v-5h4v5\"/></svg>");
const ICON_TIMELINE: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M3 12h18\"/><circle cx=\"7\" cy=\"12\" r=\"2\"/><circle cx=\"17\" cy=\"12\" r=\"2\"/><path d=\"M7 6v4M17 14v4\"/></svg>");
const ICON_GRID: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><rect x=\"3\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/></svg>");
const ICON_SHIELD_CHECK: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M12 2 4 5v6c0 5 3.5 8.6 8 11 4.5-2.4 8-6 8-11V5l-8-3Z\"/><path d=\"m9 12 2 2 4-4\"/></svg>");
const ICON_SHIELD_ALERT: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M12 2 4 5v6c0 5 3.5 8.6 8 11 4.5-2.4 8-6 8-11V5l-8-3Z\"/><path d=\"M12 8v4M12 16h.01\"/></svg>");
const ICON_SHIELD: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M12 2 4 5v6c0 5 3.5 8.6 8 11 4.5-2.4 8-6 8-11V5l-8-3Z\"/></svg>");
const ICON_REFRESH: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M21 12a9 9 0 1 1-2.6-6.4\"/><path d=\"M21 3v6h-6\"/></svg>");
const ICON_STAMP: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M5 22h14\"/><path d=\"M19.3 18H4.7a1.7 1.7 0 0 1-1.7-1.7v-1.6a1.7 1.7 0 0 1 1.7-1.7H8a3 3 0 0 0 3-3V8a1 1 0 0 1 2 0v2a3 3 0 0 0 3 3h3.3a1.7 1.7 0 0 1 1.7 1.7v1.6a1.7 1.7 0 0 1-1.7 1.7Z\"/></svg>");
const ICON_FILTER: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M3 5h18l-7 8v6l-4 2v-8z\"/></svg>");
const ICON_DOWNLOAD: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3\"/></svg>");
const ICON_FILE_CODE: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z\"/><path d=\"M14 2v6h6M10 13l-2 2 2 2M14 13l2 2-2 2\"/></svg>");
const ICON_LIST: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01\"/></svg>");
const ICON_BELL: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0\"/></svg>");
const ICON_ZAP: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M13 2 3 14h9l-1 8 10-12h-9z\"/></svg>");
const ICON_CHECK: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"m5 12 5 5L20 7\"/></svg>");
const ICON_X: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M18 6 6 18M6 6l12 12\"/></svg>");
const ICON_CLOCK: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7.6V12l3 1.8\"/></svg>");
const ICON_ARROW_LEFT: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M19 12H5M11 6l-6 6 6 6\"/></svg>");
const ICON_ARROW_UP_RIGHT: &str = svg("<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M7 17 17 7M8 7h9v9\"/></svg>");

/// `GET /` — render the dashboard for the current filter, with a live integrity badge.
pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Html<String> {
    let filter_actor = query.actor.clone().unwrap_or_default();
    let filter_action = query.action.clone().unwrap_or_default();
    let filter_source = query.source.clone().unwrap_or_default();
    let filter_severity = query.severity.clone().unwrap_or_default();
    let filter_q = query.q.clone().unwrap_or_default();
    let filter_since = query.since.map(|s| s.to_string()).unwrap_or_default();
    let filter_until = query.until.map(|s| s.to_string()).unwrap_or_default();
    let filter_limit = query.limit.map(|s| s.to_string()).unwrap_or_default();
    let filter = query.into_filter();

    // Whole chain -> integrity band, counts, chain strip. Filtered slice -> the visible table.
    let all = state.store.all_events().await.unwrap_or_default();
    let report = verify_chain(&all);
    let rows = state.store.query(&filter).await.unwrap_or_default();
    let total_matches = state.store.count(&filter).await.unwrap_or(rows.len());
    let checkpoints = state.store.all_checkpoints().await.unwrap_or_default();
    let alert_rules = state.store.all_alert_rules().await.unwrap_or_default();
    let alert_matches = state
        .store
        .recent_alert_matches(20)
        .await
        .unwrap_or_default();

    let email = header_str(&headers, "x-auth-email");
    let chrome = Chrome::from_headers(&headers, &email, "audit");

    let (badge_class, badge_text) = badge(&report);
    let badge_icon = match badge_class {
        "integ-bad" => ICON_SHIELD_ALERT,
        "integ-empty" => ICON_SHIELD,
        _ => ICON_SHIELD_CHECK,
    };
    let banner = tamper_banner(&report);
    let severity_pills = severity_pills(&all);
    let chain = chain_strip(&all, &report, 5);
    let head_hash = hash_chip(&report.head_hash, "hash", None);
    let timeline = timeline_rows(&rows);
    let checkpoint_rows = checkpoint_rows(&checkpoints, &all);
    let alert_rule_rows = alert_rule_rows(&alert_rules);
    let alert_match_rows = alert_match_rows(&alert_matches);
    // The seal form is shown only to a gateway-SSO identity; its CSRF token is keyed by the
    // ingest secret and bound to that identity (matching the POST /api/checkpoint check).
    let head_action = if email.is_empty() {
        String::new()
    } else {
        seal_form(&csrf_token(&state.config.ingest_token, &email))
    };
    let alert_form = if email.is_empty() {
        String::new()
    } else {
        alert_form(&csrf_token(&state.config.ingest_token, &email))
    };
    let pagination = pagination_links(&filter, total_matches, rows.len());
    let export_csv = export_href(&filter, "csv");
    let export_json = export_href(&filter, "json");
    let first = if rows.is_empty() {
        0
    } else {
        filter.offset + 1
    };
    let last = filter.offset + rows.len();
    let showing = format!(
        "Showing {first}-{last} of {total_matches} matching event{} · {} total",
        if total_matches == 1 { "" } else { "s" },
        all.len(),
    );
    let head_sub = format!(
        "{} · {} · {}",
        plural(all.len(), "event", "events"),
        plural(checkpoints.len(), "checkpoint", "checkpoints"),
        plural(alert_rules.len(), "alert rule", "alert rules"),
    );

    let html = chrome
        .fill(TEMPLATE)
        .replace("{{HEAD_SUB}}", &esc(&head_sub))
        .replace("{{HEAD_ACTION}}", &head_action)
        .replace("{{BADGE_CLASS}}", badge_class)
        .replace("{{BADGE_ICON}}", badge_icon)
        .replace("{{BADGE_TEXT}}", &badge_text)
        .replace("{{ICON_REFRESH}}", ICON_REFRESH)
        .replace("{{BANNER}}", &banner)
        .replace("{{TOTAL}}", &fmt_count(all.len()))
        .replace("{{SEVERITY_PILLS}}", &severity_pills)
        .replace("{{CHAIN_COUNT}}", &esc(&chain_count(&report)))
        .replace("{{CHAIN}}", &chain)
        .replace("{{HEAD_HASH}}", &head_hash)
        .replace("{{CHECKPOINT_COUNT}}", &checkpoints.len().to_string())
        .replace("{{CHECKPOINT_ROWS}}", &checkpoint_rows)
        .replace("{{ALERT_COUNT}}", &alert_rules.len().to_string())
        .replace("{{ALERT_FORM}}", &alert_form)
        .replace("{{ALERT_RULE_ROWS}}", &alert_rule_rows)
        .replace("{{MATCH_COUNT}}", &alert_matches.len().to_string())
        .replace("{{ALERT_MATCH_ROWS}}", &alert_match_rows)
        .replace("{{EVENTS_COUNT}}", &fmt_count(total_matches))
        .replace("{{F_ACTOR}}", &esc(&filter_actor))
        .replace("{{F_ACTION}}", &esc(&filter_action))
        .replace("{{F_SOURCE}}", &esc(&filter_source))
        .replace("{{F_SEVERITY}}", &esc(&filter_severity))
        .replace("{{F_Q}}", &esc(&filter_q))
        .replace("{{F_SINCE}}", &esc(&filter_since))
        .replace("{{F_UNTIL}}", &esc(&filter_until))
        .replace("{{F_LIMIT}}", &esc(&filter_limit))
        .replace("{{ICON_FILTER}}", ICON_FILTER)
        .replace("{{SHOWING}}", &esc(&showing))
        .replace("{{ICON_DOWNLOAD}}", ICON_DOWNLOAD)
        .replace("{{ICON_FILE_CODE}}", ICON_FILE_CODE)
        .replace("{{PAGINATION}}", &pagination)
        .replace("{{EXPORT_CSV}}", &esc(&export_csv))
        .replace("{{EXPORT_JSON}}", &esc(&export_json))
        .replace("{{ROWS}}", &timeline);

    Html(html)
}

/// `GET /event/{seq}` — one audit record with its chain position and verification.
pub async fn event_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(seq): Path<i64>,
) -> Response {
    let email = header_str(&headers, "x-auth-email");
    let chrome = Chrome::from_headers(&headers, &email, "audit");
    let all = state.store.all_events().await.unwrap_or_default();
    let Some(event) = all.iter().find(|e| e.seq == seq) else {
        return chrome.error_page(
            StatusCode::NOT_FOUND,
            "Event not found",
            &format!("seq {seq} is not in the audit log"),
        );
    };
    let report = verify_chain(&all);
    let checkpoints = state.store.all_checkpoints().await.unwrap_or_default();
    let matches: Vec<AlertMatch> = state
        .store
        .recent_alert_matches(500)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m.event_seq == seq)
        .collect();

    let prev = all.iter().find(|e| e.seq == seq - 1);
    let recomputed = event.recompute_hash();
    let hash_ok = recomputed == event.hash;
    let link_ok = match prev {
        Some(p) => p.hash == event.prev_hash,
        None => event.seq == 1 && event.prev_hash == GENESIS_HASH_HEX,
    };
    let verified = report
        .first_broken_seq
        .map(|broken| seq < broken)
        .unwrap_or(true)
        && hash_ok
        && link_ok;
    let covering = checkpoints
        .iter()
        .filter(|c| c.seq_hi >= seq)
        .min_by_key(|c| c.seq_hi);

    // Chain position: up to two predecessors, this event, up to two successors.
    let mut window: Vec<&AuditEvent> = all
        .iter()
        .filter(|e| e.seq >= seq - 2 && e.seq <= seq + 2)
        .collect();
    window.sort_by_key(|e| e.seq);
    let head_seq = all.last().map(|e| e.seq).unwrap_or(0);
    let chain = chain_nodes(&window, &report, head_seq, seq == 1, Some(seq));

    let sev_pill = format!(
        "<span class=\"sev {}\">{}</span>",
        severity_class(&event.severity),
        esc(&severity_label(&event.severity))
    );
    let verified_pill = if verified {
        "<span class=\"pill pill-ok\">Verified</span>".to_string()
    } else {
        "<span class=\"pill pill-down\">Broken</span>".to_string()
    };
    let chain_defs = defs(&[
        ("hash", &format!("<code>{}</code>", esc(&event.hash))),
        ("prev_hash", &format!("<code>{}</code>", esc(&event.prev_hash))),
        (
            "Encoding",
            "u64 BE seq · u64 BE ts · 8-byte length-prefixed UTF-8 fields · raw 32-byte prev_hash",
        ),
        (
            "Checkpoint",
            &match covering {
                Some(c) => esc(&format!(
                    "covered by checkpoint {} · sealed {} · root {}…",
                    c.seq_hi,
                    fmt_ts(c.created_at),
                    short_root(&c.merkle_root)
                )),
                None => "not covered yet · the next seal covers it".to_string(),
            },
        ),
    ]);
    let record_defs = defs(&[
        ("ts", &esc(&format!("{} · {}", fmt_ts(event.ts), event.ts))),
        ("seq", &event.seq.to_string()),
        ("actor", &esc(&event.actor)),
        ("action", &esc(&event.action)),
        ("target", &esc(&event.target)),
        ("severity", &esc(&event.severity)),
        ("detail", &esc(&event.detail)),
        ("source", &esc(&event.source)),
    ]);
    let steps = [
        step(
            if hash_ok { "done" } else { "denied" },
            &format!("Recompute hash({seq})"),
            &if hash_ok {
                "matches the stored hash".to_string()
            } else {
                format!("recomputed {}… ≠ stored", short_hash(&recomputed))
            },
        ),
        step(
            if link_ok { "done" } else { "denied" },
            &format!("Compare prev_hash with hash({})", seq - 1),
            &match prev {
                Some(p) if link_ok => format!("{}… = {}…", short_hash(&p.hash), short_hash(&event.prev_hash)),
                Some(p) => format!("stored {}… · expected {}…", short_hash(&event.prev_hash), short_hash(&p.hash)),
                None if link_ok => "genesis · 32 zero bytes".to_string(),
                None => "predecessor missing".to_string(),
            },
        ),
        step(
            if matches.is_empty() { "waiting" } else { "done" },
            "Alert rules",
            &if matches.is_empty() {
                "no rule matched".to_string()
            } else {
                matches
                    .iter()
                    .map(|m| m.rule_name.clone())
                    .collect::<Vec<_>>()
                    .join(" · ")
            },
        ),
        step(
            if covering.is_some() { "done" } else { "waiting" },
            "Merkle inclusion",
            &match covering {
                Some(c) => format!("checkpoint {} covers seq {}", c.seq_hi, seq),
                None => "covered at the next checkpoint".to_string(),
            },
        ),
    ]
    .join("");
    let match_defs = if matches.is_empty() {
        defs(&[("Matches", "none")])
    } else {
        let pairs: Vec<(String, String)> = matches
            .iter()
            .map(|m| {
                (
                    m.rule_name.clone(),
                    esc(&format!(
                        "matched {} · {} · {}",
                        fmt_ts(m.matched_at),
                        m.action,
                        severity_label(&m.severity)
                    )),
                )
            })
            .collect();
        let refs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        defs(&refs)
    };
    let head_sub = format!(
        "{} · {} → {} · {}",
        event.action,
        event.actor,
        event.target,
        fmt_ts(event.ts)
    );

    let html = chrome
        .fill(EVENT_TEMPLATE)
        .replace("{{SEQ}}", &seq.to_string())
        .replace("{{HEAD_SUB}}", &esc(&head_sub))
        .replace("{{ICON_ARROW_LEFT}}", ICON_ARROW_LEFT)
        .replace("{{SEV_PILL}}", &sev_pill)
        .replace("{{HASH_FULL}}", &hash_chip(&event.hash, "hash hash--full", None))
        .replace("{{VERIFIED_PILL}}", &verified_pill)
        .replace("{{CHAIN}}", &chain)
        .replace("{{CHAIN_DEFS}}", &chain_defs)
        .replace("{{RECORD_DEFS}}", &record_defs)
        .replace("{{STEPS}}", &steps)
        .replace("{{MATCH_COUNT}}", &matches.len().to_string())
        .replace("{{MATCH_DEFS}}", &match_defs);
    Html(html).into_response()
}

/// HTML error document for browser form posts (the JSON envelope stays for API clients).
pub fn form_error(headers: &HeaderMap, err: &AppError) -> Response {
    let email = header_str(headers, "x-auth-email");
    let chrome = Chrome::from_headers(headers, &email, "audit");
    let (status, heading) = match err {
        AppError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "Bad request"),
        AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "Unauthorized"),
        AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "Forbidden"),
        AppError::IdempotencyConflict(_) => (StatusCode::CONFLICT, "Conflict"),
        AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Server error"),
    };
    let detail = err.to_string();
    let detail = detail.split_once(": ").map(|(_, d)| d).unwrap_or(&detail);
    chrome.error_page(status, heading, detail)
}

// ---- shared chrome ----------------------------------------------------------------------------

/// Everything the three page shells share: theme, stylesheet path, and the suite bar.
struct Chrome {
    theme_attr: &'static str,
    color_scheme: &'static str,
    suitebar: String,
}

impl Chrome {
    fn from_headers(headers: &HeaderMap, email: &str, surface: &str) -> Self {
        let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
        let theme = odyssey::resolve_theme(cookie);
        Self {
            theme_attr: odyssey::html_theme_attr(theme),
            color_scheme: odyssey::color_scheme_meta(theme),
            suitebar: suite_bar(email, surface),
        }
    }

    fn fill(&self, template: &str) -> String {
        template
            .replace("{{THEME_ATTR}}", self.theme_attr)
            .replace("{{COLOR_SCHEME}}", self.color_scheme)
            .replace("{{CSS_PATH}}", APP_CSS_PATH)
            .replace("{{SUITEBAR}}", &self.suitebar)
    }

    fn error_page(&self, status: StatusCode, heading: &str, detail: &str) -> Response {
        let html = self
            .fill(ERROR_TEMPLATE)
            .replace("{{CODE}}", &status.as_u16().to_string())
            .replace("{{HEADING}}", &esc(heading))
            .replace("{{DETAIL}}", &esc(detail))
            .replace("{{ICON_ARROW_LEFT}}", ICON_ARROW_LEFT);
        (status, Html(html)).into_response()
    }
}

/// The suite bar shared by the audit and rca vhosts: brand tile + name, host, the two surface
/// pills, an "All apps" link back to the apex portal, the signed-in identity (avatar initial +
/// email when a gateway session is present), and the gateway logout.
fn suite_bar(email: &str, surface: &str) -> String {
    let identity = if email.is_empty() {
        "<span class=\"user-email user-email--none\" title=\"Signed in as\">— (no gateway session)</span>"
            .to_string()
    } else {
        let initial = email
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "W".to_string());
        format!(
            "<span class=\"userchip\"><span class=\"userchip__avatar\" aria-hidden=\"true\">{initial}</span>\
             <span class=\"user-email\" title=\"Signed in as\">{email}</span></span>",
            initial = esc(&initial),
            email = esc(email),
        )
    };
    let audit_active = if surface == "audit" { " is-active" } else { "" };
    let rca_active = if surface == "rca" { " is-active" } else { "" };
    format!(
        "<header class=\"suitebar\">\
           <a class=\"suitebar__brand\" href=\"/\" aria-label=\"Watchtower home\">\
             <span class=\"brand-tile\" aria-hidden=\"true\">{ICON_TOWER}</span>\
             <span class=\"suitebar__name\"><b>Steadholme</b><span>Watchtower</span></span>\
           </a>\
           <span class=\"suitebar__host\">audit.w33d.xyz</span>\
           <nav class=\"surfaces\" aria-label=\"Surfaces\">\
             <a class=\"surf surf--audit{audit_active}\" href=\"/\">{ICON_TOWER}Audit</a>\
             <a class=\"surf surf--rca{rca_active}\" href=\"https://rca.w33d.xyz/\">{ICON_TIMELINE}Hindsight</a>\
           </nav>\
           <span class=\"suitebar__spacer\"></span>\
           <div class=\"suitebar__right\">\
             <a class=\"allapps\" href=\"https://w33d.xyz\" title=\"All apps\">{ICON_GRID}<span>All apps</span></a>\
             {identity}\
             <a class=\"btn btn-ghost btn-sm\" href=\"/_gw/auth/logout\">Log out</a>\
           </div>\
         </header>",
    )
}

/// The "Seal checkpoint now" form (POSTs to `/api/checkpoint` with the hidden CSRF token).
fn seal_form(csrf: &str) -> String {
    format!(
        "<form class=\"checkpoint-seal\" method=\"post\" action=\"/api/checkpoint\">\
           <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
           <button class=\"btn btn-primary\" type=\"submit\">{ICON_STAMP}Seal checkpoint now</button>\
         </form>",
        csrf = esc(csrf),
    )
}

/// The "Create alert rule" form (POSTs to `/api/alert-rules` with the hidden CSRF token).
fn alert_form(csrf: &str) -> String {
    format!(
        "<form class=\"alert-form\" method=\"post\" action=\"/api/alert-rules\">\
           <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
           <div class=\"alert-form__grid\">\
             <label>Name<input type=\"text\" name=\"name\" placeholder=\"Login failures\" autocomplete=\"off\"></label>\
             <label>Actor<input type=\"text\" name=\"actor\" placeholder=\"optional\" autocomplete=\"off\"></label>\
             <label>Action<input type=\"text\" name=\"action\" placeholder=\"login.failure\" autocomplete=\"off\"></label>\
             <label>Source<input type=\"text\" name=\"source\" placeholder=\"optional\" autocomplete=\"off\"></label>\
             <label>Severity<input type=\"text\" name=\"severity\" placeholder=\"optional\" autocomplete=\"off\"></label>\
           </div>\
           <button class=\"btn btn-primary\" type=\"submit\">Create rule</button>\
         </form>",
        csrf = esc(csrf),
    )
}

// ---- integrity, counts, chain -----------------------------------------------------------------

/// Build the integrity band `(css_class, text)` from a verify report.
fn badge(report: &VerifyReport) -> (&'static str, String) {
    match report.first_broken_seq {
        Some(seq) => (
            "integ-bad",
            format!("TAMPERED at seq {seq} · {} events", fmt_count(report.count)),
        ),
        None if report.count == 0 => ("integ-empty integ-ok", "Verified · 0 events".to_string()),
        None => (
            "integ-ok",
            format!(
                "Verified · {} events · head {}…",
                fmt_count(report.count),
                short_hash(&report.head_hash)
            ),
        ),
    }
}

/// Red banner naming the break and what it invalidates (empty when the chain verifies).
fn tamper_banner(report: &VerifyReport) -> String {
    match report.first_broken_seq {
        Some(seq) => {
            let after = (report.count as i64 - seq).max(0);
            format!(
                "<div class=\"banner\" role=\"alert\"><span class=\"banner__msg\">Chain breaks at seq {seq} · stored prev_hash ≠ hash({prev}) · {after} later event{s} unverifiable</span>\
                 <a class=\"btn btn-secondary btn-sm\" href=\"/event/{seq}\">Open seq {seq}</a></div>",
                prev = seq - 1,
                s = if after == 1 { "" } else { "s" },
            )
        }
        None => String::new(),
    }
}

fn chain_count(report: &VerifyReport) -> String {
    match report.first_broken_seq {
        Some(seq) => format!("first broken {seq}"),
        None => format!("{} links", fmt_count(report.count)),
    }
}

/// First 12 hex chars of a hash for compact display.
fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
}

/// `8…4` hex abbreviation for chips.
fn abbrev_hash(hash: &str) -> String {
    let n = hash.chars().count();
    if n <= 14 {
        return hash.to_string();
    }
    let head: String = hash.chars().take(8).collect();
    let tail: String = hash.chars().skip(n - 4).collect();
    format!("{head}…{tail}")
}

/// A hash chip; links to the event record when `seq` is given.
fn hash_chip(hash: &str, class: &str, seq: Option<i64>) -> String {
    let text = if class.contains("hash--full") {
        esc(hash)
    } else {
        esc(&abbrev_hash(hash))
    };
    match seq {
        Some(seq) => format!(
            "<a class=\"{class}\" href=\"/event/{seq}\" title=\"{full}\">{text}</a>",
            full = esc(hash)
        ),
        None => format!("<span class=\"{class}\" title=\"{full}\">{text}</span>", full = esc(hash)),
    }
}

/// The hash chain as linked blocks: genesis → the last `tail` events → head, or, on a break,
/// the blocks around the first broken seq followed by the head.
fn chain_strip(all: &[AuditEvent], report: &VerifyReport, tail: usize) -> String {
    if all.is_empty() {
        return chain_nodes(&[], report, 0, true, None);
    }
    let head_seq = all.last().map(|e| e.seq).unwrap_or(0);
    let window: Vec<&AuditEvent> = match report.first_broken_seq {
        Some(broken) => all
            .iter()
            .filter(|e| e.seq >= broken - 2 && e.seq <= broken + 2)
            .collect(),
        None => all.iter().rev().take(tail).collect::<Vec<_>>().into_iter().rev().collect(),
    };
    let show_genesis = report.first_broken_seq.is_none();
    chain_nodes(&window, report, head_seq, show_genesis, None)
}

/// Render chain blocks for `window` (ascending seq). `show_genesis` prepends the genesis block;
/// the head block is appended when the window stops short of it. `current` marks the record
/// being viewed. A link is drawn only between contiguous blocks; gaps are shown as `…`.
fn chain_nodes(
    window: &[&AuditEvent],
    report: &VerifyReport,
    head_seq: i64,
    show_genesis: bool,
    current: Option<i64>,
) -> String {
    const GENESIS: &str = "<span class=\"chain__node chain__node--genesis\"><span class=\"chain__seq\">genesis</span><span class=\"chain__hash\">0000…0000</span></span>";
    const GAP: &str = "<span class=\"chain__gap\">…</span>";
    let broken = report.first_broken_seq;
    let mut out = String::new();
    // Seq of the previously rendered block when it is contiguous with the next one.
    let mut prev_seq: Option<i64> = None;
    if show_genesis {
        out.push_str(GENESIS);
        prev_seq = Some(0);
        if window.first().map(|e| e.seq > 1).unwrap_or(false) {
            out.push_str(GAP);
            prev_seq = None;
        }
    }
    for e in window {
        if prev_seq.is_some() {
            let cls = if broken == Some(e.seq) {
                "chain__link chain__link--broken"
            } else {
                "chain__link"
            };
            out.push_str(&format!("<span class=\"{cls}\" aria-hidden=\"true\"></span>"));
        }
        let mut cls = "chain__node".to_string();
        if broken == Some(e.seq) {
            cls.push_str(" chain__node--broken");
        } else if e.seq == head_seq {
            cls.push_str(" chain__node--head");
        }
        if current == Some(e.seq) {
            cls.push_str(" chain__node--current");
        }
        out.push_str(&format!(
            "<a class=\"{cls}\" href=\"/event/{seq}\"><span class=\"chain__seq\">seq {seq_fmt}</span><span class=\"chain__hash\">{hash}</span></a>",
            seq = e.seq,
            seq_fmt = fmt_count(e.seq.max(0) as usize),
            hash = esc(&abbrev_hash(&e.hash)),
        ));
        prev_seq = Some(e.seq);
    }
    let last_shown = window.last().map(|e| e.seq).unwrap_or(0);
    if head_seq > 0 && last_shown < head_seq {
        out.push_str(GAP);
        out.push_str(&format!(
            "<a class=\"chain__node chain__node--head\" href=\"/event/{seq}\"><span class=\"chain__seq\">seq {seq_fmt}</span><span class=\"chain__hash\">{hash}</span></a>",
            seq = head_seq,
            seq_fmt = fmt_count(head_seq as usize),
            hash = esc(&abbrev_hash(&report.head_hash)),
        ));
    }
    out
}

/// Distinct severities with counts, rendered as colored pills (most frequent first).
fn severity_pills(events: &[AuditEvent]) -> String {
    use std::collections::HashMap;
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in events {
        *counts.entry(e.severity.as_str()).or_insert(0) += 1;
    }
    if counts.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(&str, usize)> = counts.into_iter().collect();
    // Most frequent first; ties broken by label for stable output.
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    pairs
        .into_iter()
        .map(|(sev, n)| {
            format!(
                "<span class=\"sev {cls}\">{label} <b>{n}</b></span>",
                cls = severity_class(sev),
                label = esc(&severity_label(sev)),
                n = fmt_count(n),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

// ---- tables -----------------------------------------------------------------------------------

fn empty_row(colspan: usize, icon: &str, text: &str) -> String {
    format!(
        "<tr><td class=\"empty\" colspan=\"{colspan}\"><div class=\"empty-tile\">{icon}<span>{text}</span></div></td></tr>"
    )
}

/// Render alert rule rows. Empty -> placeholder row.
fn alert_rule_rows(rules: &[AlertRule]) -> String {
    if rules.is_empty() {
        return empty_row(6, ICON_BELL, "No alert rules configured");
    }
    rules
        .iter()
        .map(|rule| {
            format!(
                "<tr>\
                   <td class=\"c-name\">{name}</td>\
                   <td class=\"c-time\"><time>{time}</time></td>\
                   <td>{actor}</td>\
                   <td>{action}</td>\
                   <td>{source}</td>\
                   <td>{severity}</td>\
                 </tr>",
                time = esc(&fmt_ts(rule.created_at)),
                name = esc(&rule.name),
                actor = predicate_cell(&rule.actor, "c-actor"),
                action = predicate_cell(&rule.action, "c-action"),
                source = predicate_cell(&rule.source, "c-source"),
                severity = match rule.severity.as_deref() {
                    Some(s) => format!(
                        "<span class=\"sev {}\">{}</span>",
                        severity_class(s),
                        esc(&severity_label(s))
                    ),
                    None => "<span class=\"c-any\">—</span>".to_string(),
                },
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Render recent alert match marker rows. Empty -> placeholder row.
fn alert_match_rows(matches: &[AlertMatch]) -> String {
    if matches.is_empty() {
        return empty_row(8, ICON_ZAP, "No alert matches recorded");
    }
    matches
        .iter()
        .map(|hit| {
            format!(
                "<tr>\
                   <td class=\"c-time\"><time>{time}</time></td>\
                   <td class=\"c-name\">{rule}</td>\
                   <td class=\"c-seq\"><a href=\"/event/{seq}\">{seq}</a></td>\
                   <td class=\"c-actor\">{actor}</td>\
                   <td class=\"c-action\">{action}</td>\
                   <td><span class=\"sev {sevcls}\">{severity}</span></td>\
                   <td class=\"c-source\">{source}</td>\
                   <td><a class=\"btn btn-ghost btn-sm\" href=\"/event/{seq}\">{ICON_ARROW_UP_RIGHT}Open event</a></td>\
                 </tr>",
                time = esc(&fmt_ts(hit.matched_at)),
                rule = esc(&hit.rule_name),
                seq = hit.event_seq,
                actor = esc(&hit.actor),
                action = esc(&hit.action),
                sevcls = severity_class(&hit.severity),
                severity = esc(&severity_label(&hit.severity)),
                source = esc(&hit.source),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn predicate_cell(v: &Option<String>, class: &str) -> String {
    match v {
        Some(s) => format!("<span class=\"{class}\">{}</span>", esc(s)),
        None => "<span class=\"c-any\">—</span>".to_string(),
    }
}

/// Render the checkpoint `<tr>` rows, each re-verified against the current log: recompute the
/// Merkle root up to its `seq_hi` and show a green VERIFIED / red BROKEN status. Empty -> a
/// friendly placeholder row.
fn checkpoint_rows(checkpoints: &[Checkpoint], events: &[AuditEvent]) -> String {
    if checkpoints.is_empty() {
        return empty_row(4, ICON_STAMP, "No checkpoints sealed yet");
    }
    // Newest-first, mirroring the event timeline.
    let mut ordered: Vec<&Checkpoint> = checkpoints.iter().collect();
    ordered.sort_by(|a, b| b.seq_hi.cmp(&a.seq_hi));
    ordered
        .into_iter()
        .map(|cp| {
            let current = merkle_root_upto(events, cp.seq_hi);
            let valid = current == cp.merkle_root;
            let (cls, label, row) = if valid {
                ("sev-success", "VERIFIED", "")
            } else {
                ("sev-critical", "BROKEN", " class=\"is-broken\"")
            };
            format!(
                "<tr{row}>\
                   <td class=\"c-time\"><time>{time}</time></td>\
                   <td class=\"c-seq\">{seq_hi}</td>\
                   <td class=\"c-root\"><span class=\"root\" title=\"{full}\">{root}…</span></td>\
                   <td><span class=\"sev {cls}\">{label}</span></td>\
                 </tr>",
                time = esc(&fmt_ts(cp.created_at)),
                seq_hi = fmt_count(cp.seq_hi.max(0) as usize),
                root = esc(&short_root(&cp.merkle_root)),
                full = esc(&cp.merkle_root),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// First 16 hex chars of a Merkle root for compact display.
fn short_root(root: &str) -> String {
    root.chars().take(16).collect()
}

/// Render the timeline `<tr>` rows (escaped). Empty -> a single friendly placeholder row.
fn timeline_rows(rows: &[AuditEvent]) -> String {
    if rows.is_empty() {
        return empty_row(9, ICON_LIST, "No events match the current filter");
    }
    rows.iter()
        .map(|e| {
            let sevcls = severity_class(&e.severity);
            let row = if sevcls == "sev-critical" { " class=\"is-critical\"" } else { "" };
            format!(
                "<tr{row}>\
                   <td class=\"c-time\"><time>{time}</time></td>\
                   <td class=\"c-seq\"><a href=\"/event/{seq}\">{seq}</a></td>\
                   <td class=\"c-sev\"><span class=\"sev {sevcls}\">{sev}</span></td>\
                   <td class=\"c-actor\">{actor}</td>\
                   <td class=\"c-action\">{action}</td>\
                   <td class=\"c-target\">{target}</td>\
                   <td class=\"c-detail\">{detail}</td>\
                   <td class=\"c-source\">{source}</td>\
                   <td class=\"c-hash\">{hash}</td>\
                 </tr>",
                time = esc(&fmt_ts(e.ts)),
                seq = e.seq,
                sev = esc(&severity_label(&e.severity)),
                actor = esc(&e.actor),
                action = esc(&e.action),
                target = esc(&e.target),
                detail = esc(&e.detail),
                source = esc(&e.source),
                hash = hash_chip(&e.hash, "hash hash--sm", Some(e.seq)),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Prev/next links for the filtered timeline, with the visible range.
fn pagination_links(filter: &EventFilter, total: usize, shown: usize) -> String {
    let mut links = Vec::new();
    if filter.offset > 0 {
        let prev = filter.offset.saturating_sub(filter.limit);
        links.push(format!(
            "<a class=\"btn btn-secondary btn-sm\" href=\"{href}\">Previous</a>",
            href = esc(&events_href(filter, prev)),
        ));
    }
    if total > 0 {
        let first = if shown == 0 { 0 } else { filter.offset + 1 };
        links.push(format!(
            "<span class=\"pagination__range\">{first}–{last} of {total}</span>",
            last = filter.offset + shown,
            total = fmt_count(total),
        ));
    }
    let next = filter.offset + filter.limit;
    if next < total {
        links.push(format!(
            "<a class=\"btn btn-secondary btn-sm\" href=\"{href}\">Next</a>",
            href = esc(&events_href(filter, next)),
        ));
    }
    if links.is_empty() {
        String::new()
    } else {
        format!("<span class=\"pagination\">{}</span>", links.join(""))
    }
}

fn export_href(filter: &EventFilter, format: &str) -> String {
    query_href("/api/events/export", filter, filter.offset, Some(format))
}

fn events_href(filter: &EventFilter, offset: usize) -> String {
    query_href("", filter, offset, None)
}

fn query_href(base: &str, filter: &EventFilter, offset: usize, format: Option<&str>) -> String {
    let mut params: Vec<(String, String)> = Vec::new();
    push_param(&mut params, "actor", filter.actor.as_deref());
    push_param(&mut params, "action", filter.action.as_deref());
    push_param(&mut params, "source", filter.source.as_deref());
    push_param(&mut params, "severity", filter.severity.as_deref());
    push_i64(&mut params, "since", filter.since);
    push_i64(&mut params, "until", filter.until);
    push_param(&mut params, "q", filter.q.as_deref());
    params.push(("limit".to_string(), filter.limit.to_string()));
    if offset > 0 {
        params.push(("offset".to_string(), offset.to_string()));
    }
    if let Some(format) = format {
        params.push(("format".to_string(), format.to_string()));
    }
    if params.is_empty() {
        return base.to_string();
    }
    let query = params
        .into_iter()
        .map(|(k, v)| format!("{}={}", pct_encode(&k), pct_encode(&v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{query}")
}

fn push_param(params: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        params.push((key.to_string(), value.to_string()));
    }
}

fn push_i64(params: &mut Vec<(String, String)>, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        params.push((key.to_string(), value.to_string()));
    }
}

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---- record page bits -------------------------------------------------------------------------

/// Definition rows (term / value); values are already HTML.
fn defs(items: &[(&str, &str)]) -> String {
    items
        .iter()
        .map(|(t, v)| {
            format!(
                "<div class=\"defs__row\"><span class=\"defs__term\">{}</span><span class=\"defs__value\">{}</span></div>",
                esc(t),
                v
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// One verification step: done (check) · denied (cross) · waiting (clock).
fn step(state: &str, label: &str, who: &str) -> String {
    let icon = match state {
        "done" => ICON_CHECK,
        "denied" => ICON_X,
        _ => ICON_CLOCK,
    };
    format!(
        "<div class=\"step step--{state}\"><span class=\"step__mark\" aria-hidden=\"true\">{icon}</span><div><div class=\"step__label\">{}</div><div class=\"step__who\">{}</div></div></div>",
        esc(label),
        esc(who)
    )
}

// ---- formatting -------------------------------------------------------------------------------

/// First value of a header as a `String` (empty when absent / non-UTF-8).
fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Map a severity string to a pill color class. Open-ended input is normalized; unknowns
/// fall back to a neutral pill.
fn severity_class(severity: &str) -> &'static str {
    match severity.trim().to_lowercase().as_str() {
        "critical" | "crit" | "fatal" | "alert" | "emergency" => "sev-critical",
        "error" | "err" | "high" => "sev-error",
        "warning" | "warn" | "medium" => "sev-warning",
        "notice" | "info" | "informational" | "low" => "sev-info",
        "debug" | "trace" => "sev-debug",
        "success" | "ok" | "pass" => "sev-success",
        _ => "sev-neutral",
    }
}

/// Display label for a severity (the original text, or an em dash when blank).
fn severity_label(severity: &str) -> String {
    if severity.trim().is_empty() {
        "—".to_string()
    } else {
        severity.to_string()
    }
}

/// Thousands-grouped count (`12,408`).
fn fmt_count(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", fmt_count(n), if n == 1 { one } else { many })
}

/// Format epoch milliseconds as a compact UTC timestamp `YYYY-MM-DD HH:MM:SSZ`.
fn fmt_ts(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => ms.to_string(),
    }
}

/// Minimal HTML-escape for text rendered into the page (defense-in-depth).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn severity_classes_normalize() {
        assert_eq!(severity_class("CRITICAL"), "sev-critical");
        assert_eq!(severity_class(" warn "), "sev-warning");
        assert_eq!(severity_class("whatever"), "sev-neutral");
        assert_eq!(severity_class(""), "sev-neutral");
    }

    #[test]
    fn formats_epoch_ms_as_utc() {
        // 2023-11-14T22:13:20Z = 1_700_000_000 s.
        assert_eq!(fmt_ts(1_700_000_000_000), "2023-11-14 22:13:20Z");
    }

    #[test]
    fn groups_thousands_and_abbreviates_hashes() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(12408), "12,408");
        assert_eq!(fmt_count(1_234_567), "1,234,567");
        assert_eq!(abbrev_hash("3f2a9c1e5d7b20a4c6e8f01b3d5a7c9e"), "3f2a9c1e…7c9e");
        assert_eq!(abbrev_hash("short"), "short");
    }
}
