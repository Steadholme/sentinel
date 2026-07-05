//! The server-rendered SSO dashboard (mini-SIEM).
//!
//! `GET /` (and, because Sluice forwards the gateway prefix unmodified, any other path) renders
//! the enterprise UI: a chain-INTEGRITY badge (from a live `verify`), severity-coded counts,
//! a filter bar, and the audit TIMELINE. It does NO login of its own — it reads the
//! Sluice-injected `X-Auth-Email` to show "signed in as", and Logout points at the gateway.
//!
//! The page is fully self-contained: Odyssey CSS plus Watchtower service CSS are embedded, so
//! there are no asset round-trips (and nothing to break under gateway path-prefixing). All
//! producer-supplied fields are HTML-escaped on render (defense-in-depth against stored XSS).

use std::sync::OnceLock;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Html;

use crate::alerts::{AlertMatch, AlertRule};
use crate::auth::csrf_token;
use crate::chain::{verify_chain, AuditEvent};
use crate::handlers::events::EventsQuery;
use crate::merkle::{merkle_root_upto, Checkpoint};
use crate::store::EventFilter;
use crate::AppState;

/// Watchtower-only CSS layered after Odyssey's canonical font, tokens, and components.
const SERVICE_CSS: &str = include_str!("../../static/service.css");
static APP_CSS: OnceLock<String> = OnceLock::new();

/// Embedded design system, inlined into the rendered page's `<style>`.
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

/// Page shell with `{{PLACEHOLDER}}` slots filled in below.
const TEMPLATE: &str = include_str!("../../templates/dashboard.html");

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

    // Whole chain -> integrity badge + counts. Filtered slice -> the visible timeline.
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
    let userbox = topbar_userbox(&email);

    let (badge_class, badge_text) = badge(&report);
    let severity_pills = severity_pills(&all);
    let timeline = timeline_rows(&rows);
    let checkpoint_rows = checkpoint_rows(&checkpoints, &all);
    let alert_rule_rows = alert_rule_rows(&alert_rules);
    let alert_match_rows = alert_match_rows(&alert_matches);
    // The seal form is shown only to a gateway-SSO identity; its CSRF token is keyed by the
    // ingest secret and bound to that identity (matching the POST /api/checkpoint check).
    let checkpoint_form = if email.is_empty() {
        String::new()
    } else {
        seal_form(&csrf_token(&state.config.ingest_token, &email))
    };
    let alert_form = if email.is_empty() {
        String::new()
    } else {
        alert_form(&csrf_token(&state.config.ingest_token, &email))
    };
    let pagination = pagination_links(&filter, total_matches);
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

    let html = TEMPLATE
        .replace("{{STYLE}}", app_css())
        .replace("{{USERBOX}}", &userbox)
        .replace("{{BADGE_CLASS}}", badge_class)
        .replace("{{BADGE_TEXT}}", &badge_text)
        .replace("{{TOTAL}}", &all.len().to_string())
        .replace("{{SEVERITY_PILLS}}", &severity_pills)
        .replace("{{F_ACTOR}}", &esc(&filter_actor))
        .replace("{{F_ACTION}}", &esc(&filter_action))
        .replace("{{F_SOURCE}}", &esc(&filter_source))
        .replace("{{F_SEVERITY}}", &esc(&filter_severity))
        .replace("{{F_Q}}", &esc(&filter_q))
        .replace("{{F_SINCE}}", &esc(&filter_since))
        .replace("{{F_UNTIL}}", &esc(&filter_until))
        .replace("{{F_LIMIT}}", &esc(&filter_limit))
        .replace("{{SHOWING}}", &esc(&showing))
        .replace("{{PAGINATION}}", &pagination)
        .replace("{{EXPORT_CSV}}", &esc(&export_csv))
        .replace("{{EXPORT_JSON}}", &esc(&export_json))
        .replace("{{CHECKPOINT_FORM}}", &checkpoint_form)
        .replace("{{CHECKPOINT_ROWS}}", &checkpoint_rows)
        .replace("{{ALERT_FORM}}", &alert_form)
        .replace("{{ALERT_RULE_ROWS}}", &alert_rule_rows)
        .replace("{{ALERT_MATCH_ROWS}}", &alert_match_rows)
        .replace("{{ROWS}}", &timeline);

    Html(html)
}

/// The right side of the app-bar: an "All apps" link back to the apex portal, the signed-in
/// identity (avatar initial + email when a gateway session is present), and the gateway logout.
/// Shared chrome so the console matches the rest of the estate. No session -> a muted note and
/// no user chip (the logout link is kept, matching prior behavior).
fn topbar_userbox(email: &str) -> String {
    const ALLAPPS: &str = "<a class=\"allapps\" href=\"https://w33d.xyz\" title=\"All apps\">\
        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">\
        <rect x=\"3\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" width=\"7\" height=\"7\" rx=\"1.5\"/>\
        <rect x=\"3\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/><rect x=\"14\" y=\"14\" width=\"7\" height=\"7\" rx=\"1.5\"/></svg>All apps</a>";
    let chip = if email.is_empty() {
        "<span class=\"user-email\" title=\"Signed in as\">— (no gateway session)</span>"
            .to_string()
    } else {
        let initial = email
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "H".to_string());
        format!(
            "<span class=\"userchip\"><span class=\"userchip__avatar\" aria-hidden=\"true\">{initial}</span>\
             <span class=\"user-email\" title=\"Signed in as\">{email}</span></span>",
            initial = esc(&initial),
            email = esc(email),
        )
    };
    format!(
        "{ALLAPPS}{chip}<a class=\"btn btn-ghost btn-sm\" href=\"/_gw/auth/logout\">Log out</a>",
        ALLAPPS = ALLAPPS,
        chip = chip,
    )
}

/// The "Seal checkpoint now" form (POSTs to `/api/checkpoint` with the hidden CSRF token).
fn seal_form(csrf: &str) -> String {
    format!(
        "<form class=\"checkpoint-seal\" method=\"post\" action=\"/api/checkpoint\">\
           <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
           <button class=\"btn btn-primary btn-sm\" type=\"submit\">Seal checkpoint now</button>\
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
           <button class=\"btn btn-primary btn-sm\" type=\"submit\">Create rule</button>\
         </form>",
        csrf = esc(csrf),
    )
}

/// Render alert rule rows. Empty -> placeholder row.
fn alert_rule_rows(rules: &[AlertRule]) -> String {
    if rules.is_empty() {
        return "<tr><td class=\"empty\" colspan=\"6\">No alert rules configured.</td></tr>"
            .to_string();
    }
    rules
        .iter()
        .map(|rule| {
            format!(
                "<tr>\
                   <td class=\"c-time\"><time>{time}</time></td>\
                   <td class=\"c-action\">{name}</td>\
                   <td>{actor}</td>\
                   <td>{action}</td>\
                   <td>{source}</td>\
                   <td><span class=\"sev {sevcls}\">{severity}</span></td>\
                 </tr>",
                time = esc(&fmt_ts(rule.created_at)),
                name = esc(&rule.name),
                actor = esc(&predicate(&rule.actor)),
                action = esc(&predicate(&rule.action)),
                source = esc(&predicate(&rule.source)),
                sevcls = rule
                    .severity
                    .as_deref()
                    .map(severity_class)
                    .unwrap_or("sev-neutral"),
                severity = esc(&predicate(&rule.severity)),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Render recent alert match marker rows. Empty -> placeholder row.
fn alert_match_rows(matches: &[AlertMatch]) -> String {
    if matches.is_empty() {
        return "<tr><td class=\"empty\" colspan=\"7\">No alert matches recorded.</td></tr>"
            .to_string();
    }
    matches
        .iter()
        .map(|hit| {
            format!(
                "<tr>\
                   <td class=\"c-time\"><time>{time}</time></td>\
                   <td class=\"c-action\">{rule}</td>\
                   <td class=\"c-seq\">{seq}</td>\
                   <td class=\"c-actor\">{actor}</td>\
                   <td class=\"c-action\">{action}</td>\
                   <td><span class=\"sev {sevcls}\">{severity}</span></td>\
                   <td class=\"c-source\">{source}</td>\
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

fn predicate(v: &Option<String>) -> String {
    v.clone().unwrap_or_else(|| "*".to_string())
}

/// Render the checkpoint `<tr>` rows, each re-verified against the current log: recompute the
/// Merkle root up to its `seq_hi` and show a green VERIFIED / red BROKEN status. Empty -> a
/// friendly placeholder row.
fn checkpoint_rows(checkpoints: &[Checkpoint], events: &[AuditEvent]) -> String {
    if checkpoints.is_empty() {
        return "<tr><td class=\"empty\" colspan=\"4\">No checkpoints sealed yet.</td></tr>"
            .to_string();
    }
    // Newest-first, mirroring the event timeline.
    let mut ordered: Vec<&Checkpoint> = checkpoints.iter().collect();
    ordered.sort_by(|a, b| b.seq_hi.cmp(&a.seq_hi));
    ordered
        .into_iter()
        .map(|cp| {
            let current = merkle_root_upto(events, cp.seq_hi);
            let valid = current == cp.merkle_root;
            let (cls, label) = if valid {
                ("sev-success", "VERIFIED")
            } else {
                ("sev-critical", "BROKEN")
            };
            format!(
                "<tr>\
                   <td class=\"c-time\"><time>{time}</time></td>\
                   <td class=\"c-seq\">{seq_hi}</td>\
                   <td class=\"c-root\"><code>{root}…</code></td>\
                   <td><span class=\"sev {cls}\">{label}</span></td>\
                 </tr>",
                time = esc(&fmt_ts(cp.created_at)),
                seq_hi = cp.seq_hi,
                root = esc(&short_root(&cp.merkle_root)),
                cls = cls,
                label = label,
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// First 16 hex chars of a Merkle root for compact display.
fn short_root(root: &str) -> String {
    root.chars().take(16).collect()
}

/// First value of a header as a `String` (empty when absent / non-UTF-8).
fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Build the integrity badge `(css_class, text)` from a verify report.
fn badge(report: &crate::chain::VerifyReport) -> (&'static str, String) {
    match report.first_broken_seq {
        Some(seq) => (
            "integ-bad",
            format!("TAMPERED at seq {seq} · {} events", report.count),
        ),
        None if report.count == 0 => ("integ-ok", "Verified · 0 events".to_string()),
        None => (
            "integ-ok",
            format!(
                "Verified · {} events · head {}…",
                report.count,
                short_hash(&report.head_hash)
            ),
        ),
    }
}

/// First 12 hex chars of a hash for compact display.
fn short_hash(hash: &str) -> String {
    hash.chars().take(12).collect()
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
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Render the timeline `<tr>` rows (escaped). Empty -> a single friendly placeholder row.
fn timeline_rows(rows: &[AuditEvent]) -> String {
    if rows.is_empty() {
        return "<tr><td class=\"empty\" colspan=\"8\">No events match the current filter.</td></tr>"
            .to_string();
    }
    rows.iter()
        .map(|e| {
            format!(
                "<tr>\
                   <td class=\"c-time\"><time>{time}</time></td>\
                   <td class=\"c-seq\">{seq}</td>\
                   <td><span class=\"sev {sevcls}\">{sev}</span></td>\
                   <td class=\"c-actor\">{actor}</td>\
                   <td class=\"c-action\">{action}</td>\
                   <td class=\"c-target\">{target}</td>\
                   <td class=\"c-detail\">{detail}</td>\
                   <td class=\"c-source\">{source}</td>\
                 </tr>",
                time = esc(&fmt_ts(e.ts)),
                seq = e.seq,
                sevcls = severity_class(&e.severity),
                sev = esc(&severity_label(&e.severity)),
                actor = esc(&e.actor),
                action = esc(&e.action),
                target = esc(&e.target),
                detail = esc(&e.detail),
                source = esc(&e.source),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Prev/next links for the filtered timeline.
fn pagination_links(filter: &EventFilter, total: usize) -> String {
    let mut links = Vec::new();
    if filter.offset > 0 {
        let prev = filter.offset.saturating_sub(filter.limit);
        links.push(format!(
            "<a class=\"btn btn-secondary btn-sm\" href=\"{href}\">Previous</a>",
            href = esc(&events_href(filter, prev)),
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
        format!("<div class=\"pagination\">{}</div>", links.join(""))
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
}
