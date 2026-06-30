//! The server-rendered SSO dashboard (mini-SIEM).
//!
//! `GET /` (and, because Sluice forwards the gateway prefix unmodified, any other path) renders
//! the enterprise UI: a chain-INTEGRITY badge (from a live `verify`), severity-coded counts,
//! a filter bar, and the audit TIMELINE. It does NO login of its own — it reads the
//! Sluice-injected `X-Auth-Email` to show "signed in as", and Logout points at the gateway.
//!
//! The page is fully self-contained: the design-system CSS is embedded via `include_str!`, so
//! there are no asset round-trips (and nothing to break under gateway path-prefixing). All
//! producer-supplied fields are HTML-escaped on render (defense-in-depth against stored XSS).

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Html;

use crate::auth::csrf_token;
use crate::chain::{verify_chain, AuditEvent};
use crate::handlers::events::EventsQuery;
use crate::merkle::{merkle_root_upto, Checkpoint};
use crate::AppState;

/// Embedded design-system CSS (brand tokens shared with the Keystone login UI).
const APP_CSS: &str = include_str!("../../static/app.css");
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
    let filter_q = query.q.clone().unwrap_or_default();
    let filter_since = query.since.map(|s| s.to_string()).unwrap_or_default();
    let filter = query.into_filter();

    // Whole chain -> integrity badge + counts. Filtered slice -> the visible timeline.
    let all = state.store.all_events().await.unwrap_or_default();
    let report = verify_chain(&all);
    let rows = state.store.query(&filter).await.unwrap_or_default();
    let checkpoints = state.store.all_checkpoints().await.unwrap_or_default();

    let email = header_str(&headers, "x-auth-email");
    let userbox = topbar_userbox(&email);

    let (badge_class, badge_text) = badge(&report);
    let severity_pills = severity_pills(&all);
    let timeline = timeline_rows(&rows);
    let checkpoint_rows = checkpoint_rows(&checkpoints, &all);
    // The seal form is shown only to a gateway-SSO identity; its CSRF token is keyed by the
    // ingest secret and bound to that identity (matching the POST /api/checkpoint check).
    let checkpoint_form = if email.is_empty() {
        String::new()
    } else {
        seal_form(&csrf_token(&state.config.ingest_token, &email))
    };
    let showing = format!(
        "Showing {} of {} event{}",
        rows.len(),
        all.len(),
        if all.len() == 1 { "" } else { "s" }
    );

    let html = TEMPLATE
        .replace("{{STYLE}}", APP_CSS)
        .replace("{{USERBOX}}", &userbox)
        .replace("{{BADGE_CLASS}}", badge_class)
        .replace("{{BADGE_TEXT}}", &badge_text)
        .replace("{{TOTAL}}", &all.len().to_string())
        .replace("{{SEVERITY_PILLS}}", &severity_pills)
        .replace("{{F_ACTOR}}", &esc(&filter_actor))
        .replace("{{F_ACTION}}", &esc(&filter_action))
        .replace("{{F_Q}}", &esc(&filter_q))
        .replace("{{F_SINCE}}", &esc(&filter_since))
        .replace("{{SHOWING}}", &esc(&showing))
        .replace("{{CHECKPOINT_FORM}}", &checkpoint_form)
        .replace("{{CHECKPOINT_ROWS}}", &checkpoint_rows)
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
        "<span class=\"user-email\" title=\"Signed in as\">— (no gateway session)</span>".to_string()
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
