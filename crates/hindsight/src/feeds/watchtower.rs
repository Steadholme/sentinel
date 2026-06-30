//! Watchtower events feed — recent sealed audit events over plain HTTP.
//!
//! `GET <WATCHTOWER_URL>/api/events?limit=N` returns a newest-first JSON array of sealed audit
//! events (open internally). Hindsight folds each into a [`TimelineEvent`]. `ts` arrives in epoch
//! MILLISECONDS (Watchtower stamps appends with `now_ms`), so it is normalized to seconds.
//!
//! RESILIENCE IS THE CONTRACT: any failure leaves the feed `available = false` with no events —
//! the timeline renders the rest and shows Watchtower as "unavailable".

use std::time::Duration;

use serde::Deserialize;

use super::{Feed, TimelineEvent, SRC_WATCHTOWER};
use crate::http;

/// Per-fetch budget. Watchtower is in-network; keep it short.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// One sealed audit event (the fields the timeline renders; chain hashes are ignored). `ts` is
/// epoch MILLISECONDS.
#[derive(Clone, Debug, Deserialize)]
pub struct WtEvent {
    #[serde(default)]
    pub ts: i64,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub source: String,
}

/// Fetch recent audit events and fold them into timeline events. On ANY failure returns an
/// unavailable feed.
pub async fn fetch(watchtower_url: &str, limit: usize) -> Feed {
    let url = format!(
        "{}/api/events?limit={}",
        watchtower_url.trim_end_matches('/'),
        limit
    );
    match http::fetch_text(&url, FETCH_TIMEOUT).await {
        Some(body) => Feed {
            events: parse(&body),
            available: true,
        },
        None => Feed::unavailable(),
    }
}

/// Parse `/api/events` (a newest-first JSON array) into timeline events. Foreign/invalid JSON
/// yields an empty vec.
pub fn parse(body: &str) -> Vec<TimelineEvent> {
    let raw: Vec<WtEvent> = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    raw.into_iter().map(to_timeline).collect()
}

fn to_timeline(e: WtEvent) -> TimelineEvent {
    let action = if e.action.trim().is_empty() {
        "event".to_string()
    } else {
        e.action.clone()
    };
    let actor = if e.actor.trim().is_empty() {
        "system".to_string()
    } else {
        e.actor.clone()
    };
    // Detail carries the originating service + the target, when present.
    let mut detail = String::new();
    if !e.source.trim().is_empty() {
        detail.push_str(e.source.trim());
    }
    if !e.target.trim().is_empty() {
        if !detail.is_empty() {
            detail.push_str(" · ");
        }
        detail.push_str(e.target.trim());
    }
    if !actor.is_empty() {
        if !detail.is_empty() {
            detail.push_str(" · ");
        }
        detail.push_str(&actor);
    }
    TimelineEvent {
        ts: e.ts / 1000, // ms -> s
        source: SRC_WATCHTOWER,
        severity: normalize_severity(&e.severity),
        title: action,
        detail,
    }
}

/// Map Watchtower severities onto Hindsight's vocabulary (`info`/`notice`/`warning`).
fn normalize_severity(s: &str) -> String {
    match s.trim().to_ascii_lowercase().as_str() {
        "" => "info".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_folds_events_and_normalizes_ms() {
        let body = r#"[
            {"seq":2,"ts":1700000002000,"actor":"alice@w33d.xyz","action":"secret.reveal","target":"db/pw","severity":"notice","source":"sanctum"},
            {"seq":1,"ts":1700000001000,"actor":"","action":"","target":"keystone","severity":"","source":"keystone"}
        ]"#;
        let evs = parse(body);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].ts, 1700000002, "ms normalized to seconds");
        assert_eq!(evs[0].source, SRC_WATCHTOWER);
        assert_eq!(evs[0].title, "secret.reveal");
        assert!(evs[0].detail.contains("sanctum"));
        assert!(evs[0].detail.contains("db/pw"));
        // Empty action/actor get neutral defaults.
        assert_eq!(evs[1].title, "event");
        assert_eq!(evs[1].severity, "info");
    }

    #[test]
    fn parse_on_garbage_is_empty() {
        assert!(parse("nope").is_empty());
        assert!(parse("{}").is_empty());
        assert!(parse("[]").is_empty());
    }
}
