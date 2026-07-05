//! Vitals anomalies feed — host-gauge spikes folded into timeline events, over plain HTTP.
//!
//! `GET <VITALS_URL>/api/metrics?since=<from>` returns `{ "samples": [ { host, metric, value, ts
//! }, ... ] }` with `ts` in epoch SECONDS (open internally). Hindsight scans the window and emits
//! a timeline event for each sample that crosses an anomaly threshold (high CPU/memory/load),
//! so the merged timeline shows *when the box was under stress* alongside the audit + log
//! evidence.
//!
//! RESILIENCE IS THE CONTRACT: any failure leaves the feed `available = false` with no events.

use std::time::Duration;

use serde::Deserialize;

use super::{Feed, TimelineEvent, SRC_VITALS};
use crate::http;

/// Per-fetch budget. Vitals is in-network; keep it short.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Anomaly thresholds. A sample at/above these is notable enough to land on the timeline.
const CPU_PCT_HIGH: f64 = 90.0;
const MEM_PCT_HIGH: f64 = 90.0;
const LOAD1_HIGH: f64 = 4.0;
const LOAD1_CRITICAL: f64 = 8.0;

/// `/api/metrics` response envelope.
#[derive(Debug, Deserialize)]
struct MetricsResponse {
    #[serde(default)]
    samples: Vec<Sample>,
}

#[derive(Debug, Deserialize)]
struct Sample {
    #[serde(default)]
    host: String,
    metric: String,
    value: f64,
    ts: i64,
}

/// Fetch metric samples since `from` (epoch seconds) and fold anomalous ones into timeline
/// events. On ANY failure returns an unavailable feed.
pub async fn fetch(vitals_url: &str, from: i64) -> Feed {
    let url = format!(
        "{}/api/metrics?since={}",
        vitals_url.trim_end_matches('/'),
        from
    );
    match http::fetch_text(&url, FETCH_TIMEOUT).await {
        Some(body) => Feed {
            events: parse_anomalies(&body),
            available: true,
        },
        None => Feed::unavailable(),
    }
}

/// Parse a `/api/metrics` body and emit a timeline event for each sample crossing a threshold.
/// Foreign/invalid JSON yields an empty vec.
pub fn parse_anomalies(body: &str) -> Vec<TimelineEvent> {
    let resp: MetricsResponse = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    resp.samples.iter().filter_map(anomaly).collect()
}

/// Map one sample to a timeline event when it crosses a threshold, else `None`.
fn anomaly(s: &Sample) -> Option<TimelineEvent> {
    let host = if s.host.trim().is_empty() {
        "host".to_string()
    } else {
        s.host.trim().to_string()
    };
    let (severity, title) = match s.metric.as_str() {
        "cpu_pct" if s.value >= CPU_PCT_HIGH => ("warning", format!("High CPU {:.0}%", s.value)),
        "mem_pct" if s.value >= MEM_PCT_HIGH => ("warning", format!("High memory {:.0}%", s.value)),
        "load1" if s.value >= LOAD1_CRITICAL => {
            ("warning", format!("Critical load {:.2}", s.value))
        }
        "load1" if s.value >= LOAD1_HIGH => ("notice", format!("Elevated load {:.2}", s.value)),
        _ => return None,
    };
    Some(TimelineEvent {
        ts: s.ts,
        source: SRC_VITALS,
        severity: severity.to_string(),
        title,
        detail: host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_anomalies_keeps_only_threshold_crossers() {
        let body = r#"{"samples":[
            {"host":"h1","metric":"cpu_pct","value":42.0,"ts":100},
            {"host":"h1","metric":"cpu_pct","value":95.0,"ts":110},
            {"host":"h1","metric":"mem_pct","value":91.0,"ts":120},
            {"host":"h1","metric":"load1","value":1.0,"ts":130},
            {"host":"h1","metric":"load1","value":5.0,"ts":140},
            {"host":"h1","metric":"load1","value":9.0,"ts":150},
            {"host":"h1","metric":"disk_pct","value":99.0,"ts":160}
        ]}"#;
        let evs = parse_anomalies(body);
        // cpu 95, mem 91, load 5 (notice), load 9 (warning) = 4 anomalies.
        assert_eq!(evs.len(), 4);
        assert!(evs.iter().all(|e| e.source == SRC_VITALS));
        assert!(evs.iter().any(|e| e.title.contains("High CPU 95%")));
        assert!(evs
            .iter()
            .any(|e| e.title.contains("Elevated load 5.00") && e.severity == "notice"));
        assert!(evs
            .iter()
            .any(|e| e.title.contains("Critical load 9.00") && e.severity == "warning"));
    }

    #[test]
    fn parse_anomalies_on_garbage_is_empty() {
        assert!(parse_anomalies("nope").is_empty());
        assert!(parse_anomalies(r#"{"samples":[]}"#).is_empty());
    }
}
