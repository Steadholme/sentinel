//! The correlation engine: merge Watchtower events + Sift error/warn logs + Vitals anomalies
//! into one time-ordered timeline over a window.
//!
//! The three feeds are fetched CONCURRENTLY (copying portal's resilient fan-out): a slow or down
//! source can never serialize the others, and each independently degrades to "unavailable"
//! ([`FeedStatus`]) instead of failing the page. All timestamps are normalized to epoch SECONDS
//! before merge, so events from the audit chain (ms), logs (s), and metrics (s) interleave
//! correctly.

pub mod sift;
pub mod vitals;
pub mod watchtower;

use serde::Serialize;

use crate::config::Config;
use sift::LogReader;

/// Feed source labels (also the `source` field in the JSON timeline).
pub const SRC_WATCHTOWER: &str = "watchtower";
pub const SRC_SIFT: &str = "sift";
pub const SRC_VITALS: &str = "vitals";

/// One merged timeline entry. `ts` is always epoch SECONDS.
#[derive(Clone, Debug, Serialize)]
pub struct TimelineEvent {
    pub ts: i64,
    pub source: &'static str,
    pub severity: String,
    pub title: String,
    pub detail: String,
}

/// The result of one feed fetch: its events + whether the source was reachable.
pub struct Feed {
    pub events: Vec<TimelineEvent>,
    pub available: bool,
}

impl Feed {
    /// A reached-but-empty feed.
    pub fn empty() -> Self {
        Feed {
            events: Vec::new(),
            available: true,
        }
    }

    /// An unavailable feed (the source was down / unreachable).
    pub fn unavailable() -> Self {
        Feed {
            events: Vec::new(),
            available: false,
        }
    }
}

/// Per-source availability for the current timeline (drives the "unavailable" chips in the UI).
#[derive(Clone, Copy, Debug, Serialize)]
pub struct FeedStatus {
    pub watchtower: bool,
    pub sift: bool,
    pub vitals: bool,
}

/// The merged, time-ordered timeline plus the per-source availability.
#[derive(Serialize)]
pub struct Timeline {
    pub from: i64,
    pub to: i64,
    pub status: FeedStatus,
    pub events: Vec<TimelineEvent>,
}

/// Resolve a window's effective upper bound: `to == 0` (an open incident) means "now".
pub fn effective_to(to: i64, now: i64) -> i64 {
    if to <= 0 {
        now
    } else {
        to
    }
}

/// Correlate all three feeds over the window `[from, to]` (with `to <= 0` meaning "up to now").
///
/// `limit` bounds BOTH how many rows each feed pulls and the merged output, so a noisy window
/// can never produce an unbounded page. Fetches run concurrently; any down feed is marked in the
/// returned [`FeedStatus`] but never fails the call.
pub async fn gather(
    config: &Config,
    logs: &dyn LogReader,
    from: i64,
    to: i64,
    now: i64,
    limit: usize,
) -> Timeline {
    let eff_to = effective_to(to, now);
    let lim = limit as i64;

    // Fan out: the three feeds in flight at once. A slow/down feed can't block the others.
    let (wt, lg, vt) = tokio::join!(
        watchtower::fetch(&config.watchtower_url, limit),
        logs.recent_errors(from, eff_to, lim),
        vitals::fetch(&config.vitals_url, from),
    );

    let mut events: Vec<TimelineEvent> = Vec::new();
    let status = FeedStatus {
        watchtower: wt.available,
        // Sift returns Result — Ok means reached (even if empty).
        sift: lg.is_ok(),
        vitals: vt.available,
    };

    // Watchtower + Vitals events still need to be clipped to the window (they over-fetch).
    for e in wt.events.into_iter().chain(vt.events.into_iter()) {
        if e.ts >= from && e.ts <= eff_to {
            events.push(e);
        }
    }
    // Sift rows already arrive windowed; fold each into a timeline event.
    if let Ok(rows) = lg {
        for r in rows {
            events.push(sift_to_timeline(r));
        }
    }

    // Newest-first, with a stable tiebreak so equal-ts events don't reorder between renders.
    events.sort_by(|a, b| {
        b.ts.cmp(&a.ts)
            .then_with(|| a.source.cmp(b.source))
            .then_with(|| a.title.cmp(&b.title))
    });
    events.truncate(limit);

    Timeline {
        from,
        to: eff_to,
        status,
        events,
    }
}

/// Fold a Sift log row into a timeline event (`host · app` detail, normalized severity).
fn sift_to_timeline(r: sift::LogRow) -> TimelineEvent {
    let mut detail = String::new();
    if !r.host.trim().is_empty() {
        detail.push_str(r.host.trim());
    }
    if !r.app.trim().is_empty() {
        if !detail.is_empty() {
            detail.push_str(" · ");
        }
        detail.push_str(r.app.trim());
    }
    let severity = match r.severity.trim().to_ascii_lowercase().as_str() {
        "" => "info".to_string(),
        other => other.to_string(),
    };
    TimelineEvent {
        ts: r.ts,
        source: SRC_SIFT,
        severity,
        title: r.message,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::sift::{InMemoryLogReader, LogRow};
    use super::*;

    fn cfg() -> Config {
        // Point the HTTP feeds at a dead port so they degrade to "unavailable" deterministically.
        Config {
            bind_addr: "0.0.0.0:9180".to_string(),
            vitals_url: "http://127.0.0.1:1".to_string(),
            watchtower_url: "http://127.0.0.1:1".to_string(),
        }
    }

    #[test]
    fn effective_to_resolves_open_window() {
        assert_eq!(effective_to(0, 1000), 1000);
        assert_eq!(effective_to(-5, 1000), 1000);
        assert_eq!(effective_to(500, 1000), 500);
    }

    #[tokio::test]
    async fn gather_merges_sift_and_marks_down_http_feeds() {
        let logs = InMemoryLogReader::with_rows(vec![
            LogRow {
                id: "l1".to_string(),
                ts: 150,
                host: "h1".to_string(),
                app: "api".to_string(),
                severity: "error".to_string(),
                message: "disk full".to_string(),
                template_id: "t".to_string(),
            },
            LogRow {
                id: "l2".to_string(),
                ts: 250,
                host: "h2".to_string(),
                app: "db".to_string(),
                severity: "warn".to_string(),
                message: "slow query".to_string(),
                template_id: "t".to_string(),
            },
        ]);

        let tl = gather(&cfg(), &logs, 100, 300, 9_999, 100).await;
        // HTTP feeds are unreachable; Sift (in-memory) is reached.
        assert!(!tl.status.watchtower);
        assert!(!tl.status.vitals);
        assert!(tl.status.sift);
        // Both log rows fall in window, newest-first.
        assert_eq!(tl.events.len(), 2);
        assert_eq!(tl.events[0].title, "slow query");
        assert_eq!(tl.events[0].source, SRC_SIFT);
        assert_eq!(tl.events[1].title, "disk full");
        assert_eq!(tl.to, 300);
    }

    #[tokio::test]
    async fn gather_marks_sift_unavailable_when_down() {
        let logs = InMemoryLogReader::down();
        let tl = gather(&cfg(), &logs, 0, 0, 1000, 50).await;
        assert!(!tl.status.sift);
        assert!(tl.events.is_empty());
        assert_eq!(tl.to, 1000, "open window resolves to now");
    }
}
