//! Sift logs feed — a READ-ONLY pool over Sift's own database.
//!
//! Sift's `/api/search` is SSO-gated, so Hindsight reads Sift's `logs` table directly over a
//! lazily-connected, read-mostly Postgres pool (`SIFT_DATABASE_URL`). Only error/warn lines in
//! the correlation window are pulled. The seam mirrors cortex's federation: handlers depend only
//! on the async [`LogReader`] trait, so an in-memory fake ([`InMemoryLogReader`], used by tests +
//! the DB-free dev path) and a live [`PgLogReader`] are interchangeable behind `Arc<dyn _>`.
//!
//! RESILIENCE: a query against a down Sift DB returns `Err`, which the timeline records as the
//! Sift feed being "unavailable" — the rest of the timeline still renders. The pool is built with
//! `connect_lazy`, so a down Sift DB never blocks startup.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// Per-query acquire timeout — a down Sift DB fails fast (and is marked unavailable) rather than
/// hanging the page.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);

/// One log line read from Sift (the subset Hindsight correlates).
#[derive(Clone, Debug)]
pub struct LogRow {
    pub id: String,
    pub ts: i64, // epoch SECONDS (Sift stamps `ts` in seconds)
    pub host: String,
    pub app: String,
    pub severity: String,
    pub message: String,
    pub template_id: String,
}

/// A read-only source of recent error/warn log lines. `Err` means the source is
/// unreachable/broken and should be marked unavailable, never surfaced as a page error.
#[async_trait]
pub trait LogReader: Send + Sync {
    /// Error/warn log lines with `ts` in `[from, to]`, newest-first, capped at `limit`.
    async fn recent_errors(&self, from: i64, to: i64, limit: i64) -> Result<Vec<LogRow>, String>;
}

// ---------------------------------------------------------------------------
// In-memory fake reader (the DB-free default + tests).
// ---------------------------------------------------------------------------

/// An in-memory [`LogReader`]. Holds plain rows and applies the same window/severity filter. Set
/// `down = true` to simulate an unreachable Sift DB.
#[derive(Default)]
pub struct InMemoryLogReader {
    pub rows: Vec<LogRow>,
    pub down: bool,
}

impl InMemoryLogReader {
    /// An empty reader (the dev default: Sift not wired -> the feed is simply empty but reached).
    pub fn empty() -> Self {
        Self::default()
    }

    /// A reader seeded with `rows` (used by tests).
    pub fn with_rows(rows: Vec<LogRow>) -> Self {
        Self { rows, down: false }
    }

    /// A reader that always errors (to exercise the unavailable-feed path).
    pub fn down() -> Self {
        Self {
            rows: Vec::new(),
            down: true,
        }
    }
}

/// True when a severity string denotes an error- or warning-class line (case-insensitive).
pub fn is_error_severity(severity: &str) -> bool {
    matches!(
        severity.trim().to_ascii_lowercase().as_str(),
        "error" | "err" | "crit" | "critical" | "fatal" | "alert" | "emerg" | "warn" | "warning"
    )
}

#[async_trait]
impl LogReader for InMemoryLogReader {
    async fn recent_errors(&self, from: i64, to: i64, limit: i64) -> Result<Vec<LogRow>, String> {
        if self.down {
            return Err("simulated Sift outage".to_string());
        }
        let mut hits: Vec<LogRow> = self
            .rows
            .iter()
            .filter(|r| r.ts >= from && r.ts <= to && is_error_severity(&r.severity))
            .cloned()
            .collect();
        hits.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        hits.truncate(limit.max(0) as usize);
        Ok(hits)
    }
}

// ---------------------------------------------------------------------------
// Postgres-backed reader (read-only, portable standard SQL, runtime queries).
// ---------------------------------------------------------------------------

/// Read-only Sift `logs` reader. Holds a lazily-connected pool to Sift's database.
pub struct PgLogReader {
    pool: PgPool,
}

impl PgLogReader {
    /// Build a lazily-connected, read-mostly pool to Sift's DSN. Never touches the network here —
    /// a down Sift DB is discovered (and marked unavailable) only when the first query runs.
    pub fn connect_lazy(dsn: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect_lazy(dsn)?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LogReader for PgLogReader {
    async fn recent_errors(&self, from: i64, to: i64, limit: i64) -> Result<Vec<LogRow>, String> {
        // Standard portable SQL: window on `ts`, severity allow-list, newest-first, bounded. The
        // severity set is matched case-insensitively against the canonical error/warn vocabulary.
        let rows = sqlx::query(
            "SELECT id, ts, host, app, severity, message, template_id \
             FROM logs \
             WHERE ts >= $1 AND ts <= $2 \
               AND LOWER(severity) IN \
                   ('error','err','crit','critical','fatal','alert','emerg','warn','warning') \
             ORDER BY ts DESC LIMIT $3",
        )
        .bind(from)
        .bind(to)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| e.to_string())?;

        rows.iter()
            .map(|r| {
                Ok(LogRow {
                    id: r.try_get("id").map_err(|e: sqlx::Error| e.to_string())?,
                    ts: r.try_get("ts").map_err(|e: sqlx::Error| e.to_string())?,
                    host: r.try_get("host").map_err(|e: sqlx::Error| e.to_string())?,
                    app: r.try_get("app").map_err(|e: sqlx::Error| e.to_string())?,
                    severity: r
                        .try_get("severity")
                        .map_err(|e: sqlx::Error| e.to_string())?,
                    message: r
                        .try_get("message")
                        .map_err(|e: sqlx::Error| e.to_string())?,
                    template_id: r
                        .try_get("template_id")
                        .map_err(|e: sqlx::Error| e.to_string())?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, ts: i64, sev: &str) -> LogRow {
        LogRow {
            id: id.to_string(),
            ts,
            host: "h1".to_string(),
            app: "api".to_string(),
            severity: sev.to_string(),
            message: format!("msg {id}"),
            template_id: "t1".to_string(),
        }
    }

    #[test]
    fn severity_classification() {
        assert!(is_error_severity("ERROR"));
        assert!(is_error_severity("Warning"));
        assert!(is_error_severity("crit"));
        assert!(!is_error_severity("info"));
        assert!(!is_error_severity("debug"));
        assert!(!is_error_severity("notice"));
    }

    #[tokio::test]
    async fn in_memory_filters_window_and_severity_newest_first() {
        let reader = InMemoryLogReader::with_rows(vec![
            row("a", 100, "error"),
            row("b", 150, "info"), // dropped: not error/warn
            row("c", 200, "warn"),
            row("d", 50, "error"),  // dropped: before window
            row("e", 500, "error"), // dropped: after window
        ]);
        let hits = reader.recent_errors(80, 300, 10).await.unwrap();
        let ids: Vec<&str> = hits.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "a"]);
    }

    #[tokio::test]
    async fn down_reader_errors() {
        let reader = InMemoryLogReader::down();
        assert!(reader.recent_errors(0, i64::MAX, 10).await.is_err());
    }
}
