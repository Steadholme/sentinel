//! Typed, bounded Sift log acquisition.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

use crate::view_contract::{BoundedRows, LogRecord, TruthError, ACQUISITION_CAP_BYTES};

const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogRow {
    pub id: String,
    pub ts: i64,
    pub host: String,
    pub app: String,
    pub severity: String,
    pub message: String,
    pub template_id: String,
}

#[derive(Clone, Debug)]
pub enum LogAcquisition {
    ConfigurationAbsentOrInvalid,
    Unavailable,
    OversizeTruncated,
    InvalidSchema,
    Loaded {
        rows: BoundedRows<LogRecord>,
        acquired_from_ms: Option<i64>,
        acquired_to_ms: Option<i64>,
    },
}

#[async_trait]
pub trait LogReader: Send + Sync {
    async fn recent_errors(
        &self,
        from_inclusive_s: i64,
        to_inclusive_s: i64,
        limit_plus_one: usize,
    ) -> LogAcquisition;
}

#[derive(Default)]
pub struct InMemoryLogReader {
    pub rows: Vec<LogRow>,
    pub down: bool,
    pub configured: bool,
}

impl InMemoryLogReader {
    pub fn empty() -> Self {
        Self {
            configured: true,
            ..Self::default()
        }
    }

    pub fn unconfigured() -> Self {
        Self::default()
    }

    pub fn with_rows(rows: Vec<LogRow>) -> Self {
        Self {
            rows,
            down: false,
            configured: true,
        }
    }

    pub fn down() -> Self {
        Self {
            rows: Vec::new(),
            down: true,
            configured: true,
        }
    }
}

pub fn is_error_severity(severity: &str) -> bool {
    matches!(
        severity.to_ascii_lowercase().as_str(),
        "error" | "err" | "crit" | "critical" | "fatal" | "alert" | "emerg" | "warn" | "warning"
    )
}

#[async_trait]
impl LogReader for InMemoryLogReader {
    async fn recent_errors(
        &self,
        from_inclusive_s: i64,
        to_inclusive_s: i64,
        limit_plus_one: usize,
    ) -> LogAcquisition {
        if !self.configured {
            return LogAcquisition::ConfigurationAbsentOrInvalid;
        }
        if self.down {
            return LogAcquisition::Unavailable;
        }
        let mut rows = self
            .rows
            .iter()
            .filter(|row| {
                row.ts >= from_inclusive_s
                    && row.ts <= to_inclusive_s
                    && is_error_severity(&row.severity)
            })
            .cloned()
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            right
                .ts
                .cmp(&left.ts)
                .then_with(|| left.id.cmp(&right.id))
                .then_with(|| left.template_id.cmp(&right.template_id))
                .then_with(|| left.host.cmp(&right.host))
                .then_with(|| left.app.cmp(&right.app))
                .then_with(|| left.severity.cmp(&right.severity))
                .then_with(|| left.message.cmp(&right.message))
        });
        rows.truncate(limit_plus_one);
        let Some(limit) = limit_plus_one.checked_sub(1) else {
            return LogAcquisition::InvalidSchema;
        };
        classify_rows(rows, limit)
    }
}

pub struct PgLogReader {
    pool: PgPool,
}

impl PgLogReader {
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
    async fn recent_errors(
        &self,
        from_inclusive_s: i64,
        to_inclusive_s: i64,
        limit_plus_one: usize,
    ) -> LogAcquisition {
        let Ok(limit) = i64::try_from(limit_plus_one) else {
            return LogAcquisition::InvalidSchema;
        };
        let rows = match sqlx::query(
            "SELECT id, ts, host, app, severity, message, template_id \
             FROM logs \
             WHERE ts >= $1 AND ts <= $2 \
               AND LOWER(severity) IN \
                   ('error','err','crit','critical','fatal','alert','emerg','warn','warning') \
             ORDER BY ts DESC, \
                      id COLLATE \"C\" ASC, template_id COLLATE \"C\" ASC, \
                      host COLLATE \"C\" ASC, app COLLATE \"C\" ASC, \
                      severity COLLATE \"C\" ASC, message COLLATE \"C\" ASC \
             LIMIT $3",
        )
        .bind(from_inclusive_s)
        .bind(to_inclusive_s)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(_) => return LogAcquisition::Unavailable,
        };

        let mut decoded = Vec::with_capacity(rows.len());
        for row in rows {
            let decoded_row = (|| -> Result<LogRow, sqlx::Error> {
                Ok(LogRow {
                    id: row.try_get("id")?,
                    ts: row.try_get("ts")?,
                    host: row.try_get("host")?,
                    app: row.try_get("app")?,
                    severity: row.try_get("severity")?,
                    message: row.try_get("message")?,
                    template_id: row.try_get("template_id")?,
                })
            })();
            match decoded_row {
                Ok(row) => decoded.push(row),
                Err(_) => return LogAcquisition::InvalidSchema,
            }
        }
        let Some(limit) = limit_plus_one.checked_sub(1) else {
            return LogAcquisition::InvalidSchema;
        };
        classify_rows(decoded, limit)
    }
}

fn classify_rows(rows: Vec<LogRow>, limit: usize) -> LogAcquisition {
    let mut bytes = 0usize;
    let mut acquired_from_ms = None;
    let mut acquired_to_ms = None;
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(recorded_at_ms) = row.ts.checked_mul(1_000) else {
            return LogAcquisition::InvalidSchema;
        };
        if row.id.is_empty() || row.ts <= 0 {
            return LogAcquisition::InvalidSchema;
        }
        acquired_from_ms =
            Some(acquired_from_ms.map_or(recorded_at_ms, |value: i64| value.min(recorded_at_ms)));
        acquired_to_ms =
            Some(acquired_to_ms.map_or(recorded_at_ms, |value: i64| value.max(recorded_at_ms)));
        let string_bytes = [
            row.id.len(),
            row.template_id.len(),
            row.host.len(),
            row.app.len(),
            row.severity.len(),
            row.message.len(),
        ]
        .into_iter()
        .try_fold(0usize, |total, length| total.checked_add(length));
        let Some(row_bytes) = string_bytes.and_then(|total| total.checked_add(8)) else {
            return LogAcquisition::OversizeTruncated;
        };
        let Some(next_bytes) = bytes.checked_add(row_bytes) else {
            return LogAcquisition::OversizeTruncated;
        };
        if next_bytes > ACQUISITION_CAP_BYTES {
            return LogAcquisition::OversizeTruncated;
        }
        bytes = next_bytes;
        records.push(LogRecord {
            id: row.id,
            template_id: row.template_id,
            recorded_at_s: row.ts,
            host: row.host,
            app: row.app,
            severity: row.severity,
            message: row.message,
        });
    }
    match BoundedRows::from_limit_plus_one(records, limit) {
        Ok(rows) => LogAcquisition::Loaded {
            rows,
            acquired_from_ms,
            acquired_to_ms,
        },
        Err(TruthError::InvalidBound) => LogAcquisition::InvalidSchema,
        Err(_) => LogAcquisition::InvalidSchema,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, ts: i64, severity: &str) -> LogRow {
        LogRow {
            id: id.to_string(),
            ts,
            host: "host-a".to_string(),
            app: "api".to_string(),
            severity: severity.to_string(),
            message: format!("message {id}"),
            template_id: "template".to_string(),
        }
    }

    #[tokio::test]
    async fn in_memory_is_exact_and_limit_plus_one_bounded() {
        let reader = InMemoryLogReader::with_rows(vec![
            row("a", 100, "error"),
            row("b", 200, "warn"),
            row("c", 300, "info"),
        ]);
        let LogAcquisition::Loaded {
            rows,
            acquired_from_ms,
            acquired_to_ms,
        } = reader.recent_errors(1, 500, 2).await
        else {
            panic!("expected loaded");
        };
        assert_eq!(rows.rows.len(), 1);
        assert_eq!(rows.acquired_count, 1);
        assert_eq!(rows.rows[0].id, "b");
        assert_eq!(acquired_from_ms, Some(100_000));
        assert_eq!(acquired_to_ms, Some(200_000));
    }

    #[tokio::test]
    async fn unconfigured_and_unavailable_are_distinct() {
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
    }

    #[test]
    fn overflowing_second_timestamp_is_invalid_schema() {
        assert!(matches!(
            classify_rows(vec![row("overflow", i64::MAX, "error")], 1),
            LogAcquisition::InvalidSchema
        ));
    }
}
