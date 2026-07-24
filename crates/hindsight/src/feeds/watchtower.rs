//! Typed Watchtower audit acquisition with millisecond precision.

use std::time::Duration;

use serde::Deserialize;

use crate::http::{self, HttpAcquisition};
use crate::view_contract::{AuditRecord, ChannelId};

const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub enum AuditAcquisition {
    ConfigurationAbsentOrInvalid,
    Unavailable,
    NonSuccess,
    OversizeTruncated,
    InvalidSchema,
    Loaded(Vec<AuditRecord>),
}

#[derive(Clone, Debug, Deserialize)]
struct WireAuditRecord {
    seq: i64,
    hash: String,
    prev_hash: String,
    ts: i64,
    actor: String,
    action: String,
    target: String,
    severity: String,
    detail: String,
    source: String,
}

pub async fn fetch(watchtower_url: Option<&str>, limit: usize) -> AuditAcquisition {
    let endpoint = watchtower_url
        .map(|base| format!("{}/api/events?limit={limit}", base.trim_end_matches('/')));
    match http::acquire(ChannelId::Audit, endpoint.as_deref(), FETCH_TIMEOUT).await {
        HttpAcquisition::ConfigurationAbsentOrInvalid => {
            AuditAcquisition::ConfigurationAbsentOrInvalid
        }
        HttpAcquisition::Unavailable(_) => AuditAcquisition::Unavailable,
        HttpAcquisition::NonSuccess { .. } => AuditAcquisition::NonSuccess,
        HttpAcquisition::OversizeTruncated => AuditAcquisition::OversizeTruncated,
        HttpAcquisition::CompleteBody(body) => parse(&body),
    }
}

pub fn parse(body: &[u8]) -> AuditAcquisition {
    let rows: Vec<WireAuditRecord> = match serde_json::from_slice(body) {
        Ok(rows) => rows,
        Err(_) => return AuditAcquisition::InvalidSchema,
    };
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        if row.seq <= 0
            || row.ts <= 0
            || !is_lower_hex_64(&row.hash)
            || !is_lower_hex_64(&row.prev_hash)
        {
            return AuditAcquisition::InvalidSchema;
        }
        records.push(AuditRecord {
            sequence: row.seq,
            hash: row.hash,
            previous_hash: row.prev_hash,
            recorded_at_ms: row.ts,
            actor: row.actor,
            action: row.action,
            target: row.target,
            severity: row.severity,
            detail: row.detail,
            source: row.source,
        });
    }
    AuditAcquisition::Loaded(records)
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_retains_lossless_chain_and_millisecond_fields() {
        let hash = "a".repeat(64);
        let previous = "b".repeat(64);
        let body = format!(
            r#"[{{"seq":2,"hash":"{hash}","prev_hash":"{previous}","ts":1700000002001,"actor":"","action":"","target":"case","severity":"","detail":"","source":"watchtower"}}]"#
        );
        let AuditAcquisition::Loaded(records) = parse(body.as_bytes()) else {
            panic!("expected loaded");
        };
        assert_eq!(records[0].recorded_at_ms, 1_700_000_002_001);
        assert!(records[0].action.is_empty());
        assert!(records[0].severity.is_empty());
        assert_eq!(records[0].hash, hash);
    }

    #[test]
    fn one_invalid_record_rejects_the_whole_channel() {
        let body = br#"[{"seq":0,"hash":"","prev_hash":"","ts":1,"actor":"","action":"","target":"","severity":"","detail":"","source":""}]"#;
        assert!(matches!(parse(body), AuditAcquisition::InvalidSchema));
        assert!(matches!(parse(b"{}"), AuditAcquisition::InvalidSchema));
    }
}
