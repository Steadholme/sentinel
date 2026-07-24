//! Hindsight evidence acquisition, comparison, and compatibility projection.

pub mod sift;
pub mod vitals;
pub mod watchtower;

use serde::Serialize;

use crate::config::Config;
use crate::config::TIMELINE_LIMIT;
use crate::view_contract::{
    allocate_display, ceil_millis_to_seconds, compare_items, floor_millis_to_seconds, Boundedness,
    ChannelId, ChannelState, ChannelView, Coverage, CoverageKind, EffectiveWindowMs, EvidenceItem,
    EvidenceRecord, GapTruth, ValidationError, WindowGate,
};
use sift::{LogAcquisition, LogReader};
use vitals::MetricAcquisition;
use watchtower::AuditAcquisition;

pub const SRC_WATCHTOWER: &str = "watchtower";
pub const SRC_SIFT: &str = "sift";
pub const SRC_VITALS: &str = "vitals";

#[derive(Clone, Debug)]
pub struct ComparisonSnapshot {
    pub gate: WindowGate,
    pub channels: [ChannelView; 3],
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct LegacyFeedStatus {
    pub watchtower: bool,
    pub sift: bool,
    pub vitals: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LegacySource {
    Watchtower,
    Sift,
    Vitals,
}

#[derive(Clone, Debug, Serialize)]
pub struct LegacyTimelineEvent {
    pub ts: i64,
    pub source: LegacySource,
    pub severity: String,
    pub title: String,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct RequestedWindowJson {
    pub from_inclusive_ms: i64,
    pub to_inclusive_ms: Option<i64>,
    pub moving: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct EffectiveWindowJson {
    pub from_inclusive_ms: i64,
    pub to_inclusive_ms: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TimelineJsonV2 {
    pub from: i64,
    pub to: i64,
    pub status: LegacyFeedStatus,
    pub events: Vec<LegacyTimelineEvent>,
    pub schema_version: u8,
    pub requested_window_ms: RequestedWindowJson,
    pub effective_window_ms: EffectiveWindowJson,
    pub observed_at_ms: i64,
    pub channels: [ChannelView; 3],
}

impl ComparisonSnapshot {
    pub fn timeline_json_v2(&self) -> TimelineJsonV2 {
        let events = legacy_events(&self.channels);
        let status = LegacyFeedStatus {
            watchtower: is_legacy_loaded(&self.channels[0].state),
            sift: is_legacy_loaded(&self.channels[1].state),
            vitals: is_legacy_loaded(&self.channels[2].state),
        };
        TimelineJsonV2 {
            from: self.gate.effective.from_inclusive.div_euclid(1_000),
            to: self.gate.effective.to_inclusive.div_euclid(1_000),
            status,
            events,
            schema_version: 2,
            requested_window_ms: RequestedWindowJson {
                from_inclusive_ms: self.gate.requested.from_inclusive,
                to_inclusive_ms: self.gate.requested.to_inclusive,
                moving: self.gate.requested.to_inclusive.is_none(),
            },
            effective_window_ms: EffectiveWindowJson {
                from_inclusive_ms: self.gate.effective.from_inclusive,
                to_inclusive_ms: self.gate.effective.to_inclusive,
            },
            observed_at_ms: self.gate.observed_at_ms,
            channels: self.channels.clone(),
        }
    }
}

pub async fn gather(
    config: &Config,
    logs: &dyn LogReader,
    gate: WindowGate,
) -> Result<ComparisonSnapshot, ValidationError> {
    let from_s = ceil_millis_to_seconds(gate.effective.from_inclusive)?;
    let to_s = floor_millis_to_seconds(gate.effective.to_inclusive)?;
    let (audit, log, metric) = tokio::join!(
        watchtower::fetch(Some(config.watchtower_url.as_str()), TIMELINE_LIMIT + 1),
        logs.recent_errors(from_s, to_s, TIMELINE_LIMIT + 1),
        vitals::fetch(Some(config.vitals_url.as_str()), from_s),
    );

    let mut channels = [
        audit_channel(audit, gate)?,
        log_channel(log, gate)?,
        metric_channel(metric, gate)?,
    ];
    allocate_display(&mut channels, TIMELINE_LIMIT).map_err(|_| ValidationError::InvalidScalar)?;
    Ok(ComparisonSnapshot { gate, channels })
}

fn audit_channel(
    acquisition: AuditAcquisition,
    gate: WindowGate,
) -> Result<ChannelView, ValidationError> {
    match acquisition {
        AuditAcquisition::ConfigurationAbsentOrInvalid => {
            failed(ChannelId::Audit, ChannelState::ConfigurationAbsentOrInvalid)
        }
        AuditAcquisition::Unavailable => failed(ChannelId::Audit, ChannelState::Unavailable),
        AuditAcquisition::NonSuccess => failed(ChannelId::Audit, ChannelState::NonSuccess),
        AuditAcquisition::OversizeTruncated => {
            failed(ChannelId::Audit, ChannelState::OversizeTruncated)
        }
        AuditAcquisition::InvalidSchema => failed(ChannelId::Audit, ChannelState::InvalidSchema),
        AuditAcquisition::Loaded(records) => {
            let acquired_count = records.len();
            let acquired_from_ms = records.iter().map(|row| row.recorded_at_ms).min();
            let acquired_to_ms = records.iter().map(|row| row.recorded_at_ms).max();
            let retained = records
                .into_iter()
                .filter(|row| {
                    row.recorded_at_ms >= gate.effective.from_inclusive
                        && row.recorded_at_ms <= gate.effective.to_inclusive
                })
                .map(EvidenceRecord::Audit)
                .collect();
            loaded(
                ChannelId::Audit,
                Boundedness::CompletenessUnknown,
                coverage(
                    CoverageKind::RecentCountBounded,
                    gate,
                    acquired_from_ms,
                    acquired_to_ms,
                    GapTruth::Unknown,
                    GapTruth::Unknown,
                ),
                acquired_count,
                retained,
            )
        }
    }
}

fn log_channel(
    acquisition: LogAcquisition,
    gate: WindowGate,
) -> Result<ChannelView, ValidationError> {
    match acquisition {
        LogAcquisition::ConfigurationAbsentOrInvalid => {
            failed(ChannelId::Log, ChannelState::ConfigurationAbsentOrInvalid)
        }
        LogAcquisition::Unavailable => failed(ChannelId::Log, ChannelState::Unavailable),
        LogAcquisition::OversizeTruncated => {
            failed(ChannelId::Log, ChannelState::OversizeTruncated)
        }
        LogAcquisition::InvalidSchema => failed(ChannelId::Log, ChannelState::InvalidSchema),
        LogAcquisition::Loaded {
            rows,
            acquired_from_ms,
            acquired_to_ms,
        } => {
            let decoded_count = rows
                .acquired_count
                .checked_add(usize::from(matches!(
                    rows.boundedness,
                    Boundedness::KnownMore
                )))
                .ok_or(ValidationError::Overflow)?;
            let gap_before = match rows.boundedness {
                Boundedness::KnownMore => GapTruth::Observed,
                Boundedness::ProvenEnd => GapTruth::NotObserved,
                Boundedness::CompletenessUnknown => return Err(ValidationError::InvalidScalar),
            };
            let retained =
                clip_second_records(rows.rows, gate.effective, EvidenceRecord::Log, |record| {
                    record.recorded_at_s
                })?;
            loaded(
                ChannelId::Log,
                rows.boundedness,
                coverage(
                    CoverageKind::ExactWindowLimitPlusOne,
                    gate,
                    acquired_from_ms,
                    acquired_to_ms,
                    gap_before,
                    GapTruth::NotObserved,
                ),
                decoded_count,
                retained,
            )
        }
    }
}

fn metric_channel(
    acquisition: MetricAcquisition,
    gate: WindowGate,
) -> Result<ChannelView, ValidationError> {
    match acquisition {
        MetricAcquisition::ConfigurationAbsentOrInvalid => failed(
            ChannelId::Metric,
            ChannelState::ConfigurationAbsentOrInvalid,
        ),
        MetricAcquisition::Unavailable => failed(ChannelId::Metric, ChannelState::Unavailable),
        MetricAcquisition::NonSuccess => failed(ChannelId::Metric, ChannelState::NonSuccess),
        MetricAcquisition::OversizeTruncated => {
            failed(ChannelId::Metric, ChannelState::OversizeTruncated)
        }
        MetricAcquisition::InvalidSchema => failed(ChannelId::Metric, ChannelState::InvalidSchema),
        MetricAcquisition::Loaded {
            acquired_count,
            acquired_from_ms,
            acquired_to_ms,
            records,
        } => {
            let retained =
                clip_second_records(records, gate.effective, EvidenceRecord::Metric, |record| {
                    record.recorded_at_s
                })?;
            loaded(
                ChannelId::Metric,
                Boundedness::CompletenessUnknown,
                coverage(
                    CoverageKind::LowerBoundSizeCapped,
                    gate,
                    acquired_from_ms,
                    acquired_to_ms,
                    GapTruth::Unknown,
                    GapTruth::Unknown,
                ),
                acquired_count,
                retained,
            )
        }
    }
}

fn failed(id: ChannelId, state: ChannelState) -> Result<ChannelView, ValidationError> {
    ChannelView::failed(id, state).map_err(|_| ValidationError::InvalidScalar)
}

fn loaded(
    id: ChannelId,
    boundedness: Boundedness,
    coverage: Coverage,
    acquired_count: usize,
    records: Vec<EvidenceRecord>,
) -> Result<ChannelView, ValidationError> {
    ChannelView::loaded(id, boundedness, coverage, acquired_count, records)
        .map_err(|_| ValidationError::InvalidScalar)
}

fn coverage(
    kind: CoverageKind,
    gate: WindowGate,
    acquired_from_ms: Option<i64>,
    acquired_to_ms: Option<i64>,
    gap_before_window: GapTruth,
    gap_after_window: GapTruth,
) -> Coverage {
    Coverage {
        kind,
        requested_from_ms: gate.requested.from_inclusive,
        requested_to_ms: gate.requested.to_inclusive,
        effective_from_ms: gate.effective.from_inclusive,
        effective_to_ms: gate.effective.to_inclusive,
        acquired_from_ms,
        acquired_to_ms,
        gap_before_window,
        gap_after_window,
    }
}

fn clip_second_records<T>(
    records: Vec<T>,
    window: EffectiveWindowMs,
    wrap: fn(T) -> EvidenceRecord,
    timestamp: fn(&T) -> i64,
) -> Result<Vec<EvidenceRecord>, ValidationError> {
    let mut retained = Vec::new();
    for record in records {
        let instant = timestamp(&record)
            .checked_mul(1_000)
            .ok_or(ValidationError::Overflow)?;
        if instant >= window.from_inclusive && instant <= window.to_inclusive {
            retained.push(wrap(record));
        }
    }
    Ok(retained)
}

fn is_legacy_loaded(state: &ChannelState) -> bool {
    matches!(
        state,
        ChannelState::LoadedEmpty | ChannelState::LoadedNonEmpty(_)
    )
}

fn legacy_events(channels: &[ChannelView; 3]) -> Vec<LegacyTimelineEvent> {
    let mut records = Vec::new();
    for channel in channels {
        for item in &channel.items {
            match item {
                EvidenceItem::Event { record } => records.push(record.clone()),
                EvidenceItem::Conflict { variants, .. } => {
                    records.extend(variants.iter().cloned());
                }
            }
        }
    }
    records.sort_by(|left, right| {
        compare_items(
            &EvidenceItem::Event {
                record: left.clone(),
            },
            &EvidenceItem::Event {
                record: right.clone(),
            },
        )
    });
    records.truncate(TIMELINE_LIMIT);
    records.into_iter().map(legacy_event).collect()
}

fn legacy_event(record: EvidenceRecord) -> LegacyTimelineEvent {
    match record {
        EvidenceRecord::Audit(record) => LegacyTimelineEvent {
            ts: record.recorded_at_ms.div_euclid(1_000),
            source: LegacySource::Watchtower,
            severity: record.severity,
            title: if record.action.is_empty() {
                "Source title not recorded".to_string()
            } else {
                record.action
            },
            detail: join_nonempty([
                record.source.as_str(),
                record.target.as_str(),
                record.actor.as_str(),
            ]),
        },
        EvidenceRecord::Log(record) => LegacyTimelineEvent {
            ts: record.recorded_at_s,
            source: LegacySource::Sift,
            severity: record.severity,
            title: if record.message.is_empty() {
                "Source title not recorded".to_string()
            } else {
                record.message
            },
            detail: join_nonempty([record.host.as_str(), record.app.as_str()]),
        },
        EvidenceRecord::Metric(record) => LegacyTimelineEvent {
            ts: record.recorded_at_s,
            source: LegacySource::Vitals,
            severity: match record.classification {
                crate::view_contract::MetricClassification::LoadElevated => "notice".to_string(),
                _ => "warning".to_string(),
            },
            title: record.derivation,
            detail: record.host,
        },
    }
}

fn join_nonempty<const N: usize>(parts: [&str; N]) -> String {
    parts
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::sift::{InMemoryLogReader, LogRow};
    use crate::view_contract::{RequestedWindowMs, WindowLifecycle};

    #[tokio::test]
    async fn sibling_failures_do_not_erase_loaded_log_truth() {
        let logs = InMemoryLogReader::with_rows(vec![LogRow {
            id: "log-1".to_string(),
            ts: 100,
            host: "host".to_string(),
            app: "app".to_string(),
            severity: "error".to_string(),
            message: "failure".to_string(),
            template_id: "template".to_string(),
        }]);
        let config = Config {
            bind_addr: "0.0.0.0:9180".to_string(),
            vitals_url: "invalid".to_string(),
            watchtower_url: "invalid".to_string(),
        };
        let gate = WindowGate::validate(
            RequestedWindowMs {
                from_inclusive: 1,
                to_inclusive: Some(200_000),
            },
            200_000,
            WindowLifecycle::Frozen,
        )
        .unwrap();
        let snapshot = gather(&config, &logs, gate).await.unwrap();
        assert!(matches!(
            snapshot.channels[0].state,
            ChannelState::ConfigurationAbsentOrInvalid
        ));
        assert!(matches!(
            snapshot.channels[1].state,
            ChannelState::LoadedNonEmpty(_)
        ));
        assert!(matches!(
            snapshot.channels[2].state,
            ChannelState::ConfigurationAbsentOrInvalid
        ));
    }
}
