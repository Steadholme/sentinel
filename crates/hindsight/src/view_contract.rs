//! Typed truth and one-pass composition contract for Hindsight.
//!
//! This module is deliberately the only place where dynamic application truth
//! becomes template values. Static templates own HTML; inserted values are
//! typed, context encoded, and never scanned as template syntax.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;

pub const ACQUISITION_CAP_BYTES: usize = 4_194_304;
pub const INCIDENT_LIMIT: usize = 200;
pub const NOTE_LIMIT: usize = 200;
pub const DISPLAY_LIMIT: usize = 300;
pub const MAX_WINDOW_MS: i64 = 720 * 60 * 60 * 1_000;

// ---------------------------------------------------------------------------
// Validated product scalars
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct IncidentId(String);

impl IncidentId {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        validate_prefixed_id(value, "inc_", 5)?;
        Ok(Self(value.to_string()))
    }

    pub fn generate() -> Self {
        Self(format!("inc_{}", random_hex::<16>()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IncidentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct NoteId(String);

impl NoteId {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        validate_prefixed_id(value, "note_", 6)?;
        Ok(Self(value.to_string()))
    }

    pub fn generate() -> Self {
        Self(format!("note_{}", random_hex::<16>()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NoteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

macro_rules! bounded_scalar {
    ($name:ident, $max_bytes:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: &str) -> Result<Self, ValidationError> {
                let value = value.trim();
                if value.is_empty()
                    || value.len() > $max_bytes
                    || value.chars().any(|c| c.is_ascii_control())
                {
                    return Err(ValidationError::InvalidScalar);
                }
                Ok(Self(value.to_string()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

bounded_scalar!(BoundedSubject, 256);
bounded_scalar!(BoundedDisplayEmail, 320);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct BoundedTitle(String);

impl BoundedTitle {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ValidationError::Empty);
        }
        if value.len() > 1_024
            || value.chars().count() > 160
            || value.chars().any(|c| c.is_ascii_control())
        {
            return Err(ValidationError::InvalidScalar);
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoundedTitle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct BoundedNote(String);

impl BoundedNote {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
        let value = normalized.trim();
        if value.is_empty() {
            return Err(ValidationError::Empty);
        }
        if value.len() > 16_384
            || value.chars().count() > 4_000
            || value
                .chars()
                .any(|c| c.is_ascii_control() && c != '\n' && c != '\t')
        {
            return Err(ValidationError::InvalidScalar);
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoundedNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct CsrfToken(String);

impl CsrfToken {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        validate_lower_hex(value, 64)?;
        Ok(Self(value.to_string()))
    }

    pub fn generate() -> Self {
        Self(random_hex::<32>())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct ResolveCommandId(String);

impl ResolveCommandId {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        validate_lower_hex(value, 64)?;
        Ok(Self(value.to_string()))
    }

    pub fn generate() -> Self {
        Self(random_hex::<32>())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct PublicMarkRef(String);

impl PublicMarkRef {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let Some(suffix) = value.strip_prefix("rm_") else {
            return Err(ValidationError::InvalidIdentifier);
        };
        validate_lower_hex(suffix, 32)?;
        Ok(Self(value.to_string()))
    }

    pub fn generate() -> Self {
        Self(format!("rm_{}", random_hex::<16>()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedOpen;

impl ExpectedOpen {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        (value == "open")
            .then_some(Self)
            .ok_or(ValidationError::InvalidScalar)
    }

    pub fn as_str(self) -> &'static str {
        "open"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedDisplayText {
    text: String,
    truncated: bool,
    safe: bool,
    recorded: bool,
}

impl BoundedDisplayText {
    pub fn project(value: &str) -> Self {
        if value.is_empty() {
            return Self {
                text: "Legacy value not recorded (unclassified)".to_string(),
                truncated: false,
                safe: true,
                recorded: false,
            };
        }
        if value.chars().any(|c| c.is_ascii_control()) {
            return Self {
                text: "Legacy value not safely displayable (unclassified)".to_string(),
                truncated: false,
                safe: false,
                recorded: false,
            };
        }
        let mut text = String::new();
        let mut truncated = false;
        for ch in value.chars() {
            if text.chars().count() >= 320 || text.len() + ch.len_utf8() > 1_280 {
                truncated = true;
                break;
            }
            text.push(ch);
        }
        Self {
            text,
            truncated,
            safe: true,
            recorded: true,
        }
    }

    pub fn visible(&self) -> String {
        if self.truncated {
            format!("{}… [truncated]", self.text)
        } else {
            self.text.clone()
        }
    }

    pub fn is_safe(&self) -> bool {
        self.safe
    }

    pub fn has_recorded_value(&self) -> bool {
        self.recorded
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    Empty,
    InvalidScalar,
    InvalidIdentifier,
    InvalidHex,
    InvalidWindow,
    Overflow,
}

fn validate_prefixed_id(
    value: &str,
    prefix: &str,
    minimum_len: usize,
) -> Result<(), ValidationError> {
    if value.len() < minimum_len || value.len() > 128 || !value.is_ascii() {
        return Err(ValidationError::InvalidIdentifier);
    }
    let suffix = value
        .strip_prefix(prefix)
        .ok_or(ValidationError::InvalidIdentifier)?;
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ValidationError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_lower_hex(value: &str, exact_len: usize) -> Result<(), ValidationError> {
    if value.len() != exact_len
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ValidationError::InvalidHex);
    }
    Ok(())
}

fn random_hex<const N: usize>() -> String {
    let mut bytes = [0_u8; N];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Truth vocabulary and evidence model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundedness {
    KnownMore,
    ProvenEnd,
    CompletenessUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelState {
    ConfigurationAbsentOrInvalid,
    Unavailable,
    NonSuccess,
    OversizeTruncated,
    InvalidSchema,
    LoadedEmpty,
    LoadedNonEmpty(Boundedness),
}

impl Serialize for ChannelState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(match self {
            Self::LoadedNonEmpty(_) => 2,
            _ => 1,
        }))?;
        let kind = match self {
            Self::ConfigurationAbsentOrInvalid => "configuration_absent_or_invalid",
            Self::Unavailable => "unavailable",
            Self::NonSuccess => "non_success",
            Self::OversizeTruncated => "oversize_truncated",
            Self::InvalidSchema => "invalid_schema",
            Self::LoadedEmpty => "loaded_empty",
            Self::LoadedNonEmpty(_) => "loaded_non_empty",
        };
        map.serialize_entry("kind", kind)?;
        if let Self::LoadedNonEmpty(boundedness) = self {
            map.serialize_entry("boundedness", boundedness)?;
        }
        map.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SectionState {
    Loaded { bounded: Boundedness },
    LoadedEmpty,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentLifecycle {
    Open,
    Resolved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActorTruth {
    Verified {
        subject: BoundedSubject,
        display_email: Option<BoundedDisplayEmail>,
    },
    LegacyUnclassified {
        legacy_display: BoundedDisplayText,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MarkKind {
    IncidentOpened,
    NoteAdded,
    IncidentResolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditReceiptTruth {
    OpenAttemptedNoStoredReceipt,
    NotAttemptedForNote,
    NotAttemptedForResolve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditEnqueueOutcome {
    Disabled,
    Enqueued,
    DroppedFull,
    DroppedClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelId {
    Audit,
    Log,
    Metric,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricClassification {
    CpuHigh,
    MemoryHigh,
    LoadElevated,
    LoadCritical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageKind {
    RecentCountBounded,
    ExactWindowLimitPlusOne,
    LowerBoundSizeCapped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GapTruth {
    Observed,
    NotObserved,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Coverage {
    pub kind: CoverageKind,
    pub requested_from_ms: i64,
    pub requested_to_ms: Option<i64>,
    pub effective_from_ms: i64,
    pub effective_to_ms: i64,
    pub acquired_from_ms: Option<i64>,
    pub acquired_to_ms: Option<i64>,
    pub gap_before_window: GapTruth,
    pub gap_after_window: GapTruth,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceKey {
    Audit {
        sequence: i64,
        hash: String,
    },
    Log {
        id: String,
    },
    Metric {
        host: String,
        metric_name: String,
        recorded_at_s: i64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PayloadTuple {
    Audit {
        previous_hash: String,
        recorded_at_ms: i64,
        actor: String,
        action: String,
        target: String,
        severity: String,
        detail: String,
        source: String,
    },
    Log {
        template_id: String,
        recorded_at_s: i64,
        host: String,
        app: String,
        severity: String,
        message: String,
    },
    Metric {
        raw_value_bits: u64,
        unit: String,
        recorded_at_s: i64,
        classification: MetricClassification,
        derivation: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct AuditRecord {
    pub sequence: i64,
    pub hash: String,
    pub previous_hash: String,
    pub recorded_at_ms: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub severity: String,
    pub detail: String,
    pub source: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct LogRecord {
    pub id: String,
    pub template_id: String,
    pub recorded_at_s: i64,
    pub host: String,
    pub app: String,
    pub severity: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct MetricRecord {
    pub host: String,
    pub metric_name: String,
    pub raw_value_bits: u64,
    pub unit: String,
    pub recorded_at_s: i64,
    pub classification: MetricClassification,
    pub derivation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceRecord {
    Audit(AuditRecord),
    Log(LogRecord),
    Metric(MetricRecord),
}

impl EvidenceRecord {
    pub fn channel(&self) -> ChannelId {
        match self {
            Self::Audit(_) => ChannelId::Audit,
            Self::Log(_) => ChannelId::Log,
            Self::Metric(_) => ChannelId::Metric,
        }
    }

    pub fn instant_ms(&self) -> Option<i64> {
        match self {
            Self::Audit(record) => Some(record.recorded_at_ms),
            Self::Log(record) => record.recorded_at_s.checked_mul(1_000),
            Self::Metric(record) => record.recorded_at_s.checked_mul(1_000),
        }
    }

    pub fn source_key(&self) -> SourceKey {
        match self {
            Self::Audit(record) => SourceKey::Audit {
                sequence: record.sequence,
                hash: record.hash.clone(),
            },
            Self::Log(record) => SourceKey::Log {
                id: record.id.clone(),
            },
            Self::Metric(record) => SourceKey::Metric {
                host: record.host.clone(),
                metric_name: record.metric_name.clone(),
                recorded_at_s: record.recorded_at_s,
            },
        }
    }

    pub fn payload_tuple(&self) -> PayloadTuple {
        match self {
            Self::Audit(record) => PayloadTuple::Audit {
                previous_hash: record.previous_hash.clone(),
                recorded_at_ms: record.recorded_at_ms,
                actor: record.actor.clone(),
                action: record.action.clone(),
                target: record.target.clone(),
                severity: record.severity.clone(),
                detail: record.detail.clone(),
                source: record.source.clone(),
            },
            Self::Log(record) => PayloadTuple::Log {
                template_id: record.template_id.clone(),
                recorded_at_s: record.recorded_at_s,
                host: record.host.clone(),
                app: record.app.clone(),
                severity: record.severity.clone(),
                message: record.message.clone(),
            },
            Self::Metric(record) => PayloadTuple::Metric {
                raw_value_bits: record.raw_value_bits,
                unit: record.unit.clone(),
                recorded_at_s: record.recorded_at_s,
                classification: record.classification,
                derivation: record.derivation.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceItem {
    Event {
        record: EvidenceRecord,
    },
    Conflict {
        source_key: SourceKey,
        variants: Vec<EvidenceRecord>,
    },
}

impl EvidenceItem {
    pub fn channel(&self) -> ChannelId {
        match self {
            Self::Event { record } => record.channel(),
            Self::Conflict { source_key, .. } => match source_key {
                SourceKey::Audit { .. } => ChannelId::Audit,
                SourceKey::Log { .. } => ChannelId::Log,
                SourceKey::Metric { .. } => ChannelId::Metric,
            },
        }
    }

    pub fn source_key(&self) -> SourceKey {
        match self {
            Self::Event { record } => record.source_key(),
            Self::Conflict { source_key, .. } => source_key.clone(),
        }
    }

    pub fn max_instant_ms(&self) -> i64 {
        match self {
            Self::Event { record } => record.instant_ms().unwrap_or(i64::MIN),
            Self::Conflict { variants, .. } => variants
                .iter()
                .filter_map(EvidenceRecord::instant_ms)
                .max()
                .unwrap_or(i64::MIN),
        }
    }

    fn payload_vector(&self) -> Vec<PayloadTuple> {
        match self {
            Self::Event { record } => vec![record.payload_tuple()],
            Self::Conflict { variants, .. } => {
                variants.iter().map(EvidenceRecord::payload_tuple).collect()
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChannelView {
    pub id: ChannelId,
    pub state: ChannelState,
    pub coverage: Option<Coverage>,
    pub acquired_count: Option<usize>,
    pub eligible_distinct_count: Option<usize>,
    pub displayed_distinct_count: Option<usize>,
    pub items: Vec<EvidenceItem>,
}

impl ChannelView {
    pub fn failed(id: ChannelId, state: ChannelState) -> Result<Self, TruthError> {
        if matches!(
            state,
            ChannelState::LoadedEmpty | ChannelState::LoadedNonEmpty(_)
        ) {
            return Err(TruthError::InvalidChannel);
        }
        Ok(Self {
            id,
            state,
            coverage: None,
            acquired_count: None,
            eligible_distinct_count: None,
            displayed_distinct_count: None,
            items: Vec::new(),
        })
    }

    pub fn loaded(
        id: ChannelId,
        boundedness: Boundedness,
        coverage: Coverage,
        acquired_count: usize,
        records: Vec<EvidenceRecord>,
    ) -> Result<Self, TruthError> {
        if acquired_count < records.len() || records.iter().any(|record| record.channel() != id) {
            return Err(TruthError::InvalidChannel);
        }
        let items = collapse_records(records)?;
        let eligible = items.len();
        let state = if items.is_empty() {
            ChannelState::LoadedEmpty
        } else {
            ChannelState::LoadedNonEmpty(boundedness)
        };
        let view = Self {
            id,
            state,
            coverage: Some(coverage),
            acquired_count: Some(acquired_count),
            eligible_distinct_count: Some(eligible),
            displayed_distinct_count: Some(eligible),
            items,
        };
        view.validate()?;
        Ok(view)
    }

    pub fn validate(&self) -> Result<(), TruthError> {
        match self.state {
            ChannelState::ConfigurationAbsentOrInvalid
            | ChannelState::Unavailable
            | ChannelState::NonSuccess
            | ChannelState::OversizeTruncated
            | ChannelState::InvalidSchema => {
                if self.coverage.is_some()
                    || self.acquired_count.is_some()
                    || self.eligible_distinct_count.is_some()
                    || self.displayed_distinct_count.is_some()
                    || !self.items.is_empty()
                {
                    return Err(TruthError::InvalidChannel);
                }
            }
            ChannelState::LoadedEmpty => {
                if self.coverage.is_none()
                    || self.acquired_count.is_none()
                    || self.eligible_distinct_count != Some(0)
                    || self.displayed_distinct_count != Some(0)
                    || !self.items.is_empty()
                {
                    return Err(TruthError::InvalidChannel);
                }
            }
            ChannelState::LoadedNonEmpty(_) => {
                let eligible = self
                    .eligible_distinct_count
                    .ok_or(TruthError::InvalidChannel)?;
                let displayed = self
                    .displayed_distinct_count
                    .ok_or(TruthError::InvalidChannel)?;
                if self.coverage.is_none()
                    || self.acquired_count.is_none()
                    || self.items.is_empty()
                    || eligible < displayed
                    || displayed != self.items.len()
                {
                    return Err(TruthError::InvalidChannel);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TruthError {
    InvalidChannel,
    InvalidConflict,
    InvalidBound,
    Overflow,
}

pub fn collapse_records(records: Vec<EvidenceRecord>) -> Result<Vec<EvidenceItem>, TruthError> {
    let mut grouped: BTreeMap<SourceKey, BTreeMap<PayloadTuple, EvidenceRecord>> = BTreeMap::new();
    for record in records {
        grouped
            .entry(record.source_key())
            .or_default()
            .entry(record.payload_tuple())
            .or_insert(record);
    }
    let mut items = Vec::with_capacity(grouped.len());
    for (source_key, variants) in grouped {
        if variants.len() == 1 {
            items.push(EvidenceItem::Event {
                record: variants.into_values().next().expect("one variant"),
            });
        } else {
            let variants: Vec<EvidenceRecord> = variants.into_values().collect();
            if variants.len() < 2
                || variants
                    .iter()
                    .any(|record| record.source_key() != source_key)
            {
                return Err(TruthError::InvalidConflict);
            }
            items.push(EvidenceItem::Conflict {
                source_key,
                variants,
            });
        }
    }
    items.sort_by(compare_items);
    Ok(items)
}

pub fn compare_items(left: &EvidenceItem, right: &EvidenceItem) -> Ordering {
    right
        .max_instant_ms()
        .cmp(&left.max_instant_ms())
        .then_with(|| left.channel().cmp(&right.channel()))
        .then_with(|| left.source_key().cmp(&right.source_key()))
        .then_with(|| left.payload_vector().cmp(&right.payload_vector()))
}

pub fn allocate_display(channels: &mut [ChannelView; 3], limit: usize) -> Result<(), TruthError> {
    let mut selected: [BTreeSet<usize>; 3] = std::array::from_fn(|_| BTreeSet::new());
    let mut used = 0usize;
    for (index, channel) in channels.iter().enumerate() {
        if !channel.items.is_empty() && used < limit {
            selected[index].insert(0);
            used += 1;
        }
    }
    let mut candidates = Vec::new();
    for (channel_index, channel) in channels.iter().enumerate() {
        for (item_index, item) in channel.items.iter().enumerate().skip(1) {
            candidates.push((channel_index, item_index, item.clone()));
        }
    }
    candidates.sort_by(|a, b| compare_items(&a.2, &b.2));
    for (channel_index, item_index, _) in candidates {
        if used >= limit {
            break;
        }
        selected[channel_index].insert(item_index);
        used += 1;
    }
    for (index, channel) in channels.iter_mut().enumerate() {
        let retained = channel
            .items
            .iter()
            .enumerate()
            .filter(|(item_index, _)| selected[index].contains(item_index))
            .map(|(_, item)| item.clone())
            .collect::<Vec<_>>();
        channel.items = retained;
        if channel.displayed_distinct_count.is_some() {
            channel.displayed_distinct_count = Some(channel.items.len());
        }
        channel.validate()?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedRows<T> {
    pub rows: Vec<T>,
    pub boundedness: Boundedness,
    pub acquired_count: usize,
}

impl<T> BoundedRows<T> {
    pub fn from_limit_plus_one(mut rows: Vec<T>, limit: usize) -> Result<Self, TruthError> {
        if rows.len() > limit.saturating_add(1) {
            return Err(TruthError::InvalidBound);
        }
        let boundedness = if rows.len() == limit.saturating_add(1) {
            rows.pop();
            Boundedness::KnownMore
        } else {
            Boundedness::ProvenEnd
        };
        let acquired_count = rows.len();
        Ok(Self {
            rows,
            boundedness,
            acquired_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Window contract
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RequestedWindowMs {
    pub from_inclusive: i64,
    pub to_inclusive: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct EffectiveWindowMs {
    pub from_inclusive: i64,
    pub to_inclusive: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowLifecycle {
    Moving,
    Frozen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct WindowGate {
    pub requested: RequestedWindowMs,
    pub effective: EffectiveWindowMs,
    pub observed_at_ms: i64,
    pub lifecycle: WindowLifecycle,
}

impl WindowGate {
    pub fn validate(
        requested: RequestedWindowMs,
        observed_at_ms: i64,
        lifecycle: WindowLifecycle,
    ) -> Result<Self, ValidationError> {
        if observed_at_ms <= 0 || requested.from_inclusive <= 0 {
            return Err(ValidationError::InvalidWindow);
        }
        let effective_to = requested.to_inclusive.unwrap_or(observed_at_ms);
        if effective_to <= 0
            || requested.from_inclusive > effective_to
            || effective_to > observed_at_ms
        {
            return Err(ValidationError::InvalidWindow);
        }
        let width = effective_to
            .checked_sub(requested.from_inclusive)
            .ok_or(ValidationError::Overflow)?;
        if width > MAX_WINDOW_MS {
            return Err(ValidationError::InvalidWindow);
        }
        if matches!(
            (lifecycle, requested.to_inclusive),
            (WindowLifecycle::Frozen, None) | (WindowLifecycle::Moving, Some(_))
        ) {
            return Err(ValidationError::InvalidWindow);
        }
        Ok(Self {
            requested,
            effective: EffectiveWindowMs {
                from_inclusive: requested.from_inclusive,
                to_inclusive: effective_to,
            },
            observed_at_ms,
            lifecycle,
        })
    }
}

pub fn ceil_millis_to_seconds(value: i64) -> Result<i64, ValidationError> {
    if value <= 0 {
        return Err(ValidationError::InvalidWindow);
    }
    value
        .checked_add(999)
        .map(|v| v.div_euclid(1_000))
        .ok_or(ValidationError::Overflow)
}

pub fn floor_millis_to_seconds(value: i64) -> Result<i64, ValidationError> {
    if value <= 0 {
        return Err(ValidationError::InvalidWindow);
    }
    Ok(value.div_euclid(1_000))
}

// ---------------------------------------------------------------------------
// Typed one-pass composer
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TemplateId {
    Dashboard,
    Incident,
    Topbar,
    InlineNotice,
    WindowChoice,
    Disclosure,
    FeedChannel,
    Event,
    IncidentRow,
    OperatorMark,
    Error,
    OpenIncidentForm,
    NoteForm,
    ResolveForm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BooleanAttributeKind {
    Checked,
    Hidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TokenDomain {
    Channel,
    ChannelState,
    Boundedness,
    SectionState,
    WindowLifecycle,
    IncidentLifecycle,
    Severity,
    MarkKind,
    ActorTruth,
    Current,
    AriaInvalid,
    GatewayContext,
    NoticeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FormField {
    CsrfToken,
    IncidentId,
    ExpectedLifecycle,
    ResolveCommandId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotKind {
    Text,
    Attribute,
    BooleanAttribute(BooleanAttributeKind),
    ClosedToken(TokenDomain),
    ProductPath,
    TrustedStaticUrl,
    StaticCss,
    Fragment(TemplateId),
    FragmentList(TemplateId),
    HiddenValue(FormField),
}

macro_rules! slots {
    ($($variant:ident => $marker:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub enum Slot { $($variant),+ }

        impl Slot {
            pub fn marker(self) -> &'static str {
                match self { $(Self::$variant => $marker),+ }
            }
        }
    };
}

slots! {
    StaticCss => "STATIC_CSS",
    TopbarFragment => "TOPBAR_FRAGMENT",
    DocumentTitleText => "DOCUMENT_TITLE_TEXT",
    HeadingTitleText => "HEADING_TITLE_TEXT",
    PageNoticeFragment => "PAGE_NOTICE_FRAGMENT",
    WindowRequestedText => "WINDOW_REQUESTED_TEXT",
    WindowEffectiveText => "WINDOW_EFFECTIVE_TEXT",
    WindowObservedText => "WINDOW_OBSERVED_TEXT",
    WindowObservedDatetimeAttribute => "WINDOW_OBSERVED_DATETIME_ATTRIBUTE",
    WindowLifecycleText => "WINDOW_LIFECYCLE_TEXT",
    WindowLifecycleToken => "WINDOW_LIFECYCLE_TOKEN",
    WindowChoicesFragment => "WINDOW_CHOICES_FRAGMENT",
    AuditChannelFragment => "AUDIT_CHANNEL_FRAGMENT",
    LogChannelFragment => "LOG_CHANNEL_FRAGMENT",
    MetricChannelFragment => "METRIC_CHANNEL_FRAGMENT",
    IncidentSectionStateText => "INCIDENT_SECTION_STATE_TEXT",
    IncidentSectionStateToken => "INCIDENT_SECTION_STATE_TOKEN",
    IncidentRowsFragmentList => "INCIDENT_ROWS_FRAGMENT_LIST",
    OpenIncidentFormFragment => "OPEN_INCIDENT_FORM_FRAGMENT",
    IncidentLifecycleText => "INCIDENT_LIFECYCLE_TEXT",
    IncidentLifecycleToken => "INCIDENT_LIFECYCLE_TOKEN",
    OperatorSectionStateText => "OPERATOR_SECTION_STATE_TEXT",
    OperatorSectionStateToken => "OPERATOR_SECTION_STATE_TOKEN",
    OperatorMarksFragmentList => "OPERATOR_MARKS_FRAGMENT_LIST",
    NoteFormFragment => "NOTE_FORM_FRAGMENT",
    ResolveFormFragment => "RESOLVE_FORM_FRAGMENT",
    ReturnPath => "RETURN_PATH",
    TopbarPageTitleText => "TOPBAR_PAGE_TITLE_TEXT",
    GatewayContextText => "GATEWAY_CONTEXT_TEXT",
    GatewayContextToken => "GATEWAY_CONTEXT_TOKEN",
    PortalUrl => "PORTAL_URL",
    LogoutUrl => "LOGOUT_URL",
    NoticeIdAttribute => "NOTICE_ID_ATTRIBUTE",
    NoticeKindToken => "NOTICE_KIND_TOKEN",
    NoticeHeadingText => "NOTICE_HEADING_TEXT",
    NoticeMessageText => "NOTICE_MESSAGE_TEXT",
    WindowChoicePath => "WINDOW_CHOICE_PATH",
    WindowChoiceText => "WINDOW_CHOICE_TEXT",
    WindowChoiceCurrentToken => "WINDOW_CHOICE_CURRENT_TOKEN",
    WindowChoiceAriaCurrentAttribute => "WINDOW_CHOICE_ARIA_CURRENT_ATTRIBUTE",
    DisclosureSummaryText => "DISCLOSURE_SUMMARY_TEXT",
    DisclosureBodyText => "DISCLOSURE_BODY_TEXT",
    ChannelToken => "CHANNEL_TOKEN",
    SourceLabelText => "SOURCE_LABEL_TEXT",
    StateText => "STATE_TEXT",
    StateToken => "STATE_TOKEN",
    StateDescriptionText => "STATE_DESCRIPTION_TEXT",
    CoverageText => "COVERAGE_TEXT",
    AcquiredCountText => "ACQUIRED_COUNT_TEXT",
    EligibleDistinctCountText => "ELIGIBLE_DISTINCT_COUNT_TEXT",
    DisplayedCountText => "DISPLAYED_COUNT_TEXT",
    DisplayAllocationText => "DISPLAY_ALLOCATION_TEXT",
    BoundednessText => "BOUNDEDNESS_TEXT",
    BoundednessToken => "BOUNDEDNESS_TOKEN",
    EventItemsFragmentList => "EVENT_ITEMS_FRAGMENT_LIST",
    RecordedText => "RECORDED_TEXT",
    RecordedDatetimeAttribute => "RECORDED_DATETIME_ATTRIBUTE",
    SeverityText => "SEVERITY_TEXT",
    SeverityToken => "SEVERITY_TOKEN",
    TitleText => "TITLE_TEXT",
    DetailPreviewText => "DETAIL_PREVIEW_TEXT",
    MachineValueText => "MACHINE_VALUE_TEXT",
    ProvenanceText => "PROVENANCE_TEXT",
    DisclosureFragment => "DISCLOSURE_FRAGMENT",
    ConflictFragment => "CONFLICT_FRAGMENT",
    IncidentPath => "INCIDENT_PATH",
    OpenedText => "OPENED_TEXT",
    OpenedDatetimeAttribute => "OPENED_DATETIME_ATTRIBUTE",
    ActorSubjectText => "ACTOR_SUBJECT_TEXT",
    DisplayIdentityText => "DISPLAY_IDENTITY_TEXT",
    ActorTruthToken => "ACTOR_TRUTH_TOKEN",
    LifecycleText => "LIFECYCLE_TEXT",
    LifecycleToken => "LIFECYCLE_TOKEN",
    CurrentText => "CURRENT_TEXT",
    CurrentToken => "CURRENT_TOKEN",
    MarkIdAttribute => "MARK_ID_ATTRIBUTE",
    MarkTypeText => "MARK_TYPE_TEXT",
    MarkTypeToken => "MARK_TYPE_TOKEN",
    BodyText => "BODY_TEXT",
    PublicMarkRefText => "PUBLIC_MARK_REF_TEXT",
    AuditTruthText => "AUDIT_TRUTH_TEXT",
    StatusCodeText => "STATUS_CODE_TEXT",
    SafeMessageText => "SAFE_MESSAGE_TEXT",
    RecoveryPath => "RECOVERY_PATH",
    OpenActionPath => "OPEN_ACTION_PATH",
    CsrfValueAttribute => "CSRF_VALUE_ATTRIBUTE",
    OpenTitleValueAttribute => "OPEN_TITLE_VALUE_ATTRIBUTE",
    OpenTitleInvalidToken => "OPEN_TITLE_INVALID_TOKEN",
    OpenWindow1CheckedAttribute => "OPEN_WINDOW_1_CHECKED_ATTRIBUTE",
    OpenWindow6CheckedAttribute => "OPEN_WINDOW_6_CHECKED_ATTRIBUTE",
    OpenWindow24CheckedAttribute => "OPEN_WINDOW_24_CHECKED_ATTRIBUTE",
    OpenWindow72CheckedAttribute => "OPEN_WINDOW_72_CHECKED_ATTRIBUTE",
    OpenWindow168CheckedAttribute => "OPEN_WINDOW_168_CHECKED_ATTRIBUTE",
    OpenWindowInvalidToken => "OPEN_WINDOW_INVALID_TOKEN",
    OpenErrorSummaryFragment => "OPEN_ERROR_SUMMARY_FRAGMENT",
    OpenTitleErrorText => "OPEN_TITLE_ERROR_TEXT",
    OpenTitleErrorHiddenAttribute => "OPEN_TITLE_ERROR_HIDDEN_ATTRIBUTE",
    OpenWindowErrorText => "OPEN_WINDOW_ERROR_TEXT",
    OpenWindowErrorHiddenAttribute => "OPEN_WINDOW_ERROR_HIDDEN_ATTRIBUTE",
    NoteActionPath => "NOTE_ACTION_PATH",
    MutationIncidentIdValueAttribute => "MUTATION_INCIDENT_ID_VALUE_ATTRIBUTE",
    NoteBodyText => "NOTE_BODY_TEXT",
    NoteBodyInvalidToken => "NOTE_BODY_INVALID_TOKEN",
    NoteErrorSummaryFragment => "NOTE_ERROR_SUMMARY_FRAGMENT",
    NoteBodyErrorText => "NOTE_BODY_ERROR_TEXT",
    NoteBodyErrorHiddenAttribute => "NOTE_BODY_ERROR_HIDDEN_ATTRIBUTE",
    ResolveActionPath => "RESOLVE_ACTION_PATH",
    ResolveExpectedLifecycleValueAttribute => "RESOLVE_EXPECTED_LIFECYCLE_VALUE_ATTRIBUTE",
    ResolveCommandIdValueAttribute => "RESOLVE_COMMAND_ID_VALUE_ATTRIBUTE",
    ResolveErrorSummaryFragment => "RESOLVE_ERROR_SUMMARY_FRAGMENT"
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComposeError {
    MalformedMarker,
    UnknownSlot,
    MissingSlot,
    DuplicateSlot,
    UnexpectedSlot,
    WrongValueKind,
    EmptyValueForbidden,
    InvalidProductPath,
    InvalidTrustedUrl,
    InvalidClosedToken,
    CrossSlotInvariant,
    UnresolvedMarker,
}

#[derive(Clone, Debug)]
pub struct EscapedText(String);

impl EscapedText {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug)]
pub struct EscapedAttribute(String);

impl EscapedAttribute {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TypedBooleanAttribute {
    kind: BooleanAttributeKind,
    present: bool,
}

impl TypedBooleanAttribute {
    pub fn checked(present: bool) -> Self {
        Self {
            kind: BooleanAttributeKind::Checked,
            present,
        }
    }

    pub fn hidden(present: bool) -> Self {
        Self {
            kind: BooleanAttributeKind::Hidden,
            present,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClosedToken {
    domain: TokenDomain,
    value: &'static str,
}

impl ClosedToken {
    pub fn new(domain: TokenDomain, value: &'static str) -> Result<Self, ComposeError> {
        valid_token(domain, value)
            .then_some(Self { domain, value })
            .ok_or(ComposeError::InvalidClosedToken)
    }
}

#[derive(Clone, Debug)]
pub enum ProductRelativePath {
    Root,
    DashboardWindow(i64),
    Incident(IncidentId),
    OpenIncident,
    AddNote(IncidentId),
    Resolve(IncidentId),
    IncidentOpened(IncidentId),
    NoteAdded(IncidentId, NoteId),
    Resolved(IncidentId, PublicMarkRef),
}

impl ProductRelativePath {
    pub fn as_string(&self) -> Result<String, ComposeError> {
        Ok(match self {
            Self::Root => "/".to_string(),
            Self::DashboardWindow(hours) if [1, 6, 24, 72, 168].contains(hours) => {
                format!("/?window={hours}")
            }
            Self::DashboardWindow(_) => return Err(ComposeError::InvalidProductPath),
            Self::Incident(id) => format!("/incident/{id}"),
            Self::OpenIncident => "/api/incidents".to_string(),
            Self::AddNote(id) => format!("/api/incidents/{id}/notes"),
            Self::Resolve(id) => format!("/api/incidents/{id}/resolve"),
            Self::IncidentOpened(id) => format!("/incident/{id}#incident-opened"),
            Self::NoteAdded(id, note) => format!("/incident/{id}#{note}"),
            Self::Resolved(id, mark) => format!("/incident/{id}#{}", mark.as_str()),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TrustedStaticUrl {
    Portal,
    Logout,
}

impl TrustedStaticUrl {
    fn as_str(self) -> &'static str {
        match self {
            Self::Portal => "https://w33d.xyz",
            Self::Logout => "https://sso.w33d.xyz/_gw/auth/logout",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TypedHiddenValue {
    field: FormField,
    value: String,
}

impl TypedHiddenValue {
    pub fn csrf(value: &CsrfToken) -> Self {
        Self {
            field: FormField::CsrfToken,
            value: value.as_str().to_string(),
        }
    }

    pub fn incident_id(value: &IncidentId) -> Self {
        Self {
            field: FormField::IncidentId,
            value: value.as_str().to_string(),
        }
    }

    pub fn expected_open(value: ExpectedOpen) -> Self {
        Self {
            field: FormField::ExpectedLifecycle,
            value: value.as_str().to_string(),
        }
    }

    pub fn resolve_command_id(value: &ResolveCommandId) -> Self {
        Self {
            field: FormField::ResolveCommandId,
            value: value.as_str().to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StaticCssValue(&'static str);

impl StaticCssValue {
    pub(crate) fn application() -> Self {
        Self(crate::handlers::APP_CSS_PATH)
    }
}

#[derive(Clone, Debug)]
pub struct RenderedFragment {
    template: TemplateId,
    bytes: String,
    typed_empty: bool,
    semantic: FragmentSemantic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FragmentSemantic {
    Opaque,
    WindowChoice {
        hours: i64,
        current: bool,
    },
    FeedChannel {
        channel: &'static str,
        displayed_count: usize,
    },
    OperatorMark {
        kind: &'static str,
    },
    Event {
        channel: &'static str,
        source_key: Option<Box<SourceKey>>,
        payload: Option<Box<PayloadTuple>>,
        has_conflict: bool,
    },
}

impl RenderedFragment {
    pub fn as_str(&self) -> &str {
        &self.bytes
    }

    pub fn into_string(self) -> String {
        self.bytes
    }

    pub fn typed_empty(template: TemplateId) -> Self {
        Self {
            template,
            bytes: String::new(),
            typed_empty: true,
            semantic: FragmentSemantic::Opaque,
        }
    }

    pub(crate) fn with_evidence_record(
        mut self,
        record: &EvidenceRecord,
    ) -> Result<Self, ComposeError> {
        let expected_channel = channel_token_value(record.channel());
        match &mut self.semantic {
            FragmentSemantic::Event {
                channel,
                source_key,
                payload,
                has_conflict: false,
            } if *channel == expected_channel && source_key.is_none() && payload.is_none() => {
                *source_key = Some(Box::new(record.source_key()));
                *payload = Some(Box::new(record.payload_tuple()));
                Ok(self)
            }
            _ => Err(ComposeError::CrossSlotInvariant),
        }
    }
}

#[derive(Clone, Debug)]
pub enum SlotValue {
    Text(EscapedText),
    Attribute(EscapedAttribute),
    BooleanAttribute(TypedBooleanAttribute),
    ClosedToken(ClosedToken),
    ProductPath(ProductRelativePath),
    TrustedStaticUrl(TrustedStaticUrl),
    StaticCss(StaticCssValue),
    Fragment(RenderedFragment),
    FragmentList(Vec<RenderedFragment>),
    HiddenValue(TypedHiddenValue),
}

#[derive(Clone, Copy)]
struct SlotSpec {
    slot: Slot,
    kind: SlotKind,
    empty: bool,
}

pub struct Composer;

impl Composer {
    pub fn validate_all_templates() -> Result<(), ComposeError> {
        for template in [
            TemplateId::Dashboard,
            TemplateId::Incident,
            TemplateId::Topbar,
            TemplateId::InlineNotice,
            TemplateId::WindowChoice,
            TemplateId::Disclosure,
            TemplateId::FeedChannel,
            TemplateId::Event,
            TemplateId::IncidentRow,
            TemplateId::OperatorMark,
            TemplateId::Error,
            TemplateId::OpenIncidentForm,
            TemplateId::NoteForm,
            TemplateId::ResolveForm,
        ] {
            validate_template_inventory(template)?;
        }
        Ok(())
    }

    pub fn render(
        template: TemplateId,
        values: Vec<(Slot, SlotValue)>,
    ) -> Result<RenderedFragment, ComposeError> {
        validate_template_inventory(template)?;
        let specs = template_specs(template);
        let mut by_slot = BTreeMap::new();
        for (slot, value) in values {
            if by_slot.insert(slot, value).is_some() {
                return Err(ComposeError::DuplicateSlot);
            }
        }
        if by_slot
            .keys()
            .any(|slot| !specs.iter().any(|spec| spec.slot == *slot))
        {
            return Err(ComposeError::UnexpectedSlot);
        }
        for spec in &specs {
            let value = by_slot.get(&spec.slot).ok_or(ComposeError::MissingSlot)?;
            validate_slot_value(*spec, value)?;
        }
        validate_cross_slot_invariants(template, &by_slot)?;

        let source = template_source(template);
        let mut output = String::with_capacity(source.len() + 1_024);
        let mut cursor = 0usize;
        while let Some(relative) = source[cursor..].find("[[W33D:") {
            let start = cursor + relative;
            output.push_str(&source[cursor..start]);
            let name_start = start + "[[W33D:".len();
            let tail = &source[name_start..];
            let end_relative = tail.find("]]").ok_or(ComposeError::MalformedMarker)?;
            let end = name_start + end_relative;
            let name = &source[name_start..end];
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
            {
                return Err(ComposeError::MalformedMarker);
            }
            let spec = specs
                .iter()
                .find(|spec| spec.slot.marker() == name)
                .ok_or(ComposeError::UnknownSlot)?;
            let value = by_slot.get(&spec.slot).ok_or(ComposeError::MissingSlot)?;
            output.push_str(&serialize_slot_value(value)?);
            cursor = end + 2;
        }
        output.push_str(&source[cursor..]);
        let semantic = fragment_semantic(template, &by_slot)?;
        Ok(RenderedFragment {
            template,
            bytes: output,
            typed_empty: false,
            semantic,
        })
    }
}

fn fragment_semantic(
    template: TemplateId,
    values: &BTreeMap<Slot, SlotValue>,
) -> Result<FragmentSemantic, ComposeError> {
    match template {
        TemplateId::WindowChoice => {
            let hours = match values.get(&Slot::WindowChoicePath) {
                Some(SlotValue::ProductPath(ProductRelativePath::DashboardWindow(hours))) => *hours,
                _ => return Err(ComposeError::CrossSlotInvariant),
            };
            let current = match values.get(&Slot::WindowChoiceCurrentToken) {
                Some(SlotValue::ClosedToken(ClosedToken {
                    value: "current", ..
                })) => true,
                Some(SlotValue::ClosedToken(ClosedToken {
                    value: "not-current",
                    ..
                })) => false,
                _ => return Err(ComposeError::CrossSlotInvariant),
            };
            Ok(FragmentSemantic::WindowChoice { hours, current })
        }
        TemplateId::FeedChannel => {
            let channel = closed_token_value(values, Slot::ChannelToken)?;
            let displayed_count = fragment_list(values, Slot::EventItemsFragmentList)?.len();
            Ok(FragmentSemantic::FeedChannel {
                channel,
                displayed_count,
            })
        }
        TemplateId::OperatorMark => {
            let kind = closed_token_value(values, Slot::MarkTypeToken)?;
            Ok(FragmentSemantic::OperatorMark { kind })
        }
        TemplateId::Event => {
            let channel = closed_token_value(values, Slot::ChannelToken)?;
            let conflicts = fragment_list(values, Slot::ConflictFragment)?;
            if conflicts.is_empty() {
                Ok(FragmentSemantic::Event {
                    channel,
                    source_key: None,
                    payload: None,
                    has_conflict: false,
                })
            } else {
                let source_key = match &conflicts[0].semantic {
                    FragmentSemantic::Event {
                        source_key: Some(source_key),
                        ..
                    } => source_key.as_ref().clone(),
                    _ => return Err(ComposeError::CrossSlotInvariant),
                };
                Ok(FragmentSemantic::Event {
                    channel,
                    source_key: Some(Box::new(source_key)),
                    payload: None,
                    has_conflict: true,
                })
            }
        }
        _ => Ok(FragmentSemantic::Opaque),
    }
}

fn channel_token_value(channel: ChannelId) -> &'static str {
    match channel {
        ChannelId::Audit => "audit",
        ChannelId::Log => "log",
        ChannelId::Metric => "metric",
    }
}

fn template_source(template: TemplateId) -> &'static str {
    match template {
        TemplateId::Dashboard => include_str!("../templates/dashboard.html"),
        TemplateId::Incident => include_str!("../templates/incident.html"),
        TemplateId::Topbar => include_str!("../templates/fragments/topbar.html"),
        TemplateId::InlineNotice => include_str!("../templates/fragments/inline_notice.html"),
        TemplateId::WindowChoice => include_str!("../templates/fragments/window_choice.html"),
        TemplateId::Disclosure => include_str!("../templates/fragments/disclosure.html"),
        TemplateId::FeedChannel => include_str!("../templates/fragments/feed_channel.html"),
        TemplateId::Event => include_str!("../templates/fragments/event.html"),
        TemplateId::IncidentRow => include_str!("../templates/fragments/incident_row.html"),
        TemplateId::OperatorMark => include_str!("../templates/fragments/note.html"),
        TemplateId::Error => include_str!("../templates/fragments/error.html"),
        TemplateId::OpenIncidentForm => {
            include_str!("../templates/fragments/open_incident_form.html")
        }
        TemplateId::NoteForm => include_str!("../templates/fragments/note_form.html"),
        TemplateId::ResolveForm => include_str!("../templates/fragments/resolve_form.html"),
    }
}

macro_rules! spec {
    ($slot:ident, $kind:expr, $empty:expr) => {
        SlotSpec {
            slot: Slot::$slot,
            kind: $kind,
            empty: $empty,
        }
    };
}

fn template_specs(template: TemplateId) -> Vec<SlotSpec> {
    use SlotKind::*;
    use TemplateId::*;
    use TokenDomain::*;
    match template {
        Dashboard => vec![
            spec!(StaticCss, StaticCss, false),
            spec!(TopbarFragment, Fragment(Topbar), false),
            spec!(DocumentTitleText, Text, false),
            spec!(HeadingTitleText, Text, false),
            spec!(PageNoticeFragment, Fragment(InlineNotice), true),
            spec!(WindowRequestedText, Text, false),
            spec!(WindowEffectiveText, Text, false),
            spec!(WindowObservedText, Text, false),
            spec!(WindowObservedDatetimeAttribute, Attribute, false),
            spec!(WindowLifecycleText, Text, false),
            spec!(WindowLifecycleToken, ClosedToken(WindowLifecycle), false),
            spec!(WindowChoicesFragment, FragmentList(WindowChoice), false),
            spec!(AuditChannelFragment, Fragment(FeedChannel), false),
            spec!(LogChannelFragment, Fragment(FeedChannel), false),
            spec!(MetricChannelFragment, Fragment(FeedChannel), false),
            spec!(IncidentSectionStateText, Text, false),
            spec!(IncidentSectionStateToken, ClosedToken(SectionState), false),
            spec!(IncidentRowsFragmentList, FragmentList(IncidentRow), true),
            spec!(OpenIncidentFormFragment, Fragment(OpenIncidentForm), false),
        ],
        Incident => vec![
            spec!(StaticCss, StaticCss, false),
            spec!(TopbarFragment, Fragment(Topbar), false),
            spec!(DocumentTitleText, Text, false),
            spec!(HeadingTitleText, Text, false),
            spec!(IncidentLifecycleText, Text, false),
            spec!(
                IncidentLifecycleToken,
                ClosedToken(IncidentLifecycle),
                false
            ),
            spec!(PageNoticeFragment, Fragment(InlineNotice), true),
            spec!(WindowRequestedText, Text, false),
            spec!(WindowEffectiveText, Text, false),
            spec!(WindowObservedText, Text, false),
            spec!(WindowObservedDatetimeAttribute, Attribute, false),
            spec!(WindowLifecycleText, Text, false),
            spec!(WindowLifecycleToken, ClosedToken(WindowLifecycle), false),
            spec!(AuditChannelFragment, Fragment(FeedChannel), false),
            spec!(LogChannelFragment, Fragment(FeedChannel), false),
            spec!(MetricChannelFragment, Fragment(FeedChannel), false),
            spec!(OperatorSectionStateText, Text, false),
            spec!(OperatorSectionStateToken, ClosedToken(SectionState), false),
            spec!(OperatorMarksFragmentList, FragmentList(OperatorMark), false),
            spec!(NoteFormFragment, Fragment(NoteForm), false),
            spec!(ResolveFormFragment, Fragment(ResolveForm), true),
            spec!(ReturnPath, ProductPath, false),
        ],
        Topbar => vec![
            spec!(TopbarPageTitleText, Text, false),
            spec!(GatewayContextText, Text, false),
            spec!(GatewayContextToken, ClosedToken(GatewayContext), false),
            spec!(PortalUrl, TrustedStaticUrl, false),
            spec!(LogoutUrl, TrustedStaticUrl, false),
        ],
        InlineNotice => vec![
            spec!(NoticeIdAttribute, Attribute, false),
            spec!(NoticeKindToken, ClosedToken(NoticeKind), false),
            spec!(NoticeHeadingText, Text, false),
            spec!(NoticeMessageText, Text, false),
        ],
        WindowChoice => vec![
            spec!(WindowChoicePath, ProductPath, false),
            spec!(WindowChoiceText, Text, false),
            spec!(WindowChoiceCurrentToken, ClosedToken(Current), false),
            spec!(WindowChoiceAriaCurrentAttribute, Attribute, false),
        ],
        Disclosure => vec![
            spec!(DisclosureSummaryText, Text, false),
            spec!(DisclosureBodyText, Text, false),
        ],
        FeedChannel => vec![
            spec!(ChannelToken, ClosedToken(Channel), false),
            spec!(SourceLabelText, Text, false),
            spec!(StateText, Text, false),
            spec!(StateToken, ClosedToken(ChannelState), false),
            spec!(StateDescriptionText, Text, false),
            spec!(CoverageText, Text, false),
            spec!(AcquiredCountText, Text, false),
            spec!(EligibleDistinctCountText, Text, false),
            spec!(DisplayedCountText, Text, false),
            spec!(DisplayAllocationText, Text, false),
            spec!(BoundednessText, Text, false),
            spec!(BoundednessToken, ClosedToken(Boundedness), false),
            spec!(EventItemsFragmentList, FragmentList(Event), true),
        ],
        Event => vec![
            spec!(ChannelToken, ClosedToken(Channel), false),
            spec!(RecordedText, Text, false),
            spec!(RecordedDatetimeAttribute, Attribute, false),
            spec!(SeverityText, Text, false),
            spec!(SeverityToken, ClosedToken(Severity), false),
            spec!(TitleText, Text, false),
            spec!(DetailPreviewText, Text, true),
            spec!(MachineValueText, Text, true),
            spec!(ProvenanceText, Text, false),
            spec!(DisclosureFragment, Fragment(Disclosure), true),
            spec!(ConflictFragment, FragmentList(Event), true),
        ],
        IncidentRow => vec![
            spec!(IncidentPath, ProductPath, false),
            spec!(TitleText, Text, false),
            spec!(OpenedText, Text, false),
            spec!(OpenedDatetimeAttribute, Attribute, false),
            spec!(ActorSubjectText, Text, false),
            spec!(DisplayIdentityText, Text, false),
            spec!(ActorTruthToken, ClosedToken(ActorTruth), false),
            spec!(LifecycleText, Text, false),
            spec!(LifecycleToken, ClosedToken(IncidentLifecycle), false),
            spec!(CurrentText, Text, true),
            spec!(CurrentToken, ClosedToken(Current), false),
        ],
        OperatorMark => vec![
            spec!(MarkIdAttribute, Attribute, false),
            spec!(MarkTypeText, Text, false),
            spec!(MarkTypeToken, ClosedToken(MarkKind), false),
            spec!(ActorSubjectText, Text, false),
            spec!(DisplayIdentityText, Text, false),
            spec!(ActorTruthToken, ClosedToken(ActorTruth), false),
            spec!(RecordedText, Text, false),
            spec!(RecordedDatetimeAttribute, Attribute, false),
            spec!(BodyText, Text, false),
            spec!(LifecycleText, Text, true),
            spec!(PublicMarkRefText, Text, true),
            spec!(AuditTruthText, Text, false),
        ],
        Error => vec![
            spec!(StaticCss, StaticCss, false),
            spec!(TopbarFragment, Fragment(Topbar), false),
            spec!(DocumentTitleText, Text, false),
            spec!(HeadingTitleText, Text, false),
            spec!(StatusCodeText, Text, false),
            spec!(SafeMessageText, Text, false),
            spec!(RecoveryPath, ProductPath, false),
        ],
        OpenIncidentForm => vec![
            spec!(OpenActionPath, ProductPath, false),
            spec!(CsrfValueAttribute, HiddenValue(FormField::CsrfToken), false),
            spec!(OpenTitleValueAttribute, Attribute, true),
            spec!(OpenTitleInvalidToken, ClosedToken(AriaInvalid), false),
            spec!(
                OpenWindow1CheckedAttribute,
                BooleanAttribute(BooleanAttributeKind::Checked),
                true
            ),
            spec!(
                OpenWindow6CheckedAttribute,
                BooleanAttribute(BooleanAttributeKind::Checked),
                true
            ),
            spec!(
                OpenWindow24CheckedAttribute,
                BooleanAttribute(BooleanAttributeKind::Checked),
                true
            ),
            spec!(
                OpenWindow72CheckedAttribute,
                BooleanAttribute(BooleanAttributeKind::Checked),
                true
            ),
            spec!(
                OpenWindow168CheckedAttribute,
                BooleanAttribute(BooleanAttributeKind::Checked),
                true
            ),
            spec!(OpenWindowInvalidToken, ClosedToken(AriaInvalid), false),
            spec!(OpenErrorSummaryFragment, Fragment(InlineNotice), true),
            spec!(OpenTitleErrorText, Text, true),
            spec!(
                OpenTitleErrorHiddenAttribute,
                BooleanAttribute(BooleanAttributeKind::Hidden),
                true
            ),
            spec!(OpenWindowErrorText, Text, true),
            spec!(
                OpenWindowErrorHiddenAttribute,
                BooleanAttribute(BooleanAttributeKind::Hidden),
                true
            ),
        ],
        NoteForm => vec![
            spec!(NoteActionPath, ProductPath, false),
            spec!(CsrfValueAttribute, HiddenValue(FormField::CsrfToken), false),
            spec!(
                MutationIncidentIdValueAttribute,
                HiddenValue(FormField::IncidentId),
                false
            ),
            spec!(NoteBodyText, Text, true),
            spec!(NoteBodyInvalidToken, ClosedToken(AriaInvalid), false),
            spec!(NoteErrorSummaryFragment, Fragment(InlineNotice), true),
            spec!(NoteBodyErrorText, Text, true),
            spec!(
                NoteBodyErrorHiddenAttribute,
                BooleanAttribute(BooleanAttributeKind::Hidden),
                true
            ),
        ],
        ResolveForm => vec![
            spec!(ResolveActionPath, ProductPath, false),
            spec!(CsrfValueAttribute, HiddenValue(FormField::CsrfToken), false),
            spec!(
                MutationIncidentIdValueAttribute,
                HiddenValue(FormField::IncidentId),
                false
            ),
            spec!(
                ResolveExpectedLifecycleValueAttribute,
                HiddenValue(FormField::ExpectedLifecycle),
                false
            ),
            spec!(
                ResolveCommandIdValueAttribute,
                HiddenValue(FormField::ResolveCommandId),
                false
            ),
            spec!(ResolveErrorSummaryFragment, Fragment(InlineNotice), true),
        ],
    }
}

fn validate_template_inventory(template: TemplateId) -> Result<(), ComposeError> {
    let source = template_source(template);
    let specs = template_specs(template);
    let mut counts = BTreeMap::<String, usize>::new();
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find("[[W33D:") {
        let start = cursor + relative + "[[W33D:".len();
        let tail = &source[start..];
        let end_relative = tail.find("]]").ok_or(ComposeError::MalformedMarker)?;
        let name = &tail[..end_relative];
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
        {
            return Err(ComposeError::MalformedMarker);
        }
        *counts.entry(name.to_string()).or_default() += 1;
        cursor = start + end_relative + 2;
    }
    if counts.values().any(|count| *count > 1) {
        return Err(ComposeError::DuplicateSlot);
    }
    if counts
        .keys()
        .any(|name| !specs.iter().any(|spec| spec.slot.marker() == name))
    {
        return Err(ComposeError::UnknownSlot);
    }
    if specs
        .iter()
        .any(|spec| counts.get(spec.slot.marker()) != Some(&1))
    {
        return Err(ComposeError::MissingSlot);
    }
    Ok(())
}

fn validate_slot_value(spec: SlotSpec, value: &SlotValue) -> Result<(), ComposeError> {
    let (kind_matches, empty) = match value {
        SlotValue::Text(value) => (spec.kind == SlotKind::Text, value.0.is_empty()),
        SlotValue::Attribute(value) => (spec.kind == SlotKind::Attribute, value.0.is_empty()),
        SlotValue::BooleanAttribute(value) => (
            spec.kind == SlotKind::BooleanAttribute(value.kind),
            !value.present,
        ),
        SlotValue::ClosedToken(value) => (
            spec.kind == SlotKind::ClosedToken(value.domain)
                && valid_token(value.domain, value.value),
            false,
        ),
        SlotValue::ProductPath(_) => (spec.kind == SlotKind::ProductPath, false),
        SlotValue::TrustedStaticUrl(_) => (spec.kind == SlotKind::TrustedStaticUrl, false),
        SlotValue::StaticCss(value) => (
            spec.kind == SlotKind::StaticCss && value.0 == crate::handlers::APP_CSS_PATH,
            value.0.is_empty(),
        ),
        SlotValue::Fragment(value) => (
            matches!(spec.kind, SlotKind::Fragment(template) if template == value.template),
            value.bytes.is_empty(),
        ),
        SlotValue::FragmentList(values) => (
            matches!(
                spec.kind,
                SlotKind::FragmentList(template)
                    if values.iter().all(|value| value.template == template && !value.typed_empty)
            ),
            values.is_empty(),
        ),
        SlotValue::HiddenValue(value) => (
            spec.kind == SlotKind::HiddenValue(value.field),
            value.value.is_empty(),
        ),
    };
    if !kind_matches {
        return Err(ComposeError::WrongValueKind);
    }
    if empty && !spec.empty {
        return Err(ComposeError::EmptyValueForbidden);
    }
    Ok(())
}

fn validate_cross_slot_invariants(
    template: TemplateId,
    values: &BTreeMap<Slot, SlotValue>,
) -> Result<(), ComposeError> {
    if template == TemplateId::WindowChoice {
        let path_hours = match values.get(&Slot::WindowChoicePath) {
            Some(SlotValue::ProductPath(ProductRelativePath::DashboardWindow(hours))) => *hours,
            _ => return Err(ComposeError::CrossSlotInvariant),
        };
        if ![1, 6, 24, 72, 168].contains(&path_hours) {
            return Err(ComposeError::InvalidProductPath);
        }
        let current = closed_token_value(values, Slot::WindowChoiceCurrentToken)? == "current";
        let aria_current = match values.get(&Slot::WindowChoiceAriaCurrentAttribute) {
            Some(SlotValue::Attribute(EscapedAttribute(value))) => value.as_str(),
            _ => return Err(ComposeError::WrongValueKind),
        };
        if aria_current != if current { "page" } else { "false" } {
            return Err(ComposeError::CrossSlotInvariant);
        }
    }
    if template == TemplateId::Dashboard {
        validate_global_channel_cardinality(values)?;

        let choices = fragment_list(values, Slot::WindowChoicesFragment)?;
        if choices.len() != 5 {
            return Err(ComposeError::CrossSlotInvariant);
        }
        let mut hours = Vec::with_capacity(choices.len());
        let mut current_count = 0usize;
        for choice in choices {
            let FragmentSemantic::WindowChoice {
                hours: choice_hours,
                current,
            } = choice.semantic
            else {
                return Err(ComposeError::CrossSlotInvariant);
            };
            hours.push(choice_hours);
            current_count += usize::from(current);
        }
        if hours != [1, 6, 24, 72, 168] || current_count != 1 {
            return Err(ComposeError::CrossSlotInvariant);
        }

        let incidents = fragment_list(values, Slot::IncidentRowsFragmentList)?;
        if incidents.len() > INCIDENT_LIMIT {
            return Err(ComposeError::CrossSlotInvariant);
        }
        validate_section_cardinality(
            closed_token_value(values, Slot::IncidentSectionStateToken)?,
            incidents.len(),
        )?;
    }
    if template == TemplateId::FeedChannel {
        let channel = closed_token_value(values, Slot::ChannelToken)?;
        let state = closed_token_value(values, Slot::StateToken)?;
        let boundedness = closed_token_value(values, Slot::BoundednessToken)?;
        let events = fragment_list(values, Slot::EventItemsFragmentList)?;
        if events.len() > DISPLAY_LIMIT {
            return Err(ComposeError::CrossSlotInvariant);
        }
        if state == "loaded-non-empty" {
            if events.is_empty()
                || !matches!(
                    boundedness,
                    "known-more" | "proven-end" | "completeness-unknown"
                )
            {
                return Err(ComposeError::CrossSlotInvariant);
            }
        } else if !events.is_empty() || boundedness != "not-applicable" {
            return Err(ComposeError::CrossSlotInvariant);
        }
        for event in events {
            match &event.semantic {
                FragmentSemantic::Event {
                    channel: event_channel,
                    source_key: Some(_),
                    payload: Some(_),
                    has_conflict: false,
                } if *event_channel == channel => {}
                FragmentSemantic::Event {
                    channel: event_channel,
                    source_key: Some(_),
                    payload: None,
                    has_conflict: true,
                } if *event_channel == channel => {}
                _ => return Err(ComposeError::CrossSlotInvariant),
            }
        }
    }
    if template == TemplateId::Incident {
        validate_global_channel_cardinality(values)?;

        let lifecycle = closed_token_value(values, Slot::IncidentLifecycleToken)?;
        let marks = fragment_list(values, Slot::OperatorMarksFragmentList)?;
        if marks.is_empty() || marks.len() > NOTE_LIMIT + 2 {
            return Err(ComposeError::CrossSlotInvariant);
        }
        let kinds = marks
            .iter()
            .map(|mark| match mark.semantic {
                FragmentSemantic::OperatorMark { kind } => Ok(kind),
                _ => Err(ComposeError::CrossSlotInvariant),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if kinds.first() != Some(&"incident-opened") {
            return Err(ComposeError::CrossSlotInvariant);
        }
        let resolved_marks = kinds
            .iter()
            .filter(|kind| **kind == "incident-resolved")
            .count();
        let note_count = kinds.iter().filter(|kind| **kind == "note-added").count();
        let expected_len = 1usize
            .checked_add(note_count)
            .and_then(|count| count.checked_add(resolved_marks))
            .ok_or(ComposeError::CrossSlotInvariant)?;
        if expected_len != kinds.len()
            || note_count > NOTE_LIMIT
            || resolved_marks > 1
            || (resolved_marks == 1 && kinds.last() != Some(&"incident-resolved"))
        {
            return Err(ComposeError::CrossSlotInvariant);
        }
        let resolve_form = fragment(values, Slot::ResolveFormFragment)?;
        match lifecycle {
            "open" if resolved_marks == 0 && !resolve_form.typed_empty => {}
            "resolved" if resolved_marks == 1 && resolve_form.typed_empty => {}
            _ => return Err(ComposeError::CrossSlotInvariant),
        }
        validate_section_cardinality(
            closed_token_value(values, Slot::OperatorSectionStateToken)?,
            note_count,
        )?;
    }
    if template == TemplateId::OpenIncidentForm {
        let checked = [
            Slot::OpenWindow1CheckedAttribute,
            Slot::OpenWindow6CheckedAttribute,
            Slot::OpenWindow24CheckedAttribute,
            Slot::OpenWindow72CheckedAttribute,
            Slot::OpenWindow168CheckedAttribute,
        ]
        .into_iter()
        .filter(|slot| {
            matches!(
                values.get(slot),
                Some(SlotValue::BooleanAttribute(TypedBooleanAttribute {
                    present: true,
                    ..
                }))
            )
        })
        .count();
        if checked != 1 {
            return Err(ComposeError::CrossSlotInvariant);
        }
        validate_field_error(
            values,
            Slot::OpenTitleInvalidToken,
            Slot::OpenTitleErrorText,
            Slot::OpenTitleErrorHiddenAttribute,
        )?;
        validate_field_error(
            values,
            Slot::OpenWindowInvalidToken,
            Slot::OpenWindowErrorText,
            Slot::OpenWindowErrorHiddenAttribute,
        )?;
    }
    if template == TemplateId::NoteForm {
        validate_field_error(
            values,
            Slot::NoteBodyInvalidToken,
            Slot::NoteBodyErrorText,
            Slot::NoteBodyErrorHiddenAttribute,
        )?;
    }
    if template == TemplateId::Event {
        let channel = closed_token_value(values, Slot::ChannelToken)?;
        let conflicts = fragment_list(values, Slot::ConflictFragment)?;
        if conflicts.len() == 1 || conflicts.len() > DISPLAY_LIMIT {
            return Err(ComposeError::CrossSlotInvariant);
        }
        let mut expected_source = None;
        let mut previous_payload = None;
        for conflict in conflicts {
            let FragmentSemantic::Event {
                channel: conflict_channel,
                source_key: Some(source_key),
                payload: Some(payload),
                has_conflict: false,
            } = &conflict.semantic
            else {
                return Err(ComposeError::CrossSlotInvariant);
            };
            if *conflict_channel != channel {
                return Err(ComposeError::CrossSlotInvariant);
            }
            if let Some(expected) = &expected_source {
                if expected != source_key {
                    return Err(ComposeError::CrossSlotInvariant);
                }
            } else {
                expected_source = Some(source_key.clone());
            }
            if previous_payload
                .as_ref()
                .is_some_and(|previous| previous >= payload)
            {
                return Err(ComposeError::CrossSlotInvariant);
            }
            previous_payload = Some(payload.clone());
        }
    }
    Ok(())
}

fn closed_token_value(
    values: &BTreeMap<Slot, SlotValue>,
    slot: Slot,
) -> Result<&'static str, ComposeError> {
    match values.get(&slot) {
        Some(SlotValue::ClosedToken(ClosedToken { value, .. })) => Ok(value),
        _ => Err(ComposeError::WrongValueKind),
    }
}

fn fragment_list(
    values: &BTreeMap<Slot, SlotValue>,
    slot: Slot,
) -> Result<&[RenderedFragment], ComposeError> {
    match values.get(&slot) {
        Some(SlotValue::FragmentList(fragments)) => Ok(fragments),
        _ => Err(ComposeError::WrongValueKind),
    }
}

fn fragment(
    values: &BTreeMap<Slot, SlotValue>,
    slot: Slot,
) -> Result<&RenderedFragment, ComposeError> {
    match values.get(&slot) {
        Some(SlotValue::Fragment(fragment)) => Ok(fragment),
        _ => Err(ComposeError::WrongValueKind),
    }
}

fn channel_display_count(
    values: &BTreeMap<Slot, SlotValue>,
    slot: Slot,
    expected: &'static str,
) -> Result<usize, ComposeError> {
    let channel = fragment(values, slot)?;
    match channel.semantic {
        FragmentSemantic::FeedChannel {
            channel,
            displayed_count,
        } if channel == expected => Ok(displayed_count),
        _ => Err(ComposeError::CrossSlotInvariant),
    }
}

fn validate_global_channel_cardinality(
    values: &BTreeMap<Slot, SlotValue>,
) -> Result<(), ComposeError> {
    let displayed = [
        channel_display_count(values, Slot::AuditChannelFragment, "audit")?,
        channel_display_count(values, Slot::LogChannelFragment, "log")?,
        channel_display_count(values, Slot::MetricChannelFragment, "metric")?,
    ]
    .into_iter()
    .try_fold(0usize, |total, count| total.checked_add(count))
    .ok_or(ComposeError::CrossSlotInvariant)?;
    if displayed > DISPLAY_LIMIT {
        Err(ComposeError::CrossSlotInvariant)
    } else {
        Ok(())
    }
}

fn validate_section_cardinality(state: &str, rows: usize) -> Result<(), ComposeError> {
    match state {
        "loaded-known-more" | "loaded-proven-end" if rows > 0 => Ok(()),
        "loaded-empty" | "unavailable" if rows == 0 => Ok(()),
        _ => Err(ComposeError::CrossSlotInvariant),
    }
}

fn validate_field_error(
    values: &BTreeMap<Slot, SlotValue>,
    invalid_slot: Slot,
    text_slot: Slot,
    hidden_slot: Slot,
) -> Result<(), ComposeError> {
    let invalid = matches!(
        values.get(&invalid_slot),
        Some(SlotValue::ClosedToken(ClosedToken { value: "true", .. }))
    );
    let text_empty = matches!(
        values.get(&text_slot),
        Some(SlotValue::Text(EscapedText(value))) if value.is_empty()
    );
    let hidden = matches!(
        values.get(&hidden_slot),
        Some(SlotValue::BooleanAttribute(TypedBooleanAttribute {
            kind: BooleanAttributeKind::Hidden,
            present: true,
        }))
    );
    if invalid == text_empty || hidden == invalid {
        return Err(ComposeError::CrossSlotInvariant);
    }
    Ok(())
}

fn serialize_slot_value(value: &SlotValue) -> Result<String, ComposeError> {
    Ok(match value {
        SlotValue::Text(value) => escape_text(&value.0),
        SlotValue::Attribute(value) => escape_attribute(&value.0),
        SlotValue::BooleanAttribute(value) => {
            if !value.present {
                String::new()
            } else {
                match value.kind {
                    BooleanAttributeKind::Checked => " checked".to_string(),
                    BooleanAttributeKind::Hidden => " hidden".to_string(),
                }
            }
        }
        SlotValue::ClosedToken(value) => value.value.to_string(),
        SlotValue::ProductPath(value) => escape_attribute(&value.as_string()?),
        SlotValue::TrustedStaticUrl(value) => escape_attribute(value.as_str()),
        SlotValue::StaticCss(value) => value.0.to_string(),
        SlotValue::Fragment(value) => value.bytes.clone(),
        SlotValue::FragmentList(values) => {
            values.iter().map(|value| value.bytes.as_str()).collect()
        }
        SlotValue::HiddenValue(value) => escape_attribute(&value.value),
    })
}

fn escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attribute(value: &str) -> String {
    escape_text(value)
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn valid_token(domain: TokenDomain, value: &str) -> bool {
    let allowed: &[&str] = match domain {
        TokenDomain::Channel => &["audit", "log", "metric"],
        TokenDomain::ChannelState => &[
            "configuration-absent-or-invalid",
            "unavailable",
            "non-success",
            "oversize-truncated",
            "invalid-schema",
            "loaded-empty",
            "loaded-non-empty",
        ],
        TokenDomain::Boundedness => &[
            "known-more",
            "proven-end",
            "completeness-unknown",
            "not-applicable",
        ],
        TokenDomain::SectionState => &[
            "loaded-known-more",
            "loaded-proven-end",
            "loaded-empty",
            "unavailable",
        ],
        TokenDomain::WindowLifecycle => &["moving", "frozen"],
        TokenDomain::IncidentLifecycle => &["open", "resolved"],
        TokenDomain::Severity => &[
            "unknown",
            "producer-info",
            "producer-notice",
            "producer-warning",
            "producer-error",
            "derived-notice",
            "derived-warning",
        ],
        TokenDomain::MarkKind => &["incident-opened", "note-added", "incident-resolved"],
        TokenDomain::ActorTruth => &["verified", "legacy-unclassified"],
        TokenDomain::Current => &["current", "not-current"],
        TokenDomain::AriaInvalid => &["true", "false"],
        TokenDomain::GatewayContext => &["authenticated", "unavailable"],
        TokenDomain::NoticeKind => &["status", "validation-error", "stale-conflict"],
    };
    allowed.contains(&value)
}

pub fn token(domain: TokenDomain, value: &'static str) -> SlotValue {
    SlotValue::ClosedToken(
        ClosedToken::new(domain, value).expect("closed token literal must be valid"),
    )
}

pub fn emergency_html() -> &'static str {
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Hindsight error</title></head><body><main><h1>Hindsight could not complete the request</h1><p>Return to the Hindsight timeline and try again.</p><a href=\"/\">Back to Hindsight</a></main></body></html>"
}

pub fn emergency_json() -> &'static str {
    "{\"error\":{\"code\":\"internal_error\",\"message\":\"Hindsight could not complete the request\"}}"
}
