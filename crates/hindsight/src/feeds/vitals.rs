//! Typed Vitals anomaly acquisition.

use std::time::Duration;

use serde::Deserialize;

use crate::http::{self, HttpAcquisition};
use crate::view_contract::{ChannelId, MetricClassification, MetricRecord};

const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub enum MetricAcquisition {
    ConfigurationAbsentOrInvalid,
    Unavailable,
    NonSuccess,
    OversizeTruncated,
    InvalidSchema,
    Loaded {
        acquired_count: usize,
        acquired_from_ms: Option<i64>,
        acquired_to_ms: Option<i64>,
        records: Vec<MetricRecord>,
    },
}

#[derive(Debug, Deserialize)]
struct MetricsResponse {
    samples: Vec<Sample>,
}

#[derive(Debug, Deserialize)]
struct Sample {
    host: String,
    metric: String,
    value: f64,
    ts: i64,
}

pub async fn fetch(vitals_url: Option<&str>, from_inclusive_s: i64) -> MetricAcquisition {
    let endpoint = vitals_url.map(|base| {
        format!(
            "{}/api/metrics?since={from_inclusive_s}",
            base.trim_end_matches('/')
        )
    });
    match http::acquire(ChannelId::Metric, endpoint.as_deref(), FETCH_TIMEOUT).await {
        HttpAcquisition::ConfigurationAbsentOrInvalid => {
            MetricAcquisition::ConfigurationAbsentOrInvalid
        }
        HttpAcquisition::Unavailable(_) => MetricAcquisition::Unavailable,
        HttpAcquisition::NonSuccess { .. } => MetricAcquisition::NonSuccess,
        HttpAcquisition::OversizeTruncated => MetricAcquisition::OversizeTruncated,
        HttpAcquisition::CompleteBody(body) => parse(&body),
    }
}

pub fn parse(body: &[u8]) -> MetricAcquisition {
    let response: MetricsResponse = match serde_json::from_slice(body) {
        Ok(response) => response,
        Err(_) => return MetricAcquisition::InvalidSchema,
    };
    let acquired_count = response.samples.len();
    let mut acquired_from_ms = None;
    let mut acquired_to_ms = None;
    let mut records = Vec::new();
    for sample in response.samples {
        let Some(recorded_at_ms) = sample.ts.checked_mul(1_000) else {
            return MetricAcquisition::InvalidSchema;
        };
        if sample.host.is_empty()
            || sample.metric.is_empty()
            || !sample.value.is_finite()
            || sample.ts <= 0
        {
            return MetricAcquisition::InvalidSchema;
        }
        acquired_from_ms =
            Some(acquired_from_ms.map_or(recorded_at_ms, |value: i64| value.min(recorded_at_ms)));
        acquired_to_ms =
            Some(acquired_to_ms.map_or(recorded_at_ms, |value: i64| value.max(recorded_at_ms)));
        let Some((classification, unit, derivation)) = classify(&sample.metric, sample.value)
        else {
            continue;
        };
        records.push(MetricRecord {
            host: sample.host,
            metric_name: sample.metric,
            raw_value_bits: sample.value.to_bits(),
            unit: unit.to_string(),
            recorded_at_s: sample.ts,
            classification,
            derivation: derivation.to_string(),
        });
    }
    MetricAcquisition::Loaded {
        acquired_count,
        acquired_from_ms,
        acquired_to_ms,
        records,
    }
}

pub fn classify(
    metric: &str,
    value: f64,
) -> Option<(MetricClassification, &'static str, &'static str)> {
    match metric {
        "cpu_pct" if value >= 90.0 => {
            Some((MetricClassification::CpuHigh, "percent", "cpu_pct >= 90.0"))
        }
        "mem_pct" if value >= 90.0 => Some((
            MetricClassification::MemoryHigh,
            "percent",
            "mem_pct >= 90.0",
        )),
        "load1" if value >= 8.0 => Some((
            MetricClassification::LoadCritical,
            "one-minute load average",
            "load1 >= 8.0",
        )),
        "load1" if value >= 4.0 => Some((
            MetricClassification::LoadElevated,
            "one-minute load average",
            "4.0 <= load1 < 8.0",
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_and_raw_bits_are_exact() {
        let body = br#"{"samples":[
          {"host":"h","metric":"cpu_pct","value":90.0,"ts":100},
          {"host":"h","metric":"mem_pct","value":89.999,"ts":101},
          {"host":"h","metric":"load1","value":4.0,"ts":102},
          {"host":"h","metric":"load1","value":8.0,"ts":103}
        ]}"#;
        let MetricAcquisition::Loaded {
            acquired_count,
            acquired_from_ms,
            acquired_to_ms,
            records,
        } = parse(body)
        else {
            panic!("expected loaded");
        };
        assert_eq!(acquired_count, 4);
        assert_eq!(acquired_from_ms, Some(100_000));
        assert_eq!(acquired_to_ms, Some(103_000));
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].raw_value_bits, 90.0f64.to_bits());
        assert_eq!(
            records[1].classification,
            MetricClassification::LoadElevated
        );
        assert_eq!(
            records[2].classification,
            MetricClassification::LoadCritical
        );
    }

    #[test]
    fn invalid_identity_rejects_the_complete_channel() {
        let body = br#"{"samples":[{"host":"","metric":"cpu_pct","value":95.0,"ts":100}]}"#;
        assert!(matches!(parse(body), MetricAcquisition::InvalidSchema));
        assert!(matches!(parse(b"{}"), MetricAcquisition::InvalidSchema));
        let overflow =
            br#"{"samples":[{"host":"h","metric":"cpu_pct","value":95.0,"ts":9223372036854775807}]}"#;
        assert!(matches!(parse(overflow), MetricAcquisition::InvalidSchema));
    }
}
