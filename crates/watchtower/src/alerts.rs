//! Alert rules and append-only alert match markers.
//!
//! Rules are exact-match predicates over audit event metadata. A blank predicate means
//! "wildcard", but handlers require at least one predicate before creating a rule so an
//! accidental catch-all is not introduced from the dashboard. Matches are stored as separate
//! append-only markers; the audit event chain itself is not mutated.

use sha2::{Digest, Sha256};

use crate::chain::AuditEvent;

/// A stored alert rule. Optional match fields are exact predicates; `None` means wildcard.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub actor: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub severity: Option<String>,
    pub created_by: String,
    pub created_at: i64,
}

impl AlertRule {
    /// True when at least one predicate is configured.
    pub fn has_predicate(&self) -> bool {
        self.actor.is_some()
            || self.action.is_some()
            || self.source.is_some()
            || self.severity.is_some()
    }

    /// Check whether an audit event matches this rule.
    pub fn matches(&self, event: &AuditEvent) -> bool {
        matches_exact(&self.actor, &event.actor)
            && matches_exact(&self.action, &event.action)
            && matches_exact(&self.source, &event.source)
            && matches_severity(&self.severity, &event.severity)
    }
}

/// A stored alert match marker. Fields snapshot the event/rule labels needed for the UI/export
/// without joining through mutable rule names later.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AlertMatch {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub event_seq: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub severity: String,
    pub source: String,
    pub matched_at: i64,
}

/// Build a rule with a stable content-derived identifier.
pub fn make_alert_rule(
    name: String,
    actor: Option<String>,
    action: Option<String>,
    source: Option<String>,
    severity: Option<String>,
    created_by: String,
    created_at: i64,
) -> AlertRule {
    let id = alert_rule_id(
        &name,
        actor.as_deref(),
        action.as_deref(),
        source.as_deref(),
        severity.as_deref(),
        &created_by,
        created_at,
    );
    AlertRule {
        id,
        name,
        actor,
        action,
        source,
        severity,
        created_by,
        created_at,
    }
}

/// Build the append-only marker for a rule/event match.
pub fn make_alert_match(rule: &AlertRule, event: &AuditEvent, matched_at: i64) -> AlertMatch {
    AlertMatch {
        id: alert_match_id(&rule.id, event.seq),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        event_seq: event.seq,
        actor: event.actor.clone(),
        action: event.action.clone(),
        target: event.target.clone(),
        severity: event.severity.clone(),
        source: event.source.clone(),
        matched_at,
    }
}

fn matches_exact(rule_value: &Option<String>, actual: &str) -> bool {
    rule_value.as_deref().map_or(true, |want| want == actual)
}

fn matches_severity(rule_value: &Option<String>, actual: &str) -> bool {
    rule_value
        .as_deref()
        .map_or(true, |want| want.eq_ignore_ascii_case(actual))
}

fn alert_rule_id(
    name: &str,
    actor: Option<&str>,
    action: Option<&str>,
    source: Option<&str>,
    severity: Option<&str>,
    created_by: &str,
    created_at: i64,
) -> String {
    let mut h = Sha256::new();
    for field in [
        name,
        actor.unwrap_or(""),
        action.unwrap_or(""),
        source.unwrap_or(""),
        severity.unwrap_or(""),
        created_by,
    ] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    h.update(created_at.to_be_bytes());
    format!("ar_{}", &hex::encode(h.finalize())[..16])
}

fn alert_match_id(rule_id: &str, event_seq: i64) -> String {
    let mut h = Sha256::new();
    h.update(rule_id.as_bytes());
    h.update(event_seq.to_be_bytes());
    format!("am_{}", &hex::encode(h.finalize())[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{EventInput, GENESIS_HASH_HEX};

    fn event() -> AuditEvent {
        EventInput {
            ts: 1,
            actor: "u_admin".to_string(),
            action: "login.failure".to_string(),
            target: "keystone".to_string(),
            severity: "warning".to_string(),
            detail: "bad password".to_string(),
            source: "keystone".to_string(),
        }
        .seal(1, GENESIS_HASH_HEX.to_string())
    }

    #[test]
    fn rules_match_exact_metadata() {
        let ev = event();
        let rule = make_alert_rule(
            "login failures".to_string(),
            Some("u_admin".to_string()),
            Some("login.failure".to_string()),
            Some("keystone".to_string()),
            Some("WARNING".to_string()),
            "admin@steadholme.local".to_string(),
            2,
        );
        assert!(rule.has_predicate());
        assert!(rule.matches(&ev));

        let wrong_actor = make_alert_rule(
            "other".to_string(),
            Some("u_bob".to_string()),
            None,
            None,
            None,
            "admin@steadholme.local".to_string(),
            2,
        );
        assert!(!wrong_actor.matches(&ev));
    }

    #[test]
    fn alert_match_id_is_stable_per_rule_event() {
        let ev = event();
        let rule = make_alert_rule(
            "login failures".to_string(),
            None,
            Some("login.failure".to_string()),
            None,
            None,
            "admin@steadholme.local".to_string(),
            2,
        );
        assert_eq!(
            make_alert_match(&rule, &ev, 3).id,
            make_alert_match(&rule, &ev, 4).id
        );
    }
}
