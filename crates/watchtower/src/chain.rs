//! The tamper-evident, hash-chained audit log core.
//!
//! Each event carries a `hash` that commits to its own contents AND the previous event's
//! hash, so any modification, reordering, insertion, or deletion breaks the chain from the
//! point of tampering onward:
//!
//! ```text
//! hash(n) = SHA256( seq || ts || actor || action || target || severity || detail ||
//!                   source || prev_hash )
//! prev_hash(1) = 32 zero bytes (genesis)
//! prev_hash(n) = hash(n-1)
//! ```
//!
//! Encoding is canonical and unambiguous: the two integers are fixed 8-byte big-endian; each
//! string field is length-prefixed (8-byte big-endian length, then its UTF-8 bytes) so no
//! shifting of bytes between adjacent fields can produce a colliding pre-image; `prev_hash`
//! is folded in as its raw 32 bytes (decoded from hex). Hashes are stored/returned hex-encoded
//! so they live in portable TEXT columns and read cleanly in JSON.
//!
//! This module is pure (no I/O): the [`Store`](crate::store) owns serialization of appends,
//! and [`verify_chain`] recomputes an entire ordered slice. That keeps the integrity logic
//! trivially unit-testable and independent of the backend.

use sha2::{Digest, Sha256};

/// Genesis predecessor: 32 zero bytes, hex-encoded (64 `'0'`).
pub const GENESIS_HASH_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// The not-yet-sealed contents of an event: everything a producer supplies, plus the
/// server-assigned timestamp. The chain fields (`seq`, `prev_hash`, `hash`) are added by
/// the store when it seals this into an [`AuditEvent`].
#[derive(Clone, Debug)]
pub struct EventInput {
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub severity: String,
    pub detail: String,
    pub source: String,
}

impl EventInput {
    /// Seal this input at position `seq` chained onto `prev_hash` (hex), computing the
    /// committed `hash`. Called by the store inside its serialized-append critical section.
    pub fn seal(self, seq: i64, prev_hash: String) -> AuditEvent {
        let hash = hash_event(
            seq, self.ts, &self.actor, &self.action, &self.target, &self.severity,
            &self.detail, &self.source, &prev_hash,
        );
        AuditEvent {
            seq,
            ts: self.ts,
            actor: self.actor,
            action: self.action,
            target: self.target,
            severity: self.severity,
            detail: self.detail,
            source: self.source,
            prev_hash,
            hash,
        }
    }
}

/// One sealed, hash-chained audit event (maps 1:1 to a row of `audit_events`).
#[derive(Clone, Debug, serde::Serialize)]
pub struct AuditEvent {
    pub seq: i64,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub severity: String,
    pub detail: String,
    pub source: String,
    /// Predecessor hash (hex); `GENESIS_HASH_HEX` for `seq == 1`.
    pub prev_hash: String,
    /// This event's committed hash (hex).
    pub hash: String,
}

impl AuditEvent {
    /// Recompute this event's hash from its own stored fields and its stored `prev_hash`.
    /// Used by [`verify_chain`]: if a field was tampered after sealing, this no longer
    /// equals the stored [`AuditEvent::hash`].
    pub fn recompute_hash(&self) -> String {
        hash_event(
            self.seq, self.ts, &self.actor, &self.action, &self.target, &self.severity,
            &self.detail, &self.source, &self.prev_hash,
        )
    }
}

/// Canonical hash of one event's contents over its predecessor. See the module docs for the
/// exact encoding.
#[allow(clippy::too_many_arguments)]
pub fn hash_event(
    seq: i64,
    ts: i64,
    actor: &str,
    action: &str,
    target: &str,
    severity: &str,
    detail: &str,
    source: &str,
    prev_hash_hex: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_be_bytes());
    h.update(ts.to_be_bytes());
    for field in [actor, action, target, severity, detail, source] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    // Fold in the previous hash as its raw 32 bytes. A malformed/tampered hex prev_hash
    // decodes to something other than the genuine predecessor, so the mismatch is caught.
    let prev_bytes = hex::decode(prev_hash_hex).unwrap_or_default();
    h.update(&prev_bytes);
    hex::encode(h.finalize())
}

/// Result of recomputing the entire chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    /// True when every event verifies: contiguous `seq` from 1, each `prev_hash` links the
    /// running head, and each stored `hash` equals its recomputation.
    pub ok: bool,
    /// Total events considered.
    pub count: usize,
    /// Hash (hex) of the last stored event — the externally-anchorable chain head
    /// (`GENESIS_HASH_HEX` for an empty log).
    pub head_hash: String,
    /// The `seq` of the first event that fails verification, when `ok` is false.
    pub first_broken_seq: Option<i64>,
}

/// Recompute and verify an entire chain. `events` MUST be ordered by `seq` ascending (as the
/// store returns them). The first event that violates any invariant sets `first_broken_seq`
/// and stops the walk; everything up to it is consistent.
pub fn verify_chain(events: &[AuditEvent]) -> VerifyReport {
    let mut running_prev = GENESIS_HASH_HEX.to_string();
    let mut first_broken = None;

    // `seq` is 1-based and contiguous, so the expected value is the (1-based) position.
    for (expected_seq, event) in (1_i64..).zip(events.iter()) {
        let seq_ok = event.seq == expected_seq;
        let link_ok = event.prev_hash == running_prev;
        let hash_ok = event.recompute_hash() == event.hash;
        if !(seq_ok && link_ok && hash_ok) {
            first_broken = Some(event.seq);
            break;
        }
        running_prev = event.hash.clone();
    }

    let head_hash = events
        .last()
        .map(|e| e.hash.clone())
        .unwrap_or_else(|| GENESIS_HASH_HEX.to_string());

    VerifyReport {
        ok: first_broken.is_none(),
        count: events.len(),
        head_hash,
        first_broken_seq: first_broken,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid chain of `n` events by sealing each onto the previous head.
    fn build_chain(n: i64) -> Vec<AuditEvent> {
        let mut events = Vec::new();
        let mut prev = GENESIS_HASH_HEX.to_string();
        for seq in 1..=n {
            let input = EventInput {
                ts: 1_700_000_000_000 + seq,
                actor: format!("u_{seq}"),
                action: "login".to_string(),
                target: "keystone".to_string(),
                severity: "info".to_string(),
                detail: format!("event number {seq}"),
                source: "test".to_string(),
            };
            let ev = input.seal(seq, prev.clone());
            prev = ev.hash.clone();
            events.push(ev);
        }
        events
    }

    #[test]
    fn empty_chain_verifies() {
        let report = verify_chain(&[]);
        assert!(report.ok);
        assert_eq!(report.count, 0);
        assert_eq!(report.head_hash, GENESIS_HASH_HEX);
        assert_eq!(report.first_broken_seq, None);
    }

    #[test]
    fn well_formed_chain_verifies() {
        let events = build_chain(50);
        let report = verify_chain(&events);
        assert!(report.ok, "freshly built chain must verify");
        assert_eq!(report.count, 50);
        assert_eq!(report.head_hash, events.last().unwrap().hash);
        assert_eq!(report.first_broken_seq, None);
        // Genesis links to all zeros; each subsequent prev_hash links the prior hash.
        assert_eq!(events[0].prev_hash, GENESIS_HASH_HEX);
        assert_eq!(events[1].prev_hash, events[0].hash);
    }

    #[test]
    fn tampering_a_middle_events_detail_breaks_at_that_seq() {
        let mut events = build_chain(20);
        // Simulate a raw-storage tamper: rewrite event 12's detail but LEAVE its stored
        // hash (an attacker who can't, or didn't, re-chain forward). Recomputation no longer
        // matches the stored hash, so verify pinpoints seq 12 exactly.
        let idx = 11; // seq 12
        assert_eq!(events[idx].seq, 12);
        events[idx].detail = "TAMPERED".to_string();

        let report = verify_chain(&events);
        assert!(!report.ok);
        assert_eq!(report.first_broken_seq, Some(12), "exact first broken seq");
        assert_eq!(report.count, 20);
    }

    #[test]
    fn rechaining_a_tampered_event_still_breaks_the_forward_link() {
        let mut events = build_chain(10);
        // A craftier attacker rewrites event 5's detail AND recomputes its hash so seq 5
        // self-verifies — but they did not re-seal 6..10, so event 6's prev_hash no longer
        // matches the new hash(5). The break surfaces at seq 6.
        let idx = 4; // seq 5
        events[idx].detail = "covertly changed".to_string();
        events[idx].hash = events[idx].recompute_hash();

        let report = verify_chain(&events);
        assert!(!report.ok);
        assert_eq!(report.first_broken_seq, Some(6));
    }

    #[test]
    fn deleting_a_middle_event_is_detected() {
        let mut events = build_chain(8);
        events.remove(3); // drop seq 4 -> a gap, next event is seq 5 where 4 was expected
        let report = verify_chain(&events);
        assert!(!report.ok);
        assert_eq!(report.first_broken_seq, Some(5));
    }

    #[test]
    fn field_boundary_is_unambiguous() {
        // Length-prefixing means moving a byte across a field boundary changes the hash:
        // ("ab","c") must not collide with ("a","bc").
        let a = hash_event(1, 0, "ab", "c", "", "", "", "", GENESIS_HASH_HEX);
        let b = hash_event(1, 0, "a", "bc", "", "", "", "", GENESIS_HASH_HEX);
        assert_ne!(a, b);
    }
}
