//! RFC6962-inspired Merkle checkpoints over the existing hash chain.
//!
//! The per-row hash chain (see [`crate::chain`]) stays the integrity spine. A *checkpoint*
//! is an ADDED, faster tamper-evidence summary: a single Merkle Tree Hash (MTH) committing to
//! every event up to a fixed `seq_hi`. Once a checkpoint is sealed and externally retained, a
//! later out-of-band rewrite of ANY event below `seq_hi` — even a *consistent* rewrite that
//! re-chains the whole forward log so `GET /api/verify` still reports `ok` — produces a
//! different root than the one the checkpoint recorded, so the tamper is caught.
//!
//! The construction follows RFC6962 §2.1:
//!
//! ```text
//! MTH({})        = SHA256()                                  (empty input)
//! MTH({d0})      = SHA256(0x00 || d0)                        (leaf)
//! MTH(d[0:n]>1)  = SHA256(0x01 || MTH(d[0:k]) || MTH(d[k:n])) (interior, k = 2^floor(log2(n-1)))
//! ```
//!
//! The leaf payload `d_i` is each event's *recomputed content hash*
//! ([`AuditEvent::recompute_hash`]) decoded to its 32 raw bytes — NOT the stored `hash` column.
//! Binding the leaf to recomputed content means a content edit changes the leaf (and thus the
//! root) regardless of whether the attacker also rewrote the stored hash, so "tamper anywhere
//! below a checkpoint changes the root" holds for content edits, hash edits, reordering, and
//! deletion alike.
//!
//! Pure (no I/O), exactly like [`crate::chain`]: storage lives in [`crate::store`].

use sha2::{Digest, Sha256};

use crate::chain::AuditEvent;

/// RFC6962 domain-separation prefix for leaf hashes.
const LEAF_PREFIX: u8 = 0x00;
/// RFC6962 domain-separation prefix for interior-node hashes.
const NODE_PREFIX: u8 = 0x01;

/// A sealed Merkle checkpoint — maps 1:1 to a row of `checkpoints`.
///
/// `seq_hi` is the highest event `seq` the root commits to (`0` for an empty log). `merkle_root`
/// is the hex MTH over events `1..=seq_hi`. `created_at` is epoch milliseconds (same clock as
/// [`crate::now_ms`]). `id` is a content-derived stable identifier (see [`checkpoint_id`]).
#[derive(Clone, Debug, serde::Serialize)]
pub struct Checkpoint {
    pub id: String,
    pub seq_hi: i64,
    pub merkle_root: String,
    pub created_at: i64,
}

/// Hex SHA-256 of the empty input — the RFC6962 hash of an empty tree.
fn empty_root() -> String {
    hex::encode(Sha256::new().finalize())
}

/// Leaf hash: `SHA256(0x00 || leaf_data)`.
fn leaf_hash(leaf_data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(leaf_data);
    h.finalize().into()
}

/// Interior-node hash: `SHA256(0x01 || left || right)`.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (defined for `n >= 2`). This is RFC6962's split
/// point `k`: `2^floor(log2(n-1))`.
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle Tree Hash of the ordered leaf payloads (RFC6962 §2.1). Recursive; depth is `log2(n)`.
fn mth(leaves: &[Vec<u8>]) -> [u8; 32] {
    match leaves.len() {
        // Caller handles the empty case via `empty_root`; never reached for a non-empty slice.
        0 => Sha256::new().finalize().into(),
        1 => leaf_hash(&leaves[0]),
        n => {
            let k = split_point(n);
            let left = mth(&leaves[..k]);
            let right = mth(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

/// Collect the leaf payloads for events with `seq <= seq_hi`: each event's recomputed content
/// hash, decoded to raw bytes. `events` MUST be ordered by `seq` ascending (as the store
/// returns them).
fn leaves_upto(events: &[AuditEvent], seq_hi: i64) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter(|e| e.seq <= seq_hi)
        .map(|e| hex::decode(e.recompute_hash()).unwrap_or_default())
        .collect()
}

/// Compute the hex Merkle root over events `1..=seq_hi`. Returns the empty-tree root when no
/// event qualifies (`seq_hi == 0` or an empty log).
pub fn merkle_root_upto(events: &[AuditEvent], seq_hi: i64) -> String {
    let leaves = leaves_upto(events, seq_hi);
    if leaves.is_empty() {
        return empty_root();
    }
    hex::encode(mth(&leaves))
}

/// A stable, content-derived checkpoint id: `cp_<first 16 hex of SHA256(seq_hi||root||created_at)>`.
/// Two identical seals (same prefix, same root, same instant) collapse to one id, so the
/// idempotent `INSERT .. ON CONFLICT (id) DO NOTHING` is a harmless no-op.
pub fn checkpoint_id(seq_hi: i64, merkle_root: &str, created_at: i64) -> String {
    let mut h = Sha256::new();
    h.update(seq_hi.to_be_bytes());
    h.update(merkle_root.as_bytes());
    h.update(created_at.to_be_bytes());
    format!("cp_{}", &hex::encode(h.finalize())[..16])
}

/// Seal a checkpoint over the current head: `seq_hi` is the last event's `seq` (`0` for an empty
/// log), `merkle_root` the MTH over the whole prefix, stamped `created_at`.
pub fn make_checkpoint(events: &[AuditEvent], created_at: i64) -> Checkpoint {
    let seq_hi = events.last().map(|e| e.seq).unwrap_or(0);
    let merkle_root = merkle_root_upto(events, seq_hi);
    let id = checkpoint_id(seq_hi, &merkle_root, created_at);
    Checkpoint {
        id,
        seq_hi,
        merkle_root,
        created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{EventInput, GENESIS_HASH_HEX};

    /// Build a valid chain of `n` events (same helper shape as the chain tests).
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
    fn empty_and_single_roots_follow_rfc6962() {
        // Empty tree -> SHA256 of the empty input.
        assert_eq!(merkle_root_upto(&[], 0), empty_root());
        // Single leaf -> SHA256(0x00 || d0).
        let events = build_chain(1);
        let d0 = hex::decode(events[0].recompute_hash()).unwrap();
        assert_eq!(merkle_root_upto(&events, 1), hex::encode(leaf_hash(&d0)));
    }

    #[test]
    fn root_is_deterministic_and_prefix_scoped() {
        let events = build_chain(16);
        // Recompute is stable.
        assert_eq!(merkle_root_upto(&events, 16), merkle_root_upto(&events, 16));
        // A checkpoint at seq_hi only commits to its prefix: extending the log past seq_hi must
        // NOT change the root computed up to seq_hi.
        let root8 = merkle_root_upto(&events, 8);
        let more = build_chain(20);
        assert_eq!(
            root8,
            merkle_root_upto(&more, 8),
            "prefix root is stable as the log grows"
        );
        // A bigger prefix gives a different root.
        assert_ne!(root8, merkle_root_upto(&events, 16));
    }

    #[test]
    fn consistent_rewrite_below_checkpoint_changes_the_root() {
        // Seal a checkpoint over 10 events.
        let original = build_chain(10);
        let cp = make_checkpoint(&original, 1_700_000_000_000);
        assert_eq!(cp.seq_hi, 10);

        // A craftier attacker edits event 4's detail AND re-chains the ENTIRE forward log so the
        // per-row chain still verifies end-to-end (GET /api/verify would say ok). Rebuild the
        // chain with the edit baked in from seq 4 onward.
        let mut tampered = Vec::new();
        let mut prev = GENESIS_HASH_HEX.to_string();
        for seq in 1..=10 {
            let detail = if seq == 4 {
                "covertly rewritten".to_string()
            } else {
                format!("event number {seq}")
            };
            let input = EventInput {
                ts: 1_700_000_000_000 + seq,
                actor: format!("u_{seq}"),
                action: "login".to_string(),
                target: "keystone".to_string(),
                severity: "info".to_string(),
                detail,
                source: "test".to_string(),
            };
            let ev = input.seal(seq, prev.clone());
            prev = ev.hash.clone();
            tampered.push(ev);
        }
        // The re-chained log is internally consistent...
        assert!(
            crate::chain::verify_chain(&tampered).ok,
            "attacker re-chained cleanly"
        );
        // ...but the checkpoint root no longer matches: the tamper IS caught.
        assert_ne!(
            cp.merkle_root,
            merkle_root_upto(&tampered, cp.seq_hi),
            "checkpoint detects a consistent rewrite the live chain alone cannot"
        );
    }

    #[test]
    fn split_point_matches_rfc6962() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
    }
}
