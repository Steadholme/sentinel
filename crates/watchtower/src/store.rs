//! Append-only audit storage.
//!
//! `Store` is a small trait with an in-memory and a PostgreSQL implementation, mirroring
//! the keystone/keyward seam: handlers depend only on the trait, so a FusionDB-backed store
//! can drop in later. The PostgreSQL data model and queries use portable primitives (TEXT/BIGINT,
//! PRIMARY KEY/NOT NULL, parameterized queries, `lower(..) LIKE ..`, plain indexes) and runtime
//! queries (no compile-time macros), so the build needs NO database. Cross-process append
//! serialization intentionally uses PostgreSQL's transaction advisory lock; another pgwire
//! backend must provide an equivalent transaction-scoped global writer primitive.
//!
//! INVARIANT — append-only & single-writer: there is NO update or delete code path. The
//! only audit-event mutation is [`Store::append`], which is serialized (the in-memory store
//! behind its `Mutex`; the Postgres store behind a transaction-scoped database advisory lock)
//! so the chain head is read, extended, and written atomically and the chain stays well-defined.
//! Idempotency mappings are additive and are committed in the same boundary as their event.
//! Production additionally grants the audit DB user only INSERT/SELECT, so even a compromised
//! service cannot rewrite history.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::alerts::{make_alert_match, AlertMatch, AlertRule};
use crate::chain::{AuditEvent, EventInput, GENESIS_HASH_HEX};
use crate::config::QUERY_LIMIT;
use crate::merkle::Checkpoint;

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("idempotency key was already used for a different event")]
    IdempotencyConflict,

    #[error("store error: {0}")]
    Backend(String),
}

/// Result of an idempotent append attempt.
#[derive(Clone, Debug)]
pub struct AppendOutcome {
    /// The newly committed event, or the original event when the key was replayed.
    pub event: AuditEvent,
    /// `true` only when this call extended the audit chain.
    pub appended: bool,
}

/// Filters for `GET /api/events` and the dashboard timeline.
///
/// `actor`/`action`/`source`/`severity` are exact matches; `since`/`until` bound `ts`; `q` is
/// a case-insensitive substring search over the searchable event text (the semantic-search seam
/// for the later FusionDB hook). Results are newest-first (`seq` DESC), capped at
/// [`EventFilter::limit`] after skipping [`EventFilter::offset`].
#[derive(Clone, Debug, Default)]
pub struct EventFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub severity: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub q: Option<String>,
    pub limit: usize,
    pub offset: usize,
}

impl EventFilter {
    /// A filter with the default row cap applied.
    pub fn new() -> Self {
        EventFilter {
            limit: QUERY_LIMIT,
            ..Default::default()
        }
    }

    /// Apply this filter to one event (the in-memory matching logic, kept next to the
    /// filter so memory and Postgres share one definition of "matches").
    fn matches(&self, e: &AuditEvent) -> bool {
        if let Some(actor) = &self.actor {
            if &e.actor != actor {
                return false;
            }
        }
        if let Some(action) = &self.action {
            if &e.action != action {
                return false;
            }
        }
        if let Some(source) = &self.source {
            if &e.source != source {
                return false;
            }
        }
        if let Some(severity) = &self.severity {
            if &e.severity != severity {
                return false;
            }
        }
        if let Some(since) = self.since {
            if e.ts < since {
                return false;
            }
        }
        if let Some(until) = self.until {
            if e.ts > until {
                return false;
            }
        }
        if let Some(q) = &self.q {
            let needle = q.to_lowercase();
            let hit = e.actor.to_lowercase().contains(&needle)
                || e.action.to_lowercase().contains(&needle)
                || e.target.to_lowercase().contains(&needle)
                || e.detail.to_lowercase().contains(&needle)
                || e.source.to_lowercase().contains(&needle)
                || e.severity.to_lowercase().contains(&needle);
            if !hit {
                return false;
            }
        }
        true
    }
}

/// Pluggable append-only audit store. Methods are `async`: the axum handlers `.await` them
/// directly on the serving runtime, so a full-chain read can never block a worker thread.
/// Appends stay strictly serialized internally (the single-writer guarantee), but reads never
/// wait on that serializer and never block a runtime worker.
#[async_trait]
pub trait Store: Send + Sync {
    /// Serialized append. Computes `seq` (monotonic from 1), `prev_hash` (the current head,
    /// or genesis), and the committed `hash`, persists atomically, and returns the sealed
    /// event. The single-writer guarantee lives here.
    async fn append(&self, input: EventInput) -> Result<AuditEvent, StoreError>;

    /// Append once for a stable producer key. The key mapping and event append share one atomic
    /// boundary. Replaying the same key + event content returns the original event with
    /// `appended=false`; reusing a key for different content fails closed.
    async fn append_idempotent(
        &self,
        input: EventInput,
        key: String,
    ) -> Result<AppendOutcome, StoreError>;

    /// Every event ordered by `seq` ascending — the input to [`crate::chain::verify_chain`].
    async fn all_events(&self) -> Result<Vec<AuditEvent>, StoreError>;

    /// Filtered, newest-first, capped query for the API + dashboard timeline.
    async fn query(&self, filter: &EventFilter) -> Result<Vec<AuditEvent>, StoreError>;

    /// Count all events matching the filter, ignoring `limit`/`offset`.
    async fn count(&self, filter: &EventFilter) -> Result<usize, StoreError>;

    /// Persist a sealed Merkle [`Checkpoint`] (ADDED tamper-evidence summary; see
    /// [`crate::merkle`]). Idempotent on `id`: re-sealing an identical state is a no-op, so this
    /// is NOT a mutation of any existing row. The append-only chain is untouched.
    async fn insert_checkpoint(&self, checkpoint: Checkpoint) -> Result<(), StoreError>;

    /// Every stored checkpoint, ordered by `seq_hi` ascending.
    async fn all_checkpoints(&self) -> Result<Vec<Checkpoint>, StoreError>;

    /// Persist a new alert rule. Idempotent on `id` and stored outside the audit chain.
    async fn insert_alert_rule(&self, rule: AlertRule) -> Result<(), StoreError>;

    /// Every stored alert rule, newest-first by creation time.
    async fn all_alert_rules(&self) -> Result<Vec<AlertRule>, StoreError>;

    /// Evaluate stored alert rules against one committed event and persist match markers.
    async fn record_alert_matches(
        &self,
        event: &AuditEvent,
        matched_at: i64,
    ) -> Result<Vec<AlertMatch>, StoreError>;

    /// Recent alert match markers, newest-first.
    async fn recent_alert_matches(&self, limit: usize) -> Result<Vec<AlertMatch>, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct IdempotencyRecord {
    request_hash: String,
    event_seq: i64,
}

#[derive(Default)]
struct InMemoryAuditState {
    events: Vec<AuditEvent>,
    idempotency_keys: HashMap<String, IdempotencyRecord>,
}

/// In-memory `Store`. The single audit-state mutex is the serial guard: every append takes the
/// lock, reads the head, seals, and pushes. Idempotency key claims live in that same critical
/// section, so a key can never be visible without its event or vice versa.
#[derive(Default)]
pub struct InMemoryStore {
    audit: Mutex<InMemoryAuditState>,
    /// Sealed Merkle checkpoints. Separate lock from `events`: sealing/listing checkpoints never
    /// contends with the append critical section, and reads never block appends.
    checkpoints: Mutex<Vec<Checkpoint>>,
    /// Alert rules are additive control-plane records; separate from the audit append lock.
    alert_rules: Mutex<Vec<AlertRule>>,
    /// Append-only alert match markers.
    alert_matches: Mutex<Vec<AlertMatch>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn append(&self, input: EventInput) -> Result<AuditEvent, StoreError> {
        // The std `Mutex` is fine here: the whole critical section is synchronous (no `.await`
        // inside), so the guard is never held across a yield point.
        let mut audit = self.audit.lock().expect("audit state lock poisoned");
        let (seq, prev_hash) = match audit.events.last() {
            Some(head) => (head.seq + 1, head.hash.clone()),
            None => (1, GENESIS_HASH_HEX.to_string()),
        };
        let event = input.seal(seq, prev_hash);
        audit.events.push(event.clone());
        Ok(event)
    }

    async fn append_idempotent(
        &self,
        input: EventInput,
        key: String,
    ) -> Result<AppendOutcome, StoreError> {
        let key_hash = idempotency_key_hash(&input.source, &key);
        let request_hash = idempotency_request_hash(&input);
        let mut audit = self.audit.lock().expect("audit state lock poisoned");

        if let Some(record) = audit.idempotency_keys.get(&key_hash).cloned() {
            if record.request_hash != request_hash {
                return Err(StoreError::IdempotencyConflict);
            }
            let event = audit
                .events
                .iter()
                .find(|event| event.seq == record.event_seq)
                .cloned()
                .ok_or_else(|| {
                    StoreError::Backend(format!(
                        "idempotency mapping references missing event seq {}",
                        record.event_seq
                    ))
                })?;
            return Ok(AppendOutcome {
                event,
                appended: false,
            });
        }

        let (seq, prev_hash) = match audit.events.last() {
            Some(head) => (head.seq + 1, head.hash.clone()),
            None => (1, GENESIS_HASH_HEX.to_string()),
        };
        let event = input.seal(seq, prev_hash);
        audit.events.push(event.clone());
        audit.idempotency_keys.insert(
            key_hash,
            IdempotencyRecord {
                request_hash,
                event_seq: event.seq,
            },
        );
        Ok(AppendOutcome {
            event,
            appended: true,
        })
    }

    async fn all_events(&self) -> Result<Vec<AuditEvent>, StoreError> {
        Ok(self
            .audit
            .lock()
            .expect("audit state lock poisoned")
            .events
            .clone())
    }

    async fn query(&self, filter: &EventFilter) -> Result<Vec<AuditEvent>, StoreError> {
        let audit = self.audit.lock().expect("audit state lock poisoned");
        let mut out: Vec<AuditEvent> = audit
            .events
            .iter()
            .rev() // newest first
            .filter(|e| filter.matches(e))
            .skip(filter.offset)
            .take(filter.limit)
            .cloned()
            .collect();
        out.shrink_to_fit();
        Ok(out)
    }

    async fn count(&self, filter: &EventFilter) -> Result<usize, StoreError> {
        let audit = self.audit.lock().expect("audit state lock poisoned");
        Ok(audit.events.iter().filter(|e| filter.matches(e)).count())
    }

    async fn insert_checkpoint(&self, checkpoint: Checkpoint) -> Result<(), StoreError> {
        let mut cps = self.checkpoints.lock().expect("checkpoints lock poisoned");
        // Idempotent on id (mirrors the Postgres `ON CONFLICT (id) DO NOTHING`).
        if !cps.iter().any(|c| c.id == checkpoint.id) {
            cps.push(checkpoint);
        }
        Ok(())
    }

    async fn all_checkpoints(&self) -> Result<Vec<Checkpoint>, StoreError> {
        let mut out = self
            .checkpoints
            .lock()
            .expect("checkpoints lock poisoned")
            .clone();
        out.sort_by_key(|c| c.seq_hi);
        Ok(out)
    }

    async fn insert_alert_rule(&self, rule: AlertRule) -> Result<(), StoreError> {
        let mut rules = self.alert_rules.lock().expect("alert rules lock poisoned");
        if !rules.iter().any(|r| r.id == rule.id) {
            rules.push(rule);
        }
        Ok(())
    }

    async fn all_alert_rules(&self) -> Result<Vec<AlertRule>, StoreError> {
        let mut out = self
            .alert_rules
            .lock()
            .expect("alert rules lock poisoned")
            .clone();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    async fn record_alert_matches(
        &self,
        event: &AuditEvent,
        matched_at: i64,
    ) -> Result<Vec<AlertMatch>, StoreError> {
        let rules = self
            .alert_rules
            .lock()
            .expect("alert rules lock poisoned")
            .clone();
        let mut matches = self
            .alert_matches
            .lock()
            .expect("alert matches lock poisoned");
        let mut inserted = Vec::new();
        for rule in rules.iter().filter(|r| r.matches(event)) {
            let hit = make_alert_match(rule, event, matched_at);
            if !matches.iter().any(|m| m.id == hit.id) {
                matches.push(hit.clone());
                inserted.push(hit);
            }
        }
        Ok(inserted)
    }

    async fn recent_alert_matches(&self, limit: usize) -> Result<Vec<AlertMatch>, StoreError> {
        let mut out = self
            .alert_matches
            .lock()
            .expect("alert matches lock poisoned")
            .clone();
        out.sort_by(|a, b| b.matched_at.cmp(&a.matched_at));
        out.truncate(limit);
        Ok(out)
    }
}

fn hash_fields(domain: &[u8], fields: &[&str]) -> String {
    let mut hash = Sha256::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hex::encode(hash.finalize())
}

/// Hash producer keys before storage so opaque credentials or identifiers never become database
/// lookup material in plaintext.
fn idempotency_key_hash(source: &str, key: &str) -> String {
    hash_fields(b"watchtower:idempotency-key:v1", &[source, key])
}

/// Bind a key to producer-controlled event content. `ts` is intentionally excluded because the
/// server assigns a fresh wall-clock value on every HTTP attempt; a replay must return the
/// timestamp of the original event.
fn idempotency_request_hash(input: &EventInput) -> String {
    hash_fields(
        b"watchtower:idempotency-request:v1",
        &[
            &input.actor,
            &input.action,
            &input.target,
            &input.severity,
            &input.detail,
            &input.source,
        ],
    )
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (runtime queries, no compile-time database/macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `WATCHTOWER_STORE=postgres`. The `Store` trait is async, so each method
// uses sqlx natively and the handlers `.await` it on the serving runtime — there is NO
// `block_in_place` and NO sync-over-async, so a full-chain read never blocks a worker thread.
// Appends are serialized in-process by a `tokio::sync::Mutex<()>` and across processes by a
// transaction-scoped PostgreSQL advisory lock. The "claim key -> read head -> seal -> insert
// event + key mapping" sequence is therefore one global writer boundary; reads remain fully
// concurrent.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds a `PgPool` and an async serial guard that makes append a
/// single writer. The async trait methods drive sqlx natively, so no worker thread is ever
/// blocked on a DB round-trip.
pub struct PgStore {
    pool: PgPool,
    /// Process-wide append serializer (the "serial guard"). A `tokio::sync::Mutex` so it can be
    /// held across the `.await` of the read-head -> insert transaction WITHOUT blocking a worker
    /// thread (waiting on it yields); two appends can never race for the same `seq`/`prev_hash`,
    /// and reads never take it.
    append_guard: tokio::sync::Mutex<()>,
}

/// Stable database-global lock identity for Watchtower's audit append lane.
///
/// Every process using this implementation takes the transaction-scoped lock before it reads the
/// chain head. It also covers unkeyed appends, so mixed keyed/unkeyed traffic cannot fork the
/// chain across replicas.
const POSTGRES_APPEND_LOCK_ID: i64 = 0x5733_4457_4154_4348;

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            append_guard: tokio::sync::Mutex::new(()),
        }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    /// Mirrors the audit_events shape exactly: `hash` is the only explicit NOT NULL; `seq`
    /// is the primary key. Indexes back the `ts`/`actor`/`action` filters.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_events (\
                 seq BIGINT PRIMARY KEY, \
                 ts BIGINT, \
                 actor TEXT, \
                 action TEXT, \
                 target TEXT, \
                 severity TEXT, \
                 detail TEXT, \
                 source TEXT, \
                 prev_hash TEXT, \
                 hash TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events (ts)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events (action)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_source ON audit_events (source)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_severity ON audit_events (severity)",
        )
        .execute(&self.pool)
        .await?;
        // ADDITIVE: Merkle checkpoints (RFC6962-inspired tamper-evidence summary over the chain
        // prefix). Standard SQL only; the audit_events table and its append path are untouched.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS checkpoints (\
                 id TEXT PRIMARY KEY, \
                 seq_hi BIGINT, \
                 merkle_root TEXT, \
                 created_at BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_checkpoints_seq_hi ON checkpoints (seq_hi)")
            .execute(&self.pool)
            .await?;
        // ADDITIVE: alert rules and append-only match markers. These are independent from the
        // audit event spine and contain no rewrite path.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alert_rules (\
                 id TEXT PRIMARY KEY, \
                 name TEXT, \
                 actor TEXT, \
                 action TEXT, \
                 source TEXT, \
                 severity TEXT, \
                 created_by TEXT, \
                 created_at BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_alert_rules_created_at ON alert_rules (created_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alert_matches (\
                 id TEXT PRIMARY KEY, \
                 rule_id TEXT, \
                 rule_name TEXT, \
                 event_seq BIGINT, \
                 actor TEXT, \
                 action TEXT, \
                 target TEXT, \
                 severity TEXT, \
                 source TEXT, \
                 matched_at BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_alert_matches_matched_at ON alert_matches (matched_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_alert_matches_event_seq ON alert_matches (event_seq)",
        )
        .execute(&self.pool)
        .await?;
        // ADDITIVE: permanent, digest-only producer key claims. A claim and its audit event are
        // inserted in one transaction; no update/delete path exists. `request_hash` rejects
        // accidental reuse of one key for different producer-controlled event content.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_idempotency_keys (\
                 key_hash TEXT PRIMARY KEY, \
                 request_hash TEXT NOT NULL, \
                 event_seq BIGINT NOT NULL UNIQUE, \
                 created_at BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_idempotency_event_seq \
             ON audit_idempotency_keys (event_seq)",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn event_from_row(row: &sqlx::postgres::PgRow) -> Result<AuditEvent, sqlx::Error> {
        Ok(AuditEvent {
            seq: row.try_get("seq")?,
            ts: row.try_get("ts")?,
            actor: row.try_get("actor")?,
            action: row.try_get("action")?,
            target: row.try_get("target")?,
            severity: row.try_get("severity")?,
            detail: row.try_get("detail")?,
            source: row.try_get("source")?,
            prev_hash: row.try_get("prev_hash")?,
            hash: row.try_get("hash")?,
        })
    }

    async fn append_async(
        &self,
        input: EventInput,
        idempotency_key: Option<String>,
    ) -> Result<AppendOutcome, StoreError> {
        let key_claim = idempotency_key.map(|key| {
            (
                idempotency_key_hash(&input.source, &key),
                idempotency_request_hash(&input),
            )
        });
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        // Unlike the local tokio mutex, this transaction-scoped lock coordinates every PgStore
        // process using the same database. The next statement gets a fresh READ COMMITTED
        // snapshot after any previous appender commits, so the observed head is authoritative.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(POSTGRES_APPEND_LOCK_ID)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        if let Some((key_hash, request_hash)) = &key_claim {
            let existing = sqlx::query(
                "SELECT request_hash, event_seq FROM audit_idempotency_keys WHERE key_hash = $1",
            )
            .bind(key_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
            if let Some(row) = existing {
                let stored_request_hash: String = row
                    .try_get("request_hash")
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                if stored_request_hash != *request_hash {
                    return Err(StoreError::IdempotencyConflict);
                }
                let event_seq: i64 = row
                    .try_get("event_seq")
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                let event_row = sqlx::query(
                    "SELECT seq, ts, actor, action, target, severity, detail, source, \
                            prev_hash, hash \
                     FROM audit_events WHERE seq = $1",
                )
                .bind(event_seq)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .ok_or_else(|| {
                    StoreError::Backend(format!(
                        "idempotency mapping references missing event seq {event_seq}"
                    ))
                })?;
                let event = Self::event_from_row(&event_row)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                return Ok(AppendOutcome {
                    event,
                    appended: false,
                });
            }
        }

        // Read and extend the current head inside the same transaction as the optional key claim.
        let head = sqlx::query("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let (seq, prev_hash) = match head {
            Some(row) => {
                let s: i64 = row
                    .try_get("seq")
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                let h: String = row
                    .try_get("hash")
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                (s + 1, h)
            }
            None => (1, GENESIS_HASH_HEX.to_string()),
        };
        let event = input.seal(seq, prev_hash);
        sqlx::query(
            "INSERT INTO audit_events \
                 (seq, ts, actor, action, target, severity, detail, source, prev_hash, hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(event.seq)
        .bind(event.ts)
        .bind(&event.actor)
        .bind(&event.action)
        .bind(&event.target)
        .bind(&event.severity)
        .bind(&event.detail)
        .bind(&event.source)
        .bind(&event.prev_hash)
        .bind(&event.hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::Backend(e.to_string()))?;

        if let Some((key_hash, request_hash)) = key_claim {
            sqlx::query(
                "INSERT INTO audit_idempotency_keys \
                     (key_hash, request_hash, event_seq, created_at) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(key_hash)
            .bind(request_hash)
            .bind(event.seq)
            .bind(event.ts)
            .execute(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(AppendOutcome {
            event,
            appended: true,
        })
    }

    fn checkpoint_from_row(row: &sqlx::postgres::PgRow) -> Result<Checkpoint, sqlx::Error> {
        Ok(Checkpoint {
            id: row.try_get("id")?,
            seq_hi: row.try_get("seq_hi")?,
            merkle_root: row.try_get("merkle_root")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn alert_rule_from_row(row: &sqlx::postgres::PgRow) -> Result<AlertRule, sqlx::Error> {
        Ok(AlertRule {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            actor: row.try_get("actor")?,
            action: row.try_get("action")?,
            source: row.try_get("source")?,
            severity: row.try_get("severity")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn alert_match_from_row(row: &sqlx::postgres::PgRow) -> Result<AlertMatch, sqlx::Error> {
        Ok(AlertMatch {
            id: row.try_get("id")?,
            rule_id: row.try_get("rule_id")?,
            rule_name: row.try_get("rule_name")?,
            event_seq: row.try_get("event_seq")?,
            actor: row.try_get("actor")?,
            action: row.try_get("action")?,
            target: row.try_get("target")?,
            severity: row.try_get("severity")?,
            source: row.try_get("source")?,
            matched_at: row.try_get("matched_at")?,
        })
    }

    async fn insert_checkpoint_async(&self, cp: Checkpoint) -> Result<(), sqlx::Error> {
        // Idempotent insert: re-sealing an identical (id) state is a harmless no-op, so this is
        // not a mutation. No update/delete path exists for checkpoints either.
        sqlx::query(
            "INSERT INTO checkpoints (id, seq_hi, merkle_root, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING",
        )
        .bind(&cp.id)
        .bind(cp.seq_hi)
        .bind(&cp.merkle_root)
        .bind(cp.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn all_checkpoints_async(&self) -> Result<Vec<Checkpoint>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, seq_hi, merkle_root, created_at FROM checkpoints ORDER BY seq_hi ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::checkpoint_from_row).collect()
    }

    async fn insert_alert_rule_async(&self, rule: AlertRule) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO alert_rules \
                 (id, name, actor, action, source, severity, created_by, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO NOTHING",
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.actor)
        .bind(&rule.action)
        .bind(&rule.source)
        .bind(&rule.severity)
        .bind(&rule.created_by)
        .bind(rule.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn all_alert_rules_async(&self) -> Result<Vec<AlertRule>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, name, actor, action, source, severity, created_by, created_at \
             FROM alert_rules ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::alert_rule_from_row).collect()
    }

    async fn insert_alert_match_async(&self, hit: &AlertMatch) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO alert_matches \
                 (id, rule_id, rule_name, event_seq, actor, action, target, severity, source, matched_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id) DO NOTHING",
        )
        .bind(&hit.id)
        .bind(&hit.rule_id)
        .bind(&hit.rule_name)
        .bind(hit.event_seq)
        .bind(&hit.actor)
        .bind(&hit.action)
        .bind(&hit.target)
        .bind(&hit.severity)
        .bind(&hit.source)
        .bind(hit.matched_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_alert_matches_async(
        &self,
        event: &AuditEvent,
        matched_at: i64,
    ) -> Result<Vec<AlertMatch>, sqlx::Error> {
        let rules = self.all_alert_rules_async().await?;
        let mut inserted = Vec::new();
        for rule in rules.iter().filter(|r| r.matches(event)) {
            let hit = make_alert_match(rule, event, matched_at);
            self.insert_alert_match_async(&hit).await?;
            inserted.push(hit);
        }
        Ok(inserted)
    }

    async fn recent_alert_matches_async(
        &self,
        limit: usize,
    ) -> Result<Vec<AlertMatch>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, rule_id, rule_name, event_seq, actor, action, target, severity, source, matched_at \
             FROM alert_matches ORDER BY matched_at DESC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::alert_match_from_row).collect()
    }

    async fn all_events_async(&self) -> Result<Vec<AuditEvent>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT seq, ts, actor, action, target, severity, detail, source, prev_hash, hash \
             FROM audit_events ORDER BY seq ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::event_from_row).collect()
    }

    async fn query_async(&self, filter: &EventFilter) -> Result<Vec<AuditEvent>, sqlx::Error> {
        // Build the WHERE incrementally so placeholders ($1, $2, ...) line up with the bind
        // order below. All filters are optional; q expands to three LIKE binds.
        let mut sql = String::from(
            "SELECT seq, ts, actor, action, target, severity, detail, source, prev_hash, hash \
             FROM audit_events",
        );
        let mut conds: Vec<String> = Vec::new();
        let mut n = 0;
        if filter.actor.is_some() {
            n += 1;
            conds.push(format!("actor = ${n}"));
        }
        if filter.action.is_some() {
            n += 1;
            conds.push(format!("action = ${n}"));
        }
        if filter.source.is_some() {
            n += 1;
            conds.push(format!("source = ${n}"));
        }
        if filter.severity.is_some() {
            n += 1;
            conds.push(format!("severity = ${n}"));
        }
        if filter.since.is_some() {
            n += 1;
            conds.push(format!("ts >= ${n}"));
        }
        if filter.until.is_some() {
            n += 1;
            conds.push(format!("ts <= ${n}"));
        }
        if filter.q.is_some() {
            let (a, b, c, d, e, f) = (n + 1, n + 2, n + 3, n + 4, n + 5, n + 6);
            n += 6;
            conds.push(format!(
                "(lower(actor) LIKE ${a} OR lower(action) LIKE ${b} OR lower(target) LIKE ${c} \
                  OR lower(detail) LIKE ${d} OR lower(source) LIKE ${e} OR lower(severity) LIKE ${f})"
            ));
        }
        if !conds.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conds.join(" AND "));
        }
        n += 1;
        let limit_n = n;
        n += 1;
        let offset_n = n;
        sql.push_str(&format!(
            " ORDER BY seq DESC LIMIT ${limit_n} OFFSET ${offset_n}"
        ));

        let mut query = sqlx::query(&sql);
        if let Some(actor) = &filter.actor {
            query = query.bind(actor);
        }
        if let Some(action) = &filter.action {
            query = query.bind(action);
        }
        if let Some(source) = &filter.source {
            query = query.bind(source);
        }
        if let Some(severity) = &filter.severity {
            query = query.bind(severity);
        }
        if let Some(since) = filter.since {
            query = query.bind(since);
        }
        if let Some(until) = filter.until {
            query = query.bind(until);
        }
        if let Some(q) = &filter.q {
            let pat = format!("%{}%", q.to_lowercase());
            query = query
                .bind(pat.clone())
                .bind(pat.clone())
                .bind(pat.clone())
                .bind(pat.clone())
                .bind(pat.clone())
                .bind(pat);
        }
        query = query.bind(filter.limit as i64).bind(filter.offset as i64);

        let rows = query.fetch_all(&self.pool).await?;
        rows.iter().map(Self::event_from_row).collect()
    }

    async fn count_async(&self, filter: &EventFilter) -> Result<usize, sqlx::Error> {
        let mut sql = String::from("SELECT COUNT(*) AS count FROM audit_events");
        let mut conds: Vec<String> = Vec::new();
        let mut n = 0;
        if filter.actor.is_some() {
            n += 1;
            conds.push(format!("actor = ${n}"));
        }
        if filter.action.is_some() {
            n += 1;
            conds.push(format!("action = ${n}"));
        }
        if filter.source.is_some() {
            n += 1;
            conds.push(format!("source = ${n}"));
        }
        if filter.severity.is_some() {
            n += 1;
            conds.push(format!("severity = ${n}"));
        }
        if filter.since.is_some() {
            n += 1;
            conds.push(format!("ts >= ${n}"));
        }
        if filter.until.is_some() {
            n += 1;
            conds.push(format!("ts <= ${n}"));
        }
        if filter.q.is_some() {
            let (a, b, c, d, e, f) = (n + 1, n + 2, n + 3, n + 4, n + 5, n + 6);
            conds.push(format!(
                "(lower(actor) LIKE ${a} OR lower(action) LIKE ${b} OR lower(target) LIKE ${c} \
                  OR lower(detail) LIKE ${d} OR lower(source) LIKE ${e} OR lower(severity) LIKE ${f})"
            ));
        }
        if !conds.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conds.join(" AND "));
        }

        let mut query = sqlx::query(&sql);
        if let Some(actor) = &filter.actor {
            query = query.bind(actor);
        }
        if let Some(action) = &filter.action {
            query = query.bind(action);
        }
        if let Some(source) = &filter.source {
            query = query.bind(source);
        }
        if let Some(severity) = &filter.severity {
            query = query.bind(severity);
        }
        if let Some(since) = filter.since {
            query = query.bind(since);
        }
        if let Some(until) = filter.until {
            query = query.bind(until);
        }
        if let Some(q) = &filter.q {
            let pat = format!("%{}%", q.to_lowercase());
            query = query
                .bind(pat.clone())
                .bind(pat.clone())
                .bind(pat.clone())
                .bind(pat.clone())
                .bind(pat.clone())
                .bind(pat);
        }

        let row = query.fetch_one(&self.pool).await?;
        let count: i64 = row.try_get("count")?;
        Ok(count.max(0) as usize)
    }
}

#[async_trait]
impl Store for PgStore {
    async fn append(&self, input: EventInput) -> Result<AuditEvent, StoreError> {
        // The tokio mutex avoids needless same-process database lock contention; append_async's
        // transaction-scoped advisory lock is the cross-process chain authority.
        let _guard = self.append_guard.lock().await;
        Ok(self.append_async(input, None).await?.event)
    }

    async fn append_idempotent(
        &self,
        input: EventInput,
        key: String,
    ) -> Result<AppendOutcome, StoreError> {
        let _guard = self.append_guard.lock().await;
        self.append_async(input, Some(key)).await
    }

    async fn all_events(&self) -> Result<Vec<AuditEvent>, StoreError> {
        self.all_events_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn query(&self, filter: &EventFilter) -> Result<Vec<AuditEvent>, StoreError> {
        self.query_async(filter)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn count(&self, filter: &EventFilter) -> Result<usize, StoreError> {
        self.count_async(filter)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn insert_checkpoint(&self, checkpoint: Checkpoint) -> Result<(), StoreError> {
        self.insert_checkpoint_async(checkpoint)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn all_checkpoints(&self) -> Result<Vec<Checkpoint>, StoreError> {
        self.all_checkpoints_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn insert_alert_rule(&self, rule: AlertRule) -> Result<(), StoreError> {
        self.insert_alert_rule_async(rule)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn all_alert_rules(&self) -> Result<Vec<AlertRule>, StoreError> {
        self.all_alert_rules_async()
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn record_alert_matches(
        &self,
        event: &AuditEvent,
        matched_at: i64,
    ) -> Result<Vec<AlertMatch>, StoreError> {
        self.record_alert_matches_async(event, matched_at)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn recent_alert_matches(&self, limit: usize) -> Result<Vec<AlertMatch>, StoreError> {
        self.recent_alert_matches_async(limit)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod idempotency_tests {
    use std::sync::Arc;

    use super::*;

    fn input(source: &str, detail: &str) -> EventInput {
        EventInput {
            ts: 100,
            actor: "u_test".to_string(),
            action: "message.send".to_string(),
            target: "room_42".to_string(),
            severity: "info".to_string(),
            detail: detail.to_string(),
            source: source.to_string(),
        }
    }

    #[tokio::test]
    async fn memory_claim_is_atomic_source_scoped_and_payload_bound() {
        let store = InMemoryStore::new();
        let key = "c".repeat(64);

        let original = store
            .append_idempotent(input("murmur", "m_1"), key.clone())
            .await
            .unwrap();
        assert!(original.appended);
        let mut retried_input = input("murmur", "m_1");
        retried_input.ts = 999;
        let replay = store
            .append_idempotent(retried_input, key.clone())
            .await
            .unwrap();
        assert!(!replay.appended);
        assert_eq!(replay.event.hash, original.event.hash);
        assert_eq!(replay.event.seq, original.event.seq);

        let conflict = store
            .append_idempotent(input("murmur", "m_2"), key.clone())
            .await;
        assert!(matches!(conflict, Err(StoreError::IdempotencyConflict)));

        let other_source = store
            .append_idempotent(input("sluice", "m_2"), key)
            .await
            .unwrap();
        assert!(other_source.appended);
        assert_eq!(other_source.event.seq, 2);
        assert_eq!(store.all_events().await.unwrap().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn memory_concurrent_retries_have_one_authoritative_event() {
        let store = Arc::new(InMemoryStore::new());
        let key = "1".repeat(64);
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let store = Arc::clone(&store);
            let key = key.clone();
            tasks.push(tokio::spawn(async move {
                store
                    .append_idempotent(input("murmur", "m_concurrent"), key)
                    .await
                    .unwrap()
            }));
        }

        let mut outcomes = Vec::new();
        for task in tasks {
            outcomes.push(task.await.unwrap());
        }
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.appended).count(),
            1
        );
        assert!(outcomes.iter().all(|outcome| {
            outcome.event.seq == outcomes[0].event.seq
                && outcome.event.hash == outcomes[0].event.hash
                && outcome.event.ts == outcomes[0].event.ts
        }));
        assert_eq!(store.all_events().await.unwrap().len(), 1);
    }
}
