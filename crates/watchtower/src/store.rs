//! Append-only audit storage.
//!
//! `Store` is a small trait with an in-memory and a PostgreSQL implementation, mirroring
//! the keystone/keyward seam: handlers depend only on the trait, so a FusionDB-backed store
//! can drop in later. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT,
//! PRIMARY KEY/NOT NULL, parameterized queries, `lower(..) LIKE ..`, plain indexes) and
//! runtime queries (no compile-time macros), so the build needs NO database and the same
//! statements later run unchanged on FusionDB over pgwire.
//!
//! INVARIANT — append-only & single-writer: there is NO update or delete code path. The
//! only mutation is [`Store::append`], which is serialized (the in-memory store behind its
//! `Mutex`; the Postgres store behind a process-wide serial guard + a DB transaction) so the
//! chain head is read, extended, and written atomically and the chain stays well-defined.
//! Production additionally grants the audit DB user only INSERT/SELECT, so even a compromised
//! service cannot rewrite history.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::chain::{AuditEvent, EventInput, GENESIS_HASH_HEX};
use crate::config::QUERY_LIMIT;
use crate::merkle::Checkpoint;

/// Storage failure surfaced to the handler layer (mapped to a 500 `server_error`).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Filters for `GET /api/events` and the dashboard timeline.
///
/// `actor`/`action` are exact matches; `since` is `ts >= since`; `q` is a case-insensitive
/// substring search over `action`/`target`/`detail` (the semantic-search seam for the later
/// FusionDB hook). Results are newest-first (`seq` DESC), capped at [`EventFilter::limit`].
#[derive(Clone, Debug, Default)]
pub struct EventFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub since: Option<i64>,
    pub q: Option<String>,
    pub limit: usize,
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
        if let Some(since) = self.since {
            if e.ts < since {
                return false;
            }
        }
        if let Some(q) = &self.q {
            let needle = q.to_lowercase();
            let hit = e.action.to_lowercase().contains(&needle)
                || e.target.to_lowercase().contains(&needle)
                || e.detail.to_lowercase().contains(&needle);
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

    /// Every event ordered by `seq` ascending — the input to [`crate::chain::verify_chain`].
    async fn all_events(&self) -> Result<Vec<AuditEvent>, StoreError>;

    /// Filtered, newest-first, capped query for the API + dashboard timeline.
    async fn query(&self, filter: &EventFilter) -> Result<Vec<AuditEvent>, StoreError>;

    /// Persist a sealed Merkle [`Checkpoint`] (ADDED tamper-evidence summary; see
    /// [`crate::merkle`]). Idempotent on `id`: re-sealing an identical state is a no-op, so this
    /// is NOT a mutation of any existing row. The append-only chain is untouched.
    async fn insert_checkpoint(&self, checkpoint: Checkpoint) -> Result<(), StoreError>;

    /// Every stored checkpoint, ordered by `seq_hi` ascending.
    async fn all_checkpoints(&self) -> Result<Vec<Checkpoint>, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

/// In-memory `Store`. The `Mutex<Vec<_>>` IS the serial guard: every append takes the lock,
/// reads the head, seals, and pushes — so appends are strictly serialized and the vector is
/// always ordered by `seq` ascending.
#[derive(Default)]
pub struct InMemoryStore {
    events: Mutex<Vec<AuditEvent>>,
    /// Sealed Merkle checkpoints. Separate lock from `events`: sealing/listing checkpoints never
    /// contends with the append critical section, and reads never block appends.
    checkpoints: Mutex<Vec<Checkpoint>>,
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
        let mut events = self.events.lock().expect("events lock poisoned");
        let (seq, prev_hash) = match events.last() {
            Some(head) => (head.seq + 1, head.hash.clone()),
            None => (1, GENESIS_HASH_HEX.to_string()),
        };
        let event = input.seal(seq, prev_hash);
        events.push(event.clone());
        Ok(event)
    }

    async fn all_events(&self) -> Result<Vec<AuditEvent>, StoreError> {
        Ok(self.events.lock().expect("events lock poisoned").clone())
    }

    async fn query(&self, filter: &EventFilter) -> Result<Vec<AuditEvent>, StoreError> {
        let events = self.events.lock().expect("events lock poisoned");
        let mut out: Vec<AuditEvent> = events
            .iter()
            .rev() // newest first
            .filter(|e| filter.matches(e))
            .take(filter.limit)
            .cloned()
            .collect();
        out.shrink_to_fit();
        Ok(out)
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
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `WATCHTOWER_STORE=postgres`. The `Store` trait is async, so each method
// uses sqlx natively and the handlers `.await` it on the serving runtime — there is NO
// `block_in_place` and NO sync-over-async, so a full-chain read never blocks a worker thread.
// Appends are serialized by an in-process `tokio::sync::Mutex<()>` guard held across the DB
// transaction, so the "read head -> seal -> insert" step is the single writer and the chain
// stays well-defined; reads never take that guard, so they run fully concurrently.

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

    async fn append_async(&self, input: EventInput) -> Result<AuditEvent, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Read the current head inside the transaction (the serial guard already prevents a
        // concurrent appender in-process; the transaction bounds the read+write atomically).
        let head = sqlx::query("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
        let (seq, prev_hash) = match head {
            Some(row) => {
                let s: i64 = row.try_get("seq")?;
                let h: String = row.try_get("hash")?;
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
        .await?;
        tx.commit().await?;
        Ok(event)
    }

    fn checkpoint_from_row(row: &sqlx::postgres::PgRow) -> Result<Checkpoint, sqlx::Error> {
        Ok(Checkpoint {
            id: row.try_get("id")?,
            seq_hi: row.try_get("seq_hi")?,
            merkle_root: row.try_get("merkle_root")?,
            created_at: row.try_get("created_at")?,
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
        if filter.since.is_some() {
            n += 1;
            conds.push(format!("ts >= ${n}"));
        }
        if filter.q.is_some() {
            let (a, b, c) = (n + 1, n + 2, n + 3);
            n += 3;
            conds.push(format!(
                "(lower(action) LIKE ${a} OR lower(target) LIKE ${b} OR lower(detail) LIKE ${c})"
            ));
        }
        if !conds.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conds.join(" AND "));
        }
        n += 1;
        sql.push_str(&format!(" ORDER BY seq DESC LIMIT ${n}"));

        let mut query = sqlx::query(&sql);
        if let Some(actor) = &filter.actor {
            query = query.bind(actor);
        }
        if let Some(action) = &filter.action {
            query = query.bind(action);
        }
        if let Some(since) = filter.since {
            query = query.bind(since);
        }
        if let Some(q) = &filter.q {
            let pat = format!("%{}%", q.to_lowercase());
            query = query.bind(pat.clone()).bind(pat.clone()).bind(pat);
        }
        query = query.bind(filter.limit as i64);

        let rows = query.fetch_all(&self.pool).await?;
        rows.iter().map(Self::event_from_row).collect()
    }
}

#[async_trait]
impl Store for PgStore {
    async fn append(&self, input: EventInput) -> Result<AuditEvent, StoreError> {
        // Serial guard: only one append runs the read-head -> insert sequence at a time. The
        // tokio `Mutex` is held across the transaction `.await` without blocking a worker thread,
        // and reads never take it — so an append burst can never starve concurrent full-chain
        // reads or `/healthz`.
        let _guard = self.append_guard.lock().await;
        self.append_async(input)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
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
}
