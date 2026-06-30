//! Incident + note storage (Hindsight's OWN database).
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring
//! the keystone/inkwell seam: handlers depend only on the trait, so a FusionDB-backed store can
//! drop in later. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT,
//! PK/NOT NULL/DEFAULT, parameterized queries) and runtime queries (no compile-time macros), so
//! the build needs NO database and the same statements later run unchanged on FusionDB over
//! pgwire.
//!
//! The methods are `async`: the axum handlers `.await` them directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge, so
//! a DB round-trip never blocks a worker thread. Writes are serialized through a `tokio::sync::
//! Mutex` so id generation + insert form one critical section.

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::LIST_LIMIT;

/// An incident (maps 1:1 to an `incidents` row). `to_ts == 0` means the incident is still open /
/// ongoing — the evidence window extends to "now" when correlating.
#[derive(Clone, Debug)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub status: String,
    pub from_ts: i64,
    pub to_ts: i64,
    pub created_by: String,
    pub created_at: i64,
}

/// A free-text note attached to an incident (maps 1:1 to a `notes` row).
#[derive(Clone, Debug)]
pub struct Note {
    pub id: String,
    pub incident_id: String,
    pub body: String,
    pub author_sub: String,
    pub created_at: i64,
}

/// Storage failure surfaced to the handler layer (collapsed to a 500).
#[derive(Debug, Error)]
pub enum StoreError {
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable incident store.
#[async_trait]
pub trait Store: Send + Sync {
    /// All incidents, newest-first (`created_at` DESC), capped at [`LIST_LIMIT`].
    async fn list_incidents(&self) -> Vec<Incident>;
    /// One incident by its id.
    async fn get_incident(&self, id: &str) -> Option<Incident>;
    /// Insert a new incident.
    async fn create_incident(&self, incident: &Incident) -> Result<(), StoreError>;
    /// All notes for an incident, oldest-first (`created_at` ASC) so the thread reads in order.
    async fn list_notes(&self, incident_id: &str) -> Vec<Note>;
    /// Insert a new note.
    async fn add_note(&self, note: &Note) -> Result<(), StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    incidents: Mutex<Vec<Incident>>,
    notes: Mutex<Vec<Note>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no
    // `.await` inside), so a guard is never held across a yield point.
    async fn list_incidents(&self) -> Vec<Incident> {
        let incidents = self.incidents.lock().expect("incidents lock poisoned");
        let mut v: Vec<Incident> = incidents.clone();
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        v.truncate(LIST_LIMIT);
        v
    }

    async fn get_incident(&self, id: &str) -> Option<Incident> {
        self.incidents
            .lock()
            .expect("incidents lock poisoned")
            .iter()
            .find(|i| i.id == id)
            .cloned()
    }

    async fn create_incident(&self, incident: &Incident) -> Result<(), StoreError> {
        self.incidents
            .lock()
            .expect("incidents lock poisoned")
            .push(incident.clone());
        Ok(())
    }

    async fn list_notes(&self, incident_id: &str) -> Vec<Note> {
        let notes = self.notes.lock().expect("notes lock poisoned");
        let mut v: Vec<Note> = notes
            .iter()
            .filter(|n| n.incident_id == incident_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.id.cmp(&b.id)));
        v
    }

    async fn add_note(&self, note: &Note) -> Result<(), StoreError> {
        self.notes
            .lock()
            .expect("notes lock poisoned")
            .push(note.clone());
        Ok(())
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `HINDSIGHT_STORE=postgres`. Each method drives sqlx natively and the
// handlers `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. Writes
// are serialized through a `tokio::sync::Mutex` so a single connection runs the insert.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use tokio::sync::Mutex as AsyncMutex;

/// PostgreSQL-backed [`Store`]. Holds a `PgPool` plus a write serializer.
pub struct PgStore {
    pool: PgPool,
    write_lock: AsyncMutex<()>,
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
            write_lock: AsyncMutex::new(()),
        }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS incidents (\
                 id TEXT PRIMARY KEY, \
                 title TEXT NOT NULL, \
                 status TEXT NOT NULL DEFAULT 'open', \
                 from_ts BIGINT, \
                 to_ts BIGINT NOT NULL DEFAULT 0, \
                 created_by TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS notes (\
                 id TEXT PRIMARY KEY, \
                 incident_id TEXT NOT NULL, \
                 body TEXT NOT NULL, \
                 author_sub TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs the newest-first incident list scan.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at)")
            .execute(&self.pool)
            .await?;
        // Backs the per-incident note lookup.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_notes_incident_id ON notes (incident_id)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn incident_from_row(row: &sqlx::postgres::PgRow) -> Result<Incident, sqlx::Error> {
        // `from_ts` / `created_at` are nullable columns; default a NULL to 0 so reads never fail.
        let from_ts: Option<i64> = row.try_get("from_ts")?;
        let created_at: Option<i64> = row.try_get("created_at")?;
        Ok(Incident {
            id: row.try_get("id")?,
            title: row.try_get("title")?,
            status: row.try_get("status")?,
            from_ts: from_ts.unwrap_or(0),
            to_ts: row.try_get("to_ts")?,
            created_by: row.try_get("created_by")?,
            created_at: created_at.unwrap_or(0),
        })
    }

    fn note_from_row(row: &sqlx::postgres::PgRow) -> Result<Note, sqlx::Error> {
        let created_at: Option<i64> = row.try_get("created_at")?;
        Ok(Note {
            id: row.try_get("id")?,
            incident_id: row.try_get("incident_id")?,
            body: row.try_get("body")?,
            author_sub: row.try_get("author_sub")?,
            created_at: created_at.unwrap_or(0),
        })
    }

    async fn list_incidents_async(&self) -> Result<Vec<Incident>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, title, status, from_ts, to_ts, created_by, created_at \
             FROM incidents ORDER BY created_at DESC, id DESC LIMIT $1",
        )
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::incident_from_row).collect()
    }

    async fn get_incident_async(&self, id: &str) -> Result<Option<Incident>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, title, status, from_ts, to_ts, created_by, created_at \
             FROM incidents WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Self::incident_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn create_incident_async(&self, i: &Incident) -> Result<(), sqlx::Error> {
        let _guard = self.write_lock.lock().await;
        sqlx::query(
            "INSERT INTO incidents \
                 (id, title, status, from_ts, to_ts, created_by, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&i.id)
        .bind(&i.title)
        .bind(&i.status)
        .bind(i.from_ts)
        .bind(i.to_ts)
        .bind(&i.created_by)
        .bind(i.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_notes_async(&self, incident_id: &str) -> Result<Vec<Note>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, incident_id, body, author_sub, created_at \
             FROM notes WHERE incident_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind(incident_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::note_from_row).collect()
    }

    async fn add_note_async(&self, n: &Note) -> Result<(), sqlx::Error> {
        let _guard = self.write_lock.lock().await;
        sqlx::query(
            "INSERT INTO notes (id, incident_id, body, author_sub, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&n.id)
        .bind(&n.incident_id)
        .bind(&n.body)
        .bind(&n.author_sub)
        .bind(n.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_incidents(&self) -> Vec<Incident> {
        self.list_incidents_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_incidents failed");
            Vec::new()
        })
    }

    async fn get_incident(&self, id: &str) -> Option<Incident> {
        self.get_incident_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_incident failed");
            None
        })
    }

    async fn create_incident(&self, incident: &Incident) -> Result<(), StoreError> {
        self.create_incident_async(incident)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_notes(&self, incident_id: &str) -> Vec<Note> {
        self.list_notes_async(incident_id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_notes failed");
            Vec::new()
        })
    }

    async fn add_note(&self, note: &Note) -> Result<(), StoreError> {
        self.add_note_async(note)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inc(id: &str, created_at: i64) -> Incident {
        Incident {
            id: id.to_string(),
            title: format!("incident {id}"),
            status: "open".to_string(),
            from_ts: created_at - 3600,
            to_ts: 0,
            created_by: "u_op".to_string(),
            created_at,
        }
    }

    #[tokio::test]
    async fn incidents_listed_newest_first() {
        let store = InMemoryStore::new();
        store.create_incident(&inc("inc_1", 100)).await.unwrap();
        store.create_incident(&inc("inc_2", 300)).await.unwrap();
        store.create_incident(&inc("inc_3", 200)).await.unwrap();
        let list = store.list_incidents().await;
        let ids: Vec<&str> = list.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["inc_2", "inc_3", "inc_1"]);
    }

    #[tokio::test]
    async fn notes_scoped_to_incident_oldest_first() {
        let store = InMemoryStore::new();
        store.create_incident(&inc("inc_1", 100)).await.unwrap();
        for (id, ts) in [("n_b", 20), ("n_a", 10), ("n_c", 30)] {
            store
                .add_note(&Note {
                    id: id.to_string(),
                    incident_id: "inc_1".to_string(),
                    body: "x".to_string(),
                    author_sub: "u_op".to_string(),
                    created_at: ts,
                })
                .await
                .unwrap();
        }
        store
            .add_note(&Note {
                id: "n_other".to_string(),
                incident_id: "inc_2".to_string(),
                body: "y".to_string(),
                author_sub: "u_op".to_string(),
                created_at: 5,
            })
            .await
            .unwrap();
        let notes = store.list_notes("inc_1").await;
        let ids: Vec<&str> = notes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["n_a", "n_b", "n_c"]);
    }
}
