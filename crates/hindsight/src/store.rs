//! Fallible incident, operator-mark, and atomic resolution storage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;

use crate::view_contract::{
    ActorTruth, BoundedDisplayEmail, BoundedDisplayText, BoundedNote, BoundedRows, BoundedSubject,
    BoundedTitle, ExpectedOpen, IncidentId, IncidentLifecycle, NoteId, PublicMarkRef,
    ResolveCommandId, TruthError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreFailureKind {
    Connect,
    Timeout,
    Query,
    Decode,
    Transaction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("store unavailable")]
pub enum StoreError {
    Unavailable(StoreFailureKind),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentCase {
    pub id: IncidentId,
    pub title: BoundedTitle,
    pub lifecycle: IncidentLifecycle,
    pub from_ts_s: i64,
    pub to_ts_s_compat: i64,
    pub actor: ActorTruth,
    pub created_at_s: i64,
    pub resolution: Option<ResolutionMark>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewIncident {
    pub id: IncidentId,
    pub title: BoundedTitle,
    pub from_ts_s: i64,
    pub actor_sub: BoundedSubject,
    pub display_email: Option<BoundedDisplayEmail>,
    pub created_at_s: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorNote {
    pub id: NoteId,
    pub incident_id: IncidentId,
    pub body: BoundedNote,
    pub actor: ActorTruth,
    pub created_at_s: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewNote {
    pub id: NoteId,
    pub incident_id: IncidentId,
    pub body: BoundedNote,
    pub actor_sub: BoundedSubject,
    pub display_email: Option<BoundedDisplayEmail>,
    pub created_at_s: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionMark {
    pub incident_id: IncidentId,
    pub mark_ref: PublicMarkRef,
    pub actor: ActorTruth,
    pub resolved_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersistedResolution {
    command_id: ResolveCommandId,
    mark: ResolutionMark,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveCommand {
    pub incident_id: IncidentId,
    pub command_id: ResolveCommandId,
    pub expected_lifecycle: ExpectedOpen,
    pub actor_sub: BoundedSubject,
    pub display_email: Option<BoundedDisplayEmail>,
    pub observed_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveResult {
    Resolved {
        incident: IncidentCase,
        mark: ResolutionMark,
    },
    AlreadyResolved {
        incident: IncidentCase,
        mark: ResolutionMark,
    },
    StaleConflict {
        incident: IncidentCase,
        mark: ResolutionMark,
    },
    NotFound,
    InvariantFailure(ResolveInvariant),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveInvariant {
    UnknownLifecycle,
    OpenWithMark,
    OpenWithClosedTimestamp,
    ResolvedWithoutMark,
    ResolvedTimestampMismatch,
    OrphanMark,
    CommandIdentityCollision,
    PublicMarkRefCollision,
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn list_incidents_bounded(
        &self,
        limit_plus_one: usize,
    ) -> Result<BoundedRows<IncidentCase>, StoreError>;
    async fn get_incident_case(&self, id: &IncidentId) -> Result<Option<IncidentCase>, StoreError>;
    async fn create_incident(&self, new: NewIncident) -> Result<IncidentCase, StoreError>;
    async fn list_notes_bounded(
        &self,
        incident_id: &IncidentId,
        limit_plus_one: usize,
    ) -> Result<BoundedRows<OperatorNote>, StoreError>;
    async fn add_note(&self, new: NewNote) -> Result<OperatorNote, StoreError>;
    async fn resolve_incident(&self, command: ResolveCommand) -> Result<ResolveResult, StoreError>;
}

#[derive(Default)]
struct MemoryState {
    incidents: BTreeMap<IncidentId, IncidentCase>,
    notes: BTreeMap<NoteId, OperatorNote>,
    marks: BTreeMap<IncidentId, PersistedResolution>,
    command_index: BTreeMap<ResolveCommandId, IncidentId>,
    mark_refs: BTreeSet<PublicMarkRef>,
}

#[derive(Default)]
pub struct InMemoryStore {
    state: Mutex<MemoryState>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn list_incidents_bounded(
        &self,
        limit_plus_one: usize,
    ) -> Result<BoundedRows<IncidentCase>, StoreError> {
        let state = self.state.lock().map_err(|_| store_transaction())?;
        let mut rows = state.incidents.values().cloned().collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            right
                .created_at_s
                .cmp(&left.created_at_s)
                .then_with(|| right.id.cmp(&left.id))
        });
        rows.truncate(limit_plus_one);
        bounded(rows, limit_plus_one)
    }

    async fn get_incident_case(&self, id: &IncidentId) -> Result<Option<IncidentCase>, StoreError> {
        let state = self.state.lock().map_err(|_| store_transaction())?;
        Ok(state.incidents.get(id).cloned())
    }

    async fn create_incident(&self, new: NewIncident) -> Result<IncidentCase, StoreError> {
        if new.from_ts_s <= 0 || new.created_at_s <= 0 {
            return Err(store_decode());
        }
        let mut state = self.state.lock().map_err(|_| store_transaction())?;
        if state.incidents.contains_key(&new.id) {
            return Err(store_query());
        }
        let incident = IncidentCase {
            id: new.id.clone(),
            title: new.title,
            lifecycle: IncidentLifecycle::Open,
            from_ts_s: new.from_ts_s,
            to_ts_s_compat: 0,
            actor: ActorTruth::Verified {
                subject: new.actor_sub,
                display_email: new.display_email,
            },
            created_at_s: new.created_at_s,
            resolution: None,
        };
        state.incidents.insert(new.id, incident.clone());
        Ok(incident)
    }

    async fn list_notes_bounded(
        &self,
        incident_id: &IncidentId,
        limit_plus_one: usize,
    ) -> Result<BoundedRows<OperatorNote>, StoreError> {
        let state = self.state.lock().map_err(|_| store_transaction())?;
        let mut rows = state
            .notes
            .values()
            .filter(|note| &note.incident_id == incident_id)
            .cloned()
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.created_at_s
                .cmp(&right.created_at_s)
                .then_with(|| left.id.cmp(&right.id))
        });
        rows.truncate(limit_plus_one);
        bounded(rows, limit_plus_one)
    }

    async fn add_note(&self, new: NewNote) -> Result<OperatorNote, StoreError> {
        if new.created_at_s <= 0 {
            return Err(store_decode());
        }
        let mut state = self.state.lock().map_err(|_| store_transaction())?;
        if !state.incidents.contains_key(&new.incident_id) {
            return Err(store_query());
        }
        if state.notes.contains_key(&new.id) {
            return Err(store_query());
        }
        let note = OperatorNote {
            id: new.id.clone(),
            incident_id: new.incident_id,
            body: new.body,
            actor: ActorTruth::Verified {
                subject: new.actor_sub,
                display_email: new.display_email,
            },
            created_at_s: new.created_at_s,
        };
        state.notes.insert(new.id, note.clone());
        Ok(note)
    }

    async fn resolve_incident(&self, command: ResolveCommand) -> Result<ResolveResult, StoreError> {
        if command.observed_at_ms <= 0 {
            return Ok(ResolveResult::InvariantFailure(
                ResolveInvariant::ResolvedTimestampMismatch,
            ));
        }
        let mut state = self.state.lock().map_err(|_| store_transaction())?;
        let Some(current) = state.incidents.get(&command.incident_id).cloned() else {
            return Ok(ResolveResult::NotFound);
        };
        let persisted_mark = state.marks.get(&command.incident_id).cloned();
        if let Some(persisted) = &persisted_mark {
            if persisted.mark.incident_id != current.id {
                return Ok(ResolveResult::InvariantFailure(
                    ResolveInvariant::OrphanMark,
                ));
            }
        }
        match current.lifecycle {
            IncidentLifecycle::Open => {
                if persisted_mark.is_some() || current.resolution.is_some() {
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::OpenWithMark,
                    ));
                }
                if current.to_ts_s_compat > 0 {
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::OpenWithClosedTimestamp,
                    ));
                }
                if state
                    .command_index
                    .get(&command.command_id)
                    .is_some_and(|id| id != &command.incident_id)
                {
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::CommandIdentityCollision,
                    ));
                }
                let mark_ref = PublicMarkRef::generate();
                if state.mark_refs.contains(&mark_ref) {
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::PublicMarkRefCollision,
                    ));
                }
                let mark = ResolutionMark {
                    incident_id: command.incident_id.clone(),
                    mark_ref: mark_ref.clone(),
                    actor: ActorTruth::Verified {
                        subject: command.actor_sub,
                        display_email: command.display_email,
                    },
                    resolved_at_ms: command.observed_at_ms,
                };
                let mut resolved = current;
                resolved.lifecycle = IncidentLifecycle::Resolved;
                resolved.to_ts_s_compat = command.observed_at_ms.div_euclid(1_000);
                resolved.resolution = Some(mark.clone());
                state
                    .command_index
                    .insert(command.command_id.clone(), command.incident_id.clone());
                state.mark_refs.insert(mark_ref);
                state.marks.insert(
                    command.incident_id.clone(),
                    PersistedResolution {
                        command_id: command.command_id.clone(),
                        mark: mark.clone(),
                    },
                );
                state
                    .incidents
                    .insert(command.incident_id, resolved.clone());
                Ok(ResolveResult::Resolved {
                    incident: resolved,
                    mark,
                })
            }
            IncidentLifecycle::Resolved => {
                let Some(persisted) = persisted_mark else {
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::ResolvedWithoutMark,
                    ));
                };
                let mark = persisted.mark;
                if current.to_ts_s_compat != mark.resolved_at_ms.div_euclid(1_000) {
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::ResolvedTimestampMismatch,
                    ));
                }
                if persisted.command_id == command.command_id {
                    Ok(ResolveResult::AlreadyResolved {
                        incident: current,
                        mark,
                    })
                } else {
                    Ok(ResolveResult::StaleConflict {
                        incident: current,
                        mark,
                    })
                }
            }
        }
    }
}

pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await
            .map_err(map_sqlx)?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_transaction)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS incidents (\
               id TEXT PRIMARY KEY, title TEXT NOT NULL, \
               status TEXT NOT NULL DEFAULT 'open', from_ts BIGINT, \
               to_ts BIGINT NOT NULL DEFAULT 0, \
               created_by TEXT NOT NULL DEFAULT '', created_at BIGINT\
             )",
        )
        .execute(&mut *transaction)
        .await
        .map_err(map_transaction)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS notes (\
               id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, \
               body TEXT NOT NULL, author_sub TEXT NOT NULL DEFAULT '', \
               created_at BIGINT\
             )",
        )
        .execute(&mut *transaction)
        .await
        .map_err(map_transaction)?;

        match migration_state(&mut transaction).await? {
            MigrationState::Legacy => {
                preflight_legacy_rows(&mut transaction).await?;
                ensure_nullable_text_column(
                    &mut transaction,
                    "incidents",
                    "actor_sub",
                    "ALTER TABLE incidents ADD COLUMN actor_sub TEXT NULL",
                )
                .await?;
                ensure_nullable_text_column(
                    &mut transaction,
                    "incidents",
                    "display_email",
                    "ALTER TABLE incidents ADD COLUMN display_email TEXT NULL",
                )
                .await?;
                ensure_nullable_text_column(
                    &mut transaction,
                    "notes",
                    "display_email",
                    "ALTER TABLE notes ADD COLUMN display_email TEXT NULL",
                )
                .await?;
                ensure_resolution_table(&mut transaction).await?;
            }
            MigrationState::Current => {
                validate_current_schema(&mut transaction).await?;
                preflight_current_rows(&mut transaction).await?;
            }
        }

        ensure_index(
            &mut transaction,
            "idx_incidents_created_at",
            "incidents",
            "created_at",
            "CREATE INDEX idx_incidents_created_at ON incidents (created_at)",
        )
        .await?;
        ensure_index(
            &mut transaction,
            "idx_notes_incident_id",
            "notes",
            "incident_id",
            "CREATE INDEX idx_notes_incident_id ON notes (incident_id)",
        )
        .await?;
        validate_current_schema(&mut transaction).await?;
        preflight_current_rows(&mut transaction).await?;
        transaction.commit().await.map_err(map_transaction)
    }

    pub async fn schema_fingerprint(&self) -> Result<String, StoreError> {
        let column_rows = sqlx::query(
            "SELECT table_name, column_name, data_type, is_nullable \
             FROM information_schema.columns \
             WHERE table_schema = 'public' \
               AND table_name IN ('incidents','notes','resolution_marks') \
             ORDER BY table_name, ordinal_position",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let mut hash = 0xcbf29ce484222325_u64;
        for row in column_rows {
            for value in [
                "column".to_string(),
                row.try_get::<String, _>("table_name")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("column_name")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("data_type")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("is_nullable")
                    .map_err(|_| store_decode())?,
            ] {
                fingerprint_value(&mut hash, &value);
            }
        }
        let constraint_rows = sqlx::query(
            "SELECT rel.relname AS table_name, con.conname, con.contype::text AS contype, \
                    pg_get_constraintdef(con.oid, true) AS definition \
             FROM pg_constraint con \
             JOIN pg_class rel ON rel.oid=con.conrelid \
             JOIN pg_namespace ns ON ns.oid=rel.relnamespace \
             WHERE ns.nspname='public' \
               AND rel.relname IN ('incidents','notes','resolution_marks') \
             ORDER BY rel.relname, con.conname",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        for row in constraint_rows {
            for value in [
                "constraint".to_string(),
                row.try_get::<String, _>("table_name")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("conname")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("contype")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("definition")
                    .map_err(|_| store_decode())?,
            ] {
                fingerprint_value(&mut hash, &value);
            }
        }
        let index_rows = sqlx::query(
            "SELECT table_rel.relname AS table_name, index_rel.relname AS index_name, \
                    pg_get_indexdef(idx.indexrelid) AS definition \
             FROM pg_index idx \
             JOIN pg_class index_rel ON index_rel.oid=idx.indexrelid \
             JOIN pg_class table_rel ON table_rel.oid=idx.indrelid \
             JOIN pg_namespace ns ON ns.oid=table_rel.relnamespace \
             WHERE ns.nspname='public' \
               AND index_rel.relname IN ('idx_incidents_created_at','idx_notes_incident_id') \
             ORDER BY table_rel.relname, index_rel.relname",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        for row in index_rows {
            for value in [
                "index".to_string(),
                row.try_get::<String, _>("table_name")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("index_name")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("definition")
                    .map_err(|_| store_decode())?,
            ] {
                fingerprint_value(&mut hash, &value);
            }
        }
        Ok(format!("{hash:016x}"))
    }

    async fn select_decoded_incident(
        executor: impl sqlx::Executor<'_, Database = Postgres>,
        id: &IncidentId,
    ) -> Result<Option<DecodedIncidentRow>, StoreError> {
        let row = sqlx::query(
            "SELECT i.id, i.title, i.status, i.from_ts, i.to_ts, \
                    i.created_by, i.actor_sub, i.display_email, i.created_at, \
                    r.command_id AS resolution_command_id, \
                    r.mark_ref AS resolution_mark_ref, \
                    r.actor_sub AS resolution_actor_sub, \
                    r.display_email AS resolution_display_email, \
                    r.resolved_at_ms \
             FROM incidents i \
             LEFT JOIN resolution_marks r ON r.incident_id = i.id \
             WHERE i.id = $1",
        )
        .bind(id.as_str())
        .fetch_optional(executor)
        .await
        .map_err(map_sqlx)?;
        row.map(|row| decode_incident_row(&row)).transpose()
    }

    async fn select_incident(
        executor: impl sqlx::Executor<'_, Database = Postgres>,
        id: &IncidentId,
    ) -> Result<Option<IncidentCase>, StoreError> {
        Self::select_decoded_incident(executor, id)
            .await?
            .map(incident_from_decoded)
            .transpose()
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_incidents_bounded(
        &self,
        limit_plus_one: usize,
    ) -> Result<BoundedRows<IncidentCase>, StoreError> {
        let limit = i64::try_from(limit_plus_one).map_err(|_| store_decode())?;
        let rows = sqlx::query(
            "SELECT i.id, i.title, i.status, i.from_ts, i.to_ts, \
                    i.created_by, i.actor_sub, i.display_email, i.created_at, \
                    r.command_id AS resolution_command_id, \
                    r.mark_ref AS resolution_mark_ref, \
                    r.actor_sub AS resolution_actor_sub, \
                    r.display_email AS resolution_display_email, \
                    r.resolved_at_ms \
             FROM incidents i \
             LEFT JOIN resolution_marks r ON r.incident_id = i.id \
             ORDER BY i.created_at DESC, i.id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let rows = rows
            .iter()
            .map(incident_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        bounded(rows, limit_plus_one)
    }

    async fn get_incident_case(&self, id: &IncidentId) -> Result<Option<IncidentCase>, StoreError> {
        Self::select_incident(&self.pool, id).await
    }

    async fn create_incident(&self, new: NewIncident) -> Result<IncidentCase, StoreError> {
        if new.from_ts_s <= 0 || new.created_at_s <= 0 {
            return Err(store_decode());
        }
        sqlx::query(
            "INSERT INTO incidents \
             (id,title,status,from_ts,to_ts,created_by,actor_sub,display_email,created_at) \
             VALUES ($1,$2,'open',$3,0,$4,$4,$5,$6)",
        )
        .bind(new.id.as_str())
        .bind(new.title.as_str())
        .bind(new.from_ts_s)
        .bind(new.actor_sub.as_str())
        .bind(new.display_email.as_ref().map(BoundedDisplayEmail::as_str))
        .bind(new.created_at_s)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(IncidentCase {
            id: new.id,
            title: new.title,
            lifecycle: IncidentLifecycle::Open,
            from_ts_s: new.from_ts_s,
            to_ts_s_compat: 0,
            actor: ActorTruth::Verified {
                subject: new.actor_sub,
                display_email: new.display_email,
            },
            created_at_s: new.created_at_s,
            resolution: None,
        })
    }

    async fn list_notes_bounded(
        &self,
        incident_id: &IncidentId,
        limit_plus_one: usize,
    ) -> Result<BoundedRows<OperatorNote>, StoreError> {
        let limit = i64::try_from(limit_plus_one).map_err(|_| store_decode())?;
        let rows = sqlx::query(
            "SELECT id, incident_id, body, author_sub, display_email, created_at \
             FROM notes WHERE incident_id = $1 \
             ORDER BY created_at ASC, id ASC LIMIT $2",
        )
        .bind(incident_id.as_str())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let rows = rows
            .iter()
            .map(note_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        bounded(rows, limit_plus_one)
    }

    async fn add_note(&self, new: NewNote) -> Result<OperatorNote, StoreError> {
        if new.created_at_s <= 0 {
            return Err(store_decode());
        }
        let inserted = sqlx::query(
            "INSERT INTO notes \
             (id,incident_id,body,author_sub,display_email,created_at) \
             SELECT $1,$2,$3,$4,$5,$6 \
             WHERE EXISTS (SELECT 1 FROM incidents WHERE id=$2)",
        )
        .bind(new.id.as_str())
        .bind(new.incident_id.as_str())
        .bind(new.body.as_str())
        .bind(new.actor_sub.as_str())
        .bind(new.display_email.as_ref().map(BoundedDisplayEmail::as_str))
        .bind(new.created_at_s)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if inserted.rows_affected() != 1 {
            return Err(store_query());
        }
        Ok(OperatorNote {
            id: new.id,
            incident_id: new.incident_id,
            body: new.body,
            actor: ActorTruth::Verified {
                subject: new.actor_sub,
                display_email: new.display_email,
            },
            created_at_s: new.created_at_s,
        })
    }

    async fn resolve_incident(&self, command: ResolveCommand) -> Result<ResolveResult, StoreError> {
        if command.observed_at_ms <= 0 {
            return Ok(ResolveResult::InvariantFailure(
                ResolveInvariant::ResolvedTimestampMismatch,
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(map_transaction)?;
        let locked = sqlx::query("SELECT id FROM incidents WHERE id=$1 FOR UPDATE")
            .bind(command.incident_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_transaction)?;
        if locked.is_none() {
            transaction.rollback().await.map_err(map_transaction)?;
            return Ok(ResolveResult::NotFound);
        }
        let Some(decoded) =
            Self::select_decoded_incident(&mut *transaction, &command.incident_id).await?
        else {
            transaction.rollback().await.map_err(map_transaction)?;
            return Ok(ResolveResult::InvariantFailure(
                ResolveInvariant::UnknownLifecycle,
            ));
        };
        let lifecycle = match decoded.status.as_str() {
            "open" => IncidentLifecycle::Open,
            "resolved" => IncidentLifecycle::Resolved,
            _ => {
                transaction.rollback().await.map_err(map_transaction)?;
                return Ok(ResolveResult::InvariantFailure(
                    ResolveInvariant::UnknownLifecycle,
                ));
            }
        };
        match lifecycle {
            IncidentLifecycle::Open => {
                if decoded.resolution.is_some() {
                    transaction.rollback().await.map_err(map_transaction)?;
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::OpenWithMark,
                    ));
                }
                if decoded.to_ts_s_compat > 0 {
                    transaction.rollback().await.map_err(map_transaction)?;
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::OpenWithClosedTimestamp,
                    ));
                }
                let current = decoded.into_case(IncidentLifecycle::Open);
                let mark_ref = PublicMarkRef::generate();
                let insert = sqlx::query(
                    "INSERT INTO resolution_marks \
                     (incident_id,command_id,mark_ref,actor_sub,display_email,resolved_at_ms) \
                     VALUES ($1,$2,$3,$4,$5,$6)",
                )
                .bind(command.incident_id.as_str())
                .bind(command.command_id.as_str())
                .bind(mark_ref.as_str())
                .bind(command.actor_sub.as_str())
                .bind(
                    command
                        .display_email
                        .as_ref()
                        .map(BoundedDisplayEmail::as_str),
                )
                .bind(command.observed_at_ms)
                .execute(&mut *transaction)
                .await;
                if let Err(error) = insert {
                    let invariant = unique_invariant(&error);
                    transaction.rollback().await.map_err(map_transaction)?;
                    return match invariant {
                        Some(invariant) => Ok(ResolveResult::InvariantFailure(invariant)),
                        None => Err(map_sqlx(error)),
                    };
                }
                let updated =
                    sqlx::query("UPDATE incidents SET status='resolved', to_ts=$2 WHERE id=$1")
                        .bind(command.incident_id.as_str())
                        .bind(command.observed_at_ms.div_euclid(1_000))
                        .execute(&mut *transaction)
                        .await
                        .map_err(map_transaction)?;
                if updated.rows_affected() != 1 {
                    transaction.rollback().await.map_err(map_transaction)?;
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::UnknownLifecycle,
                    ));
                }
                let mark = ResolutionMark {
                    incident_id: command.incident_id.clone(),
                    mark_ref,
                    actor: ActorTruth::Verified {
                        subject: command.actor_sub,
                        display_email: command.display_email,
                    },
                    resolved_at_ms: command.observed_at_ms,
                };
                let mut incident = current;
                incident.lifecycle = IncidentLifecycle::Resolved;
                incident.to_ts_s_compat = mark.resolved_at_ms.div_euclid(1_000);
                incident.resolution = Some(mark.clone());
                transaction.commit().await.map_err(map_transaction)?;
                Ok(ResolveResult::Resolved { incident, mark })
            }
            IncidentLifecycle::Resolved => {
                let Some(persisted) = decoded.resolution.clone() else {
                    transaction.rollback().await.map_err(map_transaction)?;
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::ResolvedWithoutMark,
                    ));
                };
                if decoded.to_ts_s_compat != persisted.mark.resolved_at_ms.div_euclid(1_000) {
                    transaction.rollback().await.map_err(map_transaction)?;
                    return Ok(ResolveResult::InvariantFailure(
                        ResolveInvariant::ResolvedTimestampMismatch,
                    ));
                }
                let current = decoded.into_case(IncidentLifecycle::Resolved);
                transaction.commit().await.map_err(map_transaction)?;
                if persisted.command_id == command.command_id {
                    Ok(ResolveResult::AlreadyResolved {
                        incident: current,
                        mark: persisted.mark,
                    })
                } else {
                    Ok(ResolveResult::StaleConflict {
                        incident: current,
                        mark: persisted.mark,
                    })
                }
            }
        }
    }
}

#[derive(Clone)]
struct DecodedIncidentRow {
    id: IncidentId,
    title: BoundedTitle,
    status: String,
    from_ts_s: i64,
    to_ts_s_compat: i64,
    actor: ActorTruth,
    created_at_s: i64,
    resolution: Option<PersistedResolution>,
}

impl DecodedIncidentRow {
    fn into_case(self, lifecycle: IncidentLifecycle) -> IncidentCase {
        IncidentCase {
            id: self.id,
            title: self.title,
            lifecycle,
            from_ts_s: self.from_ts_s,
            to_ts_s_compat: self.to_ts_s_compat,
            actor: self.actor,
            created_at_s: self.created_at_s,
            resolution: self.resolution.map(|persisted| persisted.mark),
        }
    }
}

fn decode_incident_row(row: &PgRow) -> Result<DecodedIncidentRow, StoreError> {
    let id = IncidentId::parse(&row.try_get::<String, _>("id").map_err(|_| store_decode())?)
        .map_err(|_| store_decode())?;
    let raw_title: String = row.try_get("title").map_err(|_| store_decode())?;
    let title = BoundedTitle::parse(&raw_title).map_err(|_| store_decode())?;
    if title.as_str() != raw_title {
        return Err(store_decode());
    }
    let status: String = row.try_get("status").map_err(|_| store_decode())?;
    let from_ts_s: i64 = row.try_get("from_ts").map_err(|_| store_decode())?;
    let to_ts_s_compat: i64 = row.try_get("to_ts").map_err(|_| store_decode())?;
    let created_at_s: i64 = row.try_get("created_at").map_err(|_| store_decode())?;
    if from_ts_s <= 0 || created_at_s <= 0 {
        return Err(store_decode());
    }
    let actor_sub: Option<String> = row.try_get("actor_sub").map_err(|_| store_decode())?;
    let display_email: Option<String> = row.try_get("display_email").map_err(|_| store_decode())?;
    let actor = actor_truth(
        actor_sub,
        display_email,
        row.try_get::<String, _>("created_by")
            .map_err(|_| store_decode())?,
    )?;

    let command_id: Option<String> = row
        .try_get("resolution_command_id")
        .map_err(|_| store_decode())?;
    let resolution = match command_id {
        None => None,
        Some(command_id) => {
            let command_id = ResolveCommandId::parse(&command_id).map_err(|_| store_decode())?;
            let mark_ref = PublicMarkRef::parse(
                &row.try_get::<String, _>("resolution_mark_ref")
                    .map_err(|_| store_decode())?,
            )
            .map_err(|_| store_decode())?;
            let actor_sub = canonical_subject(
                row.try_get::<String, _>("resolution_actor_sub")
                    .map_err(|_| store_decode())?,
            )?;
            let resolution_email: Option<String> = row
                .try_get("resolution_display_email")
                .map_err(|_| store_decode())?;
            let resolved_at_ms: i64 = row.try_get("resolved_at_ms").map_err(|_| store_decode())?;
            if resolved_at_ms <= 0 {
                return Err(store_decode());
            }
            Some(PersistedResolution {
                command_id,
                mark: ResolutionMark {
                    incident_id: id.clone(),
                    mark_ref,
                    actor: ActorTruth::Verified {
                        subject: actor_sub,
                        display_email: canonical_display_email(resolution_email)?,
                    },
                    resolved_at_ms,
                },
            })
        }
    };
    Ok(DecodedIncidentRow {
        id,
        title,
        status,
        from_ts_s,
        to_ts_s_compat,
        actor,
        created_at_s,
        resolution,
    })
}

fn incident_from_row(row: &PgRow) -> Result<IncidentCase, StoreError> {
    incident_from_decoded(decode_incident_row(row)?)
}

fn incident_from_decoded(decoded: DecodedIncidentRow) -> Result<IncidentCase, StoreError> {
    let lifecycle = match decoded.status.as_str() {
        "open" => IncidentLifecycle::Open,
        "resolved" => IncidentLifecycle::Resolved,
        _ => return Err(store_decode()),
    };
    if matches!(lifecycle, IncidentLifecycle::Open)
        && (decoded.resolution.is_some() || decoded.to_ts_s_compat > 0)
    {
        return Err(store_decode());
    }
    if matches!(lifecycle, IncidentLifecycle::Resolved)
        && decoded.resolution.as_ref().is_none_or(|persisted| {
            persisted.mark.resolved_at_ms.div_euclid(1_000) != decoded.to_ts_s_compat
        })
    {
        return Err(store_decode());
    }
    Ok(decoded.into_case(lifecycle))
}

fn note_from_row(row: &PgRow) -> Result<OperatorNote, StoreError> {
    let id = NoteId::parse(&row.try_get::<String, _>("id").map_err(|_| store_decode())?)
        .map_err(|_| store_decode())?;
    let incident_id = IncidentId::parse(
        &row.try_get::<String, _>("incident_id")
            .map_err(|_| store_decode())?,
    )
    .map_err(|_| store_decode())?;
    let raw_body: String = row.try_get("body").map_err(|_| store_decode())?;
    let body = BoundedNote::parse(&raw_body).map_err(|_| store_decode())?;
    if body.as_str() != raw_body {
        return Err(store_decode());
    }
    let subject = canonical_subject(
        row.try_get::<String, _>("author_sub")
            .map_err(|_| store_decode())?,
    )?;
    let display_email: Option<String> = row.try_get("display_email").map_err(|_| store_decode())?;
    let created_at_s: i64 = row.try_get("created_at").map_err(|_| store_decode())?;
    if created_at_s <= 0 {
        return Err(store_decode());
    }
    Ok(OperatorNote {
        id,
        incident_id,
        body,
        actor: ActorTruth::Verified {
            subject,
            display_email: canonical_display_email(display_email)?,
        },
        created_at_s,
    })
}

fn actor_truth(
    subject: Option<String>,
    display_email: Option<String>,
    legacy: String,
) -> Result<ActorTruth, StoreError> {
    match subject {
        Some(subject) => Ok(ActorTruth::Verified {
            subject: canonical_subject(subject)?,
            display_email: canonical_display_email(display_email)?,
        }),
        None if display_email.is_none() => Ok(ActorTruth::LegacyUnclassified {
            legacy_display: BoundedDisplayText::project(&legacy),
        }),
        None => Err(store_decode()),
    }
}

fn canonical_subject(raw: String) -> Result<BoundedSubject, StoreError> {
    let subject = BoundedSubject::parse(&raw).map_err(|_| store_decode())?;
    if subject.as_str() != raw {
        return Err(store_decode());
    }
    Ok(subject)
}

fn canonical_display_email(raw: Option<String>) -> Result<Option<BoundedDisplayEmail>, StoreError> {
    raw.map(|raw| {
        let email = BoundedDisplayEmail::parse(&raw).map_err(|_| store_decode())?;
        if email.as_str() != raw {
            return Err(store_decode());
        }
        Ok(email)
    })
    .transpose()
}

async fn ensure_nullable_text_column(
    transaction: &mut Transaction<'_, Postgres>,
    table: &'static str,
    column: &'static str,
    statement: &'static str,
) -> Result<(), StoreError> {
    let rows = sqlx::query(
        "SELECT data_type,is_nullable \
         FROM information_schema.columns \
         WHERE table_schema='public' AND table_name=$1 AND column_name=$2",
    )
    .bind(table)
    .bind(column)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_transaction)?;
    if rows.is_empty() {
        sqlx::query(statement)
            .execute(&mut **transaction)
            .await
            .map_err(map_transaction)?;
        return Ok(());
    }
    if rows.len() != 1 {
        return Err(store_decode());
    }
    let row = &rows[0];
    if row
        .try_get::<String, _>("data_type")
        .map_err(|_| store_decode())?
        == "text"
        && row
            .try_get::<String, _>("is_nullable")
            .map_err(|_| store_decode())?
            == "YES"
    {
        Ok(())
    } else {
        Err(store_decode())
    }
}

async fn ensure_resolution_table(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), StoreError> {
    let exists =
        sqlx::query("SELECT to_regclass('public.resolution_marks') IS NOT NULL AS table_exists")
            .fetch_one(&mut **transaction)
            .await
            .map_err(map_transaction)?
            .try_get::<bool, _>("table_exists")
            .map_err(|_| store_decode())?;
    if exists {
        return Err(store_decode());
    }
    sqlx::query(
        "CREATE TABLE resolution_marks (\
           incident_id TEXT PRIMARY KEY REFERENCES incidents(id), \
           command_id TEXT UNIQUE NOT NULL, mark_ref TEXT UNIQUE NOT NULL, \
           actor_sub TEXT NOT NULL, display_email TEXT NULL, \
           resolved_at_ms BIGINT NOT NULL\
         )",
    )
    .execute(&mut **transaction)
    .await
    .map_err(map_transaction)?;
    Ok(())
}

async fn ensure_index(
    transaction: &mut Transaction<'_, Postgres>,
    index_name: &'static str,
    table_name: &'static str,
    key_definition: &'static str,
    statement: &'static str,
) -> Result<(), StoreError> {
    let row = sqlx::query(
        "SELECT table_rel.relname AS table_name, idx.indisunique, idx.indisvalid, \
                idx.indisready, idx.indnkeyatts::bigint AS key_count, \
                idx.indnatts::bigint AS total_count, \
                pg_get_indexdef(idx.indexrelid, 1, true) AS key_definition, \
                idx.indpred IS NULL AS no_predicate, idx.indexprs IS NULL AS no_expression \
         FROM pg_index idx \
         JOIN pg_class index_rel ON index_rel.oid=idx.indexrelid \
         JOIN pg_class table_rel ON table_rel.oid=idx.indrelid \
         JOIN pg_namespace ns ON ns.oid=table_rel.relnamespace \
         WHERE ns.nspname='public' AND index_rel.relname=$1",
    )
    .bind(index_name)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_transaction)?;
    let Some(row) = row else {
        sqlx::query(statement)
            .execute(&mut **transaction)
            .await
            .map_err(map_transaction)?;
        return Ok(());
    };
    let exact = row
        .try_get::<String, _>("table_name")
        .map_err(|_| store_decode())?
        == table_name
        && !row
            .try_get::<bool, _>("indisunique")
            .map_err(|_| store_decode())?
        && row
            .try_get::<bool, _>("indisvalid")
            .map_err(|_| store_decode())?
        && row
            .try_get::<bool, _>("indisready")
            .map_err(|_| store_decode())?
        && row
            .try_get::<i64, _>("key_count")
            .map_err(|_| store_decode())?
            == 1
        && row
            .try_get::<i64, _>("total_count")
            .map_err(|_| store_decode())?
            == 1
        && row
            .try_get::<String, _>("key_definition")
            .map_err(|_| store_decode())?
            == key_definition
        && row
            .try_get::<bool, _>("no_predicate")
            .map_err(|_| store_decode())?
        && row
            .try_get::<bool, _>("no_expression")
            .map_err(|_| store_decode())?;
    if exact {
        Ok(())
    } else {
        Err(store_decode())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationState {
    Legacy,
    Current,
}

async fn migration_state(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<MigrationState, StoreError> {
    let row = sqlx::query(
        "SELECT \
           EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema='public' AND table_name='incidents' AND column_name='actor_sub') \
             AS incident_actor_sub, \
           EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema='public' AND table_name='incidents' AND column_name='display_email') \
             AS incident_display_email, \
           EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema='public' AND table_name='notes' AND column_name='display_email') \
             AS note_display_email, \
           to_regclass('public.resolution_marks') IS NOT NULL AS resolution_marks",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_transaction)?;
    let flags = [
        row.try_get::<bool, _>("incident_actor_sub")
            .map_err(|_| store_decode())?,
        row.try_get::<bool, _>("incident_display_email")
            .map_err(|_| store_decode())?,
        row.try_get::<bool, _>("note_display_email")
            .map_err(|_| store_decode())?,
        row.try_get::<bool, _>("resolution_marks")
            .map_err(|_| store_decode())?,
    ];
    if flags.iter().all(|flag| !flag) {
        Ok(MigrationState::Legacy)
    } else if flags.iter().all(|flag| *flag) {
        Ok(MigrationState::Current)
    } else {
        Err(store_decode())
    }
}

async fn validate_current_schema(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), StoreError> {
    let rows = sqlx::query(
        "SELECT table_name,column_name,data_type,is_nullable \
         FROM information_schema.columns \
         WHERE table_schema='public' \
           AND table_name IN ('incidents','notes','resolution_marks')",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_transaction)?;
    let mut actual = BTreeMap::new();
    for row in rows {
        let table: String = row.try_get("table_name").map_err(|_| store_decode())?;
        let column: String = row.try_get("column_name").map_err(|_| store_decode())?;
        let data_type: String = row.try_get("data_type").map_err(|_| store_decode())?;
        let nullable: String = row.try_get("is_nullable").map_err(|_| store_decode())?;
        actual.insert((table, column), (data_type, nullable));
    }
    for (table, column, data_type, nullable) in [
        ("incidents", "id", "text", "NO"),
        ("incidents", "title", "text", "NO"),
        ("incidents", "status", "text", "NO"),
        ("incidents", "from_ts", "bigint", "YES"),
        ("incidents", "to_ts", "bigint", "NO"),
        ("incidents", "created_by", "text", "NO"),
        ("incidents", "created_at", "bigint", "YES"),
        ("incidents", "actor_sub", "text", "YES"),
        ("incidents", "display_email", "text", "YES"),
        ("notes", "id", "text", "NO"),
        ("notes", "incident_id", "text", "NO"),
        ("notes", "body", "text", "NO"),
        ("notes", "author_sub", "text", "NO"),
        ("notes", "created_at", "bigint", "YES"),
        ("notes", "display_email", "text", "YES"),
        ("resolution_marks", "incident_id", "text", "NO"),
        ("resolution_marks", "command_id", "text", "NO"),
        ("resolution_marks", "mark_ref", "text", "NO"),
        ("resolution_marks", "actor_sub", "text", "NO"),
        ("resolution_marks", "display_email", "text", "YES"),
        ("resolution_marks", "resolved_at_ms", "bigint", "NO"),
    ] {
        if actual.get(&(table.to_string(), column.to_string()))
            != Some(&(data_type.to_string(), nullable.to_string()))
        {
            return Err(store_decode());
        }
    }

    let constraints = sqlx::query(
        "SELECT rel.relname AS table_name, con.conname, con.contype::text AS contype, \
                pg_get_constraintdef(con.oid, true) AS definition \
         FROM pg_constraint con \
         JOIN pg_class rel ON rel.oid=con.conrelid \
         JOIN pg_namespace ns ON ns.oid=rel.relnamespace \
         WHERE ns.nspname='public' \
           AND rel.relname IN ('incidents','notes','resolution_marks')",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_transaction)?;
    let constraints = constraints
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("table_name")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("conname")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("contype")
                    .map_err(|_| store_decode())?,
                row.try_get::<String, _>("definition")
                    .map_err(|_| store_decode())?,
            ))
        })
        .collect::<Result<BTreeSet<_>, StoreError>>()?;
    for required in [
        ("incidents", "incidents_pkey", "p", "PRIMARY KEY (id)"),
        ("notes", "notes_pkey", "p", "PRIMARY KEY (id)"),
        (
            "resolution_marks",
            "resolution_marks_pkey",
            "p",
            "PRIMARY KEY (incident_id)",
        ),
        (
            "resolution_marks",
            "resolution_marks_command_id_key",
            "u",
            "UNIQUE (command_id)",
        ),
        (
            "resolution_marks",
            "resolution_marks_mark_ref_key",
            "u",
            "UNIQUE (mark_ref)",
        ),
        (
            "resolution_marks",
            "resolution_marks_incident_id_fkey",
            "f",
            "FOREIGN KEY (incident_id) REFERENCES incidents(id)",
        ),
    ] {
        if !constraints.contains(&(
            required.0.to_string(),
            required.1.to_string(),
            required.2.to_string(),
            required.3.to_string(),
        )) {
            return Err(store_decode());
        }
    }

    let indexes = sqlx::query(
        "SELECT index_rel.relname AS index_name, table_rel.relname AS table_name, \
                idx.indisunique, idx.indisvalid, idx.indisready, \
                idx.indnkeyatts::bigint AS key_count, idx.indnatts::bigint AS total_count, \
                pg_get_indexdef(idx.indexrelid, 1, true) AS key_definition, \
                idx.indpred IS NULL AS no_predicate, idx.indexprs IS NULL AS no_expression \
         FROM pg_index idx \
         JOIN pg_class index_rel ON index_rel.oid=idx.indexrelid \
         JOIN pg_class table_rel ON table_rel.oid=idx.indrelid \
         JOIN pg_namespace ns ON ns.oid=table_rel.relnamespace \
         WHERE ns.nspname='public' \
           AND index_rel.relname IN ('idx_incidents_created_at','idx_notes_incident_id')",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_transaction)?;
    let mut actual_indexes = BTreeSet::new();
    for row in indexes {
        actual_indexes.insert((
            row.try_get::<String, _>("index_name")
                .map_err(|_| store_decode())?,
            row.try_get::<String, _>("table_name")
                .map_err(|_| store_decode())?,
            row.try_get::<bool, _>("indisunique")
                .map_err(|_| store_decode())?,
            row.try_get::<bool, _>("indisvalid")
                .map_err(|_| store_decode())?,
            row.try_get::<bool, _>("indisready")
                .map_err(|_| store_decode())?,
            row.try_get::<i64, _>("key_count")
                .map_err(|_| store_decode())?,
            row.try_get::<i64, _>("total_count")
                .map_err(|_| store_decode())?,
            row.try_get::<String, _>("key_definition")
                .map_err(|_| store_decode())?,
            row.try_get::<bool, _>("no_predicate")
                .map_err(|_| store_decode())?,
            row.try_get::<bool, _>("no_expression")
                .map_err(|_| store_decode())?,
        ));
    }
    for required in [
        (
            "idx_incidents_created_at",
            "incidents",
            false,
            true,
            true,
            1_i64,
            1_i64,
            "created_at",
            true,
            true,
        ),
        (
            "idx_notes_incident_id",
            "notes",
            false,
            true,
            true,
            1_i64,
            1_i64,
            "incident_id",
            true,
            true,
        ),
    ] {
        if !actual_indexes.contains(&(
            required.0.to_string(),
            required.1.to_string(),
            required.2,
            required.3,
            required.4,
            required.5,
            required.6,
            required.7.to_string(),
            required.8,
            required.9,
        )) {
            return Err(store_decode());
        }
    }
    Ok(())
}

async fn preflight_legacy_rows(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), StoreError> {
    let incidents =
        sqlx::query("SELECT id,title,status,from_ts,to_ts,created_by,created_at FROM incidents")
            .fetch_all(&mut **transaction)
            .await
            .map_err(map_transaction)?;
    let mut incident_ids = BTreeSet::new();
    for row in incidents {
        let id: String = row.try_get("id").map_err(|_| store_decode())?;
        IncidentId::parse(&id).map_err(|_| store_decode())?;
        let raw_title: String = row.try_get("title").map_err(|_| store_decode())?;
        let title = BoundedTitle::parse(&raw_title).map_err(|_| store_decode())?;
        if title.as_str() != raw_title || !incident_ids.insert(id) {
            return Err(store_decode());
        }
        if row
            .try_get::<String, _>("status")
            .map_err(|_| store_decode())?
            != "open"
            || row
                .try_get::<i64, _>("from_ts")
                .map_err(|_| store_decode())?
                <= 0
            || row
                .try_get::<i64, _>("created_at")
                .map_err(|_| store_decode())?
                <= 0
            || row.try_get::<i64, _>("to_ts").map_err(|_| store_decode())? > 0
        {
            return Err(store_decode());
        }
    }
    let notes = sqlx::query("SELECT id,incident_id,body,author_sub,created_at FROM notes")
        .fetch_all(&mut **transaction)
        .await
        .map_err(map_transaction)?;
    let mut note_ids = BTreeSet::new();
    for row in notes {
        let raw_note_id: String = row.try_get("id").map_err(|_| store_decode())?;
        NoteId::parse(&raw_note_id).map_err(|_| store_decode())?;
        if !note_ids.insert(raw_note_id) {
            return Err(store_decode());
        }
        let incident_id: String = row.try_get("incident_id").map_err(|_| store_decode())?;
        if !incident_ids.contains(&incident_id) {
            return Err(store_decode());
        }
        let raw_body: String = row.try_get("body").map_err(|_| store_decode())?;
        let body = BoundedNote::parse(&raw_body).map_err(|_| store_decode())?;
        let raw_subject: String = row.try_get("author_sub").map_err(|_| store_decode())?;
        let subject = BoundedSubject::parse(&raw_subject).map_err(|_| store_decode())?;
        if body.as_str() != raw_body || subject.as_str() != raw_subject {
            return Err(store_decode());
        }
        if row
            .try_get::<i64, _>("created_at")
            .map_err(|_| store_decode())?
            <= 0
        {
            return Err(store_decode());
        }
    }
    Ok(())
}

async fn preflight_current_rows(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), StoreError> {
    let incident_rows = sqlx::query(
        "SELECT i.id, i.title, i.status, i.from_ts, i.to_ts, \
                i.created_by, i.actor_sub, i.display_email, i.created_at, \
                r.command_id AS resolution_command_id, \
                r.mark_ref AS resolution_mark_ref, \
                r.actor_sub AS resolution_actor_sub, \
                r.display_email AS resolution_display_email, \
                r.resolved_at_ms \
         FROM incidents i \
         LEFT JOIN resolution_marks r ON r.incident_id=i.id",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_transaction)?;
    let mut incident_ids = BTreeSet::new();
    for row in &incident_rows {
        let incident = incident_from_row(row)?;
        if !incident_ids.insert(incident.id) {
            return Err(store_decode());
        }
    }

    let note_rows =
        sqlx::query("SELECT id,incident_id,body,author_sub,display_email,created_at FROM notes")
            .fetch_all(&mut **transaction)
            .await
            .map_err(map_transaction)?;
    let mut note_ids = BTreeSet::new();
    for row in &note_rows {
        let note = note_from_row(row)?;
        if !incident_ids.contains(&note.incident_id) || !note_ids.insert(note.id) {
            return Err(store_decode());
        }
    }

    let mark_rows = sqlx::query("SELECT incident_id,command_id,mark_ref FROM resolution_marks")
        .fetch_all(&mut **transaction)
        .await
        .map_err(map_transaction)?;
    let mut marked_incidents = BTreeSet::new();
    let mut command_ids = BTreeSet::new();
    let mut mark_refs = BTreeSet::new();
    for row in mark_rows {
        let incident_id = IncidentId::parse(
            &row.try_get::<String, _>("incident_id")
                .map_err(|_| store_decode())?,
        )
        .map_err(|_| store_decode())?;
        let command_id = ResolveCommandId::parse(
            &row.try_get::<String, _>("command_id")
                .map_err(|_| store_decode())?,
        )
        .map_err(|_| store_decode())?;
        let mark_ref = PublicMarkRef::parse(
            &row.try_get::<String, _>("mark_ref")
                .map_err(|_| store_decode())?,
        )
        .map_err(|_| store_decode())?;
        if !incident_ids.contains(&incident_id)
            || !marked_incidents.insert(incident_id)
            || !command_ids.insert(command_id)
            || !mark_refs.insert(mark_ref)
        {
            return Err(store_decode());
        }
    }
    Ok(())
}

fn bounded<T>(rows: Vec<T>, limit_plus_one: usize) -> Result<BoundedRows<T>, StoreError> {
    let limit = limit_plus_one.checked_sub(1).ok_or_else(store_decode)?;
    BoundedRows::from_limit_plus_one(rows, limit).map_err(|error| match error {
        TruthError::InvalidBound => store_decode(),
        _ => store_decode(),
    })
}

fn fingerprint_value(hash: &mut u64, value: &str) {
    for byte in value.bytes().chain(std::iter::once(0)) {
        *hash ^= u64::from(byte);
        *hash = (*hash).wrapping_mul(0x100000001b3);
    }
}

fn unique_invariant(error: &sqlx::Error) -> Option<ResolveInvariant> {
    let database = error.as_database_error()?;
    match database.constraint()? {
        "resolution_marks_command_id_key" => Some(ResolveInvariant::CommandIdentityCollision),
        "resolution_marks_mark_ref_key" => Some(ResolveInvariant::PublicMarkRefCollision),
        _ => None,
    }
}

fn map_sqlx(error: sqlx::Error) -> StoreError {
    use sqlx::Error;
    let kind = match error {
        Error::PoolTimedOut => StoreFailureKind::Timeout,
        Error::Io(_) | Error::Tls(_) | Error::PoolClosed => StoreFailureKind::Connect,
        Error::ColumnDecode { .. }
        | Error::ColumnNotFound(_)
        | Error::Decode(_)
        | Error::TypeNotFound { .. } => StoreFailureKind::Decode,
        _ => StoreFailureKind::Query,
    };
    StoreError::Unavailable(kind)
}

fn map_transaction(_: sqlx::Error) -> StoreError {
    StoreError::Unavailable(StoreFailureKind::Transaction)
}

fn store_query() -> StoreError {
    StoreError::Unavailable(StoreFailureKind::Query)
}

fn store_decode() -> StoreError {
    StoreError::Unavailable(StoreFailureKind::Decode)
}

fn store_transaction() -> StoreError {
    StoreError::Unavailable(StoreFailureKind::Transaction)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_incident(id: &str, created_at_s: i64) -> NewIncident {
        NewIncident {
            id: IncidentId::parse(id).unwrap(),
            title: BoundedTitle::parse(&format!("Incident {id}")).unwrap(),
            from_ts_s: created_at_s - 60,
            actor_sub: BoundedSubject::parse("subject").unwrap(),
            display_email: None,
            created_at_s,
        }
    }

    #[tokio::test]
    async fn incidents_and_notes_have_exact_order_and_bounds() {
        let store = InMemoryStore::new();
        store
            .create_incident(new_incident("inc_a", 100))
            .await
            .unwrap();
        store
            .create_incident(new_incident("inc_b", 200))
            .await
            .unwrap();
        let rows = store.list_incidents_bounded(2).await.unwrap();
        assert_eq!(rows.rows.len(), 1);
        assert_eq!(rows.rows[0].id.as_str(), "inc_b");
        assert_eq!(
            rows.boundedness,
            crate::view_contract::Boundedness::KnownMore
        );
    }

    #[tokio::test]
    async fn same_command_is_idempotent_and_different_command_is_stale() {
        let store = InMemoryStore::new();
        let incident = store
            .create_incident(new_incident("inc_case", 100))
            .await
            .unwrap();
        let command_id = ResolveCommandId::generate();
        let command = ResolveCommand {
            incident_id: incident.id.clone(),
            command_id: command_id.clone(),
            expected_lifecycle: ExpectedOpen,
            actor_sub: BoundedSubject::parse("subject").unwrap(),
            display_email: None,
            observed_at_ms: 123_456,
        };
        let ResolveResult::Resolved { mark, .. } =
            store.resolve_incident(command.clone()).await.unwrap()
        else {
            panic!("expected first resolve");
        };
        let ResolveResult::AlreadyResolved {
            mark: same_mark, ..
        } = store.resolve_incident(command).await.unwrap()
        else {
            panic!("expected same-command retry");
        };
        assert_eq!(same_mark, mark);
        let stale = ResolveCommand {
            incident_id: incident.id,
            command_id: ResolveCommandId::generate(),
            expected_lifecycle: ExpectedOpen,
            actor_sub: BoundedSubject::parse("other").unwrap(),
            display_email: None,
            observed_at_ms: 999_999,
        };
        let ResolveResult::StaleConflict {
            mark: stale_mark, ..
        } = store.resolve_incident(stale).await.unwrap()
        else {
            panic!("expected stale conflict");
        };
        assert_eq!(stale_mark, mark);
    }
}
