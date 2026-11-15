//! Зашифрованное хранилище подписок. Ключ предоставляется вызывающей стороной.

mod backup;
mod maintenance;
pub use maintenance::{MaintenanceAccess, MaintenanceControl, MaintenanceError};
mod batch_targets;
mod native_profiles;
pub use native_profiles::{
    CatalogPage, CatalogProfile, CatalogSelection, NativeSummary, ResolvedCatalogProfile,
};
#[cfg(test)]
mod cancellation_tests;
#[cfg(any(test, feature = "test-support"))]
mod path_diagnostics;

use std::fs::{self, DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const SMALL_LIMIT: usize = 32 * 1024;
const BODY_LIMIT: usize = 8 * 1024 * 1024;
const SOURCE_LIMIT: i64 = 20_000;
static OPEN_GATE: Semaphore = Semaphore::const_new(2);
// Часть формата хранилища: бренд не меняет проверку существующей БД.
const SENTINEL: &[u8] = b"tofu subscription repository v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    InvalidInput,
    UnsafePath,
    UnsupportedVersion,
    Corrupt,
    Storage,
    Conflict,
    NotFound,
}
impl std::fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "Некорректные данные хранилища",
            Self::UnsafePath => "Небезопасный путь хранилища",
            Self::UnsupportedVersion => "Неподдерживаемая версия хранилища",
            Self::Corrupt => "Не удалось проверить зашифрованное хранилище",
            Self::Storage => "Ошибка хранилища",
            Self::Conflict => "Запись была изменена",
            Self::NotFound => "Запись не найдена",
        })
    }
}
impl std::error::Error for RepositoryError {}
type Result<T> = std::result::Result<T, RepositoryError>;

/// Отмена отделена от ошибок совместимого API хранилища.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotCommitError {
    Cancelled,
    Repository(RepositoryError),
}
impl std::fmt::Display for SnapshotCommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Запись snapshot отменена"),
            Self::Repository(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for SnapshotCommitError {}

impl From<RepositoryError> for SnapshotCommitError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

fn compat_commit_error(error: SnapshotCommitError) -> RepositoryError {
    match error {
        SnapshotCommitError::Repository(error) => error,
        // Совместимый API удерживает sender и не запрашивает отмену.
        SnapshotCommitError::Cancelled => RepositoryError::Storage,
    }
}

// Секретные поля намеренно не реализуют Debug.
pub struct SourceRecord {
    pub id: i64,
    pub generation: i64,
    pub payload: Zeroizing<Vec<u8>>,
}
pub struct SourceRecordsPage {
    pub records: Vec<SourceRecord>,
    pub total: usize,
}
pub struct SnapshotInput {
    pub body: Vec<u8>,
    pub metadata: Vec<u8>,
    pub validators: Option<Vec<u8>>,
}
pub struct StoredSnapshot {
    pub revision: i64,
    pub source_generation: i64,
    pub body: Zeroizing<Vec<u8>>,
    pub metadata: Zeroizing<Vec<u8>>,
    pub validators: Option<Zeroizing<Vec<u8>>>,
}
pub struct StoredSubscription {
    pub source: SourceRecord,
    pub snapshot: Option<StoredSnapshot>,
}

#[derive(Clone)]
pub struct EncryptedSubscriptionRepository {
    inner: Arc<Mutex<Database>>,
    gate: Arc<Semaphore>,
    #[cfg(test)]
    commit_boundary: Arc<Mutex<Option<CommitBoundaryHook>>>,
}
#[cfg(test)]
type CommitBoundaryHook = Box<dyn Fn(CommitCheckpoint) + Send>;
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitCheckpoint {
    WriteBlocked,
    BeforeAdmission,
    Admitted,
}
struct Database {
    #[cfg(test)]
    fail_format4: bool,
    connection: Connection,
    key: Zeroizing<[u8; 32]>,
    id: [u8; 32],
}

impl EncryptedSubscriptionRepository {
    #[cfg(test)]
    pub(crate) fn observe_write_wait(&self, notify: Arc<tokio::sync::Notify>) {
        *self.commit_boundary.lock().expect("test hook") = Some(Box::new(move |phase| {
            if phase == CommitCheckpoint::WriteBlocked {
                notify.notify_one();
            }
        }));
    }

    /// Несекретный идентификатор экземпляра; не является разрешением доступа.
    pub async fn database_identity(&self) -> Result<[u8; 32]> {
        self.run(|database| Ok(database.id)).await
    }

    pub async fn open(path: PathBuf, key: Zeroizing<[u8; 32]>) -> Result<Self> {
        let permit = OPEN_GATE
            .acquire()
            .await
            .map_err(|_| RepositoryError::Storage)?;
        let database = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            Database::open(&path, key)
        })
        .await
        .map_err(|_| RepositoryError::Storage)??;
        Ok(Self {
            inner: Arc::new(Mutex::new(database)),
            gate: Arc::new(Semaphore::new(1)),
            #[cfg(test)]
            commit_boundary: Arc::new(Mutex::new(None)),
        })
    }

    /// Закрывает этот handle на blocking pool. Последний handle в GUI следует
    /// освобождать этим методом: SQLite при закрытии может checkpoint-ить WAL.
    pub async fn close(self) -> Result<()> {
        let permit = self
            .gate
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RepositoryError::Storage)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            drop(self);
        })
        .await
        .map_err(|_| RepositoryError::Storage)
    }

    async fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Database) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let permit = self
            .gate
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RepositoryError::Storage)?;
        let cpu_permit = crate::subscriptions::IMPORT_GATE
            .acquire()
            .await
            .map_err(|_| RepositoryError::Storage)?;
        let database = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let _cpu_permit = cpu_permit;
            let _permit = permit;
            let mut database = database.lock().map_err(|_| RepositoryError::Storage)?;
            operation(&mut database)
        })
        .await
        .map_err(|_| RepositoryError::Storage)?
    }

    async fn run_cancellable<T: Send + 'static>(
        &self,
        mut cancel: crate::Cancellation,
        ack: Option<tokio::sync::OwnedSemaphorePermit>,
        operation: impl FnOnce(&mut Database) -> std::result::Result<T, SnapshotCommitError>
        + Send
        + 'static,
    ) -> std::result::Result<T, SnapshotCommitError> {
        cancel.check().map_err(|_| SnapshotCommitError::Cancelled)?;
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(SnapshotCommitError::Cancelled),
            result = self.gate.clone().acquire_owned() => result.map_err(|_| RepositoryError::Storage)?,
        };
        let cpu_permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(SnapshotCommitError::Cancelled),
            result = crate::subscriptions::IMPORT_GATE.acquire() => result.map_err(|_| RepositoryError::Storage)?,
        };
        let database = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let _ack = ack;
            let _permit = permit;
            let _cpu_permit = cpu_permit;
            let mut db = database.lock().map_err(|_| RepositoryError::Storage)?;
            cancel.check().map_err(|_| SnapshotCommitError::Cancelled)?;
            db.connection
                .busy_timeout(std::time::Duration::ZERO)
                .map_err(storage)?;
            let result = operation(&mut db);
            let restore = db
                .connection
                .busy_timeout(std::time::Duration::from_secs(3))
                .map_err(storage);
            restore?;
            result
        })
        .await
        .map_err(|_| RepositoryError::Storage)?
    }

    pub async fn create_source(&self, payload: Vec<u8>) -> Result<SourceRecord> {
        if payload_is_v2(&payload) {
            return Err(RepositoryError::InvalidInput);
        }
        self.create_source_format(payload, false, None).await
    }
    /// Atomic SourceDataV2 create + format4; backup нужен только при первом повышении.
    pub async fn create_source_v2(
        &self,
        payload: Vec<u8>,
        backup: Option<PathBuf>,
    ) -> Result<SourceRecord> {
        if payload_version(&payload) != Some(2) {
            return Err(RepositoryError::InvalidInput);
        }
        self.create_source_format(payload, true, backup).await
    }
    async fn create_source_format(
        &self,
        payload: Vec<u8>,
        v2: bool,
        backup: Option<PathBuf>,
    ) -> Result<SourceRecord> {
        let payload = Zeroizing::new(payload);
        check_small(&payload)?;
        self.run(move |db| {
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            if v2 {
                backup::admit_format4(&tx, &db.key, &db.id, backup.as_deref())?;
            }
            let count: i64 = tx
                .query_row("SELECT count(*) FROM sources", [], |r| r.get(0))
                .map_err(storage)?;
            if count >= SOURCE_LIMIT {
                return Err(RepositoryError::InvalidInput);
            }
            let next: i64 = tx
                .query_row(
                    "SELECT last_id FROM source_sequence WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            let id = next.checked_add(1).ok_or(RepositoryError::InvalidInput)?;
            if next < 0 {
                return Err(RepositoryError::Corrupt);
            }
            tx.execute(
                "UPDATE source_sequence SET last_id=?1 WHERE singleton=1 AND last_id=?2",
                params![id, next],
            )
            .map_err(storage)?;
            let encrypted = encrypt(&db.key, &db.id, 1, id, 1, 0, &payload)?;
            tx.execute(
                "INSERT INTO sources(id,generation,payload) VALUES (?1,1,?2)",
                params![id, encrypted],
            )
            .map_err(storage)?;
            if v2 {
                preserve_format4(&tx).map_err(storage)?;
                #[cfg(test)]
                if db.fail_format4 {
                    return Err(RepositoryError::Storage);
                }
            }
            tx.commit().map_err(storage)?;
            Ok(SourceRecord {
                id,
                generation: 1,
                payload,
            })
        })
        .await
    }

    pub async fn create_local_snapshot(
        &self,
        payload: Vec<u8>,
        original: Vec<u8>,
        cancel: crate::Cancellation,
        backup: Option<PathBuf>,
    ) -> Result<SourceRecord> {
        if !payload_is_v2(&payload) {
            return Err(RepositoryError::InvalidInput);
        }
        let payload = Zeroizing::new(payload);
        check_small(&payload)?;
        let original = Zeroizing::new(original);
        if original.len() > BODY_LIMIT {
            return Err(RepositoryError::InvalidInput);
        }
        #[cfg(test)]
        let boundary = self.commit_boundary.clone();
        self.run(move |db| {
            cancel.check().map_err(|_| RepositoryError::Conflict)?;
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            backup::admit_format4(&tx, &db.key, &db.id, backup.as_deref())?;
            let count: i64 = tx
                .query_row("SELECT count(*) FROM sources", [], |r| r.get(0))
                .map_err(storage)?;
            if count >= SOURCE_LIMIT {
                return Err(RepositoryError::InvalidInput);
            }
            let next: i64 = tx
                .query_row(
                    "SELECT last_id FROM source_sequence WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            let id = next.checked_add(1).ok_or(RepositoryError::InvalidInput)?;
            if next < 0 {
                return Err(RepositoryError::Corrupt);
            }
            tx.execute(
                "UPDATE source_sequence SET last_id=?1 WHERE singleton=1 AND last_id=?2",
                params![id, next],
            )
            .map_err(storage)?;
            let encrypted = encrypt(&db.key, &db.id, 1, id, 1, 0, &payload)?;
            tx.execute(
                "INSERT INTO sources(id,generation,payload) VALUES (?1,1,?2)",
                params![id, encrypted],
            )
            .map_err(storage)?;
            let parsed = prepare_profiles_checked(&db.key, &db.id, id, &original, &|| cancel.check().map_err(|_| SnapshotCommitError::Cancelled)).map_err(compat_commit_error)?;
            let body = encrypt(&db.key, &db.id, 2, id, 1, 1, &original)?;
            let metadata = encrypt(&db.key, &db.id, 3, id, 1, 1, b"{\"version\":1}")?;
            tx.execute("INSERT INTO snapshots(source_id,source_generation,revision,body,metadata,validators) VALUES (?1,1,1,?2,?3,NULL)", params![id, body, metadata]).map_err(storage)?;
            reconcile_checked(&tx, &db.key, &db.id, id, 1, 1, parsed, &|| cancel.check().map_err(|_| SnapshotCommitError::Cancelled)).map_err(compat_commit_error)?;
            preserve_format4(&tx).map_err(storage)?;
            #[cfg(test)]
            if db.fail_format4 { return Err(RepositoryError::Storage); }
            #[cfg(test)]
            if let Some(hook) = boundary.lock().map_err(|_| RepositoryError::Storage)?.as_ref() { hook(CommitCheckpoint::BeforeAdmission); }
            cancel.admit_commit().map_err(|_| RepositoryError::Conflict)?;
            tx.commit().map_err(storage)?;
            Ok(SourceRecord {
                id,
                generation: 1,
                payload,
            })
        })
        .await
    }

    pub async fn change_source(
        &self,
        id: i64,
        expected_generation: i64,
        payload: Vec<u8>,
    ) -> Result<SourceRecord> {
        positive(id)?;
        positive(expected_generation)?;
        let generation = expected_generation
            .checked_add(1)
            .ok_or(RepositoryError::InvalidInput)?;
        let payload = Zeroizing::new(payload);
        check_small(&payload)?;
        self.run(move |db| {
            let encrypted = encrypt(&db.key, &db.id, 1, id, generation, 0, &payload)?;
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            if payload_is_v2(&payload) {
                let format: i64 = tx
                    .query_row("PRAGMA user_version", [], |r| r.get(0))
                    .map_err(storage)?;
                if !(4..=5).contains(&format) {
                    return Err(RepositoryError::InvalidInput);
                }
            }
            let changed = tx
                .execute(
                    "UPDATE sources SET generation=?1,payload=?2 WHERE id=?3 AND generation=?4",
                    params![generation, encrypted, id, expected_generation],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(RepositoryError::Conflict);
            }
            tx.execute(
                "UPDATE snapshots SET validators=NULL WHERE source_id=?1",
                [id],
            )
            .map_err(storage)?;
            tx.commit().map_err(storage)?;
            Ok(SourceRecord {
                id,
                generation,
                payload,
            })
        })
        .await
    }

    /// Метаданные не меняют ресурс: сохраняем generation и validators.
    pub(crate) async fn update_source_metadata(
        &self,
        id: i64,
        expected_generation: i64,
        expected_payload: Zeroizing<Vec<u8>>,
        payload: Vec<u8>,
    ) -> Result<()> {
        positive(id)?;
        positive(expected_generation)?;
        let payload = Zeroizing::new(payload);
        check_small(&payload)?;
        self.run(move |db| {
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            if payload_is_v2(&payload) {
                let format: i64 = tx
                    .query_row("PRAGMA user_version", [], |r| r.get(0))
                    .map_err(storage)?;
                if !(4..=5).contains(&format) {
                    return Err(RepositoryError::InvalidInput);
                }
            }
            let row: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT generation,payload FROM sources WHERE id=?1",
                    [id],
                    |r| Ok((r.get(0)?, bounded_blob(r, 1, SMALL_LIMIT + 40)?)),
                )
                .optional()
                .map_err(storage)?;
            let Some((generation, encrypted)) = row else {
                return Err(RepositoryError::NotFound);
            };
            if generation != expected_generation {
                return Err(RepositoryError::Conflict);
            }
            let current = decrypt(
                &db.key,
                &db.id,
                1,
                id,
                generation,
                0,
                &encrypted,
                SMALL_LIMIT,
            )?;
            if *current != *expected_payload {
                return Err(RepositoryError::Conflict);
            }
            let encrypted = encrypt(&db.key, &db.id, 1, id, generation, 0, &payload)?;
            tx.execute(
                "UPDATE sources SET payload=?1 WHERE id=?2 AND generation=?3",
                params![encrypted, id, generation],
            )
            .map_err(storage)?;
            tx.commit().map_err(storage)
        })
        .await
    }

    pub async fn delete_source(&self, id: i64) -> Result<()> {
        positive(id)?;
        self.run(move |db| {
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            tx.execute("DELETE FROM profiles WHERE source_id=?1", [id])
                .map_err(storage)?;
            tx.execute("DELETE FROM native_profiles WHERE source_id=?1", [id])
                .map_err(storage)?;
            tx.execute("DELETE FROM profile_projection WHERE source_id=?1", [id])
                .map_err(storage)?;
            tx.execute("DELETE FROM profile_catalog WHERE source_id=?1", [id])
                .map_err(storage)?;
            tx.execute("DELETE FROM snapshots WHERE source_id=?1", [id])
                .map_err(storage)?;
            if tx
                .execute("DELETE FROM sources WHERE id=?1", [id])
                .map_err(storage)?
                != 1
            {
                return Err(RepositoryError::NotFound);
            }
            tx.commit().map_err(storage)
        })
        .await
    }

    pub async fn commit_snapshot(
        &self,
        id: i64,
        expected_generation: i64,
        expected_revision: i64,
        input: SnapshotInput,
    ) -> Result<i64> {
        let (_sender, cancel) = crate::Cancellation::new();
        self.commit_snapshot_cancellable(id, expected_generation, expected_revision, input, cancel)
            .await
            .map_err(compat_commit_error)
    }

    /// После допуска COMMIT возвращает его фактический результат. При отмене
    /// ожидает rollback worker и освобождение обоих gates.
    pub async fn commit_snapshot_cancellable(
        &self,
        id: i64,
        expected_generation: i64,
        expected_revision: i64,
        input: SnapshotInput,
        cancel: crate::Cancellation,
    ) -> std::result::Result<i64, SnapshotCommitError> {
        self.commit_snapshot_ack(
            id,
            expected_generation,
            expected_revision,
            input,
            cancel,
            None,
        )
        .await
    }

    pub(crate) async fn commit_snapshot_ack(
        &self,
        id: i64,
        expected_generation: i64,
        expected_revision: i64,
        input: SnapshotInput,
        cancel: crate::Cancellation,
        ack: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> std::result::Result<i64, SnapshotCommitError> {
        positive(id)?;
        positive(expected_generation)?;
        if expected_revision < 0 {
            return Err(RepositoryError::InvalidInput.into());
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(RepositoryError::InvalidInput)?;
        let body = Zeroizing::new(input.body);
        let metadata = Zeroizing::new(input.metadata);
        let validators = input.validators.map(Zeroizing::new);
        if body.len() > BODY_LIMIT {
            return Err(RepositoryError::InvalidInput.into());
        }
        check_small(&metadata)?;
        if let Some(value) = &validators {
            check_small(value)?;
        }
        #[cfg(test)]
        let boundary = self.commit_boundary.clone();
        self.run_cancellable(cancel.clone(), ack, move |db| {
            let check = || cancel.check().map_err(|_| SnapshotCommitError::Cancelled);
            check()?;
            let parsed = prepare_profiles_checked(&db.key, &db.id, id, &body, &check)?;
            let body = encrypt(&db.key, &db.id, 2, id, expected_generation, revision, &body)?;
            let metadata = encrypt(&db.key, &db.id, 3, id, expected_generation, revision, &metadata)?;
            let validators = validators.as_ref().map(|v| encrypt(&db.key, &db.id, 4, id, expected_generation, revision, v)).transpose()?;
            let started = std::time::Instant::now();
            let tx = loop {
                check()?;
                match rusqlite::Transaction::new_unchecked(&db.connection, TransactionBehavior::Immediate) {
                    Ok(tx) => break tx,
                    Err(error) if matches!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)) && started.elapsed() < std::time::Duration::from_secs(3) => {
                        #[cfg(test)]
                        if let Some(hook) = boundary.lock().map_err(|_| RepositoryError::Storage)?.as_ref() { hook(CommitCheckpoint::WriteBlocked); }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(error) => return Err(storage(error).into()),
                }
            };
            let generation: Option<i64> = tx.query_row("SELECT generation FROM sources WHERE id=?1", [id], |r| r.get(0)).optional().map_err(storage)?;
            let previous: i64 = tx.query_row("SELECT revision FROM snapshots WHERE source_id=?1", [id], |r| r.get(0)).optional().map_err(storage)?.unwrap_or(0);
            if generation != Some(expected_generation) || previous != expected_revision { return Err(RepositoryError::Conflict.into()); }
            tx.execute("INSERT INTO snapshots(source_id,source_generation,revision,body,metadata,validators) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(source_id) DO UPDATE SET source_generation=excluded.source_generation,revision=excluded.revision,body=excluded.body,metadata=excluded.metadata,validators=excluded.validators", params![id, expected_generation, revision, body, metadata, validators]).map_err(storage)?;
            reconcile_checked(&tx, &db.key, &db.id, id, expected_generation, revision, parsed, &check)?;
            #[cfg(test)]
            if let Some(hook) = boundary.lock().map_err(|_| RepositoryError::Storage)?.as_ref() { hook(CommitCheckpoint::BeforeAdmission); }
            cancel.admit_commit().map_err(|_| SnapshotCommitError::Cancelled)?;
            #[cfg(test)]
            if let Some(hook) = boundary.lock().map_err(|_| RepositoryError::Storage)?.as_ref() { hook(CommitCheckpoint::Admitted); }
            tx.commit().map_err(storage)?;
            Ok(revision)
        }).await
    }

    pub async fn list_ids(&self) -> Result<Vec<i64>> {
        self.run(|db| {
            let mut statement = db
                .connection
                .prepare("SELECT id FROM sources ORDER BY id LIMIT 20001")
                .map_err(storage)?;
            let ids = statement
                .query_map([], |r| r.get::<_, i64>(0))
                .map_err(storage)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(storage)?;
            if ids.len() > SOURCE_LIMIT as usize || ids.iter().any(|id| *id <= 0) {
                return Err(RepositoryError::Corrupt);
            }
            Ok(ids)
        })
        .await
    }

    /// Страница source metadata без чтения/дешифровки snapshot body.
    pub async fn source_records(&self, offset: usize, limit: usize) -> Result<SourceRecordsPage> {
        if offset > SOURCE_LIMIT as usize || !(1..=64).contains(&limit) {
            return Err(RepositoryError::InvalidInput);
        }
        self.run(move |db| {
            let tx = db.connection.transaction().map_err(storage)?;
            let total: usize = tx
                .query_row("SELECT count(*) FROM sources", [], |row| row.get(0))
                .map_err(storage)?;
            if total > SOURCE_LIMIT as usize {
                return Err(RepositoryError::Corrupt);
            }
            let records = {
                let mut query = tx
                    .prepare(
                        "SELECT id,generation,payload FROM sources ORDER BY id LIMIT ?1 OFFSET ?2",
                    )
                    .map_err(storage)?;
                let rows = query
                    .query_map(params![limit, offset], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            bounded_blob(row, 2, SMALL_LIMIT + 40)?,
                        ))
                    })
                    .map_err(storage)?;
                let mut records = Vec::new();
                for row in rows {
                    let (id, generation, payload) = row.map_err(|_| RepositoryError::Corrupt)?;
                    if id <= 0 || generation <= 0 {
                        return Err(RepositoryError::Corrupt);
                    }
                    records.push(SourceRecord {
                        id,
                        generation,
                        payload: decrypt(
                            &db.key,
                            &db.id,
                            1,
                            id,
                            generation,
                            0,
                            &payload,
                            SMALL_LIMIT,
                        )?,
                    });
                }
                records
            };
            tx.commit().map_err(storage)?;
            Ok(SourceRecordsPage { records, total })
        })
        .await
    }

    pub(crate) async fn source_record_by_id(&self, id: i64) -> Result<Option<SourceRecord>> {
        positive(id)?;
        self.run(move |db| {
            let row: Option<(i64, Vec<u8>)> = db
                .connection
                .query_row(
                    "SELECT generation,payload FROM sources WHERE id=?1",
                    [id],
                    |r| Ok((r.get(0)?, bounded_blob(r, 1, SMALL_LIMIT + 40)?)),
                )
                .optional()
                .map_err(storage)?;
            row.map(|(generation, payload)| {
                if generation <= 0 {
                    return Err(RepositoryError::Corrupt);
                }
                Ok(SourceRecord {
                    id,
                    generation,
                    payload: decrypt(&db.key, &db.id, 1, id, generation, 0, &payload, SMALL_LIMIT)?,
                })
            })
            .transpose()
        })
        .await
    }

    pub async fn load(&self, id: i64) -> Result<Option<StoredSubscription>> {
        positive(id)?;
        self.run(move |db| {
            // Транзакция фиксирует согласованную пару source/snapshot при втором соединении.
            let tx = db.connection.transaction().map_err(storage)?;
            let source: Option<(i64, Vec<u8>)> = tx.query_row("SELECT generation,payload FROM sources WHERE id=?1", [id], |r| Ok((r.get(0)?, bounded_blob(r, 1, SMALL_LIMIT + 40)?))).optional().map_err(|_| RepositoryError::Corrupt)?;
            let Some((generation, payload)) = source else { return Ok(None); };
            if generation <= 0 { return Err(RepositoryError::Corrupt); }
            let payload = decrypt(&db.key, &db.id, 1, id, generation, 0, &payload, SMALL_LIMIT)?;
            type SnapshotRow = (i64, i64, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
            let snapshot: Option<SnapshotRow> = tx.query_row("SELECT source_generation,revision,body,metadata,validators FROM snapshots WHERE source_id=?1", [id], |r| Ok((r.get(0)?,r.get(1)?,bounded_blob(r, 2, BODY_LIMIT + 40)?,bounded_blob(r, 3, SMALL_LIMIT + 40)?,optional_blob(r, 4, SMALL_LIMIT + 40)?))).optional().map_err(|_| RepositoryError::Corrupt)?;
            let snapshot = snapshot.map(|(source_generation, revision, body, metadata, validators)| {
                if source_generation <= 0 || source_generation > generation || revision <= 0 { return Err(RepositoryError::Corrupt); }
                Ok(StoredSnapshot {
                    source_generation, revision,
                    body: decrypt(&db.key, &db.id, 2, id, source_generation, revision, &body, BODY_LIMIT)?,
                    metadata: decrypt(&db.key, &db.id, 3, id, source_generation, revision, &metadata, SMALL_LIMIT)?,
                    validators: validators.map(|v| decrypt(&db.key, &db.id, 4, id, source_generation, revision, &v, SMALL_LIMIT)).transpose()?,
                })
            }).transpose()?;
            Ok(Some(StoredSubscription { source: SourceRecord { id, generation, payload }, snapshot }))
        }).await
    }
}

impl Database {
    fn open(path: &Path, key: Zeroizing<[u8; 32]>) -> Result<Self> {
        secure_path(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, flags).map_err(storage)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(3))
            .map_err(storage)?;
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(storage)?;
        if version > 5 {
            return Err(RepositoryError::UnsupportedVersion);
        }
        if version < 0 {
            return Err(RepositoryError::Corrupt);
        }
        let id = if version == 0 {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let tables: i64 = tx
                .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
                .map_err(storage)?;
            if tables != 0 {
                return Err(RepositoryError::Corrupt);
            }
            let mut id = [0_u8; 32];
            getrandom::getrandom(&mut id).map_err(|_| RepositoryError::Storage)?;
            let sentinel = encrypt(&key, &id, 0, 0, 0, 0, SENTINEL)?;
            tx.execute_batch("CREATE TABLE repository(id BLOB NOT NULL,sentinel BLOB NOT NULL); CREATE TABLE sources(id INTEGER PRIMARY KEY CHECK(id>0),generation INTEGER NOT NULL CHECK(generation>0),payload BLOB NOT NULL); CREATE TABLE snapshots(source_id INTEGER PRIMARY KEY REFERENCES sources(id),source_generation INTEGER NOT NULL CHECK(source_generation>0),revision INTEGER NOT NULL CHECK(revision>0),body BLOB NOT NULL,metadata BLOB NOT NULL,validators BLOB); PRAGMA user_version=1;").map_err(storage)?;
            tx.execute(
                "INSERT INTO repository(id,sentinel) VALUES (?1,?2)",
                params![id.as_slice(), sentinel],
            )
            .map_err(storage)?;
            tx.commit().map_err(storage)?;
            id
        } else {
            let count: i64 = connection
                .query_row("SELECT count(*) FROM repository", [], |r| r.get(0))
                .map_err(|_| RepositoryError::Corrupt)?;
            if count != 1 {
                return Err(RepositoryError::Corrupt);
            }
            let (id, sentinel): (Vec<u8>, Vec<u8>) = connection
                .query_row("SELECT id,sentinel FROM repository", [], |r| {
                    Ok((
                        bounded_blob(r, 0, 32)?,
                        bounded_blob(r, 1, SMALL_LIMIT + 40)?,
                    ))
                })
                .map_err(|_| RepositoryError::Corrupt)?;
            let id: [u8; 32] = id.try_into().map_err(|_| RepositoryError::Corrupt)?;
            if decrypt(&key, &id, 0, 0, 0, 0, &sentinel, SMALL_LIMIT)?.as_slice() != SENTINEL {
                return Err(RepositoryError::Corrupt);
            }
            id
        };
        if version < 2 {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            tx.execute_batch("CREATE TABLE profile_catalog(source_id INTEGER PRIMARY KEY REFERENCES sources(id),generation INTEGER NOT NULL,revision INTEGER NOT NULL,raw_count INTEGER NOT NULL,unique_count INTEGER NOT NULL); CREATE TABLE profiles(id INTEGER PRIMARY KEY AUTOINCREMENT,source_id INTEGER NOT NULL REFERENCES sources(id),fingerprint BLOB NOT NULL,generation INTEGER NOT NULL,revision INTEGER NOT NULL,ordinal INTEGER NOT NULL,present INTEGER NOT NULL,payload BLOB NOT NULL,UNIQUE(source_id,fingerprint)); PRAGMA user_version=2;").map_err(storage)?;
            tx.commit().map_err(storage)?;
        }
        if version < 3 {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            tx.execute_batch("CREATE TABLE source_sequence(singleton INTEGER PRIMARY KEY CHECK(singleton=1),last_id INTEGER NOT NULL CHECK(last_id>=0)); INSERT INTO source_sequence(singleton,last_id) SELECT 1,COALESCE(MAX(id),0) FROM sources; PRAGMA user_version=3;").map_err(storage)?;
            tx.commit().map_err(storage)?;
        }
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;").map_err(storage)?;
        native_profiles::initialize(&mut connection)?;
        Ok(Self {
            #[cfg(test)]
            fail_format4: false,
            connection,
            key,
            id,
        })
    }
}

fn unsafe_path(
    _path: &Path,
    _branch: &'static str,
    _node: &Path,
    _observed: Option<&fs::Metadata>,
    _error: Option<&std::io::Error>,
) -> RepositoryError {
    #[cfg(any(test, feature = "test-support"))]
    path_diagnostics::record(_path, _branch, _node, _observed, _error);
    RepositoryError::UnsafePath
}

fn secure_path(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(unsafe_path(path, "input_shape", path, None, None));
    }
    let parent = path
        .parent()
        .ok_or_else(|| unsafe_path(path, "parent_missing", path, None, None))?;
    if !parent.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(parent)
            .map_err(|error| unsafe_path(path, "parent_create", parent, None, Some(&error)))?;
    }
    // canonicalize выявляет симлинки и в предках, а не только в последнем компоненте.
    if parent
        .canonicalize()
        .map_err(|error| unsafe_path(path, "parent_canonicalize", parent, None, Some(&error)))?
        != parent
    {
        return Err(unsafe_path(path, "parent_noncanonical", parent, None, None));
    }
    let meta = fs::symlink_metadata(parent)
        .map_err(|error| unsafe_path(path, "parent_stat", parent, None, Some(&error)))?;
    let uid = rustix::process::getuid().as_raw();
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
        return Err(unsafe_path(
            path,
            "parent_policy",
            parent,
            Some(&meta),
            None,
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file()
                || meta.uid() != uid
                || meta.mode() & 0o7777 != 0o600
                || meta.nlink() != 1
            {
                return Err(unsafe_path(
                    path,
                    "database_policy",
                    path,
                    Some(&meta),
                    None,
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(path)
                .map_err(|error| unsafe_path(path, "database_create", path, None, Some(&error)))?;
        }
        Err(error) => return Err(unsafe_path(path, "database_stat", path, None, Some(&error))),
    }
    // SQLite использует эти имена самостоятельно. Не разрешаем готовые симлинки.
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match fs::symlink_metadata(&sidecar) {
            Ok(meta)
                if !meta.is_file()
                    || meta.uid() != uid
                    || meta.mode() & 0o077 != 0
                    || meta.nlink() != 1 =>
            {
                return Err(unsafe_path(
                    path,
                    "sidecar_policy",
                    &sidecar,
                    Some(&meta),
                    None,
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(unsafe_path(
                    path,
                    "sidecar_stat",
                    &sidecar,
                    None,
                    Some(&error),
                ));
            }
        }
    }
    Ok(())
}
fn bounded_blob(row: &rusqlite::Row<'_>, index: usize, limit: usize) -> rusqlite::Result<Vec<u8>> {
    match row.get_ref(index)? {
        rusqlite::types::ValueRef::Blob(value) if value.len() <= limit => Ok(value.to_vec()),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn optional_blob(
    row: &rusqlite::Row<'_>,
    index: usize,
    limit: usize,
) -> rusqlite::Result<Option<Vec<u8>>> {
    if row.get_ref(index)? == rusqlite::types::ValueRef::Null {
        return Ok(None);
    }
    bounded_blob(row, index, limit).map(Some)
}
fn storage(_: rusqlite::Error) -> RepositoryError {
    RepositoryError::Storage
}
fn positive(value: i64) -> Result<()> {
    if value > 0 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidInput)
    }
}
fn check_small(value: &[u8]) -> Result<()> {
    if value.len() <= SMALL_LIMIT {
        Ok(())
    } else {
        Err(RepositoryError::InvalidInput)
    }
}
fn aad(db: &[u8; 32], kind: u8, id: i64, generation: i64, revision: i64) -> [u8; 57] {
    let mut value = [0_u8; 57];
    value[..32].copy_from_slice(db);
    value[32] = kind;
    value[33..41].copy_from_slice(&id.to_le_bytes());
    value[41..49].copy_from_slice(&generation.to_le_bytes());
    value[49..].copy_from_slice(&revision.to_le_bytes());
    value
}
fn encrypt(
    key: &[u8; 32],
    db: &[u8; 32],
    kind: u8,
    id: i64,
    generation: i64,
    revision: i64,
    value: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0_u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| RepositoryError::Storage)?;
    let encrypted = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: value,
                aad: &aad(db, kind, id, generation, revision),
            },
        )
        .map_err(|_| RepositoryError::Corrupt)?;
    let mut result = Vec::with_capacity(24 + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
fn decrypt(
    key: &[u8; 32],
    db: &[u8; 32],
    kind: u8,
    id: i64,
    generation: i64,
    revision: i64,
    value: &[u8],
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if value.len() < 40 || value.len() > limit + 40 {
        return Err(RepositoryError::Corrupt);
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&value[..24]),
            Payload {
                msg: &value[24..],
                aad: &aad(db, kind, id, generation, revision),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| RepositoryError::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn rebranding_preserves_stored_profile_fingerprint() {
        // Вектор legacy-формата использует только синтетические данные.
        let report = yonik_import::import_bytes(b"socks5://example.org:1080".to_vec()).unwrap();
        assert_eq!(SENTINEL, b"tofu subscription repository v1");
        assert_eq!(
            fingerprint(&[7; 32], &[9; 32], 11, &report.servers[0]).unwrap(),
            vec![
                122, 210, 253, 69, 37, 169, 167, 86, 100, 213, 100, 233, 69, 237, 44, 92, 250, 176,
                66, 65, 25, 138, 202, 206, 187, 162, 202, 221, 80, 92, 17, 221
            ],
        );
    }

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let root = std::env::temp_dir();
            let path = root.join(format!(
                "yonik-repository-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("приватный каталог теста");
            Self(path)
        }
        fn database(&self) -> PathBuf {
            self.0.join("subscriptions.sqlite")
        }
        async fn open(&self) -> EncryptedSubscriptionRepository {
            EncryptedSubscriptionRepository::open(self.database(), Zeroizing::new([7; 32]))
                .await
                .expect("открытие")
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("очистка своего каталога теста");
        }
    }
    fn snapshot() -> SnapshotInput {
        SnapshotInput {
            body: b"trojan://secret-snapshot-marker@fixture.invalid:443#test".to_vec(),
            metadata: b"secret-metadata-marker".to_vec(),
            validators: Some(b"secret-validator-marker".to_vec()),
        }
    }

    async fn assert_original_snapshot(repo: &EncryptedSubscriptionRepository, source: i64) {
        let stored = repo.load(source).await.expect("чтение").expect("источник");
        assert_eq!(stored.source.payload.as_slice(), b"source");
        let stored = stored.snapshot.expect("snapshot");
        let expected = snapshot();
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.source_generation, 1);
        assert_eq!(*stored.body, expected.body);
        assert_eq!(*stored.metadata, expected.metadata);
        assert_eq!(stored.validators.as_deref(), expected.validators.as_ref());
        let page = repo
            .profiles(source, ProfileQuery::default())
            .await
            .expect("каталог");
        assert_eq!(page.total, 1);
        assert_eq!(page.snapshot_revision, 1);
    }

    #[tokio::test]
    async fn failed_reconcile_rolls_back_snapshot_after_reopen() {
        let dir = TestDirectory::new();
        let repo = dir.open().await;
        let source = repo
            .create_source(b"source".to_vec())
            .await
            .expect("источник")
            .id;
        repo.commit_snapshot(source, 1, 0, snapshot())
            .await
            .expect("snapshot");
        repo.close().await.expect("закрытие");
        let connection = Connection::open(dir.database()).expect("fixture");
        // Отказ в конце reconcile: snapshot и profiles уже обновлены внутри tx.
        connection.execute_batch("CREATE TRIGGER fail_catalog BEFORE INSERT ON profile_catalog BEGIN SELECT RAISE(ABORT, 'fixture'); END;").expect("триггер");
        drop(connection);
        let repo = dir.open().await;
        let replacement = SnapshotInput {
            body: b"trojan://replacement@new.invalid:8443#new".to_vec(),
            metadata: b"new metadata".to_vec(),
            validators: Some(b"new validators".to_vec()),
        };
        assert!(matches!(
            repo.commit_snapshot(source, 1, 1, replacement).await,
            Err(RepositoryError::Storage)
        ));
        repo.close().await.expect("закрытие");
        let repo = dir.open().await;
        assert_original_snapshot(&repo, source).await;
        repo.close().await.expect("закрытие");
    }

    #[tokio::test]
    async fn interrupted_transaction_recovers_after_reopen() {
        use std::io::{Read, Write};
        use std::process::Stdio;

        const CHILD_PATH: &str = "YONIK_REPOSITORY_CRASH_FIXTURE";
        if let Some(mode) = std::env::var_os(CHILD_PATH) {
            // Переменная выбирает только протокол, никогда путь к данным.
            assert_eq!(mode, "child-v1", "неподдерживаемый child-протокол");
            let mut message = Vec::new();
            std::io::stdin()
                .take(16 * 1024)
                .read_to_end(&mut message)
                .expect("канал родителя");
            let (path, nonce): (PathBuf, [u8; 32]) =
                serde_json::from_slice(&message).expect("child-сообщение");
            let marker = path.parent().expect("каталог fixture").join("crash-marker");
            assert_eq!(fs::read(marker).expect("маркер fixture"), nonce);
            assert!(path.is_file(), "родитель должен заранее создать БД");
            let repo = EncryptedSubscriptionRepository::open(path, Zeroizing::new([7; 32]))
                .await
                .expect("дочернее открытие");
            repo.run::<()>(|db| {
                let tx = db.connection.transaction().map_err(storage)?;
                tx.execute_batch(
                    "DELETE FROM profiles; DELETE FROM profile_catalog; DELETE FROM snapshots;",
                )
                .map_err(storage)?;
                // Без Drop/close: SQLite должен восстановить только committed состояние.
                std::process::exit(73);
            })
            .await
            .expect("дочерняя транзакция");
            panic!("дочерний процесс должен завершиться внутри транзакции");
        }
        let dir = TestDirectory::new();
        let repo = dir.open().await;
        let source = repo
            .create_source(b"source".to_vec())
            .await
            .expect("источник")
            .id;
        repo.commit_snapshot(source, 1, 0, snapshot())
            .await
            .expect("snapshot");
        repo.close().await.expect("закрытие");
        let mut nonce = [0_u8; 32];
        getrandom::getrandom(&mut nonce).expect("nonce fixture");
        let marker = dir
            .database()
            .parent()
            .expect("каталог fixture")
            .join("crash-marker");
        fs::write(marker, nonce).expect("маркер fixture");
        let mut child =
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "repository::tests::interrupted_transaction_recovers_after_reopen",
                ])
                .env(CHILD_PATH, "child-v1")
                .stdin(Stdio::piped())
                .spawn()
                .expect("дочерний процесс");
        child
            .stdin
            .take()
            .expect("канал fixture")
            .write_all(&serde_json::to_vec(&(dir.database(), nonce)).expect("сообщение"))
            .expect("отправка fixture");
        let status = child.wait().expect("завершение child");
        assert_eq!(status.code(), Some(73));
        let repo = dir.open().await;
        assert_original_snapshot(&repo, source).await;
        repo.close().await.expect("закрытие");
    }

    #[test]
    fn inherited_crash_fixture_path_cannot_open_database() {
        let dir = TestDirectory::new();
        fs::write(dir.database(), []).expect("посторонний пустой файл");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "repository::tests::interrupted_transaction_recovers_after_reopen",
            ])
            .env("YONIK_REPOSITORY_CRASH_FIXTURE", dir.database())
            .stdin(std::process::Stdio::null())
            .output()
            .expect("дочерний процесс");
        assert!(!output.status.success());
        assert_ne!(output.status.code(), Some(73));
        assert!(
            fs::read(dir.database())
                .expect("неизменённый файл")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn snapshot_corruption_fails_closed_after_reopen() {
        for sql in [
            "UPDATE snapshots SET body=zeroblob(length(body))",
            "UPDATE snapshots SET metadata=zeroblob(length(metadata))",
            "UPDATE snapshots SET validators=zeroblob(length(validators))",
            "UPDATE snapshots SET revision=revision+1",
            "UPDATE snapshots SET source_generation=source_generation+1",
        ] {
            let dir = TestDirectory::new();
            let repo = dir.open().await;
            let source = repo
                .create_source(b"source".to_vec())
                .await
                .expect("источник")
                .id;
            repo.commit_snapshot(source, 1, 0, snapshot())
                .await
                .expect("snapshot");
            repo.close().await.expect("закрытие");
            let connection = Connection::open(dir.database()).expect("fixture");
            connection.execute_batch(sql).expect("повреждение");
            drop(connection);
            let repo = dir.open().await;
            assert!(
                matches!(repo.load(source).await, Err(RepositoryError::Corrupt)),
                "{sql}"
            );
            repo.close().await.expect("закрытие");
        }
    }

    #[tokio::test]
    async fn wrong_key_preserves_legacy_domain_and_data_after_reopen() {
        let dir = TestDirectory::new();
        let repo = dir.open().await;
        let source = repo
            .create_source(b"source".to_vec())
            .await
            .expect("источник")
            .id;
        repo.commit_snapshot(source, 1, 0, snapshot())
            .await
            .expect("snapshot");
        repo.close().await.expect("закрытие");
        let connection = Connection::open(dir.database()).expect("fixture");
        connection.execute_batch("DROP TABLE profiles; DROP TABLE profile_catalog; DROP TABLE source_sequence; PRAGMA user_version=1;").expect("legacy fixture");
        let domain: (Vec<u8>, Vec<u8>) = connection
            .query_row("SELECT id,sentinel FROM repository", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .expect("домен");
        drop(connection);
        assert!(matches!(
            EncryptedSubscriptionRepository::open(dir.database(), Zeroizing::new([0; 32])).await,
            Err(RepositoryError::Corrupt)
        ));
        let connection = Connection::open(dir.database()).expect("fixture");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("версия");
        assert_eq!(version, 1);
        let unchanged: (Vec<u8>, Vec<u8>) = connection
            .query_row("SELECT id,sentinel FROM repository", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .expect("домен");
        assert_eq!(domain, unchanged);
        drop(connection);
        let repo = dir.open().await;
        assert_original_snapshot(&repo, source).await;
        repo.close().await.expect("закрытие");
        let repo = dir.open().await;
        assert_original_snapshot(&repo, source).await;
        repo.close().await.expect("закрытие");
    }

    #[tokio::test]
    async fn source_ids_never_repeat_after_delete_and_reopen() {
        let dir = TestDirectory::new();
        let db = dir.open().await;
        let first = db
            .create_source(b"first".to_vec())
            .await
            .expect("первый")
            .id;
        db.delete_source(first).await.expect("удаление");
        let second = db
            .create_source(b"second".to_vec())
            .await
            .expect("второй")
            .id;
        assert!(second > first);
        db.delete_source(second).await.expect("удаление");
        db.close().await.expect("закрытие");
        let reopened = dir.open().await;
        let third = reopened
            .create_source(b"third".to_vec())
            .await
            .expect("третий")
            .id;
        assert!(third > second);
    }

    #[tokio::test]
    async fn metadata_cas_rejects_concurrent_change_without_resetting_snapshot() {
        let dir = TestDirectory::new();
        let db = dir.open().await;
        let source = db
            .create_source(b"original".to_vec())
            .await
            .expect("источник");
        db.commit_snapshot(source.id, source.generation, 0, snapshot())
            .await
            .expect("snapshot");
        db.update_source_metadata(
            source.id,
            source.generation,
            Zeroizing::new(b"original".to_vec()),
            b"renamed".to_vec(),
        )
        .await
        .expect("метаданные");
        assert_eq!(
            db.update_source_metadata(
                source.id,
                source.generation,
                Zeroizing::new(b"original".to_vec()),
                b"stale".to_vec()
            )
            .await,
            Err(RepositoryError::Conflict)
        );
        let record = db.load(source.id).await.expect("БД").expect("источник");
        assert_eq!(record.source.generation, source.generation);
        assert_eq!(&*record.source.payload, b"renamed");
        let snapshot = record.snapshot.expect("snapshot");
        assert_eq!(snapshot.revision, 1);
        assert_eq!(
            snapshot.validators.as_deref().map(Vec::as_slice),
            Some(b"secret-validator-marker".as_slice())
        );
    }

    #[tokio::test]
    async fn reopen_and_no_plaintext() {
        let dir = TestDirectory::new();
        let db = dir.open().await;
        let source = db
            .create_source(b"secret-source-marker".to_vec())
            .await
            .expect("источник");
        assert_eq!(db.commit_snapshot(source.id, 1, 0, snapshot()).await, Ok(1));
        for entry in fs::read_dir(&dir.0).expect("файлы") {
            let bytes = fs::read(entry.expect("файл").path()).expect("данные");
            for marker in [
                b"secret-source-marker".as_slice(),
                b"trojan://secret-snapshot-marker@fixture.invalid:443#test",
                b"secret-metadata-marker",
                b"secret-validator-marker",
            ] {
                assert!(!bytes.windows(marker.len()).any(|v| v == marker));
            }
        }
        db.close().await.expect("закрытие");
        let reopened = dir.open().await;
        let value = reopened
            .load(source.id)
            .await
            .expect("чтение")
            .expect("запись");
        assert_eq!(value.source.payload.as_slice(), b"secret-source-marker");
        let value = value.snapshot.expect("снимок");
        assert_eq!(
            value.body.as_slice(),
            b"trojan://secret-snapshot-marker@fixture.invalid:443#test"
        );
        assert_eq!(
            value.validators.expect("валидаторы").as_slice(),
            b"secret-validator-marker"
        );
    }

    #[tokio::test]
    async fn source_change_preserves_snapshot_and_cas_across_instances() {
        let dir = TestDirectory::new();
        let first = dir.open().await;
        let source = first
            .create_source(b"old".to_vec())
            .await
            .expect("источник");
        let second = dir.open().await;
        first
            .commit_snapshot(source.id, 1, 0, snapshot())
            .await
            .expect("снимок");
        assert_eq!(
            second.commit_snapshot(source.id, 1, 0, snapshot()).await,
            Err(RepositoryError::Conflict)
        );
        second
            .change_source(source.id, 1, b"new".to_vec())
            .await
            .expect("изменение");
        assert!(matches!(
            first.change_source(source.id, 1, b"stale".to_vec()).await,
            Err(RepositoryError::Conflict)
        ));
        assert_eq!(
            first.commit_snapshot(source.id, 1, 1, snapshot()).await,
            Err(RepositoryError::Conflict)
        );
        let value = first
            .load(source.id)
            .await
            .expect("чтение")
            .expect("запись");
        assert_eq!(value.source.generation, 2);
        assert_eq!(value.source.payload.as_slice(), b"new");
        let value = value.snapshot.expect("старый снимок");
        assert_eq!(value.revision, 1);
        assert_eq!(value.source_generation, 1);
        assert_eq!(
            value.body.as_slice(),
            b"trojan://secret-snapshot-marker@fixture.invalid:443#test"
        );
        assert!(value.validators.is_none());
        assert_eq!(
            first.commit_snapshot(source.id, 2, 1, snapshot()).await,
            Ok(2)
        );
    }

    #[tokio::test]
    async fn wrong_key_and_tampering_are_rejected() {
        let dir = TestDirectory::new();
        let db = dir.open().await;
        let source = db
            .create_source(b"source".to_vec())
            .await
            .expect("источник");
        db.commit_snapshot(source.id, 1, 0, snapshot())
            .await
            .expect("снимок");
        db.close().await.expect("закрытие");
        assert!(matches!(
            EncryptedSubscriptionRepository::open(dir.database(), Zeroizing::new([8; 32])).await,
            Err(RepositoryError::Corrupt)
        ));
        let connection = Connection::open(dir.database()).expect("тестовое соединение");
        connection
            .execute("UPDATE snapshots SET revision=2", [])
            .expect("повреждение AAD");
        drop(connection);
        let db = dir.open().await;
        assert!(matches!(
            db.load(source.id).await,
            Err(RepositoryError::Corrupt)
        ));
        db.close().await.expect("закрытие");
        let connection = Connection::open(dir.database()).expect("тестовое соединение");
        connection
            .execute("UPDATE repository SET sentinel=zeroblob(64)", [])
            .expect("повреждение sentinel");
        drop(connection);
        assert!(matches!(
            EncryptedSubscriptionRepository::open(dir.database(), Zeroizing::new([7; 32])).await,
            Err(RepositoryError::Corrupt)
        ));
    }

    async fn commit_body(
        repo: &EncryptedSubscriptionRepository,
        source: i64,
        revision: i64,
        body: &str,
    ) {
        repo.commit_snapshot(
            source,
            1,
            revision,
            SnapshotInput {
                body: body.as_bytes().to_vec(),
                metadata: Vec::new(),
                validators: None,
            },
        )
        .await
        .expect("снимок");
    }
    #[tokio::test]
    async fn catalog_identity_favorites_and_tamper() {
        let dir = TestDirectory::new();
        let repo = dir.open().await;
        let source = repo
            .create_source(b"source".to_vec())
            .await
            .expect("источник")
            .id;
        commit_body(&repo,source,0,"trojan://password@one.invalid:443#first\ntrojan://second@two.invalid:443#second\ntrojan://password@one.invalid:443#duplicate").await;
        let page = repo
            .profiles(source, ProfileQuery::default())
            .await
            .expect("каталог");
        assert_eq!(
            (page.raw_count, page.unique_count, page.duplicate_count),
            (3, 2, 1)
        );
        let favorite = page.profiles[0].id;
        let retired = page.profiles[1].id;
        let other = repo
            .create_source(b"other source".to_vec())
            .await
            .expect("источник")
            .id;
        commit_body(&repo, other, 0, "trojan://password@one.invalid:443#first").await;
        let other_page = repo
            .profiles(other, ProfileQuery::default())
            .await
            .expect("другой каталог");
        assert_ne!(other_page.profiles[0].id, favorite);
        assert!(!other_page.profiles[0].favorite);
        assert_eq!(page.profiles[0].name, "first");
        repo.set_favorite(favorite, true).await.expect("избранное");
        commit_body(
            &repo,
            source,
            1,
            "trojan://second@two.invalid:443#second\ntrojan://password@one.invalid:443#renamed",
        )
        .await;
        let resolved = repo.resolve_profile(favorite, 2).await.expect("resolve");
        assert_eq!(resolved.profile.name, "renamed");
        assert!(resolved.profile.favorite);
        assert_eq!(resolved.profile.ordinal, 1);
        commit_body(&repo, source, 2, "trojan://new@three.invalid:443#new").await;
        let page = repo
            .profiles(
                source,
                ProfileQuery {
                    include_unavailable: true,
                    ..Default::default()
                },
            )
            .await
            .expect("каталог");
        assert_eq!(page.total, 2);
        assert!(
            page.profiles
                .iter()
                .any(|p| p.id == favorite && !p.available && p.favorite)
        );
        assert!(matches!(
            repo.resolve_profile(favorite, 3).await,
            Err(RepositoryError::NotFound)
        ));
        assert!(matches!(
            repo.commit_snapshot(source, 1, 2, snapshot()).await,
            Err(RepositoryError::Conflict)
        ));
        commit_body(
            &repo,
            source,
            3,
            "trojan://password@one.invalid:443#returned\ntrojan://second@two.invalid:443#second",
        )
        .await;
        let page = repo
            .profiles(source, ProfileQuery::default())
            .await
            .expect("каталог");
        assert_eq!(page.profiles[0].id, favorite);
        assert!(page.profiles[0].favorite);
        assert!(page.profiles[1].id > retired);
        commit_body(&repo,source,4,"trojan://changed@one.invalid:443#returned\ntrojan://password@one.invalid:443?unknown=x#changed-option").await;
        let page = repo
            .profiles(source, ProfileQuery::default())
            .await
            .expect("каталог");
        assert!(page.profiles.iter().all(|p| p.id != favorite));
        let connection = Connection::open(dir.database()).expect("соединение");
        connection
            .execute(
                "UPDATE profiles SET fingerprint=zeroblob(32) WHERE id=?1",
                [page.profiles[0].id],
            )
            .expect("tamper");
        assert!(matches!(
            repo.profiles(source, ProfileQuery::default()).await,
            Err(RepositoryError::Corrupt)
        ));
    }
    #[tokio::test]
    async fn migration_lazy_catalog_and_invalid_body() {
        let dir = TestDirectory::new();
        let repo = dir.open().await;
        let source = repo
            .create_source(b"source".to_vec())
            .await
            .expect("источник")
            .id;
        commit_body(
            &repo,
            source,
            0,
            "trojan://password@fixture.invalid:443#sensitive-display-marker",
        )
        .await;
        repo.close().await.expect("close");
        let connection = Connection::open(dir.database()).expect("соединение");
        connection
            .execute_batch(
                "DROP TABLE profiles; DROP TABLE profile_catalog; DROP TABLE source_sequence; PRAGMA user_version=1;",
            )
            .expect("fixture v1");
        drop(connection);
        let repo = dir.open().await;
        let page = repo
            .profiles(source, ProfileQuery::default())
            .await
            .expect("lazy migration");
        assert_eq!(page.total, 1);
        assert_eq!(page.snapshot_revision, 1);
        let next = repo
            .create_source(b"after-migration".to_vec())
            .await
            .expect("ID после миграции")
            .id;
        assert!(next > source);
        assert!(matches!(
            repo.commit_snapshot(
                source,
                1,
                1,
                SnapshotInput {
                    body: b"invalid".to_vec(),
                    metadata: Vec::new(),
                    validators: None
                }
            )
            .await,
            Err(RepositoryError::InvalidInput)
        ));
        assert_eq!(
            repo.profiles(source, ProfileQuery::default())
                .await
                .expect("каталог сохранён")
                .snapshot_revision,
            1
        );
        repo.close().await.expect("close");
        let bytes = fs::read(dir.database()).expect("файл");
        for secret in [
            b"password".as_slice(),
            b"fixture.invalid",
            b"sensitive-display-marker",
        ] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret));
        }
    }

    #[tokio::test]
    async fn future_version_is_not_modified() {
        let dir = TestDirectory::new();
        drop(dir.open().await);
        assert!(matches!(
            EncryptedSubscriptionRepository::open(dir.database(), Zeroizing::new([8; 32])).await,
            Err(RepositoryError::Corrupt)
        ));
        let connection = Connection::open(dir.database()).expect("тестовое соединение");
        connection
            .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA user_version=6;")
            .expect("будущая версия");
        drop(connection);
        let before = fs::read(dir.database()).expect("данные");
        assert!(matches!(
            EncryptedSubscriptionRepository::open(dir.database(), Zeroizing::new([7; 32])).await,
            Err(RepositoryError::UnsupportedVersion)
        ));
        assert_eq!(before, fs::read(dir.database()).expect("данные"));
        assert!(!dir.0.join("subscriptions.sqlite-wal").exists());
    }

    #[tokio::test]
    async fn symlinks_permissions_and_limits() {
        let dir = TestDirectory::new();
        let db = dir.open().await;
        assert!(matches!(
            db.create_source(vec![1; SMALL_LIMIT + 1]).await,
            Err(RepositoryError::InvalidInput)
        ));
        let source = db.create_source(vec![]).await.expect("источник");
        assert_eq!(db.list_ids().await.expect("список"), vec![source.id]);
        assert!(matches!(
            db.load(0).await,
            Err(RepositoryError::InvalidInput)
        ));
        assert!(matches!(
            db.change_source(source.id, i64::MAX, vec![]).await,
            Err(RepositoryError::InvalidInput)
        ));
        let mut input = snapshot();
        input.body = vec![0; BODY_LIMIT + 1];
        assert_eq!(
            db.commit_snapshot(source.id, 1, 0, input).await,
            Err(RepositoryError::InvalidInput)
        );
        db.close().await.expect("закрытие");
        let link = dir.0.join("link.sqlite");
        std::os::unix::fs::symlink(dir.database(), &link).expect("симлинк");
        assert!(matches!(
            EncryptedSubscriptionRepository::open(link, Zeroizing::new([7; 32])).await,
            Err(RepositoryError::UnsafePath)
        ));
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.database(), fs::Permissions::from_mode(0o644)).expect("права");
        assert!(matches!(
            EncryptedSubscriptionRepository::open(dir.database(), Zeroizing::new([7; 32])).await,
            Err(RepositoryError::UnsafePath)
        ));
    }
    #[tokio::test]
    async fn corrupt_catalog_counts_and_replayed_current_profile_are_rejected() {
        let dir = TestDirectory::new();
        let repo = dir.open().await;
        let source = repo.create_source(vec![]).await.expect("источник").id;
        commit_body(
            &repo,
            source,
            0,
            "trojan://password@fixture.invalid:443#old",
        )
        .await;
        let page = repo
            .profiles(source, ProfileQuery::default())
            .await
            .expect("страница");
        let id = page.profiles[0].id;
        let connection = Connection::open(dir.database()).expect("fixture соединение");
        for query in [
            "UPDATE profile_catalog SET raw_count=20001",
            "UPDATE profile_catalog SET raw_count=1,unique_count=2",
            "UPDATE profile_catalog SET unique_count=1,revision=0",
        ] {
            connection.execute_batch(query).expect("tamper marker");
            assert!(matches!(
                repo.profiles(source, ProfileQuery::default()).await,
                Err(RepositoryError::Corrupt)
            ));
        }
        connection
            .execute_batch("UPDATE profile_catalog SET raw_count=1,unique_count=1,revision=1")
            .expect("fixture marker");
        let payload: Vec<u8> = connection
            .query_row("SELECT payload FROM profiles WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .expect("старый ciphertext");
        commit_body(
            &repo,
            source,
            1,
            "trojan://password@fixture.invalid:443#new",
        )
        .await;
        // Ciphertext корректен для этой записи, но относится к прежнему revision.
        connection
            .execute(
                "UPDATE profiles SET generation=1,revision=1,payload=?1 WHERE id=?2",
                params![payload, id],
            )
            .expect("replay fixture");
        assert!(matches!(
            repo.profiles(source, ProfileQuery::default()).await,
            Err(RepositoryError::Corrupt)
        ));
        assert!(matches!(
            repo.resolve_profile(id, 2).await,
            Err(RepositoryError::Corrupt)
        ));
        drop(connection);
        repo.close().await.expect("закрытие");
    }
}

#[derive(Default)]
pub enum ProfileSort {
    #[default]
    SourceOrder,
    Name,
}
pub struct ProfileQuery {
    pub search: String,
    pub favorites_only: bool,
    pub include_unavailable: bool,
    pub sort: ProfileSort,
    pub offset: usize,
    pub limit: usize,
}
impl Default for ProfileQuery {
    fn default() -> Self {
        Self {
            search: String::new(),
            favorites_only: false,
            include_unavailable: false,
            sort: ProfileSort::SourceOrder,
            offset: 0,
            limit: 200,
        }
    }
}
// Метаданные чувствительны; Debug намеренно отсутствует.
pub struct ServerProfile {
    pub id: i64,
    pub source_id: i64,
    pub ordinal: usize,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub favorite: bool,
    pub available: bool,
}
pub struct ResolvedProfile {
    pub profile: ServerProfile,
    pub server: yonik_import::ParsedServer,
    pub snapshot_revision: i64,
    pub snapshot_generation: i64,
    pub source_generation: i64,
}
pub struct ProfilePage {
    pub profiles: Vec<ServerProfile>,
    pub total: usize,
    pub raw_count: usize,
    pub unique_count: usize,
    pub duplicate_count: usize,
    pub source_generation: i64,
    pub snapshot_generation: i64,
    pub snapshot_revision: i64,
}
struct Prepared {
    fingerprint: Vec<u8>,
    ordinal: usize,
    name: String,
    host: String,
    port: u16,
    protocol: String,
}
struct PreparedCatalog {
    raw: usize,
    rows: Vec<Prepared>,
    native: Vec<native_profiles::PreparedNative>,
}
struct ProfileRow {
    id: i64,
    source: i64,
    fingerprint: Vec<u8>,
    generation: i64,
    revision: i64,
    ordinal: usize,
    present: bool,
    payload: Vec<u8>,
}
fn fingerprint(
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    server: &yonik_import::ParsedServer,
) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    let identity = server
        .identity_material()
        .map_err(|_| RepositoryError::InvalidInput)?;
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).map_err(|_| RepositoryError::Storage)?;
    // Домен HMAC сохраняет идентичность профилей существующей БД.
    mac.update(b"tofu-profile-fingerprint\0v1\0");
    mac.update(db);
    mac.update(&source.to_le_bytes());
    mac.update(identity.expose());
    Ok(mac.finalize().into_bytes().to_vec())
}
fn prepare_profiles(
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    body: &[u8],
) -> Result<PreparedCatalog> {
    prepare_profiles_checked(key, db, source, body, &|| Ok(())).map_err(compat_commit_error)
}
fn prepare_profiles_checked(
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    body: &[u8],
    check: &impl Fn() -> std::result::Result<(), SnapshotCommitError>,
) -> std::result::Result<PreparedCatalog, SnapshotCommitError> {
    check()?;
    let profiles = yonik_import::import_profiles(body.to_vec());
    if let Err(error) = &profiles {
        if error.kind() != yonik_import::FatalError::UnsupportedFormat {
            return Err(RepositoryError::InvalidInput.into());
        }
    }
    if let Ok(report) = profiles {
        check()?;
        if report
            .entries
            .iter()
            .any(|entry| matches!(entry, yonik_import::ProfileEntry::Xray(_)))
        {
            let native = native_profiles::prepare(key, db, source, report, check)?;
            return Ok(PreparedCatalog {
                raw: 0,
                rows: Vec::new(),
                native,
            });
        }
    }
    let mut report = yonik_import::import_bytes_cancellable(body.to_vec(), || check().is_ok())
        .map_err(|error| match error {
            yonik_import::CancellableImportError::Cancelled => SnapshotCommitError::Cancelled,
            yonik_import::CancellableImportError::Import(_) => RepositoryError::InvalidInput.into(),
        })?;
    // Legacy native DATA (в том числе sing-box) сохраняются без fake endpoints.
    if report.native_json.is_some() {
        report.servers.clear();
    }
    if report.servers.len() > 20_000 || (report.servers.is_empty() && report.native_json.is_none())
    {
        return Err(RepositoryError::InvalidInput.into());
    }
    let raw = report.servers.len();
    let mut seen = std::collections::HashSet::new();
    let mut rows = Vec::new();
    for (ordinal, server) in report.servers.iter().enumerate() {
        check()?;
        let fingerprint = fingerprint(key, db, source, server)?;
        if seen.insert(fingerprint.clone()) {
            rows.push(Prepared {
                fingerprint,
                ordinal,
                name: server.display_name().expose().to_owned(),
                host: server.endpoint().host().to_owned(),
                port: server.endpoint().port(),
                protocol: server.protocol().as_str().to_owned(),
            });
        }
    }
    Ok(PreparedCatalog {
        raw,
        rows,
        native: Vec::new(),
    })
}
fn profile_aad(db: &[u8; 32], r: &ProfileRow) -> Vec<u8> {
    let mut v = aad(db, 5, r.id, r.generation, r.revision).to_vec();
    v.extend_from_slice(&r.source.to_le_bytes());
    v.extend_from_slice(&r.fingerprint);
    v.extend_from_slice(&(r.ordinal as u64).to_le_bytes());
    v.push(u8::from(r.present));
    v
}
fn seal_profile(
    key: &[u8; 32],
    db: &[u8; 32],
    r: &ProfileRow,
    p: &ServerProfile,
) -> Result<Vec<u8>> {
    let value = Zeroizing::new(
        serde_json::to_vec(&(
            p.name.as_str(),
            p.host.as_str(),
            p.port,
            p.protocol.as_str(),
            p.favorite,
        ))
        .map_err(|_| RepositoryError::InvalidInput)?,
    );
    check_small(&value)?;
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| RepositoryError::Storage)?;
    let mut out = nonce.to_vec();
    out.extend(
        XChaCha20Poly1305::new(key.into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &value,
                    aad: &profile_aad(db, r),
                },
            )
            .map_err(|_| RepositoryError::Corrupt)?,
    );
    Ok(out)
}
// Единый инвариант актуальности для чтения и maintenance preflight.
fn validate_profile_snapshot(row: &ProfileRow, generation: i64, revision: i64) -> Result<()> {
    if row.present && (row.generation != generation || row.revision != revision) {
        return Err(RepositoryError::Corrupt);
    }
    Ok(())
}

fn open_profile(key: &[u8; 32], db: &[u8; 32], r: &ProfileRow) -> Result<ServerProfile> {
    if r.payload.len() < 40 || r.fingerprint.len() != 32 {
        return Err(RepositoryError::Corrupt);
    }
    let value = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                XNonce::from_slice(&r.payload[..24]),
                Payload {
                    msg: &r.payload[24..],
                    aad: &profile_aad(db, r),
                },
            )
            .map_err(|_| RepositoryError::Corrupt)?,
    );
    let (name, host, port, protocol, favorite): (String, String, u16, String, bool) =
        serde_json::from_slice(&value).map_err(|_| RepositoryError::Corrupt)?;
    Ok(ServerProfile {
        id: r.id,
        source_id: r.source,
        ordinal: r.ordinal,
        name,
        host,
        port,
        protocol,
        favorite,
        available: r.present,
    })
}
fn read_profiles(tx: &rusqlite::Transaction<'_>, source: i64) -> Result<Vec<ProfileRow>> {
    read_profiles_checked(tx, source, &|| Ok(())).map_err(compat_commit_error)
}
fn read_profiles_checked(
    tx: &rusqlite::Transaction<'_>,
    source: i64,
    check: &impl Fn() -> std::result::Result<(), SnapshotCommitError>,
) -> std::result::Result<Vec<ProfileRow>, SnapshotCommitError> {
    let mut stmt=tx.prepare("SELECT id,source_id,fingerprint,generation,revision,ordinal,present,payload FROM profiles WHERE source_id=?1 LIMIT 40001").map_err(storage)?;
    let rows = stmt
        .query_map([source], |r| {
            Ok(ProfileRow {
                id: r.get(0)?,
                source: r.get(1)?,
                fingerprint: bounded_blob(r, 2, 32)?,
                generation: r.get(3)?,
                revision: r.get(4)?,
                ordinal: r.get(5)?,
                present: r.get(6)?,
                payload: bounded_blob(r, 7, SMALL_LIMIT + 40)?,
            })
        })
        .map_err(storage)?;
    let mut collected = Vec::new();
    for row in rows {
        check()?;
        collected.push(row.map_err(|_| RepositoryError::Corrupt)?);
    }
    let rows = collected;
    if rows.len() > 40_000 {
        return Err(RepositoryError::Corrupt.into());
    }
    Ok(rows)
}
fn reconcile(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    generation: i64,
    revision: i64,
    prepared: PreparedCatalog,
) -> Result<()> {
    reconcile_checked(tx, key, db, source, generation, revision, prepared, &|| {
        Ok(())
    })
    .map_err(compat_commit_error)
}
// Дополнительный callback сохраняет существующие координаты legacy AAD.
#[allow(clippy::too_many_arguments)]
fn reconcile_checked(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    generation: i64,
    revision: i64,
    prepared: PreparedCatalog,
    check: &impl Fn() -> std::result::Result<(), SnapshotCommitError>,
) -> std::result::Result<(), SnapshotCommitError> {
    native_profiles::reconcile(
        tx,
        key,
        db,
        source,
        generation,
        revision,
        &prepared.native,
        check,
    )?;
    let mut old = std::collections::HashMap::new();
    for r in read_profiles_checked(tx, source, check)? {
        check()?;
        let p = open_profile(key, db, &r)?;
        old.insert(r.fingerprint.clone(), (r, p));
    }
    let unique = prepared.rows.len();
    for p in prepared.rows {
        check()?;
        let existing = old.remove(&p.fingerprint);
        let (id, favorite) = if let Some((r, profile)) = existing {
            (r.id, profile.favorite)
        } else {
            tx.execute("INSERT INTO profiles(source_id,fingerprint,generation,revision,ordinal,present,payload) VALUES (?1,?2,?3,?4,?5,1,X'')",params![source,p.fingerprint,generation,revision,p.ordinal]).map_err(storage)?;
            (tx.last_insert_rowid(), false)
        };
        let r = ProfileRow {
            id,
            source,
            fingerprint: p.fingerprint,
            generation,
            revision,
            ordinal: p.ordinal,
            present: true,
            payload: Vec::new(),
        };
        let profile = ServerProfile {
            id,
            source_id: source,
            ordinal: p.ordinal,
            name: p.name,
            host: p.host,
            port: p.port,
            protocol: p.protocol,
            favorite,
            available: true,
        };
        let payload = seal_profile(key, db, &r, &profile)?;
        tx.execute("UPDATE profiles SET generation=?1,revision=?2,ordinal=?3,present=1,payload=?4 WHERE id=?5",params![generation,revision,r.ordinal,payload,id]).map_err(storage)?;
    }
    for (_, (mut r, p)) in old {
        check()?;
        if p.favorite {
            r.present = false;
            let payload = seal_profile(key, db, &r, &p)?;
            tx.execute(
                "UPDATE profiles SET present=0,payload=?1 WHERE id=?2",
                params![payload, r.id],
            )
            .map_err(storage)?;
        } else {
            tx.execute("DELETE FROM profiles WHERE id=?1", [r.id])
                .map_err(storage)?;
        }
    }
    tx.execute("INSERT INTO profile_catalog VALUES (?1,?2,?3,?4,?5) ON CONFLICT(source_id) DO UPDATE SET generation=excluded.generation,revision=excluded.revision,raw_count=excluded.raw_count,unique_count=excluded.unique_count",params![source,generation,revision,prepared.raw,unique]).map_err(storage)?;
    Ok(())
}

fn ensure_catalog(
    tx: &rusqlite::Transaction<'_>,
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
) -> Result<(i64, i64, usize, usize)> {
    let snapshot: Option<(i64, i64)> = tx
        .query_row(
            "SELECT source_generation,revision FROM snapshots WHERE source_id=?1",
            [source],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    let Some((generation, revision)) = snapshot else {
        return Ok((0, 0, 0, 0));
    };
    if generation <= 0 || revision <= 0 {
        return Err(RepositoryError::Corrupt);
    }
    let marker:Option<(i64,i64,usize,usize)>=tx.query_row("SELECT generation,revision,raw_count,unique_count FROM profile_catalog WHERE source_id=?1",[source],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(storage)?;
    if let Some(value) = marker {
        if value.0 <= 0 || value.1 <= 0 || value.2 > yonik_import::MAX_RECORDS || value.3 > value.2
        {
            return Err(RepositoryError::Corrupt);
        }
        if value.0 == generation
            && value.1 == revision
            && native_profiles::is_current(tx, source, generation, revision)?
        {
            return Ok(value);
        }
    }
    let body: Vec<u8> = tx
        .query_row(
            "SELECT body FROM snapshots WHERE source_id=?1",
            [source],
            |r| bounded_blob(r, 0, BODY_LIMIT + 40),
        )
        .map_err(storage)?;
    let body = decrypt(key, db, 2, source, generation, revision, &body, BODY_LIMIT)?;
    let prepared = prepare_profiles(key, db, source, &body)?;
    let raw = prepared.raw;
    let unique = prepared.rows.len();
    reconcile(tx, key, db, source, generation, revision, prepared)?;
    Ok((generation, revision, raw, unique))
}
impl EncryptedSubscriptionRepository {
    pub async fn profiles(&self, source: i64, query: ProfileQuery) -> Result<ProfilePage> {
        positive(source)?;
        if !(1..=200).contains(&query.limit)
            || query.offset > 40_000
            || query.search.len() > 512
            || query.search.chars().any(char::is_control)
        {
            return Err(RepositoryError::InvalidInput);
        }
        self.run(move |db| {
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let source_generation = tx
                .query_row(
                    "SELECT generation FROM sources WHERE id=?1",
                    [source],
                    |r| r.get(0),
                )
                .optional()
                .map_err(storage)?
                .ok_or(RepositoryError::NotFound)?;
            let (snapshot_generation, snapshot_revision, raw_count, unique_count) =
                ensure_catalog(&tx, &db.key, &db.id, source)?;
            let search = query.search.to_lowercase();
            let mut profiles = Vec::new();
            for r in read_profiles(&tx, source)? {
                validate_profile_snapshot(&r, snapshot_generation, snapshot_revision)?;
                let p = open_profile(&db.key, &db.id, &r)?;
                let name = p.name.to_lowercase();
                if (query.include_unavailable || p.available)
                    && (!query.favorites_only || p.favorite)
                    && (search.is_empty()
                        || name.contains(&search)
                        || p.host.to_lowercase().contains(&search))
                {
                    profiles.push((name, p));
                }
            }
            match query.sort {
                ProfileSort::Name => {
                    profiles.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.id.cmp(&b.1.id)))
                }
                ProfileSort::SourceOrder => profiles.sort_by_key(|(_, p)| (p.ordinal, p.id)),
            }
            let total = profiles.len();
            let profiles = profiles
                .into_iter()
                .skip(query.offset)
                .take(query.limit)
                .map(|(_, p)| p)
                .collect();
            tx.commit().map_err(storage)?;
            Ok(ProfilePage {
                profiles,
                total,
                raw_count,
                unique_count,
                duplicate_count: raw_count.saturating_sub(unique_count),
                source_generation,
                snapshot_generation,
                snapshot_revision,
            })
        })
        .await
    }
    pub async fn set_favorite(&self, id: i64, favorite: bool) -> Result<()> {
        positive(id)?;
        self.run(move |db| {
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let source: i64 = tx
                .query_row("SELECT source_id FROM profiles WHERE id=?1", [id], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(storage)?
                .ok_or(RepositoryError::NotFound)?;
            let rows = read_profiles(&tx, source)?;
            let mut favorites = native_profiles::favorite_count(&tx, &db.key, &db.id, source)?;
            let mut target = None;
            for r in rows {
                let p = open_profile(&db.key, &db.id, &r)?;
                favorites += usize::from(p.favorite);
                if r.id == id {
                    target = Some((r, p))
                }
            }
            let (r, mut p) = target.ok_or(RepositoryError::NotFound)?;
            if favorite && !p.favorite && favorites >= 20_000 {
                return Err(RepositoryError::InvalidInput);
            }
            p.favorite = favorite;
            if !favorite && !r.present {
                tx.execute("DELETE FROM profiles WHERE id=?1", [id])
                    .map_err(storage)?;
            } else {
                let payload = seal_profile(&db.key, &db.id, &r, &p)?;
                tx.execute(
                    "UPDATE profiles SET payload=?1 WHERE id=?2",
                    params![payload, id],
                )
                .map_err(storage)?;
            }
            tx.commit().map_err(storage)?;
            Ok(())
        })
        .await
    }
    pub async fn resolve_profile(
        &self,
        id: i64,
        expected_snapshot_revision: i64,
    ) -> Result<ResolvedProfile> {
        positive(id)?;
        positive(expected_snapshot_revision)?;
        self.run(move |db| {
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let source: i64 = tx
                .query_row("SELECT source_id FROM profiles WHERE id=?1", [id], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(storage)?
                .ok_or(RepositoryError::NotFound)?;
            let (generation, revision, _, _) = ensure_catalog(&tx, &db.key, &db.id, source)?;
            if revision != expected_snapshot_revision {
                return Err(RepositoryError::Conflict);
            }
            let r = read_profiles(&tx, source)?
                .into_iter()
                .find(|r| r.id == id)
                .ok_or(RepositoryError::NotFound)?;
            let p = open_profile(&db.key, &db.id, &r)?;
            if !p.available {
                return Err(RepositoryError::NotFound);
            }
            validate_profile_snapshot(&r, generation, revision)?;
            let body: Vec<u8> = tx
                .query_row(
                    "SELECT body FROM snapshots WHERE source_id=?1",
                    [source],
                    |r| bounded_blob(r, 0, BODY_LIMIT + 40),
                )
                .map_err(storage)?;
            let body = decrypt(
                &db.key, &db.id, 2, source, generation, revision, &body, BODY_LIMIT,
            )?;
            let report =
                yonik_import::import_bytes(body.to_vec()).map_err(|_| RepositoryError::Corrupt)?;
            let server = report
                .servers
                .get(p.ordinal)
                .ok_or(RepositoryError::Corrupt)?;
            if fingerprint(&db.key, &db.id, source, server)? != r.fingerprint {
                return Err(RepositoryError::Corrupt);
            }
            let source_generation = tx
                .query_row(
                    "SELECT generation FROM sources WHERE id=?1",
                    [source],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            let server = report
                .servers
                .into_iter()
                .nth(p.ordinal)
                .ok_or(RepositoryError::Corrupt)?;
            tx.commit().map_err(storage)?;
            Ok(ResolvedProfile {
                profile: p,
                server,
                snapshot_revision: revision,
                snapshot_generation: generation,
                source_generation,
            })
        })
        .await
    }
}

impl EncryptedSubscriptionRepository {
    /// Независимый versioned payload редактора; повреждённая запись не заменяется.
    pub async fn routing_draft(&self) -> Result<Option<(i64, Zeroizing<Vec<u8>>)>> {
        self.run(|db| {
            db.connection.execute_batch("CREATE TABLE IF NOT EXISTS routing_draft(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL CHECK(revision>0),payload BLOB NOT NULL)").map_err(storage)?;
            let row: Option<(i64, Vec<u8>)> = db.connection.query_row("SELECT revision,payload FROM routing_draft WHERE singleton=1", [], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage)?;
            row.map(|(revision, raw)| Ok((revision, decrypt(&db.key, &db.id, 8, 0, 0, revision, &raw, 262144)?))).transpose()
        }).await
    }
    pub async fn save_routing_draft(&self, expected: i64, payload: Vec<u8>) -> Result<i64> {
        if payload_version(&payload).is_some_and(|v| v != 1) {
            return Err(RepositoryError::InvalidInput);
        }
        self.save_routing_draft_format(expected, payload, false, None)
            .await
    }
    /// Storage validation принадлежит typed caller; здесь обязательны backup и CAS.
    pub async fn save_routing_draft_v2(
        &self,
        expected: i64,
        payload: Vec<u8>,
        backup: Option<PathBuf>,
    ) -> Result<i64> {
        if !payload_is_v2(&payload) {
            return Err(RepositoryError::InvalidInput);
        }
        self.save_routing_draft_format(expected, payload, true, backup)
            .await
    }
    pub async fn save_routing_draft_v3(
        &self,
        expected: i64,
        payload: Vec<u8>,
        backup: Option<PathBuf>,
    ) -> Result<i64> {
        if payload_version(&payload) != Some(3) {
            return Err(RepositoryError::InvalidInput);
        }
        self.save_routing_draft_format(expected, payload, true, backup)
            .await
    }
    async fn save_routing_draft_format(
        &self,
        expected: i64,
        payload: Vec<u8>,
        v2: bool,
        backup: Option<PathBuf>,
    ) -> Result<i64> {
        if expected < 0 || payload.len() > 262144 {
            return Err(RepositoryError::InvalidInput);
        }
        self.run(move |db| {
            let revision = expected.checked_add(1).ok_or(RepositoryError::InvalidInput)?;
            let encrypted = encrypt(&db.key, &db.id, 8, 0, 0, revision, &payload)?;
            let tx = db.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            if payload_version(&payload) == Some(3) { backup::admit_format5(&tx, &db.key, &db.id, backup.as_deref())?; } else if v2 { backup::admit_format4(&tx, &db.key, &db.id, backup.as_deref())?; }
            let changed = if expected == 0 {
                tx.execute("INSERT OR IGNORE INTO routing_draft(singleton,revision,payload) VALUES(1,?1,?2)", params![revision, encrypted]).map_err(storage)?
            } else {
                tx.execute("UPDATE routing_draft SET revision=?1,payload=?2 WHERE singleton=1 AND revision=?3", params![revision, encrypted, expected]).map_err(storage)?
            };
            if changed != 1 { return Err(RepositoryError::Conflict); }
            if payload_version(&payload) == Some(3) {
                tx.execute_batch("PRAGMA user_version=5;").map_err(storage)?;
                #[cfg(test)]
                if db.fail_format4 { return Err(RepositoryError::Storage); }
            } else if v2 {
                preserve_format4(&tx).map_err(storage)?;
                #[cfg(test)]
                if db.fail_format4 { return Err(RepositoryError::Storage); }
            }
            tx.commit().map_err(storage)?;
            Ok(revision)
        }).await
    }
}

fn payload_is_v2(payload: &[u8]) -> bool {
    payload_version(payload) == Some(2)
}

fn payload_version(payload: &[u8]) -> Option<u8> {
    #[derive(serde::Deserialize)]
    struct Version {
        version: u8,
    }
    serde_json::from_slice::<Version>(payload)
        .ok()
        .map(|v| v.version)
}

#[cfg(test)]
#[path = "repository/format4_tests.rs"]
mod format4_tests;

fn preserve_format4(tx: &Connection) -> rusqlite::Result<()> {
    let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 4 {
        tx.execute_batch("PRAGMA user_version=4;")?;
    }
    Ok(())
}
