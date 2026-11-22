use std::{fs, os::unix::fs::DirBuilderExt};
use yonik_linux::{EncryptedSubscriptionRepository as Repository, RepositoryError};
use zeroize::Zeroizing;

#[tokio::test]
async fn backup_restore_reopen_and_refuse_overwrite() {
    let dir = std::env::temp_dir().join(format!("yonik-backup-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let source = dir.join("source.sqlite");
    let backup = dir.join("backup.sqlite");
    let restored = dir.join("restored.sqlite");
    let repo = Repository::open(source.clone(), Zeroizing::new([7; 32]))
        .await
        .unwrap();
    let id = repo
        .create_source(b"secret-marker".to_vec())
        .await
        .unwrap()
        .id;
    assert!(
        Repository::backup_closed(source.clone(), backup.clone(), Zeroizing::new([7; 32]))
            .await
            .is_err()
    );
    repo.commit_snapshot(
        id,
        1,
        0,
        yonik_linux::SnapshotInput {
            body: b"socks5://fixture.invalid:1080".to_vec(),
            metadata: b"metadata".to_vec(),
            validators: Some(b"validator".to_vec()),
        },
    )
    .await
    .unwrap();
    repo.close().await.unwrap();
    let sidecar = dir.join("backup.sqlite-wal");
    fs::write(&sidecar, b"foreign-sidecar").unwrap();
    assert_eq!(
        Repository::backup_closed(source.clone(), backup.clone(), Zeroizing::new([7; 32])).await,
        Err(RepositoryError::Conflict)
    );
    fs::remove_file(sidecar).unwrap();
    Repository::backup_closed(source.clone(), backup.clone(), Zeroizing::new([7; 32]))
        .await
        .unwrap();
    assert!(
        !fs::read(&backup)
            .unwrap()
            .windows(13)
            .any(|v| v == b"secret-marker")
    );
    assert!(
        Repository::restore_closed(backup.clone(), restored.clone(), Zeroizing::new([8; 32]))
            .await
            .is_err()
    );
    assert!(!restored.exists());
    Repository::restore_closed(backup.clone(), restored.clone(), Zeroizing::new([7; 32]))
        .await
        .unwrap();
    assert_eq!(
        Repository::restore_closed(backup.clone(), restored.clone(), Zeroizing::new([7; 32])).await,
        Err(RepositoryError::Conflict)
    );
    let repo = Repository::open(restored.clone(), Zeroizing::new([7; 32]))
        .await
        .unwrap();
    assert_eq!(
        repo.load(id)
            .await
            .unwrap()
            .unwrap()
            .source
            .payload
            .as_slice(),
        b"secret-marker"
    );
    repo.close().await.unwrap();
    // Повреждение ciphertext при корректной структуре SQLite.
    let connection = rusqlite::Connection::open(&backup).unwrap();
    connection
        .execute("UPDATE sources SET payload=zeroblob(length(payload))", [])
        .unwrap();
    drop(connection);
    assert!(
        Repository::restore_closed(
            backup.clone(),
            dir.join("corrupt.sqlite"),
            Zeroizing::new([7; 32])
        )
        .await
        .is_err()
    );
    assert!(!dir.join("corrupt.sqlite").exists());
    // Уже восстановленные данные пережили отказ кандидата.
    let repo = Repository::open(restored.clone(), Zeroizing::new([7; 32]))
        .await
        .unwrap();
    assert_eq!(
        repo.load(id)
            .await
            .unwrap()
            .unwrap()
            .source
            .payload
            .as_slice(),
        b"secret-marker"
    );
    repo.close().await.unwrap();
    let bytes = fs::read(&backup).unwrap();
    fs::write(&backup, &bytes[..bytes.len() / 2]).unwrap();
    assert!(
        Repository::restore_closed(backup, dir.join("bad.sqlite"), Zeroizing::new([7; 32]))
            .await
            .is_err()
    );
    assert!(!dir.join("bad.sqlite").exists());
    let connection = rusqlite::Connection::open(&source).unwrap();
    connection
        .execute_batch(
            "DROP TABLE native_profiles; DROP TABLE profile_projection;
             DROP TABLE profiles; DROP TABLE profile_catalog; DROP TABLE source_sequence;
             PRAGMA user_version=1;",
        )
        .unwrap();
    let sentinel: Vec<u8> = connection
        .query_row("SELECT sentinel FROM repository", [], |r| r.get(0))
        .unwrap();
    drop(connection);
    let legacy = dir.join("legacy.sqlite");
    Repository::backup_closed(source, legacy.clone(), Zeroizing::new([7; 32]))
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&legacy).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT sentinel FROM repository", [], |r| r
                .get::<_, Vec<u8>>(0))
            .unwrap(),
        sentinel
    );
    drop(connection);
    let repo = Repository::open(legacy, Zeroizing::new([7; 32]))
        .await
        .unwrap();
    assert_eq!(
        repo.load(id)
            .await
            .unwrap()
            .unwrap()
            .snapshot
            .unwrap()
            .revision,
        1
    );
    repo.close().await.unwrap();
    fs::remove_dir_all(dir).unwrap();
}

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("yonik-backup-{label}-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    async fn database(&self) -> std::path::PathBuf {
        let path = self.0.join("original.sqlite");
        let repo = Repository::open(path.clone(), Zeroizing::new([7; 32]))
            .await
            .unwrap();
        let id = repo.create_source(b"source".to_vec()).await.unwrap().id;
        repo.commit_snapshot(id, 1, 0, snapshot_input())
            .await
            .unwrap();
        repo.close().await.unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn snapshot_input() -> yonik_linux::SnapshotInput {
    yonik_linux::SnapshotInput {
        body: b"socks5://fixture.invalid:1080".to_vec(),
        metadata: b"meta".to_vec(),
        validators: None,
    }
}
async fn refuses_candidate(
    original: &std::path::Path,
    candidate: &std::path::Path,
    target: &std::path::Path,
) {
    let before = fs::read(original).unwrap();
    let candidate_before = fs::read(candidate).unwrap();
    let result = Repository::restore_closed(
        candidate.to_owned(),
        target.to_owned(),
        Zeroizing::new([7; 32]),
    )
    .await;
    assert_eq!(fs::read(original).unwrap(), before, "исходная БД изменена");
    assert_eq!(
        fs::read(candidate).unwrap(),
        candidate_before,
        "кандидат изменён"
    );
    assert!(result.is_err(), "повреждённый кандидат опубликован");
    assert!(!target.exists(), "назначение появилось после отказа");
}

#[tokio::test]
async fn rejects_incomplete_versioned_schema() {
    let fixture = Fixture::new("schema");
    let original = fixture.database().await;
    for (index, sql) in [
        "DROP TABLE source_sequence", "DROP TABLE profile_catalog",
        "DROP TABLE profiles",
        "DROP TABLE source_sequence; PRAGMA user_version=2; DROP TABLE profile_catalog",
        "DROP TABLE profiles; DROP TABLE profile_catalog; DROP TABLE source_sequence; PRAGMA user_version=1; ALTER TABLE snapshots RENAME COLUMN validators TO missing",
        "ALTER TABLE sources RENAME TO old_sources; CREATE TABLE sources AS SELECT * FROM old_sources", "ALTER TABLE source_sequence RENAME COLUMN last_id TO missing",
        "ALTER TABLE profile_catalog RENAME COLUMN unique_count TO missing",
        "ALTER TABLE profiles RENAME COLUMN ordinal TO missing",
        "DELETE FROM source_sequence", "UPDATE source_sequence SET last_id=0",
        "UPDATE profile_catalog SET unique_count=raw_count+1",
        "CREATE TABLE routing_draft(singleton INTEGER PRIMARY KEY,revision INTEGER,payload BLOB); INSERT INTO routing_draft VALUES(1,1,zeroblob(40))",
    ].iter().enumerate() {
        let candidate = fixture.0.join(format!("candidate-{index}.sqlite"));
        fs::copy(&original, &candidate).unwrap();
        let connection = rusqlite::Connection::open(&candidate).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        refuses_candidate(&original, &candidate, &fixture.0.join(format!("target-{index}.sqlite"))).await;
    }
}

#[tokio::test]
async fn rejects_authenticated_profile_replay() {
    let fixture = Fixture::new("replay");
    let original = fixture.database().await;
    let connection = rusqlite::Connection::open(&original).unwrap();
    let old: (i64, i64, i64, Vec<u8>) = connection
        .query_row(
            "SELECT id,generation,revision,payload FROM profiles",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    drop(connection);
    let repo = Repository::open(original.clone(), Zeroizing::new([7; 32]))
        .await
        .unwrap();
    repo.commit_snapshot(1, 1, 1, snapshot_input())
        .await
        .unwrap();
    repo.close().await.unwrap();
    let candidate = fixture.0.join("candidate.sqlite");
    fs::copy(&original, &candidate).unwrap();
    let connection = rusqlite::Connection::open(&candidate).unwrap();
    connection
        .execute(
            "UPDATE profiles SET generation=?1,revision=?2,payload=?3 WHERE id=?4",
            rusqlite::params![old.1, old.2, old.3, old.0],
        )
        .unwrap();
    drop(connection);
    refuses_candidate(&original, &candidate, &fixture.0.join("target.sqlite")).await;
}

#[tokio::test]
async fn legacy_schema_and_optional_draft_matrix() {
    let fixture = Fixture::new("legacy-matrix");
    let original = fixture.database().await;
    let repo = Repository::open(original.clone(), Zeroizing::new([7; 32]))
        .await
        .unwrap();
    repo.set_favorite(1, true).await.unwrap();
    repo.commit_snapshot(
        1,
        1,
        1,
        yonik_linux::SnapshotInput {
            body: b"socks5://other.invalid:1080".to_vec(),
            metadata: vec![],
            validators: None,
        },
    )
    .await
    .unwrap();
    repo.close().await.unwrap();
    for version in [1, 2, 3] {
        for draft in [false, true] {
            let source = fixture.0.join(format!("v{version}-{draft}.sqlite"));
            fs::copy(&original, &source).unwrap();
            if draft {
                let repo = Repository::open(source.clone(), Zeroizing::new([7; 32]))
                    .await
                    .unwrap();
                repo.routing_draft().await.unwrap();
                repo.save_routing_draft(0, b"draft".to_vec()).await.unwrap();
                repo.close().await.unwrap();
            }
            let connection = rusqlite::Connection::open(&source).unwrap();
            connection
                .execute_batch("DROP TABLE native_profiles; DROP TABLE profile_projection")
                .unwrap();
            if version < 3 {
                connection
                    .execute_batch("DROP TABLE source_sequence")
                    .unwrap();
            }
            if version < 2 {
                connection
                    .execute_batch("DROP TABLE profiles; DROP TABLE profile_catalog")
                    .unwrap();
            }
            connection
                .pragma_update(None, "user_version", version)
                .unwrap();
            drop(connection);
            let before = fs::read(&source).unwrap();
            let target = fixture.0.join(format!("target-{version}-{draft}.sqlite"));
            Repository::restore_closed(source.clone(), target.clone(), Zeroizing::new([7; 32]))
                .await
                .unwrap();
            assert_eq!(fs::read(&source).unwrap(), before);
            let repo = Repository::open(target, Zeroizing::new([7; 32]))
                .await
                .unwrap();
            assert!(repo.load(1).await.unwrap().is_some());
            assert_eq!(
                repo.profiles(1, yonik_linux::ProfileQuery::default())
                    .await
                    .unwrap()
                    .total,
                1
            );
            repo.create_source(b"next".to_vec()).await.unwrap();
            if draft {
                assert_eq!(
                    repo.routing_draft().await.unwrap().unwrap().1.as_slice(),
                    b"draft"
                );
            }
            repo.close().await.unwrap();
        }
    }
}
