#![cfg(target_os = "linux")]
//! Только временные SQLite и тестовые ключи; без транспорта и Secret Service.
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use yonik_import::ProfileEntry;
use yonik_linux::{
    CatalogPage, CatalogProfile, EncryptedSubscriptionRepository, ProfileQuery, RepositoryError,
    SnapshotCommitError, SnapshotInput,
};
use zeroize::Zeroizing;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "yonik-native-catalog-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("собственный каталог");
        Self(path)
    }
    fn database(&self) -> PathBuf {
        self.0.join("catalog.sqlite")
    }
    async fn open(&self) -> EncryptedSubscriptionRepository {
        EncryptedSubscriptionRepository::open(self.database(), Zeroizing::new([84; 32]))
            .await
            .expect("тестовая БД")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("очистка своей fixture");
    }
}
fn input(body: &str) -> SnapshotInput {
    SnapshotInput {
        body: body.as_bytes().to_vec(),
        metadata: b"{}".to_vec(),
        validators: None,
    }
}
async fn save(repo: &EncryptedSubscriptionRepository, source: i64, revision: i64, body: &str) {
    assert_eq!(
        repo.commit_snapshot(source, 1, revision, input(body)).await,
        Ok(revision + 1)
    );
}
async fn page(repo: &EncryptedSubscriptionRepository, source: i64) -> CatalogPage {
    repo.catalog(source, ProfileQuery::default())
        .await
        .expect("проекция v2")
}
fn root(name: &str, value: &str) -> String {
    format!(
        r#"{{"remarks":"{name}","opaque":{value},"outbounds":[{{"protocol":"future-data","settings":{{"password":"sensitive-catalog-secret"}}}}]}}"#
    )
}

#[tokio::test]
async fn seven_roots_are_seven_profiles_and_exact_encrypted_originals() {
    let dir = Directory::new();
    let repo = dir.open().await;
    let source = repo.create_source(vec![]).await.expect("источник").id;
    let body = include_str!("../../../tests/fixtures/xray-full-profile-seven.json");
    let imported = yonik_import::import_profiles(body.as_bytes().to_vec()).expect("P1");
    save(&repo, source, 0, body).await;
    assert_eq!(
        repo.profiles(source, ProfileQuery::default())
            .await
            .expect("legacy")
            .total,
        0
    );
    let catalog = page(&repo, source).await;
    assert_eq!(catalog.catalog_version, 2);
    assert_eq!(catalog.total, 7);
    assert_eq!(
        (
            catalog.raw_count,
            catalog.unique_count,
            catalog.duplicate_count
        ),
        (7, 7, 0)
    );
    for ((summary, selection), expected) in catalog.profiles.into_iter().zip(imported.entries) {
        let (CatalogProfile::Xray(summary), ProfileEntry::Xray(expected)) = (summary, expected)
        else {
            panic!("только полные профили");
        };
        assert_eq!(summary.name, expected.name());
        assert_eq!(summary.ordinal, expected.ordinal());
        let resolved = repo.resolve_catalog(selection).await.expect("resolve DATA");
        let ProfileEntry::Xray(actual) = resolved.entry else {
            panic!("без fake endpoint");
        };
        assert_eq!(actual.source().expose(), expected.source().expose());
    }
    assert_eq!(
        repo.load(source)
            .await
            .expect("load")
            .expect("source")
            .snapshot
            .expect("snapshot")
            .body
            .as_slice(),
        body.as_bytes()
    );
    repo.close().await.expect("close");
    for item in fs::read_dir(&dir.0).expect("файлы") {
        let bytes = fs::read(item.expect("файл").path()).expect("bytes");
        assert!(!bytes.windows(b"outbounds".len()).any(|v| v == b"outbounds"));
    }
    let repo = dir.open().await;
    assert_eq!(page(&repo, source).await.total, 7);
    repo.close().await.expect("close");
}

#[tokio::test]
async fn key_order_rename_reorder_and_opaque_numbers_preserve_identity() {
    let dir = Directory::new();
    let repo = dir.open().await;
    let source = repo.create_source(vec![]).await.expect("source").id;
    let first = root("первый", "1e999");
    let second = root("второй", "2");
    save(&repo, source, 0, &format!("[{first},{second}]")).await;
    let before = page(&repo, source).await;
    let (_, selection) = &before.profiles[0];
    repo.set_catalog_favorite(selection.clone(), true)
        .await
        .expect("избранное");
    let id = match &before.profiles[0].0 {
        CatalogProfile::Xray(p) => p.id,
        _ => panic!("native"),
    };
    let renamed = r#"{"outbounds":[{"settings":{"password":"sensitive-catalog-secret"},"protocol":"future-data"}],"opaque":1e999,"tag":"ignored","remarks":"новое"}"#;
    save(&repo, source, 1, &format!("[{second},{renamed}]")).await;
    assert!(matches!(
        repo.resolve_catalog(selection.clone()).await,
        Err(RepositoryError::Conflict)
    ));
    let after = page(&repo, source).await;
    let CatalogProfile::Xray(p) = &after.profiles[1].0 else {
        panic!("native");
    };
    assert_eq!(p.id, id);
    assert!(p.favorite);
    assert_eq!(p.name, "новое");
    let ProfileEntry::Xray(p) = repo
        .resolve_catalog(after.profiles[1].1.clone())
        .await
        .expect("opaque resolve")
        .entry
    else {
        panic!("native");
    };
    assert_eq!(p.source().expose(), renamed);
    save(&repo, source, 2, &root("новое", "3")).await;
    let historical = repo
        .catalog(
            source,
            ProfileQuery {
                favorites_only: true,
                include_unavailable: true,
                ..Default::default()
            },
        )
        .await
        .expect("historical");
    let CatalogProfile::Xray(p) = &historical.profiles[0].0 else {
        panic!("native");
    };
    assert_eq!(p.id, id);
    assert!(!p.available && p.requires_reselection);
    repo.close().await.expect("close");
}

#[tokio::test]
async fn duplicates_are_multiset_and_ambiguous_favorite_requires_reselection() {
    let dir = Directory::new();
    let repo = dir.open().await;
    let source = repo.create_source(vec![]).await.expect("source").id;
    let body = format!("[{},{}]", root("a", "1"), root("b", "1"));
    save(&repo, source, 0, &body).await;
    let before = page(&repo, source).await;
    assert_eq!(before.total, 2);
    repo.set_catalog_favorite(before.profiles[0].1.clone(), true)
        .await
        .expect("favorite");
    save(&repo, source, 1, &body).await;
    let all = repo
        .catalog(
            source,
            ProfileQuery {
                include_unavailable: true,
                ..Default::default()
            },
        )
        .await
        .expect("all");
    assert_eq!(all.total, 3);
    assert_eq!(
        all.profiles
            .iter()
            .filter(|(p, _)| matches!(p,CatalogProfile::Xray(p) if p.favorite && !p.available))
            .count(),
        1
    );
    repo.close().await.expect("close");
}

#[tokio::test]
async fn source_and_kind_are_separate_and_failed_commit_preserves_working_snapshot() {
    let dir = Directory::new();
    let repo = dir.open().await;
    let a = repo.create_source(vec![]).await.expect("a").id;
    let b = repo.create_source(vec![]).await.expect("b").id;
    let body = root("same", "[1,2]");
    save(&repo, a, 0, &body).await;
    save(&repo, b, 0, &body).await;
    let pa = page(&repo, a).await;
    let pb = page(&repo, b).await;
    repo.set_catalog_favorite(pa.profiles[0].1.clone(), true)
        .await
        .expect("favorite");
    let CatalogProfile::Xray(p) = &pb.profiles[0].0 else {
        panic!("native");
    };
    assert!(!p.favorite);
    let (sender, cancel) = yonik_linux::Cancellation::new();
    sender.send_replace(true);
    assert!(matches!(
        repo.commit_snapshot_cancellable(a, 1, 1, input(&root("late", "4")), cancel)
            .await,
        Err(SnapshotCommitError::Cancelled)
    ));
    assert_eq!(
        repo.commit_snapshot(a, 1, 0, input(&body)).await,
        Err(RepositoryError::Conflict)
    );
    assert!(
        repo.commit_snapshot(a, 1, 1, input("{broken"))
            .await
            .is_err()
    );
    assert_eq!(page(&repo, a).await.snapshot_revision, 1);
    save(&repo, a, 1, "trojan://synthetic@example.invalid:443#server").await;
    let all = repo
        .catalog(
            a,
            ProfileQuery {
                include_unavailable: true,
                ..Default::default()
            },
        )
        .await
        .expect("kinds");
    assert!(
        all.profiles
            .iter()
            .any(|(p, _)| matches!(p, CatalogProfile::Server(_)))
    );
    assert!(
        all.profiles
            .iter()
            .any(|(p, _)| matches!(p,CatalogProfile::Xray(p) if !p.available))
    );
    repo.close().await.expect("close");
}

#[tokio::test]
async fn lazy_projection_rebuild_and_backup_authenticate_native_ciphertext() {
    let dir = Directory::new();
    let repo = dir.open().await;
    let source = repo.create_source(vec![]).await.expect("source").id;
    save(&repo, source, 0, &root("private-name", "1e999")).await;
    repo.close().await.expect("close");
    EncryptedSubscriptionRepository::backup_closed(
        dir.database(),
        dir.0.join("copy.sqlite"),
        Zeroizing::new([84; 32]),
    )
    .await
    .expect("native backup");
    let c = rusqlite::Connection::open(dir.database()).expect("fixture");
    c.execute_batch("DELETE FROM profile_projection; DELETE FROM native_profiles;")
        .expect("projection v1 fixture");
    drop(c);
    let repo = dir.open().await;
    assert_eq!(page(&repo, source).await.total, 1);
    repo.close().await.expect("close");
    let c = rusqlite::Connection::open(dir.database()).expect("fixture");
    c.execute_batch("UPDATE native_profiles SET payload=zeroblob(length(payload));")
        .expect("tamper");
    drop(c);
    assert!(
        EncryptedSubscriptionRepository::backup_closed(
            dir.database(),
            dir.0.join("bad.sqlite"),
            Zeroizing::new([84; 32])
        )
        .await
        .is_err()
    );
    assert!(!dir.0.join("bad.sqlite").exists());
}

#[test]
fn profile_staging_counts_roots_requires_review_and_rejects_stale_approval() {
    let mut state = yonik_subscription::Subscription::new(std::num::NonZeroU64::MIN);
    let ticket = state.begin().expect("ticket");
    let body = include_bytes!("../../../tests/fixtures/xray-full-profile-seven.json");
    let staged = state
        .stage_profiles_cancellable(ticket, body.to_vec(), || true)
        .expect("stage");
    assert_eq!(staged.summary().accepted, 7);
    assert!(staged.summary().needs_review());
    assert!(matches!(
        staged.accept_clean(),
        Err(yonik_subscription::Error::ReviewRequired)
    ));
    let staged = state
        .stage_profiles_cancellable(ticket, body.to_vec(), || true)
        .expect("stage");
    state.begin().expect("supersede");
    assert_eq!(
        state.commit_profiles(staged.approve_after_review()),
        Err(yonik_subscription::Error::Stale)
    );
    assert_eq!(state.revision(), 0);
}

#[tokio::test]
async fn old_database_rebuild_retains_flattened_favorite_as_unavailable() {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    let dir = Directory::new();
    let repo = dir.open().await;
    let source = repo.create_source(vec![]).await.expect("source").id;
    save(
        &repo,
        source,
        0,
        "trojan://synthetic@legacy.invalid:443#outbound",
    )
    .await;
    let legacy = repo
        .profiles(source, ProfileQuery::default())
        .await
        .expect("legacy")
        .profiles[0]
        .id;
    repo.set_favorite(legacy, true).await.expect("favorite");
    repo.close().await.expect("close");
    let c = rusqlite::Connection::open(dir.database()).expect("fixture");
    let database_id: Vec<u8> = c
        .query_row("SELECT id FROM repository", [], |r| r.get(0))
        .expect("database id");
    let original = r#"{"remarks":"balancer","outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"legacy.invalid","port":443,"password":"synthetic"}]}}],"routing":{"balancers":[{"tag":"auto","selector":["proxy"]}]}}"#;
    let mut aad = database_id;
    aad.push(2);
    for value in [source, 1, 1] {
        aad.extend_from_slice(&value.to_le_bytes());
    }
    let nonce = [37; 24];
    let encrypted = XChaCha20Poly1305::new((&[84u8; 32]).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: original.as_bytes(),
                aad: &aad,
            },
        )
        .expect("fixture AEAD");
    let mut body = nonce.to_vec();
    body.extend(encrypted);
    c.execute(
        "UPDATE snapshots SET body=?1 WHERE source_id=?2",
        rusqlite::params![body, source],
    )
    .expect("old snapshot");
    c.execute_batch(
        "DROP TABLE native_profiles; DROP TABLE profile_projection; PRAGMA user_version=3;",
    )
    .expect("old schema");
    drop(c);
    let repo = dir.open().await;
    let all = repo
        .catalog(
            source,
            ProfileQuery {
                include_unavailable: true,
                ..Default::default()
            },
        )
        .await
        .expect("atomic rebuild");
    assert_eq!(all.total, 2);
    assert!(all.profiles.iter().any(
        |(p, _)| matches!(p,CatalogProfile::Server(p) if p.id==legacy && p.favorite && !p.available)
    ));
    assert!(
        all.profiles
            .iter()
            .any(|(p, _)| matches!(p,CatalogProfile::Xray(p) if p.available && !p.favorite))
    );
    repo.close().await.expect("close");
    EncryptedSubscriptionRepository::backup_closed(
        dir.database(),
        dir.0.join("migrated.sqlite"),
        Zeroizing::new([84; 32]),
    )
    .await
    .expect("migration backup");
    EncryptedSubscriptionRepository::restore_closed(
        dir.0.join("migrated.sqlite"),
        dir.0.join("restored.sqlite"),
        Zeroizing::new([84; 32]),
    )
    .await
    .expect("restore");
}

#[tokio::test]
async fn failed_projection_write_rolls_back_snapshot_and_array_order_changes_identity() {
    let dir = Directory::new();
    let repo = dir.open().await;
    let source = repo.create_source(vec![]).await.expect("source").id;
    save(&repo, source, 0, &root("private-name", "[1,2]")).await;
    let first = page(&repo, source).await;
    let CatalogProfile::Xray(p) = &first.profiles[0].0 else {
        panic!("native");
    };
    let old = p.id;
    let c = rusqlite::Connection::open(dir.database()).expect("fixture");
    c.execute_batch("CREATE TRIGGER fail_projection BEFORE INSERT ON profile_projection BEGIN SELECT RAISE(ABORT,'fixture'); END;").expect("failure fixture");
    assert_eq!(
        repo.commit_snapshot(source, 1, 1, input(&root("new", "[2,1]")))
            .await,
        Err(RepositoryError::Storage)
    );
    let retained = page(&repo, source).await;
    assert_eq!(retained.snapshot_revision, 1);
    assert!(
        repo.resolve_catalog(first.profiles[0].1.clone())
            .await
            .is_ok()
    );
    c.execute_batch("DROP TRIGGER fail_projection;")
        .expect("remove own fixture");
    drop(c);
    save(&repo, source, 1, &root("new", "[2,1]")).await;
    let second = page(&repo, source).await;
    let CatalogProfile::Xray(p) = &second.profiles[0].0 else {
        panic!("native");
    };
    assert_ne!(p.id, old);
    repo.close().await.expect("close");
    let bytes = fs::read(dir.database()).expect("bytes");
    for secret in [b"sensitive-catalog-secret".as_slice(), b"private-name"] {
        assert!(!bytes.windows(secret.len()).any(|v| v == secret));
    }
}

#[tokio::test]
async fn failed_refresh_preserves_native_snapshot_and_selection_without_transport() {
    use yonik_linux::{
        FetchError, FetchResponse, FetchRoute, FetchValidators, Source, SubscriptionFetch,
        SubscriptionService, SubscriptionSource,
    };
    struct FailedFetch;
    impl SubscriptionFetch for FailedFetch {
        fn fetch<'a>(
            &'a self,
            _: &'a Source,
            _: FetchRoute,
            _: Option<&'a FetchValidators>,
            _: tokio::sync::watch::Receiver<bool>,
        ) -> futures_util::future::BoxFuture<'a, Result<FetchResponse, FetchError>> {
            Box::pin(async { Err(FetchError::Transport) })
        }
    }
    let dir = Directory::new();
    let repo = dir.open().await;
    let service = SubscriptionService::new(repo.clone());
    let source = service
        .add(
            SubscriptionSource::new(
                "source".into(),
                "https://fixture.invalid/sub".into(),
                false,
                FetchRoute::Direct,
            )
            .expect("spec"),
        )
        .await
        .expect("source");
    let body = root("working", "1e999");
    save(&repo, source, 0, &body).await;
    let before = service
        .catalog(source, ProfileQuery::default())
        .await
        .expect("before");
    let (_sender, cancel) = tokio::sync::watch::channel(false);
    assert!(
        service
            .refresh_with_host(source, Some(1), &FailedFetch, cancel)
            .await
            .is_err()
    );
    assert_eq!(
        service
            .catalog(source, ProfileQuery::default())
            .await
            .expect("after")
            .snapshot_revision,
        1
    );
    assert!(matches!(
        service
            .select_catalog_profile(before.profiles[0].1.clone())
            .await
            .expect("selection")
            .entry,
        ProfileEntry::Xray(_)
    ));
    let (_sender, cancel) = yonik_linux::Cancellation::new();
    assert_eq!(
        service
            .offline_profiles(source, cancel)
            .await
            .expect("offline")
            .original()
            .expose(),
        body
    );
    service.close().await.expect("service close");
    repo.close().await.expect("close");
}
