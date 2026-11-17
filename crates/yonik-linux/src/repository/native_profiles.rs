//! Проекция v2: native DATA отделены от серверных endpoint и runtime authority.
use super::{
    BODY_LIMIT, EncryptedSubscriptionRepository, MaintenanceControl, ProfileQuery, ProfileRow,
    ProfileSort, RepositoryError, Result, SMALL_LIMIT, ServerProfile, SnapshotCommitError,
    TransactionBehavior, bounded_blob, decrypt, ensure_catalog, open_profile, params, positive,
    read_profiles, storage,
};
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde_json::value::RawValue;
use std::collections::{BTreeMap, HashMap, VecDeque};
use yonik_import::{NativeProfile, ProfileEntry, ProfileImportReport};
use zeroize::Zeroizing;

const SCHEMA: &str = "CREATE TABLE native_profiles(id INTEGER PRIMARY KEY AUTOINCREMENT,source_id INTEGER NOT NULL REFERENCES sources(id),fingerprint BLOB NOT NULL,generation INTEGER NOT NULL,revision INTEGER NOT NULL,ordinal INTEGER NOT NULL,present INTEGER NOT NULL,payload BLOB NOT NULL); CREATE INDEX native_profile_source ON native_profiles(source_id); CREATE TABLE profile_projection(source_id INTEGER PRIMARY KEY REFERENCES sources(id),version INTEGER NOT NULL CHECK(version=2),generation INTEGER NOT NULL,revision INTEGER NOT NULL,native_count INTEGER NOT NULL);";

pub(super) fn initialize(connection: &mut Connection) -> Result<()> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='profile_projection')",
            [],
            |r| r.get(0),
        )
        .map_err(storage)?;
    if !exists {
        tx.execute_batch(SCHEMA).map_err(storage)?;
    }
    tx.commit().map_err(storage)
}

pub struct NativeSummary {
    pub id: i64,
    pub source_id: i64,
    pub ordinal: usize,
    pub name: String,
    pub favorite: bool,
    pub available: bool,
    pub requires_reselection: bool,
}
pub enum CatalogProfile {
    Server(ServerProfile),
    Xray(NativeSummary),
}
/// Закрытый token связывает вид, identity и все поколения показанной страницы.
#[derive(Clone)]
pub struct CatalogSelection {
    id: i64,
    source: i64,
    native: bool,
    fingerprint: Vec<u8>,
    source_generation: i64,
    generation: i64,
    revision: i64,
}
pub struct CatalogPage {
    pub profiles: Vec<(CatalogProfile, CatalogSelection)>,
    pub total: usize,
    pub raw_count: usize,
    pub unique_count: usize,
    pub duplicate_count: usize,
    pub catalog_version: u8,
    pub source_generation: i64,
    pub snapshot_generation: i64,
    pub snapshot_revision: i64,
}
pub struct ResolvedCatalogProfile {
    pub entry: ProfileEntry,
    pub source_id: i64,
    pub source_generation: i64,
    pub snapshot_generation: i64,
    pub snapshot_revision: i64,
}
pub(super) struct PreparedNative {
    fingerprint: Vec<u8>,
    ordinal: usize,
    name: String,
}

// RawValue сохраняет числа вне f64. Глубина и общий объём уже ограничены P1.
fn canonical(raw: &str, root: bool, output: &mut Vec<u8>) -> Result<()> {
    match raw.as_bytes().first() {
        Some(b'{') => {
            let fields: BTreeMap<String, &RawValue> =
                serde_json::from_str(raw).map_err(|_| RepositoryError::InvalidInput)?;
            output.push(b'{');
            for (key, value) in fields {
                if root && matches!(key.as_str(), "remarks" | "tag") {
                    continue;
                }
                output.push(b'k');
                output.extend_from_slice(&(key.len() as u64).to_le_bytes());
                output.extend_from_slice(key.as_bytes());
                canonical(value.get(), false, output)?;
            }
            output.push(b'}');
        }
        Some(b'[') => {
            let values: Vec<&RawValue> =
                serde_json::from_str(raw).map_err(|_| RepositoryError::InvalidInput)?;
            output.push(b'[');
            for value in values {
                canonical(value.get(), false, output)?;
            }
            output.push(b']');
        }
        Some(b'"') => {
            let value: String =
                serde_json::from_str(raw).map_err(|_| RepositoryError::InvalidInput)?;
            output.push(b's');
            output.extend_from_slice(&(value.len() as u64).to_le_bytes());
            output.extend_from_slice(value.as_bytes());
        }
        _ => {
            output.push(b'p');
            output.extend_from_slice(&(raw.len() as u64).to_le_bytes());
            output.extend_from_slice(raw.as_bytes());
        }
    }
    Ok(())
}
fn identity(
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    profile: &NativeProfile,
) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    let mut bytes = Zeroizing::new(Vec::new());
    canonical(profile.source().expose(), true, &mut bytes)?;
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).map_err(|_| RepositoryError::Storage)?;
    mac.update(b"yonik-profile-fingerprint\0v2\0xray\0");
    mac.update(db);
    mac.update(&source.to_le_bytes());
    mac.update(&bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}
pub(super) fn prepare(
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    report: ProfileImportReport,
    check: &impl Fn() -> std::result::Result<(), SnapshotCommitError>,
) -> std::result::Result<Vec<PreparedNative>, SnapshotCommitError> {
    let mut rows = Vec::with_capacity(report.entries.len());
    for entry in report.entries {
        check()?;
        let ProfileEntry::Xray(profile) = entry else {
            return Err(RepositoryError::InvalidInput.into());
        };
        rows.push(PreparedNative {
            fingerprint: identity(key, db, source, &profile)?,
            ordinal: profile.ordinal(),
            name: profile.name().to_owned(),
        });
    }
    Ok(rows)
}
fn native_aad(db: &[u8; 32], row: &ProfileRow) -> Vec<u8> {
    let mut value = super::profile_aad(db, row);
    value.extend_from_slice(b"\0native-xray-projection-v2");
    value
}
fn seal(
    key: &[u8; 32],
    db: &[u8; 32],
    row: &ProfileRow,
    name: &str,
    favorite: bool,
) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    let plain = Zeroizing::new(
        serde_json::to_vec(&(2u8, name, favorite)).map_err(|_| RepositoryError::InvalidInput)?,
    );
    let mut nonce = [0; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| RepositoryError::Storage)?;
    let mut value = nonce.to_vec();
    value.extend(
        XChaCha20Poly1305::new(key.into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &native_aad(db, row),
                },
            )
            .map_err(|_| RepositoryError::Storage)?,
    );
    Ok(value)
}
fn open(key: &[u8; 32], db: &[u8; 32], row: &ProfileRow) -> Result<NativeSummary> {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    if row.payload.len() < 40
        || row.payload.len() > SMALL_LIMIT + 40
        || row.fingerprint.len() != 32
        || row.ordinal >= 20_000
        || row.id <= 0
        || row.source <= 0
        || row.generation <= 0
        || row.revision <= 0
    {
        return Err(RepositoryError::Corrupt);
    }
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                XNonce::from_slice(&row.payload[..24]),
                Payload {
                    msg: &row.payload[24..],
                    aad: &native_aad(db, row),
                },
            )
            .map_err(|_| RepositoryError::Corrupt)?,
    );
    let (version, name, favorite): (u8, String, bool) =
        serde_json::from_slice(&plain).map_err(|_| RepositoryError::Corrupt)?;
    if version != 2 || name.chars().count() > 160 || name.chars().any(char::is_control) {
        return Err(RepositoryError::Corrupt);
    }
    Ok(NativeSummary {
        id: row.id,
        source_id: row.source,
        ordinal: row.ordinal,
        name,
        favorite,
        available: row.present,
        requires_reselection: !row.present,
    })
}
fn rows(connection: &Connection, source: i64) -> Result<Vec<ProfileRow>> {
    projection_rows(connection, source, true)
}
fn projection_rows(connection: &Connection, source: i64, native: bool) -> Result<Vec<ProfileRow>> {
    let table = if native {
        "native_profiles"
    } else {
        "profiles"
    };
    let sql = format!(
        "SELECT id,source_id,fingerprint,generation,revision,ordinal,present,payload FROM {table} WHERE source_id=?1 ORDER BY id LIMIT 40001"
    );
    let mut stmt = connection.prepare(&sql).map_err(storage)?;
    let result = stmt
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
        .map_err(storage)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| RepositoryError::Corrupt)?;
    if result.len() > 40_000 {
        return Err(RepositoryError::Corrupt);
    }
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn reconcile(
    tx: &Transaction<'_>,
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    generation: i64,
    revision: i64,
    prepared: &[PreparedNative],
    check: &impl Fn() -> std::result::Result<(), SnapshotCommitError>,
) -> std::result::Result<(), SnapshotCommitError> {
    let mut old: HashMap<Vec<u8>, VecDeque<(ProfileRow, NativeSummary)>> = HashMap::new();
    for row in rows(tx, source)? {
        check()?;
        let summary = open(key, db, &row)?;
        old.entry(row.fingerprint.clone())
            .or_default()
            .push_back((row, summary));
    }
    let mut counts = HashMap::new();
    for p in prepared {
        *counts.entry(&p.fingerprint).or_insert(0usize) += 1;
    }
    // Неоднозначное избранное остаётся историческим, а не переезжает по ordinal.
    let ambiguous: std::collections::HashSet<Vec<u8>> = old
        .iter()
        .filter(|(fp, values)| {
            (values.len() > 1 || counts.get(fp).copied().unwrap_or(0) > 1)
                && values.iter().any(|(_, p)| p.favorite)
        })
        .map(|(fp, _)| fp.clone())
        .collect();
    for p in prepared {
        check()?;
        let previous = if ambiguous.contains(&p.fingerprint) {
            None
        } else {
            old.get_mut(&p.fingerprint).and_then(VecDeque::pop_front)
        };
        let (id, favorite) = if let Some((row, summary)) = previous {
            (row.id, summary.favorite)
        } else {
            tx.execute("INSERT INTO native_profiles(source_id,fingerprint,generation,revision,ordinal,present,payload) VALUES (?1,?2,?3,?4,?5,1,X'')",params![source,p.fingerprint,generation,revision,p.ordinal]).map_err(storage)?;
            (tx.last_insert_rowid(), false)
        };
        let row = ProfileRow {
            id,
            source,
            fingerprint: p.fingerprint.clone(),
            generation,
            revision,
            ordinal: p.ordinal,
            present: true,
            payload: Vec::new(),
        };
        let payload = seal(key, db, &row, &p.name, favorite)?;
        tx.execute("UPDATE native_profiles SET generation=?1,revision=?2,ordinal=?3,present=1,payload=?4 WHERE id=?5",params![generation,revision,p.ordinal,payload,id]).map_err(storage)?;
    }
    for (_, group) in old {
        for (mut row, summary) in group {
            check()?;
            if summary.favorite {
                row.present = false;
                let payload = seal(key, db, &row, &summary.name, true)?;
                tx.execute(
                    "UPDATE native_profiles SET present=0,payload=?1 WHERE id=?2",
                    params![payload, row.id],
                )
                .map_err(storage)?;
            } else {
                tx.execute("DELETE FROM native_profiles WHERE id=?1", [row.id])
                    .map_err(storage)?;
            }
        }
    }
    tx.execute("INSERT INTO profile_projection VALUES (?1,2,?2,?3,?4) ON CONFLICT(source_id) DO UPDATE SET version=2,generation=excluded.generation,revision=excluded.revision,native_count=excluded.native_count",params![source,generation,revision,prepared.len()]).map_err(storage)?;
    Ok(())
}
pub(super) fn is_current(
    tx: &Transaction<'_>,
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    generation: i64,
    revision: i64,
    report: &mut Option<ProfileImportReport>,
) -> Result<bool> {
    let marker:Option<(i64,i64,i64,usize)>=tx.query_row("SELECT version,generation,revision,native_count FROM profile_projection WHERE source_id=?1",[source],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(storage)?;
    match marker {
        None => Ok(false),
        Some((v, g, r, n)) if v == 2 && g > 0 && r > 0 && n <= 20_000 => {
            let actual: usize = tx
                .query_row(
                    "SELECT count(*) FROM native_profiles WHERE source_id=?1 AND present=1",
                    [source],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if g == generation && r == revision && actual != n {
                return Err(RepositoryError::Corrupt);
            }
            if g == generation && r == revision {
                *report = validate_composition(tx, key, db, source, g, r, &|| Ok(()))?;
            }
            Ok(g == generation && r == revision)
        }
        _ => Err(RepositoryError::Corrupt),
    }
}

pub(super) fn original_report(
    connection: &Connection,
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    generation: i64,
    revision: i64,
    check: &impl Fn() -> Result<()>,
) -> Result<Option<ProfileImportReport>> {
    check()?;
    let encrypted: Vec<u8> = connection
        .query_row(
            "SELECT body FROM snapshots WHERE source_id=?1",
            [source],
            |r| bounded_blob(r, 0, BODY_LIMIT + 40),
        )
        .map_err(storage)?;
    let body = decrypt(
        key, db, 2, source, generation, revision, &encrypted, BODY_LIMIT,
    )?;
    let parsed = yonik_import::import_profiles(body.to_vec());
    check()?;
    match parsed {
        Ok(report) => Ok(Some(report)),
        Err(error) if error.kind() == yonik_import::FatalError::UnsupportedFormat => {
            // Legacy native DATA остаются непрозрачными, без selectable endpoints.
            let legacy = yonik_import::import_bytes_cancellable(body.to_vec(), || check().is_ok())
                .map_err(|_| RepositoryError::Corrupt)?;
            check()?;
            if legacy.native_json.is_none() {
                return Err(RepositoryError::Corrupt);
            }
            Ok(None)
        }
        Err(_) => Err(RepositoryError::Corrupt),
    }
}

/// AEAD каждой строки не доказывает полноту набора. Original задаёт точный
/// multiset вида/ordinal/identity; historical favourites проверяются отдельно.
fn validate_composition(
    connection: &Connection,
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
    generation: i64,
    revision: i64,
    check: &impl Fn() -> Result<()>,
) -> Result<Option<ProfileImportReport>> {
    let report = original_report(connection, key, db, source, generation, revision, check)?;
    let mut expected = HashMap::new();
    let mut servers = std::collections::HashSet::new();
    if let Some(report) = &report {
        for (ordinal, entry) in report.entries.iter().enumerate() {
            check()?;
            match entry {
                ProfileEntry::Xray(profile) => {
                    expected.insert((true, ordinal), identity(key, db, source, profile)?);
                }
                ProfileEntry::Server(server) => {
                    let fp = super::fingerprint(key, db, source, server)?;
                    if servers.insert(fp.clone()) {
                        expected.insert((false, ordinal), fp);
                    }
                }
            }
        }
    }
    for native in [false, true] {
        for row in projection_rows(connection, source, native)? {
            check()?;
            super::validate_profile_snapshot(&row, generation, revision)?;
            if native {
                open(key, db, &row)?;
            } else {
                open_profile(key, db, &row)?;
            }
            if row.present
                && expected.remove(&(native, row.ordinal)).as_ref() != Some(&row.fingerprint)
            {
                return Err(RepositoryError::Corrupt);
            }
        }
    }
    check()?;
    if !expected.is_empty() {
        return Err(RepositoryError::Corrupt);
    }
    Ok(report)
}

impl EncryptedSubscriptionRepository {
    pub async fn catalog(&self, source: i64, query: ProfileQuery) -> Result<CatalogPage> {
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
            let sg: i64 = tx
                .query_row(
                    "SELECT generation FROM sources WHERE id=?1",
                    [source],
                    |r| r.get(0),
                )
                .optional()
                .map_err(storage)?
                .ok_or(RepositoryError::NotFound)?;
            let (g, r, raw, unique) = ensure_catalog(&tx, &db.key, &db.id, source)?;
            let native_count: usize = tx
                .query_row(
                    "SELECT count(*) FROM native_profiles WHERE source_id=?1 AND present=1",
                    [source],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            let mut collected = Vec::new();
            let search = query.search.to_lowercase();
            for row in read_profiles(&tx, source)? {
                super::validate_profile_snapshot(&row, g, r)?;
                let p = open_profile(&db.key, &db.id, &row)?;
                let name = p.name.to_lowercase();
                if (query.include_unavailable || p.available)
                    && (!query.favorites_only || p.favorite)
                    && (name.contains(&search) || p.host.to_lowercase().contains(&search))
                {
                    let token = selection(&row, false, sg, g, r);
                    collected.push((p.ordinal, name, CatalogProfile::Server(p), token));
                }
            }
            for row in rows(&tx, source)? {
                super::validate_profile_snapshot(&row, g, r)?;
                let p = open(&db.key, &db.id, &row)?;
                let name = p.name.to_lowercase();
                if (query.include_unavailable || p.available)
                    && (!query.favorites_only || p.favorite)
                    && name.contains(&search)
                {
                    let token = selection(&row, true, sg, g, r);
                    collected.push((p.ordinal, name, CatalogProfile::Xray(p), token));
                }
            }
            match query.sort {
                ProfileSort::Name => {
                    collected.sort_by(|a, b| a.1.cmp(&b.1).then(a.3.id.cmp(&b.3.id)))
                }
                ProfileSort::SourceOrder => collected.sort_by_key(|v| (v.0, v.3.native, v.3.id)),
            }
            let total = collected.len();
            let profiles = collected
                .into_iter()
                .skip(query.offset)
                .take(query.limit)
                .map(|(_, _, p, t)| (p, t))
                .collect();
            tx.commit().map_err(storage)?;
            Ok(CatalogPage {
                profiles,
                total,
                raw_count: raw + native_count,
                unique_count: unique + native_count,
                duplicate_count: raw.saturating_sub(unique),
                catalog_version: 2,
                source_generation: sg,
                snapshot_generation: g,
                snapshot_revision: r,
            })
        })
        .await
    }
    pub async fn resolve_catalog(&self, token: CatalogSelection) -> Result<ResolvedCatalogProfile> {
        self.run(move |db| {
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let mut report = None;
            let (g, r, _, _) =
                super::ensure_catalog_report(&tx, &db.key, &db.id, token.source, &mut report)?;
            let sg: i64 = tx
                .query_row(
                    "SELECT generation FROM sources WHERE id=?1",
                    [token.source],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if (sg, g, r) != (token.source_generation, token.generation, token.revision) {
                return Err(RepositoryError::Conflict);
            }
            let row = if token.native {
                rows(&tx, token.source)?
            } else {
                read_profiles(&tx, token.source)?
            }
            .into_iter()
            .find(|row| row.id == token.id)
            .ok_or(RepositoryError::NotFound)?;
            if token.native {
                open(&db.key, &db.id, &row)?;
            } else {
                open_profile(&db.key, &db.id, &row)?;
            }
            if !row.present {
                return Err(RepositoryError::NotFound);
            }
            super::validate_profile_snapshot(&row, g, r)?;
            if row.fingerprint != token.fingerprint {
                return Err(RepositoryError::Conflict);
            }
            let report = match report {
                Some(report) => report,
                None => original_report(&tx, &db.key, &db.id, token.source, g, r, &|| Ok(()))?
                    .ok_or(RepositoryError::Corrupt)?,
            };
            let entry = report
                .entries
                .into_iter()
                .nth(row.ordinal)
                .ok_or(RepositoryError::Corrupt)?;
            let actual = match &entry {
                ProfileEntry::Xray(p) if token.native => {
                    identity(&db.key, &db.id, token.source, p)?
                }
                ProfileEntry::Server(p) if !token.native => {
                    super::fingerprint(&db.key, &db.id, token.source, p)?
                }
                _ => return Err(RepositoryError::Corrupt),
            };
            if actual != row.fingerprint {
                return Err(RepositoryError::Corrupt);
            }
            tx.commit().map_err(storage)?;
            Ok(ResolvedCatalogProfile {
                entry,
                source_id: token.source,
                source_generation: sg,
                snapshot_generation: g,
                snapshot_revision: r,
            })
        })
        .await
    }
    pub async fn set_catalog_favorite(
        &self,
        token: CatalogSelection,
        favorite: bool,
    ) -> Result<()> {
        self.run(move |db| {
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let (g, r, _, _) = ensure_catalog(&tx, &db.key, &db.id, token.source)?;
            if (g, r) != (token.generation, token.revision) {
                return Err(RepositoryError::Conflict);
            }
            let sg: i64 = tx
                .query_row(
                    "SELECT generation FROM sources WHERE id=?1",
                    [token.source],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if sg != token.source_generation {
                return Err(RepositoryError::Conflict);
            }
            if !token.native {
                let mut count = favorite_count(&tx, &db.key, &db.id, token.source)?;
                let mut target = None;
                for row in read_profiles(&tx, token.source)? {
                    let p = open_profile(&db.key, &db.id, &row)?;
                    count += usize::from(p.favorite);
                    if row.id == token.id {
                        target = Some((row, p));
                    }
                }
                let (row, mut p) = target.ok_or(RepositoryError::NotFound)?;
                if row.fingerprint != token.fingerprint {
                    return Err(RepositoryError::Conflict);
                }
                if favorite && !p.favorite && count >= 20_000 {
                    return Err(RepositoryError::InvalidInput);
                }
                p.favorite = favorite;
                if !favorite && !row.present {
                    tx.execute("DELETE FROM profiles WHERE id=?1", [row.id])
                        .map_err(storage)?;
                } else {
                    let payload = super::seal_profile(&db.key, &db.id, &row, &p)?;
                    tx.execute(
                        "UPDATE profiles SET payload=?1 WHERE id=?2",
                        params![payload, row.id],
                    )
                    .map_err(storage)?;
                }
                return tx.commit().map_err(storage);
            }
            let all = rows(&tx, token.source)?;
            let mut count = 0;
            for row in read_profiles(&tx, token.source)? {
                count += usize::from(open_profile(&db.key, &db.id, &row)?.favorite);
            }
            let mut target = None;
            for row in all {
                let p = open(&db.key, &db.id, &row)?;
                count += usize::from(p.favorite);
                if row.id == token.id {
                    target = Some((row, p));
                }
            }
            let (row, p) = target.ok_or(RepositoryError::NotFound)?;
            if row.fingerprint != token.fingerprint {
                return Err(RepositoryError::Conflict);
            }
            if favorite && !p.favorite && count >= 20_000 {
                return Err(RepositoryError::InvalidInput);
            }
            if !favorite && !row.present {
                tx.execute("DELETE FROM native_profiles WHERE id=?1", [row.id])
                    .map_err(storage)?;
            } else {
                let payload = seal(&db.key, &db.id, &row, &p.name, favorite)?;
                tx.execute(
                    "UPDATE native_profiles SET payload=?1 WHERE id=?2",
                    params![payload, row.id],
                )
                .map_err(storage)?;
            }
            tx.commit().map_err(storage)
        })
        .await
    }
}
pub(super) fn favorite_count(
    connection: &Connection,
    key: &[u8; 32],
    db: &[u8; 32],
    source: i64,
) -> Result<usize> {
    rows(connection, source)?.iter().try_fold(0, |count, row| {
        Ok(count + usize::from(open(key, db, row)?.favorite))
    })
}
fn selection(
    row: &ProfileRow,
    native: bool,
    source_generation: i64,
    generation: i64,
    revision: i64,
) -> CatalogSelection {
    CatalogSelection {
        id: row.id,
        source: row.source,
        native,
        fingerprint: row.fingerprint.clone(),
        source_generation,
        generation,
        revision,
    }
}

pub(super) fn validate_backup(
    connection: &Connection,
    key: &[u8; 32],
    db: &[u8; 32],
    control: &MaintenanceControl,
) -> Result<()> {
    let projection: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='profile_projection')",
            [],
            |r| r.get(0),
        )
        .map_err(storage)?;
    let native: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='native_profiles')",
            [],
            |r| r.get(0),
        )
        .map_err(storage)?;
    if !projection && !native {
        return Ok(());
    }
    if projection != native {
        return Err(RepositoryError::Corrupt);
    }
    let unknown:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT IN ('repository','sources','snapshots','profiles','profile_catalog','source_sequence','routing_draft','sqlite_sequence','native_profiles','profile_projection'))",[],|r|r.get(0)).map_err(storage)?;
    if unknown {
        return Err(RepositoryError::Corrupt);
    }
    // Точный DDL v2, включая отсутствие UNIQUE(fingerprint): дубликаты — multiset.
    for (name, expected) in [
        "native_profiles",
        "native_profile_source",
        "profile_projection",
    ]
    .into_iter()
    .zip(SCHEMA.split(';').filter(|s| !s.is_empty()))
    {
        let actual: String = connection
            .query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .map_err(|_| RepositoryError::Corrupt)?;
        if actual.trim() != expected.trim() {
            return Err(RepositoryError::Corrupt);
        }
    }
    let bad:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM native_profiles WHERE typeof(id)!='integer' OR id<=0 OR typeof(source_id)!='integer' OR typeof(fingerprint)!='blob' OR length(fingerprint)!=32 OR typeof(generation)!='integer' OR generation<=0 OR typeof(revision)!='integer' OR revision<=0 OR typeof(ordinal)!='integer' OR ordinal<0 OR ordinal>=20000 OR typeof(present)!='integer' OR present NOT IN (0,1) OR typeof(payload)!='blob' OR NOT EXISTS(SELECT 1 FROM sources WHERE sources.id=native_profiles.source_id))",[],|r|r.get(0)).map_err(|_|RepositoryError::Corrupt)?;
    if bad {
        return Err(RepositoryError::Corrupt);
    }
    let sequence_bad:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='native_profiles' AND (typeof(seq)!='integer' OR seq<(SELECT COALESCE(MAX(id),0) FROM native_profiles)))",[],|r|r.get(0)).map_err(storage)?;
    if sequence_bad {
        return Err(RepositoryError::Corrupt);
    }
    let bad:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM profile_projection p LEFT JOIN snapshots s ON p.source_id=s.source_id WHERE p.version!=2 OR p.generation<=0 OR p.revision<=0 OR p.native_count<0 OR p.native_count>20000 OR s.source_id IS NULL OR p.generation!=s.source_generation OR p.revision!=s.revision OR p.native_count!=(SELECT count(*) FROM native_profiles n WHERE n.source_id=p.source_id AND n.present=1))",[],|r|r.get(0)).map_err(|_|RepositoryError::Corrupt)?;
    if bad {
        return Err(RepositoryError::Corrupt);
    }
    let mut stmt = connection
        .prepare(
            "SELECT source_id FROM profile_projection UNION SELECT source_id FROM native_profiles",
        )
        .map_err(storage)?;
    let sources = stmt
        .query_map([], |r| r.get::<_, i64>(0))
        .map_err(storage)?;
    for source in sources {
        control.check()?;
        let source = source.map_err(storage)?;
        let (g, r): (i64, i64) = connection
            .query_row(
                "SELECT generation,revision FROM profile_projection WHERE source_id=?1",
                [source],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| RepositoryError::Corrupt)?;
        validate_composition(connection, key, db, source, g, r, &|| control.check())?;
    }
    Ok(())
}
