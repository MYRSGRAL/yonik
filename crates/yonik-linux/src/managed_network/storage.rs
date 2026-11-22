use super::{Document, JournalError, MAX_JOURNAL_BYTES};
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags};
use std::{
    fs::File,
    io::{Read, Write},
    ops::Deref,
    path::{Component, Path},
};

const JOURNAL: &str = "journal.json";
const PENDING: &str = "journal.next";
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::NOFOLLOW
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);

/// Единственный владелец блокировки; дубликаты FD её временем жизни не управляют.
pub(super) struct LockedDirectory(File);

impl Deref for LockedDirectory {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for LockedDirectory {
    fn drop(&mut self) {
        // После fork CLOEXEC-дубликат до exec удерживает то же open file description.
        // Явный unlock освобождает flock сразу, не дожидаясь закрытия дубликата.
        loop {
            match fs::flock(&self.0, FlockOperation::Unlock) {
                Ok(()) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => {
                    // Drop не может вернуть ошибку. При иной ошибке оставляем
                    // штатное закрытие File; унаследованный FD закроется при exec.
                    break;
                }
            }
        }
    }
}

fn safe_file(file: &File) -> Result<(), JournalError> {
    let stat = fs::fstat(file).map_err(|_| JournalError::Io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(JournalError::UnsafePath);
    }
    Ok(())
}

/// Каждый компонент открывается относительно закреплённого FD с NOFOLLOW.
/// Предки — root/euid-owned, без чужой записи (кроме root-owned sticky /tmp).
/// Только последний компонент разрешено создать; права существующих не чиним.
pub(super) fn directory(path: &Path) -> Result<LockedDirectory, JournalError> {
    directory_with_sync(path, &mut File::sync_all)
}

fn directory_with_sync(
    path: &Path,
    sync_parent: &mut impl FnMut(&File) -> std::io::Result<()>,
) -> Result<LockedDirectory, JournalError> {
    if !path.is_absolute() {
        return Err(JournalError::UnsafePath);
    }
    let components: Vec<_> = path.components().collect();
    if components.len() < 2
        || components
            .iter()
            .skip(1)
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(JournalError::UnsafePath);
    }
    let mut current =
        File::from(fs::open("/", DIR_FLAGS, Mode::empty()).map_err(|_| JournalError::UnsafePath)?);
    for (index, part) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = part else {
            return Err(JournalError::UnsafePath);
        };
        let last = index == components.len() - 1;
        let opened = match fs::openat(&current, *name, DIR_FLAGS, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if last => {
                match fs::mkdirat(&current, *name, Mode::from_raw_mode(0o700)) {
                    Ok(()) => {}
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(JournalError::Io),
                }
                fs::openat(&current, *name, DIR_FLAGS, Mode::empty())
                    .map_err(|_| JournalError::UnsafePath)?
            }
            Err(_) => return Err(JournalError::UnsafePath),
        };
        let stat = fs::fstat(&opened).map_err(|_| JournalError::Io)?;
        let effective = rustix::process::geteuid().as_raw();
        let safe = if last {
            stat.st_uid == effective && stat.st_mode & 0o7777 == 0o700
        } else {
            (stat.st_uid == 0 || stat.st_uid == effective)
                && (stat.st_mode & 0o022 == 0 || stat.st_uid == 0 && stat.st_mode & 0o1000 != 0)
        };
        if !safe {
            return Err(JournalError::UnsafePath);
        }
        // Предыдущий процесс мог создать каталог и умереть до parent fsync.
        // Поэтому подтверждаем его имя и при повторном открытии.
        if last {
            sync_parent(&current).map_err(|_| JournalError::Io)?;
        }
        current = File::from(opened);
    }
    fs::flock(&current, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if error == rustix::io::Errno::WOULDBLOCK {
            JournalError::Busy
        } else {
            JournalError::Io
        }
    })?;
    Ok(LockedDirectory(current))
}

fn existing(directory: &File, name: &str, flags: OFlags) -> Result<Option<File>, JournalError> {
    match fs::openat(directory, name, FILE_FLAGS | flags, Mode::empty()) {
        Ok(fd) => {
            let file = File::from(fd);
            safe_file(&file)?;
            Ok(Some(file))
        }
        Err(rustix::io::Errno::NOENT) => {
            // Dangling symlink даёт ELOOP с NOFOLLOW, но сохраняем проверку
            // имени явно: отсутствующим считается только отсутствие inode.
            match fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => Ok(None),
                _ => Err(JournalError::UnsafePath),
            }
        }
        Err(_) => Err(JournalError::UnsafePath),
    }
}

pub(super) fn read(directory: &File) -> Result<Option<Document>, JournalError> {
    let Some(bytes) = read_bounded(directory, JOURNAL, MAX_JOURNAL_BYTES)? else {
        return Ok(None);
    };
    // Каждая историческая версия разбирается собственной строгой схемой:
    // новые поля нельзя незаметно протащить через миграцию старого формата.
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyV1 {
        version: u32,
        ownership: super::Ownership,
        records: Vec<super::Record>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyV2 {
        version: u32,
        ownership: super::Ownership,
        records: Vec<super::Record>,
        public_policy: Option<super::PublicPolicyRecord>,
        policy_sequence: u64,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyV3 {
        version: u32,
        ownership: super::Ownership,
        records: Vec<super::Record>,
        public_policy: Option<super::PublicPolicyRecord>,
        policy_sequence: u64,
        #[serde(deserialize_with = "super::session_state::deserialize_recovery")]
        session_recovery: Option<super::SessionRecoveryRecord>,
    }
    let document = match value.get("version").and_then(serde_json::Value::as_u64) {
        Some(1) => {
            let legacy: LegacyV1 =
                serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
            Document {
                version: legacy.version,
                ownership: legacy.ownership,
                records: legacy.records,
                public_policy: None,
                policy_sequence: 0,
                session_recovery: None,
                fake_quarantine: None,
            }
        }
        Some(2) => {
            let legacy: LegacyV2 =
                serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
            Document {
                version: legacy.version,
                ownership: legacy.ownership,
                records: legacy.records,
                public_policy: legacy.public_policy,
                policy_sequence: legacy.policy_sequence,
                session_recovery: None,
                fake_quarantine: None,
            }
        }
        Some(3) => {
            let legacy: LegacyV3 =
                serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
            Document {
                version: legacy.version,
                ownership: legacy.ownership,
                records: legacy.records,
                public_policy: legacy.public_policy,
                policy_sequence: legacy.policy_sequence,
                session_recovery: legacy.session_recovery,
                fake_quarantine: None,
            }
        }
        Some(4) => serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?,
        Some(_) => return Err(JournalError::Version),
        None => return Err(JournalError::Corrupt),
    };
    Ok(Some(document))
}

pub(super) fn write(directory: &File, document: &Document) -> Result<(), JournalError> {
    let bytes = serde_json::to_vec(document).map_err(|_| JournalError::Invalid)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::Limit);
    }
    write_atomic(directory, JOURNAL, PENDING, &bytes)
}

pub(super) fn read_bounded(
    directory: &File,
    name: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>, JournalError> {
    let Some(file) = existing(directory, name, OFlags::RDONLY)? else {
        return Ok(None);
    };
    if file.metadata().map_err(|_| JournalError::Io)?.len() > limit as u64 {
        return Err(JournalError::Limit);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| JournalError::Io)?;
    if bytes.len() > limit {
        return Err(JournalError::Limit);
    }
    Ok(Some(bytes))
}

pub(super) fn write_atomic(
    directory: &File,
    name: &str,
    temporary: &str,
    bytes: &[u8],
) -> Result<(), JournalError> {
    // Небезопасный существующий файл нельзя заменить даже атомарным rename.
    existing(directory, name, OFlags::RDONLY)?;
    let mut pending = match existing(directory, temporary, OFlags::WRONLY)? {
        Some(file) => file,
        None => File::from(
            fs::openat(
                directory,
                temporary,
                FILE_FLAGS | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| JournalError::Io)?,
        ),
    };
    safe_file(&pending)?;
    pending.set_len(0).map_err(|_| JournalError::Io)?;
    pending.write_all(bytes).map_err(|_| JournalError::Io)?;
    pending.sync_all().map_err(|_| JournalError::Io)?;
    fs::renameat(directory, temporary, directory, name).map_err(|_| JournalError::Io)?;
    directory
        .sync_all()
        .map_err(|_| JournalError::UncertainWrite)
}

#[cfg(test)]
mod tests {
    use super::{JournalError, directory_with_sync};
    use crate::managed_network::{Journal, Ownership};
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

    struct Area(PathBuf);
    impl Drop for Area {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("Очистка собственного тестового каталога");
        }
    }

    #[test]
    fn owner_drop_unlocks_directory_with_duplicate_descriptor_alive() {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).expect("Тестовая случайность");
        let area_path = std::env::temp_dir().join(format!(
            "yonik-lock-lifetime-{:016x}",
            u64::from_le_bytes(nonce)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&area_path)
            .expect("Тестовый каталог");
        let area = Area(area_path);
        let path = area.0.join("state");
        let ownership = Ownership::new(1000, 1, 1, 1, 1).expect("Тестовый владелец");
        let owner = Journal::open(&path, ownership).expect("Первый владелец");
        // try_clone сохраняет то же open file description, как FD после fork.
        let inherited = owner.directory.try_clone().expect("Дубликат FD");
        assert!(
            rustix::io::fcntl_getfd(&*owner.directory)
                .expect("Флаги FD журнала")
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(matches!(
            Journal::open(&path, ownership),
            Err(JournalError::Busy)
        ));

        drop(owner);
        let next_owner = Journal::open(&path, ownership)
            .expect("Drop владельца освобождает блокировку при живом дубликате");
        drop(inherited);
        assert!(matches!(
            Journal::open(&path, ownership),
            Err(JournalError::Busy)
        ));
        drop(next_owner);
        Journal::open(&path, ownership).expect("Следующий владелец освободил блокировку");
    }

    #[test]
    fn reopen_retries_parent_sync_after_interrupted_directory_creation() {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).expect("Тестовая случайность");
        let area_path = std::env::temp_dir().join(format!(
            "yonik-parent-sync-{:016x}",
            u64::from_le_bytes(nonce)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&area_path)
            .expect("Тестовый каталог");
        let area = Area(area_path);
        let path = area.0.join("state");
        let mut first_syncs = 0;
        let failed = directory_with_sync(&path, &mut |_| {
            first_syncs += 1;
            Err(std::io::Error::other("Инъекция ошибки parent fsync"))
        });
        assert!(matches!(failed, Err(JournalError::Io)));
        assert_eq!(first_syncs, 1);
        assert!(path.is_dir());

        let mut retry_syncs = 0;
        let reopened = directory_with_sync(&path, &mut |parent| {
            retry_syncs += 1;
            parent.sync_all()
        })
        .expect("Повторное открытие");
        drop(reopened);
        assert_eq!(
            retry_syncs, 1,
            "Существующее имя каталога тоже требует parent fsync"
        );
    }
}
