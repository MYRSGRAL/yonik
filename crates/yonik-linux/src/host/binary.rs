use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    str::FromStr,
    sync::{Arc, Weak},
};

use rustix::fs::{MemfdFlags, Mode, OFlags, SealFlags, fchmod, fcntl_add_seals, memfd_create};
use sha2::{Digest, Sha256 as Hasher};
use tokio::process::Command;
use yonik_engine::Engine;

use super::HostError;
use crate::helper::memory::ByteLease;

#[derive(Clone, Copy)]
pub struct Sha256(pub(crate) [u8; 32]);
impl std::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sha256(..)")
    }
}
impl FromStr for Sha256 {
    type Err = HostError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(HostError::BinaryHash);
        }
        let mut bytes = [0; 32];
        for (output, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let hex = |b: u8| {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b.to_ascii_lowercase() - b'a' + 10
                }
            };
            *output = hex(pair[0]) * 16 + hex(pair[1]);
        }
        Ok(Self(bytes))
    }
}

/// Один sealed inode используется для version/config-check/start. Исходный путь
/// после копирования больше не читается; ни пути, ни содержимое не попадают в Debug.
pub struct BinarySnapshot {
    producer: Option<crate::helper::ImageContract>,
    pub(crate) file: File,
    pub(crate) engine: Engine,
    image: Arc<SharedImage>,
}

/// Lease живёт столько же, сколько sealed inode и все его snapshot-дескрипторы.
pub(crate) struct SharedImage {
    file: File,
    engine: Engine,
    expected: Sha256,
    _lease: Option<ByteLease>,
}
impl std::fmt::Debug for BinarySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BinarySnapshot(<скрыто>)")
    }
}
impl BinarySnapshot {
    pub(crate) fn with_producer(mut self, proof: Option<crate::helper::ImageContract>) -> Self {
        self.producer = proof;
        self
    }
    pub(crate) fn producer(&self) -> Option<crate::helper::ImageContract> {
        self.producer.clone()
    }
    pub(crate) const MAX_SIZE: u64 = 128 * 1024 * 1024;
    pub fn load(path: &Path, expected: Sha256, engine: Engine) -> Result<Self, HostError> {
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(OFlags::NONBLOCK.bits() as i32)
            .open(path)
            .map_err(|_| HostError::BinaryIo)?;
        Self::load_file(source, expected, engine)
    }

    /// Копирует уже открытый источник: helper не переоткрывает проверенный путь.
    pub(crate) fn load_file(
        source: File,
        expected: Sha256,
        engine: Engine,
    ) -> Result<Self, HostError> {
        Self::copy_file(source, expected, engine, None)
    }

    pub(crate) fn load_budgeted(
        source: File,
        expected: Sha256,
        engine: Engine,
        lease: ByteLease,
    ) -> Result<Self, HostError> {
        Self::copy_file(source, expected, engine, Some(lease))
    }

    fn copy_file(
        mut source: File,
        expected: Sha256,
        engine: Engine,
        mut lease: Option<ByteLease>,
    ) -> Result<Self, HostError> {
        let metadata = source.metadata().map_err(|_| HostError::BinaryIo)?;
        if !metadata.is_file()
            || metadata.len() < 4
            || metadata.len() > Self::MAX_SIZE
            || metadata.permissions().mode() & 0o111 == 0
        {
            return Err(HostError::InvalidBinary);
        }
        if let Some(lease) = lease.as_mut() {
            if metadata.len() as usize > lease.bytes() {
                lease
                    .resize(metadata.len() as usize)
                    .map_err(|_| HostError::ResourceLimit)?;
            }
        }
        let descriptor = memfd_create(
            "yonik-engine",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::EXEC,
        )
        .map_err(|_| HostError::Snapshot)?;
        let mut file = File::from(descriptor);
        let mut hasher = Hasher::new();
        let mut buffer = [0; 64 * 1024];
        let mut size = 0_u64;
        loop {
            let read = source.read(&mut buffer).map_err(|_| HostError::BinaryIo)?;
            if read == 0 {
                break;
            }
            if size == 0 && (read < 4 || &buffer[..4] != b"\x7fELF") {
                return Err(HostError::InvalidBinary);
            }
            size += read as u64;
            if size > Self::MAX_SIZE {
                return Err(HostError::InvalidBinary);
            }
            // Сначала резервируем рост: даже изменяемый источник не обходит лимит.
            if let Some(lease) = lease.as_mut() {
                if size as usize > lease.bytes() {
                    lease
                        .resize(size as usize)
                        .map_err(|_| HostError::ResourceLimit)?;
                }
            }
            hasher.update(&buffer[..read]);
            file.write_all(&buffer[..read])
                .map_err(|_| HostError::Snapshot)?;
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected.0 {
            return Err(HostError::BinaryHash);
        }
        fchmod(&file, Mode::RUSR | Mode::XUSR).map_err(|_| HostError::Snapshot)?;
        fcntl_add_seals(
            &file,
            SealFlags::WRITE
                | SealFlags::SHRINK
                | SealFlags::GROW
                | SealFlags::EXEC
                | SealFlags::SEAL,
        )
        .map_err(|_| HostError::Snapshot)?;
        if let Some(lease) = lease.as_mut() {
            lease
                .resize(size as usize)
                .map_err(|_| HostError::ResourceLimit)?;
        }
        Self::from_image(
            Arc::new(SharedImage {
                file,
                engine,
                expected,
                _lease: lease,
            }),
            expected,
            engine,
        )
    }

    pub(crate) fn trusted_hash(&self) -> [u8; 32] {
        self.image.expected.0
    }

    pub(crate) fn weak_image(&self) -> Weak<SharedImage> {
        Arc::downgrade(&self.image)
    }

    pub(crate) fn from_image(
        image: Arc<SharedImage>,
        expected: Sha256,
        engine: Engine,
    ) -> Result<Self, HostError> {
        if image.expected.0 != expected.0 || image.engine != engine {
            return Err(HostError::BinaryHash);
        }
        let file = image.file.try_clone().map_err(|_| HostError::Snapshot)?;
        Ok(Self {
            producer: None,
            file,
            engine,
            image,
        })
    }
    pub(crate) fn command(&self) -> Command {
        let mut command = Command::new(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
        command
            .env_clear()
            .env("LANG", "C")
            .current_dir("/")
            .process_group(0)
            .kill_on_drop(true);
        for key in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        yonik_nsfs::local_parent_death::install_kill_on_parent_death(command.as_std_mut());
        command
    }
}

#[cfg(test)]
mod budget_tests {
    use super::{BinarySnapshot, Engine, File, Hasher, HostError, Sha256};
    use crate::helper::memory::ByteBudget;
    use rustix::fs::{MemfdFlags, Mode, fchmod, memfd_create};
    use sha2::Digest;
    use std::io::{Seek, SeekFrom, Write};

    const ELF: &[u8] = b"\x7fELFbudget fixture: never execute";

    fn source() -> File {
        let mut file =
            File::from(memfd_create("yonik-budget-source", MemfdFlags::CLOEXEC).unwrap());
        file.write_all(ELF).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        fchmod(&file, Mode::RUSR | Mode::XUSR).unwrap();
        file
    }

    #[test]
    fn source_growth_since_reservation_cannot_bypass_budget() {
        let budget = ByteBudget::new(4);
        let lease = budget.reserve(4).unwrap();
        assert_eq!(
            BinarySnapshot::load_budgeted(
                source(),
                Sha256(Hasher::digest(ELF).into()),
                Engine::Xray,
                lease
            )
            .err(),
            Some(HostError::ResourceLimit)
        );
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn successful_copy_shrinks_reservation_to_actual_sealed_size() {
        let budget = ByteBudget::new(ELF.len() * 2);
        let lease = budget.reserve(ELF.len() * 2).unwrap();
        let snapshot = BinarySnapshot::load_budgeted(
            source(),
            Sha256(Hasher::digest(ELF).into()),
            Engine::Xray,
            lease,
        )
        .unwrap();
        assert_eq!(budget.used(), ELF.len());
        assert!(snapshot.file.set_len(ELF.len() as u64 + 1).is_err());
        drop(snapshot);
        assert_eq!(budget.used(), 0);
    }
}
