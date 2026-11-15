//! Xray assets исключительно на unit-private bounded tmpfs. Имена не поступают из IPC.
use super::{ResourceSession, WorkerError, WorkerMode, native_resources::OwnedResource};
use crate::resource_fd_receiver::Reservation;
use rustix::fs::{self, AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt},
    },
};
const FLAGS: OFlags = OFlags::CLOEXEC
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
fn io_error(_: impl std::fmt::Debug) -> WorkerError {
    WorkerError::Io
}
fn mount_id(file: &File) -> Result<u64, WorkerError> {
    let mut text = String::new();
    File::open(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        .map_err(io_error)?
        .take(4097)
        .read_to_string(&mut text)
        .map_err(io_error)?;
    if text.len() > 4096 {
        return Err(WorkerError::Protocol);
    }
    text.lines()
        .find_map(|l| {
            l.strip_prefix("mnt_id:")
                .and_then(|s| s.trim().parse().ok())
        })
        .filter(|n| *n != 0)
        .ok_or(WorkerError::Protocol)
}
pub(super) struct ShmProof {
    base: File,
    pub(super) mount: u64,
    pub(super) dev: u64,
    pub(super) ino: u64,
    cgroup: String,
}
pub(super) fn check_base(mode: WorkerMode) -> Result<ShmProof, WorkerError> {
    let expected = if mode == WorkerMode::Check {
        "0::/system.slice/yonik-worker-check.service"
    } else {
        "0::/system.slice/yonik-worker.service"
    };
    check_base_cgroup(expected)
}
fn check_base_cgroup(expected: &str) -> Result<ShmProof, WorkerError> {
    let base = File::from(
        fs::open(
            "/dev/shm",
            FLAGS | OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map_err(io_error)?,
    );
    let stat = fs::fstatfs(&base).map_err(io_error)?;
    // TMPFS_MAGIC, ST_RDONLY/NOSUID/NODEV/NOEXEC — Linux statfs ABI.
    if stat.f_type as u64 != 0x0102_1994
        || stat.f_flags as u64 & 15 != 14
        || (stat.f_blocks as u64).checked_mul(stat.f_bsize as u64) != Some(64 * 1024 * 1024)
        || stat.f_files as u64 != 128
    {
        return Err(WorkerError::Protocol);
    }
    let metadata = base.metadata().map_err(io_error)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o1777 {
        return Err(WorkerError::Protocol);
    }
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").map_err(io_error)?;
    if cgroup.len() > 4096 || cgroup.trim() != expected {
        return Err(WorkerError::Protocol);
    }
    Ok(ShmProof {
        mount: mount_id(&base)?,
        dev: metadata.dev(),
        ino: metadata.ino(),
        base,
        cgroup,
    })
}
struct Entry {
    name: String,
    dev: u64,
    ino: u64,
    bytes: u64,
    digest: [u8; 32],
}
pub(super) struct Assets {
    base: File,
    root: File,
    name: String,
    path: String,
    dev: u64,
    ino: u64,
    mount: u64,
    entries: Vec<Entry>,
    reservation: Option<Reservation>,
    issued: bool,
    cleaned: bool,
}
struct AssetInput<'a> {
    file: &'a File,
    name: String,
    bytes: u64,
    digest: [u8; 32],
}
impl Assets {
    pub(super) fn root_fd(&self) -> &File {
        &self.root
    }
    pub(super) fn create_profile(
        resources: &[super::native_resources::NativeAsset],
        session: ResourceSession,
        mode: WorkerMode,
    ) -> Result<Self, WorkerError> {
        super::native_resources::preflight_native(resources.iter().map(|a| a.descriptor))?;
        for resource in resources {
            super::native_resources::validate_native(&resource.file, resource.descriptor)?;
        }
        let proof = check_base(mode)?;
        let inputs = resources
            .iter()
            .map(|a| AssetInput {
                file: &a.file,
                name: a.descriptor.name(),
                bytes: a.descriptor.bytes,
                digest: a.descriptor.digest,
            })
            .collect::<Vec<_>>();
        Self::create_inputs(&inputs, session, mode, proof)
    }
    pub(super) fn create(
        resources: &[OwnedResource],
        session: ResourceSession,
        mode: WorkerMode,
    ) -> Result<Self, WorkerError> {
        if resources.is_empty() || resources.len() > 16 {
            return Err(WorkerError::Protocol);
        }
        let proof = check_base(mode)?;
        Self::create_with_proof(resources, session, mode, proof)
    }
    fn create_with_proof(
        resources: &[OwnedResource],
        session: ResourceSession,
        mode: WorkerMode,
        proof: ShmProof,
    ) -> Result<Self, WorkerError> {
        for resource in resources {
            super::native_resources::validate(&resource.file, &resource.reference)?;
        }
        let inputs = resources
            .iter()
            .map(|r| AssetInput {
                file: &r.file,
                name: format!("{}.dat", r.reference.tag()),
                bytes: r.reference.bytes,
                digest: r.reference.digest,
            })
            .collect::<Vec<_>>();
        Self::create_inputs(&inputs, session, mode, proof)
    }
    fn create_inputs(
        resources: &[AssetInput<'_>],
        session: ResourceSession,
        mode: WorkerMode,
        proof: ShmProof,
    ) -> Result<Self, WorkerError> {
        if resources.len() > 16 {
            return Err(WorkerError::Limit);
        }
        let mut bytes = 8192u64;
        for resource in resources {
            bytes = bytes
                .checked_add(resource.bytes)
                .ok_or(WorkerError::Limit)?;
        }
        if bytes > 64 * 1024 * 1024 {
            return Err(WorkerError::Limit);
        }
        let reservation = Reservation::acquire(bytes).map_err(|_| WorkerError::Limit)?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(io_error)?;
        use std::fmt::Write as FmtWrite;
        let mut encoded_nonce = String::with_capacity(32);
        for byte in nonce {
            write!(&mut encoded_nonce, "{byte:02x}").map_err(io_error)?;
        }
        let nonce = encoded_nonce;
        let role = if mode == WorkerMode::Check {
            "check"
        } else {
            "run"
        };
        let name = format!("yonik-xray-{role}-{:016x}-{nonce}", session.session);
        fs::mkdirat(&proof.base, &name, Mode::RWXU).map_err(io_error)?;
        let root = match fs::openat(
            &proof.base,
            &name,
            FLAGS | OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        ) {
            Ok(root) => File::from(root),
            Err(_) => {
                std::mem::forget(reservation);
                return Err(WorkerError::Io);
            }
        };
        let metadata = match root.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                std::mem::forget(reservation);
                return Err(WorkerError::Io);
            }
        };
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.dev() != proof.dev
            || mount_id(&root).ok() != Some(proof.mount)
        {
            std::mem::forget(reservation);
            return Err(WorkerError::Protocol);
        }
        let mut assets = Self {
            path: format!("/dev/shm/{name}"),
            name,
            dev: metadata.dev(),
            ino: metadata.ino(),
            mount: proof.mount,
            base: proof.base,
            root,
            entries: Vec::new(),
            reservation: Some(reservation),
            issued: false,
            cleaned: false,
        };
        let started = std::time::Instant::now();
        for resource in resources {
            let name = resource.name.clone();
            let mut file = File::from(
                fs::openat(
                    &assets.root,
                    &name,
                    FLAGS | OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(io_error)?,
            );
            let metadata = file.metadata().map_err(io_error)?;
            // Записать ownership сразу после EXCL: ошибки копирования тоже имеют cleanup ledger.
            assets.entries.push(Entry {
                name,
                dev: metadata.dev(),
                ino: metadata.ino(),
                bytes: resource.bytes,
                digest: resource.digest,
            });
            let mut buffer = [0u8; 8192];
            let mut offset = 0;
            let mut hash = Sha256::new();
            while offset < resource.bytes {
                if started.elapsed() > super::TIMEOUT {
                    return Err(WorkerError::Timeout);
                }
                let length = (resource.bytes - offset).min(buffer.len() as u64) as usize;
                let n = resource
                    .file
                    .read_at(&mut buffer[..length], offset)
                    .map_err(io_error)?;
                if n == 0 {
                    return Err(WorkerError::Protocol);
                }
                file.write_all(&buffer[..n]).map_err(io_error)?;
                hash.update(&buffer[..n]);
                offset += n as u64;
            }
            if hash.finalize().as_slice() != resource.digest
                || file.metadata().map_err(io_error)?.len() != resource.bytes
            {
                return Err(WorkerError::Protocol);
            }
            file.sync_all().map_err(io_error)?;
            let mut target = Sha256::new();
            offset = 0;
            while offset < resource.bytes {
                if started.elapsed() > super::TIMEOUT {
                    return Err(WorkerError::Timeout);
                }
                let length = (resource.bytes - offset).min(buffer.len() as u64) as usize;
                let n = file
                    .read_at(&mut buffer[..length], offset)
                    .map_err(io_error)?;
                if n == 0 {
                    return Err(WorkerError::Protocol);
                }
                target.update(&buffer[..n]);
                offset += n as u64;
            }
            if target.finalize().as_slice() != resource.digest {
                return Err(WorkerError::Protocol);
            }
            fs::fchmod(&file, Mode::RUSR).map_err(io_error)?;
            // RDWR fd больше не удерживается и не наследуется native child.
        }
        let entries=assets.entries.iter().map(|e|serde_json::json!({"name":e.name,"dev":e.dev,"ino":e.ino,"bytes":e.bytes,"digest":e.digest})).collect::<Vec<_>>();
        let journal=serde_json::to_vec(&serde_json::json!({"version":1,"session":session.session,"generation":session.generation,"role":role,"nonce":nonce,"cgroup":proof.cgroup,"root_dev":assets.dev,"root_ino":assets.ino,"mount":assets.mount,"entries":entries})).map_err(io_error)?;
        if journal.len() > 8192 {
            return Err(WorkerError::Limit);
        }
        let mut ledger = File::from(
            fs::openat(
                &assets.root,
                ".custody",
                FLAGS | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(io_error)?,
        );
        let metadata = ledger.metadata().map_err(io_error)?;
        assets.entries.push(Entry {
            name: ".custody".into(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            bytes: journal.len() as u64,
            digest: Sha256::digest(&journal).into(),
        });
        ledger.write_all(&journal).map_err(io_error)?;
        ledger.sync_all().map_err(io_error)?;
        fs::fchmod(&ledger, Mode::RUSR).map_err(io_error)?;
        assets.root.sync_all().map_err(io_error)?;
        Ok(assets)
    }
    pub(super) fn path(&self) -> &str {
        &self.path
    }
    pub(super) fn issued(&mut self) {
        self.issued = true;
    }
    pub(super) fn cleanup_after_reap(&mut self) -> Result<(), WorkerError> {
        // Reap одного процесса не доказывает отсутствие потомков с открытым asset.
        if self.issued {
            return Err(WorkerError::Protocol);
        }
        self.cleanup()
    }
    pub(super) fn cleanup_after_failed_exec(&mut self) -> Result<(), WorkerError> {
        // Только exec текущего worker вернулся ошибкой: новый consumer не возник.
        self.issued = false;
        self.cleanup()
    }
    fn cleanup(&mut self) -> Result<(), WorkerError> {
        let metadata = self.root.metadata().map_err(io_error)?;
        let named =
            fs::statat(&self.base, &self.name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
        if metadata.dev() != self.dev
            || metadata.ino() != self.ino
            || named.st_dev != self.dev
            || named.st_ino != self.ino
            || mount_id(&self.root)? != self.mount
        {
            return Err(WorkerError::Protocol);
        }
        // Сначала проверяем весь ledger; mismatch не удаляет даже корректные entries.
        for entry in &self.entries {
            let file = File::from(
                fs::openat(
                    &self.root,
                    &entry.name,
                    FLAGS | OFlags::RDONLY,
                    Mode::empty(),
                )
                .map_err(io_error)?,
            );
            let metadata = file.metadata().map_err(io_error)?;
            if !metadata.is_file()
                || metadata.dev() != entry.dev
                || metadata.ino() != entry.ino
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.nlink() != 1
                || metadata.len() != entry.bytes
            {
                return Err(WorkerError::Protocol);
            }
            let mut hash = Sha256::new();
            let mut offset = 0;
            let mut buffer = [0u8; 8192];
            while offset < entry.bytes {
                let length = (entry.bytes - offset).min(buffer.len() as u64) as usize;
                let count = file
                    .read_at(&mut buffer[..length], offset)
                    .map_err(io_error)?;
                if count == 0 {
                    return Err(WorkerError::Protocol);
                }
                hash.update(&buffer[..count]);
                offset += count as u64;
            }
            let after = file.metadata().map_err(io_error)?;
            if hash.finalize().as_slice() != entry.digest
                || after.len() != metadata.len()
                || after.mtime() != metadata.mtime()
                || after.mtime_nsec() != metadata.mtime_nsec()
                || after.ctime() != metadata.ctime()
                || after.ctime_nsec() != metadata.ctime_nsec()
            {
                return Err(WorkerError::Protocol);
            }
        }
        while let Some(entry) = self.entries.last() {
            let named =
                fs::statat(&self.root, &entry.name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
            if named.st_dev != entry.dev || named.st_ino != entry.ino {
                return Err(WorkerError::Protocol);
            }
            fs::unlinkat(&self.root, &entry.name, AtFlags::empty()).map_err(io_error)?;
            self.entries.pop();
        }
        fs::unlinkat(&self.base, &self.name, AtFlags::REMOVEDIR).map_err(io_error)?;
        self.cleaned = true;
        self.reservation = None;
        Ok(())
    }
}
impl Drop for Assets {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        if self.cleanup_after_reap().is_ok() {
            return;
        }
        // Неизвестный child/cgroup или foreign entry: только private namespace
        // lifetime cleanup у PID1; process budget остаётся в bounded quarantine.
        if let Some(reservation) = self.reservation.take() {
            std::mem::forget(reservation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::check_base;
    use crate::worker::WorkerMode;
    #[test]
    fn shared_host_shm_is_not_private_unit_evidence() {
        // Обычный cargo test не находится в controlled worker cgroup.
        assert!(check_base(WorkerMode::Check).is_err());
        assert!(check_base(WorkerMode::Run).is_err());
    }
}

#[cfg(test)]
mod actual_guard_tests {
    use super::{Assets, File, Mode, OFlags, ResourceSession, WorkerMode, check_base_cgroup, fs};
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
    };
    #[test]
    #[ignore = "Только private bounded tmpfs controlled fixture unit в disposable VM"]
    fn actual_owned_cleanup_foreign_sentinel_and_budget() {
        assert_eq!(
            std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
                .unwrap()
                .trim(),
            "QEMU"
        );
        let expected = "0::/system.slice/yonik-assets-fixture.service";
        let proof = check_base_cgroup(expected).unwrap();
        let bytes = b"fixture-native-artifact";
        let mut source = File::from(
            fs::memfd_create(
                "asset-fixture",
                fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
            )
            .unwrap(),
        );
        source.write_all(bytes).unwrap();
        fs::fcntl_add_seals(
            &source,
            fs::SealFlags::SEAL
                | fs::SealFlags::WRITE
                | fs::SealFlags::SHRINK
                | fs::SealFlags::GROW,
        )
        .unwrap();
        let source = File::open(format!("/proc/self/fd/{}", source.as_raw_fd())).unwrap();
        let reference = yonik_engine::resource_bundle::ExternalRef {
            engine: yonik_engine::Engine::Xray,
            digest: Sha256::digest(bytes).into(),
            bytes: bytes.len() as u64,
            records: 1,
            kind: yonik_engine::resource_bundle::ResourceKind::Cidrs,
            format_version: 1,
        };
        let owned =
            super::super::native_resources::copy_owned(&source, &reference, &|| false).unwrap();
        let baseline = crate::resource_fd_receiver::physical_reserved_bytes();
        let mut assets = Assets::create_with_proof(
            std::slice::from_ref(&owned),
            ResourceSession::fresh().unwrap(),
            WorkerMode::Check,
            proof,
        )
        .unwrap();
        let original = assets.path.clone();
        // Даже 0400 не делает файл immutable для его владельца.
        let artifact = std::path::Path::new(&original).join(&assets.entries[0].name);
        let original_inode = std::fs::metadata(&artifact).unwrap().ino();
        std::fs::set_permissions(
            &artifact,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let mut altered = bytes.to_vec();
        altered[0] ^= 1;
        std::fs::write(&artifact, &altered).unwrap();
        assert_eq!(std::fs::metadata(&artifact).unwrap().ino(), original_inode);
        assert!(assets.cleanup_after_reap().is_err());
        assert!(assets.reservation.is_some());
        assert!(std::path::Path::new(&original).join(".custody").exists());
        std::fs::write(&artifact, bytes).unwrap();
        std::fs::set_permissions(
            &artifact,
            std::os::unix::fs::PermissionsExt::from_mode(0o400),
        )
        .unwrap();
        super::assert_reaped_parent_retains_descendant(&mut assets, &artifact);
        // Только fixture знает завершение собственного единственного consumer.
        assets.issued = false;
        let sentinel = File::from(
            fs::openat(
                &assets.root,
                "foreign-sentinel",
                super::FLAGS | OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap(),
        );
        let inode = fs::fstat(&sentinel).unwrap().st_ino;
        assert!(assets.cleanup_after_reap().is_err());
        let retained = fs::statat(
            &assets.root,
            "foreign-sentinel",
            fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        assert_eq!(retained.st_ino, inode);
        assert!(std::path::Path::new(&original).exists());
        // Сам fixture удаляет только свой отдельный sentinel после проверки guard.
        fs::unlinkat(&assets.root, "foreign-sentinel", fs::AtFlags::empty()).unwrap();
        assets.cleanup_after_reap().unwrap();
        assert!(!std::path::Path::new(&original).exists());
        assert_eq!(
            crate::resource_fd_receiver::physical_reserved_bytes(),
            baseline
        );
        let guard =
            crate::resource_fd_receiver::Reservation::acquire(64 * 1024 * 1024 - baseline).unwrap();
        let proof = check_base_cgroup(expected).unwrap();
        let before = std::fs::read_dir("/dev/shm").unwrap().count();
        assert!(
            Assets::create_with_proof(
                std::slice::from_ref(&owned),
                ResourceSession::fresh().unwrap(),
                WorkerMode::Check,
                proof
            )
            .is_err()
        );
        assert_eq!(std::fs::read_dir("/dev/shm").unwrap().count(), before);
        drop(guard);
        eprintln!(
            "private_tmpfs=true owned_cleanup=true foreign_sentinel_preserved=true budget_refused_before_mkdir=true same_inode_rewrite_quarantined=true direct_reap_descendant_quarantined=true"
        );
    }
}

#[cfg(test)]
mod cleanup_regressions {
    use super::*;
    use std::path::PathBuf;

    struct Fixture {
        assets: Assets,
        directory: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0u8; 16];
            getrandom::getrandom(&mut nonce).unwrap();
            let directory = std::env::temp_dir().join(format!(
                "yonik-assets-regression-{}-{:x}",
                std::process::id(),
                u128::from_ne_bytes(nonce)
            ));
            std::fs::create_dir(&directory).unwrap();
            let path = directory.join("owned");
            std::fs::create_dir(&path).unwrap();
            let body = b"verified-native";
            std::fs::write(path.join("artifact"), body).unwrap();
            let base = File::open(&directory).unwrap();
            let root = File::open(&path).unwrap();
            let metadata = root.metadata().unwrap();
            let entry = std::fs::metadata(path.join("artifact")).unwrap();
            Self {
                assets: Assets {
                    base,
                    mount: mount_id(&root).unwrap(),
                    root,
                    name: "owned".into(),
                    path: path.to_str().unwrap().into(),
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                    entries: vec![Entry {
                        name: "artifact".into(),
                        dev: entry.dev(),
                        ino: entry.ino(),
                        bytes: body.len() as u64,
                        digest: Sha256::digest(body).into(),
                    }],
                    reservation: Some(Reservation::acquire(128).unwrap()),
                    issued: false,
                    cleaned: false,
                },
                directory,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Fixture не запускал native consumers; возвращает только свои данные.
            self.assets.issued = false;
            if !self.assets.cleaned {
                let _ = std::fs::write(self.directory.join("owned/artifact"), b"verified-native");
                let _ = self.assets.cleanup();
            }
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
    #[test]
    fn direct_reap_does_not_authorize_issued_asset_cleanup() {
        let mut fixture = Fixture::new();
        let artifact = fixture.directory.join("owned/artifact");
        super::assert_reaped_parent_retains_descendant(&mut fixture.assets, &artifact);
        assert!(fixture.assets.cleanup_after_reap().is_err());
        assert!(fixture.assets.issued);
        assert!(fixture.assets.reservation.is_some());
        assert!(fixture.directory.join("owned/artifact").exists());
    }
    #[test]
    fn same_inode_size_change_retains_custody() {
        let mut fixture = Fixture::new();
        std::fs::write(fixture.directory.join("owned/artifact"), b"changed").unwrap();
        assert!(fixture.assets.cleanup_after_reap().is_err());
        assert!(fixture.assets.reservation.is_some());
        assert!(fixture.directory.join("owned/artifact").exists());
    }
    #[test]
    fn same_inode_same_size_rewrite_retains_custody() {
        let mut fixture = Fixture::new();
        std::fs::write(fixture.directory.join("owned/artifact"), b"tampered-native").unwrap();
        assert!(fixture.assets.cleanup_after_reap().is_err());
        assert!(fixture.assets.reservation.is_some());
        assert!(fixture.directory.join("owned/artifact").exists());
    }
}

#[cfg(test)]
fn assert_reaped_parent_retains_descendant(assets: &mut Assets, artifact: &std::path::Path) {
    let output = std::process::Command::new("/bin/sh")
        .args([
            "-c",
            "exec 9<\"$1\"; sleep 1 >/dev/null 2>&1 & echo $!",
            "fixture",
        ])
        .arg(artifact)
        .output()
        .unwrap();
    assert!(output.status.success()); // Прямой parent уже reap, descendant ещё держит fd9.
    let pid: u32 = String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let held = format!("/proc/{pid}/fd/9");
    assert_eq!(
        std::fs::metadata(&held).unwrap().ino(),
        std::fs::metadata(artifact).unwrap().ino()
    );
    assets.issued();
    assert!(assets.cleanup_after_reap().is_err());
    assert!(assets.reservation.is_some());
    assert!(artifact.exists());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::path::Path::new(&held).exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
