//! Закрытая проверка установленного producer; сама по себе не выдаёт admission.
use super::systemd_worker::{
    BootstrapUnitObservation, FILE_FLAGS, SystemWorkerSupervisor, WorkerSupervisorError as Error,
    child, root, trusted, verify_installed,
};
use crate::Cancellation;
use rustix::fs::{Mode, openat};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt};
use tokio::time::Instant;

type Result<T> = std::result::Result<T, Error>;
const MAX_METADATA: u64 = 4096;
const MAX_ELF: u64 = 128 * 1024 * 1024;
const MAX_SOURCE: u64 = 512 * 1024 * 1024;
// Identity политики отдельно от хеша image, который эту политику исполняет.
const POLICY: &str = "yonik-own-namespace-fixed16-v1";
const ABI: &str = "linux-native-abi260-ynkch004-ynkns004-v1";

// derive отвергает duplicate fields, deny_unknown_fields закрывает расширения.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deployment {
    schema: u32,
    worker_sha256: [u8; 32],
    source_archive_sha256: [u8; 32],
    policy_id: String,
    policy_sha256: [u8; 32],
    kernel_release: String,
    kernel_build_id: [u8; 20],
    kernel_machine: String,
    kernel_abi: String,
}

#[derive(PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn stamp(file: &File) -> Result<FileStamp> {
    let m = file.metadata().map_err(|_| Error::Unavailable)?;
    Ok(FileStamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    })
}
fn immutable(file: &File) -> Result<()> {
    trusted(file, false)?;
    // «Immutable» здесь — граница root/package TCB, не FS_IMMUTABLE_FL.
    if file.metadata().map_err(|_| Error::Unavailable)?.mode() & 0o222 != 0 {
        return Err(Error::Untrusted);
    }
    Ok(())
}
fn fixed_file(directory: &File, name: &str) -> Result<File> {
    let f = File::from(
        openat(directory, name, FILE_FLAGS, Mode::empty()).map_err(|_| Error::Unavailable)?,
    );
    immutable(&f)?;
    Ok(f)
}
fn hash(file: &File, limit: u64, elf: bool) -> Result<[u8; 32]> {
    let before = stamp(file)?;
    if before.len == 0 || before.len > limit {
        return Err(Error::Untrusted);
    }
    let mut reader = file;
    let mut buf = [0u8; 16384];
    let mut digest = Sha256::new();
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(|_| Error::Unavailable)?;
        if n == 0 {
            break;
        }
        if total == 0 && elf && (n < 4 || &buf[..4] != b"\x7fELF") {
            return Err(Error::Untrusted);
        }
        total = total.checked_add(n as u64).ok_or(Error::Untrusted)?;
        if total > limit {
            return Err(Error::Untrusted);
        }
        digest.update(&buf[..n]);
    }
    if total != before.len || stamp(file)? != before {
        return Err(Error::Stale);
    }
    Ok(digest.finalize().into())
}
fn parse(file: &File) -> Result<Deployment> {
    let before = stamp(file)?;
    if before.len == 0 || before.len > MAX_METADATA {
        return Err(Error::Untrusted);
    }
    let mut bytes = Vec::with_capacity(before.len as usize);
    file.take(MAX_METADATA + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() as u64 != before.len || stamp(file)? != before {
        return Err(Error::Stale);
    }
    parse_bytes(&bytes)
}
fn parse_bytes(bytes: &[u8]) -> Result<Deployment> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_METADATA {
        return Err(Error::Untrusted);
    }
    let value: Deployment = serde_json::from_slice(bytes).map_err(|_| Error::Untrusted)?;
    if value.schema != 1
        || value.policy_id != POLICY
        || value.kernel_abi != ABI
        || value.worker_sha256 == [0; 32]
        || value.source_archive_sha256 == [0; 32]
        || value.policy_sha256 == [0; 32]
        || value.kernel_build_id == [0; 20]
        || value.kernel_release.is_empty()
        || value.kernel_release.len() > 128
        || !value
            .kernel_release
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        || value.kernel_machine != std::env::consts::ARCH
    {
        return Err(Error::Untrusted);
    }
    Ok(value)
}

struct InstalledContract {
    _metadata: File,
    _source: File,
    image: File,
    deployment: Deployment,
}
impl InstalledContract {
    fn verify() -> Result<Self> {
        verify_installed()?;
        let directory = child(&child(&child(&root()?, "usr")?, "lib")?, "yonik")?;
        let metadata = fixed_file(&directory, "native-profile-v1.json")?;
        let deployment = parse(&metadata)?;
        let image = fixed_file(&directory, "yonik-worker")?;
        if image.metadata().map_err(|_| Error::Unavailable)?.mode() & 0o111 == 0
            || hash(&image, MAX_ELF, true)? != deployment.worker_sha256
        {
            return Err(Error::Untrusted);
        }
        let source = fixed_file(&directory, "native-source-v1.tar")?;
        if hash(&source, MAX_SOURCE, false)? != deployment.source_archive_sha256 {
            return Err(Error::Untrusted);
        }
        let kernel = child(&child(&root()?, "sys")?, "kernel")?;
        let notes = fixed_file(&kernel, "notes")?;
        let mut data = Vec::new();
        notes
            .take(65537)
            .read_to_end(&mut data)
            .map_err(|_| Error::Unavailable)?;
        if data.len() > 65536 || kernel_build_id(&data)? != deployment.kernel_build_id {
            return Err(Error::Untrusted);
        }
        // Читаем declared kernel/proc TCB, не запускаем feature probes.
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|_| Error::Unavailable)?;
        if release != format!("{}\n", deployment.kernel_release) {
            return Err(Error::Untrusted);
        }
        Ok(Self {
            _metadata: metadata,
            _source: source,
            image,
            deployment,
        })
    }
}
struct ExecutableIdentity {
    _actual: File,
}
impl ExecutableIdentity {
    fn verify(
        observation: &BootstrapUnitObservation,
        installed: &InstalledContract,
    ) -> Result<Self> {
        observation.validate_identity()?;
        // Единственная намеренная proc magic-link: actual exe canonical pidfd/start.
        // Никакой путь из sidecar или caller здесь не используется.
        let actual = File::open(format!("/proc/{}/exe", observation.native_pid()))
            .map_err(|_| Error::Unavailable)?;
        immutable(&actual)?;
        if stamp(&actual)? != stamp(&installed.image)?
            || hash(&actual, MAX_ELF, true)? != installed.deployment.worker_sha256
        {
            return Err(Error::Untrusted);
        }
        observation.validate_identity()?;
        Ok(Self { _actual: actual })
    }
}

/// Move-only owning input будущего coverage verifier. Не UnitProfile/permit.
/// Поля закрыты; нет bytes/FD/bool конструктора, Clone или Serialize.
pub(super) struct VerifiedInstalledProfile {
    observation: BootstrapUnitObservation,
    installed: InstalledContract,
    _executable: ExecutableIdentity,
}
impl VerifiedInstalledProfile {
    pub(super) async fn verify(
        supervisor: &SystemWorkerSupervisor,
        observation: BootstrapUnitObservation,
        cancel: &mut Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        supervisor
            .validate_native_profile_context(&observation, cancel, deadline)
            .await?;
        let installed = InstalledContract::verify()?;
        let executable = ExecutableIdentity::verify(&observation, &installed)?;
        supervisor
            .validate_native_profile_context(&observation, cancel, deadline)
            .await?;
        Ok(Self {
            observation,
            installed,
            _executable: executable,
        })
    }
    /// Consuming recheck после await; старый token при ошибке уничтожается.
    /// Consumers удерживают возвращённый token до consume coverage/owner lease.
    pub(super) async fn revalidate(
        self,
        supervisor: &SystemWorkerSupervisor,
        cancel: &mut Cancellation,
        deadline: Instant,
    ) -> Result<Self> {
        let fresh = Self::verify(supervisor, self.observation, cancel, deadline).await?;
        if fresh.installed.deployment.worker_sha256 != self.installed.deployment.worker_sha256
            || fresh.installed.deployment.source_archive_sha256
                != self.installed.deployment.source_archive_sha256
            || fresh.installed.deployment.policy_sha256 != self.installed.deployment.policy_sha256
        {
            return Err(Error::Stale);
        }
        Ok(fresh)
    }
    pub(super) fn policy_digest(&self) -> [u8; 32] {
        self.installed.deployment.policy_sha256
    }
    pub(super) fn observation(&self) -> &BootstrapUnitObservation {
        &self.observation
    }
}

/// Linux экспортирует native-endian ELF notes; принимается один полный GNU build-id.
fn kernel_build_id(notes: &[u8]) -> Result<[u8; 20]> {
    if notes.len() > 65536 {
        return Err(Error::Untrusted);
    }
    let mut offset = 0usize;
    let mut found = None;
    while offset < notes.len() {
        let header = notes
            .get(offset..offset.checked_add(12).ok_or(Error::Untrusted)?)
            .ok_or(Error::Untrusted)?;
        let word = |n| u32::from_ne_bytes(header[n..n + 4].try_into().unwrap_or([0; 4])) as usize;
        let (namesz, descsz, kind) = (word(0), word(4), word(8));
        offset += 12;
        let name_end = offset.checked_add(namesz).ok_or(Error::Untrusted)?;
        let name = notes.get(offset..name_end).ok_or(Error::Untrusted)?;
        let desc_start = name_end.checked_add(3).ok_or(Error::Untrusted)? & !3;
        let desc_end = desc_start.checked_add(descsz).ok_or(Error::Untrusted)?;
        let desc = notes.get(desc_start..desc_end).ok_or(Error::Untrusted)?;
        if kind == 3 && name == b"GNU\0" {
            if found.is_some() || descsz != 20 {
                return Err(Error::Untrusted);
            }
            let id: [u8; 20] = desc.try_into().map_err(|_| Error::Untrusted)?;
            if id == [0; 20] {
                return Err(Error::Untrusted);
            }
            found = Some(id);
        }
        offset = desc_end.checked_add(3).ok_or(Error::Untrusted)? & !3;
        if offset > notes.len() {
            return Err(Error::Untrusted);
        }
    }
    found.ok_or(Error::Unavailable)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn metadata() -> serde_json::Value {
        serde_json::json!({ "schema":1, "worker_sha256":vec![1u8;32],
            "source_archive_sha256":vec![2u8;32],"policy_id":POLICY,
            "policy_sha256":vec![3u8;32],"kernel_release":"6.18.1-test",
            "kernel_build_id":vec![4u8;20],"kernel_machine":std::env::consts::ARCH,"kernel_abi":ABI })
    }
    #[test]
    fn pure_deployment_metadata_accepts_complete_contract_data() {
        assert!(parse_bytes(&serde_json::to_vec(&metadata()).unwrap()).is_ok());
    }
    #[test]
    fn pure_deployment_metadata_rejects_unknown_duplicate_missing_and_zero_digest() {
        let mut value = metadata();
        value["enabled"] = true.into();
        assert!(parse_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        let encoded = serde_json::to_string(&metadata()).unwrap();
        let duplicate = format!("{{\"schema\":1,{}", &encoded[1..]);
        assert!(parse_bytes(duplicate.as_bytes()).is_err());
        for field in ["schema", "worker_sha256", "kernel_release", "kernel_abi"] {
            let mut value = metadata();
            value.as_object_mut().unwrap().remove(field);
            assert!(parse_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for field in ["worker_sha256", "source_archive_sha256", "policy_sha256"] {
            let mut value = metadata();
            value[field] = serde_json::json!([0; 32].to_vec());
            assert!(parse_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    #[test]
    fn pure_deployment_metadata_rejects_bounds_path_and_abi_substitution() {
        assert!(parse_bytes(&vec![b' '; 4097]).is_err());
        for (field, bad) in [
            ("kernel_release", "../../release"),
            ("kernel_machine", "unknown"),
            ("kernel_abi", "v3"),
            ("policy_id", "unit"),
        ] {
            let mut value = metadata();
            value[field] = bad.into();
            assert!(parse_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
}

#[cfg(test)]
mod kernel_note_tests {
    use super::*;
    fn note() -> Vec<u8> {
        let mut data = Vec::new();
        for value in [4u32, 20, 3] {
            data.extend(value.to_ne_bytes());
        }
        data.extend(b"GNU\0");
        data.extend([1u8; 20]);
        data
    }
    #[test]
    fn pure_kernel_build_id_accepts_exact_note() {
        assert_eq!(kernel_build_id(&note()).unwrap(), [1; 20]);
    }
    #[test]
    fn pure_kernel_build_id_rejects_truncation_duplicate_zero_and_oversize() {
        let data = note();
        for end in 0..data.len() {
            assert!(kernel_build_id(&data[..end]).is_err());
        }
        let mut duplicate = data.clone();
        duplicate.extend(&data);
        assert!(kernel_build_id(&duplicate).is_err());
        let mut zero = data;
        zero[16..].fill(0);
        assert!(kernel_build_id(&zero).is_err());
        assert!(kernel_build_id(&vec![0; 65537]).is_err());
    }
}
