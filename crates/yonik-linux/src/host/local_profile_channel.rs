//! Local custody принадлежит normal Host и живёт до reap его exact child.
use super::{BinarySnapshot, Cancellation, HostError};
use crate::helper::{native_profile_channel as issuer, profile_intent::FullProfileSources};
use crate::profile_channel::{Binding, LaunchRecord, Mode, OwnedCapsule};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Write,
    os::{
        fd::OwnedFd,
        unix::fs::{DirBuilderExt, FileExt, MetadataExt, PermissionsExt},
    },
    path::PathBuf,
    sync::Arc,
};
use yonik_engine::native_profile::{OwnedRuntimePlan, ProfileIntent};

fn rejected<T>(_: T) -> HostError {
    HostError::ConfigRejected
}
/// Source-bound normal Host factory. Не System namespace/owner proof.
pub(crate) fn create_udp_relay() -> Result<(OwnedFd, OwnedFd), HostError> {
    let before = File::open("/proc/thread-self/ns/net").map_err(rejected)?;
    if yonik_nsfs::namespace_type(&before).map_err(rejected)? != yonik_nsfs::NamespaceType::Net {
        return Err(HostError::Unsupported);
    }
    let identity = before.metadata().map_err(rejected)?;
    let fd = rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        Some(rustix::net::ipproto::UDP),
    )
    .map_err(rejected)?;
    rustix::net::bind(
        &fd,
        &std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0),
    )
    .map_err(rejected)?;
    yonik_nsfs::socket_namespace::prepare_profile_udp(&fd).map_err(rejected)?;
    let after = File::open("/proc/thread-self/ns/net")
        .map_err(rejected)?
        .metadata()
        .map_err(rejected)?;
    if (identity.dev(), identity.ino()) != (after.dev(), after.ino()) {
        return Err(HostError::Unsupported);
    }
    Ok((fd, before.into()))
}
pub(crate) struct Prepared {
    _consumer: issuer::ConsumerReady,
    intent: ProfileIntent,
    sources: FullProfileSources,
    pub capsule: Arc<OwnedCapsule>,
    root: File,
    path: PathBuf,
    files: Vec<(String, File, [u8; 32], u64)>,
    _storage: crate::resource_fd_receiver::Reservation,
}
impl Prepared {
    pub(crate) fn resolver_snapshot(
        &self,
    ) -> Option<&crate::helper::profile_intent::PinnedResolverSnapshot> {
        self.sources.snapshot()
    }
    pub(crate) fn prepare(
        binary: &BinarySnapshot,
        intent: ProfileIntent,
        plan: OwnedRuntimePlan,
        cancel: &Cancellation,
    ) -> Result<(Arc<Self>, yonik_engine::CompiledConfig), HostError> {
        Self::prepare_with_sources(binary, intent, plan, cancel, |intent, cancel| {
            FullProfileSources::capture(intent, cancel).map_err(rejected)
        })
    }
    fn prepare_with_sources(
        binary: &BinarySnapshot,
        intent: ProfileIntent,
        plan: OwnedRuntimePlan,
        cancel: &Cancellation,
        capture: impl FnOnce(&ProfileIntent, &Cancellation) -> Result<FullProfileSources, HostError>,
    ) -> Result<(Arc<Self>, yonik_engine::CompiledConfig), HostError> {
        cancel.check().map_err(|_| HostError::Cancelled)?;
        // Exact selected image/scope proof до capture/staging/config-check.
        let consumer = issuer::require_consumer(&intent, Mode::Local, binary)
            .map_err(|_| HostError::Unsupported)?;
        // Текущий builder capsule связывает Local aliases только с SOCKS.
        // Двойной план требует отдельной TCP-only строки HTTP в таблице ingress.
        if plan.local_http_port().is_some() {
            return Err(HostError::Unsupported);
        }
        if plan.is_system()
            || rustix::process::geteuid().as_raw() == 0
            || rustix::process::geteuid() != rustix::process::getuid()
        {
            return Err(HostError::ConfigRejected);
        }
        cancel.check().map_err(|_| HostError::Cancelled)?;
        let sources = capture(&intent, cancel)?;
        issuer::validate_consumer_sources(&intent, &sources, cancel)
            .map_err(|_| HostError::Unsupported)?;
        let plan = sources.bind(&intent, plan, cancel).map_err(rejected)?;
        intent.validate_ingress_mapping(&plan).map_err(rejected)?;
        let config = intent
            .compile_local(&plan)
            .map_err(rejected)?
            .with_local_runtime_logging();
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        config.write_sensitive(&mut *bytes).map_err(rejected)?;
        let digest = Sha256::digest(&bytes).into();
        let capsule = Arc::new(
            OwnedCapsule::build(
                &intent,
                &plan,
                sources.snapshot().map(|s| s.reference()),
                digest,
                1,
                1,
            )
            .map_err(rejected)?,
        );
        let count = sources.assets().count() + usize::from(sources.snapshot().is_some());
        let total = sources
            .assets()
            .try_fold(8192u64, |n, (_, r)| n.checked_add(r.bytes))
            .and_then(|n| {
                n.checked_add(
                    sources
                        .snapshot()
                        .map_or(0, |s| s.asset_bytes().len() as u64),
                )
            })
            .filter(|n| *n <= 64 * 1024 * 1024)
            .ok_or(HostError::ResourceLimit)?;
        if count > 16 {
            return Err(HostError::ResourceLimit);
        }
        let storage = crate::resource_fd_receiver::Reservation::acquire(total).map_err(rejected)?;
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(rejected)?;
        let path = PathBuf::from(format!("/tmp/yonik-profile-{}", hex(&nonce)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(rejected)?;
        let root = File::from(
            rustix::fs::open(
                &path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(rejected)?,
        );
        let mut prepared = Self {
            _consumer: consumer,
            intent,
            sources,
            capsule,
            root,
            path,
            files: Vec::with_capacity(count),
            _storage: storage,
        };
        for (source, reference) in prepared.sources.assets() {
            let name = format!("r-{}.dat", hex(&reference.digest));
            let file = stage(
                &prepared.root,
                &name,
                Some(source),
                &[],
                reference.bytes,
                reference.digest,
                cancel,
            )?;
            prepared
                .files
                .push((name, file, reference.digest, reference.bytes));
        }
        if let Some(snapshot) = prepared.sources.snapshot() {
            let reference = snapshot.reference();
            let name = format!("dns-{}.bin", hex(&reference.asset));
            let file = stage(
                &prepared.root,
                &name,
                None,
                snapshot.asset_bytes(),
                u64::from(reference.bytes),
                reference.asset,
                cancel,
            )?;
            prepared
                .files
                .push((name, file, reference.asset, u64::from(reference.bytes)));
        }
        prepared.revalidate(cancel)?;
        Ok((Arc::new(prepared), config))
    }
    pub(crate) fn revalidate(&self, cancel: &Cancellation) -> Result<(), HostError> {
        self.sources
            .revalidate(&self.intent, cancel)
            .map_err(rejected)?;
        let m = self.root.metadata().map_err(rejected)?;
        let p = std::fs::symlink_metadata(&self.path).map_err(rejected)?;
        if !m.is_dir()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o777 != 0o700
            || (m.dev(), m.ino()) != (p.dev(), p.ino())
        {
            return Err(HostError::ConfigRejected);
        }
        for (name, file, digest, length) in &self.files {
            let current = File::from(
                rustix::fs::openat(
                    &self.root,
                    name.as_str(),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(rejected)?,
            );
            let a = file.metadata().map_err(rejected)?;
            let b = current.metadata().map_err(rejected)?;
            if !b.is_file()
                || b.nlink() != 1
                || b.uid() != m.uid()
                || b.mode() & 0o222 != 0
                || b.len() != *length
                || (a.dev(), a.ino()) != (b.dev(), b.ino())
                || hash(&current, *length, cancel)? != *digest
            {
                return Err(HostError::ConfigRejected);
            }
        }
        Ok(())
    }
    pub(crate) fn root_path(&self) -> &std::path::Path {
        &self.path
    }
    pub(crate) fn launch(
        self: &Arc<Self>,
        digest: [u8; 32],
        cancel: &Cancellation,
    ) -> Result<Launch, HostError> {
        self.revalidate(cancel)?;
        let mut nonce = [0; 32];
        let mut session = [0; 16];
        let mut invocation = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(rejected)?;
        getrandom::getrandom(&mut session).map_err(rejected)?;
        getrandom::getrandom(&mut invocation).map_err(rejected)?;
        let capsule = crate::profile_channel::Capsule::decode(self.capsule.bytes(), &digest)
            .map_err(rejected)?;
        if capsule.mode != Mode::Local {
            return Err(HostError::ConfigRejected);
        }
        let pid = std::process::id();
        let record = LaunchRecord {
            mode: Mode::Local,
            nonce,
            binding: Binding {
                digest,
                session,
                invocation,
                generation: 1,
                epoch: 1,
            },
            owner_pid: pid,
            child_pid: 0,
            owner_start: issuer::process_start(pid).map_err(rejected)?,
            child_start: 0,
            manifest: capsule.manifest,
        };
        let (host, worker) = issuer::channel_pair().map_err(rejected)?;
        let mut launch = File::from(
            rustix::fs::memfd_create(
                "yonik-local-profile",
                rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
            )
            .map_err(rejected)?,
        );
        launch
            .write_all(&record.encode().map_err(rejected)?)
            .map_err(rejected)?;
        rustix::fs::fcntl_add_seals(
            &launch,
            rustix::fs::SealFlags::SEAL
                | rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW,
        )
        .map_err(rejected)?;
        let owner = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid as i32).ok_or(HostError::Process)?,
            rustix::process::PidfdFlags::NONBLOCK,
        )
        .map_err(rejected)?;
        Ok(Launch {
            configured: false,
            prepared: Arc::clone(self),
            record,
            host,
            worker,
            launch,
            owner,
        })
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        for (name, _, _, _) in &self.files {
            let _removed =
                rustix::fs::unlinkat(&self.root, name.as_str(), rustix::fs::AtFlags::empty());
        }
        if let (Ok(owned), Ok(current)) =
            (self.root.metadata(), std::fs::symlink_metadata(&self.path))
        {
            if current.is_dir() && (owned.dev(), owned.ino()) == (current.dev(), current.ino()) {
                let _removed = std::fs::remove_dir(&self.path);
            }
        }
    }
}
pub(crate) struct Launch {
    configured: bool,
    prepared: Arc<Prepared>,
    record: LaunchRecord,
    host: OwnedFd,
    worker: OwnedFd,
    launch: File,
    owner: OwnedFd,
}
impl Launch {
    pub(crate) fn configure(
        &mut self,
        mut command: tokio::process::Command,
    ) -> Result<ConfiguredCommand, HostError> {
        claim_configuration(&mut self.configured, command.as_std())?;
        use std::os::fd::AsFd;
        let fds = [
            self.worker.as_fd(),
            self.launch.as_fd(),
            self.owner.as_fd(),
            self.prepared.root.as_fd(),
        ];
        let owned = fds.map(|fd| rustix::io::fcntl_dupfd_cloexec(fd, 3).map_err(rejected));
        let [control, launch, peer, root] = owned;
        let owned = [control?, launch?, peer?, root?];
        command.env_clear().env("LANG", "C");
        yonik_nsfs::local_parent_death::install_local_profile_fds(command.as_std_mut(), owned)
            .map_err(rejected)?;
        Ok(ConfiguredCommand { command })
    }
    pub(crate) fn start(
        self,
        child: &tokio::process::Child,
        binary: &BinarySnapshot,
        config: &[u8],
    ) -> Result<issuer::ProfileRuntime, HostError> {
        let peer = issuer::Peer::local(self.record, child, binary, config).map_err(rejected)?;
        issuer::ProfileRuntime::start_local(self.record, peer, self.prepared, self.host)
            .map_err(rejected)
    }
}
/// После configure raw Command недоступен: нельзя удалить locators и накопить
/// новые hooks другим Launch. Единственная операция потребляет весь Command.
pub(crate) struct ConfiguredCommand {
    command: tokio::process::Command,
}
impl ConfiguredCommand {
    pub(crate) fn spawn(mut self) -> Result<tokio::process::Child, HostError> {
        self.command.spawn().map_err(|_| HostError::Process)
    }
}
fn claim_configuration(
    configured: &mut bool,
    command: &std::process::Command,
) -> Result<(), HostError> {
    let names = yonik_nsfs::local_parent_death::LOCAL_PROFILE_LOCATORS;
    if *configured
        || command
            .get_envs()
            .any(|(name, _)| names.iter().any(|key| name == *key))
    {
        return Err(HostError::State);
    }
    // Даже неудачная настройка одноразовая, включая повтор после env_clear.
    *configured = true;
    Ok(())
}
fn stage(
    root: &File,
    name: &str,
    source: Option<&File>,
    bytes: &[u8],
    length: u64,
    digest: [u8; 32],
    cancel: &Cancellation,
) -> Result<File, HostError> {
    let mut file = File::from(
        rustix::fs::openat(
            root,
            name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(rejected)?,
    );
    let mut cleanup = StageCleanup {
        root,
        name,
        armed: true,
    };
    if let Some(source) = source {
        let mut buffer = [0; 8192];
        let mut offset = 0;
        while offset < length {
            cancel.check()?;
            let n = source
                .read_at(&mut buffer[..(length - offset).min(8192) as usize], offset)
                .map_err(rejected)?;
            if n == 0 {
                return Err(HostError::ConfigRejected);
            }
            file.write_all(&buffer[..n]).map_err(rejected)?;
            offset += n as u64;
        }
    } else {
        file.write_all(bytes).map_err(rejected)?;
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o400))
        .map_err(rejected)?;
    if hash(&file, length, cancel)? != digest {
        return Err(HostError::ConfigRejected);
    }
    let readonly = File::from(
        rustix::fs::openat(
            root,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(rejected)?,
    );
    let before = file.metadata().map_err(rejected)?;
    let after = readonly.metadata().map_err(rejected)?;
    if (before.dev(), before.ino(), before.len()) != (after.dev(), after.ino(), after.len()) {
        return Err(HostError::ConfigRejected);
    }
    cleanup.armed = false;
    Ok(readonly)
}
struct StageCleanup<'a> {
    root: &'a File,
    name: &'a str,
    armed: bool,
}
impl Drop for StageCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _removed = rustix::fs::unlinkat(self.root, self.name, rustix::fs::AtFlags::empty());
        }
    }
}
fn hash(file: &File, length: u64, cancel: &Cancellation) -> Result<[u8; 32], HostError> {
    let mut h = Sha256::new();
    let mut buffer = [0; 8192];
    let mut offset = 0;
    while offset < length {
        cancel.check()?;
        let n = file
            .read_at(&mut buffer[..(length - offset).min(8192) as usize], offset)
            .map_err(rejected)?;
        if n == 0 {
            return Err(HostError::ConfigRejected);
        }
        h.update(&buffer[..n]);
        offset += n as u64;
    }
    Ok(h.finalize().into())
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                char::from(H[(b >> 4) as usize]),
                char::from(H[(b & 15) as usize]),
            ]
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn france_reviewed_image_reaches_actual_prepare_capture_boundary() {
        let report = yonik_import::import_profiles(
            include_bytes!("../../../../tests/fixtures/xray-full-profile-seven.json").to_vec(),
        )
        .unwrap();
        let profile = report
            .entries
            .iter()
            .find_map(|entry| match entry {
                yonik_import::ProfileEntry::Xray(p) if p.name() == "FranceSS" => Some(p),
                _ => None,
            })
            .unwrap();
        let intent = ProfileIntent::from_profile(profile).unwrap();
        let binary = fixture_image();
        let proof = issuer::fake_reviewed_france_image(binary.trusted_hash());
        let binary = binary.with_producer(Some(proof));
        let plan =
            OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
        let (_keep, cancel) = Cancellation::new();
        let mut capture = 0;
        let result = Prepared::prepare_with_sources(&binary, intent, plan, &cancel, |_, _| {
            capture += 1;
            // OS capture/staging отсутствуют: намеренная test leaf boundary.
            Err(HostError::State)
        });
        assert!(matches!(result, Err(HostError::State)));
        assert_eq!(capture, 1);
    }
    #[test]
    fn france_ss_actual_prepare_never_captures_with_tcp_only_bootstrap_capabilities() {
        let report = yonik_import::import_profiles(
            include_bytes!("../../../../tests/fixtures/xray-full-profile-seven.json").to_vec(),
        )
        .unwrap();
        let profile = report
            .entries
            .iter()
            .find_map(|entry| match entry {
                yonik_import::ProfileEntry::Xray(p) if p.name() == "FranceSS" => Some(p),
                _ => None,
            })
            .unwrap();
        let intent = ProfileIntent::from_profile(profile).unwrap();
        let binary = fixture_image();
        let proof = issuer::fake_consumer_image(binary.trusted_hash());
        let binary = binary.with_producer(Some(proof));
        let plan =
            OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
        let (_keep, cancel) = Cancellation::new();
        let mut effects = 0;
        let result = Prepared::prepare_with_sources(&binary, intent, plan, &cancel, |_, _| {
            effects += 1;
            Err(HostError::State)
        });
        assert!(matches!(result, Err(HostError::Unsupported)));
        assert_eq!(effects, 0);
    }
    #[test]
    fn local_configure_is_one_shot_even_after_env_clear_or_failed_setup() {
        let mut command = std::process::Command::new("не-исполняемый-fixture");
        let mut configured = false;
        claim_configuration(&mut configured, &command).unwrap();
        command.env_clear();
        assert_eq!(
            claim_configuration(&mut configured, &command),
            Err(HostError::State)
        );
        let mut fresh = false;
        command.env("YONIK_PROFILE_CONTROL_FD", "20");
        assert_eq!(
            claim_configuration(&mut fresh, &command),
            Err(HostError::State)
        );
        assert!(!fresh);
    }
    #[test]
    fn missing_consumer_denies_before_sources_staging_or_spawn() {
        let binary = fixture_image();
        let intent = ProfileIntent::decode(
            r#"{"version":1,"graph":{"outbounds":[{"tag":"direct","protocol":"freedom"}]}}"#,
        )
        .unwrap();
        let plan =
            OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
        let (_keep, cancel) = Cancellation::new();
        assert!(matches!(
            Prepared::prepare(&binary, intent, plan, &cancel),
            Err(HostError::Unsupported)
        ));
    }
    fn fixture_image() -> BinarySnapshot {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("yonik-readiness-{}", hex(&nonce)));
        let bytes = b"\x7fELFfixture-never-executed";
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let image = BinarySnapshot::load(
            &path,
            super::super::Sha256(Sha256::digest(bytes).into()),
            yonik_engine::Engine::Xray,
        )
        .unwrap();
        std::fs::remove_file(path).unwrap();
        image
    }
    #[test]
    fn local_subset_actual_prepare_checks_selected_image_before_capture() {
        for (capability, matching, cancelled, expected) in [
            (false, true, false, 0),
            (true, false, false, 0),
            (true, true, false, 1),
            (true, true, true, 0),
        ] {
            let mut binary = fixture_image();
            if capability {
                let hash = if matching {
                    binary.trusted_hash()
                } else {
                    [19; 32]
                };
                binary = binary.with_producer(Some(issuer::fake_consumer_image(hash)));
            }
            let intent = ProfileIntent::decode(r#"{"version":1,"graph":{"outbounds":[{"tag":"b","protocol":"vless","settings":{"vnext":[{"address":"physical.invalid","port":8443,"users":[{"id":"00000000-0000-0000-0000-000000000001","encryption":"none"}]}]}}]}}"#).unwrap();
            let plan =
                OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
            let (keep, cancel) = Cancellation::new();
            if cancelled {
                keep.send(true).unwrap();
            }
            let mut captures = 0;
            let result = Prepared::prepare_with_sources(&binary, intent, plan, &cancel, |_, _| {
                captures += 1;
                Err(HostError::State)
            });
            assert!(result.is_err());
            assert_eq!(captures, expected);
            if expected == 1 {
                assert!(matches!(result, Err(HostError::State)));
            }
        }
    }
}
