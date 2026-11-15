//! Worker-owned native ресурсы: отдельная физическая reservation до native exec.
use super::WorkerError;
use crate::resource_fd_receiver::Reservation;
use rustix::fs::{self, OFlags, SealFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Write,
    os::{fd::AsRawFd, unix::fs::FileExt},
};
use yonik_engine::resource_bundle::ExternalRef;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum NativeKind {
    DatCidrs = 1,
    DatDomains = 2,
    Resolver = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeDescriptor {
    pub kind: NativeKind,
    pub digest: [u8; 32],
    pub bytes: u64,
    pub records: u64,
    pub source: [u8; 32],
    pub flags: u32,
}
impl NativeDescriptor {
    fn validate(self) -> Result<(), WorkerError> {
        if self.digest == [0; 32] || self.bytes == 0 || self.bytes > 64 * 1024 * 1024 {
            return Err(WorkerError::Limit);
        }
        match self.kind {
            NativeKind::Resolver
                if self.bytes > 2 * 1024 * 1024
                    || self.records != 0
                    || self.source == [0; 32]
                    || self.flags & !1 != 0 =>
            {
                Err(WorkerError::Protocol)
            }
            NativeKind::DatCidrs | NativeKind::DatDomains
                if self.source != [0; 32]
                    || self.flags != 0
                    || self.records == 0
                    || self.records > 1_500_000 =>
            {
                Err(WorkerError::Protocol)
            }
            _ => Ok(()),
        }
    }
    pub(crate) fn encode(self) -> Result<[u8; 88], WorkerError> {
        self.validate()?;
        let mut out = [0; 88];
        out[0] = self.kind as u8;
        out[1] = 1;
        out[4..36].copy_from_slice(&self.digest);
        out[36..44].copy_from_slice(&self.bytes.to_be_bytes());
        out[44..52].copy_from_slice(&self.records.to_be_bytes());
        out[52..84].copy_from_slice(&self.source);
        out[84..88].copy_from_slice(&self.flags.to_be_bytes());
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WorkerError> {
        if bytes.len() != 88 || bytes[1..4] != [1, 0, 0] {
            return Err(WorkerError::Protocol);
        }
        let descriptor = Self {
            kind: match bytes[0] {
                1 => NativeKind::DatCidrs,
                2 => NativeKind::DatDomains,
                3 => NativeKind::Resolver,
                _ => return Err(WorkerError::Protocol),
            },
            digest: bytes[4..36].try_into().map_err(|_| WorkerError::Protocol)?,
            bytes: u64::from_be_bytes(
                bytes[36..44]
                    .try_into()
                    .map_err(|_| WorkerError::Protocol)?,
            ),
            records: u64::from_be_bytes(
                bytes[44..52]
                    .try_into()
                    .map_err(|_| WorkerError::Protocol)?,
            ),
            source: bytes[52..84]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
            flags: u32::from_be_bytes(
                bytes[84..88]
                    .try_into()
                    .map_err(|_| WorkerError::Protocol)?,
            ),
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
    pub(crate) fn name(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(72);
        out.push_str(if self.kind == NativeKind::Resolver {
            "dns-"
        } else {
            "r-"
        });
        for b in self.digest {
            out.push(char::from(HEX[(b >> 4) as usize]));
            out.push(char::from(HEX[(b & 15) as usize]));
        }
        out.push_str(if self.kind == NativeKind::Resolver {
            ".bin"
        } else {
            ".dat"
        });
        out
    }
}
pub(crate) struct NativeAsset {
    pub file: File,
    pub descriptor: NativeDescriptor,
    _reservation: Option<Reservation>,
}
pub(crate) fn copy_native(
    source: &File,
    descriptor: NativeDescriptor,
    cancel: &impl Fn() -> bool,
) -> Result<NativeAsset, WorkerError> {
    validate_native(source, descriptor)?;
    let reservation = Reservation::acquire(
        descriptor
            .bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(8192))
            .ok_or(WorkerError::Limit)?,
    )
    .map_err(|_| WorkerError::Limit)?;
    let mut target = File::from(
        fs::memfd_create(
            "yonik-worker-native",
            fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|_| WorkerError::Io)?,
    );
    fs::fchmod(&target, fs::Mode::RUSR | fs::Mode::WUSR).map_err(|_| WorkerError::Io)?;
    let mut buffer = [0; 8192];
    let mut offset = 0;
    while offset < descriptor.bytes {
        if cancel() {
            return Err(WorkerError::Timeout);
        }
        let n = source
            .read_at(
                &mut buffer[..(descriptor.bytes - offset).min(8192) as usize],
                offset,
            )
            .map_err(|_| WorkerError::Io)?;
        if n == 0 {
            return Err(WorkerError::Protocol);
        }
        target
            .write_all(&buffer[..n])
            .map_err(|_| WorkerError::Io)?;
        offset += n as u64;
    }
    fs::fcntl_add_seals(
        &target,
        SealFlags::SEAL | SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK,
    )
    .map_err(|_| WorkerError::Io)?;
    let file =
        File::open(format!("/proc/self/fd/{}", target.as_raw_fd())).map_err(|_| WorkerError::Io)?;
    validate_native(&file, descriptor)?;
    if descriptor.kind == NativeKind::Resolver {
        let _memory = crate::helper::memory::config_budget()
            .reserve(descriptor.bytes as usize)
            .map_err(|_| WorkerError::Limit)?;
        let mut bytes = vec![0; descriptor.bytes as usize];
        file.read_exact_at(&mut bytes, 0)
            .map_err(|_| WorkerError::Io)?;
        crate::profile_channel::verify_resolver_asset(
            &bytes,
            crate::profile_channel::SnapshotRef {
                source: descriptor.source,
                asset: descriptor.digest,
                bytes: descriptor.bytes as u32,
                flags: descriptor.flags,
            },
        )
        .map_err(|_| WorkerError::Protocol)?;
    }
    Ok(NativeAsset {
        file,
        descriptor,
        _reservation: Some(reservation),
    })
}
pub(crate) struct TrustedNativePayload {
    pub assets: Vec<NativeAsset>,
    _reservation: Reservation,
}
impl TrustedNativePayload {
    pub(crate) fn capture(
        profile: &crate::helper::profile_intent::PreparedFullProfile,
        cancel: &crate::Cancellation,
    ) -> Result<Self, WorkerError> {
        profile
            .revalidate(cancel)
            .map_err(|_| WorkerError::Protocol)?;
        let count =
            profile.resources().source_files().count() + usize::from(profile.resolver().is_some());
        if count > 16 {
            return Err(WorkerError::Limit);
        }
        let files = profile.resources().source_files();
        let mut descriptors = Vec::with_capacity(count);
        for (file, reference) in files {
            let descriptor = NativeDescriptor {
                kind: match reference.kind {
                    yonik_engine::resource_bundle::ResourceKind::Cidrs => NativeKind::DatCidrs,
                    yonik_engine::resource_bundle::ResourceKind::Domains => NativeKind::DatDomains,
                },
                digest: reference.digest,
                bytes: reference.bytes,
                records: reference.records,
                source: [0; 32],
                flags: 0,
            };
            descriptors.push((Some(file), descriptor));
        }
        if let Some(snapshot) = profile.resolver() {
            let r = snapshot.reference();
            descriptors.push((
                None,
                NativeDescriptor {
                    kind: NativeKind::Resolver,
                    digest: r.asset,
                    bytes: u64::from(r.bytes),
                    records: 0,
                    source: r.source,
                    flags: r.flags,
                },
            ));
        }
        preflight_native(descriptors.iter().map(|(_, d)| *d))?;
        let bytes = descriptors
            .iter()
            .try_fold(8192u64, |n, (_, d)| n.checked_add(d.bytes))
            .ok_or(WorkerError::Limit)?;
        let reservation = Reservation::acquire(bytes).map_err(|_| WorkerError::Limit)?;
        let mut assets = Vec::with_capacity(descriptors.len());
        for (source, descriptor) in descriptors {
            descriptor.validate()?;
            if cancel.check().is_err() {
                return Err(WorkerError::Timeout);
            }
            let mut file = File::from(
                fs::memfd_create(
                    "yonik-native-asset",
                    fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
                )
                .map_err(|_| WorkerError::Io)?,
            );
            fs::fchmod(&file, fs::Mode::RUSR | fs::Mode::WUSR).map_err(|_| WorkerError::Io)?;
            let mut hash = Sha256::new();
            if let Some(source) = source {
                let mut buffer = [0; 8192];
                let mut offset = 0;
                while offset < descriptor.bytes {
                    if cancel.check().is_err() {
                        return Err(WorkerError::Timeout);
                    }
                    let n = source
                        .read_at(
                            &mut buffer[..(descriptor.bytes - offset).min(8192) as usize],
                            offset,
                        )
                        .map_err(|_| WorkerError::Io)?;
                    if n == 0 {
                        return Err(WorkerError::Protocol);
                    }
                    file.write_all(&buffer[..n]).map_err(|_| WorkerError::Io)?;
                    hash.update(&buffer[..n]);
                    offset += n as u64;
                }
            } else {
                let bytes = profile
                    .resolver()
                    .ok_or(WorkerError::Protocol)?
                    .asset_bytes();
                file.write_all(bytes).map_err(|_| WorkerError::Io)?;
                hash.update(bytes);
            }
            if <[u8; 32]>::from(hash.finalize()) != descriptor.digest {
                return Err(WorkerError::Protocol);
            }
            fs::fcntl_add_seals(
                &file,
                SealFlags::SEAL | SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK,
            )
            .map_err(|_| WorkerError::Io)?;
            let file = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
                .map_err(|_| WorkerError::Io)?;
            validate_native(&file, descriptor)?;
            assets.push(NativeAsset {
                file,
                descriptor,
                _reservation: None,
            });
        }
        profile
            .revalidate(cancel)
            .map_err(|_| WorkerError::Protocol)?;
        Ok(Self {
            assets,
            _reservation: reservation,
        })
    }
}
pub(crate) fn preflight_native(
    descriptors: impl IntoIterator<Item = NativeDescriptor>,
) -> Result<(), WorkerError> {
    let mut seen = [[0; 32]; 16];
    let mut total = 8192u64;
    for (count, d) in descriptors.into_iter().enumerate() {
        d.validate()?;
        if count == 16 || seen[..count].contains(&d.digest) {
            return Err(WorkerError::Limit);
        }
        seen[count] = d.digest;
        total = total
            .checked_add(d.bytes)
            .filter(|n| *n <= 64 * 1024 * 1024)
            .ok_or(WorkerError::Limit)?;
    }
    Ok(())
}
pub(crate) fn validate_native(file: &File, d: NativeDescriptor) -> Result<(), WorkerError> {
    d.validate()?;
    let metadata = file.metadata().map_err(|_| WorkerError::Protocol)?;
    if !metadata.is_file()
        || metadata.len() != d.bytes
        || fs::fcntl_getfl(file).map_err(|_| WorkerError::Protocol)? & OFlags::ACCMODE
            != OFlags::RDONLY
        || !fs::fcntl_get_seals(file)
            .map_err(|_| WorkerError::Protocol)?
            .contains(SealFlags::SEAL | SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK)
    {
        return Err(WorkerError::Protocol);
    }
    super::validate_file(file, d.bytes as usize, d.digest)
}

pub(super) struct OwnedResource {
    pub(super) file: File,
    pub(super) reference: ExternalRef,
    _reservation: Reservation,
}
pub(super) fn validate(source: &File, resource: &ExternalRef) -> Result<(), WorkerError> {
    resource.validate().map_err(|_| WorkerError::Protocol)?;
    let metadata = source.metadata().map_err(|_| WorkerError::Protocol)?;
    let seals = SealFlags::SEAL | SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK;
    if !metadata.is_file()
        || metadata.len() != resource.bytes
        || fs::fcntl_getfl(source).map_err(|_| WorkerError::Protocol)? & OFlags::ACCMODE
            != OFlags::RDONLY
        || !fs::fcntl_get_seals(source)
            .map_err(|_| WorkerError::Protocol)?
            .contains(seals)
        || !std::fs::read_link(format!("/proc/self/fd/{}", source.as_raw_fd()))
            .map_err(|_| WorkerError::Protocol)?
            .as_os_str()
            .as_encoded_bytes()
            .starts_with(b"/memfd:")
    {
        return Err(WorkerError::Protocol);
    }
    Ok(())
}
pub(super) fn copy_owned(
    source: &File,
    resource: &ExternalRef,
    cancel: &impl Fn() -> bool,
) -> Result<OwnedResource, WorkerError> {
    validate(source, resource)?;
    let reservation = Reservation::acquire(
        resource
            .bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(8192))
            .ok_or(WorkerError::Limit)?,
    )
    .map_err(|_| WorkerError::Limit)?;
    if cancel() {
        return Err(WorkerError::Timeout);
    }
    let mut target = File::from(
        fs::memfd_create(
            format!("yonik-{}", resource.tag()),
            fs::MemfdFlags::CLOEXEC | fs::MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|_| WorkerError::Io)?,
    );
    fs::fchmod(&target, fs::Mode::RUSR | fs::Mode::WUSR).map_err(|_| WorkerError::Io)?;
    let mut buffer = [0u8; 8192];
    let mut offset = 0;
    let mut hash = Sha256::new();
    while offset < resource.bytes {
        if cancel() {
            return Err(WorkerError::Timeout);
        }
        let length = (resource.bytes - offset).min(buffer.len() as u64) as usize;
        let n = source
            .read_at(&mut buffer[..length], offset)
            .map_err(|_| WorkerError::Io)?;
        if n == 0 {
            return Err(WorkerError::Protocol);
        }
        target
            .write_all(&buffer[..n])
            .map_err(|_| WorkerError::Io)?;
        hash.update(&buffer[..n]);
        offset += n as u64;
    }
    if hash.finalize().as_slice() != resource.digest
        || target.metadata().map_err(|_| WorkerError::Io)?.len() != resource.bytes
    {
        return Err(WorkerError::Protocol);
    }
    fs::fcntl_add_seals(
        &target,
        SealFlags::SEAL | SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK,
    )
    .map_err(|_| WorkerError::Io)?;
    let readonly =
        File::open(format!("/proc/self/fd/{}", target.as_raw_fd())).map_err(|_| WorkerError::Io)?;
    Ok(OwnedResource {
        file: readonly,
        reference: resource.clone(),
        _reservation: reservation,
    })
}
impl OwnedResource {
    pub(super) fn into_slot(mut self, index: usize) -> Result<Self, WorkerError> {
        if index >= 16 {
            return Err(WorkerError::Protocol);
        }
        let slot = 32 + index as i32;
        let duplicate =
            rustix::io::fcntl_dupfd_cloexec(&self.file, slot).map_err(|_| WorkerError::Io)?;
        if duplicate.as_raw_fd() != slot {
            return Err(WorkerError::Protocol);
        }
        self.file = File::from(duplicate);
        Ok(self)
    }
    pub(super) fn inherit(&self, enabled: bool) -> Result<(), WorkerError> {
        rustix::io::fcntl_setfd(
            &self.file,
            if enabled {
                rustix::io::FdFlags::empty()
            } else {
                rustix::io::FdFlags::CLOEXEC
            },
        )
        .map_err(|_| WorkerError::Io)
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn profile_descriptor_layout_bounds_and_owned_names_are_exact() {
        use super::{NativeDescriptor, NativeKind};
        let descriptor = NativeDescriptor {
            kind: NativeKind::DatDomains,
            digest: [1; 32],
            bytes: 64,
            records: 1,
            source: [0; 32],
            flags: 0,
        };
        let bytes = descriptor.encode().unwrap();
        assert_eq!(bytes.len(), 88);
        assert_eq!(&bytes[..4], &[2, 1, 0, 0]);
        assert_eq!(NativeDescriptor::decode(&bytes).unwrap(), descriptor);
        assert_eq!(descriptor.name(), format!("r-{}.dat", "01".repeat(32)));
        for end in 0..bytes.len() {
            assert!(NativeDescriptor::decode(&bytes[..end]).is_err());
        }
        for index in [0, 1, 2, 3, 52, 87] {
            let mut malformed = bytes;
            malformed[index] ^= 128;
            assert!(
                NativeDescriptor::decode(&malformed).is_err(),
                "byte {index}"
            );
        }
        let mut snapshot = descriptor;
        snapshot.kind = NativeKind::Resolver;
        snapshot.source = [2; 32];
        snapshot.records = 0;
        snapshot.flags = 1;
        assert_eq!(snapshot.name(), format!("dns-{}.bin", "01".repeat(32)));
        assert!(NativeDescriptor::decode(&snapshot.encode().unwrap()).is_ok());
        snapshot.bytes = 2 * 1024 * 1024 + 1;
        assert!(snapshot.encode().is_err());
    }
    use super::copy_owned;
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
    use sha2::{Digest, Sha256};
    use std::io::Write;
    #[test]
    fn owned_native_copy_has_exact_bytes_and_readonly_seals() {
        let bytes = b"native-fixture";
        let mut file = std::fs::File::from(
            memfd_create(
                "native-input",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
            )
            .unwrap(),
        );
        file.write_all(bytes).unwrap();
        fcntl_add_seals(
            &file,
            SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
        )
        .unwrap();
        use std::os::fd::AsRawFd;
        let source = std::fs::File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        let resource = yonik_engine::resource_bundle::ExternalRef {
            engine: yonik_engine::Engine::Xray,
            digest: Sha256::digest(bytes).into(),
            bytes: bytes.len() as u64,
            records: 1,
            kind: yonik_engine::resource_bundle::ResourceKind::Cidrs,
            format_version: 1,
        };
        let copy = copy_owned(&source, &resource, &|| false).unwrap();
        assert_ne!(
            rustix::fs::fstat(&source).unwrap().st_ino,
            rustix::fs::fstat(&copy.file).unwrap().st_ino
        );
        assert_eq!(
            rustix::fs::fcntl_getfl(&copy.file).unwrap() & rustix::fs::OFlags::ACCMODE,
            rustix::fs::OFlags::RDONLY
        );
        assert!(
            rustix::fs::fcntl_get_seals(&copy.file)
                .unwrap()
                .contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL)
        );
        let mut wrong = resource.clone();
        wrong.digest[0] ^= 1;
        assert!(copy_owned(&source, &wrong, &|| false).is_err());
        assert!(copy_owned(&source, &resource, &|| true).is_err());
    }
}

#[cfg(test)]
mod native_gate {
    use super::{File, copy_owned};
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        num::NonZeroU16,
        process::{Command, Stdio},
    };
    use yonik_engine::{
        Engine,
        external_rules::{Format, Limits, compile_records},
        resource_bundle::{
            Action, BoundPolicy, ExternalRef, Policy, ResourceBinding, ResourceKind, ResourceRule,
            Rule, policy_identity,
        },
    };
    #[test]
    #[ignore = "Требуются pinned binaries и изолированный user/net namespace"]
    fn actual_fixed_fd_native_config_gate() {
        let parent_ns = std::env::var("YONIK_GATE_PARENT_NET_NS")
            .expect("Runner должен зафиксировать исходный net namespace до unshare");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net")
                .unwrap()
                .to_string_lossy(),
            parent_ns,
            "Требуется изолированный net namespace"
        );
        let source = b"10.0.0.0/8\n";
        let mut failures = Vec::new();
        for (engine, format, path, pin) in [
            (
                Engine::Xray,
                Format::XrayCidrs,
                "/home/myrs/projects/yonik/local/engines/xray-26.10.31/xray",
                "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
            ),
            (
                Engine::SingBox,
                Format::SingCidrs,
                "/home/myrs/projects/yonik/local/artifacts/sing-box-external-tun-versioned-v1.14.4/sing-box",
                "4c31db07cb394479b58cc9aace8c8bef5da05a73db6dacca4a019aeb8b14e16d",
            ),
        ] {
            assert_eq!(
                format!("{:x}", Sha256::digest(std::fs::read(path).unwrap())),
                pin
            );
            let mut native = Vec::new();
            compile_records(
                std::io::Cursor::new(source),
                &mut native,
                format,
                1,
                Limits::default(),
            )
            .unwrap();
            let reference = ExternalRef {
                engine,
                digest: Sha256::digest(&native).into(),
                bytes: native.len() as u64,
                records: 1,
                kind: ResourceKind::Cidrs,
                format_version: if engine == Engine::Xray { 1 } else { 3 },
            };
            let mut input = File::from(
                rustix::fs::memfd_create(
                    "gate-input",
                    rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
                )
                .unwrap(),
            );
            input.write_all(&native).unwrap();
            rustix::fs::fcntl_add_seals(
                &input,
                rustix::fs::SealFlags::WRITE
                    | rustix::fs::SealFlags::GROW
                    | rustix::fs::SealFlags::SHRINK
                    | rustix::fs::SealFlags::SEAL,
            )
            .unwrap();
            use std::os::fd::AsRawFd;
            let input = File::open(format!("/proc/self/fd/{}", input.as_raw_fd())).unwrap();
            let owned = copy_owned(&input, &reference, &|| false)
                .unwrap()
                .into_slot(0)
                .unwrap();
            struct Catalog(ExternalRef);
            impl yonik_engine::resource_bundle::VerifiedCatalog for Catalog {
                fn manifest(&self) -> &[ExternalRef] {
                    std::slice::from_ref(&self.0)
                }
                fn matches_domain(
                    &self,
                    _: usize,
                    _: &yonik_engine::resource_bundle::DomainName,
                ) -> bool {
                    false
                }
                fn matches_ip(&self, _: usize, _: std::net::IpAddr) -> bool {
                    false
                }
            }
            let catalog = Catalog(reference);
            let policy = Policy {
                user_rules: vec![Rule {
                    id: 1,
                    enabled: true,
                    conditions: Default::default(),
                    action: Action::Block,
                }],
                ..Policy::default()
            };
            let identity = policy_identity(&policy);
            let bound = BoundPolicy::bind(
                &policy,
                1,
                &identity,
                &catalog,
                vec![ResourceBinding {
                    rule: ResourceRule::User(1),
                    resource: 0,
                }],
            )
            .unwrap();
            let server = yonik_import::import_bytes(b"socks://127.0.0.1:18081".to_vec()).unwrap();
            let tun = yonik_engine::SystemTun::new(
                123,
                1500,
                987,
                vec!["198.18.0.1/30".parse().unwrap()],
            )
            .unwrap();
            let config = yonik_engine::compile_system_bound_policy(
                &server.servers[0],
                engine,
                NonZeroU16::new(21001).unwrap(),
                NonZeroU16::new(21002).unwrap(),
                &bound,
                1,
                &identity,
                &tun,
            )
            .unwrap();
            let mut bytes = Vec::new();
            config.write_sensitive(&mut bytes).unwrap();
            if engine == Engine::Xray {
                // Исторический raw-FD negative control, не production renderer.
                bytes=serde_json::to_vec(&serde_json::json!({"log":{"loglevel":"error"},"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","ip":["ext:/proc/self/fd/32:YONIK"],"outboundTag":"direct"}]}})).unwrap();
            }
            let mut fd = File::from(
                rustix::fs::memfd_create("gate-config", rustix::fs::MemfdFlags::CLOEXEC).unwrap(),
            );
            fd.write_all(&bytes).unwrap();
            use std::io::{Seek, SeekFrom};
            fd.seek(SeekFrom::Start(0)).unwrap();
            owned.inherit(true).unwrap();
            let mut command = Command::new(path);
            command
                .env_clear()
                .env("LANG", "C")
                .current_dir("/")
                .stdin(Stdio::from(fd));
            if engine == Engine::Xray {
                command.args(["run", "-test", "-c", "stdin:"]);
            } else {
                command.args(["check", "-c", "/dev/stdin"]);
            }
            let output = command.output().unwrap();
            owned.inherit(false).unwrap();
            eprintln!(
                "engine={engine:?} pinned_fd_config_check={} stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let expected = if engine == Engine::Xray {
                !output.status.success()
                    && String::from_utf8_lossy(&output.stdout)
                        .contains("asset path must stay in asset directory")
            } else {
                output.status.success()
            };
            if !expected {
                failures.push(engine);
            }
        }
        assert!(
            failures.is_empty(),
            "Pinned native FD-path gate отклонён: {failures:?}"
        );
    }
}

#[cfg(test)]
mod slot_tests {
    #[test]
    fn occupied_slot_is_preserved_in_isolated_test_process() {
        const CHILD: &str = "YONIK_NATIVE_SLOT_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status=std::process::Command::new(std::env::current_exe().unwrap()).args(["worker::native_resources::slot_tests::occupied_slot_is_preserved_in_isolated_test_process","--exact","--test-threads=1"]).env(CHILD,"1").status().unwrap();
            assert!(status.success());
            return;
        }
        use sha2::{Digest, Sha256};
        use std::{fs::File, io::Write, os::fd::AsRawFd};
        let sentinel = File::open("/dev/null").unwrap();
        let slot = rustix::io::fcntl_dupfd_cloexec(&sentinel, 32).unwrap();
        assert_eq!(slot.as_raw_fd(), 32);
        let before = rustix::fs::fstat(&slot).unwrap();
        let mut source = File::from(
            rustix::fs::memfd_create(
                "slot-source",
                rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
            )
            .unwrap(),
        );
        source.write_all(b"native").unwrap();
        rustix::fs::fcntl_add_seals(
            &source,
            rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::SEAL,
        )
        .unwrap();
        let source = File::open(format!("/proc/self/fd/{}", source.as_raw_fd())).unwrap();
        let resource = yonik_engine::resource_bundle::ExternalRef {
            engine: yonik_engine::Engine::Xray,
            digest: Sha256::digest(b"native").into(),
            bytes: 6,
            records: 1,
            kind: yonik_engine::resource_bundle::ResourceKind::Cidrs,
            format_version: 1,
        };
        let owned = super::copy_owned(&source, &resource, &|| false).unwrap();
        assert!(owned.into_slot(0).is_err());
        let after = rustix::fs::fstat(&slot).unwrap();
        assert_eq!((before.st_dev, before.st_ino), (after.st_dev, after.st_ino));
    }
}
