//! DATA-проекция закрытого compiler graph. Не IPC codec и не разрешение запуска.
use crate::{
    Cancellation,
    managed_network::firewall::{BoundTransport, TransportProtocol},
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    net::{IpAddr, SocketAddr},
};
use yonik_engine::native_profile::{EgressPlan, PhysicalEndpoint};

/// Клиент передаёт typed intent и selection coordinates, но не host proofs.
pub struct FullProfileRequest {
    intent: yonik_engine::native_profile::ProfileIntent,
    generation: u64,
    selection: [u8; 32],
    kill_switch: bool,
    peer: Option<std::sync::Arc<crate::attribution::PeerProcess>>,
    _memory: super::memory::ByteLease,
}
impl FullProfileRequest {
    pub(crate) fn capture_sources(
        &self,
        cancel: &Cancellation,
    ) -> Result<FullProfileSources, EgressError> {
        FullProfileSources::capture(&self.intent, cancel)
    }
    pub(super) fn bind_peer(
        &mut self,
        peer: std::sync::Arc<crate::attribution::PeerProcess>,
    ) -> Result<(), super::ServiceError> {
        if self.peer.is_some() {
            return Err(super::ServiceError::InvalidRequest);
        }
        self.peer = Some(peer);
        Ok(())
    }
    pub(super) fn peer(
        &self,
    ) -> Result<&std::sync::Arc<crate::attribution::PeerProcess>, super::ServiceError> {
        self.peer.as_ref().ok_or(super::ServiceError::Unsupported)
    }
    pub(super) fn coordinates(&self) -> (u64, [u8; 32]) {
        (self.generation, self.selection)
    }
    pub(super) fn intent(&self) -> &yonik_engine::native_profile::ProfileIntent {
        &self.intent
    }
    pub(super) fn kill_switch(&self) -> bool {
        self.kill_switch
    }
    /// Compile/source milestone внутри serialized backend. Не owner/image proof
    /// и не готовое разрешение Apply: все источники revalidate перед effects.
    pub fn prepare_system(
        &self,
        plan: yonik_engine::native_profile::OwnedRuntimePlan,
        policy_revision: u64,
        admission_id: u64,
        cancel: &Cancellation,
    ) -> Result<PreparedFullProfile, EgressError> {
        let sources = self.capture_sources(cancel)?;
        self.prepare_system_captured(plan, policy_revision, admission_id, sources, cancel)
    }
    pub(crate) fn prepare_system_captured(
        &self,
        mut plan: yonik_engine::native_profile::OwnedRuntimePlan,
        policy_revision: u64,
        admission_id: u64,
        sources: FullProfileSources,
        cancel: &Cancellation,
    ) -> Result<PreparedFullProfile, EgressError> {
        if !plan.is_system() {
            return Err(EgressError::InvalidBinding);
        }
        check_cancel(cancel)?;
        let graph = self.intent.validate().map_err(|_| EgressError::Encoding)?;
        self.intent
            .validate_ingress_mapping(&plan)
            .map_err(|_| EgressError::InvalidBinding)?;
        sources.revalidate(&self.intent, cancel)?;
        let FullProfileSources {
            resources,
            resolver,
            ..
        } = sources;
        plan = plan
            .bind_resources(&graph, &resources)
            .map_err(|_| EgressError::Resource)?;
        if let Some(snapshot) = &resolver {
            plan = plan
                .bind_system_resolver(snapshot)
                .map_err(|_| EgressError::Resolver)?;
        }
        let compiled = self
            .intent
            .compile_system(&plan)
            .map_err(|_| EgressError::Encoding)?;
        let retained = RetainedSystemProfile::seal(compiled, self.generation, self.selection)?;
        let capsule = crate::profile_channel::OwnedCapsule::build(
            &self.intent,
            &plan,
            resolver.as_ref().map(PinnedResolverSnapshot::reference),
            *retained.digest(),
            policy_revision,
            admission_id,
        )
        .map_err(|_| EgressError::InvalidBinding)?;
        let prepared = PreparedFullProfile {
            retained,
            resources,
            resolver,
            capsule: std::sync::Arc::new(capsule),
            kill_switch: self.kill_switch,
        };
        prepared.revalidate(cancel)?;
        Ok(prepared)
    }
    pub fn new(
        intent: yonik_engine::native_profile::ProfileIntent,
        generation: u64,
        selection: [u8; 32],
        kill_switch: bool,
    ) -> Result<Self, super::ServiceError> {
        let memory = super::memory::config_budget()
            .reserve(super::MAX_ARTIFACT_BYTES)
            .map_err(|_| super::ServiceError::Busy)?;
        Self::with_memory(intent, generation, selection, kill_switch, memory)
    }
    fn with_memory(
        intent: yonik_engine::native_profile::ProfileIntent,
        generation: u64,
        selection: [u8; 32],
        kill_switch: bool,
        memory: super::memory::ByteLease,
    ) -> Result<Self, super::ServiceError> {
        if generation == 0 || selection == [0; 32] {
            return Err(super::ServiceError::InvalidRequest);
        }
        intent
            .validate()
            .map_err(|_| super::ServiceError::InvalidRequest)?;
        Ok(Self {
            intent,
            generation,
            selection,
            kill_switch,
            peer: None,
            _memory: memory,
        })
    }
    pub fn decode(wire: &str) -> Result<Self, super::ServiceError> {
        if wire.len() > super::MAX_REQUEST {
            return Err(super::ServiceError::InvalidRequest);
        }
        // Общий admission credit до typed strings/vectors и повторного P3 Value.
        let memory = super::memory::config_budget()
            .reserve(super::MAX_ARTIFACT_BYTES)
            .map_err(|_| super::ServiceError::Busy)?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Request<'a> {
            version: u32,
            generation: u64,
            selection: [u8; 32],
            kill_switch: bool,
            #[serde(borrow)]
            intent: &'a serde_json::value::RawValue,
        }
        let request: Request<'_> =
            serde_json::from_str(wire).map_err(|_| super::ServiceError::InvalidRequest)?;
        if request.version != 1 {
            return Err(super::ServiceError::InvalidRequest);
        }
        let intent = yonik_engine::native_profile::ProfileIntent::decode(request.intent.get())
            .map_err(|_| super::ServiceError::InvalidRequest)?;
        Self::with_memory(
            intent,
            request.generation,
            request.selection,
            request.kill_switch,
            memory,
        )
    }
    pub fn write_sensitive(&self, writer: impl Write) -> Result<(), super::ServiceError> {
        let mut bytes = Vec::new();
        self.intent
            .write_sensitive(&mut bytes)
            .map_err(|_| super::ServiceError::InvalidRequest)?;
        let raw: &serde_json::value::RawValue =
            serde_json::from_slice(&bytes).map_err(|_| super::ServiceError::InvalidRequest)?;
        #[derive(serde::Serialize)]
        struct Request<'a> {
            version: u32,
            generation: u64,
            selection: [u8; 32],
            kill_switch: bool,
            intent: &'a serde_json::value::RawValue,
        }
        serde_json::to_writer(
            RequestWriter { writer, bytes: 0 },
            &Request {
                version: 1,
                generation: self.generation,
                selection: self.selection,
                kill_switch: self.kill_switch,
                intent: raw,
            },
        )
        .map_err(|_| super::ServiceError::InvalidRequest)
    }
    /// Production dispatch вызывает эту проверку до любого privileged эффекта.
    /// Selection остаётся заявлением клиента до trusted catalog/owner admission.
    pub(super) fn preflight(&self, cancel: &Cancellation) -> Result<(), super::ServiceError> {
        cancel.check().map_err(|_| super::ServiceError::Cancelled)?;
        let graph = self
            .intent
            .validate()
            .map_err(|_| super::ServiceError::InvalidRequest)?;
        PhysicalRequirements::new(graph.egress())
            .map_err(|_| super::ServiceError::InvalidRequest)?;
        cancel.check().map_err(|_| super::ServiceError::Cancelled)?;
        Ok(())
    }
}
pub(crate) struct FullProfileSources {
    resources: NativeResourceSet,
    resolver: Option<PinnedResolverSnapshot>,
    intent_digest: [u8; 32],
}
impl FullProfileSources {
    pub(crate) fn bind(
        &self,
        intent: &yonik_engine::native_profile::ProfileIntent,
        mut plan: yonik_engine::native_profile::OwnedRuntimePlan,
        cancel: &Cancellation,
    ) -> Result<yonik_engine::native_profile::OwnedRuntimePlan, EgressError> {
        self.revalidate(intent, cancel)?;
        let graph = intent.validate().map_err(|_| EgressError::Encoding)?;
        plan = plan
            .bind_resources(&graph, &self.resources)
            .map_err(|_| EgressError::Resource)?;
        if let Some(snapshot) = &self.resolver {
            plan = plan
                .bind_system_resolver(snapshot)
                .map_err(|_| EgressError::Resolver)?;
        }
        Ok(plan)
    }
    pub(crate) fn assets(
        &self,
    ) -> impl Iterator<Item = (&std::fs::File, &yonik_engine::resource_bundle::ExternalRef)> {
        self.resources.source_files()
    }
    pub(crate) fn snapshot(&self) -> Option<&PinnedResolverSnapshot> {
        self.resolver.as_ref()
    }
    fn digest(
        intent: &yonik_engine::native_profile::ProfileIntent,
    ) -> Result<[u8; 32], EgressError> {
        let mut hash = DigestWriter {
            digest: Sha256::new(),
            bytes: 0,
        };
        intent
            .write_sensitive(&mut hash)
            .map_err(|_| EgressError::Encoding)?;
        Ok(hash.digest.finalize().into())
    }
    pub(crate) fn capture(
        intent: &yonik_engine::native_profile::ProfileIntent,
        cancel: &Cancellation,
    ) -> Result<Self, EgressError> {
        check_cancel(cancel)?;
        let graph = intent.validate().map_err(|_| EgressError::Encoding)?;
        let resources = NativeResourceSet::capture(&graph, cancel)?;
        let resolver = if graph.egress().system_resolvers().is_empty() {
            None
        } else {
            Some(PinnedResolverSnapshot::capture(cancel)?)
        };
        delivery_preflight(
            resources
                .source_files()
                .map(|(_, reference)| reference.bytes)
                .chain(
                    resolver
                        .as_ref()
                        .map(|snapshot| snapshot.asset_bytes().len() as u64),
                ),
        )?;
        Ok(Self {
            resources,
            resolver,
            intent_digest: Self::digest(intent)?,
        })
    }
    pub(crate) fn revalidate(
        &self,
        intent: &yonik_engine::native_profile::ProfileIntent,
        cancel: &Cancellation,
    ) -> Result<(), EgressError> {
        if Self::digest(intent)? != self.intent_digest {
            return Err(EgressError::Stale);
        }
        self.resources.revalidate(cancel)?;
        if let Some(snapshot) = &self.resolver {
            snapshot.revalidate(cancel)?;
        }
        Ok(())
    }
}
fn delivery_preflight(lengths: impl IntoIterator<Item = u64>) -> Result<(), EgressError> {
    let mut bytes = 8192u64;
    for (index, length) in lengths.into_iter().enumerate() {
        if index >= 16 || length == 0 {
            return Err(EgressError::Budget);
        }
        bytes = bytes
            .checked_add(length)
            .filter(|total| *total <= 64 * 1024 * 1024)
            .ok_or(EgressError::Budget)?;
    }
    Ok(())
}
/// Один результат compile и actual source custody: provider credentials не
/// реконструируются при seal/handoff; capsule builder получает тот же intent.
pub struct PreparedFullProfile {
    retained: RetainedSystemProfile,
    resources: NativeResourceSet,
    resolver: Option<PinnedResolverSnapshot>,
    capsule: std::sync::Arc<crate::profile_channel::OwnedCapsule>,
    kill_switch: bool,
}
impl PreparedFullProfile {
    pub(crate) fn capsule(&self) -> &std::sync::Arc<crate::profile_channel::OwnedCapsule> {
        &self.capsule
    }
    pub fn retained(&self) -> &RetainedSystemProfile {
        &self.retained
    }
    pub fn resources(&self) -> &NativeResourceSet {
        &self.resources
    }
    pub fn resolver(&self) -> Option<&PinnedResolverSnapshot> {
        self.resolver.as_ref()
    }
    pub fn capsule_bytes(&self) -> &[u8] {
        self.capsule.bytes()
    }
    pub fn kill_switch(&self) -> bool {
        self.kill_switch
    }
    pub fn revalidate(&self, cancel: &Cancellation) -> Result<(), EgressError> {
        check_cancel(cancel)?;
        self.resources.revalidate(cancel)?;
        if let Some(snapshot) = &self.resolver {
            snapshot.revalidate(cancel)?;
        }
        check_cancel(cancel)
    }
}
struct RequestWriter<W> {
    writer: W,
    bytes: usize,
}
impl<W: Write> Write for RequestWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let available = super::MAX_REQUEST.saturating_sub(self.bytes);
        if bytes.len() > available {
            return Err(io::Error::other("request budget"));
        }
        let count = self.writer.write(bytes)?;
        self.bytes += count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressError {
    Budget,
    BootstrapRequired,
    InvalidEndpoint,
    Stale,
    Cancelled,
    InvalidBinding,
    Encoding,
    Resource,
    Resolver,
}
fn revalidate_source(
    invalid: &std::sync::atomic::AtomicBool,
    check: impl FnOnce() -> Result<(), EgressError>,
) -> Result<(), EgressError> {
    use std::sync::atomic::Ordering;
    if invalid.load(Ordering::Acquire) {
        return Err(EgressError::Stale);
    }
    let result = check();
    if result.is_err() {
        invalid.store(true, Ordering::Release);
    }
    result?;
    if invalid.load(Ordering::Acquire) {
        return Err(EgressError::Stale);
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
struct SourceStamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn source_stamp(file: &std::fs::File) -> Result<SourceStamp, EgressError> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata().map_err(|_| EgressError::Resource)?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.nlink() != 1 {
        return Err(EgressError::Resource);
    }
    Ok(SourceStamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    })
}
fn read_pinned(
    file: &std::fs::File,
    stamp: &SourceStamp,
    limit: u64,
    cancel: &Cancellation,
) -> Result<Vec<u8>, EgressError> {
    use std::os::unix::fs::FileExt;
    if stamp.len == 0 || stamp.len > limit {
        return Err(EgressError::Budget);
    }
    let count = usize::try_from(stamp.len).map_err(|_| EgressError::Budget)?;
    let mut bytes = vec![0; count];
    let mut offset = 0;
    while offset < count {
        check_cancel(cancel)?;
        let end = (offset + 16384).min(count);
        let n = file
            .read_at(&mut bytes[offset..end], offset as u64)
            .map_err(|_| EgressError::Resource)?;
        if n == 0 {
            return Err(EgressError::Stale);
        }
        offset += n;
    }
    check_cancel(cancel)?;
    if source_stamp(file)? != *stamp {
        return Err(EgressError::Stale);
    }
    Ok(bytes)
}

/// Source/custody proof содержит реальный retained FD, не digest из IPC.
/// Trusted store обязан передать FD; staging owned basename остаётся его задачей.
pub struct PinnedNativeDat {
    file: std::fs::File,
    stamp: SourceStamp,
    reference: yonik_engine::resource_bundle::ExternalRef,
    requirements: Vec<yonik_engine::native_profile::OwnedResourceRequirement>,
}
impl PinnedNativeDat {
    pub fn verify(
        file: std::fs::File,
        reference: yonik_engine::resource_bundle::ExternalRef,
        requirements: &[yonik_engine::native_profile::OwnedResourceRequirement],
        cancel: &Cancellation,
    ) -> Result<Self, EgressError> {
        check_cancel(cancel)?;
        if rustix::fs::fcntl_getfl(&file).map_err(|_| EgressError::Resource)?
            & rustix::fs::OFlags::ACCMODE
            != rustix::fs::OFlags::RDONLY
        {
            return Err(EgressError::Resource);
        }
        reference.validate().map_err(|_| EgressError::Resource)?;
        if reference.engine != yonik_engine::Engine::Xray
            || requirements.is_empty()
            || requirements.len() > 16
            || requirements.iter().any(|r| r.kind() != reference.kind)
        {
            return Err(EgressError::Resource);
        }
        let stamp = source_stamp(&file)?;
        if stamp.len != reference.bytes {
            return Err(EgressError::Resource);
        }
        let reservation = usize::try_from(stamp.len)
            .map_err(|_| EgressError::Budget)?
            .checked_add(512 * 1024)
            .ok_or(EgressError::Budget)?;
        let _memory = super::memory::config_budget()
            .reserve(reservation)
            .map_err(|_| EgressError::Budget)?;
        let bytes = read_pinned(&file, &stamp, 128 * 1024 * 1024, cancel)?;
        verify_dat_content(&bytes, &reference, requirements, cancel)?;
        Ok(Self {
            file,
            stamp,
            reference,
            requirements: requirements.to_vec(),
        })
    }
    pub fn revalidate(&self, cancel: &Cancellation) -> Result<(), EgressError> {
        let _memory = super::memory::config_budget()
            .reserve(usize::try_from(self.stamp.len).map_err(|_| EgressError::Budget)?)
            .map_err(|_| EgressError::Budget)?;
        if source_stamp(&self.file)? != self.stamp {
            return Err(EgressError::Stale);
        }
        let bytes = read_pinned(&self.file, &self.stamp, 128 * 1024 * 1024, cancel)?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != self.reference.digest {
            return Err(EgressError::Stale);
        }
        Ok(())
    }
}
impl yonik_engine::native_profile::VerifiedNativeResources for PinnedNativeDat {
    fn lookup(
        &self,
        requirement: &yonik_engine::native_profile::OwnedResourceRequirement,
    ) -> Option<yonik_engine::resource_bundle::ExternalRef> {
        self.requirements
            .contains(requirement)
            .then(|| self.reference.clone())
    }
}

// Pinned common/geodata/geodat.proto: length-delimited entries и records.
// Строгий parser не принимает неизвестные protobuf effects/неоднозначные поля.
fn varint(bytes: &mut &[u8]) -> Result<u64, EgressError> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = bytes.split_first().ok_or(EgressError::Resource)?;
        *bytes = rest;
        if shift == 63 && byte > 1 {
            return Err(EgressError::Resource);
        }
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(EgressError::Resource)
}
fn block<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], EgressError> {
    let len = usize::try_from(varint(bytes)?).map_err(|_| EgressError::Resource)?;
    if len > bytes.len() {
        return Err(EgressError::Resource);
    }
    let (value, rest) = bytes.split_at(len);
    *bytes = rest;
    Ok(value)
}
fn proto_text(bytes: &[u8]) -> Result<&str, EgressError> {
    std::str::from_utf8(bytes).map_err(|_| EgressError::Resource)
}
fn dat_record(
    mut bytes: &[u8],
    kind: yonik_engine::resource_bundle::ResourceKind,
    cancel: &Cancellation,
) -> Result<(), EgressError> {
    use yonik_engine::resource_bundle::ResourceKind;
    let mut seen = 0u8;
    let mut ip_len = 0;
    let mut prefix = 0;
    while !bytes.is_empty() {
        check_cancel(cancel)?;
        let tag = varint(&mut bytes)?;
        if tag != 26 {
            let bit = match tag {
                8 | 10 => 1,
                16 | 18 => 2,
                _ => return Err(EgressError::Resource),
            };
            if seen & bit != 0 {
                return Err(EgressError::Resource);
            }
            seen |= bit;
        }
        match (kind, tag) {
            (ResourceKind::Domains, 8) => {
                if varint(&mut bytes)? > 3 {
                    return Err(EgressError::Resource);
                }
            }
            (ResourceKind::Domains, 18) => {
                proto_text(block(&mut bytes)?)?;
            }
            (ResourceKind::Domains, 26) => {
                let mut attr = block(&mut bytes)?;
                let mut fields = 0u8;
                while !attr.is_empty() {
                    check_cancel(cancel)?;
                    let tag = varint(&mut attr)?;
                    let bit = match tag {
                        10 => 1,
                        16 | 24 => 2,
                        _ => return Err(EgressError::Resource),
                    };
                    if fields & bit != 0 {
                        return Err(EgressError::Resource);
                    }
                    fields |= bit;
                    if tag == 10 {
                        proto_text(block(&mut attr)?)?;
                    } else {
                        let v = varint(&mut attr)?;
                        if tag == 16 && v > 1 {
                            return Err(EgressError::Resource);
                        }
                    }
                }
            }
            (ResourceKind::Cidrs, 10) => {
                ip_len = block(&mut bytes)?.len();
                if ![4, 16].contains(&ip_len) {
                    return Err(EgressError::Resource);
                }
            }
            (ResourceKind::Cidrs, 16) => prefix = varint(&mut bytes)?,
            _ => return Err(EgressError::Resource),
        }
    }
    if kind == ResourceKind::Cidrs && (ip_len == 0 || prefix > (ip_len * 8) as u64) {
        return Err(EgressError::Resource);
    }
    Ok(())
}
fn verify_dat_content(
    bytes: &[u8],
    reference: &yonik_engine::resource_bundle::ExternalRef,
    requirements: &[yonik_engine::native_profile::OwnedResourceRequirement],
    cancel: &Cancellation,
) -> Result<(), EgressError> {
    let categories = verify_dat_index(bytes, reference, cancel)?;
    for requirement in requirements {
        if !dat_contains(&categories, reference, requirement) {
            return Err(EgressError::Resource);
        }
    }
    Ok(())
}
fn dat_contains(
    categories: &std::collections::BTreeSet<&str>,
    reference: &yonik_engine::resource_bundle::ExternalRef,
    requirement: &yonik_engine::native_profile::OwnedResourceRequirement,
) -> bool {
    let mut parts = requirement.category().split('@');
    let Some(code) = parts.next() else {
        return false;
    };
    requirement.kind() == reference.kind
        && categories.contains(code.to_ascii_uppercase().as_str())
        && !parts.any(str::is_empty)
}
fn verify_dat_index<'a>(
    bytes: &'a [u8],
    reference: &yonik_engine::resource_bundle::ExternalRef,
    cancel: &Cancellation,
) -> Result<std::collections::BTreeSet<&'a str>, EgressError> {
    check_cancel(cancel)?;
    use yonik_engine::resource_bundle::ResourceKind;
    if bytes.len() as u64 != reference.bytes
        || <[u8; 32]>::from(Sha256::digest(bytes)) != reference.digest
    {
        return Err(EgressError::Resource);
    }
    let mut input = bytes;
    let mut categories = std::collections::BTreeSet::new();
    let mut records = 0u64;
    while !input.is_empty() {
        check_cancel(cancel)?;
        if input.first() != Some(&10) || categories.len() >= 4096 {
            return Err(EgressError::Resource);
        }
        input = &input[1..];
        let mut entry = block(&mut input)?;
        // Pinned seek сравнивает tag/code length как single bytes, не как
        // произвольный protobuf varint. Иначе category proof расходится с core.
        if entry.len() < 2 || entry[0] != 10 || entry[1] == 0 || entry[1] > 127 {
            return Err(EgressError::Resource);
        }
        let length = usize::from(entry[1]);
        entry = &entry[2..];
        if length > entry.len() {
            return Err(EgressError::Resource);
        }
        let category = proto_text(&entry[..length])?;
        entry = &entry[length..];
        if category.is_empty()
            || category.len() > 127
            || !category.is_ascii()
            || !categories.insert(category)
        {
            return Err(EgressError::Resource);
        }
        let mut reverse = false;
        while !entry.is_empty() {
            check_cancel(cancel)?;
            match varint(&mut entry)? {
                18 => {
                    records = records.checked_add(1).ok_or(EgressError::Budget)?;
                    if records > 1_500_000 {
                        return Err(EgressError::Budget);
                    }
                    dat_record(block(&mut entry)?, reference.kind, cancel)?;
                }
                24 if reference.kind == ResourceKind::Cidrs && !reverse => {
                    reverse = true;
                    if varint(&mut entry)? > 1 {
                        return Err(EgressError::Resource);
                    }
                }
                _ => return Err(EgressError::Resource),
            }
        }
    }
    if records != reference.records {
        return Err(EgressError::Resource);
    }
    Ok(categories)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCatalog {
    version: u32,
    resources: CatalogEntries,
}
struct CatalogEntries(Vec<CatalogEntry>);
impl<'de> serde::Deserialize<'de> for CatalogEntries {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entries;
        impl<'de> serde::de::Visitor<'de> for Entries {
            type Value = CatalogEntries;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("не более 16 native DAT entries")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut entries = Vec::new();
                while entries.len() < 16 {
                    match seq.next_element()? {
                        Some(entry) => entries.push(entry),
                        None => return Ok(CatalogEntries(entries)),
                    }
                }
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("native catalog budget"));
                }
                Ok(CatalogEntries(entries))
            }
        }
        deserializer.deserialize_seq(Entries)
    }
}
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum CatalogKind {
    Geoip,
    Geosite,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    kind: CatalogKind,
    sha256: [u8; 32],
    bytes: u64,
    records: u64,
    basename: String,
}
impl CatalogEntry {
    fn reference(&self) -> yonik_engine::resource_bundle::ExternalRef {
        use yonik_engine::resource_bundle::{ExternalRef, ResourceKind};
        ExternalRef {
            engine: yonik_engine::Engine::Xray,
            digest: self.sha256,
            bytes: self.bytes,
            records: self.records,
            kind: match self.kind {
                CatalogKind::Geoip => ResourceKind::Cidrs,
                CatalogKind::Geosite => ResourceKind::Domains,
            },
            format_version: 1,
        }
    }
}
fn digest_basename(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(68);
    for byte in digest {
        name.push(char::from(HEX[(byte >> 4) as usize]));
        name.push(char::from(HEX[(byte & 15) as usize]));
    }
    name.push_str(".dat");
    name
}
fn parse_native_catalog(bytes: &[u8]) -> Result<NativeCatalog, EgressError> {
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err(EgressError::Budget);
    }
    let catalog: NativeCatalog =
        serde_json::from_slice(bytes).map_err(|_| EgressError::Resource)?;
    if catalog.version != 1 {
        return Err(EgressError::Resource);
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in &catalog.resources.0 {
        entry
            .reference()
            .validate()
            .map_err(|_| EgressError::Resource)?;
        if entry.sha256 == [0; 32]
            || entry.basename != digest_basename(entry.sha256)
            || !seen.insert(entry.sha256)
        {
            return Err(EgressError::Resource);
        }
    }
    Ok(catalog)
}

#[derive(PartialEq, Eq)]
struct DirectoryStamp {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn directory_stamp(file: &std::fs::File) -> Result<DirectoryStamp, EgressError> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata().map_err(|_| EgressError::Resource)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(EgressError::Resource);
    }
    Ok(DirectoryStamp {
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode(),
        uid: m.uid(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    })
}
struct NativeCatalogSource {
    directories: Vec<std::fs::File>,
    stamps: Vec<DirectoryStamp>,
    file: std::fs::File,
    stamp: SourceStamp,
    bytes: Vec<u8>,
}
impl NativeCatalogSource {
    fn capture(cancel: &Cancellation) -> Result<Self, EgressError> {
        use rustix::fs::{Mode, OFlags, open, openat};
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        let mut directories = vec![std::fs::File::from(
            open("/", flags | OFlags::DIRECTORY, Mode::empty())
                .map_err(|_| EgressError::Resource)?,
        )];
        let mut stamps = vec![directory_stamp(&directories[0])?];
        for name in ["usr", "share", "yonik", "xray-geodata", "v1"] {
            check_cancel(cancel)?;
            let file = std::fs::File::from(
                openat(
                    directories.last().ok_or(EgressError::Resource)?,
                    name,
                    flags | OFlags::DIRECTORY,
                    Mode::empty(),
                )
                .map_err(|_| EgressError::Resource)?,
            );
            stamps.push(directory_stamp(&file)?);
            directories.push(file);
        }
        let file = std::fs::File::from(
            openat(
                directories.last().ok_or(EgressError::Resource)?,
                "catalog.json",
                flags,
                Mode::empty(),
            )
            .map_err(|_| EgressError::Resource)?,
        );
        let stamp = source_stamp(&file)?;
        let bytes = read_pinned(&file, &stamp, 65536, cancel)?;
        Ok(Self {
            directories,
            stamps,
            file,
            stamp,
            bytes,
        })
    }
    fn revalidate(&self, cancel: &Cancellation) -> Result<(), EgressError> {
        let current = Self::capture(cancel)?;
        if current.stamps != self.stamps
            || current.stamp != self.stamp
            || current.bytes != self.bytes
        {
            return Err(EgressError::Stale);
        }
        for (directory, stamp) in self.directories.iter().zip(&self.stamps) {
            if directory_stamp(directory)? != *stamp {
                return Err(EgressError::Stale);
            }
        }
        if source_stamp(&self.file)? != self.stamp
            || read_pinned(&self.file, &self.stamp, 65536, cancel)? != self.bytes
        {
            return Err(EgressError::Stale);
        }
        Ok(())
    }
}
/// Fixed root-owned catalog + actual FD/parser proofs. Metadata из IPC не принимается.
pub struct NativeResourceSet {
    catalog: Option<NativeCatalogSource>,
    files: Vec<PinnedNativeDat>,
    catalog_digest: [u8; 32],
    invalid: std::sync::atomic::AtomicBool,
    _memory: super::memory::ByteLease,
}
impl NativeResourceSet {
    pub(crate) fn source_files(
        &self,
    ) -> impl Iterator<Item = (&std::fs::File, &yonik_engine::resource_bundle::ExternalRef)> {
        self.files
            .iter()
            .filter(|file| !file.requirements.is_empty())
            .map(|file| (&file.file, &file.reference))
    }
    pub fn capture(
        graph: &yonik_engine::native_profile::ValidatedGraph,
        cancel: &Cancellation,
    ) -> Result<Self, EgressError> {
        check_cancel(cancel)?;
        let memory = super::memory::config_budget()
            .reserve(256 * 1024)
            .map_err(|_| EgressError::Budget)?;
        if graph.resources().is_empty() {
            return Ok(Self {
                catalog: None,
                files: Vec::new(),
                catalog_digest: [0; 32],
                invalid: std::sync::atomic::AtomicBool::new(false),
                _memory: memory,
            });
        }
        let source = NativeCatalogSource::capture(cancel)?;
        let catalog = parse_native_catalog(&source.bytes)?;
        let mut assigned = [None; 16];
        let mut files = Vec::new();
        for entry in &catalog.resources.0 {
            let reference = entry.reference();
            if !graph
                .resources()
                .iter()
                .any(|requirement| requirement.kind() == reference.kind)
            {
                continue;
            }
            if reference.bytes > 64 * 1024 * 1024 {
                return Err(EgressError::Budget);
            }
            let file = std::fs::File::from(
                rustix::fs::openat(
                    source.directories.last().ok_or(EgressError::Resource)?,
                    entry.basename.as_str(),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::NONBLOCK,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|_| EgressError::Resource)?,
            );
            let stamp = source_stamp(&file)?;
            if stamp.len != reference.bytes {
                return Err(EgressError::Resource);
            }
            let _parse_memory = super::memory::config_budget()
                .reserve(
                    usize::try_from(stamp.len)
                        .map_err(|_| EgressError::Budget)?
                        .checked_add(512 * 1024)
                        .ok_or(EgressError::Budget)?,
                )
                .map_err(|_| EgressError::Budget)?;
            let bytes = read_pinned(&file, &stamp, 64 * 1024 * 1024, cancel)?;
            let index = verify_dat_index(&bytes, &reference, cancel)?;
            let mut requirements = Vec::new();
            for (i, requirement) in graph.resources().iter().enumerate() {
                if dat_contains(&index, &reference, requirement) {
                    if assigned[i].is_some() {
                        return Err(EgressError::Resource);
                    }
                    assigned[i] = Some(reference.digest);
                    requirements.push(requirement.clone());
                }
            }
            files.push(PinnedNativeDat {
                file,
                stamp,
                reference,
                requirements,
            });
        }
        if assigned[..graph.resources().len()]
            .iter()
            .any(Option::is_none)
        {
            return Err(EgressError::Resource);
        }
        let total = files
            .iter()
            .filter(|file| !file.requirements.is_empty())
            .try_fold(0u64, |sum, file| sum.checked_add(file.reference.bytes))
            .ok_or(EgressError::Budget)?;
        if total > 64 * 1024 * 1024 {
            return Err(EgressError::Budget);
        }
        source.revalidate(cancel)?;
        let catalog_digest = Sha256::digest(&source.bytes).into();
        Ok(Self {
            catalog: Some(source),
            files,
            catalog_digest,
            invalid: std::sync::atomic::AtomicBool::new(false),
            _memory: memory,
        })
    }
    pub fn revalidate(&self, cancel: &Cancellation) -> Result<(), EgressError> {
        revalidate_source(&self.invalid, || self.revalidate_inner(cancel))
    }
    fn revalidate_inner(&self, cancel: &Cancellation) -> Result<(), EgressError> {
        check_cancel(cancel)?;
        if let Some(catalog) = &self.catalog {
            catalog.revalidate(cancel)?;
        }
        for file in &self.files {
            file.revalidate(cancel)?;
        }
        Ok(())
    }
    pub fn catalog_digest(&self) -> &[u8; 32] {
        &self.catalog_digest
    }
}
impl yonik_engine::native_profile::VerifiedNativeResources for NativeResourceSet {
    fn lookup(
        &self,
        requirement: &yonik_engine::native_profile::OwnedResourceRequirement,
    ) -> Option<yonik_engine::resource_bundle::ExternalRef> {
        if self.invalid.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        self.files.iter().find_map(|file| {
            yonik_engine::native_profile::VerifiedNativeResources::lookup(file, requirement)
        })
    }
}

#[derive(PartialEq, Eq)]
struct ResolverIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn resolver_identity(file: &std::fs::File) -> Result<ResolverIdentity, EgressError> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata().map_err(|_| EgressError::Resolver)?;
    if m.uid() != 0 || !m.file_type().is_symlink() && m.mode() & 0o022 != 0 {
        return Err(EgressError::Resolver);
    }
    Ok(ResolverIdentity {
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode(),
        uid: m.uid(),
        len: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    })
}
struct ResolverSource {
    custody: Vec<(std::fs::File, ResolverIdentity)>,
    file: Option<std::fs::File>,
    bytes: Vec<u8>,
}
impl ResolverSource {
    /// Fixed caller locator; relative symlinks нормализуются под удерживаемым /.
    /// O_PATH|NOFOLLOW удерживает каждый link до readlinkat и проверки identity.
    fn capture(
        path: &str,
        limit: usize,
        absent: bool,
        hostname: bool,
        cancel: &Cancellation,
    ) -> Result<Self, EgressError> {
        use rustix::fs::{Mode, OFlags, open, openat, readlinkat};
        use std::{
            collections::VecDeque,
            path::{Component, Path},
        };
        fn parts(path: &Path) -> Result<VecDeque<String>, EgressError> {
            let mut out = VecDeque::new();
            for c in path.components() {
                let value = match c {
                    Component::RootDir => continue,
                    Component::CurDir => continue,
                    Component::ParentDir => "..",
                    Component::Normal(s) => s.to_str().ok_or(EgressError::Resolver)?,
                    _ => return Err(EgressError::Resolver),
                };
                if out.len() == 32 || value.len() > 255 {
                    return Err(EgressError::Budget);
                }
                out.push_back(value.to_owned());
            }
            Ok(out)
        }
        check_cancel(cancel)?;
        let mut pending = parts(Path::new(path))?;
        let root = std::fs::File::from(
            open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| EgressError::Resolver)?,
        );
        let identity = resolver_identity(&root)?;
        let mut custody = vec![(root, identity)];
        let mut parents = vec![0usize];
        let mut links = 0;
        loop {
            check_cancel(cancel)?;
            if custody.len() >= 128 {
                return Err(EgressError::Budget);
            }
            let name = pending.pop_front().ok_or(EgressError::Resolver)?;
            if name == ".." {
                if parents.len() == 1 {
                    return Err(EgressError::Resolver);
                }
                parents.pop();
                continue;
            }
            let parent = *parents.last().ok_or(EgressError::Resolver)?;
            let node = match openat(
                &custody[parent].0,
                name.as_str(),
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ) {
                Ok(fd) => std::fs::File::from(fd),
                Err(rustix::io::Errno::NOENT) if absent && pending.is_empty() && links == 0 => {
                    return Ok(Self {
                        custody,
                        file: None,
                        bytes: Vec::new(),
                    });
                }
                Err(_) => return Err(EgressError::Resolver),
            };
            let identity = resolver_identity(&node)?;
            let m = node.metadata().map_err(|_| EgressError::Resolver)?;
            if m.file_type().is_symlink() {
                if links == 4 || identity.len > 1024 || !path.ends_with("resolv.conf") {
                    return Err(EgressError::Resolver);
                }
                links += 1;
                let target = readlinkat(&node, "", Vec::with_capacity(1024))
                    .map_err(|_| EgressError::Resolver)?;
                if target.as_bytes().len() > 1024 {
                    return Err(EgressError::Budget);
                }
                let target = Path::new(
                    std::str::from_utf8(target.as_bytes()).map_err(|_| EgressError::Resolver)?,
                );
                if target.is_absolute() {
                    parents.truncate(1);
                }
                let mut next = parts(target)?;
                if next.len() + pending.len() > 32 {
                    return Err(EgressError::Budget);
                }
                next.append(&mut pending);
                pending = next;
                if resolver_identity(&node)? != identity {
                    return Err(EgressError::Stale);
                }
                custody.push((node, identity));
            } else if m.is_dir() && !pending.is_empty() {
                if custody.len() >= 128 {
                    return Err(EgressError::Budget);
                }
                parents.push(custody.len());
                custody.push((node, identity));
            } else {
                if !m.is_file() || !pending.is_empty() {
                    return Err(EgressError::Resolver);
                }
                let file = std::fs::File::from(
                    openat(
                        &custody[parent].0,
                        name.as_str(),
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                        Mode::empty(),
                    )
                    .map_err(|_| EgressError::Resolver)?,
                );
                if resolver_identity(&file)? != identity {
                    return Err(EgressError::Stale);
                }
                custody.push((node, identity));
                let stamp = source_stamp(&file)?;
                if !hostname && stamp.len > limit as u64 {
                    return Err(EgressError::Budget);
                }
                let mut bytes = vec![
                    0;
                    if hostname {
                        limit + 1
                    } else {
                        stamp.len as usize
                    }
                ];
                use std::os::unix::fs::FileExt;
                let mut offset = 0;
                while offset < bytes.len() {
                    check_cancel(cancel)?;
                    let n = file
                        .read_at(&mut bytes[offset..], offset as u64)
                        .map_err(|_| EgressError::Resolver)?;
                    if n == 0 {
                        break;
                    }
                    offset += n;
                }
                if hostname {
                    if offset == bytes.len() {
                        return Err(EgressError::Budget);
                    }
                    bytes.truncate(offset);
                    if bytes.last() == Some(&b'\n') {
                        bytes.pop();
                    }
                } else if offset != bytes.len() {
                    return Err(EgressError::Stale);
                }
                if source_stamp(&file)? != stamp {
                    return Err(EgressError::Stale);
                }
                let result = Self {
                    custody,
                    file: Some(file),
                    bytes,
                };
                result.validate_handles()?;
                return Ok(result);
            }
        }
    }
    fn validate_handles(&self) -> Result<(), EgressError> {
        for (file, identity) in &self.custody {
            if resolver_identity(file)? != *identity {
                return Err(EgressError::Stale);
            }
        }
        if let Some(file) = &self.file {
            if self
                .custody
                .last()
                .is_none_or(|(_, identity)| resolver_identity(file).as_ref() != Ok(identity))
            {
                return Err(EgressError::Stale);
            }
        }
        Ok(())
    }
    fn same(&self, other: &Self) -> bool {
        self.bytes == other.bytes
            && self.file.is_some() == other.file.is_some()
            && self.custody.len() == other.custody.len()
            && self
                .custody
                .iter()
                .zip(&other.custody)
                .all(|((_, a), (_, b))| a == b)
    }
}
/// Exact source files и canonical asset pinned отдельно от provider DNS.
/// Capture вызывается только production producer; unit tests работают с bytes.
pub struct PinnedResolverSnapshot {
    sources: [ResolverSource; 4],
    servers: Vec<SocketAddr>,
    digest: [u8; 32],
    asset: Vec<u8>,
    asset_hash: [u8; 32],
    source_flags: u32,
    invalid: std::sync::atomic::AtomicBool,
    _memory: super::memory::ByteLease,
}
impl PinnedResolverSnapshot {
    pub(crate) fn server_endpoints(&self) -> &[SocketAddr] {
        &self.servers
    }
    pub fn capture(cancel: &Cancellation) -> Result<Self, EgressError> {
        check_cancel(cancel)?;
        let memory = super::memory::config_budget()
            .reserve(2 * 1024 * 1024)
            .map_err(|_| EgressError::Budget)?;
        let sources = [
            ResolverSource::capture("/etc/nsswitch.conf", 65536, false, false, cancel)?,
            ResolverSource::capture("/etc/resolv.conf", 65536, false, false, cancel)?,
            ResolverSource::capture("/etc/hosts", 1024 * 1024, true, false, cancel)?,
            ResolverSource::capture("/proc/sys/kernel/hostname", 254, false, true, cancel)?,
        ];
        let data = resolver_snapshot_data(
            &sources[0].bytes,
            &sources[1].bytes,
            sources[2]
                .file
                .as_ref()
                .map(|_| sources[2].bytes.as_slice()),
            &sources[3].bytes,
        )?;
        let asset = data.encode().map_err(|_| EgressError::Resolver)?;
        let asset_hash = Sha256::digest(&asset).into();
        let digest = data.source;
        let source_flags = data.source_flags;
        let servers = data.peers.clone();
        let result = Self {
            sources,
            servers,
            digest,
            asset,
            asset_hash,
            source_flags,
            invalid: std::sync::atomic::AtomicBool::new(false),
            _memory: memory,
        };
        let reference = result.reference();
        crate::profile_channel::verify_resolver_asset(&result.asset, reference)
            .map_err(|_| EgressError::Resolver)?;
        for source in &result.sources {
            source.validate_handles()?;
        }
        Ok(result)
    }
    pub fn revalidate(&self, cancel: &Cancellation) -> Result<(), EgressError> {
        revalidate_source(&self.invalid, || self.revalidate_inner(cancel))
    }
    fn revalidate_inner(&self, cancel: &Cancellation) -> Result<(), EgressError> {
        let current = Self::capture(cancel)?;
        if current.digest != self.digest
            || current.asset_hash != self.asset_hash
            || !current
                .sources
                .iter()
                .zip(&self.sources)
                .all(|(a, b)| a.same(b))
        {
            return Err(EgressError::Stale);
        }
        for source in &self.sources {
            source.validate_handles()?;
        }
        Ok(())
    }
    pub fn asset_bytes(&self) -> &[u8] {
        &self.asset
    }
    pub(crate) fn reference(&self) -> crate::profile_channel::SnapshotRef {
        crate::profile_channel::SnapshotRef {
            source: self.digest,
            asset: self.asset_hash,
            bytes: self.asset.len() as u32,
            flags: self.source_flags,
        }
    }
}
impl yonik_engine::native_profile::VerifiedSystemResolver for PinnedResolverSnapshot {
    fn snapshot_digest(&self) -> [u8; 32] {
        if self.invalid.load(std::sync::atomic::Ordering::Acquire) {
            return [0; 32];
        }
        self.digest
    }
    fn servers(&self) -> Vec<SocketAddr> {
        self.servers.clone()
    }
}
fn resolver_snapshot_data(
    nss: &[u8],
    resolv: &[u8],
    hosts: Option<&[u8]>,
    hostname: &[u8],
) -> Result<crate::profile_channel::ResolverData, EgressError> {
    use crate::profile_channel::{ResolverData, ResolverHost};
    if nss.len() > 65536
        || resolv.len() > 65536
        || hosts.is_some_and(|h| h.len() > 1024 * 1024)
        || hostname.len() > 253
    {
        return Err(EgressError::Budget);
    }
    // net/parse.go::file.readLine не растит fixed 64KiB buffer: слишком
    // длинная строка остановила бы pinned reader. Не разбирать её иначе.
    if [nss, resolv, hosts.unwrap_or_default()]
        .iter()
        .any(|source| {
            source
                .split(|b| *b == b'\n')
                .any(|line| line.len() >= 65536)
        })
    {
        return Err(EgressError::Budget);
    }
    // Raw retained sources + parsed aliases + canonical asset/readback scratch.
    let memory = super::memory::config_budget()
        .reserve(8 * 1024 * 1024)
        .map_err(|_| EgressError::Budget)?;
    fn ascii(bytes: &[u8]) -> Result<&str, EgressError> {
        if !bytes.is_ascii()
            || bytes
                .iter()
                .any(|b| b.is_ascii_control() && ![b'\n', b'\r', b'\t'].contains(b))
        {
            return Err(EgressError::Resolver);
        }
        std::str::from_utf8(bytes).map_err(|_| EgressError::Resolver)
    }
    fn name(value: &str, root: bool, lower: bool) -> Result<String, EgressError> {
        if value.is_empty()
            || value.len() > 253
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || [b'.', b'-', b'_'].contains(&b))
        {
            return Err(EgressError::Resolver);
        }
        let mut result = if lower {
            value.to_ascii_lowercase()
        } else {
            value.to_owned()
        };
        if root && !result.ends_with('.') {
            if result.len() == 253 {
                return Err(EgressError::Budget);
            }
            result.push('.');
        }
        crate::profile_channel::resolver_name(&result, root, lower)
            .map_err(|_| EgressError::Resolver)?;
        Ok(result)
    }
    let host = ascii(hostname)?;
    let mut data = ResolverData {
        source: [0; 32],
        source_flags: u32::from(hosts.is_none()),
        nss_hash: Sha256::digest(nss).into(),
        hosts_hash: Sha256::digest(hosts.unwrap_or_default()).into(),
        resolv_hash: Sha256::digest(resolv).into(),
        order: resolver_nss_order(ascii(nss)?)?,
        ndots: 1,
        attempts: 2,
        timeout_ms: 5000,
        flags: 16,
        hostname: name(host, false, false)?,
        search: Vec::new(),
        peers: Vec::new(),
        hosts: Vec::new(),
        _memory: memory,
    };
    for line in ascii(resolv)?.lines() {
        // dnsReadConfig считает comment только в первом byte всей строки.
        // Inline search comments нельзя молча вырезать и менять search list.
        if line.starts_with(['#', ';']) {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        match fields.next() {
            None => {}
            Some("nameserver") => {
                if data.peers.len() == 3 {
                    continue;
                }
                let Some(value) = fields.next() else { continue };
                // netip.ParseAddr accepts zones; selected zone cannot be encoded.
                if let Some((ip, zone)) = value.split_once('%') {
                    if ip.parse::<std::net::Ipv6Addr>().is_ok() && !zone.is_empty() {
                        return Err(EgressError::Resolver);
                    }
                }
                let Ok(ip) = value.parse::<IpAddr>() else {
                    continue;
                };
                if ip.is_unspecified()
                    || ip.is_multicast()
                    || matches!(ip,IpAddr::V4(ip) if ip.is_broadcast())
                    || matches!(ip,IpAddr::V6(ip) if ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some())
                {
                    return Err(EgressError::Resolver);
                }
                data.peers.push(SocketAddr::new(ip, 53));
            }
            Some("search") => {
                data.search.clear();
                for field in fields {
                    if field == "." {
                        continue;
                    }
                    if data.search.len() == 6 {
                        return Err(EgressError::Budget);
                    }
                    data.search.push(name(field, true, false)?);
                }
            }
            Some("domain") => {
                if let Some(field) = fields.next() {
                    data.search.clear();
                    data.search.push(name(field, true, false)?);
                }
            }
            Some("options") => {
                for option in fields {
                    match option {
                        "rotate" => data.flags |= 1,
                        "single-request" | "single-request-reopen" => data.flags |= 2,
                        "use-vc" | "usevc" | "tcp" => data.flags |= 4,
                        "trust-ad" => data.flags |= 8,
                        "edns0" | "no-reload" => {}
                        _ => {
                            let (key, value) =
                                option.split_once(':').ok_or(EgressError::Resolver)?;
                            // net/parse.go::dtoi насыщается на 0xffffff;
                            // отрицательный prefix даёт 0, а не signed integer.
                            // Повреждённые/trailing формы, терпимые Go, закрыты
                            // capture policy: они не становятся новой grammar.
                            let digits = value.strip_prefix('-').unwrap_or(value);
                            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                                return Err(EgressError::Resolver);
                            }
                            let n = if value.starts_with('-') {
                                0
                            } else {
                                digits
                                    .bytes()
                                    .fold(0u32, |n, b| (n * 10 + u32::from(b - b'0')).min(0xffffff))
                            };
                            match key {
                                "ndots" => data.ndots = n.min(15) as u8,
                                "attempts" if n.max(1) <= 5 => data.attempts = n.max(1) as u8,
                                "timeout" if n.max(1) <= 30 => data.timeout_ms = n.max(1) * 1000,
                                _ => return Err(EgressError::Resolver),
                            }
                        }
                    }
                }
            }
            Some(_) => return Err(EgressError::Resolver),
        }
    }
    if data.peers.is_empty() {
        data.peers
            .push(SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 53));
        data.peers
            .push(SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 53));
    }
    if data.search.is_empty() {
        if let Some((_, suffix)) = host.split_once('.') {
            if !suffix.is_empty() {
                data.search.push(name(suffix, true, false)?);
            }
        }
    }
    let mut aliases = std::collections::BTreeMap::<String, usize>::new();
    if let Some(hosts) = hosts {
        for line in ascii(hosts)?.lines() {
            let mut fields = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_ascii_whitespace();
            let Some(address) = fields.next() else {
                continue;
            };
            // readHosts пропускает len(fields)<2 до parseLiteralIP: zone или
            // mapped literal без alias не является записью и не даёт отказ.
            let Some(first_alias) = fields.next() else {
                continue;
            };
            if let Some((ip, zone)) = address.split_once('%') {
                if ip.parse::<std::net::Ipv6Addr>().is_ok() && !zone.is_empty() {
                    return Err(EgressError::Resolver);
                }
            }
            let Ok(ip) = address.parse::<IpAddr>() else {
                continue;
            };
            if matches!(ip,IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()) {
                return Err(EgressError::Resolver);
            }
            for alias in std::iter::once(first_alias).chain(fields) {
                // Canonical lookup на stack: 4097-я unique alias не аллоцирует
                // String до проверки cap; повторные aliases не копируют keys.
                if alias.is_empty()
                    || alias.len() > 253
                    || !alias
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || [b'.', b'-', b'_'].contains(&b))
                {
                    return Err(EgressError::Resolver);
                }
                let mut canonical = [0u8; 254];
                for (out, input) in canonical.iter_mut().zip(alias.bytes()) {
                    *out = input.to_ascii_lowercase();
                }
                let mut length = alias.len();
                if alias.contains('.') && !alias.ends_with('.') {
                    if length == 253 {
                        return Err(EgressError::Budget);
                    }
                    canonical[length] = b'.';
                    length += 1;
                }
                let alias =
                    std::str::from_utf8(&canonical[..length]).map_err(|_| EgressError::Resolver)?;
                crate::profile_channel::resolver_name(alias, alias.contains('.'), true)
                    .map_err(|_| EgressError::Resolver)?;
                let index = match aliases.get(alias) {
                    Some(index) => *index,
                    None => {
                        if data.hosts.len() == 4096 {
                            return Err(EgressError::Budget);
                        }
                        let index = data.hosts.len();
                        aliases.insert(alias.to_owned(), index);
                        data.hosts.push(ResolverHost {
                            alias: alias.to_owned(),
                            addresses: Vec::new(),
                        });
                        index
                    }
                };
                let addresses = &mut data.hosts[index].addresses;
                if addresses.len() == 16 {
                    return Err(EgressError::Budget);
                }
                addresses.push(ip);
            }
        }
    }
    let mut hash = Sha256::new();
    hash.update(b"YONIK-RESOLVER-SOURCES-v2\0");
    for source in [nss, resolv] {
        hash.update((source.len() as u32).to_be_bytes());
        hash.update(source);
    }
    hash.update([u8::from(hosts.is_some())]);
    for source in [hosts.unwrap_or_default(), hostname] {
        hash.update((source.len() as u32).to_be_bytes());
        hash.update(source);
    }
    hash.update(1u16.to_be_bytes());
    data.source = hash.finalize().into();
    Ok(data)
}
fn resolver_nss_order(nss: &str) -> Result<u8, EgressError> {
    // net/nss.go::parseNSSConf дописывает повторные databases. Храним
    // только hosts sources, но проверяем grammar остальных строк: их ошибка
    // в Go инвалидирует весь nssConf. Никаких NSS plugins здесь нет.
    let mut names = [""; 64];
    let mut count = 0;
    for line in nss.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (database, mut sources) = line.split_once(':').ok_or(EgressError::Resolver)?;
        loop {
            sources = sources.trim_matches([' ', '\t', '\r']);
            if sources.is_empty() {
                break;
            }
            // Именно literal space, как в Go1.27.1. Внутренний TAB остаётся
            // частью unknown source; files\tdns НЕ означает files + dns.
            let n = sources.find(' ').unwrap_or(sources.len());
            let source = &sources[..n];
            if !source
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || [b'_', b'-', b'\t'].contains(&b))
            {
                return Err(EgressError::Resolver);
            }
            if database.trim() == "hosts" {
                if count == names.len() {
                    return Err(EgressError::Budget);
                }
                names[count] = source;
                count += 1;
            }
            sources = sources[n..].trim_start_matches([' ', '\t', '\r']);
            if let Some(criteria) = sources.strip_prefix('[') {
                let end = criteria.find(']').ok_or(EgressError::Resolver)?;
                for criterion in criteria[..end].split_ascii_whitespace() {
                    let (status, action) =
                        criterion.split_once('=').ok_or(EgressError::Resolver)?;
                    let status = status.strip_prefix('!').unwrap_or(status);
                    if !["SUCCESS", "NOTFOUND", "UNAVAIL", "TRYAGAIN"]
                        .iter()
                        .any(|s| status.eq_ignore_ascii_case(s))
                        || !["return", "continue"]
                            .iter()
                            .any(|a| action.eq_ignore_ascii_case(a))
                    {
                        return Err(EgressError::Resolver);
                    }
                }
                // lookupOrder проверяет standardCriteria только canUseCgo.
                // В закрытом CGO0 режиме recognized actions не меняют order.
                sources = &criteria[end + 1..];
            }
        }
    }
    let names = &names[..count];
    if names.is_empty() {
        return Ok(3);
    }
    let explicit_dns = names.contains(&"dns");
    let mut first = None;
    let mut files = false;
    let mut dns = false;
    for &source in names {
        match source {
            "files" => {
                files = true;
                first.get_or_insert(1);
            }
            "dns" => {
                dns = true;
                first.get_or_insert(2);
            }
            _ if !explicit_dns => {
                dns = true;
                first.get_or_insert(2);
            }
            _ => {}
        }
    }
    Ok(match (files, dns, first) {
        (true, true, Some(1)) => 3,
        (true, true, _) => 4,
        (true, false, _) => 1,
        (false, true, _) => 2,
        _ => 3,
    })
}
/// Отдельно от DNS: resolver requirement не становится firewall exception.
pub struct PhysicalRequirements<'a> {
    plan: &'a EgressPlan,
}
impl<'a> PhysicalRequirements<'a> {
    pub(crate) fn validate_numeric(&self) -> Result<(), EgressError> {
        for endpoint in self.endpoints() {
            numeric(endpoint)?;
        }
        Ok(())
    }
    pub fn new(plan: &'a EgressPlan) -> Result<Self, EgressError> {
        // Тот же верхний предел, что у firewall. DNS/LAN потребляют оставшийся
        // бюджет отдельно в PublicBlockPolicy::new, до dedup.
        if plan.physical().len() > 128 {
            return Err(EgressError::Budget);
        }
        Ok(Self { plan })
    }
    pub fn endpoints(&self) -> &'a [PhysicalEndpoint] {
        self.plan.physical()
    }

    pub fn provider_resolvers(&self) -> &'a [yonik_engine::native_profile::ResolverRequirement] {
        self.plan.resolvers()
    }

    pub fn system_resolvers(
        &self,
    ) -> &'a [yonik_engine::native_profile::SystemResolverRequirement] {
        self.plan.system_resolvers()
    }

    /// Только numeric leaves. Host проверяет namespace/table/mark и сохраняет
    /// полный route capture в T; возвращённый ifindex сам по себе не proof.
    /// Hostname требует отдельного DNS provenance bridge, его здесь нет.
    pub fn capture_numeric<T>(
        &self,
        worker_uid: u32,
        mark: u32,
        cancel: &Cancellation,
        mut capture: impl FnMut(SocketAddr, TransportProtocol) -> Result<(u32, T), EgressError>,
    ) -> Result<CapturedPhysicalRoutes<T>, EgressError> {
        check_cancel(cancel)?;
        if worker_uid == 0 || worker_uid == u32::MAX || mark == 0 {
            return Err(EgressError::InvalidBinding);
        }
        // Полная проверка адресов до первого host query и выделения вектора.
        for endpoint in self.endpoints() {
            numeric(endpoint)?;
        }
        let mut routes = Vec::with_capacity(self.endpoints().len());
        for endpoint in self.endpoints() {
            check_cancel(cancel)?;
            let address = numeric(endpoint)?;
            let protocol = match endpoint.protocol() {
                yonik_engine::native_profile::TransportProtocol::Tcp => TransportProtocol::Tcp,
                yonik_engine::native_profile::TransportProtocol::Udp => TransportProtocol::Udp,
            };
            let (ifindex, snapshot) = capture(SocketAddr::new(address, endpoint.port()), protocol)?;
            check_cancel(cancel)?;
            let transport = BoundTransport::new(
                address,
                protocol,
                endpoint.port(),
                ifindex,
                worker_uid,
                mark,
            )
            .map_err(|_| EgressError::InvalidBinding)?;
            routes.push((transport, snapshot));
        }
        check_cancel(cancel)?;
        Ok(CapturedPhysicalRoutes {
            routes,
            invalid: false,
        })
    }
}

fn numeric(endpoint: &PhysicalEndpoint) -> Result<IpAddr, EgressError> {
    let ip: IpAddr = endpoint
        .host()
        .parse()
        .map_err(|_| EgressError::BootstrapRequired)?;
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast() || ip.is_link_local())
        || matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local() || ip.to_ipv4().is_some())
    {
        return Err(EgressError::InvalidEndpoint);
    }
    Ok(ip)
}
fn check_cancel(cancel: &Cancellation) -> Result<(), EgressError> {
    cancel.check().map_err(|_| EgressError::Cancelled)
}

/// Bounded route observations. Это не session admission и не владелец worker.
/// Любая неудачная повторная проверка необратимо инвалидирует весь набор.
pub struct CapturedPhysicalRoutes<T> {
    routes: Vec<(BoundTransport, T)>,
    invalid: bool,
}
impl<T> CapturedPhysicalRoutes<T> {
    pub fn revalidate(
        &mut self,
        cancel: &Cancellation,
        mut verify: impl FnMut(&T) -> Result<(), EgressError>,
    ) -> Result<(), EgressError> {
        if self.invalid {
            return Err(EgressError::Stale);
        }
        // Инвалидация предшествует callbacks: ошибка/отмена не возвращает
        // частично проверенный набор вызывающему коду.
        self.invalid = true;
        check_cancel(cancel)?;
        for (_, snapshot) in &self.routes {
            check_cancel(cancel)?;
            verify(snapshot)?;
            check_cancel(cancel)?;
        }
        self.invalid = false;
        Ok(())
    }
    pub fn transports(&self) -> Result<impl Iterator<Item = BoundTransport> + '_, EgressError> {
        if self.invalid {
            return Err(EgressError::Stale);
        }
        Ok(self.routes.iter().map(|(transport, _)| *transport))
    }
}

/// Удерживает ровно один compiler result с его случайными probe credentials.
/// Identity — DATA binding; не подтверждает selection, resources или native grants.
pub struct RetainedSystemProfile {
    compiled: yonik_engine::native_profile::CompiledProfileSystem,
    digest: [u8; 32],
    generation: u64,
    selection: [u8; 32],
}
impl RetainedSystemProfile {
    pub fn seal(
        compiled: yonik_engine::native_profile::CompiledProfileSystem,
        generation: u64,
        selection: [u8; 32],
    ) -> Result<Self, EgressError> {
        if generation == 0 || selection == [0; 32] {
            return Err(EgressError::InvalidBinding);
        }
        let mut writer = DigestWriter {
            digest: Sha256::new(),
            bytes: 0,
        };
        compiled
            .config()
            .write_sensitive(&mut writer)
            .map_err(|_| EgressError::Encoding)?;
        Ok(Self {
            compiled,
            digest: writer.digest.finalize().into(),
            generation,
            selection,
        })
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn compiled(&self) -> &yonik_engine::native_profile::CompiledProfileSystem {
        &self.compiled
    }
    pub fn matches(&self, generation: u64, selection: [u8; 32], digest: [u8; 32]) -> bool {
        self.generation == generation && self.selection == selection && self.digest == digest
    }
    pub fn into_compiled(self) -> yonik_engine::native_profile::CompiledProfileSystem {
        self.compiled
    }
}
struct DigestWriter {
    digest: Sha256,
    bytes: usize,
}
impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= super::MAX_ARTIFACT_BYTES)
            .ok_or_else(|| io::Error::other("Превышен бюджет runtime config"))?;
        self.digest.update(bytes);
        self.bytes = total;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "profile_intent_tests.rs"]
mod tests;
