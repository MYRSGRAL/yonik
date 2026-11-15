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
    _memory: super::memory::ByteLease,
}
impl FullProfileRequest {
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
    for requirement in requirements {
        let mut parts = requirement.category().split('@');
        let code = parts
            .next()
            .ok_or(EgressError::Resource)?
            .to_ascii_uppercase();
        if requirement.kind() != reference.kind
            || !categories.contains(code.as_str())
            || parts.any(str::is_empty)
        {
            return Err(EgressError::Resource);
        }
    }
    Ok(())
}

/// Exact source files pinned отдельно от provider DNS. Этот snapshot ещё должен
/// быть принят native carrier; live fallback по нему не разрешается.
pub struct PinnedResolverSnapshot {
    files: [std::fs::File; 2],
    stamps: [SourceStamp; 2],
    bytes: [Vec<u8>; 2],
    servers: Vec<SocketAddr>,
    digest: [u8; 32],
    _memory: super::memory::ByteLease,
}
impl PinnedResolverSnapshot {
    pub fn capture(cancel: &Cancellation) -> Result<Self, EgressError> {
        check_cancel(cancel)?;
        use rustix::fs::{Mode, OFlags, open};
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        let resolv = std::fs::File::from(
            open("/etc/resolv.conf", flags, Mode::empty()).map_err(|_| EgressError::Resolver)?,
        );
        let nss = std::fs::File::from(
            open("/etc/nsswitch.conf", flags, Mode::empty()).map_err(|_| EgressError::Resolver)?,
        );
        let files = [resolv, nss];
        let stamps = [source_stamp(&files[0])?, source_stamp(&files[1])?];
        let memory = super::memory::config_budget()
            .reserve(128 * 1024)
            .map_err(|_| EgressError::Budget)?;
        let bytes = [
            read_pinned(&files[0], &stamps[0], 65536, cancel)?,
            read_pinned(&files[1], &stamps[1], 65536, cancel)?,
        ];
        let (servers, digest) = resolver_content(&bytes[0], &bytes[1])?;
        Ok(Self {
            files,
            stamps,
            bytes,
            servers,
            digest,
            _memory: memory,
        })
    }
    pub fn revalidate(&self, cancel: &Cancellation) -> Result<(), EgressError> {
        let current = Self::capture(cancel)?;
        if current.digest != self.digest
            || current.stamps != self.stamps
            || current.bytes != self.bytes
        {
            return Err(EgressError::Stale);
        }
        for (file, stamp) in self.files.iter().zip(&self.stamps) {
            if source_stamp(file)? != *stamp {
                return Err(EgressError::Stale);
            }
        }
        Ok(())
    }
}
impl yonik_engine::native_profile::VerifiedSystemResolver for PinnedResolverSnapshot {
    fn snapshot_digest(&self) -> [u8; 32] {
        self.digest
    }
    fn servers(&self) -> Vec<SocketAddr> {
        self.servers.clone()
    }
}
fn resolver_content(resolv: &[u8], nss: &[u8]) -> Result<(Vec<SocketAddr>, [u8; 32]), EgressError> {
    if resolv.len() > 65536 || nss.len() > 65536 {
        return Err(EgressError::Budget);
    }
    // Единственная поддержанная NSS grammar исключает files/mDNS/resolve и
    // dynamic modules. Расширение требует custody всех дополнительных sources.
    let nss = std::str::from_utf8(nss).map_err(|_| EgressError::Resolver)?;
    let mut hosts = nss
        .lines()
        .filter_map(|line| line.split('#').next())
        .filter_map(|line| line.split_once(':'))
        .filter_map(|(database, sources)| (database.trim() == "hosts").then_some(sources));
    if hosts.next().map(str::trim) != Some("dns") || hosts.next().is_some() {
        return Err(EgressError::Resolver);
    }
    let mut servers = Vec::new();
    for line in std::str::from_utf8(resolv)
        .map_err(|_| EgressError::Resolver)?
        .lines()
    {
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") || servers.len() >= 16 {
            return Err(EgressError::Resolver);
        }
        let ip: IpAddr = fields
            .next()
            .ok_or(EgressError::Resolver)?
            .parse()
            .map_err(|_| EgressError::Resolver)?;
        if fields.next().is_some()
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip,IpAddr::V6(ip) if ip.is_unicast_link_local()||ip.to_ipv4().is_some())
        {
            return Err(EgressError::Resolver);
        }
        servers.push(SocketAddr::new(ip, 53));
    }
    if servers.is_empty() {
        return Err(EgressError::Resolver);
    }
    let mut digest = Sha256::new();
    digest.update(b"YONIK-RESOLVER-SOURCES-v1\0");
    digest.update((resolv.len() as u64).to_be_bytes());
    digest.update(resolv);
    digest.update((nss.len() as u64).to_be_bytes());
    digest.update(nss.as_bytes());
    Ok((servers, digest.finalize().into()))
}

/// Отдельно от DNS: resolver requirement не становится firewall exception.
pub struct PhysicalRequirements<'a> {
    plan: &'a EgressPlan,
}
impl<'a> PhysicalRequirements<'a> {
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
