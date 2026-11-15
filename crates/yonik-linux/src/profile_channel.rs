//! Закрытый versioned sideband. Decode/manifest — DATA, не runtime authority.

use sha2::{Digest, Sha256};

pub(crate) const FRAME_LIMIT: usize = 65536;
const HEADER: usize = 128;
const NONE: u16 = u16::MAX;
pub(crate) const CONTROL_FD_LOCATOR: &str = "YONIK_PROFILE_CONTROL_FD";
pub(crate) const LAUNCH_FD_LOCATOR: &str = "YONIK_PROFILE_LAUNCH_FD";
pub(crate) const PEER_PIDFD_LOCATOR: &str = "YONIK_PROFILE_PEER_PIDFD";
pub(crate) const ASSET_ROOT_FD_LOCATOR: &str = "YONIK_PROFILE_ASSET_ROOT_FD";

#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerIdentity {
    pid: u32,
    uid: u32,
    start: u64,
}
struct AncillaryShape {
    credentials: usize,
    rights: usize,
    truncated: bool,
    seqpacket: bool,
    peer: PeerIdentity,
}
impl AncillaryShape {
    /// Только проверка формы. OS wrapper обязан удерживать и проверять pidfd,
    /// закрывать все unexpected rights и получать observation самостоятельно.
    fn validate(&self, expected: PeerIdentity, expected_rights: usize) -> Result<()> {
        if self.credentials != 1
            || self.rights != expected_rights
            || self.truncated
            || !self.seqpacket
            || self.peer != expected
            || expected.pid == 0
            || expected.start == 0
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Bounds,
    Schema,
    Binding,
    Hash,
    Reference,
    Budget,
}
type Result<T> = std::result::Result<T, Error>;

macro_rules! wire_enum {
    ($name:ident, $ty:ty, $($variant:ident = $value:expr),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr($ty)]
        pub(crate) enum $name { $($variant = $value),+ }
        impl TryFrom<$ty> for $name {
            type Error = Error;
            fn try_from(value: $ty) -> Result<Self> {
                match value { $($value => Ok(Self::$variant),)+ _ => Err(Error::Schema) }
            }
        }
    }
}
wire_enum!(Mode, u8, Local = 1, System = 2);
impl Mode {
    pub(crate) fn required(self) -> bool {
        self == Self::System
    }
}
wire_enum!(
    Kind,
    u16,
    Hello = 1,
    Admit = 2,
    AdmitAck = 3,
    OpenIngress = 16,
    IngressReply = 17,
    Authorize = 18,
    Grant = 19,
    Probe = 20,
    Renew = 21,
    Deny = 22,
    Cancel = 32,
    Revoke = 33,
    CloseAck = 34
);
wire_enum!(Status, u8, Allow = 1, Deny = 2, Unknown = 3);
wire_enum!(CloseStatus, u8, KnownClosed = 1, Unknown = 3);
wire_enum!(
    ReceiptKind,
    u8,
    None = 0,
    FrozenSent = 1,
    SidebandOperation = 2
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub session: [u8; 16],
    pub invocation: [u8; 16],
    pub digest: [u8; 32],
    pub generation: u64,
    pub epoch: u64,
}
impl Binding {
    fn validate(self) -> Result<()> {
        if self.session == [0; 16]
            || self.invocation == [0; 16]
            || self.digest == [0; 32]
            || self.generation == 0
            || self.epoch == 0
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub kind: Kind,
    pub sequence: u64,
    pub reply_to: u64,
    pub binding: Binding,
    pub object_id: u64,
}
impl Header {
    pub(crate) fn encode(self, body_len: usize) -> Result<[u8; HEADER]> {
        self.binding.validate()?;
        let total = HEADER
            .checked_add(body_len)
            .filter(|n| *n <= FRAME_LIMIT)
            .ok_or(Error::Bounds)?;
        if self.sequence == 0 {
            return Err(Error::Schema);
        }
        let mut out = [0; HEADER];
        out[..8].copy_from_slice(b"YNKCAP01");
        put16(&mut out, 8, 1);
        put16(&mut out, 10, self.kind as u16);
        put32(&mut out, 12, total as u32);
        put64(&mut out, 16, self.sequence);
        put64(&mut out, 24, self.reply_to);
        out[32..48].copy_from_slice(&self.binding.session);
        out[48..64].copy_from_slice(&self.binding.invocation);
        out[64..96].copy_from_slice(&self.binding.digest);
        put64(&mut out, 96, self.binding.generation);
        put64(&mut out, 104, self.binding.epoch);
        put64(&mut out, 112, self.object_id);
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8], total: usize) -> Result<Self> {
        if bytes.len() != HEADER || !(HEADER..=FRAME_LIMIT).contains(&total) {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(bytes);
        if r.take(8)? != b"YNKCAP01" || r.u16()? != 1 {
            return Err(Error::Schema);
        }
        let kind = Kind::try_from(r.u16()?)?;
        if r.u32()? as usize != total {
            return Err(Error::Bounds);
        }
        let sequence = r.u64()?;
        let reply_to = r.u64()?;
        let binding = Binding {
            session: r.array()?,
            invocation: r.array()?,
            digest: r.array()?,
            generation: r.u64()?,
            epoch: r.u64()?,
        };
        let object_id = r.u64()?;
        r.zero(8)?;
        r.end()?;
        binding.validate()?;
        if sequence == 0 {
            return Err(Error::Schema);
        }
        Ok(Self {
            kind,
            sequence,
            reply_to,
            binding,
            object_id,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LaunchRecord {
    pub mode: Mode,
    pub nonce: [u8; 32],
    pub binding: Binding,
    pub owner_pid: u32,
    pub child_pid: u32,
    pub owner_start: u64,
    pub child_start: u64,
    pub manifest: [u8; 32],
}
impl LaunchRecord {
    pub(crate) fn encode(self) -> Result<[u8; 192]> {
        self.binding.validate()?;
        if self.nonce == [0; 32]
            || self.manifest == [0; 32]
            || self.owner_pid == 0
            || self.owner_start == 0
            || match self.mode {
                Mode::Local => self.child_pid != 0 || self.child_start != 0,
                Mode::System => self.child_pid == 0 || self.child_start == 0,
            }
        {
            return Err(Error::Binding);
        }
        let mut out = [0; 192];
        out[..8].copy_from_slice(match self.mode {
            Mode::Local => b"YNKLOC01",
            Mode::System => b"YNKEXT01",
        });
        put16(&mut out, 8, 1);
        put16(&mut out, 10, 192);
        put16(&mut out, 12, u16::from(self.mode.required()));
        out[16..48].copy_from_slice(&self.nonce);
        out[48..80].copy_from_slice(&self.binding.digest);
        out[80..96].copy_from_slice(&self.binding.session);
        out[96..112].copy_from_slice(&self.binding.invocation);
        put64(&mut out, 112, self.binding.generation);
        put64(&mut out, 120, self.binding.epoch);
        put32(&mut out, 128, self.owner_pid);
        put32(&mut out, 132, self.child_pid);
        put64(&mut out, 136, self.owner_start);
        put64(&mut out, 144, self.child_start);
        out[152..184].copy_from_slice(&self.manifest);
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8], expected: Mode) -> Result<Self> {
        if bytes.len() != 192 {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(bytes);
        if r.take(8)?
            != match expected {
                Mode::Local => b"YNKLOC01",
                Mode::System => b"YNKEXT01",
            }
            || r.u16()? != 1
            || r.u16()? != 192
            || r.u16()? != u16::from(expected.required())
        {
            return Err(Error::Schema);
        }
        r.zero(2)?;
        let nonce = r.array()?;
        let digest = r.array()?;
        let session = r.array()?;
        let invocation = r.array()?;
        let binding = Binding {
            digest,
            session,
            invocation,
            generation: r.u64()?,
            epoch: r.u64()?,
        };
        let record = Self {
            mode: expected,
            nonce,
            binding,
            owner_pid: r.u32()?,
            child_pid: r.u32()?,
            owner_start: r.u64()?,
            child_start: r.u64()?,
            manifest: r.array()?,
        };
        r.zero(8)?;
        r.end()?;
        record.encode()?;
        Ok(record)
    }
    pub(crate) fn ack(self) -> Result<[u8; 40]> {
        let mut ack = [0; 40];
        ack[..8].copy_from_slice(b"YNKEXAK1");
        ack[8..].copy_from_slice(&Sha256::digest(self.encode()?));
        Ok(ack)
    }
    pub(crate) fn verify_ack(self, bytes: &[u8]) -> Result<()> {
        if bytes != self.ack()? {
            return Err(Error::Hash);
        }
        Ok(())
    }
}

fn put16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

const TABLE_CAPS: [usize; 11] = [256, 512, 1024, 256, 64, 16, 4, 1, 512, 16, 1];
const MAX_CAPS: [u32; 8] = [4096, 128, 128, 64, 8 * 1024 * 1024, 30000, 4096, 256];

struct MemoryPreflight {
    metadata: usize,
    buffer_bytes: usize,
}
impl MemoryPreflight {
    fn new(caps: [u32; 8], capsule_bytes: usize) -> Result<Self> {
        for (actual, max) in caps.iter().zip(MAX_CAPS) {
            if *actual == 0 || *actual > max {
                return Err(Error::Budget);
            }
        }
        // Payload и fixed scratch учитываются одновременно с будущими ledgers.
        let mut metadata = capsule_bytes
            .checked_add(2 * FRAME_LIMIT)
            .and_then(|n| n.checked_add(std::mem::size_of::<Capsule<'_>>() + 32768))
            .ok_or(Error::Budget)?;
        for (count, width) in [
            (caps[3], 2 * 1024),
            (caps[3], 2048),
            (caps[7], 64),
            (caps[6], 192),
            (caps[0], 256),
            (caps[2], 1024),
            (caps[1], 512),
            (caps[0], 128),
            (64, 128),
        ] {
            metadata = metadata
                .checked_add((count as usize).checked_mul(width).ok_or(Error::Budget)?)
                .ok_or(Error::Budget)?;
        }
        let buffer_bytes = (caps[4] as usize)
            .checked_sub(metadata)
            .ok_or(Error::Budget)?;
        Ok(Self {
            metadata,
            buffer_bytes,
        })
    }
}

/// Только reference DATA. Владение asset/source проверяет отдельный issuer.
#[derive(Clone, Copy)]
pub(crate) struct SnapshotRef {
    pub source: [u8; 32],
    pub asset: [u8; 32],
    pub bytes: u32,
    pub flags: u32,
}
pub(crate) struct ResolverHost {
    pub alias: String,
    pub addresses: Vec<std::net::IpAddr>,
}
/// Только canonical DATA. Source FDs и env/image proofs удерживает producer.
pub(crate) struct ResolverData {
    pub source: [u8; 32],
    pub source_flags: u32,
    pub nss_hash: [u8; 32],
    pub hosts_hash: [u8; 32],
    pub resolv_hash: [u8; 32],
    pub order: u8,
    pub ndots: u8,
    pub attempts: u8,
    pub timeout_ms: u32,
    pub flags: u16,
    pub hostname: String,
    pub search: Vec<String>,
    pub peers: Vec<std::net::SocketAddr>,
    pub hosts: Vec<ResolverHost>,
    pub _memory: crate::helper::memory::ByteLease,
}
impl ResolverData {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.search.len() > 6
            || !(1..=3).contains(&self.peers.len())
            || self.hosts.len() > 4096
            || self.source_flags & !1 != 0
            || self.source_flags == 1 && !self.hosts.is_empty()
        {
            return Err(Error::Budget);
        }
        resolver_name(&self.hostname, false, false)?;
        for search in &self.search {
            resolver_name(search, true, false)?;
        }
        for host in &self.hosts {
            resolver_name(&host.alias, host.alias.contains('.'), true)?;
            if !(1..=16).contains(&host.addresses.len()) {
                return Err(Error::Budget);
            }
        }
        // Worst-case encoded size bounded до reserve: не realloc после overflow.
        let mut size = 170 + self.hostname.len();
        for search in &self.search {
            size = size.checked_add(2 + search.len()).ok_or(Error::Budget)?;
        }
        for peer in &self.peers {
            size = size
                .checked_add(if peer.is_ipv4() { 8 } else { 20 })
                .ok_or(Error::Budget)?;
        }
        for host in &self.hosts {
            size = size
                .checked_add(4 + host.alias.len())
                .ok_or(Error::Budget)?;
            for ip in &host.addresses {
                size = size
                    .checked_add(if ip.is_ipv4() { 5 } else { 17 })
                    .ok_or(Error::Budget)?;
            }
        }
        if size > 2 * 1024 * 1024 {
            return Err(Error::Budget);
        }
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(b"YNKDNS01");
        out.extend_from_slice(&[0, 1, 0, 120]);
        out.extend_from_slice(&(size as u32).to_be_bytes());
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.nss_hash);
        out.extend_from_slice(&self.hosts_hash);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&self.resolv_hash);
        out.extend_from_slice(&[self.order, self.ndots, self.attempts, 0]);
        out.extend_from_slice(&self.timeout_ms.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        string(&mut out, &self.hostname, 253)?;
        out.extend_from_slice(&(self.search.len() as u16).to_be_bytes());
        for search in &self.search {
            string(&mut out, search, 253)?;
        }
        out.extend_from_slice(&(self.peers.len() as u16).to_be_bytes());
        for peer in &self.peers {
            out.extend_from_slice(&[if peer.is_ipv4() { 4 } else { 6 }, 0]);
            out.extend_from_slice(&peer.port().to_be_bytes());
            resolver_ip_write(&mut out, peer.ip());
        }
        out.extend_from_slice(&(self.hosts.len() as u16).to_be_bytes());
        for host in &self.hosts {
            string(&mut out, &host.alias, 253)?;
            out.extend_from_slice(&(host.addresses.len() as u16).to_be_bytes());
            for ip in &host.addresses {
                out.push(if ip.is_ipv4() { 4 } else { 6 });
                resolver_ip_write(&mut out, *ip);
            }
        }
        if out.len() != size {
            return Err(Error::Bounds);
        }
        validate_resolver_asset(&out, self.source, self.source_flags)?;
        Ok(out)
    }
}
fn resolver_ip_write(out: &mut Vec<u8>, ip: std::net::IpAddr) {
    match ip {
        std::net::IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
}
fn resolver_ip_read(r: &mut Reader<'_>, family: u8) -> Result<std::net::IpAddr> {
    match family {
        4 => Ok(std::net::Ipv4Addr::from(r.array::<4>()?).into()),
        6 => {
            let ip = std::net::Ipv6Addr::from(r.array::<16>()?);
            if ip.to_ipv4_mapped().is_some() {
                return Err(Error::Schema);
            }
            Ok(ip.into())
        }
        _ => Err(Error::Schema),
    }
}
pub(crate) fn resolver_name(name: &str, rooted: bool, lowercase: bool) -> Result<()> {
    if name.len() > 253
        || name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || [b'.', b'-', b'_'].contains(&b))
        || rooted && !name.ends_with('.')
        || lowercase && name.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(Error::Schema);
    }
    if name != "."
        && name
            .strip_suffix('.')
            .unwrap_or(name)
            .split('.')
            .any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
            })
    {
        return Err(Error::Schema);
    }
    Ok(())
}
/// Zero-allocation readback; source/hash provenance остаётся отдельным proof.
pub(crate) fn verify_resolver_asset(bytes: &[u8], reference: SnapshotRef) -> Result<()> {
    if bytes.len() != reference.bytes as usize
        || bytes.len() > 2 * 1024 * 1024
        || <[u8; 32]>::from(Sha256::digest(bytes)) != reference.asset
    {
        return Err(Error::Hash);
    }
    validate_resolver_asset(bytes, reference.source, reference.flags)
}
pub(crate) fn validate_resolver_asset(
    bytes: &[u8],
    source: [u8; 32],
    source_flags: u32,
) -> Result<()> {
    if !(170..=2 * 1024 * 1024).contains(&bytes.len())
        || source == [0; 32]
        || source_flags & !1 != 0
    {
        return Err(Error::Bounds);
    }
    let mut r = Reader::new(bytes);
    if r.take(8)? != b"YNKDNS01"
        || r.u16()? != 1
        || r.u16()? != 120
        || r.u32()? as usize != bytes.len()
        || r.array::<32>()? != source
    {
        return Err(Error::Schema);
    }
    let nss = r.array::<32>()?;
    let hosts = r.array::<32>()?;
    if nss == [0; 32]
        || hosts == [0; 32]
        || source_flags == 1 && hosts != <[u8; 32]>::from(Sha256::digest([]))
    {
        return Err(Error::Hash);
    }
    r.zero(8)?;
    if r.array::<32>()? == [0; 32] {
        return Err(Error::Hash);
    }
    if !(1..=4).contains(&r.u8()?) || r.u8()? > 15 || !(1..=5).contains(&r.u8()?) {
        return Err(Error::Schema);
    }
    r.zero(1)?;
    if !(1..=30000).contains(&r.u32()?) || r.u16()? & !31 != 0 {
        return Err(Error::Schema);
    }
    resolver_name(r.string(253)?, false, false)?;
    let searches = r.u16()?;
    if searches > 6 {
        return Err(Error::Budget);
    }
    for _ in 0..searches {
        resolver_name(r.string(253)?, true, false)?;
    }
    let peers = r.u16()?;
    if !(1..=3).contains(&peers) {
        return Err(Error::Budget);
    }
    for _ in 0..peers {
        let family = r.u8()?;
        r.zero(1)?;
        if r.u16()? != 53 {
            return Err(Error::Schema);
        }
        let ip = resolver_ip_read(&mut r, family)?;
        if ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, std::net::IpAddr::V4(ip) if ip.is_broadcast())
            || matches!(ip, std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            return Err(Error::Schema);
        }
    }
    let count = r.u16()? as usize;
    if count > 4096 || source_flags == 1 && count != 0 {
        return Err(Error::Budget);
    }
    // Fixed scratch, не heap; сортировка не меняет порядок rows самого asset.
    let mut aliases = [""; 4096];
    for alias in &mut aliases[..count] {
        *alias = r.string(253)?;
        resolver_name(alias, alias.contains('.'), true)?;
        let addresses = r.u16()?;
        if !(1..=16).contains(&addresses) {
            return Err(Error::Budget);
        }
        for _ in 0..addresses {
            let family = r.u8()?;
            resolver_ip_read(&mut r, family)?;
        }
    }
    aliases[..count].sort_unstable();
    if aliases[..count].windows(2).any(|p| p[0] == p[1]) {
        return Err(Error::Reference);
    }
    r.end()
}
pub(crate) struct OwnedCapsule {
    bytes: Vec<u8>,
    _memory: crate::helper::memory::ByteLease,
}
struct Tables {
    rows: [Vec<Vec<u8>>; 11],
    size: usize,
}
impl Tables {
    fn new() -> Self {
        Self {
            rows: std::array::from_fn(|_| Vec::new()),
            size: 128 + 11 * 8,
        }
    }
    fn push(&mut self, table: usize, row: Vec<u8>) -> Result<u16> {
        let rows = &mut self.rows[table];
        if rows.len() >= TABLE_CAPS[table] || row.len() > u16::MAX as usize {
            return Err(Error::Budget);
        }
        self.size = self
            .size
            .checked_add(4 + row.len())
            .filter(|n| *n <= FRAME_LIMIT - HEADER)
            .ok_or(Error::Budget)?;
        let index = rows.len() as u16;
        rows.push(row);
        Ok(index)
    }
    fn endpoint(&mut self, host: &str, port: u16, protocol: u8) -> Result<u16> {
        let mut row = destination_bytes(host, port, protocol)?;
        row.extend_from_slice(&[0; 4]);
        if let Some(index) = self.rows[1].iter().position(|previous| *previous == row) {
            return Ok(index as u16);
        }
        self.push(1, row)
    }
}
fn string(out: &mut Vec<u8>, value: &str, max: usize) -> Result<()> {
    if value.len() > max || value.len() > u16::MAX as usize {
        return Err(Error::Bounds);
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn destination_bytes(host: &str, port: u16, protocol: u8) -> Result<Vec<u8>> {
    network(protocol)?;
    canonical_host(host)?;
    if port == 0 {
        return Err(Error::Schema);
    }
    let mut row = Vec::with_capacity(8 + host.len().max(16));
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            row.extend_from_slice(&[4, protocol]);
            row.extend_from_slice(&port.to_be_bytes());
            row.extend_from_slice(&[0, 4, 0, 0]);
            row.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            row.extend_from_slice(&[6, protocol]);
            row.extend_from_slice(&port.to_be_bytes());
            row.extend_from_slice(&[0, 16, 0, 0]);
            row.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            row.extend_from_slice(&[3, protocol]);
            row.extend_from_slice(&port.to_be_bytes());
            row.extend_from_slice(&(host.len() as u16).to_be_bytes());
            row.extend_from_slice(&[0, 0]);
            row.extend_from_slice(host.as_bytes());
        }
    }
    let mut r = Reader::new(&row);
    Destination::read(&mut r)?;
    r.end()?;
    Ok(row)
}
struct HashWriter(Sha256);
struct BranchDeriver<'a> {
    intent: &'a yonik_engine::native_profile::ProfileIntent,
    names: &'a [String],
    indices: &'a std::collections::BTreeMap<&'a str, u16>,
    remotes:
        &'a std::collections::BTreeMap<&'a str, &'a yonik_engine::native_profile::PhysicalEndpoint>,
    cache: [[[u8; 3]; 2]; 256],
}
impl BranchDeriver<'_> {
    fn mask(
        &mut self,
        subject: u16,
        input: yonik_engine::native_profile::WireNetwork,
        port: Option<u16>,
        depth: usize,
    ) -> Result<u8> {
        use yonik_engine::native_profile::WireNetwork;
        if depth > 256 {
            return Err(Error::Reference);
        }
        let i = usize::from(input == WireNetwork::Udp);
        let p = match port {
            None => 0,
            Some(443) => 1,
            Some(_) => 2,
        };
        let cached = self.cache[subject as usize][i][p];
        if cached == 254 {
            return Err(Error::Reference);
        }
        if cached != 255 {
            return Ok(cached);
        }
        self.cache[subject as usize][i][p] = 254;
        let name = &self.names[subject as usize];
        let mut mask = self
            .intent
            .branch_mask(name, input, port)
            .map_err(|_| Error::Schema)?;
        for b in 0..2 {
            if mask & (1 << b) == 0 {
                continue;
            }
            let projection = self
                .intent
                .project_branch(name, input, b == 1)
                .map_err(|_| Error::Schema)?;
            if let Some(next) = projection.next_subject() {
                let next = *self.indices.get(next).ok_or(Error::Reference)?;
                let port = self
                    .remotes
                    .get(name.as_str())
                    .ok_or(Error::Reference)?
                    .port();
                let carrier = projection.carrier().ok_or(Error::Reference)?;
                if self.mask(next, carrier, Some(port), depth + 1)? == 0 {
                    mask &= !(1 << b);
                }
            }
        }
        self.cache[subject as usize][i][p] = mask;
        Ok(mask)
    }
}
impl std::io::Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl OwnedCapsule {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn build(
        intent: &yonik_engine::native_profile::ProfileIntent,
        plan: &yonik_engine::native_profile::OwnedRuntimePlan,
        snapshot: Option<SnapshotRef>,
        digest: [u8; 32],
        policy_revision: u64,
        admission_id: u64,
    ) -> Result<Self> {
        use yonik_engine::native_profile::{OwnedIngress, ProviderIngressProtocol, WireNetwork};
        // До validate/typed graph/container allocation: один aggregate credit.
        let mut memory = crate::helper::memory::config_budget()
            .reserve(8 * 1024 * 1024)
            .map_err(|_| Error::Budget)?;
        if digest == [0; 32] || policy_revision == 0 || admission_id == 0 {
            return Err(Error::Binding);
        }
        let graph = intent.validate().map_err(|_| Error::Schema)?;
        intent
            .validate_ingress_mapping(plan)
            .map_err(|_| Error::Reference)?;
        let mode = if plan.is_system() {
            Mode::System
        } else {
            Mode::Local
        };
        let names = graph.subjects();
        for endpoint in graph.egress().physical() {
            if (endpoint.host().eq_ignore_ascii_case("localhost")
                || endpoint
                    .host()
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()))
                && [plan.local_port().get(), plan.probe_port().get()].contains(&endpoint.port())
            {
                return Err(Error::Reference);
            }
        }
        let mut t = Tables::new();
        let indices: std::collections::BTreeMap<&str, u16> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), i as u16))
            .collect();
        let remotes: std::collections::BTreeMap<
            &str,
            &yonik_engine::native_profile::PhysicalEndpoint,
        > = graph
            .egress()
            .subject_endpoints()
            .iter()
            .map(|(n, e)| (n.as_str(), e))
            .collect();
        let mut deriver = BranchDeriver {
            intent,
            names,
            indices: &indices,
            remotes: &remotes,
            cache: [[[255; 3]; 2]; 256],
        };
        for (i, name) in names.iter().enumerate() {
            let (kind, security) = intent.transport_kind(name).map_err(|_| Error::Schema)?;
            let mut hash = HashWriter(Sha256::new());
            hash.0.update(b"YNKCAP-TRANSPORT-v1\0");
            intent
                .write_transport_sensitive(name, &mut hash)
                .map_err(|_| Error::Bounds)?;
            let mut transport = vec![kind as u8, security as u8, 0, 0];
            transport.extend_from_slice(&hash.0.finalize());
            t.push(3, transport)?;
            let mut row = Vec::new();
            string(&mut row, name, 160)?;
            row.extend_from_slice(&[intent.proxy_kind(name).map_err(|_| Error::Schema)?, 0]);
            for index in [i as u16, 2 * i as u16, 2 * i as u16 + 1] {
                row.extend_from_slice(&index.to_be_bytes());
            }
            t.push(0, row)?;
            for input in [WireNetwork::Tcp, WireNetwork::Udp] {
                let mask = deriver.mask(i as u16, input, None, 0)?;
                let mut branches = [Branch::ABSENT; 2];
                for (b, branch) in branches.iter_mut().enumerate() {
                    if mask & (1 << b) == 0 {
                        continue;
                    }
                    let projection = intent
                        .project_branch(name, input, b == 1)
                        .map_err(|_| Error::Schema)?;
                    branch.action = projection.action() as u8;
                    if branch.action == 4 {
                        *branch = Branch::NO_DIAL;
                        continue;
                    }
                    branch.dial = projection.dial().ok_or(Error::Reference)? as u8;
                    branch.carrier = projection.carrier().ok_or(Error::Reference)? as u8;
                    branch.stream = if projection.active_stream() {
                        i as u16
                    } else {
                        NONE
                    };
                    if branch.action == 3 {
                        continue;
                    }
                    let remote = remotes.get(name.as_str()).ok_or(Error::Reference)?;
                    branch.endpoint = t.endpoint(remote.host(), remote.port(), branch.carrier)?;
                    if let Some(next) = projection.next_subject() {
                        let next_subject = *indices.get(next).ok_or(Error::Reference)?;
                        let next_input = projection.carrier().ok_or(Error::Reference)?;
                        let next_scope =
                            2 * next_subject + u16::from(next_input == WireNetwork::Udp);
                        let next_mask =
                            deriver.mask(next_subject, next_input, Some(remote.port()), 0)?;
                        if next_mask == 0 {
                            return Err(Error::Reference);
                        }
                        let mut chain = Vec::new();
                        chain.extend_from_slice(&(t.rows[8].len() as u16).to_be_bytes());
                        chain.extend_from_slice(&next_scope.to_be_bytes());
                        chain.extend_from_slice(&[b as u8, next_mask, 0, 0]);
                        branch.chain = t.push(2, chain)?;
                    } else if !graph.egress().physical().iter().any(|leaf| {
                        leaf.host() == remote.host()
                            && leaf.port() == remote.port()
                            && protocol(leaf.protocol()) == branch.carrier
                    }) {
                        return Err(Error::Reference);
                    }
                }
                let mut row = vec![];
                row.extend_from_slice(&(i as u16).to_be_bytes());
                row.extend_from_slice(&[input as u8, mask]);
                for branch in branches {
                    row.extend_from_slice(&[branch.dial, branch.carrier]);
                }
                for branch in branches {
                    row.extend_from_slice(&branch.endpoint.to_be_bytes());
                }
                for branch in branches {
                    row.extend_from_slice(&branch.stream.to_be_bytes());
                }
                for branch in branches {
                    row.extend_from_slice(&branch.chain.to_be_bytes());
                }
                for branch in branches {
                    row.push(branch.action);
                }
                row.extend_from_slice(&[0, 0]);
                t.push(8, row)?;
            }
        }
        let subject_index = |name: Option<&str>| -> Result<u16> {
            name.map_or(Ok(NONE), |n| {
                indices.get(n).copied().ok_or(Error::Reference)
            })
        };
        for resolver in graph.egress().resolvers() {
            let endpoint = resolver.endpoint();
            let p = protocol(endpoint.protocol());
            let mut row = vec![1, p];
            row.extend_from_slice(&subject_index(resolver.subject())?.to_be_bytes());
            row.extend_from_slice(&[0; 32]);
            row.extend_from_slice(&destination_bytes(endpoint.host(), endpoint.port(), p)?);
            t.push(4, row)?;
        }
        if !graph.egress().system_resolvers().is_empty() {
            let reference = snapshot.ok_or(Error::Reference)?;
            let binding = plan.system_resolver_binding().ok_or(Error::Reference)?;
            if reference.source != *binding.snapshot_digest() {
                return Err(Error::Reference);
            }
            for resolver in graph.egress().system_resolvers() {
                for peer in binding.servers() {
                    for p in [6, 17] {
                        let mut row = vec![2, p];
                        row.extend_from_slice(&subject_index(resolver.subject())?.to_be_bytes());
                        row.extend_from_slice(&reference.source);
                        row.extend_from_slice(&destination_bytes(
                            &peer.ip().to_string(),
                            peer.port(),
                            p,
                        )?);
                        t.push(4, row)?;
                    }
                }
            }
            let mut row = Vec::new();
            row.extend_from_slice(&reference.source);
            row.extend_from_slice(&reference.asset);
            row.extend_from_slice(&reference.bytes.to_be_bytes());
            row.extend_from_slice(&[0, 1, 0, 0]);
            row.extend_from_slice(&reference.flags.to_be_bytes());
            t.push(10, row)?;
        } else if snapshot.is_some() {
            return Err(Error::Reference);
        }
        if plan.resource_bindings().len() != graph.resources().len() {
            return Err(Error::Reference);
        }
        for requirement in graph.resources() {
            let (_, reference) = plan
                .resource_bindings()
                .iter()
                .find(|(r, _)| r == requirement)
                .ok_or(Error::Reference)?;
            reference.validate().map_err(|_| Error::Schema)?;
            if reference.engine != yonik_engine::Engine::Xray
                || reference.kind != requirement.kind()
            {
                return Err(Error::Reference);
            }
            let kind = match requirement.kind() {
                yonik_engine::resource_bundle::ResourceKind::Cidrs => 1,
                yonik_engine::resource_bundle::ResourceKind::Domains => 2,
            };
            let mut row = vec![kind, 0];
            string(&mut row, requirement.category(), 160)?;
            row.extend_from_slice(&reference.digest);
            row.extend_from_slice(&reference.bytes.to_be_bytes());
            t.push(5, row)?;
        }
        for (kind, mask, port, name) in [
            (2, 3, plan.local_port().get(), "yonik-owned-local"),
            (4, 1, plan.probe_port().get(), "yonik-owned-probe"),
        ] {
            let mut row = vec![kind, mask];
            row.extend_from_slice(&port.to_be_bytes());
            string(&mut row, name, 160)?;
            t.push(6, row)?;
        }
        if mode == Mode::System {
            let mut row = vec![1, 3, 0, 0];
            string(&mut row, "system-tun", 160)?;
            t.push(6, row)?;
        }
        for ingress in graph.ingresses() {
            let owned = plan
                .ingress_mappings()
                .find(|(tag, _)| *tag == ingress.tag())
                .map(|(_, o)| o)
                .ok_or(Error::Reference)?;
            let mut row = vec![];
            string(&mut row, ingress.tag(), 128)?;
            row.extend_from_slice(
                &(if owned == OwnedIngress::System {
                    2u16
                } else {
                    0u16
                })
                .to_be_bytes(),
            );
            row.extend_from_slice(&[
                match ingress.protocol() {
                    ProviderIngressProtocol::Socks => 1,
                    ProviderIngressProtocol::Http => 2,
                },
                0,
            ]);
            t.push(9, row)?;
        }
        if let Some(probe) = graph.probe() {
            let url = reqwest::Url::parse(probe.url()).map_err(|_| Error::Schema)?;
            if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
                return Err(Error::Schema);
            }
            let scheme = match url.scheme() {
                "http" => 1,
                "https" => 2,
                _ => return Err(Error::Schema),
            };
            let port = url.port_or_known_default().ok_or(Error::Schema)?;
            let host = url
                .host_str()
                .ok_or(Error::Schema)?
                .trim_matches(['[', ']']);
            let mut path = url.path().to_owned();
            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }
            let mut row = vec![scheme, 0];
            row.extend_from_slice(&port.to_be_bytes());
            string(&mut row, host, 253)?;
            string(&mut row, &path, 2048)?;
            row.extend_from_slice(&(probe.subjects().len() as u16).to_be_bytes());
            for name in probe.subjects() {
                row.extend_from_slice(&subject_index(Some(name))?.to_be_bytes());
            }
            t.push(7, row)?;
        }
        let mut bytes = vec![0; 128];
        put64(&mut bytes, 64, admission_id);
        put32(&mut bytes, 72, 60000);
        bytes[76] = mode as u8;
        bytes[77] = u8::from(mode.required());
        put16(&mut bytes, 78, 3);
        put64(&mut bytes, 80, policy_revision);
        for (i, cap) in MAX_CAPS.iter().enumerate() {
            put32(&mut bytes, 88 + 4 * i, *cap);
        }
        put16(&mut bytes, 120, 11);
        bytes
            .try_reserve_exact(t.size - 128)
            .map_err(|_| Error::Budget)?;
        for (i, rows) in t.rows.iter().enumerate() {
            bytes.extend_from_slice(&((i + 1) as u16).to_be_bytes());
            bytes.extend_from_slice(&(rows.len() as u16).to_be_bytes());
            let size = rows.iter().map(|r| r.len() + 4).sum::<usize>();
            bytes.extend_from_slice(&(size as u32).to_be_bytes());
            for row in rows {
                bytes.extend_from_slice(&(row.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&[0, 0]);
                bytes.extend_from_slice(row);
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"YNKCAP-MANIFEST-v1\0");
        hash.update(digest);
        hash.update(&bytes[76..78]);
        hash.update(&bytes[80..120]);
        hash.update(&bytes[128..]);
        bytes[..32].copy_from_slice(&hash.finalize());
        Capsule::decode(&bytes, &digest)?;
        drop(t);
        drop(remotes);
        drop(indices);
        drop(graph);
        memory
            .resize(bytes.capacity() + std::mem::size_of::<Self>())
            .map_err(|_| Error::Budget)?;
        Ok(Self {
            bytes,
            _memory: memory,
        })
    }
}
fn protocol(value: yonik_engine::native_profile::TransportProtocol) -> u8 {
    match value {
        yonik_engine::native_profile::TransportProtocol::Tcp => 6,
        yonik_engine::native_profile::TransportProtocol::Udp => 17,
    }
}

struct Table<'a> {
    bytes: &'a [u8],
    count: u16,
    offsets: [u16; 1024],
}
impl<'a> Table<'a> {
    fn rows(&self) -> Rows<'a> {
        Rows(self.bytes)
    }
    fn row(&self, index: u16) -> Result<&'a [u8]> {
        if index >= self.count {
            return Err(Error::Reference);
        }
        let start = self.offsets[index as usize] as usize;
        let mut r = Reader::new(self.bytes.get(start..).ok_or(Error::Reference)?);
        let n = r.u16()? as usize;
        r.zero(2)?;
        r.take(n)
    }
}
struct Rows<'a>(&'a [u8]);
impl<'a> Iterator for Rows<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        let prefix = self.0.get(..4)?;
        let n = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;
        let row = self.0.get(4..4 + n)?;
        self.0 = self.0.get(4 + n..)?;
        Some(row)
    }
}

/// Zero-copy view: даже malformed caps не вызывают allocations.
pub(crate) struct Capsule<'a> {
    body: &'a [u8],
    tables: [Table<'a>; 11],
    pub mode: Mode,
    pub manifest: [u8; 32],
    pub admission_id: u64,
    pub lease_ms: u32,
    pub policy_revision: u64,
}
impl<'a> Capsule<'a> {
    pub(crate) fn decode(body: &'a [u8], digest: &[u8; 32]) -> Result<Self> {
        if body.len() < 128 || body.len() > FRAME_LIMIT - HEADER {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(body);
        let manifest = r.array()?;
        let _previous: [u8; 32] = r.array()?;
        let admission_id = r.u64()?;
        let lease_ms = r.u32()?;
        let mode = Mode::try_from(r.u8()?)?;
        if r.u8()? != u8::from(mode.required()) || r.u16()? != 3 {
            return Err(Error::Schema);
        }
        let policy_revision = r.u64()?;
        let mut caps = [0; 8];
        for cap in &mut caps {
            *cap = r.u32()?;
        }
        MemoryPreflight::new(caps, body.len())?;
        if r.u16()? != 11 {
            return Err(Error::Schema);
        }
        r.zero(6)?;
        if admission_id == 0 || lease_ms == 0 || lease_ms > 60000 || policy_revision == 0 {
            return Err(Error::Schema);
        }
        let mut tables = std::array::from_fn(|_| Table {
            bytes: &[][..],
            count: 0,
            offsets: [0; 1024],
        });
        for (i, table) in tables.iter_mut().enumerate() {
            if r.u16()? != (i + 1) as u16 {
                return Err(Error::Schema);
            }
            let count = r.u16()?;
            let len = r.u32()? as usize;
            if count as usize > TABLE_CAPS[i] {
                return Err(Error::Budget);
            }
            let bytes = r.take(len)?;
            let mut rows = Reader::new(bytes);
            for i in 0..count {
                table.offsets[i as usize] = rows.position as u16;
                let n = rows.u16()? as usize;
                rows.zero(2)?;
                rows.take(n)?;
            }
            rows.end()?;
            table.bytes = bytes;
            table.count = count;
        }
        r.end()?;
        let mut h = Sha256::new();
        h.update(b"YNKCAP-MANIFEST-v1\0");
        h.update(digest);
        h.update(&body[76..78]);
        h.update(&body[80..120]);
        h.update(&body[128..]);
        if <[u8; 32]>::from(h.finalize()) != manifest {
            return Err(Error::Hash);
        }
        let out = Self {
            body,
            tables,
            mode,
            manifest,
            admission_id,
            lease_ms,
            policy_revision,
        };
        out.validate()?;
        Ok(out)
    }
    fn validate(&self) -> Result<()> {
        let t = &self.tables;
        if t[0].count == 0
            || t[0].count != t[3].count
            || usize::from(t[8].count) != usize::from(t[0].count) * 2
            || t[6].count == 0
        {
            return Err(Error::Reference);
        }
        let mut names = [""; 256];
        for (i, row) in t[0].rows().enumerate() {
            let s = subject(row)?;
            names[i] = s.name;
            if s.stream != i as u16 || s.tcp != 2 * i as u16 || s.udp != 2 * i as u16 + 1 {
                return Err(Error::Reference);
            }
        }
        names[..t[0].count as usize].sort_unstable();
        if names[..t[0].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        for row in t[1].rows() {
            let mut r = Reader::new(row);
            Destination::read(&mut r)?;
            r.zero(4)?;
            r.end()?;
        }
        for row in t[3].rows() {
            let mut r = Reader::new(row);
            if !(1..=4).contains(&r.u8()?) || r.u8()? > 2 {
                return Err(Error::Schema);
            }
            r.zero(2)?;
            let hash: [u8; 32] = r.array()?;
            if hash == [0; 32] {
                return Err(Error::Hash);
            }
            r.end()?;
        }
        let mut chain_seen = [false; 1024];
        for (i, row) in t[8].rows().enumerate() {
            let scope = scope(row)?;
            if scope.subject != i as u16 / 2 || scope.input != if i % 2 == 0 { 6 } else { 17 } {
                return Err(Error::Reference);
            }
            for (b, branch) in scope.branches.iter().enumerate() {
                if scope.mask & (1 << b) == 0 {
                    if *branch != Branch::ABSENT {
                        return Err(Error::Reference);
                    }
                    continue;
                }
                let kind = subject(t[0].row(scope.subject)?)?.kind;
                if branch.action == 4 {
                    if *branch != Branch::NO_DIAL || kind != 6 && kind != 7 {
                        return Err(Error::Reference);
                    }
                    continue;
                }
                network(branch.dial)?;
                network(branch.carrier)?;
                if kind == 6
                    || kind == 7
                    || matches!(kind, 1 | 4) && branch.dial != 6
                    || matches!(kind, 2 | 3 | 5)
                        && branch.dial != if b == 1 { 6 } else { scope.input }
                    || kind == 4 && branch.carrier != 17
                {
                    return Err(Error::Reference);
                }
                if branch.dial == 17 && (branch.carrier != 17 || branch.stream != NONE)
                    || branch.dial == 6 && branch.stream != scope.subject
                {
                    return Err(Error::Reference);
                }
                if branch.action == 3 {
                    if branch.endpoint != NONE
                        || branch.chain != NONE
                        || subject(t[0].row(scope.subject)?)?.kind != 5
                    {
                        return Err(Error::Reference);
                    }
                } else {
                    let mut r = Reader::new(t[1].row(branch.endpoint)?);
                    let endpoint = Destination::read(&mut r)?;
                    if endpoint.protocol != branch.carrier {
                        return Err(Error::Reference);
                    }
                    match branch.action {
                        1 => {
                            if branch.chain != NONE {
                                return Err(Error::Reference);
                            }
                        }
                        2 => {
                            let c = chain(t[2].row(branch.chain)?)?;
                            if c.source != i as u16
                                || c.branch != b as u8
                                || c.mask == 0
                                || c.mask & !3 != 0
                            {
                                return Err(Error::Reference);
                            }
                            let next = scope_from(t, c.next)?;
                            if next.input != branch.carrier || c.mask & !next.mask != 0 {
                                return Err(Error::Reference);
                            }
                            if chain_seen[branch.chain as usize] {
                                return Err(Error::Reference);
                            }
                            chain_seen[branch.chain as usize] = true;
                        }
                        _ => return Err(Error::Schema),
                    }
                }
            }
        }
        if chain_seen[..t[2].count as usize].iter().any(|seen| !*seen) {
            return Err(Error::Reference);
        }
        // Acyclic проверяется по subject graph, независимо от input/branch.
        let mut edges = [NONE; 256];
        for row in t[2].rows() {
            let c = chain(row)?;
            let source = (c.source / 2) as usize;
            let next = c.next / 2;
            if edges[source] != NONE && edges[source] != next {
                return Err(Error::Reference);
            }
            edges[source] = next;
        }
        let n = t[0].count as usize;
        let mut indegree = [0u16; 256];
        for next in &edges[..n] {
            if *next != NONE {
                indegree[*next as usize] += 1;
            }
        }
        let mut queue = [0usize; 256];
        let mut end = 0;
        let mut completed = 0;
        for (i, degree) in indegree[..n].iter().enumerate() {
            if *degree == 0 {
                queue[end] = i;
                end += 1;
            }
        }
        while completed < end {
            let next = edges[queue[completed]];
            completed += 1;
            if next != NONE {
                let i = next as usize;
                indegree[i] -= 1;
                if indegree[i] == 0 {
                    queue[end] = i;
                    end += 1;
                }
            }
        }
        if completed != n {
            return Err(Error::Reference);
        }
        self.validate_auxiliary()
    }
}

fn network(n: u8) -> Result<()> {
    if n != 6 && n != 17 {
        return Err(Error::Schema);
    }
    Ok(())
}
impl Capsule<'_> {
    /// Проверяет DATA scope запроса. Peer/ingress/owner authority выдаёт issuer.
    fn validate_request(&self, message: &Message<'_>) -> Result<()> {
        let t = &self.tables;
        match message {
            Message::OpenIngress {
                ingress,
                provenance,
                tuple,
                ..
            } => {
                let row = t[6].row(*ingress)?;
                let kind = row[0];
                let mask = row[1];
                let port = u16::from_be_bytes([row[2], row[3]]);
                let bit = if tuple.protocol == 6 { 1 } else { 2 };
                if mask & bit == 0
                    || kind == 4
                    || (kind == 1) != (*provenance == 1)
                    || kind != 1 && tuple.local_port != port
                    || kind == 3 && *provenance != 2
                {
                    return Err(Error::Reference);
                }
            }
            Message::Authorize(a) => {
                if a.branch > 1 || a.class != 1 && a.class != 3 {
                    return Err(Error::Schema);
                }
                if self.mode == Mode::Local && a.receipt.kind != ReceiptKind::None {
                    return Err(Error::Binding);
                }
                if a.class == 1 {
                    let scope = scope_from(t, a.scope)?;
                    if scope.subject != a.subject || scope.mask & (1 << a.branch) == 0 {
                        return Err(Error::Reference);
                    }
                    let branch = scope.branches[a.branch as usize];
                    if branch.action == 4 || branch.stream != a.transport || branch.chain != a.chain
                    {
                        return Err(Error::Reference);
                    }
                } else {
                    let mut r = Reader::new(t[4].row(a.resolver)?);
                    r.take(36)?;
                    let destination = Destination::read(&mut r)?;
                    if destination != a.effective {
                        return Err(Error::Reference);
                    }
                }
            }
            Message::Probe {
                purpose,
                index,
                subject,
                resolver,
            } => {
                if *purpose == 1 {
                    let mut r = Reader::new(t[7].row(*index)?);
                    r.take(4)?;
                    r.string(253)?;
                    r.string(2048)?;
                    let count = r.u16()?;
                    let mut found = false;
                    for _ in 0..count {
                        found |= r.u16()? == *subject;
                    }
                    if !found {
                        return Err(Error::Reference);
                    }
                } else if *purpose == 2 {
                    let mut r = Reader::new(t[1].row(*index)?);
                    let endpoint = Destination::read(&mut r)?;
                    if endpoint.family != 3 {
                        return Err(Error::Reference);
                    }
                    t[4].row(*resolver)?;
                    if *subject != NONE {
                        t[0].row(*subject)?;
                    }
                } else {
                    return Err(Error::Schema);
                }
            }
            _ => return Err(Error::Schema),
        }
        Ok(())
    }
    fn validate_auxiliary(&self) -> Result<()> {
        let t = &self.tables;
        let mut snapshot = None;
        let mut asset_bytes = 0u64;
        let mut assets = [([0u8; 32], 0u64, 0u8); 16];
        let mut unique = 0usize;
        if t[10].count == 1 {
            let mut r = Reader::new(t[10].row(0)?);
            let source: [u8; 32] = r.array()?;
            let asset: [u8; 32] = r.array()?;
            let bytes = r.u32()?;
            if source == [0; 32]
                || asset == [0; 32]
                || !(120..=2 * 1024 * 1024).contains(&bytes)
                || r.u16()? != 1
            {
                return Err(Error::Schema);
            }
            r.zero(2)?;
            if r.u32()? & !1 != 0 {
                return Err(Error::Schema);
            }
            r.end()?;
            snapshot = Some(source);
            assets[0] = (asset, bytes as u64, 0);
            unique = 1;
            asset_bytes = bytes as u64;
        }
        let mut system_rows = 0;
        for row in t[4].rows() {
            let mut r = Reader::new(row);
            let backend = r.u8()?;
            let protocol = r.u8()?;
            network(protocol)?;
            let s = r.u16()?;
            if s != NONE {
                t[0].row(s)?;
            }
            let hash: [u8; 32] = r.array()?;
            let dest = Destination::read(&mut r)?;
            r.end()?;
            if dest.protocol != protocol {
                return Err(Error::Reference);
            }
            match backend {
                1 => {
                    if hash != [0; 32] {
                        return Err(Error::Reference);
                    }
                }
                2 => {
                    if snapshot != Some(hash) {
                        return Err(Error::Reference);
                    }
                    system_rows += 1;
                }
                _ => return Err(Error::Schema),
            }
        }
        if snapshot.is_some() != (system_rows > 0) {
            return Err(Error::Reference);
        }
        let mut resource_keys = [(0u8, ""); 16];
        for (i, row) in t[5].rows().enumerate() {
            let mut r = Reader::new(row);
            let kind = r.u8()?;
            if kind != 1 && kind != 2 {
                return Err(Error::Schema);
            }
            r.zero(1)?;
            let category = r.string(160)?;
            if category.is_empty()
                || !category.is_ascii()
                || category.bytes().any(|b| b.is_ascii_control())
            {
                return Err(Error::Schema);
            }
            resource_keys[i] = (kind, category);
            let hash: [u8; 32] = r.array()?;
            let bytes = r.u64()?;
            r.end()?;
            if hash == [0; 32] || bytes == 0 || bytes > 64 * 1024 * 1024 {
                return Err(Error::Budget);
            }
            if let Some((_, existing, existing_kind)) =
                assets[..unique].iter().find(|(h, _, _)| *h == hash)
            {
                if *existing != bytes || *existing_kind != kind {
                    return Err(Error::Reference);
                }
            } else {
                if unique == 16 {
                    return Err(Error::Budget);
                }
                assets[unique] = (hash, bytes, kind);
                unique += 1;
                asset_bytes = asset_bytes
                    .checked_add(bytes)
                    .filter(|n| *n <= 64 * 1024 * 1024)
                    .ok_or(Error::Budget)?;
            }
        }
        resource_keys[..t[5].count as usize].sort_unstable();
        if resource_keys[..t[5].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        let mut ingress_names = [""; 4];
        let mut has_tun = false;
        for (i, row) in t[6].rows().enumerate() {
            let mut r = Reader::new(row);
            let kind = r.u8()?;
            let mask = r.u8()?;
            let port = r.u16()?;
            let name = r.string(160)?;
            r.end()?;
            if !(1..=4).contains(&kind)
                || mask == 0
                || mask & !3 != 0
                || name.is_empty()
                || name.chars().any(char::is_control)
            {
                return Err(Error::Schema);
            }
            if kind == 1 {
                if has_tun || self.mode != Mode::System || mask != 3 || port != 0 {
                    return Err(Error::Reference);
                }
                has_tun = true;
            } else if port == 0 || (kind == 3 || kind == 4) && mask != 1 {
                return Err(Error::Reference);
            }
            ingress_names[i] = name;
        }
        if self.mode.required() != has_tun {
            return Err(Error::Reference);
        }
        ingress_names[..t[6].count as usize].sort_unstable();
        if ingress_names[..t[6].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        let mut aliases = [""; 16];
        for (i, row) in t[9].rows().enumerate() {
            let mut r = Reader::new(row);
            let tag = r.string(128)?;
            let ingress = r.u16()?;
            let protocol = r.u8()?;
            r.zero(1)?;
            r.end()?;
            if tag.is_empty() || tag.chars().any(char::is_control) || protocol != 1 && protocol != 2
            {
                return Err(Error::Schema);
            }
            let owned = t[6].row(ingress)?;
            if owned[0] != 1 && owned[0] != 2 && owned[0] != 3 {
                return Err(Error::Reference);
            }
            aliases[i] = tag;
        }
        aliases[..t[9].count as usize].sort_unstable();
        if aliases[..t[9].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        for row in t[7].rows() {
            let mut r = Reader::new(row);
            let scheme = r.u8()?;
            if scheme != 1 && scheme != 2 {
                return Err(Error::Schema);
            }
            r.zero(1)?;
            if r.u16()? == 0 {
                return Err(Error::Schema);
            }
            let host = r.string(253)?;
            canonical_host(host)?;
            let path = r.string(2048)?;
            if !path.starts_with('/')
                || path.bytes().any(|b| b.is_ascii_control())
                || path.contains('#')
            {
                return Err(Error::Schema);
            }
            let count = r.u16()?;
            if count == 0 || count > t[0].count {
                return Err(Error::Budget);
            }
            let mut seen = [false; 256];
            for _ in 0..count {
                let i = r.u16()?;
                t[0].row(i)?;
                if seen[i as usize] {
                    return Err(Error::Reference);
                }
                seen[i as usize] = true;
            }
            r.end()?;
        }
        let mut physical = [false; 512];
        for row in t[8].rows() {
            for b in scope(row)?.branches {
                if b.action == 1 {
                    physical[b.endpoint as usize] = true;
                }
            }
        }
        if physical.iter().filter(|b| **b).count() > 128 {
            return Err(Error::Budget);
        }
        // Row bytes уже bounded; sorted borrowed refs не копируют payload.
        let mut endpoints = [&[][..]; 512];
        for (i, row) in t[1].rows().enumerate() {
            endpoints[i] = row;
        }
        endpoints[..t[1].count as usize].sort_unstable();
        if endpoints[..t[1].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        Ok(())
    }
}
fn canonical_host(host: &str) -> Result<()> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip,std::net::IpAddr::V6(v) if v.to_ipv4_mapped().is_some())
        {
            return Err(Error::Schema);
        }
        Ok(())
    } else {
        hostname(host)
    }
}
fn hostname(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Error::Schema);
    }
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Destination<'a> {
    protocol: u8,
    port: u16,
    family: u8,
    bytes: &'a [u8],
}
impl<'a> Destination<'a> {
    fn read(r: &mut Reader<'a>) -> Result<Self> {
        let family = r.u8()?;
        let protocol = r.u8()?;
        network(protocol)?;
        let port = r.u16()?;
        let n = r.u16()? as usize;
        r.zero(2)?;
        if port == 0 || n > 253 {
            return Err(Error::Schema);
        }
        let bytes = r.take(n)?;
        match family {
            3 => {
                let host = std::str::from_utf8(bytes).map_err(|_| Error::Schema)?;
                if host.parse::<std::net::IpAddr>().is_ok() {
                    return Err(Error::Schema);
                }
                hostname(host)?;
            }
            4 if n == 4 => {
                let ip = std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(bytes).map_err(|_| Error::Schema)?,
                );
                if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                    return Err(Error::Schema);
                }
            }
            6 if n == 16 => {
                let ip = std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(bytes).map_err(|_| Error::Schema)?,
                );
                if ip.is_unspecified() || ip.is_multicast() || ip.to_ipv4_mapped().is_some() {
                    return Err(Error::Schema);
                }
            }
            _ => return Err(Error::Schema),
        }
        Ok(Self {
            protocol,
            port,
            family,
            bytes,
        })
    }
}
struct Subject<'a> {
    name: &'a str,
    kind: u8,
    stream: u16,
    tcp: u16,
    udp: u16,
}
fn subject(row: &[u8]) -> Result<Subject<'_>> {
    let mut r = Reader::new(row);
    let name = r.string(160)?;
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(Error::Schema);
    }
    let kind = r.u8()?;
    if !(1..=7).contains(&kind) {
        return Err(Error::Schema);
    }
    r.zero(1)?;
    let out = Subject {
        name,
        kind,
        stream: r.u16()?,
        tcp: r.u16()?,
        udp: r.u16()?,
    };
    r.end()?;
    Ok(out)
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Branch {
    dial: u8,
    carrier: u8,
    endpoint: u16,
    stream: u16,
    chain: u16,
    action: u8,
}
impl Branch {
    const ABSENT: Self = Self {
        dial: 0,
        carrier: 0,
        endpoint: NONE,
        stream: NONE,
        chain: NONE,
        action: 0,
    };
    const NO_DIAL: Self = Self {
        action: 4,
        ..Self::ABSENT
    };
}
struct Scope {
    subject: u16,
    input: u8,
    mask: u8,
    branches: [Branch; 2],
}
fn scope(row: &[u8]) -> Result<Scope> {
    let mut r = Reader::new(row);
    let subject = r.u16()?;
    let input = r.u8()?;
    network(input)?;
    let mask = r.u8()?;
    if mask & !3 != 0 {
        return Err(Error::Schema);
    }
    let mut branches = [Branch::ABSENT; 2];
    for b in &mut branches {
        b.dial = r.u8()?;
        b.carrier = r.u8()?;
    }
    for b in &mut branches {
        b.endpoint = r.u16()?;
    }
    for b in &mut branches {
        b.stream = r.u16()?;
    }
    for b in &mut branches {
        b.chain = r.u16()?;
    }
    for b in &mut branches {
        b.action = r.u8()?;
    }
    r.zero(2)?;
    r.end()?;
    Ok(Scope {
        subject,
        input,
        mask,
        branches,
    })
}
fn scope_from(t: &[Table<'_>; 11], index: u16) -> Result<Scope> {
    scope(t[8].row(index)?)
}
struct Chain {
    source: u16,
    next: u16,
    branch: u8,
    mask: u8,
}
fn chain(row: &[u8]) -> Result<Chain> {
    let mut r = Reader::new(row);
    let out = Chain {
        source: r.u16()?,
        next: r.u16()?,
        branch: r.u8()?,
        mask: r.u8()?,
    };
    r.zero(2)?;
    r.end()?;
    if out.branch > 1 {
        return Err(Error::Schema);
    }
    Ok(out)
}
fn put32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn put64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(Error::Bounds)?;
        let out = &self.bytes[self.position..end];
        self.position = end;
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Bounds)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn zero(&mut self, n: usize) -> Result<()> {
        if self.take(n)?.iter().any(|b| *b != 0) {
            return Err(Error::Schema);
        }
        Ok(())
    }
    fn end(self) -> Result<()> {
        if self.position != self.bytes.len() {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    fn string(&mut self, max: usize) -> Result<&'a str> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(Error::Bounds);
        }
        std::str::from_utf8(self.take(n)?).map_err(|_| Error::Schema)
    }
}

#[derive(Clone, Copy)]
struct Receipt {
    kind: ReceiptKind,
    id: u64,
}
impl Receipt {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let kind = ReceiptKind::try_from(r.u8()?)?;
        r.zero(7)?;
        let id = r.u64()?;
        if (kind == ReceiptKind::None) != (id == 0) {
            return Err(Error::Schema);
        }
        Ok(Self { kind, id })
    }
    fn write(self, w: &mut Writer<'_>) -> Result<()> {
        w.u8(self.kind as u8)?;
        w.take(&[0; 7])?;
        w.u64(self.id)
    }
}
#[derive(Clone, Copy)]
struct Tuple {
    protocol: u8,
    family: u8,
    local_port: u16,
    remote_port: u16,
    local: [u8; 16],
    remote: [u8; 16],
}
impl Tuple {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let protocol = r.u8()?;
        network(protocol)?;
        let family = r.u8()?;
        r.zero(2)?;
        let out = Self {
            protocol,
            family,
            local_port: r.u16()?,
            remote_port: r.u16()?,
            local: r.array()?,
            remote: r.array()?,
        };
        if out.local_port == 0 || out.remote_port == 0 {
            return Err(Error::Schema);
        }
        for address in [&out.local, &out.remote] {
            let n = match family {
                4 => {
                    if address[4..].iter().any(|b| *b != 0) {
                        return Err(Error::Schema);
                    }
                    4
                }
                6 => 16,
                _ => return Err(Error::Schema),
            };
            let mut bytes = [0u8; 24];
            bytes[..2].copy_from_slice(&[family, protocol]);
            put16(&mut bytes, 2, 1);
            put16(&mut bytes, 4, n as u16);
            bytes[8..8 + n].copy_from_slice(&address[..n]);
            Destination::read(&mut Reader::new(&bytes[..8 + n]))?;
        }
        Ok(out)
    }
    fn write(self, w: &mut Writer<'_>) -> Result<()> {
        w.take(&[self.protocol, self.family, 0, 0])?;
        w.u16(self.local_port)?;
        w.u16(self.remote_port)?;
        w.take(&self.local)?;
        w.take(&self.remote)
    }
}
#[derive(Clone, Copy)]
struct Authorize<'a> {
    source_flow: u64,
    class: u8,
    subject: u16,
    chain: u16,
    transport: u16,
    scope: u16,
    branch: u8,
    original: Destination<'a>,
    effective: Destination<'a>,
    resolver: u16,
    query: &'a str,
    receipt: Receipt,
}
enum Message<'a> {
    Hello {
        nonce: [u8; 32],
        mode: Mode,
    },
    Admit(&'a [u8]),
    AdmitAck {
        manifest: [u8; 32],
        admission: u64,
        status: Status,
    },
    OpenIngress {
        ingress: u16,
        provenance: u8,
        tuple: Tuple,
        original: Destination<'a>,
    },
    IngressReply {
        status: Status,
        required: bool,
        flow: u64,
        revision: u64,
    },
    Authorize(Authorize<'a>),
    Grant {
        status: Status,
        class: u8,
        required: bool,
        grant: u64,
        flow: u64,
        lease: u32,
        revision: u64,
        fresh: u64,
        receipt: Receipt,
    },
    Probe {
        purpose: u16,
        index: u16,
        subject: u16,
        resolver: u16,
    },
    Renew {
        admission: u64,
        manifest: [u8; 32],
    },
    Deny {
        status: Status,
        reason: u8,
    },
    Cancel {
        target: u8,
        reason: u8,
        id: u64,
    },
    Revoke {
        reason: u16,
    },
    CloseAck {
        target: u8,
        status: CloseStatus,
        id: u64,
    },
}
impl<'a> Message<'a> {
    fn decode(kind: Kind, body: &'a [u8]) -> Result<Self> {
        if kind != Kind::Admit && body.len() > 1024 {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(body);
        let out = match kind {
            Kind::Hello => {
                let nonce = r.array()?;
                let mode = Mode::try_from(r.u8()?)?;
                r.zero(7)?;
                if nonce == [0; 32] {
                    return Err(Error::Binding);
                }
                Self::Hello { nonce, mode }
            }
            Kind::Admit => {
                if body.len() < 128 || body.len() > FRAME_LIMIT - HEADER {
                    return Err(Error::Bounds);
                }
                r.take(body.len())?;
                Self::Admit(body)
            }
            Kind::AdmitAck => {
                let manifest = r.array()?;
                let admission = r.u64()?;
                let status = Status::try_from(r.u8()?)?;
                r.zero(7)?;
                if manifest == [0; 32] || admission == 0 {
                    return Err(Error::Schema);
                }
                Self::AdmitAck {
                    manifest,
                    admission,
                    status,
                }
            }
            Kind::OpenIngress => {
                let ingress = r.u16()?;
                let provenance = r.u8()?;
                r.zero(1)?;
                if !(1..=3).contains(&provenance) {
                    return Err(Error::Schema);
                }
                let tuple = Tuple::read(&mut r)?;
                let original = Destination::read(&mut r)?;
                if tuple.protocol != original.protocol
                    || provenance == 2 && tuple.protocol != 6
                    || provenance == 3 && tuple.protocol != 17
                {
                    return Err(Error::Reference);
                }
                Self::OpenIngress {
                    ingress,
                    provenance,
                    tuple,
                    original,
                }
            }
            Kind::IngressReply => {
                let status = Status::try_from(r.u8()?)?;
                let required = boolean(r.u8()?)?;
                r.zero(2)?;
                let flow = r.u64()?;
                if r.u32()? != 0 {
                    return Err(Error::Schema);
                }
                let revision = r.u64()?;
                if (status == Status::Allow) != (flow != 0)
                    || status == Status::Allow && revision == 0
                {
                    return Err(Error::Schema);
                }
                Self::IngressReply {
                    status,
                    required,
                    flow,
                    revision,
                }
            }
            Kind::Authorize => {
                let source_flow = r.u64()?;
                let class = r.u8()?;
                r.zero(1)?;
                let subject = r.u16()?;
                let chain = r.u16()?;
                let transport = r.u16()?;
                let scope = r.u16()?;
                let branch = r.u8()?;
                r.zero(1)?;
                let original = Destination::read(&mut r)?;
                let effective = Destination::read(&mut r)?;
                let resolver = r.u16()?;
                let query = r.string(253)?;
                let receipt = Receipt::read(&mut r)?;
                if source_flow == 0 || branch > 1 {
                    return Err(Error::Schema);
                }
                match class {
                    1 => {
                        if subject == NONE || scope == NONE || resolver != NONE || !query.is_empty()
                        {
                            return Err(Error::Reference);
                        }
                    }
                    3 => {
                        if [subject, chain, transport, scope] != [NONE; 4]
                            || branch != 0
                            || resolver == NONE
                        {
                            return Err(Error::Reference);
                        }
                        hostname(query)?;
                    }
                    _ => return Err(Error::Schema),
                }
                Self::Authorize(Authorize {
                    source_flow,
                    class,
                    subject,
                    chain,
                    transport,
                    scope,
                    branch,
                    original,
                    effective,
                    resolver,
                    query,
                    receipt,
                })
            }
            Kind::Grant => {
                let status = Status::try_from(r.u8()?)?;
                let class = r.u8()?;
                let required = boolean(r.u8()?)?;
                r.zero(1)?;
                let grant = r.u64()?;
                let flow = r.u64()?;
                let lease = r.u32()?;
                let revision = r.u64()?;
                let fresh = r.u64()?;
                let receipt = Receipt::read(&mut r)?;
                if !(1..=3).contains(&class)
                    || fresh > 20_000_000
                    || lease > 1000
                    || status == Status::Allow && (grant == 0 || lease == 0 || revision == 0)
                    || status == Status::Allow && class == 1 && flow == 0
                    || status != Status::Allow && (grant != 0 || lease != 0)
                    || class == 2
                        && (flow != 0
                            || required
                            || fresh != 0
                            || receipt.kind != ReceiptKind::None)
                    || !required && (fresh != 0 || receipt.kind != ReceiptKind::None)
                    || required
                        && status == Status::Allow
                        && (fresh == 0 || receipt.kind == ReceiptKind::None)
                {
                    return Err(Error::Schema);
                }
                Self::Grant {
                    status,
                    class,
                    required,
                    grant,
                    flow,
                    lease,
                    revision,
                    fresh,
                    receipt,
                }
            }
            Kind::Probe => {
                let purpose = r.u16()?;
                let index = r.u16()?;
                let subject = r.u16()?;
                let resolver = r.u16()?;
                if purpose != 1 && purpose != 2
                    || purpose == 1 && resolver != NONE
                    || purpose == 2 && resolver == NONE
                {
                    return Err(Error::Schema);
                }
                Self::Probe {
                    purpose,
                    index,
                    subject,
                    resolver,
                }
            }
            Kind::Renew => {
                let admission = r.u64()?;
                let manifest = r.array()?;
                if admission == 0 || manifest == [0; 32] {
                    return Err(Error::Schema);
                }
                Self::Renew {
                    admission,
                    manifest,
                }
            }
            Kind::Deny => {
                let status = Status::try_from(r.u8()?)?;
                let reason = r.u8()?;
                r.zero(6)?;
                if status == Status::Allow {
                    return Err(Error::Schema);
                }
                Self::Deny { status, reason }
            }
            Kind::Cancel => {
                let target = r.u8()?;
                let reason = r.u8()?;
                r.zero(2)?;
                let id = r.u64()?;
                target_id(target, id)?;
                Self::Cancel { target, reason, id }
            }
            Kind::Revoke => {
                let reason = r.u16()?;
                r.zero(6)?;
                Self::Revoke { reason }
            }
            Kind::CloseAck => {
                let target = r.u8()?;
                let status = CloseStatus::try_from(r.u8()?)?;
                r.zero(2)?;
                let id = r.u64()?;
                target_id(target, id)?;
                Self::CloseAck { target, status, id }
            }
        };
        r.end()?;
        Ok(out)
    }
    fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer {
            bytes: out,
            position: 0,
        };
        match self {
            Self::Hello { nonce, mode } => {
                w.take(nonce)?;
                w.u8(*mode as u8)?;
                w.take(&[0; 7])?;
            }
            Self::Admit(bytes) => w.take(bytes)?,
            Self::AdmitAck {
                manifest,
                admission,
                status,
            } => {
                w.take(manifest)?;
                w.u64(*admission)?;
                w.u8(*status as u8)?;
                w.take(&[0; 7])?;
            }
            Self::OpenIngress {
                ingress,
                provenance,
                tuple,
                original,
            } => {
                w.u16(*ingress)?;
                w.take(&[*provenance, 0])?;
                tuple.write(&mut w)?;
                original.write(&mut w)?;
            }
            Self::IngressReply {
                status,
                required,
                flow,
                revision,
            } => {
                w.take(&[*status as u8, u8::from(*required), 0, 0])?;
                w.u64(*flow)?;
                w.u32(0)?;
                w.u64(*revision)?;
            }
            Self::Authorize(a) => {
                w.u64(a.source_flow)?;
                w.take(&[a.class, 0])?;
                for i in [a.subject, a.chain, a.transport, a.scope] {
                    w.u16(i)?;
                }
                w.take(&[a.branch, 0])?;
                a.original.write(&mut w)?;
                a.effective.write(&mut w)?;
                w.u16(a.resolver)?;
                w.string(a.query, 253)?;
                a.receipt.write(&mut w)?;
            }
            Self::Grant {
                status,
                class,
                required,
                grant,
                flow,
                lease,
                revision,
                fresh,
                receipt,
            } => {
                w.take(&[*status as u8, *class, u8::from(*required), 0])?;
                w.u64(*grant)?;
                w.u64(*flow)?;
                w.u32(*lease)?;
                w.u64(*revision)?;
                w.u64(*fresh)?;
                receipt.write(&mut w)?;
            }
            Self::Probe {
                purpose,
                index,
                subject,
                resolver,
            } => {
                for i in [purpose, index, subject, resolver] {
                    w.u16(*i)?;
                }
            }
            Self::Renew {
                admission,
                manifest,
            } => {
                w.u64(*admission)?;
                w.take(manifest)?;
            }
            Self::Deny { status, reason } => {
                w.take(&[*status as u8, *reason])?;
                w.take(&[0; 6])?;
            }
            Self::Cancel { target, reason, id } => {
                w.take(&[*target, *reason, 0, 0])?;
                w.u64(*id)?;
            }
            Self::Revoke { reason } => {
                w.u16(*reason)?;
                w.take(&[0; 6])?;
            }
            Self::CloseAck { target, status, id } => {
                w.take(&[*target, *status as u8, 0, 0])?;
                w.u64(*id)?;
            }
        }
        let n = w.position;
        Message::decode(self.kind(), &out[..n])?;
        Ok(n)
    }
    fn kind(&self) -> Kind {
        match self {
            Self::Hello { .. } => Kind::Hello,
            Self::Admit(_) => Kind::Admit,
            Self::AdmitAck { .. } => Kind::AdmitAck,
            Self::OpenIngress { .. } => Kind::OpenIngress,
            Self::IngressReply { .. } => Kind::IngressReply,
            Self::Authorize(_) => Kind::Authorize,
            Self::Grant { .. } => Kind::Grant,
            Self::Probe { .. } => Kind::Probe,
            Self::Renew { .. } => Kind::Renew,
            Self::Deny { .. } => Kind::Deny,
            Self::Cancel { .. } => Kind::Cancel,
            Self::Revoke { .. } => Kind::Revoke,
            Self::CloseAck { .. } => Kind::CloseAck,
        }
    }
}
fn boolean(n: u8) -> Result<bool> {
    match n {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Schema),
    }
}
fn target_id(target: u8, id: u64) -> Result<()> {
    if !(1..=4).contains(&target) || (target == 4) != (id == 0) {
        return Err(Error::Schema);
    }
    Ok(())
}
impl Destination<'_> {
    fn write(self, w: &mut Writer<'_>) -> Result<()> {
        w.take(&[self.family, self.protocol])?;
        w.u16(self.port)?;
        w.u16(self.bytes.len() as u16)?;
        w.u16(0)?;
        w.take(self.bytes)
    }
}
struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}
impl Writer<'_> {
    fn take(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .position
            .checked_add(bytes.len())
            .filter(|n| *n <= self.bytes.len())
            .ok_or(Error::Bounds)?;
        self.bytes[self.position..end].copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }
    fn u8(&mut self, n: u8) -> Result<()> {
        self.take(&[n])
    }
    fn u16(&mut self, n: u16) -> Result<()> {
        self.take(&n.to_be_bytes())
    }
    fn u32(&mut self, n: u32) -> Result<()> {
        self.take(&n.to_be_bytes())
    }
    fn u64(&mut self, n: u64) -> Result<()> {
        self.take(&n.to_be_bytes())
    }
    fn string(&mut self, value: &str, max: usize) -> Result<()> {
        if value.len() > max {
            return Err(Error::Bounds);
        }
        self.u16(value.len() as u16)?;
        self.take(value.as_bytes())
    }
}

struct Frame<'a> {
    header: Header,
    message: Message<'a>,
}
impl<'a> Frame<'a> {
    fn encode(header: Header, message: &Message<'_>, out: &mut [u8]) -> Result<usize> {
        if header.kind != message.kind() {
            return Err(Error::Schema);
        }
        let limit = FRAME_LIMIT.min(out.len());
        let body = out.get_mut(HEADER..limit).ok_or(Error::Bounds)?;
        let n = message.encode(body)?;
        let wire = header.encode(n)?;
        out[..HEADER].copy_from_slice(&wire);
        Ok(HEADER + n)
    }
    fn decode(bytes: &'a [u8], binding: Binding, mode: Mode, from_host: bool) -> Result<Self> {
        let header = Header::decode(bytes.get(..HEADER).ok_or(Error::Bounds)?, bytes.len())?;
        if header.binding != binding {
            return Err(Error::Binding);
        }
        let message = Message::decode(header.kind, &bytes[HEADER..])?;
        let host_kind = matches!(
            header.kind,
            Kind::Admit | Kind::IngressReply | Kind::Grant | Kind::Deny | Kind::Revoke
        );
        if !matches!(header.kind, Kind::Cancel | Kind::CloseAck) && host_kind != from_host {
            return Err(Error::Schema);
        }
        match &message {
            Message::Hello { mode: actual, .. } => {
                if *actual != mode || header.reply_to != 0 || header.object_id != 0 {
                    return Err(Error::Binding);
                }
            }
            Message::Admit(body) => {
                if Capsule::decode(body, &binding.digest)?.mode != mode
                    || header.object_id != 0
                    || header.reply_to == 0
                {
                    return Err(Error::Binding);
                }
            }
            Message::Grant {
                status,
                required,
                grant,
                flow,
                ..
            } => {
                if header.object_id != *grant
                    || header.reply_to == 0
                    || mode == Mode::Local && *required
                    || mode == Mode::System && *flow != 0 && *status == Status::Allow && !required
                {
                    return Err(Error::Binding);
                }
            }
            Message::IngressReply { required, .. } => {
                if *required != mode.required() || header.object_id != 0 || header.reply_to == 0 {
                    return Err(Error::Binding);
                }
            }
            Message::Authorize(a) => {
                if header.reply_to != 0
                    || mode == Mode::Local && a.receipt.kind != ReceiptKind::None
                {
                    return Err(Error::Binding);
                }
            }
            Message::AdmitAck { .. } | Message::Deny { .. } | Message::CloseAck { .. } => {
                if header.reply_to == 0 || header.object_id != 0 {
                    return Err(Error::Schema);
                }
            }
            Message::OpenIngress { .. }
            | Message::Probe { .. }
            | Message::Renew { .. }
            | Message::Cancel { .. }
            | Message::Revoke { .. } => {
                if header.object_id != 0 || header.reply_to != 0 {
                    return Err(Error::Schema);
                }
            }
        }
        Ok(Self { header, message })
    }
}

/// Отдельно от object/request IDs. Ошибка навсегда закрывает decoder direction.
struct Sequence {
    next: u64,
    revoked: bool,
}
impl Sequence {
    fn new() -> Self {
        Self {
            next: 1,
            revoked: false,
        }
    }
    fn accept(&mut self, sequence: u64) -> Result<()> {
        if self.revoked || sequence != self.next || sequence == u64::MAX {
            self.revoked = true;
            return Err(Error::Binding);
        }
        self.next += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_go_a004e92_launch_admission_golden_has_identical_layout() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/go-a004e92-launch-admission.json"
        ))
        .unwrap();
        let config = unhex(f["config_hex"].as_str().unwrap());
        let record = unhex(f["local_record_hex"].as_str().unwrap());
        let launch = LaunchRecord::decode(&record, Mode::Local).unwrap();
        assert_eq!(launch.encode().unwrap().as_slice(), record);
        assert_eq!(
            launch.binding.digest,
            <[u8; 32]>::from(Sha256::digest(&config))
        );
        let body = unhex(f["admit_body_hex"].as_str().unwrap());
        let capsule = Capsule::decode(&body, &launch.binding.digest).unwrap();
        assert_eq!(capsule.manifest, launch.manifest);
        assert_eq!(
            capsule.manifest.to_vec(),
            unhex(f["manifest_sha256"].as_str().unwrap())
        );
        assert!(!capsule.mode.required());
        // Golden проверяет wire grammar, не production construction или config proof.
        assert!(
            yonik_engine::native_profile::ProfileIntent::decode(
                std::str::from_utf8(&config).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn ancillary_shapes_deny_mixed_rights_wrong_peer_and_truncation() {
        let peer = PeerIdentity {
            pid: 12,
            uid: 1000,
            start: 13,
        };
        for credentials in [0, 1, 2] {
            for rights in [0, 1, 2] {
                let observation = AncillaryShape {
                    credentials,
                    rights,
                    truncated: false,
                    seqpacket: true,
                    peer,
                };
                assert_eq!(
                    observation.validate(peer, 1).is_ok(),
                    credentials == 1 && rights == 1
                );
                assert_eq!(
                    observation.validate(peer, 0).is_ok(),
                    credentials == 1 && rights == 0
                );
            }
        }
        for peer in [
            PeerIdentity { pid: 13, ..peer },
            PeerIdentity { uid: 0, ..peer },
            PeerIdentity { start: 14, ..peer },
        ] {
            let observation = AncillaryShape {
                credentials: 1,
                rights: 0,
                truncated: false,
                seqpacket: true,
                peer,
            };
            assert!(
                observation
                    .validate(
                        PeerIdentity {
                            pid: 12,
                            uid: 1000,
                            start: 13
                        },
                        0
                    )
                    .is_err()
            );
        }
        assert!(
            AncillaryShape {
                credentials: 1,
                rights: 0,
                truncated: true,
                seqpacket: true,
                peer
            }
            .validate(peer, 0)
            .is_err()
        );
        assert!(
            AncillaryShape {
                credentials: 1,
                rights: 0,
                truncated: false,
                seqpacket: false,
                peer
            }
            .validate(peer, 0)
            .is_err()
        );
        assert_eq!(
            [
                CONTROL_FD_LOCATOR,
                LAUNCH_FD_LOCATOR,
                PEER_PIDFD_LOCATOR,
                ASSET_ROOT_FD_LOCATOR
            ]
            .len(),
            4
        );
    }
    #[test]
    fn chain_udp443_default_rejection_does_not_remove_valid_tcp_path() {
        use yonik_engine::native_profile::{OwnedIngress, OwnedRuntimePlan, ProfileIntent};
        let mut f = fixture(true);
        f["profile"]["graph"]["outbounds"][1]["mux"]
            .as_object_mut()
            .unwrap()
            .remove("xudpProxyUDP443");
        let intent = ProfileIntent::decode(&f["profile"].to_string()).unwrap();
        let tun = yonik_engine::SystemTun::new(
            1,
            1500,
            42,
            vec![yonik_engine::SystemTunAddress::new("198.18.0.1".parse().unwrap(), 30).unwrap()],
        )
        .unwrap();
        let plan = OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap())
            .unwrap()
            .with_system(tun)
            .map_ingress("provider", OwnedIngress::System)
            .unwrap()
            .bind_system_resolver(&FakeResolver)
            .unwrap();
        let built = OwnedCapsule::build(
            &intent,
            &plan,
            Some(SnapshotRef {
                source: [8; 32],
                asset: [9; 32],
                bytes: 120,
                flags: 0,
            }),
            [3; 32],
            1,
            1,
        )
        .unwrap();
        let capsule = Capsule::decode(built.bytes(), &[3; 32]).unwrap();
        assert_eq!(scope(capsule.tables[8].row(0).unwrap()).unwrap().mask, 1);
        assert_eq!(scope(capsule.tables[8].row(1).unwrap()).unwrap().mask, 0);
        assert_eq!(capsule.tables[2].count, 1);
        assert_eq!(capsule.tables[1].count, 2);
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/system-chain-default-reject.json"
        ))
        .unwrap();
        assert_eq!(
            built.bytes(),
            unhex(golden["capsule_hex"].as_str().unwrap())
        );
        assert_eq!(f["profile"], golden["profile"]);
    }
    #[test]
    fn request_scope_indices_and_actual_branch_must_match_capsule() {
        let built = golden_build(true);
        let capsule = Capsule::decode(built.bytes(), &[3; 32]).unwrap();
        assert!(capsule.mode.required());
        let destination = destination_bytes("example.test", 443, 6).unwrap();
        let mut r = Reader::new(&destination);
        let destination = Destination::read(&mut r).unwrap();
        let mut a = Authorize {
            source_flow: 1,
            class: 1,
            subject: 0,
            chain: 0,
            transport: 0,
            scope: 0,
            branch: 0,
            original: destination,
            effective: destination,
            resolver: NONE,
            query: "",
            receipt: Receipt {
                kind: ReceiptKind::None,
                id: 0,
            },
        };
        assert!(capsule.validate_request(&Message::Authorize(a)).is_ok());
        a.scope = 2;
        assert!(capsule.validate_request(&Message::Authorize(a)).is_err());
        a.subject = 1;
        a.chain = NONE;
        a.transport = 1;
        a.branch = 0;
        assert!(capsule.validate_request(&Message::Authorize(a)).is_err());
        a.branch = 1;
        assert!(capsule.validate_request(&Message::Authorize(a)).is_ok());
        a.branch = 255;
        assert!(capsule.validate_request(&Message::Authorize(a)).is_err());
        assert!(
            capsule
                .validate_request(&Message::Probe {
                    purpose: 1,
                    index: 0,
                    subject: 0,
                    resolver: NONE
                })
                .is_ok()
        );
        assert!(
            capsule
                .validate_request(&Message::Probe {
                    purpose: 1,
                    index: 0,
                    subject: 2,
                    resolver: NONE
                })
                .is_err()
        );
        assert!(
            capsule
                .validate_request(&Message::Probe {
                    purpose: 2,
                    index: 0,
                    subject: 0,
                    resolver: 0
                })
                .is_err()
        );
    }
    #[test]
    fn every_message_and_launch_matches_independent_wire_vectors() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/messages-and-launch.json"
        ))
        .unwrap();
        for vector in f["frames"].as_array().unwrap() {
            let wire = unhex(vector["frame_hex"].as_str().unwrap());
            let host = vector["from_host"].as_bool().unwrap();
            let frame = Frame::decode(&wire, binding(), Mode::Local, host).unwrap();
            assert_eq!(
                frame.header.kind as u16,
                vector["kind"].as_u64().unwrap() as u16
            );
            let mut encoded = [0; 1024];
            let n = frame.message.encode(&mut encoded).unwrap();
            assert_eq!(&encoded[..n], &wire[128..]);
            assert_eq!(frame.header.encode(n).unwrap().as_slice(), &wire[..128]);
            let mut encoded_frame = [0; 2048];
            let n = Frame::encode(frame.header, &frame.message, &mut encoded_frame).unwrap();
            assert_eq!(&encoded_frame[..n], wire);
            for end in 0..wire.len() {
                assert!(Frame::decode(&wire[..end], binding(), Mode::Local, host).is_err());
            }
            let mut bad = wire.clone();
            bad[120] = 1;
            assert!(Frame::decode(&bad, binding(), Mode::Local, host).is_err());
            let mut bad = wire;
            bad[10..12].copy_from_slice(&65535u16.to_be_bytes());
            assert!(Frame::decode(&bad, binding(), Mode::Local, host).is_err());
        }
        for vector in f["launch"].as_array().unwrap() {
            let mode = if vector["system"].as_bool().unwrap() {
                Mode::System
            } else {
                Mode::Local
            };
            let bytes = unhex(vector["record_hex"].as_str().unwrap());
            let record = LaunchRecord::decode(&bytes, mode).unwrap();
            assert_eq!(record.encode().unwrap().as_slice(), bytes);
            record
                .verify_ack(&unhex(vector["ack_hex"].as_str().unwrap()))
                .unwrap();
            let mut bad = bytes.clone();
            bad[184] = 1;
            assert!(LaunchRecord::decode(&bad, mode).is_err());
            for end in 0..bytes.len() {
                assert!(LaunchRecord::decode(&bytes[..end], mode).is_err());
            }
        }
        let budget = MemoryPreflight::new(MAX_CAPS, 65536).unwrap();
        assert_eq!(budget.metadata + budget.buffer_bytes, 8 * 1024 * 1024);
        let mut small = MAX_CAPS;
        small[4] = 1;
        assert!(MemoryPreflight::new(small, 128).is_err());
    }
    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    fn fixture(system: bool) -> serde_json::Value {
        serde_json::from_str(if system {
            include_str!("../../../tests/fixtures/xray-profile-channel-v3/system-chain-probe.json")
        } else {
            include_str!("../../../tests/fixtures/xray-profile-channel-v3/local-minimal.json")
        })
        .unwrap()
    }
    fn binding() -> Binding {
        Binding {
            session: [1; 16],
            invocation: [2; 16],
            digest: [3; 32],
            generation: 4,
            epoch: 5,
        }
    }
    struct FakeResolver;
    impl yonik_engine::native_profile::VerifiedSystemResolver for FakeResolver {
        fn snapshot_digest(&self) -> [u8; 32] {
            [8; 32]
        }
        fn servers(&self) -> Vec<std::net::SocketAddr> {
            vec!["127.0.0.53:53".parse().unwrap()]
        }
    }
    fn golden_build(system: bool) -> OwnedCapsule {
        use yonik_engine::native_profile::{OwnedIngress, OwnedRuntimePlan, ProfileIntent};
        let f = fixture(system);
        let intent = ProfileIntent::decode(&f["profile"].to_string()).unwrap();
        let graph = intent.validate().unwrap();
        for (i, name) in graph.subjects().iter().enumerate() {
            let mut bytes = Vec::new();
            intent.write_transport_sensitive(name, &mut bytes).unwrap();
            assert_eq!(
                bytes,
                unhex(f["transport_preimages_hex"][i].as_str().unwrap()),
                "independent P5STRM01 {name}"
            );
        }
        let mut plan =
            OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
        if system {
            let tun = yonik_engine::SystemTun::new(
                1,
                1500,
                42,
                vec![
                    yonik_engine::SystemTunAddress::new("198.18.0.1".parse().unwrap(), 30).unwrap(),
                ],
            )
            .unwrap();
            plan = plan
                .with_system(tun)
                .map_ingress("provider", OwnedIngress::System)
                .unwrap()
                .bind_system_resolver(&FakeResolver)
                .unwrap();
        }
        OwnedCapsule::build(
            &intent,
            &plan,
            system.then_some(SnapshotRef {
                source: [8; 32],
                asset: [9; 32],
                bytes: 120,
                flags: 0,
            }),
            [3; 32],
            1,
            1,
        )
        .unwrap()
    }
    #[test]
    fn independent_capsule_and_full_frame_vectors_match() {
        for system in [false, true] {
            let f = fixture(system);
            let built = golden_build(system);
            let expected = unhex(f["capsule_hex"].as_str().unwrap());
            assert_eq!(built.bytes(), expected);
            let capsule = Capsule::decode(&expected, &[3; 32]).unwrap();
            assert_eq!(capsule.body, expected);
            assert_eq!(capsule.admission_id, 1);
            assert_eq!(capsule.lease_ms, 60000);
            assert_eq!(capsule.policy_revision, 1);
            assert_eq!(
                capsule.manifest.to_vec(),
                unhex(f["manifest_sha256"].as_str().unwrap())
            );
            let full = unhex(f["admit_frame_hex"].as_str().unwrap());
            let mode = if system { Mode::System } else { Mode::Local };
            let frame = Frame::decode(&full, binding(), mode, true).unwrap();
            assert_eq!(frame.header.sequence, 1);
            assert!(matches!(frame.message, Message::Admit(_)));
            assert!(
                Frame::decode(
                    &full,
                    binding(),
                    if system { Mode::Local } else { Mode::System },
                    true
                )
                .is_err()
            );
            assert!(Frame::decode(&full, binding(), mode, false).is_err());
        }
    }
    fn rehash(bytes: &mut [u8]) {
        let mut hash = Sha256::new();
        hash.update(b"YNKCAP-MANIFEST-v1\0");
        hash.update([3; 32]);
        hash.update(&bytes[76..78]);
        hash.update(&bytes[80..120]);
        hash.update(&bytes[128..]);
        bytes[..32].copy_from_slice(&hash.finalize());
    }
    fn table_start(bytes: &[u8], table: u16) -> usize {
        let mut r = Reader::new(bytes);
        r.take(128).unwrap();
        for _ in 1..table {
            r.u16().unwrap();
            r.u16().unwrap();
            let n = r.u32().unwrap();
            r.take(n as usize).unwrap();
        }
        r.position
    }
    #[test]
    fn malformed_caps_and_rehashed_reference_mutations_fail_without_materialization() {
        let bytes = golden_build(true).bytes().to_vec();
        for n in 0..bytes.len() {
            assert!(Capsule::decode(&bytes[..n], &[3; 32]).is_err());
        }
        for table in 1..=11 {
            let mut bad = bytes.clone();
            let offset = table_start(&bad, table);
            put16(&mut bad, offset + 2, u16::MAX);
            assert!(matches!(
                Capsule::decode(&bad, &[3; 32]),
                Err(Error::Budget)
            ));
        }
        let scope_start = table_start(&bytes, 9) + 8 + 4;
        for (relative, value) in [(0, 255), (3, 4), (4, 17), (8, 255), (16, 255), (22, 1)] {
            let mut bad = bytes.clone();
            bad[scope_start + relative] = value;
            rehash(&mut bad);
            assert!(Capsule::decode(&bad, &[3; 32]).is_err());
        }
        let mut bad = bytes.clone();
        let offset = table_start(&bad, 11) + 8 + 4;
        bad[offset] ^= 1;
        rehash(&mut bad);
        assert!(matches!(
            Capsule::decode(&bad, &[3; 32]),
            Err(Error::Reference)
        ));
        let mut bad = bytes;
        bad[79] = 2;
        assert!(matches!(
            Capsule::decode(&bad, &[3; 32]),
            Err(Error::Schema)
        ));
    }
    #[test]
    fn missing_owner_proof_and_mixed_modes_never_decode_as_allow() {
        let mut body = [0; 128];
        let missing = Message::Grant {
            status: Status::Allow,
            class: 1,
            required: true,
            grant: 1,
            flow: 1,
            lease: 1,
            revision: 1,
            fresh: 0,
            receipt: Receipt {
                kind: ReceiptKind::None,
                id: 0,
            },
        };
        assert!(missing.encode(&mut body).is_err());
        let local = Message::Grant {
            status: Status::Allow,
            class: 1,
            required: false,
            grant: 1,
            flow: 1,
            lease: 1,
            revision: 1,
            fresh: 0,
            receipt: Receipt {
                kind: ReceiptKind::None,
                id: 0,
            },
        };
        let n = local.encode(&mut body).unwrap();
        let header = Header {
            kind: Kind::Grant,
            sequence: 1,
            reply_to: 1,
            binding: binding(),
            object_id: 1,
        }
        .encode(n)
        .unwrap();
        let wire = [header.as_slice(), &body[..n]].concat();
        assert!(Frame::decode(&wire, binding(), Mode::Local, true).is_ok());
        assert!(Frame::decode(&wire, binding(), Mode::System, true).is_err());
        let mut seq = Sequence::new();
        assert!(seq.accept(1).is_ok());
        assert!(seq.accept(3).is_err());
        assert!(seq.accept(2).is_err());
    }
    #[test]
    fn capsule_builder_roundtrips_all_eleven_tables_and_rejects_mutation() {
        use yonik_engine::native_profile::{OwnedRuntimePlan, ProfileIntent};
        let intent=ProfileIntent::decode(r#"{"version":1,"graph":{"outbounds":[{"tag":"direct","protocol":"freedom"}],"dns":{"servers":["192.0.2.53"]}}}"#).unwrap();
        let plan =
            OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
        let built = OwnedCapsule::build(&intent, &plan, None, [3; 32], 1, 1).unwrap();
        let decoded = Capsule::decode(built.bytes(), &[3; 32]).unwrap();
        assert_eq!(decoded.tables.len(), 11);
        assert_eq!(decoded.tables[8].count, 2);
        assert_eq!(decoded.mode, Mode::Local);
        assert!(!decoded.mode.required());
        for n in 0..built.bytes().len() {
            assert!(Capsule::decode(&built.bytes()[..n], &[3; 32]).is_err());
        }
        let mut bad = built.bytes().to_vec();
        bad[77] = 1;
        assert!(Capsule::decode(&bad, &[3; 32]).is_err());
        assert!(Capsule::decode(built.bytes(), &[4; 32]).is_err());
    }
    #[test]
    fn header_and_launch_are_exact_and_mode_separated() {
        let binding = Binding {
            session: [1; 16],
            invocation: [2; 16],
            digest: [3; 32],
            generation: 4,
            epoch: 5,
        };
        let h = Header {
            kind: Kind::Hello,
            sequence: 1,
            reply_to: 0,
            binding,
            object_id: 0,
        };
        let bytes = h.encode(40).unwrap();
        assert_eq!(&bytes[..8], b"YNKCAP01");
        assert_eq!(&bytes[12..16], &168u32.to_be_bytes());
        assert_eq!(Header::decode(&bytes, 168).unwrap(), h);
        let local = LaunchRecord {
            mode: Mode::Local,
            nonce: [6; 32],
            binding,
            owner_pid: 12,
            child_pid: 0,
            owner_start: 13,
            child_start: 0,
            manifest: [7; 32],
        };
        let record = local.encode().unwrap();
        assert_eq!(&record[..8], b"YNKLOC01");
        assert_eq!(LaunchRecord::decode(&record, Mode::Local).unwrap(), local);
        assert!(LaunchRecord::decode(&record, Mode::System).is_err());
        assert!(LaunchRecord::decode(&record[..191], Mode::Local).is_err());
        assert_eq!(&local.ack().unwrap()[..8], b"YNKEXAK1");
    }
    #[test]
    fn messages_reject_unknown_receipts_and_preserve_scope_bytes() {
        let original = destination_bytes("example.test", 443, 6).unwrap();
        let mut r = Reader::new(&original);
        let destination = Destination::read(&mut r).unwrap();
        let message = Message::Authorize(Authorize {
            source_flow: 1,
            class: 1,
            subject: 2,
            chain: NONE,
            transport: 2,
            scope: 4,
            branch: 0,
            original: destination,
            effective: destination,
            resolver: NONE,
            query: "",
            receipt: Receipt {
                kind: ReceiptKind::None,
                id: 0,
            },
        });
        let mut out = [0u8; 1024];
        let n = message.encode(&mut out).unwrap();
        assert_eq!(&out[16..20], &[0, 4, 0, 0]);
        assert!(matches!(
            Message::decode(Kind::Authorize, &out[..n]).unwrap(),
            Message::Authorize(Authorize { scope: 4, .. })
        ));
        for end in 0..n {
            assert!(Message::decode(Kind::Authorize, &out[..end]).is_err());
        }
        out[n - 16] = 3;
        assert!(Message::decode(Kind::Authorize, &out[..n]).is_err());
    }
}
