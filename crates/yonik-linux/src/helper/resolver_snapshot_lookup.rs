//! Captured netgo DATA. Ни I/O, ни SourceObservationId, ни разрешений здесь нет.
use super::super::memory::{ByteBudget, ByteLease};
use super::EgressError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const CANDIDATES: usize = 7;
#[cfg(test)]
static PLAN_PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(super) fn audit_peak() -> [usize; 2] {
    [
        PLAN_PEAK.load(std::sync::atomic::Ordering::Relaxed),
        SCAN_BYTES,
    ]
}
#[derive(Clone, Copy)]
struct NameBuffer {
    bytes: [u8; 254],
    len: usize,
}
impl NameBuffer {
    fn empty() -> Self {
        Self {
            bytes: [0; 254],
            len: 0,
        }
    }
    fn join(parts: &[&str]) -> Result<Self, EgressError> {
        let mut value = Self::empty();
        for part in parts {
            let end = value
                .len
                .checked_add(part.len())
                .filter(|n| *n <= 254)
                .ok_or(EgressError::Budget)?;
            value.bytes[value.len..end].copy_from_slice(part.as_bytes());
            value.len = end;
        }
        Ok(value)
    }
    fn text(&self) -> Result<&str, EgressError> {
        std::str::from_utf8(&self.bytes[..self.len]).map_err(|_| EgressError::Resolver)
    }
}
struct CandidateNames {
    names: [NameBuffer; CANDIDATES],
    unique: usize,
    order: [u8; CANDIDATES],
    count: usize,
}
impl CandidateNames {
    fn new() -> Self {
        Self {
            names: [NameBuffer::empty(); CANDIDATES],
            unique: 0,
            order: [0; CANDIDATES],
            count: 0,
        }
    }
    fn add(&mut self, parts: &[&str]) -> Result<(), EgressError> {
        let value = NameBuffer::join(parts)?;
        let fqdn = value.text()?;
        if avoid_dns(fqdn) {
            return Ok(());
        }
        if !dns_name(fqdn) {
            return Err(EgressError::Resolver);
        }
        if self.count == CANDIDATES {
            return Err(EgressError::Budget);
        }
        let mut index = None;
        for (i, q) in self.names[..self.unique].iter().enumerate() {
            if q.text()? == fqdn {
                index = Some(i);
                break;
            }
        }
        let index = if let Some(i) = index {
            i
        } else {
            let i = self.unique;
            self.names[i] = value;
            self.unique += 1;
            i
        };
        self.order[self.count] = index as u8;
        self.count += 1;
        Ok(())
    }
    fn bytes(&self) -> usize {
        self.names[..self.unique]
            .iter()
            .map(|q| q.len + if q.len == 1 { 1 } else { q.len - 1 })
            .sum()
    }
    fn materialize(&self) -> Result<Vec<Question>, EgressError> {
        let mut out = Vec::with_capacity(self.unique);
        for q in &self.names[..self.unique] {
            let fqdn = q.text()?;
            out.push(Question {
                fqdn: fqdn.to_owned(),
                canonical: if fqdn == "." {
                    ".".to_owned()
                } else {
                    fqdn[..fqdn.len() - 1].to_ascii_lowercase()
                },
            });
        }
        Ok(out)
    }
}
// Все preflight buffers фиксированы; в materialization они ещё живы и оплачены
// отдельно от exact retained capacities. Нет format/clone временных Strings.
const SCAN_BYTES: usize = std::mem::size_of::<CandidateNames>()
    + 2 * std::mem::size_of::<NameBuffer>()
    + 6 * std::mem::size_of::<&str>()
    + std::mem::size_of::<Reader<'static>>()
    + std::mem::size_of::<HostScan<'static>>()
    + 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupFamily {
    Any,
    Ipv4,
    Ipv6,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIdentity {
    pub source_epoch: u64,
    pub source_digest: [u8; 32],
    pub asset_hash: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseSource {
    SourceObservationRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostMember {
    pub index: u16,
    pub address: IpAddr,
}
pub struct HostsStep<'a> {
    row: u16,
    alias: &'a str,
    members: Vec<HostMember>,
}
impl<'a> HostsStep<'a> {
    pub fn row(&self) -> u16 {
        self.row
    }
    pub fn alias(&self) -> &'a str {
        self.alias
    }
    pub fn members(&self) -> &[HostMember] {
        &self.members
    }
    pub fn lease_source(&self) -> LeaseSource {
        LeaseSource::SourceObservationRequired
    }
    /// Верхняя граница будущего observation, не уже выданный lease/deadline.
    pub fn max_observation_ns(&self) -> u64 {
        1_000_000_000
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkOptions {
    pub attempts: u8,
    pub timeout_ms: u32,
    pub rotate: bool,
    pub single_request: bool,
    pub use_tcp: bool,
    pub query_options: u16,
    pub udp_payload: u16,
}
pub struct Question {
    fqdn: String,
    canonical: String,
}
impl Question {
    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }
    pub fn canonical(&self) -> &str {
        &self.canonical
    }
}
pub struct NetworkStep<'a> {
    peers: &'a [SocketAddr],
    options: NetworkOptions,
    family: LookupFamily,
    questions: Vec<Question>,
    order: [u8; CANDIDATES],
    count: usize,
}
impl<'a> NetworkStep<'a> {
    pub fn peers(&self) -> &'a [SocketAddr] {
        self.peers
    }
    pub fn options(&self) -> NetworkOptions {
        self.options
    }
    pub fn qtypes(&self) -> &'static [u16] {
        match self.family {
            LookupFamily::Any => &[1, 28],
            LookupFamily::Ipv4 => &[1],
            LookupFamily::Ipv6 => &[28],
        }
    }
    /// Повторные search suffixes сохраняют pinned sequence, но не копии строк.
    pub fn questions(&self) -> impl Iterator<Item = &Question> {
        self.order[..self.count]
            .iter()
            .map(|i| &self.questions[usize::from(*i)])
    }
    pub fn unique_question_count(&self) -> usize {
        self.questions.len()
    }
}
/// Следующий step допустим только если предыдущий DNS step не дал адресов.
/// Конкретные DNS errors/retries/семейства обрабатывает future runner по policy.
pub enum LookupStep<'a> {
    Hosts(HostsStep<'a>),
    Network(NetworkStep<'a>),
}
pub struct ResolverLookupPlan<'a> {
    original: &'a str,
    key: String,
    identity: SourceIdentity,
    steps: Vec<LookupStep<'a>>,
    _memory: ByteLease,
}
impl<'a> ResolverLookupPlan<'a> {
    pub fn original(&self) -> &'a str {
        self.original
    }
    pub fn lookup_key(&self) -> &str {
        &self.key
    }
    pub fn identity(&self) -> SourceIdentity {
        self.identity
    }
    pub fn steps(&self) -> &[LookupStep<'a>] {
        &self.steps
    }
}
pub enum ResolverLookup<'a> {
    Numeric(IpAddr),
    Hostname(ResolverLookupPlan<'a>),
}
/// Конструктор доступен только owning profile_intent. Это DATA, не custody proof.
pub(super) struct Captured<'a> {
    pub asset: &'a [u8],
    pub peers: &'a [SocketAddr],
    pub reference: crate::profile_channel::SnapshotRef,
    pub epoch: u64,
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], EgressError> {
        let end = self.at.checked_add(n).ok_or(EgressError::Budget)?;
        let out = self.bytes.get(self.at..end).ok_or(EgressError::Resolver)?;
        self.at = end;
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8, EgressError> {
        Ok(self.take(1)?[0])
    }
    fn short(&mut self) -> Result<u16, EgressError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn string(&mut self) -> Result<&'a str, EgressError> {
        let n = usize::from(self.short()?);
        std::str::from_utf8(self.take(n)?).map_err(|_| EgressError::Resolver)
    }
    fn ip(&mut self) -> Result<IpAddr, EgressError> {
        match self.byte()? {
            4 => {
                let b = self.take(4)?;
                Ok(Ipv4Addr::new(b[0], b[1], b[2], b[3]).into())
            }
            6 => {
                let b: [u8; 16] = self
                    .take(16)?
                    .try_into()
                    .map_err(|_| EgressError::Resolver)?;
                Ok(Ipv6Addr::from(b).into())
            }
            _ => Err(EgressError::Resolver),
        }
    }
}
fn avoid_dns(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    name.get(name.len().saturating_sub(6)..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".onion"))
}
fn dns_name(name: &str) -> bool {
    if name == "." {
        return true;
    }
    if name.is_empty() || name.len() > 254 || name.len() == 254 && !name.ends_with('.') {
        return false;
    }
    let key = name.strip_suffix('.').unwrap_or(name);
    key.bytes()
        .any(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'-')
        && key.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}
struct HostScan<'a> {
    row: u16,
    alias: &'a str,
    count: usize,
    at: usize,
}
fn hosts<'a>(r: &mut Reader<'a>, key: &str) -> Result<Option<HostScan<'a>>, EgressError> {
    let count = r.short()?;
    for row in 0..count {
        let alias = r.string()?;
        let count = r.short()?;
        if count > 16 {
            return Err(EgressError::Budget);
        }
        let at = r.at;
        for _ in 0..count {
            r.ip()?;
        }
        if alias == key {
            return Ok(Some(HostScan {
                row,
                alias,
                count: usize::from(count),
                at,
            }));
        }
    }
    Ok(None)
}
pub(super) fn plan<'a>(
    capture: Captured<'a>,
    original: &'a str,
    family: LookupFamily,
    budget: &ByteBudget,
) -> Result<ResolverLookupPlan<'a>, EgressError> {
    if capture.epoch == 0 || capture.epoch == u64::MAX {
        return Err(EgressError::InvalidBinding);
    }
    if original.len() > 253 {
        return Err(EgressError::Budget);
    }
    if original.parse::<IpAddr>().is_ok() {
        return Err(EgressError::InvalidEndpoint);
    }
    crate::profile_channel::resolver_name(original, original.ends_with('.'), false)
        .map_err(|_| EgressError::Resolver)?;
    // Fixed verifier scratch оплачен owning channel/snapshot и завершён
    // до новых scan buffers. Это не источник custody/authority.
    crate::profile_channel::verify_resolver_asset(capture.asset, capture.reference)
        .map_err(|_| EgressError::Stale)?;
    let _scratch = budget
        .reserve(SCAN_BYTES)
        .map_err(|_| EgressError::Budget)?;
    let mut r = Reader {
        bytes: capture.asset,
        at: 152,
    };
    let order = r.byte()?;
    let ndots = r.byte()?;
    let attempts = r.byte()?;
    r.take(1)?;
    let timeout = u32::from_be_bytes(r.take(4)?.try_into().map_err(|_| EgressError::Resolver)?);
    let flags = r.short()?;
    r.string()?;
    let count = usize::from(r.short()?);
    if count > 6 {
        return Err(EgressError::Budget);
    }
    let mut searches = [""; 6];
    for suffix in &mut searches[..count] {
        *suffix = r.string()?;
    }
    let peers = usize::from(r.short()?);
    if peers != capture.peers.len() {
        return Err(EgressError::Stale);
    }
    for peer in capture.peers {
        let family = r.byte()?;
        r.take(1)?;
        let port = r.short()?;
        let ip = match family {
            4 => {
                let b = r.take(4)?;
                IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(r.take(16)?).map_err(|_| EgressError::Resolver)?,
            )),
            _ => return Err(EgressError::Resolver),
        };
        if *peer != SocketAddr::new(ip, port) {
            return Err(EgressError::Stale);
        }
    }
    let mut key_buffer = NameBuffer::join(&[
        original,
        if original.contains('.') && !original.ends_with('.') {
            "."
        } else {
            ""
        },
    ])?;
    key_buffer.bytes[..key_buffer.len].make_ascii_lowercase();
    let key = key_buffer.text()?;
    let host = if order == 2 {
        None
    } else {
        hosts(&mut r, key)?
    };
    let host_first = matches!(order, 1 | 3) && host.is_some();
    let network_needed = !host_first && order != 1;
    let mut names = CandidateNames::new();
    if network_needed {
        if !dns_name(original) {
            return Err(EgressError::Resolver);
        }
        if original.ends_with('.') {
            names.add(&[original])?;
        } else {
            let first = original.bytes().filter(|b| *b == b'.').count() >= usize::from(ndots);
            if first {
                names.add(&[original, "."])?;
            }
            for suffix in &searches[..count] {
                if original.len() + 1 + suffix.len() <= 254 {
                    names.add(&[original, ".", suffix])?;
                }
            }
            if !first {
                names.add(&[original, "."])?;
            }
        }
    }
    let include_host = host_first || order == 4 && host.is_some();
    let step_count = usize::from(include_host) + usize::from(names.count != 0);
    let member_count = if include_host {
        host.as_ref().map_or(0, |h| h.count)
    } else {
        0
    };
    let bytes = std::mem::size_of::<ResolverLookupPlan<'_>>()
        + key.len()
        + step_count * std::mem::size_of::<LookupStep<'_>>()
        + member_count * std::mem::size_of::<HostMember>()
        + names.unique * std::mem::size_of::<Question>()
        + names.bytes();
    let memory = budget.reserve(bytes).map_err(|_| EgressError::Budget)?;
    #[cfg(test)]
    PLAN_PEAK.fetch_max(budget.used(), std::sync::atomic::Ordering::Relaxed);
    let key = key.to_owned();
    let mut steps = Vec::with_capacity(step_count);
    let host = if include_host {
        let h = host.ok_or(EgressError::Resolver)?;
        let mut r = Reader {
            bytes: capture.asset,
            at: h.at,
        };
        let mut members = Vec::with_capacity(h.count);
        for index in 0..h.count {
            members.push(HostMember {
                index: index as u16,
                address: r.ip()?,
            });
        }
        Some(HostsStep {
            row: h.row,
            alias: h.alias,
            members,
        })
    } else {
        None
    };
    if host_first {
        steps.push(LookupStep::Hosts(host.ok_or(EgressError::Resolver)?));
    } else {
        if names.count != 0 {
            let network = NetworkStep {
                peers: capture.peers,
                family,
                options: NetworkOptions {
                    attempts,
                    timeout_ms: timeout,
                    rotate: flags & 1 != 0,
                    single_request: flags & 2 != 0,
                    use_tcp: flags & 4 != 0,
                    query_options: 1
                        | if flags & 16 != 0 { 8 } else { 0 }
                        | if flags & 8 != 0 { 16 } else { 0 },
                    udp_payload: if flags & 16 != 0 { 1232 } else { 0 },
                },
                questions: names.materialize()?,
                order: names.order,
                count: names.count,
            };
            steps.push(LookupStep::Network(network));
        }
        if order == 4 {
            if let Some(host) = host {
                steps.push(LookupStep::Hosts(host));
            }
        }
    }
    Ok(ResolverLookupPlan {
        original,
        key,
        identity: SourceIdentity {
            source_epoch: capture.epoch,
            source_digest: capture.reference.source,
            asset_hash: capture.reference.asset,
        },
        steps,
        _memory: memory,
    })
}
