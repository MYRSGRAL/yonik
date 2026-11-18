//! Типизированные факты RTNETLINK без вычисления политики маршрутизации.

#[cfg(test)]
mod tests;

use super::read::{
    self, NetlinkReader, NetworkAttribute, NetworkNamespace, NetworkReadError, ReadOperation,
};
use crate::Cancellation;
use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[derive(Clone, PartialEq, Eq)]
pub struct IpPrefix {
    pub address: IpAddr,
    pub length: u8,
}
#[derive(Clone, PartialEq, Eq)]
pub struct LinuxLink {
    pub index: u32,
    pub link_type: u16,
    pub flags: u32,
    pub name: Vec<u8>,
    /// IFLA_IFALIAS не является секретом, но Debug его не раскрывает.
    pub alias: Option<Vec<u8>>,
    pub mtu: Option<u32>,
    pub master: Option<u32>,
    pub parent: Option<u32>,
    pub kind: Option<Vec<u8>>,
    pub operational_state: Option<u8>,
    pub unknown: Vec<NetworkAttribute>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct LinuxAddress {
    pub family: u8,
    pub index: u32,
    pub address: IpAddr,
    pub local: Option<IpAddr>,
    pub prefix_len: u8,
    pub scope: u8,
    pub flags: u32,
    pub unknown: Vec<NetworkAttribute>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct RouteNexthop {
    pub flags: u8,
    pub weight: u16,
    pub output_interface: u32,
    pub gateway: Option<IpAddr>,
    pub unknown: Vec<NetworkAttribute>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct LinuxRoute {
    pub family: u8,
    pub destination: IpPrefix,
    pub source: IpPrefix,
    pub table: u32,
    pub preferred_source: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub output_interface: Option<u32>,
    pub input_interface: Option<u32>,
    pub priority: Option<u32>,
    pub protocol: u8,
    pub kind: u8,
    pub scope: u8,
    pub tos: u8,
    pub flags: u32,
    pub multipath: Vec<RouteNexthop>,
    pub nexthop_id: Option<u32>,
    pub unknown: Vec<NetworkAttribute>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct LinuxRule {
    pub family: u8,
    pub destination: IpPrefix,
    pub source: IpPrefix,
    pub tos: u8,
    pub table: u32,
    pub action: u8,
    pub flags: u32,
    pub priority: Option<u32>,
    pub goto: Option<u32>,
    pub fwmark: Option<u32>,
    pub fwmask: Option<u32>,
    pub uid_range: Option<(u32, u32)>,
    pub input_interface: Option<Vec<u8>>,
    pub output_interface: Option<Vec<u8>>,
    pub protocol: Option<u8>,
    pub ip_protocol: Option<u8>,
    pub source_ports: Option<(u16, u16)>,
    pub destination_ports: Option<(u16, u16)>,
    pub suppress_prefix_len: Option<u32>,
    pub suppress_interface_group: Option<u32>,
    pub l3mdev: Option<bool>,
    pub unknown: Vec<NetworkAttribute>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct NexthopMember {
    pub id: u32,
    pub weight: u32,
}
#[derive(Clone, PartialEq, Eq)]
pub struct LinuxNexthop {
    pub id: u32,
    pub family: u8,
    pub scope: u8,
    pub protocol: u8,
    pub flags: u32,
    pub blackhole: bool,
    pub output_interface: Option<u32>,
    pub gateway: Option<IpAddr>,
    pub group_type: Option<u16>,
    pub group: Vec<NexthopMember>,
    pub unknown: Vec<NetworkAttribute>,
}
/// Данные одного ограниченного чтения; не lease и не доказательство применимости TUN.
#[derive(Clone, PartialEq, Eq)]
pub struct LinuxTopology {
    pub namespace: NetworkNamespace,
    pub links: Vec<LinuxLink>,
    pub addresses: Vec<LinuxAddress>,
    pub routes: Vec<LinuxRoute>,
    pub rules: Vec<LinuxRule>,
    pub nexthops: Vec<LinuxNexthop>,
}
macro_rules! redacted_debug {
    ($($name:ty),+ $(,)?) => { $(impl fmt::Debug for $name {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($name), " { <скрыто> }")) }
    })+ };
}
redacted_debug!(
    IpPrefix,
    LinuxLink,
    LinuxAddress,
    RouteNexthop,
    LinuxRoute,
    LinuxRule,
    NexthopMember,
    LinuxNexthop
);
impl fmt::Debug for LinuxTopology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxTopology")
            .field("links", &self.links.len())
            .field("addresses", &self.addresses.len())
            .field("routes", &self.routes.len())
            .field("rules", &self.rules.len())
            .field("nexthops", &self.nexthops.len())
            .field("unsupported", &self.unsupported_count())
            .finish()
    }
}
impl LinuxTopology {
    pub fn unsupported_count(&self) -> usize {
        self.links.iter().map(|v| v.unknown.len()).sum::<usize>()
            + self
                .addresses
                .iter()
                .map(|v| v.unknown.len())
                .sum::<usize>()
            + self
                .routes
                .iter()
                .map(|v| {
                    v.unknown.len() + v.multipath.iter().map(|h| h.unknown.len()).sum::<usize>()
                })
                .sum::<usize>()
            + self.rules.iter().map(|v| v.unknown.len()).sum::<usize>()
            + self.nexthops.iter().map(|v| v.unknown.len()).sum::<usize>()
    }
    /// Неинтерпретированные атрибуты, не проверка целостности ссылок или lease Apply.
    pub fn incomplete(&self) -> bool {
        self.unsupported_count() != 0
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TopologyCapture {
    addresses: [super::equivalence::CaptureWindow; 2],
    routes: [super::equivalence::RouteCapture; 2],
}
impl TopologyCapture {
    pub(crate) fn route(self, family: u8) -> super::equivalence::RouteCapture {
        self.routes[usize::from(family == 10)]
    }
    pub(crate) fn family(self, family: u8) -> super::equivalence::CaptureWindow {
        self.addresses[usize::from(family == 10)]
    }
}
/// Ограничение действует на все запросы целиком, без автоматических повторов.
/// Требует Tokio runtime с включёнными I/O и time; не выполняет Apply.
pub async fn read_topology(
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<LinuxTopology, NetworkReadError> {
    read_topology_captured(cancel, timeout)
        .await
        .map(|(topology, _)| topology)
}
pub(crate) async fn read_topology_captured(
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<(LinuxTopology, TopologyCapture), NetworkReadError> {
    cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
    if timeout.is_zero() || timeout > Duration::from_secs(5) {
        return Err(NetworkReadError::Limit);
    }
    let deadline = tokio::time::Instant::now() + timeout;
    let mut reader = NetlinkReader::open()?;
    let mut result = LinuxTopology {
        namespace: reader.namespace(),
        links: Vec::new(),
        addresses: Vec::new(),
        routes: Vec::new(),
        rules: Vec::new(),
        nexthops: Vec::new(),
    };
    for message in reader
        .request(ReadOperation::Links, &[0; 16], cancel, deadline)
        .await?
    {
        result.links.push(parse_link(&message.payload)?);
    }
    let now = tokio::time::Instant::now();
    let mut capture = TopologyCapture {
        addresses: [super::equivalence::CaptureWindow {
            start: now,
            end: now,
        }; 2],
        routes: [super::equivalence::RouteCapture::new(now, now); 2],
    };
    for (slot, family) in [2, 10].into_iter().enumerate() {
        let mut addr = [0; 8];
        addr[0] = family;
        let start = tokio::time::Instant::now();
        let messages = reader
            .request(ReadOperation::Addresses, &addr, cancel, deadline)
            .await?;
        capture.addresses[slot] = super::equivalence::CaptureWindow {
            start,
            end: tokio::time::Instant::now(),
        };
        for message in messages {
            result.addresses.push(parse_address(&message.payload)?);
        }
        let mut header = [0; 12];
        header[0] = family;
        let start = tokio::time::Instant::now();
        let messages = reader
            .request(ReadOperation::Routes, &header, cancel, deadline)
            .await?;
        capture.routes[slot] =
            super::equivalence::RouteCapture::new(start, tokio::time::Instant::now());
        for message in messages {
            result.routes.push(parse_route(&message.payload)?);
        }
        for message in reader
            .request(ReadOperation::Rules, &header, cancel, deadline)
            .await?
        {
            result.rules.push(parse_rule(&message.payload)?);
        }
    }
    for message in reader
        .request(ReadOperation::Nexthops, &[0; 8], cancel, deadline)
        .await?
    {
        result.nexthops.push(parse_nexthop(&message.payload)?);
    }
    reader.finish(cancel, deadline)?;
    cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
    if tokio::time::Instant::now() >= deadline {
        return Err(NetworkReadError::Timeout);
    }
    Ok((result, capture))
}

pub(crate) async fn reread_changed_topology(
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<(LinuxTopology, TopologyCapture), NetworkReadError> {
    retry_snapshot(cancel, timeout, read_topology_captured).await
}

async fn retry_snapshot<T>(
    cancel: &mut Cancellation,
    timeout: Duration,
    mut read: impl AsyncFnMut(&mut Cancellation, Duration) -> Result<T, NetworkReadError>,
) -> Result<T, NetworkReadError> {
    const RETRIES: usize = 2;
    if timeout.is_zero() || timeout > Duration::from_secs(5) {
        return Err(NetworkReadError::Limit);
    }
    let deadline = tokio::time::Instant::now() + timeout;
    let mut retries = 0;
    loop {
        cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(NetworkReadError::Timeout);
        }
        match read(cancel, remaining).await {
            Err(NetworkReadError::Changed | NetworkReadError::Interrupted) if retries < RETRIES => {
                retries += 1;
                tokio::task::yield_now().await;
            }
            result => return result,
        }
    }
}

type Error = NetworkReadError;
/// Проверяет дубликаты за O(n log n), сохраняя исходные флаги неизвестных типов.
struct Attrs<'a>(BTreeMap<u16, (u16, &'a [u8])>);
impl<'a> Attrs<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut result = BTreeMap::new();
        for (raw, value) in read::attributes(bytes)? {
            let kind = raw & 0x3fff;
            if let Some((old_raw, old)) = result.insert(kind, (raw, value)) {
                if old_raw != raw || old != value {
                    return Err(Error::Malformed);
                }
            }
        }
        Ok(Self(result))
    }
    fn take(&mut self, kind: u16) -> Option<&'a [u8]> {
        let (raw, _) = self.0.get(&kind)?;
        // Флаги неизвестного представления сохраняем вместе с исходными байтами.
        if raw & 0x4000 != 0 || (raw & 0x8000 != 0 && kind != 18) {
            return None;
        }
        self.0.remove(&kind).map(|(_, v)| v)
    }
    fn u32(&mut self, kind: u16) -> Result<Option<u32>, Error> {
        self.take(kind).map(read::u32_value).transpose()
    }
    fn u8(&mut self, kind: u16) -> Result<Option<u8>, Error> {
        self.take(kind).map(byte).transpose()
    }
    fn ip(&mut self, kind: u16, family: u8) -> Result<Option<IpAddr>, Error> {
        self.take(kind)
            .map(|v| read::ip_value(family, v))
            .transpose()
    }
    fn name(&mut self, kind: u16) -> Result<Option<Vec<u8>>, Error> {
        self.take(kind).map(name).transpose()
    }
    fn unknown(self) -> Vec<NetworkAttribute> {
        self.0
            .into_values()
            .map(|(kind, value)| NetworkAttribute {
                kind,
                value: value.to_vec(),
            })
            .collect()
    }
}
fn byte(value: &[u8]) -> Result<u8, Error> {
    match value {
        [v] => Ok(*v),
        _ => Err(Error::Malformed),
    }
}
fn name(value: &[u8]) -> Result<Vec<u8>, Error> {
    if value.len() < 2
        || value.len() > 16
        || value.last() != Some(&0)
        || value[..value.len() - 1].contains(&0)
    {
        return Err(Error::Malformed);
    }
    Ok(value[..value.len() - 1].to_vec())
}
fn header(bytes: &[u8], len: usize) -> Result<&[u8], Error> {
    bytes.get(..len).ok_or(Error::Malformed)
}
fn prefix(family: u8, length: u8, address: Option<IpAddr>) -> Result<IpPrefix, Error> {
    let address = match (family, address) {
        (2, Some(IpAddr::V4(ip))) if length <= 32 => IpAddr::V4(Ipv4Addr::from(
            u32::from(ip) & u32::MAX.checked_shl(u32::from(32 - length)).unwrap_or(0),
        )),
        (10, Some(IpAddr::V6(ip))) if length <= 128 => IpAddr::V6(Ipv6Addr::from(
            u128::from(ip) & u128::MAX.checked_shl(u32::from(128 - length)).unwrap_or(0),
        )),
        (2, None) if length == 0 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        (10, None) if length == 0 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        _ => return Err(Error::Malformed),
    };
    Ok(IpPrefix { address, length })
}
pub(super) fn parse_link(bytes: &[u8]) -> Result<LinuxLink, Error> {
    let h = header(bytes, 16)?;
    let index = read::u32_value(&h[4..8])?;
    if index == 0 || index > i32::MAX as u32 {
        return Err(Error::Malformed);
    }
    let mut a = Attrs::new(&bytes[16..])?;
    let name = a.name(3)?.ok_or(Error::Malformed)?;
    let alias = a.take(20).map(link_alias).transpose()?;
    let mtu = a.u32(4)?;
    let master = a.u32(10)?;
    let parent = a.u32(5)?;
    let operational_state = a.u8(16)?;
    let mut extra_info = None;
    let info_kind = a.0.get(&18).map(|(raw, _)| *raw).unwrap_or(18);
    let kind = if let Some(info_bytes) = a.take(18) {
        let mut info = Attrs::new(info_bytes)?;
        let kind = info
            .take(1)
            .map(|v| {
                if v.len() < 2
                    || v.len() > 256
                    || v.last() != Some(&0)
                    || v[..v.len() - 1].contains(&0)
                {
                    return Err(Error::Malformed);
                }
                Ok(v[..v.len() - 1].to_vec())
            })
            .transpose()?;
        // Не теряем вложенные данные драйвера вместе с известным KIND.
        if !info.0.is_empty() {
            extra_info = Some(NetworkAttribute {
                kind: info_kind,
                value: info_bytes.to_vec(),
            });
        }
        kind
    } else {
        None
    };
    let mut unknown = a.unknown();
    unknown.extend(extra_info);
    Ok(LinuxLink {
        index,
        link_type: read::u16_value(&h[2..4])?,
        flags: read::u32_value(&h[8..12])?,
        name,
        alias,
        mtu,
        master,
        parent,
        kind,
        operational_state,
        unknown,
    })
}
fn link_alias(value: &[u8]) -> Result<Vec<u8>, Error> {
    // IFALIASZ=256 из Linux uapi/linux/if.h; dump включает завершающий NUL.
    if value.is_empty()
        || value.len() > 256
        || value.last() != Some(&0)
        || value[..value.len() - 1].contains(&0)
    {
        return Err(Error::Malformed);
    }
    Ok(value[..value.len() - 1].to_vec())
}
pub(super) fn parse_address(bytes: &[u8]) -> Result<LinuxAddress, Error> {
    let h = header(bytes, 8)?;
    let mut a = Attrs::new(&bytes[8..])?;
    let address = a.ip(1, h[0])?;
    let local = a.ip(2, h[0])?;
    let address = address.or(local).ok_or(Error::Malformed)?;
    prefix(h[0], h[1], Some(address))?;
    let flags = a.u32(8)?.unwrap_or(u32::from(h[2]));
    if flags & 0xff != u32::from(h[2]) {
        return Err(Error::Malformed);
    }
    let index = read::u32_value(&h[4..8])?;
    if index == 0 {
        return Err(Error::Malformed);
    }
    Ok(LinuxAddress {
        family: h[0],
        index,
        address,
        local,
        prefix_len: h[1],
        scope: h[3],
        flags,
        unknown: a.unknown(),
    })
}
pub(super) fn parse_route(bytes: &[u8]) -> Result<LinuxRoute, Error> {
    let h = header(bytes, 12)?;
    let mut a = Attrs::new(&bytes[12..])?;
    let destination = prefix(h[0], h[1], a.ip(1, h[0])?)?;
    let source = prefix(h[0], h[2], a.ip(2, h[0])?)?;
    let table = a.u32(15)?.unwrap_or(u32::from(h[4]));
    let gateway = a.ip(5, h[0])?;
    let preferred_source = a.ip(7, h[0])?;
    let output_interface = a.u32(4)?;
    let input_interface = a.u32(3)?;
    let priority = a.u32(6)?;
    let nexthop_id = a.u32(30)?;
    let multipath = a
        .take(9)
        .map(|v| parse_multipath(v, h[0]))
        .transpose()?
        .unwrap_or_default();
    Ok(LinuxRoute {
        family: h[0],
        destination,
        source,
        table,
        preferred_source,
        gateway,
        output_interface,
        input_interface,
        priority,
        protocol: h[5],
        scope: h[6],
        kind: h[7],
        tos: h[3],
        flags: read::u32_value(&h[8..12])?,
        multipath,
        nexthop_id,
        unknown: a.unknown(),
    })
}
fn parse_multipath(mut bytes: &[u8], family: u8) -> Result<Vec<RouteNexthop>, Error> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let h = header(bytes, 8)?;
        let len = usize::from(read::u16_value(&h[..2])?);
        if len < 8 || len > bytes.len() {
            return Err(Error::Malformed);
        }
        let output_interface = read::u32_value(&h[4..8])?;
        if output_interface > i32::MAX as u32 {
            return Err(Error::Malformed);
        }
        let mut a = Attrs::new(&bytes[8..len])?;
        let gateway = a.ip(5, family)?;
        result.push(RouteNexthop {
            flags: h[2],
            weight: u16::from(h[3]) + 1,
            output_interface,
            gateway,
            unknown: a.unknown(),
        });
        let aligned = (len + 3) & !3;
        bytes = bytes.get(aligned..).ok_or(Error::Malformed)?;
    }
    if result.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(result)
}
fn range32(value: &[u8]) -> Result<(u32, u32), Error> {
    header(value, 8)?;
    if value.len() != 8 {
        return Err(Error::Malformed);
    }
    let start = read::u32_value(&value[..4])?;
    let end = read::u32_value(&value[4..])?;
    if start > end {
        return Err(Error::Malformed);
    }
    Ok((start, end))
}
fn range16(value: &[u8]) -> Result<(u16, u16), Error> {
    header(value, 4)?;
    if value.len() != 4 {
        return Err(Error::Malformed);
    }
    let start = read::u16_value(&value[..2])?;
    let end = read::u16_value(&value[2..])?;
    if start > end {
        return Err(Error::Malformed);
    }
    Ok((start, end))
}
pub(super) fn parse_rule(bytes: &[u8]) -> Result<LinuxRule, Error> {
    let h = header(bytes, 12)?;
    let mut a = Attrs::new(&bytes[12..])?;
    let destination = prefix(h[0], h[1], a.ip(1, h[0])?)?;
    let source = prefix(h[0], h[2], a.ip(2, h[0])?)?;
    let table = a.u32(15)?.unwrap_or(u32::from(h[4]));
    let priority = a.u32(6)?;
    let goto = a.u32(4)?;
    let fwmark = a.u32(10)?;
    let fwmask = a.u32(16)?;
    let uid_range = a.take(20).map(range32).transpose()?;
    let input_interface = a.name(3)?;
    let output_interface = a.name(17)?;
    let protocol = a.u8(21)?;
    let ip_protocol = a.u8(22)?;
    let source_ports = a.take(23).map(range16).transpose()?;
    let destination_ports = a.take(24).map(range16).transpose()?;
    let suppress_prefix_len = a.u32(14)?;
    let suppress_interface_group = a.u32(13)?;
    let l3mdev = a
        .u8(19)?
        .map(|v| match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Malformed),
        })
        .transpose()?;
    Ok(LinuxRule {
        family: h[0],
        destination,
        source,
        tos: h[3],
        table,
        action: h[7],
        flags: read::u32_value(&h[8..12])?,
        priority,
        goto,
        fwmark,
        fwmask,
        uid_range,
        input_interface,
        output_interface,
        protocol,
        ip_protocol,
        source_ports,
        destination_ports,
        suppress_prefix_len,
        suppress_interface_group,
        l3mdev,
        unknown: a.unknown(),
    })
}
pub(super) fn parse_nexthop(bytes: &[u8]) -> Result<LinuxNexthop, Error> {
    let h = header(bytes, 8)?;
    if ![0, 2, 10].contains(&h[0]) {
        return Err(Error::Unsupported);
    }
    let mut a = Attrs::new(&bytes[8..])?;
    let id = a.u32(1)?.filter(|v| *v != 0).ok_or(Error::Malformed)?;
    let blackhole = match a.take(4) {
        None => false,
        Some([]) => true,
        Some(_) => return Err(Error::Malformed),
    };
    let output_interface = a.u32(5)?;
    let gateway = a.ip(6, h[0])?;
    let group_type = a.take(3).map(read::u16_value).transpose()?;
    let mut group = Vec::new();
    if let Some(members) = a.take(2) {
        if members.is_empty() || members.len() % 8 != 0 {
            return Err(Error::Malformed);
        }
        for member in members.chunks_exact(8) {
            let id = read::u32_value(&member[..4])?;
            if id == 0 || member[6..] != [0, 0] {
                return Err(Error::Malformed);
            }
            group.push(NexthopMember {
                id,
                weight: u32::from(member[4]) + (u32::from(member[5]) << 8) + 1,
            });
        }
    }
    if (blackhole && (output_interface.is_some() || gateway.is_some()))
        || (!group.is_empty() && (blackhole || output_interface.is_some() || gateway.is_some()))
        || (group.is_empty() && group_type.is_some())
    {
        return Err(Error::Malformed);
    }
    Ok(LinuxNexthop {
        id,
        family: h[0],
        scope: h[1],
        protocol: h[2],
        flags: read::u32_value(&h[4..8])?,
        blackhole,
        output_interface,
        gateway,
        group_type,
        group,
        unknown: a.unknown(),
    })
}
