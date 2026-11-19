//! Запрос решения ядра для заданного контекста. Пакеты при этом не отправляются.

use super::read::{
    NetlinkReader, NetworkAttribute, NetworkNamespace, NetworkReadError, ReadOperation, attributes,
    ip_value, retry_snapshot, u32_value,
};
use crate::Cancellation;
use std::{fmt, net::IpAddr, num::NonZeroU32, time::Duration};
use tokio::time::Instant;

/// Порты имеют смысл только вместе с явным транспортным протоколом.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// UID задаётся вызывающим кодом явно; это контекст запроса, а не авторизация.
#[derive(Clone, PartialEq, Eq)]
pub struct RouteQuery {
    destination: IpAddr,
    source: Option<IpAddr>,
    uid: u32,
    mark: u32,
    tos: u8,
    input_interface: Option<NonZeroU32>,
    output_interface: Option<NonZeroU32>,
    transport: Option<TransportProtocol>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
}
impl RouteQuery {
    pub fn new(destination: IpAddr, uid: u32) -> Self {
        Self {
            destination,
            source: None,
            uid,
            mark: 0,
            tos: 0,
            input_interface: None,
            output_interface: None,
            transport: None,
            source_port: None,
            destination_port: None,
        }
    }
    pub fn with_source(mut self, source: IpAddr) -> Result<Self, NetworkReadError> {
        if self.destination.is_ipv4() != source.is_ipv4() {
            return Err(NetworkReadError::Malformed);
        }
        self.source = Some(source);
        Ok(self)
    }
    pub fn with_mark(mut self, mark: u32) -> Self {
        self.mark = mark;
        self
    }
    pub fn with_tos(mut self, tos: u8) -> Self {
        self.tos = tos;
        self
    }
    pub fn with_interfaces(
        mut self,
        input: Option<NonZeroU32>,
        output: Option<NonZeroU32>,
    ) -> Self {
        self.input_interface = input;
        self.output_interface = output;
        self
    }
    pub fn with_transport(
        mut self,
        transport: TransportProtocol,
        source_port: Option<u16>,
        destination_port: Option<u16>,
    ) -> Self {
        self.transport = Some(transport);
        self.source_port = source_port;
        self.destination_port = destination_port;
        self
    }
    pub fn destination(&self) -> IpAddr {
        self.destination
    }
    pub fn source(&self) -> Option<IpAddr> {
        self.source
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn mark(&self) -> u32 {
        self.mark
    }
    pub fn tos(&self) -> u8 {
        self.tos
    }
    pub fn input_interface(&self) -> Option<NonZeroU32> {
        self.input_interface
    }
    pub fn output_interface(&self) -> Option<NonZeroU32> {
        self.output_interface
    }
    pub fn transport(&self) -> Option<TransportProtocol> {
        self.transport
    }
    pub fn source_port(&self) -> Option<u16> {
        self.source_port
    }
    pub fn destination_port(&self) -> Option<u16> {
        self.destination_port
    }
}
impl fmt::Debug for RouteQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteQuery")
            .field("ipv6", &self.destination.is_ipv6())
            .field("has_source", &self.source.is_some())
            .field("has_transport", &self.transport.is_some())
            .finish_non_exhaustive()
    }
}

/// Тип записи ядра не означает успешного соединения с адресатом.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    Unspecified,
    Unicast,
    Local,
    Broadcast,
    Anycast,
    Multicast,
    Blackhole,
    Unreachable,
    Prohibit,
    Throw,
    Nat,
    ExternalResolve,
    Unknown(u8),
}
impl From<u8> for RouteKind {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Unspecified,
            1 => Self::Unicast,
            2 => Self::Local,
            3 => Self::Broadcast,
            4 => Self::Anycast,
            5 => Self::Multicast,
            6 => Self::Blackhole,
            7 => Self::Unreachable,
            8 => Self::Prohibit,
            9 => Self::Throw,
            10 => Self::Nat,
            11 => Self::ExternalResolve,
            v => Self::Unknown(v),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupIncomplete {
    Multipath,
    UnknownAttributes,
    CachedError,
    UnknownRouteKind,
    MissingTable,
    MissingOutputInterface,
    UnresolvedNexthop,
}

#[derive(Clone, PartialEq, Eq)]
pub struct KernelRoute {
    pub namespace: NetworkNamespace,
    pub query: RouteQuery,
    pub table: Option<u32>,
    pub output_interface: Option<NonZeroU32>,
    pub gateway: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub kind: RouteKind,
    pub flags: u32,
    pub nexthop_id: Option<u32>,
    /// Атрибуты, не сведённые к полям результата, сохраняются без потерь.
    pub attributes: Vec<NetworkAttribute>,
    pub incomplete: Vec<LookupIncomplete>,
}
impl fmt::Debug for KernelRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelRoute")
            .field("attributes", &self.attributes.len())
            .field("incomplete", &self.incomplete.len())
            .finish_non_exhaustive()
    }
}

/// Только RTM_GETROUTE; не отправляет пакет и не проверяет достижимость или bind.
/// Требует Tokio runtime с включёнными I/O и time.
pub async fn lookup_route(
    query: RouteQuery,
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<KernelRoute, NetworkReadError> {
    lookup_route_captured(query, cancel, timeout)
        .await
        .map(|(route, _)| route)
}
pub(crate) async fn lookup_route_captured(
    query: RouteQuery,
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<(KernelRoute, super::equivalence::RouteCapture), NetworkReadError> {
    if timeout.is_zero() || timeout > Duration::from_secs(5) {
        return Err(NetworkReadError::Limit);
    }
    cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
    let deadline = Instant::now() + timeout;
    let payload = request_payload(&query);
    let mut reader = NetlinkReader::open()?;
    let namespace = reader.namespace();
    let start = Instant::now();
    let replies = reader
        .request(ReadOperation::RouteGet, &payload, cancel, deadline)
        .await?;
    let capture = super::equivalence::RouteCapture::new(start, Instant::now());
    if replies.len() != 1 {
        return Err(NetworkReadError::Malformed);
    }
    let route = parse_reply(&replies[0].payload, query, namespace)?;
    reader.finish(cancel, deadline)?;
    cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
    if Instant::now() >= deadline {
        return Err(NetworkReadError::Timeout);
    }
    Ok((route, capture))
}

pub(crate) async fn reread_changed_route(
    query: RouteQuery,
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<(KernelRoute, super::equivalence::RouteCapture), NetworkReadError> {
    retry_snapshot(cancel, timeout, async |cancel, remaining| {
        lookup_route_captured(query.clone(), cancel, remaining).await
    })
    .await
}

fn family(address: IpAddr) -> u8 {
    if address.is_ipv4() { 2 } else { 10 }
}
fn add_ip(bytes: &mut Vec<u8>, kind: u16, address: IpAddr) {
    match address {
        IpAddr::V4(ip) => add_attribute(bytes, kind, &ip.octets()),
        IpAddr::V6(ip) => add_attribute(bytes, kind, &ip.octets()),
    }
}
fn add_attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = 4 + value.len();
    bytes.extend_from_slice(&(length as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize((bytes.len() + 3) & !3, 0);
}
fn request_payload(query: &RouteQuery) -> Vec<u8> {
    let prefix = if query.destination.is_ipv4() { 32 } else { 128 };
    let mut bytes = vec![
        family(query.destination),
        prefix,
        if query.source.is_some() { prefix } else { 0 },
        query.tos,
        0,
        0,
        0,
        0,
    ];
    // UAPI linux/rtnetlink.h: вернуть таблицу фактического FIB lookup.
    bytes.extend_from_slice(&0x1000u32.to_ne_bytes());
    add_ip(&mut bytes, 1, query.destination);
    if let Some(source) = query.source {
        add_ip(&mut bytes, 2, source);
    }
    for (kind, index) in [(3, query.input_interface), (4, query.output_interface)] {
        if let Some(index) = index {
            add_attribute(&mut bytes, kind, &index.get().to_ne_bytes());
        }
    }
    add_attribute(&mut bytes, 25, &query.uid.to_ne_bytes());
    add_attribute(&mut bytes, 16, &query.mark.to_ne_bytes());
    if let Some(transport) = query.transport {
        add_attribute(
            &mut bytes,
            27,
            &[match transport {
                TransportProtocol::Tcp => 6,
                TransportProtocol::Udp => 17,
            }],
        );
        for (kind, port) in [(28, query.source_port), (29, query.destination_port)] {
            if let Some(port) = port {
                add_attribute(&mut bytes, kind, &port.to_be_bytes());
            }
        }
    }
    bytes
}

fn parse_reply(
    bytes: &[u8],
    query: RouteQuery,
    namespace: NetworkNamespace,
) -> Result<KernelRoute, NetworkReadError> {
    if bytes.len() < 12 || bytes[0] != family(query.destination) {
        return Err(NetworkReadError::Malformed);
    }
    let max_prefix = if bytes[0] == 2 { 32 } else { 128 };
    if bytes[1] > max_prefix || bytes[2] > max_prefix {
        return Err(NetworkReadError::Malformed);
    }
    let kind = RouteKind::from(bytes[7]);
    let mut route = KernelRoute {
        namespace,
        query,
        table: (bytes[4] != 0).then_some(u32::from(bytes[4])),
        output_interface: None,
        gateway: None,
        preferred_source: None,
        kind,
        flags: u32_value(&bytes[8..12])?,
        nexthop_id: None,
        attributes: Vec::new(),
        incomplete: Vec::new(),
    };
    let mut seen = std::collections::BTreeSet::new();
    for (kind, value) in attributes(&bytes[12..])? {
        if !seen.insert(kind & 0x3fff) {
            return Err(NetworkReadError::Malformed);
        }
        // Флаги вложенности/порядка байт нельзя интерпретировать как обычный атрибут.
        if kind & 0xc000 != 0 {
            route.attributes.push(NetworkAttribute {
                kind,
                value: value.to_vec(),
            });
            continue;
        }
        match kind {
            1 | 2 => {
                ip_value(bytes[0], value)?;
            }
            3 | 6 | 16 | 25 => {
                u32_value(value)?;
            }
            4 => {
                route.output_interface = NonZeroU32::new(u32_value(value)?);
                if route.output_interface.is_none() {
                    return Err(NetworkReadError::Malformed);
                }
            }
            5 => route.gateway = Some(ip_value(bytes[0], value)?),
            7 => route.preferred_source = Some(ip_value(bytes[0], value)?),
            15 => {
                let table = u32_value(value)?;
                route.table = (table != 0).then_some(table);
            }
            // RTA_PREF — предпочтение маршрутизатора IPv6. Храним для сравнения.
            20 if bytes[0] == 10 && matches!(value, [0 | 1 | 3]) => {
                route.attributes.push(NetworkAttribute {
                    kind,
                    value: value.to_vec(),
                });
            }
            20 => return Err(NetworkReadError::Malformed),
            30 => {
                let id = u32_value(value)?;
                if id == 0 {
                    return Err(NetworkReadError::Malformed);
                }
                route.nexthop_id = Some(id);
            }
            27 if value.len() == 1 => {}
            28 | 29 if value.len() == 2 => {}
            27..=29 => return Err(NetworkReadError::Malformed),
            _ => {
                if kind == 9 {
                    validate_multipath(value)?;
                    route.incomplete.push(LookupIncomplete::Multipath);
                }
                route.attributes.push(NetworkAttribute {
                    kind,
                    value: value.to_vec(),
                });
            }
        }
    }
    // RTA_CACHEINFO — фиксированные восемь u32 UAPI, не новый selector.
    // Сохраняем байты для последующей проверки expires/error/id; неизвестные
    // layouts и NLA flags по-прежнему не объявляются поддержанными.
    let cache_info =
        |attribute: &NetworkAttribute| attribute.kind == 12 && attribute.value.len() == 32;
    if route.attributes.iter().any(|attribute| {
        !(matches!(attribute.kind, 9 | 20)
            || cache_info(attribute)
            || attribute.kind == 23 && attribute.value.len() == 4)
    }) {
        route.incomplete.push(LookupIncomplete::UnknownAttributes);
    }
    if route
        .attributes
        .iter()
        .any(|attribute| cache_info(attribute) && attribute.value[12..16] != [0; 4])
    {
        route.incomplete.push(LookupIncomplete::CachedError);
    }
    if matches!(route.kind, RouteKind::Unknown(_) | RouteKind::Unspecified) {
        route.incomplete.push(LookupIncomplete::UnknownRouteKind);
    }
    if route.table.is_none() {
        route.incomplete.push(LookupIncomplete::MissingTable);
    }
    if matches!(
        route.kind,
        RouteKind::Unicast
            | RouteKind::Local
            | RouteKind::Broadcast
            | RouteKind::Anycast
            | RouteKind::Multicast
    ) && route.output_interface.is_none()
    {
        route
            .incomplete
            .push(LookupIncomplete::MissingOutputInterface);
        if route.nexthop_id.is_some() {
            route.incomplete.push(LookupIncomplete::UnresolvedNexthop);
        }
    }
    Ok(route)
}

fn validate_multipath(mut bytes: &[u8]) -> Result<(), NetworkReadError> {
    if bytes.is_empty() {
        return Err(NetworkReadError::Malformed);
    }
    while !bytes.is_empty() {
        if bytes.len() < 8 {
            return Err(NetworkReadError::Malformed);
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        if length < 8 || length > bytes.len() {
            return Err(NetworkReadError::Malformed);
        }
        attributes(&bytes[8..length])?;
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            return Err(NetworkReadError::Malformed);
        }
        bytes = &bytes[aligned..];
    }
    Ok(())
}

#[cfg(test)]
mod tests;
