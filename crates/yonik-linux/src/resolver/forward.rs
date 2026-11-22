//! Ограниченный passthrough DNS по заранее подключённому и помеченному сокету.
//!
//! Модуль не выбирает upstream, не создаёт сокеты и не меняет route mark.

use std::{
    borrow::Cow,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use rustix::time::{ClockId, clock_gettime};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

use crate::{Cancellation, managed_network::FAKE_POOLS};

use super::{ResolverError, dot::DotPeer};

mod policy_proxy;
#[cfg(test)]
pub(crate) use policy_proxy::tests as policy_proxy_fixture;
mod policy_rrset;
pub use policy_proxy::PolicyProxyResolver;
pub(crate) use policy_proxy::dns_question;
pub use policy_rrset::PolicyRrset;

const HEADER_LEN: usize = 12;
const MAX_DNS_PACKET: usize = 4096;
const UDP_RECEIVE_LEN: usize = MAX_DNS_PACKET + 1;
const MAX_LABELS: usize = 127;
const MAX_POINTER_HOPS: usize = 32;

pub(crate) fn boottime_now() -> Option<Duration> {
    let now = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).ok()?;
    let nanoseconds = u32::try_from(now.tv_nsec).ok()?;
    if nanoseconds >= 1_000_000_000 {
        return None;
    }
    Some(Duration::new(seconds, nanoseconds))
}

/// Ответ DNS. При `truncated()` вызывающая сторона может повторить исходный запрос
/// по TCP к тому же доверенному узлу.
#[derive(Clone, PartialEq, Eq)]
pub struct ForwardResponse {
    packet: Vec<u8>,
    truncated: bool,
    question: Question,
    received_at: Instant,
    received_boottime: Duration,
    peer: ForwardPeer,
}

#[derive(Clone)]
pub(super) enum ForwardPeer {
    Plain(SocketAddr),
    Tls(SocketAddr, Arc<DotPeer>),
    Proxy(Arc<PolicyProxyResolver>),
}

impl PartialEq for ForwardPeer {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Plain(left), Self::Plain(right)) => left == right,
            (Self::Tls(left, left_policy), Self::Tls(right, right_policy)) => {
                left == right && Arc::ptr_eq(left_policy, right_policy)
            }
            (Self::Proxy(left), Self::Proxy(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for ForwardPeer {}

impl std::fmt::Debug for ForwardResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardResponse")
            .field("packet_len", &self.packet.len())
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

impl ForwardResponse {
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    pub fn into_packet(self) -> Vec<u8> {
        self.packet
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Отклоняет ответ, если любая IN A/AAAA запись содержит зарезервированный адрес.
    pub fn reject_addresses(
        &self,
        is_reserved: impl Fn(IpAddr) -> bool,
    ) -> Result<(), ResolverError> {
        let parsed = parse_message(&self.packet, true)?;
        let returned = parsed.question;
        if returned.id != self.question.id
            || returned.opcode != self.question.opcode
            || returned.name != self.question.name
            || returned.qtype != self.question.qtype
            || returned.qclass != self.question.qclass
            || returned.truncated != self.truncated
        {
            return Err(ResolverError::Malformed);
        }
        if parsed.addresses.into_iter().any(is_reserved) {
            return Err(ResolverError::Untrusted);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Question {
    id: u16,
    opcode: u8,
    name: Vec<u8>,
    qtype: u16,
    qclass: u16,
    truncated: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedMessage {
    question: Question,
    addresses: Vec<IpAddr>,
}

pub(crate) fn forward_query_name(packet: &[u8]) -> Result<String, ResolverError> {
    let question = parse_message(packet, false)?.question;
    query_name(&question)
}

/// Оставляет только вопрос и заголовок опционального EDNS v0.
pub(crate) fn private_forward_query(
    packet: &[u8],
) -> Result<(String, Cow<'_, [u8]>), ResolverError> {
    let (question, mut offset) = parse_question(packet, false)?;
    let name = query_name(&question)?;
    let query = match section_counts(packet)? {
        [0, 0, 0] => Cow::Borrowed(packet),
        [0, 0, 1] => {
            if packet.get(offset) != Some(&0) {
                return Err(ResolverError::Unsupported);
            }
            let opt = read_record(packet, &mut offset)?;
            if opt.kind != 41 || opt.class < 512 || opt.ttl & !0x8000 != 0 {
                return Err(ResolverError::Unsupported);
            }
            if opt.data.is_empty() {
                Cow::Borrowed(packet)
            } else {
                let mut normalized = packet[..opt.data.start].to_vec();
                normalized[opt.data.start - 2..].fill(0);
                Cow::Owned(normalized)
            }
        }
        _ => return Err(ResolverError::Unsupported),
    };
    if offset != packet.len() {
        return Err(ResolverError::Malformed);
    }
    Ok((name, query))
}

fn query_name(question: &Question) -> Result<String, ResolverError> {
    if question.opcode != 0 || question.truncated || question.name.len() == 1 {
        return Err(ResolverError::Unsupported);
    }
    let mut name = String::with_capacity(question.name.len() - 2);
    let mut labels = question.name.as_slice();
    while let Some((&length, rest)) = labels.split_first() {
        if length == 0 {
            return Ok(name);
        }
        let (label, tail) = rest.split_at(usize::from(length));
        if label
            .iter()
            .any(|byte| !byte.is_ascii_graphic() || *byte == b'.')
        {
            return Err(ResolverError::Unsupported);
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(label).map_err(|_| ResolverError::Malformed)?);
        labels = tail;
    }
    Err(ResolverError::Malformed)
}

/// Пересылает один IN-вопрос по уже подключённому UDP-сокету.
/// Ответ с TC возвращается вызывающей стороне без автоматической смены транспорта.
pub async fn forward_udp(
    socket: &UdpSocket,
    trusted_peer: SocketAddr,
    query: &[u8],
    timeout_budget: Duration,
    cancel: &mut Cancellation,
) -> Result<ForwardResponse, ResolverError> {
    let peer = socket.peer_addr().map_err(|_| ResolverError::Unavailable)?;
    if peer != trusted_peer {
        return Err(ResolverError::Untrusted);
    }
    if timeout_budget.is_zero() || timeout_budget > Duration::from_secs(10) {
        return Err(ResolverError::Limit);
    }
    let original = parse_message(query, false)?.question;
    let outbound_id = random_id(original.id)?;
    let mut outbound = query.to_vec();
    outbound[..2].copy_from_slice(&outbound_id.to_be_bytes());

    run_cancellable(cancel, timeout_budget, async {
        let sent = socket.send(&outbound).await.map_err(map_io)?;
        if sent != outbound.len() {
            return Err(ResolverError::Closed);
        }
        let mut buffer = vec![0; UDP_RECEIVE_LEN];
        let received = socket.recv(&mut buffer).await.map_err(map_io)?;
        let received_at = Instant::now();
        let received_boottime = boottime_now().ok_or(ResolverError::Unavailable)?;
        if received > MAX_DNS_PACKET {
            return Err(ResolverError::Limit);
        }
        let mut response = buffer[..received].to_vec();
        let returned = verify_response(&response, outbound_id, &original)?;
        response[..2].copy_from_slice(&original.id.to_be_bytes());
        Ok(ForwardResponse {
            packet: response,
            truncated: returned.truncated,
            question: original,
            received_at,
            received_boottime,
            peer: ForwardPeer::Plain(trusted_peer),
        })
    })
    .await
}

/// Пересылает один IN-вопрос по уже подключённому TCP-сокету с DNS length-prefix.
/// После UDP TC вызывающая сторона должна передать TCP-сокет к тому же `trusted_peer`.
/// После timeout, отмены или ошибки протокола TCP-сокет нельзя переиспользовать.
pub async fn forward_tcp(
    stream: &mut TcpStream,
    trusted_peer: SocketAddr,
    query: &[u8],
    timeout_budget: Duration,
    cancel: &mut Cancellation,
) -> Result<ForwardResponse, ResolverError> {
    let peer = stream.peer_addr().map_err(|_| ResolverError::Unavailable)?;
    if peer != trusted_peer {
        return Err(ResolverError::Untrusted);
    }
    forward_tcp_for_peer(
        stream,
        query,
        timeout_budget,
        cancel,
        ForwardPeer::Plain(peer),
    )
    .await
}

async fn forward_tcp_for_peer(
    stream: &mut TcpStream,
    query: &[u8],
    budget: Duration,
    cancel: &mut Cancellation,
    peer: ForwardPeer,
) -> Result<ForwardResponse, ResolverError> {
    forward_framed(query, budget, cancel, peer, async |outbound| {
        let frame_len = u16::try_from(outbound.len()).map_err(|_| ResolverError::Limit)?;
        stream.write_u16(frame_len).await.map_err(map_io)?;
        stream.write_all(outbound).await.map_err(map_io)?;
        let response_len = usize::from(stream.read_u16().await.map_err(map_io)?);
        if !(HEADER_LEN..=MAX_DNS_PACKET).contains(&response_len) {
            return Err(ResolverError::Limit);
        }
        let mut response = vec![0; response_len];
        stream.read_exact(&mut response).await.map_err(map_io)?;
        Ok(response)
    })
    .await
}

pub(super) async fn forward_framed(
    query: &[u8],
    timeout_budget: Duration,
    cancel: &mut Cancellation,
    peer: ForwardPeer,
    exchange: impl AsyncFnOnce(&[u8]) -> Result<Vec<u8>, ResolverError>,
) -> Result<ForwardResponse, ResolverError> {
    if timeout_budget.is_zero() || timeout_budget > Duration::from_secs(10) {
        return Err(ResolverError::Limit);
    }
    let original = parse_message(query, false)?.question;
    let outbound_id = random_id(original.id)?;
    let mut outbound = query.to_vec();
    outbound[..2].copy_from_slice(&outbound_id.to_be_bytes());
    run_cancellable(cancel, timeout_budget, async {
        let mut response = exchange(&outbound).await?;
        let received_at = Instant::now();
        let received_boottime = boottime_now().ok_or(ResolverError::Unavailable)?;
        let returned = verify_response(&response, outbound_id, &original)?;
        response[..2].copy_from_slice(&original.id.to_be_bytes());
        Ok(ForwardResponse {
            packet: response,
            truncated: returned.truncated,
            question: original,
            received_at,
            received_boottime,
            peer,
        })
    })
    .await
}

async fn run_cancellable<T>(
    cancel: &mut Cancellation,
    budget: Duration,
    operation: impl Future<Output = Result<T, ResolverError>>,
) -> Result<T, ResolverError> {
    cancel.check().map_err(|_| ResolverError::Cancelled)?;
    timeout(budget, async {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ResolverError::Cancelled),
            result = operation => result,
        }
    })
    .await
    .map_err(|_| ResolverError::Timeout)?
}

fn verify_response(
    response: &[u8],
    expected_id: u16,
    query: &Question,
) -> Result<Question, ResolverError> {
    let returned = parse_message(response, true)?.question;
    if returned.id != expected_id
        || returned.opcode != query.opcode
        || returned.name != query.name
        || returned.qtype != query.qtype
        || returned.qclass != query.qclass
    {
        return Err(ResolverError::Malformed);
    }
    Ok(returned)
}

fn random_id(original: u16) -> Result<u16, ResolverError> {
    let mut random = [0; 2];
    getrandom::getrandom(&mut random).map_err(|_| ResolverError::Unavailable)?;
    let id = original ^ u16::from_be_bytes(random);
    Ok(if id == original {
        id.wrapping_add(1)
    } else {
        id
    })
}

fn parse_message(packet: &[u8], response: bool) -> Result<ParsedMessage, ResolverError> {
    let (question, mut offset) = parse_question(packet, response)?;
    let mut addresses = Vec::new();
    for count in section_counts(packet)? {
        for _ in 0..count {
            let record = read_record(packet, &mut offset)?;
            if let Some(address) = record.address(packet)? {
                addresses.push(address);
            }
        }
    }
    if offset != packet.len() {
        return Err(ResolverError::Malformed);
    }
    Ok(ParsedMessage {
        question,
        addresses,
    })
}

fn parse_question(packet: &[u8], response: bool) -> Result<(Question, usize), ResolverError> {
    if !(HEADER_LEN..=MAX_DNS_PACKET).contains(&packet.len()) {
        return Err(ResolverError::Limit);
    }
    let flags = read_u16(packet, 2)?;
    let qr = flags & 0x8000 != 0;
    if qr != response {
        return Err(ResolverError::Malformed);
    }
    let qd = read_u16(packet, 4)?;
    if qd != 1 {
        return Err(ResolverError::Unsupported);
    }
    let (name, offset) = decode_name(packet, HEADER_LEN, false)?;
    let qtype = read_u16(packet, offset)?;
    let qclass = read_u16(packet, offset + 2)?;
    if qclass != 1 {
        return Err(ResolverError::Unsupported);
    }
    Ok((
        Question {
            id: read_u16(packet, 0)?,
            opcode: ((flags >> 11) & 0x0f) as u8,
            name,
            qtype,
            qclass,
            truncated: flags & 0x0200 != 0,
        },
        offset + 4,
    ))
}

fn section_counts(packet: &[u8]) -> Result<[u16; 3], ResolverError> {
    Ok([
        read_u16(packet, 6)?,
        read_u16(packet, 8)?,
        read_u16(packet, 10)?,
    ])
}

struct ResourceRecord {
    owner: Vec<u8>,
    kind: u16,
    class: u16,
    ttl: u32,
    data: std::ops::Range<usize>,
}

impl ResourceRecord {
    fn address(&self, packet: &[u8]) -> Result<Option<IpAddr>, ResolverError> {
        let bytes = &packet[self.data.clone()];
        match (self.class, self.kind) {
            (1, 1) => {
                let octets: [u8; 4] = bytes.try_into().map_err(|_| ResolverError::Malformed)?;
                Ok(Some(Ipv4Addr::from(octets).into()))
            }
            (1, 28) => {
                let octets: [u8; 16] = bytes.try_into().map_err(|_| ResolverError::Malformed)?;
                Ok(Some(Ipv6Addr::from(octets).into()))
            }
            _ => Ok(None),
        }
    }
}

fn read_record(packet: &[u8], offset: &mut usize) -> Result<ResourceRecord, ResolverError> {
    let (owner, header) = decode_name(packet, *offset, true)?;
    let start = header + 10;
    let end = start + usize::from(read_u16(packet, header + 8)?);
    if end > packet.len() {
        return Err(ResolverError::Malformed);
    }
    *offset = end;
    Ok(ResourceRecord {
        owner,
        kind: read_u16(packet, header)?,
        class: read_u16(packet, header + 2)?,
        ttl: read_u32(packet, header + 4)?,
        data: start..end,
    })
}

/// Возвращает canonical wire-name и конец исходного encoded name.
fn decode_name(
    packet: &[u8],
    start: usize,
    allow_compression: bool,
) -> Result<(Vec<u8>, usize), ResolverError> {
    let mut name = Vec::with_capacity(32);
    let mut cursor = start;
    let mut consumed_end = None;
    let mut hops = 0usize;
    let mut expanded_len = 1usize;
    let mut labels = 0usize;
    loop {
        let length = *packet.get(cursor).ok_or(ResolverError::Malformed)?;
        if length & 0xc0 == 0xc0 {
            if !allow_compression || hops >= MAX_POINTER_HOPS {
                return Err(ResolverError::Malformed);
            }
            let second = *packet.get(cursor + 1).ok_or(ResolverError::Malformed)?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if target < HEADER_LEN || target >= cursor {
                return Err(ResolverError::Malformed);
            }
            consumed_end.get_or_insert(cursor + 2);
            cursor = target;
            hops += 1;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(ResolverError::Malformed);
        }
        cursor += 1;
        let length = usize::from(length);
        if length == 0 {
            name.push(0);
            return Ok((name, consumed_end.unwrap_or(cursor)));
        }
        labels += 1;
        if length > 63 || labels > MAX_LABELS {
            return Err(ResolverError::Malformed);
        }
        let end = cursor.checked_add(length).ok_or(ResolverError::Malformed)?;
        let label = packet.get(cursor..end).ok_or(ResolverError::Malformed)?;
        expanded_len = expanded_len
            .checked_add(length + 1)
            .filter(|length| *length <= 255)
            .ok_or(ResolverError::Malformed)?;
        name.push(length as u8);
        name.extend(label.iter().map(u8::to_ascii_lowercase));
        cursor = end;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, ResolverError> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or(ResolverError::Malformed)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, ResolverError> {
    let mut value = [0; 4];
    value.copy_from_slice(
        packet
            .get(offset..offset + 4)
            .ok_or(ResolverError::Malformed)?,
    );
    Ok(u32::from_be_bytes(value))
}

fn map_io(error: std::io::Error) -> ResolverError {
    match error.kind() {
        std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::UnexpectedEof => ResolverError::Closed,
        _ => ResolverError::Unavailable,
    }
}

pub(crate) fn is_reserved_fake(address: IpAddr) -> bool {
    let address = address.to_canonical();
    FAKE_POOLS
        .iter()
        .any(|(network, length)| match (*network, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                u32::from(address) & (u32::MAX << (32 - length)) == u32::from(base)
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                u128::from(address) & (u128::MAX << (128 - length)) == u128::from(base)
            }
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::{net::TcpListener, task::JoinHandle};

    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1, 7, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 4, b't', b'e', b's', b't', 0, 0, 28, 0, 1, 0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0,
    ];

    fn answer(query: &[u8], id: u16, change_question: bool, truncated: bool) -> Vec<u8> {
        let mut response = query.to_vec();
        response[..2].copy_from_slice(&id.to_be_bytes());
        response[2] |= 0x80;
        if truncated {
            response[2] |= 0x02;
            response.truncate(query.len());
        } else {
            let edns_offset = query.len() - 11;
            response = query[..edns_offset].to_vec();
            response[..2].copy_from_slice(&id.to_be_bytes());
            response[2] |= 0x80;
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            if query[26..28] == [0, 1] {
                response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                response.extend_from_slice(&[198, 18, 0, 1]);
            } else {
                response.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                response.extend_from_slice(
                    &"fd00::1"
                        .parse::<std::net::Ipv6Addr>()
                        .expect("IPv6")
                        .octets(),
                );
            }
            response.extend_from_slice(&query[edns_offset..]);
        }
        if change_question {
            response[13] = b'X';
        }
        response
    }

    async fn connected_udp() -> (UdpSocket, UdpSocket, SocketAddr) {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("server bind");
        let peer = server.local_addr().expect("server address");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("client bind");
        client.connect(peer).await.expect("connect");
        (client, server, peer)
    }

    async fn udp_server(
        server: UdpSocket,
        behavior: impl FnOnce(Vec<u8>, u16) -> Vec<u8> + Send + 'static,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut packet = [0; MAX_DNS_PACKET];
            let (length, peer) = server.recv_from(&mut packet).await.expect("receive query");
            let id = u16::from_be_bytes([packet[0], packet[1]]);
            let response = behavior(packet[..length].to_vec(), id);
            server
                .send_to(&response, peer)
                .await
                .expect("send response");
        })
    }

    #[tokio::test]
    async fn udp_preserves_edns_do_restores_id_and_reports_truncation() {
        let (client, server, peer) = connected_udp().await;
        let task = udp_server(server, |query, id| {
            assert_ne!(id, u16::from_be_bytes([QUERY[0], QUERY[1]]));
            answer(&query, id, false, true)
        })
        .await;
        let (_cancel_tx, mut cancel) = Cancellation::new();
        let response = forward_udp(&client, peer, QUERY, Duration::from_secs(1), &mut cancel)
            .await
            .expect("forward");
        assert!(response.truncated());
        assert_eq!(&response.packet()[..2], &QUERY[..2]);
        assert!(response.packet()[2] & 0x02 != 0);
        assert!(
            response.packet()[20..]
                .windows(4)
                .any(|window| window == [0, 0, 0x80, 0])
        );
        task.await.expect("server");
    }

    #[tokio::test]
    async fn udp_rejects_mismatched_response_id_and_question() {
        for (wrong_id, wrong_question) in [(true, false), (false, true)] {
            let (client, server, peer) = connected_udp().await;
            let task = udp_server(server, move |query, id| {
                answer(
                    &query,
                    if wrong_id { id.wrapping_add(1) } else { id },
                    wrong_question,
                    false,
                )
            })
            .await;
            let (_cancel_tx, mut cancel) = Cancellation::new();
            assert_eq!(
                forward_udp(&client, peer, QUERY, Duration::from_secs(1), &mut cancel).await,
                Err(ResolverError::Malformed)
            );
            task.await.expect("server");
        }
    }

    #[test]
    fn rejects_reserved_addresses_in_a_and_aaaa_response_records() {
        for (query, reserved) in [
            (QUERY.to_vec(), "fd00::1".parse::<IpAddr>().expect("IPv6")),
            (
                {
                    let mut query = QUERY.to_vec();
                    query[26..28].copy_from_slice(&1u16.to_be_bytes());
                    query
                },
                "198.18.0.1".parse::<IpAddr>().expect("IPv4"),
            ),
        ] {
            let original = parse_message(&query, false)
                .expect("valid question")
                .question;
            let packet = answer(&query, original.id, false, false);
            verify_response(&packet, original.id, &original).expect("validated answer");
            let response = ForwardResponse {
                packet,
                truncated: false,
                question: original,
                received_at: Instant::now(),
                received_boottime: boottime_now().expect("boottime clock is available"),
                peer: ForwardPeer::Plain((Ipv4Addr::LOCALHOST, 53).into()),
            };
            assert_eq!(
                response.reject_addresses(|address| address == reserved),
                Err(ResolverError::Untrusted)
            );
            assert_eq!(response.reject_addresses(|_| false), Ok(()));
        }
    }

    #[tokio::test]
    async fn udp_timeout_cancellation_and_untrusted_peer_are_distinct() {
        let (client, server, peer) = connected_udp().await;
        let silent_server = tokio::spawn(async move {
            let mut packet = [0; MAX_DNS_PACKET];
            let _ = server.recv_from(&mut packet).await.expect("receive query");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let (_cancel_tx, mut cancel) = Cancellation::new();
        assert_eq!(
            forward_udp(&client, peer, QUERY, Duration::from_millis(20), &mut cancel).await,
            Err(ResolverError::Timeout)
        );
        silent_server.await.expect("silent server");
        assert_eq!(
            forward_udp(
                &client,
                "127.0.0.1:9".parse().expect("peer"),
                QUERY,
                Duration::from_secs(1),
                &mut cancel
            )
            .await,
            Err(ResolverError::Untrusted)
        );

        let (client, _server, peer) = connected_udp().await;
        let (cancel_tx, mut cancel) = Cancellation::new();
        let cancelled = tokio::spawn(async move {
            forward_udp(&client, peer, QUERY, Duration::from_secs(2), &mut cancel).await
        });
        tokio::task::yield_now().await;
        cancel_tx.send(true).expect("cancel");
        assert_eq!(
            cancelled.await.expect("task"),
            Err(ResolverError::Cancelled)
        );
    }

    #[tokio::test]
    async fn tcp_frames_queries_and_validates_response_question() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listen");
        let peer = listener.local_addr().expect("peer");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let length = usize::from(stream.read_u16().await.expect("length"));
            let mut query = vec![0; length];
            stream.read_exact(&mut query).await.expect("query");
            assert_ne!(query[..2], QUERY[..2]);
            let response = answer(
                &query,
                u16::from_be_bytes([query[0], query[1]]),
                false,
                false,
            );
            stream
                .write_u16(response.len() as u16)
                .await
                .expect("response length");
            stream.write_all(&response).await.expect("response");
        });
        let mut stream = TcpStream::connect(peer).await.expect("connect");
        let (_cancel_tx, mut cancel) = Cancellation::new();
        let response = forward_tcp(
            &mut stream,
            peer,
            QUERY,
            Duration::from_secs(1),
            &mut cancel,
        )
        .await
        .expect("forward");
        assert!(!response.truncated());
        assert_eq!(&response.packet()[..2], &QUERY[..2]);
        server.await.expect("server");
    }

    #[tokio::test]
    async fn tcp_timeout_and_cancellation_drop_pending_read() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listen");
        let peer = listener.local_addr().expect("peer");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let mut stream = TcpStream::connect(peer).await.expect("connect");
        let (_cancel_tx, mut cancel) = Cancellation::new();
        assert_eq!(
            forward_tcp(
                &mut stream,
                peer,
                QUERY,
                Duration::from_millis(20),
                &mut cancel
            )
            .await,
            Err(ResolverError::Timeout)
        );
        server.await.expect("server");

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listen");
        let peer = listener.local_addr().expect("peer");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let mut stream = TcpStream::connect(peer).await.expect("connect");
        let (cancel_tx, mut cancel) = Cancellation::new();
        let cancelled = tokio::spawn(async move {
            forward_tcp(
                &mut stream,
                peer,
                QUERY,
                Duration::from_secs(1),
                &mut cancel,
            )
            .await
        });
        tokio::task::yield_now().await;
        cancel_tx.send(true).expect("cancel");
        assert_eq!(
            cancelled.await.expect("task"),
            Err(ResolverError::Cancelled)
        );
        server.await.expect("server");
    }

    #[test]
    fn rejects_non_in_multi_question_oversized_and_malformed_queries() {
        let mut query = QUERY.to_vec();
        query[5] = 2;
        assert_eq!(
            parse_message(&query, false),
            Err(ResolverError::Unsupported)
        );
        let mut query = QUERY.to_vec();
        let last = query.len() - 1;
        query[last] = 3;
        assert_eq!(parse_message(&query, false), Err(ResolverError::Malformed));
        assert_eq!(
            parse_message(&vec![0; MAX_DNS_PACKET + 1], false),
            Err(ResolverError::Limit)
        );
    }
}
