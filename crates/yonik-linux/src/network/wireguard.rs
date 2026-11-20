//! Снимок UDP-транспорта WireGuard. GET не выдаёт право менять маршруты или nft.

use super::{
    IpPrefix, NetworkNamespace, NetworkReadError as Error,
    read::{NetlinkReader, ReadOperation, attributes, u16_value, u32_value},
};
use crate::Cancellation;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    time::Duration,
};
use tokio::time::Instant;

const MAX_WAIT: Duration = Duration::from_secs(5);
const MAX_PEERS: usize = 256;
const MAX_PREFIXES: usize = 4096;
const ATTR_TYPE: u16 = 0x3fff;
const ATTR_NETWORK_ORDER: u16 = 0x4000;

#[derive(PartialEq, Eq)]
pub struct WireGuardDevice {
    pub namespace: NetworkNamespace,
    pub ifindex: u32,
    pub ifname: Vec<u8>,
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: Vec<WireGuardPeer>,
}

#[derive(PartialEq, Eq)]
pub struct WireGuardPeer {
    identity: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpPrefix>,
}

/// Реквизиты завершённого WG_CMD_GET_DEVICE, включая число частей снимка.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireGuardReadReceipt {
    pub port_id: u32,
    pub sequence: u32,
    pub ifindex: u32,
    pub namespace: NetworkNamespace,
    pub listen_port: u16,
    pub parts: usize,
}

/// Подтверждение происхождения пары UDP-сокетов конкретного снимка WireGuard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireGuardSocketObservation {
    pub port_id: u32,
    pub sequence: u32,
    pub ifindex: u32,
    /// Inode сетевого пространства интерфейса из ядра.
    pub device_namespace: u64,
    /// Общий inode пространства creating_net и пространств обоих сокетов.
    pub socket_namespace: u64,
    pub ipv4_cookie: u64,
    pub ipv6_cookie: u64,
    pub listen_port: u16,
    pub generation: u32,
    pub parts: usize,
}

/// Источник синхронного подтверждения для завершённого netlink-запроса.
pub trait WireGuardSocketObserver: Send {
    /// Начинает наблюдение нового запроса и сбрасывает предыдущий результат.
    fn prepare(&mut self, port_id: u32, sequence: u32) -> Result<(), Error>;

    /// Возвращает результат без ожидания новых событий. При потере частей,
    /// несогласованном поколении или расхождении пространств сокетов выдаёт ошибку.
    fn observe(
        &mut self,
        receipt: WireGuardReadReceipt,
    ) -> Result<WireGuardSocketObservation, Error>;
}

impl fmt::Debug for WireGuardDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WireGuardDevice(<скрыто>)")
    }
}
impl fmt::Debug for WireGuardPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WireGuardPeer(<скрыто>)")
    }
}

/// Читает один интерфейс по ifindex. Ключи из ответа не покидают очищаемый
/// буфер. Для проверки давности caller повторно читает снимок и сверяет
/// маршруты. Изменение endpoint не обязано порождать событие RTNETLINK.
pub async fn read_wireguard_device(
    ifindex: u32,
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<WireGuardDevice, Error> {
    let (snapshot, _) = read_wireguard_device_inner(ifindex, cancel, timeout, None).await?;
    Ok(snapshot)
}

/// Читает снимок и принимает только подтверждение, связанное со всеми
/// частями того же запроса. Использует единый срок для чтения и наблюдения.
pub async fn read_wireguard_device_observed(
    ifindex: u32,
    cancel: &mut Cancellation,
    timeout: Duration,
    observer: &mut dyn WireGuardSocketObserver,
) -> Result<(WireGuardDevice, WireGuardSocketObservation), Error> {
    let (snapshot, observation) =
        read_wireguard_device_inner(ifindex, cancel, timeout, Some(observer)).await?;
    Ok((snapshot, observation.ok_or(Error::Unavailable)?))
}

async fn read_wireguard_device_inner(
    ifindex: u32,
    cancel: &mut Cancellation,
    timeout: Duration,
    mut observer: Option<&mut dyn WireGuardSocketObserver>,
) -> Result<(WireGuardDevice, Option<WireGuardSocketObservation>), Error> {
    if timeout.is_zero() || timeout > MAX_WAIT || !(1..=i32::MAX as u32).contains(&ifindex) {
        return Err(Error::Limit);
    }
    cancel.check().map_err(|_| Error::Cancelled)?;
    let deadline = Instant::now() + timeout;
    let mut reader = NetlinkReader::open_generic()?;
    let mut family = reader
        .request_decoded(
            ReadOperation::WireGuardFamily,
            &request(3, 2, 2, b"wireguard\0"), // CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_NAME.
            cancel,
            deadline,
            family_id,
        )
        .await?;
    let family = family.pop().ok_or(Error::Malformed)?;
    if let Some(observer) = observer.as_mut() {
        check_read_deadline(cancel, deadline)?;
        let (port_id, sequence) = reader.next_request_identity()?;
        observer.prepare(port_id, sequence)?;
        check_read_deadline(cancel, deadline)?;
    }
    let parts = reader
        .request_decoded(
            ReadOperation::WireGuardDevice(family),
            &request(0, 1, 1, &ifindex.to_ne_bytes()), // WG_CMD_GET_DEVICE, WGDEVICE_A_IFINDEX.
            cancel,
            deadline,
            device_part,
        )
        .await?;
    let part_count = parts.len();
    let snapshot = assemble(reader.namespace(), ifindex, parts)?;
    check_read_deadline(cancel, deadline)?;
    let observation = if let Some(observer) = observer {
        let (port_id, sequence) = reader.request_identity();
        let receipt = WireGuardReadReceipt {
            port_id,
            sequence,
            ifindex,
            namespace: snapshot.namespace,
            listen_port: snapshot.listen_port,
            parts: part_count,
        };
        // Пока наблюдение не завершилось, reader удерживает port_id этого запроса.
        Some(observe_socket(observer, receipt, cancel, deadline)?)
    } else {
        None
    };
    Ok((snapshot, observation))
}

fn check_read_deadline(cancel: &Cancellation, deadline: Instant) -> Result<(), Error> {
    cancel.check().map_err(|_| Error::Cancelled)?;
    if Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    Ok(())
}

fn observe_socket(
    observer: &mut dyn WireGuardSocketObserver,
    receipt: WireGuardReadReceipt,
    cancel: &Cancellation,
    deadline: Instant,
) -> Result<WireGuardSocketObservation, Error> {
    check_read_deadline(cancel, deadline)?;
    if receipt.listen_port == 0 {
        return Err(Error::Unavailable);
    }
    let observation = observer.observe(receipt);
    check_read_deadline(cancel, deadline)?;
    let observation = observation?;
    check_socket_observation(receipt, observation)?;
    Ok(observation)
}

fn check_socket_observation(
    receipt: WireGuardReadReceipt,
    observation: WireGuardSocketObservation,
) -> Result<(), Error> {
    if observation.port_id != receipt.port_id
        || observation.sequence != receipt.sequence
        || observation.ifindex != receipt.ifindex
        || observation.device_namespace != receipt.namespace.inode
        || observation.listen_port != receipt.listen_port
        || observation.parts != receipt.parts
    {
        return Err(Error::Changed);
    }
    if observation.socket_namespace == 0
        || observation.ipv4_cookie == 0
        || observation.ipv6_cookie == 0
        || observation.ipv4_cookie == observation.ipv6_cookie
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn request(command: u8, version: u8, kind: u16, value: &[u8]) -> Vec<u8> {
    let mut payload = vec![command, version, 0, 0];
    attribute(&mut payload, kind, value);
    payload
}

fn attribute(payload: &mut Vec<u8>, kind: u16, value: &[u8]) {
    payload.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
    payload.extend_from_slice(&kind.to_ne_bytes());
    payload.extend_from_slice(value);
    payload.resize((payload.len() + 3) & !3, 0);
}

fn family_id(payload: &[u8]) -> Result<u16, Error> {
    let mut id = None;
    let mut name = None;
    for (kind, value) in attributes(body(payload, [1, 2, 0, 0])?)? {
        match kind {
            1 if id.is_none() => id = Some(u16_value(value)?),
            2 if name.is_none() => name = Some(value),
            1 | 2 => return Err(Error::Malformed),
            _ => (),
        }
    }
    if name != Some(b"wireguard\0".as_slice()) {
        return Err(Error::Malformed);
    }
    id.filter(|id| *id > 16).ok_or(Error::Malformed)
}

fn body(payload: &[u8], header: [u8; 4]) -> Result<&[u8], Error> {
    payload.strip_prefix(&header).ok_or(Error::Malformed)
}

fn fields<const N: usize>(bytes: &[u8]) -> Result<[Option<&[u8]>; N], Error> {
    let mut result = [None; N];
    for (kind, value) in attributes(bytes)? {
        if kind == 0 {
            if value.is_empty() {
                continue;
            } // NLA_PAD при выравнивании kernel u64.
            return Err(Error::Malformed);
        }
        if kind & ATTR_NETWORK_ORDER != 0 || kind & ATTR_TYPE == 0 {
            return Err(Error::Unsupported);
        }
        let field = result
            .get_mut(usize::from(kind & ATTR_TYPE))
            .ok_or(Error::Unsupported)?;
        if field.replace(value).is_some() {
            return Err(Error::Malformed);
        }
    }
    Ok(result)
}

struct DevicePart {
    ifindex: Option<u32>,
    ifname: Option<Vec<u8>>,
    listen_port: Option<u16>,
    fwmark: Option<u32>,
    peers: Vec<WireGuardPeer>,
}

fn device_part(payload: &[u8]) -> Result<DevicePart, Error> {
    let data = fields::<9>(body(payload, [0, 1, 0, 0])?)?;
    // WGDEVICE_A_PRIVATE_KEY и WGDEVICE_A_PUBLIC_KEY остаются в буфере.
    let ifname = data[2].map(interface_name).transpose()?;
    Ok(DevicePart {
        ifindex: data[1].map(u32_value).transpose()?,
        ifname,
        listen_port: data[6].map(u16_value).transpose()?,
        fwmark: data[7].map(u32_value).transpose()?,
        peers: data[8].map(peer_list).transpose()?.unwrap_or_default(),
    })
}

fn interface_name(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let name = bytes.strip_suffix(&[0]).ok_or(Error::Malformed)?;
    if name.is_empty() || name.len() > 15 || name.contains(&0) {
        return Err(Error::Malformed);
    }
    Ok(name.to_vec())
}

fn peer_list(bytes: &[u8]) -> Result<Vec<WireGuardPeer>, Error> {
    let entries = attributes(bytes)?;
    if entries.len() > MAX_PEERS {
        return Err(Error::Limit);
    }
    entries.into_iter().map(|(_, value)| peer(value)).collect()
}

fn peer(bytes: &[u8]) -> Result<WireGuardPeer, Error> {
    let data = fields::<11>(bytes)?;
    // Идентификатор нужен для объединения частей одного peer. Секретный
    // WGPEER_A_PRESHARED_KEY не читается, открытый ключ сохраняется как digest.
    let key = data[1]
        .filter(|value| value.len() == 32)
        .ok_or(Error::Malformed)?;
    if !matches!(data[10].map(u32_value).transpose()?, None | Some(1)) {
        return Err(Error::Unsupported);
    }
    let allowed_ips = match data[9] {
        Some(entries) => attributes(entries)?
            .into_iter()
            .map(|(_, value)| allowed_ip(value))
            .collect::<Result<_, _>>()?,
        None => Vec::new(),
    };
    Ok(WireGuardPeer {
        identity: Sha256::digest(key).into(),
        endpoint: data[4].map(endpoint).transpose()?,
        allowed_ips,
    })
}

fn endpoint(bytes: &[u8]) -> Result<SocketAddr, Error> {
    let family = u16_value(bytes.get(..2).ok_or(Error::Malformed)?)?;
    let port = u16::from_be_bytes(
        bytes
            .get(2..4)
            .ok_or(Error::Malformed)?
            .try_into()
            .map_err(|_| Error::Malformed)?,
    );
    match (family, bytes.len()) {
        (2, 16) => {
            let address: [u8; 4] = bytes[4..8].try_into().map_err(|_| Error::Malformed)?;
            Ok((Ipv4Addr::from(address), port).into())
        }
        (10, 28) => {
            let address: [u8; 16] = bytes[8..24].try_into().map_err(|_| Error::Malformed)?;
            let flow = u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| Error::Malformed)?);
            Ok(SocketAddrV6::new(
                Ipv6Addr::from(address),
                port,
                flow,
                u32_value(&bytes[24..28])?,
            )
            .into())
        }
        _ => Err(Error::Malformed),
    }
}

fn allowed_ip(bytes: &[u8]) -> Result<IpPrefix, Error> {
    let data = fields::<5>(bytes)?;
    if !matches!(data[4].map(u32_value).transpose()?, None | Some(0)) {
        return Err(Error::Unsupported);
    }
    let family = u16_value(data[1].ok_or(Error::Malformed)?)?;
    let length = match data[3] {
        Some([length]) => *length,
        _ => return Err(Error::Malformed),
    };
    let binary = data[2].ok_or(Error::Malformed)?;
    let address = match family {
        2 => {
            let address: [u8; 4] = binary.try_into().map_err(|_| Error::Malformed)?;
            let address = Ipv4Addr::from(address);
            if length > 32 || u32::from(address).trailing_zeros() < 32 - u32::from(length) {
                return Err(Error::Malformed);
            }
            IpAddr::V4(address)
        }
        10 => {
            let address: [u8; 16] = binary.try_into().map_err(|_| Error::Malformed)?;
            let address = Ipv6Addr::from(address);
            if length > 128 || u128::from(address).trailing_zeros() < 128 - u32::from(length) {
                return Err(Error::Malformed);
            }
            IpAddr::V6(address)
        }
        _ => return Err(Error::Unsupported),
    };
    Ok(IpPrefix { address, length })
}

fn assemble(
    namespace: NetworkNamespace,
    ifindex: u32,
    parts: Vec<DevicePart>,
) -> Result<WireGuardDevice, Error> {
    let mut parts = parts.into_iter();
    let first = parts.next().ok_or(Error::Malformed)?;
    if first.ifindex != Some(ifindex) {
        return Err(Error::Changed);
    }
    let mut result = WireGuardDevice {
        namespace,
        ifindex,
        ifname: first.ifname.ok_or(Error::Malformed)?,
        listen_port: first.listen_port.ok_or(Error::Malformed)?,
        fwmark: first.fwmark.ok_or(Error::Malformed)?,
        peers: Vec::new(),
    };
    let mut identities = BTreeSet::new();
    let mut count = 0;
    append_peers(&mut result.peers, &mut identities, &mut count, first.peers)?;
    for part in parts {
        // Kernel повторяет поля устройства, пока первый peer не уместился
        // целиком. В следующих частях поля могут отсутствовать.
        if part
            .ifname
            .as_ref()
            .is_some_and(|name| *name != result.ifname)
            || part.ifindex.is_some_and(|index| index != result.ifindex)
            || part
                .listen_port
                .is_some_and(|port| port != result.listen_port)
            || part.fwmark.is_some_and(|mark| mark != result.fwmark)
        {
            return Err(Error::Changed);
        }
        append_peers(&mut result.peers, &mut identities, &mut count, part.peers)?;
    }
    for peer in &mut result.peers {
        peer.allowed_ips
            .sort_unstable_by_key(|value| (value.address, value.length));
        if peer.allowed_ips.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Malformed);
        }
    }
    result.peers.sort_unstable_by_key(|peer| peer.identity);
    Ok(result)
}

fn append_peers(
    peers: &mut Vec<WireGuardPeer>,
    identities: &mut BTreeSet<[u8; 32]>,
    count: &mut usize,
    fragments: Vec<WireGuardPeer>,
) -> Result<(), Error> {
    for (position, mut peer) in fragments.into_iter().enumerate() {
        *count += peer.allowed_ips.len();
        if *count > MAX_PREFIXES {
            return Err(Error::Limit);
        }
        if identities.insert(peer.identity) {
            if peers.len() == MAX_PEERS {
                return Err(Error::Limit);
            }
            peers.push(peer);
        } else if let Some(previous) = peers.last_mut().filter(|previous| {
            position == 0 && peer.endpoint.is_none() && peer.identity == previous.identity
        }) {
            previous.allowed_ips.append(&mut peer.allowed_ips);
        } else {
            return Err(Error::Changed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> WireGuardReadReceipt {
        WireGuardReadReceipt {
            port_id: 42,
            sequence: 17,
            ifindex: 7,
            namespace: NetworkNamespace {
                device: 1,
                inode: 2,
            },
            listen_port: 24177,
            parts: 3,
        }
    }

    fn observation() -> WireGuardSocketObservation {
        WireGuardSocketObservation {
            port_id: 42,
            sequence: 17,
            ifindex: 7,
            device_namespace: 2,
            socket_namespace: 3,
            ipv4_cookie: 11,
            ipv6_cookie: 12,
            listen_port: 24177,
            generation: 5,
            parts: 3,
        }
    }

    #[test]
    fn socket_observation_must_match_every_part_of_the_request() {
        let receipt = receipt();
        let observation = observation();
        assert_eq!(check_socket_observation(receipt, observation), Ok(()));
        let changes: [fn(&mut WireGuardSocketObservation); 6] = [
            |value| value.port_id += 1,
            |value| value.sequence += 1,
            |value| value.ifindex += 1,
            |value| value.device_namespace += 1,
            |value| value.listen_port += 1,
            |value| value.parts -= 1,
        ];
        for change in changes {
            let mut different = observation;
            change(&mut different);
            assert_eq!(
                check_socket_observation(receipt, different),
                Err(Error::Changed)
            );
        }
    }

    #[test]
    fn socket_observation_requires_two_distinct_cookies_and_a_namespace() {
        let changes: [fn(&mut WireGuardSocketObservation); 4] = [
            |value| value.socket_namespace = 0,
            |value| value.ipv4_cookie = 0,
            |value| value.ipv6_cookie = 0,
            |value| value.ipv6_cookie = value.ipv4_cookie,
        ];
        for change in changes {
            let mut invalid = observation();
            change(&mut invalid);
            assert_eq!(
                check_socket_observation(receipt(), invalid),
                Err(Error::Unavailable)
            );
        }
    }

    struct TestObserver<F>(F);

    impl<F> WireGuardSocketObserver for TestObserver<F>
    where
        F: FnMut(WireGuardReadReceipt) -> Result<WireGuardSocketObservation, Error> + Send,
    {
        fn prepare(&mut self, _port_id: u32, _sequence: u32) -> Result<(), Error> {
            Ok(())
        }

        fn observe(
            &mut self,
            receipt: WireGuardReadReceipt,
        ) -> Result<WireGuardSocketObservation, Error> {
            (self.0)(receipt)
        }
    }

    #[test]
    fn observer_honors_cancellation_during_observation() {
        let (sender, cancel) = Cancellation::new();
        let mut observer = TestObserver(move |actual| {
            assert_eq!(actual, receipt());
            sender.send(true).unwrap();
            Ok(observation())
        });
        assert_eq!(
            observe_socket(&mut observer, receipt(), &cancel, Instant::now() + MAX_WAIT),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn expired_deadline_prevents_observation() {
        let (_sender, cancel) = Cancellation::new();
        let mut observer = TestObserver(|_actual| panic!("Истёк срок наблюдения"));
        assert_eq!(
            observe_socket(&mut observer, receipt(), &cancel, Instant::now()),
            Err(Error::Timeout)
        );
    }

    #[test]
    fn unbound_device_cannot_prove_socket_origin() {
        let (_sender, cancel) = Cancellation::new();
        let mut observer = TestObserver(|_actual| panic!("Сокеты устройства не открыты"));
        let receipt = WireGuardReadReceipt {
            listen_port: 0,
            ..receipt()
        };
        assert_eq!(
            observe_socket(&mut observer, receipt, &cancel, Instant::now() + MAX_WAIT),
            Err(Error::Unavailable)
        );
    }

    #[tokio::test]
    async fn refuses_cancelled_read_before_opening_netlink() {
        let (sender, mut cancel) = Cancellation::new();
        sender.send(true).unwrap();
        assert_eq!(
            read_wireguard_device(7, &mut cancel, MAX_WAIT).await,
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn multipart_reassembles_only_adjacent_peer_fragments() {
        let namespace = NetworkNamespace {
            device: 1,
            inode: 2,
        };
        let part = |first: bool, identity, octet| DevicePart {
            ifindex: first.then_some(7),
            ifname: first.then(|| b"wg-test".to_vec()),
            listen_port: first.then_some(24177),
            fwmark: first.then_some(42),
            peers: vec![WireGuardPeer {
                identity: [identity; 32],
                endpoint: first.then_some("192.0.2.2:24177".parse().unwrap()),
                allowed_ips: vec![IpPrefix {
                    address: Ipv4Addr::new(192, 0, 2, octet).into(),
                    length: 32,
                }],
            }],
        };
        let first = part(true, 1, 22);
        let mut second = part(true, 1, 1);
        second.peers[0].endpoint = None;
        let third = part(false, 1, 5);
        let result = assemble(namespace, 7, vec![first, second, third]).unwrap();
        assert_eq!(
            result.peers[0].endpoint,
            Some("192.0.2.2:24177".parse().unwrap())
        );
        assert_eq!(
            result.peers[0].allowed_ips[0].address,
            Ipv4Addr::new(192, 0, 2, 1)
        );
        assert_eq!(result.peers[0].allowed_ips.len(), 3);
        assert_eq!(format!("{result:?}"), "WireGuardDevice(<скрыто>)");
        assert_eq!(
            assemble(
                namespace,
                7,
                vec![part(true, 1, 22), part(false, 2, 1), part(false, 1, 2)]
            ),
            Err(Error::Changed)
        );
    }

    #[test]
    fn rejects_ambiguous_attributes_and_malformed_endpoints() {
        let mut message = request(0, 1, 2, b"wg-test\0");
        attribute(&mut message, 2, b"foreign\0");
        assert_eq!(device_part(&message).err(), Some(Error::Malformed));
        let mut address = [0; 28];
        address[..2].copy_from_slice(&10_u16.to_ne_bytes());
        address[2..4].copy_from_slice(&24177_u16.to_be_bytes());
        address[8..24].copy_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        address[24..].copy_from_slice(&7_u32.to_ne_bytes());
        assert_eq!(
            endpoint(&address).unwrap(),
            "[fe80::1%7]:24177".parse().unwrap()
        );
        assert_eq!(endpoint(&address[..27]), Err(Error::Malformed));
    }
}
