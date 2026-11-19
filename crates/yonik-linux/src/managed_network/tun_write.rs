//! Закрытый RTNETLINK write transport: ACK не заменяет последующую сверку.
use super::config::{TunAddress, TunRoute};
use super::{OperationLease, ResolverRouteRule, TunError, TunRule};
use rustix::net::{
    self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink::SocketAddrNetlink,
};
use std::{io, os::fd::OwnedFd, sync::Arc};
use tokio::io::unix::AsyncFd;

const MAX_BYTES: usize = 64 * 1024;
const HEADER: usize = 16;

pub(super) enum Action {
    Rule {
        rule: TunRule,
        add: bool,
    },
    ResolverRule {
        rule: ResolverRouteRule,
        add: bool,
    },
    SetAlias {
        index: u32,
        alias: Vec<u8>,
    },
    SetLink {
        index: u32,
        mtu: u32,
    },
    Delete {
        index: u32,
    },
    Address {
        index: u32,
        address: TunAddress,
        add: bool,
    },
    Route {
        index: u32,
        route: TunRoute,
        add: bool,
    },
}
fn attribute(body: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = 4 + value.len();
    body.extend_from_slice(&(length as u16).to_ne_bytes());
    body.extend_from_slice(&kind.to_ne_bytes());
    body.extend_from_slice(value);
    body.resize((body.len() + 3) & !3, 0);
}
fn address_bytes(address: std::net::IpAddr) -> Vec<u8> {
    match address {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}
impl Action {
    fn kind(&self) -> u16 {
        match self {
            Self::SetAlias { .. } | Self::SetLink { .. } => 19,
            Self::Delete { .. } => 17,
            Self::Address { add: true, .. } => 20,
            Self::Address { add: false, .. } => 21,
            Self::Route { add: true, .. } => 24,
            Self::Route { add: false, .. } => 25,
            Self::Rule { add: true, .. } | Self::ResolverRule { add: true, .. } => 32,
            Self::Rule { add: false, .. } | Self::ResolverRule { add: false, .. } => 33,
        }
    }
    fn flags(&self) -> u16 {
        if matches!(
            self,
            Self::Address { add: true, .. }
                | Self::Route { add: true, .. }
                | Self::Rule { add: true, .. }
                | Self::ResolverRule { add: true, .. }
        ) {
            0x605
        } else {
            5
        }
    }
    fn request(&self, sequence: u32, port: u32) -> Result<Vec<u8>, TunError> {
        let index = match self {
            Self::SetAlias { index, .. }
            | Self::SetLink { index, .. }
            | Self::Delete { index }
            | Self::Address { index, .. }
            | Self::Route { index, .. } => *index,
            Self::Rule { .. } | Self::ResolverRule { .. } => 1,
        };
        if index == 0 || index > i32::MAX as u32 {
            return Err(TunError::Invalid);
        }
        let mut body = match self {
            Self::Rule { rule, .. } => {
                let mut value = vec![if rule.ipv6() { 10 } else { 2 }, 0, 0, 0, 0, 0, 0, 1];
                value.extend_from_slice(&2_u32.to_ne_bytes()); // FIB_RULE_INVERT.
                attribute(&mut value, 6, &rule.priority().to_ne_bytes());
                attribute(&mut value, 10, &rule.mark().to_ne_bytes());
                attribute(&mut value, 15, &rule.table().to_ne_bytes());
                attribute(&mut value, 16, &u32::MAX.to_ne_bytes());
                attribute(&mut value, 21, &[253]);
                value
            }
            Self::ResolverRule { rule, .. } => {
                if rule.mark() == 0 {
                    return Err(TunError::Invalid);
                }
                let endpoint = rule.endpoint();
                let address = address_bytes(endpoint.ip());
                let (family, prefix) = if endpoint.is_ipv4() {
                    (2, 32)
                } else {
                    (10, 128)
                };
                let mut value = vec![family, prefix, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
                let uid = rule.uid().to_ne_bytes();
                let mut uid_range = [0; 8];
                uid_range[..4].copy_from_slice(&uid);
                uid_range[4..].copy_from_slice(&uid);
                let port = endpoint.port().to_ne_bytes();
                let mut port_range = [0; 4];
                port_range[..2].copy_from_slice(&port);
                port_range[2..].copy_from_slice(&port);
                attribute(&mut value, 1, &address); // FRA_DST.
                attribute(&mut value, 6, &rule.priority().to_ne_bytes()); // FRA_PRIORITY.
                // Нулевая маска сохраняет метку владения в правиле, не ограничивая трафик.
                attribute(&mut value, 10, &rule.mark().to_ne_bytes()); // FRA_FWMARK.
                attribute(&mut value, 15, &rule.table().to_ne_bytes()); // FRA_TABLE.
                attribute(&mut value, 16, &0_u32.to_ne_bytes()); // FRA_FWMASK.
                attribute(&mut value, 20, &uid_range); // FRA_UID_RANGE.
                attribute(&mut value, 21, &[253]); // FRA_PROTOCOL.
                attribute(&mut value, 22, &[6]); // FRA_IP_PROTO: TCP.
                attribute(&mut value, 24, &port_range); // FRA_DPORT_RANGE.
                value
            }
            Self::Address { address, .. } => {
                let mut value = vec![
                    if address.address().is_ipv4() { 2 } else { 10 },
                    address.prefix_len(),
                    2,
                    0,
                ];
                value.extend_from_slice(&index.to_ne_bytes());
                let ip = address_bytes(address.address());
                attribute(&mut value, 1, &ip);
                attribute(&mut value, 2, &ip);
                // NODAD и NOPREFIXROUTE: маршруты принадлежат отдельным intents.
                attribute(&mut value, 8, &0x202_u32.to_ne_bytes());
                value
            }
            Self::Route { route, .. } => {
                let mut value = vec![
                    if route.destination().is_ipv4() { 2 } else { 10 },
                    route.prefix_len(),
                    0,
                    0,
                    0,
                    253,
                    route.scope(),
                    route.kind(),
                ];
                value.extend_from_slice(&0_u32.to_ne_bytes());
                if route.prefix_len() != 0 {
                    attribute(&mut value, 1, &address_bytes(route.destination()));
                }
                if !route.is_throw() {
                    attribute(&mut value, 4, &index.to_ne_bytes());
                }
                attribute(&mut value, 6, &route.priority().to_ne_bytes());
                attribute(&mut value, 15, &route.table().to_ne_bytes());
                value
            }
            _ => {
                let mut value = vec![0; 16];
                value[4..8].copy_from_slice(&index.to_ne_bytes());
                value
            }
        };
        match self {
            Self::SetAlias { alias, .. } => {
                if alias.is_empty() || alias.len() > 254 || alias.contains(&0) {
                    return Err(TunError::Invalid);
                }
                let mut terminated = alias.clone();
                terminated.push(0);
                attribute(&mut body, 20, &terminated);
            }
            Self::SetLink { mtu, .. } => {
                if !(1280..=9000).contains(mtu) {
                    return Err(TunError::Invalid);
                }
                body[8..12].copy_from_slice(&1_u32.to_ne_bytes());
                body[12..16].copy_from_slice(&1_u32.to_ne_bytes());
                // Свой TUN использует только явно назначенные helper адреса.
                // Устанавливаем NONE до attach, чтобы не запускать link-local/RS.
                let mut inet6 = Vec::new();
                attribute(&mut inet6, 8, &[1]); // IFLA_INET6_ADDR_GEN_MODE=NONE
                let mut families = Vec::new();
                attribute(&mut families, 10, &inet6); // AF_INET6
                attribute(&mut body, 26, &families); // IFLA_AF_SPEC
                attribute(&mut body, 4, &mtu.to_ne_bytes());
            }
            _ => {}
        }
        let mut bytes = Vec::with_capacity(HEADER + body.len());
        bytes.extend_from_slice(&((HEADER + body.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&self.kind().to_ne_bytes());
        bytes.extend_from_slice(&self.flags().to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&port.to_ne_bytes());
        bytes.extend(body);
        Ok(bytes)
    }
}

fn value_u32(bytes: &[u8]) -> Result<u32, TunError> {
    Ok(u32::from_ne_bytes(
        bytes.try_into().map_err(|_| TunError::Evidence)?,
    ))
}
fn value_u16(bytes: &[u8]) -> Result<u16, TunError> {
    Ok(u16::from_ne_bytes(
        bytes.try_into().map_err(|_| TunError::Evidence)?,
    ))
}
fn accept(
    bytes: &[u8],
    sequence: u32,
    port: u32,
    kind: u16,
    request_length: usize,
    flags: u16,
) -> Result<bool, TunError> {
    let mut rest = bytes;
    let mut acknowledged = false;
    while !rest.is_empty() {
        if rest.len() < HEADER {
            return Err(TunError::Evidence);
        }
        let length = value_u32(&rest[..4])? as usize;
        if length < HEADER || length > rest.len() {
            return Err(TunError::Evidence);
        }
        let size = (length + 3) & !3;
        if size > rest.len() {
            return Err(TunError::Evidence);
        }
        if value_u32(&rest[8..12])? == sequence {
            if acknowledged
                || value_u16(&rest[6..8])? & !0x0300 != 0
                || value_u16(&rest[4..6])? != 2
                || value_u32(&rest[12..16])? != port
                || length < 36
            {
                return Err(TunError::Evidence);
            }
            let original = &rest[20..36];
            if value_u32(&original[..4])? as usize != request_length
                || value_u16(&original[6..8])? != flags
                || value_u16(&original[4..6])? != kind
                || value_u32(&original[8..12])? != sequence
                || value_u32(&original[12..16])? != port
            {
                return Err(TunError::Evidence);
            }
            let error =
                i32::from_ne_bytes(rest[16..20].try_into().map_err(|_| TunError::Evidence)?);
            if error < 0 {
                return Err(TunError::Rejected);
            }
            if error != 0 {
                return Err(TunError::Evidence);
            }
            acknowledged = true;
        }
        rest = &rest[size..];
    }
    Ok(acknowledged)
}

pub(super) async fn run(action: Action, lease: Arc<OperationLease>) -> Result<(), TunError> {
    let kind = action.kind();
    let flags = action.flags();
    let socket = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| TunError::Io)?;
    net::bind(&socket, &SocketAddrNetlink::new(0, 0)).map_err(|_| TunError::Io)?;
    let address = net::getsockname(&socket).map_err(|_| TunError::Io)?;
    let port = SocketAddrNetlink::try_from(address)
        .map_err(|_| TunError::Io)?
        .pid();
    let mut random = [0; 4];
    getrandom::getrandom(&mut random).map_err(|_| TunError::Io)?;
    let sequence = u32::from_ne_bytes(random).max(1);
    let request = action.request(sequence, port)?;
    #[allow(deprecated)]
    let socket = AsyncFd::new(socket).map_err(|_| TunError::Io)?;
    // После отправки ACK ожидается даже при Drop вызывающего future: новая
    // операция не обгоняет уже переданный kernel запрос внутри процесса.
    tokio::spawn(async move {
        let _lease = lease;
        tokio::time::timeout(
            super::DEADLINE,
            exchange(socket, request, sequence, port, kind, flags),
        )
        .await
        .map_err(|_| TunError::Timeout)?
    })
    .await
    .map_err(|_| TunError::Io)?
}
async fn exchange(
    socket: AsyncFd<OwnedFd>,
    request: Vec<u8>,
    sequence: u32,
    port: u32,
    kind: u16,
    flags: u16,
) -> Result<(), TunError> {
    loop {
        let mut ready = socket.writable().await.map_err(|_| TunError::Io)?;
        match ready.try_io(|fd| {
            net::sendto(
                fd.get_ref(),
                &request,
                SendFlags::empty(),
                &SocketAddrNetlink::new(0, 0),
            )
            .map_err(io::Error::from)
        }) {
            Err(_) => continue,
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(_)) => return Err(TunError::Io),
            Ok(Ok(length)) if length == request.len() => break,
            Ok(Ok(_)) => return Err(TunError::Evidence),
        }
    }
    let mut bytes = vec![0; MAX_BYTES];
    let mut used = 0_usize;
    loop {
        let mut ready = socket.readable().await.map_err(|_| TunError::Io)?;
        let (length, address) = match ready.try_io(|fd| {
            net::recvfrom(fd.get_ref(), &mut bytes, RecvFlags::TRUNC)
                .map(|(_, length, address)| (length, address))
                .map_err(io::Error::from)
        }) {
            Err(_) => continue,
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(_)) => return Err(TunError::Io),
            Ok(Ok(value)) => value,
        };
        used = used.checked_add(length).ok_or(TunError::OutputLimit)?;
        if length == 0 || length > bytes.len() || used > MAX_BYTES {
            return Err(TunError::OutputLimit);
        }
        let sender = address
            .and_then(|v| SocketAddrNetlink::try_from(v).ok())
            .ok_or(TunError::Evidence)?;
        if sender.pid() != 0 {
            continue;
        }
        if sender.groups() != 0 {
            return Err(TunError::Evidence);
        }
        if accept(&bytes[..length], sequence, port, kind, request.len(), flags)? {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ack() -> Vec<u8> {
        let request = Action::Delete { index: 7 }.request(3, 5).unwrap();
        let mut bytes = vec![0; 36];
        bytes[..4].copy_from_slice(&36_u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&2_u16.to_ne_bytes());
        bytes[8..12].copy_from_slice(&3_u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&5_u32.to_ne_bytes());
        bytes[20..36].copy_from_slice(&request[..16]);
        bytes
    }
    #[test]
    fn request_is_closed_and_targets_index_without_name() {
        let request = Action::Delete { index: 7 }.request(3, 5).unwrap();
        assert_eq!(request.len(), 32);
        assert_eq!(&request[20..24], &7_u32.to_ne_bytes());
        assert!(Action::Delete { index: 0 }.request(3, 5).is_err());
        assert!(
            Action::SetAlias {
                index: 7,
                alias: b"bad\0value".to_vec()
            }
            .request(3, 5)
            .is_err()
        );
        let request = Action::SetAlias {
            index: 7,
            alias: b"owner".to_vec(),
        }
        .request(3, 5)
        .unwrap();
        assert_eq!(&request[32..36], &[10, 0, 20, 0]);
        assert_eq!(&request[36..42], b"owner\0");
    }
    #[test]
    fn address_and_route_creation_are_exclusive_without_replace() {
        let address = TunAddress::new("198.18.0.1".parse().unwrap(), 30).unwrap();
        let route = TunRoute::new("198.18.0.0".parse().unwrap(), 30, 1001, 47).unwrap();
        for action in [
            Action::Address {
                index: 7,
                address,
                add: true,
            },
            Action::Route {
                index: 7,
                route,
                add: true,
            },
        ] {
            let request = action.request(3, 5).unwrap();
            let flags = value_u16(&request[6..8]).unwrap();
            assert_eq!(flags & 0x600, 0x600); // CREATE | EXCL.
            assert_eq!(flags & 0x100, 0); // Никогда REPLACE.
            assert_eq!(flags & 5, 5); // REQUEST | ACK.
        }
        for action in [
            Action::Address {
                index: 7,
                address,
                add: false,
            },
            Action::Route {
                index: 7,
                route,
                add: false,
            },
        ] {
            let request = action.request(3, 5).unwrap();
            assert_eq!(value_u16(&request[6..8]).unwrap(), 5);
        }
        assert!(
            Action::SetLink {
                index: 7,
                mtu: 1279
            }
            .request(3, 5)
            .is_err()
        );
    }
    #[test]
    fn rule_wire_image_has_only_fixed_selectors_and_exact_delete() {
        for ipv6 in [false, true] {
            let rule = TunRule::new(10001, 1001, 47, ipv6).unwrap();
            let add = Action::Rule { rule, add: true }.request(3, 5).unwrap();
            let delete = Action::Rule { rule, add: false }.request(3, 5).unwrap();
            assert_eq!(value_u16(&add[4..6]), Ok(32));
            assert_eq!(value_u16(&add[6..8]), Ok(0x605));
            assert_eq!(value_u16(&delete[4..6]), Ok(33));
            assert_eq!(value_u16(&delete[6..8]), Ok(5));
            assert_eq!(&add[16..], &delete[16..]);
            let mut expected = vec![if ipv6 { 10 } else { 2 }, 0, 0, 0, 0, 0, 0, 1];
            expected.extend_from_slice(&2_u32.to_ne_bytes());
            for (kind, value) in [(6, 10001_u32), (10, 47), (15, 1001), (16, u32::MAX)] {
                attribute(&mut expected, kind, &value.to_ne_bytes());
            }
            attribute(&mut expected, 21, &[253]);
            assert_eq!(&add[16..], expected);
        }
    }
    #[test]
    fn resolver_rule_wire_image_matches_only_exact_tcp_endpoint_and_uid() {
        let ipv4 = [192, 0, 2, 53];
        let ipv6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
        ];
        for (endpoint, family, prefix, destination) in [
            ("192.0.2.53:853", 2, 32, ipv4.as_slice()),
            ("[2001:db8::53]:853", 10, 128, ipv6.as_slice()),
        ] {
            let owner = crate::managed_network::Ownership::new(1000, 7, 9, 1, 2).unwrap();
            let rule = ResolverRouteRule::new(10000, 1001, 1000, endpoint.parse().unwrap())
                .unwrap()
                .with_owner(owner, 2);
            let add = Action::ResolverRule { rule, add: true }
                .request(3, 5)
                .unwrap();
            let delete = Action::ResolverRule { rule, add: false }
                .request(3, 5)
                .unwrap();
            assert_eq!(value_u32(&add[..4]), Ok(add.len() as u32));
            assert_eq!(value_u16(&add[4..6]), Ok(32));
            assert_eq!(value_u16(&add[6..8]), Ok(0x605));
            assert_eq!(value_u16(&delete[4..6]), Ok(33));
            assert_eq!(value_u16(&delete[6..8]), Ok(5));
            assert_eq!(&add[8..], &delete[8..]);
            assert_eq!(
                &add[16..28],
                &[family, prefix, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
            );
            let mut attributes = &add[28..];
            for (kind, payload) in [
                (1, destination),
                (6, &10000_u32.to_ne_bytes()),
                (10, &rule.mark().to_ne_bytes()),
                (15, &1001_u32.to_ne_bytes()),
                (16, &0_u32.to_ne_bytes()),
                (20, &1000_u32.to_ne_bytes().repeat(2)),
                (21, &[253]),
                (22, &[6]),
                (24, &853_u16.to_ne_bytes().repeat(2)),
            ] {
                let length = payload.len() + 4;
                let aligned_length = (length + 3) & !3;
                assert_eq!(value_u16(&attributes[..2]), Ok(length as u16));
                assert_eq!(value_u16(&attributes[2..4]), Ok(kind));
                assert_eq!(&attributes[4..length], payload);
                assert!(
                    attributes[length..aligned_length]
                        .iter()
                        .all(|byte| *byte == 0)
                );
                attributes = &attributes[aligned_length..];
            }
            assert!(attributes.is_empty());
        }
    }
    #[test]
    fn ack_requires_matching_outer_and_original_identity() {
        let original = ack();
        assert_eq!(accept(&original, 3, 5, 17, 32, 5), Ok(true));
        assert_eq!(accept(&original, 4, 5, 17, 32, 5), Ok(false));
        for offset in [4, 6, 12, 20, 24, 26, 28, 32] {
            let mut value = original.clone();
            value[offset] ^= 1;
            assert!(accept(&value, 3, 5, 17, 32, 5).is_err(), "offset {offset}");
        }
        for length in [0, 1, 15, 16, 35] {
            assert!(accept(&original[..length], 3, 5, 17, 32, 5).is_err() || length == 0);
        }
        let mut rejected = original;
        rejected[16..20].copy_from_slice(&(-1_i32).to_ne_bytes());
        assert_eq!(accept(&rejected, 3, 5, 17, 32, 5), Err(TunError::Rejected));
    }
}
