use super::{IpPrefix, LinuxLink, LinuxRoute, NetworkReadError, read_topology};
use crate::Cancellation;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

const IFF_UP: u32 = 1;
const RT_TABLE_MAIN: u32 = 254;
const RTN_UNICAST: u8 = 1;
const RTNH_F_UNAVAILABLE: u32 = 1 | 16; // DEAD | LINKDOWN
const MAX_SPLIT_PREFIXES: usize = 256;

/// Маршруты текущего снимка основной таблицы. Для Local прозрачность заканчивается
/// выбором DIRECT: последующий маршрут пакета по-прежнему определяет Linux.
pub async fn local_vpn_split_cidrs(
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<Vec<IpPrefix>, NetworkReadError> {
    let topology = read_topology(cancel, timeout).await?;
    let cidrs = split_cidrs(&topology.links, &topology.routes)?;
    cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
    Ok(cidrs)
}

fn split_cidrs(
    links: &[LinuxLink],
    routes: &[LinuxRoute],
) -> Result<Vec<IpPrefix>, NetworkReadError> {
    let vpn_indices: BTreeSet<_> = links
        .iter()
        .filter(|link| {
            link.flags & IFF_UP != 0
                && matches!(link.kind.as_deref(), Some(b"wireguard" | b"tun"))
                && !link.name.strip_prefix(b"tofu").is_some_and(|suffix| {
                    suffix.len() == 8 && suffix.iter().all(u8::is_ascii_hexdigit)
                })
        })
        .map(|link| link.index)
        .collect();
    let main_routes = || {
        routes
            .iter()
            .filter(|route| route.table == RT_TABLE_MAIN && route.destination.length >= 2)
    };
    let eligible = |route: &LinuxRoute| {
        route.kind == RTN_UNICAST
            && route.flags & RTNH_F_UNAVAILABLE == 0
            && route.source.length == 0
            && route.tos == 0
            && route.input_interface.is_none()
            && route.nexthop_id.is_none()
            && route.multipath.is_empty()
            && route
                .output_interface
                .is_some_and(|index| vpn_indices.contains(&index))
    };
    let mut prefixes: BTreeSet<_> = main_routes()
        .filter(|route| eligible(route))
        .map(|route| (route.destination.address, route.destination.length))
        .collect();
    if prefixes.is_empty() {
        return Ok(Vec::new());
    }
    // Одно совпадение префикса в ядре маршрутизации означает DIRECT для всего CIDR.
    // Маршрут другого типа на этом или более узком CIDR делает его неоднозначным.
    for route in main_routes().filter(|route| !eligible(route)) {
        for length in 2..=route.destination.length {
            prefixes.remove(&(network_address(route.destination.address, length), length));
        }
    }
    if prefixes.len() > MAX_SPLIT_PREFIXES {
        return Err(NetworkReadError::Limit);
    }
    Ok(prefixes
        .into_iter()
        .map(|(address, length)| IpPrefix { address, length })
        .collect())
}

fn network_address(address: IpAddr, length: u8) -> IpAddr {
    match address {
        IpAddr::V4(ip) => Ipv4Addr::from(u32::from(ip) & (u32::MAX << (32 - length))).into(),
        IpAddr::V6(ip) => Ipv6Addr::from(u128::from(ip) & (u128::MAX << (128 - length))).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::topology::{parse_link, parse_route};

    fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        bytes.extend(((value.len() + 4) as u16).to_ne_bytes());
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
    }

    fn link(index: u32, name: &[u8], kind: &[u8], flags: u32) -> LinuxLink {
        let mut bytes = vec![0; 16];
        bytes[4..8].copy_from_slice(&index.to_ne_bytes());
        bytes[8..12].copy_from_slice(&flags.to_ne_bytes());
        attribute(&mut bytes, 3, name);
        let mut info = Vec::new();
        attribute(&mut info, 1, kind);
        attribute(&mut bytes, 18, &info);
        parse_link(&bytes).unwrap()
    }

    fn route(cidr: &str, interface: u32, table: u8) -> LinuxRoute {
        let (address, length) = cidr.split_once('/').unwrap();
        let address: std::net::IpAddr = address.parse().unwrap();
        let family = if address.is_ipv4() { 2 } else { 10 };
        let mut bytes = vec![
            family,
            length.parse().unwrap(),
            0,
            0,
            table,
            4,
            0,
            1,
            0,
            0,
            0,
            0,
        ];
        match address {
            std::net::IpAddr::V4(address) => attribute(&mut bytes, 1, &address.octets()),
            std::net::IpAddr::V6(address) => attribute(&mut bytes, 1, &address.octets()),
        }
        attribute(&mut bytes, 4, &interface.to_ne_bytes());
        parse_route(&bytes).unwrap()
    }

    #[test]
    fn только_однозначные_маршруты_через_активные_локальные_vpn() {
        let links = [
            link(1, b"wg0\0", b"wireguard\0", 1),
            link(2, b"tun0\0", b"tun\0", 1),
            link(3, b"tun1\0", b"tun\0", 0),
            link(4, b"eth0\0", b"ether\0", 1),
            link(5, b"tofu1234abcd\0", b"tun\0", 1),
        ];
        let mut routes = vec![
            route("10.10.0.0/16", 1, 254),
            route("10.10.0.0/16", 1, 254),
            route("fd00::/64", 2, 254),
            route("0.0.0.0/0", 1, 254),
            route("128.0.0.0/1", 2, 254),
            route("8000::/1", 2, 254),
            route("10.11.0.0/16", 1, 50),
            route("10.12.0.0/16", 3, 254),
            route("10.13.0.0/16", 4, 254),
            route("10.14.0.0/16", 5, 254),
            route("10.15.0.0/16", 1, 254),
            route("10.15.10.0/24", 4, 254),
            route("10.16.0.0/16", 1, 254),
            route("10.16.0.0/16", 4, 254),
        ];
        let mut link_down = route("10.17.0.0/16", 1, 254);
        link_down.flags = 16;
        routes.push(link_down);
        assert_eq!(
            split_cidrs(&links, &routes).unwrap(),
            [
                IpPrefix {
                    address: "10.10.0.0".parse().unwrap(),
                    length: 16
                },
                IpPrefix {
                    address: "fd00::".parse().unwrap(),
                    length: 64
                },
            ]
        );
    }
}
