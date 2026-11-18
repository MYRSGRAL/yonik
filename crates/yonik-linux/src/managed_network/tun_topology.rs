//! Чистая проекция внешней топологии: исключает только доказанные эффекты сессии.
use super::{
    Journal, RecordState, Resource, Scope, TunAddress, TunError, TunRule, alias, config, observed,
    rule,
};
use crate::{LinuxRoute, LinuxTopology};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
#[cfg(test)]
#[path = "tun_topology_tests.rs"]
mod tests;

#[cfg(test)]
fn session_external_topology(
    topology: LinuxTopology,
    journal: &Journal,
    tun_id: u64,
    mtu: u16,
) -> Result<LinuxTopology, TunError> {
    session_external_topology_with_framing(topology, journal, tun_id, mtu, false)
}
pub(crate) fn session_external_topology_with_framing(
    topology: LinuxTopology,
    journal: &Journal,
    tun_id: u64,
    mtu: u16,
    vnet_hdr: bool,
) -> Result<LinuxTopology, TunError> {
    project(
        topology,
        journal,
        tun_id,
        mtu,
        vnet_hdr,
        QueuePhase::Detached,
    )
}
// Attached phase нельзя получить из caller bool или ожидаемого счётчика.
pub(super) enum QueuePhase<'a> {
    Detached,
    Attached(&'a super::custody::BoundTun),
}
pub(super) fn attached_topology(
    topology: LinuxTopology,
    journal: &Journal,
    bound: &super::custody::BoundTun,
) -> Result<LinuxTopology, TunError> {
    bound.check_binding(journal, &topology)?;
    project(
        topology,
        journal,
        bound.tun_id,
        bound.mtu,
        bound.framing == yonik_nsfs::tun::Framing::Vnet10,
        QueuePhase::Attached(bound),
    )
}
// Pre-attach проверяет Journal и сам link. IPv6 routes могут появиться только
// при carrier-on; полноту configured topology по-прежнему проверяет project.
pub(super) fn detached_parent(
    topology: &LinuxTopology,
    journal: &Journal,
    tun_id: u64,
    mtu: u16,
    vnet_hdr: bool,
) -> Result<(), TunError> {
    parent(
        topology,
        journal,
        tun_id,
        mtu,
        vnet_hdr,
        &QueuePhase::Detached,
    )
    .map(|_| ())
}
fn parent(
    topology: &LinuxTopology,
    journal: &Journal,
    tun_id: u64,
    mtu: u16,
    vnet_hdr: bool,
    phase: &QueuePhase<'_>,
) -> Result<(u32, Vec<u8>), TunError> {
    if !(1280..=9000).contains(&mtu) {
        return Err(TunError::Invalid);
    }
    if (topology.namespace.device, topology.namespace.inode) != journal.ownership().namespace() {
        return Err(TunError::Namespace);
    }
    let mut parent = None;
    for record in journal.records() {
        if record.scope() == Scope::PublicBlock
            && matches!(record.resource(), Resource::NftTable { .. })
        {
            continue;
        }
        if record.scope() != Scope::Session
            || record.state() != RecordState::Confirmed
            || journal.needs_reconciliation(record.id())
        {
            return Err(TunError::Evidence);
        }
        if let Resource::Tun { name_id } = record.resource() {
            if parent.replace((record.id(), *name_id)).is_some() {
                return Err(TunError::Evidence);
            }
        }
    }
    let (id, name_id) = parent.ok_or(TunError::Evidence)?;
    if id != tun_id {
        return Err(TunError::Evidence);
    }
    let index = observed(&topology.links, name_id, &alias(journal.ownership(), id)?)?
        .ok_or(TunError::Evidence)?;
    let mut indices = BTreeSet::new();
    for link in &topology.links {
        if !indices.insert(link.index) || link.parent == Some(index) || link.master == Some(index) {
            return Err(TunError::Foreign);
        }
    }
    let link = topology
        .links
        .iter()
        .find(|link| link.index == index)
        .ok_or(TunError::Evidence)?;
    if link.mtu != Some(u32::from(mtu))
        || link.master.is_some()
        || link.parent.is_some()
        || link.flags & 0x1091 != 0x1091
        || link.flags & !0x110d1 != 0
        || !matches!(link.operational_state, None | Some(0 | 2 | 6))
        || !link_metadata(
            &link.unknown,
            journal.ownership().owner_uid(),
            vnet_hdr,
            phase,
        )
    {
        return Err(TunError::Foreign);
    }
    if let QueuePhase::Attached(bound) = phase {
        bound.queue.verify().map_err(|_| TunError::Evidence)?;
        if link.flags & 0x10000 == 0 || !link.unknown.iter().any(|a| a.kind == 33 && a.value == [1])
        {
            return Err(TunError::Evidence);
        }
    }
    Ok((index, link.name.clone()))
}
fn project(
    mut topology: LinuxTopology,
    journal: &Journal,
    tun_id: u64,
    mtu: u16,
    vnet_hdr: bool,
    phase: QueuePhase<'_>,
) -> Result<LinuxTopology, TunError> {
    let (index, link_name) = parent(&topology, journal, tun_id, mtu, vnet_hdr, &phase)?;
    let mut addresses = BTreeMap::new();
    let mut routes = BTreeMap::new();
    let mut rules = BTreeMap::new();
    let mut tables = BTreeSet::new();
    for record in journal
        .records()
        .iter()
        .filter(|r| r.scope() == Scope::Session)
    {
        match record.resource() {
            Resource::Tun { .. } => (),
            Resource::Address {
                tun_id: parent,
                ifindex,
                address,
                prefix_len,
            } if *parent == tun_id && *ifindex == index => {
                if addresses
                    .insert(*address, TunAddress::new(*address, *prefix_len)?)
                    .is_some()
                {
                    return Err(TunError::Evidence);
                }
            }
            resource @ (Resource::Route { .. } | Resource::ThrowRoute { .. }) => {
                let route =
                    config::recorded_route(resource, tun_id, index).ok_or(TunError::Evidence)?;
                tables.insert(route.table());
                if routes
                    .insert(
                        (route.table(), route.destination(), route.prefix_len()),
                        route,
                    )
                    .is_some()
                {
                    return Err(TunError::Evidence);
                }
            }
            Resource::TunRule {
                tun_id: parent,
                ifindex,
                priority,
                table,
                mark,
                ipv6,
            } if *parent == tun_id && *ifindex == index => {
                tables.insert(*table);
                if rules
                    .insert(
                        (if *ipv6 { 10 } else { 2 }, *priority),
                        TunRule::new(*priority, *table, *mark, *ipv6)?,
                    )
                    .is_some()
                {
                    return Err(TunError::Evidence);
                }
            }
            _ => return Err(TunError::Evidence),
        }
    }
    let configured = addresses.clone();
    let mut remaining_addresses = Vec::new();
    for address in topology.addresses {
        if address.index != index {
            if configured.contains_key(&address.address)
                || address.local.is_some_and(|ip| configured.contains_key(&ip))
            {
                return Err(TunError::Foreign);
            }
            remaining_addresses.push(address);
            continue;
        }
        if let Some(expected) = configured.get(&address.address) {
            if !config::address_matches(&address, index, *expected)
                || addresses.remove(&address.address).is_none()
                || address.unknown.iter().any(|a| {
                    a.kind == 3 && a.value.strip_suffix(&[0]) != Some(link_name.as_slice())
                })
            {
                return Err(TunError::Foreign);
            }
        } else {
            remaining_addresses.push(address);
        }
    }
    if !addresses.is_empty() {
        return Err(TunError::Evidence);
    }
    topology.addresses = remaining_addresses;
    let mut remaining_routes = Vec::new();
    let mut consumed_routes = BTreeSet::new();
    let mut derived_local = BTreeSet::new();
    let loopback = config::loopback_ifindex(&topology);
    for route in topology.routes {
        let key = (
            route.table,
            route.destination.address,
            route.destination.length,
        );
        if let Some(expected) = routes.get(&key) {
            if !config::route_matches(&route, index, loopback, *expected)
                || !consumed_routes.insert(key)
            {
                return Err(TunError::Foreign);
            }
        } else if derived_address_route(&route, index, &configured) {
            if !derived_local.insert((route.family, route.destination.address)) {
                return Err(TunError::Foreign);
            }
        } else {
            if tables.contains(&route.table) {
                return Err(TunError::Foreign);
            }
            remaining_routes.push(route);
        }
    }
    if consumed_routes.len() != routes.len() {
        return Err(TunError::Evidence);
    }
    topology.routes = remaining_routes;
    let mut remaining_rules = Vec::new();
    let mut consumed_rules = BTreeSet::new();
    for value in topology.rules {
        let key = (value.family, value.priority.unwrap_or(0));
        if let Some(expected) = rules.get(&key) {
            if !rule::rule_matches(&value, *expected) || !consumed_rules.insert(key) {
                return Err(TunError::Foreign);
            }
        } else {
            if tables.contains(&value.table) {
                return Err(TunError::Foreign);
            }
            remaining_rules.push(value);
        }
    }
    if consumed_rules.len() != rules.len() {
        return Err(TunError::Evidence);
    }
    topology.rules = remaining_rules;
    config::check_tun_teardown(&topology, index)?;
    // Остатки разрешены предыдущей проверкой только как kernel LL/multicast.
    let mut seen = BTreeSet::new();
    for address in topology.addresses.iter().filter(|a| a.index == index) {
        if !seen.insert(address.address) {
            return Err(TunError::Foreign);
        }
    }
    let mut seen = BTreeSet::new();
    for route in topology
        .routes
        .iter()
        .filter(|r| r.output_interface == Some(index))
    {
        if !seen.insert((
            route.family,
            route.table,
            route.destination.address,
            route.destination.length,
            route.kind,
            route.priority,
        )) {
            return Err(TunError::Foreign);
        }
    }
    topology.links.retain(|l| l.index != index);
    topology.addresses.retain(|a| a.index != index);
    topology
        .routes
        .retain(|r| r.output_interface != Some(index));
    Ok(topology)
}

fn derived_address_route(
    route: &LinuxRoute,
    index: u32,
    addresses: &BTreeMap<IpAddr, TunAddress>,
) -> bool {
    let ip = route.destination.address;
    let broadcast = route.kind == 3
        && route.family == 2
        && route.preferred_source.is_some_and(|source| {
            let Some(expected) = addresses.get(&source) else {
                return false;
            };
            let IpAddr::V4(address) = source else {
                return false;
            };
            expected.prefix_len() <= 30
                && ip
                    == IpAddr::V4(std::net::Ipv4Addr::from(
                        u32::from(address) | (u32::MAX >> expected.prefix_len()),
                    ))
        });
    ((route.kind == 2 && addresses.contains_key(&ip)) || broadcast)
        && route.family == if ip.is_ipv4() { 2 } else { 10 }
        && route.destination.length == if ip.is_ipv4() { 32 } else { 128 }
        && route.table == 255
        && route.protocol == 2
        && route.scope
            == if broadcast {
                253
            } else if ip.is_ipv4() {
                254
            } else {
                0
            }
        && route.priority == if ip.is_ipv4() { None } else { Some(0) }
        && (broadcast || route.preferred_source == if ip.is_ipv4() { Some(ip) } else { None })
        && route.output_interface == Some(index)
        && route.input_interface.is_none()
        && route.gateway.is_none()
        && route.source.length == 0
        && route.source.address.is_unspecified()
        && route.tos == 0
        && route.flags & !16 == 0
        && route.multipath.is_empty()
        && route.nexthop_id.is_none()
        && route.unknown.iter().all(|a| match a.kind {
            20 => ip.is_ipv6() && a.value == [0],
            12 => a.value.len() == 32 && a.value[8..16] == [0; 8],
            _ => false,
        })
}

// Только ограниченные ABI-атрибуты Linux if_link.h. Неизвестные вложения,
// активный XDP и новые типы требуют явного расширения проверки.
fn attributes(bytes: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut bytes = bytes;
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 || result.len() >= 128 {
            return None;
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        let aligned = (length + 3) & !3;
        if length < 4 || aligned > bytes.len() || !seen.insert(kind) {
            return None;
        }
        result.push((kind, &bytes[4..length]));
        bytes = &bytes[aligned..];
    }
    Some(result)
}
pub(super) fn addrgen_none(link: &crate::LinuxLink) -> bool {
    let Some(families) = link
        .unknown
        .iter()
        .find(|a| a.kind == 26)
        .and_then(|a| attributes(&a.value))
    else {
        return false;
    };
    families
        .into_iter()
        .find(|(kind, _)| *kind == 10)
        .and_then(|(_, value)| attributes(value))
        .is_some_and(|attrs| {
            attrs
                .into_iter()
                .any(|(kind, value)| kind == 8 && value == [1])
        })
}
fn tun_info(bytes: &[u8], uid: u32, vnet_hdr: bool) -> bool {
    let Some(attrs) = attributes(bytes) else {
        return false;
    };
    let mut kind = false;
    let mut data = false;
    for (key, value) in attrs {
        match key {
            1 => {
                if value != b"tun\0" {
                    return false;
                }
                kind = true;
            }
            2 => {
                let Some(attrs) = attributes(value) else {
                    return false;
                };
                let mut fields = BTreeSet::new();
                for (key, value) in attrs {
                    let valid = match key {
                        1 => value == uid.to_ne_bytes(),
                        3 => value == [1],     // IFF_TUN
                        4 | 7 => value == [0], // NO_PI, без MULTI_QUEUE.
                        5 => value == [u8::from(vnet_hdr)],
                        6 => value == [1], // persistent
                        8 => value == 1u32.to_ne_bytes(),
                        9 => value == 0u32.to_ne_bytes(),
                        _ => false,
                    };
                    if !valid {
                        return false;
                    }
                    fields.insert(key);
                }
                if ![1, 3, 4, 5, 6, 7].iter().all(|key| fields.contains(key)) {
                    return false;
                }
                data = true;
            }
            _ => return false,
        }
    }
    kind && data
}
fn family_metadata(bytes: &[u8]) -> bool {
    let Some(families) = attributes(bytes) else {
        return false;
    };
    families.into_iter().all(|(family, bytes)| {
        let Some(attrs) = attributes(bytes) else {
            return false;
        };
        attrs.into_iter().all(|(key, value)| match (family, key) {
            // AF_INET/AF_INET6 devconf — ограниченные массивы u32 ABI.
            (2, 1) | (10, 2) => !value.is_empty() && value.len() <= 1024 && value.len() % 4 == 0,
            (10, 1) => value.len() == 4,
            (10, 3) | (10, 6) => !value.is_empty() && value.len() <= 1024 && value.len() % 8 == 0,
            (10, 5) | (10, 7) => value.len() == 16,
            (10, 8) => value.len() == 1 && value[0] <= 3,
            (45, 1) => value.len() == 4,
            (45, 2) => value == [0],
            _ => false,
        })
    })
}
fn link_metadata(
    attrs: &[crate::NetworkAttribute],
    uid: u32,
    vnet_hdr: bool,
    phase: &QueuePhase<'_>,
) -> bool {
    let mut seen = BTreeSet::new();
    (!matches!(phase, QueuePhase::Attached(_)) || attrs.iter().any(|a| a.kind == 18))
        && attrs.iter().all(|a| {
            seen.insert(a.kind)
                && match a.kind {
                    6 => [
                        b"noop\0".as_slice(),
                        b"noqueue\0",
                        b"fq_codel\0",
                        b"pfifo_fast\0",
                    ]
                    .contains(&a.value.as_slice()),
                    7 => a.value.len() == 96,
                    14 => a.value.len() == 32 && a.value.iter().all(|v| *v == 0),
                    17 | 39 => a.value == [0],
                    18 => tun_info(&a.value, uid, vnet_hdr),
                    23 => matches!(a.value.len(), 192 | 200),
                    26 => family_metadata(&a.value),
                    27 | 30 | 61 => a.value == [0; 4], // group, promiscuity, allmulti
                    31 | 32 => a.value == 1u32.to_ne_bytes(), // одна очередь
                    33 => a.value == [0] || a.value == [1],
                    43 => attributes(&a.value).is_some_and(|v| v == vec![(2, [0].as_slice())]),
                    13 | 35 | 40 | 41 | 47 | 48 | 50 | 51 | 58 | 59 | 60 | 63 | 64 | 66 => {
                        a.value.len() == 4
                    }
                    67 => a.value == [0] || a.value == [1],
                    68 | 69 => a.value == [0; 2],
                    32830 | 32833 => a.value.is_empty(), // пустые вложенные DPLL/devlink metadata
                    _ => false,
                }
        })
}
