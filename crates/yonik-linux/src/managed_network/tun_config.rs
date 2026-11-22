//! Настройки и дочерние ресурсы принадлежащего helper TUN.
use super::{DEADLINE, TunError, TunExecutor, alias, lease, observed, write};
use crate::managed_network::{Journal, JournalError, Reconciled, RecordState, Resource, Scope};
use crate::{Cancellation, LinuxAddress, LinuxRoute, LinuxTopology};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::Arc,
};

#[cfg(test)]
#[path = "tun_config_tests.rs"]
mod tests;

const ROUTE_PROTOCOL: u8 = 253;
const RTN_UNICAST: u8 = 1;
const RTN_THROW: u8 = 9;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TunAddress {
    address: IpAddr,
    prefix_len: u8,
}
impl TunAddress {
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, TunError> {
        if prefix_len == 0
            || prefix_len > if address.is_ipv4() { 32 } else { 128 }
            || address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || match address {
                IpAddr::V4(ip) => ip.is_broadcast() || ip.is_link_local(),
                IpAddr::V6(ip) => ip.is_unicast_link_local() || ip.to_ipv4().is_some(),
            }
        {
            return Err(TunError::Invalid);
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }
    pub fn address(self) -> IpAddr {
        self.address
    }
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TunRoute {
    destination: IpAddr,
    prefix_len: u8,
    table: u32,
    priority: u32,
    kind: u8,
}
impl TunRoute {
    pub fn new(
        destination: IpAddr,
        prefix_len: u8,
        table: u32,
        priority: u32,
    ) -> Result<Self, TunError> {
        let canonical = match destination {
            IpAddr::V4(ip) => {
                prefix_len <= 32 && u32::from(ip).trailing_zeros() >= 32 - u32::from(prefix_len)
            }
            IpAddr::V6(ip) => {
                prefix_len <= 128 && u128::from(ip).trailing_zeros() >= 128 - u32::from(prefix_len)
            }
        };
        if !canonical || !(256..u32::MAX).contains(&table) || priority == 0 {
            return Err(TunError::Invalid);
        }
        Ok(Self {
            destination,
            prefix_len,
            table,
            priority,
            kind: RTN_UNICAST,
        })
    }
    /// Более точный маршрут прерывает поиск в своей таблице. Допуск выхода
    /// через следующий результат RPDB обязан отдельно ограничивать firewall.
    pub fn new_throw(
        destination: IpAddr,
        prefix_len: u8,
        table: u32,
        priority: u32,
    ) -> Result<Self, TunError> {
        if prefix_len == 0 {
            return Err(TunError::Invalid);
        }
        let mut route = Self::new(destination, prefix_len, table, priority)?;
        route.kind = RTN_THROW;
        Ok(route)
    }
    pub(super) fn kind(self) -> u8 {
        self.kind
    }
    pub(super) fn is_throw(self) -> bool {
        self.kind == RTN_THROW
    }
    pub(super) fn scope(self) -> u8 {
        if self.destination.is_ipv4() && !self.is_throw() {
            253
        } else {
            0
        }
    }
    pub fn destination(self) -> IpAddr {
        self.destination
    }
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
    pub fn table(self) -> u32 {
        self.table
    }
    pub fn priority(self) -> u32 {
        self.priority
    }

    fn resource(self, tun_id: u64, ifindex: u32) -> Resource {
        if self.is_throw() {
            Resource::ThrowRoute {
                tun_id,
                ifindex,
                table: self.table,
                destination: self.destination,
                prefix_len: self.prefix_len,
                priority: self.priority,
            }
        } else {
            Resource::Route {
                table: self.table,
                destination: self.destination,
                prefix_len: self.prefix_len,
                priority: self.priority,
                protocol: ROUTE_PROTOCOL,
                ifindex,
            }
        }
    }
}

pub(super) fn recorded_route(resource: &Resource, tun_id: u64, index: u32) -> Option<TunRoute> {
    match *resource {
        Resource::Route {
            table,
            destination,
            prefix_len,
            priority,
            protocol: ROUTE_PROTOCOL,
            ifindex,
        } if ifindex == index => TunRoute::new(destination, prefix_len, table, priority).ok(),
        Resource::ThrowRoute {
            tun_id: parent,
            ifindex,
            table,
            destination,
            prefix_len,
            priority,
        } if parent == tun_id && ifindex == index => {
            TunRoute::new_throw(destination, prefix_len, table, priority).ok()
        }
        _ => None,
    }
}
pub(super) fn ownership(executor: &TunExecutor, journal: &Journal) -> Result<(), TunError> {
    if journal.ownership() != executor.owner {
        return Err(JournalError::WrongOwnership.into());
    }
    Ok(())
}
pub(super) fn parent_index(
    executor: &TunExecutor,
    journal: &Journal,
    tun_id: u64,
    topology: &LinuxTopology,
    adding: bool,
) -> Result<Option<u32>, TunError> {
    ownership(executor, journal)?;
    let record = journal
        .records()
        .iter()
        .find(|r| r.id() == tun_id)
        .ok_or(JournalError::Missing)?;
    let Resource::Tun { name_id } = record.resource() else {
        return Err(TunError::Invalid);
    };
    if record.scope() != Scope::Session || adding && record.state() == RecordState::CleanupRemaining
    {
        return Err(JournalError::Conflict.into());
    }
    observed(&topology.links, *name_id, &alias(executor.owner, tun_id)?)
}
pub(super) fn record_state(journal: &Journal, id: u64) -> Result<RecordState, TunError> {
    journal
        .records()
        .iter()
        .find(|r| r.id() == id)
        .map(|r| r.state())
        .ok_or(JournalError::Missing.into())
}
pub(super) fn address_matches(value: &LinuxAddress, index: u32, expected: TunAddress) -> bool {
    value.index == index
        && value.family == if expected.address.is_ipv4() { 2 } else { 10 }
        && value.address == expected.address
        && value.local.is_none_or(|ip| ip == expected.address)
        && value.prefix_len == expected.prefix_len
        && value.scope == 0
        && value.flags
            == if expected.address.is_ipv4() {
                0x280
            } else {
                0x282
            }
        && value.unknown.iter().all(|a| match a.kind {
            // Kernel lifetime timestamps не изменяют selectors адреса.
            6 => a.value.len() == 16 && a.value[..8] == [255; 8],
            // Label отсутствует в запросе: kernel возвращает имя интерфейса.
            3 => a.value.last() == Some(&0) && !a.value[..a.value.len() - 1].contains(&0),
            _ => false,
        })
}
fn observe_address(
    topology: &LinuxTopology,
    index: u32,
    expected: TunAddress,
) -> Result<bool, TunError> {
    let mut candidates = topology.addresses.iter().filter(|a| {
        a.index == index && (a.address == expected.address || a.local == Some(expected.address))
    });
    let Some(found) = candidates.next() else {
        return Ok(false);
    };
    if candidates.next().is_some() || !address_matches(found, index, expected) {
        return Err(TunError::Foreign);
    }
    if found.unknown.iter().any(|a| {
        a.kind == 3
            && topology
                .links
                .iter()
                .find(|l| l.index == index)
                .is_none_or(|l| a.value.strip_suffix(&[0]) != Some(l.name.as_slice()))
    }) {
        return Err(TunError::Foreign);
    }
    Ok(true)
}
pub(super) fn loopback_ifindex(topology: &LinuxTopology) -> Option<u32> {
    let mut indices = topology.links.iter().filter(|link| link.flags & 8 != 0);
    let first = indices.next()?.index;
    indices.next().is_none().then_some(first)
}

pub(super) fn route_matches(
    value: &LinuxRoute,
    index: u32,
    loopback: Option<u32>,
    expected: TunRoute,
) -> bool {
    let output_matches = if expected.is_throw() {
        if expected.destination.is_ipv4() {
            value.output_interface.is_none()
        } else {
            // Ядро привязывает IPv6 reject nexthop к loopback.
            loopback.is_some() && value.output_interface == loopback
        }
    } else {
        value.output_interface == Some(index)
    };
    let allowed_flags = if expected.is_throw() { 0 } else { 16 };
    value.family
        == if expected.destination.is_ipv4() {
            2
        } else {
            10
        }
        && value.destination.address == expected.destination
        && value.destination.length == expected.prefix_len
        && value.source.length == 0
        && value.source.address.is_unspecified()
        && value.table == expected.table
        && value.priority == Some(expected.priority)
        && value.protocol == ROUTE_PROTOCOL
        && output_matches
        && value.gateway.is_none()
        && value.preferred_source.is_none()
        && value.input_interface.is_none()
        && value.kind == expected.kind()
        && value.scope == expected.scope()
        && value.tos == 0
        // LINKDOWN выставляется kernel до открытия очереди engine и снимается
        // при attach; это состояние carrier, а не дополнительный selector.
        && value.flags & !allowed_flags == 0
        && value.multipath.is_empty()
        && value.nexthop_id.is_none()
        && value.unknown.iter().all(|a| match a.kind {
            20 => value.family == 10 && a.value == [0], // IPv6 preference medium.
            12 => a.value.len() == 32 && a.value[8..16] == [0; 8], // no expiration/error.
            _ => false,
        })
}
fn observe_route(
    topology: &LinuxTopology,
    index: u32,
    expected: TunRoute,
) -> Result<bool, TunError> {
    let mut candidates = topology.routes.iter().filter(|r| {
        r.table == expected.table
            && r.destination.address == expected.destination
            && r.destination.length == expected.prefix_len
    });
    let Some(found) = candidates.next() else {
        return Ok(false);
    };
    if candidates.next().is_some()
        || !route_matches(found, index, loopback_ifindex(topology), expected)
    {
        return Err(TunError::Foreign);
    }
    Ok(true)
}
fn check_route_rules(
    topology: &LinuxTopology,
    journal: &Journal,
    index: u32,
    expected: TunRoute,
) -> Result<(), TunError> {
    if expected.is_throw()
        && topology
            .rules
            .iter()
            .any(|rule| rule.table == expected.table)
    {
        return Err(TunError::Foreign);
    }
    super::rule::check_references(topology, journal, index, expected.table, None)
}

fn check_route_table(
    topology: &LinuxTopology,
    journal: &Journal,
    tun_id: u64,
    index: u32,
    expected: TunRoute,
) -> Result<(), TunError> {
    check_route_rules(topology, journal, index, expected)?;
    let mut known = BTreeMap::new();
    for record in journal.records().iter().filter(|record| {
        record.scope() == Scope::Session && record.state() == RecordState::Confirmed
    }) {
        if let Some(route) = recorded_route(record.resource(), tun_id, index)
            .filter(|route| route.table == expected.table)
        {
            let key = (route.destination, route.prefix_len, route.priority);
            if known.insert(key, route).is_some() {
                return Err(TunError::Foreign);
            }
        }
    }
    let loopback = loopback_ifindex(topology);
    let mut has_anchor = !expected.is_throw();
    for route in topology
        .routes
        .iter()
        .filter(|route| route.table == expected.table)
    {
        if route.destination.address == expected.destination
            && route.destination.length == expected.prefix_len
        {
            continue;
        }
        let key = (
            route.destination.address,
            route.destination.length,
            route.priority.unwrap_or(0),
        );
        if known
            .get(&key)
            .is_none_or(|expected| !route_matches(route, index, loopback, *expected))
        {
            return Err(TunError::Foreign);
        }
        has_anchor |= route.kind == RTN_UNICAST
            && route.destination.length == 0
            && route.destination.address.is_ipv4() == expected.destination.is_ipv4();
    }
    if has_anchor {
        Ok(())
    } else {
        Err(TunError::Evidence)
    }
}

fn kernel_link_local(address: &LinuxAddress, index: u32) -> bool {
    let IpAddr::V6(ip) = address.address else {
        return false;
    };
    address.family==10 && address.index==index && address.prefix_len==64
        && ip.octets()[..8]==[0xfe,0x80,0,0,0,0,0,0] && address.scope==253
        && address.local.is_none_or(|local|local==address.address)
        // PERMANENT с возможными kernel DAD/stable-privacy флагами.
        && address.flags&0x80!=0 && address.flags&!0x8ca==0
        && address.unknown.iter().any(|a|a.kind==11 && a.value==[3])
        && address.unknown.iter().all(|a|match a.kind {
            11=>a.value==[3], // IFAPROT_KERNEL_LL, не произвольный proto=kernel.
            6=>a.value.len()==16 && a.value[..8]==[255;8],
            _=>false,
        })
}
fn kernel_link_route(
    route: &LinuxRoute,
    index: u32,
    link_local: &BTreeSet<IpAddr>,
    multicast: bool,
) -> bool {
    if route.family != 10
        || route.output_interface != Some(index)
        || route.input_interface.is_some()
        || route.source.length != 0
        || !route.source.address.is_unspecified()
        || route.gateway.is_some()
        || route.preferred_source.is_some()
        || route.protocol != 2
        || route.scope != 0
        || route.tos != 0
        || route.flags & !16 != 0
        || !route.multipath.is_empty()
        || route.nexthop_id.is_some()
        || !route.unknown.iter().all(|a| match a.kind {
            20 => a.value == [0],
            12 => a.value.len() == 32 && a.value[8..16] == [0; 8],
            _ => false,
        })
    {
        return false;
    }
    match (
        route.table,
        route.kind,
        route.destination.length,
        route.priority,
    ) {
        (254, 1, 64, Some(256)) => {
            !link_local.is_empty()
                && route.destination.address
                    == IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0))
        }
        (255, 2, 128, Some(0)) => link_local.contains(&route.destination.address),
        (255, 5, 8, Some(256)) => {
            multicast
                && route.destination.address
                    == IpAddr::V6(std::net::Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0))
        }
        _ => false,
    }
}
pub(super) fn check_tun_teardown(topology: &LinuxTopology, index: u32) -> Result<(), TunError> {
    let link = topology
        .links
        .iter()
        .find(|link| link.index == index)
        .ok_or(TunError::Evidence)?;
    let mut link_local = BTreeSet::new();
    for address in topology
        .addresses
        .iter()
        .filter(|address| address.index == index)
    {
        if !kernel_link_local(address, index) {
            return Err(TunError::Foreign);
        }
        link_local.insert(address.address);
    }
    // Явные nexthop objects не создаются этим executor. Удаление link не должно
    // инвалидировать чужой объект или использующие его multipath routes.
    if topology
        .nexthops
        .iter()
        .any(|next| next.output_interface == Some(index))
    {
        return Err(TunError::Foreign);
    }
    for route in topology.routes.iter().filter(|route| {
        route.output_interface == Some(index)
            || route.input_interface == Some(index)
            || route
                .multipath
                .iter()
                .any(|next| next.output_interface == index)
    }) {
        if !kernel_link_route(route, index, &link_local, link.flags & 0x1000 != 0) {
            return Err(TunError::Foreign);
        }
    }
    if topology.rules.iter().any(|rule| {
        rule.input_interface.as_deref() == Some(link.name.as_slice())
            || rule.output_interface.as_deref() == Some(link.name.as_slice())
    }) {
        return Err(TunError::Foreign);
    }
    Ok(())
}
impl TunExecutor {
    pub(super) async fn configuration_snapshot(&self) -> Result<LinuxTopology, TunError> {
        self.check_namespace()?;
        let (_keep, mut cancel) = Cancellation::new();
        let deadline = tokio::time::Instant::now() + DEADLINE;
        for attempt in 0..3 {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(TunError::Timeout);
            }
            match crate::read_topology(&mut cancel, remaining).await {
                Ok(value) => {
                    if (value.namespace.device, value.namespace.inode) != self.owner.namespace() {
                        return Err(TunError::Namespace);
                    }
                    return Ok(value);
                }
                // LL/DAD после UP может изменить dump. Повторяем только чтение,
                // не NEW/DEL и не истёкший ACK; общий deadline не продлевается.
                Err(crate::NetworkReadError::Changed | crate::NetworkReadError::Interrupted)
                    if attempt < 2 =>
                {
                    tokio::task::yield_now().await
                }
                Err(error) => {
                    #[cfg(test)]
                    eprintln!("Снимок TUN: {error:?}");
                    return Err(if error == crate::NetworkReadError::Timeout {
                        TunError::Timeout
                    } else {
                        TunError::Evidence
                    });
                }
            }
        }
        Err(TunError::Evidence)
    }
    /// Меняет только полностью принадлежащий TUN. Его durable record учитывает
    /// интерфейс целиком; teardown удаляет его после всех дочерних ресурсов.
    pub async fn configure_link(
        &mut self,
        journal: &mut Journal,
        tun_id: u64,
        mtu: u32,
    ) -> Result<u32, TunError> {
        if !(1280..=9000).contains(&mtu) {
            return Err(TunError::Invalid);
        }
        let operation = lease().await?;
        let index = parent_index(
            self,
            journal,
            tun_id,
            &self.configuration_snapshot().await?,
            true,
        )?
        .ok_or(TunError::Evidence)?;
        journal.require_reconciliation(self.owner, tun_id)?;
        write::run(write::Action::SetLink { index, mtu }, operation).await?;
        let topology = self.configuration_snapshot().await?;
        if parent_index(self, journal, tun_id, &topology, true)? != Some(index)
            || !topology.links.iter().any(|l| {
                l.index == index
                    && l.mtu == Some(mtu)
                    && l.flags & 1 != 0
                    && super::topology::addrgen_none(l)
            })
        {
            return Err(TunError::Evidence);
        }
        journal.reconcile(self.owner, tun_id, Reconciled::Owned)?;
        Ok(index)
    }
    pub async fn ensure_address(
        &mut self,
        journal: &mut Journal,
        tun_id: u64,
        id: u64,
        address: TunAddress,
    ) -> Result<(), TunError> {
        let operation = lease().await?;
        let index = parent_index(
            self,
            journal,
            tun_id,
            &self.configuration_snapshot().await?,
            true,
        )?
        .ok_or(TunError::Evidence)?;
        let fresh = journal.intent(
            self.owner,
            Scope::Session,
            id,
            Resource::Address {
                tun_id,
                ifindex: index,
                address: address.address,
                prefix_len: address.prefix_len,
            },
        )?;
        let state = record_state(journal, id)?;
        journal.require_reconciliation(self.owner, id)?;
        let topology = self.configuration_snapshot().await?;
        if parent_index(self, journal, tun_id, &topology, true)? != Some(index) {
            return Err(TunError::Evidence);
        }
        if topology.addresses.iter().any(|a| {
            a.index != index && (a.address == address.address || a.local == Some(address.address))
        }) {
            return Err(TunError::Foreign);
        }
        if observe_address(&topology, index, address)? {
            if fresh || state != RecordState::Confirmed {
                return Err(TunError::Evidence);
            }
        } else {
            if !fresh {
                return Err(TunError::Evidence);
            }
            self.check_namespace()?;
            write::run(
                write::Action::Address {
                    index,
                    address,
                    add: true,
                },
                Arc::clone(&operation),
            )
            .await?;
            let topology = self.configuration_snapshot().await?;
            if parent_index(self, journal, tun_id, &topology, true)? != Some(index)
                || !observe_address(&topology, index, address)?
            {
                return Err(TunError::Evidence);
            }
        }
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        Ok(())
    }
    pub async fn remove_address(
        &mut self,
        journal: &mut Journal,
        tun_id: u64,
        id: u64,
    ) -> Result<(), TunError> {
        let operation = lease().await?;
        ownership(self, journal)?;
        let record = journal
            .records()
            .iter()
            .find(|r| r.id() == id)
            .ok_or(JournalError::Missing)?;
        let Resource::Address {
            tun_id: parent,
            ifindex,
            address,
            prefix_len,
        } = record.resource()
        else {
            return Err(TunError::Invalid);
        };
        if record.scope() != Scope::Session || *parent != tun_id {
            return Err(TunError::Invalid);
        }
        let (index, address, state) = (
            *ifindex,
            TunAddress::new(*address, *prefix_len)?,
            record.state(),
        );
        journal.require_reconciliation(self.owner, id)?;
        let topology = self.configuration_snapshot().await?;
        if !observe_address(&topology, index, address)? {
            journal.reconcile(self.owner, id, Reconciled::Absent)?;
            return Ok(());
        }
        if state == RecordState::Intent
            || parent_index(self, journal, tun_id, &topology, false)? != Some(index)
        {
            return Err(TunError::Evidence);
        }
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        journal.mark_cleanup(self.owner, id)?;
        self.check_namespace()?;
        write::run(
            write::Action::Address {
                index,
                address,
                add: false,
            },
            operation,
        )
        .await?;
        let topology = self.configuration_snapshot().await?;
        if observe_address(&topology, index, address)? {
            return Err(TunError::Evidence);
        }
        journal.reconcile(self.owner, id, Reconciled::Absent)?;
        Ok(())
    }
    pub async fn ensure_route(
        &mut self,
        journal: &mut Journal,
        tun_id: u64,
        id: u64,
        route: TunRoute,
    ) -> Result<(), TunError> {
        let operation = lease().await?;
        let before = self.configuration_snapshot().await?;
        let index =
            parent_index(self, journal, tun_id, &before, true)?.ok_or(TunError::Evidence)?;
        if route.is_throw() {
            check_route_table(&before, journal, tun_id, index, route)?;
            if !journal.records().iter().any(|record| record.id() == id)
                && observe_route(&before, index, route)?
            {
                return Err(TunError::Foreign);
            }
        } else {
            check_route_rules(&before, journal, index, route)?;
        }
        let fresh = journal.intent(
            self.owner,
            Scope::Session,
            id,
            route.resource(tun_id, index),
        )?;
        let state = record_state(journal, id)?;
        journal.require_reconciliation(self.owner, id)?;
        let topology = self.configuration_snapshot().await?;
        if parent_index(self, journal, tun_id, &topology, true)? != Some(index) {
            return Err(TunError::Evidence);
        }
        check_route_table(&topology, journal, tun_id, index, route)?;
        if observe_route(&topology, index, route)? {
            if fresh || state != RecordState::Confirmed {
                return Err(TunError::Evidence);
            }
        } else {
            if !fresh {
                return Err(TunError::Evidence);
            }
            self.check_namespace()?;
            write::run(
                write::Action::Route {
                    index,
                    route,
                    add: true,
                },
                Arc::clone(&operation),
            )
            .await?;
            let topology = self.configuration_snapshot().await?;
            if parent_index(self, journal, tun_id, &topology, true)? != Some(index)
                || !observe_route(&topology, index, route)?
            {
                return Err(TunError::Evidence);
            }
            if route.is_throw() {
                check_route_table(&topology, journal, tun_id, index, route)?;
            }
        }
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        Ok(())
    }
    pub async fn remove_route(
        &mut self,
        journal: &mut Journal,
        tun_id: u64,
        id: u64,
    ) -> Result<(), TunError> {
        let operation = lease().await?;
        ownership(self, journal)?;
        let record = journal
            .records()
            .iter()
            .find(|r| r.id() == id)
            .ok_or(JournalError::Missing)?;
        let index = match *record.resource() {
            Resource::Route { ifindex, .. } | Resource::ThrowRoute { ifindex, .. } => ifindex,
            _ => return Err(TunError::Invalid),
        };
        if record.scope() != Scope::Session {
            return Err(TunError::Invalid);
        }
        let route = recorded_route(record.resource(), tun_id, index).ok_or(TunError::Invalid)?;
        let state = record.state();
        // Удаление даже не-default маршрута не должно менять путь действующей RPDB.
        if journal.records().iter().any(|other| {
            matches!(other.resource(), Resource::TunRule { table, .. } if *table == route.table)
                || record.resource().anchors_throw_route(other.resource())
        }) {
            return Err(JournalError::Conflict.into());
        }
        journal.require_reconciliation(self.owner, id)?;
        let topology = self.configuration_snapshot().await?;
        check_route_rules(&topology, journal, index, route)?;
        if !observe_route(&topology, index, route)? {
            journal.reconcile(self.owner, id, Reconciled::Absent)?;
            return Ok(());
        }
        if state == RecordState::Intent
            || parent_index(self, journal, tun_id, &topology, false)? != Some(index)
        {
            return Err(TunError::Evidence);
        }
        if route.is_throw() {
            check_route_table(&topology, journal, tun_id, index, route)?;
        }
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        journal.mark_cleanup(self.owner, id)?;
        self.check_namespace()?;
        write::run(
            write::Action::Route {
                index,
                route,
                add: false,
            },
            operation,
        )
        .await?;
        if observe_route(&self.configuration_snapshot().await?, index, route)? {
            return Err(TunError::Evidence);
        }
        journal.reconcile(self.owner, id, Reconciled::Absent)?;
        Ok(())
    }
}

impl std::fmt::Debug for TunAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TunAddress(<скрыто>)")
    }
}
impl std::fmt::Debug for TunRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TunRoute(<скрыто>)")
    }
}
