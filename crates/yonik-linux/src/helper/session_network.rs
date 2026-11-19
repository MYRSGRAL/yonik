//! Неизменяемый сетевой план системной сессии. Авторизацию и порядок worker/nft
//! обеспечивает session host; этот модуль не публикует Applied/Connected.
#[cfg(test)]
#[path = "external_diagnostics.rs"]
pub(in crate::helper) mod diagnostics;
use crate::{
    LinuxTopology,
    managed_network::{
        Journal, Ownership, RecordState, Resource, Scope,
        firewall::PublicBlockPolicy,
        tun::{
            ResolverRouteRule, TunAddress, TunError, TunExecutor, TunRoute, TunRule,
            session_external_topology_with_framing,
        },
    },
};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use yonik_engine::{SystemTun, SystemTunAddress};

const MTU: u16 = 1500;
// ID 1 занят действующей public-protection policy; session использует своё окно.
const TUN: u64 = 16;
const ADDRESSES: u64 = TUN + 1;
const ROUTES: u64 = TUN + 3;
const RULES: u64 = TUN + 5;
pub(super) const FIRST_THROW_ROUTE: u64 = RULES + 2;
const MAX_THROW_ROUTES: usize = 64;
pub(super) const LAST_THROW_ROUTE: u64 = FIRST_THROW_ROUTE + MAX_THROW_ROUTES as u64 - 1;
pub(super) const FIRST_RESOLVER_RULE: u64 = LAST_THROW_ROUTE + 1;
const MAX_RESOLVER_RULES: usize = 16;
pub(super) const LAST_RESOLVER_RULE: u64 = FIRST_RESOLVER_RULE + MAX_RESOLVER_RULES as u64 - 1;
const ALLOCATION_ATTEMPTS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ExternalTopologyCheck {
    Verified,
    RetryDhcpLifetimes,
}

/// Числа ресурсов выбираются helper, а не десериализуются из запроса UI.
/// Существование плана не доказывает готовность транспорта или DNS.
pub struct SessionNetworkPlan {
    owner: Ownership,
    vnet_hdr: bool,
    name: u32,
    table: u32,
    priority: u32,
    mark: u32,
    addresses: [TunAddress; 2],
    throw_routes: Vec<TunRoute>,
    resolver_rules: Vec<ResolverRouteRule>,
}
impl fmt::Debug for SessionNetworkPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionNetworkPlan(<скрыто>)")
    }
}
impl SessionNetworkPlan {
    pub fn reserve(owner: Ownership, baseline: &LinuxTopology) -> Result<Self, TunError> {
        if owner.namespace() != (baseline.namespace.device, baseline.namespace.inode) {
            return Err(TunError::Namespace);
        }
        for _ in 0..ALLOCATION_ATTEMPTS {
            let mut random = [0; 24];
            getrandom::getrandom(&mut random).map_err(|_| TunError::Io)?;
            let plan = Self::candidate(owner, random)?;
            if plan.available(baseline) {
                return Ok(plan);
            }
        }
        Err(TunError::Foreign)
    }
    pub(crate) fn reserve_for_engine(
        owner: Ownership,
        baseline: &LinuxTopology,
        engine: yonik_engine::Engine,
    ) -> Result<Self, TunError> {
        let mut plan = Self::reserve(owner, baseline)?;
        plan.vnet_hdr = match engine {
            yonik_engine::Engine::Xray => true,
            yonik_engine::Engine::SingBox => false,
        };
        Ok(plan)
    }
    pub(crate) fn reserve_for_fake_dns(
        owner: Ownership,
        baseline: &LinuxTopology,
        engine: yonik_engine::Engine,
        pools: &[(IpAddr, u8)],
    ) -> Result<Self, TunError> {
        if pools.iter().any(|&(network, length)| {
            baseline
                .addresses
                .iter()
                .any(|address| overlaps(network, length, address.address, address.prefix_len))
                || baseline.routes.iter().any(|route| {
                    route.destination.length != 0
                        && overlaps(
                            network,
                            length,
                            route.destination.address,
                            route.destination.length,
                        )
                })
        }) {
            return Err(TunError::Foreign);
        }
        for _ in 0..ALLOCATION_ATTEMPTS {
            let plan = Self::reserve_for_engine(owner, baseline, engine)?;
            if plan.addresses.iter().all(|address| {
                pools.iter().all(|&(network, length)| {
                    !overlaps(address.address(), address.prefix_len(), network, length)
                })
            }) {
                return Ok(plan);
            }
        }
        Err(TunError::Foreign)
    }
    /// Служебный адрес назначения внутри IPv4 /30, где TUN получает .1.
    pub(crate) fn fake_dns_marker(&self) -> Result<IpAddr, TunError> {
        match self.addresses[0].address() {
            IpAddr::V4(address) => {
                let [a, b, c, 1] = address.octets() else {
                    return Err(TunError::Invalid);
                };
                Ok(Ipv4Addr::new(a, b, c, 2).into())
            }
            _ => Err(TunError::Invalid),
        }
    }
    pub(crate) fn quarantine_tun(&self, ifindex: u32) -> crate::managed_network::QuarantineTun {
        crate::managed_network::QuarantineTun {
            ifindex,
            name_id: self.name,
        }
    }
    fn candidate(owner: Ownership, random: [u8; 24]) -> Result<Self, TunError> {
        let number = |offset| {
            u32::from_le_bytes([
                random[offset],
                random[offset + 1],
                random[offset + 2],
                random[offset + 3],
            ])
        };
        Ok(Self {
            owner,
            vnet_hdr: false,
            name: number(0).max(1),
            table: 10000 + number(4) % 20000,
            priority: 10000 + number(8) % 10000,
            mark: 0x5900_0000 | (number(12) & 0x00ff_ffff),
            addresses: [
                TunAddress::new(
                    IpAddr::V4(Ipv4Addr::new(198, 18 + (random[16] & 1), random[17], 1)),
                    30,
                )?,
                TunAddress::new(
                    IpAddr::V6(Ipv6Addr::new(
                        0xfd79,
                        0x6f6e,
                        u16::from_le_bytes([random[18], random[19]]),
                        u16::from_le_bytes([random[20], random[21]]),
                        0,
                        0,
                        0,
                        1,
                    )),
                    126,
                )?,
            ],
            throw_routes: Vec::new(),
            resolver_rules: Vec::new(),
        })
    }
    fn available(&self, topology: &LinuxTopology) -> bool {
        let name = format!("tofu{:08x}", self.name);
        !topology
            .links
            .iter()
            .any(|link| link.name == name.as_bytes())
            && !topology
                .routes
                .iter()
                .any(|route| route.table == self.table)
            && !topology.rules.iter().any(|rule| {
                rule.table == self.table
                    || rule.priority == Some(self.priority)
                    || rule.fwmark.is_some_and(|mark| {
                        mark & rule.fwmask.unwrap_or(u32::MAX)
                            == self.mark & rule.fwmask.unwrap_or(u32::MAX)
                    })
            })
            && !self.addresses.iter().any(|planned| {
                topology.addresses.iter().any(|address| {
                    overlaps(
                        planned.address(),
                        planned.prefix_len(),
                        address.address,
                        address.prefix_len,
                    )
                }) || topology.routes.iter().any(|route| {
                    route.destination.length != 0
                        && overlaps(
                            planned.address(),
                            planned.prefix_len(),
                            route.destination.address,
                            route.destination.length,
                        )
                })
            })
    }
    pub fn compiler_tun(&self) -> Result<SystemTun, TunError> {
        let addresses = self
            .addresses
            .iter()
            .map(|address| {
                SystemTunAddress::new(address.address(), address.prefix_len())
                    .map_err(|_| TunError::Invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        SystemTun::new(self.name, MTU, self.mark, addresses).map_err(|_| TunError::Invalid)
    }
    pub fn socket_mark(&self) -> u32 {
        self.mark
    }
    pub fn routing_table(&self) -> u32 {
        self.table
    }
    /// Вызывающий заранее проверяет внешние префиксы и защиту следующего
    /// маршрута RPDB. Дескрипторы относятся только к таблице этого плана.
    pub fn with_throw_routes(mut self, prefixes: &[(IpAddr, u8)]) -> Result<Self, TunError> {
        if prefixes.len() > MAX_THROW_ROUTES {
            return Err(TunError::Invalid);
        }
        let mut prefixes = prefixes.to_vec();
        prefixes.sort_unstable();
        prefixes.dedup();
        self.throw_routes = prefixes
            .into_iter()
            .map(|(address, length)| {
                let route = TunRoute::new_throw(address, length, self.table, 100)?;
                if self
                    .addresses
                    .iter()
                    .any(|own| overlaps(own.address(), own.prefix_len(), address, length))
                {
                    return Err(TunError::Invalid);
                }
                Ok(route)
            })
            .collect::<Result<_, _>>()?;
        Ok(self)
    }

    /// Вызывающий подтверждает физический маршрут, UID резолвера и защиту nft
    /// для каждого TCP-сокета перед вызовом capture.
    pub fn with_resolver_routes(
        mut self,
        baseline: &LinuxTopology,
        uid: u32,
        routes: &[(SocketAddr, u32)],
    ) -> Result<Self, TunError> {
        if self.owner.namespace() != (baseline.namespace.device, baseline.namespace.inode) {
            return Err(TunError::Namespace);
        }
        if routes.len() > MAX_RESOLVER_RULES || routes.iter().any(|(_, table)| *table == self.table)
        {
            return Err(TunError::Invalid);
        }
        let mut routes = routes.to_vec();
        routes.sort_unstable();
        routes.dedup();
        if routes.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(TunError::Foreign);
        }
        let previous = baseline
            .rules
            .iter()
            .filter_map(|rule| rule.priority)
            .filter(|&priority| priority < self.priority)
            .max()
            .unwrap_or(0);
        if routes.len() as u32 >= self.priority - previous {
            return Err(TunError::Foreign);
        }
        self.resolver_rules = routes
            .into_iter()
            .enumerate()
            .map(|(offset, (endpoint, table))| {
                ResolverRouteRule::new(self.priority - 1 - offset as u32, table, uid, endpoint)
            })
            .collect::<Result<_, _>>()?;
        Ok(self)
    }

    fn planned_resolver_rules(&self) -> impl Iterator<Item = (u64, ResolverRouteRule)> + '_ {
        self.resolver_rules
            .iter()
            .copied()
            .enumerate()
            .map(|(offset, rule)| (FIRST_RESOLVER_RULE + offset as u64, rule))
    }

    fn configured_count(&self) -> usize {
        5 + self.throw_routes.len()
    }
    fn captured_count(&self) -> usize {
        self.configured_count() + 2 + self.resolver_rules.len()
    }
    fn routes(&self) -> Result<[TunRoute; 2], TunError> {
        Ok([
            TunRoute::new(Ipv4Addr::UNSPECIFIED.into(), 0, self.table, 100)?,
            TunRoute::new(Ipv6Addr::UNSPECIFIED.into(), 0, self.table, 100)?,
        ])
    }
    fn rules(&self) -> Result<[TunRule; 2], TunError> {
        Ok([
            TunRule::new(self.priority, self.table, self.mark, false)?,
            TunRule::new(self.priority, self.table, self.mark, true)?,
        ])
    }
    fn resources(&self, index: u32) -> Vec<(u64, Resource)> {
        let mut resources = vec![(TUN, Resource::Tun { name_id: self.name })];
        for (offset, address) in self.addresses.iter().enumerate() {
            resources.push((
                ADDRESSES + offset as u64,
                Resource::Address {
                    tun_id: TUN,
                    ifindex: index,
                    address: address.address(),
                    prefix_len: address.prefix_len(),
                },
            ));
        }
        for (offset, destination) in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ]
        .into_iter()
        .enumerate()
        {
            resources.push((
                ROUTES + offset as u64,
                Resource::Route {
                    table: self.table,
                    destination,
                    prefix_len: 0,
                    protocol: 253,
                    priority: 100,
                    ifindex: index,
                },
            ));
            resources.push((
                RULES + offset as u64,
                Resource::TunRule {
                    tun_id: TUN,
                    ifindex: index,
                    priority: self.priority,
                    table: self.table,
                    mark: self.mark,
                    ipv6: offset == 1,
                },
            ));
        }
        for (offset, route) in self.throw_routes.iter().enumerate() {
            resources.push((
                FIRST_THROW_ROUTE + offset as u64,
                Resource::ThrowRoute {
                    tun_id: TUN,
                    ifindex: index,
                    table: route.table(),
                    destination: route.destination(),
                    prefix_len: route.prefix_len(),
                    priority: route.priority(),
                },
            ));
        }
        resources.extend(
            self.planned_resolver_rules()
                .map(|(id, rule)| (id, rule.expected_resource(self.owner, id, TUN, index))),
        );
        resources
    }
    fn check_records(
        &self,
        journal: &Journal,
        index: u32,
        expected_count: Option<usize>,
    ) -> Result<(), TunError> {
        if journal.ownership() != self.owner {
            return Err(TunError::Foreign);
        }
        let expected = self.resources(index);
        if journal.records().iter().any(|record| {
            record.scope() == Scope::PublicBlock
                && expected.iter().any(|(id, _)| *id == record.id())
        }) {
            return Err(TunError::Foreign);
        }
        let mut count = 0;
        for record in journal
            .records()
            .iter()
            .filter(|record| record.scope() == Scope::Session)
        {
            count += 1;
            if !expected
                .iter()
                .any(|(id, resource)| *id == record.id() && resource == record.resource())
                || expected_count.is_some()
                    && (record.state() != RecordState::Confirmed
                        || journal.needs_reconciliation(record.id()))
            {
                return Err(TunError::Foreign);
            }
        }
        if expected_count.is_some_and(|expected| count != expected) {
            return Err(TunError::Evidence);
        }
        Ok(())
    }
    /// Только адреса/таблицы, без захвата трафика. При ошибке host обязан перейти
    /// в recovery: частичный durable journal сохраняется для явного cleanup.
    pub async fn configure(
        &self,
        executor: &mut TunExecutor,
        journal: &mut Journal,
    ) -> Result<u32, TunError> {
        self.check_records(journal, 0, Some(0))?;
        let index = executor
            .ensure_tun_with_framing(journal, TUN, self.name, self.vnet_hdr)
            .await?;
        executor
            .configure_link(journal, TUN, u32::from(MTU))
            .await?;
        for (offset, address) in self.addresses.iter().enumerate() {
            executor
                .ensure_address(journal, TUN, ADDRESSES + offset as u64, *address)
                .await?;
        }
        for (offset, route) in self.routes()?.into_iter().enumerate() {
            executor
                .ensure_route(journal, TUN, ROUTES + offset as u64, route)
                .await?;
        }
        for (offset, &route) in self.throw_routes.iter().enumerate() {
            executor
                .ensure_route(journal, TUN, FIRST_THROW_ROUTE + offset as u64, route)
                .await?;
        }
        self.check_records(journal, index, Some(self.configured_count()))?;
        Ok(index)
    }
    /// Вызывать после подготовки защиты и проверки transport escape. Успех этого
    /// метода сам по себе не означает readiness ядра или соединения.
    pub async fn capture(
        &self,
        executor: &mut TunExecutor,
        journal: &mut Journal,
        index: u32,
    ) -> Result<(), TunError> {
        self.check_records(journal, index, Some(self.configured_count()))?;
        for (id, rule) in self.planned_resolver_rules() {
            executor
                .ensure_resolver_rule(journal, TUN, id, rule)
                .await?;
        }
        for (offset, rule) in self.rules()?.into_iter().enumerate() {
            executor
                .ensure_rule(journal, TUN, RULES + offset as u64, rule)
                .await?;
        }
        self.check_records(journal, index, Some(self.captured_count()))
    }
    /// Проверяет только внешнюю топологию. Per-link devconf/token своего TUN
    /// требуют отдельного binding; этот результат нельзя публиковать как Applied.
    pub fn verify_external(
        &self,
        baseline: &LinuxTopology,
        current: LinuxTopology,
        journal: &Journal,
        index: u32,
    ) -> Result<(), TunError> {
        self.check_records(journal, index, Some(self.captured_count()))?;
        let projected =
            session_external_topology_with_framing(current, journal, TUN, MTU, self.vnet_hdr)?;
        if !crate::network::same_external_topology(&projected, baseline) {
            return Err(TunError::Evidence);
        }
        Ok(())
    }
    pub(super) fn verify_external_captured(
        &self,
        baseline: (&LinuxTopology, crate::network::TopologyCapture),
        current: (LinuxTopology, crate::network::TopologyCapture),
        journal: &Journal,
        index: u32,
        dhcp: &[crate::network::RenewedDhcpAddress],
        dhcp_retry_policy: Option<&PublicBlockPolicy>,
    ) -> Result<ExternalTopologyCheck, TunError> {
        let (current, current_capture) = current;
        #[cfg(test)]
        let (baseline, baseline_capture) = baseline;
        let records = self.check_records(journal, index, Some(self.captured_count()));
        #[cfg(test)]
        let records = records.inspect_err(|&error| {
            diagnostics::failure(
                "records",
                error,
                (baseline, baseline_capture),
                (&current, current_capture),
                journal,
                None,
                (self, index),
            );
        });
        records?;
        #[cfg(test)]
        let raw = diagnostics::snapshot(&current);
        let projected =
            match session_external_topology_with_framing(current, journal, TUN, MTU, self.vnet_hdr)
            {
                Ok(value) => value,
                Err(error) => {
                    #[cfg(test)]
                    if let Some(raw) = raw.as_ref() {
                        diagnostics::failure(
                            "projection",
                            error,
                            (baseline, baseline_capture),
                            (raw, current_capture),
                            journal,
                            None,
                            (self, index),
                        );
                    }
                    #[cfg(test)]
                    if raw.is_none() {
                        diagnostics::stage("projection", error);
                    }
                    return Err(error);
                }
            };
        #[cfg(test)]
        let baseline_pair = (baseline, baseline_capture);
        #[cfg(not(test))]
        let baseline_pair = baseline;
        if !crate::network::same_session_topology(
            baseline_pair,
            (&projected, current_capture),
            dhcp,
        ) {
            if let Some(policy) = dhcp_retry_policy {
                let known = |address: &crate::LinuxAddress| {
                    let IpAddr::V4(local) = address.local.unwrap_or(address.address) else {
                        return false;
                    };
                    policy.has_dhcp_rule_for_address(address.index, local)
                };
                if crate::network::only_dhcp_lifetimes_changed(
                    baseline_pair,
                    (&projected, current_capture),
                    &known,
                ) {
                    return Ok(ExternalTopologyCheck::RetryDhcpLifetimes);
                }
            }
            #[cfg(test)]
            diagnostics::failure(
                "equivalence",
                TunError::Evidence,
                (baseline, baseline_capture),
                (&projected, current_capture),
                journal,
                raw.as_ref(),
                (self, index),
            );
            return Err(TunError::Evidence);
        }
        Ok(ExternalTopologyCheck::Verified)
    }
    pub(crate) async fn bind_queue(
        &self,
        executor: &TunExecutor,
        journal: &Journal,
        cancel: &mut crate::Cancellation,
    ) -> Result<crate::managed_network::tun::BoundTun, TunError> {
        let framing = if self.vnet_hdr {
            yonik_nsfs::tun::Framing::Vnet10
        } else {
            yonik_nsfs::tun::Framing::Plain
        };
        executor
            .bind_session_queue(journal, TUN, MTU, framing, cancel)
            .await
    }
    /// Host обязан сначала подтвердить пустую worker cgroup. Сам план не умеет
    /// подтверждать остановку процесса и не снимает публичную блокировку.
    pub async fn cleanup_after_worker(
        &self,
        executor: &mut TunExecutor,
        journal: &mut Journal,
        index: u32,
    ) -> Result<(), TunError> {
        self.check_records(journal, index, None)?;
        let throw_end = FIRST_THROW_ROUTE + self.throw_routes.len() as u64;
        let resolver_end = FIRST_RESOLVER_RULE + self.resolver_rules.len() as u64;
        let order = (FIRST_RESOLVER_RULE..resolver_end)
            .rev()
            .chain((RULES..FIRST_THROW_ROUTE).rev())
            .chain((FIRST_THROW_ROUTE..throw_end).rev())
            .chain((TUN..RULES).rev());
        for id in order {
            if !journal
                .records()
                .iter()
                .any(|record| record.scope() == Scope::Session && record.id() == id)
            {
                continue;
            }
            if id >= FIRST_RESOLVER_RULE {
                executor.remove_resolver_rule(journal, TUN, id).await?;
            } else if (RULES..FIRST_THROW_ROUTE).contains(&id) {
                executor.remove_rule(journal, TUN, id).await?;
            } else if id >= ROUTES {
                executor.remove_route(journal, TUN, id).await?;
            } else if id >= ADDRESSES {
                executor.remove_address(journal, TUN, id).await?;
            } else {
                executor.remove_tun(journal, TUN).await?;
            }
        }
        self.check_records(journal, index, Some(0))
    }
}
fn overlaps(left: IpAddr, left_len: u8, right: IpAddr, right_len: u8) -> bool {
    let length = left_len.min(right_len);
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) if length <= 32 => {
            length == 0 || (u32::from(left) >> (32 - length)) == (u32::from(right) >> (32 - length))
        }
        (IpAddr::V6(left), IpAddr::V6(right)) if length <= 128 => {
            length == 0
                || (u128::from(left) >> (128 - length)) == (u128::from(right) >> (128 - length))
        }
        _ => false,
    }
}
#[cfg(test)]
mod tests;
