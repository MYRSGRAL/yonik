use std::net::IpAddr;

use crate::{Cidr, Decision, DomainName, Policy, Route, RuleOrigin};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VpnId(std::num::NonZeroU64);
impl VpnId {
    pub fn new(value: u64) -> Option<Self> {
        std::num::NonZeroU64::new(value).map(Self)
    }
    pub fn get(self) -> u64 {
        self.0.get()
    }
}
#[derive(Debug)]
pub struct PrivateDomain {
    pub domain: crate::DomainPattern,
    pub vpn: VpnId,
    pub available: bool,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
/// Host не переиспользует epochs, пока жив хотя бы один ответ/mapping,
/// включая restart и persistent cache. engine обозначает сессию, не версию ядра.
pub struct DnsEpoch {
    pub network: u64,
    pub engine: u64,
    pub resolver: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverPath {
    Policy,
    Vpn(VpnId),
}
#[derive(Debug, Clone, Copy)]
pub struct AnswerSet<'a> {
    pub addresses: &'a [IpAddr],
    /// Все разрешённые семейства завершились ответом или NODATA, не timeout.
    pub complete: bool,
    pub expires_at: u64,
    pub epoch: DnsEpoch,
    pub path: ResolverPath,
}
#[derive(Debug, Clone, Copy)]
pub enum Resolution<'a> {
    Missing,
    Failed,
    Answer(AnswerSet<'a>),
}
#[derive(Debug, PartialEq, Eq)]
pub struct FakeMapping {
    pub address: IpAddr,
    pub name: DomainName,
    pub epoch: DnsEpoch,
    pub expires_at: u64,
}
#[derive(Debug)]
pub enum Destination<'a> {
    Ip {
        address: IpAddr,
        name: Option<&'a DomainName>,
    },
    Name {
        name: &'a DomainName,
        resolution: Resolution<'a>,
    },
    Fake {
        address: IpAddr,
        mapping: Option<&'a FakeMapping>,
        resolution: Resolution<'a>,
    },
}
#[derive(Debug)]
pub struct DestinationFlow<'a> {
    pub executable: Option<&'a str>,
    pub destination: Destination<'a>,
}
#[derive(Debug, Default)]
pub struct EvaluationContext<'a> {
    pub now: u64,
    pub epoch: DnsEpoch,
    pub fake_pools: &'a [Cidr],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFault {
    UnsupportedSelector(u64),
    TransportUnavailable(u64),
    DnsPolicyUnresolved,
    DnsPolicyAmbiguous,
    UnknownFakeMapping,
    WrongResolver,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evaluation {
    Decided {
        decision: Decision,
        vpn: Option<VpnId>,
        /// Адрес для подключения, когда путь зависит от проверенного ответа
        /// DNS или вход уже содержит буквальный IP.
        selected_address: Option<IpAddr>,
    },
    NeedResolution(ResolverPath),
    Rejected(PolicyFault),
}

fn decided(
    action: Route,
    origin: RuleOrigin,
    vpn: Option<VpnId>,
    selected_address: Option<IpAddr>,
) -> Evaluation {
    Evaluation::Decided {
        decision: Decision { action, origin },
        vpn,
        selected_address: if action == Route::Block {
            None
        } else {
            selected_address
        },
    }
}

fn lowest_address(addresses: &[IpAddr]) -> Option<IpAddr> {
    addresses.iter().map(|address| address.to_canonical()).min()
}

fn unresolved() -> Evaluation {
    Evaluation::Rejected(PolicyFault::DnsPolicyUnresolved)
}
fn ambiguous() -> Evaluation {
    Evaluation::Rejected(PolicyFault::DnsPolicyAmbiguous)
}

enum Addresses<'a> {
    Literal(&'a [IpAddr]),
    Lookup(Resolution<'a>, ResolverPath),
}
impl<'a> Addresses<'a> {
    fn get(&self, context: &EvaluationContext<'_>) -> Result<&'a [IpAddr], Evaluation> {
        match self {
            Self::Literal(addresses) => Ok(addresses),
            Self::Lookup(Resolution::Missing, path) => Err(Evaluation::NeedResolution(*path)),
            Self::Lookup(Resolution::Failed, _) => Err(unresolved()),
            Self::Lookup(Resolution::Answer(answer), path) => {
                if answer.epoch != context.epoch || answer.expires_at <= context.now {
                    return Err(Evaluation::NeedResolution(*path));
                }
                if answer.path != *path {
                    return Err(Evaluation::Rejected(PolicyFault::WrongResolver));
                }
                if !answer.complete
                    || answer.addresses.is_empty()
                    || answer.addresses.len() > 64
                    || answer.addresses.iter().any(|address| {
                        context
                            .fake_pools
                            .iter()
                            .any(|pool| pool.contains(address.to_canonical()))
                    })
                {
                    return Err(unresolved());
                }
                Ok(answer.addresses)
            }
        }
    }
}

impl Policy {
    /// Выбор пути без I/O. NeedResolution — запрос host, а не разрешение
    /// продолжить младшие правила. Ответы/время/поколения сообщает доверенный host.
    pub fn evaluate_destination(
        &self,
        flow: &DestinationFlow<'_>,
        context: &EvaluationContext<'_>,
    ) -> Evaluation {
        self.evaluate_with_resources(flow, context, &crate::resources::EmptyResources)
    }

    pub fn evaluate_with_resources(
        &self,
        flow: &DestinationFlow<'_>,
        context: &EvaluationContext<'_>,
        resources: &impl crate::ResourceConditions,
    ) -> Evaluation {
        self.evaluate_transport(
            flow,
            context,
            resources,
            crate::TransportWitness::Unavailable,
        )
    }

    pub fn evaluate_transport(
        &self,
        flow: &DestinationFlow<'_>,
        context: &EvaluationContext<'_>,
        resources: &impl crate::ResourceConditions,
        transport: crate::TransportWitness,
    ) -> Evaluation {
        if let Some(id) = self.unsupported_selector() {
            return Evaluation::Rejected(PolicyFault::UnsupportedSelector(id));
        }
        let literal;
        let (name, resolution) = match &flow.destination {
            Destination::Ip { address, name } => {
                if context
                    .fake_pools
                    .iter()
                    .any(|pool| pool.contains(address.to_canonical()))
                {
                    return Evaluation::Rejected(PolicyFault::UnknownFakeMapping);
                }
                literal = Some([address.to_canonical()]);
                (*name, Resolution::Missing)
            }
            Destination::Name { name, resolution } => {
                literal = None;
                (Some(*name), *resolution)
            }
            Destination::Fake {
                address,
                mapping,
                resolution,
            } => {
                let Some(mapping) = mapping.filter(|mapping| {
                    mapping.address.to_canonical() == address.to_canonical()
                        && mapping.epoch == context.epoch
                        && mapping.expires_at > context.now
                        && context
                            .fake_pools
                            .iter()
                            .any(|pool| pool.contains(address.to_canonical()))
                }) else {
                    return Evaluation::Rejected(PolicyFault::UnknownFakeMapping);
                };
                literal = None;
                (Some(&mapping.name), *resolution)
            }
        };
        let mut zone_owner = None;
        let mut zone_available = true;
        for zone in &self.private_domains {
            if name.is_some_and(|name| zone.domain.matches(name)) {
                if zone_owner.is_some_and(|id| id != zone.vpn) {
                    return ambiguous();
                }
                zone_owner = Some(zone.vpn);
                zone_available &= zone.available;
            }
        }
        if !zone_available {
            return decided(Route::Block, RuleOrigin::PrivateDomain, None, None);
        }
        let path = zone_owner.map_or(ResolverPath::Policy, ResolverPath::Vpn);
        let facts = match &literal {
            Some(addresses) => Addresses::Literal(addresses),
            None => Addresses::Lookup(resolution, path),
        };
        let mut checked_addresses = literal.as_ref().map(|addresses| addresses.as_slice());
        if !self.private_networks.is_empty() || zone_owner.is_some() {
            let addresses = match facts.get(context) {
                Ok(addresses) => addresses,
                Err(result) => return result,
            };
            checked_addresses = Some(addresses);
            let mut owner = None;
            let mut public = false;
            let mut available = true;
            for address in addresses {
                let mut private = false;
                for network in &self.private_networks {
                    if network.network.contains(address.to_canonical()) {
                        private = true;
                        if owner.is_some_and(|id| id != network.vpn) {
                            return ambiguous();
                        }
                        owner = Some(network.vpn);
                        available &= network.available;
                    }
                }
                public |= !private;
            }
            if owner.is_some() && public {
                return ambiguous();
            }
            if let (Some(zone), Some(network)) = (zone_owner, owner) {
                if zone != network {
                    return ambiguous();
                }
            }
            if let Some(vpn) = owner.or(zone_owner) {
                return decided(
                    if available {
                        Route::PrivateVpn
                    } else {
                        Route::Block
                    },
                    if zone_owner.is_some() {
                        RuleOrigin::PrivateDomain
                    } else {
                        RuleOrigin::PrivateNetwork
                    },
                    available.then_some(vpn),
                    lowest_address(addresses),
                );
            }
        }
        if !self.lan.is_empty() {
            let addresses = match facts.get(context) {
                Ok(addresses) => addresses,
                Err(result) => return result,
            };
            checked_addresses = Some(addresses);
            let selected = addresses
                .iter()
                .map(|address| address.to_canonical())
                .filter(|&address| self.lan.iter().any(|cidr| cidr.contains(address)))
                .min();
            if selected.is_some() {
                return decided(Route::Direct, RuleOrigin::Lan, None, selected);
            }
        }
        for (rules, origin) in [
            (&self.user_rules, RuleOrigin::User as fn(u64) -> RuleOrigin),
            (&self.preset_rules, RuleOrigin::Preset),
        ] {
            for rule in rules {
                let resource_rule = match origin(rule.id) {
                    RuleOrigin::User(id) => crate::ResourceRule::User(id),
                    _ => crate::ResourceRule::Preset(rule.id),
                };
                let condition = &rule.conditions;
                if !rule.enabled || !condition.matches_source(flow.executable) {
                    continue;
                }
                match condition.transport.matches(transport) {
                    Ok(false) => continue,
                    Err(_) => {
                        return Evaluation::Rejected(PolicyFault::TransportUnavailable(rule.id));
                    }
                    Ok(true) => {}
                }
                if (!condition.domains.is_empty() || resources.has_domains(resource_rule))
                    && !name.is_some_and(|name| {
                        condition.domains.iter().any(|domain| domain.matches(name))
                            || resources.matches_domain(resource_rule, name)
                    })
                {
                    continue;
                }
                let selected =
                    if !condition.destinations.is_empty() || resources.has_cidrs(resource_rule) {
                        let addresses = match facts.get(context) {
                            Ok(addresses) => addresses,
                            Err(result) => return result,
                        };
                        checked_addresses = Some(addresses);
                        let selected = addresses
                            .iter()
                            .map(|address| address.to_canonical())
                            .filter(|&address| {
                                condition
                                    .destinations
                                    .iter()
                                    .any(|cidr| cidr.contains(address))
                                    || resources.matches_ip(resource_rule, address)
                            })
                            .min();
                        if selected.is_none() {
                            continue;
                        }
                        selected
                    } else {
                        checked_addresses.and_then(lowest_address)
                    };
                return decided(rule.action.into(), origin(rule.id), None, selected);
            }
        }
        decided(
            self.default_action.into(),
            RuleOrigin::Default,
            None,
            checked_addresses.and_then(lowest_address),
        )
    }
}
