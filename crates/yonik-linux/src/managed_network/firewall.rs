//! Типизированная публичная блокировка. Проверка принадлежности интерфейсов — задача адаптера.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr},
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
};

const MAX_EXCEPTIONS: usize = 128;
pub(crate) const MAX_BOUND_DIRECT: usize = MAX_EXCEPTIONS / 2;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const OUTPUT_CHAIN: &str = "output";
pub(super) const DHCP_RENEWAL_CHAIN: &str = "dhcp_renewal";
pub(super) const DHCP_RENEWAL_SET: &str = "dhcp_renewal_leases";
pub(super) const DHCP_CGROUP_PATH: &str = "system.slice/systemd-networkd.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    Prefix,
    Interface,
    Port,
    Mark,
    Limit,
    ConflictingPrivateRoute,
    PrivateTransport,
    LoopbackAddress,
    Gateway,
}
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Prefix => "Нужен канонический CIDR с ненулевой длиной префикса",
            Self::Interface => "Индекс интерфейса должен быть ненулевым",
            Self::Port => "Порт должен быть ненулевым",
            Self::Mark => "Метка сокета должна быть ненулевой",
            Self::Limit => "Превышен лимит 128 исключений",
            Self::PrivateTransport => "Служебное назначение пересекает защищённую приватную сеть",
            Self::ConflictingPrivateRoute => "Один приватный префикс связан с разными VPN",
            Self::LoopbackAddress => "Нужен выделенный IPv4 loopback адрес для службы",
            Self::Gateway => "Шлюз должен быть заданного семейства и не быть специальным адресом",
        })
    }
}
impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "IpPrefixDto")]
pub struct IpPrefix {
    address: IpAddr,
    length: u8,
}
impl IpPrefix {
    pub fn new(address: IpAddr, length: u8) -> Result<Self, PolicyError> {
        let canonical = match address {
            IpAddr::V4(address) if (1..=32).contains(&length) => {
                length == 32 || u32::from(address) & (u32::MAX >> length) == 0
            }
            IpAddr::V6(address) if (1..=128).contains(&length) => {
                // Сдвиг на полную ширину запрещён даже для host-префиксов.
                length == 128 || u128::from(address) & (u128::MAX >> length) == 0
            }
            _ => false,
        };
        if !canonical {
            return Err(PolicyError::Prefix);
        }
        Ok(Self { address, length })
    }
    pub(crate) fn contains(self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(prefix), IpAddr::V4(address)) => {
                u32::from(prefix) == u32::from(address) & (u32::MAX << (32 - self.length))
            }
            (IpAddr::V6(prefix), IpAddr::V6(address)) => {
                u128::from(prefix) == u128::from(address) & (u128::MAX << (128 - self.length))
            }
            _ => false,
        }
    }
    fn expression(self) -> Value {
        json!({"prefix": {"addr": self.address.to_string(), "len": self.length}})
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "PrivateRouteDto")]
pub struct PrivateRoute {
    prefix: IpPrefix,
    vpn_ifindex: Option<NonZeroU32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vpn_ifname: Option<InterfaceName>,
}
impl PrivateRoute {
    pub fn new(prefix: IpPrefix, vpn_ifindex: Option<u32>) -> Result<Self, PolicyError> {
        Ok(Self {
            prefix,
            vpn_ifindex: vpn_ifindex.map(interface).transpose()?,
            vpn_ifname: None,
        })
    }
    /// Только имя из проверенного link snapshot; само имя не доказывает владение.
    pub fn bound(
        prefix: IpPrefix,
        ifindex: u32,
        verified_ifname: &str,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            prefix,
            vpn_ifindex: Some(interface(ifindex)?),
            vpn_ifname: Some(InterfaceName::try_from(verified_ifname.to_owned())?),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
struct InterfaceName([u8; 16]);
impl TryFrom<String> for InterfaceName {
    type Error = PolicyError;
    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.is_empty()
            || name.len() > 15
            || matches!(name.as_str(), "." | "..")
            || name
                .bytes()
                .any(|b| b == 0 || b == b'/' || b == b':' || b.is_ascii_whitespace())
        {
            return Err(PolicyError::Interface);
        }
        let mut bytes = [0; 16];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self(bytes))
    }
}
impl From<InterfaceName> for String {
    fn from(name: InterfaceName) -> String {
        let end = name.0.iter().position(|b| *b == 0).unwrap_or(16);
        // Конструктор принимает только UTF-8 строку и не изменяет её байты.
        String::from_utf8(name.0[..end].to_vec()).expect("Проверенное имя link")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "LanExceptionDto")]
pub struct LanException {
    prefix: IpPrefix,
    ifindex: NonZeroU32,
}
impl LanException {
    pub fn new(prefix: IpPrefix, ifindex: u32) -> Result<Self, PolicyError> {
        Ok(Self {
            prefix,
            ifindex: interface(ifindex)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}
impl TransportProtocol {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "BoundTransportDto")]
pub struct BoundTransport {
    destination: IpAddr,
    protocol: TransportProtocol,
    port: NonZeroU16,
    ifindex: NonZeroU32,
    uid: u32,
    mark: NonZeroU32,
}

/// Выход worker через проверенный физический интерфейс к заданной сети.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "BoundDirectDto")]
pub(crate) struct BoundDirect {
    prefix: IpPrefix,
    gateway: IpAddr,
    ifindex: NonZeroU32,
    ifname: InterfaceName,
    uid: NonZeroU32,
    mark: NonZeroU32,
}
impl BoundDirect {
    pub(crate) fn new(
        prefix: IpPrefix,
        ifindex: u32,
        ifname: &str,
        uid: u32,
        mark: u32,
        gateway: IpAddr,
    ) -> Result<Self, PolicyError> {
        if prefix.address.is_ipv4() != gateway.is_ipv4()
            || gateway.is_unspecified()
            || gateway.is_loopback()
            || gateway.is_multicast()
        {
            return Err(PolicyError::Gateway);
        }
        if ifname.ends_with('*') {
            return Err(PolicyError::Interface);
        }
        Ok(Self {
            prefix,
            gateway,
            ifindex: interface(ifindex)?,
            ifname: InterfaceName::try_from(ifname.to_owned())?,
            uid: interface(uid)?,
            mark: NonZeroU32::new(mark).ok_or(PolicyError::Mark)?,
        })
    }
}
impl BoundTransport {
    pub fn new(
        destination: IpAddr,
        protocol: TransportProtocol,
        port: u16,
        ifindex: u32,
        uid: u32,
        mark: u32,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            destination,
            protocol,
            port: NonZeroU16::new(port).ok_or(PolicyError::Port)?,
            ifindex: interface(ifindex)?,
            uid,
            mark: NonZeroU32::new(mark).ok_or(PolicyError::Mark)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DhcpRule {
    ifindex: NonZeroU32,
    ifname: InterfaceName,
    address: Ipv4Addr,
    server: Ipv4Addr,
    uid: NonZeroU32,
    cgroup_id: NonZeroU64,
    dscp: u8,
    mark: u32,
    namespace_device: u64,
    namespace_inode: NonZeroU64,
}

pub(super) struct DhcpRenewalKey {
    pub(super) address: Ipv4Addr,
    pub(super) server: Ipv4Addr,
    pub(super) ifindex: NonZeroU32,
    pub(super) ifname: String,
}

impl DhcpRule {
    fn command(&self, table: &str) -> Value {
        let payload = |protocol, field| json!({"payload":{"protocol":protocol,"field":field}});
        let addresses_and_link = json!({"concat":[
            payload("ip", "saddr"), payload("ip", "daddr"),
            {"meta":{"key":"oif"}}, {"meta":{"key":"oifname"}}
        ]});
        rule_in(
            table,
            DHCP_RENEWAL_CHAIN,
            vec![
                compare(payload("ip", "saddr"), json!(self.address)),
                compare(payload("ip", "daddr"), json!(self.server)),
                meta("oif", json!(self.ifindex.get())),
                meta("oifname", json!(String::from(self.ifname))),
                meta("skuid", json!(self.uid.get())),
                compare(payload("udp", "sport"), json!(68)),
                compare(payload("udp", "dport"), json!(67)),
                compare(payload("ip", "dscp"), json!(self.dscp)),
                meta("mark", json!(self.mark)),
                compare(
                    json!({"socket":{"key":"cgroupv2","level":2}}),
                    json!(DHCP_CGROUP_PATH),
                ),
                compare(addresses_and_link, json!(format!("@{DHCP_RENEWAL_SET}"))),
                json!({"accept":null}),
            ],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PublicBlockPolicyDto")]
pub struct PublicBlockPolicy {
    loopback_ifindex: NonZeroU32,
    tun_ifindex: Option<NonZeroU32>,
    private_routes: Vec<PrivateRoute>,
    lan: Vec<LanException>,
    transport: Vec<BoundTransport>,
    bootstrap_dns: Vec<BoundTransport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bound_direct: Vec<BoundDirect>,
    link_control: Vec<NonZeroU32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    isolated_loopback: Option<IsolatedLoopback>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    dhcp_renewal_anchor: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dhcp_renewal_rule: Option<Box<DhcpRule>>,
}

/// Выделенный 127/8 адрес, доступный через loopback helper UID 0 и одному worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "IsolatedLoopbackDto")]
pub struct IsolatedLoopback {
    address: std::net::Ipv4Addr,
    worker_uid: NonZeroU32,
}

impl IsolatedLoopback {
    fn new(address: std::net::Ipv4Addr, worker_uid: u32) -> Result<Self, PolicyError> {
        if !address.is_loopback()
            || address == std::net::Ipv4Addr::LOCALHOST
            || address == std::net::Ipv4Addr::new(127, 255, 255, 255)
        {
            return Err(PolicyError::LoopbackAddress);
        }
        Ok(Self {
            address,
            worker_uid: interface(worker_uid)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IsolatedLoopbackDto {
    address: std::net::Ipv4Addr,
    worker_uid: u32,
}

impl TryFrom<IsolatedLoopbackDto> for IsolatedLoopback {
    type Error = PolicyError;

    fn try_from(value: IsolatedLoopbackDto) -> Result<Self, Self::Error> {
        Self::new(value.address, value.worker_uid)
    }
}

impl PublicBlockPolicy {
    fn exception_count(&self) -> usize {
        self.private_routes.len()
            + self.lan.len()
            + self.transport.len()
            + self.bootstrap_dns.len()
            + self.link_control.len() * 3
            + self.isolated_loopback.map_or(0, |_| 6)
            + self.bound_direct.len() * 2
            + usize::from(self.dhcp_renewal_anchor)
            + usize::from(self.dhcp_renewal_rule.is_some())
    }

    pub(crate) fn with_bound_direct(
        mut self,
        mut entries: Vec<BoundDirect>,
    ) -> Result<Self, PolicyError> {
        if entries.len() > MAX_BOUND_DIRECT {
            return Err(PolicyError::Limit);
        }
        if !entries.is_empty() && self.tun_ifindex.is_none() {
            return Err(PolicyError::Interface);
        }
        let loopback = InterfaceName::try_from("lo".to_owned())?;
        if entries.iter().any(|entry| {
            entry.ifindex == self.loopback_ifindex
                || entry.ifname == loopback
                || self.tun_ifindex == Some(entry.ifindex)
        }) {
            return Err(PolicyError::Interface);
        }
        if entries.iter().any(|entry| {
            self.private_routes
                .iter()
                .any(|route| prefixes_overlap(entry.prefix, route.prefix))
        }) {
            return Err(PolicyError::PrivateTransport);
        }
        let used = self.exception_count() - self.bound_direct.len() * 2 + entries.len() * 2;
        if used > MAX_EXCEPTIONS {
            return Err(PolicyError::Limit);
        }
        entries.sort_unstable();
        entries.dedup();
        self.bound_direct = entries;
        Ok(self)
    }

    pub(crate) fn permits_lan_endpoint(&self, destination: IpAddr, ifindex: u32) -> bool {
        self.lan
            .iter()
            .any(|entry| entry.ifindex.get() == ifindex && entry.prefix.contains(destination))
    }
    /// Замена сохраняет все прежние ограничения и общий предел исключений.
    pub(crate) fn with_additional_transport(
        &self,
        extra: &[BoundTransport],
    ) -> Result<Self, PolicyError> {
        let used = self.exception_count();
        if extra.len() > MAX_EXCEPTIONS.saturating_sub(used) {
            return Err(PolicyError::Limit);
        }
        let mut transport = self.transport.clone();
        transport.extend_from_slice(extra);
        Self::new(
            self.loopback_ifindex.get(),
            self.tun_ifindex.map(NonZeroU32::get),
            self.private_routes.clone(),
            self.lan.clone(),
            transport,
            self.bootstrap_dns.clone(),
        )?
        .with_link_control(self.link_control.iter().map(|i| i.get()).collect())?
        .with_isolated_loopback_config(self.isolated_loopback)?
        .with_bound_direct(self.bound_direct.clone())?
        .with_dhcp_renewal_anchor(self.dhcp_renewal_anchor)?
        .with_dhcp_rule_config(self.dhcp_renewal_rule.clone())
    }
    pub fn new(
        loopback_ifindex: u32,
        tun_ifindex: Option<u32>,
        mut private_routes: Vec<PrivateRoute>,
        mut lan: Vec<LanException>,
        mut transport: Vec<BoundTransport>,
        mut bootstrap_dns: Vec<BoundTransport>,
    ) -> Result<Self, PolicyError> {
        // Проверяем до dedup: дубликаты не обходят ограничение входных данных.
        if private_routes
            .len()
            .saturating_add(lan.len())
            .saturating_add(transport.len())
            .saturating_add(bootstrap_dns.len())
            > MAX_EXCEPTIONS
        {
            return Err(PolicyError::Limit);
        }
        if transport.iter().chain(&bootstrap_dns).any(|endpoint| {
            private_routes
                .iter()
                .any(|route| route.prefix.contains(endpoint.destination))
        }) {
            return Err(PolicyError::PrivateTransport);
        }
        private_routes.sort_unstable();
        if private_routes.windows(2).any(|pair| {
            pair[0].prefix == pair[1].prefix
                && (pair[0].vpn_ifindex != pair[1].vpn_ifindex
                    || pair[0].vpn_ifname != pair[1].vpn_ifname)
        }) {
            return Err(PolicyError::ConflictingPrivateRoute);
        }
        private_routes.dedup();
        // Более специфичная приватная сеть определяет свой VPN раньше широкой.
        private_routes
            .sort_unstable_by_key(|route| (std::cmp::Reverse(route.prefix.length), *route));
        lan.sort_unstable();
        lan.dedup();
        transport.sort_unstable();
        transport.dedup();
        bootstrap_dns.sort_unstable();
        bootstrap_dns.dedup();
        Ok(Self {
            loopback_ifindex: interface(loopback_ifindex)?,
            tun_ifindex: tun_ifindex.map(interface).transpose()?,
            private_routes,
            lan,
            transport,
            bootstrap_dns,
            bound_direct: Vec::new(),
            link_control: Vec::new(),
            isolated_loopback: None,
            dhcp_renewal_anchor: false,
            dhcp_renewal_rule: None,
        })
    }

    /// Разрешает только служебные IPv6 RS/NS/NA с hoplimit=255 и code=0
    /// на явно выбранных интерфейсах; это не широкое разрешение ICMPv6.
    pub fn with_link_control(mut self, interfaces: Vec<u32>) -> Result<Self, PolicyError> {
        let used = self.exception_count() - self.link_control.len() * 3;
        if interfaces.len() > MAX_EXCEPTIONS.saturating_sub(used) / 3 {
            return Err(PolicyError::Limit);
        }
        self.link_control = interfaces
            .into_iter()
            .map(interface)
            .collect::<Result<_, _>>()?;
        self.link_control.sort_unstable();
        self.link_control.dedup();
        Ok(self)
    }

    /// Разрешает выделенный loopback адрес только helper и системному worker.
    pub fn with_isolated_loopback(
        self,
        address: std::net::Ipv4Addr,
        worker_uid: u32,
    ) -> Result<Self, PolicyError> {
        self.with_isolated_loopback_config(Some(IsolatedLoopback::new(address, worker_uid)?))
    }

    fn with_isolated_loopback_config(
        mut self,
        guard: Option<IsolatedLoopback>,
    ) -> Result<Self, PolicyError> {
        let used = self.exception_count() - self.isolated_loopback.map_or(0, |_| 6);
        if guard.is_some() && used.saturating_add(6) > MAX_EXCEPTIONS {
            return Err(PolicyError::Limit);
        }
        self.isolated_loopback = guard;
        Ok(self)
    }

    /// Резервирует пустую цепочку продления DHCP в активной политике TUN.
    pub(crate) fn with_dhcp_renewal_anchor(mut self, enabled: bool) -> Result<Self, PolicyError> {
        if (enabled && self.tun_ifindex.is_none()) || (!enabled && self.dhcp_renewal_rule.is_some())
        {
            return Err(PolicyError::Interface);
        }
        self.dhcp_renewal_anchor = enabled;
        if self.exception_count() > MAX_EXCEPTIONS {
            return Err(PolicyError::Limit);
        }
        Ok(self)
    }

    pub(super) fn has_dhcp_renewal_anchor(&self) -> bool {
        self.dhcp_renewal_anchor
    }

    /// Добавляет правило для проверенного сокета. Набор разрешённых лизингов пуст.
    pub fn with_dhcp_renewal_rule(
        self,
        lease: &crate::helper::dhcp_networkd::DhcpNetworkdLease,
    ) -> Result<Self, PolicyError> {
        let path = lease.path().ok_or(PolicyError::Interface)?;
        self.with_dhcp_renewal_anchor(true)?
            .with_dhcp_rule_config(Some(Box::new(DhcpRule {
                ifindex: interface(path.interface)?,
                ifname: InterfaceName::try_from(path.ifname.to_owned())?,
                address: path.address,
                server: path.server,
                uid: interface(path.uid)?,
                cgroup_id: path.cgroup_id,
                dscp: path.route_tos >> 2,
                mark: path.route_mark,
                namespace_device: path.namespace.device,
                namespace_inode: NonZeroU64::new(path.namespace.inode)
                    .ok_or(PolicyError::Interface)?,
            })))
    }

    fn with_dhcp_rule_config(mut self, rule: Option<Box<DhcpRule>>) -> Result<Self, PolicyError> {
        if let Some(rule) = &rule {
            let name = String::from(rule.ifname);
            if !self.dhcp_renewal_anchor
                || rule.ifindex == self.loopback_ifindex
                || Some(rule.ifindex) == self.tun_ifindex
                || rule.dscp > 63
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            {
                return Err(PolicyError::Interface);
            }
            if rule.address == rule.server
                || [rule.address, rule.server].into_iter().any(|address| {
                    address.is_unspecified()
                        || address.is_broadcast()
                        || address.is_loopback()
                        || address.is_multicast()
                        || self
                            .private_routes
                            .iter()
                            .any(|route| route.prefix.contains(address.into()))
                })
            {
                return Err(PolicyError::PrivateTransport);
            }
        }
        self.dhcp_renewal_rule = rule;
        if self.exception_count() > MAX_EXCEPTIONS {
            return Err(PolicyError::Limit);
        }
        Ok(self)
    }

    pub(super) fn dhcp_rule_identity(&self) -> Option<((u64, u64), NonZeroU64)> {
        let rule = self.dhcp_renewal_rule.as_ref()?;
        Some((
            (rule.namespace_device, rule.namespace_inode.get()),
            rule.cgroup_id,
        ))
    }

    pub(super) fn dhcp_renewal_key(&self) -> Option<DhcpRenewalKey> {
        let rule = self.dhcp_renewal_rule.as_ref()?;
        Some(DhcpRenewalKey {
            address: rule.address,
            server: rule.server,
            ifindex: rule.ifindex,
            ifname: String::from(rule.ifname),
        })
    }

    pub(crate) fn dhcp_renewal_ifindex(&self) -> Option<NonZeroU32> {
        self.dhcp_renewal_rule.as_ref().map(|rule| rule.ifindex)
    }

    /// Отпечаток канонических правил не зависит от имени принадлежащей helper таблицы.
    pub fn digest(&self) -> [u8; 32] {
        // Value сериализуется однозначно; здесь не бывает пользовательских map/чисел float.
        let mut hash = Sha256::new();
        hash.update(Value::Array(self.commands("policy")).to_string().as_bytes());
        if let Some(((device, inode), cgroup)) = self.dhcp_rule_identity() {
            hash.update(device.to_le_bytes());
            hash.update(inode.to_le_bytes());
            hash.update(cgroup.get().to_le_bytes());
        }
        hash.finalize().into()
    }

    /// Таблицу и её owner-comment создаёт executor.
    pub(super) fn commands(&self, table_name: &str) -> Vec<Value> {
        let mut commands = Vec::new();
        if self.dhcp_renewal_anchor {
            commands.push(json!({"add":{"set":{
                "family":"inet", "table":table_name,"name":DHCP_RENEWAL_SET,
                "type":["ipv4_addr","ipv4_addr","iface_index","ifname"],
                "flags":["timeout"], "size":16
            }}}));
            commands.push(json!({"add":{"chain":{
                "family":"inet","table":table_name,"name":DHCP_RENEWAL_CHAIN
            }}}));
            if let Some(rule) = &self.dhcp_renewal_rule {
                commands.push(rule.command(table_name));
            }
        }
        commands.push(
            // Фильтруем после обычного DNAT (-100): LAN-адрес не должен
            // превратиться в разрешённый публичный выход после нашего accept.
            json!({"add": {"chain": {"family": "inet", "table": table_name, "name": OUTPUT_CHAIN, "type": "filter", "hook": "output", "prio": 0, "policy": "drop"}}}),
        );
        if let Some(guard) = self.isolated_loopback {
            for field in ["saddr", "daddr"] {
                let address = compare(
                    json!({"payload":{"protocol":"ip","field":field}}),
                    json!(guard.address.to_string()),
                );
                for uid in [0, guard.worker_uid.get()] {
                    commands.push(rule(
                        table_name,
                        vec![
                            meta("nfproto", json!("ipv4")),
                            meta("oif", json!(self.loopback_ifindex.get())),
                            address.clone(),
                            meta("skuid", json!(uid)),
                            json!({"accept":null}),
                        ],
                    ));
                }
                commands.push(rule(
                    table_name,
                    vec![
                        meta("nfproto", json!("ipv4")),
                        meta("oif", json!(self.loopback_ifindex.get())),
                        address,
                        json!({"drop":null}),
                    ],
                ));
            }
        }
        commands.push(rule(
            table_name,
            vec![
                meta("oif", json!(self.loopback_ifindex.get())),
                json!({"accept": null}),
            ],
        ));
        for ifindex in &self.link_control {
            for kind in [133, 135, 136] {
                commands.push(rule(
                    table_name,
                    vec![
                        meta("oif", json!(ifindex.get())),
                        compare(
                            json!({"payload":{"protocol":"ip6","field":"hoplimit"}}),
                            json!(255),
                        ),
                        compare(
                            json!({"payload":{"protocol":"icmpv6","field":"type"}}),
                            json!(kind),
                        ),
                        compare(
                            json!({"payload":{"protocol":"icmpv6","field":"code"}}),
                            json!(0),
                        ),
                        json!({"accept":null}),
                    ],
                ));
            }
        }
        for endpoint in self.transport.iter().chain(&self.bootstrap_dns) {
            let protocol = endpoint.protocol.name();
            commands.push(rule(
                table_name,
                vec![
                    destination(
                        endpoint.destination,
                        json!(endpoint.destination.to_string()),
                    ),
                    meta("oif", json!(endpoint.ifindex.get())),
                    meta("l4proto", json!(protocol)),
                    compare(
                        json!({"payload": {"protocol": protocol, "field": "dport"}}),
                        json!(endpoint.port.get()),
                    ),
                    meta("skuid", json!(endpoint.uid)),
                    meta("mark", json!(endpoint.mark.get())),
                    json!({"accept": null}),
                ],
            ));
        }
        for route in &self.private_routes {
            if let Some(ifindex) = route.vpn_ifindex {
                let mut expr = vec![
                    destination(route.prefix.address, route.prefix.expression()),
                    meta("oif", json!(ifindex.get())),
                ];
                if let Some(name) = route.vpn_ifname {
                    expr.push(meta("oifname", json!(String::from(name))));
                }
                expr.push(json!({"accept": null}));
                commands.push(rule(table_name, expr));
            }
            // Терминальная блокировка не даёт широкой LAN/TUN обойти назначенный VPN.
            commands.push(rule(
                table_name,
                vec![
                    destination(route.prefix.address, route.prefix.expression()),
                    json!({"drop": null}),
                ],
            ));
        }
        if self.dhcp_renewal_anchor {
            commands.push(rule(
                table_name,
                vec![json!({"jump":{"target":DHCP_RENEWAL_CHAIN}})],
            ));
        }
        for direct in &self.bound_direct {
            for protocol in [IPPROTO_TCP, IPPROTO_UDP] {
                commands.push(rule(
                    table_name,
                    vec![
                        destination(direct.prefix.address, direct.prefix.expression()),
                        destination_not_equal(direct.prefix.address, direct.gateway),
                        compare(
                            json!({"rt":{"key":"nexthop","family":if direct.gateway.is_ipv4() {"ip"} else {"ip6"}}}),
                            json!(direct.gateway.to_string()),
                        ),
                        meta("oif", json!(direct.ifindex.get())),
                        meta("oifname", json!(String::from(direct.ifname))),
                        meta("l4proto", json!(protocol)),
                        meta("skuid", json!(direct.uid.get())),
                        meta("mark", json!(direct.mark.get())),
                        json!({"accept": null}),
                    ],
                ));
            }
        }
        for exception in &self.lan {
            commands.push(rule(
                table_name,
                vec![
                    destination(exception.prefix.address, exception.prefix.expression()),
                    meta("oif", json!(exception.ifindex.get())),
                    json!({"accept": null}),
                ],
            ));
        }
        if let Some(ifindex) = self.tun_ifindex {
            commands.push(rule(
                table_name,
                vec![meta("oif", json!(ifindex.get())), json!({"accept": null})],
            ));
        }
        commands
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IpPrefixDto {
    address: IpAddr,
    length: u8,
}
impl TryFrom<IpPrefixDto> for IpPrefix {
    type Error = PolicyError;
    fn try_from(value: IpPrefixDto) -> Result<Self, Self::Error> {
        Self::new(value.address, value.length)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateRouteDto {
    prefix: IpPrefix,
    vpn_ifindex: Option<u32>,
    #[serde(default)]
    vpn_ifname: Option<InterfaceName>,
}
impl TryFrom<PrivateRouteDto> for PrivateRoute {
    type Error = PolicyError;
    fn try_from(value: PrivateRouteDto) -> Result<Self, Self::Error> {
        match value.vpn_ifname {
            Some(name) => Self::bound(
                value.prefix,
                value.vpn_ifindex.ok_or(PolicyError::Interface)?,
                &String::from(name),
            ),
            None => Self::new(value.prefix, value.vpn_ifindex),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LanExceptionDto {
    prefix: IpPrefix,
    ifindex: u32,
}
impl TryFrom<LanExceptionDto> for LanException {
    type Error = PolicyError;
    fn try_from(value: LanExceptionDto) -> Result<Self, Self::Error> {
        Self::new(value.prefix, value.ifindex)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundTransportDto {
    destination: IpAddr,
    protocol: TransportProtocol,
    port: u16,
    ifindex: u32,
    uid: u32,
    mark: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundDirectDto {
    prefix: IpPrefix,
    gateway: IpAddr,
    ifindex: u32,
    ifname: String,
    uid: u32,
    mark: u32,
}
impl TryFrom<BoundDirectDto> for BoundDirect {
    type Error = PolicyError;

    fn try_from(value: BoundDirectDto) -> Result<Self, Self::Error> {
        Self::new(
            value.prefix,
            value.ifindex,
            &value.ifname,
            value.uid,
            value.mark,
            value.gateway,
        )
    }
}
impl TryFrom<BoundTransportDto> for BoundTransport {
    type Error = PolicyError;
    fn try_from(value: BoundTransportDto) -> Result<Self, Self::Error> {
        Self::new(
            value.destination,
            value.protocol,
            value.port,
            value.ifindex,
            value.uid,
            value.mark,
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicBlockPolicyDto {
    loopback_ifindex: u32,
    tun_ifindex: Option<u32>,
    private_routes: Vec<PrivateRoute>,
    lan: Vec<LanException>,
    transport: Vec<BoundTransport>,
    bootstrap_dns: Vec<BoundTransport>,
    #[serde(default)]
    bound_direct: Vec<BoundDirect>,
    link_control: Vec<u32>,
    #[serde(default)]
    isolated_loopback: Option<IsolatedLoopback>,
    #[serde(default)]
    dhcp_renewal_anchor: bool,
    #[serde(default)]
    dhcp_renewal_rule: Option<Box<DhcpRule>>,
}
impl TryFrom<PublicBlockPolicyDto> for PublicBlockPolicy {
    type Error = PolicyError;
    fn try_from(value: PublicBlockPolicyDto) -> Result<Self, Self::Error> {
        Self::new(
            value.loopback_ifindex,
            value.tun_ifindex,
            value.private_routes,
            value.lan,
            value.transport,
            value.bootstrap_dns,
        )?
        .with_link_control(value.link_control)?
        .with_isolated_loopback_config(value.isolated_loopback)?
        .with_bound_direct(value.bound_direct)?
        .with_dhcp_renewal_anchor(value.dhcp_renewal_anchor)?
        .with_dhcp_rule_config(value.dhcp_renewal_rule)
    }
}

fn interface(value: u32) -> Result<NonZeroU32, PolicyError> {
    NonZeroU32::new(value).ok_or(PolicyError::Interface)
}
fn prefixes_overlap(first: IpPrefix, second: IpPrefix) -> bool {
    first.contains(second.address) || second.contains(first.address)
}
fn compare(left: Value, right: Value) -> Value {
    json!({"match": {"op": "==", "left": left, "right": right}})
}
fn meta(key: &str, right: Value) -> Value {
    compare(json!({"meta": {"key": key}}), right)
}
fn destination(address: IpAddr, right: Value) -> Value {
    compare(
        json!({"payload": {"protocol": if address.is_ipv4() { "ip" } else { "ip6" }, "field": "daddr"}}),
        right,
    )
}
fn destination_not_equal(address: IpAddr, gateway: IpAddr) -> Value {
    json!({"match": {
        "op": "!=",
        "left": {"payload": {"protocol": if address.is_ipv4() {"ip"} else {"ip6"}, "field": "daddr"}},
        "right": gateway.to_string()
    }})
}
fn rule(table: &str, expr: Vec<Value>) -> Value {
    rule_in(table, OUTPUT_CHAIN, expr)
}

fn rule_in(table: &str, chain: &str, mut expr: Vec<Value>) -> Value {
    let family = match expr
        .first()
        .and_then(|value| value.pointer("/match/left/payload/protocol"))
        .and_then(Value::as_str)
    {
        Some("ip") => Some("ipv4"),
        Some("ip6") => Some("ipv6"),
        _ => None,
    };
    if let Some(family) = family {
        expr.insert(0, meta("nfproto", json!(family)));
    }
    json!({"add": {"rule": {"family": "inet", "table": table, "chain": chain, "expr": expr}}})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(address: &str, length: u8) -> IpPrefix {
        IpPrefix::new(address.parse().expect("Тестовый IP"), length).expect("Тестовый CIDR")
    }
    fn policy(
        private: Vec<PrivateRoute>,
        lan: Vec<LanException>,
        transport: Vec<BoundTransport>,
    ) -> PublicBlockPolicy {
        PublicBlockPolicy::new(1, Some(8), private, lan, transport, vec![])
            .expect("Тестовая политика")
    }
    fn endpoint(address: &str) -> BoundTransport {
        BoundTransport::new(
            address.parse().expect("Тестовый IP"),
            TransportProtocol::Tcp,
            443,
            2,
            987,
            11,
        )
        .expect("Тестовый endpoint")
    }
    fn direct(prefix: IpPrefix, ifindex: u32, ifname: &str) -> BoundDirect {
        let gateway: IpAddr = if prefix.address.is_ipv4() {
            "192.0.2.1".parse().unwrap()
        } else {
            "2001:db8::1".parse().unwrap()
        };
        BoundDirect::new(prefix, ifindex, ifname, 987, 11, gateway).expect("Тестовый Direct")
    }
    #[test]
    fn bound_direct_is_scoped_ordered_serialized_and_preserved() {
        let network = prefix("192.0.2.0", 24);
        let first = direct(network, 2, "enp1s0");
        let base = policy(vec![], vec![], vec![])
            .with_bound_direct(vec![first])
            .unwrap();
        let rules = base.commands("fixture");
        assert_eq!(rules.len(), 5);
        for (rule, protocol) in rules[2..4].iter().zip([IPPROTO_TCP, IPPROTO_UDP]) {
            let expressions = rule["add"]["rule"]["expr"].as_array().unwrap();
            assert_eq!(expressions[0], meta("nfproto", json!("ipv4")));
            assert_eq!(
                expressions[1],
                destination("192.0.2.0".parse().unwrap(), network.expression())
            );
            assert_eq!(
                expressions[2],
                json!({"match":{"op":"!=","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.1"}})
            );
            assert_eq!(
                expressions[3],
                compare(
                    json!({"rt":{"key":"nexthop","family":"ip"}}),
                    json!("192.0.2.1")
                )
            );
            assert_eq!(expressions[4], meta("oif", json!(2)));
            assert_eq!(expressions[5], meta("oifname", json!("enp1s0")));
            assert_eq!(expressions[6], meta("l4proto", json!(protocol)));
            assert_eq!(expressions[7], meta("skuid", json!(987)));
            assert_eq!(expressions[8], meta("mark", json!(11)));
            assert_eq!(expressions[9], json!({"accept":null}));
        }
        assert_eq!(
            BoundDirect::new(network, 2, "enp1s0*", 987, 11, "192.0.2.1".parse().unwrap()),
            Err(PolicyError::Interface)
        );
        assert_eq!(
            BoundDirect::new(network, 2, "enp1s0", 0, 11, "192.0.2.1".parse().unwrap()),
            Err(PolicyError::Interface)
        );
        assert_eq!(
            BoundDirect::new(network, 2, "enp1s0", 987, 0, "192.0.2.1".parse().unwrap()),
            Err(PolicyError::Mark)
        );
        let encoded = serde_json::to_value(&base).unwrap();
        assert!(
            serde_json::to_value(policy(vec![], vec![], vec![]))
                .unwrap()
                .get("bound_direct")
                .is_none()
        );
        let mut invalid = encoded.clone();
        invalid["bound_direct"][0]["unknown"] = json!(true);
        assert!(serde_json::from_value::<PublicBlockPolicy>(invalid).is_err());
        let mut missing_gateway = encoded.clone();
        missing_gateway["bound_direct"][0]
            .as_object_mut()
            .unwrap()
            .remove("gateway");
        assert!(serde_json::from_value::<PublicBlockPolicy>(missing_gateway).is_err());
        let restored: PublicBlockPolicy = serde_json::from_value(encoded).unwrap();
        assert_eq!(restored, base);
        assert_eq!(restored.digest(), base.digest());
        let updated = base
            .with_additional_transport(&[endpoint("203.0.113.4")])
            .unwrap();
        assert_ne!(updated.digest(), base.digest());
        let direct_rules = |commands: &[Value]| {
            commands
                .iter()
                .filter(|command| {
                    command.pointer("/add/rule/expr").is_some_and(|expr| {
                        expr.as_array().is_some_and(|items| {
                            items.iter().any(|item| {
                                item.pointer("/match/left/meta/key").and_then(Value::as_str)
                                    == Some("oifname")
                                    && item.pointer("/match/right").and_then(Value::as_str)
                                        == Some("enp1s0")
                            })
                        })
                    })
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            direct_rules(&updated.commands("fixture")),
            direct_rules(&base.commands("fixture"))
        );

        let duplicate = base.clone().with_bound_direct(vec![first, first]).unwrap();
        assert_eq!(duplicate.digest(), base.digest());
        assert_eq!(duplicate.commands("fixture"), base.commands("fixture"));
        let second = direct(prefix("198.51.100.0", 24), 3, "enp2s0");
        let ordered = policy(vec![], vec![], vec![])
            .with_bound_direct(vec![first, second])
            .unwrap();
        let reversed = policy(vec![], vec![], vec![])
            .with_bound_direct(vec![second, first])
            .unwrap();
        assert_eq!(ordered.digest(), reversed.digest());
        assert_ne!(
            base.digest(),
            policy(vec![], vec![], vec![])
                .with_bound_direct(vec![direct(network, 3, "enp1s0")])
                .unwrap()
                .digest()
        );
        assert_ne!(
            base.digest(),
            policy(vec![], vec![], vec![])
                .with_bound_direct(vec![
                    BoundDirect::new(network, 2, "enp1s0", 987, 11, "192.0.2.2".parse().unwrap(),)
                        .unwrap()
                ])
                .unwrap()
                .digest()
        );
    }

    #[test]
    fn bound_direct_requires_a_distinct_physical_link_and_respects_limits_and_private_routes() {
        let route = prefix("10.0.0.0", 8);
        let private = PrivateRoute::bound(route, 7, "wg0").unwrap();
        let base = policy(vec![private], vec![], vec![]);
        let make = |prefix| direct(prefix, 2, "enp1s0");
        assert_eq!(
            base.clone().with_bound_direct(vec![make(route)]),
            Err(PolicyError::PrivateTransport)
        );
        assert_eq!(
            PublicBlockPolicy::new(1, None, vec![], vec![], vec![], vec![])
                .unwrap()
                .with_bound_direct(vec![make(prefix("192.0.2.0", 24))]),
            Err(PolicyError::Interface)
        );
        assert_eq!(
            policy(vec![], vec![], vec![]).with_bound_direct(vec![direct(
                prefix("192.0.2.0", 24),
                1,
                "lo"
            )]),
            Err(PolicyError::Interface)
        );
        assert_eq!(
            policy(vec![], vec![], vec![]).with_bound_direct(vec![direct(
                prefix("192.0.2.0", 24),
                8,
                "tofu"
            )]),
            Err(PolicyError::Interface)
        );
        let bounded = policy(vec![], vec![], vec![])
            .with_link_control(vec![2])
            .unwrap();
        assert_eq!(
            bounded
                .clone()
                .with_bound_direct(vec![make(prefix("192.0.2.0", 24)); MAX_BOUND_DIRECT + 1]),
            Err(PolicyError::Limit)
        );
        let maximum = (1..=MAX_BOUND_DIRECT)
            .map(|last| direct(prefix(&format!("198.18.{}.0", last), 24), 2, "enp1s0"))
            .collect();
        assert_eq!(bounded.with_bound_direct(maximum), Err(PolicyError::Limit));
    }

    #[test]
    fn bound_direct_gateway_is_family_checked_and_encoded_for_both_families() {
        let network = prefix("2001:db8:5::", 64);
        let gateway: IpAddr = "fe80::1".parse().unwrap();
        let entry = BoundDirect::new(network, 2, "enp1s0", 987, 11, gateway).unwrap();
        let policy_with_gateway = policy(vec![], vec![], vec![])
            .with_bound_direct(vec![entry])
            .unwrap();
        let encoded = policy_with_gateway.commands("fixture");
        let expressions = encoded[2]["add"]["rule"]["expr"].as_array().unwrap();
        assert_eq!(expressions[0], meta("nfproto", json!("ipv6")));
        assert_eq!(
            expressions[2],
            json!({"match":{"op":"!=","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":"fe80::1"}})
        );
        assert_eq!(
            expressions[3],
            compare(
                json!({"rt":{"key":"nexthop","family":"ip6"}}),
                json!("fe80::1")
            )
        );
        assert_eq!(
            serde_json::from_value::<PublicBlockPolicy>(
                serde_json::to_value(&policy_with_gateway).unwrap()
            )
            .unwrap(),
            policy_with_gateway
        );
        assert_ne!(
            policy_with_gateway.digest(),
            policy(vec![], vec![], vec![]).digest()
        );

        for invalid in ["::", "::1", "ff02::1", "192.0.2.1"] {
            assert!(
                BoundDirect::new(network, 2, "enp1s0", 987, 11, invalid.parse().unwrap()).is_err()
            );
        }
        let v4 = prefix("192.0.2.0", 24);
        for invalid in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "2001:db8::1"] {
            assert!(BoundDirect::new(v4, 2, "enp1s0", 987, 11, invalid.parse().unwrap()).is_err());
        }
    }
    #[test]
    fn bound_identity_is_additive_and_legacy_codec_stays_canonical() {
        let legacy = PrivateRoute::new(prefix("10.42.1.0", 24), Some(27)).unwrap();
        let old = json!({"prefix":{"address":"10.42.1.0","length":24},"vpn_ifindex":27});
        assert_eq!(serde_json::to_value(legacy).unwrap(), old);
        assert_eq!(
            serde_json::from_value::<PrivateRoute>(old.clone()).unwrap(),
            legacy
        );
        let bound = PrivateRoute::bound(prefix("10.42.1.0", 24), 27, "vpn").unwrap();
        let rules = policy(vec![bound], vec![], vec![]).commands("owned");
        assert_eq!(
            rules[2]["add"]["rule"]["expr"][3],
            meta("oifname", json!("vpn"))
        );
        assert_eq!(
            serde_json::from_value::<PrivateRoute>(serde_json::to_value(bound).unwrap()).unwrap(),
            bound
        );
        for invalid in [
            "",
            ".",
            "..",
            "has space",
            "has:colon",
            "has/slash",
            "0123456789012345",
            "nul\0name",
        ] {
            assert!(PrivateRoute::bound(prefix("10.42.1.0", 24), 27, invalid).is_err());
        }
        let quoted = PrivateRoute::bound(prefix("10.42.1.0", 24), 27, "v\"pn").unwrap();
        assert_eq!(
            serde_json::to_value(quoted).unwrap()["vpn_ifname"],
            json!("v\"pn")
        );
        let mut invalid = old;
        invalid["vpn_ifname"] = json!("vpn");
        invalid["vpn_ifindex"] = Value::Null;
        assert!(serde_json::from_value::<PrivateRoute>(invalid).is_err());
        let legacy_policy = policy(vec![legacy], vec![], vec![]);
        let restored: PublicBlockPolicy =
            serde_json::from_value(serde_json::to_value(&legacy_policy).unwrap()).unwrap();
        assert_eq!(restored.digest(), legacy_policy.digest());
        assert_eq!(
            legacy_policy.digest(),
            [
                55, 195, 79, 50, 98, 85, 84, 40, 210, 111, 52, 177, 3, 169, 43, 98, 57, 147, 117,
                53, 153, 22, 234, 163, 239, 221, 207, 250, 172, 213, 186, 176
            ]
        );
        assert_ne!(
            legacy_policy.digest(),
            policy(vec![bound], vec![], vec![]).digest()
        );
    }
    #[test]
    fn policy_codec_validates_every_nested_constructor_and_unknown_field() {
        let original = policy(
            vec![PrivateRoute::new(prefix("10.0.0.0", 8), Some(7)).unwrap()],
            vec![LanException::new(prefix("192.168.0.0", 16), 2).unwrap()],
            vec![endpoint("192.0.2.1")],
        )
        .with_link_control(vec![2])
        .unwrap();
        let value = serde_json::to_value(&original).unwrap();
        assert_eq!(
            serde_json::from_value::<PublicBlockPolicy>(value.clone()).unwrap(),
            original
        );
        for pointer in [
            "/loopback_ifindex",
            "/tun_ifindex",
            "/private_routes/0/vpn_ifindex",
            "/lan/0/ifindex",
            "/transport/0/port",
            "/transport/0/ifindex",
            "/transport/0/mark",
            "/link_control/0",
        ] {
            let mut invalid = value.clone();
            *invalid.pointer_mut(pointer).unwrap() = 0.into();
            assert!(
                serde_json::from_value::<PublicBlockPolicy>(invalid).is_err(),
                "{pointer}"
            );
        }
        for pointer in [
            "",
            "/private_routes/0",
            "/private_routes/0/prefix",
            "/lan/0",
            "/transport/0",
        ] {
            let mut invalid = value.clone();
            invalid
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".into(), true.into());
            assert!(
                serde_json::from_value::<PublicBlockPolicy>(invalid).is_err(),
                "{pointer}"
            );
        }
        let mut invalid = value.clone();
        invalid["private_routes"][0]["prefix"]["address"] = "10.0.0.1".into();
        assert!(serde_json::from_value::<PublicBlockPolicy>(invalid).is_err());
        let mut invalid = value.clone();
        invalid["transport"][0]["destination"] = "10.1.2.3".into();
        assert!(serde_json::from_value::<PublicBlockPolicy>(invalid).is_err());
        let mut invalid = value;
        invalid["transport"] = serde_json::Value::Array(vec![invalid["transport"][0].clone(); 129]);
        assert!(serde_json::from_value::<PublicBlockPolicy>(invalid).is_err());
    }
    #[test]
    fn rejects_noncanonical_and_default_prefixes_and_accepts_host_prefixes() {
        for (address, length) in [
            ("10.0.0.1", 24),
            ("10.0.0.0", 0),
            ("10.0.0.0", 33),
            ("fd00::1", 64),
            ("::", 0),
            ("::", 129),
        ] {
            assert_eq!(
                IpPrefix::new(address.parse().expect("Тестовый IP"), length),
                Err(PolicyError::Prefix)
            );
        }
        assert!(IpPrefix::new("192.0.2.1".parse().expect("IP"), 32).is_ok());
        assert!(IpPrefix::new("2001:db8::1".parse().expect("IP"), 128).is_ok());
    }
    #[test]
    fn rejects_zero_interface_port_mark_and_excessive_exceptions() {
        assert_eq!(
            LanException::new(prefix("10.0.0.0", 24), 0),
            Err(PolicyError::Interface)
        );
        assert_eq!(
            PrivateRoute::new(prefix("fd00::", 64), Some(0)),
            Err(PolicyError::Interface)
        );
        assert_eq!(
            PublicBlockPolicy::new(0, None, vec![], vec![], vec![], vec![]),
            Err(PolicyError::Interface)
        );
        assert_eq!(
            PublicBlockPolicy::new(1, Some(0), vec![], vec![], vec![], vec![]),
            Err(PolicyError::Interface)
        );
        let address = "192.0.2.1".parse().expect("IP");
        assert_eq!(
            BoundTransport::new(address, TransportProtocol::Udp, 0, 2, 5, 1),
            Err(PolicyError::Port)
        );
        assert_eq!(
            BoundTransport::new(address, TransportProtocol::Udp, 53, 2, 5, 0),
            Err(PolicyError::Mark)
        );
        assert_eq!(
            PublicBlockPolicy::new(
                1,
                None,
                vec![],
                vec![],
                vec![endpoint("192.0.2.1"); 129],
                vec![]
            ),
            Err(PolicyError::Limit)
        );
    }
    #[test]
    fn private_destinations_cannot_bypass_vpn_through_service_exception() {
        for (cidr, length, destination) in [("10.0.0.0", 8, "10.2.3.4"), ("fd00::", 8, "fd12::1")] {
            let private = vec![PrivateRoute::new(prefix(cidr, length), Some(7)).expect("VPN")];
            assert_eq!(
                PublicBlockPolicy::new(
                    1,
                    None,
                    private.clone(),
                    vec![],
                    vec![endpoint(destination)],
                    vec![]
                ),
                Err(PolicyError::PrivateTransport)
            );
            assert_eq!(
                PublicBlockPolicy::new(
                    1,
                    None,
                    private,
                    vec![],
                    vec![],
                    vec![endpoint(destination)]
                ),
                Err(PolicyError::PrivateTransport)
            );
        }
    }
    #[test]
    fn private_guard_precedes_lan_and_tun_and_uses_longest_prefix() {
        let rules = policy(
            vec![
                PrivateRoute::new(prefix("10.0.0.0", 8), Some(7)).expect("VPN"),
                PrivateRoute::new(prefix("10.1.0.0", 16), None).expect("VPN"),
            ],
            vec![LanException::new(prefix("10.0.0.0", 8), 2).expect("LAN")],
            vec![],
        )
        .commands("owned");
        assert_eq!(rules[0]["add"]["chain"]["policy"], "drop");
        assert_eq!(rules[0]["add"]["chain"]["family"], "inet");
        assert_eq!(rules[0]["add"]["chain"]["prio"], 0);
        assert_eq!(
            rules[2]["add"]["rule"]["expr"][1]["match"]["right"],
            json!({"prefix": {"addr":"10.1.0.0", "len":16}})
        );
        assert_eq!(rules[2]["add"]["rule"]["expr"][2], json!({"drop":null}));
        assert_eq!(rules[3]["add"]["rule"]["expr"][2]["match"]["right"], 7);
        assert_eq!(rules[4]["add"]["rule"]["expr"][2], json!({"drop":null}));
        assert_eq!(rules[5]["add"]["rule"]["expr"][2]["match"]["right"], 2);
        assert_eq!(rules[6]["add"]["rule"]["expr"][0]["match"]["right"], 8);
    }
    #[test]
    fn endpoint_has_complete_identity_and_ipv6_destination() {
        let rules = policy(vec![], vec![], vec![endpoint("2001:db8::1")]).commands("owned");
        let expr = &rules[2]["add"]["rule"]["expr"];
        assert_eq!(expr[0]["match"]["right"], "ipv6");
        assert_eq!(expr[1]["match"]["left"]["payload"]["protocol"], "ip6");
        assert_eq!(expr[2]["match"]["right"], 2);
        assert_eq!(expr[3]["match"]["right"], "tcp");
        assert_eq!(expr[4]["match"]["right"], 443);
        assert_eq!(expr[5]["match"]["left"]["meta"]["key"], "skuid");
        assert_eq!(expr[5]["match"]["right"], 987);
        assert_eq!(expr[6]["match"]["left"]["meta"]["key"], "mark");
        assert_eq!(expr[6]["match"]["right"], 11);
        assert_eq!(expr[7], json!({"accept":null}));
    }
    #[test]
    fn canonical_order_and_digest_ignore_duplicate_input_and_bind_identity() {
        let a = endpoint("192.0.2.1");
        let b = endpoint("192.0.2.2");
        let first = policy(vec![], vec![], vec![a, b]);
        let second = policy(vec![], vec![], vec![b, a, a]);
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.commands("a"), second.commands("a"));
        assert_ne!(first.digest(), policy(vec![], vec![], vec![a]).digest());
        assert_ne!(
            first.digest(),
            PublicBlockPolicy::new(1, Some(9), vec![], vec![], vec![a, b], vec![])
                .expect("Policy")
                .digest()
        );
        assert_ne!(first.commands("a"), first.commands("b"));
    }
    #[test]
    fn rejects_ambiguous_private_prefix_binding() {
        let cidr = prefix("fd00::", 8);
        assert_eq!(
            PublicBlockPolicy::new(
                1,
                None,
                vec![
                    PrivateRoute::new(cidr, Some(7)).expect("VPN"),
                    PrivateRoute::new(cidr, None).expect("VPN")
                ],
                vec![],
                vec![],
                vec![]
            ),
            Err(PolicyError::ConflictingPrivateRoute)
        );
    }
    #[test]
    fn link_control_is_explicit_bounded_and_not_generic_icmp() {
        let base = PublicBlockPolicy::new(1, None, vec![], vec![], vec![], vec![]).unwrap();
        let nd = base.clone().with_link_control(vec![3, 2, 3]).unwrap();
        assert_ne!(nd.digest(), base.digest());
        assert_eq!(
            nd.digest(),
            base.clone().with_link_control(vec![2, 3]).unwrap().digest()
        );
        assert_eq!(
            base.clone().with_link_control(vec![0]),
            Err(PolicyError::Interface)
        );
        assert_eq!(base.with_link_control(vec![2; 43]), Err(PolicyError::Limit));
        let rules = nd.commands("fixture");
        assert_eq!(rules.len(), 8);
        for command in &rules[2..] {
            let expr = command["add"]["rule"]["expr"].as_array().unwrap();
            assert_eq!(expr[1]["match"]["right"], 255);
            assert!([133, 135, 136].contains(&expr[2]["match"]["right"].as_u64().unwrap()));
            assert_eq!(expr[3]["match"]["right"], 0);
        }
    }

    #[test]
    fn isolated_loopback_guards_both_addresses_before_general_loopback_accept() {
        let base = PublicBlockPolicy::new(1, Some(8), vec![], vec![], vec![], vec![]).unwrap();
        let legacy = serde_json::to_value(&base).unwrap();
        assert!(legacy.get("isolated_loopback").is_none());
        assert_eq!(
            serde_json::from_value::<PublicBlockPolicy>(legacy).unwrap(),
            base
        );
        let address = std::net::Ipv4Addr::new(127, 42, 7, 9);
        let guarded = base.clone().with_isolated_loopback(address, 987).unwrap();
        let commands = guarded.commands("fixture");
        assert_eq!(commands.len(), 9);
        assert_eq!(
            commands[1]["add"]["rule"]["expr"][2]["match"]["left"]["payload"]["field"],
            "saddr"
        );
        assert_eq!(
            commands[1]["add"]["rule"]["expr"][2]["match"]["right"],
            address.to_string()
        );
        assert_eq!(
            commands[1]["add"]["rule"]["expr"][3],
            meta("skuid", json!(0))
        );
        assert_eq!(
            commands[1]["add"]["rule"]["expr"][4],
            json!({"accept":null})
        );
        assert_eq!(
            commands[2]["add"]["rule"]["expr"][3],
            meta("skuid", json!(987))
        );
        assert_eq!(commands[3]["add"]["rule"]["expr"][3], json!({"drop":null}));
        assert_eq!(
            commands[4]["add"]["rule"]["expr"][2]["match"]["left"]["payload"]["field"],
            "daddr"
        );
        assert_eq!(commands[6]["add"]["rule"]["expr"][3], json!({"drop":null}));
        assert_eq!(commands[7]["add"]["rule"]["expr"][0], meta("oif", json!(1)));

        let encoded = serde_json::to_value(&guarded).unwrap();
        assert_eq!(encoded["isolated_loopback"]["address"], address.to_string());
        assert_eq!(encoded["isolated_loopback"]["worker_uid"], 987);
        let restored: PublicBlockPolicy = serde_json::from_value(encoded).unwrap();
        assert_eq!(restored, guarded);
        let replaced = guarded
            .with_additional_transport(&[endpoint("203.0.113.9")])
            .unwrap();
        assert_eq!(replaced.isolated_loopback, guarded.isolated_loopback);
        assert_eq!(
            replaced.commands("fixture")[1..7],
            guarded.commands("fixture")[1..7]
        );
        assert_ne!(guarded.digest(), base.digest());
    }

    #[test]
    fn isolated_loopback_requires_a_dedicated_address_and_non_root_worker() {
        let base = PublicBlockPolicy::new(1, None, vec![], vec![], vec![], vec![]).unwrap();
        for address in [
            std::net::Ipv4Addr::UNSPECIFIED,
            std::net::Ipv4Addr::LOCALHOST,
            std::net::Ipv4Addr::new(126, 1, 2, 3),
            std::net::Ipv4Addr::new(127, 255, 255, 255),
        ] {
            assert_eq!(
                base.clone().with_isolated_loopback(address, 987),
                Err(PolicyError::LoopbackAddress)
            );
        }
        assert_eq!(
            base.clone()
                .with_isolated_loopback(std::net::Ipv4Addr::new(127, 42, 7, 9), 0),
            Err(PolicyError::Interface)
        );
        assert_eq!(
            base.with_isolated_loopback(std::net::Ipv4Addr::new(127, 42, 7, 9), u32::MAX)
                .unwrap()
                .isolated_loopback
                .unwrap()
                .worker_uid
                .get(),
            u32::MAX
        );
    }
    #[test]
    fn dynamic_replacement_preserves_private_lan_dns_controls_and_aggregate_cap() {
        let base = PublicBlockPolicy::new(
            1,
            Some(8),
            vec![PrivateRoute::new(prefix("10.0.0.0", 8), Some(7)).unwrap()],
            vec![LanException::new(prefix("192.168.0.0", 16), 2).unwrap()],
            vec![endpoint("192.0.2.1")],
            vec![endpoint("192.0.2.53")],
        )
        .unwrap()
        .with_link_control(vec![2])
        .unwrap();
        assert!(base.permits_lan_endpoint("192.168.1.2".parse().unwrap(), 2));
        assert!(!base.permits_lan_endpoint("192.168.1.2".parse().unwrap(), 3));
        let extra = endpoint("203.0.113.9");
        let replaced = base.with_additional_transport(&[extra]).unwrap();
        assert_eq!(replaced.private_routes, base.private_routes);
        assert_eq!(replaced.lan, base.lan);
        assert_eq!(replaced.bootstrap_dns, base.bootstrap_dns);
        assert_eq!(replaced.link_control, base.link_control);
        assert_eq!(
            base.with_additional_transport(&vec![extra; 122]),
            Err(PolicyError::Limit)
        );
        assert!(base.with_additional_transport(&vec![extra; 121]).is_ok());
        assert_eq!(
            base.with_additional_transport(&[endpoint("10.1.2.3")]),
            Err(PolicyError::PrivateTransport)
        );
    }
}
