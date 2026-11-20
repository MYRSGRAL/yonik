//! Замкнутый маршрут Fake-IP через внешний DNS и SOCKS-обработчик helper.
use super::{SystemTun, attach};
use crate::{
    CompileError, CompiledConfig, Engine, PolicyCompileError, compile,
    fake_dns::SYSTEM_FAKE_DNS_PROBE_NAME,
    routing::{PolicyMode, ProbeCredentials},
};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU16,
};
use yonik_domain::{Action, Cidr, DomainPattern, Policy, Rule};
use yonik_import::ParsedServer;

const LINK_SCOPED_DESTINATIONS: [&str; 5] = [
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "fe80::/10",
    "ff00::/8",
];
const DNS_PORT: u16 = 53;
// IP-only конфигурация не резолвит домены для сопоставления с CIDR.
const LITERAL_DESTINATIONS: [&str; 2] = ["0.0.0.0/0", "::/0"];

enum ScopedFakePolicy<'a> {
    ProxyOnly,
    Names,
    NamesAndLiteral,
    ResolvedCidr {
        policy: &'a Policy,
        direct_auth: &'a ProbeCredentials,
    },
}

/// Только маршрутизация между принадлежащими сессии локальными службами.
/// Host проверяет пересечение пулов с реальной топологией, держит службы и
/// начинает выдачу Fake-IP только после подтверждения обратного тракта.
pub struct SystemFakeDnsBridge {
    dns_address: IpAddr,
    pools: Vec<Cidr>,
    loopback: Ipv4Addr,
    dns_port: NonZeroU16,
    lookup_port: NonZeroU16,
    reinject_port: NonZeroU16,
    plain_dns_peers: Vec<PlainDnsPeer>,
    reject_unbound_dns: bool,
    lookup_auth: ProbeCredentials,
    reinject_auth: ProbeCredentials,
    policy_resolver: Option<(SocketAddr, ProbeCredentials)>,
    resolved_direct_auth: Option<ProbeCredentials>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlainDnsPeer {
    endpoint: SocketAddr,
    loopback_port: NonZeroU16,
}

impl SystemFakeDnsBridge {
    pub const MAX_PLAIN_DNS_PEERS: usize = 16;
    pub const POLICY_RESOLVER_USERNAME: &str = "yonik-policy-resolver";
    pub const RESOLVED_DIRECT_USERNAME: &str = "yonik-resolved-direct";

    pub fn new(
        dns_address: IpAddr,
        pools: Vec<Cidr>,
        dns_port: NonZeroU16,
        lookup_port: NonZeroU16,
        reinject_port: NonZeroU16,
    ) -> Result<Self, CompileError> {
        if reserved_prefix(dns_address).is_none()
            || pools.iter().any(|pool| pool.contains(dns_address))
            || pools.is_empty()
            || pools.len() > 2
            || pools.len() == 2 && pools[0].network().is_ipv4() == pools[1].network().is_ipv4()
            || pools.iter().any(|pool| {
                reserved_prefix(pool.network()).is_none_or(|minimum| pool.prefix_len() < minimum)
            })
        {
            return Err(CompileError::InvalidParameter);
        }
        if dns_port == lookup_port || dns_port == reinject_port || lookup_port == reinject_port {
            return Err(CompileError::ListenerConflict);
        }
        let lookup_auth = ProbeCredentials::random().map_err(|_| CompileError::InvalidParameter)?;
        let reinject_auth =
            ProbeCredentials::random().map_err(|_| CompileError::InvalidParameter)?;
        Ok(Self {
            dns_address,
            pools,
            loopback: Ipv4Addr::LOCALHOST,
            dns_port,
            lookup_port,
            reinject_port,
            plain_dns_peers: Vec::new(),
            reject_unbound_dns: false,
            lookup_auth,
            reinject_auth,
            policy_resolver: None,
            resolved_direct_auth: None,
        })
    }

    pub fn lookup_auth(&self) -> &ProbeCredentials {
        &self.lookup_auth
    }

    pub fn reinject_auth(&self) -> &ProbeCredentials {
        &self.reinject_auth
    }

    /// Отдельная SOCKS-учётная запись для TCP-соединения с одним DNS-сервером.
    pub fn with_policy_resolver(mut self, endpoint: SocketAddr) -> Result<Self, CompileError> {
        let ip = endpoint.ip();
        if endpoint.port() == 0
            || matches!(endpoint, SocketAddr::V6(address)
                if address.scope_id() != 0 || address.flowinfo() != 0 || address.ip().to_ipv4().is_some())
            || !valid_plain_dns_peer(ip)
            || ip == self.dns_address
            || self.pools.iter().any(|pool| pool.contains(ip))
        {
            return Err(CompileError::InvalidParameter);
        }
        let auth = ProbeCredentials::random().map_err(|_| CompileError::InvalidParameter)?;
        self.policy_resolver = Some((endpoint, auth));
        Ok(self)
    }

    /// Пароль берётся из credentials, имя фиксировано в POLICY_RESOLVER_USERNAME.
    pub fn policy_resolver(&self) -> Option<(SocketAddr, &ProbeCredentials)> {
        self.policy_resolver
            .as_ref()
            .map(|(endpoint, auth)| (*endpoint, auth))
    }

    /// Разрешает host передавать предварительно классифицированные буквальные IP.
    pub fn with_resolved_cidr_policy(mut self) -> Result<Self, CompileError> {
        if self.policy_resolver.is_none() {
            return Err(CompileError::InvalidParameter);
        }
        let auth = ProbeCredentials::random().map_err(|_| CompileError::InvalidParameter)?;
        self.resolved_direct_auth = Some(auth);
        Ok(self)
    }

    /// Пароль для отдельной учётной записи с именем RESOLVED_DIRECT_USERNAME.
    pub fn resolved_direct_auth(&self) -> Option<&ProbeCredentials> {
        self.resolved_direct_auth.as_ref()
    }

    /// Принимает только публичный профиль с непустой политикой по CIDR.
    pub fn supports_resolved_cidr_policy(policy: &Policy) -> bool {
        if !supports_public_fake_dns_policy(policy) {
            return false;
        }
        let mut rules = enabled_rules(policy).peekable();
        rules.peek().is_some()
            && rules.all(|rule| {
                !rule.conditions.destinations.is_empty() && rule.conditions.domains.is_empty()
            })
    }

    pub fn reinject_endpoint(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.loopback, self.reinject_port.get())
    }

    pub fn helper_endpoints(&self) -> [SocketAddrV4; 2] {
        [
            SocketAddrV4::new(self.loopback, self.dns_port.get()),
            SocketAddrV4::new(self.loopback, self.lookup_port.get()),
        ]
    }

    /// Адрес отдельно защищает host своим сетевым правилом до запуска служб.
    pub fn with_isolated_loopback(mut self, address: Ipv4Addr) -> Result<Self, CompileError> {
        if !address.is_loopback()
            || address == Ipv4Addr::LOCALHOST
            || address.octets() == [127, 255, 255, 255]
            || address.octets() == [127, 0, 0, 0]
        {
            return Err(CompileError::InvalidParameter);
        }
        self.loopback = address;
        Ok(self)
    }

    /// Маршрутизирует запросы на порт 53 через локальные обработчики DNS.
    pub fn with_plain_dns_peers(
        self,
        peers: Vec<(IpAddr, NonZeroU16)>,
    ) -> Result<Self, CompileError> {
        if peers.len() > Self::MAX_PLAIN_DNS_PEERS {
            return Err(CompileError::InvalidParameter);
        }
        self.with_plain_dns_endpoints(
            peers
                .into_iter()
                .map(|(address, port)| (SocketAddr::new(address, DNS_PORT), port))
                .collect(),
        )
    }

    /// Маршрутизирует TCP и UDP из system-tun по точным IP и порту назначения.
    /// Для каждого назначения выделяется отдельный порт на IPv4 loopback.
    pub fn with_plain_dns_endpoints(
        mut self,
        endpoints: Vec<(SocketAddr, NonZeroU16)>,
    ) -> Result<Self, CompileError> {
        if endpoints.len() > Self::MAX_PLAIN_DNS_PEERS {
            return Err(CompileError::InvalidParameter);
        }
        let mut typed: Vec<PlainDnsPeer> = Vec::with_capacity(endpoints.len());
        for (endpoint, loopback_port) in endpoints {
            let address = endpoint.ip();
            if endpoint.port() == 0
                || matches!(endpoint, SocketAddr::V6(address) if address.scope_id() != 0)
                || !valid_plain_dns_peer(address)
                || address == self.dns_address
                || self.pools.iter().any(|pool| pool.contains(address))
            {
                return Err(CompileError::InvalidParameter);
            }
            // Правила обоих ядер сопоставляют только IP и порт.
            let endpoint = SocketAddr::new(address, endpoint.port());
            if typed.iter().any(|existing| existing.endpoint == endpoint) {
                return Err(CompileError::InvalidParameter);
            }
            if [self.dns_port, self.lookup_port, self.reinject_port].contains(&loopback_port)
                || typed
                    .iter()
                    .any(|existing| existing.loopback_port == loopback_port)
            {
                return Err(CompileError::ListenerConflict);
            }
            typed.push(PlainDnsPeer {
                endpoint,
                loopback_port,
            });
        }
        self.plain_dns_peers = typed;
        Ok(self)
    }

    pub fn reject_unbound_system_dns(mut self) -> Self {
        self.reject_unbound_dns = true;
        self
    }
}

fn valid_plain_dns_peer(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip == Ipv4Addr::BROADCAST
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 169 && octets[1] == 254))
        }
        IpAddr::V6(ip) => {
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some())
        }
    }
}

fn reserved_prefix(address: IpAddr) -> Option<u8> {
    match address {
        IpAddr::V4(ip) if ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19) => Some(15),
        IpAddr::V6(ip) if ip.octets()[0] == 0xfd => Some(8),
        _ => None,
    }
}

/// Начальный профиль Fake DNS с направлением именных потоков в выбранный
/// прокси. Нативные генераторы Fake-IP ядер при этом не используются.
pub fn compile_system_fake_dns_bridge(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    tun: &SystemTun,
    bridge: &SystemFakeDnsBridge,
) -> Result<CompiledConfig, CompileError> {
    validate_bridge(server, port, tun, bridge)?;
    attach_fake_dns(
        compile(server, engine, port)?,
        tun,
        bridge,
        ScopedFakePolicy::ProxyOnly,
    )
}

fn validate_bridge(
    server: &ParsedServer,
    port: NonZeroU16,
    tun: &SystemTun,
    bridge: &SystemFakeDnsBridge,
) -> Result<(), CompileError> {
    let remote: IpAddr = server
        .endpoint()
        .host()
        .parse()
        .map_err(|_| CompileError::InvalidParameter)?;
    if remote.is_loopback()
        || bridge.dns_address == remote
        || bridge.pools.iter().any(|pool| pool.contains(remote))
        || bridge
            .plain_dns_peers
            .iter()
            .any(|peer| same_ip_address(peer.endpoint.ip(), remote))
        || bridge.policy_resolver().is_some_and(|(endpoint, _)| {
            same_ip_address(endpoint.ip(), remote)
                || tun
                    .addresses
                    .iter()
                    .any(|address| same_ip_address(endpoint.ip(), address.address))
        })
        || tun.addresses.iter().any(|address| {
            address.address == bridge.dns_address
                || bridge
                    .pools
                    .iter()
                    .any(|pool| pool.contains(address.address))
        })
    {
        return Err(CompileError::InvalidParameter);
    }
    if [bridge.dns_port, bridge.lookup_port, bridge.reinject_port].contains(&port)
        || bridge
            .plain_dns_peers
            .iter()
            .any(|peer| peer.loopback_port == port)
    {
        return Err(CompileError::ListenerConflict);
    }
    Ok(())
}

fn attach_fake_dns(
    mut config: CompiledConfig,
    tun: &SystemTun,
    bridge: &SystemFakeDnsBridge,
    mode: ScopedFakePolicy<'_>,
) -> Result<CompiledConfig, CompileError> {
    let engine = config.engine;
    let pools: Vec<_> = bridge.pools.iter().map(ToString::to_string).collect();
    let dns_prefix = format!(
        "{}/{}",
        bridge.dns_address,
        if bridge.dns_address.is_ipv4() {
            32
        } else {
            128
        },
    );
    let local = bridge.loopback.to_string();
    let dns_port = bridge.dns_port.get();
    let lookup_port = bridge.lookup_port.get();
    let reinject_port = bridge.reinject_port.get();
    let (lookup, reinject) = (&bridge.lookup_auth, &bridge.reinject_auth);
    let policy_username = SystemFakeDnsBridge::POLICY_RESOLVER_USERNAME;
    let direct_username = SystemFakeDnsBridge::RESOLVED_DIRECT_USERNAME;
    // Host уже применил порядок user/preset к всему DNS-ответу. Здесь
    // независимо ограничиваем адреса, разрешённые для учётной записи Direct.
    let direct_cidrs: Vec<_> = match mode {
        ScopedFakePolicy::ResolvedCidr { policy, .. } => enabled_rules(policy)
            .filter(|rule| rule.action == Action::Direct)
            .flat_map(|rule| &rule.conditions.destinations)
            .map(ToString::to_string)
            .collect(),
        _ => Vec::new(),
    };

    let (inbound, dns, socks) = match engine {
        Engine::Xray => {
            let mut rules = Vec::with_capacity(bridge.plain_dns_peers.len() + 8);
            let mut accounts = vec![json!({"user":reinject.username(),"pass":reinject.password()})];
            if let Some((endpoint, auth)) = bridge.policy_resolver() {
                accounts.push(json!({"user":policy_username,"pass":auth.password()}));
                rules.extend([
                    json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[policy_username],
                        "ip":[ip_prefix(endpoint.ip())],"port":endpoint.port().to_string(),
                        "network":"tcp","outboundTag":"proxy"}),
                    json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[policy_username],
                        "outboundTag":"fake-dns-reject"}),
                ]);
            }
            for (index, peer) in bridge.plain_dns_peers.iter().enumerate() {
                rules.push(json!({
                    "type":"field",
                    "inboundTag":["system-tun"],
                    "ip":[ip_prefix(peer.endpoint.ip())],
                    "port":peer.endpoint.port().to_string(),
                    "network":"tcp,udp",
                    "outboundTag":plain_dns_tag(index),
                }));
            }
            rules.extend([
                json!({"type":"field", "inboundTag":["system-tun"], "ip":[dns_prefix],
                    "port":53, "network":"tcp,udp", "outboundTag":"fake-dns-stub"}),
                json!({"type":"field", "inboundTag":["system-tun"], "ip":[dns_prefix],
                    "outboundTag":"fake-dns-reject"}),
            ]);
            if bridge.reject_unbound_dns {
                rules.push(json!({"type":"field", "inboundTag":["system-tun"],
                    "port":"53", "network":"tcp,udp", "outboundTag":"fake-dns-reject"}));
            }
            rules.extend([
                json!({"type":"field", "inboundTag":["system-tun"], "ip":pools,
                    "outboundTag":"fake-ip-lookup"}),
                json!({"type":"field", "inboundTag":["system-tun"], "ip":LINK_SCOPED_DESTINATIONS,
                    "outboundTag":"fake-dns-reject"}),
            ]);
            match mode {
                ScopedFakePolicy::ProxyOnly => rules.push(json!({"type":"field", "inboundTag":["fake-ip-reinject"], "outboundTag":"proxy"})),
                ScopedFakePolicy::NamesAndLiteral => rules.push(json!({"type":"field", "inboundTag":["fake-ip-reinject"],
                    "domain":[format!("full:{SYSTEM_FAKE_DNS_PROBE_NAME}")], "outboundTag":"fake-dns-reject"})),
                ScopedFakePolicy::ResolvedCidr { direct_auth, .. } => {
                    accounts.push(json!({"user":direct_username,"pass":direct_auth.password()}));
                    rules.push(json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[reinject.username()],
                        "ip":LITERAL_DESTINATIONS,"outboundTag":"proxy"}));
                    if !direct_cidrs.is_empty() {
                        rules.push(json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[direct_username],
                            "ip":direct_cidrs,"outboundTag":"direct"}));
                    }
                    rules.push(json!({"type":"field","inboundTag":["fake-ip-reinject"],"outboundTag":"fake-dns-reject"}));
                }
                ScopedFakePolicy::Names => {}
            }
            if config.value.get("routing").is_none() {
                config.value["routing"] = json!({"domainStrategy":"AsIs"});
            }
            prepend_rules(&mut config.value["routing"]["rules"], rules)?;
            config.value["outbounds"]
                .as_array_mut()
                .ok_or(CompileError::InvalidParameter)?
                .push(json!({"tag":"fake-dns-reject","protocol":"blackhole"}));
            (
                json!({"tag":"fake-ip-reinject","protocol":"socks","listen":local,"port":reinject_port,
                    "settings":{"auth":"password","udp":true,"ip":local,
                    "accounts":accounts}}),
                json!({"tag":"fake-dns-stub","protocol":"freedom","settings":{
                    "redirect":format!("{local}:{dns_port}"),
                    "finalRules":[{"action":"allow","ip":[format!("{local}/32")],"port":dns_port.to_string()}]
                }}),
                json!({"tag":"fake-ip-lookup","protocol":"socks","settings":{"servers":[{
                    "address":local,"port":lookup_port,
                    "users":[{"user":lookup.username(),"pass":lookup.password()}]
                }]}}),
            )
        }
        Engine::SingBox => {
            let mut rules = Vec::with_capacity(bridge.plain_dns_peers.len() + 8);
            let mut users =
                vec![json!({"username":reinject.username(),"password":reinject.password()})];
            if let Some((endpoint, auth)) = bridge.policy_resolver() {
                users.push(json!({"username":policy_username,"password":auth.password()}));
                rules.extend([
                    json!({"inbound":["fake-ip-reinject"],"auth_user":[policy_username],
                        "ip_cidr":[ip_prefix(endpoint.ip())],"port":[endpoint.port()],"network":["tcp"],
                        "action":"route","outbound":"proxy"}),
                    json!({"inbound":["fake-ip-reinject"],"auth_user":[policy_username],
                        "action":"reject"}),
                ]);
            }
            for peer in &bridge.plain_dns_peers {
                rules.push(json!({
                    "inbound":["system-tun"],
                    "ip_cidr":[ip_prefix(peer.endpoint.ip())],
                    "port":[peer.endpoint.port()],
                    "network":["tcp","udp"],
                    "action":"route",
                    "outbound":"fake-dns-stub",
                    "override_address":local,
                    "override_port":peer.loopback_port.get(),
                }));
            }
            rules.extend([
                json!({
                    "inbound":["system-tun"],"ip_cidr":[dns_prefix],"port":[53],
                    "network":["tcp","udp"],"action":"route","outbound":"fake-dns-stub",
                    "override_address":local,"override_port":dns_port
                }),
                json!({"inbound":["system-tun"],"ip_cidr":[dns_prefix],"action":"reject"}),
            ]);
            if bridge.reject_unbound_dns {
                rules.push(json!({"inbound":["system-tun"],"port":[53],
                    "network":["tcp","udp"],"action":"reject"}));
            }
            rules.extend([
                json!({"inbound":["system-tun"],"ip_cidr":pools,"action":"route","outbound":"fake-ip-lookup"}),
                json!({"inbound":["system-tun"],"ip_cidr":LINK_SCOPED_DESTINATIONS,"action":"reject"}),
            ]);
            match mode {
                ScopedFakePolicy::ProxyOnly => rules.push(
                    json!({"inbound":["fake-ip-reinject"],"action":"route","outbound":"proxy"}),
                ),
                ScopedFakePolicy::NamesAndLiteral => rules
                    .push(json!({"inbound":["fake-ip-reinject"],
                    "domain":[SYSTEM_FAKE_DNS_PROBE_NAME], "action":"reject"})),
                ScopedFakePolicy::ResolvedCidr { direct_auth, .. } => {
                    users.push(
                        json!({"username":direct_username,"password":direct_auth.password()}),
                    );
                    rules.push(
                        json!({"inbound":["fake-ip-reinject"],"auth_user":[reinject.username()],
                        "ip_cidr":LITERAL_DESTINATIONS,"action":"route","outbound":"proxy"}),
                    );
                    if !direct_cidrs.is_empty() {
                        rules.push(
                            json!({"inbound":["fake-ip-reinject"],"auth_user":[direct_username],
                            "ip_cidr":direct_cidrs,"action":"route","outbound":"direct"}),
                        );
                    }
                    rules.push(json!({"inbound":["fake-ip-reinject"],"action":"reject"}));
                }
                ScopedFakePolicy::Names => {}
            }
            prepend_rules(&mut config.value["route"]["rules"], rules)?;
            (
                json!({"type":"socks","tag":"fake-ip-reinject","listen":local,"listen_port":reinject_port,
                    "users":users}),
                json!({"type":"direct","tag":"fake-dns-stub"}),
                json!({"type":"socks","tag":"fake-ip-lookup","server":local,"server_port":lookup_port,
                    "version":"5","username":lookup.username(),"password":lookup.password()}),
            )
        }
    };
    config.value["inbounds"]
        .as_array_mut()
        .ok_or(CompileError::InvalidParameter)?
        .push(inbound);
    config.value["outbounds"]
        .as_array_mut()
        .ok_or(CompileError::InvalidParameter)?
        .extend([dns, socks]);
    if engine == Engine::Xray {
        let outbounds = config.value["outbounds"]
            .as_array_mut()
            .ok_or(CompileError::InvalidParameter)?;
        for (index, peer) in bridge.plain_dns_peers.iter().enumerate() {
            let local_port = peer.loopback_port.get();
            outbounds.push(json!({
                "tag":plain_dns_tag(index),
                "protocol":"freedom",
                "settings":{
                    "redirect":format!("{local}:{local_port}"),
                    "finalRules":[
                        {"action":"allow","network":"tcp,udp","ip":[format!("{local}/32")],
                         "port":local_port.to_string()},
                        {"action":"block"}
                    ]
                }
            }));
        }
    }
    attach(config, tun)
}

fn prepend_rules(target: &mut Value, rules: Vec<Value>) -> Result<(), CompileError> {
    if target.is_null() {
        *target = Value::Array(rules);
    } else {
        target
            .as_array_mut()
            .ok_or(CompileError::InvalidParameter)?
            .splice(0..0, rules);
    }
    Ok(())
}

pub fn validate_scoped_fake_dns_policy(
    policy: &Policy,
    suffixes: &[String],
) -> Result<(), PolicyCompileError> {
    scoped_fake_dns_policy_mode(policy, suffixes).map(|_| ())
}

fn enabled_rules(policy: &Policy) -> impl Iterator<Item = &Rule> {
    policy
        .user_rules
        .iter()
        .chain(&policy.preset_rules)
        .filter(|rule| rule.enabled)
}

fn supports_public_fake_dns_policy(policy: &Policy) -> bool {
    policy.default_action == Action::Proxy
        && policy.private_networks.is_empty()
        && policy.private_domains.is_empty()
        && policy.lan.is_empty()
        && enabled_rules(policy).all(|rule| {
            rule.conditions.executables.is_empty()
                && rule.conditions.platform_sources.is_empty()
                && !rule.conditions.transport.constrained()
                && (rule.action != Action::Direct
                    || (!rule.conditions.destinations.is_empty()
                        && rule
                            .conditions
                            .destinations
                            .iter()
                            .all(|cidr| cidr.prefix_len() != 0)))
        })
}

fn scoped_fake_dns_policy_mode<'a>(
    policy: &'a Policy,
    suffixes: &[String],
) -> Result<ScopedFakePolicy<'a>, PolicyCompileError> {
    let rules = || enabled_rules(policy);
    if !supports_public_fake_dns_policy(policy) {
        return Err(PolicyCompileError::InvalidPolicy);
    }
    if rules().all(|rule| rule.action == Action::Proxy && rule.conditions.domains.is_empty()) {
        return Ok(ScopedFakePolicy::ProxyOnly);
    }

    // SOCKS reinjection получает каноническое имя из живой Fake-IP записи.
    let suffixes = suffixes
        .iter()
        .map(|suffix| suffix.parse().map(DomainPattern::Suffix))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PolicyCompileError::InvalidPolicy)?;
    if rules().any(|rule| {
        (!rule.conditions.destinations.is_empty() && !rule.conditions.domains.is_empty())
            || (rule.action == Action::Block
                && rule.conditions.domains.is_empty()
                && rule.conditions.destinations.is_empty())
            || rule
                .conditions
                .domains
                .iter()
                .any(|pattern| !suffixes.iter().any(|suffix| suffix.matches(pattern.name())))
    }) {
        return Err(PolicyCompileError::InvalidPolicy);
    }
    if !rules().any(|rule| !rule.conditions.destinations.is_empty()) {
        return Ok(ScopedFakePolicy::Names);
    }
    // Каждая возможная запись для выбранных суффиксов должна получить
    // решение в порядке user/preset до первого правила, которому нужен IP.
    if suffixes.is_empty()
        || suffixes.iter().any(|suffix| {
            !rules()
                .take_while(|rule| rule.conditions.destinations.is_empty())
                .any(|rule| {
                    rule.conditions.domains.is_empty()
                        || rule.conditions.domains.iter().any(|pattern| {
                            matches!(pattern, DomainPattern::Suffix(_))
                                && pattern.matches(suffix.name())
                        })
                })
        })
    {
        return Err(PolicyCompileError::InvalidPolicy);
    }
    Ok(ScopedFakePolicy::NamesAndLiteral)
}

/// Ставит правила транспортировки Fake-IP перед правилами политики.
/// В режиме Names восстановленное имя проходит штатный порядок user/preset/default.
#[allow(clippy::too_many_arguments)]
pub fn compile_system_fake_dns_policy(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    tun: &SystemTun,
    bridge: &SystemFakeDnsBridge,
    suffixes: &[String],
) -> Result<CompiledConfig, PolicyCompileError> {
    let mode = match bridge.resolved_direct_auth() {
        Some(direct_auth) if SystemFakeDnsBridge::supports_resolved_cidr_policy(policy) => {
            ScopedFakePolicy::ResolvedCidr {
                policy,
                direct_auth,
            }
        }
        _ => scoped_fake_dns_policy_mode(policy, suffixes)?,
    };
    if [bridge.dns_port, bridge.lookup_port, bridge.reinject_port].contains(&probe_port)
        || bridge
            .plain_dns_peers
            .iter()
            .any(|peer| peer.loopback_port == probe_port)
    {
        return Err(crate::PolicyCompileError::ProbePort);
    }

    validate_bridge(server, port, tun, bridge).map_err(crate::PolicyCompileError::Server)?;
    let config = match mode {
        ScopedFakePolicy::ProxyOnly | ScopedFakePolicy::ResolvedCidr { .. } => {
            crate::routing::compile_tun_policy(server, engine, port, probe_port, policy)
        }
        ScopedFakePolicy::Names => crate::routing::compile_policy(
            server,
            engine,
            port,
            probe_port,
            policy,
            PolicyMode::Names,
        ),
        ScopedFakePolicy::NamesAndLiteral => crate::routing::compile_tun_fake_literal_policy(
            server, engine, port, probe_port, policy,
        ),
    }?;
    attach_fake_dns(config, tun, bridge, mode).map_err(PolicyCompileError::Server)
}

fn plain_dns_tag(index: usize) -> String {
    format!("fake-plain-dns-{index}")
}

fn ip_prefix(address: IpAddr) -> String {
    format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 })
}

fn same_ip_address(left: IpAddr, right: IpAddr) -> bool {
    left == right
        || matches!(
            (left, right),
            (IpAddr::V4(v4), IpAddr::V6(v6)) | (IpAddr::V6(v6), IpAddr::V4(v4))
                if v6.to_ipv4_mapped() == Some(v4)
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn empty_bridge() -> SystemFakeDnsBridge {
        SystemFakeDnsBridge::new(
            "198.18.0.2".parse().unwrap(),
            vec![
                "198.18.4.0/24".parse().unwrap(),
                "fd10::/112".parse().unwrap(),
            ],
            port(12553),
            port(12554),
            port(12555),
        )
        .unwrap()
    }

    fn cidr_rule(id: u64, action: Action, destination: &str) -> yonik_domain::Rule {
        yonik_domain::Rule {
            id,
            enabled: true,
            action,
            conditions: yonik_domain::Conditions {
                destinations: vec![destination.parse().unwrap()],
                ..Default::default()
            },
        }
    }

    #[test]
    fn resolved_cidr_mode_requires_nonempty_public_cidr_only_policy_and_resolver() {
        let supports = SystemFakeDnsBridge::supports_resolved_cidr_policy;
        let mut policy = Policy::default();
        assert!(!supports(&policy));
        policy
            .user_rules
            .push(cidr_rule(1, Action::Direct, "8.8.8.0/24"));
        assert!(supports(&policy));
        policy
            .preset_rules
            .push(cidr_rule(2, Action::Block, "::/0"));
        assert!(supports(&policy));
        policy.preset_rules[0].action = Action::Direct;
        assert!(!supports(&policy));
        policy.preset_rules[0].action = Action::Block;
        policy.preset_rules[0].conditions.domains =
            vec![DomainPattern::Exact("example.test".parse().unwrap())];
        assert!(!supports(&policy));
        policy.preset_rules[0].conditions.domains.clear();
        policy.preset_rules[0].conditions.destinations.clear();
        assert!(!supports(&policy));
        policy.preset_rules[0].enabled = false;
        assert!(supports(&policy));
        policy.user_rules[0]
            .conditions
            .executables
            .push("/bin/browser".into());
        assert!(!supports(&policy));
        policy.user_rules[0].conditions.executables.clear();
        policy.user_rules[0].conditions.platform_sources =
            vec![yonik_domain::PlatformSource::AndroidPackage {
                package: yonik_domain::AndroidPackageId::parse("example.browser").unwrap(),
            }];
        assert!(!supports(&policy));
        policy.user_rules[0].conditions.platform_sources.clear();
        policy.user_rules[0].conditions.transport =
            yonik_domain::TransportConditions::parse(Some(&["tcp"]), None).unwrap();
        assert!(!supports(&policy));
        policy.user_rules[0].conditions.transport = Default::default();
        policy.lan.push("192.168.0.0/16".parse().unwrap());
        assert!(!supports(&policy));
        policy.lan.clear();
        policy.default_action = Action::Direct;
        assert!(!supports(&policy));

        assert!(empty_bridge().resolved_direct_auth().is_none());
        assert!(matches!(
            empty_bridge().with_resolved_cidr_policy(),
            Err(CompileError::InvalidParameter)
        ));
    }

    #[test]
    fn resolved_cidr_reinject_routes_only_authorized_literal_destinations() {
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let server = &imported.servers[0];
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let bridge = empty_bridge()
            .with_policy_resolver("192.0.2.53:1053".parse().unwrap())
            .unwrap();
        let direct_policy = Policy {
            user_rules: vec![
                cidr_rule(1, Action::Block, "8.8.8.8/32"),
                cidr_rule(2, Action::Direct, "8.8.8.0/24"),
                cidr_rule(3, Action::Proxy, "1.1.1.0/24"),
            ],
            preset_rules: vec![cidr_rule(4, Action::Direct, "2606:4700::/32")],
            ..Default::default()
        };
        let compile_for = |engine, policy: &Policy, bridge: &SystemFakeDnsBridge| {
            compile_system_fake_dns_policy(
                server,
                engine,
                port(12556),
                port(12552),
                policy,
                &tun,
                bridge,
                &["example.test".into()],
            )
        };
        assert!(matches!(
            compile_for(Engine::Xray, &direct_policy, &bridge),
            Err(PolicyCompileError::InvalidPolicy)
        ));
        let bridge = bridge.with_resolved_cidr_policy().unwrap();
        let direct_user = SystemFakeDnsBridge::RESOLVED_DIRECT_USERNAME;
        let proxy_user = bridge.reinject_auth().username();
        let (resolver, resolver_auth) = bridge.policy_resolver().unwrap();
        let resolver_user = SystemFakeDnsBridge::POLICY_RESOLVER_USERNAME;
        let direct_auth = bridge.resolved_direct_auth().unwrap();
        assert_ne!(direct_user, proxy_user);
        assert_ne!(direct_user, resolver_user);
        assert!(direct_auth.password() != bridge.reinject_auth().password());
        assert!(direct_auth.password() != resolver_auth.password());
        assert!(direct_auth.password() != bridge.lookup_auth().password());

        let block_policy = Policy {
            user_rules: vec![cidr_rule(1, Action::Block, "0.0.0.0/0")],
            ..Default::default()
        };
        for engine in [Engine::Xray, Engine::SingBox] {
            let (
                routing,
                ingress,
                cidrs,
                users_path,
                user_key,
                password_key,
                allow_dns,
                reject_dns,
                allow_proxy,
                allow_direct,
                reject_reinject,
            ) = match engine {
                Engine::Xray => (
                    "routing",
                    "inboundTag",
                    "ip",
                    "/settings/accounts",
                    "user",
                    "pass",
                    json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[resolver_user],
                        "ip":["192.0.2.53/32"],"port":resolver.port().to_string(),"network":"tcp","outboundTag":"proxy"}),
                    json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[resolver_user],"outboundTag":"fake-dns-reject"}),
                    json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[proxy_user],
                        "ip":["0.0.0.0/0","::/0"],"outboundTag":"proxy"}),
                    json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[direct_user],
                        "ip":["8.8.8.0/24","2606:4700::/32"],"outboundTag":"direct"}),
                    json!({"type":"field","inboundTag":["fake-ip-reinject"],"outboundTag":"fake-dns-reject"}),
                ),
                Engine::SingBox => (
                    "route",
                    "inbound",
                    "ip_cidr",
                    "/users",
                    "username",
                    "password",
                    json!({"inbound":["fake-ip-reinject"],"auth_user":[resolver_user],
                        "ip_cidr":["192.0.2.53/32"],"port":[resolver.port()],"network":["tcp"],"action":"route","outbound":"proxy"}),
                    json!({"inbound":["fake-ip-reinject"],"auth_user":[resolver_user],"action":"reject"}),
                    json!({"inbound":["fake-ip-reinject"],"auth_user":[proxy_user],
                        "ip_cidr":["0.0.0.0/0","::/0"],"action":"route","outbound":"proxy"}),
                    json!({"inbound":["fake-ip-reinject"],"auth_user":[direct_user],
                        "ip_cidr":["8.8.8.0/24","2606:4700::/32"],"action":"route","outbound":"direct"}),
                    json!({"inbound":["fake-ip-reinject"],"action":"reject"}),
                ),
            };
            for (policy, has_direct) in [(&direct_policy, true), (&block_policy, false)] {
                let compiled = compile_for(engine, policy, &bridge).unwrap().value;
                let rules = compiled[routing]["rules"].as_array().unwrap();
                let reinject_rules: Vec<_> = rules
                    .iter()
                    .filter(|rule| rule[ingress] == json!(["fake-ip-reinject"]))
                    .cloned()
                    .collect();
                let mut expected = vec![allow_dns.clone(), reject_dns.clone(), allow_proxy.clone()];
                if has_direct {
                    expected.push(allow_direct.clone());
                }
                expected.push(reject_reinject.clone());
                assert_eq!(reinject_rules, expected);
                assert_eq!(&rules[..2], &expected[..2]);
                let reject_index = rules
                    .iter()
                    .position(|rule| rule == &reject_reinject)
                    .unwrap();
                let literal_index = rules
                    .iter()
                    .position(|rule| {
                        rule[cidrs]
                            == json!([policy.user_rules[0].conditions.destinations[0].to_string()])
                    })
                    .unwrap();
                assert!(reject_index < literal_index);
                let baseline = crate::routing::compile_tun_policy(
                    server,
                    engine,
                    port(12556),
                    port(12552),
                    policy,
                )
                .unwrap();
                assert_eq!(
                    &rules[reject_index + 1..],
                    baseline.value[routing]["rules"].as_array().unwrap()
                );

                let users = compiled["inbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|inbound| inbound["tag"] == "fake-ip-reinject")
                    .unwrap()
                    .pointer(users_path)
                    .unwrap()
                    .as_array()
                    .unwrap();
                assert_eq!(users.len(), 3);
                for (user, (name, password)) in users.iter().zip([
                    (proxy_user, bridge.reinject_auth().password()),
                    (resolver_user, resolver_auth.password()),
                    (direct_user, direct_auth.password()),
                ]) {
                    assert_eq!(user[user_key], name);
                    assert!(user[password_key] == password);
                }
            }
        }
    }

    #[test]
    fn policy_resolver_routes_only_exact_tcp_destination_before_legacy_rules() {
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let legacy = empty_bridge().reject_unbound_system_dns();
        assert!(legacy.policy_resolver().is_none());
        for (server, prefix) in [
            ("192.0.2.53:1053", "192.0.2.53/32"),
            ("[2001:db8::53]:1053", "2001:db8::53/128"),
        ] {
            let endpoint = server.parse().unwrap();
            let bridge = empty_bridge()
                .reject_unbound_system_dns()
                .with_policy_resolver(endpoint)
                .unwrap();
            let (stored_endpoint, auth) = bridge.policy_resolver().unwrap();
            assert_eq!(stored_endpoint, endpoint);
            assert!(auth.password() != bridge.reinject_auth().password());
            assert!(auth.password() != bridge.lookup_auth().password());
            let username = SystemFakeDnsBridge::POLICY_RESOLVER_USERNAME;
            let policy = Policy::default();
            for engine in [Engine::Xray, Engine::SingBox] {
                let config_for = |bridge| {
                    compile_system_fake_dns_policy(
                        &imported.servers[0],
                        engine,
                        port(12556),
                        port(12552),
                        &policy,
                        &tun,
                        bridge,
                        &[],
                    )
                    .unwrap()
                    .value
                };
                let (config, legacy_config) = (config_for(&bridge), config_for(&legacy));
                let (rules_path, users_path, username_key, password_key, allow, reject) =
                    match engine {
                        Engine::Xray => (
                            "/routing/rules",
                            "/settings/accounts",
                            "user",
                            "pass",
                            json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[username],
                            "ip":[prefix],"port":"1053","network":"tcp","outboundTag":"proxy"}),
                            json!({"type":"field","inboundTag":["fake-ip-reinject"],"user":[username],
                            "outboundTag":"fake-dns-reject"}),
                        ),
                        Engine::SingBox => (
                            "/route/rules",
                            "/users",
                            "username",
                            "password",
                            json!({"inbound":["fake-ip-reinject"],"auth_user":[username],
                            "ip_cidr":[prefix],"port":[1053],"network":["tcp"],
                            "action":"route","outbound":"proxy"}),
                            json!({"inbound":["fake-ip-reinject"],"auth_user":[username],
                            "action":"reject"}),
                        ),
                    };
                let rules = config.pointer(rules_path).unwrap().as_array().unwrap();
                let legacy_rules = legacy_config
                    .pointer(rules_path)
                    .unwrap()
                    .as_array()
                    .unwrap();
                assert_eq!(rules[0], allow);
                assert_eq!(rules[1], reject);
                assert_eq!(&rules[2..], legacy_rules.as_slice());

                for (compiled, expected_count, reinject_auth) in [
                    (&config, 2, bridge.reinject_auth()),
                    (&legacy_config, 1, legacy.reinject_auth()),
                ] {
                    let users = compiled["inbounds"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|inbound| inbound["tag"] == "fake-ip-reinject")
                        .unwrap()
                        .pointer(users_path)
                        .unwrap()
                        .as_array()
                        .unwrap();
                    assert_eq!(users.len(), expected_count);
                    assert_eq!(users[0][username_key], reinject_auth.username());
                    assert!(users[0][password_key] == reinject_auth.password());
                    if let Some(account) = users.get(1) {
                        assert_eq!(account[username_key], username);
                        assert!(account[password_key] == auth.password());
                    }
                }
            }
        }
    }

    #[test]
    fn policy_resolver_rejects_unusable_and_reserved_destinations() {
        for invalid in [
            "192.0.2.53:0",
            "0.0.0.0:53",
            "127.0.1.2:53",
            "169.254.1.2:53",
            "224.0.0.1:53",
            "255.255.255.255:53",
            "[::]:53",
            "[::1]:53",
            "[::192.0.2.53]:53",
            "[::ffff:192.0.2.53]:53",
            "[fe80::53]:53",
            "[ff02::53]:53",
            "[2001:db8::53%3]:53",
            "198.18.0.2:53",
            "198.18.4.1:53",
            "[fd10::53]:53",
        ] {
            assert!(matches!(
                empty_bridge().with_policy_resolver(invalid.parse().unwrap()),
                Err(CompileError::InvalidParameter)
            ));
        }
    }

    #[test]
    fn policy_resolver_rejects_proxy_and_system_tun_addresses_even_on_other_ports() {
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        for endpoint in ["10.203.0.2:53", "198.18.0.1:53"] {
            let bridge = empty_bridge()
                .with_policy_resolver(endpoint.parse().unwrap())
                .unwrap();
            for engine in [Engine::Xray, Engine::SingBox] {
                assert!(matches!(
                    compile_system_fake_dns_policy(
                        &imported.servers[0],
                        engine,
                        port(12556),
                        port(12552),
                        &Policy::default(),
                        &tun,
                        &bridge,
                        &[],
                    ),
                    Err(PolicyCompileError::Server(CompileError::InvalidParameter))
                ));
            }
        }
    }

    #[test]
    fn dns_and_reverse_routes_are_scoped_to_tun_and_reinjection_cannot_loop() {
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let bridge = SystemFakeDnsBridge::new(
            "198.18.0.2".parse().unwrap(),
            vec![
                "198.18.4.0/24".parse().unwrap(),
                "fd10::/112".parse().unwrap(),
            ],
            port(12553),
            port(12554),
            port(12555),
        )
        .unwrap();
        assert_ne!(
            bridge.lookup_auth().password(),
            bridge.reinject_auth().password()
        );
        for engine in [Engine::Xray, Engine::SingBox] {
            let c = compile_system_fake_dns_bridge(
                &imported.servers[0],
                engine,
                port(12556),
                &tun,
                &bridge,
            )
            .unwrap();
            let (rules, inbound, outbound, prefixes) = match engine {
                Engine::Xray => (
                    &c.value["routing"]["rules"],
                    "inboundTag",
                    "outboundTag",
                    "ip",
                ),
                Engine::SingBox => (&c.value["route"]["rules"], "inbound", "outbound", "ip_cidr"),
            };
            assert_eq!(rules.as_array().unwrap().len(), 5);
            assert_eq!(rules[0][inbound], json!(["system-tun"]));
            assert_eq!(rules[0][outbound], "fake-dns-stub");
            assert_eq!(rules[1][inbound], json!(["system-tun"]));
            assert_eq!(rules[2][inbound], json!(["system-tun"]));
            assert_eq!(rules[2][outbound], "fake-ip-lookup");
            assert_eq!(rules[3][inbound], json!(["system-tun"]));
            assert_eq!(rules[3][prefixes], json!(LINK_SCOPED_DESTINATIONS));
            assert_eq!(rules[4][inbound], json!(["fake-ip-reinject"]));
            assert_eq!(rules[4][outbound], "proxy");
            assert_eq!(c.value["inbounds"][1]["listen"], "127.0.0.1");
            let lookup = c.value["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|outbound| outbound["tag"] == "fake-ip-lookup")
                .unwrap();
            let mark = match engine {
                Engine::Xray => &lookup["streamSettings"]["sockopt"]["mark"],
                Engine::SingBox => &lookup["routing_mark"],
            };
            assert_eq!(mark, 99);
        }
    }

    #[test]
    fn rejects_overlap_public_pools_and_listener_port_conflicts() {
        for pool in ["198.18.0.0/24", "0.0.0.0/0", "fe80::/64", "192.0.2.0/24"] {
            assert!(
                SystemFakeDnsBridge::new(
                    "198.18.0.2".parse().unwrap(),
                    vec![pool.parse().unwrap()],
                    port(1001),
                    port(1002),
                    port(1003),
                )
                .is_err()
            );
        }
        assert!(matches!(
            SystemFakeDnsBridge::new(
                "198.18.0.2".parse().unwrap(),
                vec!["fd10::/112".parse().unwrap()],
                port(1001),
                port(1001),
                port(1003),
            ),
            Err(CompileError::ListenerConflict)
        ));
    }

    #[test]
    fn plain_dns_endpoints_are_exactly_routed_to_isolated_loopback_listeners() {
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let peers = vec![
            ("192.0.2.53:1053".parse().unwrap(), port(12557)),
            ("192.0.2.53:53".parse().unwrap(), port(12558)),
            ("[2001:db8::53]:53".parse().unwrap(), port(12559)),
        ];
        let bridge = SystemFakeDnsBridge::new(
            "198.18.0.2".parse().unwrap(),
            vec![
                "198.18.4.0/24".parse().unwrap(),
                "fd10::/112".parse().unwrap(),
            ],
            port(12553),
            port(12554),
            port(12555),
        )
        .unwrap()
        .with_isolated_loopback("127.42.7.9".parse().unwrap())
        .unwrap()
        .with_plain_dns_endpoints(peers.clone())
        .unwrap()
        .reject_unbound_system_dns();

        for engine in [Engine::Xray, Engine::SingBox] {
            let config = compile_system_fake_dns_bridge(
                &imported.servers[0],
                engine,
                port(12556),
                &tun,
                &bridge,
            )
            .unwrap();
            let rules = match engine {
                Engine::Xray => &config.value["routing"]["rules"],
                Engine::SingBox => &config.value["route"]["rules"],
            };
            assert_eq!(rules.as_array().unwrap().len(), peers.len() + 6);
            for (index, (peer, local_port)) in peers.iter().enumerate() {
                let rule = &rules[index];
                let prefix = ip_prefix(peer.ip());
                match engine {
                    Engine::Xray => {
                        let tag = plain_dns_tag(index);
                        assert_eq!(rule["inboundTag"], json!(["system-tun"]));
                        assert_eq!(rule["ip"], json!([prefix]));
                        assert_eq!(rule["port"], peer.port().to_string());
                        assert_eq!(rule["network"], "tcp,udp");
                        assert_eq!(rule["outboundTag"], tag);
                        let outbound = config.value["outbounds"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|outbound| outbound["tag"] == tag)
                            .unwrap();
                        assert_eq!(outbound["protocol"], "freedom");
                        assert_eq!(
                            outbound["settings"]["redirect"],
                            format!("127.42.7.9:{}", local_port)
                        );
                        assert_eq!(
                            outbound["settings"]["finalRules"][0],
                            json!({
                                "action":"allow","network":"tcp,udp","ip":["127.42.7.9/32"],
                                "port":local_port.get().to_string()
                            })
                        );
                        assert_eq!(
                            outbound["settings"]["finalRules"][1],
                            json!({"action":"block"})
                        );
                        assert!(
                            !outbound["settings"]
                                .to_string()
                                .contains(&peer.ip().to_string())
                        );
                    }
                    Engine::SingBox => {
                        assert_eq!(rule["inbound"], json!(["system-tun"]));
                        assert_eq!(rule["ip_cidr"], json!([prefix]));
                        assert_eq!(rule["port"], json!([peer.port()]));
                        assert_eq!(rule["network"], json!(["tcp", "udp"]));
                        assert_eq!(rule["outbound"], "fake-dns-stub");
                        assert_eq!(rule["override_address"], "127.42.7.9");
                        assert_eq!(rule["override_port"], local_port.get());
                        assert!(
                            !config.value["outbounds"]
                                .to_string()
                                .contains(&peer.ip().to_string())
                        );
                    }
                }
            }
            assert_eq!(
                rules[peers.len()][match engine {
                    Engine::Xray => "outboundTag",
                    Engine::SingBox => "outbound",
                }],
                "fake-dns-stub"
            );
            assert_eq!(
                rules[peers.len() + 2],
                match engine {
                    Engine::Xray => json!({"type":"field","inboundTag":["system-tun"],"port":"53",
                        "network":"tcp,udp","outboundTag":"fake-dns-reject"}),
                    Engine::SingBox => json!({"inbound":["system-tun"],"port":[53],
                        "network":["tcp","udp"],"action":"reject"}),
                }
            );
        }
    }

    #[test]
    fn rejects_invalid_plain_dns_endpoints() {
        for endpoint in [
            "192.0.2.53:0",
            "[2001:db8::53%3]:1053",
            "198.18.0.2:1053",
            "198.18.4.1:1053",
        ] {
            assert!(matches!(
                empty_bridge()
                    .with_plain_dns_endpoints(vec![(endpoint.parse().unwrap(), port(12557))]),
                Err(CompileError::InvalidParameter)
            ));
        }
        let endpoint = "192.0.2.53:1053".parse().unwrap();
        assert!(matches!(
            empty_bridge()
                .with_plain_dns_endpoints(vec![(endpoint, port(12557)), (endpoint, port(12558)),]),
            Err(CompileError::InvalidParameter)
        ));
    }

    #[test]
    fn validates_plain_dns_peers_and_listener_collisions() {
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "169.254.1.1",
            "240.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "::ffff:203.0.113.1",
            "198.18.0.2",
            "198.18.4.5",
            "fd10::5",
        ] {
            assert!(
                matches!(
                    empty_bridge()
                        .with_plain_dns_peers(vec![(address.parse().unwrap(), port(12557))]),
                    Err(CompileError::InvalidParameter)
                ),
                "адрес должен быть запрещён: {address}"
            );
        }
        assert!(matches!(
            empty_bridge().with_plain_dns_peers(vec![
                ("1.1.1.1".parse().unwrap(), port(12557)),
                ("1.1.1.1".parse().unwrap(), port(12558)),
            ]),
            Err(CompileError::InvalidParameter)
        ));
        assert!(matches!(
            empty_bridge().with_plain_dns_peers(vec![
                ("1.1.1.1".parse().unwrap(), port(12557)),
                ("8.8.8.8".parse().unwrap(), port(12557)),
            ]),
            Err(CompileError::ListenerConflict)
        ));
        for reserved_port in [port(12553), port(12554), port(12555)] {
            assert!(matches!(
                empty_bridge()
                    .with_plain_dns_peers(vec![("1.1.1.1".parse().unwrap(), reserved_port)]),
                Err(CompileError::ListenerConflict)
            ));
        }
        assert!(
            empty_bridge()
                .with_plain_dns_peers(vec![
                    ("1.1.1.1".parse().unwrap(), port(12557)),
                    ("8.8.8.8".parse().unwrap(), port(12558)),
                    ("9.9.9.9".parse().unwrap(), port(12559)),
                    ("208.67.222.222".parse().unwrap(), port(12560)),
                ])
                .is_ok()
        );
        let too_many = (1..=SystemFakeDnsBridge::MAX_PLAIN_DNS_PEERS as u8 + 1)
            .map(|index| {
                (
                    Ipv4Addr::new(192, 0, 2, index).into(),
                    port(12600 + u16::from(index)),
                )
            })
            .collect();
        assert!(matches!(
            empty_bridge().with_plain_dns_peers(too_many),
            Err(CompileError::InvalidParameter)
        ));
    }

    #[test]
    fn rejects_peer_collision_with_remote_and_base_listener_port() {
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let bridge = SystemFakeDnsBridge::new(
            "198.18.0.2".parse().unwrap(),
            vec![
                "198.18.4.0/24".parse().unwrap(),
                "fd10::/112".parse().unwrap(),
            ],
            port(12553),
            port(12554),
            port(12555),
        )
        .unwrap()
        .with_plain_dns_endpoints(vec![("1.1.1.1:1053".parse().unwrap(), port(12557))])
        .unwrap();
        let server = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@1.1.1.1:24443?security=none".to_vec(),
        )
        .unwrap();
        assert!(matches!(
            compile_system_fake_dns_bridge(
                &server.servers[0],
                Engine::Xray,
                port(12556),
                &tun,
                &bridge,
            ),
            Err(CompileError::InvalidParameter)
        ));

        let server = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        assert!(matches!(
            compile_system_fake_dns_bridge(
                &server.servers[0],
                Engine::SingBox,
                port(12557),
                &tun,
                &bridge,
            ),
            Err(CompileError::ListenerConflict)
        ));
    }

    #[test]
    fn fake_policy_prepends_scoped_rules_and_preserves_ip_policy_rules() {
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let server = &imported.servers[0];
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let bridge = empty_bridge()
            .with_plain_dns_peers(vec![("1.1.1.1".parse().unwrap(), port(12557))])
            .unwrap();
        let mut policy = Policy::default();
        policy.user_rules.push(yonik_domain::Rule {
            id: 10,
            enabled: true,
            conditions: yonik_domain::Conditions {
                destinations: vec!["203.0.113.0/24".parse().unwrap()],
                ..Default::default()
            },
            action: Action::Proxy,
        });

        for engine in [Engine::Xray, Engine::SingBox] {
            let base = crate::routing::compile_tun_policy(
                server,
                engine,
                port(12556),
                port(12552),
                &policy,
            )
            .unwrap();
            let compiled = compile_system_fake_dns_policy(
                server,
                engine,
                port(12556),
                port(12552),
                &policy,
                &tun,
                &bridge,
                &[],
            )
            .unwrap();
            let route_key = if engine == Engine::Xray {
                "routing"
            } else {
                "route"
            };
            let baseline_rules = base.value[route_key]["rules"].as_array().unwrap();
            let actual_rules = compiled.value[route_key]["rules"].as_array().unwrap();
            let injected = bridge.plain_dns_peers.len() + 5;
            assert_eq!(&actual_rules[injected..], baseline_rules);
            assert_eq!(
                actual_rules[0]["inboundTag"].as_array().is_some(),
                engine == Engine::Xray
            );
            assert_eq!(
                actual_rules[0]["port"],
                match engine {
                    Engine::Xray => json!("53"),
                    Engine::SingBox => json!([53]),
                }
            );
            if engine == Engine::Xray {
                assert_eq!(
                    compiled.value["routing"]["domainStrategy"],
                    base.value["routing"]["domainStrategy"]
                );
            } else {
                assert_eq!(
                    compiled.value["route"]["final"],
                    base.value["route"]["final"]
                );
            }
            assert!(
                actual_rules[..injected]
                    .iter()
                    .any(|rule| rule["inboundTag"] == json!(["system-tun"])
                        || rule["inbound"] == json!(["system-tun"]))
            );
        }
    }

    #[test]
    fn fake_domain_policy_keeps_rule_order_after_reinject() {
        use yonik_domain::{Conditions, DomainPattern, Rule};

        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let policy = Policy {
            user_rules: vec![Rule {
                id: 1,
                enabled: true,
                conditions: Conditions {
                    domains: vec![DomainPattern::Exact(
                        "allowed.example.test".parse().unwrap(),
                    )],
                    ..Default::default()
                },
                action: Action::Proxy,
            }],
            preset_rules: vec![Rule {
                id: 2,
                enabled: true,
                conditions: Conditions {
                    domains: vec![DomainPattern::Suffix("example.test".parse().unwrap())],
                    ..Default::default()
                },
                action: Action::Block,
            }],
            ..Default::default()
        };
        for engine in [Engine::Xray, Engine::SingBox] {
            let compiled = compile_system_fake_dns_policy(
                &imported.servers[0],
                engine,
                port(12556),
                port(12552),
                &policy,
                &tun,
                &empty_bridge(),
                &["example.test".to_owned()],
            )
            .unwrap();
            let (rules, inbound, exact, suffix, action, blocked) = match engine {
                Engine::Xray => (
                    &compiled.value["routing"]["rules"],
                    "inboundTag",
                    "domain",
                    "domain",
                    "outboundTag",
                    "block",
                ),
                Engine::SingBox => (
                    &compiled.value["route"]["rules"],
                    "inbound",
                    "domain",
                    "domain_suffix",
                    "action",
                    "reject",
                ),
            };
            let rules = rules.as_array().unwrap();
            assert!(
                !rules
                    .iter()
                    .any(|rule| rule[inbound] == json!(["fake-ip-reinject"]))
            );
            let allow = if engine == Engine::Xray {
                "full:allowed.example.test"
            } else {
                "allowed.example.test"
            };
            let deny = if engine == Engine::Xray {
                "domain:example.test"
            } else {
                "example.test"
            };
            let allow_index = rules
                .iter()
                .position(|rule| rule[exact] == json!([allow]))
                .unwrap();
            let deny_index = rules
                .iter()
                .position(|rule| rule[suffix] == json!([deny]))
                .unwrap();
            assert!(allow_index < deny_index);
            assert_eq!(rules[deny_index][action], blocked);
        }
    }

    #[test]
    fn fake_domain_policy_requires_covered_names_without_real_ip_decisions() {
        use yonik_domain::{Conditions, DomainPattern, Rule};

        let suffixes = ["example.test".to_owned()];
        let mut policy = Policy {
            user_rules: vec![Rule {
                id: 1,
                enabled: true,
                conditions: Conditions {
                    domains: vec![DomainPattern::Suffix("child.example.test".parse().unwrap())],
                    ..Default::default()
                },
                action: Action::Block,
            }],
            ..Default::default()
        };
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_ok());
        assert!(validate_scoped_fake_dns_policy(&policy, &["ample.test".to_owned()]).is_err());
        assert!(
            validate_scoped_fake_dns_policy(&policy, &["child.example..test".to_owned()]).is_err()
        );
        policy.user_rules[0].action = Action::Direct;
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_err());
        policy.user_rules[0].action = Action::Block;
        policy.preset_rules.push(Rule {
            id: 2,
            enabled: true,
            conditions: Conditions {
                destinations: vec!["192.0.2.0/24".parse().unwrap()],
                ..Default::default()
            },
            action: Action::Proxy,
        });
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_err());
        policy.preset_rules[0].enabled = false;
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_ok());
    }

    #[test]
    fn literal_cidr_policy_requires_a_prior_terminal_rule_for_every_fake_suffix() {
        use yonik_domain::{Conditions, DomainPattern, Rule};

        let suffixes = ["example.test".to_owned()];
        let mut policy = Policy {
            user_rules: vec![
                Rule {
                    id: 1,
                    enabled: true,
                    conditions: Conditions {
                        domains: vec![DomainPattern::Suffix("example.test".parse().unwrap())],
                        ..Default::default()
                    },
                    action: Action::Proxy,
                },
                Rule {
                    id: 2,
                    enabled: true,
                    conditions: Conditions {
                        destinations: vec!["192.0.2.0/24".parse().unwrap()],
                        ..Default::default()
                    },
                    action: Action::Block,
                },
            ],
            ..Default::default()
        };
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_ok());
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let bridge = empty_bridge()
            .with_plain_dns_endpoints(vec![("192.0.2.53:1053".parse().unwrap(), port(12557))])
            .unwrap();
        for engine in [Engine::Xray, Engine::SingBox] {
            let config = compile_system_fake_dns_policy(
                &imported.servers[0],
                engine,
                port(12556),
                port(12552),
                &policy,
                &tun,
                &bridge,
                &suffixes,
            )
            .unwrap();
            let (routing, inbound, literal, suffix, name, probe, action, reject) = match engine {
                Engine::Xray => (
                    "routing",
                    "inboundTag",
                    "ip",
                    "domain",
                    "domain:example.test",
                    "full:probe.invalid",
                    "outboundTag",
                    "fake-dns-reject",
                ),
                Engine::SingBox => (
                    "route",
                    "inbound",
                    "ip_cidr",
                    "domain_suffix",
                    "example.test",
                    "probe.invalid",
                    "action",
                    "reject",
                ),
            };
            let rules = config.value[routing]["rules"].as_array().unwrap();
            let index = |key: &str, entry: &str| {
                rules
                    .iter()
                    .position(|rule| rule[key] == json!([entry]))
                    .unwrap()
            };
            let probe = index("domain", probe);
            let named = index(suffix, name);
            let cidr = index(literal, "192.0.2.0/24");
            let resolver = index(literal, "192.0.2.53/32");
            assert!(resolver < probe && probe < named && named < cidr);
            assert_eq!(rules[resolver][inbound], json!(["system-tun"]));
            match engine {
                Engine::Xray => {
                    assert_eq!(rules[resolver]["port"], "1053");
                    assert_eq!(rules[resolver][action], "fake-plain-dns-0");
                }
                Engine::SingBox => {
                    assert_eq!(rules[resolver]["port"], json!([1053]));
                    assert_eq!(rules[resolver][action], "route");
                    assert_eq!(rules[resolver]["override_port"], 12557);
                }
            }
            assert_eq!(rules[probe][inbound], json!(["fake-ip-reinject"]));
            assert_eq!(rules[probe][action], reject);
            assert_eq!(rules[named][inbound], json!(["fake-ip-reinject"]));
            assert_eq!(rules[cidr][inbound], json!(["system-tun"]));
        }
        policy.user_rules[1].action = Action::Direct;
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_ok());
        policy.user_rules[1].conditions.destinations = vec!["0.0.0.0/0".parse().unwrap()];
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_err());
        policy.user_rules[1].conditions.destinations = vec!["192.0.2.0/24".parse().unwrap()];
        policy.user_rules[1].action = Action::Block;
        policy.preset_rules.push(policy.user_rules.pop().unwrap());
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_ok());
        std::mem::swap(&mut policy.user_rules, &mut policy.preset_rules);
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_err());
        std::mem::swap(&mut policy.user_rules, &mut policy.preset_rules);
        policy.user_rules.push(policy.preset_rules.pop().unwrap());
        policy.user_rules.swap(0, 1);
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_err());
        policy.user_rules.swap(0, 1);
        assert!(
            validate_scoped_fake_dns_policy(
                &policy,
                &[suffixes[0].clone(), "other.test".to_owned()],
            )
            .is_err()
        );
        policy.user_rules[0].conditions.domains =
            vec![DomainPattern::Exact("example.test".parse().unwrap())];
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_err());
        policy.user_rules[0].conditions.domains =
            vec![DomainPattern::Suffix("example.test".parse().unwrap())];
        policy.user_rules[0].enabled = false;
        assert!(validate_scoped_fake_dns_policy(&policy, &suffixes).is_err());
    }

    #[test]
    fn scoped_fake_policy_rejects_non_proxy_decisions_and_probe_port_collisions() {
        let mut policy = Policy::default();
        assert!(validate_scoped_fake_dns_policy(&policy, &[]).is_ok());
        policy.default_action = Action::Direct;
        assert!(matches!(
            validate_scoped_fake_dns_policy(&policy, &[]),
            Err(crate::PolicyCompileError::InvalidPolicy)
        ));
        policy.default_action = Action::Proxy;
        policy.preset_rules.push(yonik_domain::Rule {
            id: 1,
            enabled: true,
            conditions: Default::default(),
            action: Action::Block,
        });
        assert!(matches!(
            validate_scoped_fake_dns_policy(&policy, &[]),
            Err(crate::PolicyCompileError::InvalidPolicy)
        ));
        policy.preset_rules[0].enabled = false;
        assert!(validate_scoped_fake_dns_policy(&policy, &[]).is_ok());
        policy.preset_rules[0].enabled = true;
        policy.preset_rules[0].action = Action::Proxy;
        policy.preset_rules[0].conditions.executables = vec!["/usr/bin/firefox".into()];
        assert!(validate_scoped_fake_dns_policy(&policy, &[]).is_err());
        policy.preset_rules[0].enabled = false;
        assert!(validate_scoped_fake_dns_policy(&policy, &[]).is_ok());
        policy.lan.push("192.168.50.0/24".parse().unwrap());
        assert!(matches!(
            validate_scoped_fake_dns_policy(&policy, &[]),
            Err(crate::PolicyCompileError::InvalidPolicy)
        ));
        policy.lan.clear();
        policy.private_networks.push(yonik_domain::PrivateNetwork {
            network: "10.0.0.0/8".parse().unwrap(),
            available: false,
            vpn: yonik_domain::VpnId::new(1).unwrap(),
        });
        assert!(matches!(
            validate_scoped_fake_dns_policy(&policy, &[]),
            Err(crate::PolicyCompileError::InvalidPolicy)
        ));

        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        assert!(matches!(
            compile_system_fake_dns_policy(
                &imported.servers[0],
                Engine::Xray,
                port(12556),
                port(12553),
                &Policy::default(),
                &tun,
                &empty_bridge(),
                &[],
            ),
            Err(crate::PolicyCompileError::ProbePort)
        ));
    }
}
