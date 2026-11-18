//! Замкнутый маршрут Fake-IP через внешний DNS и SOCKS-обработчик helper.
use super::{SystemTun, attach};
use crate::{CompileError, CompiledConfig, Engine, compile, routing::ProbeCredentials};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
};
use yonik_domain::{Action, Cidr, Policy};
use yonik_import::ParsedServer;

const LINK_SCOPED_DESTINATIONS: [&str; 5] = [
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "fe80::/10",
    "ff00::/8",
];

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
    lookup_auth: ProbeCredentials,
    reinject_auth: ProbeCredentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlainDnsPeer {
    address: IpAddr,
    loopback_port: NonZeroU16,
}

impl SystemFakeDnsBridge {
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
            lookup_auth,
            reinject_auth,
        })
    }

    pub fn lookup_auth(&self) -> &ProbeCredentials {
        &self.lookup_auth
    }

    pub fn reinject_auth(&self) -> &ProbeCredentials {
        &self.reinject_auth
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

    /// Маршрутизирует точные peer:53 запросы из system-tun inbound на отдельные
    /// listeners локального Fake DNS bridge. Порты предназначены для IPv4 lo.
    pub fn with_plain_dns_peers(
        mut self,
        peers: Vec<(IpAddr, NonZeroU16)>,
    ) -> Result<Self, CompileError> {
        if peers.len() > 3 {
            return Err(CompileError::InvalidParameter);
        }
        let mut typed = Vec::with_capacity(peers.len());
        for (address, loopback_port) in peers {
            if !valid_plain_dns_peer(address)
                || address == self.dns_address
                || self.pools.iter().any(|pool| pool.contains(address))
                || typed
                    .iter()
                    .any(|existing: &PlainDnsPeer| existing.address == address)
            {
                return Err(CompileError::InvalidParameter);
            }
            if [self.dns_port, self.lookup_port, self.reinject_port].contains(&loopback_port)
                || typed
                    .iter()
                    .any(|existing: &PlainDnsPeer| existing.loopback_port == loopback_port)
            {
                return Err(CompileError::ListenerConflict);
            }
            typed.push(PlainDnsPeer {
                address,
                loopback_port,
            });
        }
        self.plain_dns_peers = typed;
        Ok(self)
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
    attach_fake_dns(compile(server, engine, port)?, tun, bridge)
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
            .any(|peer| same_ip_address(peer.address, remote))
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

    let (inbound, dns, socks) = match engine {
        Engine::Xray => {
            let mut rules = Vec::with_capacity(bridge.plain_dns_peers.len() + 5);
            for (index, peer) in bridge.plain_dns_peers.iter().enumerate() {
                rules.push(json!({
                    "type":"field",
                    "inboundTag":["system-tun"],
                    "ip":[ip_prefix(peer.address)],
                    "port":"53",
                    "network":"tcp,udp",
                    "outboundTag":plain_dns_tag(index),
                }));
            }
            rules.extend([
                json!({"type":"field", "inboundTag":["system-tun"], "ip":[dns_prefix],
                    "port":53, "network":"tcp,udp", "outboundTag":"fake-dns-stub"}),
                json!({"type":"field", "inboundTag":["system-tun"], "ip":[dns_prefix],
                    "outboundTag":"fake-dns-reject"}),
                json!({"type":"field", "inboundTag":["system-tun"], "ip":pools,
                    "outboundTag":"fake-ip-lookup"}),
                json!({"type":"field", "inboundTag":["system-tun"], "ip":LINK_SCOPED_DESTINATIONS,
                    "outboundTag":"fake-dns-reject"}),
                json!({"type":"field", "inboundTag":["fake-ip-reinject"], "outboundTag":"proxy"}),
            ]);
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
                    "accounts":[{"user":reinject.username(),"pass":reinject.password()}]}}),
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
            let mut rules = Vec::with_capacity(bridge.plain_dns_peers.len() + 5);
            for peer in &bridge.plain_dns_peers {
                rules.push(json!({
                    "inbound":["system-tun"],
                    "ip_cidr":[ip_prefix(peer.address)],
                    "port":[53],
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
                json!({"inbound":["system-tun"],"ip_cidr":pools,"action":"route","outbound":"fake-ip-lookup"}),
                json!({"inbound":["system-tun"],"ip_cidr":LINK_SCOPED_DESTINATIONS,"action":"reject"}),
                json!({"inbound":["fake-ip-reinject"],"action":"route","outbound":"proxy"}),
            ]);
            prepend_rules(&mut config.value["route"]["rules"], rules)?;
            (
                json!({"type":"socks","tag":"fake-ip-reinject","listen":local,"listen_port":reinject_port,
                    "users":[{"username":reinject.username(),"password":reinject.password()}]}),
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

/// Первая фаза reinjection допустима только когда policy доказывает Proxy
/// для любого IP и имени: без более специфичных решений Direct/Block/VPN.
pub fn validate_scoped_fake_dns_policy(policy: &Policy) -> Result<(), crate::PolicyCompileError> {
    if policy.default_action != Action::Proxy
        || !policy.private_networks.is_empty()
        || !policy.private_domains.is_empty()
        || !policy.lan.is_empty()
        || policy
            .user_rules
            .iter()
            .chain(&policy.preset_rules)
            .any(|rule| rule.enabled && rule.action != Action::Proxy)
    {
        return Err(crate::PolicyCompileError::InvalidPolicy);
    }
    Ok(())
}

/// Компилирует обычную IP-only policy и ставит Fake-IP bridge rules перед ней.
/// Базовые routing rules, domainStrategy и final остаются принадлежащими policy compiler.
#[allow(clippy::too_many_arguments)]
pub fn compile_system_fake_dns_policy(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    tun: &SystemTun,
    bridge: &SystemFakeDnsBridge,
) -> Result<CompiledConfig, crate::PolicyCompileError> {
    validate_scoped_fake_dns_policy(policy)?;
    if [bridge.dns_port, bridge.lookup_port, bridge.reinject_port].contains(&probe_port)
        || bridge
            .plain_dns_peers
            .iter()
            .any(|peer| peer.loopback_port == probe_port)
    {
        return Err(crate::PolicyCompileError::ProbePort);
    }

    validate_bridge(server, port, tun, bridge).map_err(crate::PolicyCompileError::Server)?;
    let config = crate::routing::compile_tun_policy(server, engine, port, probe_port, policy)?;
    attach_fake_dns(config, tun, bridge).map_err(crate::PolicyCompileError::Server)
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
    fn plain_dns_peers_are_exactly_routed_to_isolated_loopback_listeners() {
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )
        .unwrap();
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let peers = vec![
            ("1.1.1.1".parse::<IpAddr>().unwrap(), port(12557)),
            (
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
                port(12558),
            ),
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
        .with_plain_dns_peers(peers.clone())
        .unwrap();

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
            assert_eq!(rules.as_array().unwrap().len(), 7);
            for (index, (peer, local_port)) in peers.iter().enumerate() {
                let rule = &rules[index];
                let prefix = ip_prefix(*peer);
                match engine {
                    Engine::Xray => {
                        let tag = plain_dns_tag(index);
                        assert_eq!(rule["inboundTag"], json!(["system-tun"]));
                        assert_eq!(rule["ip"], json!([prefix]));
                        assert_eq!(rule["port"], "53");
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
                        assert!(!outbound["settings"].to_string().contains(&peer.to_string()));
                    }
                    Engine::SingBox => {
                        assert_eq!(rule["inbound"], json!(["system-tun"]));
                        assert_eq!(rule["ip_cidr"], json!([prefix]));
                        assert_eq!(rule["port"], json!([53]));
                        assert_eq!(rule["network"], json!(["tcp", "udp"]));
                        assert_eq!(rule["outbound"], "fake-dns-stub");
                        assert_eq!(rule["override_address"], "127.42.7.9");
                        assert_eq!(rule["override_port"], local_port.get());
                        assert!(
                            !config.value["outbounds"]
                                .to_string()
                                .contains(&peer.to_string())
                        );
                    }
                }
            }
            assert_eq!(
                rules[2][match engine {
                    Engine::Xray => "outboundTag",
                    Engine::SingBox => "outbound",
                }],
                "fake-dns-stub"
            );
        }
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
        assert!(matches!(
            empty_bridge().with_plain_dns_peers(vec![
                ("1.1.1.1".parse().unwrap(), port(12557)),
                ("8.8.8.8".parse().unwrap(), port(12558)),
                ("9.9.9.9".parse().unwrap(), port(12559)),
                ("208.67.222.222".parse().unwrap(), port(12560)),
            ]),
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
        .with_plain_dns_peers(vec![("1.1.1.1".parse().unwrap(), port(12557))])
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
    fn scoped_fake_policy_rejects_non_proxy_decisions_and_probe_port_collisions() {
        let mut policy = Policy::default();
        assert!(validate_scoped_fake_dns_policy(&policy).is_ok());
        policy.default_action = Action::Direct;
        assert!(matches!(
            validate_scoped_fake_dns_policy(&policy),
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
            validate_scoped_fake_dns_policy(&policy),
            Err(crate::PolicyCompileError::InvalidPolicy)
        ));
        policy.preset_rules[0].enabled = false;
        assert!(validate_scoped_fake_dns_policy(&policy).is_ok());
        policy.lan.push("192.168.50.0/24".parse().unwrap());
        assert!(matches!(
            validate_scoped_fake_dns_policy(&policy),
            Err(crate::PolicyCompileError::InvalidPolicy)
        ));
        policy.lan.clear();
        policy.private_networks.push(yonik_domain::PrivateNetwork {
            network: "10.0.0.0/8".parse().unwrap(),
            available: false,
            vpn: yonik_domain::VpnId::new(1).unwrap(),
        });
        assert!(matches!(
            validate_scoped_fake_dns_policy(&policy),
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
            ),
            Err(crate::PolicyCompileError::ProbePort)
        ));
    }
}
