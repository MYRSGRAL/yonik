//! Замкнутый маршрут Fake-IP через внешний DNS и SOCKS-обработчик helper.
use super::{SystemTun, attach};
use crate::{CompileError, CompiledConfig, Engine, compile, routing::ProbeCredentials};
use serde_json::json;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
};
use yonik_domain::Cidr;
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
    lookup_auth: ProbeCredentials,
    reinject_auth: ProbeCredentials,
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
    let remote: IpAddr = server
        .endpoint()
        .host()
        .parse()
        .map_err(|_| CompileError::InvalidParameter)?;
    if remote.is_loopback()
        || bridge.dns_address == remote
        || bridge.pools.iter().any(|pool| pool.contains(remote))
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
    if [bridge.dns_port, bridge.lookup_port, bridge.reinject_port].contains(&port) {
        return Err(CompileError::ListenerConflict);
    }

    let mut config = compile(server, engine, port)?;
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
            config.value["routing"] = json!({
                "domainStrategy": "AsIs",
                "rules": [
                    {"type":"field", "inboundTag":["system-tun"], "ip":[dns_prefix],
                     "port":53, "network":"tcp,udp", "outboundTag":"fake-dns-stub"},
                    {"type":"field", "inboundTag":["system-tun"], "ip":[dns_prefix],
                     "outboundTag":"fake-dns-reject"},
                    {"type":"field", "inboundTag":["system-tun"], "ip":pools,
                     "outboundTag":"fake-ip-lookup"},
                    {"type":"field", "inboundTag":["system-tun"], "ip":LINK_SCOPED_DESTINATIONS,
                     "outboundTag":"fake-dns-reject"},
                    {"type":"field", "inboundTag":["fake-ip-reinject"], "outboundTag":"proxy"},
                ]
            });
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
            config.value["route"]["rules"] = json!([
                {"inbound":["system-tun"],"ip_cidr":[dns_prefix],"port":[53],
                 "network":["tcp","udp"],"action":"route","outbound":"fake-dns-stub",
                 "override_address":local,"override_port":dns_port},
                {"inbound":["system-tun"],"ip_cidr":[dns_prefix],"action":"reject"},
                {"inbound":["system-tun"],"ip_cidr":pools,"action":"route","outbound":"fake-ip-lookup"},
                {"inbound":["system-tun"],"ip_cidr":LINK_SCOPED_DESTINATIONS,"action":"reject"},
                {"inbound":["fake-ip-reinject"],"action":"route","outbound":"proxy"},
            ]);
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
    attach(config, tun)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
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
}
