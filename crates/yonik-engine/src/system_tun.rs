//! Системный TUN inbound; сетью и проверкой применённого состояния владеет host.
use crate::{CompileError, CompiledConfig, Engine, PolicyCompileError, compile};
use serde_json::json;
use std::{fmt, net::IpAddr, num::NonZeroU16, str::FromStr};
use yonik_domain::Policy;
use yonik_import::ParsedServer;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SystemTunAddress {
    address: IpAddr,
    prefix: u8,
}
impl SystemTunAddress {
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, CompileError> {
        let allowed = match address {
            IpAddr::V4(ip) => {
                prefix > 0 && prefix <= 32 && !ip.is_broadcast() && !ip.is_link_local()
            }
            IpAddr::V6(ip) => {
                prefix > 0 && prefix <= 128 && !ip.is_unicast_link_local() && ip.to_ipv4().is_none()
            }
        };
        if !allowed || address.is_unspecified() || address.is_loopback() || address.is_multicast() {
            return Err(CompileError::InvalidParameter);
        }
        Ok(Self { address, prefix })
    }
}
impl FromStr for SystemTunAddress {
    type Err = CompileError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or(CompileError::InvalidParameter)?;
        Self::new(
            address
                .parse()
                .map_err(|_| CompileError::InvalidParameter)?,
            prefix.parse().map_err(|_| CompileError::InvalidParameter)?,
        )
    }
}
impl fmt::Debug for SystemTunAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SystemTunAddress(<скрыто>)")
    }
}

pub struct SystemTun {
    name_id: u32,
    mtu: u16,
    mark: u32,
    addresses: Vec<SystemTunAddress>,
}
impl SystemTun {
    pub fn new(
        name_id: u32,
        mtu: u16,
        mark: u32,
        addresses: Vec<SystemTunAddress>,
    ) -> Result<Self, CompileError> {
        if name_id == 0
            || !(1280..=9000).contains(&mtu)
            || mark == 0
            || mark > i32::MAX as u32
            || addresses.is_empty()
            || addresses.len() > 2
            || addresses.len() == 2
                && addresses[0].address.is_ipv4() == addresses[1].address.is_ipv4()
        {
            return Err(CompileError::InvalidParameter);
        }
        Ok(Self {
            name_id,
            mtu,
            mark,
            addresses,
        })
    }
    pub fn interface_name(&self) -> String {
        format!("tofu{:08x}", self.name_id)
    }
}
impl fmt::Debug for SystemTun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SystemTun(<скрыто>)")
    }
}

/// Для SingBox нужен закреплённый адаптер external_tun_configuration.
/// Генерация не подтверждает TUN/DNS capabilities или владение интерфейсом.
/// Host обязан закрепить транспорт/маршрут и разрешение endpoint до Apply.
pub fn compile_system(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    tun: &SystemTun,
) -> Result<CompiledConfig, CompileError> {
    attach(compile(server, engine, port)?, tun)
}

/// Пакетный IP-вход не выдаётся за доменный вход: Names/Fake-DNS требуют
/// отдельного подтверждённого resolver/provenance пути и пока не включаются.
pub fn compile_system_policy(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    tun: &SystemTun,
) -> Result<CompiledConfig, PolicyCompileError> {
    attach(
        crate::routing::compile_tun_policy(server, engine, port, probe_port, policy)?,
        tun,
    )
    .map_err(PolicyCompileError::Server)
}
/// SystemTUN bound resources сохраняют IP-only gates и существующий native routing.
#[allow(clippy::too_many_arguments)]
pub fn compile_system_bound_policy<C: crate::resource_bundle::VerifiedCatalog>(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    bound: &crate::resource_bundle::BoundPolicy<'_, C>,
    revision: u64,
    identity: &[u8],
    tun: &SystemTun,
) -> Result<CompiledConfig, PolicyCompileError> {
    bound
        .validate_revision(revision, identity)
        .map_err(|_| PolicyCompileError::InvalidPolicy)?;
    if bound.manifest().iter().any(|r| r.engine != engine) {
        return Err(PolicyCompileError::InvalidPolicy);
    }
    attach(
        crate::routing::compile_tun_policy_resources(server, engine, port, probe_port, bound)?,
        tun,
    )
    .map_err(PolicyCompileError::Server)
}

pub(crate) fn attach(
    mut config: CompiledConfig,
    tun: &SystemTun,
) -> Result<CompiledConfig, CompileError> {
    let addresses: Vec<_> = tun
        .addresses
        .iter()
        .map(|a| format!("{}/{}", a.address, a.prefix))
        .collect();
    let inbound = match config.engine {
        Engine::Xray => {
            json!({"tag":"system-tun","protocol":"tun","settings":{"name":tun.interface_name(),"mtu":tun.mtu,"autoSystemRoutingTable":[],"autoSystemDnsToGateway":false}})
        }
        Engine::SingBox => {
            json!({"tag":"system-tun","type":"tun","interface_name":tun.interface_name(),"mtu":tun.mtu,"address":addresses,"auto_route":false,"auto_redirect":false,"dns_mode":"disabled","external_configuration":true})
        }
    };
    config.value["inbounds"]
        .as_array_mut()
        .ok_or(CompileError::InvalidParameter)?
        .push(inbound);
    for outbound in config.value["outbounds"]
        .as_array_mut()
        .ok_or(CompileError::InvalidParameter)?
    {
        match config.engine {
            Engine::Xray if outbound["protocol"] != "blackhole" => {
                outbound["streamSettings"]["sockopt"]["mark"] = json!(tun.mark)
            }
            Engine::SingBox => outbound["routing_mark"] = json!(tun.mark),
            _ => {}
        }
    }
    Ok(config)
}
