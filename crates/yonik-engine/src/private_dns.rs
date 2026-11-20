//! Статические DNS-параметры не являются свидетельством полномочий или live сети.
use crate::{CompiledConfig, Engine, PolicyCapability, PolicyCompileError, PolicyMode};
use std::{net::SocketAddr, num::NonZeroU16};
pub use yonik_domain::{
    DnsEpoch, DnsPolicy, DomainPattern, NativeDnsMode, Policy, PrivateDomain, VpnId,
};
use yonik_import::ParsedServer;

#[derive(Clone, Debug)]
pub struct PrivateDnsRoute {
    zone: DomainPattern,
    vpn: VpnId,
    resolver: SocketAddr,
    bind_ifname: String,
}
impl PrivateDnsRoute {
    pub fn new(
        zone: &PrivateDomain,
        resolver: SocketAddr,
        bind_ifname: &str,
    ) -> Result<Self, PolicyCompileError> {
        if bind_ifname.is_empty()
            || bind_ifname.len() > 15
            || matches!(bind_ifname, "." | "..")
            || bind_ifname
                .bytes()
                .any(|b| b == 0 || b == b'/' || b == b':' || b.is_ascii_whitespace())
            || resolver.port() == 0
            || resolver.ip().is_unspecified()
            || resolver.ip().is_multicast()
            || resolver.ip().is_loopback()
            || matches!(resolver, SocketAddr::V6(v) if v.scope_id() != 0 || v.flowinfo() != 0 || v.ip().to_ipv4_mapped().is_some())
        {
            return Err(PolicyCompileError::InvalidPolicy);
        }
        Ok(Self {
            zone: zone.domain.clone(),
            vpn: zone.vpn,
            resolver,
            bind_ifname: bind_ifname.into(),
        })
    }
    pub fn zone(&self) -> &DomainPattern {
        &self.zone
    }
    pub fn vpn(&self) -> VpnId {
        self.vpn
    }
    pub fn resolver(&self) -> SocketAddr {
        self.resolver
    }
    pub fn bind_ifname(&self) -> &str {
        &self.bind_ifname
    }
}

/// Отдельная статическая граница. Stock pinned cores не имеют live epoch/lease
/// revoke hooks: не выдаём частичный config за поддержку полного private DNS.
#[allow(clippy::too_many_arguments)]
pub fn compile_native_dns_with_private(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    mode: PolicyMode,
    dns: &DnsPolicy,
    private: &[PrivateDnsRoute],
) -> Result<CompiledConfig, PolicyCompileError> {
    if !private.is_empty() {
        return Err(PolicyCompileError::Unsupported(
            PolicyCapability::DnsContract,
        ));
    }
    crate::compile_native_dns(server, engine, port, probe_port, policy, mode, dns)
}

#[cfg(test)]
mod tests {
    use super::{DomainPattern, PrivateDnsRoute, PrivateDomain, VpnId};
    #[test]
    fn static_route_is_bounded_and_does_not_grant_capability() {
        let zone = PrivateDomain {
            domain: DomainPattern::Suffix("corp.test".parse().unwrap()),
            vpn: VpnId::new(7).unwrap(),
            available: false,
        };
        let resolver = "10.42.1.2:1053".parse().unwrap();
        let route = PrivateDnsRoute::new(&zone, resolver, "vpn").unwrap();
        assert_eq!(route.vpn(), zone.vpn);
        assert_eq!(route.resolver(), resolver);
        for invalid in [
            "",
            ".",
            "..",
            "has space",
            "has:colon",
            "a/b",
            "0123456789012345",
            "nul\0",
        ] {
            assert!(PrivateDnsRoute::new(&zone, resolver, invalid).is_err());
        }
        for invalid in [
            "0.0.0.0:53",
            "127.0.0.1:53",
            "224.0.0.1:53",
            "10.42.1.2:0",
            "[::ffff:10.42.1.2]:53",
        ] {
            assert!(PrivateDnsRoute::new(&zone, invalid.parse().unwrap(), "vpn").is_err());
        }
    }
}
