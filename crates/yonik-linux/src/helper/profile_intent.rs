//! DATA-проекция закрытого compiler graph. Не IPC codec и не разрешение запуска.
use crate::{
    Cancellation,
    managed_network::firewall::{BoundTransport, TransportProtocol},
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    net::{IpAddr, SocketAddr},
};
use yonik_engine::native_profile::{EgressPlan, PhysicalEndpoint};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressError {
    Budget,
    BootstrapRequired,
    InvalidEndpoint,
    Stale,
    Cancelled,
    InvalidBinding,
    Encoding,
}

/// Отдельно от DNS: resolver requirement не становится firewall exception.
pub struct PhysicalRequirements<'a> {
    plan: &'a EgressPlan,
}
impl<'a> PhysicalRequirements<'a> {
    pub fn new(plan: &'a EgressPlan) -> Result<Self, EgressError> {
        // Тот же верхний предел, что у firewall. DNS/LAN потребляют оставшийся
        // бюджет отдельно в PublicBlockPolicy::new, до dedup.
        if plan.physical().len() > 128 {
            return Err(EgressError::Budget);
        }
        Ok(Self { plan })
    }
    pub fn endpoints(&self) -> &'a [PhysicalEndpoint] {
        self.plan.physical()
    }

    pub fn provider_resolvers(&self) -> &'a [yonik_engine::native_profile::ResolverRequirement] {
        self.plan.resolvers()
    }

    pub fn system_resolvers(
        &self,
    ) -> &'a [yonik_engine::native_profile::SystemResolverRequirement] {
        self.plan.system_resolvers()
    }

    /// Только numeric leaves. Host проверяет namespace/table/mark и сохраняет
    /// полный route capture в T; возвращённый ifindex сам по себе не proof.
    /// Hostname требует отдельного DNS provenance bridge, его здесь нет.
    pub fn capture_numeric<T>(
        &self,
        worker_uid: u32,
        mark: u32,
        cancel: &Cancellation,
        mut capture: impl FnMut(SocketAddr, TransportProtocol) -> Result<(u32, T), EgressError>,
    ) -> Result<CapturedPhysicalRoutes<T>, EgressError> {
        check_cancel(cancel)?;
        if worker_uid == 0 || worker_uid == u32::MAX || mark == 0 {
            return Err(EgressError::InvalidBinding);
        }
        // Полная проверка адресов до первого host query и выделения вектора.
        for endpoint in self.endpoints() {
            numeric(endpoint)?;
        }
        let mut routes = Vec::with_capacity(self.endpoints().len());
        for endpoint in self.endpoints() {
            check_cancel(cancel)?;
            let address = numeric(endpoint)?;
            let protocol = match endpoint.protocol() {
                yonik_engine::native_profile::TransportProtocol::Tcp => TransportProtocol::Tcp,
                yonik_engine::native_profile::TransportProtocol::Udp => TransportProtocol::Udp,
            };
            let (ifindex, snapshot) = capture(SocketAddr::new(address, endpoint.port()), protocol)?;
            check_cancel(cancel)?;
            let transport = BoundTransport::new(
                address,
                protocol,
                endpoint.port(),
                ifindex,
                worker_uid,
                mark,
            )
            .map_err(|_| EgressError::InvalidBinding)?;
            routes.push((transport, snapshot));
        }
        check_cancel(cancel)?;
        Ok(CapturedPhysicalRoutes {
            routes,
            invalid: false,
        })
    }
}

fn numeric(endpoint: &PhysicalEndpoint) -> Result<IpAddr, EgressError> {
    let ip: IpAddr = endpoint
        .host()
        .parse()
        .map_err(|_| EgressError::BootstrapRequired)?;
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast() || ip.is_link_local())
        || matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local() || ip.to_ipv4().is_some())
    {
        return Err(EgressError::InvalidEndpoint);
    }
    Ok(ip)
}
fn check_cancel(cancel: &Cancellation) -> Result<(), EgressError> {
    cancel.check().map_err(|_| EgressError::Cancelled)
}

/// Bounded route observations. Это не session admission и не владелец worker.
/// Любая неудачная повторная проверка необратимо инвалидирует весь набор.
pub struct CapturedPhysicalRoutes<T> {
    routes: Vec<(BoundTransport, T)>,
    invalid: bool,
}
impl<T> CapturedPhysicalRoutes<T> {
    pub fn revalidate(
        &mut self,
        cancel: &Cancellation,
        mut verify: impl FnMut(&T) -> Result<(), EgressError>,
    ) -> Result<(), EgressError> {
        if self.invalid {
            return Err(EgressError::Stale);
        }
        // Инвалидация предшествует callbacks: ошибка/отмена не возвращает
        // частично проверенный набор вызывающему коду.
        self.invalid = true;
        check_cancel(cancel)?;
        for (_, snapshot) in &self.routes {
            check_cancel(cancel)?;
            verify(snapshot)?;
            check_cancel(cancel)?;
        }
        self.invalid = false;
        Ok(())
    }
    pub fn transports(&self) -> Result<impl Iterator<Item = BoundTransport> + '_, EgressError> {
        if self.invalid {
            return Err(EgressError::Stale);
        }
        Ok(self.routes.iter().map(|(transport, _)| *transport))
    }
}

/// Удерживает ровно один compiler result с его случайными probe credentials.
/// Identity — DATA binding; не подтверждает selection, resources или native grants.
pub struct RetainedSystemProfile {
    compiled: yonik_engine::native_profile::CompiledProfileSystem,
    digest: [u8; 32],
    generation: u64,
    selection: [u8; 32],
}
impl RetainedSystemProfile {
    pub fn seal(
        compiled: yonik_engine::native_profile::CompiledProfileSystem,
        generation: u64,
        selection: [u8; 32],
    ) -> Result<Self, EgressError> {
        if generation == 0 || selection == [0; 32] {
            return Err(EgressError::InvalidBinding);
        }
        let mut writer = DigestWriter {
            digest: Sha256::new(),
            bytes: 0,
        };
        compiled
            .config()
            .write_sensitive(&mut writer)
            .map_err(|_| EgressError::Encoding)?;
        Ok(Self {
            compiled,
            digest: writer.digest.finalize().into(),
            generation,
            selection,
        })
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn compiled(&self) -> &yonik_engine::native_profile::CompiledProfileSystem {
        &self.compiled
    }
    pub fn matches(&self, generation: u64, selection: [u8; 32], digest: [u8; 32]) -> bool {
        self.generation == generation && self.selection == selection && self.digest == digest
    }
    pub fn into_compiled(self) -> yonik_engine::native_profile::CompiledProfileSystem {
        self.compiled
    }
}
struct DigestWriter {
    digest: Sha256,
    bytes: usize,
}
impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= super::MAX_ARTIFACT_BYTES)
            .ok_or_else(|| io::Error::other("Превышен бюджет runtime config"))?;
        self.digest.update(bytes);
        self.bytes = total;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "profile_intent_tests.rs"]
mod tests;
