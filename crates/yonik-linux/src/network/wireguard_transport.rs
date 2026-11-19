//! Краткоживущая проверка маршрута внешнего UDP-транспорта WireGuard.

use super::{
    KernelRoute, LinuxLink, LinuxTopology, NetworkReadError as Error, RouteCapture, RouteKind,
    RouteQuery, TransportProtocol, WireGuardDevice, equivalence::same_link, lookup_route_captured,
    read::NetlinkReader, read_topology_captured, read_wireguard_device, same_captured_kernel_route,
    same_captured_topology,
};
use crate::Cancellation;
use rustix::time::{ClockId, clock_gettime};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    num::NonZeroU32,
    time::Duration,
};
use tokio::time::Instant;

const VALIDITY: Duration = Duration::from_secs(2);
const MAX_ENDPOINTS: usize = 32;
const IFF_UP: u32 = 1;
const IFF_LOOPBACK: u32 = 8;
const ARPHRD_ETHER: u16 = 1;
const IFA_UNUSABLE: u32 = 0x08 | 0x40; // IFA_F_DADFAILED, IFA_F_TENTATIVE.

#[derive(Clone, Copy)]
struct TransportDeadline {
    monotonic: Instant,
    boottime: Duration,
}

impl TransportDeadline {
    fn start() -> Result<Self, Error> {
        let started = boottime()?;
        Ok(Self {
            monotonic: Instant::now() + VALIDITY,
            boottime: started.checked_add(VALIDITY).ok_or(Error::Limit)?,
        })
    }

    fn remaining_at(&self, monotonic: Instant, boottime: Duration) -> Duration {
        self.monotonic
            .saturating_duration_since(monotonic)
            .min(self.boottime.saturating_sub(boottime))
    }
}

/// Результат RTM_GETROUTE для UDP-адресов, портов и метки. Он описывает
/// выходной L3-интерфейс, включая виртуальный Ethernet, и не проверяет L2-путь.
pub struct WireGuardUdpPath {
    source: SocketAddr,
    endpoint: SocketAddr,
    fwmark: NonZeroU32,
    link: LinuxLink,
    selected: (KernelRoute, RouteCapture),
    source_bound: (KernelRoute, RouteCapture),
}

impl WireGuardUdpPath {
    pub fn source(&self) -> SocketAddr {
        self.source
    }
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
    pub fn fwmark(&self) -> NonZeroU32 {
        self.fwmark
    }
    pub fn ifindex(&self) -> u32 {
        self.link.index
    }
    pub fn ifname(&self) -> &[u8] {
        &self.link.name
    }
    pub fn gateway(&self) -> Option<IpAddr> {
        self.selected.0.gateway
    }

    fn same_path(&self, other: &Self) -> bool {
        let matches = |a: &(KernelRoute, RouteCapture), b: &(KernelRoute, RouteCapture)| {
            same_captured_kernel_route(&a.0, &b.0, Some((a.1, b.1)))
        };
        self.source == other.source
            && self.endpoint == other.endpoint
            && self.fwmark == other.fwmark
            && same_link(&self.link, &other.link)
            && matches(&self.selected, &other.selected)
            && matches(&self.source_bound, &other.source_bound)
    }
}

pub struct WireGuardUdpRouteSnapshot {
    device: WireGuardDevice,
    link: LinuxLink,
    paths: Vec<WireGuardUdpPath>,
    expires_at: TransportDeadline,
    cancellation: Cancellation,
    revoked: bool,
}

impl WireGuardUdpRouteSnapshot {
    /// Только чтение FIB текущего namespace. WireGuard GET не показывает
    /// namespace UDP-сокета или запомненный source peer. Перед выдачей допуска
    /// nft требуется отдельно подтвердить фактический выход UDP WireGuard.
    pub async fn capture(ifindex: u32, cancel: &mut Cancellation) -> Result<Self, Error> {
        let expires_at = TransportDeadline::start()?;
        remaining(expires_at, cancel)?;
        let mut fence = NetlinkReader::open()?;
        let (topology, timing) =
            read_topology_captured(cancel, remaining(expires_at, cancel)?).await?;
        let link = topology
            .links
            .iter()
            .find(|link| {
                link.index == ifindex
                    && link.kind.as_deref() == Some(b"wireguard")
                    && link.flags & IFF_UP != 0
                    && link.master.is_none()
            })
            .ok_or(Error::Unsupported)?;
        let device = read_wireguard_device(ifindex, cancel, remaining(expires_at, cancel)?).await?;
        if device.namespace != topology.namespace || device.ifname != link.name {
            return Err(Error::Changed);
        }
        let fwmark = NonZeroU32::new(device.fwmark).ok_or(Error::Unsupported)?;
        let endpoints: BTreeSet<_> = device
            .peers
            .iter()
            .filter_map(|peer| peer.endpoint)
            .collect();
        if endpoints.is_empty() || device.listen_port == 0 || endpoints.len() > MAX_ENDPOINTS {
            return Err(Error::Unsupported);
        }
        let mut paths = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            paths.push(
                check_endpoint(
                    &topology,
                    endpoint,
                    device.listen_port,
                    fwmark,
                    expires_at,
                    cancel,
                )
                .await?,
            );
        }
        let (after, after_timing) =
            read_topology_captured(cancel, remaining(expires_at, cancel)?).await?;
        if !same_captured_topology(&topology, timing, &after, after_timing)
            || device
                != read_wireguard_device(ifindex, cancel, remaining(expires_at, cancel)?).await?
        {
            return Err(Error::Changed);
        }
        fence.finish(cancel, expires_at.monotonic)?;
        remaining(expires_at, cancel)?;
        Ok(Self {
            device,
            link: link.clone(),
            paths,
            expires_at,
            cancellation: cancel.clone(),
            revoked: false,
        })
    }

    /// Любая ошибка или пропуск срока отзывает этот результат. Для нового
    /// транспорта вызывающий заново проверяет маршрут и собственные правила.
    pub async fn revalidate(&mut self, cancel: &mut Cancellation) -> Result<(), Error> {
        if self.paths().is_none() {
            self.revoked = true;
            return Err(Error::Changed);
        }
        let previous_expiry = self.expires_at;
        // Отзываем до await: закрытие future не оставляет разрешение в памяти.
        self.revoked = true;
        let mut current = Self::capture(self.device.ifindex, cancel).await?;
        self.cancellation.check().map_err(|_| Error::Cancelled)?;
        if remaining(previous_expiry, cancel).is_err()
            || self.device != current.device
            || !same_link(&self.link, &current.link)
            || self.paths.len() != current.paths.len()
            || !self
                .paths
                .iter()
                .zip(&current.paths)
                .all(|(before, after)| before.same_path(after))
        {
            return Err(Error::Changed);
        }
        current.cancellation = self.cancellation.clone();
        *self = current;
        Ok(())
    }

    /// Возвращает пути живого снимка и монотонную верхнюю границу срока.
    /// После сна предел может наступить раньше этой границы.
    pub fn paths(&self) -> Option<(Instant, &[WireGuardUdpPath])> {
        (!self.revoked && remaining(self.expires_at, &self.cancellation).is_ok())
            .then_some((self.expires_at.monotonic, &self.paths))
    }
}

async fn check_endpoint(
    topology: &LinuxTopology,
    endpoint: SocketAddr,
    port: u16,
    fwmark: NonZeroU32,
    deadline: TransportDeadline,
    cancel: &mut Cancellation,
) -> Result<WireGuardUdpPath, Error> {
    if !unicast_address(endpoint.ip()) || endpoint.port() == 0 {
        return Err(Error::Unsupported);
    }
    let scope = match endpoint {
        SocketAddr::V6(address) if address.flowinfo() == 0 => {
            let scope = NonZeroU32::new(address.scope_id());
            if address.ip().is_unicast_link_local() && scope.is_none() {
                return Err(Error::Unsupported);
            }
            scope
        }
        SocketAddr::V6(_) => return Err(Error::Unsupported),
        SocketAddr::V4(_) => None,
    };
    // У scoped IPv6 endpoint scope_id является частью kernel lookup. Для
    // остальных адресов нельзя навязывать oif и скрывать выигравший маршрут.
    // UID 0 соответствует нулевому flowi_uid в UDP lookup WireGuard.
    let query = RouteQuery::new(endpoint.ip(), 0)
        .with_mark(fwmark.get())
        .with_transport(TransportProtocol::Udp, Some(port), Some(endpoint.port()))
        .with_interfaces(None, scope);
    let selected =
        lookup_route_captured(query.clone(), cancel, remaining(deadline, cancel)?).await?;
    let index = checked_output(&selected.0, topology)?;
    if scope.is_some_and(|scope| scope.get() != index) {
        return Err(Error::Unsupported);
    }
    let source = selected
        .0
        .preferred_source
        .filter(|ip| unicast_address(*ip))
        .ok_or(Error::Unsupported)?;
    let link = topology
        .links
        .iter()
        .find(|link| link.index == index && is_uplink(link))
        .ok_or(Error::Unsupported)?;
    if !topology.addresses.iter().any(|address| {
        address.index == index
            && address.local.unwrap_or(address.address) == source
            && address.flags & IFA_UNUSABLE == 0
    }) {
        return Err(Error::Unsupported);
    }
    let source_bound = lookup_route_captured(
        query.with_source(source)?,
        cancel,
        remaining(deadline, cancel)?,
    )
    .await?;
    if checked_output(&source_bound.0, topology)? != index
        || source_bound.0.table != selected.0.table
        || source_bound.0.gateway != selected.0.gateway
        || source_bound
            .0
            .preferred_source
            .is_some_and(|value| value != source)
    {
        return Err(Error::Changed);
    }
    let source = match source {
        IpAddr::V6(ip) if ip.is_unicast_link_local() => {
            SocketAddrV6::new(ip, port, 0, index).into()
        }
        _ => SocketAddr::new(source, port),
    };
    Ok(WireGuardUdpPath {
        source,
        endpoint,
        fwmark,
        link: link.clone(),
        selected,
        source_bound,
    })
}

fn checked_output(route: &KernelRoute, topology: &LinuxTopology) -> Result<u32, Error> {
    if route.namespace != topology.namespace
        || route.kind != RouteKind::Unicast
        || route.table.is_none()
        || route.nexthop_id.is_some()
        || !route.incomplete.is_empty()
    {
        return Err(Error::Unsupported);
    }
    route
        .output_interface
        .map(NonZeroU32::get)
        .ok_or(Error::Unsupported)
}

fn is_uplink(link: &LinuxLink) -> bool {
    link.flags & (IFF_UP | IFF_LOOPBACK) == IFF_UP
        && link.link_type == ARPHRD_ETHER
        && matches!(
            link.kind.as_deref(),
            None | Some(b"veth" | b"vlan" | b"bridge" | b"bond" | b"team" | b"macvlan" | b"ipvlan")
        )
}

fn unicast_address(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
        && !matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
}

fn boottime() -> Result<Duration, Error> {
    let time = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(time.tv_sec).map_err(|_| Error::Unavailable)?;
    let nanos = u32::try_from(time.tv_nsec).map_err(|_| Error::Unavailable)?;
    if nanos >= 1_000_000_000 {
        return Err(Error::Unavailable);
    }
    Ok(Duration::new(seconds, nanos))
}

fn remaining(deadline: TransportDeadline, cancel: &Cancellation) -> Result<Duration, Error> {
    cancel.check().map_err(|_| Error::Cancelled)?;
    let duration = deadline.remaining_at(Instant::now(), boottime()?);
    if duration.is_zero() {
        Err(Error::Timeout)
    } else {
        Ok(duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_expires_the_snapshot_without_advancing_monotonic_time() {
        let monotonic = Instant::now();
        let boot = Duration::from_secs(10);
        let deadline = TransportDeadline {
            monotonic: monotonic + VALIDITY,
            boottime: boot + VALIDITY,
        };
        let short = Duration::from_millis(20);
        assert_eq!(
            deadline.remaining_at(monotonic + short, boot + short),
            VALIDITY - short,
        );
        assert_eq!(
            deadline.remaining_at(monotonic + short, boot + VALIDITY),
            Duration::ZERO,
        );
        assert_eq!(
            deadline.remaining_at(monotonic + VALIDITY, boot + short),
            Duration::ZERO,
        );
    }
}
