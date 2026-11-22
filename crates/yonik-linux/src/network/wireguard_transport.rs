//! Краткоживущая проверка маршрута внешнего UDP-транспорта WireGuard.

use super::{
    KernelRoute, LinuxLink, LinuxTopology, NetworkReadError as Error, RouteCapture, RouteKind,
    RouteQuery, TransportProtocol, WireGuardDevice, WireGuardSocketObservation,
    WireGuardSocketObserver, equivalence::same_link, lookup_route_captured, read::NetlinkReader,
    read_topology_captured, read_wireguard_device, read_wireguard_device_observed,
    same_captured_kernel_route, same_captured_topology,
};
use crate::Cancellation;
use rustix::time::{ClockId, clock_gettime};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
use tokio::time::Instant;

const VALIDITY: Duration = Duration::from_secs(2);
const MAX_ENDPOINTS: usize = 32;
const IFF_UP: u32 = 1;
const IFF_LOOPBACK: u32 = 8;
const ARPHRD_ETHER: u16 = 1;
const IFA_UNUSABLE: u32 = 0x08 | 0x40; // IFA_F_DADFAILED, IFA_F_TENTATIVE.
const PACKET_KEY_SIZE: usize = 80;

/// Запись для таблицы допуска WireGuard в ядре с абсолютным сроком действия.
pub struct WireGuardPacketLease {
    key: [u8; PACKET_KEY_SIZE],
    expires_at_boottime_ns: u64,
}

impl WireGuardPacketLease {
    pub fn bpf_key(&self) -> &[u8; PACKET_KEY_SIZE] {
        &self.key
    }

    pub fn expires_at_boottime_ns(&self) -> u64 {
        self.expires_at_boottime_ns
    }
}

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
    sockets: Option<WireGuardSocketObservation>,
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
        Self::capture_inner(ifindex, cancel, None).await
    }

    /// Проверяет маршрут и принадлежность транспортных сокетов тому же namespace.
    pub async fn capture_observed(
        ifindex: u32,
        cancel: &mut Cancellation,
        observer: &mut dyn WireGuardSocketObserver,
    ) -> Result<Self, Error> {
        Self::capture_inner(ifindex, cancel, Some(observer)).await
    }

    async fn capture_inner(
        ifindex: u32,
        cancel: &mut Cancellation,
        mut observer: Option<&mut dyn WireGuardSocketObserver>,
    ) -> Result<Self, Error> {
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
        let (device, sockets) =
            read_transport_device(ifindex, cancel, expires_at, &mut observer).await?;
        if device.namespace != topology.namespace || device.ifname != link.name {
            return Err(Error::Changed);
        }
        if sockets.is_some_and(|sockets| sockets.socket_namespace != topology.namespace.inode) {
            return Err(Error::Unsupported);
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
        if !same_captured_topology(&topology, timing, &after, after_timing) {
            return Err(Error::Changed);
        }
        let (after_device, after_sockets) =
            read_transport_device(ifindex, cancel, expires_at, &mut observer).await?;
        if device != after_device || !same_sockets(sockets, after_sockets) {
            return Err(Error::Changed);
        }
        fence.finish(cancel, expires_at.monotonic)?;
        remaining(expires_at, cancel)?;
        Ok(Self {
            device,
            sockets,
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
        self.revalidate_inner(cancel, None).await
    }

    pub async fn revalidate_observed(
        &mut self,
        cancel: &mut Cancellation,
        observer: &mut dyn WireGuardSocketObserver,
    ) -> Result<(), Error> {
        self.revalidate_inner(cancel, Some(observer)).await
    }

    async fn revalidate_inner(
        &mut self,
        cancel: &mut Cancellation,
        observer: Option<&mut dyn WireGuardSocketObserver>,
    ) -> Result<(), Error> {
        if self.paths().is_none() {
            self.revoked = true;
            return Err(Error::Changed);
        }
        let previous_expiry = self.expires_at;
        // Отзываем до await: закрытие future не оставляет разрешение в памяти.
        self.revoked = true;
        if self.sockets.is_some() != observer.is_some() {
            return Err(Error::Changed);
        }
        let mut current = Self::capture_inner(self.device.ifindex, cancel, observer).await?;
        self.cancellation.check().map_err(|_| Error::Cancelled)?;
        if remaining(previous_expiry, cancel).is_err()
            || self.device != current.device
            || !same_sockets(self.sockets, current.sockets)
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

    pub fn packet_leases(
        &self,
        generation: NonZeroU64,
    ) -> Result<Vec<WireGuardPacketLease>, Error> {
        if self.revoked {
            return Err(Error::Changed);
        }
        remaining(self.expires_at, &self.cancellation)?;
        let sockets = self.sockets.ok_or(Error::Unsupported)?;
        let expires_at_boottime_ns =
            u64::try_from(self.expires_at.boottime.as_nanos()).map_err(|_| Error::Limit)?;
        let mut leases = Vec::with_capacity(self.paths.len());
        for path in &self.paths {
            let cookie = match path.endpoint.ip() {
                IpAddr::V4(_) => sockets.ipv4_cookie,
                IpAddr::V6(_) => sockets.ipv6_cookie,
            };
            let key = packet_key(
                path.source,
                path.endpoint,
                path.gateway().unwrap_or(path.endpoint.ip()),
                path.fwmark,
                path.ifindex(),
                cookie,
                generation,
            )?;
            leases.push(WireGuardPacketLease {
                key,
                expires_at_boottime_ns,
            });
        }
        remaining(self.expires_at, &self.cancellation)?;
        Ok(leases)
    }
}

async fn read_transport_device(
    ifindex: u32,
    cancel: &mut Cancellation,
    deadline: TransportDeadline,
    observer: &mut Option<&mut dyn WireGuardSocketObserver>,
) -> Result<(WireGuardDevice, Option<WireGuardSocketObservation>), Error> {
    let timeout = remaining(deadline, cancel)?;
    if let Some(observer) = observer {
        let (device, sockets) =
            read_wireguard_device_observed(ifindex, cancel, timeout, *observer).await?;
        Ok((device, Some(sockets)))
    } else {
        Ok((read_wireguard_device(ifindex, cancel, timeout).await?, None))
    }
}

fn same_sockets(
    before: Option<WireGuardSocketObservation>,
    after: Option<WireGuardSocketObservation>,
) -> bool {
    match (before, after) {
        (None, None) => true,
        (Some(before), Some(after)) => {
            before.ifindex == after.ifindex
                && before.device_namespace == after.device_namespace
                && before.socket_namespace == after.socket_namespace
                && before.ipv4_cookie == after.ipv4_cookie
                && before.ipv6_cookie == after.ipv6_cookie
                && before.listen_port == after.listen_port
                && before.generation == after.generation
        }
        _ => false,
    }
}

fn packet_key(
    source: SocketAddr,
    endpoint: SocketAddr,
    gateway: IpAddr,
    mark: NonZeroU32,
    ifindex: u32,
    cookie: u64,
    generation: NonZeroU64,
) -> Result<[u8; PACKET_KEY_SIZE], Error> {
    // Совпадает с struct yonik_wg_packet. Порты хранятся в сетевом порядке.
    let mut key = [0; PACKET_KEY_SIZE];
    let family: u32 = match (source.ip(), endpoint.ip(), gateway) {
        (IpAddr::V4(source), IpAddr::V4(endpoint), IpAddr::V4(gateway)) => {
            key[16..20].copy_from_slice(&source.octets());
            key[32..36].copy_from_slice(&endpoint.octets());
            key[56..60].copy_from_slice(&gateway.octets());
            2 // AF_INET
        }
        (IpAddr::V6(source), IpAddr::V6(endpoint), IpAddr::V6(gateway)) => {
            key[16..32].copy_from_slice(&source.octets());
            key[32..48].copy_from_slice(&endpoint.octets());
            key[56..72].copy_from_slice(&gateway.octets());
            10 // AF_INET6
        }
        _ => return Err(Error::Unsupported),
    };
    key[0..8].copy_from_slice(&cookie.to_ne_bytes());
    key[8..12].copy_from_slice(&mark.get().to_ne_bytes());
    key[12..16].copy_from_slice(&ifindex.to_ne_bytes());
    key[48..50].copy_from_slice(&source.port().to_be_bytes());
    key[50..52].copy_from_slice(&endpoint.port().to_be_bytes());
    key[52..56].copy_from_slice(&family.to_ne_bytes());
    key[72..80].copy_from_slice(&generation.get().to_ne_bytes());
    Ok(key)
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
    fn packet_key_matches_kernel_layout_for_both_families() {
        let mark = NonZeroU32::new(0x51820).unwrap();
        let generation = NonZeroU64::new(42).unwrap();
        for (source, endpoint, next_hop, family) in [
            ("192.0.2.5:13124", "198.51.100.7:21862", "192.0.2.1", 2u32),
            (
                "[2001:db8::5]:13124",
                "[2001:db8:1::7]:21862",
                "fe80::1",
                10,
            ),
        ] {
            let source: SocketAddr = source.parse().unwrap();
            let endpoint: SocketAddr = endpoint.parse().unwrap();
            let next_hop: IpAddr = next_hop.parse().unwrap();
            let cookie = 0x1234_5678_9abc_def0u64;
            let key = packet_key(source, endpoint, next_hop, mark, 9, cookie, generation).unwrap();
            let address_bytes = |address: IpAddr| {
                let mut bytes = [0; 16];
                match address {
                    IpAddr::V4(ip) => bytes[..4].copy_from_slice(&ip.octets()),
                    IpAddr::V6(ip) => bytes = ip.octets(),
                }
                bytes
            };
            assert_eq!(key[0..8], cookie.to_ne_bytes());
            assert_eq!(key[8..12], mark.get().to_ne_bytes());
            assert_eq!(key[12..16], 9u32.to_ne_bytes());
            assert_eq!(key[16..32], address_bytes(source.ip()));
            assert_eq!(key[32..48], address_bytes(endpoint.ip()));
            assert_eq!(key[48..52], [0x33, 0x44, 0x55, 0x66]);
            assert_eq!(key[52..56], family.to_ne_bytes());
            assert_eq!(key[56..72], address_bytes(next_hop));
            assert_eq!(key[72..80], generation.get().to_ne_bytes());
        }
    }

    #[test]
    fn next_hop_from_another_address_family_cannot_be_encoded() {
        assert!(matches!(
            packet_key(
                "192.0.2.5:13124".parse().unwrap(),
                "198.51.100.7:21862".parse().unwrap(),
                "fe80::1".parse().unwrap(),
                NonZeroU32::MIN,
                9,
                1,
                NonZeroU64::MIN,
            ),
            Err(Error::Unsupported)
        ));
    }

    #[test]
    fn socket_identity_is_independent_of_the_dump_but_not_its_generation() {
        let first = WireGuardSocketObservation {
            port_id: 4,
            sequence: 10,
            ifindex: 3,
            device_namespace: 100,
            socket_namespace: 100,
            ipv4_cookie: 21,
            ipv6_cookie: 22,
            listen_port: 51111,
            generation: 9,
            parts: 1,
        };
        let after = WireGuardSocketObservation {
            port_id: 5,
            sequence: 11,
            parts: 2,
            ..first
        };
        assert!(same_sockets(Some(first), Some(after)));
        for changed in [
            WireGuardSocketObservation {
                generation: 10,
                ..after
            },
            WireGuardSocketObservation {
                ipv4_cookie: 23,
                ..after
            },
            WireGuardSocketObservation {
                socket_namespace: 101,
                ..after
            },
        ] {
            assert!(!same_sockets(Some(first), Some(changed)));
        }
        assert!(!same_sockets(Some(first), None));
    }

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
