//! Привязка системного DHCPv4-лизинга к маршруту и параметрам сокета.

pub(crate) use super::systemd_network_service::dhcpcd_instance_cgroup;
use super::{
    dhcp_dhcpcd_control::{ControlLease, read_lease as read_dhcpcd},
    memory::ByteBudget,
    resolver_stub::CaptureCredits,
    systemd_network_service::{
        Daemon, NetworkService, daemon as capture_daemon, dhcpcd_daemon, property, same_pid,
        trusted_connection,
    },
};
use crate::{
    Cancellation, KernelRoute, LookupIncomplete, NetworkNamespace, NetworkReadError as Error,
    RouteKind, RouteQuery, TransportProtocol,
    attribution::broker::{
        Unavailable as SocketReadError,
        kernel::{Listener, ListenerSet, listener_census},
    },
    network::{
        RouteCapture, lookup_route_captured, read_topology_captured, same_captured_kernel_route,
        same_captured_topology,
    },
};
use rustix::{
    process::{Pid, PidfdFlags, pidfd_open},
    time::{ClockId, clock_gettime},
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    num::{NonZeroU32, NonZeroU64},
    os::fd::OwnedFd,
    sync::{LazyLock, atomic::AtomicBool},
    time::Duration,
};
use tokio::time::Instant;
use zbus::{
    Connection,
    fdo::DBusProxy,
    names::OwnedUniqueName,
    zvariant::{OwnedObjectPath, OwnedValue},
};

const VALIDITY: Duration = Duration::from_secs(2);
pub(crate) const DHCP_PROBE_TIMEOUT: Duration = Duration::from_millis(100);
pub(crate) const DHCP_PROBE_CONCURRENCY: usize = 4;
const MAX_REPLY: usize = 64 * 1024;
const CLIENT_PORT: u16 = 68;
const SERVER_PORT: u16 = 67;
pub(crate) const NETWORKD_DSCPS: [u8; 3] = [0, 32, 48]; // none, CS4, CS6.
static CAPTURE_BUDGET: LazyLock<(ByteBudget, ByteBudget, ByteBudget)> = LazyLock::new(|| {
    (
        ByteBudget::new(16),
        ByteBudget::new(4),
        ByteBudget::new(4 * MAX_REPLY),
    )
});

#[derive(Debug, PartialEq, Eq)]
struct Lease {
    index: u32,
    name: String,
    address: Ipv4Addr,
    server: Ipv4Addr,
    prefix: u8,
    timing: LeaseTiming,
}

#[derive(Debug, PartialEq, Eq)]
enum LeaseTiming {
    Networkd {
        acquired: u64,
        t1: u64,
        t2: u64,
        address_lifetimes: Option<[u64; 2]>,
    },
    NetworkManager {
        config: OwnedObjectPath,
        acquired: u64,
        expiry: u64,
        duration: u32,
    },
    Dhcpcd {
        acquired: u64,
        duration: u32,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DhcpSource {
    Bus(NetworkService),
    Dhcpcd,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LinkDescription {
    index: u32,
    name: String,
    addresses: Vec<AddressDescription>,
    #[serde(rename = "DHCPv4Client")]
    dhcp: Option<ClientDescription>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AddressDescription {
    family: u8,
    address: Vec<u8>,
    prefix_length: u8,
    config_source: String,
    config_state: String,
    config_provider: Option<Vec<u8>>,
    #[serde(rename = "PreferredLifetimeUSec")]
    preferred: Option<u64>,
    #[serde(rename = "ValidLifetimeUSec")]
    valid: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ClientDescription {
    lease: Option<LeaseTimes>,
}

#[derive(Deserialize)]
struct LeaseTimes {
    #[serde(rename = "LeaseTimestampUSec")]
    acquired: u64,
    #[serde(rename = "Timeout1USec")]
    t1: u64,
    #[serde(rename = "Timeout2USec")]
    t2: u64,
}

fn parse_lease(json: &str, index: u32, now: u64) -> Result<Lease, Error> {
    if json.len() > MAX_REPLY {
        return Err(Error::Limit);
    }
    let link: LinkDescription = serde_json::from_str(json).map_err(|_| Error::Malformed)?;
    if link.index != index {
        return Err(Error::Changed);
    }
    let lease = link
        .dhcp
        .and_then(|client| client.lease)
        .ok_or(Error::Unsupported)?;
    if !(0 < lease.acquired && lease.acquired < lease.t1 && lease.t1 < lease.t2) {
        return Err(Error::Malformed);
    }
    if now < lease.acquired || now >= lease.t2 {
        return Err(Error::Changed);
    }
    let mut addresses = link
        .addresses
        .into_iter()
        .filter(|address| address.family == 2 && address.config_source == "DHCPv4");
    let address = addresses.next().ok_or(Error::Unsupported)?;
    if addresses.next().is_some()
        || address.config_state != "configured"
        || !(1..=32).contains(&address.prefix_length)
    {
        return Err(Error::Unsupported);
    }
    let address_bytes = ipv4(address.address)?;
    let server = ipv4(address.config_provider.ok_or(Error::Unsupported)?)?;
    let address_lifetimes = address
        .preferred
        .zip(address.valid)
        .and_then(|(preferred, valid)| {
            (lease.t2 <= preferred && preferred <= valid && valid < u64::MAX)
                .then_some([preferred, valid])
        });
    if address_bytes == server {
        return Err(Error::Unsupported);
    }
    Ok(Lease {
        index,
        name: link.name,
        address: address_bytes,
        server,
        prefix: address.prefix_length,
        timing: LeaseTiming::Networkd {
            acquired: lease.acquired,
            t1: lease.t1,
            t2: lease.t2,
            address_lifetimes,
        },
    })
}

fn ipv4(bytes: Vec<u8>) -> Result<Ipv4Addr, Error> {
    let octets: [u8; 4] = bytes.try_into().map_err(|_| Error::Malformed)?;
    let ip = Ipv4Addr::from(octets);
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
        return Err(Error::Unsupported);
    }
    Ok(ip)
}

pub struct DhcpNetworkdLease {
    lease: Lease,
    source: DhcpSource,
    daemon: Daemon,
    namespace: NetworkNamespace,
    socket: Option<Listener>,
    routes: Vec<(KernelRoute, RouteCapture)>,
    pidfd: OwnedFd,
    expires: u64,
    address_lifetimes: Option<[u64; 2]>,
    cancellation: Cancellation,
    revoked: bool,
}

impl DhcpNetworkdLease {
    /// Читает только networkd и ядро. Разрешение nft требует отдельной установки.
    pub async fn capture(index: NonZeroU32, cancel: &mut Cancellation) -> Result<Self, Error> {
        Self::capture_source(index, DhcpSource::Bus(NetworkService::Networkd), cancel).await
    }

    pub(super) async fn capture_managed(
        index: NonZeroU32,
        cancel: &mut Cancellation,
    ) -> Result<Self, Error> {
        for source in [
            DhcpSource::Bus(NetworkService::Networkd),
            DhcpSource::Bus(NetworkService::NetworkManager),
            DhcpSource::Dhcpcd,
        ] {
            match Self::capture_source(index, source, cancel).await {
                Err(Error::Unavailable | Error::Unsupported) if source != DhcpSource::Dhcpcd => {}
                result => return result,
            }
        }
        Err(Error::Unavailable)
    }

    async fn capture_source(
        index: NonZeroU32,
        source: DhcpSource,
        cancel: &mut Cancellation,
    ) -> Result<Self, Error> {
        cancel.check().map_err(|_| Error::Cancelled)?;
        let deadline = Instant::now() + VALIDITY;
        let expires = boottime()?
            .checked_add(VALIDITY.as_micros() as u64)
            .ok_or(Error::Limit)?;
        let mut operation_cancel = cancel.clone();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::Cancelled),
            result = tokio::time::timeout_at(deadline, async {
                match source {
                    DhcpSource::Bus(service) => collect(index, service, &mut operation_cancel, deadline, expires).await,
                    DhcpSource::Dhcpcd => collect_dhcpcd(index, &mut operation_cancel, deadline, expires).await,
                }
            }) => result.map_err(|_| Error::Timeout)?,
        }
    }

    /// Срок, адреса и идентичность относятся к моменту проверки лизинга.
    pub fn path(&self) -> Option<DhcpRenewalPath<'_>> {
        let now = boottime().ok()?;
        if self.revoked
            || self.cancellation.check().is_err()
            || now >= self.expires
            || !same_pid(&self.pidfd, self.daemon.pid).ok()?
        {
            return None;
        }
        let route = &self.routes.last()?.0;
        Some(DhcpRenewalPath {
            interface: self.lease.index,
            ifname: &self.lease.name,
            address: self.lease.address,
            prefix_len: self.lease.prefix,
            acquired: match self.lease.timing {
                LeaseTiming::Networkd { acquired, .. }
                | LeaseTiming::NetworkManager { acquired, .. }
                | LeaseTiming::Dhcpcd { acquired, .. } => acquired,
            },
            network_manager: self.source == DhcpSource::Bus(NetworkService::NetworkManager),
            dhcpcd: self.source == DhcpSource::Dhcpcd,
            dhcpcd_instance: self.daemon.dhcpcd_instance,
            server: self.lease.server,
            uid: self.daemon.uid,
            cgroup_id: self.daemon.group.1,
            namespace: self.namespace,
            route_tos: self
                .socket
                .and_then(|socket| socket.tos)
                .unwrap_or(route.query.tos()),
            route_mark: route.query.mark(),
            route_dscps: self
                .routes
                .iter()
                .fold(0, |mask, (route, _)| mask | (1 << (route.query.tos() >> 2))),
            expires_boottime_micros: self.expires,
        })
    }

    pub(crate) fn remaining(&self) -> Option<Duration> {
        let path = self.path()?;
        Some(Duration::from_micros(
            path.expires_boottime_micros.checked_sub(boottime().ok()?)?,
        ))
    }

    pub(crate) fn address_expiries(&self) -> Option<[Instant; 2]> {
        let [preferred, valid] = self.address_lifetimes?;
        let now = boottime().ok()?;
        let sample = Instant::now();
        let expiry =
            |value: u64| sample.checked_add(Duration::from_micros(value.checked_sub(now)?));
        Some([expiry(preferred)?, expiry(valid)?])
    }

    /// Ошибка чтения, изменения лизинга или завершение проверки через Drop
    /// отзывают предыдущий снимок до следующего await.
    pub async fn revalidate(&mut self, cancel: &mut Cancellation) -> Result<(), Error> {
        let was_current = self.path().is_some();
        self.revoked = true;
        if !was_current {
            return Err(Error::Changed);
        }
        let mut current = Self::capture_source(
            NonZeroU32::new(self.lease.index).ok_or(Error::Malformed)?,
            self.source,
            cancel,
        )
        .await?;
        self.cancellation.check().map_err(|_| Error::Cancelled)?;
        if boottime()? >= self.expires
            || !same_pid(&self.pidfd, self.daemon.pid)?
            || self.daemon != current.daemon
            || self.lease != current.lease
            || self.socket != current.socket
            || self.routes.len() != current.routes.len()
            || !self
                .routes
                .iter()
                .zip(&current.routes)
                .all(|(before, after)| {
                    same_captured_kernel_route(&before.0, &after.0, Some((before.1, after.1)))
                })
        {
            return Err(Error::Changed);
        }
        current.cancellation = self.cancellation.clone();
        *self = current;
        Ok(())
    }
}

pub struct DhcpRenewalPath<'a> {
    pub interface: u32,
    pub ifname: &'a str,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub(crate) acquired: u64,
    pub(crate) network_manager: bool,
    pub(crate) dhcpcd: bool,
    pub(crate) dhcpcd_instance: bool,
    pub server: Ipv4Addr,
    pub uid: u32,
    pub cgroup_id: NonZeroU64,
    pub namespace: NetworkNamespace,
    /// Параметры поиска маршрута проверяются по DSCP и метке пакета в nftables.
    pub route_tos: u8,
    pub route_mark: u32,
    pub(crate) route_dscps: u64,
    pub expires_boottime_micros: u64,
}

async fn collect(
    index: NonZeroU32,
    service: NetworkService,
    cancel: &mut Cancellation,
    deadline: Instant,
    expires: u64,
) -> Result<DhcpNetworkdLease, Error> {
    let connection = trusted_connection().await?;
    let bus = DBusProxy::new(&connection).await.map_err(unavailable)?;
    let daemon = capture_daemon(&connection, &bus, service).await?;
    let raw = i32::try_from(daemon.pid).map_err(unavailable)?;
    let pidfd = pidfd_open(
        Pid::from_raw(raw).ok_or(Error::Malformed)?,
        PidfdFlags::NONBLOCK,
    )
    .map_err(unavailable)?;
    let (topology, timing) = read_topology_captured(cancel, remaining(deadline)?).await?;
    let link = topology
        .links
        .iter()
        .find(|link| link.index == index.get())
        .ok_or(Error::Changed)?;
    let ifname = std::str::from_utf8(&link.name).map_err(|_| Error::Unsupported)?;
    let describe_current = || async {
        match service {
            NetworkService::Networkd => describe(&connection, &daemon.owner, index.get()).await,
            NetworkService::NetworkManager => {
                describe_network_manager(&connection, &daemon.owner, index.get(), ifname).await
            }
            NetworkService::Resolved => Err(Error::Unsupported),
        }
    };
    let lease = describe_current().await?;
    // UP и LOWER_UP, ARPHRD_ETHER. Не выдаём доказательство для down/loopback.
    if link.flags & (1 | 0x10000) != (1 | 0x10000)
        || link.link_type != 1
        || link.name != lease.name.as_bytes()
    {
        return Err(Error::Changed);
    }
    let kernel_address = topology
        .addresses
        .iter()
        .find(|address| {
            address.index == index.get()
                && address.family == 2
                && address.prefix_len == lease.prefix
                && address.local.unwrap_or(address.address) == lease.address
                && address.flags & (0x08 | 0x40) == 0
        })
        .ok_or(Error::Changed)?;
    let (cutoff, address_lifetimes) = match lease.timing {
        LeaseTiming::Networkd {
            t2,
            address_lifetimes,
            ..
        } => (t2, address_lifetimes),
        LeaseTiming::NetworkManager {
            expiry, duration, ..
        } => network_manager_expiries(kernel_address, expiry, duration, timing.family(2).start)?,
        LeaseTiming::Dhcpcd { .. } => return Err(Error::Unsupported),
    };
    let expires = expires.min(cutoff);
    let socket = sample_socket(topology.namespace, &lease, &daemon, service, deadline).await?;
    let observed = socket
        .map(|socket| socket.tos.zip(socket.mark).ok_or(Error::Unsupported))
        .transpose()?;
    let mark = observed.map_or(0, |(_, mark)| mark);
    let standard = NETWORKD_DSCPS.map(|dscp| dscp << 2);
    // networkd может открыть сокет вместе с первой отправкой. Проверяем
    // каждый штатный DSCP, который nftables сможет проверить на самом пакете.
    let candidates = match &observed {
        Some((tos, _)) if service == NetworkService::NetworkManager => std::slice::from_ref(tos),
        Some((tos, mark)) if *mark != 0 || !standard.contains(tos) => std::slice::from_ref(tos),
        _ => &standard,
    };
    let query = RouteQuery::new(lease.server.into(), daemon.uid)
        .with_source(lease.address.into())?
        .with_interfaces(None, Some(index))
        .with_mark(mark)
        .with_transport(TransportProtocol::Udp, Some(CLIENT_PORT), Some(SERVER_PORT));
    let mut routes = Vec::with_capacity(candidates.len());
    for &tos in candidates {
        let observed_tos = observed.is_some_and(|(actual, _)| actual == tos);
        let route =
            match lookup_route_captured(query.clone().with_tos(tos), cancel, remaining(deadline)?)
                .await
            {
                Ok(route) => route,
                Err(Error::Kernel(code))
                    if !observed_tos
                        && [
                            rustix::io::Errno::NETUNREACH,
                            rustix::io::Errno::HOSTUNREACH,
                        ]
                        .iter()
                        .any(|error| error.raw_os_error() == code) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
        if route.0.namespace != topology.namespace {
            return Err(Error::Unsupported);
        }
        // При неудачном FIB lookup Linux может построить on-link маршрут
        // только из заданного oif. У синтетического ответа нет таблицы FIB.
        match route.0.incomplete.as_slice() {
            [] => {}
            [LookupIncomplete::MissingTable] if !observed_tos => continue,
            _ => return Err(Error::Unsupported),
        }
        if route.0.kind == RouteKind::Unicast && route.0.output_interface == Some(index) {
            routes.push(route);
        } else if observed_tos {
            return Err(Error::Unsupported);
        }
    }
    if routes.is_empty() {
        return Err(Error::Unsupported);
    }
    let (after, after_timing) = read_topology_captured(cancel, remaining(deadline)?).await?;
    if !same_captured_topology(&topology, timing, &after, after_timing)
        || lease != describe_current().await?
        || daemon != capture_daemon(&connection, &bus, service).await?
        || socket != sample_socket(topology.namespace, &lease, &daemon, service, deadline).await?
        || !same_pid(&pidfd, daemon.pid)?
        || boottime()? >= expires
    {
        return Err(Error::Changed);
    }
    Ok(DhcpNetworkdLease {
        lease,
        source: DhcpSource::Bus(service),
        daemon,
        namespace: topology.namespace,
        socket,
        routes,
        pidfd,
        expires,
        address_lifetimes,
        cancellation: cancel.clone(),
        revoked: false,
    })
}

async fn sample_socket(
    namespace: NetworkNamespace,
    lease: &Lease,
    daemon: &Daemon,
    service: NetworkService,
    deadline: Instant,
) -> Result<Option<Listener>, Error> {
    let uid = daemon.uid;
    let group = daemon.group.1.get();
    let address = lease.address.octets();
    let server = lease.server.octets();
    let index = lease.index;
    let rows = socket_rows(namespace, 17, CLIENT_PORT, deadline).await?;
    let mut matches = rows.iter().filter(|socket| {
        socket.family == 2
            && socket.local[..4] == address
            && if service == NetworkService::NetworkManager {
                socket.state == 1
                    && socket.remote_port == SERVER_PORT
                    && socket.remote[..4] == server
            } else {
                socket.remote_port == 0
            }
            && socket.interface == index
            && socket.uid == uid
            && socket.cgroup == group
            && socket.inode != 0
    });
    let socket = matches.next().copied();
    if matches.next().is_some() || (socket.is_none() && service == NetworkService::NetworkManager) {
        return Err(Error::Unsupported);
    }
    Ok(socket)
}

async fn socket_rows(
    namespace: NetworkNamespace,
    protocol: u8,
    port: u16,
    deadline: Instant,
) -> Result<ListenerSet, Error> {
    let (fds, pending, bytes) = &*CAPTURE_BUDGET;
    let credits = CaptureCredits::reserve_shared(fds, pending, bytes).map_err(unavailable)?;
    tokio::task::spawn_blocking(move || {
        let cancelled = AtomicBool::new(false);
        let read = || {
            listener_census(
                protocol,
                port,
                (namespace.device, namespace.inode),
                deadline.into_std(),
                &cancelled,
                &credits,
            )
        };
        match read() {
            // Повтор после загрузки обработчика SOCK_DIAG в пределах исходного дедлайна.
            Err(SocketReadError::Timeout) if Instant::now() < deadline => read(),
            result => result,
        }
        .map_err(unavailable)
    })
    .await
    .map_err(unavailable)?
}

async fn dhcpcd_socket(
    namespace: NetworkNamespace,
    group: NonZeroU64,
    index: NonZeroU32,
    address: Ipv4Addr,
    deadline: Instant,
) -> Result<Listener, Error> {
    const IPPROTO_RAW: u8 = 255;
    const IPPROTO_UDP: u16 = 17;
    let rows = socket_rows(namespace, IPPROTO_RAW, IPPROTO_UDP, deadline).await?;
    let mut matches = rows.iter().filter(|socket| {
        socket.uid == 0
            && socket.cgroup == group.get()
            && socket.inode != 0
            && (socket.interface == 0 || socket.interface == index.get())
            && (socket.local[..4] == [0; 4] || socket.local[..4] == address.octets())
            && socket.remote == [0; 16]
            && socket.remote_port == 0
    });
    let socket = matches.next().copied().ok_or(Error::Unsupported)?;
    if matches.next().is_some() {
        return Err(Error::Unsupported);
    }
    Ok(socket)
}

async fn collect_dhcpcd(
    index: NonZeroU32,
    cancel: &mut Cancellation,
    deadline: Instant,
    expires: u64,
) -> Result<DhcpNetworkdLease, Error> {
    let connection = trusted_connection().await?;
    let bus = DBusProxy::new(&connection).await.map_err(unavailable)?;
    let (topology, timing) = read_topology_captured(cancel, remaining(deadline)?).await?;
    let link = topology
        .links
        .iter()
        .find(|link| link.index == index.get())
        .ok_or(Error::Changed)?;
    if link.flags & (1 | 0x10000) != (1 | 0x10000) || link.link_type != 1 {
        return Err(Error::Unsupported);
    }
    if !topology.addresses.iter().any(|address| {
        address.index == index.get()
            && address.family == 2
            && address.scope == 0
            && address.flags & (0x08 | 0x40 | 0x80) == 0
    }) {
        return Err(Error::Unsupported);
    }
    let name = std::str::from_utf8(&link.name).map_err(|_| Error::Unsupported)?;
    let state = read_dhcpcd(name, deadline).await?;
    let daemon = dhcpcd_daemon(&connection, &bus, state.peer_pid, name).await?;
    let mut candidates = topology.addresses.iter().filter(|address| {
        address.index == index.get()
            && address.family == 2
            && address.scope == 0
            && address.prefix_len == state.prefix
            && address.local.unwrap_or(address.address) == state.address
            && address.flags & (0x08 | 0x40 | 0x80) == 0
    });
    let address = candidates.next().ok_or(Error::Changed)?;
    if candidates.next().is_some() {
        return Err(Error::Changed);
    }
    let lease_time = dhcpcd_lifetimes(address, state.duration, timing.family(2).start)?;
    let expires = expires.min(lease_time.cutoff);
    let socket = dhcpcd_socket(
        topology.namespace,
        daemon.group.1,
        index,
        state.address,
        deadline,
    )
    .await?;
    let (tos, mark) = socket.tos.zip(socket.mark).ok_or(Error::Unsupported)?;
    let query = RouteQuery::new(state.server.into(), daemon.uid)
        .with_source(state.address.into())?
        .with_interfaces(None, Some(index))
        .with_mark(mark)
        .with_tos(tos)
        .with_transport(TransportProtocol::Udp, Some(CLIENT_PORT), Some(SERVER_PORT));
    let route = lookup_route_captured(query, cancel, remaining(deadline)?).await?;
    if route.0.namespace != topology.namespace
        || route.0.kind != RouteKind::Unicast
        || route.0.output_interface != Some(index)
        || !route.0.incomplete.is_empty()
    {
        return Err(Error::Unsupported);
    }
    let after_state = read_dhcpcd(name, deadline).await?;
    let (after, after_timing) = read_topology_captured(cancel, remaining(deadline)?).await?;
    if !same_captured_topology(&topology, timing, &after, after_timing)
        || !same_dhcpcd_lease(&state, &after_state)?
        || daemon != dhcpcd_daemon(&connection, &bus, state.peer_pid, name).await?
        || socket
            != dhcpcd_socket(
                topology.namespace,
                daemon.group.1,
                index,
                state.address,
                deadline,
            )
            .await?
        || !same_pid(&state.peer_pidfd, state.peer_pid)?
        || boottime()? >= expires
    {
        return Err(Error::Changed);
    }
    Ok(DhcpNetworkdLease {
        lease: Lease {
            index: index.get(),
            name: name.to_owned(),
            address: state.address,
            server: state.server,
            prefix: state.prefix,
            timing: LeaseTiming::Dhcpcd {
                acquired: lease_time.acquired,
                duration: state.duration,
            },
        },
        source: DhcpSource::Dhcpcd,
        daemon,
        namespace: topology.namespace,
        socket: Some(socket),
        routes: vec![route],
        pidfd: state.peer_pidfd,
        expires,
        address_lifetimes: Some(lease_time.expiries),
        cancellation: cancel.clone(),
        revoked: false,
    })
}

fn same_dhcpcd_lease(before: &ControlLease, after: &ControlLease) -> Result<bool, Error> {
    Ok(before.peer_pid == after.peer_pid
        && before.address == after.address
        && before.server == after.server
        && before.prefix == after.prefix
        && before.duration == after.duration
        && same_pid(&after.peer_pidfd, after.peer_pid)?)
}

async fn describe(
    connection: &Connection,
    owner: &OwnedUniqueName,
    index: u32,
) -> Result<Lease, Error> {
    let proxy = zbus::Proxy::new(
        connection,
        owner.as_str(),
        "/org/freedesktop/network1",
        "org.freedesktop.network1.Manager",
    )
    .await
    .map_err(unavailable)?;
    let index_for_bus = i32::try_from(index).map_err(unavailable)?;
    let reply = proxy
        .call_method("DescribeLink", &(index_for_bus,))
        .await
        .map_err(unavailable)?;
    if reply.body().len() > MAX_REPLY {
        return Err(Error::Limit);
    }
    let body = reply.body();
    let json: &str = body.deserialize().map_err(unavailable)?;
    parse_lease(json, index, boottime()?)
}

async fn describe_network_manager(
    connection: &Connection,
    owner: &OwnedUniqueName,
    index: u32,
    ifname: &str,
) -> Result<Lease, Error> {
    const MANAGER: &str = "org.freedesktop.NetworkManager";
    const DEVICE: &str = "org.freedesktop.NetworkManager.Device";
    let proxy = zbus::Proxy::new(
        connection,
        owner.as_str(),
        "/org/freedesktop/NetworkManager",
        MANAGER,
    )
    .await
    .map_err(unavailable)?;
    let reply = proxy
        .call_method("GetDeviceByIpIface", &(ifname,))
        .await
        .map_err(unavailable)?;
    if reply.body().len() > MAX_REPLY {
        return Err(Error::Limit);
    }
    let device: OwnedObjectPath = reply.body().deserialize().map_err(unavailable)?;
    let properties = zbus::Proxy::new(
        connection,
        owner.as_str(),
        device.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .map_err(unavailable)?;
    if property::<u32>(&properties, DEVICE, "State").await? != 100
        || property::<String>(&properties, DEVICE, "IpInterface").await? != ifname
    {
        return Err(Error::Unsupported);
    }
    let config: OwnedObjectPath = property(&properties, DEVICE, "Dhcp4Config").await?;
    if config.as_str() == "/" {
        return Err(Error::Unsupported);
    }
    let properties = zbus::Proxy::new(
        connection,
        owner.as_str(),
        config.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .map_err(unavailable)?;
    let options: HashMap<String, OwnedValue> = property(
        &properties,
        "org.freedesktop.NetworkManager.DHCP4Config",
        "Options",
    )
    .await?;
    let read = |key: &str| {
        options
            .get(key)
            .ok_or(Error::Unsupported)
            .and_then(|value| <&str>::try_from(value).map_err(|_| Error::Malformed))
    };
    let ip = |key| {
        let address: Ipv4Addr = read(key)?.parse().map_err(|_| Error::Malformed)?;
        ipv4(address.octets().to_vec())
    };
    let address = ip("ip_address")?;
    let server = ip("dhcp_server_identifier")?;
    let mask = u32::from(
        read("subnet_mask")?
            .parse::<Ipv4Addr>()
            .map_err(|_| Error::Malformed)?,
    );
    let prefix = mask.leading_ones();
    if prefix == 0 || mask.trailing_zeros() != 32 - prefix || address == server {
        return Err(Error::Unsupported);
    }
    let expiry: u64 = read("expiry")?.parse().map_err(|_| Error::Malformed)?;
    let duration: u32 = read("dhcp_lease_time")?
        .parse()
        .map_err(|_| Error::Malformed)?;
    let acquired = expiry
        .checked_sub(u64::from(duration))
        .ok_or(Error::Malformed)?;
    Ok(Lease {
        index,
        name: ifname.to_owned(),
        address,
        server,
        prefix: prefix as u8,
        timing: LeaseTiming::NetworkManager {
            config,
            acquired,
            expiry,
            duration,
        },
    })
}

fn network_manager_expiries(
    address: &crate::network::LinuxAddress,
    expiry: u64,
    duration: u32,
    captured: Instant,
) -> Result<(u64, Option<[u64; 2]>), Error> {
    let [preferred, valid, _, _] = address_cache(address)?;
    let wall = u64::try_from(clock_gettime(ClockId::Realtime).tv_sec).map_err(unavailable)?;
    let wall_remaining = expiry.checked_sub(wall).ok_or(Error::Changed)?;
    if preferred <= 1
        || preferred > valid
        || valid > duration
        || duration == u32::MAX
        || wall_remaining == 0
        || wall_remaining > u64::from(duration)
        || wall_remaining.abs_diff(u64::from(valid)) > 2
    {
        return Err(Error::Unsupported);
    }
    let boot = boottime()?;
    let before = boot
        .checked_sub(u64::try_from(captured.elapsed().as_micros()).map_err(unavailable)?)
        .ok_or(Error::Changed)?;
    let add = |seconds: u32| {
        before
            .checked_add(u64::from(seconds) * 1_000_000)
            .ok_or(Error::Limit)
    };
    // Ядро округляет остаток до секунд. Вычитаем секунду для допуска;
    // исходные сроки нужны только для сверки принятого обновления адреса.
    Ok((add(preferred - 1)?, Some([add(preferred)?, add(valid)?])))
}

fn boottime() -> Result<u64, Error> {
    clock_micros(ClockId::Boottime)
}

fn clock_micros(clock: ClockId) -> Result<u64, Error> {
    let time = clock_gettime(clock);
    let seconds = u64::try_from(time.tv_sec).map_err(unavailable)?;
    let nanos = u64::try_from(time.tv_nsec).map_err(unavailable)?;
    seconds
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(nanos / 1000))
        .ok_or(Error::Limit)
}

fn address_cache(address: &crate::network::LinuxAddress) -> Result<[u32; 4], Error> {
    let mut cache = address
        .unknown
        .iter()
        .filter(|attribute| attribute.kind == 6);
    let bytes = &cache.next().ok_or(Error::Unsupported)?.value;
    if bytes.len() != 16 || cache.next().is_some() {
        return Err(Error::Malformed);
    }
    let mut fields = [0; 4];
    for (field, bytes) in fields.iter_mut().zip(bytes.chunks_exact(4)) {
        *field = u32::from_ne_bytes(bytes.try_into().map_err(|_| Error::Malformed)?);
    }
    Ok(fields)
}

struct DhcpcdLifetimes {
    acquired: u64,
    cutoff: u64,
    expiries: [u64; 2],
}

fn dhcpcd_lifetimes(
    address: &crate::network::LinuxAddress,
    duration: u32,
    captured: Instant,
) -> Result<DhcpcdLifetimes, Error> {
    let [preferred, valid, _, updated] = address_cache(address)?;
    let boot = boottime()?;
    let mono = clock_micros(ClockId::Monotonic)?;
    let elapsed = u64::try_from(captured.elapsed().as_micros()).map_err(unavailable)?;
    let captured_mono_cs = mono.checked_sub(elapsed).ok_or(Error::Changed)? / 10_000;
    let captured_boot = boot.checked_sub(elapsed).ok_or(Error::Changed)?;
    checked_dhcpcd_lifetimes(
        preferred,
        valid,
        updated,
        duration,
        captured_mono_cs,
        captured_boot,
    )
}

fn checked_dhcpcd_lifetimes(
    preferred: u32,
    valid: u32,
    updated: u32,
    duration: u32,
    captured_mono_cs: u64,
    captured_boot: u64,
) -> Result<DhcpcdLifetimes, Error> {
    // IFA_CACHEINFO хранит tstamp в сотых секунды с переполнением u32.
    let age_cs = u64::from((captured_mono_cs as u32).wrapping_sub(updated));
    let duration_cs = u64::from(duration) * 100;
    if preferred <= 1
        || preferred >= valid
        || valid > duration
        || age_cs >= duration_cs
        || (age_cs + u64::from(valid) * 100).abs_diff(duration_cs) > 110
    {
        return Err(Error::Changed);
    }
    let add = |seconds: u32| {
        captured_boot
            .checked_add(u64::from(seconds) * 1_000_000)
            .ok_or(Error::Limit)
    };
    let acquired = captured_mono_cs.checked_sub(age_cs).ok_or(Error::Changed)?;
    Ok(DhcpcdLifetimes {
        acquired,
        cutoff: add(preferred - 1)?,
        expiries: [add(preferred)?, add(valid)?],
    })
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(Error::Timeout)
    } else {
        Ok(remaining)
    }
}

fn unavailable<T: std::fmt::Debug>(_error: T) -> Error {
    #[cfg(any(test, feature = "test-support"))]
    if std::env::var_os("YONIK_SESSION_DIAGNOSTICS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        eprintln!("session diagnostic dhcp_capture: {_error:?}");
    }
    Error::Unavailable
}

#[cfg(test)]
mod tests {
    use super::{Error, checked_dhcpcd_lifetimes, parse_lease, same_pid};
    use serde_json::json;

    fn describe() -> serde_json::Value {
        json!({
            "Index": 3, "Name": "eth0",
            "Addresses": [{"Family": 2, "Address": [192,0,2,20], "PrefixLength": 24,
                "ConfigProvider": [192,0,2,1], "ConfigSource": "DHCPv4", "ConfigState": "configured"}],
            "DHCPv4Client": {"Lease": {"LeaseTimestampUSec": 100, "Timeout1USec": 300, "Timeout2USec": 500}}
        })
    }

    #[test]
    fn accepts_only_one_current_v4_lease() {
        let mut link = describe();
        let lease = parse_lease(&link.to_string(), 3, 200).expect("Лизинг DHCPv4");
        assert_eq!(lease.server.octets(), [192, 0, 2, 1]);
        assert_eq!(lease.address.octets(), [192, 0, 2, 20]);
        assert_eq!(parse_lease(&link.to_string(), 3, 500), Err(Error::Changed));
        assert_eq!(parse_lease(&link.to_string(), 4, 200), Err(Error::Changed));
        let second = link["Addresses"][0].clone();
        link["Addresses"]
            .as_array_mut()
            .expect("Адреса")
            .push(second);
        assert_eq!(
            parse_lease(&link.to_string(), 3, 200),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn reconstructs_current_dhcpcd_generation_across_cacheinfo_wrap() {
        let generation = u64::from(u32::MAX) + 1 - 20;
        let sampled =
            checked_dhcpcd_lifetimes(34, 40, generation as u32, 42, generation + 240, 500)
                .expect("Лизинг с согласованным сроком");
        assert_eq!(sampled.acquired, generation);
        assert_eq!(sampled.cutoff, 33_000_500);
        assert_eq!(sampled.expiries, [34_000_500, 40_000_500]);
    }

    #[test]
    fn rejects_dhcpcd_lease_with_stale_or_expired_address_time() {
        for (preferred, valid, updated) in [(34, 40, 650), (0, 5, 400), (39, 42, 750)] {
            assert!(matches!(
                checked_dhcpcd_lifetimes(preferred, valid, updated, 42, 1000, 500),
                Err(Error::Changed)
            ));
        }
    }

    #[test]
    fn reap_is_not_required_to_reject_an_exited_pid() {
        use rustix::process::{Pid, PidfdFlags, WaitId, WaitIdOptions, pidfd_open, waitid};
        use std::os::fd::AsFd;

        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("Тестовый процесс");
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("PID")).expect("PID");
        let fd = pidfd_open(pid, PidfdFlags::empty()).expect("pidfd");
        waitid(
            WaitId::PidFd(fd.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )
        .expect("Выход процесса без reap");
        let was_live = same_pid(&fd, child.id());
        child.wait().expect("Освобождение тестового процесса");
        assert_eq!(was_live, Ok(false));
    }
}
