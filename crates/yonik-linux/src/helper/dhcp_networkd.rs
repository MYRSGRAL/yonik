//! Read-only привязка DHCPv4-лизинга networkd к адресу, сокету и маршруту ядра.

use super::{
    memory::ByteBudget,
    resolver_stub::{CaptureCredits, bounded_socket},
};
use crate::{
    Cancellation, KernelRoute, NetworkNamespace, NetworkReadError as Error, RouteKind, RouteQuery,
    TransportProtocol,
    attribution::broker::kernel::{Listener, listener_census},
    network::{
        RouteCapture, lookup_route_captured, read_topology_captured, same_captured_kernel_route,
        same_captured_topology,
    },
};
use rustix::{
    fs::{Mode, OFlags, open, openat},
    process::{Pid, PidfdFlags, pidfd_open},
    time::{ClockId, clock_gettime},
};
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    net::Ipv4Addr,
    num::{NonZeroU32, NonZeroU64},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    sync::{LazyLock, atomic::AtomicBool},
    time::Duration,
};
use tokio::time::Instant;
use zbus::{
    Connection,
    fdo::DBusProxy,
    names::{BusName, OwnedUniqueName},
};

const VALIDITY: Duration = Duration::from_secs(2);
const MAX_REPLY: usize = 64 * 1024;
const GROUP: &str = "/system.slice/systemd-networkd.service";
const NETWORKD: &str = "org.freedesktop.network1";
const SYSTEMD: &str = "org.freedesktop.systemd1";
const CLIENT_PORT: u16 = 68;
const SERVER_PORT: u16 = 67;
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
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
    acquired: u64,
    t1: u64,
    t2: u64,
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
    if address_bytes == server {
        return Err(Error::Unsupported);
    }
    Ok(Lease {
        index,
        name: link.name,
        address: address_bytes,
        server,
        prefix: address.prefix_length,
        acquired: lease.acquired,
        t1: lease.t1,
        t2: lease.t2,
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

#[derive(PartialEq, Eq)]
struct Daemon {
    owner: OwnedUniqueName,
    uid: u32,
    pid: u32,
    invocation: [u8; 16],
    group: (u64, NonZeroU64),
}

pub struct DhcpNetworkdLease {
    lease: Lease,
    daemon: Daemon,
    namespace: NetworkNamespace,
    socket: Listener,
    route: (KernelRoute, RouteCapture),
    pidfd: OwnedFd,
    expires: u64,
    cancellation: Cancellation,
    revoked: bool,
}

impl DhcpNetworkdLease {
    /// Читает только networkd и ядро. Разрешение nft требует отдельной установки.
    pub async fn capture(index: NonZeroU32, cancel: &mut Cancellation) -> Result<Self, Error> {
        cancel.check().map_err(|_| Error::Cancelled)?;
        let deadline = Instant::now() + VALIDITY;
        let expires = boottime()?
            .checked_add(VALIDITY.as_micros() as u64)
            .ok_or(Error::Limit)?;
        let mut operation_cancel = cancel.clone();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::Cancelled),
            result = tokio::time::timeout_at(deadline, collect(index, &mut operation_cancel, deadline, expires)) =>
                result.map_err(|_| Error::Timeout)?,
        }
    }

    /// Срок, адреса и идентичность относятся к моменту проверки сокета.
    pub fn path(&self) -> Option<DhcpRenewalPath<'_>> {
        let now = boottime().ok()?;
        if self.revoked
            || self.cancellation.check().is_err()
            || now >= self.expires.min(self.lease.t2)
            || !same_pid(&self.pidfd, self.daemon.pid).ok()?
        {
            return None;
        }
        Some(DhcpRenewalPath {
            interface: self.lease.index,
            ifname: &self.lease.name,
            address: self.lease.address,
            server: self.lease.server,
            uid: self.daemon.uid,
            cgroup_id: self.daemon.group.1,
            namespace: self.namespace,
            route_tos: self.route.0.query.tos(),
            route_mark: self.route.0.query.mark(),
            expires_boottime_micros: self.expires.min(self.lease.t2),
        })
    }

    /// Ошибка чтения, изменения лизинга или завершение проверки через Drop
    /// отзывают предыдущий снимок до следующего await.
    pub async fn revalidate(&mut self, cancel: &mut Cancellation) -> Result<(), Error> {
        let was_current = self.path().is_some();
        self.revoked = true;
        if !was_current {
            return Err(Error::Changed);
        }
        let mut current = Self::capture(
            NonZeroU32::new(self.lease.index).ok_or(Error::Malformed)?,
            cancel,
        )
        .await?;
        self.cancellation.check().map_err(|_| Error::Cancelled)?;
        if boottime()? >= self.expires.min(self.lease.t2)
            || !same_pid(&self.pidfd, self.daemon.pid)?
            || self.daemon != current.daemon
            || self.lease != current.lease
            || self.socket != current.socket
            || !same_captured_kernel_route(
                &self.route.0,
                &current.route.0,
                Some((self.route.1, current.route.1)),
            )
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
    pub server: Ipv4Addr,
    pub uid: u32,
    pub cgroup_id: NonZeroU64,
    pub namespace: NetworkNamespace,
    /// Значения IP_TOS и SO_MARK прочитаны из сокета и переданы в RTM_GETROUTE.
    /// При выдаче разрешения отдельно сверяются DSCP и метка самого пакета.
    pub route_tos: u8,
    pub route_mark: u32,
    pub expires_boottime_micros: u64,
}

async fn collect(
    index: NonZeroU32,
    cancel: &mut Cancellation,
    deadline: Instant,
    expires: u64,
) -> Result<DhcpNetworkdLease, Error> {
    let stream = tokio::net::UnixStream::connect("/run/dbus/system_bus_socket")
        .await
        .map_err(unavailable)?;
    if stream.peer_cred().map_err(unavailable)?.uid() != 0 {
        return Err(Error::Unsupported);
    }
    let connection =
        zbus::connection::Builder::socket(bounded_socket(stream).map_err(unavailable)?)
            .auth_mechanism(zbus::AuthMechanism::External)
            .max_queued(1)
            .build()
            .await
            .map_err(unavailable)?;
    let bus = DBusProxy::new(&connection).await.map_err(unavailable)?;
    let daemon = daemon(&connection, &bus).await?;
    let raw = i32::try_from(daemon.pid).map_err(unavailable)?;
    let pidfd = pidfd_open(
        Pid::from_raw(raw).ok_or(Error::Malformed)?,
        PidfdFlags::NONBLOCK,
    )
    .map_err(unavailable)?;
    let lease = describe(&connection, &daemon.owner, index.get()).await?;
    let (topology, timing) = read_topology_captured(cancel, remaining(deadline)?).await?;
    let link = topology
        .links
        .iter()
        .find(|link| link.index == index.get())
        .ok_or(Error::Changed)?;
    // UP и LOWER_UP, ARPHRD_ETHER. Не выдаём доказательство для down/loopback.
    if link.flags & (1 | 0x10000) != (1 | 0x10000)
        || link.link_type != 1
        || link.name != lease.name.as_bytes()
        || !topology.addresses.iter().any(|address| {
            address.index == index.get()
                && address.family == 2
                && address.prefix_len == lease.prefix
                && address.local.unwrap_or(address.address) == lease.address
                && address.flags & (0x08 | 0x40) == 0
        })
    {
        return Err(Error::Changed);
    }
    let socket = sample_socket(topology.namespace, &lease, &daemon, deadline).await?;
    let query = RouteQuery::new(lease.server.into(), daemon.uid)
        .with_source(lease.address.into())?
        .with_interfaces(None, Some(index))
        .with_tos(socket.tos.ok_or(Error::Unsupported)?)
        .with_mark(socket.mark.ok_or(Error::Unsupported)?)
        .with_transport(TransportProtocol::Udp, Some(CLIENT_PORT), Some(SERVER_PORT));
    let route = lookup_route_captured(query, cancel, remaining(deadline)?).await?;
    if route.0.namespace != topology.namespace
        || route.0.kind != RouteKind::Unicast
        || route.0.output_interface != Some(index)
        || !route.0.incomplete.is_empty()
    {
        return Err(Error::Unsupported);
    }
    let (after, after_timing) = read_topology_captured(cancel, remaining(deadline)?).await?;
    if !same_captured_topology(&topology, timing, &after, after_timing)
        || lease != describe(&connection, &daemon.owner, index.get()).await?
        || daemon != self::daemon(&connection, &bus).await?
        || socket != sample_socket(topology.namespace, &lease, &daemon, deadline).await?
        || !same_pid(&pidfd, daemon.pid)?
        || boottime()? >= expires.min(lease.t2)
    {
        return Err(Error::Changed);
    }
    Ok(DhcpNetworkdLease {
        lease,
        daemon,
        namespace: topology.namespace,
        socket,
        route,
        pidfd,
        expires,
        cancellation: cancel.clone(),
        revoked: false,
    })
}

async fn sample_socket(
    namespace: NetworkNamespace,
    lease: &Lease,
    daemon: &Daemon,
    deadline: Instant,
) -> Result<Listener, Error> {
    let uid = daemon.uid;
    let group = daemon.group.1.get();
    let address = lease.address.octets();
    let index = lease.index;
    let (fds, pending, bytes) = &*CAPTURE_BUDGET;
    let credits = CaptureCredits::reserve_shared(fds, pending, bytes).map_err(unavailable)?;
    tokio::task::spawn_blocking(move || {
        let rows = listener_census(
            17,
            CLIENT_PORT,
            (namespace.device, namespace.inode),
            deadline.into_std(),
            &AtomicBool::new(false),
            &credits,
        )
        .map_err(unavailable)?;
        let mut matches = rows.iter().filter(|socket| {
            socket.family == 2
                && socket.local[..4] == address
                && socket.remote_port == 0
                && socket.interface == index
                && socket.uid == uid
                && socket.cgroup == group
                && socket.inode != 0
        });
        let socket = *matches.next().ok_or(Error::Unsupported)?;
        if matches.next().is_some() {
            return Err(Error::Unsupported);
        }
        Ok(socket)
    })
    .await
    .map_err(unavailable)?
}

async fn daemon(connection: &Connection, bus: &DBusProxy<'_>) -> Result<Daemon, Error> {
    let name = |value| BusName::try_from(value).map_err(unavailable);
    let systemd = bus
        .get_name_owner(name(SYSTEMD)?)
        .await
        .map_err(unavailable)?;
    if bus
        .get_connection_unix_user(name(systemd.as_str())?)
        .await
        .map_err(unavailable)?
        != 0
        || bus
            .get_connection_unix_process_id(name(systemd.as_str())?)
            .await
            .map_err(unavailable)?
            != 1
    {
        return Err(Error::Unsupported);
    }
    let owner = bus
        .get_name_owner(name(NETWORKD)?)
        .await
        .map_err(unavailable)?;
    // GetConnectionCredentials может включать ProcessFD на новых версиях шины.
    // Здесь транспорт принимает только числовые credentials.
    let pid = bus
        .get_connection_unix_process_id(name(owner.as_str())?)
        .await
        .map_err(unavailable)?;
    let uid = bus
        .get_connection_unix_user(name(owner.as_str())?)
        .await
        .map_err(unavailable)?;
    if pid <= 1 || uid == 0 {
        return Err(Error::Unsupported);
    }
    let properties = zbus::Proxy::new(
        connection,
        systemd.as_str(),
        "/org/freedesktop/systemd1/unit/systemd_2dnetworkd_2eservice",
        "org.freedesktop.DBus.Properties",
    )
    .await
    .map_err(unavailable)?;
    let invocation: Vec<u8> =
        property(&properties, "org.freedesktop.systemd1.Unit", "InvocationID").await?;
    let invocation: [u8; 16] = invocation.try_into().map_err(|_| Error::Malformed)?;
    if invocation == [0; 16]
        || property::<String>(&properties, "org.freedesktop.systemd1.Unit", "ActiveState").await?
            != "active"
        || property::<u32>(&properties, "org.freedesktop.systemd1.Service", "MainPID").await? != pid
        || property::<String>(
            &properties,
            "org.freedesktop.systemd1.Service",
            "ControlGroup",
        )
        .await?
            != GROUP
        || read_proc(&format!("/proc/{pid}/cgroup"))? != format!("0::{GROUP}\n")
    {
        return Err(Error::Changed);
    }
    let cgroup = open("/sys/fs/cgroup", DIRECTORY, Mode::empty()).map_err(unavailable)?;
    let slice = openat(&cgroup, "system.slice", DIRECTORY, Mode::empty()).map_err(unavailable)?;
    let unit = File::from(
        openat(&slice, "systemd-networkd.service", DIRECTORY, Mode::empty())
            .map_err(unavailable)?,
    );
    let metadata = unit.metadata().map_err(unavailable)?;
    if usize::BITS != 64
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || rustix::fs::fstatfs(&unit).map_err(unavailable)?.f_type as u64 != 0x6367_7270
    {
        return Err(Error::Unsupported);
    }
    let group = (
        metadata.dev(),
        NonZeroU64::new(metadata.ino()).ok_or(Error::Unsupported)?,
    );
    Ok(Daemon {
        owner,
        uid,
        pid,
        invocation,
        group,
    })
}

async fn property<T: TryFrom<zbus::zvariant::OwnedValue>>(
    proxy: &zbus::Proxy<'_>,
    interface: &str,
    key: &str,
) -> Result<T, Error> {
    let reply = proxy
        .call_method("Get", &(interface, key))
        .await
        .map_err(unavailable)?;
    if reply.body().len() > MAX_REPLY {
        return Err(Error::Limit);
    }
    let value: zbus::zvariant::OwnedValue = reply.body().deserialize().map_err(unavailable)?;
    T::try_from(value).map_err(unavailable)
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

fn read_proc(path: &str) -> Result<String, Error> {
    let mut buffer = String::new();
    File::open(path)
        .map_err(unavailable)?
        .take(4097)
        .read_to_string(&mut buffer)
        .map_err(unavailable)?;
    if buffer.len() > 4096 {
        return Err(Error::Limit);
    }
    Ok(buffer)
}

fn same_pid(fd: &OwnedFd, pid: u32) -> Result<bool, Error> {
    let fdinfo = format!("/proc/self/fdinfo/{}", fd.as_raw_fd());
    let equal = || -> Result<bool, Error> {
        Ok(read_proc(&fdinfo)?
            .lines()
            .find_map(|line| line.strip_prefix("Pid:\t"))
            .and_then(|value| value.parse().ok())
            == Some(pid))
    };
    if !equal()? {
        return Ok(false);
    }
    // До wait/reap fdinfo сохраняет PID завершённого процесса.
    let stat = read_proc(&format!("/proc/{pid}/stat"))?;
    let (_, tail) = stat.rsplit_once(") ").ok_or(Error::Malformed)?;
    let state = tail
        .split_ascii_whitespace()
        .next()
        .ok_or(Error::Malformed)?;
    Ok(!matches!(state, "Z" | "X" | "x") && equal()?)
}

fn boottime() -> Result<u64, Error> {
    let time = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(time.tv_sec).map_err(unavailable)?;
    let nanos = u64::try_from(time.tv_nsec).map_err(unavailable)?;
    seconds
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(nanos / 1000))
        .ok_or(Error::Limit)
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(Error::Timeout)
    } else {
        Ok(remaining)
    }
}

fn unavailable<T>(_: T) -> Error {
    Error::Unavailable
}

#[cfg(test)]
mod tests {
    use super::{Error, parse_lease, same_pid};
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
