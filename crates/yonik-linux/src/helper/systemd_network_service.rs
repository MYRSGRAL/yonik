//! Сверка владельца системной D-Bus службы с процессом и cgroup её unit.

use super::resolver_stub::bounded_socket;
use crate::NetworkReadError as Error;
use rustix::{
    fs::{Mode, OFlags, open, openat},
    process::{Pid, PidfdFlags, pidfd_open},
};
use std::{
    fs::File,
    io::Read,
    num::NonZeroU64,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
};
use zbus::{
    Connection,
    fdo::DBusProxy,
    names::{BusName, OwnedUniqueName},
};

const MAX_REPLY: usize = 64 * 1024;
const SYSTEMD: &str = "org.freedesktop.systemd1";
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkService {
    Networkd,
    NetworkManager,
    Resolved,
}

impl NetworkService {
    fn identity(self) -> (&'static str, &'static str, &'static str, &'static str) {
        match self {
            Self::Networkd => (
                "org.freedesktop.network1",
                "/org/freedesktop/systemd1/unit/systemd_2dnetworkd_2eservice",
                "/system.slice/systemd-networkd.service",
                "systemd-networkd.service",
            ),
            Self::NetworkManager => (
                "org.freedesktop.NetworkManager",
                "/org/freedesktop/systemd1/unit/NetworkManager_2eservice",
                "/system.slice/NetworkManager.service",
                "NetworkManager.service",
            ),
            Self::Resolved => (
                "org.freedesktop.resolve1",
                "/org/freedesktop/systemd1/unit/systemd_2dresolved_2eservice",
                "/system.slice/systemd-resolved.service",
                "systemd-resolved.service",
            ),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Daemon {
    pub(crate) owner: OwnedUniqueName,
    pub(crate) uid: u32,
    pub(crate) dynamic_uid: bool,
    pub(crate) pid: u32,
    invocation: [u8; 16],
    pub(crate) group: (u64, NonZeroU64),
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Daemon(<скрыто>)")
    }
}

pub(crate) async fn bind_resolved<T>(
    read: impl AsyncFnOnce(&Connection, &str) -> Result<T, crate::resolver::ResolverError>,
) -> Result<(T, Daemon), crate::resolver::ResolverError> {
    use crate::resolver::ResolverError;

    let map = |error| match error {
        Error::Unsupported => ResolverError::Unsupported,
        Error::Changed => ResolverError::NetworkChanged,
        Error::Malformed => ResolverError::Malformed,
        _ => ResolverError::Unavailable,
    };
    let connection = trusted_connection().await.map_err(map)?;
    let bus = DBusProxy::new(&connection)
        .await
        .map_err(|_| ResolverError::Unavailable)?;
    let before = daemon(&connection, &bus, NetworkService::Resolved)
        .await
        .map_err(map)?;
    let raw = i32::try_from(before.pid).map_err(|_| ResolverError::Untrusted)?;
    let pid = Pid::from_raw(raw).ok_or(ResolverError::Untrusted)?;
    let pidfd = pidfd_open(pid, PidfdFlags::NONBLOCK).map_err(|_| ResolverError::Unavailable)?;
    let result = read(&connection, before.owner.as_str()).await?;
    let after = daemon(&connection, &bus, NetworkService::Resolved)
        .await
        .map_err(map)?;
    if before != after || !same_pid(&pidfd, before.pid).map_err(map)? {
        return Err(ResolverError::NetworkChanged);
    }
    Ok((result, before))
}

pub(super) async fn trusted_connection() -> Result<Connection, Error> {
    let stream = tokio::net::UnixStream::connect("/run/dbus/system_bus_socket")
        .await
        .map_err(unavailable)?;
    if stream.peer_cred().map_err(unavailable)?.uid() != 0 {
        return Err(Error::Unsupported);
    }
    zbus::connection::Builder::socket(bounded_socket(stream).map_err(unavailable)?)
        .auth_mechanism(zbus::AuthMechanism::External)
        .max_queued(1)
        .build()
        .await
        .map_err(unavailable)
}

pub(super) async fn daemon(
    connection: &Connection,
    bus: &DBusProxy<'_>,
    service: NetworkService,
) -> Result<Daemon, Error> {
    let (bus_name, object, group_path, unit_name) = service.identity();
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
        .get_name_owner(name(bus_name)?)
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
    if pid <= 1 || (uid == 0) != (service == NetworkService::NetworkManager) || uid == u32::MAX {
        return Err(Error::Unsupported);
    }
    let properties = zbus::Proxy::new(
        connection,
        systemd.as_str(),
        object,
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
            != group_path
        || read_proc(&format!("/proc/{pid}/cgroup"))? != format!("0::{group_path}\n")
    {
        return Err(Error::Changed);
    }
    let resolved = matches!(service, NetworkService::Resolved);
    if (resolved || service == NetworkService::NetworkManager)
        && property::<bool>(&properties, "org.freedesktop.systemd1.Service", "Delegate").await?
    {
        return Err(Error::Unsupported);
    }
    let dynamic_uid = resolved
        && property::<bool>(
            &properties,
            "org.freedesktop.systemd1.Service",
            "DynamicUser",
        )
        .await?;
    let cgroup = open("/sys/fs/cgroup", DIRECTORY, Mode::empty()).map_err(unavailable)?;
    let slice = openat(&cgroup, "system.slice", DIRECTORY, Mode::empty()).map_err(unavailable)?;
    let unit =
        File::from(openat(&slice, unit_name, DIRECTORY, Mode::empty()).map_err(unavailable)?);
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
        dynamic_uid,
        pid,
        invocation,
        group,
    })
}

pub(super) async fn property<T: TryFrom<zbus::zvariant::OwnedValue>>(
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
    T::try_from(value).map_err(|_| Error::Malformed)
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

pub(super) fn same_pid(fd: &OwnedFd, pid: u32) -> Result<bool, Error> {
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

fn unavailable<T>(_error: T) -> Error {
    Error::Unavailable
}
