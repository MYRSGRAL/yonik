//! Отзыв права публиковать DHCP-элементы до перехода logind в сон.
use futures_util::StreamExt;
use rustix::{
    fd::OwnedFd as RuntimeFd,
    fs::{self, FileType, FlockOperation, Mode, OFlags},
    io::Errno,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use zbus::{Proxy, names::BusName, proxy::CacheProperties, zvariant::OwnedFd};

const BUS: &str = "unix:path=/run/dbus/system_bus_socket";
const LOGIN: &str = "org.freedesktop.login1";
const PATH: &str = "/org/freedesktop/login1";
const MANAGER: &str = "org.freedesktop.login1.Manager";
const CONNECT_BUDGET: Duration = Duration::from_secs(1);
const QUIESCE_BUDGET: Duration = Duration::from_secs(2);
const MIN_DELAY_MICROS: u64 = 2_500_000;
// 650 мс в ядре плюс запас на округление тиков и сборку элемента.
const DHCP_DRAIN_TIME: Duration = Duration::from_millis(750);
const RUNTIME: &str = "/run/yonik";
const SLEEP_RUNTIME: &str = "/run/yonik-dhcp-sleep";
const SLEEP_UNIT: &str = "yonik-dhcp-sleep.service";
const SLEEP_REQUIREMENT: &str = "/usr/lib/systemd/system/sleep.target.d/50-yonik-dhcp-sleep.conf";
const SLEEP_ORDER: &str =
    "[Unit]\nRequires=yonik-dhcp-sleep.service\nAfter=yonik-dhcp-sleep.service\n";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn open_root_runtime(path: &str) -> std::result::Result<RuntimeFd, Errno> {
    let directory = fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = fs::fstat(&directory)?;
    if stat.st_uid != 0 || stat.st_mode & 0o077 != 0 {
        return Err(Errno::ACCESS);
    }
    Ok(directory)
}

fn open_writer_lock(runtime: &RuntimeFd, create: bool) -> std::result::Result<RuntimeFd, Errno> {
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    flags.set(OFlags::CREATE, create);
    let lock = fs::openat(runtime, "dhcp-writer.lock", flags, Mode::RUSR | Mode::WUSR)?;
    let stat = fs::fstat(&lock)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(Errno::ACCESS);
    }
    Ok(lock)
}

pub(crate) fn lock_dhcp_nft_writer() -> io::Result<RuntimeFd> {
    if std::fs::read_to_string(SLEEP_REQUIREMENT)? != SLEEP_ORDER {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let runtime = open_root_runtime(RUNTIME)?;
    let writer = open_writer_lock(&runtime, true)?;
    fs::flock(&writer, FlockOperation::NonBlockingLockExclusive)?;
    match std::fs::symlink_metadata(SLEEP_RUNTIME) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(writer),
        Err(error) => Err(error),
        Ok(_) => Err(io::ErrorKind::PermissionDenied.into()),
    }
}

/// Системная служба удерживает свой RuntimeDirectory до окончания сна.
pub fn quiesce_dhcp_before_sleep() -> io::Result<()> {
    if !rustix::process::geteuid().is_root() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let _sleep_runtime = open_root_runtime(SLEEP_RUNTIME)?;
    let _writer =
        match open_root_runtime(RUNTIME).and_then(|runtime| open_writer_lock(&runtime, false)) {
            Ok(writer) => {
                fs::flock(&writer, FlockOperation::LockExclusive)?;
                Some(writer)
            }
            Err(Errno::NOENT) => None,
            Err(error) => return Err(error.into()),
        };
    std::thread::sleep(DHCP_DRAIN_TIME);
    Ok(())
}

pub(crate) struct DhcpSleep {
    generation: AtomicU64,
    dirty: AtomicBool,
    writers: Arc<Semaphore>,
}

impl Default for DhcpSleep {
    fn default() -> Self {
        Self {
            generation: AtomicU64::new(0),
            // После перезапуска helper в ядре может оставаться прежний элемент.
            dirty: AtomicBool::new(true),
            writers: Arc::new(Semaphore::new(1)),
        }
    }
}

impl DhcpSleep {
    fn close(&self) {
        let _ = self
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(epoch & 1)
            });
    }

    fn arm(&self) {
        let _ = self
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                (epoch < u64::MAX - 1).then(|| epoch + 1 - (epoch & 1))
            });
    }

    pub(crate) fn ticket(self: &Arc<Self>) -> Option<DhcpSleepTicket> {
        let generation = self.generation.load(Ordering::Acquire);
        (generation & 1 != 0).then(|| DhcpSleepTicket {
            gate: Arc::clone(self),
            generation,
        })
    }

    async fn drain(&self) -> Result<()> {
        let _no_writers = self.writers.acquire().await?;
        if self.dirty.load(Ordering::Acquire) {
            tokio::time::sleep(DHCP_DRAIN_TIME).await;
            self.dirty.store(false, Ordering::Release);
        }
        Ok(())
    }
}

pub(crate) struct DhcpSleepTicket {
    gate: Arc<DhcpSleep>,
    generation: u64,
}

impl DhcpSleepTicket {
    pub(crate) fn begin(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.gate.writers).try_acquire_owned().ok()?;
        if self.gate.generation.load(Ordering::Acquire) != self.generation {
            return None;
        }
        self.gate.dirty.store(true, Ordering::Release);
        Some(permit)
    }
}

pub(crate) struct DhcpSleepTask(tokio::task::JoinHandle<()>);

impl Drop for DhcpSleepTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Inhibitor {
    gate: Arc<DhcpSleep>,
    fd: Option<OwnedFd>,
}

impl Drop for Inhibitor {
    fn drop(&mut self) {
        self.gate.close();
        if self.gate.dirty.load(Ordering::Acquire) || self.gate.writers.available_permits() == 0 {
            if let (Some(fd), Ok(runtime)) = (self.fd.take(), tokio::runtime::Handle::try_current())
            {
                let gate = Arc::clone(&self.gate);
                runtime.spawn(async move {
                    let _hold = fd;
                    let _drain = gate.drain().await;
                });
            }
        }
    }
}

pub(crate) fn watch(gate: Arc<DhcpSleep>, wake: Arc<Notify>) -> DhcpSleepTask {
    DhcpSleepTask(tokio::spawn(async move {
        loop {
            let result = watch_connection(Arc::clone(&gate), &wake).await;
            #[cfg(any(test, feature = "test-support"))]
            if std::env::var_os("YONIK_SESSION_DIAGNOSTICS").as_deref()
                == Some(std::ffi::OsStr::new("1"))
            {
                eprintln!("session diagnostic dhcp_sleep: {result:?}");
            }
            let _result = result;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }))
}

async fn connect() -> Result<(zbus::Connection, zbus::names::OwnedUniqueName)> {
    let connection = zbus::connection::Builder::address(BUS)?
        .max_queued(8)
        .build()
        .await?;
    let dbus = zbus::fdo::DBusProxy::new(&connection).await?;
    let owner = dbus.get_name_owner(BusName::try_from(LOGIN)?).await?;
    if dbus
        .get_connection_unix_user(BusName::try_from(owner.as_str())?)
        .await?
        != 0
    {
        return Err("Владелец login1 не является root".into());
    }
    Ok((connection, owner))
}

async fn verify_sleep_target(connection: &zbus::Connection) -> Result<()> {
    let bus = zbus::fdo::DBusProxy::new(connection).await?;
    let owner = super::systemd_network_service::systemd_owner(&bus)
        .await
        .map_err(|_| "Не подтверждён владелец systemd PID 1")?;
    let manager = Proxy::new(
        connection,
        owner.as_str(),
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await?;
    let target: zbus::zvariant::OwnedObjectPath =
        manager.call("LoadUnit", &("sleep.target",)).await?;
    let target = Proxy::new(
        connection,
        owner.as_str(),
        target.as_str(),
        "org.freedesktop.systemd1.Unit",
    )
    .await?;
    for property in ["Requires", "After"] {
        if !target
            .get_property::<Vec<String>>(property)
            .await?
            .iter()
            .any(|unit| unit == SLEEP_UNIT)
        {
            return Err("systemd не загрузил обязательную службу отзыва DHCP перед сном".into());
        }
    }
    Ok(())
}

async fn inhibit(manager: &Proxy<'_>, inhibitor: &mut Inhibitor) -> Result<()> {
    if manager.get_property::<u64>("InhibitDelayMaxUSec").await? < MIN_DELAY_MICROS {
        return Err("Недостаточный срок задержки сна login1".into());
    }
    if manager.get_property::<bool>("PreparingForSleep").await? {
        return Ok(());
    }
    let fd: OwnedFd = manager
        .call(
            "Inhibit",
            &("sleep", "Yonik", "Истечение разрешений DHCP", "delay"),
        )
        .await?;
    inhibitor.fd = Some(fd);
    inhibitor.gate.drain().await?;
    if !manager.get_property::<bool>("PreparingForSleep").await? {
        inhibitor.gate.arm();
    }
    Ok(())
}

async fn watch_connection(gate: Arc<DhcpSleep>, wake: &Notify) -> Result<()> {
    let (connection, owner) = tokio::time::timeout(CONNECT_BUDGET, connect()).await??;
    tokio::time::timeout(QUIESCE_BUDGET, verify_sleep_target(&connection)).await??;
    let manager: Proxy<'_> = zbus::proxy::Builder::new(&connection)
        .destination(owner.as_str())?
        .path(PATH)?
        .interface(MANAGER)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let named = Proxy::new(&connection, LOGIN, PATH, MANAGER).await?;
    let mut owners = tokio::time::timeout(CONNECT_BUDGET, named.receive_owner_changed()).await??;
    let mut signals =
        tokio::time::timeout(CONNECT_BUDGET, manager.receive_signal("PrepareForSleep")).await??;
    let dbus = zbus::fdo::DBusProxy::new(&connection).await?;
    if dbus.get_name_owner(BusName::try_from(LOGIN)?).await? != owner {
        return Err("Изменился владелец login1".into());
    }
    let mut inhibitor = Inhibitor {
        gate: Arc::clone(&gate),
        fd: None,
    };
    tokio::time::timeout(QUIESCE_BUDGET, inhibit(&manager, &mut inhibitor)).await??;
    loop {
        let message = tokio::select! {
            biased;
            _ = owners.next() => return Err("Изменился владелец login1".into()),
            signal = signals.next() => signal.ok_or("Закрыто наблюдение за сном")?,
        };
        if message.body().len() != 4 {
            return Err("Неверный сигнал PrepareForSleep".into());
        }
        let preparing: bool = message.body().deserialize()?;
        if preparing {
            gate.close();
            tokio::time::timeout(QUIESCE_BUDGET, gate.drain()).await??;
            inhibitor.fd = None;
        } else if inhibitor.fd.is_none() {
            tokio::time::timeout(QUIESCE_BUDGET, inhibit(&manager, &mut inhibitor)).await??;
            wake.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn sleep_waits_for_the_writer_and_rejects_tickets_from_before_sleep() {
        let gate = Arc::new(DhcpSleep::default());
        assert!(gate.ticket().is_none());
        gate.arm();
        let old = gate.ticket().expect("Рабочее разрешение");
        let writer = old.begin().expect("Запись DHCP");
        gate.close();
        assert!(gate.ticket().is_none());
        assert!(old.begin().is_none());
        assert!(gate.writers.try_acquire().is_err());
        let mut drain = tokio::spawn({
            let gate = Arc::clone(&gate);
            async move { gate.drain().await }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut drain)
                .await
                .is_err()
        );
        let released = tokio::time::Instant::now();
        drop(writer);
        drain.await.unwrap().unwrap();
        assert!(released.elapsed() >= DHCP_DRAIN_TIME);
        assert!(!gate.dirty.load(Ordering::Acquire));
        gate.arm();
        assert!(old.begin().is_none());
        assert!(
            gate.ticket()
                .expect("Допуск после пробуждения")
                .begin()
                .is_some()
        );
    }

    #[tokio::test]
    async fn dropping_sleep_watch_keeps_the_inhibitor_until_the_entry_expires() {
        let gate = Arc::new(DhcpSleep::default());
        gate.arm();
        let (mut reader, writer) = tokio::net::UnixStream::pair().unwrap();
        let fd: std::os::fd::OwnedFd = writer.into_std().unwrap().into();
        let inhibitor = Inhibitor {
            gate: Arc::clone(&gate),
            fd: Some(fd.into()),
        };
        drop(inhibitor);
        assert!(gate.ticket().is_none());
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), reader.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(reader.read(&mut byte).await.unwrap(), 0);
        assert!(!gate.dirty.load(Ordering::Acquire));
    }
}
