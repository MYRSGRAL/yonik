//! Отзыв права публиковать DHCP-элементы до перехода logind в сон.
use futures_util::StreamExt;
use std::{
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
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

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
