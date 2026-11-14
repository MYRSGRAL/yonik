//! Владелец двух фиксированных systemd worker, с подтверждением пустой cgroup.
//! Accepted подтверждает передачу FD, но не готовность сети и не Applied.
use super::run_authorization::{RunAuthority, RunAuthorization, RunRevocationGuard};
use crate::{
    Cancellation,
    worker::{WorkerAck, WorkerMode, WorkerPayload, WorkerStatus},
};
use futures_util::StreamExt;
use rustix::fs::{Mode, OFlags, fstatfs, open, openat};
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{task::JoinHandle, time::Instant};
use zbus::{
    Connection,
    zvariant::{OwnedObjectPath, OwnedValue},
};

const BUS: &str = "unix:path=/run/dbus/system_bus_socket";
const DESTINATION: &str = "org.freedesktop.systemd1";
const MANAGER: &str = "/org/freedesktop/systemd1";
const UNIT_IFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_IFACE: &str = "org.freedesktop.systemd1.Service";
const SOCKET_IFACE: &str = "org.freedesktop.systemd1.Socket";
const DEADLINE: Duration = Duration::from_secs(8);
static OWNED: AtomicBool = AtomicBool::new(false);
type Properties = HashMap<String, OwnedValue>;
type TransferResult = Result<(WorkerAck, Option<InvocationBinding>)>;
type ExecCommands = Vec<(String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerSupervisorError {
    Busy,
    Unavailable,
    Untrusted,
    Timeout,
    Cancelled,
    Protocol,
    Stale,
    NotEmpty,
    RecoveryRequired,
    UnitProofGap,
}
impl std::fmt::Display for WorkerSupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Busy => "Worker уже имеет владельца",
            Self::Unavailable => "Systemd worker недоступен",
            Self::Untrusted => "Контракт systemd worker не подтверждён",
            Self::Timeout => "Истёк срок операции worker",
            Self::Cancelled => "Операция worker отменена",
            Self::Protocol => "Некорректный ответ worker",
            Self::Stale => "Экземпляр worker изменился",
            Self::NotEmpty => "Завершение worker не подтверждено",
            Self::UnitProofGap => "Не подтверждён unit/kernel proof worker",
            Self::RecoveryRequired => "Требуется восстановление worker",
        })
    }
}
impl std::error::Error for WorkerSupervisorError {}
type Result<T> = std::result::Result<T, WorkerSupervisorError>;

struct Permit;
impl Permit {
    fn acquire() -> Result<Arc<Self>> {
        OWNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| WorkerSupervisorError::Busy)?;
        Ok(Arc::new(Self))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        OWNED.store(false, Ordering::Release);
    }
}

/// Неподделываемая локальная ссылка на конкретную invocation, не только PID.
#[derive(Debug)]
pub struct WorkerTicket {
    pid: u32,
    invocation: [u8; 16],
}
impl WorkerTicket {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    fn matches(&self, state: &WorkerState) -> bool {
        self.pid != 0
            && self.pid == state.pid
            && self.invocation.as_slice() == state.invocation
            && self.invocation != [0; 16]
    }
}
/// Удерживает lifetime authorized transfer; не открывает production factory.
#[allow(dead_code)] // Consumer подключается отдельно после supported report.
pub(crate) struct AuthorizedRun {
    ticket: WorkerTicket,
    lease: AuthorizedLease,
}
#[allow(dead_code)]
impl AuthorizedRun {
    pub(super) fn validate_owner(
        &self,
        owner: &RunAuthority,
        payload: &Arc<WorkerPayload>,
    ) -> Result<()> {
        self.ticket()?;
        self.lease.binding.validate_owner(owner, payload)
    }
    // Только retention/link unit boundary: намеренно не заменяет validate_owner.
    #[cfg(test)]
    pub(super) fn unit_validate_owner_link(
        &self,
        owner: &RunAuthority,
        payload: &Arc<WorkerPayload>,
    ) -> Result<()> {
        if self
            .lease
            .binding
            .kernel
            .as_ref()
            .map(|kernel| kernel.retained_namespace_count())
            != Some(2)
        {
            return Err(WorkerSupervisorError::Stale);
        }
        self.lease.binding.validate_owner(owner, payload)
    }
    /// Ticket не является admission; доступ требует живого retained binding.
    pub(crate) fn ticket(&self) -> Result<&WorkerTicket> {
        self.lease.binding.validate()?;
        if self.ticket.pid != self.lease.binding.observation.pid
            || self.ticket.invocation != self.lease.binding.observation.invocation
        {
            return Err(WorkerSupervisorError::Stale);
        }

        if self
            .lease
            .binding
            .kernel
            .as_ref()
            .map(|kernel| kernel.retained_namespace_count())
            != Some(2)
        {
            return Err(WorkerSupervisorError::UnitProofGap);
        }
        Ok(&self.ticket)
    }
}
#[allow(dead_code)]
struct AuthorizedLease {
    binding: InvocationBinding,
    _guard: RunRevocationGuard,
}
/// Наблюдение canonical PID1 bootstrap, ещё не proof неизменности namespace.
/// Конструктор закрыт; caller PID/UID и namespace numbers не принимаются.
pub struct BootstrapUnitObservation {
    pid: u32,
    uid: u32,
    gid: u32,
    start: u64,
    invocation: [u8; 16],
    expires: Instant,
    pidfd: std::os::fd::OwnedFd,
    #[cfg(test)]
    fixture_io: Option<FixtureIdentityIo>,
}
// Единственный parser/predicate path для production и instance-scoped unit IO.
trait RawIdentityIo {
    fn now(&self) -> Instant;
    fn read(&self, path: &str) -> Result<String>;
}
struct RealIdentityIo;
impl RawIdentityIo for RealIdentityIo {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn read(&self, path: &str) -> Result<String> {
        std::fs::read_to_string(path).map_err(unavailable)
    }
}
#[cfg(test)]
struct FixtureIdentityIo {
    now: Instant,
    files: std::collections::BTreeMap<String, String>,
}
#[cfg(test)]
impl RawIdentityIo for FixtureIdentityIo {
    fn now(&self) -> Instant {
        self.now
    }
    fn read(&self, path: &str) -> Result<String> {
        self.files
            .get(path)
            .cloned()
            .ok_or(WorkerSupervisorError::Untrusted)
    }
}
impl BootstrapUnitObservation {
    pub(super) fn native_pid(&self) -> u32 {
        self.pid
    }
    pub(super) fn native_uid(&self) -> u32 {
        self.uid
    }
    pub(super) fn native_start(&self) -> u64 {
        self.start
    }
    pub(super) fn native_invocation(&self) -> [u8; 16] {
        self.invocation
    }
    /// Только transport observation: NS_GET_NSTYPE/kernel attestation обязательны
    /// отдельно. Возвращаемое значение не может активировать attribution.
    pub fn exchange(
        self,
        stream: &std::os::unix::net::UnixStream,
        digest: [u8; 32],
        session: [u8; 16],
        generation: u64,
    ) -> Result<crate::worker::anchor_exchange::NamespaceObservation> {
        self.validate_identity()?;
        let witness = crate::worker::anchor_exchange::Challenge::new(
            digest,
            session,
            generation,
            self.invocation,
        )
        .and_then(|challenge| challenge.exchange_kernel(stream, self.pid, self.uid))
        .map_err(|_| WorkerSupervisorError::Protocol)?;
        self.validate_identity()?;
        Ok(witness)
    }
    /// Canonical issuer до закрытого kernel gate. Observation и namespace FD
    /// уничтожаются при отказе; payload и роли ещё не отправлены.
    pub fn probe_run_role_gate(
        self,
        stream: &std::os::unix::net::UnixStream,
        digest: [u8; 32],
        session: [u8; 16],
        generation: u64,
    ) -> Result<()> {
        let observation = self.exchange(stream, digest, session, generation)?;
        let result = crate::worker::role_handoff::ProductionPermit::mint()
            .map(|_| ())
            .map_err(|_| WorkerSupervisorError::UnitProofGap);
        drop(observation);
        result
    }
    fn validate_state(&self, state: &WorkerState) -> Result<()> {
        if state.active != "active" || state.pid != self.pid || state.invocation != self.invocation
        {
            return Err(WorkerSupervisorError::Stale);
        }
        Ok(())
    }
    pub(super) fn validate_identity(&self) -> Result<()> {
        let io: &dyn RawIdentityIo = &RealIdentityIo;
        #[cfg(test)]
        let io: &dyn RawIdentityIo = self.fixture_io.as_ref().map_or(io, |fixture| fixture);
        self.validate_identity_io(io)
    }
    fn validate_identity_io(&self, io: &dyn RawIdentityIo) -> Result<()> {
        if io.now() >= self.expires {
            return Err(WorkerSupervisorError::UnitProofGap);
        }
        use std::os::fd::AsRawFd;
        let info = io.read(&format!("/proc/self/fdinfo/{}", self.pidfd.as_raw_fd()))?;
        if info.lines().find_map(|line| {
            line.strip_prefix("Pid:")
                .and_then(|v| v.trim().parse::<u32>().ok())
        }) != Some(self.pid)
            || parse_bootstrap_start(&io.read(&format!("/proc/{}/stat", self.pid))?)? != self.start
        {
            return Err(WorkerSupervisorError::Stale);
        }
        let status = io.read(&format!("/proc/{}/status", self.pid))?;
        let uids = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .ok_or(WorkerSupervisorError::Untrusted)?;
        let uids = uids
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(unavailable)?;
        let gids = status
            .lines()
            .find_map(|line| line.strip_prefix("Gid:"))
            .ok_or(WorkerSupervisorError::Untrusted)?;
        let gids = gids
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(unavailable)?;
        if uids != [self.uid; 4]
            || gids != [self.gid; 4]
            || io.read(&format!("/proc/{}/cgroup", self.pid))?
                != format!("0::{}\n", WorkerMode::Run.cgroup())
        {
            return Err(WorkerSupervisorError::Stale);
        }
        Ok(())
    }
}
fn bootstrap_start(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(unavailable)?;
    parse_bootstrap_start(&stat)
}
fn parse_bootstrap_start(stat: &str) -> Result<u64> {
    stat.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|v| v.parse().ok())
        .ok_or(WorkerSupervisorError::Untrusted)
}

/// Связывает удерживаемый immutable payload с одной canonical invocation.
/// Не доказывает непрерывность runtime exec и не открывает namespace gate.
struct InvocationBinding {
    authorization: RunAuthorization,
    observation: BootstrapUnitObservation,
    payload: Arc<WorkerPayload>,
    digest: yonik_application::ConfigDigest,
    kernel: Option<crate::worker::anchor_exchange::NamespaceObservation>,
}
impl InvocationBinding {
    fn validate(&self) -> Result<()> {
        self.authorization
            .validate()
            .map_err(|_| WorkerSupervisorError::Stale)?;
        if self.payload.digest() != self.digest {
            return Err(WorkerSupervisorError::Stale);
        }
        self.observation.validate_identity()
    }
    fn validate_owner(&self, owner: &RunAuthority, payload: &Arc<WorkerPayload>) -> Result<()> {
        self.authorization
            .validate_owner(owner)
            .map_err(|_| WorkerSupervisorError::Stale)?;
        if !Arc::ptr_eq(&self.payload, payload) {
            return Err(WorkerSupervisorError::Stale);
        }
        Ok(())
    }
    fn validate_state(&self, state: &WorkerState) -> Result<()> {
        self.observation.validate_state(state)
    }
    fn transfer(mut self, stream: &std::os::unix::net::UnixStream) -> Result<(WorkerAck, Self)> {
        self.validate()?;
        let witness = crate::worker::anchor_exchange::Challenge::for_authorization(
            &self.authorization,
            *self.digest.as_bytes(),
            self.observation.invocation,
        )
        .and_then(|challenge| {
            challenge.exchange_kernel(stream, self.observation.pid, self.observation.uid)
        })
        .map_err(|_| WorkerSupervisorError::Protocol)?;
        self.validate()?;
        self.authorization
            .bind_custody(&witness)
            .map_err(|_| WorkerSupervisorError::Stale)?;
        self.kernel = Some(witness);
        // Эти три наблюдения не закрывают legacy clone/per-flag gap.
        crate::worker::role_handoff::ProductionPermit::mint()
            .map_err(|_| WorkerSupervisorError::UnitProofGap)?;
        let ack = Self::transfer_payload(&self.payload, &self.authorization, stream)?;
        self.validate()?;
        Ok((ack, self))
    }
    fn transfer_payload(
        payload: &WorkerPayload,
        authorization: &RunAuthorization,
        stream: &std::os::unix::net::UnixStream,
    ) -> Result<WorkerAck> {
        authorization
            .validate()
            .map_err(|_| WorkerSupervisorError::Stale)?;
        let ack = payload
            .send(stream, WorkerMode::Run)
            .map_err(|_| WorkerSupervisorError::Protocol)?;
        authorization
            .validate()
            .map_err(|_| WorkerSupervisorError::Stale)?;
        Ok(ack)
    }
    fn accept(self, ack: WorkerAck) -> Result<Self> {
        self.validate()?;
        if ack.status != WorkerStatus::Accepted || ack.pid != self.observation.pid {
            return Err(WorkerSupervisorError::Protocol);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerLiveness {
    Running,
    Stopped,
}
struct WorkerState {
    active: String,
    pid: u32,
    invocation: Vec<u8>,
}
trait WorkerFence: Send + Sync {
    fn empty(&self, mode: WorkerMode) -> Result<bool>;
}
struct SystemFence;
impl WorkerFence for SystemFence {
    fn empty(&self, mode: WorkerMode) -> Result<bool> {
        cgroup_empty(mode)
    }
}
impl WorkerState {
    fn stopped(&self) -> bool {
        matches!(self.active.as_str(), "inactive" | "failed") && self.pid == 0
    }
}
impl WorkerMode {
    fn service(self) -> &'static str {
        match self {
            Self::Check => "yonik-worker-check.service",
            Self::Run => "yonik-worker.service",
        }
    }
    fn socket(self) -> &'static str {
        match self {
            Self::Check => "yonik-worker-check.socket",
            Self::Run => "yonik-worker.socket",
        }
    }
    fn cgroup(self) -> &'static str {
        match self {
            Self::Check => "/system.slice/yonik-worker-check.service",
            Self::Run => "/system.slice/yonik-worker.service",
        }
    }
    fn channel(self) -> &'static str {
        match self {
            Self::Check => "/run/yonik-worker/check.sock",
            Self::Run => "/run/yonik-worker/run.sock",
        }
    }
}

fn native_activation_ready(active: &str, pid: u32) -> Result<bool> {
    match (active, pid) {
        ("active", 1..) => Ok(true),
        ("activating" | "inactive" | "active", _) => Ok(false),
        _ => Err(WorkerSupervisorError::Stale),
    }
}
/// Отмена выигрывает select, но завершённый неполученный результат остаётся owning.
async fn wait_owned<T>(
    slot: &mut Option<JoinHandle<T>>,
    cancel: &mut Cancellation,
    deadline: Instant,
) -> Result<T> {
    let handle = slot.as_mut().ok_or(WorkerSupervisorError::Protocol)?;
    let mut joined = false;
    let result = bounded(cancel, deadline, async {
        let result = handle.await.map_err(unavailable);
        joined = true;
        result
    })
    .await;
    if joined {
        *slot = None;
    }
    result
}
type NativeAdmission = Result<(
    super::native_bootstrap::VerifiedPendingRun,
    crate::worker::anchor_exchange::NamespaceObservation,
    [u8; 512],
)>;
struct NativeRuntime {
    task_start: u64,
    stamp: Arc<std::sync::Mutex<Option<super::native_bootstrap::RuntimeScopeStamp>>>,
    stop: Arc<AtomicBool>,
    thread: Option<
        std::thread::JoinHandle<std::result::Result<(), crate::attribution::broker::Unavailable>>,
    >,
    ready: std::sync::mpsc::Receiver<()>,
    attached: bool,
}
impl Drop for NativeRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _result = thread.join();
        }
    }
}
/// Не Clone: один владелец в процессе. Отменённая future оставляет pending и
/// blocking transfer внутри владельца; только recover снова разрешает запуск.
pub struct SystemWorkerSupervisor {
    connection: Connection,
    owner: String,
    permit: Arc<Permit>,
    pending: Option<WorkerMode>,
    transfer: Option<JoinHandle<TransferResult>>,
    current: Option<WorkerTicket>,
    clean: bool,
    retained_copy: Option<Arc<WorkerPayload>>,
    fence: Box<dyn WorkerFence>,
    native_runtime: Option<NativeRuntime>,
    native_transfer: Option<JoinHandle<Result<WorkerAck>>>,
    native_admission: Option<JoinHandle<NativeAdmission>>,
    native_custody: Option<crate::worker::anchor_exchange::NamespaceRetention>,
}
impl Drop for SystemWorkerSupervisor {
    fn drop(&mut self) {
        if !self.clean {
            if let Some(custody) = self.native_custody.take() {
                std::mem::forget(custody);
            }

            if let Some(task) = self.native_admission.take() {
                std::mem::forget(task);
            }
            if let Some(task) = self.native_transfer.take() {
                std::mem::forget(task);
            }

            if let Some(runtime) = self.native_runtime.take() {
                std::mem::forget(runtime);
            }
            if let Some(payload) = self.retained_copy.take() {
                // Без empty-cgroup proof нельзя освободить global reserve:
                // он остаётся в карантине до выхода helper, ограничен ByteBudget.
                // BindsTo прекращает worker при завершении helper unit.
                std::mem::forget(payload);
            }
        }
    }
}
impl SystemWorkerSupervisor {
    pub async fn system() -> Result<Self> {
        let permit = Permit::acquire()?;
        tokio::time::timeout(DEADLINE, async {
            verify_installed()?;
            let connection = zbus::connection::Builder::address(BUS)
                .map_err(unavailable)?
                .build()
                .await
                .map_err(unavailable)?;
            let proxy = zbus::fdo::DBusProxy::new(&connection)
                .await
                .map_err(unavailable)?;
            let name = zbus::names::BusName::try_from(DESTINATION).map_err(unavailable)?;
            let owner = proxy
                .get_name_owner(name)
                .await
                .map_err(unavailable)?
                .to_string();
            let unique = zbus::names::BusName::try_from(owner.as_str()).map_err(unavailable)?;
            if proxy
                .get_connection_unix_user(unique)
                .await
                .map_err(unavailable)?
                != 0
            {
                return Err(WorkerSupervisorError::Untrusted);
            }
            let mut supervisor = Self {
                connection,
                owner,
                permit,
                pending: None,
                transfer: None,
                current: None,
                clean: false,
                retained_copy: None,
                fence: Box::new(SystemFence),
                native_runtime: None,
                native_transfer: None,
                native_admission: None,
                native_custody: None,
            };
            supervisor.validate_contract().await?;
            // Startup лишь проверяет состояние. Старый worker останавливает только recover.
            supervisor.clean = supervisor.all_empty().await?;
            Ok(supervisor)
        })
        .await
        .map_err(|_| WorkerSupervisorError::Timeout)?
    }
    /// Только свежая socket-activated Run invocation до передачи payload.
    /// Эта проверка не mint-ит OpaqueVerifiedWorkerUnit без kernel proof.
    pub async fn inspect_anchor_bootstrap(&self) -> Result<BootstrapUnitObservation> {
        tokio::time::timeout(Duration::from_secs(1), async {
            if self.pending != Some(WorkerMode::Run)
                || self.current.is_some()
                || self.transfer.is_some()
            {
                return Err(WorkerSupervisorError::UnitProofGap);
            }
            let proxy = zbus::fdo::DBusProxy::new(&self.connection)
                .await
                .map_err(unavailable)?;
            let owner = proxy
                .get_name_owner(zbus::names::BusName::try_from(DESTINATION).map_err(unavailable)?)
                .await
                .map_err(unavailable)?;
            let unique =
                zbus::names::BusName::try_from(self.owner.as_str()).map_err(unavailable)?;
            if owner.as_str() != self.owner
                || proxy
                    .get_connection_unix_user(unique.clone())
                    .await
                    .map_err(unavailable)?
                    != 0
                || proxy
                    .get_connection_unix_process_id(unique)
                    .await
                    .map_err(unavailable)?
                    != 1
            {
                return Err(WorkerSupervisorError::Untrusted);
            }
            verify_installed()?;
            self.validate_contract().await?;
            let state = self.state(WorkerMode::Run).await?;
            if state.pid == 0 || state.active != "active" {
                return Err(WorkerSupervisorError::UnitProofGap);
            }
            let invocation: [u8; 16] = state
                .invocation
                .try_into()
                .map_err(|_| WorkerSupervisorError::UnitProofGap)?;
            if invocation == [0; 16] {
                return Err(WorkerSupervisorError::UnitProofGap);
            }
            // Защищает loader/ранний bootstrap до установки nondumpable.
            if !matches!(
                std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
                    .map_err(unavailable)?
                    .trim(),
                "1" | "2" | "3"
            ) {
                return Err(WorkerSupervisorError::UnitProofGap);
            }
            let etc = child(&root()?, "etc")?;
            let passwd =
                File::from(openat(&etc, "passwd", FILE_FLAGS, Mode::empty()).map_err(unavailable)?);
            trusted(&passwd, false)?;
            let passwd = read_bounded(passwd)?;
            let mut entries = passwd
                .lines()
                .filter(|line| line.starts_with("yonik-worker:"));
            let entry = entries.next().ok_or(WorkerSupervisorError::Untrusted)?;
            if entries.next().is_some() {
                return Err(WorkerSupervisorError::Untrusted);
            }
            let uid = entry
                .split(':')
                .nth(2)
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|v| *v != 0)
                .ok_or(WorkerSupervisorError::Untrusted)?;
            let gid = entry
                .split(':')
                .nth(3)
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|v| *v != 0)
                .ok_or(WorkerSupervisorError::Untrusted)?;
            let group =
                File::from(openat(&etc, "group", FILE_FLAGS, Mode::empty()).map_err(unavailable)?);
            trusted(&group, false)?;
            let groups = read_bounded(group)?;
            let mut groups = groups
                .lines()
                .filter(|line| line.starts_with("yonik-worker:"));
            if groups
                .next()
                .and_then(|line| line.split(':').nth(2))
                .and_then(|v| v.parse::<u32>().ok())
                != Some(gid)
                || groups.next().is_some()
            {
                return Err(WorkerSupervisorError::Untrusted);
            }
            let pid =
                rustix::process::Pid::from_raw(i32::try_from(state.pid).map_err(unavailable)?)
                    .ok_or(WorkerSupervisorError::Untrusted)?;
            let observation = BootstrapUnitObservation {
                #[cfg(test)]
                fixture_io: None,
                pid: state.pid,
                uid,
                gid,
                start: bootstrap_start(state.pid)?,
                invocation,
                expires: Instant::now() + Duration::from_secs(1),
                pidfd: rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::NONBLOCK)
                    .map_err(unavailable)?,
            };
            observation.validate_identity()?;
            let after = self.state(WorkerMode::Run).await?;
            if after.pid != observation.pid || after.invocation != observation.invocation {
                return Err(WorkerSupervisorError::Stale);
            }
            Ok(observation)
        })
        .await
        .map_err(|_| WorkerSupervisorError::Timeout)?
    }
    pub async fn check(
        &mut self,
        payload: Arc<WorkerPayload>,
        cancel: &mut Cancellation,
    ) -> Result<()> {
        let deadline = Instant::now() + DEADLINE;
        self.begin(WorkerMode::Check, cancel, deadline).await?;
        let ack = self
            .send(payload, WorkerMode::Check, cancel, deadline)
            .await?;
        if ack.status != WorkerStatus::Checked {
            return Err(WorkerSupervisorError::Protocol);
        }
        self.cleanup(cancel, deadline).await
    }
    /// Conditional native start. Отсутствующий immutable deployment закрывает admission.
    #[allow(clippy::too_many_arguments)] // Каждый owning вход проверяется отдельным boundary.
    pub(crate) async fn start_native(
        &mut self,
        payload: Arc<WorkerPayload>,
        owner: &RunAuthority,
        authorization: RunAuthorization,
        queue: Arc<crate::managed_network::tun::BoundTun>,
        journal: &crate::managed_network::Journal,
        topology: crate::LinuxTopology,
        epoch: u64,
        cancel: &mut Cancellation,
    ) -> Result<WorkerTicket> {
        use super::native_bootstrap::{VerifiedPendingRun, verify_pending};
        use crate::worker::role_handoff::{Binding, Roles};
        let deadline = Instant::now() + DEADLINE;
        self.begin(WorkerMode::Run, cancel, deadline).await?;
        self.retained_copy = Some(Arc::clone(&payload));
        let stream = bounded(cancel, deadline, async {
            tokio::net::UnixStream::connect(WorkerMode::Run.channel())
                .await
                .map_err(unavailable)
        })
        .await?;
        verify_socket(WorkerMode::Run)?;
        let stream = stream.into_std().map_err(unavailable)?;
        stream.set_nonblocking(false).map_err(unavailable)?;
        loop {
            let state = bounded(cancel, deadline, self.state(WorkerMode::Run)).await?;
            authorization.validate_owner(owner).map_err(unavailable)?;
            if native_activation_ready(&state.active, state.pid)? {
                break;
            }
            bounded(cancel, deadline, async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(())
            })
            .await?;
        }
        let mut observation = bounded(cancel, deadline, self.inspect_anchor_bootstrap()).await?;
        observation.expires = deadline;
        let task_start = observation.start;
        let pid = observation.pid;
        let uid = observation.uid;
        let invocation = observation.invocation;
        let pending = VerifiedPendingRun::verify(
            self,
            owner,
            authorization,
            observation,
            *payload.digest().as_bytes(),
            epoch,
            cancel,
            deadline,
        )
        .await?;
        let admission_stream = stream.try_clone().map_err(unavailable)?;
        let permit = Arc::clone(&self.permit);
        self.native_admission = Some(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            pending.receive_blocking(admission_stream)
        }));
        let (pending, custody, frame) =
            wait_owned(&mut self.native_admission, cancel, deadline).await??;
        self.native_custody = Some(custody.retention());
        let coverage = pending
            .finish_receive(self, owner, custody, frame, cancel)
            .await?;
        let handoff = coverage.take_handoff()?;
        let (helper, worker) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(unavailable)?;
        let issued = verify_pending(coverage, owner, queue, journal, topology, helper)?;
        let (nonce, session, generation, invocation_context, epoch, digest) =
            issued.run.context()?;
        let binding = Binding {
            nonce,
            session,
            generation,
            invocation: invocation_context,
            epoch,
            digest,
            server_pid: std::process::id(),
            server_start: bootstrap_start(std::process::id())?,
        };
        let server_pid = rustix::process::Pid::from_raw(std::process::id() as i32)
            .ok_or(WorkerSupervisorError::Protocol)?;
        let roles = Roles {
            channel: worker,
            server_pidfd: rustix::process::pidfd_open(
                server_pid,
                rustix::process::PidfdFlags::NONBLOCK,
            )
            .map_err(unavailable)?,
            record: binding.record().map_err(unavailable)?,
        };
        let session = crate::attribution::native_session::Session::from_verified(issued.session)
            .map_err(unavailable)?;
        let (ready_tx, ready) = std::sync::mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("yonik-native-broker".into())
            .spawn(move || {
                session.serve_with_ready(&thread_stop, || {
                    ready_tx
                        .send(())
                        .map_err(|_| crate::attribution::broker::Unavailable::Cancelled)
                })
            })
            .map_err(unavailable)?;
        let scope = Arc::new(std::sync::Mutex::new(None));
        self.native_runtime = Some(NativeRuntime {
            task_start,
            stamp: Arc::clone(&scope),
            stop,
            thread: Some(thread),
            ready,
            attached: false,
        });
        let permit = Arc::clone(&self.permit);
        self.native_transfer = Some(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            crate::worker::role_handoff::handoff_verified_run(
                issued.run,
                &handoff,
                roles,
                &binding,
                pid,
                uid,
                deadline.into_std(),
                |stamp| {
                    *scope
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stamp);
                },
            )
            .map_err(unavailable)?;
            payload
                .send_output_before(&stream, WorkerMode::Run, None, deadline.into_std())
                .map_err(unavailable)
        }));
        let ack = wait_owned(&mut self.native_transfer, cancel, deadline).await??;
        if ack.status != WorkerStatus::Accepted || ack.pid != pid {
            return Err(WorkerSupervisorError::Protocol);
        }
        let ticket = WorkerTicket { pid, invocation };
        let state = bounded(cancel, deadline, self.state(WorkerMode::Run)).await?;
        if !ticket.matches(&state) {
            return Err(WorkerSupervisorError::Stale);
        }
        self.current = Some(WorkerTicket { pid, invocation });
        self.pending = None;
        Ok(ticket)
    }
    /// ATTACH ACK плюс текущая canonical invocation; network health проверяет owner.
    pub(crate) async fn native_attached(&mut self, ticket: &WorkerTicket) -> Result<bool> {
        if self.observe(ticket).await? != WorkerLiveness::Running {
            return Err(WorkerSupervisorError::Stale);
        }
        let runtime = self
            .native_runtime
            .as_mut()
            .ok_or(WorkerSupervisorError::Stale)?;
        if bootstrap_start(ticket.pid())? != runtime.task_start {
            return Err(WorkerSupervisorError::Stale);
        }
        runtime
            .stamp
            .lock()
            .map_err(unavailable)?
            .as_ref()
            .ok_or(WorkerSupervisorError::Stale)?
            .validate()?;
        if runtime
            .thread
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
        {
            return Err(WorkerSupervisorError::Stale);
        }
        if !runtime.attached {
            match runtime.ready.try_recv() {
                Ok(()) => runtime.attached = true,
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(_) => return Err(WorkerSupervisorError::Protocol),
            }
        }
        Ok(runtime.attached)
    }
    pub async fn start(
        &mut self,
        payload: Arc<WorkerPayload>,
        cancel: &mut Cancellation,
    ) -> Result<WorkerTicket> {
        self.start_inner(payload, None, None, cancel)
            .await
            .map(|(ticket, _)| ticket)
    }
    pub(crate) async fn start_output(
        &mut self,
        payload: Arc<WorkerPayload>,
        output: Option<crate::output_transport::ValidatedWriters>,
        cancel: &mut Cancellation,
    ) -> Result<WorkerTicket> {
        self.start_inner(payload, None, output, cancel)
            .await
            .map(|(ticket, _)| ticket)
    }
    /// Только helper owner; разрешение не заменяет kernel namespace admission.
    #[allow(dead_code)] // W4 подключает issuer отдельно.
    pub(crate) async fn start_authorized(
        &mut self,
        payload: Arc<WorkerPayload>,
        authorization: RunAuthorization,
        cancel: &mut Cancellation,
    ) -> Result<AuthorizedRun> {
        let (ticket, lease) = self
            .start_inner(payload, Some(authorization), None, cancel)
            .await?;
        Ok(AuthorizedRun {
            ticket,
            lease: lease.ok_or(WorkerSupervisorError::Protocol)?,
        })
    }
    async fn start_inner(
        &mut self,
        payload: Arc<WorkerPayload>,
        authorization: Option<RunAuthorization>,
        output: Option<crate::output_transport::ValidatedWriters>,
        cancel: &mut Cancellation,
    ) -> Result<(WorkerTicket, Option<AuthorizedLease>)> {
        // Guard живёт в future, а не в blocking task: drop отзывает поздний ACK.
        let revocation = authorization.as_ref().map(RunAuthorization::guard);
        let deadline = Instant::now() + DEADLINE;
        self.begin(WorkerMode::Run, cancel, deadline).await?;
        let (ack, binding) = self
            .send_inner(
                payload,
                WorkerMode::Run,
                authorization,
                output,
                cancel,
                deadline,
            )
            .await?;
        if ack.status != WorkerStatus::Accepted {
            return Err(WorkerSupervisorError::Protocol);
        }
        let state = bounded(cancel, deadline, self.state(WorkerMode::Run)).await?;
        let binding = binding
            .map(|binding| {
                binding.validate_state(&state)?;
                binding.accept(ack)
            })
            .transpose()?;
        let invocation: [u8; 16] = state
            .invocation
            .try_into()
            .map_err(|_| WorkerSupervisorError::Protocol)?;
        if ack.pid != state.pid || invocation == [0; 16] || state.active != "active" {
            return Err(WorkerSupervisorError::Protocol);
        }
        let ticket = WorkerTicket {
            pid: ack.pid,
            invocation,
        };
        self.current = Some(WorkerTicket {
            pid: ticket.pid,
            invocation: ticket.invocation,
        });
        self.pending = None;
        let lease = match (binding, revocation) {
            (Some(binding), Some(guard)) => Some(AuthorizedLease {
                binding,
                _guard: guard,
            }),
            (None, None) => None,
            _ => return Err(WorkerSupervisorError::Protocol),
        };
        Ok((ticket, lease))
    }
    pub async fn observe(&self, ticket: &WorkerTicket) -> Result<WorkerLiveness> {
        tokio::time::timeout(DEADLINE, async {
            let state = self.state(WorkerMode::Run).await?;
            if state.stopped() && self.fence.empty(WorkerMode::Run)? {
                return Ok(WorkerLiveness::Stopped);
            }
            if !ticket.matches(&state) {
                return Err(WorkerSupervisorError::Stale);
            }
            Ok(WorkerLiveness::Running)
        })
        .await
        .map_err(|_| WorkerSupervisorError::Timeout)?
    }
    pub async fn stop(&mut self, ticket: &WorkerTicket, cancel: &mut Cancellation) -> Result<()> {
        let deadline = Instant::now() + DEADLINE;
        let state = bounded(cancel, deadline, self.state(WorkerMode::Run)).await?;
        if !(ticket.matches(&state) || state.stopped() && self.fence.empty(WorkerMode::Run)?) {
            return Err(WorkerSupervisorError::Stale);
        }
        if !self
            .current
            .as_ref()
            .is_some_and(|owned| owned.pid == ticket.pid && owned.invocation == ticket.invocation)
        {
            return Err(WorkerSupervisorError::Stale);
        }
        self.pending = Some(WorkerMode::Run);
        self.cleanup(cancel, deadline).await
    }
    /// Явное восстановление фиксированных owned units, включая прошлую invocation.
    pub async fn recover(&mut self, cancel: &mut Cancellation) -> Result<()> {
        let deadline = Instant::now() + DEADLINE;
        bounded(cancel, deadline, self.validate_contract()).await?;
        self.clean = false;
        self.current = None;
        self.cleanup(cancel, deadline).await
    }
    async fn begin(
        &mut self,
        mode: WorkerMode,
        cancel: &mut Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        if !self.clean
            || self.pending.is_some()
            || self.transfer.is_some()
            || self.current.is_some()
        {
            return Err(WorkerSupervisorError::RecoveryRequired);
        }
        bounded(cancel, deadline, self.validate_contract()).await?;
        if !bounded(cancel, deadline, self.all_empty()).await? {
            self.clean = false;
            return Err(WorkerSupervisorError::RecoveryRequired);
        }
        cancel
            .check()
            .map_err(|_| WorkerSupervisorError::Cancelled)?;
        // Записано до первого эффекта: drop future не теряет необходимость recovery.
        self.pending = Some(mode);
        self.clean = false;
        bounded(cancel, deadline, self.unit_job("StartUnit", mode.socket())).await
    }
    async fn send(
        &mut self,
        payload: Arc<WorkerPayload>,
        mode: WorkerMode,
        cancel: &mut Cancellation,
        deadline: Instant,
    ) -> Result<WorkerAck> {
        self.send_inner(payload, mode, None, None, cancel, deadline)
            .await
            .map(|(ack, _)| ack)
    }
    async fn send_inner(
        &mut self,
        payload: Arc<WorkerPayload>,
        mode: WorkerMode,
        authorization: Option<RunAuthorization>,
        output: Option<crate::output_transport::ValidatedWriters>,
        cancel: &mut Cancellation,
        deadline: Instant,
    ) -> TransferResult {
        if (authorization.is_some() && mode != WorkerMode::Run)
            || (output.is_some() && (mode != WorkerMode::Run || authorization.is_some()))
        {
            return Err(WorkerSupervisorError::Protocol);
        }
        if payload.needs_tmpfs_assets() {
            let properties = bounded(
                cancel,
                deadline,
                self.properties(mode.service(), SERVICE_IFACE),
            )
            .await?;
            validate_private_assets(&properties)?;
        }
        if payload.engine() == yonik_engine::Engine::SingBox || payload.has_resources() {
            self.retained_copy = Some(Arc::clone(&payload));
        }
        let stream = bounded(cancel, deadline, async {
            tokio::net::UnixStream::connect(mode.channel())
                .await
                .map_err(unavailable)
        })
        .await?;
        verify_socket(mode)?;
        let stream = stream.into_std().map_err(unavailable)?;
        stream.set_nonblocking(false).map_err(unavailable)?;
        let binding = if let Some(authorization) = authorization {
            authorization
                .validate()
                .map_err(|_| WorkerSupervisorError::Stale)?;
            // connect активирует unit, но Type=exec ещё может быть activating.
            loop {
                let state = bounded(cancel, deadline, self.state(WorkerMode::Run)).await?;
                authorization
                    .validate()
                    .map_err(|_| WorkerSupervisorError::Stale)?;
                if state.active == "active" {
                    break;
                }
                if !matches!(state.active.as_str(), "activating" | "inactive") {
                    return Err(WorkerSupervisorError::Stale);
                }
                bounded(cancel, deadline, async {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok(())
                })
                .await?;
            }
            let mut observation =
                bounded(cancel, deadline, self.inspect_anchor_bootstrap()).await?;
            observation.expires = deadline;
            let binding = InvocationBinding {
                authorization,
                observation,
                digest: payload.digest(),
                kernel: None,
                payload: Arc::clone(&payload),
            };
            self.revalidate_binding(&binding, cancel, deadline).await?;
            Some(binding)
        } else {
            None
        };
        let permit = Arc::clone(&self.permit);
        self.transfer = Some(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if let Some(binding) = binding {
                binding
                    .transfer(&stream)
                    .map(|(ack, binding)| (ack, Some(binding)))
            } else {
                payload
                    .send_output(&stream, mode, output)
                    .map(|ack| (ack, None))
                    .map_err(|_| WorkerSupervisorError::Protocol)
            }
        }));
        let handle = self
            .transfer
            .as_mut()
            .ok_or(WorkerSupervisorError::Unavailable)?;
        let result = bounded(cancel, deadline, async {
            handle.await.map_err(unavailable)?
        })
        .await;
        // При timeout/cancel handle остаётся; повторный cleanup обязательно его ждёт.
        if self.transfer.as_ref().is_some_and(JoinHandle::is_finished) {
            self.transfer = None;
        }
        let (ack, binding) = result?;
        if let Some(binding) = &binding {
            self.revalidate_binding(binding, cancel, deadline).await?;
        }
        Ok((ack, binding))
    }
    pub(super) async fn validate_native_profile_context(
        &self,
        observation: &BootstrapUnitObservation,
        cancel: &mut Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        observation.validate_identity()?;
        bounded(cancel, deadline, self.validate_contract()).await?;
        observation.validate_identity()?;
        let state = bounded(cancel, deadline, self.state(WorkerMode::Run)).await?;
        observation.validate_state(&state)?;
        observation.validate_identity()
    }
    async fn revalidate_binding(
        &self,
        binding: &InvocationBinding,
        cancel: &mut Cancellation,
        deadline: Instant,
    ) -> Result<()> {
        binding.validate()?;
        let state = bounded(cancel, deadline, self.state(WorkerMode::Run)).await?;
        binding.validate_state(&state)?;
        binding.validate()
    }
    async fn cleanup(&mut self, cancel: &mut Cancellation, deadline: Instant) -> Result<()> {
        self.clean = false;
        // Сначала запрет новой активации, затем завершение уже начатой передачи.
        for mode in [WorkerMode::Check, WorkerMode::Run] {
            bounded(cancel, deadline, self.unit_job("StopUnit", mode.socket())).await?;
        }
        if let Some(handle) = self.native_admission.as_mut() {
            let result = bounded(cancel, deadline, async {
                handle.await.map_err(unavailable)
            })
            .await?;
            self.native_admission = None;
            if let Ok((pending, custody, frame)) = result {
                self.native_custody = Some(custody.retention());
                drop((pending, custody, frame));
            }
        }
        if let Some(handle) = self.native_transfer.as_mut() {
            bounded(cancel, deadline, async {
                let _result = handle.await.map_err(unavailable)?;
                Ok(())
            })
            .await?;
            self.native_transfer = None;
        }
        if let Some(handle) = self.transfer.as_mut() {
            bounded(cancel, deadline, async {
                let _result = handle.await.map_err(unavailable)?;
                Ok(())
            })
            .await?;
            self.transfer = None;
        }
        for mode in [WorkerMode::Check, WorkerMode::Run] {
            if mode == WorkerMode::Run {
                if let Some(ticket) = self.current.as_ref() {
                    let state = bounded(cancel, deadline, self.state(mode)).await?;
                    if !(ticket.matches(&state) || state.stopped() && self.fence.empty(mode)?) {
                        return Err(WorkerSupervisorError::Stale);
                    }
                }
            }
            bounded(cancel, deadline, self.unit_job("StopUnit", mode.service())).await?;
        }
        loop {
            if bounded(cancel, deadline, self.all_empty()).await? {
                self.pending = None;
                self.current = None;
                self.clean = true;
                self.retained_copy = None;
                self.native_runtime = None;
                self.native_custody = None;
                return Ok(());
            }
            bounded(cancel, deadline, async {
                tokio::time::sleep(Duration::from_millis(25)).await;
                Ok(())
            })
            .await?;
        }
    }
    async fn unit_job(&self, method: &str, unit: &'static str) -> Result<()> {
        tokio::time::timeout(DEADLINE, async {
            let proxy = zbus::Proxy::new(
                &self.connection,
                self.owner.as_str(),
                MANAGER,
                "org.freedesktop.systemd1.Manager",
            )
            .await
            .map_err(unavailable)?;
            let subscribed: std::result::Result<(), zbus::Error> =
                proxy.call("Subscribe", &()).await;
            if let Err(error) = subscribed {
                match error {
                    zbus::Error::MethodError(name, _, _)
                        if name.as_str() == "org.freedesktop.systemd1.AlreadySubscribed" => {}
                    _ => return Err(WorkerSupervisorError::Unavailable),
                }
            }
            // Match устанавливается до запроса: быстрый job может завершиться
            // ещё до ответа StartUnit/StopUnit. Ответ содержит только job path.
            let mut events = proxy
                .receive_signal_with_args("JobRemoved", &[(2, unit)])
                .await
                .map_err(unavailable)?;
            let reply = proxy
                .call_method(method, &(unit, "replace"))
                .await
                .map_err(unavailable)?;
            let (job,): (OwnedObjectPath,) = reply.body().deserialize().map_err(unavailable)?;
            while let Some(message) = events.next().await {
                let (_, completed, name, result): (u32, OwnedObjectPath, String, String) =
                    message.body().deserialize().map_err(unavailable)?;
                if completed == job {
                    return if name == unit && result == "done" {
                        Ok(())
                    } else {
                        Err(WorkerSupervisorError::Protocol)
                    };
                }
            }
            Err(WorkerSupervisorError::Unavailable)
        })
        .await
        .map_err(|_| WorkerSupervisorError::Timeout)?
    }
    async fn path(&self, unit: &str) -> Result<OwnedObjectPath> {
        let reply = self
            .connection
            .call_method(
                Some(self.owner.as_str()),
                MANAGER,
                Some("org.freedesktop.systemd1.Manager"),
                "LoadUnit",
                &(unit,),
            )
            .await
            .map_err(unavailable)?;
        let (path,): (OwnedObjectPath,) = reply.body().deserialize().map_err(unavailable)?;
        Ok(path)
    }
    async fn properties(&self, unit: &str, interface: &str) -> Result<Properties> {
        let path = self.path(unit).await?;
        let proxy = zbus::Proxy::new(
            &self.connection,
            self.owner.as_str(),
            path.as_str(),
            "org.freedesktop.DBus.Properties",
        )
        .await
        .map_err(unavailable)?;
        proxy
            .call("GetAll", &(interface,))
            .await
            .map_err(unavailable)
    }
    async fn state(&self, mode: WorkerMode) -> Result<WorkerState> {
        let unit = self.properties(mode.service(), UNIT_IFACE).await?;
        let service = self.properties(mode.service(), SERVICE_IFACE).await?;
        let cgroup = string(&service, "ControlGroup")?;
        if !cgroup.is_empty() && cgroup != mode.cgroup() {
            return Err(WorkerSupervisorError::Untrusted);
        }
        Ok(WorkerState {
            active: string(&unit, "ActiveState")?,
            pid: number32(&service, "MainPID")?,
            invocation: array(&unit, "InvocationID")?,
        })
    }
    async fn all_empty(&self) -> Result<bool> {
        for mode in [WorkerMode::Check, WorkerMode::Run] {
            let state = self.state(mode).await?;
            if !state.stopped() || !self.fence.empty(mode)? {
                return Ok(false);
            }
            let socket = self.properties(mode.socket(), UNIT_IFACE).await?;
            if !matches!(
                string(&socket, "ActiveState")?.as_str(),
                "inactive" | "failed"
            ) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn validate_contract(&self) -> Result<()> {
        for mode in [WorkerMode::Check, WorkerMode::Run] {
            for (name, interface) in [
                (mode.service(), SERVICE_IFACE),
                (mode.socket(), SOCKET_IFACE),
            ] {
                let unit = self.properties(name, UNIT_IFACE).await?;
                if string(&unit, "LoadState")? != "loaded"
                    || string(&unit, "FragmentPath")? != format!("/usr/lib/systemd/system/{name}")
                    || boolean(&unit, "Transient")?
                    || !strings(&unit, "DropInPaths")?.is_empty()
                {
                    return Err(WorkerSupervisorError::Untrusted);
                }
                for dependency in ["BindsTo", "After"] {
                    if !strings(&unit, dependency)?
                        .iter()
                        .any(|name| name == "yonik-helper.service")
                    {
                        return Err(WorkerSupervisorError::Untrusted);
                    }
                }
                let properties = self.properties(name, interface).await?;
                if interface == SERVICE_IFACE {
                    validate_service(&properties, mode)?;
                } else {
                    validate_socket(&properties, mode)?;
                }
            }
        }
        Ok(())
    }
}
fn unavailable<T>(_: T) -> WorkerSupervisorError {
    WorkerSupervisorError::Unavailable
}
fn string(p: &Properties, k: &str) -> Result<String> {
    p.get(k)
        .and_then(|v| <&str>::try_from(v).ok())
        .map(str::to_owned)
        .ok_or(WorkerSupervisorError::Untrusted)
}
fn boolean(p: &Properties, k: &str) -> Result<bool> {
    p.get(k)
        .and_then(|v| bool::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)
}
fn number32(p: &Properties, k: &str) -> Result<u32> {
    p.get(k)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)
}
fn integer(p: &Properties, k: &str) -> Result<i32> {
    p.get(k)
        .and_then(|v| i32::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)
}
fn number64(p: &Properties, k: &str) -> Result<u64> {
    p.get(k)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)
}
fn strings(p: &Properties, k: &str) -> Result<Vec<String>> {
    p.get(k)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<String>::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)
}
fn array(p: &Properties, k: &str) -> Result<Vec<u8>> {
    p.get(k)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<u8>::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)
}
fn validate_private_assets(p: &Properties) -> Result<()> {
    let mounts: Vec<(String, String)> = p
        .get("TemporaryFileSystem")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)?;
    let entries = mounts
        .iter()
        .filter(|(path, _)| path == "/dev/shm")
        .collect::<Vec<_>>();
    if entries.len() != 1 || mounts.len() != 1 {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let mut flags = std::collections::HashSet::new();
    let (mut mode, mut size, mut inodes) = (None, None, None);
    for option in entries[0].1.split(',') {
        if !flags.insert(option) {
            return Err(WorkerSupervisorError::Untrusted);
        }
        if let Some(n) = option.strip_prefix("mode=") {
            mode = u32::from_str_radix(n, 8).ok();
        } else if let Some(n) = option.strip_prefix("size=") {
            let n = n
                .strip_suffix('B')
                .or_else(|| n.strip_suffix('b'))
                .unwrap_or(n);
            let n = n
                .strip_suffix('i')
                .or_else(|| n.strip_suffix('I'))
                .unwrap_or(n);
            let unit = n.as_bytes().last().copied();
            let multiplier = match unit {
                Some(b'k' | b'K') => 1024,
                Some(b'm' | b'M') => 1024 * 1024,
                Some(b'g' | b'G') => 1024 * 1024 * 1024,
                _ => 1,
            };
            let number = if multiplier == 1 {
                n
            } else {
                &n[..n.len() - 1]
            };
            size = number
                .parse::<u64>()
                .ok()
                .and_then(|n| n.checked_mul(multiplier));
        } else if let Some(n) = option.strip_prefix("nr_inodes=") {
            inodes = n.parse::<u64>().ok();
        } else if !["rw", "nosuid", "nodev", "noexec"].contains(&option) {
            return Err(WorkerSupervisorError::Untrusted);
        }
    }
    if !["rw", "nosuid", "nodev", "noexec"]
        .iter()
        .all(|n| flags.contains(n))
        || flags.len() != 7
        || mode != Some(0o1777)
        || size != Some(64 * 1024 * 1024)
        || inodes != Some(128)
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}

fn validate_service(p: &Properties, mode: WorkerMode) -> Result<()> {
    let caps = if mode == WorkerMode::Check {
        0
    } else {
        1 << 12
    };
    for (key, value) in [
        ("User", "yonik-worker"),
        ("Group", "yonik-worker"),
        ("Type", "exec"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Slice", "system.slice"),
        ("StandardInput", "socket"),
        ("StandardOutput", "null"),
        ("StandardError", "null"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "yes"),
        ("DevicePolicy", "closed"),
    ] {
        if string(p, key)? != value {
            return Err(WorkerSupervisorError::Untrusted);
        }
    }
    for key in [
        "NoNewPrivileges",
        "SendSIGKILL",
        "PrivateTmp",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectKernelLogs",
        "ProtectControlGroups",
        "RestrictRealtime",
        "RestrictSUIDSGID",
        "LockPersonality",
        "MemoryDenyWriteExecute",
    ] {
        if !boolean(p, key)? {
            return Err(WorkerSupervisorError::Untrusted);
        }
    }
    // D-Bus t — allowed-mask: ноль запрещает все namespace types, включая новые.
    // Properties не доказывают фактическую установку seccomp в kernel.
    if number64(p, "RestrictNamespaces")? != 0
        || strings(p, "SystemCallArchitectures")? != ["native"]
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    if boolean(p, "PrivateNetwork")? != (mode == WorkerMode::Check)
        || boolean(p, "PrivateDevices")? != (mode == WorkerMode::Check)
        || number64(p, "CapabilityBoundingSet")? != caps
        || number64(p, "AmbientCapabilities")? != caps
        || number64(p, "MemoryMax")? != 256 * 1024 * 1024
        || number64(p, "TasksMax")? != 64
        || number32(p, "UMask")? != 0o77
        || integer(p, "KillSignal")? != 15
        || integer(p, "FinalKillSignal")? != 9
        || number64(p, "TimeoutStopUSec")? != 5_000_000
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let exec: ExecCommands = p
        .get("ExecStart")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)?;
    if exec.len() != 1
        || exec[0].0 != "/usr/lib/yonik/yonik-worker"
        || exec[0].1
            != [
                "/usr/lib/yonik/yonik-worker",
                if mode == WorkerMode::Check {
                    "--check"
                } else {
                    "--run"
                },
            ]
        || exec[0].2
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let devices: Vec<(String, String)> = p
        .get("DeviceAllow")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)?;
    if (mode == WorkerMode::Check && !devices.is_empty())
        || (mode == WorkerMode::Run && devices != [("/dev/net/tun".into(), "rw".into())])
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}
fn validate_socket(p: &Properties, mode: WorkerMode) -> Result<()> {
    if boolean(p, "Accept")?
        || !boolean(p, "RemoveOnStop")?
        || number32(p, "SocketMode")? != 0o600
        || number32(p, "DirectoryMode")? != 0o700
        || string(p, "SocketUser")? != "root"
        || string(p, "SocketGroup")? != "root"
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let listen: Vec<(String, String)> = p
        .get("Listen")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::try_from(v).ok())
        .ok_or(WorkerSupervisorError::Untrusted)?;
    if listen != [("Stream".into(), mode.channel().into())] {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}
async fn bounded<T>(
    cancel: &mut Cancellation,
    deadline: Instant,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {biased; _=cancel.cancelled()=>Err(WorkerSupervisorError::Cancelled),_=tokio::time::sleep_until(deadline)=>Err(WorkerSupervisorError::Timeout),result=operation=>result}
}

pub(super) const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
const DIR_FLAGS: OFlags = FILE_FLAGS.union(OFlags::DIRECTORY);
pub(super) fn trusted(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata().map_err(unavailable)?;
    if m.uid() != 0
        || m.mode() & 0o022 != 0
        || (directory && !m.is_dir())
        || (!directory && !m.is_file())
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}
pub(super) fn child(parent: &File, name: &str) -> Result<File> {
    let file = File::from(openat(parent, name, DIR_FLAGS, Mode::empty()).map_err(unavailable)?);
    trusted(&file, true)?;
    Ok(file)
}
pub(super) fn root() -> Result<File> {
    let file = File::from(open("/", DIR_FLAGS, Mode::empty()).map_err(unavailable)?);
    trusted(&file, true)?;
    Ok(file)
}
fn read_bounded(file: File) -> Result<String> {
    let mut contents = String::new();
    file.take(16 * 1024 + 1)
        .read_to_string(&mut contents)
        .map_err(unavailable)?;
    if contents.len() > 16 * 1024 {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(contents)
}
pub(super) fn verify_installed() -> Result<()> {
    let mut parent = root()?;
    for component in ["usr", "lib", "systemd", "system"] {
        parent = child(&parent, component)?;
    }
    for (name, expected) in [
        (
            "yonik-worker.service",
            include_str!("../../../../packaging/systemd/yonik-worker.service"),
        ),
        (
            "yonik-worker.socket",
            include_str!("../../../../packaging/systemd/yonik-worker.socket"),
        ),
        (
            "yonik-worker-check.service",
            include_str!("../../../../packaging/systemd/yonik-worker-check.service"),
        ),
        (
            "yonik-worker-check.socket",
            include_str!("../../../../packaging/systemd/yonik-worker-check.socket"),
        ),
    ] {
        let file =
            File::from(openat(&parent, name, FILE_FLAGS, Mode::empty()).map_err(unavailable)?);
        trusted(&file, false)?;
        if read_bounded(file)? != expected {
            return Err(WorkerSupervisorError::Untrusted);
        }
    }
    let launcher_directory = child(&child(&child(&root()?, "usr")?, "lib")?, "yonik")?;
    let launcher = File::from(
        openat(
            &launcher_directory,
            "yonik-worker",
            FILE_FLAGS,
            Mode::empty(),
        )
        .map_err(unavailable)?,
    );
    trusted(&launcher, false)?;
    if launcher.metadata().map_err(unavailable)?.mode() & 0o111 == 0 {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}
fn verify_socket(mode: WorkerMode) -> Result<()> {
    let run = child(&root()?, "run")?;
    let directory = child(&run, "yonik-worker")?;
    if directory.metadata().map_err(unavailable)?.mode() & 0o777 != 0o700 {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let stat = rustix::fs::statat(
        &directory,
        if mode == WorkerMode::Check {
            "check.sock"
        } else {
            "run.sock"
        },
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(unavailable)?;
    if stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o777 != 0o600
        || rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Socket
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    // Каталог root не позволяет UID worker подменить сокет после stat.
    Ok(())
}
fn cgroup_empty(mode: WorkerMode) -> Result<bool> {
    let mut directory = root()?;
    for component in ["sys", "fs", "cgroup"] {
        directory = child(&directory, component)?;
    }
    if fstatfs(&directory).map_err(unavailable)?.f_type as u64 != 0x6367_7270 {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let parent = child(&directory, "system.slice")?;
    let Some(group) = open_worker_group(&parent, mode)? else {
        return Ok(true);
    };
    trusted(&group, true)?;
    let events = File::from(
        openat(&group, "cgroup.events", FILE_FLAGS, Mode::empty()).map_err(unavailable)?,
    );
    empty_events(&read_bounded(events)?)
}
// Вызывающий проверяет root-владельца parent и cgroup2fs до интерпретации ENOENT.
fn open_worker_group(parent: &File, mode: WorkerMode) -> Result<Option<File>> {
    match openat(parent, mode.service(), DIR_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(WorkerSupervisorError::Unavailable),
    }
}
fn empty_events(contents: &str) -> Result<bool> {
    if !contents.ends_with('\n') {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let mut populated = None;
    for line in contents.lines() {
        let (name, value) = line
            .split_once(' ')
            .ok_or(WorkerSupervisorError::Untrusted)?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WorkerSupervisorError::Untrusted);
        }
        if name == "populated" {
            if populated.is_some() {
                return Err(WorkerSupervisorError::Untrusted);
            }
            populated = Some(match value {
                "0" => true,
                "1" => false,
                _ => return Err(WorkerSupervisorError::Untrusted),
            });
        }
    }
    populated.ok_or(WorkerSupervisorError::Untrusted)
}
#[cfg(test)]
#[path = "systemd_worker_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn unit_owner_result(
    owner: &RunAuthority,
    payload: Arc<WorkerPayload>,
) -> AuthorizedRun {
    let authorization = owner.authorize([4; 32]).unwrap();
    let (_, session, generation) = authorization.challenge_context().unwrap();
    let guard = authorization.guard();
    let kernel = crate::worker::anchor_exchange::NamespaceObservation::test_kernel_observation(
        session, generation,
    );
    authorization.bind_custody(&kernel).unwrap();
    let binding = InvocationBinding {
        authorization,
        observation: BootstrapUnitObservation {
            fixture_io: None,
            pid: 42,
            uid: 0,
            gid: 0,
            start: 1,
            invocation: [3; 16],
            expires: Instant::now() + DEADLINE,
            pidfd: std::fs::File::open("/dev/null").unwrap().into(),
        },
        digest: payload.digest(),
        payload,
        kernel: Some(kernel),
    };
    // Только ownership fixture: не имитирует successful canonical verification/mint.
    AuthorizedRun {
        ticket: WorkerTicket {
            pid: 42,
            invocation: [3; 16],
        },
        lease: AuthorizedLease {
            binding,
            _guard: guard,
        },
    }
}

#[cfg(test)]
pub(super) fn unit_raw_identity_result(
    owner: &RunAuthority,
    payload: Arc<WorkerPayload>,
) -> AuthorizedRun {
    use std::os::fd::AsRawFd;
    let mut run = unit_owner_result(owner, payload);
    let observation = &mut run.lease.binding.observation;
    let mut fields = vec!["0"; 20];
    fields[19] = "1";
    observation.fixture_io = Some(FixtureIdentityIo {
        now: Instant::now(),
        files: [
            (
                format!("/proc/self/fdinfo/{}", observation.pidfd.as_raw_fd()),
                "Pid:\t42\n".into(),
            ),
            (
                "/proc/42/stat".into(),
                format!("42 (unit raw fixture) {}", fields.join(" ")),
            ),
            (
                "/proc/42/status".into(),
                "Uid:\t0 0 0 0\nGid:\t0 0 0 0\n".into(),
            ),
            (
                "/proc/42/cgroup".into(),
                format!("0::{}\n", WorkerMode::Run.cgroup()),
            ),
        ]
        .into(),
    });
    run
}

#[cfg(test)]
pub(super) fn unit_owner_payload() -> Arc<WorkerPayload> {
    tests::binding_test_payload()
}

#[cfg(test)]
mod native_activation_tests {
    use super::*;
    #[tokio::test]
    async fn ready_admission_result_cancel_retains_ownership_until_consumed() {
        struct Guard(Arc<AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Guard(Arc::clone(&dropped));
        let mut slot = Some(tokio::spawn(async move { guard }));
        tokio::task::yield_now().await;
        assert!(slot.as_ref().unwrap().is_finished());
        let (cancel_tx, mut cancel) = Cancellation::new();
        cancel_tx.send(true).unwrap();
        assert!(matches!(
            wait_owned(&mut slot, &mut cancel, Instant::now() + DEADLINE).await,
            Err(WorkerSupervisorError::Cancelled)
        ));
        assert!(slot.is_some());
        assert!(!dropped.load(Ordering::Acquire));
        let (_keep, mut fresh) = Cancellation::new();
        let retained = wait_owned(&mut slot, &mut fresh, Instant::now() + DEADLINE)
            .await
            .unwrap();
        assert!(slot.is_none());
        assert!(!dropped.load(Ordering::Acquire));
        drop(retained);
        assert!(dropped.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn bootstrap_inspection_uses_existing_absolute_deadline() {
        let (_keep, mut cancel) = Cancellation::new();
        let result = bounded(&mut cancel, Instant::now(), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        })
        .await;
        assert_eq!(result, Err(WorkerSupervisorError::Timeout));
    }
    #[tokio::test]
    async fn cancelled_wait_retains_owned_transfer_until_join() {
        struct Guard(Arc<AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Guard(Arc::clone(&dropped));
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let mut task = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            release_rx.recv().unwrap();
            Ok(())
        });
        let (cancel_tx, mut cancel) = Cancellation::new();
        cancel_tx.send(true).unwrap();
        let result = bounded(&mut cancel, Instant::now() + DEADLINE, async {
            (&mut task).await.map_err(unavailable)?
        })
        .await;
        assert_eq!(result, Err(WorkerSupervisorError::Cancelled));
        assert!(!dropped.load(Ordering::Acquire));
        release_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(dropped.load(Ordering::Acquire));
    }
    #[test]
    fn activating_and_zero_pid_never_admit() {
        assert_eq!(native_activation_ready("activating", 0), Ok(false));
        assert_eq!(native_activation_ready("active", 0), Ok(false));
        assert_eq!(native_activation_ready("active", 42), Ok(true));
        assert_eq!(
            native_activation_ready("failed", 0),
            Err(WorkerSupervisorError::Stale)
        );
    }
}
