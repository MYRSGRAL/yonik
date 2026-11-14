//! Ограниченный private receiver. Не активирует native attribution.
//!
//! Конструктор вызывается trusted host, не RPC decoder. Протокол этого receiver
//! предназначен только для независимых fixtures, не является shared native ABI.
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};
use std::{
    collections::VecDeque,
    fs,
    io::{IoSliceMut, Read},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

mod kernel;

pub const FRAME_BYTES: usize = 136;
const CACHE_ENTRIES: usize = 64;
const MAX_SOCKET_BUFFER: usize = 256 * 1024;
pub const DEADLINE: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    Authority,
    Coverage,
    Limit,
    Timeout,
    Malformed,
    Revoked,
    Cancelled,
    ReceiveOverflow,
    AmbiguousSocket,
    WorkerViewUnavailable,
    Disconnected,
}
#[derive(Debug)]
pub enum Lookup {
    KnownOwner(OwnerSnapshot),
    UnknownFlow,
    MechanismUnavailable(Unavailable),
}
#[derive(Debug)]
pub struct OwnerSnapshot {
    socket_inode: u64,
    task_id: u32,
    task_start: u64,
    socket_fd: u32,
    pub pidfd: OwnedFd,
    pub executable_fd: fs::File,
    pub observed_from: Instant,
    pub observed_until: Instant,
    pub pid: u32,
    pub start_time: u64,
    pub executable: (u64, u64),
    pub cookie: u64,
    pub epoch: u64,
}

/// Только canonical tuple: адреса всегда в network byte order, IPv4 в первых 4 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub family: u8,
    pub protocol: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub local: [u8; 16],
    pub remote: [u8; 16],
    pub cookie: Option<u64>,
}

#[derive(Debug)]
struct Process {
    pid: u32,
    uid: u32,
    start: u64,
    pidfd: OwnedFd,
    namespaces: [(u64, u64); 3],
}
fn bounded(path: &str) -> Result<String, Unavailable> {
    let mut text = String::new();
    fs::File::open(path)
        .map_err(|_| Unavailable::Coverage)?
        .take(16385)
        .read_to_string(&mut text)
        .map_err(|_| Unavailable::Coverage)?;
    if text.len() > 16384 {
        return Err(Unavailable::Limit);
    }
    Ok(text)
}
fn start(pid: u32) -> Result<u64, Unavailable> {
    bounded(&format!("/proc/{pid}/stat"))?
        .rsplit_once(')')
        .and_then(|(_, t)| t.split_whitespace().nth(19))
        .and_then(|s| s.parse().ok())
        .ok_or(Unavailable::Coverage)
}
fn namespaces(pid: u32) -> Result<[(u64, u64); 3], Unavailable> {
    let mut result = [(0, 0); 3];
    for (slot, name) in result.iter_mut().zip(["net", "pid", "mnt"]) {
        let m =
            fs::metadata(format!("/proc/{pid}/ns/{name}")).map_err(|_| Unavailable::Coverage)?;
        *slot = (m.dev(), m.ino());
    }
    Ok(result)
}
impl Process {
    fn capture(pid: u32, uid: u32) -> Result<Self, Unavailable> {
        let id = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or(Unavailable::Authority)?;
        let pidfd = rustix::process::pidfd_open(id, rustix::process::PidfdFlags::NONBLOCK)
            .map_err(|_| Unavailable::Authority)?;
        let p = Self {
            pid,
            uid,
            start: start(pid)?,
            pidfd,
            namespaces: namespaces(pid)?,
        };
        p.validate()?;
        Ok(p)
    }
    fn accept_credentials(&self, c: rustix::net::UCred) -> Result<(), Unavailable> {
        if c.pid.as_raw_pid() as u32 != self.pid || c.uid.as_raw() != self.uid {
            return Err(Unavailable::Authority);
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), Unavailable> {
        let info = bounded(&format!("/proc/self/fdinfo/{}", self.pidfd.as_raw_fd()))?;
        let pid = info.lines().find_map(|s| {
            s.strip_prefix("Pid:")
                .and_then(|s| s.trim().parse::<u32>().ok())
        });
        if pid != Some(self.pid)
            || start(self.pid)? != self.start
            || fs::metadata(format!("/proc/{}", self.pid))
                .map_err(|_| Unavailable::Coverage)?
                .uid()
                != self.uid
            || namespaces(self.pid)? != self.namespaces
        {
            return Err(Unavailable::Authority);
        }
        Ok(())
    }
}

fn receive_frame(
    socket: &OwnedFd,
) -> Result<([u8; FRAME_BYTES + 1], rustix::net::UCred), Unavailable> {
    if rustix::net::sockopt::socket_type(socket).map_err(|_| Unavailable::Authority)?
        != rustix::net::SocketType::SEQPACKET
        || rustix::net::sockopt::socket_domain(socket).map_err(|_| Unavailable::Authority)?
            != rustix::net::AddressFamily::UNIX
    {
        return Err(Unavailable::Authority);
    }
    if rustix::net::sockopt::socket_recv_buffer_size(socket).map_err(|_| Unavailable::Coverage)?
        > MAX_SOCKET_BUFFER
        || rustix::net::sockopt::socket_send_buffer_size(socket)
            .map_err(|_| Unavailable::Coverage)?
            > MAX_SOCKET_BUFFER
    {
        return Err(Unavailable::Limit);
    }
    if !rustix::net::sockopt::socket_passcred(socket).map_err(|_| Unavailable::Authority)? {
        return Err(Unavailable::Authority);
    }
    let mut bytes = [0; FRAME_BYTES + 1];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1), ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let msg = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
    )
    .map_err(|e| {
        if e == rustix::io::Errno::AGAIN {
            Unavailable::Timeout
        } else {
            Unavailable::Coverage
        }
    })?;
    let mut credentials = None;
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmCredentials(c) if credentials.is_none() => {
                credentials = Some(c)
            }
            _ => return Err(Unavailable::Malformed),
        }
    }
    if msg.bytes == 0 {
        return Err(Unavailable::Disconnected);
    }
    if msg
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || msg.bytes != FRAME_BYTES
    {
        return Err(Unavailable::Malformed);
    }
    Ok((bytes, credentials.ok_or(Unavailable::Authority)?))
}

/// Lookup использует только scope broker; worker mount namespace не является
/// свидетельством покрытия таблиц процессов и FD владельцев приложения.
pub struct BrokerLookupView {
    pid: u32,
    namespaces: [(u64, u64); 3],
}
impl BrokerLookupView {
    pub fn capture() -> Result<Self, Unavailable> {
        let pid = std::process::id();
        Ok(Self {
            pid,
            namespaces: namespaces(pid)?,
        })
    }
    fn validate(&self) -> Result<(), Unavailable> {
        if self.pid != std::process::id() || namespaces(self.pid)? != self.namespaces {
            return Err(Unavailable::Coverage);
        }
        Ok(())
    }
}

/// Не Deserialize: worker PID и UID никогда не берутся из запроса.
pub struct TrustedContext {
    scope: Option<crate::helper::native_bootstrap::RuntimeScopeStamp>,
    worker: Process,
    lookup_view: BrokerLookupView,
    target_uid: u32,
    epoch: u64,
    nonce: [u8; 32],
    digest: [u8; 32],
    revoked: bool,
    cancelled: Arc<AtomicBool>,
}
pub(crate) struct VerifiedLookupScope {
    context: TrustedContext,
}
impl VerifiedLookupScope {
    pub(crate) fn verify(
        scope: crate::helper::native_bootstrap::RuntimeScopeStamp,
    ) -> Result<Self, Unavailable> {
        scope.validate().map_err(|_| Unavailable::Authority)?;
        let (worker_pid, worker_uid, owner) = scope.lookup_binding();
        let view = BrokerLookupView::capture()?;
        if view.namespaces[0] != owner.namespace() {
            return Err(Unavailable::Coverage);
        }
        let (nonce, _, _, _, epoch, digest) = scope.context();
        let context = TrustedContext {
            worker: Process::capture(worker_pid, worker_uid)?,
            lookup_view: view,
            target_uid: owner.owner_uid(),
            epoch,
            nonce,
            digest,
            revoked: false,
            cancelled: Arc::new(AtomicBool::new(false)),
            scope: Some(scope),
        };
        Ok(Self { context })
    }
}
impl TrustedContext {
    fn validate_scope(&self) -> Result<(), Unavailable> {
        if let Some(scope) = &self.scope {
            scope.validate().map_err(|_| Unavailable::Revoked)?;
        }
        self.lookup_view.validate()
    }

    pub fn from_host(
        worker_pid: u32,
        worker_uid: u32,
        target_uid: u32,
        epoch: u64,
        nonce: [u8; 32],
        digest: [u8; 32],
    ) -> Result<Self, Unavailable> {
        if target_uid == 0 || nonce == [0; 32] || digest == [0; 32] {
            return Err(Unavailable::Authority);
        }
        Ok(Self {
            scope: None,
            worker: Process::capture(worker_pid, worker_uid).map_err(|e| {
                if e == Unavailable::Coverage {
                    Unavailable::WorkerViewUnavailable
                } else {
                    e
                }
            })?,
            lookup_view: BrokerLookupView::capture()?,
            target_uid,
            epoch,
            nonce,
            digest,
            revoked: false,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// Отмена доступна другому потоку, необратима для текущего epoch.
#[derive(Clone)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Процесс должен быть уже запущен от app UID без capabilities.
/// Сначала выключается dumpability, затем становится возможен receiver.
pub struct Broker {
    context: TrustedContext,
    cache: VecDeque<(Flow, OwnerSnapshot)>,
    last_cold: Option<Instant>,
}
#[cfg(test)]
type CandidateHook = Box<dyn FnOnce(&mut OwnerSnapshot)>;
#[cfg(test)]
thread_local! {static CANDIDATE_HOOK: std::cell::RefCell<Option<CandidateHook>> = std::cell::RefCell::new(None);}

// Одноразовый результат синхронного RPC; authority не сохраняется в cache.
pub(super) struct ValidatedProjection {
    owner: OwnerSnapshot,
    path: String,
    ttl: Duration,
}
impl ValidatedProjection {
    pub(super) fn expiry(&self) -> Result<Instant, Unavailable> {
        self.owner
            .observed_from
            .checked_add(DEADLINE)
            .ok_or(Unavailable::Timeout)
    }
    pub(super) fn into_parts(self) -> (OwnerSnapshot, String, Duration) {
        (self.owner, self.path, self.ttl)
    }
}
pub(super) enum ProjectedLookup {
    Known(ValidatedProjection),
    Unknown,
    Unavailable(Unavailable),
}

impl Broker {
    pub(crate) fn from_verified(scope: VerifiedLookupScope) -> Result<Self, Unavailable> {
        Self::build(scope.context, false)
    }
    pub fn new(context: TrustedContext) -> Result<Self, Unavailable> {
        Self::build(context, true)
    }
    fn build(context: TrustedContext, legacy: bool) -> Result<Self, Unavailable> {
        if rustix::process::getuid().as_raw() != context.target_uid
            || rustix::process::geteuid().as_raw() != context.target_uid
        {
            return Err(Unavailable::Authority);
        }
        let status = bounded("/proc/self/status")?;
        for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
            if status
                .lines()
                .find_map(|l| l.strip_prefix(field))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
                != Some(0)
            {
                return Err(Unavailable::Authority);
            }
        }
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|_| Unavailable::Authority)?;
        context.worker.validate()?;
        context.validate_scope()?;
        // Legacy direct-proc admission сохраняет прежний контракт общего scope.
        if legacy && context.worker.namespaces != context.lookup_view.namespaces {
            return Err(Unavailable::Coverage);
        }
        Ok(Self {
            context,
            cache: VecDeque::new(),
            last_cold: None,
        })
    }
    pub fn cancellation(&self) -> Cancellation {
        Cancellation(Arc::clone(&self.context.cancelled))
    }
    pub fn revoke(&mut self) {
        self.context.revoke();
        self.context.cancelled.store(true, Ordering::Release);
        self.cache.clear();
    }
    /// Ровно один bounded receive, без очереди задач и background scans.
    /// SO_PASSCRED включается до передачи endpoint отправителю.
    pub fn receive(&mut self, socket: &OwnedFd) -> Result<Flow, Unavailable> {
        let result = self.receive_inner(socket);
        if let Err(reason) = result {
            if reason != Unavailable::Timeout {
                self.cache.clear();
            }
            if matches!(
                reason,
                Unavailable::Authority | Unavailable::Coverage | Unavailable::WorkerViewUnavailable
            ) {
                self.revoke();
            }
        }
        result
    }
    fn receive_inner(&mut self, socket: &OwnedFd) -> Result<Flow, Unavailable> {
        if self.context.revoked {
            return Err(Unavailable::Revoked);
        }
        if self.context.cancelled.load(Ordering::Acquire) {
            return Err(Unavailable::Cancelled);
        }
        self.context.validate_scope()?;
        self.context.worker.validate()?;
        let (bytes, c) = match receive_frame(socket) {
            Ok(frame) => frame,
            Err(Unavailable::Disconnected) => {
                self.revoke();
                return Err(Unavailable::Disconnected);
            }
            Err(error) => return Err(error),
        };
        self.context.worker.accept_credentials(c)?;
        self.context.validate_scope()?;
        self.context.worker.validate()?;
        if self.context.cancelled.load(Ordering::Acquire) {
            return Err(Unavailable::Cancelled);
        }
        self.decode(&bytes[..FRAME_BYTES])
    }
    fn decode(&self, b: &[u8]) -> Result<Flow, Unavailable> {
        if b.len() != FRAME_BYTES
            || &b[..4] != b"YOB1"
            || b[4] != 1
            || ![2, 10].contains(&b[5])
            || ![6, 17].contains(&b[6])
            || b[7] > 1
            || b[124..].iter().any(|v| *v != 0)
            || b[8..16] != self.context.epoch.to_be_bytes()
            || b[16..48] != self.context.nonce
            || b[48..80] != self.context.digest
        {
            return Err(Unavailable::Malformed);
        }
        let mut local = [0; 16];
        local.copy_from_slice(&b[84..100]);
        let mut remote = [0; 16];
        remote.copy_from_slice(&b[100..116]);
        if b[5] == 2 && (local[4..].iter().any(|v| *v != 0) || remote[4..].iter().any(|v| *v != 0))
        {
            return Err(Unavailable::Malformed);
        }
        Ok(Flow {
            family: b[5],
            protocol: b[6],
            local_port: u16::from_be_bytes([b[80], b[81]]),
            remote_port: u16::from_be_bytes([b[82], b[83]]),
            local,
            remote,
            cookie: if b[7] == 1 {
                Some(u64::from_be_bytes(
                    b[116..124].try_into().map_err(|_| Unavailable::Malformed)?,
                ))
            } else {
                if b[116..124].iter().any(|v| *v != 0) {
                    return Err(Unavailable::Malformed);
                }
                None
            },
        })
    }
    /// Проекция только через retained snapshot и повторный kernel witness.
    /// Не выпускает authority и не продлевает исходный TTL.
    pub(super) fn project(
        &self,
        flow: Flow,
        snapshot: &OwnerSnapshot,
        epoch: u64,
    ) -> Result<(OwnerSnapshot, String, Duration), Unavailable> {
        if self.context.revoked {
            return Err(Unavailable::Revoked);
        }
        if self.context.cancelled.load(Ordering::Acquire) {
            return Err(Unavailable::Cancelled);
        }
        if epoch != self.context.epoch || snapshot.epoch != epoch {
            return Err(Unavailable::Authority);
        }
        let path = || -> Result<String, Unavailable> {
            let metadata = snapshot
                .executable_fd
                .metadata()
                .map_err(|_| Unavailable::Coverage)?;
            if (metadata.dev(), metadata.ino()) != snapshot.executable {
                return Err(Unavailable::Authority);
            }
            let path = fs::read_link(format!(
                "/proc/self/fd/{}",
                snapshot.executable_fd.as_raw_fd()
            ))
            .map_err(|_| Unavailable::Coverage)?;
            let text = path.to_str().ok_or(Unavailable::Coverage)?;
            super::native_wire::executable_path(text.as_bytes())
                .map_err(|_| Unavailable::Coverage)?;
            let current = fs::metadata(&path).map_err(|_| Unavailable::Coverage)?;
            if (current.dev(), current.ino()) != snapshot.executable {
                return Err(Unavailable::Authority);
            }
            Ok(text.to_owned())
        };
        let before = path()?;
        let validated = kernel::revalidate(&self.context, flow, snapshot)?;
        if path()? != before {
            return Err(Unavailable::Authority);
        }
        if self.context.revoked {
            return Err(Unavailable::Revoked);
        }
        if self.context.cancelled.load(Ordering::Acquire) {
            return Err(Unavailable::Cancelled);
        }
        let ttl = DEADLINE
            .checked_sub(snapshot.observed_from.elapsed())
            .filter(|ttl| !ttl.is_zero())
            .ok_or(Unavailable::Timeout)?;
        Ok((validated, before, ttl))
    }
    /// Candidate не покидает синхронную операцию до финальной проверки project.
    pub(super) fn lookup_and_project(&mut self, flow: Flow, epoch: u64) -> ProjectedLookup {
        #[allow(unused_mut)]
        let mut candidate = self.lookup_candidate(flow, false);
        #[cfg(test)]
        if let Lookup::KnownOwner(snapshot) = &mut candidate {
            CANDIDATE_HOOK.with(|h| {
                if let Some(hook) = h.borrow_mut().take() {
                    hook(snapshot);
                }
            });
        }
        let result = match candidate {
            Lookup::KnownOwner(snapshot) => match self.project(flow, &snapshot, epoch) {
                Ok((owner, path, ttl)) => {
                    ProjectedLookup::Known(ValidatedProjection { owner, path, ttl })
                }
                Err(reason) => ProjectedLookup::Unavailable(reason),
            },
            Lookup::UnknownFlow => ProjectedLookup::Unknown,
            Lookup::MechanismUnavailable(reason) => ProjectedLookup::Unavailable(reason),
        };
        if self.context.cancelled.load(Ordering::Acquire) && !self.context.revoked {
            self.cache.clear();
            return ProjectedLookup::Unavailable(Unavailable::Cancelled);
        }
        if matches!(result, ProjectedLookup::Unavailable(_)) {
            self.cache.clear();
        }
        result
    }
    /// Проверенный snapshot интервала lookup; не identity при рождении socket.
    pub fn lookup(&mut self, flow: Flow) -> Lookup {
        let result = self.lookup_inner(flow);
        if self.context.cancelled.load(Ordering::Acquire) && !self.context.revoked {
            self.cache.clear();
            return Lookup::MechanismUnavailable(Unavailable::Cancelled);
        }
        if matches!(result, Lookup::MechanismUnavailable(_)) {
            self.cache.clear();
        }
        result
    }
    fn lookup_inner(&mut self, flow: Flow) -> Lookup {
        self.lookup_candidate(flow, true)
    }
    fn lookup_candidate(&mut self, flow: Flow, revalidate: bool) -> Lookup {
        if self.context.revoked {
            return Lookup::MechanismUnavailable(Unavailable::Revoked);
        }
        if self.context.cancelled.load(Ordering::Acquire) {
            self.cache.clear();
            return Lookup::MechanismUnavailable(Unavailable::Cancelled);
        }
        self.cache
            .retain(|(_, s)| s.observed_from.elapsed() < DEADLINE);
        if let Some((_, snapshot)) = self.cache.iter().find(|(key, _)| *key == flow) {
            return match if revalidate {
                kernel::revalidate(&self.context, flow, snapshot)
            } else {
                kernel::duplicate(snapshot)
            } {
                Ok(snapshot) => Lookup::KnownOwner(snapshot),
                Err(reason) => {
                    self.cache.clear();
                    Lookup::MechanismUnavailable(reason)
                }
            };
        }
        if self.last_cold.is_some_and(|last| last.elapsed() < DEADLINE) {
            return Lookup::MechanismUnavailable(Unavailable::Limit);
        }
        self.last_cold = Some(Instant::now());
        let result = kernel::lookup(&self.context, flow);
        if let Lookup::KnownOwner(snapshot) = &result {
            let saved = match kernel::duplicate(snapshot) {
                Ok(saved) => saved,
                Err(reason) => return Lookup::MechanismUnavailable(reason),
            };
            if self.cache.len() == CACHE_ENTRIES {
                self.cache.pop_front();
            }
            self.cache.push_back((flow, saved));
        }
        result
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.context.cancelled.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::{Process, TrustedContext, Unavailable};
    #[test]
    fn trusted_identity_fences_without_pid_churn() {
        let uid = rustix::process::getuid().as_raw();
        let mut process = Process::capture(std::process::id(), uid).unwrap();
        process.start = process.start.wrapping_add(1);
        assert_eq!(process.validate(), Err(Unavailable::Authority));
        let mut process = Process::capture(std::process::id(), uid).unwrap();
        process.uid = uid.wrapping_add(1);
        assert_eq!(process.validate(), Err(Unavailable::Authority));
        let mut process = Process::capture(std::process::id(), uid).unwrap();
        process.namespaces[0].1 ^= 1;
        assert_eq!(process.validate(), Err(Unavailable::Authority));
        assert!(
            TrustedContext::from_host(std::process::id(), uid, 0, 1, [1; 32], [2; 32]).is_err()
        );
        assert!(
            TrustedContext::from_host(std::process::id(), uid, uid, 1, [0; 32], [2; 32]).is_err()
        );
    }
}

#[cfg(test)]
#[path = "receiver_tests.rs"]
mod receiver_tests;

// Test-only pending validator до согласования trusted unit proof и custody с Root/FDwriter109.
#[cfg(test)]
mod worker_anchor;

#[cfg(test)]
mod lookup_view_tests {
    use super::*;
    #[test]
    fn broker_view_is_bound_to_its_own_process_scope() {
        let mut view = BrokerLookupView::capture().unwrap();
        assert_eq!(view.validate(), Ok(()));
        view.namespaces[2].1 ^= 1;
        assert_eq!(view.validate(), Err(Unavailable::Coverage));
    }
}

#[cfg(test)]
pub(in crate::attribution) use kernel::report_cold_witnesses;
