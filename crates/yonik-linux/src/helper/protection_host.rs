//! Доверенный host public-protection IPC. Файловый I/O и nft работают в отдельной
//! blocking-задаче: private D-Bus dispatcher не ждёт fsync на своём runtime.
use super::service::{ProtectionHost, ProtectionState, ServiceError};
use super::{PreparedArtifact, PreparedContext, PreparedError};
use crate::managed_network::{
    Journal, Ownership,
    firewall::{IpPrefix, LanException, PublicBlockPolicy},
    nft::{NftExecutor, PublicPolicyRecovery},
};
use crate::{Cancellation, NetworkMonitor, NetworkStamp, NetworkWatch, read_topology};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    num::NonZeroU64,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use yonik_application::{ConfigDigest, EnvironmentStamp};

#[path = "session_host.rs"]
pub(super) mod session_host;
use session_host::{ActiveSession, HelperTunCustody, SessionArtifact};

const STATE_PATH: &str = "/run/yonik/network";
const MAX_PLAN_BYTES: usize = 64 * 1024;
const RT_SCOPE_LINK: u8 = 253;
const RT_TABLE_MAIN: u32 = 254;
const RTPROT_KERNEL: u8 = 2;
const ARPHRD_ETHER: u16 = 1;
const IFF_UP: u32 = 1;
const IFF_LOOPBACK: u32 = 8;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardPlan {
    version: u32,
    uid: u32,
    stamp: String,
    policy: PublicBlockPolicy,
}
pub struct GuardArtifact {
    bytes: Vec<u8>,
    stamp: NetworkStamp,
    session: Option<Arc<SessionArtifact>>,
}
impl std::fmt::Debug for GuardArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuardArtifact(<скрыто>)")
    }
}
impl PreparedArtifact for GuardArtifact {
    fn bundle_digests(&self) -> Option<super::service::BundleDigests> {
        self.session.as_ref().and_then(|session| session.bundle)
    }
    fn current_digest(&self) -> ConfigDigest {
        ConfigDigest::new(Sha256::digest(&self.bytes).into())
    }
    fn byte_len(&self) -> usize {
        self.bytes.len()
            + self
                .session
                .as_ref()
                .map_or(0, |value| value.payload.retained_bytes())
    }
    fn retained_bytes(&self) -> usize {
        self.bytes.capacity()
            + self
                .session
                .as_ref()
                .map_or(0, |value| value.retained_bytes())
    }
}

pub struct SystemProtectionHost {
    backend: Arc<Mutex<Backend>>,
    operations: Arc<tokio::sync::Semaphore>,
    stop_admission: Arc<tokio::sync::Semaphore>,
    _monitor: NetworkMonitor,
    runtime: tokio::runtime::Handle,
    _safety: Option<session_host::SafetyTask>,
}
struct Backend {
    path: PathBuf,
    journal: Option<Journal>,
    watch: NetworkWatch,
    seed: u64,
    epoch: u64,
    native_owner: session_host::native_owner::NativeOwnerState,
    bindings: Option<NetworkStamp>,
    supervisor: Option<super::SystemWorkerSupervisor>,
    worker_uncertain: bool,
    active: Option<ActiveSession>,
    tun_custody: Option<HelperTunCustody>,
    registry: Option<super::TrustedRegistry>,
    exited: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    isolated: bool,
}
enum Operation {
    Prepare(u32, bool),
    PrepareProfile(u32, Box<super::service::SystemProfileRequest>),
    PrepareBundle(u32, Box<super::service::SystemBundleRequest>),
    Apply(u32, GuardPlan, NetworkStamp),
    ApplyProfile(
        u32,
        Arc<SessionArtifact>,
        NetworkStamp,
        Option<crate::output_transport::ValidatedWriters>,
    ),
    State(u32),
    Stop(u32),
    Unlock(u32),
    #[cfg(test)]
    RuntimeProbe(tokio::sync::oneshot::Sender<()>),
    #[cfg(test)]
    RetentionProbe {
        entered: tokio::sync::oneshot::Sender<()>,
        resume: tokio::sync::oneshot::Receiver<()>,
        finished: tokio::sync::oneshot::Sender<()>,
    },
}
enum Reply {
    Prepared(GuardArtifact),
    State(ProtectionState),
}
fn unavailable<T>(_: T) -> ServiceError {
    ServiceError::Unavailable
}
fn stale() -> ServiceError {
    ServiceError::Prepared(PreparedError::Stale)
}
fn namespace() -> Result<(u64, u64), ServiceError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata("/proc/thread-self/ns/net").map_err(unavailable)?;
    Ok((metadata.dev(), metadata.ino()))
}
impl SystemProtectionHost {
    pub async fn system(mut cancel: Cancellation) -> Result<Self, ServiceError> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(ServiceError::Unavailable);
        }
        Self::create(PathBuf::from(STATE_PATH), &mut cancel, false).await
    }
    async fn create(
        path: PathBuf,
        cancel: &mut Cancellation,
        isolated: bool,
    ) -> Result<Self, ServiceError> {
        let monitor = NetworkMonitor::start().map_err(unavailable)?;
        let mut watch = monitor.watch();
        tokio::time::timeout(Duration::from_secs(5),async {
            while !watch.current().coverage.routes {
                tokio::select! { biased; _=cancel.cancelled()=>return Err(ServiceError::Cancelled), result=watch.changed()=>{result.map_err(unavailable)?;} }
            }
            Ok::<_,ServiceError>(())
        }).await.map_err(unavailable)??;
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).map_err(unavailable)?;
        let seed = u64::from_le_bytes(random).max(1);
        let exited = Arc::new(tokio::sync::Notify::new());
        let backend_exited = Arc::clone(&exited);
        let backend = tokio::task::spawn_blocking(move || {
            let journal = Journal::open_existing(&path).map_err(unavailable)?;
            if journal
                .as_ref()
                .is_some_and(|j| Some(j.ownership().namespace()) != namespace().ok())
            {
                return Err(ServiceError::Unavailable);
            }
            let _fixture_only = isolated;
            Ok::<_, ServiceError>(Backend {
                path,
                journal,
                watch,
                seed,
                epoch: 1,
                native_owner: session_host::native_owner::NativeOwnerState::fresh(),
                bindings: None,
                supervisor: None,
                worker_uncertain: false,
                active: None,
                tun_custody: None,
                registry: None,
                exited: backend_exited,
                #[cfg(test)]
                isolated,
            })
        })
        .await
        .map_err(unavailable)??;
        let backend = Arc::new(Mutex::new(backend));
        let runtime = tokio::runtime::Handle::current();
        let operations = Arc::new(tokio::sync::Semaphore::new(1));
        let safety = session_host::spawn_safety(
            session_host::SessionEvents::new(monitor.watch(), exited),
            Arc::downgrade(&backend),
            runtime.clone(),
            Arc::clone(&operations),
            session_host::reconcile_network_event,
        );
        Ok(Self {
            backend,
            operations,
            stop_admission: Arc::new(tokio::sync::Semaphore::new(1)),
            _monitor: monitor,
            runtime,
            _safety: Some(safety),
        })
    }
    async fn job(&self, operation: Operation, cancel: Cancellation) -> Result<Reply, ServiceError> {
        cancel.check().map_err(|_| ServiceError::Cancelled)?;
        let shared = Arc::clone(&self.backend);
        let runtime = self.runtime.clone();
        if matches!(operation, Operation::Stop(_)) {
            // Единственный допущенный Stop ожидает FIFO gate до spawn_blocking.
            // Drop caller не отменяет уже допущенную задачу и durable cleanup.
            let slot = Arc::clone(&self.stop_admission)
                .try_acquire_owned()
                .map_err(|_| super::service::busy_at("stop_admission_capacity"))?;
            let operations = Arc::clone(&self.operations);
            return tokio::spawn(async move {
                let mut cancel = cancel;
                let permit =
                    wait_for_stop(operations, &mut cancel, super::service::STOP_WAIT_BOUND).await?;
                execute_job(shared, runtime, operation, cancel, (permit, Some(slot))).await
            })
            .await
            .map_err(unavailable)?;
        }
        let permit = Arc::clone(&self.operations)
            .try_acquire_owned()
            .map_err(|_| super::service::busy_at("backend_operation_capacity"))?;
        drop(self.backend.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => super::service::busy_at("backend_job_preflight"),
            _ => ServiceError::Unavailable,
        })?);
        execute_job(shared, runtime, operation, cancel, (permit, None)).await
    }
    #[cfg(test)]
    pub(super) async fn fixture(
        path: PathBuf,
        mut cancel: Cancellation,
    ) -> Result<Self, ServiceError> {
        Self::create(path, &mut cancel, true).await
    }
}
async fn wait_for_stop(
    operations: Arc<tokio::sync::Semaphore>,
    cancel: &mut Cancellation,
    bound: Duration,
) -> Result<tokio::sync::OwnedSemaphorePermit, ServiceError> {
    tokio::select! {
        biased;
        _=cancel.cancelled()=>Err(ServiceError::Cancelled),
        result=tokio::time::timeout(bound,operations.acquire_owned())=>result.map_err(|_|ServiceError::Prepared(PreparedError::Timeout))?.map_err(unavailable),
    }
}
async fn execute_job(
    shared: Arc<Mutex<Backend>>,
    runtime: tokio::runtime::Handle,
    operation: Operation,
    cancel: Cancellation,
    permits: (
        tokio::sync::OwnedSemaphorePermit,
        Option<tokio::sync::OwnedSemaphorePermit>,
    ),
) -> Result<Reply, ServiceError> {
    tokio::task::spawn_blocking(move || {
        let _permits = permits;
        let mut backend = shared.lock().map_err(unavailable)?;
        runtime.block_on(backend.perform(operation, cancel))
    })
    .await
    .map_err(unavailable)?
}
impl Backend {
    fn snapshot(&self) -> Result<crate::NetworkSnapshot, ServiceError> {
        let snapshot = self.watch.current();
        if !snapshot.coverage.routes || snapshot.exhausted {
            return Err(ServiceError::Unavailable);
        }
        Ok(snapshot)
    }
    fn owner(&self, uid: u32) -> Result<Ownership, ServiceError> {
        if let Some(journal) = &self.journal {
            if journal.ownership().owner_uid() == uid {
                return Ok(journal.ownership());
            }
            if !journal.records().is_empty()
                || journal.public_policy().is_some()
                || journal.session_recovery().is_some()
            {
                return Err(super::service::busy_at("backend_owner_uid"));
            }
        }
        let ns = namespace()?;
        Ownership::new(uid, (self.seed ^ u64::from(uid)).max(1), 1, ns.0, ns.1).map_err(unavailable)
    }
    fn context(&self, uid: u32) -> Result<PreparedContext, ServiceError> {
        let owner = self.owner(uid)?;
        let stamp = self.snapshot()?.stamp;
        let digest: [u8; 32] = Sha256::digest(stamp.to_string().as_bytes()).into();
        let network = u64::from_le_bytes(digest[..8].try_into().map_err(unavailable)?).max(1);
        PreparedContext::new(
            NonZeroU64::new(owner.session()).ok_or(ServiceError::Unavailable)?,
            NonZeroU64::new(owner.generation()).ok_or(ServiceError::Unavailable)?,
            EnvironmentStamp {
                network,
                applications: 1,
                authorization: self.epoch,
                engine: self.seed,
                authorized: true,
            },
        )
        .map_err(ServiceError::Prepared)
    }
    fn executor(&self, owner: Ownership) -> Result<NftExecutor, ServiceError> {
        #[cfg(test)]
        if self.isolated {
            return NftExecutor::isolated_fixture(owner).map_err(unavailable);
        }
        NftExecutor::open(owner).map_err(unavailable)
    }
    fn invalidate(&mut self) -> Result<(), ServiceError> {
        self.native_owner.revoke();
        self.epoch = self.epoch.checked_add(1).ok_or_else(|| {
            self.native_owner.close();
            ServiceError::Unavailable
        })?;
        Ok(())
    }
    fn ensure_owner(&mut self, uid: u32) -> Result<Ownership, ServiceError> {
        let next = self.owner(uid)?;
        match &mut self.journal {
            Some(journal) if journal.ownership() != next => {
                journal.reassign_empty_owner(next).map_err(unavailable)?
            }
            None => self.journal = Some(Journal::open(&self.path, next).map_err(unavailable)?),
            _ => {}
        }
        Ok(next)
    }
    async fn observe_state(&mut self, uid: u32) -> Result<ProtectionState, ServiceError> {
        let owner = self.owner(uid)?;
        if self.has_session() || self.worker_uncertain {
            return self.observe_session(uid).await;
        }
        if self.journal.is_none() {
            return Ok(ProtectionState::NoManagedPolicy);
        }
        let mut executor = self.executor(owner)?;
        let journal = self.journal.as_mut().ok_or(ServiceError::Unavailable)?;
        match executor.recover_public_policy(journal).await {
            Ok(PublicPolicyRecovery::NoPolicy) => Ok(ProtectionState::NoManagedPolicy),
            Ok(PublicPolicyRecovery::DesiredRules { .. })
                if self
                    .bindings
                    .is_some_and(|s| self.watch.current().is_current(s)) =>
            {
                Ok(ProtectionState::VerifiedRules)
            }
            Ok(_) => Ok(ProtectionState::RecoveryRequired),
            Err(_) => Ok(ProtectionState::Unknown),
        }
    }
    async fn perform(
        &mut self,
        operation: Operation,
        mut cancel: Cancellation,
    ) -> Result<Reply, ServiceError> {
        cancel.check().map_err(|_| ServiceError::Cancelled)?;
        match operation {
            #[cfg(test)]
            Operation::RuntimeProbe(completed) => {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    let _ = completed.send(());
                });
                Ok(Reply::State(ProtectionState::NoManagedPolicy))
            }
            #[cfg(test)]
            Operation::RetentionProbe {
                entered,
                resume,
                finished,
            } => {
                let _ = entered.send(());
                resume.await.map_err(unavailable)?;
                let _ = finished.send(());
                Ok(Reply::State(ProtectionState::NoManagedPolicy))
            }
            Operation::PrepareBundle(uid, request) => self
                .prepare_bundle_profile(uid, *request, &mut cancel)
                .await
                .map(Reply::Prepared),
            Operation::PrepareProfile(uid, request) => self
                .prepare_profile(uid, *request, &mut cancel)
                .await
                .map(Reply::Prepared),
            Operation::ApplyProfile(uid, artifact, stamp, output) => self
                .apply_profile(uid, artifact, stamp, output, &mut cancel)
                .await
                .map(Reply::State),
            Operation::Prepare(uid, allow_lan) => {
                if self.has_session() || self.worker_uncertain {
                    return Err(super::service::busy_at("backend_prepare_active"));
                }
                // До live-reconciler нельзя сохранять разрешающие LAN bindings
                // после смены topology; RPC явно отказывает, а не ослабляет защиту.
                if allow_lan {
                    return Err(ServiceError::Unsupported);
                }
                let stamp = self.snapshot()?.stamp;
                let owner = self.owner(uid)?;
                let topology = read_topology(&mut cancel, Duration::from_secs(3))
                    .await
                    .map_err(unavailable)?;
                if (topology.namespace.device, topology.namespace.inode) != owner.namespace() {
                    return Err(stale());
                }
                let policy = compile_protection(&topology, allow_lan)?;
                let mut executor = self.executor(owner)?;
                executor
                    .check_public_policy(&policy)
                    .await
                    .map_err(unavailable)?;
                if !self.watch.current().is_current(stamp) {
                    return Err(stale());
                }
                let bytes = serde_json::to_vec(&GuardPlan {
                    version: 1,
                    uid,
                    stamp: stamp.to_string(),
                    policy,
                })
                .map_err(unavailable)?;
                if bytes.len() > MAX_PLAN_BYTES {
                    return Err(ServiceError::Unavailable);
                }
                Ok(Reply::Prepared(GuardArtifact {
                    bytes,
                    stamp,
                    session: None,
                }))
            }
            Operation::Apply(uid, plan, stamp) => {
                if self.has_session() || self.worker_uncertain {
                    return Err(super::service::busy_at("backend_apply_active"));
                }
                if plan.version != 1
                    || plan.uid != uid
                    || plan.stamp != stamp.to_string()
                    || !self.snapshot()?.is_current(stamp)
                {
                    return Err(stale());
                }
                let owner = self.ensure_owner(uid)?;
                self.invalidate()?;
                let table_id = self
                    .journal
                    .as_ref()
                    .and_then(Journal::public_policy)
                    .map(|p| p.table_id())
                    .unwrap_or((self.seed ^ 0xa17e_173b_291c_29ad).max(1));
                let id = self
                    .journal
                    .as_ref()
                    .and_then(Journal::public_policy)
                    .map(|p| p.id())
                    .unwrap_or(1);
                let mut executor = self.executor(owner)?;
                let journal = self.journal.as_mut().ok_or(ServiceError::Unavailable)?;
                executor
                    .apply_durable_public_policy(journal, id, table_id, plan.policy)
                    .await
                    .map_err(unavailable)?;
                self.bindings = Some(stamp);
                Ok(Reply::State(if self.watch.current().is_current(stamp) {
                    ProtectionState::VerifiedRules
                } else {
                    ProtectionState::RecoveryRequired
                }))
            }
            Operation::State(uid) => self.observe_state(uid).await.map(Reply::State),
            Operation::Stop(uid) => {
                self.owner(uid)?;
                self.invalidate()?;
                if self.has_session() || self.worker_uncertain {
                    return self.finish_session(uid, false).await.map(Reply::State);
                }
                self.observe_state(uid).await.map(Reply::State)
            }
            Operation::Unlock(uid) => {
                let owner = self.owner(uid)?;
                self.invalidate()?;
                if self.has_session() || self.worker_uncertain {
                    return self.finish_session(uid, true).await.map(Reply::State);
                }
                if let Some(journal) = &self.journal {
                    let id = journal.public_policy().map(|p| p.id()).unwrap_or(1);
                    let mut executor = self.executor(owner)?;
                    executor
                        .unlock_durable_public_policy(
                            self.journal.as_mut().ok_or(ServiceError::Unavailable)?,
                            id,
                        )
                        .await
                        .map_err(unavailable)?;
                }
                self.bindings = None;
                Ok(Reply::State(ProtectionState::NoManagedPolicy))
            }
        }
    }
}
fn compile_protection(
    topology: &crate::LinuxTopology,
    allow_lan: bool,
) -> Result<PublicBlockPolicy, ServiceError> {
    let loopback = topology
        .links
        .iter()
        .find(|l| l.flags & IFF_LOOPBACK != 0)
        .ok_or(ServiceError::Unavailable)?
        .index;
    let eligible: std::collections::BTreeSet<_> = topology
        .links
        .iter()
        .filter(|l| {
            l.flags & IFF_UP != 0
                && l.flags & IFF_LOOPBACK == 0
                && l.link_type == ARPHRD_ETHER
                && !matches!(l.kind.as_deref(), Some(b"tun" | b"wireguard"))
        })
        .map(|l| l.index)
        .collect();
    let controls: Vec<_> = eligible.iter().copied().collect();
    let mut lan = Vec::new();
    if allow_lan {
        for route in &topology.routes {
            let Some(index) = route.output_interface else {
                continue;
            };
            if route.table == RT_TABLE_MAIN
                && route.protocol == RTPROT_KERNEL
                && route.kind == 1
                && route.destination.length > 0
                && route.gateway.is_none()
                && route.multipath.is_empty()
                && route.nexthop_id.is_none()
                && (route.scope == RT_SCOPE_LINK || route.family == 10 && route.scope == 0)
                && eligible.contains(&index)
            {
                let prefix = IpPrefix::new(route.destination.address, route.destination.length)
                    .map_err(unavailable)?;
                lan.push(LanException::new(prefix, index).map_err(unavailable)?);
            }
        }
    }
    PublicBlockPolicy::new(loopback, None, vec![], lan, vec![], vec![])
        .and_then(|p| p.with_link_control(controls))
        .map_err(unavailable)
}
impl ProtectionHost for SystemProtectionHost {
    type Artifact = GuardArtifact;
    fn bundle_transport(&self) -> bool {
        true
    }
    async fn prepare_bundle(
        &mut self,
        uid: u32,
        request: super::service::SystemBundleRequest,
        cancel: Cancellation,
    ) -> Result<(GuardArtifact, PreparedContext), ServiceError> {
        let Reply::Prepared(artifact) = self
            .job(Operation::PrepareBundle(uid, Box::new(request)), cancel)
            .await?
        else {
            return Err(ServiceError::Unavailable);
        };
        let context = self.context(uid)?;
        if !self._monitor.watch().current().is_current(artifact.stamp) {
            return Err(stale());
        }
        Ok((artifact, context))
    }
    async fn prepare_profile(
        &mut self,
        uid: u32,
        request: super::service::SystemProfileRequest,
        cancel: Cancellation,
    ) -> Result<(GuardArtifact, PreparedContext), ServiceError> {
        let Reply::Prepared(artifact) = self
            .job(Operation::PrepareProfile(uid, Box::new(request)), cancel)
            .await?
        else {
            return Err(ServiceError::Unavailable);
        };
        let context = self.context(uid)?;
        if !self._monitor.watch().current().is_current(artifact.stamp) {
            return Err(stale());
        }
        Ok((artifact, context))
    }
    async fn prepare(
        &mut self,
        uid: u32,
        allow_lan: bool,
        cancel: Cancellation,
    ) -> Result<(GuardArtifact, PreparedContext), ServiceError> {
        let Reply::Prepared(artifact) =
            self.job(Operation::Prepare(uid, allow_lan), cancel).await?
        else {
            return Err(ServiceError::Unavailable);
        };
        let context = self.context(uid)?;
        if !self._monitor.watch().current().is_current(artifact.stamp) {
            return Err(stale());
        }
        Ok((artifact, context))
    }
    fn context(&self, uid: u32) -> Result<PreparedContext, ServiceError> {
        self.backend
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => super::service::busy_at("backend_context"),
                _ => ServiceError::Unavailable,
            })?
            .context(uid)
    }
    async fn apply(
        &mut self,
        uid: u32,
        artifact: &GuardArtifact,
        cancel: Cancellation,
    ) -> Result<ProtectionState, ServiceError> {
        if let Some(session) = &artifact.session {
            return match self
                .job(
                    Operation::ApplyProfile(uid, Arc::clone(session), artifact.stamp, None),
                    cancel,
                )
                .await?
            {
                Reply::State(state) => Ok(state),
                _ => Err(ServiceError::Unavailable),
            };
        }
        let plan: GuardPlan =
            serde_json::from_slice(&artifact.bytes).map_err(|_| ServiceError::InvalidRequest)?;
        match self
            .job(Operation::Apply(uid, plan, artifact.stamp), cancel)
            .await?
        {
            Reply::State(state) => Ok(state),
            _ => Err(ServiceError::Unavailable),
        }
    }
    async fn apply_output(
        &mut self,
        uid: u32,
        artifact: &GuardArtifact,
        output: crate::output_transport::ValidatedWriters,
        cancel: Cancellation,
    ) -> Result<ProtectionState, ServiceError> {
        let session = artifact.session.as_ref().ok_or(ServiceError::Unsupported)?;
        match self
            .job(
                Operation::ApplyProfile(uid, Arc::clone(session), artifact.stamp, Some(output)),
                cancel,
            )
            .await?
        {
            Reply::State(state) => Ok(state),
            _ => Err(ServiceError::Unavailable),
        }
    }
    async fn stop(
        &mut self,
        uid: u32,
        cancel: Cancellation,
    ) -> Result<ProtectionState, ServiceError> {
        match self.job(Operation::Stop(uid), cancel).await? {
            Reply::State(state) => Ok(state),
            _ => Err(ServiceError::Unavailable),
        }
    }
    async fn unlock(
        &mut self,
        uid: u32,
        cancel: Cancellation,
    ) -> Result<ProtectionState, ServiceError> {
        match self.job(Operation::Unlock(uid), cancel).await? {
            Reply::State(state) => Ok(state),
            _ => Err(ServiceError::Unavailable),
        }
    }
    async fn state(
        &mut self,
        uid: u32,
        cancel: Cancellation,
    ) -> Result<ProtectionState, ServiceError> {
        match self.job(Operation::State(uid), cancel).await? {
            Reply::State(state) => Ok(state),
            _ => Err(ServiceError::Unavailable),
        }
    }
}

#[cfg(test)]
#[path = "protection_host_tests.rs"]
mod tests;
