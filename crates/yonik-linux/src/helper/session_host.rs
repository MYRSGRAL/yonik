//! Системная сессия использует тот же backend и тот же durable journal, что и
//! public protection. Accepted worker не доказывает готовность TCP/UDP/DNS.
use super::{
    ARPHRD_ETHER, Backend, GuardArtifact, IFF_LOOPBACK, IFF_UP, Journal, Ownership,
    PreparedContext, ProtectionState, PublicBlockPolicy, PublicPolicyRecovery, ServiceError,
    compile_protection, stale, unavailable,
};
use crate::helper::{
    SessionNetworkPlan, SystemWorkerSupervisor, TrustedRegistry, WorkerLiveness, WorkerTicket,
    memory::{ByteLease, config_budget},
    service::SystemProfileRequest,
};
use crate::{
    Cancellation, KernelRoute, LinuxLink, LinuxTopology, NetworkStamp, RouteKind, RouteQuery,
    managed_network::{Resource, Scope, tun::TunExecutor},
    network::{
        RouteCapture, TopologyCapture, lookup_route_captured, read_topology_captured,
        same_captured_kernel_route, same_captured_topology,
    },
    read_topology,
    worker::WorkerPayload,
};
#[path = "native_owner.rs"]
pub(in crate::helper) mod native_owner;
use sha2::Digest;
use std::{
    fs::File,
    io::Read,
    mem::size_of,
    net::{IpAddr, TcpListener},
    num::NonZeroU16,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
    time::Duration,
};

// Диагностика доступна только lib-test и явно включается в disposable fixture.
fn diagnostic_result<T, E: std::fmt::Debug>(_stage: &str, result: Result<T, E>) -> Result<T, E> {
    #[cfg(test)]
    if std::env::var_os("YONIK_SESSION_DIAGNOSTICS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        eprintln!(
            "session diagnostic {}: {:?}",
            _stage,
            result.as_ref().map(|_| ())
        );
    }
    result
}
fn diagnostic_value<T: std::fmt::Debug, E: std::fmt::Debug>(
    _stage: &str,
    result: Result<T, E>,
) -> Result<T, E> {
    #[cfg(test)]
    if std::env::var_os("YONIK_SESSION_DIAGNOSTICS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        eprintln!("session diagnostic {}: {:?}", _stage, result);
    }
    result
}
#[cfg(test)]
fn diagnostic_link(stage: &str, expected: &LinuxLink, actual: &LinuxLink) {
    if std::env::var_os("YONIK_SESSION_DIAGNOSTICS").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    for (label, link) in [("baseline", expected), ("current", actual)] {
        eprintln!(
            "TUN {stage} {label}: index={} type={} flags={:#x} mtu={:?} master={:?} parent={:?} operstate={:?}",
            link.index,
            link.link_type,
            link.flags,
            link.mtu,
            link.master,
            link.parent,
            link.operational_state
        );
    }
    let before: std::collections::BTreeMap<_, _> =
        expected.unknown.iter().map(|a| (a.kind, a)).collect();
    let after: std::collections::BTreeMap<_, _> =
        actual.unknown.iter().map(|a| (a.kind, a)).collect();
    for kind in before
        .keys()
        .chain(after.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
    {
        let before = before.get(&kind).copied();
        let after = after.get(&kind).copied();
        if before == after {
            continue;
        }
        for (label, value) in [("baseline", before), ("current", after)] {
            match value {
                Some(a) => eprintln!(
                    "TUN {stage} {label} kind={} len={} value={:02x?}",
                    kind,
                    a.value.len(),
                    &a.value[..a.value.len().min(8192)]
                ),
                None => eprintln!("TUN {stage} {label} kind={kind}: отсутствует"),
            }
        }
    }
}

const DEADLINE: Duration = Duration::from_secs(3);
const MAX_BASELINE_BYTES: usize = 3 * 1024 * 1024;
const MAX_PASSWD_BYTES: u64 = 1024 * 1024;
const TUN_ID: u64 = 16;
const MAX_STATUS_BYTES: u64 = 16 * 1024;

/// В ожидании события держим только Weak. Drop host прерывает ожидание, а уже
/// начатый blocking переход сохраняет Backend до завершения cleanup.
pub(super) struct SafetyTask(tokio::task::JoinHandle<()>);
impl Drop for SafetyTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(super) trait SafetyEvents: Send + 'static {
    fn next_event(&mut self) -> impl std::future::Future<Output = bool> + Send;
}
impl SafetyEvents for crate::NetworkWatch {
    async fn next_event(&mut self) -> bool {
        self.changed().await.is_ok()
    }
}
pub(super) struct SessionEvents<N> {
    network: N,
    exited: Arc<tokio::sync::Notify>,
}
impl<N> SessionEvents<N> {
    pub(super) fn new(network: N, exited: Arc<tokio::sync::Notify>) -> Self {
        Self { network, exited }
    }
}
impl<N: SafetyEvents> SafetyEvents for SessionEvents<N> {
    async fn next_event(&mut self) -> bool {
        tokio::select! {
            event = self.network.next_event() => event,
            _ = self.exited.notified() => true,
        }
    }
}
fn watch_worker_exit(
    pid: u32,
    exited: Arc<tokio::sync::Notify>,
) -> Result<SafetyTask, ServiceError> {
    let raw = i32::try_from(pid).map_err(unavailable)?;
    let pid = rustix::process::Pid::from_raw(raw).ok_or(ServiceError::Unavailable)?;
    let fd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::NONBLOCK)
        .map_err(unavailable)?;
    // OwnedFd целиком принадлежит AsyncFd и не предоставляет наружу изменяемый
    // raw descriptor. Новое register API unsafe; используем тот же безопасный
    // ownership pattern, что и RTNETLINK reader, без unsafe-блока.
    #[allow(deprecated)]
    let fd = tokio::io::unix::AsyncFd::new(fd).map_err(unavailable)?;
    Ok(SafetyTask(tokio::spawn(async move {
        // Ошибка наблюдения тоже будит safety: отсутствие события нельзя
        // принять за живой worker. Процессная идентичность закреплена pidfd.
        let _readiness = fd.readable().await;
        exited.notify_one();
    })))
}

pub(super) fn spawn_safety<B: Send + 'static>(
    mut events: impl SafetyEvents,
    backend: std::sync::Weak<Mutex<B>>,
    runtime: tokio::runtime::Handle,
    operations: Arc<tokio::sync::Semaphore>,
    reconcile: fn(&mut B, &tokio::runtime::Handle),
) -> SafetyTask {
    let task_runtime = runtime.clone();
    SafetyTask(runtime.spawn(async move {
        loop {
            // Первый sweep восстанавливает durable owned session после crash;
            // последующий sweep выполняется и при закрытии источника событий.
            let shared = backend.clone();
            let runtime = task_runtime.clone();
            let Ok(permit) = Arc::clone(&operations).acquire_owned().await else {
                break;
            };
            if !matches!(
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let Some(shared) = shared.upgrade() else {
                        return false;
                    };
                    let Ok(mut backend) = shared.lock() else {
                        return false;
                    };
                    reconcile(&mut backend, &runtime);
                    true
                })
                .await,
                Ok(true)
            ) {
                break;
            }
            if !events.next_event().await {
                let shared = backend.clone();
                let runtime = task_runtime.clone();
                let Ok(permit) = Arc::clone(&operations).acquire_owned().await else {
                    break;
                };
                let _ = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    if let Some(shared) = shared.upgrade() {
                        if let Ok(mut backend) = shared.lock() {
                            reconcile(&mut backend, &runtime);
                        }
                    }
                })
                .await;
                break;
            }
        }
    }))
}
pub(super) fn reconcile_network_event(backend: &mut Backend, runtime: &tokio::runtime::Handle) {
    // Legacy public protection живёт независимо; источник событий не меняет её.
    if !backend.has_session() && !backend.worker_uncertain {
        return;
    }
    let Some(uid) = backend
        .journal
        .as_ref()
        .map(|journal| journal.ownership().owner_uid())
    else {
        let (_keep, mut cancel) = fresh_cancel();
        if let Some(supervisor) = &mut backend.supervisor {
            if runtime.block_on(supervisor.recover(&mut cancel)).is_ok() {
                backend.worker_uncertain = false;
            }
        }
        return;
    };
    // Ошибка сохраняет durable intent/блокировку; следующее событие либо явный
    // RPC повторит независимую проверку. Сеть вслепую не очищается.
    let snapshot = backend.watch.current();
    if !snapshot.coverage.routes || snapshot.exhausted {
        if backend.invalidate().is_ok() {
            let _state = runtime.block_on(backend.finish_session(uid, false));
        }
    } else {
        let _state = runtime.block_on(backend.observe_session(uid));
    }
}

fn verify_worker_process(pid: u32, uid: u32) -> Result<(), ServiceError> {
    use rustix::fs::{Mode, OFlags, open};
    if pid == 0 || uid == 0 {
        return Err(ServiceError::Unavailable);
    }
    let file = File::from(
        open(
            format!("/proc/{pid}/status"),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(unavailable)?,
    );
    let mut bytes = Vec::new();
    file.take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    if bytes.len() as u64 > MAX_STATUS_BYTES {
        return Err(ServiceError::Unavailable);
    }
    let result = verify_worker_status(&bytes, uid);
    #[cfg(test)]
    if result.is_err()
        && std::env::var_os("YONIK_SESSION_DIAGNOSTICS").as_deref()
            == Some(std::ffi::OsStr::new("1"))
    {
        eprintln!("worker status expected uid={uid}");
        for line in String::from_utf8_lossy(&bytes).lines().filter(|line| {
            [
                "Uid:",
                "CapInh:",
                "CapPrm:",
                "CapEff:",
                "CapBnd:",
                "CapAmb:",
                "NoNewPrivs:",
                "State:",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        }) {
            eprintln!("worker status {line}");
        }
    }
    result
}
fn verify_worker_status(bytes: &[u8], uid: u32) -> Result<(), ServiceError> {
    if bytes.len() as u64 > MAX_STATUS_BYTES {
        return Err(ServiceError::Unavailable);
    }
    let status = std::str::from_utf8(bytes).map_err(unavailable)?;
    let field = |name: &str| -> Result<&str, ServiceError> {
        let mut fields = status.lines().filter_map(|line| line.strip_prefix(name));
        let value = fields.next().ok_or(ServiceError::Unavailable)?.trim();
        if fields.next().is_some() {
            return Err(ServiceError::Unavailable);
        }
        Ok(value)
    };
    let mut identities = field("Uid:")?.split_whitespace();
    for _ in 0..4 {
        if identities
            .next()
            .ok_or(ServiceError::Unavailable)?
            .parse::<u32>()
            .map_err(unavailable)?
            != uid
        {
            return Err(ServiceError::Unavailable);
        }
    }
    if uid == 0 || identities.next().is_some() || field("NoNewPrivs:")? != "1" {
        return Err(ServiceError::Unavailable);
    }
    for name in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if u64::from_str_radix(field(name)?, 16).map_err(unavailable)? != 0x1000 {
            return Err(ServiceError::Unavailable);
        }
    }
    Ok(())
}

struct BundleCompile {
    resource_session: crate::worker::ResourceSession,
    bus_owner: String,
    peer_identity: [u8; 32],
    resources: Arc<crate::resource_fd_receiver::RebuiltBatch>,
    revision: u64,
    identity: Vec<u8>,
    bindings: Vec<yonik_engine::resource_bundle::ResourceBinding>,
    intent: [u8; 32],
    native_pin: [u8; 32],
}
pub(super) struct SessionArtifact {
    pub(super) bundle: Option<crate::helper::service::BundleDigests>,
    pub(super) payload: Arc<WorkerPayload>,
    plan: SessionNetworkPlan,
    baseline: LinuxTopology,
    baseline_capture: TopologyCapture,
    route: KernelRoute,
    route_capture: RouteCapture,
    context: PreparedContext,
    uid: u32,
    worker_uid: u32,
    kill_switch: bool,
    attribution_required: bool,
    peer: Option<Arc<crate::attribution::PeerProcess>>,
    endpoint: IpAddr,
    port: u16,
    protocol: crate::TransportProtocol,
    memory: ByteLease,
    native_owner_stamp: Option<native_owner::NativeArtifactStamp>,
}
impl SessionArtifact {
    pub(super) fn retained_bytes(&self) -> usize {
        self.payload.retained_bytes() + self.memory.bytes()
    }
    fn query(&self) -> RouteQuery {
        RouteQuery::new(self.endpoint, self.worker_uid)
            .with_mark(self.plan.socket_mark())
            .with_transport(self.protocol, None, Some(self.port))
    }
}
pub(super) struct HelperTunCustody {
    bound: Arc<crate::managed_network::tun::BoundTun>,
}
pub(super) struct ActiveSession {
    artifact: Arc<SessionArtifact>,
    ticket: WorkerTicket,
    index: u32,
    link: LinuxLink,
    _exit_watch: SafetyTask,
}

/// Системный UID читается из фиксированного локального файла. NSS, shell и
/// произвольные программы здесь не участвуют; неоднозначная запись запрещена.
fn worker_uid() -> Result<u32, ServiceError> {
    use rustix::fs::{Mode, OFlags, open};
    let file = File::from(
        open(
            "/etc/passwd",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(unavailable)?,
    );
    let metadata = file.metadata().map_err(unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > MAX_PASSWD_BYTES
    {
        return Err(ServiceError::Unavailable);
    }
    let mut bytes = Vec::new();
    file.take(MAX_PASSWD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    if bytes.len() as u64 > MAX_PASSWD_BYTES {
        return Err(ServiceError::Unavailable);
    }
    parse_worker_uid(&bytes)
}
fn parse_worker_uid(bytes: &[u8]) -> Result<u32, ServiceError> {
    let text = std::str::from_utf8(bytes).map_err(unavailable)?;
    let mut result = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.first() != Some(&"yonik-worker") {
            continue;
        }
        if fields.len() != 7 || result.is_some() {
            return Err(ServiceError::Unavailable);
        }
        let uid: u32 = fields[2].parse().map_err(unavailable)?;
        if uid == 0 || uid == u32::MAX {
            return Err(ServiceError::Unavailable);
        }
        result = Some(uid);
    }
    result.ok_or(ServiceError::Unavailable)
}

fn endpoint(
    server: &yonik_import::ParsedServer,
) -> Result<(IpAddr, crate::TransportProtocol), ServiceError> {
    // До доверенного DNS provenance hostname не порождает ни исключения nft,
    // ни конфигурацию, способную самостоятельно выбрать другой endpoint.
    let address: IpAddr = server
        .endpoint()
        .host()
        .parse()
        .map_err(|_| ServiceError::Unsupported)?;
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || matches!(address, IpAddr::V4(ip) if ip.is_broadcast() || ip.is_link_local())
        || matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local() || ip.to_ipv4().is_some())
    {
        return Err(ServiceError::Unsupported);
    }
    if !matches!(
        server.protocol(),
        yonik_import::Protocol::Vless
            | yonik_import::Protocol::Vmess
            | yonik_import::Protocol::Trojan
    ) || !matches!(
        server.transport(),
        yonik_import::Transport::Tcp
            | yonik_import::Transport::WebSocket
            | yonik_import::Transport::Grpc
            | yonik_import::Transport::Xhttp
    ) {
        return Err(ServiceError::Unsupported);
    }
    Ok((address, crate::TransportProtocol::Tcp))
}
fn checked_route(route: &KernelRoute, owner: Ownership, table: u32) -> Result<u32, ServiceError> {
    if (route.namespace.device, route.namespace.inode) != owner.namespace()
        || route.kind != RouteKind::Unicast
        || !route.incomplete.is_empty()
        || route.table.is_none_or(|value| value == table)
        || route.nexthop_id.is_some()
    {
        #[cfg(test)]
        eprintln!(
            "Проверка маршрута отклонена: kind={:?}, incomplete={:?}, table_present={}, own_table={}, oif={}, nh={}",
            route.kind,
            route.incomplete,
            route.table.is_some(),
            route.table == Some(table),
            route.output_interface.is_some(),
            route.nexthop_id.is_some()
        );
        #[cfg(test)]
        eprintln!(
            "Формы атрибутов маршрута: {:?}",
            route
                .attributes
                .iter()
                .map(|value| (value.kind, value.value.len()))
                .collect::<Vec<_>>()
        );
        return Err(ServiceError::Unsupported);
    }
    route
        .output_interface
        .map(|index| index.get())
        .ok_or(ServiceError::Unsupported)
}
fn fresh_cancel() -> (tokio::sync::watch::Sender<bool>, Cancellation) {
    Cancellation::new()
}

impl Backend {
    // Механический owner endpoint для согласуемого canonical handoff. Legacy
    // by-name сюда не входит; admission и Session factory остаются закрытыми.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn retain_canonical_queue(
        &mut self,
        plan: &SessionNetworkPlan,
        executor: &TunExecutor,
        cancel: &mut Cancellation,
    ) -> Result<(), ServiceError> {
        if self.tun_custody.is_some() || self.worker_uncertain || self.active.is_some() {
            return Err(ServiceError::Busy);
        }
        let bound = plan
            .bind_queue(
                executor,
                self.journal.as_ref().ok_or(ServiceError::Unavailable)?,
                cancel,
            )
            .await
            .map_err(unavailable)?;
        self.tun_custody = Some(HelperTunCustody {
            bound: Arc::new(bound),
        });
        let custody = self.tun_custody.as_mut().ok_or(ServiceError::Unavailable)?;
        Arc::get_mut(&mut custody.bound)
            .ok_or(ServiceError::Unavailable)?
            .transferred();
        Ok(())
    }
    // Вызывается только после успешного supervisor.recover; не admission API.
    fn release_stopped_resources(&mut self) {
        self.native_owner.release_confirmed();
        self.active = None;
        self.tun_custody = None;
    }
    pub(super) fn has_session(&self) -> bool {
        self.native_owner.busy()
            || self.tun_custody.is_some()
            || self.active.is_some()
            || self.journal.as_ref().is_some_and(|journal| {
                journal.session_recovery().is_some()
                    || journal
                        .records()
                        .iter()
                        .any(|record| record.scope() == Scope::Session)
            })
    }
    async fn supervisor(&mut self) -> Result<&mut SystemWorkerSupervisor, ServiceError> {
        if self.supervisor.is_none() {
            self.supervisor = Some(
                SystemWorkerSupervisor::system()
                    .await
                    .map_err(unavailable)?,
            );
        }
        self.supervisor.as_mut().ok_or(ServiceError::Unavailable)
    }
    pub(super) async fn prepare_bundle_profile(
        &mut self,
        uid: u32,
        request: crate::helper::service::SystemBundleRequest,
        cancel: &mut Cancellation,
    ) -> Result<GuardArtifact, ServiceError> {
        if self.has_session() || self.worker_uncertain {
            return Err(ServiceError::Busy);
        }
        request
            .peer
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .verify_identity()
            .map_err(|_| ServiceError::Unsupported)?;
        let intent = request.intent;
        if intent.digest().map_err(|_| ServiceError::InvalidRequest)? != intent.intent_digest
            || !intent.requirements.system_tun
        {
            return Err(ServiceError::InvalidRequest);
        }
        let resources = Arc::new(
            crate::resource_fd_receiver::rebuild(
                request.files,
                &intent.canonical,
                &intent.expected_native,
                &|| cancel.check().is_err(),
            )
            .map_err(|_| {
                if cancel.check().is_err() {
                    ServiceError::Cancelled
                } else {
                    ServiceError::InvalidRequest
                }
            })?,
        );
        let identity = yonik_engine::resource_bundle::policy_identity(intent.policy.policy());
        yonik_engine::resource_bundle::BoundPolicy::bind(
            intent.policy.policy(),
            intent.revision,
            &identity,
            resources.as_ref(),
            intent.bindings.clone(),
        )
        .map_err(|_| ServiceError::InvalidRequest)?;
        let bundle = BundleCompile {
            resource_session: crate::worker::ResourceSession::fresh().map_err(unavailable)?,
            bus_owner: request.owner.ok_or(ServiceError::InvalidRequest)?,
            peer_identity: request
                .peer
                .as_ref()
                .ok_or(ServiceError::Unsupported)?
                .identity_digest(),
            resources,
            revision: intent.revision,
            identity,
            bindings: intent.bindings,
            intent: intent.intent_digest,
            native_pin: intent.native_pin,
        };
        let profile = SystemProfileRequest {
            server: intent.server,
            policy: Some(intent.policy),
            engine: intent.engine,
            kill_switch: intent.requirements.kill_switch,
            peer: request.peer,
        };
        self.prepare_profile_inner(uid, profile, Some(bundle), cancel)
            .await
    }
    pub(super) async fn prepare_profile(
        &mut self,
        uid: u32,
        request: SystemProfileRequest,
        cancel: &mut Cancellation,
    ) -> Result<GuardArtifact, ServiceError> {
        self.prepare_profile_inner(uid, request, None, cancel).await
    }
    async fn prepare_profile_inner(
        &mut self,
        uid: u32,
        request: SystemProfileRequest,
        bundle: Option<BundleCompile>,
        cancel: &mut Cancellation,
    ) -> Result<GuardArtifact, ServiceError> {
        if self.has_session() || self.worker_uncertain {
            return Err(ServiceError::Busy);
        }
        let attribution_required = request
            .policy
            .as_ref()
            .is_some_and(|policy| policy.requires_attribution());
        if attribution_required {
            let admission_uid = worker_uid().map_err(|_| ServiceError::Unsupported)?;
            crate::attribution::preflight(true, request.peer.as_deref(), admission_uid)
                .await
                .map_err(|_| ServiceError::Unsupported)?;
        }
        let server = request
            .server
            .into_server()
            .map_err(|_| ServiceError::InvalidRequest)?;
        let (endpoint, protocol) = endpoint(&server)?;
        let context = self.context(uid)?;
        let stamp = self.snapshot()?.stamp;
        let owner = self.owner(uid)?;
        let (baseline, baseline_capture) = read_topology_captured(cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        let bytes = topology_bytes(&baseline);
        if bytes > MAX_BASELINE_BYTES {
            return Err(ServiceError::Unavailable);
        }
        // Резерв покрывает также отдельный pinned link и route lookup: они
        // удерживаются вместе с baseline после удаления prepared handle.
        let memory = config_budget()
            .reserve(bytes * 2 + 128 * 1024)
            .map_err(unavailable)?;
        let worker_uid = worker_uid()?;
        if worker_uid == uid {
            return Err(ServiceError::Unavailable);
        }
        let plan = SessionNetworkPlan::reserve_for_engine(owner, &baseline, request.engine)
            .map_err(unavailable)?;
        let port = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(unavailable)?
            .local_addr()
            .map_err(unavailable)?
            .port();
        let port = NonZeroU16::new(port).ok_or(ServiceError::Unavailable)?;
        let config = if let Some(policy) = request.policy.as_ref() {
            let probe =
                TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(unavailable)?;
            let probe_port = NonZeroU16::new(probe.local_addr().map_err(unavailable)?.port())
                .ok_or(ServiceError::Unavailable)?;
            if let Some(bundle) = &bundle {
                let bound = yonik_engine::resource_bundle::BoundPolicy::bind(
                    policy.policy(),
                    bundle.revision,
                    &bundle.identity,
                    bundle.resources.as_ref(),
                    bundle.bindings.clone(),
                )
                .map_err(|_| ServiceError::InvalidRequest)?;
                yonik_engine::compile_system_bound_policy(
                    &server,
                    request.engine,
                    port,
                    probe_port,
                    &bound,
                    bundle.revision,
                    &bundle.identity,
                    &plan.compiler_tun().map_err(unavailable)?,
                )
                .map_err(|_| ServiceError::Unsupported)?
            } else {
                yonik_engine::compile_system_policy(
                    &server,
                    request.engine,
                    port,
                    probe_port,
                    policy.policy(),
                    &plan.compiler_tun().map_err(unavailable)?,
                )
                .map_err(|_| ServiceError::Unsupported)?
            }
        } else {
            yonik_engine::compile_system(
                &server,
                request.engine,
                port,
                &plan.compiler_tun().map_err(unavailable)?,
            )
            .map_err(|_| ServiceError::Unsupported)?
        };
        let config = config.with_local_runtime_logging();
        if self.registry.is_none() {
            self.registry = Some(TrustedRegistry::system().map_err(unavailable)?);
        }
        let binary = self
            .registry
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .snapshot(request.engine)
            .map_err(unavailable)?;
        let payload = Arc::new(if let Some(bundle) = &bundle {
            if binary.trusted_hash() != bundle.native_pin {
                return Err(ServiceError::Unsupported);
            }
            WorkerPayload::new_bundle(
                binary,
                config,
                Arc::clone(&bundle.resources),
                bundle.resource_session,
            )
            .map_err(unavailable)?
        } else {
            WorkerPayload::new(binary, config).map_err(unavailable)?
        });
        let query = RouteQuery::new(endpoint, worker_uid)
            .with_mark(plan.socket_mark())
            .with_transport(protocol, None, Some(server.endpoint().port()));
        let (route, route_capture) = lookup_route_captured(query, cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        checked_route(&route, owner, plan.routing_table())?;
        let block = compile_protection(&baseline, false)?;
        self.executor(owner)?
            .check_public_policy(&block)
            .await
            .map_err(unavailable)?;
        self.worker_uncertain = true;
        let result = self
            .supervisor()
            .await?
            .check(Arc::clone(&payload), cancel)
            .await;
        if result.is_err() {
            // Отмена check тоже обязана остановить activation и подтвердить cgroup.
            let (_keep, mut cleanup) = fresh_cancel();
            if self.supervisor().await?.recover(&mut cleanup).await.is_ok() {
                self.worker_uncertain = false;
            }
            return Err(if cancel.check().is_err() {
                ServiceError::Cancelled
            } else {
                ServiceError::Unsupported
            });
        }
        self.worker_uncertain = false;
        let context_matches = self.context(uid)? == context;
        let stamp_matches = self.snapshot()?.is_current(stamp);
        let (current, current_capture) = read_topology_captured(cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        let topology_matches =
            same_captured_topology(&baseline, baseline_capture, &current, current_capture);
        let uid_matches = worker_uid == self::worker_uid()?;
        if !context_matches || !stamp_matches || !topology_matches || !uid_matches {
            #[cfg(test)]
            eprintln!(
                "Актуальность Prepare: context={context_matches}, stamp={stamp_matches}, topology={topology_matches}, worker_uid={uid_matches}"
            );
            return Err(stale());
        }
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(unavailable)?;
        // Nonce связывает единственный immutable Arc baseline/plan с digest.
        // Секретный payload уже sealed и имеет собственный SHA-256.
        let bytes = serde_json::to_vec(&serde_json::json!({"version":2,"uid":uid,
            "stamp":stamp.to_string(),"kill_switch":request.kill_switch,"worker_uid":worker_uid,
            "table":plan.routing_table(),"mark":plan.socket_mark(),"nonce":nonce,
            "payload":payload.digest().as_bytes(),"bundle_owner":bundle.as_ref().map(|b|b.bus_owner.as_str()),"bundle_peer":bundle.as_ref().map(|b|b.peer_identity),"resource_session":bundle.as_ref().map(|b|[b.resource_session.session,b.resource_session.generation])}))
        .map_err(unavailable)?;
        let bundle_digests = if let Some(bundle) = &bundle {
            use yonik_engine::resource_bundle::VerifiedCatalog;
            request
                .peer
                .as_ref()
                .ok_or(ServiceError::Unsupported)?
                .verify_identity()
                .map_err(|_| ServiceError::Unsupported)?;
            let context_digest = sha2::Sha256::digest(&bytes).into();
            let config = *payload.digest().as_bytes();
            let runtime = crate::bundle_identity::runtime_bundle_digest(
                bundle.intent,
                config,
                bundle.resources.manifest(),
                context_digest,
            )
            .map_err(unavailable)?;
            Some(crate::helper::service::BundleDigests {
                intent: bundle.intent,
                config,
                runtime,
            })
        } else {
            None
        };
        let artifact = SessionArtifact {
            native_owner_stamp: if attribution_required {
                Some(self.native_owner.reserve()?)
            } else {
                None
            },
            bundle: bundle_digests,
            payload,
            plan,
            baseline,
            baseline_capture,
            route,
            route_capture,
            context,
            uid,
            worker_uid,
            kill_switch: request.kill_switch,
            attribution_required,
            peer: request.peer,
            endpoint,
            port: server.endpoint().port(),
            protocol,
            memory,
        };
        Ok(GuardArtifact {
            bytes,
            stamp,
            session: Some(Arc::new(artifact)),
        })
    }

    pub(super) async fn apply_profile(
        &mut self,
        uid: u32,
        artifact: Arc<SessionArtifact>,
        stamp: NetworkStamp,
        output: Option<crate::output_transport::ValidatedWriters>,
        cancel: &mut Cancellation,
    ) -> Result<ProtectionState, ServiceError> {
        if artifact.bundle.is_some() {
            artifact
                .peer
                .as_ref()
                .ok_or(ServiceError::Unsupported)?
                .verify_identity()
                .map_err(|_| ServiceError::Unsupported)?;
        }
        crate::attribution::preflight(
            artifact.attribution_required,
            artifact.peer.as_deref(),
            artifact.worker_uid,
        )
        .await
        .map_err(|_| ServiceError::Unsupported)?;
        if self.has_session() || self.worker_uncertain {
            return Err(ServiceError::Busy);
        }
        let (current, current_capture) = read_topology_captured(cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        if artifact.uid != uid
            || self.context(uid)? != artifact.context
            || !self.snapshot()?.is_current(stamp)
            || artifact.worker_uid != worker_uid()?
            || !same_captured_topology(
                &artifact.baseline,
                artifact.baseline_capture,
                &current,
                current_capture,
            )
            || {
                let (route, capture) = lookup_route_captured(artifact.query(), cancel, DEADLINE)
                    .await
                    .map_err(unavailable)?;
                !same_captured_kernel_route(
                    &artifact.route,
                    &route,
                    Some((artifact.route_capture, capture)),
                )
            }
        {
            return Err(stale());
        }
        let owner = self.ensure_owner(uid)?;
        self.invalidate()?;
        self.journal
            .as_mut()
            .ok_or(ServiceError::Unavailable)?
            .begin_session(owner, artifact.kill_switch)
            .map_err(unavailable)?;
        // С этого момента cancellation caller не освобождает journal/worker.
        // Любая ошибка проходит через независимый worker-first cleanup.
        let result = diagnostic_result(
            "start_profile",
            self.start_profile(owner, artifact, output, cancel).await,
        );
        if result.is_err() {
            let cleanup = diagnostic_result("error_cleanup", self.finish_session(uid, false).await);
            if cleanup.is_err() {
                return Ok(ProtectionState::RecoveryRequired);
            }
        }
        result
    }
    async fn policy(
        &mut self,
        owner: Ownership,
        policy: PublicBlockPolicy,
    ) -> Result<(), ServiceError> {
        let existing = self.journal.as_ref().and_then(Journal::public_policy);
        let id = existing.map_or(1, |policy| policy.id());
        let table = existing.map_or((self.seed ^ 0xa17e_173b_291c_29ad).max(1), |policy| {
            policy.table_id()
        });
        self.executor(owner)?
            .apply_durable_public_policy(
                self.journal.as_mut().ok_or(ServiceError::Unavailable)?,
                id,
                table,
                policy,
            )
            .await
            .map_err(unavailable)?;
        Ok(())
    }
    async fn start_profile(
        &mut self,
        owner: Ownership,
        artifact: Arc<SessionArtifact>,
        output: Option<crate::output_transport::ValidatedWriters>,
        cancel: &mut Cancellation,
    ) -> Result<ProtectionState, ServiceError> {
        self.policy(owner, compile_protection(&artifact.baseline, false)?)
            .await?;
        cancel.check().map_err(|_| ServiceError::Cancelled)?;
        let mut tun = TunExecutor::open(owner).map_err(unavailable)?;
        let index = artifact
            .plan
            .configure(
                &mut tun,
                self.journal.as_mut().ok_or(ServiceError::Unavailable)?,
            )
            .await
            .map_err(unavailable)?;
        cancel.check().map_err(|_| ServiceError::Cancelled)?;
        let (route, route_capture) = lookup_route_captured(artifact.query(), cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        let egress = checked_route(&route, owner, artifact.plan.routing_table())?;
        if !same_captured_kernel_route(
            &artifact.route,
            &route,
            Some((artifact.route_capture, route_capture)),
        ) || egress == index
        {
            return Err(stale());
        }
        let topology = read_topology(cancel, DEADLINE).await.map_err(unavailable)?;
        let link = topology
            .links
            .iter()
            .find(|link| link.index == index)
            .ok_or(ServiceError::Unavailable)?
            .clone();
        let loopback = artifact
            .baseline
            .links
            .iter()
            .find(|link| link.flags & IFF_LOOPBACK != 0)
            .ok_or(ServiceError::Unavailable)?
            .index;
        let protocol = match artifact.protocol {
            crate::TransportProtocol::Tcp => {
                crate::managed_network::firewall::TransportProtocol::Tcp
            }
            crate::TransportProtocol::Udp => {
                crate::managed_network::firewall::TransportProtocol::Udp
            }
        };
        let transport = crate::managed_network::firewall::BoundTransport::new(
            artifact.endpoint,
            protocol,
            artifact.port,
            egress,
            artifact.worker_uid,
            artifact.plan.socket_mark(),
        )
        .map_err(unavailable)?;
        let controls = artifact
            .baseline
            .links
            .iter()
            .filter(|link| {
                link.flags & IFF_UP != 0
                    && link.flags & IFF_LOOPBACK == 0
                    && link.link_type == ARPHRD_ETHER
                    && !matches!(link.kind.as_deref(), Some(b"tun" | b"wireguard"))
            })
            .map(|link| link.index)
            .collect();
        let policy = PublicBlockPolicy::new(
            loopback,
            Some(index),
            vec![],
            vec![],
            vec![transport],
            vec![],
        )
        .and_then(|policy| policy.with_link_control(controls))
        .map_err(unavailable)?;
        self.policy(owner, policy).await?;
        artifact
            .plan
            .capture(
                &mut tun,
                self.journal.as_mut().ok_or(ServiceError::Unavailable)?,
                index,
            )
            .await
            .map_err(unavailable)?;
        cancel.check().map_err(|_| ServiceError::Cancelled)?;
        let ticket = if artifact.attribution_required {
            if output.is_some() {
                return Err(ServiceError::Unsupported);
            }
            self.retain_canonical_queue(&artifact.plan, &tun, cancel)
                .await?;
            let record = self
                .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
                .await?;
            self.commit_native_owner(record)?;
            self.start_committed_native(cancel).await?
        } else {
            self.worker_uncertain = true;
            diagnostic_result(
                "worker_start",
                self.supervisor()
                    .await?
                    .start_output(Arc::clone(&artifact.payload), output, cancel)
                    .await,
            )
            .map_err(unavailable)?
        };
        let exit_watch = diagnostic_result(
            "pidfd_watch",
            watch_worker_exit(ticket.pid(), Arc::clone(&self.exited)),
        )?;
        let active = ActiveSession {
            _exit_watch: exit_watch,
            artifact,
            ticket,
            index,
            link,
        };
        // Сохраняем ticket до verification: даже ошибка снимка не теряет worker.
        self.active = Some(active);
        if !self
            .active
            .as_ref()
            .is_some_and(|active| active.artifact.attribution_required)
        {
            self.worker_uncertain = false;
        }
        self.verify_session(cancel).await?;
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.artifact.attribution_required)
        {
            let ticket = &self
                .active
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .ticket;
            if self
                .supervisor
                .as_mut()
                .ok_or(ServiceError::Unavailable)?
                .native_attached(ticket)
                .await
                .map_err(unavailable)?
            {
                self.worker_uncertain = false;
            }
        }
        self.bindings = None;
        Ok(ProtectionState::TunnelStarting)
    }
    async fn verify_network_facts(
        &mut self,
        artifact: &SessionArtifact,
        index: u32,
        link: &LinuxLink,
        cancel: &mut Cancellation,
    ) -> Result<(), ServiceError> {
        let (current, current_capture) = diagnostic_result(
            "topology_read",
            read_topology_captured(cancel, DEADLINE).await,
        )
        .map_err(unavailable)?;
        let current_link = current
            .links
            .iter()
            .find(|link| link.index == index)
            .ok_or(ServiceError::Unavailable);
        let current_link = diagnostic_result("own_link_present", current_link)?;
        if !same_link_contract(link, current_link) {
            #[cfg(test)]
            diagnostic_link("raw", link, current_link);
            return diagnostic_result("same_link_contract", Err(stale()));
        }
        diagnostic_result(
            "external_verification",
            artifact.plan.verify_external_captured(
                &artifact.baseline,
                artifact.baseline_capture,
                current,
                current_capture,
                self.journal.as_ref().ok_or(ServiceError::Unavailable)?,
                index,
            ),
        )
        .map_err(unavailable)?;
        let (route, route_capture) = lookup_route_captured(artifact.query(), cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        if !same_captured_kernel_route(
            &artifact.route,
            &route,
            Some((artifact.route_capture, route_capture)),
        ) {
            return diagnostic_result("escape_route_contract", Err(stale()));
        }
        let owner = self
            .journal
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .ownership();
        if !matches!(
            diagnostic_value(
                "recover_public_policy",
                self.executor(owner)?
                    .recover_public_policy(self.journal.as_mut().ok_or(ServiceError::Unavailable)?)
                    .await
            )
            .map_err(unavailable)?,
            PublicPolicyRecovery::DesiredRules { .. }
        ) {
            return diagnostic_result(
                "verification_state_mismatch",
                Err(ServiceError::Unavailable),
            );
        }
        Ok(())
    }
    async fn verify_session(&mut self, cancel: &mut Cancellation) -> Result<(), ServiceError> {
        let active = self.active.as_ref().ok_or(ServiceError::Unavailable)?;
        let supervisor = self.supervisor.as_ref().ok_or(ServiceError::Unavailable)?;
        if diagnostic_value("observe_before", supervisor.observe(&active.ticket).await)
            .map_err(unavailable)?
            != WorkerLiveness::Running
        {
            return diagnostic_result(
                "verification_state_mismatch",
                Err(ServiceError::Unavailable),
            );
        }
        diagnostic_result(
            "worker_status",
            verify_worker_process(active.ticket.pid(), active.artifact.worker_uid),
        )?;
        let artifact = Arc::clone(&active.artifact);
        let index = active.index;
        let link = active.link.clone();
        self.verify_network_facts(&artifact, index, &link, cancel)
            .await?;
        let active = self.active.as_ref().ok_or(ServiceError::Unavailable)?;
        diagnostic_result(
            "worker_status",
            verify_worker_process(active.ticket.pid(), active.artifact.worker_uid),
        )?;
        if diagnostic_value(
            "observe_after",
            self.supervisor
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .observe(&active.ticket)
                .await,
        )
        .map_err(unavailable)?
            != WorkerLiveness::Running
        {
            return diagnostic_result(
                "verification_state_mismatch",
                Err(ServiceError::Unavailable),
            );
        }
        Ok(())
    }
    pub(super) async fn observe_session(
        &mut self,
        uid: u32,
    ) -> Result<ProtectionState, ServiceError> {
        let (_keep, mut cancel) = fresh_cancel();
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.artifact.attribution_required)
        {
            if self.verify_session(&mut cancel).await.is_ok() {
                let ticket = &self
                    .active
                    .as_ref()
                    .ok_or(ServiceError::Unavailable)?
                    .ticket;
                if let Ok(attached) = self
                    .supervisor
                    .as_mut()
                    .ok_or(ServiceError::Unavailable)?
                    .native_attached(ticket)
                    .await
                {
                    if attached {
                        self.worker_uncertain = false;
                    }
                    return Ok(ProtectionState::TunnelStarting);
                }
            }
            self.invalidate()?;
            return self.finish_session(uid, false).await;
        }
        if !self.worker_uncertain {
            if let (Some(active), Some(supervisor)) = (&self.active, &self.supervisor) {
                if supervisor.observe(&active.ticket).await == Ok(WorkerLiveness::Running)
                    && self.verify_session(&mut cancel).await.is_ok()
                {
                    return Ok(ProtectionState::TunnelStarting);
                }
            }
        }
        self.invalidate()?;
        self.finish_session(uid, false).await
    }
    pub(super) async fn finish_session(
        &mut self,
        uid: u32,
        unlock: bool,
    ) -> Result<ProtectionState, ServiceError> {
        let owner = self.owner(uid)?;
        let keep_block = keep_after_stop(
            unlock,
            self.journal
                .as_ref()
                .and_then(Journal::session_recovery)
                .map(|record| record.kill_switch()),
        );
        let has_journal = self.journal.is_some();
        let mut recovery = BackendRecovery {
            backend: self,
            owner,
        };
        match recover_ordered(&mut recovery, has_journal, keep_block).await {
            Ok(()) => Ok(if keep_block && has_journal {
                ProtectionState::RecoveryRequired
            } else {
                ProtectionState::NoManagedPolicy
            }),
            Err(RecoveryFailure::WorkerUnknown) => Ok(ProtectionState::Unknown),
            Err(RecoveryFailure::Network(error)) => Err(error),
        }
    }
}

/// Разделяет только границы эффектов для детерминированной проверки порядка;
/// actual backend остаётся единственным владельцем supervisor и journal.
trait RecoveryHost {
    async fn stop_worker(&mut self) -> Result<(), ServiceError>;
    async fn restrict(&mut self) -> Result<(), ServiceError>;
    async fn cleanup_network(&mut self) -> Result<(), ServiceError>;
    async fn unlock(&mut self) -> Result<(), ServiceError>;
    async fn clear_intent(&mut self) -> Result<(), ServiceError>;
}
enum RecoveryFailure {
    WorkerUnknown,
    Network(ServiceError),
}
fn keep_after_stop(unlock: bool, disposition: Option<bool>) -> bool {
    !unlock && disposition.unwrap_or(true)
}
async fn recover_ordered(
    host: &mut impl RecoveryHost,
    has_journal: bool,
    keep_block: bool,
) -> Result<(), RecoveryFailure> {
    host.stop_worker()
        .await
        .map_err(|_| RecoveryFailure::WorkerUnknown)?;
    if !has_journal {
        return Ok(());
    }
    host.restrict().await.map_err(RecoveryFailure::Network)?;
    host.cleanup_network()
        .await
        .map_err(RecoveryFailure::Network)?;
    if !keep_block {
        host.unlock().await.map_err(RecoveryFailure::Network)?;
    }
    host.clear_intent().await.map_err(RecoveryFailure::Network)
}
struct BackendRecovery<'a> {
    backend: &'a mut Backend,
    owner: Ownership,
}
impl RecoveryHost for BackendRecovery<'_> {
    async fn stop_worker(&mut self) -> Result<(), ServiceError> {
        let (_keep, mut cancel) = fresh_cancel();
        self.backend.native_owner.revoke();
        self.backend.worker_uncertain = true;
        // recover подтверждает оба fixed cgroup и отключённые socket activation.
        // Повторный Stop не использует stale ticket успешно остановленного worker.
        self.backend
            .supervisor()
            .await?
            .recover(&mut cancel)
            .await
            .map_err(unavailable)?;
        self.backend.worker_uncertain = false;
        self.backend.release_stopped_resources();
        Ok(())
    }
    async fn restrict(&mut self) -> Result<(), ServiceError> {
        let (_keep, mut cancel) = fresh_cancel();
        let topology = read_topology(&mut cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        self.backend
            .policy(self.owner, compile_protection(&topology, false)?)
            .await
    }
    async fn cleanup_network(&mut self) -> Result<(), ServiceError> {
        if self.backend.worker_uncertain || self.backend.tun_custody.is_some() {
            return Err(ServiceError::Busy);
        }
        cleanup_records(
            self.owner,
            self.backend
                .journal
                .as_mut()
                .ok_or(ServiceError::Unavailable)?,
        )
        .await
    }
    async fn unlock(&mut self) -> Result<(), ServiceError> {
        let id = self
            .backend
            .journal
            .as_ref()
            .and_then(Journal::public_policy)
            .map_or(1, |policy| policy.id());
        self.backend
            .executor(self.owner)?
            .unlock_durable_public_policy(
                self.backend
                    .journal
                    .as_mut()
                    .ok_or(ServiceError::Unavailable)?,
                id,
            )
            .await
            .map_err(unavailable)?;
        Ok(())
    }
    async fn clear_intent(&mut self) -> Result<(), ServiceError> {
        self.backend
            .journal
            .as_mut()
            .ok_or(ServiceError::Unavailable)?
            .clear_session(self.owner)
            .map_err(unavailable)?;
        self.backend.bindings = None;
        Ok(())
    }
}

/// Не зависит от живого плана/ticket: исполнители заново проверяют каждый exact
/// descriptor и alias. Неизвестный тип оставляет journal и блокировку целыми.
async fn cleanup_records(owner: Ownership, journal: &mut Journal) -> Result<(), ServiceError> {
    let mut records: Vec<_> = journal
        .records()
        .iter()
        .filter(|record| record.scope() == Scope::Session)
        .map(|record| (record.id(), record.resource().clone()))
        .collect();
    if records.is_empty() {
        return Ok(());
    }
    if records.iter().any(|(id, resource)| {
        !matches!(
            (id, resource),
            (16, Resource::Tun { .. })
                | (17 | 18, Resource::Address { tun_id: 16, .. })
                | (19 | 20, Resource::Route { .. })
                | (21 | 22, Resource::TunRule { tun_id: 16, .. })
        )
    }) {
        return Err(ServiceError::Unavailable);
    }
    records.sort_by_key(|(id, _)| std::cmp::Reverse(*id));
    let mut executor = TunExecutor::open(owner).map_err(unavailable)?;
    for (id, resource) in records {
        match resource {
            Resource::TunRule { tun_id, .. } => executor.remove_rule(journal, tun_id, id).await,
            Resource::Route { .. } => executor.remove_route(journal, TUN_ID, id).await,
            Resource::Address { tun_id, .. } => executor.remove_address(journal, tun_id, id).await,
            Resource::Tun { .. } => executor.remove_tun(journal, id).await,
            _ => return Err(ServiceError::Unavailable),
        }
        .map_err(unavailable)?;
    }
    Ok(())
}

// Полный opaque link binding сохраняет devconf/token/GSO и все новые атрибуты.
// Исключаются только счётчики и carrier/operstate, меняющиеся при attach worker.
fn same_link_contract(expected: &LinuxLink, actual: &LinuxLink) -> bool {
    fn stable(link: &LinuxLink) -> Option<LinuxLink> {
        let mut link = link.clone();
        link.flags &= !(0x10000 | 0x40); // LOWER_UP/RUNNING не являются readiness.
        link.operational_state = None;
        for attribute in &mut link.unknown {
            if matches!(attribute.kind, 7 | 23 | 33 | 35 | 47 | 48) {
                let valid = match attribute.kind {
                    7 => attribute.value.len() == 96,
                    23 => matches!(attribute.value.len(), 192 | 200),
                    33 => attribute.value.len() == 1 && attribute.value[0] <= 1,
                    _ => attribute.value.len() == 4,
                };
                if !valid {
                    return None;
                }
                attribute.value.fill(0);
            } else if attribute.kind == 26 {
                attribute.value = normalize_nested(&attribute.value, |family, bytes| {
                    if family == 10 {
                        normalize_nested(bytes, |kind, value| {
                            // Счётчики/время и carrier flags динамичны. CONF/TOKEN,
                            // ADDR_GEN_MODE и все неизвестные поля сравниваются целиком.
                            let mut value = value.to_vec();
                            match kind {
                                1 if value.len() == 4 => {
                                    let flags = u32::from_ne_bytes(
                                        value.as_slice().try_into().map_err(|_| ())?,
                                    );
                                    value.copy_from_slice(&(flags & !0x8000_0000).to_ne_bytes()); // IF_READY
                                }
                                3 | 6
                                    if !value.is_empty()
                                        && value.len() <= 1024
                                        && value.len() % 8 == 0 =>
                                {
                                    value[8..].fill(0)
                                }
                                5 if value.len() == 16 => value[4..8].fill(0),
                                1 | 3 | 5 | 6 => return Err(()),
                                _ => {}
                            }
                            Ok(Some(value))
                        })
                    } else {
                        Ok(bytes.to_vec())
                    }
                    .map(Some)
                })
                .ok()?;
            } else if attribute.kind == 18 {
                attribute.value = normalize_nested(&attribute.value, |kind, bytes| {
                    if kind == 2 {
                        normalize_nested(bytes, |key, value| {
                            // Число attached/disabled очередей отдельно проверяет
                            // строгая session_external_topology после start.
                            let mut value = value.to_vec();
                            if matches!(key, 8 | 9) {
                                if value.len() != 4 {
                                    return Err(());
                                }
                                value.fill(0);
                            }
                            Ok(Some(value))
                        })
                    } else {
                        Ok(bytes.to_vec())
                    }
                    .map(Some)
                })
                .ok()?;
            }
        }
        Some(link)
    }
    match (stable(expected), stable(actual)) {
        (Some(expected), Some(actual)) => {
            #[cfg(test)]
            if expected != actual {
                diagnostic_link("stable", &expected, &actual);
            }
            expected == actual
        }
        _ => {
            #[cfg(test)]
            let _ = diagnostic_result::<(), _>("stable_link_shape", Err(ServiceError::Unavailable));
            false
        }
    }
}
fn normalize_nested(
    bytes: &[u8],
    mut transform: impl FnMut(u16, &[u8]) -> Result<Option<Vec<u8>>, ()>,
) -> Result<Vec<u8>, ()> {
    let mut rest = bytes;
    let mut result = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    while !rest.is_empty() {
        if rest.len() < 4 || seen.len() >= 128 {
            return Err(());
        }
        let length = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        let kind = u16::from_ne_bytes([rest[2], rest[3]]);
        let aligned = (length + 3) & !3;
        if length < 4 || aligned > rest.len() || !seen.insert(kind) {
            return Err(());
        }
        if let Some(value) = transform(kind, &rest[4..length])? {
            let length = u16::try_from(value.len() + 4).map_err(|_| ())?;
            result.extend_from_slice(&length.to_ne_bytes());
            result.extend_from_slice(&kind.to_ne_bytes());
            result.extend_from_slice(&value);
            result.resize((result.len() + 3) & !3, 0);
        }
        rest = &rest[aligned..];
    }
    Ok(result)
}
fn topology_bytes(topology: &LinuxTopology) -> usize {
    fn vector<T>(value: &Vec<T>) -> usize {
        value.capacity().saturating_mul(size_of::<T>())
    }
    fn attributes(value: &Vec<crate::NetworkAttribute>) -> usize {
        vector(value)
            + value
                .iter()
                .map(|attribute| attribute.value.capacity())
                .sum::<usize>()
    }
    size_of::<LinuxTopology>()
        + vector(&topology.links)
        + vector(&topology.addresses)
        + vector(&topology.routes)
        + vector(&topology.rules)
        + vector(&topology.nexthops)
        + topology
            .links
            .iter()
            .map(|value| {
                value.name.capacity()
                    + value.alias.as_ref().map_or(0, Vec::capacity)
                    + value.kind.as_ref().map_or(0, Vec::capacity)
                    + attributes(&value.unknown)
            })
            .sum::<usize>()
        + topology
            .addresses
            .iter()
            .map(|value| attributes(&value.unknown))
            .sum::<usize>()
        + topology
            .routes
            .iter()
            .map(|value| {
                attributes(&value.unknown)
                    + vector(&value.multipath)
                    + value
                        .multipath
                        .iter()
                        .map(|hop| attributes(&hop.unknown))
                        .sum::<usize>()
            })
            .sum::<usize>()
        + topology
            .rules
            .iter()
            .map(|value| {
                attributes(&value.unknown)
                    + value.input_interface.as_ref().map_or(0, Vec::capacity)
                    + value.output_interface.as_ref().map_or(0, Vec::capacity)
            })
            .sum::<usize>()
        + topology
            .nexthops
            .iter()
            .map(|value| attributes(&value.unknown) + vector(&value.group))
            .sum::<usize>()
}

#[cfg(test)]
#[path = "session_host_tests.rs"]
mod tests;
