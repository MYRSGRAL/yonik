//! Системная сессия использует тот же backend и тот же durable journal, что и
//! public protection. Accepted worker не доказывает готовность TCP/UDP/DNS.
use super::{
    ARPHRD_ETHER, Backend, GuardArtifact, IFF_LOOPBACK, IFF_UP, IpPrefix, Journal, Ownership,
    PreparedContext, ProtectionState, PublicBlockPolicy, PublicPolicyRecovery, ServiceError,
    compile_protection, stale, unavailable,
};
use crate::helper::{
    SessionNetworkPlan, SystemWorkerSupervisor, TrustedRegistry, WorkerLiveness, WorkerTicket,
    memory::{ByteLease, config_budget},
    service::SystemProfileRequest,
    session_fake_dns::{self, ActiveFakeDns, PreparedFakeDns, PublicationHorizon},
    session_network::{
        ExternalTopologyCheck, FIRST_RESOLVER_RULE, FIRST_THROW_ROUTE, LAST_RESOLVER_RULE,
        LAST_THROW_ROUTE,
    },
};
use crate::{
    Cancellation, KernelRoute, LinuxLink, LinuxTopology, NetworkStamp, RouteKind, RouteQuery,
    managed_network::{
        PublicPolicyPhase, QuarantineIntent, Resource, Scope,
        firewall::{BoundDirect, MAX_BOUND_DIRECT, PrivateRoute, ResolverTls},
        tun::TunExecutor,
    },
    network::{
        RouteCapture, TopologyCapture, lookup_route_captured, read_topology_captured,
        reread_changed_route, same_captured_kernel_route, same_captured_topology,
    },
    read_topology,
    worker::WorkerPayload,
};
#[path = "native_owner.rs"]
pub(in crate::helper) mod native_owner;
#[path = "session_dhcp.rs"]
mod session_dhcp;
use sha2::Digest;
use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    io::Read,
    mem::size_of,
    net::{IpAddr, TcpListener},
    num::{NonZeroU16, NonZeroU32},
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
    time::Duration,
};

// Диагностика явно включается в тестовом стенде.
fn diagnostic_result<T, E: std::fmt::Debug>(_stage: &str, result: Result<T, E>) -> Result<T, E> {
    #[cfg(any(test, feature = "test-support"))]
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
    #[cfg(any(test, feature = "test-support"))]
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
const DHCP_TOPOLOGY_RETRY_BUDGET: Duration = Duration::from_millis(300);
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
    if backend
        .active
        .as_ref()
        .is_none_or(|active| active.fake_dns.is_none())
    {
        runtime.block_on(backend.update_quarantine_timer());
    }
    // Legacy public protection живёт независимо; источник событий не меняет её.
    if !backend.has_session()
        && !backend.worker_uncertain
        && !public_unlock_pending(backend.journal.as_ref())
    {
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
    invalid: std::sync::atomic::AtomicBool,
    installed: Option<crate::helper::native_profile::VerifiedStaticInstalledImage>,
    full_profile: Option<Arc<crate::helper::profile_intent::PreparedFullProfile>>,
    physical: Option<crate::helper::profile_intent::SystemPhysicalPlan>,
    routes: Vec<ProfileRoute>,
    owner: Ownership,
    pub(super) bundle: Option<crate::helper::service::BundleDigests>,
    pub(super) payload: Arc<WorkerPayload>,
    plan: SessionNetworkPlan,
    baseline: LinuxTopology,
    baseline_capture: TopologyCapture,
    context: PreparedContext,
    uid: u32,
    worker_uid: u32,
    kill_switch: bool,
    attribution_required: bool,
    peer: Option<Arc<crate::attribution::PeerProcess>>,
    memory: ByteLease,
    native_owner_stamp: Option<native_owner::NativeArtifactStamp>,
    fake_dns: Option<Arc<PreparedFakeDns>>,
    resolver_tls: Option<ResolvedTlsEgress>,
}

struct ResolvedTlsEgress {
    policy: ResolverTls,
    routes: Vec<(KernelRoute, RouteCapture)>,
}

impl ResolvedTlsEgress {
    async fn prepare(
        fake_dns: &PreparedFakeDns,
        plan: SessionNetworkPlan,
        baseline: &LinuxTopology,
        owner: Ownership,
        cancel: &mut Cancellation,
    ) -> Result<(SessionNetworkPlan, Option<Self>), ServiceError> {
        let peers = fake_dns.tls_peers();
        if peers.is_empty() {
            return Ok((plan, None));
        }
        let daemon = fake_dns.tls_daemon().ok_or(ServiceError::Unavailable)?;
        let mut routes = Vec::with_capacity(peers.len());
        let mut rules = Vec::with_capacity(peers.len());
        let mut endpoints = Vec::with_capacity(peers.len());
        for &(peer, route_link) in peers {
            let query = RouteQuery::new(peer.ip(), daemon.uid)
                .with_interfaces(None, route_link.and_then(NonZeroU32::new))
                .with_transport(crate::TransportProtocol::Tcp, None, Some(peer.port()));
            let (route, capture) = lookup_route_captured(query, cancel, DEADLINE)
                .await
                .map_err(unavailable)?;
            let index = checked_route(&route, owner, plan.routing_table())?;
            if route_link.is_some_and(|expected| expected != index)
                || !session_fake_dns::usable_resolver_link(baseline, index)
            {
                return Err(ServiceError::Unsupported);
            }
            let link = baseline
                .links
                .iter()
                .find(|link| link.index == index)
                .ok_or(ServiceError::Unsupported)?;
            let name = String::from_utf8(link.name.clone()).map_err(unavailable)?;
            let table = route.table.ok_or(ServiceError::Unsupported)?;
            endpoints.push((peer, index, name));
            rules.push((peer, table));
            routes.push((route, capture));
        }
        let policy = ResolverTls::new(daemon.uid, daemon.group.1, owner.namespace(), endpoints)
            .map_err(unavailable)?;
        let plan = plan
            .with_resolver_routes(baseline, daemon.uid, &rules)
            .map_err(unavailable)?;
        Ok((plan, Some(Self { policy, routes })))
    }

    async fn verify(&self, cancel: &mut Cancellation) -> Result<(), ServiceError> {
        for (expected, capture) in &self.routes {
            let (route, timing) = reread_changed_route(expected.query.clone(), cancel, DEADLINE)
                .await
                .map_err(unavailable)?;
            if !same_captured_kernel_route(expected, &route, Some((*capture, timing))) {
                return Err(stale());
            }
        }
        Ok(())
    }
}
#[derive(Clone)]
struct ProfileRoute {
    dns: bool,
    endpoint: IpAddr,
    port: u16,
    protocol: crate::TransportProtocol,
    route: KernelRoute,
    capture: RouteCapture,
}
impl SessionArtifact {
    pub(super) fn prepared_context(&self) -> PreparedContext {
        self.context
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.payload.retained_bytes() + self.memory.bytes()
    }
    fn query(&self, route: &ProfileRoute) -> RouteQuery {
        RouteQuery::new(route.endpoint, self.route_uid(route))
            .with_mark(self.plan.socket_mark())
            .with_transport(route.protocol, None, Some(route.port))
    }
    fn route_uid(&self, route: &ProfileRoute) -> u32 {
        if route.dns && self.fake_dns.is_some() {
            0
        } else {
            self.worker_uid
        }
    }
    async fn revalidate_routes(
        &self,
        cancel: &mut Cancellation,
        own_index: Option<u32>,
    ) -> Result<
        (
            Vec<crate::managed_network::firewall::BoundTransport>,
            Vec<crate::managed_network::firewall::BoundTransport>,
        ),
        ServiceError,
    > {
        use std::sync::atomic::Ordering;
        if self.invalid.load(Ordering::Acquire) {
            return Err(stale());
        }
        let result = self.capture_routes(cancel, own_index).await;
        if result.is_err() {
            self.invalid.store(true, Ordering::Release);
        }
        result
    }
    async fn capture_routes(
        &self,
        cancel: &mut Cancellation,
        own_index: Option<u32>,
    ) -> Result<
        (
            Vec<crate::managed_network::firewall::BoundTransport>,
            Vec<crate::managed_network::firewall::BoundTransport>,
        ),
        ServiceError,
    > {
        if let Some(installed) = &self.installed {
            installed
                .revalidate()
                .map_err(|_| ServiceError::Unsupported)?;
        }
        if let Some(profile) = &self.full_profile {
            self.physical
                .as_ref()
                .ok_or_else(stale)?
                .revalidate(profile, cancel)
                .map_err(unavailable)?;
        }
        if let Some(resolver_tls) = &self.resolver_tls {
            self.fake_dns
                .as_ref()
                .ok_or_else(stale)?
                .verify_tls(own_index)
                .await?;
            resolver_tls.verify(cancel).await?;
        }
        let mut transports = Vec::with_capacity(self.routes.len());
        let mut dns = Vec::new();
        for captured in &self.routes {
            // При подъёме собственного TUN уведомление carrier может прервать
            // GETROUTE. Свежий ответ всё равно сравнивается с маршрутом Prepare.
            let (route, stamp) = reread_changed_route(self.query(captured), cancel, DEADLINE)
                .await
                .map_err(|error| {
                    let _ = diagnostic_value::<(), _>(
                        "profile_route_lookup_dns_protocol_error",
                        Err((captured.dns, captured.protocol, error)),
                    );
                    unavailable(error)
                })?;
            let index = checked_route(&route, self.owner, self.plan.routing_table())?;
            if own_index == Some(index)
                || !same_captured_kernel_route(
                    &captured.route,
                    &route,
                    Some((captured.capture, stamp)),
                )
            {
                return Err(stale());
            }
            let protocol = match captured.protocol {
                crate::TransportProtocol::Tcp => {
                    crate::managed_network::firewall::TransportProtocol::Tcp
                }
                crate::TransportProtocol::Udp => {
                    crate::managed_network::firewall::TransportProtocol::Udp
                }
            };
            let bound = crate::managed_network::firewall::BoundTransport::new(
                captured.endpoint,
                protocol,
                captured.port,
                index,
                self.route_uid(captured),
                self.plan.socket_mark(),
            )
            .map_err(unavailable)?;
            if captured.dns {
                dns.push(bound);
            } else {
                transports.push(bound);
            }
        }
        Ok((transports, dns))
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
    exit_watch: SafetyTask,
    fake_dns: Option<ActiveFakeDns>,
    dhcp_refresh: Option<session_dhcp::DhcpRefresh>,
}

/// Sideband использует тот же serial backend и durable journal. Отдельного
/// executor/owner состояния рядом с SystemProtectionHost не создаётся.
pub(super) struct ProfileRoutes {
    backend: std::sync::Weak<Mutex<Backend>>,
    runtime: tokio::runtime::Handle,
    base: Option<PublicBlockPolicy>,
    revision: Option<u64>,
    dynamic: std::collections::BTreeMap<
        crate::managed_network::firewall::BoundTransport,
        (ProfileRoute, u16),
    >,
    tickets: std::collections::BTreeMap<u64, crate::managed_network::firewall::BoundTransport>,
    next: u64,
    unknown: bool,
    _credit: ByteLease,
}
impl ProfileRoutes {
    pub(super) fn new(
        backend: std::sync::Weak<Mutex<Backend>>,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            backend,
            runtime,
            base: None,
            revision: None,
            dynamic: std::collections::BTreeMap::new(),
            tickets: std::collections::BTreeMap::new(),
            next: 0,
            unknown: false,
            _credit: config_budget().reserve(384 * 1024).map_err(unavailable)?,
        })
    }
    fn stable(backend: &Backend) -> Result<(u64, PublicBlockPolicy), ServiceError> {
        let record = backend
            .journal
            .as_ref()
            .and_then(Journal::public_policy)
            .ok_or(ServiceError::Unavailable)?;
        let crate::managed_network::PublicPolicyPhase::Stable { policy } = record.phase() else {
            return Err(ServiceError::Unavailable);
        };
        Ok((record.revision(), policy.clone()))
    }
    async fn fence(
        &mut self,
        backend: &mut Backend,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        cancel: &mut Cancellation,
    ) -> Result<Arc<SessionArtifact>, ServiceError> {
        if self.unknown {
            return Err(ServiceError::Unavailable);
        }
        scope.validate().map_err(unavailable)?;
        let active = backend.active.as_ref().ok_or(ServiceError::Unavailable)?;
        let artifact = Arc::clone(&active.artifact);
        let profile = artifact
            .full_profile
            .as_ref()
            .ok_or(ServiceError::Unsupported)?;
        if scope.context().5 != *profile.retained().digest() {
            return Err(stale());
        }
        backend.verify_session(cancel).await?;
        let (revision, policy) = Self::stable(backend)?;
        if self.revision.is_some_and(|expected| expected != revision) {
            return Err(stale());
        }
        if self.base.is_none() {
            self.base = Some(policy);
            self.revision = Some(revision);
        }
        for (captured, _) in self.dynamic.values() {
            let (route, stamp) = lookup_route_captured(artifact.query(captured), cancel, DEADLINE)
                .await
                .map_err(unavailable)?;
            if !same_captured_kernel_route(&captured.route, &route, Some((captured.capture, stamp)))
            {
                return Err(stale());
            }
        }
        scope.validate().map_err(unavailable)?;
        Ok(artifact)
    }
    async fn replace(
        &mut self,
        backend: &mut Backend,
        artifact: &SessionArtifact,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        omit: Option<crate::managed_network::firewall::BoundTransport>,
    ) -> Result<(), ServiceError> {
        let transports = self
            .dynamic
            .keys()
            .filter(|bound| Some(**bound) != omit)
            .copied()
            .collect::<Vec<_>>();
        let policy = self
            .base
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .with_additional_transport(&transports)
            .map_err(unavailable)?;
        // Candidate остаётся в map при Unknown; journal записывает desired до nft.
        backend.worker_uncertain = true;
        backend.policy(artifact.owner, policy).await?;
        let (revision, _) = Self::stable(backend)?;
        self.revision = Some(revision);
        let (_keep, mut cancel) = fresh_cancel();
        backend.verify_session(&mut cancel).await?;
        scope.validate().map_err(unavailable)?;
        backend.worker_uncertain = false;
        Ok(())
    }
}
enum ProfileRouteEvidence<'a> {
    User(
        &'a crate::attribution::native_session::KnownOwnerProof,
        u64,
        crate::attribution::broker::Flow,
    ),
    Service([u8; 32]),
}
impl ProfileRoutes {
    fn check_route(
        &mut self,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        request: crate::helper::native_profile_channel::RouteRequest<'_>,
        evidence: ProfileRouteEvidence<'_>,
    ) -> Result<Option<u64>, ServiceError> {
        if let ProfileRouteEvidence::User(proof, source, flow) = evidence {
            proof.checked(scope, source, flow).map_err(unavailable)?;
        }
        let shared = self.backend.upgrade().ok_or(ServiceError::Unavailable)?;
        let mut backend = shared.try_lock().map_err(unavailable)?;
        if let ProfileRouteEvidence::User(proof, source, flow) = evidence {
            proof.checked(scope, source, flow).map_err(unavailable)?;
        }
        let runtime = self.runtime.clone();
        let result = runtime.block_on(async {
            let (_keep, mut cancel) = fresh_cancel();
            let artifact = self.fence(&mut backend, scope, &mut cancel).await?;
            if let ProfileRouteEvidence::Service(manifest)=evidence {
                let profile=artifact.full_profile.as_ref().ok_or(ServiceError::Unsupported)?;
                let capsule=crate::profile_channel::Capsule::decode(profile.capsule_bytes(),profile.retained().digest()).map_err(unavailable)?;
                if capsule.manifest!=manifest {return Err(stale());}
            }
            use crate::helper::native_profile_channel::RouteRequest;
            let (destination, dns, dynamic) = match request {
                RouteRequest::Chain => return Ok(None),
                RouteRequest::Static(d) => (d, false, false),
                RouteRequest::Dns(d) => {
                    crate::helper::native_profile_channel::reject_unproved_stub(d)?;
                    (d, true, false)
                },
                RouteRequest::Direct(d) => (d, false, true),
            };
            if destination.family==3 {
                // Только checked USER logical parent. Ни IP, ни transport rule
                // здесь не создаются. Source Numeric выдаёт отдельный ticket;
                // consuming producer требует ОБА live разрешения перед open.
                if !dns && !dynamic && matches!(evidence,ProfileRouteEvidence::User(..))
                    && artifact.physical.as_ref().is_some_and(|p| p.deferred_parent_shape(destination)) {
                    return Ok(None);
                }
                return Err(ServiceError::Unsupported);
            }
            // Не authority: issuer уже проверил exact Source/member/parent.
            // Backend дополнительно связывает service member с retained frontier.
            if matches!(evidence, ProfileRouteEvidence::Service(_)) && dynamic {
                if let Some(plan)=&artifact.physical {
                    if plan.deferred_count()>0 && !plan.member_shape(destination.port,
                        match destination.protocol {6=>crate::TransportProtocol::Tcp,17=>crate::TransportProtocol::Udp,_=>return Err(ServiceError::Unsupported)}) {
                        return Err(ServiceError::Unsupported);
                    }
                }
            }
            let endpoint = match destination.family {
                4 if destination.bytes.len() == 4 => IpAddr::V4(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(destination.bytes).map_err(unavailable)?,
                )),
                6 if destination.bytes.len() == 16 => IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(destination.bytes).map_err(unavailable)?,
                )),
                _ => return Err(ServiceError::Unsupported),
            };
            let protocol = match destination.protocol {
                6 => crate::TransportProtocol::Tcp,
                17 => crate::TransportProtocol::Udp,
                _ => return Err(ServiceError::InvalidRequest),
            };
            if !dynamic {
                if !artifact.routes.iter().any(|r| {
                    r.endpoint == endpoint
                        && r.port == destination.port
                        && r.protocol == protocol
                        && r.dns == dns
                }) {
                    return Err(ServiceError::Unavailable);
                }
                return Ok(None);
            }
            if self.tickets.len() >= 4096 {
                return Err(ServiceError::Busy);
            }
            let query = RouteQuery::new(endpoint, artifact.worker_uid)
                .with_mark(artifact.plan.socket_mark())
                .with_transport(protocol, None, Some(destination.port));
            let (route, capture) = lookup_route_captured(query, &mut cancel, DEADLINE)
                .await
                .map_err(unavailable)?;
            let index = checked_route(&route, artifact.owner, artifact.plan.routing_table())?;
                if endpoint.is_unspecified() || endpoint.is_loopback() || endpoint.is_multicast()
                    || matches!(endpoint,IpAddr::V4(ip) if ip.is_link_local() || ip.is_broadcast())
                    || matches!(endpoint,IpAddr::V6(ip) if ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some())
                    || artifact.baseline.links.iter().any(|link|link.index==index && matches!(link.kind.as_deref(),Some(b"tun"|b"wireguard")))
                {return Err(ServiceError::Unsupported);}
                let base=self.base.as_ref().ok_or(ServiceError::Unavailable)?;
                if artifact.baseline.routes.iter().any(|route|route.destination.length>0 && route.gateway.is_none() && route.output_interface==Some(index) && IpPrefix::new(route.destination.address,route.destination.length).is_ok_and(|prefix|prefix.contains(endpoint))) && !base.permits_lan_endpoint(endpoint,index) {return Err(ServiceError::Unsupported);}
            if backend
                .active
                .as_ref()
                .is_none_or(|active| active.index == index)
            {
                return Err(stale());
            }
            let bound = crate::managed_network::firewall::BoundTransport::new(
                endpoint,
                match protocol {
                    crate::TransportProtocol::Tcp => {
                        crate::managed_network::firewall::TransportProtocol::Tcp
                    }
                    crate::TransportProtocol::Udp => {
                        crate::managed_network::firewall::TransportProtocol::Udp
                    }
                },
                destination.port,
                index,
                artifact.worker_uid,
                artifact.plan.socket_mark(),
            )
            .map_err(unavailable)?;
            self.next = self.next.checked_add(1).ok_or(ServiceError::Unavailable)?;
            let ticket = self.next;
            if let Some((_, refs)) = self.dynamic.get_mut(&bound) {
                *refs = refs
                    .checked_add(1)
                    .filter(|n| *n <= 4096)
                    .ok_or(ServiceError::Busy)?;
                self.tickets.insert(ticket, bound);
                return Ok(Some(ticket));
            }
            if self.dynamic.len() >= 128 {
                return Err(ServiceError::Busy);
            }
            // Проверка общего cap до вставки и до первого kernel effect.
            let mut extra = self.dynamic.keys().copied().collect::<Vec<_>>();
            extra.push(bound);
            self.base
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .with_additional_transport(&extra)
                .map_err(unavailable)?;
            self.dynamic.insert(
                bound,
                (
                    ProfileRoute {
                        dns: false,
                        endpoint,
                        port: destination.port,
                        protocol,
                        route,
                        capture,
                    },
                    1,
                ),
            );
            self.tickets.insert(ticket, bound);
            self.replace(&mut backend, &artifact, scope, None).await?;
            Ok(Some(ticket))
        });
        if result.is_err() {
            self.unknown = true;
            scope.revoke();
            backend.native_owner.revoke();
            backend.worker_uncertain = true;
        }
        result
    }
}
impl crate::helper::native_profile_channel::RouteAuthority for ProfileRoutes {
    fn check_bootstrap_permit(
        &mut self,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        route: crate::helper::native_profile_channel::BootstrapDnsRoute,
    ) -> Result<(), ServiceError> {
        self.check_bootstrap_dns(scope, route, None)
    }
    fn bootstrap_dns_socket(
        &mut self,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        route: crate::helper::native_profile_channel::BootstrapDnsRoute,
        facts: &crate::helper::native_profile_channel::dns_transport::Facts,
    ) -> Result<(), ServiceError> {
        self.check_bootstrap_dns(scope, route, Some(facts))
    }
    fn dns_socket(
        &mut self,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        ticket: Option<u64>,
        facts: &crate::helper::native_profile_channel::dns_transport::Facts,
    ) -> Result<(), ServiceError> {
        let bound = ticket
            .map(|ticket| {
                self.tickets
                    .get(&ticket)
                    .copied()
                    .ok_or(ServiceError::Unavailable)
            })
            .transpose()?;
        let shared = self.backend.upgrade().ok_or(ServiceError::Unavailable)?;
        let mut backend = shared.try_lock().map_err(unavailable)?;
        let runtime = self.runtime.clone();
        let result = runtime.block_on(async {
            let (_keep, mut cancel) = fresh_cancel();
            let artifact = self.fence(&mut backend, scope, &mut cancel).await?;
            let route = if let Some(bound) = bound {
                &self.dynamic.get(&bound).ok_or(ServiceError::Unavailable)?.0
            } else {
                // None не authority: только exact retained static first-hop,
                // повторно проверенный existing session/network fence выше.
                artifact
                    .routes
                    .iter()
                    .find(|r| {
                        !r.dns
                            && crate::helper::native_profile_channel::dns_route_socket_matches(
                                r.endpoint,
                                r.port,
                                r.protocol,
                                r.route.preferred_source,
                                artifact.worker_uid,
                                artifact.plan.socket_mark(),
                                facts,
                            )
                    })
                    .ok_or(ServiceError::Unavailable)?
            };
            if !crate::helper::native_profile_channel::dns_route_socket_matches(
                route.endpoint,
                route.port,
                route.protocol,
                route.route.preferred_source,
                artifact.worker_uid,
                artifact.plan.socket_mark(),
                facts,
            ) {
                return Err(ServiceError::Unavailable);
            }
            scope.validate().map_err(unavailable)
        });
        if result.is_err() {
            self.unknown = true;
            scope.revoke();
            backend.native_owner.revoke();
            backend.worker_uncertain = true;
        }
        result
    }
    fn check(
        &mut self,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        request: crate::helper::native_profile_channel::RouteRequest<'_>,
        proof: &crate::attribution::native_session::KnownOwnerProof,
        source: u64,
        flow: crate::attribution::broker::Flow,
    ) -> Result<Option<u64>, ServiceError> {
        self.check_route(
            scope,
            request,
            ProfileRouteEvidence::User(proof, source, flow),
        )
    }
    fn service(
        &mut self,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        manifest: [u8; 32],
        request: crate::helper::native_profile_channel::RouteRequest<'_>,
    ) -> Result<Option<u64>, ServiceError> {
        self.check_route(scope, request, ProfileRouteEvidence::Service(manifest))
    }
    fn release(
        &mut self,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        ticket: u64,
    ) -> Result<(), ServiceError> {
        let bound = *self.tickets.get(&ticket).ok_or(ServiceError::Unavailable)?;
        let shared = self.backend.upgrade().ok_or(ServiceError::Unavailable)?;
        let mut backend = shared.try_lock().map_err(unavailable)?;
        let runtime = self.runtime.clone();
        let result = runtime.block_on(async {
            let (_keep, mut cancel) = fresh_cancel();
            let artifact = self.fence(&mut backend, scope, &mut cancel).await?;
            let (_, refs) = self
                .dynamic
                .get_mut(&bound)
                .ok_or(ServiceError::Unavailable)?;
            if *refs > 1 {
                *refs -= 1;
                self.tickets.remove(&ticket);
                return Ok(());
            }
            self.replace(&mut backend, &artifact, scope, Some(bound))
                .await?;
            self.dynamic.remove(&bound);
            self.tickets.remove(&ticket);
            Ok(())
        });
        if result.is_err() {
            self.unknown = true;
            scope.revoke();
            backend.native_owner.revoke();
            backend.worker_uncertain = true;
        }
        result
    }
}
impl ProfileRoutes {
    fn check_bootstrap_dns(
        &mut self,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        request: crate::helper::native_profile_channel::BootstrapDnsRoute,
        facts: Option<&crate::helper::native_profile_channel::dns_transport::Facts>,
    ) -> Result<(), ServiceError> {
        let shared = self.backend.upgrade().ok_or(ServiceError::Unavailable)?;
        let mut backend = shared.try_lock().map_err(unavailable)?;
        let runtime = self.runtime.clone();
        let result = runtime.block_on(async {
            let (_keep, mut cancel) = fresh_cancel();
            let artifact = self.fence(&mut backend, scope, &mut cancel).await?;
            let profile = artifact
                .full_profile
                .as_ref()
                .ok_or(ServiceError::Unsupported)?;
            let cap = crate::profile_channel::Capsule::decode(
                profile.capsule_bytes(),
                profile.retained().digest(),
            )
            .map_err(unavailable)?;
            request.validate(&cap)?;
            let peer = request.peer();
            let route = artifact
                .routes
                .iter()
                .find(|r| {
                    r.dns
                        && r.port == peer.port
                        && peer.protocol
                            == match r.protocol {
                                crate::TransportProtocol::Tcp => 6,
                                crate::TransportProtocol::Udp => 17,
                            }
                        && match r.endpoint {
                            IpAddr::V4(ip) => peer.family == 4 && peer.bytes == ip.octets(),
                            IpAddr::V6(ip) => peer.family == 6 && peer.bytes == ip.octets(),
                        }
                })
                .ok_or(ServiceError::Unavailable)?;
            if let Some(facts) = facts {
                if !crate::helper::native_profile_channel::dns_route_socket_matches(
                    route.endpoint,
                    route.port,
                    route.protocol,
                    route.route.preferred_source,
                    artifact.worker_uid,
                    artifact.plan.socket_mark(),
                    facts,
                ) {
                    return Err(ServiceError::Unavailable);
                }
            }
            scope.validate().map_err(unavailable)
        });
        if result.is_err() {
            self.unknown = true;
            scope.revoke();
            backend.native_owner.revoke();
            backend.worker_uncertain = true;
        }
        result
    }
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

fn fake_wireguard_guards(baseline: &LinuxTopology) -> Result<Vec<PrivateRoute>, ServiceError> {
    let wireguard: BTreeSet<_> = baseline
        .links
        .iter()
        .filter(|link| link.kind.as_deref() == Some(b"wireguard"))
        .map(|link| link.index)
        .collect();
    if wireguard.is_empty() {
        return Ok(Vec::new());
    }
    let is_wireguard = |index: u32| wireguard.contains(&index);
    let nexthops: BTreeSet<_> = baseline
        .nexthops
        .iter()
        .filter(|hop| hop.output_interface.is_some_and(is_wireguard))
        .map(|hop| hop.id)
        .collect();
    let groups: BTreeSet<_> = baseline
        .nexthops
        .iter()
        .filter(|hop| hop.group.iter().any(|member| nexthops.contains(&member.id)))
        .map(|hop| hop.id)
        .collect();
    // Перехват default через TUN не должен отправлять явные сети WireGuard в
    // прокси. До появления подтверждённого маршрута применяем только drop.
    baseline
        .routes
        .iter()
        .filter(|route| {
            route.destination.length > 0
                && RouteKind::from(route.kind) == RouteKind::Unicast
                && (route.output_interface.is_some_and(is_wireguard)
                    || route
                        .multipath
                        .iter()
                        .any(|hop| is_wireguard(hop.output_interface))
                    || route
                        .nexthop_id
                        .is_some_and(|id| nexthops.contains(&id) || groups.contains(&id)))
        })
        .map(|route| (route.destination.address, route.destination.length))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(address, length)| {
            let prefix = IpPrefix::new(address, length).map_err(unavailable)?;
            PrivateRoute::new(prefix, None).map_err(unavailable)
        })
        .collect()
}

fn bound_fake_literal_direct(
    policy: &yonik_engine::policy_wire::SystemPolicy,
    baseline: &LinuxTopology,
    worker_uid: u32,
    mark: u32,
) -> Result<Vec<BoundDirect>, ServiceError> {
    let mut prefixes = BTreeSet::new();
    for (address, length) in policy.enabled_direct_prefixes() {
        prefixes.insert((address, length));
        if prefixes.len() > MAX_BOUND_DIRECT {
            return Err(ServiceError::Unsupported);
        }
    }
    if prefixes.is_empty() {
        return Ok(Vec::new());
    }
    let uplinks: HashMap<_, _> = baseline
        .links
        .iter()
        .filter(|link| {
            link.flags & IFF_UP != 0
                && link.flags & IFF_LOOPBACK == 0
                && link.link_type == ARPHRD_ETHER
                && matches!(
                    link.kind.as_deref(),
                    None | Some(
                        b"veth" | b"vlan" | b"bridge" | b"bond" | b"team" | b"macvlan" | b"ipvlan"
                    )
                )
        })
        .map(|link| (link.index, &link.name))
        .collect();
    let mut egress = BTreeSet::new();
    for (address, length) in prefixes {
        let prefix = IpPrefix::new(address, length).map_err(|_| ServiceError::Unsupported)?;
        let before = egress.len();
        // Снимок ограничивает допустимые uplink и шлюзы. nft сверяет
        // фактический маршрут каждого пакета и отсекает connected-сети.
        for route in baseline.routes.iter().filter(|route| {
            RouteKind::from(route.kind) == RouteKind::Unicast
                && route.nexthop_id.is_none()
                && route.destination.address.is_ipv4() == address.is_ipv4()
                && (route.destination.length == 0
                    || prefix.contains(route.destination.address)
                    || IpPrefix::new(route.destination.address, route.destination.length)
                        .is_ok_and(|routed| routed.contains(address)))
        }) {
            let gateways = route.output_interface.zip(route.gateway).into_iter().chain(
                route
                    .multipath
                    .iter()
                    .filter_map(|hop| hop.gateway.map(|gateway| (hop.output_interface, gateway))),
            );
            for (index, gateway) in gateways {
                let Some(name) = uplinks.get(&index) else {
                    continue;
                };
                let name = std::str::from_utf8(name).map_err(|_| ServiceError::Unsupported)?;
                egress.insert(
                    BoundDirect::new(prefix, index, name, worker_uid, mark, gateway)
                        .map_err(|_| ServiceError::Unsupported)?,
                );
                if egress.len() > MAX_BOUND_DIRECT {
                    return Err(ServiceError::Unsupported);
                }
            }
        }
        if egress.len() == before {
            return Err(ServiceError::Unsupported);
        }
    }
    Ok(egress.into_iter().collect())
}

fn fresh_cancel() -> (tokio::sync::watch::Sender<bool>, Cancellation) {
    Cancellation::new()
}

impl Backend {
    pub(super) async fn recover_quarantine(
        &mut self,
    ) -> Result<Option<std::time::Instant>, ServiceError> {
        let Some(journal) = self
            .journal
            .as_ref()
            .filter(|journal| journal.fake_quarantine().is_some())
        else {
            return Ok(None);
        };
        self.executor(journal.ownership())?
            .recover_fake_quarantine(self.journal.as_mut().ok_or(ServiceError::Unavailable)?)
            .await
            .map_err(unavailable)
    }

    async fn update_quarantine_timer(&mut self) {
        let observed = self.recover_quarantine().await;
        let recheck = std::time::Instant::now() + Duration::from_secs(5);
        let next = match observed {
            Ok(Some(deadline)) => Some(recheck.min(deadline + Duration::from_secs(1))),
            Ok(None) => None,
            Err(_) => Some(recheck),
        };
        self.fake_dns_reap = next.map(|deadline| {
            let notify = Arc::clone(&self.exited);
            SafetyTask(tokio::spawn(async move {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                notify.notify_one();
            }))
        });
    }

    async fn arm_session_quarantine(
        &mut self,
        artifact: &SessionArtifact,
        ifindex: u32,
    ) -> Result<std::time::Instant, ServiceError> {
        let intent = QuarantineIntent {
            tun: Some(artifact.plan.quarantine_tun(ifindex)),
            horizon_ms: session_fake_dns::HOLD_MS,
        };
        let result = self
            .executor(artifact.owner)?
            .arm_fake_quarantine(
                self.journal.as_mut().ok_or(ServiceError::Unavailable)?,
                intent,
            )
            .await;
        let deadline = diagnostic_result("fake_ip_quarantine", result).map_err(unavailable)?;
        self.fake_dns_reap = None;
        Ok(deadline)
    }
    pub(super) async fn prepare_full_profile(
        &mut self,
        uid: u32,
        request: crate::helper::profile_intent::FullProfileRequest,
        cancel: &mut Cancellation,
    ) -> Result<GuardArtifact, ServiceError> {
        use yonik_engine::native_profile::{OwnedIngress, OwnedRuntimePlan};
        request.preflight(cancel)?;
        // Exact graph/image/scope guard до listen/check/worker. Тот же sealed
        // snapshot передаётся WorkerPayload; повторная image selection запрещена.
        let (consumer_image, _consumer) =
            crate::helper::native_profile_channel::installed_consumer(
                request.intent(),
                crate::profile_channel::Mode::System,
            )?;
        cancel.check().map_err(|_| ServiceError::Cancelled)?;
        let graph = request
            .intent()
            .validate()
            .map_err(|_| ServiceError::InvalidRequest)?;
        let sources = request
            .capture_sources(cancel)
            .map_err(|_| ServiceError::Unsupported)?;
        crate::helper::native_profile_channel::validate_consumer_sources(
            request.intent(),
            &sources,
            cancel,
        )?;
        let physical = crate::helper::profile_intent::SystemPhysicalPlan::capture(
            request.intent(),
            &sources,
            cancel,
        )
        .map_err(unavailable)?;
        let installed = crate::helper::native_bootstrap::load_static_preflight(
            std::time::Instant::now() + Duration::from_secs(3),
        )
        .map_err(|_| ServiceError::Unsupported)?;
        if self.has_session() || self.worker_uncertain {
            return Err(ServiceError::Busy);
        }
        let peer = Arc::clone(request.peer()?);
        self.ensure_peer_attestation(Arc::clone(&peer), cancel)
            .await?;
        let worker_uid = worker_uid()?;
        crate::attribution::preflight(true, Some(peer.as_ref()), worker_uid)
            .await
            .map_err(|_| ServiceError::Unsupported)?;
        if worker_uid == uid {
            return Err(ServiceError::Unsupported);
        }
        let owner = self.owner(uid)?;
        let context = self.context(uid)?;
        let stamp = self.snapshot()?.stamp;
        let (baseline, baseline_capture) = read_topology_captured(cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        let bytes = topology_bytes(&baseline);
        if bytes > MAX_BASELINE_BYTES {
            return Err(ServiceError::Unavailable);
        }
        let memory = config_budget()
            .reserve(bytes * 2 + 128 * 1024)
            .map_err(unavailable)?;
        let plan =
            SessionNetworkPlan::reserve_for_engine(owner, &baseline, yonik_engine::Engine::Xray)
                .map_err(unavailable)?;
        let local = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(unavailable)?;
        let probe = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(unavailable)?;
        let local_port = NonZeroU16::new(local.local_addr().map_err(unavailable)?.port())
            .ok_or(ServiceError::Unavailable)?;
        let probe_port = NonZeroU16::new(probe.local_addr().map_err(unavailable)?.port())
            .ok_or(ServiceError::Unavailable)?;
        let mut runtime = OwnedRuntimePlan::new(local_port, probe_port)
            .map_err(unavailable)?
            .with_system(plan.compiler_tun().map_err(unavailable)?);
        for ingress in graph.ingresses() {
            runtime = runtime
                .map_ingress(ingress.tag(), OwnedIngress::System)
                .map_err(|_| ServiceError::Unsupported)?;
        }
        let (generation, selection) = request.coordinates();
        // Apply сначала проверяет exact PreparedContext, затем invalidate
        // увеличивает server epoch ровно один раз. UI generation не policy authority.
        let policy_revision = self.epoch.checked_add(1).ok_or(ServiceError::Unavailable)?;
        let prepared = Arc::new(
            request
                .prepare_system_captured(runtime, policy_revision, 1, sources, cancel)
                .map_err(|_| ServiceError::Unsupported)?,
        );
        if !prepared
            .retained()
            .matches(generation, selection, *prepared.retained().digest())
        {
            return Err(stale());
        }
        if self.registry.is_none() {
            self.registry = Some(TrustedRegistry::system().map_err(unavailable)?);
        }
        let payload = Arc::new(
            WorkerPayload::new_full_profile(consumer_image, Arc::clone(&prepared), cancel)
                .map_err(unavailable)?,
        );
        physical
            .revalidate(&prepared, cancel)
            .map_err(unavailable)?;
        let capture_cancel = cancel.clone();
        let captured = physical
            .capture_routes(
                worker_uid,
                plan.socket_mark(),
                &capture_cancel,
                async |endpoint, transport| {
                    let protocol = match transport {
                        crate::managed_network::firewall::TransportProtocol::Tcp => {
                            crate::TransportProtocol::Tcp
                        }
                        crate::managed_network::firewall::TransportProtocol::Udp => {
                            crate::TransportProtocol::Udp
                        }
                    };
                    let address = endpoint.ip();
                    let query = RouteQuery::new(address, worker_uid)
                        .with_mark(plan.socket_mark())
                        .with_transport(protocol, None, Some(endpoint.port()));
                    let (route, capture) = lookup_route_captured(query, cancel, DEADLINE)
                        .await
                        .map_err(|_| crate::helper::profile_intent::EgressError::Stale)?;
                    let index = checked_route(&route, owner, plan.routing_table())
                        .map_err(|_| crate::helper::profile_intent::EgressError::InvalidBinding)?;
                    Ok((
                        index,
                        ProfileRoute {
                            dns: false,
                            endpoint: address,
                            port: endpoint.port(),
                            protocol,
                            route,
                            capture,
                        },
                    ))
                },
            )
            .await
            .map_err(unavailable)?;
        let mut routes = captured.into_snapshots().map_err(unavailable)?;
        if routes.len() != physical.numeric().len() {
            return Err(stale());
        }
        // Только выбранный captured NETWORK step; HOSTS и implicit app-DNS
        // declaration не требуют transport exception. Ни hostname, ни resolver
        // configuration сами по себе не становятся route authority.
        let peer_count = physical.resolver_peers().len() * 2;
        if routes
            .len()
            .saturating_add(peer_count)
            .saturating_add(physical.deferred_count())
            > 128
        {
            return Err(ServiceError::Unsupported);
        }
        let mut peers = Vec::with_capacity(peer_count);
        for server in physical.resolver_peers() {
            for protocol in [crate::TransportProtocol::Tcp, crate::TransportProtocol::Udp] {
                peers.push((server.ip(), server.port(), protocol));
            }
        }
        if routes
            .len()
            .saturating_add(peers.len())
            .saturating_add(physical.deferred_count())
            > 128
        {
            return Err(ServiceError::Unsupported);
        }
        for (address, port, protocol) in peers {
            let query = RouteQuery::new(address, worker_uid)
                .with_mark(plan.socket_mark())
                .with_transport(protocol, None, Some(port));
            let (route, capture) = lookup_route_captured(query, cancel, DEADLINE)
                .await
                .map_err(unavailable)?;
            checked_route(&route, owner, plan.routing_table())?;
            routes.push(ProfileRoute {
                dns: true,
                endpoint: address,
                port,
                protocol,
                route,
                capture,
            });
        }
        prepared.revalidate(cancel).map_err(unavailable)?;
        let mut transports = Vec::with_capacity(routes.len());
        for captured in &routes {
            let index = checked_route(&captured.route, owner, plan.routing_table())?;
            transports.push(
                crate::managed_network::firewall::BoundTransport::new(
                    captured.endpoint,
                    match captured.protocol {
                        crate::TransportProtocol::Tcp => {
                            crate::managed_network::firewall::TransportProtocol::Tcp
                        }
                        crate::TransportProtocol::Udp => {
                            crate::managed_network::firewall::TransportProtocol::Udp
                        }
                    },
                    captured.port,
                    index,
                    worker_uid,
                    plan.socket_mark(),
                )
                .map_err(unavailable)?,
            );
        }
        let preflight = compile_protection(&baseline, false)?
            .with_additional_transport(&transports)
            .map_err(|_| ServiceError::Unsupported)?;
        self.executor(owner)?
            .check_public_policy(&preflight)
            .await
            .map_err(unavailable)?;
        drop((local, probe));
        self.worker_uncertain = true;
        let checked = self
            .supervisor()
            .await?
            .check(Arc::clone(&payload), cancel)
            .await;
        if checked.is_err() {
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
        let (current, capture) = read_topology_captured(cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        if self.context(uid)? != context
            || !self.snapshot()?.is_current(stamp)
            || worker_uid != self::worker_uid()?
            || !same_captured_topology(&baseline, baseline_capture, &current, capture)
        {
            return Err(stale());
        }
        peer.verify_identity()
            .map_err(|_| ServiceError::Unsupported)?;
        let artifact = SessionArtifact {
            invalid: std::sync::atomic::AtomicBool::new(false),
            installed: Some(installed),
            full_profile: Some(prepared),
            physical: Some(physical),
            routes,
            owner,
            bundle: None,
            payload,
            plan,
            baseline,
            baseline_capture,
            context,
            uid,
            worker_uid,
            kill_switch: request.kill_switch(),
            attribution_required: true,
            peer: Some(peer),
            memory,
            native_owner_stamp: Some(self.native_owner.reserve()?),
            fake_dns: None,
            resolver_tls: None,
        };
        artifact.revalidate_routes(cancel, None).await?;
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(unavailable)?;
        let bytes=serde_json::to_vec(&serde_json::json!({"version":3,"uid":uid,"stamp":stamp.to_string(),"generation":generation,"selection":selection,"nonce":nonce,"payload":artifact.payload.digest().as_bytes()})).map_err(unavailable)?;
        Ok(GuardArtifact {
            bytes,
            stamp,
            session: Some(Arc::new(artifact)),
        })
    }
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
        self.ensure_peer_attestation(
            Arc::clone(request.peer.as_ref().ok_or(ServiceError::Unsupported)?),
            cancel,
        )
        .await?;
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
            fake_dns_domains: None,
            engine: intent.engine,
            kill_switch: intent.requirements.kill_switch,
            peer: request.peer,
        };
        self.prepare_profile_inner(uid, profile, Some(bundle), cancel)
            .await
    }
    async fn ensure_peer_attestation(
        &mut self,
        peer: Arc<crate::attribution::PeerProcess>,
        cancel: &mut Cancellation,
    ) -> Result<(), ServiceError> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        // Отсутствие approved static profile закрывает путь до любого child/Check эффекта.
        let source = super::super::native_bootstrap::load_static_preflight(deadline.into_std())
            .map_err(|_| ServiceError::Unsupported)?;
        let supervisor = tokio::select! {biased;
            _=cancel.cancelled()=>return Err(ServiceError::Cancelled),
            _=tokio::time::sleep_until(deadline)=>return Err(ServiceError::Unavailable),
            result=self.supervisor()=>result?,
        };
        supervisor
            .attest_preparation(peer, source, cancel, deadline)
            .await
            .map_err(|_| ServiceError::Unsupported)
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
        if let Some(suffixes) = &request.fake_dns_domains {
            if attribution_required || bundle.is_some() {
                return Err(ServiceError::Unsupported);
            }
            if let Some(policy) = &request.policy {
                yonik_engine::validate_scoped_fake_dns_policy(policy.policy(), suffixes)
                    .map_err(|_| ServiceError::Unsupported)?;
            }
            self.fake_dns.check_cold_start()?;
        }
        if attribution_required {
            self.ensure_peer_attestation(
                Arc::clone(request.peer.as_ref().ok_or(ServiceError::Unsupported)?),
                cancel,
            )
            .await?;
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
        let fake_dns_requested = request.fake_dns_domains.is_some();
        let plan = if fake_dns_requested {
            SessionNetworkPlan::reserve_for_fake_dns(
                owner,
                &baseline,
                request.engine,
                &session_fake_dns::POOLS,
            )
        } else {
            SessionNetworkPlan::reserve_for_engine(owner, &baseline, request.engine)
        }
        .map_err(unavailable)?;
        let direct_egress = match (fake_dns_requested, &request.policy) {
            (true, Some(policy)) => {
                bound_fake_literal_direct(policy, &baseline, worker_uid, plan.socket_mark())?
            }
            _ => Vec::new(),
        };
        let fake_dns = match request.fake_dns_domains {
            Some(domains) => Some(Arc::new(
                PreparedFakeDns::new(&plan, &baseline, domains, direct_egress, cancel).await?,
            )),
            None => None,
        };
        let (plan, resolver_tls) = if let Some(fake_dns) = &fake_dns {
            ResolvedTlsEgress::prepare(fake_dns, plan, &baseline, owner, cancel).await?
        } else {
            (plan, None)
        };
        let port = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(unavailable)?
            .local_addr()
            .map_err(unavailable)?
            .port();
        let port = NonZeroU16::new(port).ok_or(ServiceError::Unavailable)?;
        let tun = plan.compiler_tun().map_err(unavailable)?;
        let config = if let Some(policy) = request.policy.as_ref() {
            let probe =
                TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(unavailable)?;
            let probe_port = NonZeroU16::new(probe.local_addr().map_err(unavailable)?.port())
                .ok_or(ServiceError::Unavailable)?;
            if let Some(fake_dns) = &fake_dns {
                yonik_engine::compile_system_fake_dns_policy(
                    &server,
                    request.engine,
                    port,
                    probe_port,
                    policy.policy(),
                    &tun,
                    &fake_dns.config,
                    fake_dns.suffixes(),
                )
                .map_err(|_| ServiceError::Unsupported)?
            } else if let Some(bundle) = &bundle {
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
                    &tun,
                )
                .map_err(|_| ServiceError::Unsupported)?
            } else {
                yonik_engine::compile_system_policy(
                    &server,
                    request.engine,
                    port,
                    probe_port,
                    policy.policy(),
                    &tun,
                )
                .map_err(|_| ServiceError::Unsupported)?
            }
        } else if let Some(fake_dns) = &fake_dns {
            yonik_engine::compile_system_fake_dns_bridge(
                &server,
                request.engine,
                port,
                &tun,
                &fake_dns.config,
            )
            .map_err(|_| ServiceError::Unsupported)?
        } else {
            yonik_engine::compile_system(&server, request.engine, port, &tun)
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
        let mut routes = vec![ProfileRoute {
            dns: false,
            endpoint,
            port: server.endpoint().port(),
            protocol,
            route,
            capture: route_capture,
        }];
        if let Some(fake_dns) = &fake_dns {
            for (peer, expected_link) in fake_dns.plain_peers() {
                for protocol in [crate::TransportProtocol::Tcp, crate::TransportProtocol::Udp] {
                    let query = RouteQuery::new(peer.ip(), 0)
                        .with_mark(plan.socket_mark())
                        .with_transport(protocol, None, Some(peer.port()));
                    let (route, capture) = lookup_route_captured(query, cancel, DEADLINE)
                        .await
                        .map_err(unavailable)?;
                    let index = checked_route(&route, owner, plan.routing_table())?;
                    if expected_link.is_some_and(|expected| expected != index)
                        || fake_dns.uses_resolve1()
                            && !session_fake_dns::usable_resolver_link(&baseline, index)
                    {
                        return Err(ServiceError::Unsupported);
                    }
                    routes.push(ProfileRoute {
                        dns: true,
                        endpoint: peer.ip(),
                        port: peer.port(),
                        protocol,
                        route,
                        capture,
                    });
                }
            }
        }
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
        let result = diagnostic_result("check_profile_worker", result);
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
            let _ = diagnostic_value::<(), _>(
                "profile_prepare_freshness_context_stamp_topology_uid",
                Err((
                    context_matches,
                    stamp_matches,
                    topology_matches,
                    uid_matches,
                )),
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
            invalid: std::sync::atomic::AtomicBool::new(false),
            installed: None,
            full_profile: None,
            physical: None,
            owner,
            routes,
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
            context,
            uid,
            worker_uid,
            kill_switch: request.kill_switch,
            attribution_required,
            peer: request.peer,
            memory,
            fake_dns,
            resolver_tls,
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
            || artifact.owner != self.owner(uid)?
            || self.context(uid)? != artifact.context
            || !self.snapshot()?.is_current(stamp)
            || artifact.worker_uid != worker_uid()?
            || !same_captured_topology(
                &artifact.baseline,
                artifact.baseline_capture,
                &current,
                current_capture,
            )
            || artifact.revalidate_routes(cancel, None).await.is_err()
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
        let private_routes = if artifact.fake_dns.is_some() {
            fake_wireguard_guards(&artifact.baseline)?
        } else {
            Vec::new()
        };
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
        let (transports, dns) = artifact.revalidate_routes(cancel, Some(index)).await?;
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
        let mut policy = PublicBlockPolicy::new(
            loopback,
            Some(index),
            private_routes,
            vec![],
            transports,
            dns,
        )
        .and_then(|policy| policy.with_link_control(controls))
        .map_err(unavailable)?;
        let mut dhcp_interface = None;
        if let Some(fake_dns) = &artifact.fake_dns {
            policy = policy
                .with_isolated_loopback(fake_dns.loopback, artifact.worker_uid)
                .and_then(|policy| policy.with_bound_direct(fake_dns.direct_egress.clone()))
                .and_then(|policy| policy.with_dhcp_renewal_anchor(true))
                .and_then(|policy| {
                    policy.with_resolver_tls(
                        artifact.resolver_tls.as_ref().map(|tls| tls.policy.clone()),
                    )
                })
                .map_err(unavailable)?;
            if self.profile_owner.is_some() {
                if let Some((indices, bound)) =
                    session_dhcp::select_policy(&artifact.baseline, &policy, cancel).await
                {
                    let mut executor = self.executor(owner)?;
                    if session_dhcp::check_policy(&mut executor, &bound).await {
                        policy = bound;
                        dhcp_interface = Some(indices);
                    }
                }
            }
        }
        cancel.check().map_err(|_| ServiceError::Cancelled)?;
        let policy_fingerprint = policy.digest();
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
            self.retain_canonical_queue(&artifact.plan, &tun, cancel)
                .await?;
            let record = self
                .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
                .await?;
            self.commit_native_owner(record)?;
            self.start_committed_native(output, cancel).await?
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
            exit_watch,
            artifact,
            ticket,
            index,
            link,
            fake_dns: None,
            dhcp_refresh: None,
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
        if let Some(fake_dns) = self
            .active
            .as_ref()
            .and_then(|active| active.artifact.fake_dns.clone())
        {
            use crate::fake_flow::WorkerOnlyLoopbackIsolation;
            let isolation = WorkerOnlyLoopbackIsolation::verified_by(|| {
                matches!(
                    self.journal.as_ref().and_then(Journal::public_policy).map(|record| record.phase()),
                    Some(PublicPolicyPhase::Stable { policy }) if policy.digest() == policy_fingerprint
                )
            }).map_err(unavailable)?;
            cancel.check().map_err(|_| ServiceError::Cancelled)?;
            let artifact = Arc::clone(
                &self
                    .active
                    .as_ref()
                    .ok_or(ServiceError::Unavailable)?
                    .artifact,
            );
            let horizon =
                PublicationHorizon::new(self.arm_session_quarantine(&artifact, index).await?);
            let active_dns = fake_dns
                .start(
                    index,
                    isolation,
                    self.fake_dns.leases()?,
                    yonik_engine::fake_dns::DnsEpoch {
                        network: self.epoch,
                        engine: self.epoch,
                        resolver: self.epoch,
                    },
                    horizon,
                    Arc::clone(&self.exited),
                )
                .await?;
            cancel.check().map_err(|_| ServiceError::Cancelled)?;
            self.active
                .as_mut()
                .ok_or(ServiceError::Unavailable)?
                .fake_dns = Some(active_dns);
        }
        if let Some((backend, runtime)) = &self.profile_owner {
            if let Some(indices) = dhcp_interface {
                self.active
                    .as_mut()
                    .ok_or(ServiceError::Unavailable)?
                    .dhcp_refresh = Some(session_dhcp::spawn_refresh(
                    backend.clone(),
                    runtime,
                    self.epoch,
                    indices,
                ));
            }
        }
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
    async fn check_external_network_facts(
        &self,
        artifact: &SessionArtifact,
        index: u32,
        link: &LinuxLink,
        dhcp_retry_policy: Option<&PublicBlockPolicy>,
        cancel: &mut Cancellation,
    ) -> Result<ExternalTopologyCheck, ServiceError> {
        let (current, current_capture) = diagnostic_result(
            "topology_read",
            // Подключение worker к TUN может изменить carrier во время dump.
            // Повторяется только чтение; baseline, generation guards и
            // последующая проверка маршрутов остаются прежними.
            crate::network::reread_changed_topology(cancel, DEADLINE).await,
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
        let dhcp = self.verified_dhcp_addresses(cancel).await;
        diagnostic_value(
            "external_verification",
            artifact.plan.verify_external_captured(
                (&artifact.baseline, artifact.baseline_capture),
                (current, current_capture),
                self.journal.as_ref().ok_or(ServiceError::Unavailable)?,
                index,
                &dhcp,
                dhcp_retry_policy,
            ),
        )
        .map_err(unavailable)
    }

    async fn verify_network_facts(
        &mut self,
        artifact: &SessionArtifact,
        index: u32,
        link: &LinuxLink,
        cancel: &mut Cancellation,
    ) -> Result<(), ServiceError> {
        let mut check = self
            .check_external_network_facts(
                artifact,
                index,
                link,
                self.dhcp_topology_retry_policy(),
                cancel,
            )
            .await?;
        if check == ExternalTopologyCheck::RetryDhcpLifetimes {
            // Снимок ядра и DHCP-ответ могли прийти по разные стороны ACK.
            // Новый снимок проходит полную проверку, повторно пробовать нельзя.
            check = tokio::time::timeout(
                DHCP_TOPOLOGY_RETRY_BUDGET,
                self.check_external_network_facts(artifact, index, link, None, cancel),
            )
            .await
            .map_err(unavailable)??;
        }
        if check != ExternalTopologyCheck::Verified {
            return Err(ServiceError::Unavailable);
        }
        diagnostic_result(
            "profile_routes",
            artifact.revalidate_routes(cancel, Some(index)).await,
        )?;
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
        let horizon = active.fake_dns.as_ref().map(|dns| dns.horizon.clone());
        if let Some(dns) = &active.fake_dns {
            diagnostic_result("fake_dns_active", dns.verify().await)?;
        }
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
        if let Some(horizon) = horizon {
            let deadline = self
                .recover_quarantine()
                .await?
                .ok_or(ServiceError::Unavailable)?;
            if !self
                .journal
                .as_ref()
                .and_then(Journal::fake_quarantine)
                .is_some_and(|record| {
                    record.is_present_for_tun(&artifact.plan.quarantine_tun(index))
                })
            {
                return Err(ServiceError::Unavailable);
            }
            horizon.constrain(deadline)?;
            if horizon.needs_refresh() {
                horizon.extend(self.arm_session_quarantine(&artifact, index).await?)?;
            }
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
        if unlock {
            if let Some(journal) = &mut self.journal {
                journal
                    .confirm_authorized_session_unlock(owner)
                    .map_err(unavailable)?;
            }
        }
        if let Some(active) = &mut self.active {
            active.fake_dns = None;
        }
        self.revoke_session_dhcp().await;
        let keep_block = !public_unlock_pending(self.journal.as_ref())
            && keep_after_stop(
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
        let result = recover_ordered(&mut recovery, has_journal, keep_block).await;
        self.update_quarantine_timer().await;
        match result {
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
fn public_unlock_pending(journal: Option<&Journal>) -> bool {
    matches!(
        journal
            .and_then(Journal::public_policy)
            .map(|record| record.phase()),
        Some(PublicPolicyPhase::Removing { .. })
    )
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
        if public_unlock_pending(self.backend.journal.as_ref()) {
            // Removing записывается только после подтверждённого teardown.
            if self.backend.journal.as_ref().is_none_or(|journal| {
                journal
                    .records()
                    .iter()
                    .any(|record| record.scope() == Scope::Session)
            }) {
                return Err(ServiceError::Unavailable);
            }
        } else {
            let (_keep, mut cancel) = fresh_cancel();
            let topology = read_topology(&mut cancel, DEADLINE)
                .await
                .map_err(unavailable)?;
            self.backend
                .policy(self.owner, compile_protection(&topology, false)?)
                .await?;
        }
        self.backend
            .supervisor
            .as_mut()
            .ok_or(ServiceError::Unavailable)?
            .confirm_profile_rules_retired()
            .map_err(unavailable)
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
        self.backend.recover_quarantine().await?;
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
                | (
                    FIRST_RESOLVER_RULE..=LAST_RESOLVER_RULE,
                    Resource::ResolverRule { tun_id: 16, .. }
                )
                | (
                    FIRST_THROW_ROUTE..=LAST_THROW_ROUTE,
                    Resource::ThrowRoute { tun_id: 16, .. }
                )
        )
    }) {
        return Err(ServiceError::Unavailable);
    }
    records.sort_by_key(|(id, resource)| {
        std::cmp::Reverse((
            matches!(
                resource,
                Resource::TunRule { .. } | Resource::ResolverRule { .. }
            ),
            *id,
        ))
    });
    let mut executor = TunExecutor::open(owner).map_err(unavailable)?;
    for (id, resource) in records {
        match resource {
            Resource::TunRule { tun_id, .. } => executor.remove_rule(journal, tun_id, id).await,
            Resource::ResolverRule { tun_id, .. } => {
                executor.remove_resolver_rule(journal, tun_id, id).await
            }
            Resource::ThrowRoute { tun_id, .. } => executor.remove_route(journal, tun_id, id).await,
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
