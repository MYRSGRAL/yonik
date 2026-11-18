//! Отдельный владелец БД и локальной SOCKS-сессии; UI получает только DTO.
use crate::diagnostics::context::{Cause, Contexts, Slot};

#[path = "backend_startup.rs"]
mod backend_startup;
#[path = "batch_diagnostics.rs"]
mod batch_diagnostics;
#[path = "desktop_schedule.rs"]
mod desktop_schedule;
#[path = "logs.rs"]
mod logs;
#[path = "presets.rs"]
mod presets;
#[path = "startup_application.rs"]
mod startup_application;
use crate::maintenance;
use backend_startup::StartupObserver;
pub use backend_startup::StartupPhase;
#[path = "maintenance_job.rs"]
mod maintenance_job;
use crate::preferences::{Preferences, SaveError, SaveOutcome, Store};
use crate::system_session::{ProfileRevision, SystemSession};
use batch_diagnostics::{BatchEvent, BatchPoll, BatchRunning, BatchState};
use desktop_schedule::DesktopSchedule;
#[path = "source_failure.rs"]
mod source_failure;
use serde::{Deserialize, Serialize};
use source_failure::{FailureContext, SourceFailure, SourceResult};
use std::{
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    num::NonZeroU16,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, watch};
use yonik_engine::Engine;
use yonik_import::{Field, IssueCode, ReviewFlag};
use yonik_linux::system_client::{ClientError, State as SystemState, SystemClient};
use yonik_linux::{
    BinarySnapshot, Cancellation, CheckedConfig, CredentialError, EncryptedSubscriptionRepository,
    FetchError, FetchRoute, HostError, LocalSession, NetworkMonitor, NetworkSnapshot, NetworkStamp,
    NetworkWatch, PendingRefresh, ProbeResult, ProbeTarget, ProfileQuery, RefreshResult,
    ResolvedProfile, SubscriptionError, SubscriptionIdentity, SubscriptionService,
    SubscriptionSource, TCP_SERIES_SAMPLES, TcpProbeSeriesResult, TcpProbeStatus, TcpProbeTarget,
    check_tcp_series,
};
use zeroize::Zeroizing;

/// Явный ephemeral key предназначен для отдельной тестовой БД; fallback отсутствует.
#[derive(Clone)]
pub struct HostConfig {
    data_dir: PathBuf,
    engine_dir: PathBuf,
    ephemeral_key: Option<Zeroizing<[u8; 32]>>,
    listen_port: Option<NonZeroU16>,
    system_subscription_policy: bool,
    startup_observer: StartupObserver,
    startup_xdg_root: Option<PathBuf>,
    start_hidden: bool,
    startup_custody: Option<yonik_linux::CredentialOwnerGuard>,
    schedule_observer: Option<Arc<dyn Fn(yonik_linux::SubscriptionPolicy, bool) + Send + Sync>>,
    #[cfg(feature = "test-support")]
    cleanup_fault: Option<Arc<AtomicBool>>,
    #[cfg(feature = "test-support")]
    lifecycle_gate: Option<yonik_linux::LifecycleGate>,
    #[cfg(feature = "test-support")]
    catalog_observer: Option<yonik_linux::applications::CatalogObserver>,
    #[cfg(feature = "test-support")]
    scheduler_capacity: Option<usize>,
    #[cfg(feature = "test-support")]
    scheduler_owner_seed: Option<u64>,
    #[cfg(feature = "test-support")]
    scheduler_interval: Option<Duration>,
    #[cfg(feature = "test-support")]
    test_subscription_fetch: Option<Arc<yonik_linux::FetchHost>>,
    #[cfg(feature = "test-support")]
    schedule_trace: Option<(
        std::sync::mpsc::SyncSender<serde_json::Value>,
        Arc<AtomicBool>,
    )>,
}
impl HostConfig {
    pub fn new(data_dir: PathBuf, engine_dir: PathBuf) -> Self {
        Self {
            data_dir,
            engine_dir,
            ephemeral_key: None,
            listen_port: None,
            system_subscription_policy: true,
            schedule_observer: None,
            startup_observer: StartupObserver::default(),
            startup_xdg_root: crate::startup_xdg::config_root(),
            start_hidden: false,
            startup_custody: None,
            #[cfg(feature = "test-support")]
            cleanup_fault: None,
            #[cfg(feature = "test-support")]
            lifecycle_gate: None,
            #[cfg(feature = "test-support")]
            catalog_observer: None,
            #[cfg(feature = "test-support")]
            scheduler_capacity: None,
            #[cfg(feature = "test-support")]
            scheduler_owner_seed: None,
            #[cfg(feature = "test-support")]
            scheduler_interval: None,
            #[cfg(feature = "test-support")]
            test_subscription_fetch: None,
            #[cfg(feature = "test-support")]
            schedule_trace: None,
        }
    }
    /// Только hint окна; не меняет preferences и не разрешает Connect.
    pub fn with_start_hidden(mut self, hidden: bool) -> Self {
        self.start_hidden = hidden;
        self
    }
    /// Только собственный fixture root; normal host использует XDG config root.
    #[cfg(feature = "test-support")]
    pub fn with_startup_fixture_config(mut self, root: PathBuf) -> Self {
        self.startup_xdg_root = Some(root);
        self
    }
    #[cfg(feature = "test-support")]
    pub fn with_lifecycle_gate(mut self, gate: yonik_linux::LifecycleGate) -> Self {
        self.lifecycle_gate = Some(gate);
        self
    }
    /// Concrete socket transport отдельного subscription fixture; не native authority.
    #[cfg(feature = "test-support")]
    pub fn with_test_subscription_fetch(mut self, fetch: Arc<yonik_linux::FetchHost>) -> Self {
        self.test_subscription_fetch = Some(fetch);
        self
    }
    /// Bounded read-only trace; overflow/disconnect запрещают acceptance fixture.
    #[cfg(feature = "test-support")]
    pub fn with_test_schedule_trace(
        mut self,
        sender: std::sync::mpsc::SyncSender<serde_json::Value>,
        overflow: Arc<AtomicBool>,
    ) -> Self {
        self.schedule_trace = Some((sender, overflow));
        self
    }
    /// Только наблюдение реального producer в отдельном test-support стенде.
    #[cfg(feature = "test-support")]
    pub fn with_catalog_observer(
        mut self,
        observer: yonik_linux::applications::CatalogObserver,
    ) -> Self {
        self.catalog_observer = Some(observer);
        self
    }
    /// Отдельный ephemeral GUI-стенд: только уменьшение capacity, без GUI/env API.
    #[cfg(feature = "test-support")]
    pub fn ephemeral_scheduler_example(
        data_dir: PathBuf,
        engine_dir: PathBuf,
        key: [u8; 32],
        capacity: usize,
    ) -> Result<Self> {
        if !(1..=20_000).contains(&capacity) {
            return Err(DesktopError("invalid_input"));
        }
        let mut config = Self::new(data_dir, engine_dir).with_ephemeral_key(key);
        config.scheduler_capacity = Some(capacity);
        Ok(config)
    }
    /// Локальный allocator отдельного ephemeral стенда; глобальный счётчик не меняется.
    #[cfg(feature = "test-support")]
    pub fn ephemeral_scheduler_owner_example(
        data_dir: PathBuf,
        engine_dir: PathBuf,
        key: [u8; 32],
        seed: u64,
    ) -> Result<Self> {
        if seed == 0 {
            return Err(DesktopError("invalid_input"));
        }
        let mut config = Self::new(data_dir, engine_dir).with_ephemeral_key(key);
        config.scheduler_owner_seed = Some(seed);
        Ok(config)
    }
    /// Только вход validator отдельного ephemeral example; diagnostic state не задаётся.
    #[cfg(feature = "test-support")]
    pub fn ephemeral_scheduler_interval_example(
        data_dir: PathBuf,
        engine_dir: PathBuf,
        key: [u8; 32],
        interval: Duration,
    ) -> Self {
        let mut config = Self::new(data_dir, engine_dir).with_ephemeral_key(key);
        config.scheduler_interval = Some(interval);
        config
    }
    /// Доверенный наблюдатель фаз без пользовательских данных; callback не должен блокировать.
    #[cfg(feature = "startup-diagnostics")]
    pub fn with_startup_observer(
        mut self,
        observer: impl Fn(StartupPhase) + Send + Sync + 'static,
    ) -> Self {
        self.startup_observer = StartupObserver::new(observer);
        self
    }
    /// Только доверенный отрицательный Rust-стенд с отдельной ephemeral БД.
    #[cfg(feature = "test-support")]
    pub fn with_cleanup_fault(mut self, fault: Arc<AtomicBool>) -> Result<Self> {
        if self.ephemeral_key.is_none() {
            return Err(DesktopError("invalid_input"));
        }
        self.cleanup_fault = Some(fault);
        Ok(self)
    }
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
    pub fn engine_dir(&self) -> &Path {
        &self.engine_dir
    }
    pub fn with_ephemeral_key(mut self, key: [u8; 32]) -> Self {
        self.ephemeral_key = Some(Zeroizing::new(key));
        self.system_subscription_policy = false;
        self
    }
    /// Доверенная настройка platform provider; после ephemeral key требуется
    /// явное включение. GUI JSON не имеет доступа к этой настройке.
    pub fn with_system_subscription_policy(mut self, enabled: bool) -> Self {
        self.system_subscription_policy = enabled;
        self
    }
    /// Read-only наблюдение effective policy после загрузки schedule, вне GUI JSON.
    pub fn with_schedule_observer(
        mut self,
        observer: impl Fn(yonik_linux::SubscriptionPolicy, bool) + Send + Sync + 'static,
    ) -> Self {
        self.schedule_observer = Some(Arc::new(observer));
        self
    }
    pub fn with_listen_port(mut self, port: NonZeroU16) -> Self {
        self.listen_port = Some(port);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopError(&'static str);
impl DesktopError {
    pub fn key(self) -> &'static str {
        self.0
    }
}
impl fmt::Display for DesktopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for DesktopError {}

type Result<T> = std::result::Result<T, DesktopError>;
type Callback = Arc<dyn Fn(String) + Send + Sync>;
pub(crate) const DEFAULT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    PresetValidate {
        request_id: u64,
        expected_revision: i64,
    },
    PresetUpdate {
        metadata: yonik_linux::presets::Metadata,
        route: Route,
        local_exception: bool,
        request_id: u64,
    },
    PresetCancel {
        request_id: u64,
    },
    PresetActivate {
        enabled: bool,
        expected_revision: i64,
        request_id: u64,
    },
    PresetStatus,
    PresetRollback {
        #[serde(default)]
        request_id: u64,
    },
    PresetPrepare {
        target: String,
        #[serde(default)]
        request_id: u64,
    },
    MaintenanceStart {
        request_id: u64,
        operation: maintenance::Operation,
        source: Option<PathBuf>,
        destination: PathBuf,
        revision: i64,
    },
    MaintenanceCancel {
        request_id: u64,
    },
    #[cfg(feature = "test-support")]
    #[serde(skip)]
    LogsTest {
        reply: std::sync::mpsc::Sender<Option<yonik_linux::event_log::EventLog>>,
    },
    LogsSave {
        page_request_id: String,
        destination: String,
        request_id: String,
    },
    LogsRead {
        after: String,
        source: logs::Source,
        request_id: String,
    },
    RoutingApply {
        expected_revision: i64,
        request_id: u64,
        source_generation: i64,
        snapshot_revision: i64,
        selected_profile_id: i64,
    },
    RoutingExplain {
        expected_revision: i64,
        request_id: u64,
        target: String,
    },
    RoutingCatalog {
        #[serde(default)]
        request_id: u64,
        processes: bool,
        query: String,
        offset: usize,
    },
    EditRouting {
        expected_revision: i64,
        request_id: u64,
        create: bool,
        rule: crate::editor::RuleInput,
        confirm_broad: bool,
    },
    RoutingOrder {
        expected_revision: i64,
        request_id: u64,
        ids: Vec<u64>,
    },
    RoutingDefault {
        expected_revision: i64,
        request_id: u64,
        action: String,
    },
    RoutingDelete {
        expected_revision: i64,
        request_id: u64,
        id: u64,
    },
    SubscriptionVisibility {
        visible: bool,
    },
    Reload,
    AddSource {
        name: String,
        url: String,
        local_exception: bool,
        route: Route,
        #[serde(default)]
        hwid_enabled: bool,
    },
    ImportText {
        name: String,
        text: String,
    },
    ImportFile {
        name: String,
        path: String,
    },
    CancelLocalImport,
    ImportSource {
        name: String,
        url: String,
        local_exception: bool,
        route: Route,
        #[serde(default)]
        hwid_enabled: bool,
    },
    SourceChange {
        request_id: u64,
        id: i64,
        expected_generation: i64,
        name: String,
        url: String,
        local_exception: bool,
        route: Route,
        #[serde(default)]
        hwid_enabled: bool,
    },
    RenameSource {
        id: i64,
        name: String,
    },
    DeleteSource {
        id: i64,
    },
    CancelRefresh {
        id: i64,
        #[serde(default)]
        token: String,
    },
    SetSourceHwid {
        enabled: bool,
    },
    SelectSource {
        id: i64,
    },
    SourcePage {
        offset: usize,
    },
    Refresh,
    ApproveRefresh,
    DiscardRefresh,
    ReviewPage {
        offset: usize,
    },
    Query {
        search: String,
        favorites_only: bool,
        offset: usize,
    },
    Favorite {
        id: i64,
        value: bool,
    },
    SelectProfile {
        id: i64,
        revision: i64,
    },
    SelectCatalog {
        kind: CatalogKind,
        id: i64,
        page: u64,
    },
    CatalogFavorite {
        kind: CatalogKind,
        id: i64,
        page: u64,
        value: bool,
    },
    StartupPreferencesSet {
        request_id: String,
        expected_revision: String,
        autostart_into_tray: bool,
        autoconnect: bool,
    },
    AutoconnectTargetSet {
        request_id: String,
        expected_revision: String,
    },
    SetSubscriptionSchedule {
        interval_seconds: u32,
        background: bool,
    },
    SetLanguage {
        language: String,
    },
    ResetListenPort,
    SetEngine {
        engine: EngineChoice,
    },
    SetListenPort {
        port: NonZeroU16,
    },
    SetProbeTarget {
        url: String,
        expected_status: u16,
    },
    ResetProbeTarget,
    SetProxyFetchDns {
        upstream: String,
    },
    SetSystemFakeDns {
        suffixes: String,
    },
    CheckTcp,
    CheckBatch,
    CancelBatch,
    BatchPage {
        offset: usize,
    },
    CancelTcp,
    SetConnectionMode {
        mode: ConnectionMode,
    },
    SystemState,
    SystemUnlock,
    Connect,
    Stop,
    Shutdown,
}
impl Command {
    fn requires_server_selection(&self) -> bool {
        matches!(
            self,
            Self::Connect
                | Self::RoutingApply { .. }
                | Self::CheckTcp
                | Self::AutoconnectTargetSet { .. }
                | Self::StartupPreferencesSet { .. }
        )
    }
    fn preset_request_id(&self) -> Option<u64> {
        match self {
            Self::PresetPrepare { request_id, .. }
            | Self::PresetCancel { request_id }
            | Self::PresetRollback { request_id }
            | Self::PresetUpdate { request_id, .. }
            | Self::PresetValidate { request_id, .. }
            | Self::PresetActivate { request_id, .. } => Some(*request_id),
            _ => None,
        }
    }
    fn routing_request_id(&self) -> Option<u64> {
        match self {
            Self::RoutingApply { request_id, .. }
            | Self::RoutingExplain { request_id, .. }
            | Self::EditRouting { request_id, .. }
            | Self::RoutingOrder { request_id, .. }
            | Self::RoutingDefault { request_id, .. }
            | Self::RoutingDelete { request_id, .. } => Some(*request_id),
            _ => None,
        }
    }
    fn cancels_policy_connect(&self) -> bool {
        matches!(
            self,
            Self::EditRouting { .. }
                | Self::RoutingOrder { .. }
                | Self::RoutingDefault { .. }
                | Self::RoutingDelete { .. }
                | Self::SelectProfile { .. }
                | Self::SelectCatalog { .. }
                | Self::CatalogFavorite { .. }
                | Self::SelectSource { .. }
                | Self::Refresh
                | Self::Reload
                | Self::ApproveRefresh
                | Self::SetSourceHwid { .. }
                | Self::DeleteSource { .. }
                | Self::SourceChange { .. }
                | Self::PresetActivate { .. }
                | Self::PresetRollback { .. }
        )
    }
    fn is_source_operation(&self) -> bool {
        matches!(
            self,
            Self::Reload
                | Self::AddSource { .. }
                | Self::ImportText { .. }
                | Self::ImportFile { .. }
                | Self::CancelLocalImport
                | Self::ImportSource { .. }
                | Self::SourceChange { .. }
                | Self::RenameSource { .. }
                | Self::DeleteSource { .. }
                | Self::CancelRefresh { .. }
                | Self::SetSourceHwid { .. }
                | Self::SelectSource { .. }
                | Self::SourcePage { .. }
                | Self::Refresh
                | Self::ApproveRefresh
                | Self::DiscardRefresh
                | Self::ReviewPage { .. }
                | Self::Query { .. }
                | Self::Favorite { .. }
                | Self::SelectProfile { .. }
                | Self::SelectCatalog { .. }
                | Self::CatalogFavorite { .. }
        )
    }
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum CatalogKind {
    Server,
    Xray,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Route {
    Direct,
    Proxy,
}
#[derive(Clone, Copy, Deserialize, Serialize)]
enum EngineChoice {
    #[serde(rename = "xray")]
    Xray,
    #[serde(rename = "sing-box")]
    SingBox,
}
impl EngineChoice {
    fn ensure_available(self) -> Result<()> {
        ensure_engine_available(self.engine())
    }
    fn engine(self) -> Engine {
        match self {
            Self::Xray => Engine::Xray,
            Self::SingBox => Engine::SingBox,
        }
    }
}

pub(crate) fn ensure_engine_available(engine: Engine) -> Result<()> {
    crate::system_session::ensure_engine_available(engine)
        .map_err(|_| DesktopError("engine_unavailable"))
}

#[cfg(test)]
mod engine_availability_tests {
    use super::*;

    #[test]
    fn старое_ядро_читается_но_не_запускается() {
        let old: EngineChoice = serde_json::from_str("\"sing-box\"").expect("старые настройки");
        assert_eq!(serde_json::to_string(&old).expect("снимок"), "\"sing-box\"");
        assert_eq!(
            old.ensure_available().expect_err("недоступно").0,
            "engine_unavailable"
        );
        assert!(EngineChoice::Xray.ensure_available().is_ok());
    }

    #[test]
    fn sing_box_available_only_for_system_fake_dns_on_a_server_profile() {
        let mut snapshot = Snapshot::new(true);
        snapshot.selected_kind = Some("server");
        snapshot.connection_mode = ConnectionMode::System;
        assert!(
            snapshot
                .ensure_connection_engine(EngineChoice::SingBox)
                .is_err()
        );
        snapshot.system_fake_dns.push("example.test".into());
        assert!(
            snapshot
                .ensure_connection_engine(EngineChoice::SingBox)
                .is_ok()
        );
        snapshot.connection_mode = ConnectionMode::Local;
        assert!(
            snapshot
                .ensure_connection_engine(EngineChoice::SingBox)
                .is_err()
        );
        snapshot.connection_mode = ConnectionMode::System;
        snapshot.selected_kind = Some("xray");
        assert!(
            snapshot
                .ensure_connection_engine(EngineChoice::SingBox)
                .is_err()
        );
    }

    #[test]
    fn оба_connect_и_autoconnect_проходят_общий_запрет() {
        let source = include_str!("backend.rs");
        let dispatch = source
            .rsplit("let outcome: SourceResult<()> = match envelope.command {")
            .next()
            .expect("dispatch");
        let guard = dispatch.find("Command::Connect | Command::RoutingApply { .. } if actor.state.ensure_connection_engine(actor.state.engine).is_err()").expect("общий запрет");
        let system = dispatch.find("command @ (Command::Connect | Command::RoutingApply { .. }) if actor.state.connection_mode == ConnectionMode::System").expect("System Connect");
        let local = dispatch
            .find("Command::Connect => {")
            .expect("Local Connect");
        assert!(guard < system && guard < local);
        let startup = include_str!("startup_application.rs");
        assert!(startup.contains("command: Command::Connect"));
        assert!(!startup.contains("Operation::PolicyConnect"));
        assert!(!startup.contains("yonik_engine::compile"));
        let system = include_str!("system_session.rs");
        for method in ["pub async fn prepare(", "pub async fn prepare_policy("] {
            let body = system.split(method).nth(1).expect("prepare API");
            assert!(
                body.find("ensure_engine_available(engine)")
                    .expect("запрет")
                    < body
                        .find("self.fence(revision)?")
                        .expect("до изменения prepared")
            );
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum ConnectionMode {
    Local,
    System,
}

struct Envelope {
    generation: u64,
    tcp_generation: u64,
    command: Command,
}
#[derive(Clone, Copy, Default)]
struct Priority {
    generation: u64,
    shutdown: bool,
}
struct Control {
    generation: AtomicU64,
    priority: watch::Sender<Priority>,
    tcp_priority: watch::Sender<u64>,
    subscription_policy: watch::Sender<yonik_linux::SubscriptionPolicy>,
    subscription_override: AtomicBool,
    subscription_visible: watch::Sender<bool>,
    closed: (Mutex<bool>, Condvar),
}
impl Control {
    fn cancel_tcp(&self) {
        // Тот же lock watch сериализует cancel и generation для queued TCP requests.
        self.tcp_priority
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
    fn interrupt(&self, shutdown: bool) {
        // send_modify сериализует Stop/Shutdown, shutdown остаётся sticky.
        self.priority.send_modify(|state| {
            state.generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
            state.shutdown |= shutdown;
        });
    }
    fn closed(&self) {
        let (lock, condition) = &self.closed;
        if let Ok(mut closed) = lock.lock() {
            *closed = true;
            condition.notify_all();
        }
    }
}

pub struct DesktopHost {
    commands: mpsc::Sender<Envelope>,
    control: Arc<Control>,
}
#[cfg(any(test, feature = "test-support"))]
struct DiskTestInput {
    sink: (
        yonik_linux::event_log::EventLog,
        yonik_linux::event_log::DiskLogGuard,
    ),
    #[cfg(test)]
    proxy: Option<ProxyLeaseFixture>,
}
#[cfg(test)]
#[derive(Clone)]
struct ProxyLeaseFixture {
    endpoint: SocketAddr,
    observer: std::sync::mpsc::Sender<(watch::Receiver<ProxyLease>, Arc<DesktopFetch>)>,
}
impl DesktopHost {
    pub fn start(
        config: HostConfig,
        callback: impl Fn(String) + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::start_inner(
            config,
            callback,
            #[cfg(any(test, feature = "test-support"))]
            None,
        )
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_start_with_disk(
        config: HostConfig,
        fixture: &mut yonik_linux::event_log::DiskFixture,
        callback: impl Fn(String) + Send + Sync + 'static,
    ) -> Result<Self> {
        if config.data_dir != fixture.path() {
            return Err(DesktopError("invalid_input"));
        }
        let sink = fixture.take_sink().ok_or(DesktopError("invalid_input"))?;
        Self::start_inner(
            config,
            callback,
            Some(DiskTestInput {
                sink,
                #[cfg(test)]
                proxy: None,
            }),
        )
    }
    fn start_inner(
        config: HostConfig,
        callback: impl Fn(String) + Send + Sync + 'static,
        #[cfg(any(test, feature = "test-support"))] disk_fixture: Option<DiskTestInput>,
    ) -> Result<Self> {
        let (commands, receiver) = mpsc::channel(128);
        let (priority, priority_rx) = watch::channel(Priority::default());
        let (tcp_priority, _) = watch::channel(0);
        let control = Arc::new(Control {
            generation: AtomicU64::new(0),
            priority,
            tcp_priority,
            subscription_policy: watch::channel(Default::default()).0,
            subscription_override: std::sync::atomic::AtomicBool::new(false),
            subscription_visible: watch::channel(false).0,
            closed: (Mutex::new(false), Condvar::new()),
        });
        let worker_control = control.clone();
        let callback: Callback = Arc::new(callback);
        let startup_observer = config.startup_observer.clone();
        let startup_callback = Arc::clone(&callback);
        let thread = std::thread::Builder::new()
            .name("yonik-backend".into())
            .spawn(move || {
                config.startup_observer.emit(StartupPhase::RuntimeBuild);
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(run(
                        config,
                        receiver,
                        priority_rx,
                        worker_control,
                        callback,
                        #[cfg(any(test, feature = "test-support"))]
                        disk_fixture,
                    )),
                    Err(_) => {
                        let mut snapshot = Snapshot::new(config.ephemeral_key.is_some());
                        snapshot.port = config.listen_port.map_or(0, NonZeroU16::get);
                        snapshot
                            .contextual_error(false, ContextFailure::new(Cause::RuntimePanicked));
                        snapshot.closed = true;
                        snapshot.emit(&callback);
                        worker_control.closed();
                    }
                }
            });
        startup_observer.finish_thread_start(thread, &startup_callback)?;
        Ok(Self { commands, control })
    }
    /// Доверенный platform provider. Unknown/default запрещает автоматические загрузки.
    pub fn set_subscription_policy(&self, policy: yonik_linux::SubscriptionPolicy) -> Result<()> {
        self.control
            .subscription_override
            .store(true, Ordering::Release);
        self.control.subscription_policy.send_replace(policy);
        Ok(())
    }
    #[cfg(feature = "test-support")]
    pub fn test_event_log(
        &self,
        reply: std::sync::mpsc::Sender<Option<yonik_linux::event_log::EventLog>>,
    ) -> Result<()> {
        self.commands
            .try_send(Envelope {
                command: Command::LogsTest { reply },
                generation: self.control.generation.load(Ordering::SeqCst),
                tcp_generation: *self.control.tcp_priority.borrow(),
            })
            .map_err(|_| DesktopError("busy"))
    }
    pub fn dispatch(&self, request: &str) -> Result<()> {
        if request.len() > 6 * yonik_import::MAX_INPUT_BYTES + 4096 {
            return Err(DesktopError("invalid_input"));
        }
        if request.len() > 16 * 1024 {
            #[derive(Deserialize)]
            struct Header<'a> {
                command: &'a str,
            }
            let header: Header<'_> =
                serde_json::from_str(request).map_err(|_| DesktopError("invalid_input"))?;
            if header.command != "import_text" {
                return Err(DesktopError("invalid_input"));
            }
        }
        let command: Command =
            serde_json::from_str(request).map_err(|_| DesktopError("invalid_input"))?;
        if matches!(
            command,
            Command::Reload
                | Command::CancelLocalImport
                | Command::Refresh
                | Command::ApproveRefresh
                | Command::DiscardRefresh
                | Command::SystemState
                | Command::SystemUnlock
                | Command::Connect
                | Command::Stop
                | Command::Shutdown
                | Command::ResetProbeTarget
                | Command::ResetListenPort
                | Command::CheckTcp
                | Command::CheckBatch
                | Command::CancelBatch
                | Command::CancelTcp
        ) {
            let object: serde_json::Value =
                serde_json::from_str(request).map_err(|_| DesktopError("invalid_input"))?;
            if object.as_object().is_none_or(|object| object.len() != 1) {
                return Err(DesktopError("invalid_input"));
            }
        }
        validate(&command)?;
        match command {
            Command::SubscriptionVisibility { visible } => {
                self.control.subscription_visible.send_replace(visible);
                Ok(())
            }
            Command::Shutdown => {
                self.shutdown();
                Ok(())
            }
            Command::Stop => {
                self.control.interrupt(false);
                Ok(())
            }
            Command::CancelTcp | Command::CancelBatch => {
                self.control.cancel_tcp();
                Ok(())
            }
            command => self
                .commands
                .try_send(Envelope {
                    generation: self.control.generation.load(Ordering::SeqCst),
                    tcp_generation: *self.control.tcp_priority.borrow(),
                    command,
                })
                .map_err(|_| DesktopError("busy")),
        }
    }
    pub fn shutdown(&self) {
        self.control.interrupt(true);
    }
    /// Только для тестов/не-UI fallback. Qt ожидает snapshot.closed асинхронно.
    pub fn wait_closed(&self, timeout: Duration) -> bool {
        let (lock, condition) = &self.control.closed;
        let Ok(guard) = lock.lock() else {
            return false;
        };
        condition
            .wait_timeout_while(guard, timeout, |closed| !*closed)
            .is_ok_and(|(closed, _)| *closed)
    }
}
impl Drop for DesktopHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn validate(command: &Command) -> Result<()> {
    if command
        .preset_request_id()
        .is_some_and(|request_id| request_id > 9_007_199_254_740_991)
    {
        return Err(DesktopError("invalid_input"));
    }
    let text = |s: &str, max| s.len() <= max && !s.chars().any(char::is_control);
    let valid = match command {
        Command::MaintenanceStart {
            request_id,
            operation,
            source,
            destination,
            revision,
        } => {
            let path = |value: &Path| {
                value.is_absolute() && value.to_str().is_some_and(|value| text(value, 4096))
            };
            *request_id > 0
                && *request_id <= 9_007_199_254_740_991
                && *revision >= 0
                && path(destination)
                && match (operation, source) {
                    (maintenance::Operation::Backup, None) => true,
                    (maintenance::Operation::Restore, Some(source)) => path(source),
                    _ => false,
                }
        }
        Command::PresetUpdate { request_id, .. }
        | Command::PresetActivate { request_id, .. }
        | Command::PresetValidate { request_id, .. }
        | Command::PresetCancel { request_id }
        | Command::MaintenanceCancel { request_id } => {
            *request_id > 0 && *request_id <= 9_007_199_254_740_991
        }
        Command::ImportText { name, text: input } => {
            !name.trim().is_empty()
                && text(name, 512)
                && !input.is_empty()
                && input.len() <= yonik_import::MAX_INPUT_BYTES
        }
        Command::ImportFile { name, path } => {
            !name.trim().is_empty() && text(name, 512) && !path.is_empty() && text(path, 4096)
        }
        Command::AddSource { name, url, .. } | Command::ImportSource { name, url, .. } => {
            !name.trim().is_empty() && text(name, 512) && text(url, 8192)
        }
        Command::SourceChange {
            request_id,
            id,
            expected_generation,
            name,
            url,
            ..
        } => {
            *request_id > 0
                && *request_id <= 9_007_199_254_740_991
                && *id > 0
                && *expected_generation > 0
                && !name.trim().is_empty()
                && text(name, 512)
                && text(url, 8192)
        }
        Command::RenameSource { id, name } => *id > 0 && !name.trim().is_empty() && text(name, 512),
        Command::LogsSave {
            page_request_id,
            destination,
            request_id,
        } => {
            logs::valid_number(page_request_id)
                && logs::valid_number(request_id)
                && text(destination, 4096)
        }
        Command::LogsRead {
            after, request_id, ..
        } => logs::valid_number(after) && logs::valid_number(request_id),
        Command::Query { search, offset, .. } => text(search, 512) && *offset <= 40_000,
        Command::BatchPage { offset } => *offset <= 10_000,
        Command::SourcePage { offset } => *offset <= 40_000,
        Command::ReviewPage { offset } => *offset <= 160_000,
        Command::SetProbeTarget { url, .. } => text(url, 2048),
        Command::SetProxyFetchDns { upstream } => text(upstream, 128),
        Command::SetSystemFakeDns { suffixes } => text(suffixes, 1024),
        Command::SelectSource { id }
        | Command::Favorite { id, .. }
        | Command::DeleteSource { id }
        | Command::CancelRefresh { id, .. } => *id > 0,
        Command::SelectProfile { id, revision } => *id > 0 && *revision > 0,
        Command::SelectCatalog { id, page, .. } | Command::CatalogFavorite { id, page, .. } => {
            *id > 0 && *page > 0 && *page <= 9_007_199_254_740_991
        }
        Command::StartupPreferencesSet {
            request_id,
            expected_revision,
            ..
        }
        | Command::AutoconnectTargetSet {
            request_id,
            expected_revision,
        } => {
            startup_application::number(request_id).is_some_and(|id| id > 0)
                && startup_application::number(expected_revision).is_some()
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(DesktopError("invalid_input"))
    }
}

#[derive(Serialize)]
struct SourceDto {
    id: i64,
    name: String,
    hwid_enabled: bool,
}
#[derive(Serialize)]
struct ProfileDto {
    id: i64,
    name: String,
    kind: &'static str,
    host: Option<String>,
    port: Option<u16>,
    protocol: String,
    favorite: bool,
    available: bool,
    selectable: bool,
}
fn catalog_profile_dto(profile: yonik_linux::CatalogProfile) -> ProfileDto {
    use yonik_linux::CatalogProfile;
    match profile {
        CatalogProfile::Server(profile) => ProfileDto {
            id: profile.id,
            name: profile.name,
            kind: "server",
            host: Some(profile.host),
            port: Some(profile.port),
            protocol: profile.protocol,
            favorite: profile.favorite,
            available: profile.available,
            selectable: profile.available,
        },
        CatalogProfile::Xray(profile) => ProfileDto {
            id: profile.id,
            name: profile.name,
            kind: "xray",
            host: None,
            port: None,
            protocol: "xray".into(),
            favorite: profile.favorite,
            available: profile.available,
            // Выбор DATA не разрешает запуск native consumer.
            selectable: profile.available,
        },
    }
}
#[derive(Serialize)]
struct PendingDto {
    accepted: usize,
    rejected: usize,
    flagged: usize,
    native_json: bool,
    rows: Vec<ReviewRow>,
    rows_total: usize,
    rows_offset: usize,
}
#[derive(Serialize)]
struct ReviewRow {
    kind: &'static str,
    position: usize,
    code: &'static str,
    field: Option<&'static str>,
}

fn pending_dto(pending: &PendingRefresh, offset: usize) -> Result<PendingDto> {
    report_dto(pending.report(), offset)
}
fn report_dto(report: &yonik_import::ProfileImportReport, offset: usize) -> Result<PendingDto> {
    let servers = || {
        report
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| match entry {
                yonik_import::ProfileEntry::Server(server) => Some((index, server)),
                yonik_import::ProfileEntry::Xray(_) => None,
            })
    };
    let total = report.issues.len()
        + servers()
            .map(|(_, server)| server.review_flags().len())
            .sum::<usize>();
    if offset > total {
        return Err(DesktopError("invalid_input"));
    }
    // Только закрытые enum-коды и позиции: ни URI, ни пользовательские параметры.
    let issues = report.issues.iter().map(|issue| ReviewRow {
        kind: "rejected",
        position: issue.line,
        code: match issue.code {
            IssueCode::MalformedUri => "malformed_uri",
            IssueCode::UnsupportedProtocol => "unsupported_protocol",
            IssueCode::InvalidPort => "invalid_port",
            IssueCode::InvalidHost => "invalid_host",
            IssueCode::InvalidCredentials => "invalid_credentials",
            IssueCode::InvalidEncoding => "invalid_encoding",
            IssueCode::InvalidJson => "invalid_json",
            IssueCode::TooLarge => "too_large",
            IssueCode::DuplicateParameter => "duplicate_parameter",
            IssueCode::ConflictingParameter => "conflicting_parameter",
        },
        field: Some(match issue.field {
            Field::Source => "source",
            Field::Endpoint => "endpoint",
            Field::Credentials => "credentials",
            Field::Parameters => "parameters",
            Field::Payload => "payload",
        }),
    });
    let flags = servers().flat_map(|(index, server)| {
        server.review_flags().iter().map(move |flag| ReviewRow {
            kind: "flagged",
            // Это номер принятого профиля в отчёте, а не строка исходного URI.
            position: index + 1,
            code: match flag {
                ReviewFlag::UnknownParameter => "unknown_parameter",
                ReviewFlag::UnsupportedTransport => "unsupported_transport",
                ReviewFlag::UnsupportedSecurity => "unsupported_security",
                ReviewFlag::UnsupportedCipher => "unsupported_cipher",
                ReviewFlag::UnsupportedOption => "unsupported_option",
                ReviewFlag::UnsafeOption => "unsafe_option",
                ReviewFlag::LegacyOption => "legacy_option",
            },
            field: None,
        })
    });
    Ok(PendingDto {
        accepted: report.entries.len(),
        rejected: report.issues.len(),
        flagged: servers()
            .filter(|(_, server)| !server.review_flags().is_empty())
            .count(),
        native_json: report
            .entries
            .iter()
            .any(|entry| matches!(entry, yonik_import::ProfileEntry::Xray(_))),
        rows: issues.chain(flags).skip(offset).take(100).collect(),
        rows_total: total,
        rows_offset: offset,
    })
}
#[derive(Serialize)]
struct SourceChangeAck {
    request_id: u64,
    id: i64,
    generation: Option<i64>,
    error: Option<&'static str>,
}

// Только DATA affordance: installed image/owner/source authority остаётся prepare.
fn native_subset_plannable(entry: &yonik_import::ProfileEntry, mode: ConnectionMode) -> bool {
    let yonik_import::ProfileEntry::Xray(profile) = entry else {
        return false;
    };
    let Ok(intent) = yonik_engine::native_profile::ProfileIntent::from_profile(profile) else {
        return false;
    };
    let mode = match mode {
        ConnectionMode::Local => yonik_linux::FullProfileMode::Local,
        ConnectionMode::System => yonik_linux::FullProfileMode::System,
    };
    yonik_linux::full_profile_plan_preflight(mode, &intent).is_ok()
}

#[cfg(test)]
mod full_profile_review_tests {
    #[test]
    fn native_subset_data_affordance_is_not_generic_codec_availability() {
        let raw = br#"[{"remarks":"fixture","outbounds":[{"tag":"b","protocol":"vless","settings":{"vnext":[{"address":"physical.invalid","port":8443,"users":[{"id":"00000000-0000-0000-0000-000000000001","encryption":"none"}]}]}}]}]"#;
        let report = yonik_import::import_profiles(raw.to_vec()).unwrap();
        assert!(super::native_subset_plannable(
            &report.entries[0],
            super::ConnectionMode::Local
        ));
        assert!(super::native_subset_plannable(
            &report.entries[0],
            super::ConnectionMode::System
        ));
        let report = yonik_import::import_profiles(
            include_bytes!("../../../tests/fixtures/xray-full-profile-seven.json").to_vec(),
        )
        .unwrap();
        for entry in report.entries {
            for mode in [super::ConnectionMode::Local, super::ConnectionMode::System] {
                assert!(!super::native_subset_plannable(&entry, mode));
            }
        }
    }
    #[test]
    fn native_catalog_row_preserves_name_and_has_no_fake_endpoint_or_selection() {
        let row = super::catalog_profile_dto(yonik_linux::CatalogProfile::Xray(
            yonik_linux::NativeSummary {
                id: 1,
                source_id: 2,
                ordinal: 0,
                name: "Auto <private>".into(),
                favorite: true,
                available: true,
                requires_reselection: false,
            },
        ));
        let json = serde_json::to_value(&row).expect("JSON row");
        assert_eq!(json["name"], "Auto <private>");
        assert_eq!(json["kind"], "xray");
        assert_eq!(json["protocol"], "xray");
        assert!(json["host"].is_null());
        assert!(json["port"].is_null());
        assert!(row.available);
        assert!(row.favorite);
        assert!(row.selectable);
    }

    #[test]
    fn review_counts_full_roots_without_emitting_sensitive_config() {
        let report = yonik_import::import_profiles(
            include_bytes!("../../../tests/fixtures/xray-full-profile-seven.json").to_vec(),
        )
        .expect("семь полных профилей");
        let dto = super::report_dto(&report, 0).expect("review DTO");
        assert_eq!(dto.accepted, 7);
        assert_eq!(dto.rejected, 0);
        assert!(dto.native_json);
        assert!(dto.rows.is_empty());
        assert_eq!(dto.rows_total, 0);
        assert!(super::report_dto(&report, 1).is_err());
        let json = serde_json::to_string(&dto).expect("JSON DTO");
        assert!(!json.contains("outbounds"));
        assert!(!json.contains("routing"));
    }
}
#[derive(Serialize)]
struct RoutingAck {
    request_id: u64,
    saved_id: Option<u64>,
    error: Option<&'static str>,
}
enum RoutingMutation {
    Put {
        rule: crate::editor::RuleInput,
        confirm_broad: bool,
        create: bool,
    },
    Order(Vec<u64>),
    Delete(u64),
    Default(String),
}
#[derive(Serialize)]
struct Snapshot {
    startup: startup_application::View,
    presets: presets::Status,
    maintenance_available: bool,
    maintenance_ack: Option<maintenance::Ack>,
    #[serde(skip)]
    error_contexts: Contexts,
    error_generation: u64,
    helper_generation: Option<u64>,
    scheduler_generation: Option<u64>,
    routing_generation: u64,
    maintenance_generation: u64,
    logs_generation: u64,
    command_generation: u64,
    logs_channel: Option<Slot>,
    logs: logs::Page,
    routing_revision: Option<i64>,
    routing_ack: Option<RoutingAck>,
    source_change_ack: Option<SourceChangeAck>,
    routing_catalog: serde_json::Value,
    routing_diagnostics: serde_json::Value,
    routing_explanation: serde_json::Value,
    routing: crate::editor::Draft,
    language: String,
    subscription_interval_seconds: u32,
    subscription_background: bool,
    preferences_warning: bool,
    preferences_durability_warning: bool,
    build_id: &'static str,
    source_hwid_enabled: bool,
    source_local: bool,
    source_generation: Option<i64>,
    ready: bool,
    busy: bool,
    error: Option<&'static str>,
    source_error: Option<&'static str>,
    connection_error: Option<&'static str>,
    pending: Option<PendingDto>,
    sources: Vec<SourceDto>,
    sources_total: usize,
    sources_offset: usize,
    source_id: Option<i64>,
    source_name: Option<String>,
    refresh_source_id: Option<i64>,
    refresh_token: Option<String>,
    profiles: Vec<ProfileDto>,
    total: usize,
    offset: usize,
    revision: i64,
    connection_mode: ConnectionMode,
    system_state: &'static str,
    can_unlock: bool,
    system_recovery_pending: bool,
    system_busy: bool,
    system_tun_available: bool,
    status: &'static str,
    selected_profile: Option<i64>,
    selected_kind: Option<&'static str>,
    selected_catalog_page: Option<u64>,
    catalog_page: u64,
    selected_name: Option<String>,
    engine: EngineChoice,
    port: u16,
    search: String,
    favorites_only: bool,
    can_connect: bool,
    closed: bool,
    ephemeral: bool,
    can_stop: bool,
    active_name: Option<String>,
    active_engine: Option<EngineChoice>,
    proxy_fetch_dns: Option<SocketAddr>,
    system_fake_dns: Vec<String>,
    probe_custom: bool,
    probe_persistent: bool,
    probe_expected_status: u16,
    probe_result: Option<HealthResultDto>,
    batch: BatchState,
    tcp_busy: bool,
    tcp_name: Option<String>,
    tcp_result: Option<TcpResultDto>,
    network_epoch: Option<String>,
    network_observed: bool,
    network_routes: bool,
    network_resolver: bool,
    network_manager: bool,
    tcp_invalidated: bool,
}
impl Snapshot {
    fn system_fake_dns_configured(&self) -> bool {
        self.connection_mode == ConnectionMode::System
            && self.selected_kind != Some("xray")
            && !self.system_fake_dns.is_empty()
    }

    fn validate_system_fake_dns_policy(&self) -> Result<()> {
        let policy = self
            .routing
            .policy()
            .map_err(|_| DesktopError("fake_dns_policy"))?;
        yonik_engine::validate_scoped_fake_dns_policy(&policy)
            .map_err(|_| DesktopError("fake_dns_policy"))
    }

    fn ensure_connection_engine(&self, engine: EngineChoice) -> Result<()> {
        if self.system_fake_dns_configured() {
            self.validate_system_fake_dns_policy()
        } else {
            engine.ensure_available()
        }
    }

    fn new(ephemeral: bool) -> Self {
        Self {
            startup: startup_application::View::default(),
            presets: presets::Status::default(),
            maintenance_available: false,
            maintenance_ack: None,
            logs: logs::Page::default(),
            routing_diagnostics: crate::editor::Draft::default().diagnostics(),
            routing_explanation: serde_json::Value::Null,
            routing: crate::editor::Draft::default(),
            routing_revision: Some(0),
            error_contexts: Contexts::default(),
            error_generation: 0,
            helper_generation: None,
            scheduler_generation: None,
            routing_generation: 0,
            maintenance_generation: 0,
            logs_generation: 0,
            command_generation: 0,
            logs_channel: None,
            routing_ack: None,
            source_change_ack: None,
            routing_catalog: serde_json::json!({"items":[],"total":0,"offset":0,"incomplete":false}),
            language: "ru".into(),
            subscription_interval_seconds: 86400,
            subscription_background: false,
            preferences_warning: false,
            preferences_durability_warning: false,
            build_id: env!("YONIK_BUILD_ID"),
            source_hwid_enabled: false,
            source_local: false,
            source_generation: None,
            ready: false,
            busy: false,
            error: None,
            source_error: None,
            connection_error: None,
            pending: None,
            sources: Vec::new(),
            sources_total: 0,
            sources_offset: 0,
            source_id: None,
            source_name: None,
            refresh_source_id: None,
            refresh_token: None,
            profiles: Vec::new(),
            total: 0,
            offset: 0,
            revision: 0,
            connection_mode: ConnectionMode::Local,
            system_state: "Unknown",
            can_unlock: false,
            system_recovery_pending: false,
            system_busy: false,
            system_tun_available: false,
            status: "Disconnected",
            selected_profile: None,
            selected_kind: None,
            selected_catalog_page: None,
            catalog_page: 0,
            selected_name: None,
            engine: EngineChoice::Xray,
            port: 0,
            search: String::new(),
            favorites_only: false,
            can_connect: false,
            closed: false,
            ephemeral,
            can_stop: false,
            active_name: None,
            active_engine: None,
            proxy_fetch_dns: None,
            system_fake_dns: Vec::new(),
            probe_custom: false,
            probe_persistent: true,
            probe_expected_status: 204,
            probe_result: None,
            batch: BatchState::default(),
            tcp_busy: false,
            tcp_name: None,
            tcp_result: None,
            network_epoch: None,
            network_observed: false,
            network_routes: false,
            network_resolver: false,
            network_manager: false,
            tcp_invalidated: false,
        }
    }
    fn begin_command(&mut self, command: &Command) {
        self.error_contexts.clear(Slot::Error);
        self.error = None;
        if command.is_source_operation() {
            if matches!(
                command,
                Command::AddSource { .. }
                    | Command::ImportText { .. }
                    | Command::ImportFile { .. }
                    | Command::CancelLocalImport
                    | Command::ImportSource { .. }
                    | Command::SetSourceHwid { .. }
                    | Command::SelectSource { .. }
                    | Command::DeleteSource { .. }
                    | Command::Refresh
                    | Command::ApproveRefresh
                    | Command::DiscardRefresh
            ) {
                self.error_contexts
                    .clear(crate::diagnostics::context::Slot::Source);
                self.source_error = None;
            }
        } else {
            self.error_contexts
                .clear(crate::diagnostics::context::Slot::Connection);
            self.connection_error = None;
        }
    }
    fn command_error(&mut self, source: bool, error: &'static str) {
        self.error_contexts.clear(Slot::Error);
        self.error = Some(error);
        if source {
            self.error_contexts
                .clear(crate::diagnostics::context::Slot::Source);
            self.source_error = Some(error);
        } else {
            self.error_contexts
                .clear(crate::diagnostics::context::Slot::Connection);
            self.connection_error = Some(error);
        }
    }
    fn contextual_error(&mut self, source: bool, failure: ContextFailure) {
        self.command_error(source, failure.error.key());
        self.error_contexts.set(Slot::Error, failure.cause, None);
        self.error_contexts.set(
            if source {
                Slot::Source
            } else {
                Slot::Connection
            },
            failure.cause,
            None,
        );
    }
    fn source_failure(&mut self, source: bool, failure: SourceFailure, generation: u64) {
        self.command_error(source, failure.key());
        if let Some(context) = failure.context {
            let (cause, generation) = match context {
                FailureContext::Source(cause) => (cause, generation),
                FailureContext::Scheduler(cause, generation) => {
                    self.scheduler_generation = Some(generation);
                    (cause, generation)
                }
            };
            for slot in [
                Slot::Error,
                if source {
                    Slot::Source
                } else {
                    Slot::Connection
                },
            ] {
                self.error_contexts
                    .set_generation(slot, cause, Some(generation));
            }
        }
    }
    fn schedule_error(
        &mut self,
        failure: desktop_schedule::ScheduleFailure,
        generation: Option<u64>,
    ) {
        self.command_error(true, failure.key());
        self.scheduler_generation = generation;
        if let Some(cause) = failure.cause {
            self.error_contexts
                .set_generation(Slot::Error, cause, generation);
            self.error_contexts
                .set_generation(Slot::Source, cause, generation);
        }
    }
    fn schedule_replacement(
        &mut self,
        replacement: std::result::Result<DesktopSchedule, desktop_schedule::ScheduleFailure>,
        previous_generation: u64,
    ) -> Option<DesktopSchedule> {
        match replacement {
            Ok(schedule) => Some(schedule),
            Err(failure) => {
                // При отказе initialize новое поколение ещё не выделено.
                let generation = failure
                    .cause
                    .filter(|cause| cause.needs_generation())
                    .map(|_| previous_generation);
                self.schedule_error(failure, generation);
                None
            }
        }
    }
    fn session_error(&mut self, cause: Cause, generation: u64) {
        self.contextual_error(false, ContextFailure::new(cause));
        self.error_contexts
            .set_generation(Slot::Error, cause, Some(generation));
        self.error_contexts
            .set_generation(Slot::Connection, cause, Some(generation));
    }
    fn clear_logs_contexts(&mut self) {
        self.error_contexts.clear(Slot::LogsRead);
        self.error_contexts.clear(Slot::LogsSave);
    }
    fn logs_key(&self) -> Option<&'static str> {
        match self.logs.status {
            "busy" => Some("busy"),
            "refused" => Some("logs_save_failed"),
            "saved_durability_unknown" => Some("logs_save_durability_unknown"),
            "cancelled" => Some("cancelled"),
            _ => None,
        }
    }
    fn set_logs_context(&mut self, slot: Slot, cause: Option<logs::Failure>) {
        self.clear_logs_contexts();
        self.logs_channel = Some(slot);
        if let (Some(cause), Ok(request_id)) = (
            cause.and_then(logs::Failure::context),
            self.logs.request_id.parse::<u64>(),
        ) {
            if request_id.to_string() == self.logs.request_id {
                self.error_contexts
                    .set_ack(slot, cause, request_id, self.logs_generation);
            }
        }
    }
    fn emit(&self, callback: &Callback) {
        #[derive(Serialize)]
        struct View<'a> {
            #[serde(flatten)]
            snapshot: &'a Snapshot,
            listen_address: String,
            error_contexts: Vec<crate::diagnostics::context::ErrorContext>,
            system_fake_dns_enabled: bool,
        }
        let view = View {
            snapshot: self,
            system_fake_dns_enabled: self.system_fake_dns_configured()
                && self.validate_system_fake_dns_policy().is_ok(),
            error_contexts: [
                self.error_contexts.matching(Slot::Error, self.error, None),
                self.error_contexts
                    .matching(Slot::Connection, self.connection_error, None),
                self.error_contexts
                    .matching(Slot::Source, self.source_error, None),
                self.error_contexts.matching(
                    Slot::RoutingAck,
                    self.routing_ack.as_ref().and_then(|ack| ack.error),
                    self.routing_ack.as_ref().map(|ack| ack.request_id),
                ),
                self.error_contexts.matching(
                    Slot::MaintenanceAck,
                    self.maintenance_ack.as_ref().and_then(|ack| ack.error),
                    self.maintenance_ack.as_ref().map(|ack| ack.request_id),
                ),
                self.logs_channel
                    .filter(|slot| matches!(slot, Slot::LogsRead | Slot::LogsSave))
                    .and_then(|slot| {
                        self.error_contexts.matching(
                            slot,
                            self.logs_key(),
                            self.logs.request_id.parse::<u64>().ok(),
                        )
                    }),
            ]
            .into_iter()
            .flatten()
            .collect(),
            listen_address: format!("127.0.0.1:{}", self.port),
        };
        if let Ok(json) = serde_json::to_string(&view) {
            callback(json);
        }
    }
}

// Ядро не принимает готовые FD: проверка сужает окно гонки, но не резервирует порт.
// Проверяем также UDP, поскольку SOCKS inbound Xray включает udp:true.
fn available_port(requested: u16) -> Result<NonZeroU16> {
    for _ in 0..16 {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, requested))
            .map_err(|_| DesktopError("listen_port_busy"))?;
        let port = tcp
            .local_addr()
            .map_err(|_| DesktopError("listen_port_busy"))?
            .port();
        if UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return NonZeroU16::new(port).ok_or(DesktopError("listen_port_busy"));
        }
        if requested != 0 {
            break;
        }
    }
    Err(DesktopError("listen_port_busy"))
}

#[derive(Debug)]
struct ContextFailure {
    error: DesktopError,
    cause: Cause,
}
impl ContextFailure {
    fn new(cause: Cause) -> Self {
        let context = crate::diagnostics::context::ErrorContext::new(Slot::Error, cause, None);
        Self {
            error: DesktopError(context.message_key),
            cause,
        }
    }
}

fn private_directory(path: &Path) -> std::result::Result<(PathBuf, File), ContextFailure> {
    if !path.is_absolute() {
        return Err(ContextFailure::new(Cause::DataDirectoryRelative));
    }
    match DirBuilder::new().recursive(true).mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(ContextFailure::new(Cause::DataDirectoryCreate)),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ContextFailure::new(Cause::DataDirectoryMetadata))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ContextFailure::new(Cause::DataDirectoryType));
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(ContextFailure::new(Cause::DataDirectoryOwner));
    }
    if metadata.mode() & 0o7777 != 0o700 {
        return Err(ContextFailure::new(Cause::DataDirectoryPermissions));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| ContextFailure::new(Cause::DataDirectoryCanonicalize))?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY).bits() as i32)
        .open(&canonical)
        .map_err(|_| ContextFailure::new(Cause::DataDirectoryOpen))?;
    rustix::fs::flock(
        &directory,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|_| ContextFailure::new(Cause::DataDirectoryLock))?;
    Ok((canonical, directory))
}

async fn open(
    config: &mut HostConfig,
) -> std::result::Result<(SubscriptionService, File, EncryptedSubscriptionRepository), ContextFailure>
{
    let path = config.data_dir.clone();
    config.startup_observer.emit(StartupPhase::DirectoryQueued);
    let observer = config.startup_observer.clone();
    let (directory, lock) = tokio::task::spawn_blocking(move || {
        observer.emit(StartupPhase::DirectoryLock);
        let result = private_directory(&path);
        observer.emit(StartupPhase::DirectoryReturned);
        result
    })
    .await
    .map_err(|_| ContextFailure::new(Cause::StorageTaskFailed))??;
    let path = directory.join("subscriptions.sqlite");
    config.startup_observer.emit(StartupPhase::Credential);
    let key = match config.ephemeral_key.take() {
        Some(key) => key,
        None => async {
            let (key, owner) =
                yonik_linux::subscription_master_key_with_owner(!path.exists()).await?;
            config.startup_custody = owner;
            Ok::<_, CredentialError>(key)
        }
        .await
        .map_err(|error| {
            ContextFailure::new(match error {
                CredentialError::Missing => Cause::KeyringMissing,
                CredentialError::Locked => Cause::KeyringLocked,
                CredentialError::Unavailable => Cause::KeyringUnavailable,
                CredentialError::Ambiguous => Cause::KeyringAmbiguous,
                CredentialError::InvalidKey => Cause::KeyringInvalidKey,
                CredentialError::Random => Cause::KeyringRandom,
                CredentialError::Timeout => Cause::KeyringTimeout,
                CredentialError::Busy => Cause::KeyringBusy,
            })
        })?,
    };
    config.startup_observer.emit(StartupPhase::RepositoryOpen);
    let repo = EncryptedSubscriptionRepository::open(path, key)
        .await
        .map_err(|error| {
            ContextFailure::new(match error {
                yonik_linux::RepositoryError::InvalidInput => Cause::RepositoryOpenInvalidInput,
                yonik_linux::RepositoryError::UnsafePath => Cause::RepositoryOpenUnsafePath,
                yonik_linux::RepositoryError::UnsupportedVersion => {
                    Cause::RepositoryOpenUnsupportedVersion
                }
                yonik_linux::RepositoryError::Corrupt => Cause::RepositoryOpenCorrupt,
                yonik_linux::RepositoryError::Storage => Cause::RepositoryOpenStorage,
                yonik_linux::RepositoryError::Conflict => Cause::RepositoryOpenConflict,
                yonik_linux::RepositoryError::NotFound => Cause::RepositoryOpenNotFound,
            })
        })?;
    config
        .startup_observer
        .emit(StartupPhase::RepositoryReturned);
    Ok((SubscriptionService::new(repo.clone()), lock, repo))
}

fn catalog_response(request_id: u64, mut page: serde_json::Value) -> serde_json::Value {
    if request_id != 0 {
        page["request_id"] = request_id.into();
    }
    page
}

#[cfg(test)]
mod catalog_correlation_tests {
    #[test]
    fn legacy_shape_and_positive_reply_identity() {
        let page = serde_json::json!({"items":[],"offset":0,"total":0,"incomplete":false});
        assert_eq!(super::catalog_response(0, page.clone()), page);
        let reply = super::catalog_response(9_007_199_254_740_991, page.clone());
        assert_eq!(reply["request_id"], 9_007_199_254_740_991_u64);
        let mut restored = reply;
        restored
            .as_object_mut()
            .expect("catalog object")
            .remove("request_id");
        assert_eq!(restored, page);
    }
    #[test]
    fn missing_id_remains_legacy_and_invalid_ids_are_rejected() {
        let legacy = r#"{"command":"routing_catalog","processes":false,"query":"","offset":0}"#;
        assert!(matches!(
            serde_json::from_str::<super::Command>(legacy),
            Ok(super::Command::RoutingCatalog { request_id: 0, .. })
        ));
        for id in [
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("text"),
            serde_json::Value::Null,
        ] {
            let mut input: serde_json::Value = serde_json::from_str(legacy).expect("legacy JSON");
            input["request_id"] = id;
            assert!(serde_json::from_value::<super::Command>(input).is_err());
        }
    }
}

struct Actor {
    #[cfg(feature = "test-support")]
    catalog_observer: Option<yonik_linux::applications::CatalogObserver>,
    presets: Option<Arc<presets::Controller>>,
    logs_save: logs::SaveJob,
    event_log: yonik_linux::event_log::EventLog,
    routing_repository: Option<EncryptedSubscriptionRepository>,
    format4_backup: Option<PathBuf>,
    routing_revision: Option<i64>,
    preferences: Preferences,
    preferences_store: Store,
    service: Option<SubscriptionService>,
    state: Snapshot,
    callback: Callback,
    selected: Option<ResolvedProfile>,
    selected_native: Option<yonik_linux::ResolvedCatalogProfile>,
    selected_native_token: Option<yonik_linux::CatalogSelection>,
    catalog_selections: Vec<(CatalogKind, i64, yonik_linux::CatalogSelection)>,
    catalog_coordinates: Option<(i64, i64, i64, i64)>,
    pending: Option<Box<PendingRefresh>>,
    automatic_port: bool,
    probe_url: Zeroizing<String>,
    network: Option<NetworkWatch>,
}
impl Actor {
    fn preset_scope(&self) -> Option<presets::ValidationScope> {
        self.state
            .routing_revision
            .map(|routing_revision| presets::ValidationScope {
                routing_revision,
                profile: self.state.selected_profile,
                source_revision: self.state.revision,
                engine: match self.state.engine {
                    EngineChoice::Xray => "xray",
                    EngineChoice::SingBox => "sing-box",
                },
                port: self.state.port,
            })
    }
    fn invalidate_preset(&mut self) {
        self.state.presets.prepared = false;
        self.state.presets.host_validated = false;
        self.state.presets.validation_scope = None;
        self.state.presets.compiler_error = None;
        self.state.presets.decision = None;
    }
    fn preset_policy(&self, draft: &crate::editor::Draft) -> Result<yonik_domain::Policy> {
        let base = draft.base_policy().map_err(DesktopError)?;
        match &draft.ru_direct {
            Some(reference) if reference.enabled => self
                .presets
                .as_ref()
                .ok_or(DesktopError("storage"))?
                .resolve(reference, base)
                .map_err(|_| DesktopError("storage")),
            _ => Ok(base),
        }
    }
    // Внешний цикл и методы Actor работают только online. Supervisor полностью
    // перехватывает dispatch между take slots и возвратом handles после join.
    fn service(&self) -> &SubscriptionService {
        self.service
            .as_ref()
            .expect("online dispatch требует service slot")
    }
    fn routing_repository(&self) -> &EncryptedSubscriptionRepository {
        self.routing_repository
            .as_ref()
            .expect("online dispatch требует repository slot")
    }

    async fn check_routing_apply(&self, command: &Command) -> Result<()> {
        let Command::RoutingApply {
            expected_revision,
            request_id,
            source_generation,
            snapshot_revision,
            selected_profile_id,
        } = command
        else {
            return Ok(());
        };
        if *request_id == 0 || *request_id > 9_007_199_254_740_991 {
            return Err(DesktopError("invalid_input"));
        }
        if self.routing_revision != Some(*expected_revision)
            || self.state.source_generation != Some(*source_generation)
            || self.state.revision != *snapshot_revision
            || self.state.selected_profile != Some(*selected_profile_id)
        {
            return Err(DesktopError("routing_stale"));
        }
        let source = self
            .state
            .source_id
            .ok_or(DesktopError("profile_required"))?;
        if self
            .service()
            .schedule_generation(source)
            .await
            .map_err(map_subscription)?
            != Some(*source_generation)
        {
            return Err(DesktopError("routing_stale"));
        }
        Ok(())
    }

    fn current_inline_policy(&self) -> Result<(yonik_linux::system_policy::InlinePolicy, i64)> {
        let revision = self
            .routing_revision
            .ok_or(DesktopError("routing_storage"))?;
        let policy = self.state.routing.policy().map_err(DesktopError)?;
        let inline = inline_policy_conversion::inline_policy(&policy)
            .map_err(|_| DesktopError("system_unsupported"))?;
        Ok((inline, revision))
    }

    async fn save_routing(
        &mut self,
        candidate: crate::editor::Draft,
        request_id: u64,
    ) -> Result<()> {
        self.invalidate_preset();
        self.preset_policy(&candidate)?;
        let expected = self
            .routing_revision
            .ok_or(DesktopError("routing_storage"))?;
        let revision = if candidate.version == 3 {
            self.routing_repository()
                .save_routing_draft_v3(
                    expected,
                    candidate.json().into_bytes(),
                    self.format4_backup.clone(),
                )
                .await
        } else if candidate.version == 2 {
            self.routing_repository()
                .save_routing_draft_v2(
                    expected,
                    candidate.json().into_bytes(),
                    self.format4_backup.clone(),
                )
                .await
        } else {
            self.routing_repository()
                .save_routing_draft(expected, candidate.json().into_bytes())
                .await
        }
        .map_err(|error| {
            self.state.error_contexts.set_ack(
                Slot::RoutingAck,
                if error == yonik_linux::RepositoryError::Conflict {
                    Cause::RoutingRepositoryConflict
                } else {
                    Cause::RoutingRepositoryFailed
                },
                request_id,
                self.state.routing_generation,
            );
            DesktopError(if error == yonik_linux::RepositoryError::Conflict {
                "routing_stale"
            } else {
                "routing_storage"
            })
        })?;
        self.routing_revision = Some(revision);
        self.state.routing_revision = Some(revision);
        self.state.routing_diagnostics = candidate.diagnostics();
        self.state.routing_explanation = serde_json::Value::Null;
        self.state.routing = candidate;
        Ok(())
    }

    async fn mutate_routing(
        &mut self,
        expected_revision: i64,
        request_id: u64,
        mutation: RoutingMutation,
    ) -> Result<()> {
        self.invalidate_preset();
        self.state.error_contexts.clear(Slot::RoutingAck);
        let mut routing_cause = None;
        let saved_id = match &mutation {
            RoutingMutation::Put { rule, .. } => Some(rule.id),
            _ => None,
        };
        let result = async {
            if request_id == 0 || request_id > 9_007_199_254_740_991 {
                routing_cause = Some(Cause::RoutingRequestIdentity);
                return Err(DesktopError("invalid_input"));
            }
            let current = self
                .routing_revision
                .ok_or(DesktopError("routing_storage"))?;
            if expected_revision != current {
                routing_cause = Some(Cause::RoutingRevisionStale);
                return Err(DesktopError("routing_stale"));
            }
            let mut candidate = self.state.routing.clone();
            match mutation {
                RoutingMutation::Put {
                    rule,
                    confirm_broad,
                    create,
                } => {
                    let exists = candidate.rules.iter().any(|r| r.id == rule.id);
                    if exists == create {
                        routing_cause = Some(Cause::RoutingRuleIdentity);
                        return Err(DesktopError("id"));
                    }
                    candidate.put(rule, confirm_broad).map_err(DesktopError)?;
                }
                RoutingMutation::Order(ids) => {
                    if ids.len() != candidate.rules.len() {
                        routing_cause = Some(Cause::RoutingRuleIdentity);
                        return Err(DesktopError("id"));
                    }
                    let mut available: std::collections::HashMap<_, _> =
                        candidate.rules.into_iter().map(|r| (r.id, r)).collect();
                    candidate.rules = ids
                        .into_iter()
                        .map(|id| available.remove(&id).ok_or(DesktopError("id")))
                        .collect::<Result<Vec<_>>>()?;
                }
                RoutingMutation::Delete(id) => {
                    let index = candidate
                        .rules
                        .iter()
                        .position(|r| r.id == id)
                        .ok_or(DesktopError("id"))?;
                    candidate.rules.remove(index);
                }
                RoutingMutation::Default(action) => candidate.default_action = action,
            }
            self.save_routing(candidate, request_id).await
        }
        .await;
        if result
            .as_ref()
            .err()
            .is_some_and(|e| e.key() == "routing_stale")
        {
            self.state.routing_diagnostics =
                serde_json::json!({"incomplete":true,"stale":true,"warnings":[]});
            self.state.routing_explanation = serde_json::Value::Null;
        }
        let pending_context = self.state.error_contexts.matching(
            Slot::RoutingAck,
            result.as_ref().err().map(|error| error.key()),
            Some(request_id),
        );
        self.state
            .error_contexts
            .clear(crate::diagnostics::context::Slot::RoutingAck);
        self.state.routing_ack = Some(RoutingAck {
            request_id,
            saved_id: if result.is_ok() { saved_id } else { None },
            error: result.as_ref().err().map(|e| e.key()),
        });
        if let Some(cause) = routing_cause.or(pending_context.map(|context| context.reason)) {
            self.state.error_contexts.set_ack(
                Slot::RoutingAck,
                cause,
                request_id,
                self.state.routing_generation,
            );
        }
        result
    }

    fn save_preferences(&mut self, preferences: Preferences) -> Result<()> {
        let outcome = match self.preferences_store.save(&preferences) {
            Ok(outcome) => outcome,
            Err(SaveError::Conflict(current)) => {
                self.preferences = *current;
                // Старый apply receipt не подтверждает перечитанную ревизию.
                // Unknown/error не снимаются чтением без нового explicit apply.
                if self.state.startup.xdg == "applied" {
                    self.state.startup.xdg = "unchanged";
                }
                // Read refresh не переключает текущие engine/port/probe inputs,
                // не перепривязывает target/owner и не повторяет запись/Connect.
                self.state.language = self.preferences.language.clone();
                self.state.subscription_interval_seconds =
                    self.preferences.subscription_interval_seconds;
                self.state.subscription_background = self.preferences.subscription_background;
                self.state.proxy_fetch_dns = self.preferences.proxy_fetch_dns;
                self.state
                    .system_fake_dns
                    .clone_from(&self.preferences.system_fake_dns);
                self.startup_view();
                return Err(DesktopError("preferences_conflict"));
            }
            Err(SaveError::Io(error)) => {
                self.state.preferences_warning |= self.preferences_store.blocked();
                let cause = match error.kind() {
                    std::io::ErrorKind::PermissionDenied => {
                        Some(Cause::PreferencesIoPermissionDenied)
                    }
                    std::io::ErrorKind::AlreadyExists => Some(Cause::PreferencesIoAlreadyExists),
                    std::io::ErrorKind::NotFound => Some(Cause::PreferencesIoNotFound),
                    std::io::ErrorKind::InvalidInput => Some(Cause::PreferencesIoInvalidInput),
                    std::io::ErrorKind::Other => Some(Cause::PreferencesIoOther),
                    _ => None,
                };
                if let Some(cause) = cause {
                    self.state.error_contexts.set_generation(
                        Slot::Error,
                        cause,
                        Some(self.state.command_generation),
                    );
                }
                return Err(DesktopError("preferences_write"));
            }
        };
        self.state.preferences_durability_warning =
            outcome == SaveOutcome::PublishedDurabilityUnknown;
        self.preferences = preferences;
        Ok(())
    }
    fn prepare_port(&mut self) -> Result<()> {
        match available_port(self.state.port) {
            Ok(_) => Ok(()),
            Err(_) if self.automatic_port => {
                self.state.port = available_port(0)?.get();
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    async fn refresh(
        &mut self,
        generation: u64,
        scheduler_generation: u64,
        host: Arc<DesktopFetch>,
    ) -> SourceResult<RefreshTask> {
        let id = self
            .state
            .source_id
            .ok_or(DesktopError("source_required"))?;
        static NEXT_REFRESH: AtomicU64 = AtomicU64::new(1);
        let token = NEXT_REFRESH
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .map_err(|_| DesktopError("refresh_required"))?
            .to_string();
        self.pending = None;
        self.state.pending = None;
        let identity = SubscriptionIdentity {
            id,
            generation: self
                .service()
                .schedule_generation(id)
                .await
                .map_err(SourceFailure::subscription)?
                .ok_or(DesktopError("source_required"))?,
        };
        let service = self.service().clone();
        let (cancel, receiver) = watch::channel(false);
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        service
            .reserve_manual_schedule(identity, wall)
            .await
            .map_err(SourceFailure::subscription)?;
        extend_schedule_interval(
            &service,
            identity,
            Duration::from_secs(self.preferences.subscription_interval_seconds as u64),
        )
        .await
        .map_err(|failure| SourceFailure::schedule(failure, scheduler_generation))?;
        let task = tokio::spawn(async move {
            service
                .refresh_with_host(
                    identity.id,
                    Some(identity.generation),
                    host.as_ref(),
                    receiver,
                )
                .await
        });
        self.state.busy = true;
        self.state.refresh_source_id = Some(id);
        self.state.refresh_token = Some(token.clone());
        Ok((generation, cancel, task, identity, token))
    }
    fn tcp_key(&self) -> Option<TcpKey> {
        let selected = self.selected.as_ref()?;
        Some(TcpKey {
            source: selected.profile.source_id,
            profile: selected.profile.id,
            revision: selected.snapshot_revision,
        })
    }
    fn probe_target(&self) -> Result<ProbeTarget> {
        ProbeTarget::new(&self.probe_url, PROBE_TIMEOUT)
            .and_then(|target| target.with_expected_status(self.state.probe_expected_status))
            .map_err(|_| DesktopError("probe_target_invalid"))
    }
    fn update(&mut self, update: SessionUpdate) {
        apply_session_update(
            &mut self.state,
            update,
            self.network.as_ref().map(NetworkWatch::current),
        );
    }
    fn emit(&mut self) {
        self.startup_view();
        if self.state.presets.stopping
            && matches!(self.state.status, "Disconnected" | "NoManagedPolicy")
        {
            self.state.status = "Stopping";
            self.state.can_stop = true;
        }
        if self.state.presets.host_validated
            && self.state.presets.validation_scope != self.preset_scope()
        {
            self.state.presets.host_validated = false;
            self.state.presets.validation_scope = None;
        }
        self.state.can_connect = self.state.ready
            && ((self.selected.is_some()
                && self
                    .state
                    .ensure_connection_engine(self.state.engine)
                    .is_ok())
                || self.selected_native.as_ref().is_some_and(|profile| {
                    self.selected_native_token.is_some()
                        && Some(profile.source_id) == self.state.source_id
                        && native_subset_plannable(&profile.entry, self.state.connection_mode)
                }))
            && !self.state.can_stop
            && !self.state.system_busy
            && !self.state.busy
            && self.state.pending.is_none();
        self.state.emit(&self.callback);
    }
    async fn native_connect_preflight(
        &self,
        command: &Command,
        control: &Control,
        generation: u64,
        busy: bool,
    ) -> SourceResult<(yonik_engine::native_profile::ProfileIntent, BinarySnapshot)> {
        if !matches!(command, Command::Connect) {
            return Err(DesktopError("invalid_input").into());
        }
        if busy
            || self.state.can_stop
            || self.state.system_busy
            || self.state.system_recovery_pending
            || self.state.can_unlock
        {
            return Err(DesktopError("busy").into());
        }
        if self.pending.is_some() || self.state.pending.is_some() {
            return Err(DesktopError("review_required").into());
        }
        let intent = self.native_connect_intent(control, generation).await?;
        let mode = match self.state.connection_mode {
            ConnectionMode::Local => yonik_linux::FullProfileMode::Local,
            ConnectionMode::System => yonik_linux::FullProfileMode::System,
        };
        yonik_linux::full_profile_plan_preflight(mode, &intent)
            .map_err(|_| DesktopError("profile_unavailable"))?;
        let binary = tokio::task::spawn_blocking(|| {
            yonik_linux::helper::TrustedRegistry::system()
                .and_then(|registry| registry.full_profile_snapshot())
        })
        .await
        .map_err(|_| DesktopError("profile_unavailable"))?
        .map_err(|_| DesktopError("profile_unavailable"))?;
        // Новая await boundary: source/revision/selection и generation заново.
        let intent = self.native_connect_intent(control, generation).await?;
        yonik_linux::full_profile_image_preflight(mode, &intent, &binary)
            .map_err(|_| DesktopError("profile_unavailable"))?;
        if generation != control.generation.load(Ordering::SeqCst) {
            return Err(DesktopError("cancelled").into());
        }
        Ok((intent, binary))
    }
    async fn native_connect_intent(
        &self,
        control: &Control,
        generation: u64,
    ) -> SourceResult<yonik_engine::native_profile::ProfileIntent> {
        let current = self
            .selected_native
            .as_ref()
            .ok_or(DesktopError("profile_required"))?;
        let token = self
            .selected_native_token
            .clone()
            .ok_or(DesktopError("profile_unavailable"))?;
        let fence = || {
            if generation != control.generation.load(Ordering::SeqCst) {
                Err(DesktopError("cancelled"))
            } else {
                Ok(())
            }
        };
        fence()?;
        let profile = self
            .service()
            .select_catalog_profile(token)
            .await
            .map_err(SourceFailure::subscription)?;
        fence()?;
        if (
            profile.source_id,
            profile.source_generation,
            profile.snapshot_generation,
            profile.snapshot_revision,
        ) != (
            current.source_id,
            current.source_generation,
            current.snapshot_generation,
            current.snapshot_revision,
        ) || Some(profile.source_id) != self.state.source_id
            || self
                .service()
                .schedule_generation(profile.source_id)
                .await
                .map_err(SourceFailure::subscription)?
                != Some(profile.source_generation)
        {
            return Err(DesktopError("profile_unavailable").into());
        }
        fence()?;
        match profile.entry {
            yonik_import::ProfileEntry::Xray(native) => {
                yonik_engine::native_profile::ProfileIntent::from_profile(&native)
                    .map_err(|_| DesktopError("engine_config").into())
            }
            yonik_import::ProfileEntry::Server(_) => {
                Err(DesktopError("profile_unavailable").into())
            }
        }
    }
    fn catalog_selection(
        &self,
        kind: CatalogKind,
        id: i64,
        page: u64,
    ) -> SourceResult<yonik_linux::CatalogSelection> {
        if page != self.state.catalog_page {
            return Err(DesktopError("profile_unavailable").into());
        }
        self.catalog_selections
            .iter()
            .find(|(k, i, _)| *k == kind && *i == id)
            .map(|(_, _, selection)| selection.clone())
            .ok_or_else(|| DesktopError("profile_unavailable").into())
    }
    fn clear_selection(&mut self) {
        self.selected = None;
        self.selected_native = None;
        self.selected_native_token = None;
        self.state.selected_kind = None;
        self.state.selected_catalog_page = None;
        self.invalidate_preset();
        self.state.selected_profile = None;
        self.state.selected_name = None;
        self.state.tcp_result = None;
    }
    async fn reload(&mut self) -> SourceResult<()> {
        self.sources().await?;
        if self.state.source_id.is_none() {
            self.state.source_id = self.state.sources.first().map(|source| source.id);
            self.clear_selection();
        }
        self.page().await
    }
    async fn sources(&mut self) -> SourceResult<()> {
        let page = self
            .service()
            .sources_page(self.state.sources_offset)
            .await
            .map_err(SourceFailure::subscription)?;
        self.state.sources_total = page.total;
        self.state.sources_offset = page.offset;
        self.state.sources = page
            .sources
            .into_iter()
            .map(|source| SourceDto {
                id: source.id,
                name: source.name,
                hwid_enabled: source.hwid_enabled,
            })
            .collect();
        Ok(())
    }
    async fn page(&mut self) -> SourceResult<()> {
        self.catalog_selections.clear();
        self.state.catalog_page = self
            .state
            .catalog_page
            .checked_add(1)
            .filter(|v| *v <= 9_007_199_254_740_991)
            .ok_or(DesktopError("profile_unavailable"))?;
        self.state.source_generation = None;
        self.state.profiles.clear();
        self.state.total = 0;
        self.state.revision = 0;
        self.state.source_hwid_enabled = false;
        self.state.source_local = false;
        self.state.source_name = None;
        let Some(id) = self.state.source_id else {
            return Ok(());
        };
        self.state.source_generation = self
            .service()
            .schedule_generation(id)
            .await
            .map_err(SourceFailure::subscription)?;
        let summary = self
            .service()
            .source_summary(id)
            .await
            .map_err(SourceFailure::subscription)?;
        self.state.source_local = self
            .service()
            .source_is_local(id)
            .await
            .map_err(SourceFailure::subscription)?;
        self.state.source_hwid_enabled = summary.hwid_enabled;
        self.state.source_name = Some(summary.name);
        let page = self
            .service()
            .catalog(
                id,
                ProfileQuery {
                    search: self.state.search.clone(),
                    favorites_only: self.state.favorites_only,
                    include_unavailable: true,
                    offset: self.state.offset,
                    limit: 200,
                    ..ProfileQuery::default()
                },
            )
            .await
            .map_err(SourceFailure::subscription)?;
        let coordinates = (
            id,
            page.source_generation,
            page.snapshot_generation,
            page.snapshot_revision,
        );
        if self
            .service()
            .schedule_generation(id)
            .await
            .map_err(SourceFailure::subscription)?
            != Some(page.source_generation)
        {
            self.clear_selection();
            return Err(DesktopError("profile_unavailable").into());
        }
        if self.catalog_coordinates != Some(coordinates) {
            self.clear_selection();
        }
        self.catalog_coordinates = Some(coordinates);
        self.state.total = page.total;
        self.state.revision = page.snapshot_revision;
        for (profile, selection) in page.profiles {
            let row = catalog_profile_dto(profile);
            let kind = if row.kind == "xray" {
                CatalogKind::Xray
            } else {
                CatalogKind::Server
            };
            self.catalog_selections.push((kind, row.id, selection));
            self.state.profiles.push(row);
        }
        // Подтверждение нового snapshot всегда требует повторного выбора.
        if self
            .selected
            .as_ref()
            .is_some_and(|p| p.snapshot_revision != self.state.revision)
        {
            self.clear_selection();
        }
        Ok(())
    }
    async fn source_command(&mut self, command: Command) -> SourceResult<()> {
        if self.selected_native.is_some() && command.requires_server_selection() {
            return Err(DesktopError("profile_unavailable").into());
        }
        match command {
            Command::Reload => self.reload().await,
            Command::SourcePage { offset } => {
                self.state.sources_offset = offset;
                self.sources().await
            }
            Command::AddSource {
                name,
                url,
                local_exception,
                route,
                hwid_enabled,
            } => {
                let source = SubscriptionSource::new(
                    name,
                    url,
                    local_exception,
                    match route {
                        Route::Direct => FetchRoute::Direct,
                        Route::Proxy => FetchRoute::Proxy,
                    },
                )
                .and_then(|source| source.with_hwid(hwid_enabled))
                .map_err(SourceFailure::subscription)?;
                let id = self
                    .service()
                    .add(source)
                    .await
                    .map_err(SourceFailure::subscription)?;
                self.state.source_id = Some(id);
                self.state.offset = 0;
                self.pending = None;
                self.state.pending = None;
                self.clear_selection();
                self.reload().await
            }
            Command::SourceChange {
                request_id,
                id,
                expected_generation,
                name,
                url,
                local_exception,
                route,
                hwid_enabled,
            } => {
                let source = SubscriptionSource::new(
                    name,
                    url,
                    local_exception,
                    match route {
                        Route::Direct => FetchRoute::Direct,
                        Route::Proxy => FetchRoute::Proxy,
                    },
                )
                .and_then(|source| source.with_hwid(hwid_enabled))
                .map_err(SourceFailure::subscription)?;
                let generation = self
                    .service()
                    .change_source(id, expected_generation, source)
                    .await
                    .map_err(SourceFailure::subscription)?;
                self.state.source_change_ack = Some(SourceChangeAck {
                    request_id,
                    id,
                    generation: Some(generation),
                    error: None,
                });
                if self.state.source_id == Some(id) {
                    self.clear_selection();
                    self.reload().await
                } else {
                    self.sources().await
                }
            }
            Command::RenameSource { id, name } => {
                self.service()
                    .rename_source(id, name.clone())
                    .await
                    .map_err(SourceFailure::subscription)?;
                if self.state.source_id == Some(id) {
                    self.state.source_name = Some(name);
                }
                self.sources().await
            }
            Command::DeleteSource { id } => {
                if self.state.can_stop {
                    return Err(DesktopError("source_in_use").into());
                }
                if self.pending.is_some() {
                    return Err(DesktopError("busy").into());
                }
                self.service()
                    .delete_source(id)
                    .await
                    .map_err(SourceFailure::subscription)?;
                self.state.sources_offset = 0;
                self.sources().await?;
                if self.state.source_id == Some(id) {
                    self.state.source_id = self.state.sources.first().map(|source| source.id);
                    self.state.offset = 0;
                    self.clear_selection();
                    self.page().await?;
                }
                Ok(())
            }
            Command::SetSourceHwid { enabled } => {
                let id = self
                    .state
                    .source_id
                    .ok_or(DesktopError("source_required"))?;
                self.service()
                    .set_source_hwid(id, enabled)
                    .await
                    .map_err(SourceFailure::subscription)?;
                self.pending = None;
                self.state.pending = None;
                self.clear_selection();
                self.reload().await
            }
            Command::SelectSource { id } => {
                if !self.state.sources.iter().any(|s| s.id == id) {
                    return Err(DesktopError("source_required").into());
                }
                self.state.source_id = Some(id);
                self.state.offset = 0;
                self.pending = None;
                self.state.pending = None;
                self.clear_selection();
                self.page().await
            }
            Command::ApproveRefresh => {
                let pending = self.pending.take().ok_or(DesktopError("review_required"))?;
                let identity = pending.identity();
                self.state.pending = None;
                self.service()
                    .commit(pending.approve_after_review())
                    .await
                    .map_err(SourceFailure::subscription)?;
                self.persist_refresh_completion(identity, true).await?;
                self.clear_selection();
                self.page().await
            }
            Command::DiscardRefresh => {
                if let Some(pending) = self.pending.as_ref() {
                    self.persist_refresh_completion(pending.identity(), true)
                        .await?;
                }
                self.pending = None;
                self.state.pending = None;
                Ok(())
            }
            Command::ReviewPage { offset } => {
                let pending = self
                    .pending
                    .as_ref()
                    .ok_or(DesktopError("review_required"))?;
                self.state.pending = Some(pending_dto(pending, offset)?);
                Ok(())
            }
            Command::Query {
                search,
                favorites_only,
                offset,
            } => {
                self.state.search = search;
                self.state.favorites_only = favorites_only;
                self.state.offset = offset;
                self.page().await
            }
            Command::SelectCatalog { kind, id, page } => {
                let selection = self.catalog_selection(kind, id, page)?;
                self.clear_selection();
                let profile = self
                    .service()
                    .select_catalog_profile(selection.clone())
                    .await
                    .map_err(SourceFailure::subscription)?;
                if Some(profile.source_id) != self.state.source_id
                    || self.catalog_coordinates
                        != Some((
                            profile.source_id,
                            profile.source_generation,
                            profile.snapshot_generation,
                            profile.snapshot_revision,
                        ))
                    || self
                        .service()
                        .schedule_generation(profile.source_id)
                        .await
                        .map_err(SourceFailure::subscription)?
                        != Some(profile.source_generation)
                {
                    return Err(DesktopError("profile_unavailable").into());
                }
                self.state.selected_catalog_page = Some(page);
                match &profile.entry {
                    yonik_import::ProfileEntry::Xray(_) => {
                        if kind != CatalogKind::Xray {
                            return Err(DesktopError("profile_unavailable").into());
                        }
                        self.state.selected_name = self
                            .state
                            .profiles
                            .iter()
                            .find(|row| row.id == id && row.kind == "xray")
                            .map(|row| row.name.clone());
                        self.state.selected_kind = Some("xray");
                        self.state.selected_profile = Some(id);
                        self.selected_native = Some(profile);
                        self.selected_native_token = Some(selection);
                    }
                    yonik_import::ProfileEntry::Server(_) => {
                        if kind != CatalogKind::Server {
                            return Err(DesktopError("profile_unavailable").into());
                        }
                        let legacy = self
                            .service()
                            .select_profile(id, profile.snapshot_revision)
                            .await
                            .map_err(SourceFailure::selection)?;
                        if self
                            .service()
                            .schedule_generation(profile.source_id)
                            .await
                            .map_err(SourceFailure::subscription)?
                            != Some(profile.source_generation)
                        {
                            return Err(DesktopError("profile_unavailable").into());
                        }
                        self.state.selected_name = Some(legacy.profile.name.clone());
                        self.state.selected_kind = Some("server");
                        self.state.selected_profile = Some(id);
                        self.selected = Some(legacy);
                    }
                }
                Ok(())
            }
            Command::CatalogFavorite {
                kind,
                id,
                page,
                value,
            } => {
                let selection = self.catalog_selection(kind, id, page)?;
                self.service()
                    .set_catalog_favorite(selection, value)
                    .await
                    .map_err(SourceFailure::subscription)?;
                self.page().await
            }
            Command::Favorite { id, value } => {
                self.service()
                    .set_favorite(id, value)
                    .await
                    .map_err(SourceFailure::subscription)?;
                self.page().await
            }
            Command::SelectProfile { id, revision } => {
                let profile = self
                    .service()
                    .select_profile(id, revision)
                    .await
                    .map_err(SourceFailure::selection)?;
                if Some(profile.profile.source_id) != self.state.source_id
                    || profile.snapshot_revision != self.state.revision
                {
                    return Err(DesktopError("profile_unavailable").into());
                }
                self.clear_selection();
                self.state.selected_kind = Some("server");
                self.state.selected_profile = Some(id);
                self.state.selected_name = Some(profile.profile.name.clone());
                self.selected = Some(profile);
                Ok(())
            }
            command => self.command(command).await.map_err(Into::into),
        }
    }
    async fn command(&mut self, command: Command) -> Result<()> {
        match command {
            Command::PresetActivate {
                enabled,
                expected_revision,
                request_id,
            } => {
                self.invalidate_preset();
                let outcome = async {
                    if request_id == 0 || request_id > 9_007_199_254_740_991 {
                        return Err(DesktopError("invalid_input"));
                    }
                    if self.routing_revision != Some(expected_revision) {
                        return Err(DesktopError("routing_stale"));
                    }
                    let mut candidate = self.state.routing.clone();
                    if enabled {
                        let snapshot = self
                            .presets
                            .as_ref()
                            .ok_or(DesktopError("storage"))?
                            .reference()
                            .map_err(|_| DesktopError("storage"))?;
                        candidate.ru_direct =
                            Some(crate::editor::PresetReference { snapshot, enabled });
                    } else if let Some(reference) = &mut candidate.ru_direct {
                        reference.enabled = false;
                    }
                    self.save_routing(candidate, request_id).await
                }
                .await;
                self.state.presets.ack = Some(presets::Ack {
                    request_id,
                    error: outcome.as_ref().err().map(|e| e.key()),
                });
                outcome
            }
            Command::PresetStatus
            | Command::PresetRollback { .. }
            | Command::PresetPrepare { .. } => {
                let request_id = command.preset_request_id().unwrap_or(0);
                self.invalidate_preset();
                self.state.presets.operation_error = None;
                let Some(controller) = self.presets.as_ref() else {
                    self.state.presets.operation_error = Some("storage");
                    self.state.presets.ack = Some(presets::Ack {
                        request_id,
                        error: Some("storage"),
                    });
                    return if request_id > 0 {
                        Ok(())
                    } else {
                        Err(DesktopError("storage"))
                    };
                };
                let result = match command {
                    Command::PresetRollback { .. } => controller.rollback(),
                    Command::PresetPrepare { target, .. } => {
                        let ip = target.parse::<std::net::IpAddr>();
                        let name = target.parse::<yonik_domain::DomainName>();
                        if ip.is_err() && name.is_err() {
                            self.state.presets.operation_error = Some("invalid_ip");
                            self.state.presets.ack = Some(presets::Ack {
                                request_id,
                                error: Some("invalid_ip"),
                            });
                            return if request_id > 0 {
                                Ok(())
                            } else {
                                Err(DesktopError("invalid_input"))
                            };
                        }
                        let base = self.state.routing.base_policy().map_err(DesktopError)?;
                        let policy = match &self.state.routing.ru_direct {
                            Some(reference) => controller.resolve(reference, base),
                            None => controller.prepare(base),
                        };
                        policy.map(|policy| {
                            let mut status = controller.status();
                            status.prepared = true;
                            if policy
                                .user_rules
                                .iter()
                                .chain(&policy.preset_rules)
                                .any(|rule| rule.enabled && !rule.conditions.executables.is_empty())
                            {
                                status.decision = Some("Application witness required".into());
                                return status;
                            }
                            use yonik_domain::{
                                Destination, DestinationFlow, Evaluation, EvaluationContext,
                                Resolution,
                            };
                            let destination = match (&ip, &name) {
                                (Ok(address), _) => Destination::Ip {
                                    address: *address,
                                    name: None,
                                },
                                (_, Ok(name)) => Destination::Name {
                                    name,
                                    resolution: Resolution::Missing,
                                },
                                _ => return status,
                            };
                            status.decision = Some(
                                match policy.evaluate_destination(
                                    &DestinationFlow {
                                        executable: None,
                                        destination,
                                    },
                                    &EvaluationContext::default(),
                                ) {
                                    Evaluation::Decided { decision, .. } => {
                                        format!("{:?} · {:?}", decision.action, decision.origin)
                                    }
                                    Evaluation::NeedResolution(_) => "DNS witness required".into(),
                                    Evaluation::Rejected(_) => "Evaluation rejected".into(),
                                },
                            );
                            status
                        })
                    }
                    _ => Ok(controller.status()),
                };
                match result {
                    Ok(status) => {
                        self.state.presets = status;
                        if request_id > 0 {
                            self.state.presets.ack = Some(presets::Ack {
                                request_id,
                                error: None,
                            });
                        }
                        Ok(())
                    }
                    Err(error) => {
                        self.state.presets = controller.status();
                        self.state.presets.operation_error = Some(presets::store_error(error));
                        self.state.presets.ack = Some(presets::Ack {
                            request_id,
                            error: Some(presets::store_error(error)),
                        });
                        if request_id > 0 {
                            return Ok(());
                        }
                        Err(DesktopError(match error {
                            yonik_linux::presets::Error::Busy => "busy",
                            _ => "storage",
                        }))
                    }
                }
            }

            Command::MaintenanceStart {
                request_id,
                operation,
                source,
                destination,
                revision,
            } => {
                // Supervisor допускает job; обычный dispatch сохраняет matching refusal ACK.
                let request = maintenance::Request {
                    request_id,
                    operation,
                    source,
                    destination,
                    revision,
                };
                let cause = if request.operation == maintenance::Operation::Backup
                    && request.source.is_some()
                {
                    Cause::MaintenanceAdmissionInvalidInput
                } else {
                    Cause::MaintenanceAdmissionBusy
                };
                let generation = self.state.maintenance_generation;
                maintenance_refusal(&mut self.state, request_id, cause, generation);
                Ok(())
            }
            Command::MaintenanceCancel { request_id } => {
                let generation = self.state.maintenance_generation;
                maintenance_refusal(
                    &mut self.state,
                    request_id,
                    Cause::MaintenanceAdmissionBusy,
                    generation,
                );
                Ok(())
            }
            #[cfg(feature = "test-support")]
            Command::LogsTest { reply } => {
                let _ = reply.send(self.state.ephemeral.then(|| self.event_log.clone()));
                Ok(())
            }
            Command::LogsSave {
                page_request_id,
                destination,
                request_id,
            } => {
                let status = self.logs_save.start(
                    &self.state.logs,
                    &page_request_id,
                    destination,
                    request_id.clone(),
                );
                self.state.clear_logs_contexts();
                self.state.logs = logs::Page {
                    request_id,
                    status,
                    ..Default::default()
                };
                self.state
                    .set_logs_context(Slot::LogsSave, self.logs_save.cause);
                Ok(())
            }
            Command::LogsRead {
                after,
                source,
                request_id,
            } => {
                self.state.clear_logs_contexts();
                self.state.logs = logs::Page::read(
                    &self.event_log,
                    after.parse().map_err(|_| DesktopError("invalid_input"))?,
                    source,
                    request_id,
                );
                self.state
                    .set_logs_context(Slot::LogsRead, self.state.logs.cause);
                Ok(())
            }
            Command::RoutingExplain {
                expected_revision,
                request_id,
                target,
            } => {
                let result = if self.routing_revision == Some(expected_revision) {
                    self.preset_policy(&self.state.routing).and_then(|policy| {
                        self.state
                            .routing
                            .explain_with_policy(&target, policy)
                            .map_err(DesktopError)
                    })
                } else {
                    Err(DesktopError("routing_stale"))
                };
                self.state.routing_explanation = match &result {
                    Ok(value) => {
                        serde_json::json!({"revision":expected_revision,"request_id":request_id,"result":value})
                    }
                    Err(_) => serde_json::Value::Null,
                };
                self.state
                    .error_contexts
                    .clear(crate::diagnostics::context::Slot::RoutingAck);
                self.state.routing_ack = Some(RoutingAck {
                    request_id,
                    saved_id: None,
                    error: result.as_ref().err().map(|e| e.key()),
                });
                result.map(|_| ())
            }
            Command::RoutingCatalog {
                request_id,
                processes,
                query,
                offset,
            } => {
                #[cfg(feature = "test-support")]
                let observer = self.catalog_observer.clone();
                self.state.routing_catalog = tokio::task::spawn_blocking(move || {
                    crate::editor::catalog(
                        processes,
                        &query,
                        offset,
                        #[cfg(feature = "test-support")]
                        observer,
                    )
                    .map(|page| catalog_response(request_id, page))
                })
                .await
                .map_err(|_| {
                    self.state.error_contexts.set_generation(
                        Slot::Error,
                        Cause::CatalogTaskFailed,
                        Some(self.state.command_generation),
                    );
                    DesktopError("catalog")
                })?
                .map_err(|key| {
                    if key == "catalog" {
                        self.state.error_contexts.set_generation(
                            Slot::Error,
                            Cause::CatalogQueryFailed,
                            Some(self.state.command_generation),
                        );
                    }
                    DesktopError(key)
                })?;
                Ok(())
            }
            Command::EditRouting {
                expected_revision,
                request_id,
                create,
                rule,
                confirm_broad,
            } => {
                self.mutate_routing(
                    expected_revision,
                    request_id,
                    RoutingMutation::Put {
                        rule,
                        confirm_broad,
                        create,
                    },
                )
                .await
            }
            Command::RoutingOrder {
                expected_revision,
                request_id,
                ids,
            } => {
                self.mutate_routing(expected_revision, request_id, RoutingMutation::Order(ids))
                    .await
            }
            Command::RoutingDelete {
                expected_revision,
                request_id,
                id,
            } => {
                self.mutate_routing(expected_revision, request_id, RoutingMutation::Delete(id))
                    .await
            }
            Command::RoutingDefault {
                expected_revision,
                request_id,
                action,
            } => {
                self.mutate_routing(
                    expected_revision,
                    request_id,
                    RoutingMutation::Default(action),
                )
                .await
            }
            Command::SetSubscriptionSchedule {
                interval_seconds,
                background,
            } => {
                if interval_seconds < 86400 {
                    return Err(DesktopError("invalid_input"));
                }
                let mut preferences = self.preferences.clone();
                preferences.subscription_interval_seconds = interval_seconds;
                preferences.subscription_background = background;
                self.save_preferences(preferences)?;
                self.state.subscription_interval_seconds = interval_seconds;
                self.state.subscription_background = background;
                Ok(())
            }
            Command::SetProxyFetchDns { upstream } => {
                // Смена конфигурации допускается после отзыва активной сессии.
                if self.state.can_stop {
                    return Err(DesktopError("busy"));
                }
                let address = if upstream.is_empty() {
                    None
                } else {
                    let address = upstream
                        .parse::<SocketAddr>()
                        .map_err(|_| DesktopError("invalid_input"))?;
                    if !crate::preferences::valid_proxy_fetch_dns(address) {
                        return Err(DesktopError("invalid_input"));
                    }
                    Some(address)
                };
                let mut preferences = self.preferences.clone();
                preferences.proxy_fetch_dns = address;
                self.save_preferences(preferences)?;
                self.state.proxy_fetch_dns = address;
                Ok(())
            }
            Command::SetSystemFakeDns { suffixes } => {
                if self.state.can_stop
                    || self.state.system_busy
                    || self.state.system_recovery_pending
                {
                    return Err(DesktopError("busy"));
                }
                let mut suffixes = suffixes
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|suffix| !suffix.is_empty())
                    .map(|suffix| {
                        suffix
                            .parse::<yonik_domain::DomainName>()
                            .map(|name| name.as_str().to_owned())
                            .map_err(|_| DesktopError("invalid_input"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                if !crate::preferences::valid_system_fake_dns(&suffixes) {
                    return Err(DesktopError("invalid_input"));
                }
                suffixes.sort_unstable();
                suffixes.dedup();
                let mut preferences = self.preferences.clone();
                preferences.system_fake_dns.clone_from(&suffixes);
                self.save_preferences(preferences)?;
                self.state.system_fake_dns = suffixes;
                Ok(())
            }
            Command::SetLanguage { language } => {
                if !matches!(language.as_str(), "ru" | "en") {
                    return Err(DesktopError("invalid_input"));
                }
                let mut preferences = self.preferences.clone();
                preferences.language = language.clone();
                self.save_preferences(preferences)?;
                self.state.language = language;
                Ok(())
            }
            Command::ResetListenPort => {
                if self.state.can_stop {
                    return Err(DesktopError("busy"));
                }
                let port = available_port(0)?.get();
                let mut preferences = self.preferences.clone();
                preferences.port = None;
                self.save_preferences(preferences)?;
                self.state.port = port;
                self.automatic_port = true;
                Ok(())
            }
            Command::SetEngine { engine } => {
                if self.state.can_stop {
                    return Err(DesktopError("busy"));
                }
                if matches!(engine, EngineChoice::SingBox) {
                    self.state.ensure_connection_engine(engine)?;
                }
                let mut preferences = self.preferences.clone();
                preferences.engine = match engine {
                    EngineChoice::Xray => "xray",
                    EngineChoice::SingBox => "sing-box",
                }
                .into();
                self.save_preferences(preferences)?;
                self.state.engine = engine;
                Ok(())
            }
            Command::SetListenPort { port } => {
                if self.state.can_stop {
                    return Err(DesktopError("busy"));
                }
                let mut preferences = self.preferences.clone();
                preferences.port = Some(port);
                self.save_preferences(preferences)?;
                self.state.port = port.get();
                self.automatic_port = false;
                Ok(())
            }
            Command::SetProbeTarget {
                url,
                expected_status,
            } => {
                if self.state.can_stop {
                    return Err(DesktopError("busy"));
                }
                let url = Zeroizing::new(url);
                ProbeTarget::new(&url, PROBE_TIMEOUT)
                    .and_then(|target| target.with_expected_status(expected_status))
                    .map_err(|_| DesktopError("probe_target_invalid"))?;
                let mut preferences = self.preferences.clone();
                let persistent = !url.contains(['@', '?', '#']);
                preferences.probe_url = if persistent {
                    url.to_string()
                } else {
                    DEFAULT_PROBE_URL.into()
                };
                preferences.probe_status = if persistent { expected_status } else { 204 };
                self.save_preferences(preferences)?;
                self.probe_url = url;
                self.state.probe_custom = true;
                self.state.probe_persistent = persistent;
                self.state.probe_expected_status = expected_status;
                self.state.probe_result = None;
                Ok(())
            }
            Command::ResetProbeTarget => {
                if self.state.can_stop {
                    return Err(DesktopError("busy"));
                }
                let mut preferences = self.preferences.clone();
                preferences.probe_url = DEFAULT_PROBE_URL.into();
                preferences.probe_status = 204;
                self.save_preferences(preferences)?;
                self.probe_url = Zeroizing::new(DEFAULT_PROBE_URL.into());
                self.state.probe_custom = false;
                self.state.probe_persistent = true;
                self.state.probe_expected_status = 204;
                self.state.probe_result = None;
                Ok(())
            }
            _ => Err(DesktopError("invalid_input")),
        }
    }
    async fn persist_refresh_completion(
        &self,
        identity: SubscriptionIdentity,
        success: bool,
    ) -> SourceResult<()> {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.service()
            .record_schedule_completion(identity, success, wall)
            .await
            .map_err(SourceFailure::subscription)
    }
    async fn refreshed(
        &mut self,
        identity: SubscriptionIdentity,
        result: std::result::Result<RefreshResult, SubscriptionError>,
    ) -> SourceResult<()> {
        let outcome = match result.map_err(SourceFailure::subscription) {
            Err(error) => Err(error),
            Ok(result) => match result {
                RefreshResult::NotModified => self.page().await,
                RefreshResult::Pending(pending) => {
                    let summary = pending.summary();
                    if summary.needs_review() {
                        self.state.pending = Some(pending_dto(&pending, 0)?);
                        self.pending = Some(pending);
                        Ok(())
                    } else {
                        self.service()
                            .commit(
                                pending
                                    .accept_clean()
                                    .map_err(SourceFailure::subscription)?,
                            )
                            .await
                            .map_err(SourceFailure::subscription)?;
                        self.clear_selection();
                        self.page().await
                    }
                }
            },
        };
        if self.pending.is_none() {
            self.persist_refresh_completion(identity, outcome.is_ok())
                .await?;
        }
        outcome
    }
}

// Всегда дожидается ACK/drain; проверка поколения относится только к публикации.
async fn await_current_schedule<T>(
    operation: impl std::future::Future<Output = T>,
    current: &AtomicU64,
    expected: u64,
) -> Option<T> {
    let outcome = operation.await;
    (current.load(Ordering::SeqCst) == expected).then_some(outcome)
}

fn map_subscription(error: SubscriptionError) -> DesktopError {
    DesktopError(match error {
        SubscriptionError::InvalidSource => "invalid_input",
        SubscriptionError::Fetch(FetchError::HwidRequired) => "hwid_required",
        SubscriptionError::Fetch(FetchError::HwidLimit) => "hwid_limit",
        SubscriptionError::Fetch(FetchError::HwidRejected) => "hwid_rejected",
        SubscriptionError::Fetch(FetchError::HwidRedirect) => "hwid_redirect",
        SubscriptionError::Fetch(FetchError::UnsupportedPeerVerification) => "unsupported_proxy",
        SubscriptionError::Fetch(_) => "fetch",
        SubscriptionError::Import(_) => "import",
        _ => "storage",
    })
}

struct SessionUpdate {
    status: &'static str,
    error: Option<&'static str>,
    context: Option<Cause>,
    generation: Option<u64>,
    probe_result: Option<HealthResultDto>,
    network_stamp: Option<NetworkStamp>,
}

fn probe_session_update(
    result: ProbeResult,
    target: &ProbeTarget,
    generation: u64,
    network_stamp: Option<NetworkStamp>,
    network_observed: bool,
) -> SessionUpdate {
    let passed = target.accepts(result);
    let context = (!passed).then_some(match result {
        ProbeResult::Response { .. } => Cause::ProbeHttpStatus,
        ProbeResult::Timeout => Cause::ProbeTimeout,
        ProbeResult::Tls => Cause::ProbeTls,
        ProbeResult::Transport => Cause::ProbeTransport,
    });
    let error = context.map(|cause| ContextFailure::new(cause).error.key());
    let mut proof: HealthResultDto = result.into();
    proof.network_epoch = network_stamp.map(|stamp| stamp.to_string());
    proof.network_observed = network_observed;
    SessionUpdate {
        context,
        generation: Some(generation),
        status: if passed { "Connected" } else { "Limited" },
        error,
        probe_result: Some(proof),
        network_stamp,
    }
}

fn probe_operation_error(error: HostError, cause: &mut Option<Cause>) -> &'static str {
    if error == HostError::Cancelled {
        *cause = None;
        "cancelled"
    } else {
        *cause = Some(Cause::ProbeCheckFailed);
        "check_failed"
    }
}

fn network_matches(network: Option<NetworkSnapshot>, stamp: Option<NetworkStamp>) -> bool {
    match (network, stamp) {
        (Some(network), Some(stamp)) => network.is_current(stamp),
        (None, None) => true,
        _ => false,
    }
}

fn apply_session_update(
    state: &mut Snapshot,
    update: SessionUpdate,
    network: Option<NetworkSnapshot>,
) {
    if update
        .generation
        .is_some_and(|generation| generation != state.error_generation)
    {
        return;
    }
    state
        .error_contexts
        .clear(crate::diagnostics::context::Slot::Error);
    state
        .error_contexts
        .clear(crate::diagnostics::context::Slot::Connection);
    if update.network_stamp.is_some() && !network_matches(network, update.network_stamp) {
        state.status = "Limited";
        state
            .error_contexts
            .clear(crate::diagnostics::context::Slot::Error);
        state.error = Some("network_changed");
        state
            .error_contexts
            .clear(crate::diagnostics::context::Slot::Connection);
        state.connection_error = Some("network_changed");
        state.error_contexts.set_generation(
            Slot::Error,
            Cause::ProbeNetworkChanged,
            Some(state.error_generation),
        );
        state.error_contexts.set_generation(
            Slot::Connection,
            Cause::ProbeNetworkChanged,
            Some(state.error_generation),
        );
        state.probe_result = None;
        return;
    }
    state.status = update.status;
    state
        .error_contexts
        .clear(crate::diagnostics::context::Slot::Error);
    state.error = update.error;
    state
        .error_contexts
        .clear(crate::diagnostics::context::Slot::Connection);
    state.connection_error = update.error;
    if let Some(cause) = update.context.filter(|cause| {
        crate::diagnostics::context::ErrorContext::new(Slot::Error, *cause, None).message_key
            == update.error.unwrap_or("")
    }) {
        state
            .error_contexts
            .set_generation(Slot::Error, cause, update.generation);
        state
            .error_contexts
            .set_generation(Slot::Connection, cause, update.generation);
    }
    if let Some(result) = update.probe_result {
        state.probe_result = Some(result);
    }
}

fn synchronize_network(state: &mut Snapshot, network: Option<NetworkSnapshot>) {
    let epoch = network.map(|network| network.stamp.to_string());
    let changed = state.network_epoch != epoch || network.is_some_and(|network| network.exhausted);
    state.network_epoch = epoch;
    state.network_observed = network.is_some_and(NetworkSnapshot::fully_observed);
    let coverage = network.map(|network| network.coverage).unwrap_or_default();
    state.network_routes = coverage.routes;
    state.network_resolver = coverage.resolver;
    state.network_manager = coverage.manager;
    if changed {
        state.tcp_invalidated |= state.tcp_result.is_some() || state.tcp_busy;
        state.tcp_result = None;
        state.probe_result = None;
        if matches!(state.status, "Checking" | "Connected" | "Limited") {
            state.status = "Limited";
            state
                .error_contexts
                .clear(crate::diagnostics::context::Slot::Error);
            state.error = Some("network_changed");
            state
                .error_contexts
                .clear(crate::diagnostics::context::Slot::Connection);
            state.connection_error = Some("network_changed");
            state.error_contexts.set_generation(
                Slot::Error,
                Cause::ProbeNetworkChanged,
                Some(state.error_generation),
            );
            state.error_contexts.set_generation(
                Slot::Connection,
                Cause::ProbeNetworkChanged,
                Some(state.error_generation),
            );
        }
    }
}

fn apply_network_event(state: &mut Snapshot, network: Option<NetworkSnapshot>, control: &Control) {
    let changed = state.network_epoch != network.map(|network| network.stamp.to_string())
        || network.is_some_and(|network| network.exhausted);
    if changed {
        // Отменяем также CheckTcp, уже принятые UI, но ещё ожидающие в очереди.
        control.cancel_tcp();
    }
    synchronize_network(state, network);
}

async fn network_changed(network: &mut Option<NetworkWatch>) {
    match network {
        Some(watch) => {
            if watch.changed().await.is_err() {
                *network = None;
            }
        }
        None => std::future::pending().await,
    }
}

async fn network_invalidated(network: &mut Option<NetworkWatch>, stamp: Option<NetworkStamp>) {
    loop {
        if !network_matches(network.as_ref().map(NetworkWatch::current), stamp) {
            return;
        }
        network_changed(network).await;
    }
}

#[cfg(test)]
mod settings_tests {
    use super::{Actor, DEFAULT_PROBE_URL, HostConfig, Snapshot, Store, open};
    use std::{
        fs,
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    use zeroize::Zeroizing;

    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("очистка своего тестового каталога");
        }
    }

    #[test]
    fn hwid_fetch_failures_have_specific_public_codes() {
        for (error, key) in [
            (super::FetchError::HwidRequired, "hwid_required"),
            (super::FetchError::HwidLimit, "hwid_limit"),
            (super::FetchError::HwidRejected, "hwid_rejected"),
            (super::FetchError::HwidRedirect, "hwid_redirect"),
        ] {
            assert_eq!(
                super::map_subscription(super::SubscriptionError::Fetch(error)).key(),
                key
            );
        }
    }

    #[test]
    fn udp_collision_is_detected_without_touching_occupied_socket() {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("UDP fixture");
        let port = udp.local_addr().expect("адрес").port();
        assert_eq!(
            super::available_port(port).expect_err("UDP занят").key(),
            "listen_port_busy"
        );
        let automatic = super::available_port(0).expect("автопорт");
        assert_ne!(automatic.get(), port);
        assert!(udp.local_addr().is_ok());
    }

    #[tokio::test]
    async fn listen_port_is_busy_during_active_session_and_failed_cleanup() {
        let path = std::env::temp_dir().join(format!(
            "yonik-desktop-settings-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("часы")
                .as_nanos()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("создание собственного тестового каталога");
        let directory = Directory(path);
        let mut config = HostConfig::new(directory.0.clone(), directory.0.join("engines"))
            .with_ephemeral_key([77; 32]);
        let (service, _lock, routing_repository) = open(&mut config).await.expect("тестовая БД");
        let (preferences_store, preferences, _) = Store::open(&directory.0);
        let mut actor = Actor {
            #[cfg(feature = "test-support")]
            catalog_observer: None,
            presets: crate::backend::presets::Controller::open(&config.data_dir.join("presets"))
                .ok()
                .map(Arc::new),
            event_log: yonik_linux::event_log::EventLog::new(),
            logs_save: crate::backend::logs::SaveJob::default(),
            routing_repository: Some(routing_repository),
            format4_backup: None,
            routing_revision: Some(0),
            preferences_store,
            preferences,
            service: Some(service),
            state: Snapshot::new(true),
            callback: Arc::new(|_| {}),
            selected: None,
            selected_native: None,
            selected_native_token: None,
            catalog_selections: Vec::new(),
            catalog_coordinates: None,
            pending: None,
            automatic_port: true,
            probe_url: Zeroizing::new(DEFAULT_PROBE_URL.into()),
            network: None,
        };
        actor.state.port = 18888;
        actor.state.can_stop = true;
        for status in ["Preparing", "Connected", "CleanupError"] {
            actor.state.status = status;
            let command = serde_json::from_str(r#"{"command":"set_listen_port","port":18889}"#)
                .expect("команда настройки");
            assert_eq!(
                actor
                    .command(command)
                    .await
                    .expect_err("сессия удерживается")
                    .key(),
                "busy"
            );
            assert_eq!(actor.state.port, 18888);
            for raw in [
                r#"{"command":"set_engine","engine":"sing-box"}"#,
                r#"{"command":"set_probe_target","url":"https://example.com/","expected_status":200}"#,
                r#"{"command":"reset_probe_target"}"#,
                r#"{"command":"reset_listen_port"}"#,
            ] {
                let command = serde_json::from_str(raw).expect("настройка");
                assert_eq!(
                    actor
                        .command(command)
                        .await
                        .expect_err("снимок сессии неизменен")
                        .key(),
                    "busy"
                );
            }
            let command =
                serde_json::from_str(r#"{"command":"delete_source","id":1}"#).expect("удаление");
            assert_eq!(
                actor
                    .source_command(command)
                    .await
                    .expect_err("активное ядро")
                    .key(),
                "source_in_use"
            );
            assert!(actor.state.can_stop);
            assert_eq!(actor.state.status, status);
        }
        // После подтверждённого освобождения сессии настройка снова применима.
        actor.state.can_stop = false;
        let command = serde_json::from_str(r#"{"command":"set_listen_port","port":18889}"#)
            .expect("команда настройки");
        actor.command(command).await.expect("сессия освобождена");
        assert_eq!(actor.state.port, 18889);
        actor.state.startup.xdg_root = Some(directory.0.clone());
        let control = super::Control {
            generation: std::sync::atomic::AtomicU64::new(0),
            priority: tokio::sync::watch::channel(super::Priority::default()).0,
            tcp_priority: tokio::sync::watch::channel(0).0,
            subscription_policy: tokio::sync::watch::channel(Default::default()).0,
            subscription_override: std::sync::atomic::AtomicBool::new(false),
            subscription_visible: tokio::sync::watch::channel(false).0,
            closed: (std::sync::Mutex::new(false), std::sync::Condvar::new()),
        };
        let attempt = actor.state.startup.attempt;
        actor.state.startup.xdg = "applied";
        let (mut external_store, _, _) = Store::open(&directory.0);
        let (mut external, _) = external_store
            .save_startup(0, true, false, None)
            .expect("cooperating writer");
        external.language = "en".into();
        external_store
            .save(&external)
            .expect("mixed external prefs");
        let published = fs::read(directory.0.join("preferences.json")).expect("published");
        let conflict = actor
            .startup_save("1".into(), "0".into(), Some((false, true)), &control, 0)
            .await
            .expect_err("stale writer");
        assert_eq!(conflict.key(), "startup_conflict");
        assert_eq!(actor.state.startup.revision, "1");
        assert_eq!(actor.state.startup.xdg, "unchanged");
        assert!(actor.state.startup.autostart_into_tray && !actor.state.startup.autoconnect);
        assert_eq!(actor.preferences.language, "en");
        assert_eq!(actor.state.startup.attempt, attempt);
        assert!(actor.preferences.repository_identity.is_none());
        assert!(actor.selected.is_none());
        assert!(!actor.state.can_stop);
        assert!(!directory.0.join("autostart").exists());
        assert_eq!(
            fs::read(directory.0.join("preferences.json")).expect("no auto retry"),
            published
        );
        actor
            .startup_save("2".into(), "1".into(), Some((false, true)), &control, 0)
            .await
            .expect("explicit retry");
        assert_eq!(actor.state.startup.revision, "2");
        assert!(!actor.state.startup.autostart_into_tray && actor.state.startup.autoconnect);
        assert_eq!(actor.state.startup.attempt, attempt);
        assert!(!actor.state.can_stop);
        actor.preferences_store.sync_directory =
            |_| Err(std::io::Error::other("инъекция dir fsync"));
        actor
            .command(
                serde_json::from_str(r#"{"command":"set_language","language":"en"}"#)
                    .expect("язык"),
            )
            .await
            .expect("опубликованное изменение применено");
        assert_eq!(actor.state.language, "en");
        assert_eq!(actor.preferences.language, "en");
        assert!(actor.state.preferences_durability_warning);
        assert_eq!(Store::open(&directory.0).1.language, "en");
        actor.state.startup.xdg_root = Some(directory.0.clone());

        actor
            .startup_save("3".into(), "2".into(), Some((true, true)), &control, 0)
            .await
            .expect("published");
        assert_eq!(actor.state.startup.save, "durability_unknown");
        assert_eq!(actor.state.startup.xdg, "not_applied");
        assert!(!directory.0.join("autostart").exists());
        assert!(
            super::startup_application::prepare(&mut actor, &control, 0)
                .await
                .0
                .is_none()
        );
        actor
            .service
            .take()
            .expect("online service перед закрытием")
            .close()
            .await
            .expect("закрытие БД");
    }
}

#[cfg(test)]
mod error_scope_tests {
    use super::{Command, SessionUpdate, Snapshot, apply_session_update};

    #[test]
    fn metadata_query_does_not_clear_download_error() {
        let mut state = Snapshot::new(true);
        state.command_error(true, "hwid_required");
        let command: Command = serde_json::from_str(
            r#"{"command":"query","search":"","favorites_only":false,"offset":0}"#,
        )
        .expect("query");
        state.begin_command(&command);
        assert_eq!(state.source_error, Some("hwid_required"));
    }

    #[test]
    fn session_updates_and_source_commands_keep_independent_errors() {
        let mut state = Snapshot::new(true);
        state.command_error(true, "hwid_required");
        apply_session_update(
            &mut state,
            SessionUpdate {
                context: None,
                generation: None,
                status: "Connected",
                error: None,
                probe_result: None,
                network_stamp: None,
            },
            None,
        );
        assert_eq!(state.source_error, Some("hwid_required"));
        assert_eq!(state.connection_error, None);
        assert_eq!(state.status, "Connected");
        state.command_error(false, "engine_failed");
        state.begin_command(&Command::Refresh);
        assert_eq!(state.source_error, None);
        assert_eq!(state.connection_error, Some("engine_failed"));
        assert_eq!(state.status, "Connected");
        state.command_error(true, "fetch");
        state.begin_command(&Command::Connect);
        assert_eq!(state.source_error, Some("fetch"));
        assert_eq!(state.connection_error, None);
        apply_session_update(
            &mut state,
            SessionUpdate {
                context: None,
                generation: None,
                status: "Disconnected",
                error: Some("engine_missing"),
                probe_result: None,
                network_stamp: None,
            },
            None,
        );
        assert_eq!(state.source_error, Some("fetch"));
        assert_eq!(state.connection_error, Some("engine_missing"));
        assert_eq!(state.error, Some("engine_missing"));
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;

    #[tokio::test]
    async fn network_change_invalidates_tcp_commands_already_in_queue() {
        let first = NetworkMonitor::start().expect("первый наблюдатель");
        let second = NetworkMonitor::start().expect("второй наблюдатель");
        let (priority, _) = watch::channel(Priority::default());
        let (tcp_priority, _) = watch::channel(0);
        let control = Control {
            generation: AtomicU64::new(0),
            priority,
            tcp_priority,
            subscription_policy: watch::channel(Default::default()).0,
            subscription_override: std::sync::atomic::AtomicBool::new(false),
            subscription_visible: watch::channel(false).0,
            closed: (Mutex::new(false), Condvar::new()),
        };
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .try_send(Envelope {
                generation: 0,
                tcp_generation: *control.tcp_priority.borrow(),
                command: Command::CheckTcp,
            })
            .expect("проверка уже в очереди");
        let mut state = Snapshot::new(true);
        synchronize_network(&mut state, Some(first.watch().current()));
        apply_network_event(&mut state, Some(second.watch().current()), &control);
        let queued = receiver.recv().await.expect("ожидавшая команда");
        assert_ne!(queued.tcp_generation, *control.tcp_priority.borrow());
        let generation = *control.tcp_priority.borrow();
        apply_network_event(&mut state, Some(second.watch().current()), &control);
        assert_eq!(
            generation,
            *control.tcp_priority.borrow(),
            "повтор snapshot не отменяет новую ручную команду"
        );
        first.shutdown().await;
        second.shutdown().await;
    }

    #[tokio::test]
    async fn late_success_from_previous_network_cannot_restore_connected() {
        let first = NetworkMonitor::start().expect("первый наблюдатель");
        let second = NetworkMonitor::start().expect("второй наблюдатель");
        let mut state = Snapshot::new(true);
        state.status = "Limited";
        apply_session_update(
            &mut state,
            SessionUpdate {
                context: None,
                generation: None,
                status: "Connected",
                error: None,
                probe_result: Some(ProbeResult::Timeout.into()),
                network_stamp: Some(first.watch().current().stamp),
            },
            Some(second.watch().current()),
        );
        assert_eq!(state.status, "Limited");
        assert_eq!(state.error, Some("network_changed"));
        assert!(state.probe_result.is_none());
        first.shutdown().await;
        second.shutdown().await;
    }

    #[tokio::test]
    async fn new_network_removes_old_proof_without_stopping_core() {
        let first = NetworkMonitor::start().expect("первый наблюдатель");
        let second = NetworkMonitor::start().expect("второй наблюдатель");
        let mut state = Snapshot::new(true);
        state.network_epoch = Some(first.watch().current().stamp.to_string());
        state.status = "Connected";
        state.can_stop = true;
        state.probe_result = Some(ProbeResult::Timeout.into());
        state.tcp_busy = true;
        synchronize_network(&mut state, Some(second.watch().current()));
        assert!(state.probe_result.is_none());
        assert!(state.tcp_invalidated);
        assert_eq!(state.status, "Limited");
        assert!(state.can_stop);
        first.shutdown().await;
        second.shutdown().await;
    }
}
#[cfg(test)]
mod tcp_series_tests {
    use super::{TCP_SERIES_SAMPLES, TcpProbeSeriesResult, TcpProbeStatus, TcpResultDto};
    use std::time::Duration;

    #[test]
    fn cancelled_or_incomplete_series_cannot_publish_a_median() {
        let mut dto = TcpResultDto {
            source_id: 1,
            profile_id: 2,
            revision: 3,
            name: "Проверка".into(),
            host: "127.0.0.1".into(),
            port: 443,
            status: "cancelled",
            dns_ms: None,
            connect_ms: None,
            samples_ms: Vec::new(),
            samples_requested: TCP_SERIES_SAMPLES,
            selected_address: None,
            checked_at_ms: 0,
            network_epoch: None,
            network_observed: false,
        };
        for (status, count, expected) in [
            (TcpProbeStatus::Reachable, 3, Some(10)),
            (TcpProbeStatus::Cancelled, 3, None),
            (TcpProbeStatus::ConnectFailure, 1, None),
            (TcpProbeStatus::Reachable, 2, None),
        ] {
            // Поздняя отмена меняет status уже завершённой серии. Сохранённая
            // внутри неё median не должна обойти проверку при публикации DTO.
            dto.finish(TcpProbeSeriesResult {
                status,
                dns_elapsed: None,
                selected_address: Some("127.0.0.1:443".parse().expect("адрес")),
                samples: vec![Duration::from_millis(10); count],
                median: Some(Duration::from_millis(10)),
            });
            assert_eq!(dto.connect_ms, expected);
            assert_eq!(dto.samples_ms.len(), count);
        }
    }
}

#[derive(Serialize)]
struct HealthResultDto {
    kind: &'static str,
    http_status: Option<u16>,
    elapsed_ms: Option<u64>,
    network_epoch: Option<String>,
    network_observed: bool,
}
impl From<ProbeResult> for HealthResultDto {
    fn from(result: ProbeResult) -> Self {
        match result {
            ProbeResult::Response { status, elapsed } => Self {
                kind: "http",
                http_status: Some(status),
                elapsed_ms: Some(elapsed.as_millis().min(u64::MAX as u128) as u64),
                network_epoch: None,
                network_observed: false,
            },
            other => Self {
                kind: match other {
                    ProbeResult::Timeout => "timeout",
                    ProbeResult::Tls => "tls",
                    _ => "transport",
                },
                http_status: None,
                elapsed_ms: None,
                network_epoch: None,
                network_observed: false,
            },
        }
    }
}
/// Сохраняет настроенный интервал поверх legacy reservation/completion, не меняя
/// API ручного refresh. Retry due и новое поколение не перезаписываются.
async fn extend_schedule_interval(
    service: &SubscriptionService,
    identity: SubscriptionIdentity,
    interval: Duration,
) -> std::result::Result<(), desktop_schedule::ScheduleFailure> {
    if interval <= Duration::from_secs(86400) {
        return Ok(());
    }
    let Some(token) = service
        .schedule_metadata(identity.id)
        .await
        .map_err(desktop_schedule::ScheduleFailure::service)?
    else {
        return Err(DesktopError("storage").into());
    };
    if token.generation != identity.generation {
        return Err(DesktopError("storage").into());
    }
    let Some(state) = token
        .state
        .filter(|state| state.due_wall == state.recorded_wall.checked_add(86400))
    else {
        return Ok(());
    };
    service
        .persist_schedule(
            token,
            yonik_linux::ScheduleState {
                due_wall: state.recorded_wall.checked_add(interval.as_secs()),
                ..state
            },
        )
        .await
        .map_err(desktop_schedule::ScheduleFailure::service)
}

/// Completion старого ресурса не отменяет очередь/review нового поколения.
async fn reconcile_manual_schedule(
    scheduled: &mut DesktopSchedule,
    service: &SubscriptionService,
    identity: SubscriptionIdentity,
    clock: impl Fn() -> Duration,
    storage_failed: bool,
) -> std::result::Result<(), desktop_schedule::ScheduleFailure> {
    if service
        .schedule_generation(identity.id)
        .await
        .map_err(desktop_schedule::ScheduleFailure::service)?
        != Some(identity.generation)
    {
        return Ok(());
    }
    scheduled.cancel(identity.id, &clock).await?;
    if !storage_failed {
        extend_schedule_interval(service, identity, scheduled.interval).await?;
        scheduled.reload_id(service, identity.id, clock()).await?;
    }
    Ok(())
}

type RefreshTask = (
    u64,
    watch::Sender<bool>,
    tokio::task::JoinHandle<std::result::Result<RefreshResult, SubscriptionError>>,
    SubscriptionIdentity,
    String,
);

#[cfg(feature = "test-support")]
#[derive(Default)]
struct ScheduleTrace {
    window_origin: Option<Duration>,
    drain_id: u64,
    previous: Option<serde_json::Value>,
}
#[cfg(feature = "test-support")]
impl ScheduleTrace {
    fn emit(
        &mut self,
        config: &HostConfig,
        scheduled: &DesktopSchedule,
        lease: ProxyLease,
        now: Duration,
        phase: &'static str,
    ) {
        let Some((sender, overflow)) = &config.schedule_trace else {
            return;
        };
        if scheduled.window_until.is_none() {
            self.window_origin = None;
        }
        let row = serde_json::json!({"phase":phase,"window_origin_ns":self.window_origin.map(|d| d.as_nanos()),"window_deadline_ns":scheduled.window_until.map(|d|d.as_nanos()),"scheduled_generation":scheduled.generation,"lease_generation":lease.map(|l|l.0),"drain_id":self.drain_id,"fetching":scheduled.fetching});
        if self.previous.as_ref() == Some(&row) {
            return;
        }
        self.previous = Some(row.clone());
        let mut event = row;
        event["at_ns"] = serde_json::json!(now.as_nanos());
        if sender.try_send(event).is_err() {
            overflow.store(true, Ordering::Release);
        }
    }
    fn begin_drain(&mut self, config: &HostConfig) {
        match self.drain_id.checked_add(1) {
            Some(id) => self.drain_id = id,
            None => {
                if let Some((_, overflow)) = &config.schedule_trace {
                    overflow.store(true, Ordering::Release);
                }
            }
        }
    }
}

type ProxyLease = Option<(u64, SocketAddr)>;

/// Снимок подтверждённой сессии на операцию; изменение watch отзывает путь.
struct DesktopFetch {
    lease: ProxyLease,
    proxy_fetch_dns: Option<SocketAddr>,
    current: watch::Receiver<ProxyLease>,
    proxy_used: AtomicBool,
    #[cfg(feature = "test-support")]
    test_fetch: Option<Arc<yonik_linux::FetchHost>>,
}
impl DesktopFetch {
    fn new(current: &watch::Sender<ProxyLease>, proxy_fetch_dns: Option<SocketAddr>) -> Arc<Self> {
        Self::subscription(
            current,
            proxy_fetch_dns,
            #[cfg(feature = "test-support")]
            None,
        )
    }
    fn subscription(
        current: &watch::Sender<ProxyLease>,
        proxy_fetch_dns: Option<SocketAddr>,
        #[cfg(feature = "test-support")] test_fetch: Option<Arc<yonik_linux::FetchHost>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            lease: *current.borrow(),
            proxy_fetch_dns,
            current: current.subscribe(),
            proxy_used: AtomicBool::new(false),
            #[cfg(feature = "test-support")]
            test_fetch,
        })
    }
    fn stale(&self) -> bool {
        let revoked = *self.current.borrow() != self.lease;
        // Stop уведомляет тот же watch даже при None→None: fixture не теряет revoke.
        #[cfg(feature = "test-support")]
        let revoked =
            revoked || (self.test_fetch.is_some() && self.current.has_changed().unwrap_or(true));
        self.proxy_used.load(Ordering::Acquire) && revoked
    }
}
impl yonik_linux::SubscriptionFetch for DesktopFetch {
    fn fetch<'a>(
        &'a self,
        source: &'a yonik_linux::Source,
        route: FetchRoute,
        validators: Option<&'a yonik_linux::FetchValidators>,
        cancel: watch::Receiver<bool>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::result::Result<yonik_linux::FetchResponse, FetchError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            #[cfg(feature = "test-support")]
            if let Some(host) = &self.test_fetch {
                if route == FetchRoute::Proxy {
                    self.proxy_used.store(true, Ordering::Release);
                }
                if self.stale() {
                    return Err(FetchError::Cancelled);
                }
                let mut current = self.current.clone();
                return tokio::select! {
                    biased;
                    _ = current.changed() => Err(FetchError::Cancelled),
                    result = host.fetch(source, route, validators, cancel) => {
                        if self.stale() { Err(FetchError::Cancelled) } else { result }
                    }
                };
            }
            let mut host = yonik_linux::FetchHost::new(Duration::from_secs(30))?;
            if route == FetchRoute::Direct {
                return host.fetch(source, route, validators, cancel).await;
            }
            self.proxy_used.store(true, Ordering::Release);
            if self.stale() {
                return Err(FetchError::Cancelled);
            }
            let Some((_, endpoint)) = self.lease else {
                return Err(FetchError::UnsupportedPeerVerification);
            };
            host = host.with_socks_endpoint(endpoint)?;
            if let Some(upstream) = self.proxy_fetch_dns {
                host = host.with_proxy_dns(upstream)?;
            }
            let mut current = self.current.clone();
            tokio::select! {
                biased;
                _ = current.changed() => Err(FetchError::Cancelled),
                result = host.fetch(source, route, validators, cancel) => {
                    if self.stale() { Err(FetchError::Cancelled) } else { result }
                }
            }
        })
    }
}

struct Running {
    lease: (u64, SocketAddr),
    cancel: watch::Sender<bool>,
    task: tokio::task::JoinHandle<std::result::Result<(), LocalSession>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TcpKey {
    source: i64,
    profile: i64,
    revision: i64,
}
#[derive(Clone, Serialize)]
struct TcpResultDto {
    source_id: i64,
    profile_id: i64,
    revision: i64,
    name: String,
    host: String,
    port: u16,
    status: &'static str,
    dns_ms: Option<u64>,
    connect_ms: Option<u64>,
    samples_ms: Vec<u64>,
    samples_requested: usize,
    selected_address: Option<String>,
    checked_at_ms: u64,
    network_epoch: Option<String>,
    network_observed: bool,
}
impl TcpResultDto {
    fn key(&self) -> TcpKey {
        TcpKey {
            source: self.source_id,
            profile: self.profile_id,
            revision: self.revision,
        }
    }
    fn finish(&mut self, result: TcpProbeSeriesResult) {
        self.status = match result.status {
            TcpProbeStatus::Reachable => "reachable",
            TcpProbeStatus::NotApplicable => "not_applicable",
            TcpProbeStatus::ResolverUnavailable => "resolver_unavailable",
            TcpProbeStatus::DnsFailure => "dns_failed",
            TcpProbeStatus::ConnectFailure => "connect_failed",
            TcpProbeStatus::DnsTimeout => "dns_timeout",
            TcpProbeStatus::ConnectTimeout => "connect_timeout",
            TcpProbeStatus::Cancelled => "cancelled",
        };
        let millis = |duration: Duration| duration.as_millis().min(u64::MAX as u128) as u64;
        self.dns_ms = result.dns_elapsed.map(millis);
        self.connect_ms = if result.status == TcpProbeStatus::Reachable
            && result.samples.len() == TCP_SERIES_SAMPLES
        {
            result.median.map(millis)
        } else {
            None
        };
        self.samples_ms = result.samples.into_iter().map(millis).collect();
        self.selected_address = result.selected_address.map(|address| address.to_string());
        self.checked_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(millis)
            .unwrap_or_default();
    }
}
struct TcpRunning {
    generation: u64,
    tcp_generation: u64,
    network_stamp: Option<NetworkStamp>,
    result: TcpResultDto,
    cancel: watch::Sender<bool>,
    task: tokio::task::JoinHandle<std::result::Result<TcpProbeSeriesResult, HostError>>,
}

enum SessionConfig {
    Server(yonik_engine::CompiledConfig),
    FullProfile(Box<NativeSessionConfig>),
}
struct NativeSessionConfig {
    intent: yonik_engine::native_profile::ProfileIntent,
    plan: yonik_engine::native_profile::OwnedRuntimePlan,
    image: Option<BinarySnapshot>,
}
#[cfg_attr(feature = "test-support", allow(clippy::too_many_arguments))]
async fn session(
    mut config: SessionConfig,
    engine_dir: PathBuf,
    engine: Engine,
    target: ProbeTarget,
    mut cancel: Cancellation,
    updates: (
        mpsc::Sender<SessionUpdate>,
        yonik_linux::event_log::EventLog,
        u64,
    ),
    mut network: Option<NetworkWatch>,
    #[cfg(feature = "test-support")] cleanup_fault: Option<Arc<AtomicBool>>,
) -> std::result::Result<(), LocalSession> {
    let (updates, event_log, generation) = updates;
    if cancel.check().is_err() {
        return Ok(());
    }
    if matches!(&config, SessionConfig::FullProfile(native) if yonik_linux::full_profile_plan_preflight(yonik_linux::FullProfileMode::Local, &native.intent).is_err() || native.image.as_ref().is_none_or(|image| yonik_linux::full_profile_image_preflight(yonik_linux::FullProfileMode::Local, &native.intent, image).is_err()))
    {
        let _ = updates
            .send(SessionUpdate {
                context: None,
                generation: Some(generation),
                status: "Error",
                error: Some("profile_unavailable"),
                probe_result: None,
                network_stamp: None,
            })
            .await;
        return Ok(());
    }
    let native_image = match &mut config {
        SessionConfig::FullProfile(native) => native.image.take(),
        SessionConfig::Server(_) => None,
    };
    let Ok(session) = LocalSession::new() else {
        let _ = updates
            .send(SessionUpdate {
                context: None,
                generation: Some(generation),
                status: "Error",
                error: Some("engine_failed"),
                probe_result: None,
                network_stamp: None,
            })
            .await;
        return Ok(());
    };
    let mut session = session.with_event_log(event_log);
    #[cfg(feature = "test-support")]
    if let Some(fault) = cleanup_fault {
        session = session.with_cleanup_fault(fault);
    }
    let mut operation_cause = None;
    let operation = async {
        let (relative, digest) = match engine {
            Engine::Xray => (
                "xray-26.10.31/xray",
                "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
            ),
            Engine::SingBox => (
                "sing-box-1.14.4/sing-box",
                "1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a",
            ),
        };
        cancel.check().map_err(|_| "cancelled")?;
        let path = engine_dir.join(relative);
        let native = matches!(config, SessionConfig::FullProfile(..));
        let binary = if native { native_image.ok_or("profile_unavailable")? } else {tokio::task::spawn_blocking(move || {
            BinarySnapshot::load(
                &path,
                digest.parse().map_err(|_| HostError::BinaryHash)?,
                engine,
            )
        })
        .await
        .map_err(|_| "engine_missing")?
        .map_err(|_| "engine_missing")?};
        cancel.check().map_err(|_| "cancelled")?;
        let checked = match config {
            SessionConfig::Server(config) => CheckedConfig::validate(binary, config, &mut cancel).await,
            SessionConfig::FullProfile(native) => CheckedConfig::validate_full_profile(binary, native.intent, native.plan, &mut cancel).await,
        }
            .map_err(|e| {
                if e == HostError::Cancelled {
                    "cancelled"
                } else {
                    "engine_config"
                }
            })?;
        session.start(checked, &mut cancel).await.map_err(|e| {
            operation_cause = Some(if e == HostError::EngineExited { Cause::EngineStartExited } else { Cause::EngineStartFailed });
            if e == HostError::Cancelled {
                "cancelled"
            } else {
                "engine_failed"
            }
        })?;
        let checked_network = network.as_ref().map(NetworkWatch::current);
        let mut network_stamp = checked_network.map(|network| network.stamp);
        let _ = updates
            .send(SessionUpdate {
                context: None,
                generation: Some(generation),
                status: "Checking",
                error: None,
                probe_result: None,
                network_stamp,
            })
            .await;
        let result = tokio::select! {
            biased;
            _ = network_invalidated(&mut network, network_stamp) => None,
            result = session.check(&target, &mut cancel) => Some(result),
        };
        let result = result.transpose().map_err(|error| {
            probe_operation_error(error, &mut operation_cause)
        })?;
        if let Some(result) = result.filter(|_| {
            network_matches(network.as_ref().map(NetworkWatch::current), network_stamp)
        }) {
            let update = probe_session_update(
                result, &target, generation, network_stamp,
                checked_network.is_some_and(NetworkSnapshot::fully_observed),
            );
            let _ = updates.send(update).await;
        } else {
            session.invalidate_check().map_err(|error| probe_operation_error(error, &mut operation_cause))?;
            let _ = updates.send(SessionUpdate {
                context: Some(Cause::ProbeNetworkChanged),
                generation: Some(generation),
                status: "Limited",
                error: Some("network_changed"),
                probe_result: None,
                network_stamp: None,
            }).await;
            network_stamp = network.as_ref().map(|watch| watch.current().stamp);
        }
        loop {
            tokio::select! {
                biased;
                result = session.wait_exit(&mut cancel) => return result.map_err(|e| {
                    operation_cause = (e == HostError::EngineExited).then_some(Cause::EngineExited);
                    if e == HostError::Cancelled { "cancelled" } else { "engine_failed" }
                }),
                _ = network_changed(&mut network) => {
                    if !network_matches(network.as_ref().map(NetworkWatch::current), network_stamp) {
                        session.invalidate_check().map_err(|error| probe_operation_error(error, &mut operation_cause))?;
                        network_stamp = network.as_ref().map(|watch| watch.current().stamp);
                        let _ = updates.send(SessionUpdate {
                            context: Some(Cause::ProbeNetworkChanged),
                            generation: Some(generation),
                            status: "Limited",
                            error: Some("network_changed"),
                            probe_result: None,
                            network_stamp: None,
                        }).await;
                    }
                }
            }
        }
    }
    .await;
    if session.stop().await.is_err() {
        let _ = updates
            .send(SessionUpdate {
                context: Some(Cause::CleanupFailed),
                generation: Some(generation),
                status: "CleanupError",
                error: Some("cleanup_failed"),
                probe_result: None,
                network_stamp: None,
            })
            .await;
        return Err(session);
    }
    let error = operation.err().filter(|key| *key != "cancelled");
    let _ = updates
        .send(SessionUpdate {
            context: operation_cause.filter(|_| error.is_some()),
            generation: Some(generation),
            status: if error.is_some() {
                "Error"
            } else {
                "Disconnected"
            },
            error,
            probe_result: None,
            network_stamp: None,
        })
        .await;
    Ok(())
}

impl maintenance::AdmissionError {
    pub fn context(self) -> crate::diagnostics::context::Cause {
        use crate::diagnostics::context::Cause;
        match self {
            Self::Busy => Cause::MaintenanceAdmissionBusy,
            Self::Revision => Cause::MaintenanceAdmissionRevision,
            Self::Identity => Cause::MaintenanceAdmissionIdentity,
            Self::InvalidInput => Cause::MaintenanceAdmissionInvalidInput,
        }
    }
}

fn accept_maintenance_owner(
    state: &mut Snapshot,
    scheduled: &mut DesktopSchedule,
    owner: DesktopSchedule,
) {
    state.scheduler_generation = Some(owner.generation);
    *scheduled = owner;
}

fn maintenance_refusal(state: &mut Snapshot, request_id: u64, cause: Cause, generation: u64) {
    let context = crate::diagnostics::context::ErrorContext::new(
        Slot::MaintenanceAck,
        cause,
        Some(request_id),
    );
    state.maintenance_generation = generation;
    state
        .error_contexts
        .set_ack(Slot::MaintenanceAck, cause, request_id, generation);
    state.maintenance_ack = Some(maintenance::Ack {
        request_id,
        phase: maintenance::Phase::Failed,
        error: Some(context.message_key),
    });
}

fn reject_unavailable_command(
    state: &mut Snapshot,
    command: &Command,
    error: &'static str,
    cause: Cause,
    generation: u64,
) {
    if let Command::StartupPreferencesSet { request_id, .. }
    | Command::AutoconnectTargetSet { request_id, .. } = command
    {
        state.startup.request_id = Some(request_id.clone());
        state.startup.save = "error";
        state.startup.error = Some(error);
    }

    state.maintenance_available = false;
    if let Some(request_id) = command.preset_request_id() {
        state.presets.ack = Some(presets::Ack {
            request_id,
            error: Some(error),
        });
    }
    if let Command::SourceChange { request_id, id, .. } = command {
        state.source_change_ack = Some(SourceChangeAck {
            request_id: *request_id,
            id: *id,
            generation: None,
            error: Some(error),
        });
    }
    if let Command::MaintenanceStart { request_id, .. }
    | Command::MaintenanceCancel { request_id } = command
    {
        maintenance_refusal(state, *request_id, cause, generation);
    }
    if let Some(request_id) = command.routing_request_id() {
        state
            .error_contexts
            .clear(crate::diagnostics::context::Slot::RoutingAck);
        state.routing_ack = Some(RoutingAck {
            request_id,
            saved_id: None,
            error: Some(error),
        });
    }
    if let Command::LogsRead { request_id, .. } | Command::LogsSave { request_id, .. } = command {
        state.clear_logs_contexts();
        state.logs = logs::Page {
            request_id: request_id.clone(),
            status: if error == "busy" { "busy" } else { "error" },
            ..Default::default()
        };
    }
    #[cfg(feature = "test-support")]
    if let Command::LogsTest { reply } = command {
        let _sent = reply.send(None);
    }
    state.command_error(false, error);
    if matches!(
        command,
        Command::MaintenanceStart { .. } | Command::MaintenanceCancel { .. }
    ) {
        state
            .error_contexts
            .set_generation(Slot::Error, cause, Some(generation));
        state
            .error_contexts
            .set_generation(Slot::Connection, cause, Some(generation));
    }
}

async fn wait_startup_shutdown(
    state: &mut Snapshot,
    commands: &mut mpsc::Receiver<Envelope>,
    priority: &mut watch::Receiver<Priority>,
    callback: &Callback,
) {
    let mut commands_open = true;
    while !priority.borrow_and_update().shutdown {
        tokio::select! {
            changed = priority.changed() => if changed.is_err() { break; },
            command = commands.recv(), if commands_open => {
                if let Some(command) = command {
                    reject_unavailable_command(state, &command.command, "startup", Cause::MaintenanceAdmissionUnsupported, command.generation);
                    state.emit(callback);
                } else { commands_open = false; }
            }
        }
    }
}

async fn run(
    mut config: HostConfig,
    mut commands: mpsc::Receiver<Envelope>,
    mut priority: watch::Receiver<Priority>,
    control: Arc<Control>,
    callback: Callback,
    #[cfg(any(test, feature = "test-support"))] disk_fixture: Option<DiskTestInput>,
) {
    // Host generation начинается с default Priority. Даже Stop до worker закрывает startup.
    let startup_generation = Priority::default().generation;
    let mut state = Snapshot::new(config.ephemeral_key.is_some());
    state.startup.start_hidden = config.start_hidden;
    state.port = config.listen_port.map_or(0, NonZeroU16::get);
    state.busy = true;
    state.emit(&callback);
    config
        .startup_observer
        .emit(StartupPhase::SignalRegistration);
    // Обработчики регистрируются до любого spawn ядра.
    let signals = match (
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()),
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
    ) {
        (Ok(mut interrupt), Ok(mut terminate)) => {
            let control = control.clone();
            Some(tokio::spawn(async move {
                tokio::select! { _ = interrupt.recv() => (), _ = terminate.recv() => () };
                control.interrupt(true);
            }))
        }
        _ => {
            // Без обработчиков завершения не разрешаем запуск дочернего ядра.
            state.busy = false;
            state.contextual_error(false, ContextFailure::new(Cause::SignalsUnavailable));
            state.emit(&callback);
            wait_startup_shutdown(&mut state, &mut commands, &mut priority, &callback).await;
            state.closed = true;
            state.emit(&callback);
            control.closed();
            return;
        }
    };
    config.startup_observer.emit(StartupPhase::PortSelection);
    let opened = match config.listen_port.map_or_else(|| available_port(0), Ok) {
        Ok(port) => {
            state.port = port.get();
            open(&mut config).await
        }
        Err(_) => Err(ContextFailure::new(Cause::ListenPortUnavailable)),
    };
    state.busy = false;
    let (service, _lock, routing_repository) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            state.contextual_error(false, error);
            state.emit(&callback);
            wait_startup_shutdown(&mut state, &mut commands, &mut priority, &callback).await;
            state.closed = true;
            state.emit(&callback);
            control.closed();
            if let Some(task) = signals {
                task.abort();
            }
            return;
        }
    };
    config.startup_observer.emit(StartupPhase::Preferences);
    let (preferences_store, mut preferences, warning) = Store::open(&config.data_dir);
    if let Some(port) = config.listen_port {
        preferences.port = Some(port);
    }
    state.engine = if preferences.engine == "sing-box" {
        EngineChoice::SingBox
    } else {
        EngineChoice::Xray
    };
    if let Some(port) = preferences.port {
        state.port = port.get();
    }
    state.language = preferences.language.clone();
    state.subscription_interval_seconds = preferences.subscription_interval_seconds;
    state.subscription_background = preferences.subscription_background;
    state.proxy_fetch_dns = preferences.proxy_fetch_dns;
    state
        .system_fake_dns
        .clone_from(&preferences.system_fake_dns);
    state.preferences_warning = warning;
    state.probe_custom = preferences.probe_url != DEFAULT_PROBE_URL;
    state.probe_expected_status = preferences.probe_status;
    state.maintenance_available = true;
    state.ready = true;
    config
        .startup_observer
        .emit(StartupPhase::NetworkInitialization);
    let network_monitor = NetworkMonitor::start().ok();
    config.startup_observer.emit(StartupPhase::NetworkReturned);
    let mut network = network_monitor.as_ref().map(NetworkMonitor::watch);
    synchronize_network(&mut state, network.as_ref().map(NetworkWatch::current));
    let automatic_port = preferences.port.is_none();
    let probe_url = Zeroizing::new(preferences.probe_url.clone());
    #[cfg(test)]
    let proxy_fixture = disk_fixture
        .as_ref()
        .and_then(|fixture| fixture.proxy.clone());
    #[cfg(any(test, feature = "test-support"))]
    let (event_log, disk_log) = disk_fixture
        .map(|fixture| fixture.sink)
        .unwrap_or_else(|| yonik_linux::event_log::EventLog::with_disk(config.data_dir.clone()));
    #[cfg(not(any(test, feature = "test-support")))]
    let (event_log, disk_log) =
        yonik_linux::event_log::EventLog::with_disk(config.data_dir.clone());
    let mut actor = Actor {
        #[cfg(feature = "test-support")]
        catalog_observer: config.catalog_observer.clone(),
        presets: crate::backend::presets::Controller::open(&config.data_dir.join("presets"))
            .ok()
            .map(Arc::new),
        event_log,
        logs_save: crate::backend::logs::SaveJob::default(),
        routing_repository: Some(routing_repository),
        format4_backup: None,
        routing_revision: Some(0),
        preferences_store,
        preferences,
        service: Some(service),
        state,
        callback,
        selected: None,
        selected_native: None,
        selected_native_token: None,
        catalog_selections: Vec::new(),
        catalog_coordinates: None,
        pending: None,
        automatic_port,
        probe_url,
        network: network.clone(),
    };
    if let Some(controller) = &actor.presets {
        actor.state.presets = controller.status();
    }
    match tokio::time::timeout(
        Duration::from_secs(5),
        actor.routing_repository().routing_draft(),
    )
    .await
    .unwrap_or(Err(yonik_linux::RepositoryError::Storage))
    {
        Ok(None) => {}
        Ok(Some((revision, raw))) => match std::str::from_utf8(&raw)
            .ok()
            .and_then(|s| crate::editor::Draft::parse(s).ok())
        {
            Some(draft) => {
                actor.state.routing = draft;
                actor.routing_revision = Some(revision);
            }
            None => {
                actor.routing_revision = None;
                actor
                    .state
                    .error_contexts
                    .clear(crate::diagnostics::context::Slot::Error);
                actor.state.error = Some("routing_storage");
            }
        },
        Err(_) => {
            actor.routing_revision = None;
            actor
                .state
                .error_contexts
                .clear(crate::diagnostics::context::Slot::Error);
            actor.state.error = Some("routing_storage");
        }
    }
    actor.state.startup.custody = config.startup_custody.take();
    actor.state.startup.xdg_root = config.startup_xdg_root.clone();
    actor.state.startup.owner = tokio::time::timeout(
        Duration::from_secs(5),
        actor.routing_repository().database_identity(),
    )
    .await
    .ok()
    .and_then(|result| result.ok())
    .and_then(|id| crate::startup_identity::Identity::capture(&config.data_dir, id).ok());
    actor.state.routing_diagnostics = actor.state.routing.diagnostics();
    actor.state.routing_revision = actor.routing_revision;
    match tokio::time::timeout(Duration::from_secs(5), actor.reload()).await {
        Ok(Ok(())) => (),
        Ok(Err(error)) => {
            actor.state.startup.initialization_failed = true;
            actor.state.command_error(true, error.key());
        }
        Err(_) => {
            actor.state.startup.initialization_failed = true;
            actor.state.startup.error = Some("startup_timeout");
        }
    }
    actor.emit();
    let (updates, mut events) = mpsc::channel::<SessionUpdate>(16);
    let (mut startup_command, mut system_session) =
        startup_application::prepare(&mut actor, &control, startup_generation).await;
    actor.emit();
    let mut system_flight: Option<Flight> = None;
    let mut system_stop = false;
    let mut system_active = false;
    let mut system_poll = tokio::time::interval(Duration::from_secs(2));
    let mut running: Option<Running> = None;
    let mut failed_session: Option<LocalSession> = None;
    let mut refreshing: Option<RefreshTask> = None;
    type LocalTask = (
        String,
        watch::Sender<bool>,
        tokio::task::JoinHandle<
            std::result::Result<
                yonik_import::ProfileImportReport,
                crate::local_import::PrepareError,
            >,
        >,
    );
    let mut local_task: Option<LocalTask> = None;
    let mut local_pending: Option<(String, yonik_import::ProfileImportReport)> = None;
    let mut batch_running: Option<BatchRunning> = None;
    let mut tcp_running: Option<TcpRunning> = None;
    let mut preset_job: Option<presets::Job> = None;
    let mut preset_stopping = false;
    let mut preset_validation: Option<presets::ValidationScope> = None;
    let mut tcp_priority = control.tcp_priority.subscribe();
    let mut quitting = false;
    let (system_policy_sender, mut system_policy) = watch::channel(Default::default());
    let (provider_stop, provider_cancel) = Cancellation::new();
    let provider_enabled = config.system_subscription_policy;
    let provider = async move {
        if provider_enabled {
            yonik_linux::system_subscription_policy_until(system_policy_sender, provider_cancel)
                .await
        } else {
            std::future::pending().await
        }
    };
    let mut provider = Box::pin(provider);
    let mut subscription_policy = control.subscription_policy.subscribe();
    let mut subscription_visible = control.subscription_visible.subscribe();
    let origin = tokio::time::Instant::now();
    #[cfg(feature = "test-support")]
    let owner = match config.scheduler_owner_seed {
        Some(seed) => {
            DesktopSchedule::from_owner_counter(&std::sync::atomic::AtomicU64::new(seed), 20_000)
        }
        None => match config.scheduler_capacity {
            Some(capacity) => DesktopSchedule::bounded(capacity),
            None => DesktopSchedule::new(),
        },
    };
    #[cfg(not(feature = "test-support"))]
    let owner = DesktopSchedule::new();
    let mut scheduled = match owner {
        Ok(owner) => owner,
        Err(error) => {
            actor.state.schedule_error(error, None);
            actor.state.ready = false;
            actor.state.closed = actor
                .service
                .take()
                .expect("online service перед закрытием")
                .close()
                .await
                .is_ok();
            actor.state.emit(&actor.callback);
            control.closed();
            return;
        }
    };
    scheduled.policy = *subscription_policy.borrow_and_update();
    scheduled.visible = *subscription_visible.borrow_and_update();
    let mut schedule_loaded = false;
    if let Err(error) = scheduled.load(actor.service(), origin.elapsed()).await {
        actor
            .state
            .schedule_error(error, Some(scheduled.generation));
        actor.emit();
    } else {
        schedule_loaded = true;
    }
    let (proxy_session, _) = watch::channel::<ProxyLease>(None);
    #[cfg(test)]
    if let Some(fixture) = &proxy_fixture {
        // Тот же канал, который отзывается production priority-веткой Stop.
        proxy_session.send_replace(Some((17, fixture.endpoint)));
        let fetch = DesktopFetch::new(&proxy_session, None);
        let _observed = fixture.observer.send((proxy_session.subscribe(), fetch));
    }
    let mut session_generation = 0_u64;
    let mut manual_host: Option<Arc<DesktopFetch>> = None;
    let mut schedule_host = DesktopFetch::subscription(
        &proxy_session,
        actor.preferences.proxy_fetch_dns,
        #[cfg(feature = "test-support")]
        config.test_subscription_fetch.clone(),
    );
    let mut maintenance_controller = maintenance::Controller::default();
    #[cfg(feature = "test-support")]
    let mut schedule_trace = ScheduleTrace::default();
    loop {
        #[cfg(feature = "test-support")]
        schedule_trace.emit(
            &config,
            &scheduled,
            *proxy_session.borrow(),
            origin.elapsed(),
            "state",
        );
        let interval = Duration::from_secs(actor.preferences.subscription_interval_seconds as u64);
        scheduled.background_enabled = actor.preferences.subscription_background;
        #[cfg(feature = "test-support")]
        let interval = config.scheduler_interval.unwrap_or(interval);
        if let Err(error) = scheduled.set_interval(interval) {
            actor
                .state
                .schedule_error(error, Some(scheduled.generation));
        }
        let now = origin.elapsed();
        let policy = scheduled.policy();
        if scheduled.window_until.is_some_and(|until| now >= until)
            || (scheduled.window_until.is_some()
                && (!scheduled.background_enabled
                    || !policy.online
                    || policy.metered
                    || policy.battery_saver))
        {
            #[cfg(feature = "test-support")]
            {
                schedule_trace.begin_drain(&config);
                schedule_trace.emit(
                    &config,
                    &scheduled,
                    *proxy_session.borrow(),
                    origin.elapsed(),
                    "window_drain_begin",
                );
            }
            let closed = scheduled.close_window(actor.service(), now).await;
            #[cfg(feature = "test-support")]
            schedule_trace.emit(
                &config,
                &scheduled,
                *proxy_session.borrow(),
                origin.elapsed(),
                if closed.is_ok() {
                    "window_closed"
                } else {
                    "window_close_failed"
                },
            );
            if let Err(error) = closed {
                actor
                    .state
                    .schedule_error(error, Some(scheduled.generation));
            }
        }
        if let Some(observer) = &config.schedule_observer {
            observer(scheduled.policy(), schedule_loaded);
        }
        let lease = running
            .as_ref()
            .filter(|session| {
                actor.state.status == "Connected"
                    && !*session.cancel.borrow()
                    && !session.task.is_finished()
            })
            .map(|session| session.lease);
        // Без native Running fixture сохраняет только уже опубликованный lease.
        // Production Stop по-прежнему единственный источник его отзыва.
        #[cfg(test)]
        let lease = lease.or_else(|| proxy_fixture.as_ref().and_then(|_| *proxy_session.borrow()));
        if proxy_session.send_if_modified(|current| {
            if *current == lease {
                false
            } else {
                *current = lease;
                true
            }
        }) {
            #[cfg(feature = "test-support")]
            schedule_trace.emit(
                &config,
                &scheduled,
                *proxy_session.borrow(),
                origin.elapsed(),
                "lease_published",
            );
        }
        if manual_host.as_ref().is_some_and(|host| host.stale()) {
            actor.pending = None;
            if scheduled.review.is_none() {
                actor.state.pending = None;
            }
            if let Some((_, cancel, _, _, _)) = &refreshing {
                cancel.send_replace(true);
            }
            manual_host = None;
        }
        if schedule_host.stale() {
            if scheduled.review.is_some() {
                actor.state.pending = None;
            }
            if let Err(error) = scheduled.shutdown(origin.elapsed()).await {
                actor
                    .state
                    .schedule_error(error, Some(scheduled.generation));
            }
            if let Some(mut replacement) = actor
                .state
                .schedule_replacement(scheduled.replacement(), scheduled.generation)
            {
                if let Err(error) = replacement.load(actor.service(), origin.elapsed()).await {
                    actor
                        .state
                        .schedule_error(error, Some(replacement.generation));
                }
                actor.state.scheduler_generation = Some(replacement.generation);
                scheduled = replacement;
            }
            schedule_host = DesktopFetch::subscription(
                &proxy_session,
                actor.preferences.proxy_fetch_dns,
                #[cfg(feature = "test-support")]
                config.test_subscription_fetch.clone(),
            );
        }
        let allowed = !quitting
            && local_task.is_none()
            && local_pending.is_none()
            && refreshing.is_none()
            && actor.pending.is_none()
            && scheduled.review.is_none();
        let work_deadline = if allowed { scheduled.deadline() } else { None };
        let deadline = work_deadline
            .into_iter()
            .chain(scheduled.window_until)
            .min();

        tokio::select! {
            biased;
            changed = priority.changed() => {
                startup_command = None;
                if actor.state.startup.attempt == "dispatched" { actor.state.startup.attempt = "cancelled"; }
                if let Some((_, cancel, task)) = local_task.take() { cancel.send_replace(true); let _ = task.await; actor.state.busy = false; }
                if local_pending.take().is_some() { actor.state.pending = None; }

                if changed.is_err() { quitting = true; }
                if actor.state.connection_mode == ConnectionMode::System && (system_active || system_flight.is_some()) {
                    system_stop |= system_active || system_flight.as_ref().is_some_and(|flight| flight.mutating);
                    actor.state.system_busy = true;
                    actor.state.system_state = "Unknown";
                    actor.state.status = "Unknown";
                    if let Some(flight) = &system_flight { flight.cancel.send_replace(true); }
                }
                if let Some(job) = &preset_job { preset_stopping = true; actor.state.presets.stopping = true; job.stop(); }
                proxy_session.send_replace(None);
                let action = *priority.borrow_and_update();
                quitting |= action.shutdown;
                // Сначала все сигналы отмены, затем любые await: spawned TCP не должен
                // получить polling сети во время ожидания scheduler acknowledgement.
                if let Some((_, cancel, _, _, _)) = refreshing.as_ref() { cancel.send_replace(true); }
                if let Some(session) = running.as_ref() { session.cancel.send_replace(true); }
                if let Some(batch) = batch_running.as_mut() { batch.stop(); actor.state.batch.cancelled = true; actor.emit(); }
                if let Some(tcp) = tcp_running.as_ref() { tcp.cancel.send_replace(true); }
                #[cfg(feature = "test-support")]
                { schedule_trace.begin_drain(&config); schedule_trace.emit(&config, &scheduled, None, origin.elapsed(), "stop_drain_begin"); }
                let shutdown = scheduled.shutdown(origin.elapsed()).await;
                #[cfg(feature = "test-support")]
                schedule_trace.emit(&config, &scheduled, None, origin.elapsed(), if shutdown.is_ok() { "stop_drain_complete" } else { "stop_drain_failed" });
                if let Err(error) = shutdown { actor.state.schedule_error(error, Some(scheduled.generation)); }
                scheduled.fetching = false; scheduled.review = None; scheduled.deferred = None;
                if !quitting {
                    if let Some(mut replacement) = actor.state.schedule_replacement(scheduled.replacement(), scheduled.generation) {
                        if let Err(error) = replacement.load(actor.service(), origin.elapsed()).await { actor.state.schedule_error(error, Some(replacement.generation)); }
                        actor.state.scheduler_generation = Some(replacement.generation);
                scheduled = replacement;
                    }
                }
                actor.state.error_contexts.clear(crate::diagnostics::context::Slot::Connection); actor.state.connection_error = None;
                actor.pending = None; actor.state.pending = None;
                if let Some((_, cancel, _, _, _)) = refreshing.as_ref() { cancel.send_replace(true); }
                if let Some(session) = running.as_ref() { session.cancel.send_replace(true); }
                if let Some(batch) = batch_running.as_mut() { batch.stop(); actor.state.batch.cancelled = true; actor.emit(); }
                if let Some(tcp) = tcp_running.as_ref() { tcp.cancel.send_replace(true); }
                if let Some(mut session) = failed_session.take() {
                    if session.stop().await.is_err() { failed_session = Some(session); actor.state.session_error(Cause::CleanupFailed, session_generation); }
                }
                if actor.state.connection_mode == ConnectionMode::Local && running.is_none() && failed_session.is_none() && preset_job.is_none() {
                    actor.state.can_stop = false; actor.state.active_name = None; actor.state.active_engine = None;
                }
                if actor.state.connection_mode == ConnectionMode::Local { actor.state.status = if running.is_some() || preset_job.is_some() { "Stopping" } else if failed_session.is_some() { "CleanupError" } else { "Disconnected" }; }
                actor.emit();
            }
            result = async { match system_flight.as_mut() {
                Some(flight) => (&mut flight.task).await,
                None => std::future::pending().await,
            } } => {
                if let Some(flight) = system_flight.take() {
                    // После долгого State recovery-действия получают окно до следующего poll.
                    system_poll.reset();
                    if let Some(request_id) = flight.request_id {
                        actor.state.routing_ack = Some(RoutingAck { request_id, saved_id: None, error: Some("cancelled") });
                    }
                    let stale = (flight.connecting && system_stop) || flight.generation != control.generation.load(Ordering::SeqCst)
                        || (flight.connecting && (flight.revision != system_revision(&actor) || flight.source_generation != actor.state.source_generation || flight.routing_revision.is_some_and(|revision| actor.routing_revision != Some(revision))));
                    match result {
                        Ok((session, result)) => {
                            actor.state.system_tun_available = session.as_ref().is_some_and(SystemSession::system_tun_available);
                            system_session = session;
                            if !stale {
                                if let Some(request_id) = flight.request_id {
                                    actor.state.routing_ack = Some(RoutingAck { request_id, saved_id: None, error: result.as_ref().err().map(|e| system_error(*e)) });
                                }
                            }
                            if stale {
                                system_stop |= flight.mutating || system_active;
                                actor.state.system_state = "Unknown";
                                actor.state.status = "Unknown";
                            } else {
                                if flight.connecting || (flight.mutating && result.is_err()) { system_active = !matches!(result, Err(ClientError::Unsupported | ClientError::Denied | ClientError::InvalidRequest | ClientError::Busy)); }
                                if !flight.connecting && system_stop { system_active = !matches!(result, Ok(SystemState::NoManagedPolicy | SystemState::VerifiedRules | SystemState::RecoveryRequired)); system_stop = false; }
                                match result {
                                    Ok(state) => {
                                        if state == SystemState::NoManagedPolicy { system_active = false; }
                                        else if matches!(state, SystemState::TunnelStarting | SystemState::Unknown) { system_active = true; }
                                        record_system(&mut actor.state, state)
                                    },
                                    Err(error) => {
                                        record_system(&mut actor.state, SystemState::Unknown);
                                        actor.state.contextual_error(false, ContextFailure { error: DesktopError(system_error(error)), cause: helper_cause(error) });
                                        actor.state.helper_generation = Some(flight.generation);
                                        actor.state.error_contexts.set_generation(Slot::Error, helper_cause(error), Some(flight.generation));
                                        actor.state.error_contexts.set_generation(Slot::Connection, helper_cause(error), Some(flight.generation));
                                    }
                                }
                            }
                        }
                        Err(_) => { record_system(&mut actor.state, SystemState::Unknown); system_active = true; }
                    }
                    actor.state.system_busy = false;
                    actor.state.can_stop = system_active || system_stop;
                    if !actor.state.can_stop { actor.state.active_name = None; actor.state.active_engine = None; }
                    actor.emit();
                }
            }
            _ = system_poll.tick(), if actor.state.connection_mode == ConnectionMode::System && system_flight.is_none() && system_session.is_some() && !quitting => {
                if system_session.as_ref().is_some_and(|session| session.snapshot() == SystemState::Unknown) {
                    record_system(&mut actor.state, SystemState::Unknown); actor.emit();
                }
                let generation = control.generation.load(Ordering::SeqCst);
                system_flight = Some(Flight::start(system_session.take(), Operation::State, system_revision(&actor), generation, actor.event_log.clone()));
                actor.state.system_busy = true; actor.emit();
            }
            _ = &mut provider => {},
            changed = system_policy.changed(), if provider_enabled => {
                if changed.is_ok() && !control.subscription_override.load(Ordering::Acquire) {
                    scheduled.policy = *system_policy.borrow_and_update();
                }
            }
            _ = subscription_policy.changed() => {
                scheduled.policy = *subscription_policy.borrow_and_update();
            }
            _ = subscription_visible.changed() => {
                scheduled.visible = *subscription_visible.borrow_and_update();
            }
            event = async {
                if let Some(event) = scheduled.deferred.take() { return Ok(Some(event)); }
                scheduled.runtime.next_event(|| origin.elapsed()).await
            }, if scheduled.fetching || scheduled.deferred.is_some() => {
                scheduled.fetching = false;
                match event {
                    Ok(Some(yonik_linux::SubscriptionScheduleEvent::Review { id })) => {
                        scheduled.review = Some(id);
                        actor.state.source_id = Some(id);
                        actor.state.offset = 0;
                        actor.clear_selection();
                        if let Err(error) = actor.reload().await { actor.state.command_error(true, error.key()); }
                        if let Some(pending) = scheduled.runtime.review(id) {
                            match pending_dto(pending, 0) {
                                Ok(dto) => actor.state.pending = Some(dto),
                                Err(error) => actor.state.command_error(true, error.key()),
                            }
                        }
                    }
                    Ok(Some(yonik_linux::SubscriptionScheduleEvent::Failed { error, .. })) => actor.state.schedule_error(desktop_schedule::ScheduleFailure::service(error), Some(scheduled.generation)),
                    Ok(_) => {},
                    Err(error) => actor.state.schedule_error(desktop_schedule::ScheduleFailure::runtime(error), Some(scheduled.generation)),
                }
                actor.emit();
            }
            _ = async {
                match deadline {
                    Some(due) => tokio::time::sleep_until(origin + due).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                // На границе окна сначала closing ACK в начале следующей итерации.
                if scheduled.window_until.is_none_or(|until| origin.elapsed() < until) {
                    schedule_host = DesktopFetch::subscription(&proxy_session, actor.preferences.proxy_fetch_dns, #[cfg(feature = "test-support")] config.test_subscription_fetch.clone());
                    let host = &schedule_host;
                    let window_now = origin.elapsed();
                    #[cfg(feature = "test-support")]
                    let was_closed = scheduled.window_until.is_none();
                    scheduled.open_window(window_now);
                    #[cfg(feature = "test-support")]
                    {
                        if was_closed && scheduled.window_until.is_some() { schedule_trace.window_origin = Some(window_now); }
                        schedule_trace.emit(&config, &scheduled, *proxy_session.borrow(), origin.elapsed(), "dispatch");
                    }
                    let policy = scheduled.policy();
                    match scheduled.runtime.dispatch(origin.elapsed(), policy, actor.service(), host.clone()) {
                        Ok(()) => scheduled.fetching = true,
                        Err(error) => actor.state.schedule_error(desktop_schedule::ScheduleFailure::runtime(error), Some(scheduled.generation)),
                    }
                }
            }
            changed = tcp_priority.changed() => {
                let _ = changed;
                tcp_priority.borrow_and_update();
                if let Some(batch) = batch_running.as_mut() { batch.stop(); actor.state.batch.cancelled = true; actor.emit(); }
                if let Some(tcp) = tcp_running.as_ref() { tcp.cancel.send_replace(true); }
            }
            _ = network_changed(&mut network) => {
                actor.state.system_tun_available = false;
                if let Some(flight) = system_flight.as_ref().filter(|f| f.connecting) {
                    flight.cancel.send_replace(true);
                    system_stop = true;
                }
                let current = network.as_ref().map(NetworkWatch::current);
                actor.network = network.clone();
                apply_network_event(&mut actor.state, current, &control);
                if let Some(batch) = batch_running.as_mut() { batch.stop(); }
                actor.state.batch.invalidate();
                if let Some(tcp) = tcp_running.as_ref() {
                    if !network_matches(current, tcp.network_stamp) { tcp.cancel.send_replace(true); }
                }
                actor.emit();
            }
            result = async { batch_running.as_mut().expect("guard").next().await }, if batch_running.is_some() => {
                match result {
                    BatchPoll::Event(result) => {
                if let Some(result) = result {
                    let valid = batch_running.as_ref().is_some_and(|batch|
                        batch.generation == control.generation.load(Ordering::SeqCst)
                        && batch.tcp_generation == *control.tcp_priority.borrow()
                        && network_matches(network.as_ref().map(NetworkWatch::current), batch.stamp)
                        && actor.state.batch.source_id == actor.state.source_id
                        && actor.state.batch.revision == actor.state.revision);
                    if !valid {
                        let stale = batch_running.as_ref().is_some_and(|batch|
                            !network_matches(network.as_ref().map(NetworkWatch::current), batch.stamp)
                            || actor.state.batch.source_id != actor.state.source_id
                            || actor.state.batch.revision != actor.state.revision);
                        if let Some(batch) = batch_running.as_mut() { batch.stop(); }
                        if stale { actor.state.batch.invalidate(); }
                        else { actor.state.batch.cancelled = true; }
                        actor.emit(); continue;
                    }
                    match result {
                        BatchEvent::Prepared { total } => { actor.state.batch.total = total; actor.emit(); }
                        BatchEvent::Result(row) => {
                            actor.state.batch.accept(row);
                            if actor.state.batch.completed % 32 == 0 { actor.emit(); }
                        }
                    }
                } else if let Some(batch) = batch_running.as_mut() { batch.output_closed = true; }
                    }
                    BatchPoll::Finished(result) => {
                // Producer завершён, включая ACK CPU prepare. Дочитываем bounded очередь.
                let mut batch = batch_running.take().expect("guard");
                let valid = !*batch.cancel.borrow() && !quitting
                    && batch.generation == control.generation.load(Ordering::SeqCst)
                    && batch.tcp_generation == *control.tcp_priority.borrow()
                    && network_matches(network.as_ref().map(NetworkWatch::current),batch.stamp)
                    && actor.state.batch.source_id == actor.state.source_id
                    && actor.state.batch.revision == actor.state.revision;
                if valid {
                    while let Ok(event) = batch.receiver.try_recv() {
                        match event {
                            BatchEvent::Prepared { total } => actor.state.batch.total = total,
                            BatchEvent::Result(row) => actor.state.batch.accept(row),
                        }
                    }
                    match result { Ok(Err(error)) => actor.state.command_error(false,error.key()), Err(_) => actor.state.command_error(false,"tcp_failed"), _ => {} }
                }
                actor.state.batch.busy = false;
                actor.emit();
                    }
                }
            }
            result = async { (&mut tcp_running.as_mut().expect("guard").task).await }, if tcp_running.is_some() => {
                let mut tcp = tcp_running.take().expect("guard");
                actor.state.tcp_busy = false;
                actor.state.tcp_name = None;
                if actor.tcp_key() == Some(tcp.result.key()) && !quitting
                    && network_matches(network.as_ref().map(NetworkWatch::current), tcp.network_stamp) {
                    match result {
                        Ok(Ok(mut result)) => {
                            if tcp.generation != control.generation.load(Ordering::SeqCst)
                                || tcp.tcp_generation != *control.tcp_priority.borrow() {
                                result.status = TcpProbeStatus::Cancelled;
                                result.samples.clear();
                                result.median = None;
                                result.selected_address = None;
                            }
                            tcp.result.finish(result); actor.state.tcp_result = Some(tcp.result);
                        }
                        _ => { actor.state.tcp_result = None; actor.state.command_error(false, "tcp_failed"); }
                    }
                }
                actor.emit();
            }
            result = async { (&mut running.as_mut().expect("guard").task).await }, if running.is_some() => {
                #[cfg(feature = "test-support")]
                if matches!(&result, Ok(Ok(()))) {
                    if let Some(gate) = &config.lifecycle_gate { gate.confirm_stopped(session_generation); }
                }
                running = None;
                if let Ok(Err(session)) = result { failed_session = Some(session); actor.state.session_error(Cause::CleanupFailed, session_generation); }
                if failed_session.is_none() && !preset_stopping { actor.state.can_stop = false; actor.state.active_name = None; actor.state.active_engine = None; }
                // Финальный event может ожидать в канале; сначала применяем его.
                while let Ok(update) = events.try_recv() { actor.update(update); }
                if preset_stopping { actor.state.status = "Stopping"; actor.state.can_stop = true; }
                actor.emit();
            }
            result = async { (&mut local_task.as_mut().expect("guard").2).await }, if local_task.is_some() => {
                let (name, cancel, _) = local_task.take().expect("guard");
                actor.state.busy = false;
                if !*cancel.borrow() && !quitting {
                    match result {
                        Ok(Ok(report)) => {
                            match report_dto(&report, 0) {
                                Ok(dto) => { actor.state.pending = Some(dto); local_pending = Some((name, report)); }
                                Err(error) => actor.state.command_error(true, error.key()),
                            }
                        }
                        _ => actor.state.command_error(true, "invalid_input"),
                    }
                }
                actor.emit();
            }
            result = async { (&mut refreshing.as_mut().expect("guard").2).await }, if refreshing.is_some() => {
                let (generation, cancel, _, identity, _) = refreshing.take().expect("guard");
                actor.state.busy = false;
                actor.state.refresh_source_id = None;
                actor.state.refresh_token = None;
                if generation == control.generation.load(Ordering::SeqCst) && !quitting { actor.state.error_contexts.clear(crate::diagnostics::context::Slot::Source); actor.state.source_error = None; }
                if generation == control.generation.load(Ordering::SeqCst) && !quitting && !*cancel.borrow() {
                    let outcome = match result { Ok(result) => actor.refreshed(identity, result).await, Err(_) => Err(DesktopError("fetch").into()) };
                    if generation != control.generation.load(Ordering::SeqCst) { continue; }
                    let storage_failed = matches!(&outcome, Err(error) if error.key() == "storage");
                    if let Err(error) = outcome { actor.state.command_generation = generation; actor.state.source_failure(true, error, generation); }
                    let Some(reconciled) = await_current_schedule(reconcile_manual_schedule(&mut scheduled, actor.service(), identity, || origin.elapsed(), storage_failed), &control.generation, generation).await else { continue; };
                    if let Err(error) = reconciled { actor.state.schedule_error(error, Some(scheduled.generation)); }
                }
                actor.emit();
            }
            mut ack = async { match preset_job.as_mut() {
                Some(job) => job.complete().await,
                None => std::future::pending().await,
            } } => {
                preset_job = None;
                preset_stopping = false;
                if actor.state.status == "Stopping" && running.is_none() && failed_session.is_none() && actor.state.connection_mode == ConnectionMode::Local {
                    actor.state.status = "Disconnected";
                    actor.state.can_stop = false;
                }
                if actor.state.connection_mode == ConnectionMode::System && actor.state.status == "Stopping" && system_flight.is_none() {
                    actor.state.status = actor.state.system_state;
                    actor.state.can_stop = system_active || system_stop;
                }
                if let Some(controller) = &actor.presets {
                    actor.state.presets = controller.status();
                }
                if let Some(scope) = preset_validation.take() {
                    if actor.preset_scope() != Some(scope) { ack.error = Some("routing_stale"); }
                    actor.state.presets.host_validated = ack.error.is_none();
                    if ack.error.is_none() { actor.state.presets.validation_scope = Some(scope); }
                }
                actor.state.presets.ack = Some(ack);
                actor.emit();
            }
            completion = actor.logs_save.complete(), if actor.logs_save.active() => {
                if let Some((request_id, status)) = completion {
                    if actor.state.logs.request_id == request_id && actor.state.logs.status == "saving" {
                        actor.state.clear_logs_contexts(); actor.state.logs = logs::Page { request_id, status, ..Default::default() };
                        actor.state.set_logs_context(Slot::LogsSave, actor.logs_save.cause);
                        actor.emit();
                    }
                }
            }
            Some(update) = events.recv() => {
                actor.update(update);
                if preset_stopping { actor.state.status = "Stopping"; actor.state.can_stop = true; }
                actor.emit();
            }
            command = async { if let Some(envelope) = startup_command.take() { Some((envelope, true)) } else { commands.recv().await.map(|envelope| (envelope, false)) } }, if !quitting => {
                let Some((envelope, from_startup)) = command else { control.interrupt(true); continue; };
                if from_startup {
                    let validation = tokio::time::timeout(Duration::from_secs(5), actor.startup_revalidate(&control, envelope.generation)).await;
                    if !matches!(validation, Ok(Ok(()))) {
                        actor.state.startup.attempt = "blocked";
                        actor.state.startup.error = Some(match validation { Ok(Err(error)) => error.key(), _ => "startup_timeout" });
                        actor.emit(); continue;
                    }
                    actor.state.startup.attempt = "attempted";
                }
                if envelope.generation != control.generation.load(Ordering::SeqCst) {
                    if let Command::StartupPreferencesSet { request_id, .. } | Command::AutoconnectTargetSet { request_id, .. } = &envelope.command {
                        actor.state.startup.request_id = Some(request_id.clone()); actor.state.startup.save = "error"; actor.state.startup.error = Some("cancelled"); actor.emit();
                    }
                    if let Some(request_id) = envelope.command.preset_request_id() {
                        actor.state.presets.ack = Some(presets::Ack { request_id, error: Some("cancelled") });
                        actor.emit();
                    }
                    if let Command::SourceChange { request_id, id, .. } = &envelope.command {
                        actor.state.source_change_ack = Some(SourceChangeAck { request_id: *request_id, id: *id, generation: None, error: Some("cancelled") });
                        actor.emit();
                    }
                    if let Command::MaintenanceStart { request_id, .. } | Command::MaintenanceCancel { request_id } = &envelope.command {
                        maintenance_refusal(&mut actor.state, *request_id, Cause::MaintenanceAdmissionStale, envelope.generation);
                        actor.emit();
                    }
                    if let Some(request_id) = envelope.command.routing_request_id() {
                        actor.state.error_contexts.clear(crate::diagnostics::context::Slot::RoutingAck); actor.state.routing_ack = Some(RoutingAck { request_id, saved_id: None, error: Some("cancelled") });
                        actor.emit();
                    }
                    if let Command::LogsRead { request_id, .. } | Command::LogsSave { request_id, .. } = envelope.command {
                        actor.state.clear_logs_contexts(); actor.state.logs = logs::Page { request_id, status: "cancelled", ..Default::default() };
                        actor.emit();
                    }
                    continue;
                }
                if let Command::MaintenanceStart { request_id, operation, source, destination, revision } = &envelope.command {
                    let request = maintenance::Request { request_id: *request_id, operation: *operation, source: source.clone(), destination: destination.clone(), revision: *revision };
                    let live = config.data_dir.join("subscriptions.sqlite");
                    if local_task.is_some() || !actor.state.maintenance_available || preset_job.is_some() || running.is_some() || failed_session.is_some() || system_active || system_flight.is_some() || batch_running.is_some() || tcp_running.is_some() || refreshing.is_some() || scheduled.fetching || scheduled.deferred.is_some() || actor.pending.is_some() || scheduled.review.is_some() || actor.logs_save.active() {
                        let cause = if actor.state.maintenance_available { Cause::MaintenanceAdmissionBusy } else { Cause::MaintenanceAdmissionUnavailable }; maintenance_refusal(&mut actor.state, request.request_id, cause, envelope.generation);
                        actor.emit(); continue;
                    }
                    if let Err(error) = maintenance_controller.begin_typed(&request, &live, actor.state.revision) {
                        maintenance_refusal(&mut actor.state, request.request_id, error.context(), envelope.generation);
                        actor.emit(); continue;
                    }
                    let Some(service) = actor.service.take() else { maintenance_controller.drained(request.request_id, Err("busy")); maintenance_refusal(&mut actor.state, request.request_id, Cause::MaintenanceAdmissionUnavailable, envelope.generation); actor.emit(); continue; };
                    let Some(repository) = actor.routing_repository.take() else { actor.service = Some(service); maintenance_controller.drained(request.request_id, Err("busy")); maintenance_refusal(&mut actor.state, request.request_id, Cause::MaintenanceAdmissionUnavailable, envelope.generation); actor.emit(); continue; };
                    let replacement = match DesktopSchedule::new() { Ok(schedule) => schedule, Err(_) => { actor.service = Some(service); actor.routing_repository = Some(repository); maintenance_controller.drained(request.request_id, Err("startup")); maintenance_refusal(&mut actor.state, request.request_id, Cause::MaintenanceAdmissionSchedulerUnavailable, envelope.generation); actor.emit(); continue; } };
                    let owner = std::mem::replace(&mut scheduled, replacement);
                    let request_id = request.request_id;
                    let cancellation = yonik_linux::MaintenanceControl::default();
                    let backup_destination = (request.operation == maintenance::Operation::Backup).then(|| request.destination.clone());
                    let mut job = tokio::spawn(maintenance_job::run(service, repository, owner, refreshing.take(), request, cancellation.clone(), origin.elapsed()));
                    actor.state.ready = false;
                    actor.state.busy = true;
                    actor.state.error_contexts.clear(crate::diagnostics::context::Slot::MaintenanceAck); actor.state.maintenance_ack = Some(maintenance::Ack { request_id, phase: maintenance::Phase::Draining, error: None });
                    actor.emit();
                    let outcome = loop {
                        tokio::select! {
                            biased;
                            changed = priority.changed() => {
                                if changed.is_err() { quitting = true; }
                                let action = *priority.borrow_and_update();
                                quitting |= action.shutdown;
                                cancellation.cancel();
                                if local_pending.take().is_some() { actor.state.pending = None; }
                                maintenance_controller.cancel(request_id);
                                actor.state.error_contexts.clear(crate::diagnostics::context::Slot::MaintenanceAck); actor.state.maintenance_ack = maintenance_controller.ack().cloned();
                                actor.emit();
                            }
                            result = &mut job => break result,
                            command = commands.recv(), if !quitting => {
                                let Some(command) = command else { quitting = true; cancellation.cancel(); continue; };
                                match &command.command {
                                    Command::MaintenanceCancel { request_id: id } if *id == request_id => {
                                        cancellation.cancel();
                                        maintenance_controller.cancel(request_id);
                                        actor.state.error_contexts.clear(crate::diagnostics::context::Slot::MaintenanceAck); actor.state.maintenance_ack = maintenance_controller.ack().cloned();
                                    }
                                    Command::MaintenanceStart { request_id: id, .. } if *id == request_id => {
                                        actor.state.error_contexts.clear(crate::diagnostics::context::Slot::MaintenanceAck); actor.state.maintenance_ack = maintenance_controller.ack().cloned();
                                    }
                                    Command::MaintenanceStart { request_id: id, .. } | Command::MaintenanceCancel { request_id: id } => {
                                        maintenance_refusal(&mut actor.state, *id, Cause::MaintenanceAdmissionDraining, command.generation);
                                    }
                                    _ => reject_unavailable_command(&mut actor.state, &command.command, "busy", Cause::MaintenanceAdmissionReopenUnavailable, command.generation),
                                }
                                actor.emit();
                            }
                        }
                    };
                    let outcome = maintenance_job::joined(outcome);
                    let job_context = outcome.cause.map(maintenance_job::Failure::context);
                    let job_drained = outcome.drained;
                    let result = outcome.result;
                    if let Some((service, repository, owner)) = outcome.handles {
                        actor.service = Some(service); actor.routing_repository = Some(repository); accept_maintenance_owner(&mut actor.state, &mut scheduled, owner);
                    }
                    if result.is_ok() { actor.format4_backup = backup_destination; }
                    let online = actor.service.is_some() && actor.routing_repository.is_some();

                    // Completion принадлежит единственному join handle этого request;
                    // внешние callbacks не могут завершить следующую generation.
                    if job_drained { maintenance_controller.drained(request_id, result); }
                    actor.state.error_contexts.clear(crate::diagnostics::context::Slot::MaintenanceAck); actor.state.maintenance_ack = Some(maintenance::Ack { request_id, phase: if result.is_ok() { maintenance::Phase::Complete } else { maintenance::Phase::Failed }, error: result.err() });
                    actor.state.maintenance_generation = envelope.generation;
                    if let Some(cause) = job_context { actor.state.error_contexts.set_ack(Slot::MaintenanceAck, cause, request_id, envelope.generation); }
                    actor.state.ready = online && !quitting;
                    actor.state.maintenance_available = online && !quitting;
                    actor.state.busy = false;
                    actor.emit();
                    if !online {
                        // Неизвестный drain не разрешает Closed и освобождение lock.
                        // Reopen failure с подтверждённым drain ждёт явный Shutdown.
                        let mut commands_open = true;
                        while !quitting || !job_drained {
                            tokio::select! {
                                changed = priority.changed() => {
                                    quitting = changed.is_err() || priority.borrow_and_update().shutdown;
                                }
                                command = commands.recv(), if commands_open => {
                                    if let Some(command) = command {
                                        reject_unavailable_command(&mut actor.state, &command.command, "busy", Cause::MaintenanceAdmissionReopenUnavailable, command.generation);
                                        actor.emit();
                                    } else { quitting = true; commands_open = false; }
                                }
                            }
                        }
                        break;
                    }
                    if quitting { break; }
                    continue;
                }
                if (local_task.is_some() || local_pending.is_some()) && !matches!(&envelope.command, Command::CancelLocalImport | Command::ApproveRefresh | Command::DiscardRefresh | Command::ReviewPage { .. } | Command::SubscriptionVisibility { .. }) {
                    if envelope.command.is_source_operation() {
                        if let Command::SourceChange { request_id, id, .. } = &envelope.command { actor.state.source_change_ack = Some(SourceChangeAck { request_id: *request_id, id: *id, generation: None, error: Some("busy") }); }
                        actor.state.command_error(true, "busy");
                    } else {
                        let available = actor.state.maintenance_available;
                        if envelope.command.routing_request_id().is_some() { actor.state.routing_generation = envelope.generation; }
                        if matches!(&envelope.command, Command::LogsRead { .. } | Command::LogsSave { .. }) { actor.state.logs_generation = envelope.generation; }
                        reject_unavailable_command(&mut actor.state, &envelope.command, "busy", Cause::MaintenanceAdmissionBusy, envelope.generation);
                        actor.state.maintenance_available = available;
                    }
                    actor.emit(); continue;
                }
                // Запрет до scheduler.cancel/reserve и любого сетевого эффекта.
                let local_forbidden = match &envelope.command {
                    Command::Refresh | Command::SetSourceHwid { .. } | Command::SetSubscriptionSchedule { .. } => actor.state.source_id,
                    Command::SourceChange { id, .. } => Some(*id),
                    _ => None,
                };
                if let Some(id) = local_forbidden {
                    let error = match actor.service().source_is_local(id).await {
                        Ok(false) => None,
                        Ok(true) => Some(DesktopError("invalid_input").into()),
                        Err(error) => Some(SourceFailure::subscription(error)),
                    };
                    if envelope.generation != control.generation.load(Ordering::SeqCst) { continue; }
                    if let Some(error) = error {
                        if let Command::SourceChange { request_id, .. } = &envelope.command { actor.state.source_change_ack = Some(SourceChangeAck { request_id: *request_id, id, generation: None, error: Some(error.key()) }); }
                        actor.state.command_generation = envelope.generation; actor.state.source_failure(true, error, envelope.generation); actor.emit(); continue;
                    }
                }
                let apply_request = match &envelope.command { Command::RoutingApply { request_id, .. } => Some(*request_id), _ => None };
                // Отмена до первого await редактирования исключает отправку Apply после принятия edit.
                if envelope.command.cancels_policy_connect() {
                    if let Some(flight) = system_flight.as_ref().filter(|f| f.connecting) {
                        flight.cancel.send_replace(true);
                        system_stop = true;
                    }
                }

                let source_change = match &envelope.command {
                    Command::SourceChange { request_id, id, .. } => Some((*request_id, *id)),
                    _ => None,
                };
                if let Some((request_id, id)) = source_change {
                    actor.state.source_change_ack = Some(SourceChangeAck { request_id, id, generation: None, error: Some("cancelled") });
                    // Все сигналы до первого await; результаты отменённой работы не публикуются.
                    if let Some((_, cancel, _, _, _)) = refreshing.as_ref() { cancel.send_replace(true); }
                    if let Some(tcp) = tcp_running.as_ref() { tcp.cancel.send_replace(true); }
                    if let Some(batch) = batch_running.as_mut() { batch.stop(); }
                    if let Some(flight) = system_flight.as_ref().filter(|flight| flight.connecting) { flight.cancel.send_replace(true); system_stop = true; }
                    actor.state.batch.invalidate();
                    if scheduled.runtime.cancel(id, origin.elapsed()).is_err() {
                        if let Some(ack) = actor.state.source_change_ack.as_mut() { ack.error = Some("storage"); }
                        actor.state.command_error(true, "storage"); actor.emit(); continue;
                    }
                    // Domain-result отменённой работы не публикуется, panic worker запрещает мутацию.
                    let mut drain_failed = false;
                    if let Some(batch) = batch_running.take() { drain_failed |= batch.task.await.is_err(); }
                    if let Some((_, _, task, _, _)) = refreshing.take() { drain_failed |= task.await.is_err(); actor.state.busy = false; actor.state.refresh_source_id = None; }
                    if let Some(tcp) = tcp_running.take() { drain_failed |= tcp.task.await.is_err(); actor.state.tcp_busy = false; actor.state.tcp_name = None; }
                    if drain_failed {
                        if let Some(ack) = actor.state.source_change_ack.as_mut() { ack.error = Some("storage"); }
                        actor.state.command_error(true, "storage"); actor.emit(); continue;
                    }
                    if actor.pending.as_ref().is_some_and(|pending| pending.identity().id == id) {
                        if let Some(pending) = actor.pending.take() { actor.service().discard_refresh(*pending).await; }
                        actor.state.pending = None;
                    }
                }

                if matches!(&envelope.command, Command::LogsRead { .. } | Command::LogsSave { .. }) { actor.state.logs_generation = envelope.generation; }
                if matches!(&envelope.command, Command::MaintenanceCancel { .. }) { actor.state.maintenance_generation = envelope.generation; }
                let context_request_id = envelope.command.routing_request_id();
                if context_request_id.is_some() { actor.state.routing_generation = envelope.generation; actor.state.error_contexts.clear(Slot::RoutingAck); }


                let source_operation = envelope.command.is_source_operation();
                let reload_schedule = matches!(&envelope.command, Command::AddSource { .. } | Command::ImportSource { .. } | Command::SetSourceHwid { .. });
                if (scheduled.fetching || scheduled.deferred.is_some()) && matches!(&envelope.command, Command::ImportSource { .. } | Command::ApproveRefresh | Command::DiscardRefresh) {
                    actor.state.command_error(true, "busy"); actor.emit(); continue;
                }
                if matches!(&envelope.command, Command::Refresh | Command::SetSourceHwid { .. } | Command::ImportSource { .. }) && (scheduled.review.is_some() || actor.pending.is_some()) {
                    actor.state.command_error(true, "review_required"); actor.emit(); continue;
                }
                if matches!(&envelope.command, Command::Refresh) && (scheduled.fetching || scheduled.deferred.is_some()) {
                    actor.state.command_error(true, "busy"); actor.emit(); continue;
                }
                let cancel_id = match &envelope.command {
                    Command::DeleteSource { id } | Command::SourceChange { id, .. } => Some(*id),
                    Command::SetSourceHwid { .. } | Command::Refresh => actor.state.source_id,
                    _ => None,
                };
                if let Some(id) = cancel_id {
                    let cancelled_review = scheduled.review == Some(id);
                    let Some(cancelled) = await_current_schedule(scheduled.cancel(id, || origin.elapsed()), &control.generation, envelope.generation).await else { continue; };
                    if let Err(error) = cancelled {
                        if source_change.is_some() { if let Some(ack) = actor.state.source_change_ack.as_mut() { ack.error = Some(error.key()); } }
                        actor.state.schedule_error(error, Some(scheduled.generation)); actor.emit(); continue;
                    }
                    if (scheduled.deferred.is_some() || scheduled.fetching) && matches!(&envelope.command, Command::Refresh | Command::SetSourceHwid { .. }) {
                        let Some(reloaded) = await_current_schedule(scheduled.reload_id(actor.service(), id, origin.elapsed()), &control.generation, envelope.generation).await else { continue; };
                        if let Err(error) = reloaded {
                            actor.state.schedule_error(error, Some(scheduled.generation));
                        } else { actor.state.command_error(true, "busy"); }
                        actor.emit(); continue;
                    }
                    if cancelled_review { actor.state.pending = None; }
                }
                if matches!(&envelope.command, Command::RenameSource { .. } | Command::DeleteSource { .. } | Command::SetSourceHwid { .. } | Command::SelectSource { .. } | Command::Refresh | Command::ApproveRefresh | Command::ImportSource { .. } | Command::AddSource { .. }) {
                    if let Some(batch) = batch_running.as_mut() { batch.stop(); }
                    actor.state.batch.invalidate();
                }
                actor.state.command_generation = envelope.generation;
                actor.state.begin_command(&envelope.command);
                let manual_review_completion = if scheduled.review.is_none() && matches!(envelope.command, Command::ApproveRefresh | Command::DiscardRefresh) { actor.pending.as_ref().map(|pending| pending.identity()) } else { None };
                if matches!(envelope.command, Command::SelectProfile { .. } | Command::SelectCatalog { .. } | Command::SelectSource { .. } | Command::Reload | Command::ApproveRefresh) {
                    if let Some(flight) = system_flight.as_ref().filter(|flight| flight.connecting) {
                        flight.cancel.send_replace(true); system_stop = true;
                    }
                }
                let local_is_file = matches!(&envelope.command, Command::ImportFile { .. });
                let outcome: SourceResult<()> = match envelope.command {
                    Command::Connect if actor.selected_native.is_some() => {
                        if actor.state.can_stop || running.is_some() || refreshing.is_some() || system_flight.is_some() || actor.state.system_busy {
                            Err(DesktopError("busy").into())
                        } else if session_generation == u64::MAX {
                            Err(DesktopError("engine_failed").into())
                        } else if actor.pending.is_some() || scheduled.review.is_some() {
                            Err(DesktopError("review_required").into())
                        } else {
                            match actor.native_connect_preflight(&Command::Connect, &control, envelope.generation, false).await {
                                Err(error) => Err(error),
                                Ok((intent, binary)) => {
                                    let mode = match actor.state.connection_mode { ConnectionMode::System => yonik_linux::FullProfileMode::System, ConnectionMode::Local => yonik_linux::FullProfileMode::Local };
                                    if yonik_linux::full_profile_preflight(mode).is_err() { Err(DesktopError("profile_unavailable").into()) }
                                    else if envelope.generation != control.generation.load(Ordering::SeqCst) { Err(DesktopError("cancelled").into()) }
                                    else if actor.state.connection_mode == ConnectionMode::System {
                                        let mut selection = [0; 32];
                                        match getrandom::getrandom(&mut selection).map_err(|_| DesktopError("engine_failed")).and_then(|()| {
                                            yonik_linux::helper::profile_intent::FullProfileRequest::new(intent, envelope.generation.checked_add(1).ok_or(DesktopError("engine_failed"))?, selection, true).map_err(|_| DesktopError("engine_config"))
                                        }) {
                                            Err(error) => Err(error.into()),
                                            Ok(request) => {
                                                system_flight = Some(Flight::start(system_session.take(), Operation::FullProfile(Box::new(request)), system_revision(&actor), envelope.generation, actor.event_log.clone()));
                                                if let Some(flight) = &mut system_flight { flight.source_generation = actor.state.source_generation; }
                                                actor.state.can_stop = true; system_active = true;
                                                actor.state.active_name = actor.state.selected_name.clone(); actor.state.active_engine = Some(EngineChoice::Xray);
                                                actor.state.system_state = "Unknown"; actor.state.status = "Preparing"; Ok(())
                                            }
                                        }
                                    } else {
                                        match actor.prepare_port().and_then(|()| {
                                            let port = NonZeroU16::new(actor.state.port).ok_or(DesktopError("invalid_input"))?;
                                            let probe = available_port(0)?;
                                            let graph = intent.validate().map_err(|_| DesktopError("engine_config"))?;
                                            let mut plan = yonik_engine::native_profile::OwnedRuntimePlan::new(port, probe).map_err(|_| DesktopError("engine_config"))?;
                                            for ingress in graph.ingresses() { plan = plan.map_ingress(ingress.tag(), yonik_engine::native_profile::OwnedIngress::Local).map_err(|_| DesktopError("engine_config"))?; }
                                            Ok(plan)
                                        }).and_then(|plan| actor.probe_target().map(|target| (plan, target))) {
                                            Err(error) => Err(error.into()),
                                            Ok((plan, target)) => {
                                                let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, plan.local_port().get()));
                                                let (cancel, receiver) = Cancellation::new();
                                                session_generation = session_generation.saturating_add(1); actor.state.error_generation = session_generation;
                                                let task = tokio::spawn(session(SessionConfig::FullProfile(Box::new(NativeSessionConfig {intent, plan, image: Some(binary)})), config.engine_dir.clone(), Engine::Xray, target, receiver, (updates.clone(), actor.event_log.clone(), session_generation), network.clone(), #[cfg(feature = "test-support")] config.cleanup_fault.clone()));
                                                running = Some(Running { lease: (session_generation, endpoint), cancel, task });
                                                actor.state.can_stop = true; actor.state.active_name = actor.state.selected_name.clone(); actor.state.active_engine = Some(EngineChoice::Xray);
                                                actor.state.probe_result = None; actor.state.status = "Preparing"; Ok(())
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ref command if actor.selected_native.is_some() && command.requires_server_selection() => Err(DesktopError("profile_unavailable").into()),
                    Command::StartupPreferencesSet { request_id, expected_revision, autostart_into_tray, autoconnect } => actor.startup_save(request_id, expected_revision, Some((autostart_into_tray, autoconnect)), &control, envelope.generation).await.map_err(Into::into),
                    Command::AutoconnectTargetSet { request_id, expected_revision } => actor.startup_save(request_id, expected_revision, None, &control, envelope.generation).await.map_err(Into::into),
                    Command::ImportText { name, text } | Command::ImportFile { name, path: text } => {
                        if refreshing.is_some() || scheduled.fetching || scheduled.deferred.is_some() || scheduled.review.is_some() || actor.pending.is_some() || actor.state.can_stop { Err(DesktopError("busy").into()) }
                        else {
                            let is_file = local_is_file;
                            let (cancel, receiver) = watch::channel(false);
                            let task = tokio::spawn(async move {
                                if is_file { crate::local_import::prepare_file(PathBuf::from(text), receiver).await }
                                else { crate::local_import::prepare_text(text.into_bytes(), receiver).await }
                            });
                            local_task = Some((name, cancel, task)); actor.state.busy = true; Ok(())
                        }
                    }
                    Command::CancelLocalImport => {
                        if let Some((_, cancel, _)) = &local_task { cancel.send_replace(true); }
                        if local_pending.take().is_some() { actor.state.pending = None; } Ok(())
                    }
                    Command::DiscardRefresh if local_pending.is_some() => { local_pending = None; actor.state.pending = None; Ok(()) }
                    Command::ReviewPage { offset } if local_pending.is_some() => { match report_dto(&local_pending.as_ref().expect("guard").1, offset) { Ok(dto) => { actor.state.pending = Some(dto); Ok(()) }, Err(error) => Err(error.into()) } }
                    Command::ApproveRefresh if local_pending.is_some() => {
                        let (name, report) = local_pending.as_ref().expect("guard");
                        let result = {
                            let (sender, cancel) = Cancellation::new();
                            let mut interruption = control.priority.subscribe();
                            let operation = actor.service().approve_local_profiles(name.clone(), report, cancel, actor.format4_backup.clone());
                            tokio::pin!(operation);
                            tokio::select! {
                                biased;
                                _ = interruption.changed() => { sender.send_replace(true); let _ = operation.await; Err(DesktopError("cancelled").into()) }
                                result = &mut operation => result.map_err(SourceFailure::subscription),
                            }
                        };
                        match result {
                            Ok(id) if envelope.generation == control.generation.load(Ordering::SeqCst) => { local_pending = None; actor.state.pending = None; actor.state.source_id = Some(id); actor.state.offset = 0; actor.state.search.clear(); actor.state.favorites_only = false; actor.clear_selection(); actor.reload().await }
                            Ok(_) => { local_pending = None; actor.state.pending = None; Err(DesktopError("cancelled").into()) }
                            Err(error) => Err(error)
                        }
                    }
                    Command::SubscriptionVisibility { visible } => { scheduled.visible = visible; Ok(()) }
                    Command::ApproveRefresh | Command::DiscardRefresh if scheduled.review.is_some() => {
                        let approve = matches!(envelope.command, Command::ApproveRefresh);
                        let id = scheduled.review.take().expect("review guard");
                        actor.state.pending = None;
                        match scheduled.runtime.finish_review(actor.service(), id, approve, || origin.elapsed()).await {
                            Ok(_) => { actor.clear_selection(); actor.page().await }
                            Err(error) => Err(SourceFailure::subscription(error)),
                        }
                    }
                    Command::ReviewPage { offset } if scheduled.review.is_some() => {
                        match scheduled.review.and_then(|id| scheduled.runtime.review(id)) {
                            Some(pending) => pending_dto(pending, offset).map(|dto| actor.state.pending = Some(dto)).map_err(Into::into),
                            None => Err(DesktopError("review_required").into()),
                        }
                    }
                    Command::SelectSource { .. } | Command::ImportSource { .. } | Command::AddSource { .. } if scheduled.review.is_some() => Err(DesktopError("review_required").into()),

                    Command::CancelRefresh { id, token } => {
                        match refreshing.as_ref() {
                            Some((_, cancel, _, source, current_token)) if source.id == id && token == *current_token && !*cancel.borrow() => {
                                cancel.send_replace(true);
                                Ok(())
                            }
                            _ => Err(DesktopError("refresh_required").into()),
                        }
                    }
                    Command::BatchPage { offset } => { actor.state.batch.page(offset); Ok(()) }
                    Command::CheckBatch => {
                        if batch_running.is_some() || actor.state.busy { Err(DesktopError("busy").into()) }
                        else if envelope.generation != control.generation.load(Ordering::SeqCst) || envelope.tcp_generation != *control.tcp_priority.borrow() { Err(DesktopError("cancelled").into()) }
                        else { match actor.start_batch(envelope.generation, envelope.tcp_generation) {
                            Ok(batch) => { batch_running = Some(batch); Ok(()) }, Err(error) => Err(error.into())
                        } }
                    }
                    Command::CheckTcp => {
                        if envelope.tcp_generation != *control.tcp_priority.borrow() {
                            Err(DesktopError("cancelled").into())
                        } else if tcp_running.is_some() || actor.state.busy {
                            Err(DesktopError("busy").into())
                        } else if let Some(profile) = actor.selected.as_ref() {
                            let target = TcpProbeTarget::for_server(&profile.server);
                            let current = network.as_ref().map(NetworkWatch::current);
                            let network_stamp = current.map(|network| network.stamp);
                            let result = TcpResultDto {
                                source_id: profile.profile.source_id, profile_id: profile.profile.id,
                                revision: profile.snapshot_revision, name: profile.profile.name.clone(),
                                host: profile.server.endpoint().host().into(), port: profile.server.endpoint().port(),
                                status: "cancelled", dns_ms: None, connect_ms: None, checked_at_ms: 0,
                                samples_ms: Vec::new(), samples_requested: TCP_SERIES_SAMPLES,
                                selected_address: None,
                                network_epoch: network_stamp.map(|stamp| stamp.to_string()),
                                network_observed: current.is_some_and(NetworkSnapshot::fully_observed),
                            };
                            let (cancel, mut receiver) = Cancellation::new();
                            let task = tokio::spawn(async move { check_tcp_series(target, Duration::from_secs(5), &mut receiver).await });
                            actor.state.tcp_busy = true; actor.state.tcp_name = Some(result.name.clone());
                            actor.state.tcp_result = None;
                            actor.state.tcp_invalidated = false;
                            tcp_running = Some(TcpRunning { generation: envelope.generation,
                                tcp_generation: envelope.tcp_generation, network_stamp, result, cancel, task });
                            Ok(())
                        } else { Err(DesktopError("profile_required").into()) }
                    }
                    Command::ImportSource { name, url, local_exception, route, hwid_enabled } => {
                        if refreshing.is_some() { Err(DesktopError("busy").into()) }
                        else {
                            match actor.source_command(Command::AddSource { name, url, local_exception, route, hwid_enabled }).await {
                                Ok(()) => {
                                    actor.state.search.clear(); actor.state.favorites_only = false;
                                    match actor.refresh(envelope.generation, scheduled.generation, { let host = DesktopFetch::subscription(&proxy_session, actor.preferences.proxy_fetch_dns, #[cfg(feature = "test-support")] config.test_subscription_fetch.clone()); manual_host = Some(host.clone()); host }).await {
                                        Ok(task) => { refreshing = Some(task); Ok(()) }
                                        Err(error) => Err(error),
                                    }
                                }
                                Err(error) => Err(error),
                            }
                        }
                    }
                    Command::SetSourceHwid { enabled } => {
                        if refreshing.is_some() { Err(DesktopError("busy").into()) }
                        else {
                            match actor.source_command(Command::SetSourceHwid { enabled }).await {
                                Ok(()) => match actor.refresh(envelope.generation, scheduled.generation, { let host = DesktopFetch::subscription(&proxy_session, actor.preferences.proxy_fetch_dns, #[cfg(feature = "test-support")] config.test_subscription_fetch.clone()); manual_host = Some(host.clone()); host }).await {
                                    Ok(task) => { refreshing = Some(task); Ok(()) }
                                    Err(error) => Err(error),
                                },
                                Err(error) => Err(error),
                            }
                        }
                    }
                    Command::PresetValidate { request_id, .. } if actor.state.engine.ensure_available().is_err() => {
                        actor.state.presets.ack = Some(presets::Ack { request_id, error: Some(if preset_job.is_some() { "busy" } else { "engine_unavailable" }) });
                        Ok(())
                    }
                    Command::PresetValidate { request_id, expected_revision } => {
                        actor.invalidate_preset();
                        if preset_job.is_some() {
                            actor.state.presets.ack = Some(presets::Ack { request_id, error: Some("busy") });
                        } else if actor.state.routing_revision != Some(expected_revision) {
                            actor.state.presets.ack = Some(presets::Ack { request_id, error: Some("routing_stale") });
                        } else if let (Some(controller), Some(profile), Some(port), Some(probe)) = (&actor.presets, &actor.selected, NonZeroU16::new(actor.state.port), actor.state.port.checked_add(1).and_then(NonZeroU16::new)) {
                            match controller.compile(&actor.state.routing, &profile.server, actor.state.engine.engine(), port, probe) {
                                Ok(compiled) => {
                                    preset_job = Some(presets::Job::validate(compiled, config.engine_dir.clone(), request_id));
                                    preset_validation = actor.preset_scope();
                                    actor.state.presets.busy = true; actor.state.presets.active_request_id = Some(request_id);
                                    actor.state.presets.ack = None;
                                },
                                Err(error) => {
                                    actor.state.presets.compiler_error = Some(error);
                                    actor.state.presets.ack = Some(presets::Ack { request_id, error: Some("engine_config") });
                                },
                            }
                        } else { actor.state.presets.ack = Some(presets::Ack { request_id, error: Some("profile_required") }); }
                        Ok(())
                    }
                    Command::PresetUpdate { metadata, route, local_exception, request_id } => {
                        if preset_job.is_some() {
                            actor.state.presets.ack = Some(presets::Ack { request_id, error: Some("busy") });
                            Ok(())
                        } else if let Some(controller) = &actor.presets {
                            match presets::Job::start(controller.clone(), DesktopFetch::new(&proxy_session, actor.preferences.proxy_fetch_dns), metadata,
                                match route { Route::Direct => FetchRoute::Direct, Route::Proxy => FetchRoute::Proxy }, local_exception, request_id) {
                                Ok(job) => { actor.invalidate_preset(); preset_job = Some(job); actor.state.presets.busy = true; actor.state.presets.active_request_id = Some(request_id); actor.state.presets.ack = None; Ok(()) },
                                Err(error) => { actor.state.presets.ack = Some(presets::Ack { request_id, error: Some(error) }); Ok(()) },
                            }
                        } else {
                            actor.state.presets.ack = Some(presets::Ack { request_id, error: Some("storage") });
                            actor.state.presets.operation_error = Some("storage");
                            Ok(())
                        }
                    }
                    Command::PresetCancel { request_id } => {
                        if let Some(job) = &preset_job {
                            if job.request_id == request_id { job.stop(); }
                        }
                        Ok(())
                    }
                    Command::Refresh => {
                        if refreshing.is_some() { Err(DesktopError("busy").into()) }
                        else { match actor.refresh(envelope.generation, scheduled.generation, { let host = DesktopFetch::subscription(&proxy_session, actor.preferences.proxy_fetch_dns, #[cfg(feature = "test-support")] config.test_subscription_fetch.clone()); manual_host = Some(host.clone()); host }).await {
                            Ok(task) => { refreshing = Some(task); Ok(()) }
                            Err(error) => Err(error),
                        } }
                    }
                    Command::SetConnectionMode { mode } => {
                        if actor.state.can_stop || actor.state.system_recovery_pending || system_flight.is_some() || system_stop { Err(DesktopError("busy").into()) }
                        else { actor.state.connection_mode = mode; actor.state.status = "Disconnected"; Ok(()) }
                    }
                    Command::SystemState | Command::SystemUnlock => {
                        if actor.state.connection_mode != ConnectionMode::System || system_flight.is_some() || (system_active && matches!(envelope.command, Command::SystemUnlock)) { Err(DesktopError("busy").into()) }
                        else {
                            let operation = if matches!(envelope.command, Command::SystemUnlock) { Operation::Unlock } else { Operation::State };
                            system_flight = Some(Flight::start(system_session.take(), operation, system_revision(&actor), envelope.generation, actor.event_log.clone()));
                            actor.state.status = "Unknown"; Ok(())
                        }
                    }
                    Command::Connect | Command::RoutingApply { .. } if actor.state.ensure_connection_engine(actor.state.engine).is_err() => {
                        if actor.state.can_stop || running.is_some() || refreshing.is_some() || system_flight.is_some() || system_stop {
                            Err(DesktopError("busy").into())
                        } else {
                            actor.state.ensure_connection_engine(actor.state.engine).map_err(Into::into)
                        }
                    }
                    Command::Connect if actor.routing_revision.is_none() => Err(DesktopError("routing_storage").into()),
                    Command::Connect if actor.state.routing.policy().is_err() => Err(DesktopError("routing_storage").into()),
                    Command::Connect if actor.state.routing.policy().ok().and_then(|p| p.unsupported_selector().or_else(|| p.unsupported_transport())).is_some() => Err(DesktopError("unsupported_option").into()),
                    command @ (Command::Connect | Command::RoutingApply { .. }) if actor.state.connection_mode == ConnectionMode::System => {
                        let request_id = if let Command::RoutingApply { request_id, .. } = &command { Some(*request_id) } else { None };
                        if let Err(error) = actor.check_routing_apply(&command).await { Err(error.into()) }
                        else if actor.state.can_stop || (request_id.is_some() && actor.state.system_recovery_pending) || system_flight.is_some() || refreshing.is_some() || system_stop { Err(DesktopError("busy").into()) }
                        else if actor.pending.is_some() || scheduled.review.is_some() { Err(DesktopError("review_required").into()) }
                        else if let Some(profile) = actor.selected.as_ref() {
                            match yonik_import::ServerIntent::from_server(&profile.server).map_err(|_| DesktopError("engine_config")).and_then(|server| actor.current_inline_policy().map(|(policy, revision)| (server, policy, revision))) {
                                Ok((server, policy, routing_revision)) => {
                                    let suffixes = if actor.state.system_fake_dns_configured() {
                                        actor.state.system_fake_dns.clone()
                                    } else {
                                        Vec::new()
                                    };
                                    system_flight = Some(Flight::start(system_session.take(), Operation::PolicyConnect(Box::new(server), actor.state.engine.engine(), Box::new(policy), routing_revision, suffixes), system_revision(&actor), envelope.generation, actor.event_log.clone()));
                                    if let Some(flight) = &mut system_flight { flight.request_id = request_id; flight.source_generation = actor.state.source_generation; }
                                    actor.state.system_tun_available = false;
                                    actor.state.routing_ack = None;
                                    actor.state.can_stop = true; system_active = true;
                                    actor.state.active_name = Some(profile.profile.name.clone());
                                    actor.state.active_engine = Some(actor.state.engine);
                                    actor.state.system_state = "Unknown"; actor.state.status = "Preparing"; Ok(())
                                }
                                Err(error) => Err(error.into()),
                            }
                        } else { Err(DesktopError("profile_required").into()) }
                    }
                    Command::Connect => {
                        if actor.state.can_stop || running.is_some() || refreshing.is_some() { Err(DesktopError("busy").into()) }
                        else if session_generation == u64::MAX { Err(DesktopError("engine_failed").into()) }
                        else if actor.selected.is_none() { Err(DesktopError("profile_required").into()) }
                        else if actor.pending.is_some() || scheduled.review.is_some() { Err(DesktopError("review_required").into()) }
                        else if let Err(error) = actor.prepare_port() { Err(error.into()) }
                        else if let Some(profile) = actor.selected.as_ref() {
                            if actor.pending.is_some() { Err(DesktopError("review_required").into()) }
                            else {
                                match (NonZeroU16::new(actor.state.port).and_then(|port| yonik_engine::compile(&profile.server, actor.state.engine.engine(), port).ok()), actor.probe_target()) {
                                    (Some(compiled), Ok(target)) => {
                                        let (cancel, receiver) = Cancellation::new();
                                        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, compiled.listen_port().get()));
                                        session_generation = session_generation.saturating_add(1); actor.state.error_generation = session_generation;
                                        #[cfg(feature = "test-support")]
                                        let receiver = if let Some(gate) = config.lifecycle_gate.clone() { receiver.with_lifecycle_gate(gate, session_generation) } else { receiver };
                                        let task = tokio::spawn(session(SessionConfig::Server(compiled), config.engine_dir.clone(), actor.state.engine.engine(), target, receiver, (updates.clone(), actor.event_log.clone(), session_generation), network.clone(), #[cfg(feature = "test-support")] config.cleanup_fault.clone()));
                                        running = Some(Running { lease: (session_generation, endpoint), cancel, task }); actor.state.can_stop = true;
                                        actor.state.active_name = Some(profile.profile.name.clone()); actor.state.active_engine = Some(actor.state.engine);
                                        actor.state.probe_result = None; actor.state.status = "Preparing"; Ok(())
                                    }
                                    (_, Err(error)) => Err(error.into()),
                                    _ => Err(DesktopError("engine_config").into()),
                                }
                            }
                        } else { Err(DesktopError("profile_required").into()) }
                    }
                    Command::PresetActivate { request_id, .. } | Command::PresetPrepare { request_id, .. } | Command::PresetRollback { request_id } if preset_job.is_some() => {
                        actor.state.presets.ack = Some(presets::Ack { request_id, error: Some("busy") }); Ok(())
                    }
                    Command::PresetStatus if preset_job.is_some() => Err(DesktopError("busy").into()),
                    command => {
                        if refreshing.is_some() && matches!(command, Command::SelectSource { .. } | Command::AddSource { .. } | Command::ApproveRefresh | Command::RenameSource { .. } | Command::DeleteSource { .. }) {
                            Err(DesktopError("busy").into())
                        } else { actor.source_command(command).await }
                    }
                };
                if envelope.generation != control.generation.load(Ordering::SeqCst) { actor.clear_selection(); continue; }
                let command_context = outcome.as_ref().err().and_then(|failure| {
                    context_request_id.and_then(|id| actor.state.error_contexts.matching(Slot::RoutingAck, Some(failure.key()), Some(id)))
                        .or_else(|| actor.state.error_contexts.matching(Slot::Error, Some(failure.key()), None))
                        .filter(|context| matches!(context.stage, crate::diagnostics::context::Stage::RoutingSave | crate::diagnostics::context::Stage::CatalogRead | crate::diagnostics::context::Stage::StorageWrite))
                });
                if let Some(identity) = manual_review_completion {
                    let storage_failed = matches!(&outcome, Err(error) if error.key() == "storage");
                    let Some(reconciled) = await_current_schedule(reconcile_manual_schedule(&mut scheduled, actor.service(), identity, || origin.elapsed(), storage_failed), &control.generation, envelope.generation).await else { continue; };
                    if let Err(error) = reconciled { actor.state.schedule_error(error, Some(scheduled.generation)); }
                }
                let mut schedule_reload_error = None;
                if reload_schedule || cancel_id.is_some() {
                    if let Some(id) = cancel_id.or(actor.state.source_id) {
                        let Some(reloaded) = await_current_schedule(scheduled.reload_id(actor.service(), id, origin.elapsed()), &control.generation, envelope.generation).await else { continue; };
                        if let Err(error) = reloaded {
                            schedule_reload_error = Some(error.key());
                            actor.state.schedule_error(error, Some(scheduled.generation));
                        }
                    }
                }
                if let (Some(request_id), Err(error)) = (apply_request, &outcome) {
                    actor.state.routing_ack = Some(RoutingAck { request_id, saved_id: None, error: Some(error.key()) });
                }

                if source_change.is_some() {
                    if let Some(ack) = actor.state.source_change_ack.as_mut() {
                        ack.error = outcome.as_ref().err().map(|error| error.key()).or(schedule_reload_error);
                    }
                }

                if let Err(error) = outcome {
                    actor.state.source_failure(source_operation, error, envelope.generation);
                    if let Some(context) = command_context {
                        actor.state.error_contexts.set_generation(Slot::Error, context.reason, context.generation);
                        actor.state.error_contexts.set_generation(if source_operation { Slot::Source } else { Slot::Connection }, context.reason, context.generation);
                    }
                }

                actor.state.system_busy = system_flight.is_some();
                actor.emit();
            }
        }
        if batch_running.as_ref().is_some_and(|batch| {
            !batch.output_closed
                && (batch.generation != control.generation.load(Ordering::SeqCst)
                    || batch.tcp_generation != *control.tcp_priority.borrow()
                    || !network_matches(network.as_ref().map(NetworkWatch::current), batch.stamp)
                    || actor.state.batch.source_id != actor.state.source_id
                    || actor.state.batch.revision != actor.state.revision)
        }) {
            let stale = batch_running.as_ref().is_some_and(|batch| {
                !network_matches(network.as_ref().map(NetworkWatch::current), batch.stamp)
                    || actor.state.batch.source_id != actor.state.source_id
                    || actor.state.batch.revision != actor.state.revision
            });
            if let Some(batch) = batch_running.as_mut() {
                batch.stop();
            }
            if stale {
                actor.state.batch.invalidate();
            } else {
                actor.state.batch.cancelled = true;
            }
            actor.emit();
        }
        if !actor.state.batch.invalidated
            && actor.state.batch.source_id.is_some()
            && (actor.state.batch.source_id != actor.state.source_id
                || actor.state.batch.revision != actor.state.revision)
        {
            actor.state.batch.invalidate();
            actor.emit();
        }
        if let Some(tcp) = tcp_running.as_ref() {
            if actor.tcp_key() != Some(tcp.result.key()) {
                tcp.cancel.send_replace(true);
            }
        }
        if actor
            .state
            .tcp_result
            .as_ref()
            .is_some_and(|result| actor.tcp_key() != Some(result.key()))
        {
            actor.state.tcp_result = None;
            actor.emit();
        }
        if system_flight.as_ref().is_some_and(|flight| {
            flight.connecting
                && (flight.revision != system_revision(&actor)
                    || flight
                        .routing_revision
                        .is_some_and(|revision| actor.routing_revision != Some(revision)))
        }) {
            if let Some(flight) = &system_flight {
                flight.cancel.send_replace(true);
            }
            system_stop = true;
        }
        if system_stop && system_flight.is_none() {
            let generation = control.generation.load(Ordering::SeqCst);
            system_flight = Some(Flight::start(
                system_session.take(),
                Operation::Stop,
                system_revision(&actor),
                generation,
                actor.event_log.clone(),
            ));
            actor.state.system_busy = true;
            actor.emit();
        }
        if quitting
            && preset_job.is_none()
            && !actor.logs_save.active()
            && system_flight.is_none()
            && !system_stop
            && batch_running.is_none()
            && running.is_none()
            && refreshing.is_none()
            && tcp_running.is_none()
        {
            if failed_session.is_some() || system_active {
                quitting = false;
                actor
                    .state
                    .session_error(Cause::CleanupFailed, session_generation);
                actor.emit();
                continue;
            }
            break;
        }
    }
    if let Err(error) = scheduled.shutdown(origin.elapsed()).await {
        actor
            .state
            .schedule_error(error, Some(scheduled.generation));
    }
    // Отмена с acknowledgement: Drop может отложить zbus cleanup до следующего poll.
    provider_stop.send_replace(true);
    let provider_closed = !provider_enabled || provider.as_mut().await.is_ok();
    drop(provider);
    actor.pending = None;
    let network_closed = if let Some(monitor) = network_monitor {
        monitor.shutdown().await
    } else {
        true
    };
    actor.clear_selection();
    let service_closed = if let Some(service) = actor.service.take() {
        service.close().await.is_ok()
    } else {
        true
    };
    let routing_closed = if let Some(repository) = actor.routing_repository.take() {
        repository.close().await.is_ok()
    } else {
        true
    };
    let output_closed = match system_session.as_mut() {
        Some(session) => session.drain_output().await,
        None => true,
    };
    disk_log.request_shutdown();
    // Guard остаётся здесь до Done; actor не выполняет файловые операции и join.
    while !disk_log.wait_closed(Duration::ZERO) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let closed =
        service_closed && routing_closed && provider_closed && network_closed && output_closed;
    drop(_lock);
    actor.state.ready = false;
    actor.state.busy = false;
    actor.state.can_connect = false;
    actor.state.closed = closed;
    actor
        .state
        .error_contexts
        .clear(crate::diagnostics::context::Slot::Error);
    actor.state.error = if closed { None } else { Some("cleanup_failed") };
    actor
        .state
        .error_contexts
        .clear(crate::diagnostics::context::Slot::Connection);
    actor.state.connection_error = actor.state.error;
    actor.state.emit(&actor.callback);
    if closed {
        control.closed();
    }
    if let Some(task) = signals {
        task.abort();
    }
}

#[cfg(test)]
mod routing_regressions {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    async fn fixture() -> (Actor, File, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "yonik-routing-p2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("часы")
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("fixture");
        let mut config =
            HostConfig::new(path.clone(), path.join("engines")).with_ephemeral_key([71; 32]);
        let (service, lock, routing_repository) = open(&mut config).await.expect("БД");
        routing_repository
            .routing_draft()
            .await
            .expect("инициализация");
        let (preferences_store, preferences, _) = Store::open(&path);
        (
            Actor {
                #[cfg(feature = "test-support")]
                catalog_observer: None,
                presets: None,
                event_log: yonik_linux::event_log::EventLog::new(),
                logs_save: crate::backend::logs::SaveJob::default(),
                routing_repository: Some(routing_repository),
                format4_backup: None,
                routing_revision: Some(0),
                preferences_store,
                preferences,
                service: Some(service),
                state: Snapshot::new(true),
                callback: Arc::new(|_| {}),
                selected: None,
                selected_native: None,
                selected_native_token: None,
                catalog_selections: Vec::new(),
                catalog_coordinates: None,
                pending: None,
                automatic_port: true,
                probe_url: Zeroizing::new(DEFAULT_PROBE_URL.into()),
                network: None,
            },
            lock,
            path,
        )
    }
    #[tokio::test(flavor = "current_thread")]
    async fn source_actual_missing_table_проходит_через_ручные_команды() {
        let (mut actor, lock, path) = fixture().await;
        actor.state.source_id = Some(1);
        actor.state.sources = vec![SourceDto {
            id: 1,
            name: "Fixture".into(),
            hwid_enabled: false,
        }];
        actor.state.command_generation = 91;
        // Нарушаем только схему собственной fixture: настоящий SQL lookup вернёт Storage.
        let status = std::process::Command::new("python3")
            .arg("-c")
            .arg("import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute('ALTER TABLE sources RENAME TO unavailable_sources'); db.commit(); db.close()")
            .arg(path.join("subscriptions.sqlite"))
            .status()
            .expect("Python sqlite3 fixture");
        assert!(status.success());
        for value in [
            serde_json::json!({"command":"reload"}),
            serde_json::json!({"command":"source_page", "offset":0}),
            serde_json::json!({"command":"query", "search":"", "favorites_only":false, "offset":0}),
            serde_json::json!({"command":"select_source", "id":1}),
            serde_json::json!({"command":"rename_source", "id":1, "name":"Renamed"}),
            serde_json::json!({"command":"set_source_hwid", "enabled":true}),
            serde_json::json!({"command":"delete_source", "id":1}),
        ] {
            let command: Command = serde_json::from_value(value).expect("команда");
            actor.state.begin_command(&command);
            let failure = actor
                .source_command(command)
                .await
                .expect_err("реальный отказ SQL lookup");
            assert_eq!(failure.key(), "storage");
            actor.state.source_failure(true, failure, 91);
            let context = actor
                .state
                .error_contexts
                .matching(Slot::Source, Some("storage"), None)
                .expect("companion");
            assert_eq!(context.reason, Cause::SourceRepositoryStorage);
            assert_eq!(context.generation, Some(91));
        }
        let (lease, _) = watch::channel(None);
        let failure = actor
            .refresh(91, 17, DesktopFetch::new(&lease, None))
            .await
            .map(|_| ())
            .expect_err("refresh admission");
        actor.state.source_failure(true, failure, 91);
        assert_eq!(
            actor
                .state
                .error_contexts
                .matching(Slot::Source, Some("storage"), None)
                .expect("refresh")
                .reason,
            Cause::SourceRepositoryStorage
        );
        // Тот же service preflight используется runtime перед SetSubscriptionSchedule.
        let failure = actor
            .service()
            .source_is_local(1)
            .await
            .expect_err("schedule preflight");
        actor
            .state
            .source_failure(true, SourceFailure::subscription(failure), 91);
        assert_eq!(
            actor
                .state
                .error_contexts
                .matching(Slot::Source, Some("storage"), None)
                .expect("schedule")
                .reason,
            Cause::SourceRepositoryStorage
        );
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("очистка своей fixture");
    }
    #[tokio::test]
    async fn p6_native_data_selection_is_closed_and_revision_bound() {
        let (mut actor, lock, path) = fixture().await;
        let original = include_bytes!("../../../tests/fixtures/xray-full-profile-seven.json");
        actor.source_command(serde_json::from_value(serde_json::json!({"command":"add_source","name":"Полные профили","url":"https://example.org/native","local_exception":false,"route":"direct","hwid_enabled":false})).expect("источник")).await.expect("создать источник без fetch");
        let native_source = actor.state.source_id.expect("источник");
        actor
            .routing_repository()
            .commit_snapshot(
                native_source,
                1,
                0,
                yonik_linux::SnapshotInput {
                    body: original.to_vec(),
                    metadata: b"{}".to_vec(),
                    validators: None,
                },
            )
            .await
            .expect("DATA snapshot");
        actor.reload().await.expect("каталог");
        assert_eq!(actor.state.profiles.len(), 7);
        assert_eq!(actor.catalog_selections.len(), 7);
        let id = actor.state.profiles[0].id;
        let page = actor.state.catalog_page;
        for row in &actor.state.profiles {
            assert_eq!(row.kind, "xray");
            assert!(row.host.is_none() && row.port.is_none() && row.selectable);
        }
        assert!(
            actor
                .catalog_selection(CatalogKind::Server, id, page)
                .is_err()
        );
        assert!(
            actor
                .catalog_selection(CatalogKind::Xray, id, page + 1)
                .is_err()
        );
        let routing = serde_json::to_value(&actor.state.routing).expect("draft");
        actor
            .source_command(Command::SelectCatalog {
                kind: CatalogKind::Xray,
                id,
                page,
            })
            .await
            .expect("выбор DATA");
        assert!(actor.selected.is_none());
        assert!(actor.selected_native.is_some());
        assert_eq!(actor.state.selected_kind, Some("xray"));
        let control = Control {
            generation: AtomicU64::new(0),
            priority: watch::channel(Priority::default()).0,
            tcp_priority: watch::channel(0).0,
            subscription_policy: watch::channel(Default::default()).0,
            subscription_override: AtomicBool::new(false),
            subscription_visible: watch::channel(false).0,
            closed: (Mutex::new(false), Condvar::new()),
        };
        for mode in [ConnectionMode::Local, ConnectionMode::System] {
            actor.state.connection_mode = mode;
            assert_eq!(
                actor
                    .native_connect_preflight(&Command::Connect, &control, 0, false)
                    .await
                    .map(|_| ())
                    .expect_err("закрытый gate до effects")
                    .key(),
                "profile_unavailable"
            );
            assert_eq!(
                actor
                    .native_connect_preflight(&Command::Connect, &control, 0, true)
                    .await
                    .map(|_| ())
                    .expect_err("busy")
                    .key(),
                "busy"
            );
            control.generation.store(1, Ordering::SeqCst);
            assert_eq!(
                actor
                    .native_connect_preflight(&Command::Connect, &control, 0, false)
                    .await
                    .map(|_| ())
                    .expect_err("cancelled")
                    .key(),
                "cancelled"
            );
            control.generation.store(0, Ordering::SeqCst);
            assert!(actor.selected.is_none(), "legacy runner не получает native");
            assert!(!actor.state.can_stop && !actor.state.system_busy);
        }
        actor.state.connection_mode = ConnectionMode::Local;
        let source = actor.state.source_id.take();
        assert_eq!(
            actor
                .native_connect_preflight(&Command::Connect, &control, 0, false)
                .await
                .map(|_| ())
                .expect_err("смена источника")
                .key(),
            "profile_unavailable"
        );
        actor.state.source_id = source;
        actor.state.system_recovery_pending = true;
        assert_eq!(
            actor
                .native_connect_preflight(&Command::Connect, &control, 0, false)
                .await
                .map(|_| ())
                .expect_err("recovery barrier")
                .key(),
            "busy"
        );
        actor.state.system_recovery_pending = false;
        let intent = actor
            .native_connect_intent(&control, 0)
            .await
            .expect("полный intent");
        let request =
            yonik_linux::helper::profile_intent::FullProfileRequest::new(intent, 1, [47; 32], true)
                .expect("request без host proofs");
        let flight = Flight::start(
            None,
            Operation::FullProfile(Box::new(request)),
            system_revision(&actor),
            0,
            actor.event_log.clone(),
        );
        assert!(flight.connecting && flight.mutating && flight.routing_revision.is_none());
        let (retained, outcome) = flight.task.await.expect("preflight task");
        assert!(
            retained.is_none(),
            "SystemClient не создаётся при закрытом gate"
        );
        assert!(matches!(outcome, Err(ClientError::Unsupported)));
        let intent = actor
            .native_connect_intent(&control, 0)
            .await
            .expect("local intent");
        let plan = yonik_engine::native_profile::OwnedRuntimePlan::new(
            10808.try_into().expect("port"),
            10809.try_into().expect("probe port"),
        )
        .expect("owned plan");
        let (_cancel, cancellation) = Cancellation::new();
        let (output, mut events) = mpsc::channel(1);
        assert!(
            session(
                SessionConfig::FullProfile(Box::new(NativeSessionConfig {
                    intent,
                    plan,
                    image: None
                })),
                path.join("nonexistent-engine"),
                Engine::Xray,
                actor.probe_target().expect("probe target DATA"),
                cancellation,
                (output, actor.event_log.clone(), 0),
                None,
                #[cfg(feature = "test-support")]
                None
            )
            .await
            .is_ok()
        );
        assert_eq!(
            events.recv().await.expect("закрытый preflight").error,
            Some("profile_unavailable")
        );
        actor.emit();
        assert!(!actor.state.can_connect);
        for value in [
            serde_json::json!({"command":"connect"}),
            serde_json::json!({"command":"check_tcp"}),
            serde_json::json!({"command":"routing_apply","expected_revision":1,"request_id":1,"source_generation":1,"snapshot_revision":1,"selected_profile_id":id}),
            serde_json::json!({"command":"autoconnect_target_set","request_id":"1","expected_revision":"0"}),
        ] {
            let failure = actor
                .source_command(serde_json::from_value(value).expect("команда"))
                .await
                .expect_err("native Run закрыт");
            assert_eq!(failure.key(), "profile_unavailable");
        }
        assert_eq!(
            serde_json::to_value(&actor.state.routing).expect("draft"),
            routing
        );
        let dto = serde_json::to_string(&actor.state.profiles).expect("DTO");
        assert!(!dto.contains("outbounds"));
        actor
            .source_command(Command::CatalogFavorite {
                kind: CatalogKind::Xray,
                id,
                page,
                value: true,
            })
            .await
            .expect("CAS favorite");
        assert!(
            actor
                .state
                .profiles
                .iter()
                .any(|row| row.id == id && row.favorite)
        );
        assert!(
            actor
                .catalog_selection(CatalogKind::Xray, id, page)
                .is_err()
        );
        actor.source_command(serde_json::from_value(serde_json::json!({"command":"add_source","name":"URI","url":"https://example.org/uri","local_exception":false,"route":"direct","hwid_enabled":false})).expect("источник")).await.expect("URI source");
        let uri_source = actor.state.source_id.expect("URI");
        actor.routing_repository().commit_snapshot(uri_source, 1, 0, yonik_linux::SnapshotInput { body: b"vless://00000000-0000-0000-0000-000000000001@example.org:443?security=tls#URI".to_vec(), metadata: b"{}".to_vec(), validators: None }).await.expect("URI snapshot");
        actor.sources().await.expect("источники");
        actor.state.source_id = actor
            .state
            .sources
            .iter()
            .find(|source| source.name == "URI")
            .map(|source| source.id);
        actor.page().await.expect("server page");
        assert!(actor.selected_native.is_none());
        let server_id = actor.state.profiles[0].id;
        assert_eq!(server_id, id, "пространства ID независимы");
        let server_page = actor.state.catalog_page;
        actor
            .source_command(Command::SelectCatalog {
                kind: CatalogKind::Server,
                id: server_id,
                page: server_page,
            })
            .await
            .expect("URI selection");
        assert!(actor.selected.is_some() && actor.selected_native.is_none());
        assert_eq!(actor.state.selected_kind, Some("server"));
        actor
            .source_command(Command::CatalogFavorite {
                kind: CatalogKind::Server,
                id: server_id,
                page: server_page,
                value: true,
            })
            .await
            .expect("server favorite CAS");
        assert!(actor.state.profiles[0].favorite);
        let stale_page = actor.state.catalog_page;
        actor.routing_repository().commit_snapshot(uri_source, 1, 1, yonik_linux::SnapshotInput {
            body: b"vless://00000000-0000-0000-0000-000000000002@example.org:443?security=tls#Changed".to_vec(),
            metadata: b"{}".to_vec(), validators: None,
        }).await.expect("новая revision");
        assert!(
            actor
                .source_command(Command::CatalogFavorite {
                    kind: CatalogKind::Server,
                    id: server_id,
                    page: stale_page,
                    value: false
                })
                .await
                .is_err()
        );
        actor.page().await.expect("новый snapshot");
        assert!(actor.selected.is_none() && actor.selected_native.is_none());
        actor.clear_selection();
        assert!(actor.selected_native.is_none() && actor.selected.is_none());
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("своя fixture");
    }
    #[tokio::test]
    async fn startup_сохраняет_server_цель_другого_источника() {
        let (mut actor, lock, path) = fixture().await;
        let mut sources = Vec::new();
        for name in ["Первый", "Целевой"] {
            actor
                .source_command(
                    serde_json::from_value(serde_json::json!({
                        "command": "add_source", "name": name, "url": "https://example.org/uri",
                        "local_exception": false, "route": "direct", "hwid_enabled": false
                    }))
                    .expect("источник"),
                )
                .await
                .expect("добавить без fetch");
            let id = actor.state.source_id.expect("источник");
            actor.routing_repository().commit_snapshot(id, 1, 0, yonik_linux::SnapshotInput {
                body: format!("vless://00000000-0000-0000-0000-000000000001@example.org:443?security=tls#{name}").into_bytes(),
                metadata: b"{}".to_vec(), validators: None,
            }).await.expect("snapshot");
            actor.page().await.expect("проекция");
            sources.push((id, actor.state.profiles[0].id));
        }
        let profile = actor
            .service()
            .select_profile(sources[1].1, actor.state.revision)
            .await
            .expect("проверенная цель");
        actor.state.source_id = Some(sources[0].0);
        actor
            .page()
            .await
            .expect("начальная страница первого источника");
        let expected = (
            profile.profile.source_id,
            profile.source_generation,
            profile.snapshot_generation,
            profile.snapshot_revision,
        );
        actor
            .startup_select_profile(profile)
            .await
            .expect("восстановить цель");
        assert_eq!(actor.catalog_coordinates, Some(expected));
        assert_eq!(actor.state.selected_kind, Some("server"));
        assert_eq!(actor.state.selected_profile, Some(sources[1].1));
        assert_eq!(
            actor.selected.as_ref().map(|p| p.profile.id),
            Some(sources[1].1)
        );
        assert!(actor.selected_native.is_none());
        actor
            .page()
            .await
            .expect("повторная страница тех же координат");
        assert!(actor.selected.is_some());
        let stale = actor
            .service()
            .select_profile(sources[1].1, actor.state.revision)
            .await
            .expect("цель перед обновлением");
        actor.routing_repository().commit_snapshot(sources[1].0, 1, 1, yonik_linux::SnapshotInput {
            body: b"vless://00000000-0000-0000-0000-000000000002@example.org:443?security=tls#Updated".to_vec(),
            metadata: b"{}".to_vec(), validators: None,
        }).await.expect("смена snapshot");
        assert_eq!(
            actor
                .startup_select_profile(stale)
                .await
                .expect_err("устаревшая цель")
                .0,
            "startup_binding"
        );
        assert!(actor.selected.is_none() && actor.state.selected_kind.is_none());
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("своя fixture");
    }
    async fn send(actor: &mut Actor, value: serde_json::Value) -> Result<()> {
        actor
            .command(serde_json::from_value(value).expect("контракт команды редактора"))
            .await
    }
    #[tokio::test]
    async fn недоступное_ядро_не_меняет_настройки_и_busy_приоритетен() {
        let (mut actor, lock, path) = fixture().await;
        let command = || serde_json::json!({"command":"set_engine","engine":"sing-box"});
        assert_eq!(
            send(&mut actor, command()).await.expect_err("отказ").0,
            "engine_unavailable"
        );
        assert_eq!(actor.preferences.engine, "xray");
        assert!(!path.join("preferences.json").exists());
        actor.state.can_stop = true;
        assert_eq!(
            send(&mut actor, command()).await.expect_err("занято").0,
            "busy"
        );
        actor.state.can_stop = false;
        actor.state.engine = EngineChoice::SingBox;
        actor.preferences.engine = "sing-box".into();
        actor.emit();
        assert!(!actor.state.can_connect);
        assert_eq!(actor.preferences.engine, "sing-box");
        send(
            &mut actor,
            serde_json::json!({"command":"set_engine","engine":"xray"}),
        )
        .await
        .expect("явный выбор");
        assert_eq!(actor.preferences.engine, "xray");
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("очистка fixture");
    }
    fn put(id: u64, revision: i64, request: u64, create: bool) -> serde_json::Value {
        serde_json::json!({"command":"edit_routing","expected_revision":revision,"request_id":request,"create":create,"confirm_broad":false,"rule":{"id":id,"enabled":true,"executables":[],"domains":["example.org"],"destinations":[],"action":"proxy"}})
    }
    fn seed_preset(actor: &mut Actor, path: &std::path::Path) {
        let directory = path.join("presets");
        let store = yonik_linux::presets::Store::open(&directory).expect("store");
        let resource = |sha256: &str| yonik_linux::presets::Resource {
            url: "https://example.org/list".into(),
            revision: "v1".into(),
            sha256: sha256.into(),
        };
        store
            .install(
                yonik_linux::presets::Metadata {
                    source_id: "fixture".into(),
                    version: "v1".into(),
                    format: "plain-domain-cidr-v1".into(),
                    checked_at_unix: 1,
                    enabled: false,
                    domains: resource(
                        "04e512879df7acb18392404d982a1b179e94c20b53ee03b75538624863d89e96",
                    ),
                    ips: resource(
                        "1056040935d29c506274717d77a7388683810fd7ae430176f81a59de1270c994",
                    ),
                },
                b"example.org\n".to_vec(),
                b"0.0.0.0/0\n".to_vec(),
            )
            .expect("install");
        actor.presets = Some(Arc::new(
            super::presets::Controller::open(&directory).expect("controller"),
        ));
    }
    #[tokio::test]
    async fn preset_host_scope_is_invalidated_by_engine_or_port_change() {
        let (mut actor, lock, path) = fixture().await;
        actor.state.presets.host_validated = true;
        actor.state.presets.validation_scope = actor.preset_scope();
        actor.state.engine = match actor.state.engine {
            EngineChoice::Xray => EngineChoice::SingBox,
            EngineChoice::SingBox => EngineChoice::Xray,
        };
        actor.emit();
        assert!(!actor.state.presets.host_validated);
        actor.state.presets.host_validated = true;
        actor.state.presets.validation_scope = actor.preset_scope();
        actor.state.port = actor.state.port.checked_add(1).expect("port");
        actor.emit();
        assert!(!actor.state.presets.host_validated);
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("fixture");
    }
    #[test]
    fn preset_ack_identifiers_preserve_javascript_integer_precision() {
        for command in [
            serde_json::json!({"command":"preset_prepare","target":"8.8.8.8","request_id":9_007_199_254_740_992_u64}),
            serde_json::json!({"command":"preset_rollback","request_id":9_007_199_254_740_992_u64}),
        ] {
            let command: Command = serde_json::from_value(command).expect("command");
            assert!(super::validate(&command).is_err());
        }
    }
    #[tokio::test]
    async fn preset_activation_is_revision_checked_and_preserves_user_rules() {
        let (mut actor, lock, path) = fixture().await;
        seed_preset(&mut actor, &path);
        send(&mut actor, put(1, 0, 1, true))
            .await
            .expect("user rule");
        let rules = serde_json::to_value(&actor.state.routing.rules).expect("rules");
        send(&mut actor, serde_json::json!({"command":"preset_activate", "enabled":true,"expected_revision":1,"request_id":2})).await.expect("activate");
        let reference = actor
            .state
            .routing
            .ru_direct
            .as_ref()
            .expect("reference")
            .snapshot
            .clone();
        assert_eq!(reference.len(), 64);
        let store = yonik_linux::presets::Store::open(&path.join("presets")).expect("catalog");
        let (mut next, _) = store.active().expect("active").expect("metadata");
        next.version = "v2".into();
        next.domains.revision = "v2".into();
        next.ips.revision = "v2".into();
        store
            .install(next, b"example.org\n".to_vec(), b"0.0.0.0/0\n".to_vec())
            .expect("update");
        assert_ne!(store.active_id().expect("current").expect("id"), reference);
        let stored = actor
            .routing_repository()
            .routing_draft()
            .await
            .expect("saved")
            .expect("draft");
        let saved = crate::editor::Draft::parse(std::str::from_utf8(&stored.1).expect("utf8"))
            .expect("draft reference");
        assert_eq!(
            saved.ru_direct.expect("pinned stored reference").snapshot,
            reference
        );
        assert_eq!(
            actor
                .state
                .routing
                .ru_direct
                .as_ref()
                .expect("still pinned")
                .snapshot,
            reference
        );
        assert_eq!(
            serde_json::to_value(&actor.state.routing.rules).expect("rules"),
            rules
        );
        assert!(actor.state.routing.policy().is_err());
        let policy = actor
            .preset_policy(&actor.state.routing)
            .expect("trusted resolve");
        assert_eq!(policy.preset_rules.len(), 2);
        assert_eq!(policy.user_rules[0].id, 1);
        send(&mut actor, serde_json::json!({"command":"routing_explain","target":"8.8.8.8","request_id":91,"expected_revision":2})).await.expect("resolved explanation");
        assert_eq!(
            actor.state.routing_explanation["result"]["action"],
            "Direct"
        );
        assert_eq!(
            actor.state.routing_explanation["result"]["origin"],
            "Preset(2)"
        );
        assert!(send(&mut actor, serde_json::json!({"command":"preset_activate", "enabled":false,"expected_revision":1,"request_id":3})).await.is_err());
        assert!(
            actor
                .state
                .routing
                .ru_direct
                .as_ref()
                .expect("reference")
                .enabled
        );
        assert_eq!(actor.state.presets.ack.as_ref().expect("ack").request_id, 3);
        send(&mut actor, serde_json::json!({"command":"preset_activate", "enabled":false,"expected_revision":2,"request_id":4})).await.expect("disable");
        assert!(
            actor
                .state
                .routing
                .policy()
                .expect("disabled")
                .preset_rules
                .is_empty()
        );
        assert_eq!(
            actor
                .state
                .routing
                .ru_direct
                .as_ref()
                .expect("pinned")
                .snapshot,
            reference
        );
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("fixture");
    }
    #[tokio::test]
    async fn preset_prepare_does_not_invent_application_witness() {
        let (mut actor, lock, path) = fixture().await;
        seed_preset(&mut actor, &path);
        send(&mut actor, serde_json::json!({"command":"edit_routing", "request_id":1,"expected_revision":0,"create":true,"confirm_broad":false,"rule":{"id":1,"enabled":true,"executables":["/usr/bin/browser"],"domains":["example.org"],"destinations":[],"action":"block"}})).await.expect("user application rule");
        send(
            &mut actor,
            serde_json::json!({"command":"preset_prepare","request_id":2,"target":"example.org"}),
        )
        .await
        .expect("model");
        assert_eq!(
            actor.state.presets.decision.as_deref(),
            Some("Application witness required")
        );
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("fixture");
    }
    #[tokio::test]
    async fn preset_closed_catalog_is_storage_and_integrity_is_distinct() {
        let (mut actor, lock, path) = fixture().await;
        seed_preset(&mut actor, &path);
        let catalog = path.join("presets");
        let held = std::fs::File::open(&catalog).expect("directory lock");
        rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("writer lock");
        assert_eq!(
            send(&mut actor, serde_json::json!({"command":"preset_rollback"}))
                .await
                .expect_err("busy")
                .key(),
            "busy"
        );
        assert_eq!(actor.state.presets.operation_error, Some("busy"));
        drop(held);
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(catalog.join("index")).expect("index"))
                .expect("json");
        std::fs::write(
            catalog.join(index["active"].as_str().expect("id")),
            b"corrupt",
        )
        .expect("fault");
        assert_eq!(
            send(
                &mut actor,
                serde_json::json!({"command":"preset_prepare","target":"8.8.8.8"})
            )
            .await
            .expect_err("integrity")
            .key(),
            "storage"
        );
        assert_eq!(actor.state.presets.operation_error, Some("integrity"));
        std::fs::remove_dir_all(catalog).expect("closed own catalog");
        assert_eq!(
            send(
                &mut actor,
                serde_json::json!({"command":"preset_prepare","target":"8.8.8.8"})
            )
            .await
            .expect_err("closed")
            .key(),
            "storage"
        );
        assert_eq!(actor.state.presets.operation_error, Some("storage"));
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("fixture");
    }
    #[tokio::test]
    async fn preset_preparation_is_invalidated_by_draft_mutation_and_invalid_ip() {
        let (mut actor, lock, path) = fixture().await;
        seed_preset(&mut actor, &path);
        send(
            &mut actor,
            serde_json::json!({"command":"preset_prepare", "target":"example.org"}),
        )
        .await
        .expect("domain evaluator without invented DNS");
        assert_eq!(
            actor.state.presets.decision.as_deref(),
            Some("Direct · Preset(1)")
        );
        send(
            &mut actor,
            serde_json::json!({"command":"preset_prepare", "target":"8.8.8.8"}),
        )
        .await
        .expect("prepare");
        assert!(actor.state.presets.prepared);
        send(&mut actor, serde_json::json!({"command":"routing_default", "action":"block", "expected_revision":0,"request_id":1})).await.expect("Proxy→Block");
        assert!(!actor.state.presets.prepared);
        assert!(actor.state.presets.decision.is_none());
        send(
            &mut actor,
            serde_json::json!({"command":"preset_prepare", "target":"8.8.8.8"}),
        )
        .await
        .expect("prepare again");
        assert!(
            send(
                &mut actor,
                serde_json::json!({"command":"preset_prepare", "target":"invalid IP"})
            )
            .await
            .is_err()
        );
        assert!(!actor.state.presets.prepared);
        assert!(actor.state.presets.decision.is_none());
        send(
            &mut actor,
            serde_json::json!({"command":"preset_prepare", "target":"invalid IP", "request_id":88}),
        )
        .await
        .expect("typed error ACK");
        assert_eq!(
            actor
                .state
                .presets
                .ack
                .as_ref()
                .expect("matching ACK")
                .request_id,
            88
        );
        assert_eq!(
            actor
                .state
                .presets
                .ack
                .as_ref()
                .expect("matching ACK")
                .error,
            Some("invalid_ip")
        );
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("fixture");
    }
    #[tokio::test]
    async fn preset_status_and_failed_preparation_preserve_routing_draft() {
        let (mut actor, lock, path) = fixture().await;
        actor.presets = Some(Arc::new(
            super::presets::Controller::open(&path.join("presets")).expect("store"),
        ));
        send(&mut actor, put(1, 0, 1, true))
            .await
            .expect("user rule");
        let before = actor.state.routing.json();
        send(&mut actor, serde_json::json!({"command":"preset_status"}))
            .await
            .expect("status");
        assert!(actor.state.presets.current.is_none());
        assert!(
            send(
                &mut actor,
                serde_json::json!({"command":"preset_prepare", "target":"8.8.8.8"})
            )
            .await
            .is_err()
        );
        assert_eq!(actor.state.routing.json(), before);
        assert_eq!(actor.state.routing_revision, Some(1));
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("собственная fixture");
    }
    #[tokio::test]
    async fn inline_capture_берёт_текущий_сохранённый_черновик() {
        let (mut actor, lock, path) = fixture().await;
        send(&mut actor, put(17, 0, 1, true))
            .await
            .expect("сохранение");
        let (first, revision) = actor.current_inline_policy().expect("capture");
        assert_eq!(revision, 1);
        assert_eq!(first.policy().policy().user_rules[0].id, 17);
        send(&mut actor, serde_json::json!({"command":"routing_default", "expected_revision":1, "request_id":2, "action":"block"})).await.expect("изменение");
        let (current, revision) = actor.current_inline_policy().expect("capture после edit");
        assert_eq!(revision, 2);
        assert_eq!(
            current.policy().policy().default_action,
            yonik_domain::Action::Block
        );
        assert_eq!(
            first.policy().policy().default_action,
            yonik_domain::Action::Proxy
        );
        let stored = actor
            .routing_repository()
            .routing_draft()
            .await
            .expect("encrypted draft");
        assert_eq!(stored.expect("сохранённый draft").0, revision);
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("собственная fixture");
    }

    #[tokio::test]
    async fn explanation_ack_and_diagnostics_follow_revision() {
        let (mut actor, lock, path) = fixture().await;
        send(&mut actor, put(1, 0, 1, true)).await.expect("первое");
        send(&mut actor, put(2, 1, 2, true)).await.expect("второе");
        assert_eq!(actor.state.routing_diagnostics["warnings"][0]["rule_id"], 2);
        send(&mut actor, serde_json::json!({"command":"routing_explain","expected_revision":2,"request_id":3,"target":"192.0.2.1"})).await.expect("расчёт");
        assert_eq!(actor.state.routing_explanation["revision"], 2);
        assert_eq!(actor.state.routing_ack.as_ref().expect("ACK").request_id, 3);
        assert_eq!(send(&mut actor, serde_json::json!({"command":"routing_explain","expected_revision":1,"request_id":4,"target":"192.0.2.1"})).await.expect_err("stale").key(), "routing_stale");
        assert!(actor.state.routing_explanation.is_null());
        assert_eq!(actor.state.routing_ack.as_ref().expect("ACK").request_id, 4);
        assert_eq!(actor.routing_revision, Some(2));
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("очистка fixture");
    }
    #[tokio::test]
    async fn stale_order_and_partial_order_cannot_delete_queued_add() {
        let (mut actor, lock, path) = fixture().await;
        send(&mut actor, put(1, 0, 1, true)).await.expect("первое");
        send(&mut actor, put(2, 1, 2, true))
            .await
            .expect("queued add");
        assert_eq!(send(&mut actor, serde_json::json!({"command":"routing_order","expected_revision":1,"request_id":3,"ids":[1]})).await.expect_err("stale").key(), "routing_stale");
        assert_eq!(send(&mut actor, serde_json::json!({"command":"routing_order","expected_revision":2,"request_id":4,"ids":[1]})).await.expect_err("неполная перестановка").key(), "id");
        assert_eq!(
            actor
                .state
                .routing
                .rules
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        send(&mut actor, serde_json::json!({"command":"routing_order","expected_revision":2,"request_id":5,"ids":[2,1]})).await.expect("перестановка");
        send(&mut actor, serde_json::json!({"command":"routing_delete","expected_revision":3,"request_id":6,"id":1})).await.expect("явное удаление");
        assert_eq!(
            actor
                .state
                .routing
                .rules
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![2]
        );
        let saved = actor
            .routing_repository()
            .routing_draft()
            .await
            .expect("БД")
            .expect("запись");
        assert_eq!(saved.0, 4);
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("очистка");
    }
    #[tokio::test]
    async fn repository_conflict_returns_matching_error_ack_without_accepting_form() {
        let (mut actor, lock, path) = fixture().await;
        actor
            .routing_repository()
            .save_routing_draft(0, actor.state.routing.json().into_bytes())
            .await
            .expect("внешняя запись");
        assert_eq!(
            send(&mut actor, put(1, 0, 9, true))
                .await
                .expect_err("CAS conflict")
                .key(),
            "routing_stale"
        );
        assert!(actor.state.routing.rules.is_empty());
        let snapshot = serde_json::to_value(&actor.state).expect("ACK");
        assert_eq!(snapshot["routing_ack"]["request_id"], 9);
        assert_eq!(snapshot["routing_ack"]["error"], "routing_stale");
        assert!(snapshot["routing_ack"]["saved_id"].is_null());
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("очистка");
    }
    #[tokio::test]
    async fn every_mutation_rejects_stale_snapshot_and_create_is_explicit() {
        let (mut actor, lock, path) = fixture().await;
        send(&mut actor, put(1, 0, 1, true))
            .await
            .expect("добавление");
        for command in [
            put(2, 0, 2, true),
            put(1, 0, 3, false),
            serde_json::json!({"command":"routing_default","expected_revision":0,"request_id":4,"action":"direct"}),
            serde_json::json!({"command":"routing_delete","expected_revision":0,"request_id":5,"id":1}),
        ] {
            assert_eq!(
                send(&mut actor, command)
                    .await
                    .expect_err("старая ревизия")
                    .key(),
                "routing_stale"
            );
        }
        assert_eq!(
            send(&mut actor, put(1, 1, 6, true))
                .await
                .expect_err("ID уже есть")
                .key(),
            "id"
        );
        assert_eq!(
            send(&mut actor, put(2, 1, 7, false))
                .await
                .expect_err("нет ID для update")
                .key(),
            "id"
        );
        assert_eq!(actor.state.routing.rules.len(), 1);
        assert_eq!(actor.routing_revision, Some(1));
        let snapshot = serde_json::to_value(&actor.state).expect("DTO");
        assert_eq!(snapshot["routing_revision"], 1);
        assert_eq!(snapshot["routing_ack"]["request_id"], 7);
        assert_eq!(snapshot["routing_ack"]["error"], "id");
        send(&mut actor, put(1, 1, 8, false)).await.expect("update");
        let snapshot = serde_json::to_value(&actor.state).expect("ACK");
        assert_eq!(snapshot["routing_ack"]["saved_id"], 1);
        assert!(snapshot["routing_ack"]["error"].is_null());
        drop(actor);
        drop(lock);
        std::fs::remove_dir_all(path).expect("очистка");
    }
}

#[cfg(test)]
mod proxy_session_tests {
    use super::*;
    use yonik_linux::{Source, SubscriptionFetch};

    #[tokio::test]
    async fn domain_proxy_without_config_fails_before_socks_lookup() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let endpoint = listener.local_addr().expect("endpoint");
        let (session, _) = watch::channel(Some((1, endpoint)));
        let host = DesktopFetch::new(&session, None);
        let (_sender, cancel) = watch::channel(false);
        let source = Source::local("http://subscription.example/sub").expect("source");
        assert_eq!(
            host.fetch(&source, FetchRoute::Proxy, None, cancel)
                .await
                .unwrap_err(),
            FetchError::ProxyDnsRequired
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn reconnect_same_endpoint_revokes_pinned_generation_before_network() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let endpoint = listener.local_addr().expect("endpoint");
        let (session, _) = watch::channel(Some((1, endpoint)));
        let host = DesktopFetch::new(&session, None);
        session.send_replace(Some((2, endpoint)));
        let (_sender, cancel) = watch::channel(false);
        let source = Source::local("http://127.0.0.1:1/sub").expect("source");
        assert_eq!(
            host.fetch(&source, FetchRoute::Proxy, None, cancel)
                .await
                .unwrap_err(),
            FetchError::Cancelled
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stop_cancels_proxy_waiting_for_socks_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let endpoint = listener.local_addr().expect("endpoint");
        let (session, _) = watch::channel(Some((1, endpoint)));
        let host = DesktopFetch::new(&session, None);
        let (_sender, cancel) = watch::channel(false);
        let source = Source::local("http://127.0.0.1:1/sub").expect("source");
        let revoke = async {
            let (_stream, _) = listener.accept().await.expect("SOCKS accept");
            session.send_replace(None);
        };
        let (result, ()) =
            tokio::join!(host.fetch(&source, FetchRoute::Proxy, None, cancel), revoke);
        assert_eq!(result.unwrap_err(), FetchError::Cancelled);
    }
}

fn system_revision(actor: &Actor) -> ProfileRevision {
    ProfileRevision {
        source: actor.state.source_id.unwrap_or_default() as u64,
        profile: actor.state.selected_profile.unwrap_or_default() as u64,
        generation: actor.state.revision as u64,
    }
}
fn record_system(snapshot: &mut Snapshot, state: SystemState) {
    let label = match state {
        SystemState::Unknown => "Unknown",
        SystemState::NoManagedPolicy => "NoManagedPolicy",
        SystemState::TunnelStarting => "TunnelStarting",
        SystemState::VerifiedRules => "VerifiedRules",
        SystemState::RecoveryRequired => "RecoveryRequired",
    };
    snapshot.system_state = label;
    snapshot.status = label;
    // Unknown — потеря доказательства, а не доказательство отсутствия ресурсов.
    match state {
        SystemState::NoManagedPolicy => snapshot.system_recovery_pending = false,
        SystemState::TunnelStarting
        | SystemState::VerifiedRules
        | SystemState::RecoveryRequired => {
            snapshot.system_recovery_pending = true;
        }
        SystemState::Unknown => {}
    }
    snapshot.can_unlock = snapshot.system_recovery_pending;
}
fn helper_cause(error: ClientError) -> Cause {
    match error {
        ClientError::Unsupported => Cause::HelperUnsupported,
        ClientError::Denied => Cause::HelperDenied,
        ClientError::Cancelled => Cause::HelperCancelled,
        ClientError::Busy => Cause::HelperBusy,
        ClientError::OwnerLost => Cause::HelperOwnerLost,
        ClientError::Deadline => Cause::HelperDeadline,
        ClientError::Timeout => Cause::HelperTimeout,
        ClientError::InvalidRequest => Cause::HelperInvalidRequest,
        ClientError::InvalidHandle => Cause::HelperInvalidHandle,
        ClientError::Stale => Cause::HelperStale,
        ClientError::Protocol => Cause::HelperProtocol,
        ClientError::Unavailable => Cause::HelperUnavailable,
    }
}

fn system_error(error: ClientError) -> &'static str {
    match error {
        ClientError::Unsupported => "system_unsupported",
        ClientError::Denied => "system_denied",
        ClientError::Cancelled => "cancelled",
        ClientError::Busy => "busy",
        ClientError::OwnerLost => "system_owner_lost",
        ClientError::Deadline | ClientError::Timeout => "system_timeout",
        _ => "system_unavailable",
    }
}

/// Одна ограниченная операция. Владение session возвращается даже после отмены RPC.
pub(crate) enum Operation {
    FullProfile(Box<yonik_linux::helper::profile_intent::FullProfileRequest>),
    PolicyConnect(
        Box<yonik_import::ServerIntent>,
        Engine,
        Box<yonik_linux::system_policy::InlinePolicy>,
        i64,
        Vec<String>,
    ),
    Stop,
    Unlock,
    State,
}
pub(crate) struct Flight {
    pub cancel: tokio::sync::watch::Sender<bool>,
    pub task: tokio::task::JoinHandle<(
        Option<SystemSession>,
        std::result::Result<SystemState, ClientError>,
    )>,
    pub generation: u64,
    pub revision: ProfileRevision,
    pub routing_revision: Option<i64>,
    pub request_id: Option<u64>,
    pub source_generation: Option<i64>,
    pub connecting: bool,
    pub mutating: bool,
}
impl Flight {
    pub fn start(
        session: Option<SystemSession>,
        operation: Operation,
        revision: ProfileRevision,
        generation: u64,
        log: yonik_linux::event_log::EventLog,
    ) -> Self {
        let connecting = matches!(
            operation,
            Operation::PolicyConnect(..) | Operation::FullProfile(..)
        );
        let routing_revision = match &operation {
            Operation::PolicyConnect(_, _, _, revision, _) => Some(*revision),
            _ => None,
        };
        let mutating = !matches!(operation, Operation::State);
        let (cancel, cancellation) = Cancellation::new();
        let task = tokio::spawn(async move {
            if matches!(&operation, Operation::FullProfile(request) if yonik_linux::full_profile_request_preflight(yonik_linux::FullProfileMode::System, request).is_err())
            {
                return (session, Err(ClientError::Unsupported));
            }
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut session = match session {
                Some(mut session) => {
                    if session.owner_lost() {
                        match SystemClient::system(deadline, cancellation.clone()).await {
                            Ok(client) => session.replace_client(client),
                            Err(error) => return (Some(session), Err(error)),
                        }
                    }
                    session
                }
                None => match SystemClient::system(deadline, cancellation.clone()).await {
                    Ok(client) => SystemSession::new(client, revision, log),
                    Err(error) => return (None, Err(error)),
                },
            };
            session.revise(revision);
            let result = match operation {
                Operation::FullProfile(request) => {
                    match session
                        .prepare_full_profile(revision, &request, deadline, cancellation.clone())
                        .await
                    {
                        Ok(()) => session.apply(revision, deadline, cancellation).await,
                        Err(error) => Err(error),
                    }
                }
                Operation::PolicyConnect(server, engine, policy, _, suffixes) => {
                    let prepared = if suffixes.is_empty() {
                        session
                            .prepare_policy(
                                revision,
                                &server,
                                engine,
                                &policy,
                                deadline,
                                cancellation.clone(),
                            )
                            .await
                    } else {
                        session
                            .prepare_fake_dns_policy(
                                revision,
                                &server,
                                engine,
                                &policy,
                                &suffixes,
                                deadline,
                                cancellation.clone(),
                            )
                            .await
                    };
                    match prepared {
                        Ok(()) => session.apply(revision, deadline, cancellation).await,
                        Err(error) => Err(error),
                    }
                }
                Operation::Stop => session.stop(deadline, cancellation).await,
                Operation::Unlock => session.unlock(deadline, cancellation).await,
                Operation::State => session.state(deadline, cancellation).await,
            };
            (Some(session), result)
        });
        Self {
            cancel,
            task,
            generation,
            revision,
            routing_revision,
            request_id: None,
            source_generation: None,
            connecting,
            mutating,
        }
    }
}

#[cfg(test)]
mod system_recovery_tests {
    use super::*;

    #[test]
    fn неопределённый_state_сохраняет_барьер_и_unlock() {
        for retained in [
            SystemState::VerifiedRules,
            SystemState::RecoveryRequired,
            SystemState::TunnelStarting,
        ] {
            let mut snapshot = Snapshot::new(true);
            record_system(&mut snapshot, retained);
            for error in [
                ClientError::Timeout,
                ClientError::Unavailable,
                ClientError::OwnerLost,
            ] {
                record_system(&mut snapshot, SystemState::Unknown);
                snapshot.command_error(false, system_error(error));
                assert!(snapshot.system_recovery_pending);
                assert!(snapshot.can_unlock);
                assert_eq!(snapshot.system_state, "Unknown");
            }
        }
    }

    #[test]
    fn подтверждённая_очистка_снимает_барьер() {
        let mut snapshot = Snapshot::new(true);
        record_system(&mut snapshot, SystemState::VerifiedRules);
        record_system(&mut snapshot, SystemState::Unknown);
        assert!(snapshot.system_recovery_pending);
        // И State, и Unlock передают сюда только принятый typed ответ helper.
        record_system(&mut snapshot, SystemState::NoManagedPolicy);
        assert!(!snapshot.system_recovery_pending);
        assert!(!snapshot.can_unlock);
        record_system(&mut snapshot, SystemState::Unknown);
        assert!(!snapshot.system_recovery_pending);
    }
}

#[cfg(test)]
#[path = "maintenance_command_tests.rs"]
mod maintenance_command_tests;

mod inline_policy_conversion {
    use yonik_linux::system_client::ClientError;

    use serde::Serialize;
    use yonik_domain::{Action, DomainPattern, PlatformSource, Policy, Rule};
    use yonik_engine::policy_wire::SystemPolicy;
    use yonik_linux::system_policy::InlinePolicy;
    pub(crate) fn inline_policy(policy: &Policy) -> Result<InlinePolicy, ClientError> {
        if policy.unsupported_selector().is_some() || policy.unsupported_transport().is_some() {
            return Err(ClientError::Unsupported);
        }
        let version = if policy
            .user_rules
            .iter()
            .chain(&policy.preset_rules)
            .any(|r| r.conditions.transport.constrained())
        {
            3
        } else if policy
            .user_rules
            .iter()
            .chain(&policy.preset_rules)
            .any(|rule| !rule.conditions.platform_sources.is_empty())
        {
            2
        } else {
            1
        };
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum WireSource<'a> {
            AndroidPackage { package: &'a str },
        }
        #[derive(Serialize)]
        struct WireRule<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            transport: Option<yonik_engine::transport::TransportInput>,
            id: u64,
            enabled: bool,
            action: &'static str,
            domain: Vec<&'a str>,
            domain_suffix: Vec<&'a str>,
            ip_cidr: Vec<String>,
            executable_paths: &'a [String],
            #[serde(skip_serializing_if = "Option::is_none")]
            platform_sources: Option<Vec<WireSource<'a>>>,
        }
        fn action(value: Action) -> &'static str {
            match value {
                Action::Direct => "direct",
                Action::Proxy => "proxy",
                Action::Block => "block",
            }
        }
        fn rule(value: &Rule, version: u32) -> WireRule<'_> {
            let mut domain = Vec::new();
            let mut domain_suffix = Vec::new();
            for pattern in &value.conditions.domains {
                match pattern {
                    DomainPattern::Exact(name) => domain.push(name.as_str()),
                    DomainPattern::Suffix(name) => domain_suffix.push(name.as_str()),
                }
            }
            WireRule {
                transport: value.conditions.transport.constrained().then(|| {
                    yonik_engine::transport::TransportInput::from_typed(&value.conditions.transport)
                }),
                id: value.id,
                enabled: value.enabled,
                action: action(value.action),
                domain,
                domain_suffix,
                ip_cidr: value
                    .conditions
                    .destinations
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                executable_paths: &value.conditions.executables,
                platform_sources: (version >= 2).then(|| {
                    value
                        .conditions
                        .platform_sources
                        .iter()
                        .map(|source| match source {
                            PlatformSource::AndroidPackage { package } => {
                                WireSource::AndroidPackage {
                                    package: package.as_str(),
                                }
                            }
                        })
                        .collect()
                }),
            }
        }
        #[derive(Serialize)]
        struct Network {
            cidr: String,
            vpn: u64,
            available: bool,
        }
        #[derive(Serialize)]
        struct Domain<'a> {
            suffix: &'a str,
            vpn: u64,
            available: bool,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            version: u32,
            default_action: &'static str,
            user_rules: Vec<WireRule<'a>>,
            preset_rules: Vec<WireRule<'a>>,
            lan: Vec<String>,
            private_networks: Vec<Network>,
            private_domains: Vec<Domain<'a>>,
        }
        // Закрытый wire умеет только suffix приватного домена: exact нельзя расширять.
        if policy
            .private_domains
            .iter()
            .any(|d| matches!(d.domain, DomainPattern::Exact(_)))
        {
            return Err(ClientError::Unsupported);
        }
        let wire = Wire {
            version,
            default_action: action(policy.default_action),
            user_rules: policy
                .user_rules
                .iter()
                .map(|value| rule(value, version))
                .collect(),
            preset_rules: policy
                .preset_rules
                .iter()
                .map(|value| rule(value, version))
                .collect(),
            lan: policy.lan.iter().map(ToString::to_string).collect(),
            private_networks: policy
                .private_networks
                .iter()
                .map(|n| Network {
                    cidr: n.network.to_string(),
                    vpn: n.vpn.get(),
                    available: n.available,
                })
                .collect(),
            private_domains: policy
                .private_domains
                .iter()
                .map(|d| Domain {
                    suffix: d.domain.name().as_str(),
                    vpn: d.vpn.get(),
                    available: d.available,
                })
                .collect(),
        };
        let text = serde_json::to_string(&wire).map_err(|_| ClientError::InvalidRequest)?;
        SystemPolicy::parse(&text)
            .map(InlinePolicy::new)
            .map_err(|_| ClientError::InvalidRequest)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use yonik_domain::{Conditions, PrivateDomain, VpnId};

        #[test]
        fn сохраняет_порядок_условия_и_действие() {
            let policy = Policy {
                user_rules: vec![Rule {
                    id: 7,
                    enabled: true,
                    action: Action::Block,
                    conditions: Conditions {
                        transport: Default::default(),
                        platform_sources: Vec::new(),
                        executables: vec!["/usr/bin/browser".into()],
                        destinations: vec!["192.0.2.0/24".parse().unwrap()],
                        domains: vec![DomainPattern::Suffix("example.org".parse().unwrap())],
                    },
                }],
                ..Policy::default()
            };
            let wire = inline_policy(&policy).unwrap();
            let json = serde_json::to_value(wire.policy()).unwrap();
            assert_eq!(json["version"], 1);
            assert!(json["user_rules"][0].get("platform_sources").is_none());
            let restored = wire.policy().policy();
            assert_eq!(restored.user_rules[0].id, 7);
            assert_eq!(restored.user_rules[0].action, Action::Block);
            assert_eq!(
                restored.user_rules[0].conditions.executables,
                policy.user_rules[0].conditions.executables
            );
            assert_eq!(
                restored.user_rules[0].conditions.domains,
                policy.user_rules[0].conditions.domains
            );
            assert_eq!(
                restored.user_rules[0].conditions.destinations,
                policy.user_rules[0].conditions.destinations
            );
        }
        #[test]
        fn не_расширяет_exact_приватного_домена() {
            let policy = Policy {
                private_domains: vec![PrivateDomain {
                    domain: DomainPattern::Exact("example.org".parse().unwrap()),
                    vpn: VpnId::new(1).unwrap(),
                    available: true,
                }],
                ..Policy::default()
            };
            assert!(matches!(
                inline_policy(&policy),
                Err(ClientError::Unsupported)
            ));
        }
        #[test]
        fn неприменимый_selector_не_теряется_перед_apply() {
            for preset in [false, true] {
                let rule = Rule {
                    id: 41,
                    enabled: true,
                    action: Action::Proxy,
                    conditions: Conditions {
                        platform_sources: vec![yonik_domain::PlatformSource::AndroidPackage {
                            package: yonik_domain::AndroidPackageId::parse("org.example.app")
                                .unwrap(),
                        }],
                        domains: vec![DomainPattern::Suffix("example.org".parse().unwrap())],
                        ..Conditions::default()
                    },
                };
                let mut policy = Policy::default();
                if preset {
                    policy.preset_rules.push(rule);
                } else {
                    policy.user_rules.push(rule);
                }
                assert!(matches!(
                    inline_policy(&policy),
                    Err(ClientError::Unsupported)
                ));
            }
        }

        #[test]
        fn disabled_selector_сохраняется_в_inline_v2() {
            for preset in [false, true] {
                let rule = Rule {
                    id: 41,
                    enabled: false,
                    action: Action::Proxy,
                    conditions: Conditions {
                        platform_sources: vec![yonik_domain::PlatformSource::AndroidPackage {
                            package: yonik_domain::AndroidPackageId::parse("org.example.app")
                                .unwrap(),
                        }],
                        ..Conditions::default()
                    },
                };
                let mut policy = Policy::default();
                if preset {
                    policy.preset_rules.push(rule);
                } else {
                    policy.user_rules.push(rule);
                }
                let wire = inline_policy(&policy).unwrap();
                let restored = wire.policy().policy();
                let (before, after) = if preset {
                    (&policy.preset_rules, &restored.preset_rules)
                } else {
                    (&policy.user_rules, &restored.user_rules)
                };
                assert_eq!(
                    after[0].conditions.platform_sources,
                    before[0].conditions.platform_sources
                );
                assert!(!after[0].enabled);
                let json = serde_json::to_value(wire.policy()).unwrap();
                assert_eq!(json["version"], 2);
            }
            let wire = inline_policy(&Policy::default()).unwrap();
            assert_eq!(serde_json::to_value(wire.policy()).unwrap()["version"], 1);
        }

        #[test]
        fn не_обрезает_превышение_бюджета() {
            let mut policy = Policy {
                user_rules: (1..=257)
                    .map(|id| Rule {
                        id,
                        enabled: true,
                        action: Action::Proxy,
                        conditions: Conditions::default(),
                    })
                    .collect(),
                ..Policy::default()
            };
            assert!(matches!(
                inline_policy(&policy),
                Err(ClientError::InvalidRequest)
            ));
            policy.user_rules.pop();
            assert!(inline_policy(&policy).is_ok());
        }
    }
}

#[cfg(test)]
mod error_context_tests {
    use super::*;

    #[test]
    fn replacement_and_late_session_update_do_not_keep_context() {
        let mut state = Snapshot::new(true);
        state.contextual_error(false, ContextFailure::new(Cause::DataDirectoryPermissions));
        assert!(
            state
                .error_contexts
                .matching(Slot::Connection, Some("storage"), None)
                .is_some()
        );
        state.command_error(false, "storage");
        assert!(
            state
                .error_contexts
                .matching(Slot::Connection, Some("storage"), None)
                .is_none()
        );
        state.error_generation = 9;
        state.contextual_error(false, ContextFailure::new(Cause::RepositoryOpenStorage));
        apply_session_update(
            &mut state,
            SessionUpdate {
                status: "Error",
                error: Some("engine_failed"),
                context: Some(Cause::EngineExited),
                generation: Some(8),
                probe_result: None,
                network_stamp: None,
            },
            None,
        );
        assert_eq!(state.error, Some("storage"));
        assert_eq!(
            state
                .error_contexts
                .matching(Slot::Connection, state.connection_error, None)
                .expect("текущий контекст")
                .reason,
            Cause::RepositoryOpenStorage
        );
        apply_session_update(
            &mut state,
            SessionUpdate {
                status: "Disconnected",
                error: None,
                context: None,
                generation: Some(9),
                probe_result: None,
                network_stamp: None,
            },
            None,
        );
        assert!(
            state
                .error_contexts
                .matching(Slot::Connection, Some("storage"), None)
                .is_none()
        );
    }

    #[test]
    fn actual_directory_guard_has_specific_typed_cause() {
        let root = std::env::temp_dir().join(format!("p11-context-{}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&root)
            .expect("собственный каталог");
        fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("права");
        let failure = private_directory(&root).expect_err("guard отказал");
        fs::remove_dir(&root).expect("очистка");
        assert_eq!(failure.cause, Cause::DataDirectoryPermissions);
        assert_eq!(failure.error.key(), "storage");
    }
}

#[cfg(test)]
mod maintenance_context_tests {
    use super::*;
    #[test]
    fn actual_backup_conflict_is_bound_to_ack_and_v1_is_unchanged() {
        let root = std::env::temp_dir().join(format!("p11-maint-context-{}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("собственный каталог");
        let destination = root.join("existing.sqlite");
        fs::write(&destination, b"previous").expect("существующий файл");
        let (sender, receiver) = std::sync::mpsc::channel();
        let host = DesktopHost::start(
            HostConfig::new(root.join("data"), root.join("engines")).with_ephemeral_key([19; 32]),
            move |raw| {
                let _ = sender.send(raw);
            },
        )
        .expect("host");
        let wait = |predicate: &dyn Fn(&serde_json::Value) -> bool| -> serde_json::Value {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            loop {
                let raw = receiver
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                    .expect("snapshot deadline");
                let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON");
                if predicate(&value) {
                    return value;
                }
            }
        };
        let ready = wait(&|value| value["ready"] == true);
        host.dispatch(&serde_json::json!({"command":"maintenance_start","request_id":77,"operation":"backup","destination":destination,"revision":ready["revision"]}).to_string()).expect("Start");
        let state = wait(&|value| {
            value["maintenance_ack"]["request_id"] == 77
                && value["maintenance_ack"]["phase"] == "failed"
        });
        let export = crate::diagnostics::export_snapshot_v2(&state.to_string()).expect("actual V2");
        let metadata: serde_json::Value = serde_json::from_str(&export).expect("JSON");
        assert_eq!(metadata["errors"][0]["reason"], "maintenance_copy_conflict");
        assert_eq!(metadata["errors"][0]["request_id"], "77");
        let mut sibling = state.clone();
        sibling["maintenance_ack"]["request_id"] = serde_json::json!(78);
        assert!(crate::diagnostics::export_snapshot_v2(&sibling.to_string()).is_none());
        for (id, revision, reason, key) in [
            (
                78,
                ready["revision"].as_i64().expect("revision") + 1,
                "maintenance_admission_revision",
                "busy",
            ),
            (
                77,
                ready["revision"].as_i64().expect("revision"),
                "maintenance_admission_identity",
                "invalid_input",
            ),
        ] {
            host.dispatch(&serde_json::json!({"command":"maintenance_start","request_id":id,"operation":"backup","destination":destination,"revision":revision}).to_string()).expect("admission command");
            let refused = wait(&|value| {
                value["maintenance_ack"]["request_id"] == id
                    && value["maintenance_ack"]["error"] == key
            });
            super::maintenance_job::assert_admission_context(&refused, reason);
        }
        let legacy = crate::diagnostics::export_snapshot(&state.to_string()).expect("V1");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&legacy).expect("JSON"),
            serde_json::json!({"schema_version":1,"platform":"linux","errors":[]})
        );
        host.shutdown();
        assert!(host.wait_closed(Duration::from_secs(10)));
        drop(host);
        assert_eq!(fs::read(&destination).expect("исходник"), b"previous");
        fs::remove_file(destination).expect("очистка");
        fs::remove_dir(root.join("data/presets")).expect("очистка пустого preset fixture");
        for entry in fs::read_dir(root.join("data")).expect("данные") {
            fs::remove_file(entry.expect("файл").path()).expect("очистка данных");
        }
        fs::remove_dir(root.join("data")).expect("очистка data");
        fs::remove_dir(root).expect("очистка root");
    }
}

#[cfg(all(test, feature = "test-support"))]
mod scheduler_example_limits {
    use super::HostConfig;
    use std::path::PathBuf;

    #[test]
    fn interval_example_changes_only_ephemeral_input() {
        use std::time::Duration;
        let default = HostConfig::new(PathBuf::from("data"), PathBuf::from("engines"));
        assert_eq!(default.scheduler_interval, None);
        for interval in [Duration::ZERO, Duration::from_secs(86400)] {
            let config = HostConfig::ephemeral_scheduler_interval_example(
                PathBuf::from("data"),
                PathBuf::from("engines"),
                [7; 32],
                interval,
            );
            assert_eq!(config.scheduler_interval, Some(interval));
            assert_eq!(config.scheduler_capacity, None);
            assert!(config.ephemeral_key.is_some());
            assert!(!config.system_subscription_policy);
        }
    }

    #[test]
    fn capacity_cannot_disable_or_raise_production_limit() {
        for capacity in [0, 20_001, usize::MAX] {
            assert!(
                HostConfig::ephemeral_scheduler_example(
                    PathBuf::from("data"),
                    PathBuf::from("engines"),
                    [7; 32],
                    capacity,
                )
                .is_err()
            );
        }
        for capacity in [1, 20_000] {
            let config = HostConfig::ephemeral_scheduler_example(
                PathBuf::from("data"),
                PathBuf::from("engines"),
                [7; 32],
                capacity,
            )
            .expect("Допустимая ёмкость отдельного стенда");
            assert_eq!(config.scheduler_capacity, Some(capacity));
            assert!(config.ephemeral_key.is_some());
            assert!(!config.system_subscription_policy);
        }
        let config = HostConfig::new(PathBuf::from("data"), PathBuf::from("engines"));
        assert_eq!(config.scheduler_capacity, None);
    }
}

#[cfg(test)]
mod integration_policy_cancel_tests {
    use super::*;

    #[test]
    fn изменения_источника_и_presets_отменяют_inline_apply() {
        for raw in [
            serde_json::json!({"command":"source_change","request_id":1,"id":1,"expected_generation":1,"name":"Источник","url":"https://example.invalid/sub","local_exception":false,"route":"proxy"}),
            serde_json::json!({"command":"preset_activate","request_id":2,"expected_revision":0,"enabled":true}),
            serde_json::json!({"command":"preset_rollback","request_id":3}),
        ] {
            let command: Command = serde_json::from_value(raw).expect("fixture");
            assert!(command.cancels_policy_connect());
        }
        assert!(!Command::PresetCancel { request_id: 4 }.cancels_policy_connect());
    }
}

#[cfg(test)]
mod probe_context_tests {
    use super::*;
    use serde_json::Value;

    fn emitted(state: &Snapshot) -> String {
        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let output = captured.clone();
        let callback: Callback = Arc::new(move |raw| *output.lock().expect("snapshot") = raw);
        state.emit(&callback);
        let raw = captured.lock().expect("snapshot").clone();
        raw
    }

    #[test]
    fn probe_failure_and_network_loss_have_current_context() {
        let mut cause = Some(Cause::EngineExited);
        assert_eq!(
            probe_operation_error(HostError::Cancelled, &mut cause),
            "cancelled"
        );
        assert!(
            cause.is_none(),
            "ожидаемая отмена не является ошибкой probe"
        );
        assert_eq!(
            probe_operation_error(HostError::State, &mut cause),
            "check_failed"
        );
        assert_eq!(cause, Some(Cause::ProbeCheckFailed));
        let mut state = Snapshot::new(true);
        state.error_generation = 9;
        apply_session_update(
            &mut state,
            SessionUpdate {
                status: "Error",
                error: Some("check_failed"),
                context: cause,
                generation: Some(9),
                probe_result: None,
                network_stamp: None,
            },
            None,
        );
        assert!(crate::diagnostics::export_snapshot_v2(&emitted(&state)).is_some());
        state.status = "Connected";
        state.network_epoch = Some("previous-network".into());
        synchronize_network(&mut state, None);
        assert_eq!(state.status, "Limited");
        let export =
            crate::diagnostics::export_snapshot_v2(&emitted(&state)).expect("network loss context");
        let value: Value = serde_json::from_str(&export).expect("V2");
        for context in value["errors"].as_array().expect("contexts") {
            assert_eq!(context["reason"], "probe_network_changed");
            assert_eq!(context["generation"], "9");
        }
    }

    #[test]
    fn probe_producer_exports_typed_failure_and_rejects_stale_generation() {
        let target = ProbeTarget::new(
            "https://fixture.invalid/PRIVATE-PATH",
            Duration::from_secs(1),
        )
        .expect("target");
        for (result, reason) in [
            (
                ProbeResult::Response {
                    status: 503,
                    elapsed: Duration::from_millis(1),
                },
                "probe_http_status",
            ),
            (ProbeResult::Timeout, "probe_timeout"),
            (ProbeResult::Tls, "probe_tls"),
            (ProbeResult::Transport, "probe_transport"),
        ] {
            let mut state = Snapshot::new(true);
            state.error_generation = 7;
            apply_session_update(
                &mut state,
                probe_session_update(result, &target, 7, None, false),
                None,
            );
            assert_eq!(state.status, "Limited");
            let raw = emitted(&state);
            let export = crate::diagnostics::export_snapshot_v2(&raw)
                .expect("actual producer must provide typed context");
            let value: Value = serde_json::from_str(&export).expect("V2");
            let contexts = value["errors"].as_array().expect("contexts");
            assert_eq!(contexts.len(), 2);
            for context in contexts {
                assert_eq!(context["reason"], reason);
                assert_eq!(context["stage"], "probe");
                assert_eq!(context["generation"], "7");
                assert_eq!(context["params"], serde_json::json!({}));
            }
            assert!(!export.contains("PRIVATE-PATH"));
            assert!(!export.contains("fixture.invalid"));
            let success = ProbeResult::Response {
                status: 204,
                elapsed: Duration::from_millis(1),
            };
            apply_session_update(
                &mut state,
                probe_session_update(success, &target, 6, None, false),
                None,
            );
            assert_eq!(
                emitted(&state),
                raw,
                "late success must not replace current failure"
            );
            apply_session_update(
                &mut state,
                probe_session_update(success, &target, 7, None, false),
                None,
            );
            assert_eq!(state.status, "Connected");
            assert!(state.connection_error.is_none());
            let current: Value = serde_json::from_str(&emitted(&state)).expect("snapshot");
            assert_eq!(current["error_contexts"], serde_json::json!([]));
        }
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "disk_host_acceptance.rs"]
mod disk_host_acceptance;
