use super::*;

#[test]
fn cgroup_events_requires_a_single_zero_populated_field() {
    assert_eq!(empty_events("populated 0\nfrozen 0\n"), Ok(true));
    assert_eq!(empty_events("populated 1\nfrozen 0\n"), Ok(false));
    for malformed in [
        "",
        "populated 0",
        "populated 2\n",
        "populated 0\npopulated 0\n",
        "populated  0\n",
    ] {
        assert_eq!(
            empty_events(malformed),
            Err(WorkerSupervisorError::Untrusted)
        );
    }
}

#[test]
fn identity_never_accepts_a_replacement_or_unbound_pid() {
    let ticket = WorkerTicket {
        pid: 42,
        invocation: [7; 16],
    };
    let mut state = WorkerState {
        active: "active".into(),
        pid: 42,
        invocation: vec![7; 16],
    };
    assert!(ticket.matches(&state));
    state.pid = 43;
    assert!(!ticket.matches(&state));
    state.pid = 42;
    state.invocation[0] = 8;
    assert!(!ticket.matches(&state));
}

#[test]
fn fixed_units_have_no_client_supplied_names() {
    assert_eq!(WorkerMode::Run.service(), "yonik-worker.service");
    assert_eq!(WorkerMode::Check.service(), "yonik-worker-check.service");
    assert_eq!(WorkerMode::Run.socket(), "yonik-worker.socket");
    assert_eq!(
        WorkerMode::Check.cgroup(),
        "/system.slice/yonik-worker-check.service"
    );
}

use std::sync::Mutex;

struct PrivateBus {
    child: std::process::Child,
    address: String,
}
impl PrivateBus {
    fn start() -> Self {
        use std::io::BufRead;
        let mut child = std::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self {
            child,
            address: address.trim().into(),
        }
    }
    async fn connect(&self) -> Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap()
    }
}
impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[derive(Default)]
struct FakeState {
    jobs: Vec<(String, String)>,
    populated: bool,
    pid: u32,
    invocation: Vec<u8>,
    active: String,
    delay_ms: u64,
    completed: Vec<(String, String)>,
    socket_path: Option<std::path::PathBuf>,
    listener: Option<std::os::unix::net::UnixListener>,
    job_failed: bool,
}
struct FakeFence(Arc<Mutex<FakeState>>);
impl WorkerFence for FakeFence {
    fn empty(&self, _: WorkerMode) -> Result<bool> {
        Ok(!self.0.lock().unwrap().populated)
    }
}
struct FakeManager(Arc<Mutex<FakeState>>);
#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl FakeManager {
    async fn subscribe(&self) {}
    async fn load_unit(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        if ![
            WorkerMode::Run.service(),
            WorkerMode::Run.socket(),
            WorkerMode::Check.service(),
            WorkerMode::Check.socket(),
        ]
        .contains(&name)
        {
            return Err(zbus::fdo::Error::InvalidArgs("Неизвестный unit".into()));
        }
        Ok(OwnedObjectPath::try_from(format!("/test/{}", name.replace(['.', '-'], "_"))).unwrap())
    }
    async fn start_unit(
        &self,
        name: &str,
        mode: &str,
        #[zbus(signal_context)] context: zbus::object_server::SignalContext<'_>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        assert_eq!(mode, "replace");
        Ok(queue_job(
            Arc::clone(&self.0),
            "StartUnit",
            name,
            context.to_owned(),
        ))
    }
    async fn stop_unit(
        &self,
        name: &str,
        mode: &str,
        #[zbus(signal_context)] context: zbus::object_server::SignalContext<'_>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        assert_eq!(mode, "replace");
        Ok(queue_job(
            Arc::clone(&self.0),
            "StopUnit",
            name,
            context.to_owned(),
        ))
    }
    #[zbus(signal)]
    async fn job_removed(
        context: &zbus::object_server::SignalContext<'_>,
        id: u32,
        job: &OwnedObjectPath,
        unit: &str,
        result: &str,
    ) -> zbus::Result<()>;
}
fn queue_job(
    state: Arc<Mutex<FakeState>>,
    method: &'static str,
    name: &str,
    context: zbus::object_server::SignalContext<'static>,
) -> OwnedObjectPath {
    let name = name.to_owned();
    let (id, delay) = {
        let mut state = state.lock().unwrap();
        state.jobs.push((method.into(), name.clone()));
        (state.jobs.len() as u32, state.delay_ms)
    };
    let path = OwnedObjectPath::try_from(format!("/job/{id}")).unwrap();
    let result_path = path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        let result = {
            let mut state = state.lock().unwrap();
            if state.job_failed {
                "failed"
            } else {
                if method == "StartUnit" {
                    if let Some(path) = state.socket_path.as_ref() {
                        state.listener =
                            Some(std::os::unix::net::UnixListener::bind(path).unwrap());
                    }
                } else if name == WorkerMode::Run.service() {
                    state.pid = 0;
                    state.active = "inactive".into();
                }
                state.completed.push((method.into(), name.clone()));
                "done"
            }
        };
        let _ = FakeManager::job_removed(&context, id, &result_path, &name, result).await;
    });
    path
}
struct FakeUnit {
    state: Arc<Mutex<FakeState>>,
    run: bool,
}
#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl FakeUnit {
    #[zbus(property)]
    fn active_state(&self) -> String {
        if self.run {
            self.state.lock().unwrap().active.clone()
        } else {
            "inactive".into()
        }
    }
    #[zbus(property, name = "InvocationID")]
    fn invocation_id(&self) -> Vec<u8> {
        self.state.lock().unwrap().invocation.clone()
    }
}
struct FakeService {
    state: Arc<Mutex<FakeState>>,
    run: bool,
}
#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl FakeService {
    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> u32 {
        if self.run {
            self.state.lock().unwrap().pid
        } else {
            0
        }
    }
    #[zbus(property)]
    fn control_group(&self) -> String {
        if self.run {
            WorkerMode::Run.cgroup()
        } else {
            WorkerMode::Check.cgroup()
        }
        .into()
    }
}
struct Fixture {
    supervisor: SystemWorkerSupervisor,
    state: Arc<Mutex<FakeState>>,
    _server: Connection,
    _bus: PrivateBus,
}
impl Fixture {
    async fn new() -> Self {
        let bus = PrivateBus::start();
        let server = bus.connect().await;
        let state = Arc::new(Mutex::new(FakeState {
            invocation: vec![7; 16],
            active: "inactive".into(),
            ..FakeState::default()
        }));
        server
            .object_server()
            .at(MANAGER, FakeManager(Arc::clone(&state)))
            .await
            .unwrap();
        for mode in [WorkerMode::Run, WorkerMode::Check] {
            for name in [mode.service(), mode.socket()] {
                let path = format!("/test/{}", name.replace(['.', '-'], "_"));
                server
                    .object_server()
                    .at(
                        path.as_str(),
                        FakeUnit {
                            state: Arc::clone(&state),
                            run: name == WorkerMode::Run.service(),
                        },
                    )
                    .await
                    .unwrap();
                if name == mode.service() {
                    server
                        .object_server()
                        .at(
                            path.as_str(),
                            FakeService {
                                state: Arc::clone(&state),
                                run: mode == WorkerMode::Run,
                            },
                        )
                        .await
                        .unwrap();
                }
            }
        }
        let supervisor = SystemWorkerSupervisor {
            native_runtime: None,
            native_transfer: None,
            native_admission: None,
            native_custody: None,
            connection: bus.connect().await,
            owner: server.unique_name().unwrap().to_string(),
            permit: Arc::new(Permit),
            pending: Some(WorkerMode::Run),
            transfer: None,
            current: None,
            clean: false,
            retained_copy: None,
            fence: Box::new(FakeFence(Arc::clone(&state))),
        };
        Self {
            supervisor,
            state,
            _server: server,
            _bus: bus,
        }
    }
}
#[tokio::test]
async fn cleanup_stops_both_sockets_before_services_and_confirms_empty() {
    let mut fixture = Fixture::new().await;
    fixture.state.lock().unwrap().delay_ms = 20;
    let (_sender, mut cancel) = Cancellation::new();
    fixture
        .supervisor
        .cleanup(&mut cancel, Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert!(fixture.supervisor.clean);
    let jobs = fixture.state.lock().unwrap().jobs.clone();
    assert_eq!(
        jobs,
        vec![
            ("StopUnit".into(), "yonik-worker-check.socket".into()),
            ("StopUnit".into(), "yonik-worker.socket".into()),
            ("StopUnit".into(), "yonik-worker-check.service".into()),
            ("StopUnit".into(), "yonik-worker.service".into())
        ]
    );
    assert_eq!(fixture.state.lock().unwrap().completed, jobs);
}

#[tokio::test]
async fn activation_waits_for_delayed_job_before_connect() {
    let fixture = Fixture::new().await;
    let directory = std::env::temp_dir().join(format!("yonik-delayed-job-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    struct Area(std::path::PathBuf);
    impl Drop for Area {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0.join("worker.sock"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let area = Area(directory);
    let socket = area.0.join("worker.sock");
    {
        let mut state = fixture.state.lock().unwrap();
        state.delay_ms = 40;
        state.socket_path = Some(socket.clone());
    }
    fixture
        .supervisor
        .unit_job("StartUnit", WorkerMode::Run.socket())
        .await
        .unwrap();
    assert!(std::os::unix::net::UnixStream::connect(socket).is_ok());
}

#[tokio::test]
async fn failed_systemd_job_is_not_readiness() {
    let fixture = Fixture::new().await;
    fixture.state.lock().unwrap().job_failed = true;
    assert_eq!(
        fixture
            .supervisor
            .unit_job("StartUnit", WorkerMode::Run.socket())
            .await,
        Err(WorkerSupervisorError::Protocol)
    );
}
#[tokio::test]
async fn inactive_state_cannot_confirm_cleanup_of_populated_cgroup() {
    let mut fixture = Fixture::new().await;
    fixture.state.lock().unwrap().populated = true;
    let (_sender, mut cancel) = Cancellation::new();
    assert_eq!(
        fixture
            .supervisor
            .cleanup(&mut cancel, Instant::now() + Duration::from_millis(80))
            .await,
        Err(WorkerSupervisorError::Timeout)
    );
    assert!(!fixture.supervisor.clean);
    assert!(fixture.supervisor.pending.is_some());
}
#[tokio::test]
async fn replacement_ticket_never_stops_a_service() {
    let mut fixture = Fixture::new().await;
    {
        let mut state = fixture.state.lock().unwrap();
        state.pid = 42;
        state.invocation = vec![8; 16];
        state.active = "active".into();
    }
    let ticket = WorkerTicket {
        pid: 42,
        invocation: [7; 16],
    };
    let (_sender, mut cancel) = Cancellation::new();
    assert_eq!(
        fixture.supervisor.stop(&ticket, &mut cancel).await,
        Err(WorkerSupervisorError::Stale)
    );
    assert!(fixture.state.lock().unwrap().jobs.is_empty());
    assert_eq!(
        fixture.supervisor.observe(&ticket).await,
        Err(WorkerSupervisorError::Stale)
    );
}
#[tokio::test]
async fn cancelled_cleanup_retains_transfer_until_recovery_waits_for_it() {
    let mut fixture = Fixture::new().await;
    let (release, wait) = std::sync::mpsc::channel();
    fixture.supervisor.transfer = Some(tokio::task::spawn_blocking(move || {
        wait.recv().unwrap();
        Ok((
            WorkerAck {
                pid: 42,
                status: WorkerStatus::Accepted,
            },
            None,
        ))
    }));
    let (_sender, mut cancel) = Cancellation::new();
    let result = fixture
        .supervisor
        .cleanup(&mut cancel, Instant::now() + Duration::from_millis(50))
        .await;
    assert_eq!(result, Err(WorkerSupervisorError::Timeout));
    assert!(fixture.supervisor.transfer.is_some());
    assert_eq!(fixture.state.lock().unwrap().jobs.len(), 2);
    release.send(()).unwrap();
    fixture
        .supervisor
        .cleanup(&mut cancel, Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert!(fixture.supervisor.transfer.is_none());
    assert!(fixture.supervisor.clean);
}

fn value<'a>(v: impl Into<zbus::zvariant::Value<'a>>) -> OwnedValue {
    OwnedValue::try_from(v.into()).unwrap()
}
fn service_contract(mode: WorkerMode) -> Properties {
    let mut p = Properties::new();
    for (key, v) in [
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
        p.insert(key.into(), value(v));
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
        p.insert(key.into(), value(true));
    }
    for key in ["PrivateNetwork", "PrivateDevices"] {
        p.insert(key.into(), value(mode == WorkerMode::Check));
    }
    for key in ["CapabilityBoundingSet", "AmbientCapabilities"] {
        p.insert(
            key.into(),
            value(if mode == WorkerMode::Check {
                0u64
            } else {
                1 << 12
            }),
        );
    }
    for (key, v) in [
        ("MemoryMax", 256 * 1024 * 1024u64),
        ("TasksMax", 64),
        ("TimeoutStopUSec", 5_000_000),
    ] {
        p.insert(key.into(), value(v));
    }
    p.insert("RestrictNamespaces".into(), value(0u64));
    p.insert("SystemCallArchitectures".into(), value(vec!["native"]));
    p.insert("UMask".into(), value(0o77u32));
    p.insert("KillSignal".into(), value(15i32));
    p.insert("FinalKillSignal".into(), value(9i32));
    let exec: ExecCommands = vec![(
        "/usr/lib/yonik/yonik-worker".into(),
        vec![
            "/usr/lib/yonik/yonik-worker".into(),
            if mode == WorkerMode::Check {
                "--check"
            } else {
                "--run"
            }
            .into(),
        ],
        false,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )];
    p.insert("ExecStart".into(), value(exec));
    p.insert(
        "DeviceAllow".into(),
        value(if mode == WorkerMode::Check {
            Vec::<(String, String)>::new()
        } else {
            vec![("/dev/net/tun".into(), "rw".into())]
        }),
    );
    p
}
#[test]
fn loaded_service_contract_rejects_privilege_and_command_changes() {
    for mode in [WorkerMode::Run, WorkerMode::Check] {
        assert_eq!(validate_service(&service_contract(mode), mode), Ok(()));
        for (key, v) in [
            ("User", value("root")),
            ("AmbientCapabilities", value(u64::MAX)),
            ("CapabilityBoundingSet", value(u64::MAX)),
            ("NoNewPrivileges", value(false)),
            ("PrivateNetwork", value(mode != WorkerMode::Check)),
            ("KillMode", value("process")),
            ("MemoryMax", value(u64::MAX)),
            ("KillSignal", value(9i32)),
            ("TimeoutStopUSec", value(u64::MAX)),
        ] {
            let mut p = service_contract(mode);
            p.insert(key.into(), v);
            assert_eq!(
                validate_service(&p, mode),
                Err(WorkerSupervisorError::Untrusted),
                "{key}"
            );
        }
        let mut p = service_contract(mode);
        p.remove("DeviceAllow");
        assert_eq!(
            validate_service(&p, mode),
            Err(WorkerSupervisorError::Untrusted)
        );
    }
}
#[tokio::test]
async fn closed_cancellation_source_preserves_dirty_state() {
    let mut fixture = Fixture::new().await;
    let (sender, mut cancel) = Cancellation::new();
    drop(sender);
    assert_eq!(
        fixture
            .supervisor
            .cleanup(&mut cancel, Instant::now() + Duration::from_secs(1))
            .await,
        Err(WorkerSupervisorError::Cancelled)
    );
    assert!(!fixture.supervisor.clean);
    assert!(fixture.supervisor.pending.is_some());
    assert!(fixture.state.lock().unwrap().jobs.is_empty());
}

#[test]
fn missing_cgroup_is_empty_but_symlink_and_wrong_type_are_unknown() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("yonik-worker-fence-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let parent = File::open(&path).unwrap();
    assert!(
        open_worker_group(&parent, WorkerMode::Run)
            .unwrap()
            .is_none()
    );
    std::fs::write(path.join(WorkerMode::Run.service()), b"").unwrap();
    assert!(open_worker_group(&parent, WorkerMode::Run).is_err());
    std::fs::remove_file(path.join(WorkerMode::Run.service())).unwrap();
    std::os::unix::fs::symlink(&path, path.join(WorkerMode::Run.service())).unwrap();
    assert!(open_worker_group(&parent, WorkerMode::Run).is_err());
    std::fs::remove_file(path.join(WorkerMode::Run.service())).unwrap();
    std::fs::create_dir(path.join(WorkerMode::Run.service())).unwrap();
    assert!(
        open_worker_group(&parent, WorkerMode::Run)
            .unwrap()
            .is_some()
    );
    std::fs::remove_dir(path.join(WorkerMode::Run.service())).unwrap();
    std::fs::remove_dir(path).unwrap();
}

#[tokio::test]
async fn copy_reservation_survives_cancel_and_populated_cgroup_until_empty() {
    let mut fixture = Fixture::new().await;
    let payload = binding_test_payload();
    let weak = Arc::downgrade(&payload);
    fixture.supervisor.retained_copy = Some(payload);
    fixture.state.lock().unwrap().populated = true;
    let (signal, mut cancelled) = Cancellation::new();
    signal.send_replace(true);
    assert!(
        fixture
            .supervisor
            .cleanup(&mut cancelled, Instant::now() + Duration::from_secs(1))
            .await
            .is_err()
    );
    assert!(weak.upgrade().is_some());
    let (_keep, mut cancel) = Cancellation::new();
    assert!(
        fixture
            .supervisor
            .cleanup(&mut cancel, Instant::now() + Duration::from_millis(80))
            .await
            .is_err()
    );
    assert!(weak.upgrade().is_some());
    fixture.state.lock().unwrap().populated = false;
    fixture
        .supervisor
        .cleanup(&mut cancel, Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert!(weak.upgrade().is_none());
}

#[test]
fn private_asset_mount_requires_bounded_controlled_tmpfs_options() {
    let mut p = Properties::new();
    for options in [
        "rw,nosuid,nodev,noexec,mode=1777,size=64M,nr_inodes=128",
        "size=67108864,mode=01777,nr_inodes=128,noexec,nodev,nosuid,rw",
    ] {
        p.insert(
            "TemporaryFileSystem".into(),
            value(vec![("/dev/shm".to_owned(), options.to_owned())]),
        );
        assert!(validate_private_assets(&p).is_ok());
    }
    for options in [
        "rw,nosuid,nodev,noexec,mode=1777",
        "rw,nosuid,nodev,noexec,mode=1777,size=128M,nr_inodes=128",
        "rw,nosuid,nodev,noexec,mode=1777,size=64M,nr_inodes=129",
        "rw,nosuid,nodev,exec,mode=1777,size=64M,nr_inodes=128",
    ] {
        p.insert(
            "TemporaryFileSystem".into(),
            value(vec![("/dev/shm".to_owned(), options.to_owned())]),
        );
        assert!(validate_private_assets(&p).is_err());
    }
}

#[test]
fn namespace_filter_requires_typed_full_ban_and_native_abi() {
    for mode in [WorkerMode::Run, WorkerMode::Check] {
        for invalid in [value(true), value(1u64), value(u64::MAX), value(0u32)] {
            let mut p = service_contract(mode);
            p.insert("RestrictNamespaces".into(), invalid);
            assert_eq!(
                validate_service(&p, mode),
                Err(WorkerSupervisorError::Untrusted)
            );
        }
        for invalid in [vec![], vec!["x86"], vec!["native", "x86"]] {
            let mut p = service_contract(mode);
            p.insert("SystemCallArchitectures".into(), value(invalid));
            assert_eq!(
                validate_service(&p, mode),
                Err(WorkerSupervisorError::Untrusted)
            );
        }
        for missing in ["RestrictNamespaces", "SystemCallArchitectures"] {
            let mut p = service_contract(mode);
            p.remove(missing);
            assert_eq!(
                validate_service(&p, mode),
                Err(WorkerSupervisorError::Untrusted)
            );
        }
    }
}

#[tokio::test]
async fn bootstrap_observation_requires_fresh_untransferred_run() {
    let mut fixture = Fixture::new().await;
    fixture.supervisor.pending = None;
    assert!(matches!(
        fixture.supervisor.inspect_anchor_bootstrap().await,
        Err(WorkerSupervisorError::UnitProofGap)
    ));
    fixture.supervisor.pending = Some(WorkerMode::Check);
    assert!(matches!(
        fixture.supervisor.inspect_anchor_bootstrap().await,
        Err(WorkerSupervisorError::UnitProofGap)
    ));
    assert!(fixture.state.lock().unwrap().jobs.is_empty());
}

#[tokio::test]
async fn actual_controlled_bootstrap_transport_without_ptrace() -> Result<()> {
    if std::env::var_os("YONIK_ANCHOR_FIXED_UNIT_VM").is_none() {
        return Ok(());
    }
    assert_eq!(
        std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .map_err(unavailable)?
            .trim(),
        "QEMU"
    );
    let marker =
        std::fs::symlink_metadata("/etc/yonik-production-helper-vm").map_err(unavailable)?;
    assert!(marker.is_file() && marker.uid() == 0 && marker.mode() & 0o022 == 0);
    assert_eq!(
        std::fs::read_to_string("/etc/yonik-production-helper-vm").map_err(unavailable)?,
        "yonik-production-helper-disposable-v1\n"
    );
    let status = std::fs::read_to_string("/proc/self/status").map_err(unavailable)?;
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    for field in ["CapEff:", "CapPrm:", "CapBnd:"] {
        let caps = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok());
        assert_eq!(caps, Some(1 << 12), "{field}");
    }
    assert_eq!(rustix::process::getuid().as_raw(), 0);
    let mut supervisor = SystemWorkerSupervisor::system().await?;
    let (_sender, mut cancel) = Cancellation::new();
    let deadline = Instant::now() + DEADLINE;
    supervisor
        .begin(WorkerMode::Run, &mut cancel, deadline)
        .await?;
    let result = async {
        let stream = tokio::net::UnixStream::connect(WorkerMode::Run.channel())
            .await
            .map_err(unavailable)?;
        let ready = Instant::now() + Duration::from_secs(1);
        loop {
            if supervisor.state(WorkerMode::Run).await?.active == "active" {
                break;
            }
            if Instant::now() >= ready {
                return Err(WorkerSupervisorError::Timeout);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut bootstrap = supervisor.inspect_anchor_bootstrap().await?;
        let mut canonical = supervisor.state(WorkerMode::Run).await?;
        bootstrap.validate_identity()?;
        bootstrap.validate_state(&canonical)?;
        canonical.invocation[0] ^= 1;
        assert_eq!(
            bootstrap.validate_state(&canonical),
            Err(WorkerSupervisorError::Stale)
        );
        canonical.invocation[0] ^= 1;
        canonical.pid = canonical.pid.saturating_add(1);
        assert_eq!(
            bootstrap.validate_state(&canonical),
            Err(WorkerSupervisorError::Stale)
        );
        bootstrap.start += 1;
        assert_eq!(
            bootstrap.validate_identity(),
            Err(WorkerSupervisorError::Stale)
        );
        bootstrap.start -= 1;
        let expires = bootstrap.expires;
        bootstrap.expires = Instant::now();
        assert_eq!(
            bootstrap.validate_identity(),
            Err(WorkerSupervisorError::UnitProofGap)
        );
        bootstrap.expires = expires;
        let stream = stream.into_std().map_err(unavailable)?;
        stream.set_nonblocking(false).map_err(unavailable)?;
        let witness = bootstrap.exchange(&stream, [1; 32], [2; 16], 7)?;
        assert_eq!(witness.retained_namespace_count(), 2);
        // Это observation, не production anchor: payload/assets не передаются.
        witness.revoke();
        assert_eq!(witness.retained_namespace_count(), 0);
        drop(stream);
        Ok(())
    }
    .await;
    let cleanup = supervisor
        .cleanup(&mut cancel, Instant::now() + DEADLINE)
        .await;
    result?;
    cleanup
}

#[test]
fn run_authority_is_single_use_and_revokes_outstanding_token() {
    let owner = RunAuthority::new([1; 16], 7, 9).unwrap();
    let token = owner.authorize([2; 32]).unwrap();
    assert!(token.validate().is_ok());
    assert!(owner.authorize([2; 32]).is_err());
    owner.revoke();
    assert_eq!(token.validate(), Err(RunAuthorizationError::Revoked));
}

#[test]
fn dropping_run_owner_revokes_token() {
    let token = {
        let owner = RunAuthority::new([1; 16], 7, 9).unwrap();
        owner.authorize([2; 32]).unwrap()
    };
    assert_eq!(token.validate(), Err(RunAuthorizationError::Revoked));
}

use super::super::run_authorization::{RunAuthority, RunAuthorizationError};

#[test]
fn dropping_attempt_guard_revokes_outstanding_token() {
    let owner = RunAuthority::new([1; 16], 7, 9).unwrap();
    let token = owner.authorize([2; 32]).unwrap();
    let guard = token.guard();
    drop(guard);
    assert_eq!(token.validate(), Err(RunAuthorizationError::Revoked));
    assert!(owner.authorize([3; 32]).is_err());
}

#[test]
fn authority_rejects_zero_context_and_nonce() {
    assert!(RunAuthority::new([0; 16], 7, 9).is_err());
    assert!(RunAuthority::new([1; 16], 0, 9).is_err());
    assert!(RunAuthority::new([1; 16], 7, 0).is_err());
    let owner = RunAuthority::new([1; 16], 7, 9).unwrap();
    assert!(owner.authorize([0; 32]).is_err());
    assert!(owner.authorize([2; 32]).is_ok());
}

#[test]
fn run_authority_cannot_issue_after_revoke() {
    let owner = RunAuthority::new([1; 16], 7, 9).unwrap();
    owner.revoke();
    owner.revoke();
    assert!(matches!(
        owner.authorize([2; 32]),
        Err(RunAuthorizationError::Revoked)
    ));
}

#[test]
fn concurrent_authorization_has_exactly_one_winner() {
    let owner = RunAuthority::new([1; 16], 7, 9).unwrap();
    std::thread::scope(|scope| {
        let left = scope.spawn(|| owner.authorize([2; 32]));
        let right = scope.spawn(|| owner.authorize([3; 32]));
        let left = left.join().unwrap();
        let right = right.join().unwrap();
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    });
}

pub(super) fn binding_test_payload() -> Arc<WorkerPayload> {
    use sha2::Digest;
    let path = std::path::Path::new("/usr/bin/true");
    let bytes = std::fs::read(path).unwrap();
    let binary = crate::BinarySnapshot::load(
        path,
        crate::Sha256(sha2::Sha256::digest(&bytes).into()),
        yonik_engine::Engine::SingBox,
    )
    .unwrap();
    let server = yonik_import::import_bytes(b"socks5://127.0.0.1:10999".to_vec())
        .unwrap()
        .servers
        .remove(0);
    let config = yonik_engine::compile(
        &server,
        yonik_engine::Engine::SingBox,
        std::num::NonZeroU16::new(10808).unwrap(),
    )
    .unwrap();
    Arc::new(WorkerPayload::new(binary, config).unwrap())
}

#[test]
fn actual_payload_transfer_rejects_late_ack_after_revocation() {
    use std::io::{Read, Write};
    let payload = binding_test_payload();
    let owner = RunAuthority::new([1; 16], 7, 9).unwrap();
    let token = owner.authorize([2; 32]).unwrap();
    let guard = token.guard();
    let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
    let (received, wait_received) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let receiver = std::thread::spawn(move || {
        let mut header = Vec::new();
        server.read_to_end(&mut header).unwrap();
        assert!(!header.is_empty());
        received.send(()).unwrap();
        wait_release.recv().unwrap();
        let mut ack = b"YNKA".to_vec();
        ack.extend_from_slice(&42u32.to_be_bytes());
        ack.push(2);
        server.write_all(&ack).unwrap();
    });
    let transfer =
        std::thread::spawn(move || InvocationBinding::transfer_payload(&payload, &token, &client));
    wait_received.recv_timeout(Duration::from_secs(2)).unwrap();
    drop(guard);
    release.send(()).unwrap();
    assert_eq!(transfer.join().unwrap(), Err(WorkerSupervisorError::Stale));
    receiver.join().unwrap();
    assert!(owner.authorize([3; 32]).is_err());
}

#[test]
fn kernel_report_shares_run_epoch_revocation() {
    use crate::worker::anchor_exchange::NamespaceObservation;
    let owner = RunAuthority::new([2; 16], 7, 9).unwrap();
    let token = owner.authorize([4; 32]).unwrap();
    let mismatch = NamespaceObservation::test_kernel_observation([5; 16], 7);
    assert!(token.bind_custody(&mismatch).is_err());
    assert_eq!(mismatch.retained_namespace_count(), 0);
    assert!(token.validate().is_err());
    let owner = RunAuthority::new([2; 16], 7, 9).unwrap();
    let token = owner.authorize([4; 32]).unwrap();
    let observation = NamespaceObservation::test_kernel_observation([2; 16], 7);
    token.bind_custody(&observation).unwrap();
    assert_eq!(observation.retained_namespace_count(), 2);
    owner.revoke();
    assert_eq!(observation.retained_namespace_count(), 0);
    assert!(token.bind_custody(&observation).is_err());
}

#[test]
fn duplicate_kernel_report_revokes_all_custody() {
    use crate::worker::anchor_exchange::NamespaceObservation;
    let owner = RunAuthority::new([2; 16], 7, 9).unwrap();
    let token = owner.authorize([4; 32]).unwrap();
    let first = NamespaceObservation::test_kernel_observation([2; 16], 7);
    let second = NamespaceObservation::test_kernel_observation([2; 16], 7);
    token.bind_custody(&first).unwrap();
    assert!(token.bind_custody(&second).is_err());
    assert_eq!(first.retained_namespace_count(), 0);
    assert_eq!(second.retained_namespace_count(), 0);
    assert!(token.validate().is_err());
}

fn authorized_result_fixture() -> (RunAuthority, AuthorizedRun) {
    let owner = RunAuthority::new([2; 16], 7, 9).unwrap();
    let result = unit_owner_result(&owner, binding_test_payload());
    (owner, result)
}

#[test]
fn authorized_result_retains_guard_binding_and_custody_until_drop() {
    let (owner, result) = authorized_result_fixture();
    assert!(result.lease.binding.authorization.validate().is_ok());
    assert_eq!(
        result
            .lease
            .binding
            .kernel
            .as_ref()
            .unwrap()
            .retained_namespace_count(),
        2
    );
    assert_eq!(result.ticket.pid(), 42);
    assert!(!owner.is_revoked());
    drop(result);
    // Повторный revoke безопасен, а повторная выдача owner закрыта.
    assert!(owner.is_revoked());

    assert!(owner.authorize([5; 32]).is_err());
}

#[tokio::test]
async fn dropping_pending_authorized_future_revokes_token() {
    let owner = RunAuthority::new([2; 16], 7, 9).unwrap();
    let token = owner.authorize([4; 32]).unwrap();
    let mut future = Box::pin(async {
        let _guard = token.guard();
        std::future::pending::<()>().await;
    });
    assert!(futures_util::poll!(future.as_mut()).is_pending());
    drop(future);
    assert_eq!(token.validate(), Err(RunAuthorizationError::Revoked));
}

#[test]
fn custody_rejects_owner_nonce_mismatch() {
    let owner = RunAuthority::new([2; 16], 7, 9).unwrap();
    let token = owner.authorize([5; 32]).unwrap();
    let observation =
        crate::worker::anchor_exchange::NamespaceObservation::test_kernel_observation([2; 16], 7);
    assert!(token.bind_custody(&observation).is_err());
    assert_eq!(observation.retained_namespace_count(), 0);
    assert!(owner.is_revoked());
}

#[test]
fn held_authorized_result_observes_owner_revoke() {
    let (owner, result) = authorized_result_fixture();
    owner.revoke();
    assert!(matches!(result.ticket(), Err(WorkerSupervisorError::Stale)));
    assert_eq!(
        result.lease.binding.authorization.validate(),
        Err(RunAuthorizationError::Revoked)
    );
    assert_eq!(
        result
            .lease
            .binding
            .kernel
            .as_ref()
            .unwrap()
            .retained_namespace_count(),
        0
    );
}

#[test]
fn accepted_binding_rejects_expiry_and_identity_drift() {
    let (_owner, mut result) = authorized_result_fixture();
    let state = WorkerState {
        active: "active".into(),
        pid: 42,
        invocation: vec![8; 16],
    };
    assert_eq!(
        result.lease.binding.validate_state(&state),
        Err(WorkerSupervisorError::Stale)
    );
    result.lease.binding.observation.expires = Instant::now();
    assert!(matches!(
        result.ticket(),
        Err(WorkerSupervisorError::UnitProofGap)
    ));
    let AuthorizedRun { lease, .. } = result;
    assert!(matches!(
        lease.binding.accept(WorkerAck {
            pid: 42,
            status: WorkerStatus::Accepted
        }),
        Err(WorkerSupervisorError::UnitProofGap)
    ));
}

#[test]
fn owner_link_requires_exact_owner_and_payload_even_with_equal_bytes() {
    let (owner, result) = authorized_result_fixture();
    let payload = Arc::clone(&result.lease.binding.payload);
    let equal_payload = binding_test_payload();
    assert_eq!(payload.digest(), equal_payload.digest());
    assert!(!Arc::ptr_eq(&payload, &equal_payload));
    let foreign_owner = RunAuthority::new([2; 16], 7, 9).unwrap();
    // Unit link boundary: fixture не проходит canonical cgroup identity.
    assert!(
        result
            .lease
            .binding
            .validate_owner(&owner, &payload)
            .is_ok()
    );
    assert!(
        result
            .lease
            .binding
            .validate_owner(&foreign_owner, &payload)
            .is_err()
    );
    assert!(
        result
            .lease
            .binding
            .validate_owner(&owner, &equal_payload)
            .is_err()
    );
    assert!(result.validate_owner(&owner, &payload).is_err());
    owner.revoke();
    assert!(
        result
            .lease
            .binding
            .validate_owner(&owner, &payload)
            .is_err()
    );
    assert_eq!(
        result
            .lease
            .binding
            .kernel
            .as_ref()
            .unwrap()
            .retained_namespace_count(),
        0
    );
}

#[test]
fn full_owner_validation_keeps_canonical_gate_closed_for_link_fixture() {
    for case in 0..4 {
        let (owner, mut result) = authorized_result_fixture();
        let foreign = RunAuthority::new([2; 16], 7, 9).unwrap();
        let payload = if case == 1 {
            binding_test_payload()
        } else {
            Arc::clone(&result.lease.binding.payload)
        };
        assert_eq!(payload.digest(), result.lease.binding.payload.digest());
        if case == 2 {
            owner.revoke();
        }
        if case == 3 {
            result.lease.binding.observation.expires = Instant::now();
        }
        assert!(
            result
                .validate_owner(if case == 0 { &foreign } else { &owner }, &payload)
                .is_err()
        );
        // Полный метод не легализует link-only fixture даже при правильных Arc.
        assert!(
            result
                .validate_owner(&owner, &result.lease.binding.payload)
                .is_err()
        );
    }
}

#[test]
fn raw_identity_fixture_uses_every_full_validation_predicate() {
    use std::os::fd::AsRawFd;
    for case in 0..15 {
        let owner = RunAuthority::new([2; 16], 7, 9).unwrap();
        let payload = binding_test_payload();
        let mut run = unit_raw_identity_result(&owner, Arc::clone(&payload));
        run.validate_owner(&owner, &payload).unwrap();
        let observation = &mut run.lease.binding.observation;
        let fdinfo = format!("/proc/self/fdinfo/{}", observation.pidfd.as_raw_fd());
        let fixture = observation.fixture_io.as_mut().unwrap();
        match case {
            0 => fixture.now = observation.expires,
            1 => {
                fixture.files.remove(&fdinfo);
            }
            2 => {
                fixture.files.insert(fdinfo, "Pid: 43\n".into());
            }
            3 => {
                fixture.files.insert(fdinfo, "Pid: invalid\n".into());
            }
            4 => {
                fixture
                    .files
                    .insert("/proc/42/stat".into(), "malformed".into());
            }
            5 => {
                fixture.files.get_mut("/proc/42/stat").unwrap().push('2');
            }
            6 => {
                fixture
                    .files
                    .insert("/proc/42/status".into(), "Gid: 0 0 0 0\n".into());
            }
            7 => {
                fixture
                    .files
                    .insert("/proc/42/status".into(), "Uid: 0 0 0 0\n".into());
            }
            8 => {
                fixture.files.insert(
                    "/proc/42/status".into(),
                    "Uid: 0 0 x 0\nGid: 0 0 0 0\n".into(),
                );
            }
            9 => {
                fixture.files.insert(
                    "/proc/42/status".into(),
                    "Uid: 0 0 1 0\nGid: 0 0 0 0\n".into(),
                );
            }
            10 => {
                fixture.files.insert(
                    "/proc/42/status".into(),
                    "Uid: 0 0 0 0\nGid: 0 0 0 1\n".into(),
                );
            }
            11 => {
                fixture
                    .files
                    .insert("/proc/42/cgroup".into(), "0::/wrong.service\n".into());
            }
            12 => run.ticket.pid += 1,
            13 => run.ticket.invocation = [8; 16],
            14 => owner.revoke(),
            _ => unreachable!(),
        }
        assert!(
            run.validate_owner(&owner, &payload).is_err(),
            "raw predicate {case}"
        );
    }
}

#[test]
fn raw_identity_fixture_is_scoped_to_one_retained_observation() {
    let first = RunAuthority::new([2; 16], 7, 9).unwrap();
    let second = RunAuthority::new([2; 16], 7, 9).unwrap();
    let payload = binding_test_payload();
    let raw = unit_raw_identity_result(&first, Arc::clone(&payload));
    let real = unit_owner_result(&second, Arc::clone(&payload));
    raw.validate_owner(&first, &payload).unwrap();
    assert!(real.validate_owner(&second, &payload).is_err());
    raw.validate_owner(&first, &payload).unwrap();
}
