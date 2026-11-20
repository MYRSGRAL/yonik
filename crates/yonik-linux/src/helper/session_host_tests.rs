use super::{
    RecoveryFailure, RecoveryHost, ServiceError, endpoint, keep_after_stop, parse_worker_uid,
    recover_ordered, same_link_contract,
};

struct StartupJournal(std::path::PathBuf);

impl StartupJournal {
    fn new(case: &str) -> Self {
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        Self(std::env::temp_dir().join(format!(
            "yonik-startup-{case}-{:x}",
            u64::from_le_bytes(random)
        )))
    }

    fn owner() -> crate::managed_network::Ownership {
        let (dev, ino) = super::super::namespace().unwrap();
        crate::managed_network::Ownership::new(rustix::process::getuid().as_raw(), 77, 1, dev, ino)
            .unwrap()
    }
}

impl Drop for StartupJournal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("journal.json"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[tokio::test]
#[ignore = "Одноразовая QEMU VM в отдельном сетевом namespace"]
async fn throw_routes_resume_cleanup_after_reopen() {
    use crate::{
        Cancellation,
        helper::SessionNetworkPlan,
        managed_network::{Journal, Resource, tun::TunExecutor},
    };
    use std::{fs, process::Command, time::Duration};

    assert_eq!(
        std::env::var("YONIK_PRODUCTION_HELPER_VM").as_deref(),
        Ok("1")
    );
    assert_eq!(
        fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .unwrap()
            .trim(),
        "QEMU"
    );
    assert_eq!(
        fs::read_to_string("/etc/yonik-production-helper-vm").unwrap(),
        "yonik-production-helper-disposable-v1\n"
    );
    assert_ne!(
        fs::read_link("/proc/thread-self/ns/net").unwrap(),
        fs::read_link("/proc/1/ns/net").unwrap()
    );
    let ip = |arguments: &[&str]| {
        let output = Command::new("/usr/bin/ip")
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "throw-outer", "type", "dummy"]);
    ip(&["link", "set", "throw-outer", "up"]);
    ip(&["-4", "addr", "add", "192.0.2.1/24", "dev", "throw-outer"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:42::1/64",
        "dev",
        "throw-outer",
        "nodad",
    ]);

    let journal_path = StartupJournal::new("throw-routes");
    let owner = StartupJournal::owner();
    let (_keep, mut cancel) = Cancellation::new();
    let read_topology = |mut cancel| async move {
        crate::read_topology(&mut cancel, Duration::from_secs(3))
            .await
            .unwrap()
    };
    let baseline = read_topology(cancel.clone()).await;
    let plan = SessionNetworkPlan::reserve(owner, &baseline)
        .unwrap()
        .with_throw_routes(&[
            ("192.0.2.0".parse().unwrap(), 24),
            ("2001:db8:42::".parse().unwrap(), 64),
        ])
        .unwrap();
    let mut journal = Journal::open(&journal_path.0, owner).unwrap();
    let mut executor = TunExecutor::open(owner).unwrap();
    let index = plan.configure(&mut executor, &mut journal).await.unwrap();
    plan.capture(&mut executor, &mut journal, index)
        .await
        .unwrap();
    let current = read_topology(cancel.clone()).await;
    let tun_name = std::str::from_utf8(
        &current
            .links
            .iter()
            .find(|link| link.index == index)
            .unwrap()
            .name,
    )
    .unwrap()
    .to_owned();
    plan.verify_external(&baseline, current, &journal, index)
        .unwrap();
    for (family, destination) in [("-4", "192.0.2.2"), ("-6", "2001:db8:42::2")] {
        let result: serde_json::Value =
            serde_json::from_slice(&ip(&[family, "-j", "route", "get", destination])).unwrap();
        assert_eq!(result[0]["dev"], "throw-outer");
    }
    assert_eq!(
        journal
            .records()
            .iter()
            .filter(|record| matches!(record.resource(), Resource::ThrowRoute { .. }))
            .count(),
        2
    );

    let table = plan.routing_table().to_string();
    drop(executor);
    drop(journal);
    drop(plan);
    let mut journal = Journal::open(&journal_path.0, owner).unwrap();
    let foreign = [
        "throw",
        "203.0.113.0/24",
        "table",
        &table,
        "proto",
        "253",
        "metric",
        "77",
    ];
    for operation in ["add", "del"] {
        let mut arguments = vec!["-4", "route", operation];
        arguments.extend(foreign);
        ip(&arguments);
        if operation == "add" {
            let before = ip(&["-4", "-j", "route", "show", "table", &table]);
            assert!(super::cleanup_records(owner, &mut journal).await.is_err());
            let after = ip(&["-4", "-j", "route", "show", "table", &table]);
            assert_eq!(before, after);
        }
    }
    let anchor = [
        "default", "dev", &tun_name, "table", &table, "proto", "253", "scope", "link", "metric",
        "100",
    ];
    for operation in ["del", "add"] {
        let mut arguments = vec!["-4", "route", operation];
        arguments.extend(anchor);
        ip(&arguments);
        if operation == "del" {
            assert!(super::cleanup_records(owner, &mut journal).await.is_err());
            assert!(journal.records().iter().any(|record| matches!(
                record.resource(), Resource::ThrowRoute { destination, .. } if destination.is_ipv4()
            )));
            let routes: serde_json::Value =
                serde_json::from_slice(&ip(&["-4", "-j", "route", "show", "table", &table]))
                    .unwrap();
            assert_eq!(routes[0]["type"], "throw");
            assert_eq!(routes[0]["dst"], "192.0.2.0/24");
        }
    }
    super::cleanup_records(owner, &mut journal).await.unwrap();
    assert!(journal.records().is_empty());
    let after = crate::read_topology(&mut cancel, Duration::from_secs(3))
        .await
        .unwrap();
    assert!(crate::network::same_external_topology(&baseline, &after));
    eprintln!("Оба маршрута throw удалены после переоткрытия журнала. Чужая запись не изменилась");
}

#[test]
fn fake_dns_startup_issues_immediately_without_previous_quarantine() {
    use yonik_engine::fake_dns::{DnsEpoch, FakeDnsQuestion};

    let path = StartupJournal::new("empty");
    let epoch = DnsEpoch {
        network: 1,
        engine: 1,
        resolver: 1,
    };
    let question = FakeDnsQuestion::parse(
        b"\x01\x23\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01",
    )
    .unwrap();
    for journal_exists in [false, true] {
        if journal_exists {
            drop(crate::managed_network::Journal::open(&path.0, StartupJournal::owner()).unwrap());
        }
        let (journal, mut fake_dns) = super::super::open_startup_state(&path.0).unwrap();
        assert_eq!(journal.is_some(), journal_exists);
        assert!(fake_dns.check_cold_start().is_ok());
        let leases = fake_dns.leases().unwrap();
        leases.advance_epoch(epoch).unwrap();
        let response = leases.synthesize(&question, epoch);
        assert_eq!(response[3] & 15, 0);
        assert_eq!(&response[6..8], &[0, 1]);
        let tail: [u8; 10] = response[response.len() - 10..].try_into().unwrap();
        let ttl = u32::from_be_bytes(tail[..4].try_into().unwrap());
        assert!((1..=30).contains(&ttl));
        assert_eq!(&tail[4..6], &[0, 4]);
        let address = std::net::Ipv4Addr::new(tail[6], tail[7], tail[8], tail[9]);
        assert_eq!(
            leases.lookup(address.into(), epoch).unwrap().name.as_str(),
            "example.test"
        );
    }
}

#[test]
fn fake_dns_startup_waits_when_journal_contains_quarantine_intent() {
    use crate::managed_network::{Journal, QuarantineIntent};

    let path = StartupJournal::new("quarantine");
    let owner = StartupJournal::owner();
    let mut journal = Journal::open(&path.0, owner).unwrap();
    journal
        .begin_fake_quarantine(
            owner,
            42,
            QuarantineIntent {
                tun: None,
                horizon_ms: 90_000,
            },
        )
        .unwrap();
    drop(journal);

    let (_, mut fake_dns) = super::super::open_startup_state(&path.0).unwrap();
    assert!(matches!(
        fake_dns.check_cold_start(),
        Err(ServiceError::Busy)
    ));
    assert!(matches!(fake_dns.leases(), Err(ServiceError::Busy)));
}

#[test]
fn fake_dns_startup_fails_closed_when_journal_is_corrupt() {
    let path = StartupJournal::new("corrupt");
    drop(crate::managed_network::Journal::open(&path.0, StartupJournal::owner()).unwrap());
    std::fs::write(path.0.join("journal.json"), b"{").unwrap();
    assert!(matches!(
        super::super::open_startup_state(&path.0),
        Err(ServiceError::Unavailable)
    ));
}

#[test]
fn dns_proxy_static_route_facts_are_exact_and_never_uid_only() {
    let facts = crate::helper::native_profile_channel::dns_transport::fake_facts(
        "192.0.2.10:40001".parse().unwrap(),
        "203.0.113.11:8443".parse().unwrap(),
        6,
        (4, 5),
    );
    let peer = "203.0.113.11".parse().unwrap();
    let source = Some("192.0.2.10".parse().unwrap());
    let check = |ip, port, protocol, source, uid, mark| {
        crate::helper::native_profile_channel::dns_route_socket_matches(
            ip, port, protocol, source, uid, mark, &facts,
        )
    };
    assert!(check(
        peer,
        8443,
        crate::TransportProtocol::Tcp,
        source,
        997,
        42
    ));
    for (ip, port, protocol, source, uid, mark) in [
        (
            "192.0.2.53".parse().unwrap(),
            8443,
            crate::TransportProtocol::Tcp,
            source,
            997,
            42,
        ),
        (peer, 53, crate::TransportProtocol::Tcp, source, 997, 42),
        (peer, 8443, crate::TransportProtocol::Udp, source, 997, 42),
        (peer, 8443, crate::TransportProtocol::Tcp, None, 997, 42),
        (
            peer,
            8443,
            crate::TransportProtocol::Tcp,
            Some("192.0.2.11".parse().unwrap()),
            997,
            42,
        ),
        (peer, 8443, crate::TransportProtocol::Tcp, source, 998, 42),
        (peer, 8443, crate::TransportProtocol::Tcp, source, 997, 0),
    ] {
        assert!(!check(ip, port, protocol, source, uid, mark));
    }
}

fn actor_fixture() -> super::super::SystemProtectionHost {
    let monitor = crate::NetworkMonitor::start().unwrap();
    super::super::SystemProtectionHost {
        operations: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        stop_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        backend: std::sync::Arc::new(std::sync::Mutex::new(super::Backend {
            profile_owner: None,
            path: "/run/yonik/unused-actor-test".into(),
            journal: None,
            private_dns_zones: Err(crate::managed_network::JournalError::Missing),
            watch: monitor.watch(),
            seed: 1,
            epoch: 1,
            native_eligibility: None,
            native_owner: super::native_owner::NativeOwnerState::fresh(),
            bindings: None,
            supervisor: None,
            worker_uncertain: false,
            active: None,
            tun_custody: None,
            registry: None,
            fake_dns: super::session_fake_dns::FakeDnsState::new(None),
            fake_dns_reap: None,
            dhcp_sleep: Default::default(),
            exited: std::sync::Arc::new(tokio::sync::Notify::new()),
            isolated: true,
        })),
        _monitor: monitor,
        runtime: tokio::runtime::Handle::current(),
        _safety: None,
        _dhcp_sleep: None,
        standalone: false,
    }
}

struct TestEvents(tokio::sync::watch::Receiver<u64>);
impl super::SafetyEvents for TestEvents {
    async fn next_event(&mut self) -> bool {
        self.0.changed().await.is_ok()
    }
}
struct CleanupOnEvent {
    active: bool,
    calls: usize,
    cleanups: usize,
    reports: tokio::sync::watch::Sender<(usize, usize)>,
}
fn cleanup_on_event(state: &mut CleanupOnEvent, _: &tokio::runtime::Handle) {
    state.calls += 1;
    if state.active {
        state.active = false;
        state.cleanups += 1;
    }
    state.reports.send_replace((state.calls, state.cleanups));
}

#[tokio::test]
async fn network_event_cleans_session_without_rpc_and_waits_for_inflight_operation() {
    let (events, receiver) = tokio::sync::watch::channel(0);
    let (reports, mut observed) = tokio::sync::watch::channel((0, 0));
    let backend = std::sync::Arc::new(std::sync::Mutex::new(CleanupOnEvent {
        active: false,
        calls: 0,
        cleanups: 0,
        reports,
    }));
    let mut safety = super::spawn_safety(
        TestEvents(receiver),
        std::sync::Arc::downgrade(&backend),
        tokio::runtime::Handle::current(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        cleanup_on_event,
    );
    observed.changed().await.unwrap(); // startup sweep
    let (locked, lock_ready) = tokio::sync::oneshot::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let shared = std::sync::Arc::clone(&backend);
    let inflight = tokio::task::spawn_blocking(move || {
        let mut inflight = shared.lock().unwrap();
        inflight.active = true;
        locked.send(()).unwrap();
        wait_release.recv().unwrap();
        assert_eq!(inflight.cleanups, 0);
    });
    lock_ready.await.unwrap();
    events.send_replace(1);
    // Событие приходит внутри Apply. Actor обязан дождаться mutex, а не
    // проигнорировать его через try_lock и ждать нового RPC State.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), observed.changed())
            .await
            .is_err()
    );
    release.send(()).unwrap();
    inflight.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), observed.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*observed.borrow(), (2, 1));
    drop(events);
    tokio::time::timeout(std::time::Duration::from_secs(1), &mut safety.0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*observed.borrow(), (3, 1)); // закрытие источника тоже проверено
}

#[tokio::test]
async fn safety_startup_sweep_recovers_prior_session_and_does_not_own_backend_cycle() {
    let (events, receiver) = tokio::sync::watch::channel(0);
    let (reports, mut observed) = tokio::sync::watch::channel((0, 0));
    let backend = std::sync::Arc::new(std::sync::Mutex::new(CleanupOnEvent {
        active: true,
        calls: 0,
        cleanups: 0,
        reports,
    }));
    let weak = std::sync::Arc::downgrade(&backend);
    let mut safety = super::spawn_safety(
        TestEvents(receiver),
        weak.clone(),
        tokio::runtime::Handle::current(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        cleanup_on_event,
    );
    observed.changed().await.unwrap();
    assert_eq!(*observed.borrow(), (1, 1));
    drop(backend);
    drop(events);
    tokio::time::timeout(std::time::Duration::from_secs(1), &mut safety.0)
        .await
        .unwrap()
        .unwrap();
    assert!(weak.upgrade().is_none());
}

fn process_status() -> Vec<u8> {
    b"Name:\ttrusted-core\nUid:\t969\t969\t969\t969\nNoNewPrivs:\t1\nCapInh:\t0000000000001000\nCapPrm:\t0000000000001000\nCapEff:\t0000000000001000\nCapBnd:\t0000000000001000\nCapAmb:\t0000000000001000\n".to_vec()
}
#[test]
fn worker_status_pins_all_uids_no_new_privileges_and_exact_capability_sets() {
    let status = process_status();
    assert!(super::verify_worker_status(&status, 969).is_ok());
    for (from, to) in [
        ("969\t969\t969\t969", "969\t1000\t969\t969"),
        ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ("CapEff:\t0000000000001000", "CapEff:\t0000000000003000"),
        ("CapAmb:\t0000000000001000", "CapAmb:\t0000000000000000"),
        ("CapPrm:\t0000000000001000", "CapPrm:\tinvalid"),
        ("CapInh:\t0000000000001000", "CapInh:\t0000000000000000"),
        ("Uid:\t969\t969\t969\t969", "Uid:\t969\t969\t969"),
        (
            "CapBnd:\t0000000000001000",
            "CapBnd:\t0000000000001000\nCapBnd:\t0000000000001000",
        ),
    ] {
        let changed = std::str::from_utf8(&status).unwrap().replace(from, to);
        assert_eq!(
            super::verify_worker_status(changed.as_bytes(), 969),
            Err(ServiceError::Unavailable)
        );
    }
    assert_eq!(
        super::verify_worker_status(&status, 1000),
        Err(ServiceError::Unavailable)
    );
    let mut oversized = status.clone();
    oversized.resize(16 * 1024 + 1, b' ');
    assert_eq!(
        super::verify_worker_status(&oversized, 969),
        Err(ServiceError::Unavailable)
    );
}

#[tokio::test]
async fn background_tasks_keep_running_after_blocking_job_returns() {
    let host = actor_fixture();
    let (_keep, cancel) = crate::Cancellation::new();
    let (completed, receiver) = tokio::sync::oneshot::channel();
    host.job(super::super::Operation::RuntimeProbe(completed), cancel)
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), receiver)
        .await
        .unwrap()
        .unwrap();
    host._monitor.shutdown().await;
}

#[tokio::test]
async fn state_reports_no_managed_policy_with_another_users_quarantine() {
    use crate::helper::service::{ProtectionHost, ProtectionState};
    use crate::managed_network::{Journal, Ownership, QuarantineIntent};

    let path = StartupJournal::new("state-quarantine-owner");
    let (dev, ino) = super::super::namespace().unwrap();
    let owner = Ownership::new(1000, 77, 1, dev, ino).unwrap();
    let mut journal = Journal::open(&path.0, owner).unwrap();
    journal
        .begin_fake_quarantine(
            owner,
            42,
            QuarantineIntent {
                tun: None,
                horizon_ms: 90_000,
            },
        )
        .unwrap();

    let mut host = actor_fixture();
    host.backend.lock().unwrap().journal = Some(journal);
    let (_keep, cancel) = crate::Cancellation::new();
    assert_eq!(
        host.state(0, cancel).await,
        Ok(ProtectionState::NoManagedPolicy)
    );
    let backend = host.backend.lock().unwrap();
    let journal = backend.journal.as_ref().unwrap();
    assert_eq!(journal.ownership(), owner);
    assert!(journal.fake_quarantine().is_some());
}

#[tokio::test]
async fn dropping_caller_does_not_release_backend_before_effect_finishes() {
    let host = std::sync::Arc::new(actor_fixture());
    let (_keep, cancel) = crate::Cancellation::new();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (resume, resume_wait) = tokio::sync::oneshot::channel();
    let (finished, completed) = tokio::sync::oneshot::channel();
    let shared = std::sync::Arc::clone(&host);
    let caller = tokio::spawn(async move {
        shared
            .job(
                super::super::Operation::RetentionProbe {
                    entered,
                    resume: resume_wait,
                    finished,
                },
                cancel,
            )
            .await
    });
    started.await.unwrap();
    caller.abort();
    assert!(matches!(
        host.backend.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    resume.send(()).unwrap();
    completed.await.unwrap();
    // blocking job ещё может завершать Reply, но обе стороны больше не держат
    // зависимых эффектов; runtime остаётся живым до выхода из теста.
}

#[test]
fn worker_uid_is_dedicated_and_unambiguous() {
    assert_eq!(
        parse_worker_uid(
            b"root:x:0:0::/:/bin/sh\nyonik-worker:x:969:969::/nonexistent:/usr/bin/nologin\n"
        ),
        Ok(969)
    );
    for bytes in [
        b"yonik-worker:x:0:0::/:/bin/sh\n".as_slice(),
        b"yonik-worker:x:969:969::/:/bin/sh\nyonik-worker:x:970:970::/:/bin/sh\n",
        b"yonik-worker:x:969\n",
        b"root:x:0:0::/:/bin/sh\n",
    ] {
        assert_eq!(parse_worker_uid(bytes), Err(ServiceError::Unavailable));
    }
}

#[test]
fn hostname_and_unbound_transport_are_denied_before_effects() {
    for value in [
        "vless://11111111-1111-1111-1111-111111111111@192.0.2.5:443",
        "vless://11111111-1111-1111-1111-111111111111@example.org:443",
        "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443",
    ] {
        let mut report = yonik_import::import_bytes(value.as_bytes().to_vec()).unwrap();
        let server = report.servers.remove(0);
        if value.contains("192.0.2.5") {
            assert_eq!(
                endpoint(&server),
                Ok(("192.0.2.5".parse().unwrap(), crate::TransportProtocol::Tcp))
            );
        } else {
            assert_eq!(endpoint(&server), Err(ServiceError::Unsupported));
        }
    }
}

#[tokio::test]
async fn actual_backend_rejects_hostname_without_opening_journal_registry_or_worker() {
    let monitor = crate::NetworkMonitor::start().unwrap();
    let mut backend = super::Backend {
        profile_owner: None,
        path: "/run/yonik/unused-denied-session-test".into(),
        journal: None,
        private_dns_zones: Err(crate::managed_network::JournalError::Missing),
        watch: monitor.watch(),
        seed: 1,
        epoch: 1,
        native_eligibility: None,
        native_owner: super::native_owner::NativeOwnerState::fresh(),
        bindings: None,
        supervisor: None,
        worker_uncertain: false,
        active: None,
        tun_custody: None,
        registry: None,
        fake_dns: super::session_fake_dns::FakeDnsState::new(None),
        fake_dns_reap: None,
        dhcp_sleep: Default::default(),
        exited: std::sync::Arc::new(tokio::sync::Notify::new()),
        isolated: true,
    };
    let report = yonik_import::import_bytes(
        b"vless://11111111-1111-1111-1111-111111111111@example.org:443".to_vec(),
    )
    .unwrap();
    let request = crate::helper::service::SystemProfileRequest {
        policy: None,
        fake_dns_domains: None,
        fake_dns_policy_resolver: None,
        peer: None,
        server: yonik_import::ServerIntent::from_server(&report.servers[0]).unwrap(),
        engine: yonik_engine::Engine::Xray,
        kill_switch: false,
    };
    let (_keep, mut cancel) = crate::Cancellation::new();
    assert_eq!(
        backend
            .prepare_profile(1000, request, &mut cancel)
            .await
            .err(),
        Some(ServiceError::Unsupported)
    );
    assert!(backend.journal.is_none());
    assert!(backend.supervisor.is_none());
    assert!(backend.registry.is_none());
    assert!(!backend.worker_uncertain);
    monitor.shutdown().await;
}

#[test]
fn supported_tcp_underlays_share_endpoint_but_unbound_udp_is_rejected() {
    for transport in ["tcp", "ws", "grpc", "xhttp"] {
        let value =
            format!("vless://11111111-1111-1111-1111-111111111111@192.0.2.5:443?type={transport}");
        let report = yonik_import::import_bytes(value.into_bytes()).unwrap();
        assert!(endpoint(&report.servers[0]).is_ok());
    }
    let report = yonik_import::import_bytes(b"socks5://192.0.2.5:1080".to_vec()).unwrap();
    assert_eq!(endpoint(&report.servers[0]), Err(ServiceError::Unsupported));
}

#[test]
fn link_binding_keeps_devconf_token_and_gso_exact() {
    let mut expected = super::super::tests::link(16, Some(b"tun"), false);
    expected.unknown.push(crate::NetworkAttribute {
        kind: 23,
        value: vec![0; 200],
    });
    let mut actual = expected.clone();
    actual.flags |= 0x10000 | 0x40;
    actual.operational_state = Some(0);
    assert!(same_link_contract(&expected, &actual));
    for kind in [26, 40, 41, 63, 64] {
        let mut changed = actual.clone();
        changed.unknown.push(crate::NetworkAttribute {
            kind,
            value: vec![1, 2, 3, 4],
        });
        assert!(!same_link_contract(&expected, &changed));
    }
    actual.unknown[0].value.fill(99);
    assert!(same_link_contract(&expected, &actual));
}

#[test]
fn link_binding_ignores_only_dynamic_ipv6_fields_and_pins_nested_conf_and_token() {
    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u16::try_from(value.len() + 4).unwrap().to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }
    fn af(conf: u8, token: u8, stats: u8) -> Vec<u8> {
        let mut fields = attr(2, &[conf; 4]);
        fields.extend(attr(7, &[token; 16]));
        fields.extend(attr(3, &[1u64.to_ne_bytes(), [stats; 8]].concat()));
        attr(10, &fields)
    }
    let mut expected = super::super::tests::link(16, Some(b"tun"), false);
    expected.unknown.push(crate::NetworkAttribute {
        kind: 26,
        value: af(1, 2, 3),
    });
    let mut actual = expected.clone();
    actual.unknown[0].value = af(1, 2, 4);
    assert!(same_link_contract(&expected, &actual));
    actual.unknown[0].value = af(9, 2, 4);
    assert!(!same_link_contract(&expected, &actual));
    actual.unknown[0].value = af(1, 9, 4);
    assert!(!same_link_contract(&expected, &actual));
}

#[derive(Default)]
struct FakeRecovery {
    events: Vec<&'static str>,
    unknown_worker: bool,
    cancelled_network: bool,
    failed_unlock: bool,
}
impl RecoveryHost for FakeRecovery {
    async fn stop_worker(&mut self) -> Result<(), ServiceError> {
        self.events
            .push("activation-off/services-off/cgroups-empty");
        if self.unknown_worker {
            Err(ServiceError::Unavailable)
        } else {
            Ok(())
        }
    }
    async fn restrict(&mut self) -> Result<(), ServiceError> {
        self.events.push("public-block-without-exceptions");
        Ok(())
    }
    async fn cleanup_network(&mut self) -> Result<(), ServiceError> {
        self.events.push("rules/routes/addresses/tun");
        if self.cancelled_network {
            Err(ServiceError::Cancelled)
        } else {
            Ok(())
        }
    }
    async fn unlock(&mut self) -> Result<(), ServiceError> {
        self.events.push("unlock-public-block");
        if self.failed_unlock {
            Err(ServiceError::Unavailable)
        } else {
            Ok(())
        }
    }
    async fn clear_intent(&mut self) -> Result<(), ServiceError> {
        self.events.push("clear-durable-disposition");
        Ok(())
    }
}

#[tokio::test]
async fn kill_switch_false_unlocks_only_after_worker_and_network_cleanup() {
    let mut host = FakeRecovery::default();
    assert!(recover_ordered(&mut host, true, false).await.is_ok());
    assert_eq!(
        host.events,
        [
            "activation-off/services-off/cgroups-empty",
            "public-block-without-exceptions",
            "rules/routes/addresses/tun",
            "unlock-public-block",
            "clear-durable-disposition"
        ]
    );
    // Тот же recovery protocol применяется при повторном Stop; stale ticket
    // завершённой invocation не участвует в авторизации cleanup.
    host.events.clear();
    assert!(recover_ordered(&mut host, true, false).await.is_ok());
    assert_eq!(host.events.last(), Some(&"clear-durable-disposition"));
}

#[tokio::test]
async fn kill_switch_true_keeps_restrictive_policy_and_unknown_worker_blocks_cleanup() {
    let mut host = FakeRecovery::default();
    assert!(recover_ordered(&mut host, true, true).await.is_ok());
    assert!(!host.events.contains(&"unlock-public-block"));
    assert_eq!(host.events.last(), Some(&"clear-durable-disposition"));
    host.events.clear();
    host.unknown_worker = true;
    assert!(matches!(
        recover_ordered(&mut host, true, false).await,
        Err(RecoveryFailure::WorkerUnknown)
    ));
    assert_eq!(host.events, ["activation-off/services-off/cgroups-empty"]);
}

#[tokio::test]
async fn partial_cleanup_cancellation_and_unlock_failure_retain_disposition() {
    let mut host = FakeRecovery {
        cancelled_network: true,
        ..FakeRecovery::default()
    };
    assert!(matches!(
        recover_ordered(&mut host, true, false).await,
        Err(RecoveryFailure::Network(ServiceError::Cancelled))
    ));
    assert!(!host.events.contains(&"unlock-public-block"));
    assert!(!host.events.contains(&"clear-durable-disposition"));
    host.events.clear();
    host.cancelled_network = false;
    host.failed_unlock = true;
    assert!(matches!(
        recover_ordered(&mut host, true, false).await,
        Err(RecoveryFailure::Network(ServiceError::Unavailable))
    ));
    assert!(!host.events.contains(&"clear-durable-disposition"));
}

#[test]
fn durable_choice_survives_restart_and_missing_legacy_choice_is_restrictive() {
    assert!(keep_after_stop(false, Some(true)));
    assert!(!keep_after_stop(false, Some(false)));
    assert!(keep_after_stop(false, None));
    assert!(!keep_after_stop(true, Some(true)));
}

#[tokio::test]
async fn pidfd_exit_wakes_safety_without_network_event_or_rpc() {
    let (network, receiver) = tokio::sync::watch::channel(0);
    let signal = std::sync::Arc::new(tokio::sync::Notify::new());
    let (reports, mut observed) = tokio::sync::watch::channel((0, 0));
    let backend = std::sync::Arc::new(std::sync::Mutex::new(CleanupOnEvent {
        active: false,
        calls: 0,
        cleanups: 0,
        reports,
    }));
    let _safety = super::spawn_safety(
        super::SessionEvents::new(TestEvents(receiver), signal.clone()),
        std::sync::Arc::downgrade(&backend),
        tokio::runtime::Handle::current(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        cleanup_on_event,
    );
    observed.changed().await.unwrap();
    backend.lock().unwrap().active = true;
    let mut child = tokio::process::Command::new("/usr/bin/sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let _watch = super::watch_worker_exit(child.id().unwrap(), signal).unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), observed.changed())
            .await
            .is_err()
    );
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), observed.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*observed.borrow(), (2, 1));
    assert_eq!(*network.borrow(), 0);
}

#[tokio::test]
#[ignore = "Диагностическая регрессия: только отдельные namespaces через safe runner"]
async fn real_namespace_persistent_tun_queue_contract() {
    use crate::managed_network::{Journal, Ownership, tun::TunExecutor};
    use std::os::unix::fs::MetadataExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let ns = std::fs::metadata("/proc/thread-self/ns/net").unwrap();
    let owner = Ownership::new(
        rustix::process::getuid().as_raw(),
        77,
        99,
        ns.dev(),
        ns.ino(),
    )
    .unwrap();
    // До эффектов fixture требует отличный от host namespace и явный marker.
    let mut executor = TunExecutor::isolated_fixture(owner).unwrap();
    let (_keep, mut cancel) = crate::Cancellation::new();
    let baseline = crate::read_topology(&mut cancel, super::DEADLINE)
        .await
        .unwrap();
    let sing_box = std::env::var_os("YONIK_TUN_ATTACH_ENGINE").as_deref()
        == Some(std::ffi::OsStr::new("sing-box"));
    let engine = if sing_box {
        yonik_engine::Engine::SingBox
    } else {
        yonik_engine::Engine::Xray
    };
    let plan =
        crate::helper::SessionNetworkPlan::reserve_for_engine(owner, &baseline, engine).unwrap();
    let mut journal =
        Journal::open(std::path::Path::new("/tmp/yonik-attach-diagnostic"), owner).unwrap();
    let index = plan.configure(&mut executor, &mut journal).await.unwrap();
    plan.capture(&mut executor, &mut journal, index)
        .await
        .unwrap();
    // Отдельный causal control только в уже проверенном собственном namespace.
    // Production configure и fencing этим экспериментом не меняются.
    if std::env::var_os("YONIK_TUN_DIAGNOSTIC_ADDRGEN_NONE").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        let current = crate::read_topology(&mut cancel, super::DEADLINE)
            .await
            .unwrap();
        let link = current
            .links
            .iter()
            .find(|link| link.index == index)
            .unwrap();
        assert!(
            tokio::process::Command::new("/usr/bin/ip")
                .args([
                    "link",
                    "set",
                    "dev",
                    std::str::from_utf8(&link.name).unwrap(),
                    "addrgenmode",
                    "none"
                ])
                .status()
                .await
                .unwrap()
                .success()
        );
    }
    let before = crate::read_topology(&mut cancel, super::DEADLINE)
        .await
        .unwrap();
    let before = before.links.into_iter().find(|l| l.index == index).unwrap();
    let script = "import sys,fcntl,struct\nf=open('/dev/net/tun','r+b',buffering=0)\nfcntl.ioctl(f,0x400454ca,struct.pack('16sH',sys.argv[1].encode(),int(sys.argv[2]))+bytes(22))\nif int(sys.argv[2]) & 0x4000:\n h=bytearray(4)\n fcntl.ioctl(f,0x800454d7,h,True)\n assert struct.unpack('I',h)[0]==10\nprint('READY',flush=True)\nsys.stdin.buffer.read(1)\n";
    let mut child = tokio::process::Command::new("/usr/bin/python3")
        .args([
            "-c",
            script,
            std::str::from_utf8(&before.name).unwrap(),
            if sing_box { "4097" } else { "20481" },
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut output = tokio::io::BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        output.read_line(&mut ready),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(ready, "READY\n");
    let after = crate::read_topology(&mut cancel, super::DEADLINE)
        .await
        .unwrap();
    plan.verify_external(&baseline, after.clone(), &journal, index)
        .unwrap();
    for alteration in 0..3 {
        let mut foreign = after.clone();
        let link = foreign.links.iter_mut().find(|l| l.index == index).unwrap();
        match alteration {
            0 => link.unknown.push(crate::NetworkAttribute {
                kind: 9999,
                value: vec![1],
            }),
            1 => link.alias = Some(b"foreign".to_vec()),
            _ => link.index += 100,
        }
        assert!(
            plan.verify_external(&baseline, foreign, &journal, index)
                .is_err()
        );
    }
    let after = after.links.into_iter().find(|l| l.index == index).unwrap();
    super::diagnostic_link("raw", &before, &after);
    let same = same_link_contract(&before, &after);
    child.stdin.take().unwrap().write_all(b"x").await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    plan.cleanup_after_worker(&mut executor, &mut journal, index)
        .await
        .unwrap();
    // Оба framing режима заранее установлены; неизвестные поля не маскируются.
    assert!(
        same,
        "Контракт persistent TUN изменился при открытии очереди"
    );
}

#[test]
fn link_binding_pins_vnet_header_for_both_engine_modes() {
    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u16::try_from(value.len() + 4).unwrap().to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }
    for expected in [0, 1] {
        let mut before = super::super::tests::link(16, Some(b"tun"), false);
        before.unknown.push(crate::NetworkAttribute {
            kind: 18,
            value: attr(2, &attr(5, &[expected])),
        });
        let mut after = before.clone();
        assert!(same_link_contract(&before, &after));
        after.unknown[0].value = attr(2, &attr(5, &[1 - expected]));
        assert!(!same_link_contract(&before, &after));
    }
}

#[tokio::test]
async fn authorized_stop_waits_for_exact_backend_guard_used_by_safety() {
    type Hold = (
        tokio::sync::oneshot::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    );
    static HOLD: std::sync::Mutex<Option<Hold>> = std::sync::Mutex::new(None);
    fn held_sweep(_: &mut super::Backend, _: &tokio::runtime::Handle) {
        if let Some((entered, release)) = HOLD.lock().unwrap().take() {
            entered.send(()).unwrap();
            release.recv().unwrap();
        }
    }
    let host = actor_fixture();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    *HOLD.lock().unwrap() = Some((entered, wait));
    let (events, receiver) = tokio::sync::watch::channel(0);
    let mut sweep = super::spawn_safety(
        TestEvents(receiver),
        std::sync::Arc::downgrade(&host.backend),
        tokio::runtime::Handle::current(),
        std::sync::Arc::clone(&host.operations),
        held_sweep,
    );
    ready.await.unwrap();
    let (_keep, cancel) = crate::Cancellation::new();
    let stop = host.job(super::super::Operation::Stop(1000), cancel);
    tokio::pin!(stop);
    let early = tokio::time::timeout(std::time::Duration::from_millis(25), &mut stop).await;
    release.send(()).unwrap();
    assert!(
        early.is_err(),
        "Stop отклонён до освобождения настоящего safety/backend guard"
    );
    assert!(matches!(
        stop.await.unwrap(),
        super::super::Reply::State(crate::helper::ProtectionState::NoManagedPolicy)
    ));
    assert_eq!(host.backend.lock().unwrap().epoch, 2);
    drop(events);
    tokio::time::timeout(std::time::Duration::from_secs(2), &mut sweep.0)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn prepared_context_waits_for_the_safety_operation() {
    use crate::helper::ProtectionHost;

    let host = actor_fixture();
    let safety = std::sync::Arc::clone(&host.operations)
        .acquire_owned()
        .await
        .unwrap();
    let (_keep, cancel) = crate::Cancellation::new();
    let context = host.context_for_apply(1000, cancel);
    tokio::pin!(context);
    assert!(futures_util::poll!(context.as_mut()).is_pending());
    drop(safety);
    // Начальная топология тестового хоста может ещё не иметь покрытия маршрутов.
    assert!(matches!(
        context.await,
        Ok(_) | Err(ServiceError::Unavailable)
    ));
}

#[tokio::test]
async fn dropped_authorized_stop_caller_keeps_bounded_slot_until_cleanup_ack() {
    let host = actor_fixture();
    let sweep = std::sync::Arc::clone(&host.operations)
        .acquire_owned()
        .await
        .unwrap();
    let (_keep, cancel) = crate::Cancellation::new();
    let mut stop = Box::pin(host.job(super::super::Operation::Stop(1000), cancel));
    assert!(futures_util::poll!(stop.as_mut()).is_pending());
    assert_eq!(host.stop_admission.available_permits(), 0);
    drop(stop); // Уже допущенный Stop остаётся владельцем отдельной задачи.
    let (_keep2, cancel2) = crate::Cancellation::new();
    assert!(matches!(
        host.job(super::super::Operation::Stop(1000), cancel2).await,
        Err(ServiceError::Busy)
    ));
    let waiter = std::sync::Arc::clone(&host.stop_admission).acquire_owned();
    tokio::pin!(waiter);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), &mut waiter)
            .await
            .is_err()
    );
    assert_eq!(host.backend.lock().unwrap().epoch, 1);
    drop(sweep);
    let _ack = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(host.backend.lock().unwrap().epoch, 2);
}
#[tokio::test]
async fn stop_wait_preserves_timeout_cancellation_and_no_effect_before_admission() {
    let operations = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let (_keep, mut cancel) = crate::Cancellation::new();
    let timeout = super::super::wait_for_stop(
        operations.clone(),
        &mut cancel,
        std::time::Duration::from_millis(1),
    )
    .await
    .expect_err("permit удерживается");
    assert_eq!(timeout.to_string(), "timeout");
    assert!(matches!(
        super::super::wait_for_stop(
            operations.clone(),
            &mut cancel,
            std::time::Duration::from_millis(1)
        )
        .await,
        Err(ServiceError::Prepared(
            crate::helper::PreparedError::Timeout
        ))
    ));
    let (signal, mut cancel) = crate::Cancellation::new();
    signal.send_replace(true);
    assert!(matches!(
        super::super::wait_for_stop(operations, &mut cancel, std::time::Duration::from_secs(1))
            .await,
        Err(ServiceError::Cancelled)
    ));
    let host = actor_fixture();
    assert!(matches!(
        host.job(super::super::Operation::Stop(1000), cancel).await,
        Err(ServiceError::Cancelled)
    ));
    assert_eq!(host.backend.lock().unwrap().epoch, 1);
    assert_eq!(host.stop_admission.available_permits(), 1);
}

#[tokio::test]
async fn app_policy_denied_before_backend_resources() {
    let host = actor_fixture();
    let mut backend = std::sync::Arc::try_unwrap(host.backend)
        .ok()
        .unwrap()
        .into_inner()
        .ok()
        .unwrap();
    let report = yonik_import::import_bytes(
        b"vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443".to_vec(),
    )
    .unwrap();
    let policy = yonik_engine::policy_wire::SystemPolicy::parse(r#"{"version":1,"default_action":"proxy","user_rules":[{"id":1,"enabled":true,"action":"block","domain":[],"domain_suffix":[],"ip_cidr":[],"executable_paths":["/usr/bin/client"]}],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}"#).unwrap();
    let request = crate::helper::service::SystemProfileRequest {
        server: yonik_import::ServerIntent::from_server(&report.servers[0]).unwrap(),
        engine: yonik_engine::Engine::Xray,
        kill_switch: false,
        policy: Some(policy),
        fake_dns_domains: None,
        fake_dns_policy_resolver: None,
        peer: None,
    };
    let (_keep, mut cancel) = crate::Cancellation::new();
    assert_eq!(
        backend
            .prepare_profile(1000, request, &mut cancel)
            .await
            .err(),
        Some(ServiceError::Unsupported)
    );
    assert!(backend.journal.is_none());
    assert!(backend.registry.is_none());
    assert!(backend.supervisor.is_none());
    assert!(!backend.worker_uncertain);
    assert!(backend.active.is_none());
}

#[tokio::test]
#[ignore = "Только отдельный user/net namespace с YONIK_NFT_TEST_HOST_NETNS"]
async fn real_backend_custody_unknown_stop_revoke_and_cleanup() {
    use crate::managed_network::{Journal, Ownership, tun::TunExecutor};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let ns = std::fs::metadata("/proc/thread-self/ns/net").unwrap();
    let owner = Ownership::new(
        rustix::process::getuid().as_raw(),
        77,
        99,
        ns.dev(),
        ns.ino(),
    )
    .unwrap();
    let mut executor = TunExecutor::isolated_fixture(owner).unwrap();
    let (_keep, mut cancel) = crate::Cancellation::new();
    let (baseline, baseline_capture) =
        crate::network::read_topology_captured(&mut cancel, super::DEADLINE)
            .await
            .unwrap();
    let plan = crate::helper::SessionNetworkPlan::reserve_for_engine(
        owner,
        &baseline,
        yonik_engine::Engine::SingBox,
    )
    .unwrap();
    let path = std::env::temp_dir().join(format!("yonik-backend-custody-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = Journal::open(&path, owner).unwrap();
    let index = plan.configure(&mut executor, &mut journal).await.unwrap();
    plan.capture(&mut executor, &mut journal, index)
        .await
        .unwrap();
    let super::super::SystemProtectionHost {
        backend, _monitor, ..
    } = actor_fixture();
    let mut backend = match std::sync::Arc::try_unwrap(backend) {
        Ok(mutex) => mutex.into_inner().unwrap(),
        Err(_) => panic!("Fixture не должен разделять Backend"),
    };
    backend.journal = Some(journal);
    backend
        .retain_canonical_queue(&plan, &executor, &mut cancel)
        .await
        .unwrap();
    let plan = super::native_owner::check_actual_boundaries_with_synthetic_inputs(
        &mut backend,
        index,
        &mut cancel,
        plan,
        baseline,
        baseline_capture,
    )
    .await;
    assert!(backend.active.is_none());
    assert!(backend.has_session());
    #[cfg(feature = "test-support")]
    let queue_fd = std::os::fd::AsRawFd::as_raw_fd(
        &backend
            .tun_custody
            .as_ref()
            .unwrap()
            .bound
            .queue_fd_for_test(),
    );
    backend.worker_uncertain = true;
    let mut recovery = super::BackendRecovery {
        backend: &mut backend,
        owner,
    };
    assert!(matches!(
        recovery.cleanup_network().await,
        Err(ServiceError::Busy)
    ));
    assert!(recovery.backend.tun_custody.is_some());
    // Systemd stop здесь не запускается. Проверяется реальный revoke endpoint,
    // который production вызывает только после подтверждения supervisor.recover.
    recovery.backend.worker_uncertain = false;
    recovery.backend.release_stopped_resources();
    assert!(recovery.backend.tun_custody.is_none());
    #[cfg(feature = "test-support")]
    assert!(!std::path::Path::new(&format!("/proc/self/fd/{queue_fd}")).exists());
    // В userns host-root /usr не отображён как uid0: production open правильно
    // отказывает. Cleanup проверяется реальным существующим isolated executor.
    plan.cleanup_after_worker(
        &mut executor,
        recovery.backend.journal.as_mut().unwrap(),
        index,
    )
    .await
    .unwrap();
    assert!(
        recovery
            .backend
            .journal
            .as_ref()
            .unwrap()
            .records()
            .iter()
            .all(|r| r.scope() != crate::managed_network::Scope::Session)
    );
    backend.journal = None;
    drop(backend);
    std::fs::remove_file(path.join("journal.json")).unwrap();
    std::fs::remove_dir(path).unwrap();
}

#[tokio::test]
async fn native_epoch_overflow_permanently_closes_reservation() {
    let host = actor_fixture();
    let mut backend = host.backend.lock().unwrap();
    assert!(backend.native_owner.reserve().is_ok());
    backend.epoch = u64::MAX;
    assert!(backend.invalidate().is_err());
    assert!(backend.native_owner.reserve().is_err());
    assert!(backend.invalidate().is_err());
    assert!(backend.native_owner.reserve().is_err());
}
