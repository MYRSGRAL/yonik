//! Production helper на системной шине собственной одноразовой VM.
//! Это отдельный gate: private bus и подмена authorizer здесь запрещены.
#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::{fs, io, os::unix::fs::MetadataExt, process::Command, time::Duration};
const SERVICE_NAME: &str = "cloud.highpriority.yonik.Network1";
const SERVICE_INTERFACE: &str = SERVICE_NAME;
const SERVICE_PATH: &str = "/cloud/highpriority/yonik/Network";

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn require(value: bool, reason: &str) -> Result {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(reason).into())
    }
}

fn guard() -> Result {
    require(
        std::env::var("YONIK_PRODUCTION_HELPER_VM").as_deref() == Ok("1"),
        "Нет явного VM opt-in",
    )?;
    require(
        fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim() == "QEMU",
        "Требуется QEMU",
    )?;
    require(
        fs::read_to_string("/proc/1/comm")?.trim() == "systemd",
        "Требуется systemd PID 1",
    )?;
    let marker = fs::symlink_metadata("/etc/yonik-production-helper-vm")?;
    require(
        marker.is_file() && marker.uid() == 0 && marker.mode() & 0o022 == 0,
        "Небезопасный VM marker",
    )?;
    require(
        fs::read_to_string("/etc/yonik-production-helper-vm")?
            == "yonik-production-helper-disposable-v1\n",
        "Неверный VM marker",
    )?;
    require(
        std::env::var_os("DBUS_SYSTEM_BUS_ADDRESS").is_none(),
        "Подмена system bus запрещена",
    )?;
    Ok(())
}

fn helper_pid() -> Result<u32> {
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "--property=MainPID",
            "--value",
            "yonik-helper.service",
        ])
        .output()?;
    require(output.status.success(), "Не прочитан MainPID")?;
    let pid: u32 = std::str::from_utf8(&output.stdout)?.trim().parse()?;
    require(pid > 1, "Helper не запущен")?;
    require(
        fs::read_link(format!("/proc/{pid}/exe"))?
            == std::path::Path::new("/usr/lib/yonik/yonik-helper"),
        "Запущен fixture вместо production helper",
    )?;
    Ok(pid)
}

async fn call(connection: &zbus::Connection, method: &str, value: Value) -> Result<Value> {
    let request = value.to_string();
    let response = tokio::time::timeout(
        Duration::from_secs(40),
        connection.call_method(
            Some(SERVICE_NAME),
            SERVICE_PATH,
            Some(SERVICE_INTERFACE),
            method,
            &(request,),
        ),
    )
    .await??;
    let (body,): (String,) = response.body().deserialize()?;
    let value: Value = serde_json::from_str(&body)?;
    require(value["version"] == 1, "Неверная версия ответа")?;
    eprintln!("RPC {method}: state={}", value["state"]);
    Ok(value)
}

#[tokio::test]
#[ignore = "Только выделенный непривилегированный UID внутри disposable VM"]
async fn production_helper_denies_unprivileged_uid() -> Result {
    guard()?;
    require(
        !rustix::process::geteuid().is_root(),
        "Отрицательный тест требует отдельный UID",
    )?;
    let connection = zbus::Connection::system().await?;
    for method in ["Prepare", "Stop", "Unlock"] {
        let request = if method == "Prepare" {
            json!({"version":1,"mode":"public_protection","allow_lan":false})
        } else {
            json!({"version":1})
        };
        let result = call(&connection, method, request).await;
        let error = result.expect_err("Неавторизованный UID получил доступ");
        // Отказ transport/timeout не является доказательством авторизации.
        require(
            error.to_string().contains("authorization"),
            "Ожидался именно отказ polkit",
        )?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Выделенный авторизованный UID только в production helper VM"]
async fn production_helper_authorized_uid_lifecycle() -> Result {
    guard()?;
    require(
        !rustix::process::geteuid().is_root(),
        "Нужен выделенный UID",
    )?;
    let connection = zbus::Connection::system().await?;
    let empty = json!({"version":1});
    let prepared = call(
        &connection,
        "Prepare",
        json!({"version":1,"mode":"public_protection","allow_lan":false}),
    )
    .await?;
    require(
        call(
            &connection,
            "Apply",
            json!({"version":1,"handle":prepared["handle"]}),
        )
        .await?["state"]
            == "verified_rules",
        "Apply UID",
    )?;
    require(
        call(&connection, "State", empty.clone()).await?["state"] == "verified_rules",
        "State UID",
    )?;
    require(
        call(&connection, "Stop", empty.clone()).await?["state"] == "verified_rules",
        "Stop UID",
    )?;
    require(
        call(&connection, "Unlock", empty).await?["state"] == "no_managed_policy",
        "Unlock UID",
    )?;
    Ok(())
}

#[tokio::test]
#[ignore = "Root controller только в собственной disposable VM, настоящий установленный helper"]
async fn production_helper_public_policy_survives_sigkill() -> Result {
    lifecycle(false).await
}

#[tokio::test]
#[ignore = "Только production helper VM с синтетическим peer и trusted registry"]
async fn production_helper_system_profile_survives_sigkill() -> Result {
    lifecycle(true).await
}

async fn wait_for_fixture_link() -> Result {
    const DEADLINE: Duration = Duration::from_secs(5);
    const IFA_F_DADFAILED: u32 = 0x08;
    const IFA_F_TENTATIVE: u32 = 0x40;
    const LOCAL_TABLE: u32 = 255;

    let (_sender, mut cancel) = yonik_linux::Cancellation::new();
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        require(!remaining.is_zero(), "IPv6 DAD стенда не завершился")?;
        let topology = yonik_linux::read_topology(&mut cancel, remaining).await?;
        let ready = topology
            .links
            .iter()
            .find(|link| link.name == b"yonik-outer")
            .is_some_and(|link| {
                topology.addresses.iter().any(|address| {
                    address.index == link.index
                        && matches!(address.address, std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
                        && address.flags & (IFA_F_DADFAILED | IFA_F_TENTATIVE) == 0
                        && topology.routes.iter().any(|route| {
                            route.table == LOCAL_TABLE
                                && route.output_interface == Some(link.index)
                                && route.destination.length == 128
                                && route.destination.address == address.address
                        })
                })
            });
        if ready {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50).min(remaining)).await;
    }
}

async fn lifecycle(profile: bool) -> Result {
    guard()?;
    require(
        rustix::process::geteuid().is_root(),
        "Требуется VM root controller",
    )?;
    let _lock = vm_lock::acquire()?;
    if profile {
        // Первое завершение DAD меняет адрес и маршрут между снимками Prepare.
        wait_for_fixture_link().await?;
    }
    let connection = zbus::Connection::system().await?;
    let empty = json!({"version":1});
    require(
        call(&connection, "State", empty.clone()).await?["state"] == "no_managed_policy",
        "VM не чистая",
    )?;
    let original_pid = helper_pid()?;
    let prepare = if profile {
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )?;
        json!({"version":1,"mode":"system_profile","engine":"xray","kill_switch":true,"server":yonik_import::ServerIntent::from_server(&imported.servers[0])?})
    } else {
        json!({"version":1,"mode":"public_protection","allow_lan":false})
    };
    let prepared = call(&connection, "Prepare", prepare).await?;
    require(
        prepared["handle"].as_array().is_some_and(|v| v.len() == 32),
        "Неверный handle",
    )?;
    require(
        call(
            &connection,
            "Apply",
            json!({"version":1,"handle":prepared["handle"]}),
        )
        .await?["state"]
            == if profile {
                "tunnel_starting"
            } else {
                "verified_rules"
            },
        "Apply не подтвердил policy",
    )?;
    if !profile {
        require(
            call(&connection, "Stop", empty.clone()).await?["state"] == "verified_rules",
            "Stop снял защиту",
        )?;
    }
    if profile {
        require(
            !fs::read_to_string("/sys/fs/cgroup/system.slice/yonik-worker.service/cgroup.procs")?
                .trim()
                .is_empty(),
            "Worker не работает перед SIGKILL",
        )?;
    }
    require(
        Command::new("/usr/bin/systemctl")
            .args([
                "kill",
                "--kill-whom=main",
                "--signal=SIGKILL",
                "yonik-helper.service",
            ])
            .status()?
            .success(),
        "SIGKILL не выполнен",
    )?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if helper_pid().is_ok_and(|pid| pid != original_pid) {
            if let Ok(state) = call(&connection, "State", empty.clone()).await {
                require(
                    state["state"] == "recovery_required",
                    "Журнал не восстановлен",
                )?;
                break;
            }
        }
        require(
            tokio::time::Instant::now() < deadline,
            "Helper не восстановился",
        )?;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    require(
        call(&connection, "Stop", empty.clone()).await?["state"] == "recovery_required",
        "Stop после recovery",
    )?;
    if profile {
        for group in ["yonik-worker", "yonik-worker-check"] {
            let path = format!("/sys/fs/cgroup/system.slice/{group}.service/cgroup.procs");
            match fs::read_to_string(path) {
                Ok(procs) => require(procs.trim().is_empty(), "Worker остался после recovery")?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    require(
        call(&connection, "Unlock", empty.clone()).await?["state"] == "no_managed_policy",
        "Unlock не очистил policy",
    )?;
    require(
        call(&connection, "State", empty).await?["state"] == "no_managed_policy",
        "Остались ресурсы",
    )?;
    Ok(())
}

#[path = "common/vm_lock.rs"]
mod vm_lock;

#[test]
fn host_without_opt_in_is_rejected() {
    if std::env::var_os("YONIK_PRODUCTION_HELPER_VM").is_none() {
        assert!(guard().is_err());
    }
}

#[tokio::test]
#[ignore = "Только собственная production VM; app case запускает отдельный разрешённый UID"]
async fn production_helper_policy_admission() -> Result {
    guard()?;
    let app = std::env::var("YONIK_POLICY_APP").as_deref() == Ok("1");
    require(
        app != rustix::process::geteuid().is_root(),
        "Неверный UID для VM case",
    )?;
    let _lock = if app { None } else { Some(vm_lock::acquire()?) };
    let connection = zbus::Connection::system().await?;
    let empty = json!({"version":1});
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let selected = std::env::var("YONIK_POLICY_ENGINE").ok();
    require(
        selected
            .as_deref()
            .is_none_or(|engine| matches!(engine, "xray" | "sing-box")),
        "Неизвестное ядро fixture",
    )?;
    for engine in ["xray", "sing-box"] {
        if selected
            .as_deref()
            .is_some_and(|selected| selected != engine)
        {
            continue;
        }

        require(
            call(&connection, "State", empty.clone()).await?["state"] == "no_managed_policy",
            "Нечистый исходный State",
        )?;
        let rules = if app {
            json!([{"id":1,"enabled":true,"action":"block","domain":[],"domain_suffix":[],"ip_cidr":[],"executable_paths":["/usr/bin/python3"]}])
        } else {
            json!([])
        };
        let request = json!({"version":1,"mode":"system_profile_policy","engine":engine,"kill_switch":false,
            "server":yonik_import::ServerIntent::from_server(&imported.servers[0])?,
            "policy":{"version":1,"default_action":"proxy","user_rules":rules,"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}});
        let result = call(&connection, "Prepare", request).await;
        if app {
            let error = result
                .err()
                .ok_or_else(|| io::Error::other("App policy была допущена"))?;
            require(
                error.to_string().to_lowercase().contains("unsupported"),
                "Требуется Unsupported, не auth/timeout",
            )?;
            for name in ["yonik-worker", "yonik-worker-check"] {
                let path = format!("/sys/fs/cgroup/system.slice/{name}.service/cgroup.procs");
                match fs::read_to_string(path) {
                    Ok(value) => require(value.trim().is_empty(), "App denial запустил worker")?,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        } else {
            let prepared = result?;
            require(
                call(
                    &connection,
                    "Apply",
                    json!({"version":1,"handle":prepared["handle"]}),
                )
                .await?["state"]
                    == "tunnel_starting",
                "Non-app policy Apply",
            )?;
            let main = Command::new("/usr/bin/systemctl")
                .args([
                    "show",
                    "--property=MainPID",
                    "--value",
                    "yonik-worker.service",
                ])
                .output()?;
            require(main.status.success(), "Worker MainPID")?;
            let pid: u32 = std::str::from_utf8(&main.stdout)?.trim().parse()?;
            require(pid > 1, "Worker отсутствует после Apply")?;
            let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
            require(
                status
                    .lines()
                    .any(|line| line == "CapEff:\t0000000000001000"),
                "Worker capabilities",
            )?;
            require(
                status.lines().any(|line| line == "NoNewPrivs:\t1"),
                "Worker NoNewPrivileges",
            )?;
            println!("Production worker {engine}: {status}");
            call(&connection, "Stop", empty.clone()).await?;
            call(&connection, "Unlock", empty.clone()).await?;
        }
        require(
            call(&connection, "State", empty.clone()).await?["state"] == "no_managed_policy",
            "Остались эффекты",
        )?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Только production VM, настоящий helper/worker и registry; stdin control без TUN"]
async fn production_singbox_worker_owned_stdin() -> Result {
    use std::sync::Arc;
    use yonik_linux::{
        Cancellation,
        helper::{SystemWorkerSupervisor, TrustedRegistry},
        worker::WorkerPayload,
    };
    guard()?;
    require(
        rustix::process::geteuid().is_root(),
        "Нужен root VM controller",
    )?;
    let _lock = vm_lock::acquire()?;
    helper_pid()?;
    let server = yonik_import::import_bytes(b"socks5://127.0.0.1:10999".to_vec())?
        .servers
        .remove(0);
    let config = yonik_engine::compile(
        &server,
        yonik_engine::Engine::SingBox,
        std::num::NonZeroU16::new(10808).ok_or_else(|| io::Error::other("port"))?,
    )?;
    let registry = TrustedRegistry::system()?;
    let payload = Arc::new(WorkerPayload::new(
        registry.snapshot(yonik_engine::Engine::SingBox)?,
        config,
    )?);
    let mut supervisor = SystemWorkerSupervisor::system().await?;
    let (_keep, mut cancel) = Cancellation::new();
    let result: Result = async {
        supervisor.check(Arc::clone(&payload), &mut cancel).await?;
        let ticket = supervisor.start(Arc::clone(&payload), &mut cancel).await?;
        let file = fs::File::open(format!("/proc/{}/fd/0", ticket.pid()))?;
        let metadata = file.metadata()?;
        require(
            metadata.uid() != 0 && metadata.mode() & 0o777 == 0o600,
            "Config не принадлежит worker/mode0600",
        )?;
        require(
            rustix::fs::fcntl_get_seals(&file)?.contains(
                rustix::fs::SealFlags::WRITE
                    | rustix::fs::SealFlags::GROW
                    | rustix::fs::SealFlags::SHRINK
                    | rustix::fs::SealFlags::SEAL,
            ),
            "Config не sealed",
        )?;
        println!(
            "SingBox production stdin: UID={}, mode=0600, sealed, bytes={}",
            metadata.uid(),
            metadata.len()
        );
        supervisor.stop(&ticket, &mut cancel).await?;
        Ok(())
    }
    .await;
    let (_keep_cleanup, mut cleanup) = Cancellation::new();
    let recovered = supervisor.recover(&mut cleanup).await;
    result?;
    recovered?;
    Ok(())
}

#[tokio::test]
#[ignore = "Только собственная production VM, real system bus/polkit и coordinator inspection"]
async fn production_helper_resource_bundle_both_cores() -> Result {
    use sha2::{Digest, Sha256};
    use std::{io::Write, os::unix::fs::DirBuilderExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use yonik_engine::{
        Engine,
        resource_bundle::{ResourceBinding, ResourceKind, ResourceRule, VerifiedCatalog},
    };
    use yonik_linux::{
        Cancellation,
        bundle_identity::CompileRequirements,
        bundle_request::BundleRequest,
        resource_catalog::{ResourceCatalog, SourceResource},
        rule_set_store::{EncryptedRuleSetStore, WorkerEmptyEvidence},
        system_client::{State, SystemClient},
    };
    guard()?;
    require(
        rustix::process::geteuid().is_root(),
        "Требуется авторизованный VM root controller",
    )?;
    let status = fs::read_to_string("/proc/self/status")?;
    require(
        status
            .lines()
            .any(|line| line == "CapEff:\t0000000000000000"),
        "Controller должен быть без capabilities для same-UID proc identity fence",
    )?;
    let _lock = vm_lock::acquire()?;
    let base = std::path::Path::new("/opt/yonik-bundle-case/actual");
    fs::DirBuilder::new().mode(0o700).create(base)?;
    let mut source = Vec::new();
    writeln!(&mut source, "198.20.0.3/32")?;
    for i in 0..49_998u32 {
        writeln!(&mut source, "10.0.{}.{}/32", i / 256, i % 256)?;
    }
    writeln!(&mut source, "2001:db8:746f::3/128")?;
    let server = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let (_keep, cancel) = Cancellation::new();
    for (engine, label) in [(Engine::Xray, "xray"), (Engine::SingBox, "sing-box")] {
        let deadline = || tokio::time::Instant::now() + Duration::from_secs(60);
        let mut client = SystemClient::system(deadline(), cancel.clone()).await?;
        require(
            client.state(deadline(), cancel.clone()).await? == State::NoManagedPolicy,
            "Нечистый исходный State",
        )?;
        require(
            client
                .bundle_capabilities(deadline(), cancel.clone())
                .await?
                .canonical_fd_transport,
            "Нет negotiated bundle capability",
        )?;
        let path = base.join(format!("store-{label}"));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| io::Error::other("Fixture RNG недоступен"))?;
        let mut store = EncryptedRuleSetStore::open(fs::File::open(&path)?, key)?;
        let catalog = ResourceCatalog::build(
            engine,
            &[SourceResource {
                source: &source,
                digest: Sha256::digest(&source).into(),
                count: 50_000,
                kind: ResourceKind::Cidrs,
            }],
            &mut store,
        )?;
        store.commit(0, catalog.references())?;
        let expected = catalog.manifest().to_vec();
        drop(catalog);
        let lease = store.lease_current()?;
        let exported = lease.canonical_sources()?;
        let files = exported
            .resources
            .iter()
            .map(|(_, f)| f.try_clone())
            .collect::<std::io::Result<Vec<_>>>()?;
        let canonical = exported
            .resources
            .iter()
            .map(|(d, _)| d.clone())
            .collect::<Vec<_>>();
        let policy = yonik_engine::policy_wire::SystemPolicy::parse(
            r#"{"version":1,"default_action":"proxy","user_rules":[{"id":7,"enabled":true,"action":"block","domain":[],"domain_suffix":[],"ip_cidr":[],"executable_paths":[]}],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}"#,
        )?;
        let pin = Sha256::digest(fs::read(format!("/usr/lib/yonik/engines/{label}"))?).into();
        let mut request = BundleRequest {
            server: yonik_import::ServerIntent::from_server(&server.servers[0])?,
            policy,
            engine,
            native_pin: pin,
            revision: 1,
            intent_digest: [0; 32],
            requirements: CompileRequirements {
                kill_switch: false,
                system_tun: true,
            },
            bindings: vec![ResourceBinding {
                rule: ResourceRule::User(7),
                resource: 0,
            }],
            canonical,
            expected_native: expected.clone(),
        };
        request.intent_digest = request.digest()?;
        let prepared = client
            .prepare_bundle(&request, &files, deadline(), cancel.clone())
            .await?;
        require(
            prepared.intent_digest == request.intent_digest
                && prepared.runtime_bundle_digest != prepared.intent_digest,
            "Intent/runtime identities",
        )?;
        require(
            client
                .apply_bundle(prepared, deadline(), cancel.clone())
                .await?
                == State::TunnelStarting,
            "Production bundle Apply",
        )?;
        let output = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "--property=MainPID",
                "--value",
                "yonik-worker.service",
            ])
            .output()?;
        require(output.status.success(), "MainPID query")?;
        let pid: u32 = std::str::from_utf8(&output.stdout)?.trim().parse()?;
        require(pid > 1, "Worker отсутствует")?;
        let marker = serde_json::to_vec(
            &json!({"engine":label,"pid":pid,"digest":expected[0].digest,"bytes":expected[0].bytes,"records":50_000}),
        )?;
        let pending = base.join(format!("{label}-applied.pending"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        file.write_all(&marker)?;
        file.sync_all()?;
        fs::hard_link(&pending, base.join(format!("{label}-applied.json")))?;
        fs::remove_file(pending)?;
        let until = tokio::time::Instant::now() + Duration::from_secs(10);
        while !base.join(format!("{label}-inspected")).exists() {
            require(
                tokio::time::Instant::now() < until,
                "Нет coordinator inspection",
            )?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for address in [
            "198.20.0.2",
            "198.20.0.3",
            "2001:db8:746f::2",
            "2001:db8:746f::3",
        ] {
            let ip: std::net::IpAddr = address.parse()?;
            let target = std::net::SocketAddr::new(ip, 24081);
            let route = Command::new("/usr/bin/ip")
                .args(["-j", "route", "get", address, "uid", "0"])
                .output()?;
            require(route.status.success(), "Route witness")?;
            let routes: Value = serde_json::from_slice(&route.stdout)?;
            require(
                routes[0]["dev"]
                    .as_str()
                    .is_some_and(|dev| dev.starts_with("tofu")),
                "Traffic bypasses TUN",
            )?;
            for udp in [false, true] {
                let operation = async {
                    let payload = [b'p'; 32];
                    let mut response = [0u8; 42];
                    if udp {
                        let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                        let socket = tokio::net::UdpSocket::bind(bind).await?;
                        socket.connect(target).await?;
                        socket.send(&payload).await?;
                        let size = socket.recv(&mut response).await?;
                        if size != response.len() {
                            return Ok::<bool, io::Error>(false);
                        }
                    } else {
                        let mut socket = tokio::net::TcpStream::connect(target).await?;
                        socket.write_all(&payload).await?;
                        socket.read_exact(&mut response).await?;
                    }
                    Ok::<bool, io::Error>(
                        response[..10] == *b"yonik-tun:" && response[10..] == payload,
                    )
                };
                let passed = matches!(
                    tokio::time::timeout(Duration::from_secs(2), operation).await,
                    Ok(Ok(true))
                );
                let matched = address.ends_with(".3") || address.ends_with("::3");
                require(passed != matched, "Bundle membership dataflow mismatch")?;
                eprintln!(
                    "bundle engine={label} target={address} udp={udp} matched={matched} response={passed}"
                );
            }
        }
        require(
            client.stop(deadline(), cancel.clone()).await? == State::NoManagedPolicy,
            "Stop bundle",
        )?;
        require(
            client.unlock(deadline(), cancel.clone()).await? == State::NoManagedPolicy,
            "Unlock bundle",
        )?;
        struct Empty;
        impl WorkerEmptyEvidence for Empty {
            fn worker_and_cgroup_empty(&self) -> bool {
                for unit in ["yonik-worker.service", "yonik-worker-check.service"] {
                    let Ok(output) = Command::new("/usr/bin/systemctl")
                        .args(["show", "--property=MainPID", "--value", unit])
                        .output()
                    else {
                        return false;
                    };
                    if !output.status.success()
                        || String::from_utf8_lossy(&output.stdout).trim() != "0"
                    {
                        return false;
                    }
                    match fs::read_to_string(format!(
                        "/sys/fs/cgroup/system.slice/{unit}/cgroup.events"
                    )) {
                        Ok(value) if value.lines().any(|line| line == "populated 0") => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        _ => return false,
                    }
                }
                true
            }
        }
        require(
            Empty.worker_and_cgroup_empty(),
            "Нет actual worker+cgroup-empty evidence",
        )?;
        lease.release_after_empty(&Empty)?;
        require(
            store.reservations()?.active_quarantine == 0,
            "Lease не освобождён после empty evidence",
        )?;
        eprintln!("bundle engine={label} worker_cgroup_empty=true lease_released=true");
    }
    Ok(())
}
