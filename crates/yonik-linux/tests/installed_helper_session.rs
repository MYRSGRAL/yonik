//! Production helper на системной шине собственной одноразовой VM.
//! Это отдельный gate: private bus и подмена authorizer здесь запрещены.
#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::{fs, io, os::unix::fs::MetadataExt, process::Command, time::Duration};
use yonik_engine::Engine;
use yonik_linux::system_client::{PreparedOutput, State, SystemClient, output::OutputDrain};
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
    guard_init("systemd")
}

fn guard_init(expected: &str) -> Result {
    require(
        std::env::var("YONIK_PRODUCTION_HELPER_VM").as_deref() == Ok("1"),
        "Нет явного VM opt-in",
    )?;
    require(
        fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim() == "QEMU",
        "Требуется QEMU",
    )?;
    require(
        fs::read_to_string("/proc/1/comm")?.trim() == expected,
        "PID 1 не соответствует стенду",
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

async fn kill_helper_and_wait_for_recovery(
    connection: &zbus::Connection,
    original_pid: u32,
    expected_state: &str,
) -> Result {
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
            if let Ok(state) = call(connection, "State", json!({"version":1})).await {
                return require(
                    state["state"] == expected_state,
                    "Состояние после восстановления не соответствует политике kill switch",
                );
            }
        }
        require(
            tokio::time::Instant::now() < deadline,
            "Helper не восстановился",
        )?;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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
    lifecycle(None, false).await
}

#[tokio::test]
#[ignore = "Только production helper VM с синтетическим peer и trusted registry"]
async fn production_helper_system_profile_survives_sigkill() -> Result {
    lifecycle(Some(Engine::Xray), false).await
}

#[tokio::test]
#[ignore = "Только production helper VM с синтетическим peer и доверенным sing-box"]
async fn production_helper_sing_box_profile_survives_sigkill() -> Result {
    lifecycle(Some(Engine::SingBox), false).await
}

#[tokio::test]
#[ignore = "Только disposable VM, реальный helper и дескрипторы вывода Xray"]
async fn production_helper_xray_output_survives_sigkill() -> Result {
    lifecycle(Some(Engine::Xray), true).await
}

#[tokio::test]
#[ignore = "Только disposable VM, реальный helper и дескрипторы вывода sing-box"]
async fn production_helper_sing_box_output_survives_sigkill() -> Result {
    lifecycle(Some(Engine::SingBox), true).await
}

async fn wait_for_fixture_link() -> Result {
    use yonik_linux::NetworkReadError;

    const DEADLINE: Duration = Duration::from_secs(5);
    const IFA_F_DADFAILED: u32 = 0x08;
    const IFA_F_TENTATIVE: u32 = 0x40;
    const LOCAL_TABLE: u32 = 255;

    let (_sender, mut cancel) = yonik_linux::Cancellation::new();
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        require(!remaining.is_zero(), "IPv6 DAD стенда не завершился")?;
        let topology = match yonik_linux::read_topology(&mut cancel, remaining).await {
            Ok(topology) => topology,
            Err(NetworkReadError::Changed | NetworkReadError::Interrupted) => {
                tokio::time::sleep(Duration::from_millis(50).min(remaining)).await;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
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

const ECHO_PAYLOAD_BYTES: usize = 32;

async fn check_tun_traffic() -> Result {
    check_tun_traffic_to([
        "198.18.0.2:40000".parse()?,
        "[2001:db8:746f::2]:40000".parse()?,
    ])
    .await
}

async fn check_tun_traffic_to(servers: [std::net::SocketAddr; 2]) -> Result {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
    };

    const PREFIX: &[u8] = b"yonik-tun:";
    const REPLY_BYTES: usize = PREFIX.len() + ECHO_PAYLOAD_BYTES;

    tokio::time::timeout(Duration::from_secs(10), async {
        for server in servers {
            let bind = if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let mut payload = [0u8; ECHO_PAYLOAD_BYTES];
            getrandom::getrandom(&mut payload)
                .map_err(|_| io::Error::other("Не удалось создать тестовую нагрузку"))?;
            let mut expected = [0u8; REPLY_BYTES];
            expected[..PREFIX.len()].copy_from_slice(PREFIX);
            expected[PREFIX.len()..].copy_from_slice(&payload);

            let mut tcp = TcpStream::connect(server).await?;
            tcp.write_all(&payload).await?;
            let mut reply = [0u8; REPLY_BYTES];
            tcp.read_exact(&mut reply).await?;
            require(reply == expected, "Неверный TCP-ответ через TUN")?;

            let udp = UdpSocket::bind(bind).await?;
            udp.connect(server).await?;
            require(
                udp.send(&payload).await? == payload.len(),
                "Неполная UDP-отправка",
            )?;
            let mut reply = [0u8; REPLY_BYTES + 1];
            let received = udp.recv(&mut reply).await?;
            require(
                reply[..received] == expected,
                "Неверный UDP-ответ через TUN",
            )?;
        }
        Ok(())
    })
    .await?
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с тестовой сборкой установленного helper"]
async fn production_helper_resolved_fake_dns() -> Result {
    installed_fake_dns(None, HelperLifecycle::Normal, None, None).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с контролируемым DNS за veth"]
async fn production_helper_literal_fake_dns() -> Result {
    installed_fake_dns(
        Some("10.203.1.2:53".parse()?),
        HelperLifecycle::Normal,
        None,
        None,
    )
    .await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM для SIGKILL и истечения Fake-IP"]
async fn production_helper_fake_dns_survives_sigkill() -> Result {
    installed_fake_dns(None, HelperLifecycle::Crash(Engine::Xray), None, None).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с обычным Prepare и политикой Proxy"]
async fn production_helper_scoped_fake_dns_policy() -> Result {
    let policy = scoped_fake_dns_proxy_policy()?;
    installed_fake_dns(None, HelperLifecycle::Normal, Some(&policy), None).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая VM со штатным DNS и CNAME для edge-bootstrap.test и edge-expiring.test"]
async fn production_helper_named_proxy_checks_cname_ttl_at_apply() -> Result {
    use yonik_linux::system_client::ClientError;

    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let (_owner, cancel) = yonik_linux::Cancellation::new();
    let deadline = || tokio::time::Instant::now() + Duration::from_secs(25);
    let mut client =
        SystemClient::on_connection(connection.clone(), deadline(), cancel.clone()).await?;
    let profile = |host: &str| -> Result<yonik_import::ServerIntent> {
        let report = yonik_import::import_bytes(
            format!("vless://00112233-4455-6677-8899-aabbccddeeff@{host}:24443?security=tls&sni=doh.test")
                .into_bytes(),
        )?;
        Ok(yonik_import::ServerIntent::from_server(&report.servers[0])?)
    };
    let expiring = profile("edge-expiring.test")?;
    let usable = profile("edge-bootstrap.test")?;
    let domains = ["example.test".to_owned()];
    let policy = scoped_fake_dns_proxy_policy()?;
    let mut previous_fake = None;
    for engine in [Engine::Xray, Engine::SingBox] {
        let prepared = client
            .prepare_fake_dns_policy_profile(
                &expiring,
                engine,
                false,
                &domains,
                &policy,
                deadline(),
                cancel.clone(),
            )
            .await
            .map_err(|error| {
                io::Error::other(format!("{engine:?} Prepare короткого TTL: {error:?}"))
            })?;
        tokio::time::sleep(Duration::from_secs(21)).await;
        let expired = client.apply(prepared, deadline(), cancel.clone()).await;
        require(
            matches!(expired, Err(ClientError::Stale)),
            "Apply принял просроченный CNAME",
        )?;
        require(
            client.state(deadline(), cancel.clone()).await? == State::NoManagedPolicy,
            "Просроченный Apply установил сетевое состояние",
        )?;
        let drain =
            start_fake_dns_in_vm(&connection, &usable, engine, false, Some(&policy), &cancel)
                .await?;
        let v4 = getent_fake_dns("ahostsv4", "example.test").await?;
        let v6 = getent_fake_dns("ahostsv6", "example.test").await?;
        eprintln!("{engine:?}: NSS вернул {v4} и {v6}");
        if let Some((old_v4, old_v6)) = previous_fake {
            require(
                v4 != old_v4 && v6 != old_v6,
                "NSS вернул Fake-IP предыдущего движка",
            )?;
            let (blocked_v4, blocked_v6) = tokio::join!(
                check_fake_flow_blocked((old_v4, 40000).into()),
                check_fake_flow_blocked((old_v6, 40000).into()),
            );
            blocked_v4?;
            blocked_v6?;
        }
        check_tun_traffic_to([(v4, 40000).into(), (v6, 40000).into()]).await?;
        previous_fake = Some((v4, v6));
        require(
            client.stop(deadline(), cancel.clone()).await? == State::NoManagedPolicy,
            "Stop не очистил состояние",
        )?;
        require(
            tokio::time::timeout(Duration::from_secs(6), drain.drained()).await?,
            "Worker остался активен после Stop",
        )?;
        require(resolver_file_state()? == before, "Изменился resolv.conf")?;
        eprintln!(
            "{engine:?}: истёкший CNAME отклонён, свежий профиль прошёл Fake A/AAAA и TCP/UDP"
        );
    }
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая VM с чужим TCP-слушателем на адресе resolved stub"]
async fn production_helper_named_proxy_rejects_foreign_resolved_stub() -> Result {
    use yonik_linux::system_client::ClientError;

    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let (_owner, cancel) = yonik_linux::Cancellation::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut client = SystemClient::on_connection(connection, deadline, cancel.clone()).await?;
    let report = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@edge-bootstrap.test:24443?security=tls"
            .to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&report.servers[0])?;
    let result = client
        .prepare_profile(&server, Engine::Xray, false, deadline, cancel.clone())
        .await;
    require(
        matches!(result, Err(ClientError::Unsupported)),
        &format!(
            "Ожидался отказ для чужого сокета stub, получено {:?}",
            result.err()
        ),
    )?;
    require(
        client.state(deadline, cancel).await? == State::NoManagedPolicy,
        "Чужой stub установил сетевое состояние",
    )?;
    require(resolver_file_state()? == before, "Изменился resolv.conf")
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "чистая VM с NetworkManager и tools/fixtures/networkmanager_dhcp.sh"]
async fn production_helper_networkmanager_dhcp_renewal() -> Result {
    let engine = networkmanager_fixture_engine()?;
    let policy = scoped_fake_dns_proxy_policy()?;
    installed_fake_dns(
        None,
        HelperLifecycle::NetworkManagerDhcp(engine),
        Some(&policy),
        None,
    )
    .await
}

#[cfg(feature = "test-support")]
fn networkmanager_fixture_engine() -> Result<Engine> {
    match std::env::var("YONIK_NM_DHCP_ENGINE")?.as_str() {
        "xray" => Ok(Engine::Xray),
        "sing-box" => Ok(Engine::SingBox),
        _ => Err(io::Error::other("Для стенда нужен xray или sing-box").into()),
    }
}

#[cfg(feature = "test-support")]
fn dhcpcd_fixture_journal(unit: &str) -> Result<String> {
    let journal = Command::new("/usr/bin/journalctl")
        .args(["-b", "-u", unit, "--no-pager", "-o", "cat"])
        .output()?;
    require(journal.status.success(), "Не прочитан журнал стенда dhcpcd")?;
    Ok(String::from_utf8(journal.stdout)?)
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая Debian или Arch VM с пакетным dhcpcd и свежим лизингом dhcpcd-probe"]
async fn production_helper_fake_dns_during_dhcpcd_renewal() -> Result {
    const LEASE: (&str, &str, &str) = ("dhcpcd-probe", "10.234.16.10", "10.234.16.1");
    const RENEWING: &str = "dhcpcd-probe: renewing lease of 10.234.16.10";
    const RENEW_HOOK: &str = "dhcpcd-run-hooks RENEW";
    const REBINDING: &str = "dhcpcd-probe: failed to renew DHCP, rebinding";

    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let engine = match std::env::var("YONIK_DHCPCD_ENGINE")?.as_str() {
        "xray" => Engine::Xray,
        "sing-box" => Engine::SingBox,
        _ => return Err(io::Error::other("Для стенда dhcpcd нужен xray или sing-box").into()),
    };
    let dhcpcd_unit = if std::env::var_os("YONIK_DHCPCD_INSTANCE").is_some() {
        r"dhcpcd@dhcpcd\x2dprobe.service"
    } else {
        "dhcpcd.service"
    };
    require(
        Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", dhcpcd_unit])
            .status()?
            .success(),
        "Пакетная служба dhcpcd не запущена",
    )?;
    let ack_count = || -> Result<usize> {
        Ok(dhcpcd_fixture_journal("yonik-dhcpcd-server")?
            .lines()
            .filter(|line| line.ends_with("sending ACK to 10.234.16.10"))
            .count())
    };
    require(
        ack_count()? == 1 && !dhcpcd_fixture_journal(dhcpcd_unit)?.contains(RENEWING),
        "Стенд должен начать с первого DHCPACK до продления T1",
    )?;

    let resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let policy = scoped_fake_dns_proxy_policy()?;
    let (_owner, token) = yonik_linux::Cancellation::new();
    let drain =
        start_fake_dns_in_vm(&connection, &server, engine, true, Some(&policy), &token).await?;
    let observed = async {
        let worker = networkmanager_dhcp_worker_pid()?;
        check_running_dhcp_renewal(&[LEASE]).await?;
        let check_traffic = || async {
            require(
                networkmanager_dhcp_worker_pid()? == worker,
                "Worker сменился во время продления dhcpcd",
            )?;
            let v4 = getent_fake_dns("ahostsv4", "example.test").await?;
            let v6 = getent_fake_dns("ahostsv6", "example.test").await?;
            require(
                v4.is_ipv4() && v6.is_ipv6(),
                "NSS вернул неверные семейства",
            )?;
            check_tun_traffic_to([(v4, 40000).into(), (v6, 40000).into()]).await?;
            require(
                networkmanager_dhcp_worker_pid()? == worker,
                "Worker сменился во время проверки IPv4/IPv6 TCP/UDP",
            )
        };
        check_traffic().await?;
        require(
            ack_count()? == 1,
            "Второй DHCPACK появился до проверки активного TUN",
        )?;
        // Сервер пишет один DHCPACK на ответ. Клиентская запись может дублироваться.
        tokio::time::timeout(Duration::from_secs(32), async {
            loop {
                let acks = ack_count()?;
                let journal = dhcpcd_fixture_journal(dhcpcd_unit)?;
                require(
                    acks <= 2 && !journal.contains(REBINDING),
                    "Стенд перешёл к перепривязке или получил лишний DHCPACK",
                )?;
                check_traffic().await?;
                if acks == 2 && journal.contains(RENEWING) && journal.contains(RENEW_HOOK) {
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .map_err(|_| io::Error::other("Нет подтверждения второго DHCPACK и T1 RENEW"))??;
        check_running_dhcp_renewal(&[LEASE]).await?;
        check_traffic().await?;
        require(
            resolver_file_state()? == resolver_before,
            "Продление dhcpcd изменило /etc/resolv.conf",
        )
    }
    .await;

    let stopped = call(&connection, "Stop", json!({"version":1})).await;
    let drained = tokio::time::timeout(Duration::from_secs(3), drain.drained()).await;
    let dhcp_set_after_stop = dhcp_renewal_set();
    let unlocked = call(&connection, "Unlock", json!({"version":1})).await;
    observed?;
    require(
        matches!(
            stopped?["state"].as_str(),
            Some("recovery_required" | "verified_rules")
        ),
        "Stop не сохранил kill switch после продления dhcpcd",
    )?;
    require(drained?, "Worker не завершился после Stop")?;
    require(dhcp_set_after_stop?.is_none(), "Набор DHCP пережил Stop")?;
    require(
        unlocked?["state"] == "no_managed_policy",
        "Unlock не очистил правила после продления dhcpcd",
    )?;
    require(
        resolver_file_state()? == resolver_before,
        "Stop или Unlock изменили /etc/resolv.conf",
    )?;
    eprintln!(
        "{engine:?}: второй DHCPACK в T1, Fake A/AAAA и IPv4/IPv6 TCP/UDP при том же PID worker"
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая Debian VM с dhcpcd и 46-секундным лизингом на dhcpcd-probe"]
async fn production_helper_fake_dns_during_dhcpcd_rebind() -> Result {
    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let engine = match std::env::var("YONIK_DHCPCD_ENGINE")?.as_str() {
        "xray" => Engine::Xray,
        "sing-box" => Engine::SingBox,
        _ => return Err(io::Error::other("Для стенда dhcpcd нужен xray или sing-box").into()),
    };
    let resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let policy = scoped_fake_dns_proxy_policy()?;
    let (_owner, token) = yonik_linux::Cancellation::new();
    let drain =
        start_fake_dns_in_vm(&connection, &server, engine, true, Some(&policy), &token).await?;
    require_no_dhcp_permission(false)?;
    let v4 = getent_fake_dns("ahostsv4", "example.test").await?;
    let v6 = getent_fake_dns("ahostsv6", "example.test").await?;
    check_tun_traffic_to([(v4, 40000).into(), (v6, 40000).into()]).await?;
    let worker = networkmanager_dhcp_worker_pid()?;
    let client_journal = || dhcpcd_fixture_journal("yonik-dhcpcd-client");
    let renewal = "renewing lease of 10.234.16.10";
    require(
        !client_journal()?.contains(renewal),
        "Начальная проверка TUN завершилась после первой попытки продления",
    )?;
    tokio::time::timeout(Duration::from_secs(34), async {
        loop {
            if client_journal()?.contains(renewal) {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(350)).await;
        }
    })
    .await??;
    require(
        networkmanager_dhcp_worker_pid()? == worker,
        "Worker сменился во время продления dhcpcd",
    )?;
    require_no_dhcp_permission(false)?;
    let v4 = getent_fake_dns("ahostsv4", "example.test").await?;
    let v6 = getent_fake_dns("ahostsv6", "example.test").await?;
    check_tun_traffic_to([(v4, 40000).into(), (v6, 40000).into()]).await?;
    eprintln!("{engine:?}: Fake A/AAAA и IPv4/IPv6 TCP/UDP прошли после попытки продления dhcpcd");
    require(
        tokio::time::timeout(Duration::from_secs(32), drain.drained()).await?,
        "Worker продолжил работу после перепривязки лизинга dhcpcd",
    )?;
    let journal = client_journal()?;
    require(
        journal.contains("failed to renew DHCP, rebinding")
            && journal.contains("dhcpcd-run-hooks REBIND")
            && dhcpcd_fixture_journal("yonik-dhcpcd-server")?
                .matches("sending ACK to 10.234.16.10")
                .count()
                == 2,
        "Стенд не подтвердил второй DHCPACK и штатный REBIND",
    )?;
    let state = state_after_route_events(&connection).await?;
    require(
        matches!(
            state["state"].as_str(),
            Some("recovery_required" | "verified_rules")
        ),
        "После перепривязки лизинга helper не сохранил kill switch",
    )?;
    for destination in [(v4, 40000).into(), (v6, 40000).into()] {
        check_fake_flow_blocked(destination).await?;
    }
    require(
        call(&connection, "Unlock", json!({"version":1})).await?["state"] == "no_managed_policy",
        "Unlock не очистил правила после перепривязки лизинга",
    )?;
    eprintln!("{engine:?}: worker остановлен, kill switch и защита Fake-IP сработали");
    require(
        resolver_file_state()? == resolver_before,
        "Изменился /etc/resolv.conf",
    )
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM с нативным DoT на внешнем линке и известной приватной зоной"]
async fn production_helper_rejects_native_dot_with_private_dns() -> Result {
    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let (_owner, token) = yonik_linux::Cancellation::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut client =
        SystemClient::on_connection(connection.clone(), deadline, token.clone()).await?;
    for engine in [Engine::Xray, Engine::SingBox] {
        let result = client
            .prepare_fake_dns_profile(
                &server,
                engine,
                false,
                &["example.test".to_owned()],
                deadline,
                token.clone(),
            )
            .await;
        let state = result.as_ref().map(|_| ());
        require(
            matches!(
                state,
                Err(yonik_linux::system_client::ClientError::Unsupported)
            ),
            &format!("{engine:?} Prepare с приватной зоной и нативным DoT: {state:?}"),
        )?;
    }
    require(
        state_after_route_events(&connection).await?["state"] == "no_managed_policy",
        "Отказ Prepare создал сетевую политику",
    )?;
    require(
        resolver_file_state()? == resolver_before,
        "Проверка изменила /etc/resolv.conf",
    )?;
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM с глобальным DoT и известной приватной зоной wg.test"]
async fn production_helper_relays_global_dot_with_private_dns() -> Result {
    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let policy = scoped_fake_dns_proxy_policy()?;
    let (_owner, token) = yonik_linux::Cancellation::new();
    let peer = std::env::var("YONIK_CHECK_STRICT_DOT")?.parse()?;
    let alternate = std::env::var("YONIK_CHECK_ALTERNATE_DOT")?.parse()?;
    check_fallback_dns_in_vm("real.test").await?;
    for (engine, private) in [
        (Engine::Xray, "xray-denied.wg.test"),
        (Engine::SingBox, "sing-box-denied.wg.test"),
    ] {
        let drain = start_fake_dns_in_vm_with_domains(
            &connection,
            &server,
            engine,
            false,
            Some(&policy),
            &token,
            &["example.test".to_owned()],
        )
        .await?;
        check_fallback_dns_in_vm("real.test").await?;
        check_fallback_dns_in_vm("public.dot.test").await?;
        check_strict_dot_outsider(peer).await?;
        check_strict_dot_outsider(alternate).await?;
        let address = getent_fake_dns("ahostsv4", "example.test").await?;
        require(
            matches!(address, std::net::IpAddr::V4(v4) if matches!(v4.octets(), [198, 19, 224..=255, _])),
            "Публичная зона не получила Fake-IP",
        )?;
        require(
            getent_fake_dns("ahostsv4", private).await.is_err(),
            "Системный резолвер получил ответ для приватного имени",
        )?;
        call(&connection, "Stop", json!({"version":1})).await?;
        require(
            tokio::time::timeout(Duration::from_secs(3), drain.drained())
                .await
                .map_err(|error| {
                    io::Error::other(format!("{engine:?} вывод после Stop: {error}"))
                })?,
            "Не остановлен worker",
        )?;
        check_fallback_dns_in_vm("real.test")
            .await
            .map_err(|error| {
                io::Error::other(format!("{engine:?} повторный DoT после Stop: {error}"))
            })?;
        check_fallback_dns_in_vm("restored.test")
            .await
            .map_err(|error| {
                io::Error::other(format!("{engine:?} новый DoT после Stop: {error}"))
            })?;
        eprintln!("{engine:?}: YONIK_GLOBAL_DOT_PRIVATE_ZONE_RELAY");
    }
    require(
        resolver_file_state()? == resolver_before,
        "Проверка изменила /etc/resolv.conf",
    )?;
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с автономным helper и остановкой службы после Apply"]
async fn production_helper_standalone_shutdown_restores_network() -> Result {
    guard()?;
    require(
        Command::new("/usr/lib/yonik/yonik-helper")
            .arg("--standalone-service")
            .status()?
            .code()
            == Some(64),
        "Пакетный вход автономного helper открылся при systemd PID 1",
    )?;
    let policy = scoped_fake_dns_proxy_policy()?;
    installed_fake_dns(
        None,
        HelperLifecycle::Shutdown(StandaloneService::SystemdFixture),
        Some(&policy),
        None,
    )
    .await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с OpenRC или runit"]
async fn production_helper_native_init_dns_and_shutdown() -> Result {
    let service = StandaloneService::native()?;
    let policy = scoped_fake_dns_proxy_policy()?;
    installed_fake_dns(
        None,
        HelperLifecycle::Shutdown(service),
        Some(&policy),
        None,
    )
    .await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM, штатный Prepare Xray и SIGKILL установленного helper"]
async fn production_helper_xray_fake_dns_recovers() -> Result {
    let policy = scoped_fake_dns_proxy_policy()?;
    installed_fake_dns(
        None,
        HelperLifecycle::Crash(Engine::Xray),
        Some(&policy),
        None,
    )
    .await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM, штатный Prepare sing-box и SIGKILL установленного helper"]
async fn production_helper_sing_box_fake_dns_recovers() -> Result {
    let policy = scoped_fake_dns_proxy_policy()?;
    installed_fake_dns(
        None,
        HelperLifecycle::Crash(Engine::SingBox),
        Some(&policy),
        None,
    )
    .await
}

#[cfg(feature = "test-support")]
fn scoped_fake_dns_proxy_policy() -> Result<yonik_engine::policy_wire::SystemPolicy> {
    Ok(yonik_engine::policy_wire::SystemPolicy::parse(
        &json!({
            "version":1, "default_action":"proxy", "preset_rules":[],
            "lan":[], "private_networks":[], "private_domains":[],
            "user_rules":[{
                "id":1, "enabled":true, "action":"proxy",
                "ip_cidr":["203.0.113.45/32"], "domain":[],
                "domain_suffix":[], "executable_paths":[]
            }]
        })
        .to_string(),
    )?)
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с echo peer для example.test и blocked.example.test"]
async fn production_helper_scoped_fake_dns_domain_policy() -> Result {
    installed_fake_dns_with_domain_policy(FakeDnsPolicyWitness::Domains, false).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с проксируемыми IPv4/IPv6 echo endpoints"]
async fn production_helper_scoped_fake_dns_literal_cidr_policy() -> Result {
    installed_fake_dns_with_domain_policy(FakeDnsPolicyWitness::LiteralBlock, false).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM, контроль доступности тех же буквальных IP через Proxy"]
async fn production_helper_scoped_fake_dns_literal_cidr_control() -> Result {
    installed_fake_dns_with_domain_policy(FakeDnsPolicyWitness::LiteralProxy, false).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с отдельным физическим echo и блокировкой этих адресов на прокси"]
async fn production_helper_scoped_fake_dns_literal_direct() -> Result {
    installed_fake_dns_with_domain_policy(FakeDnsPolicyWitness::LiteralDirect, false).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM, физический echo и перезапуск helper через SIGKILL"]
async fn production_helper_scoped_fake_dns_literal_direct_recovers() -> Result {
    installed_fake_dns_with_domain_policy(FakeDnsPolicyWitness::LiteralDirect, true).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с двумя путями до одного тестового VLESS peer"]
async fn production_helper_fake_dns_after_route_switch() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::PeerRoute).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с активным systemd-resolved"]
async fn production_helper_fake_dns_after_resolver_revert() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::ResolverLink).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM с активным systemd-resolved и постоянным DNS-стендом"]
async fn production_helper_fake_dns_after_resolver_restart() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::ResolverRestart).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM с активным systemd-resolved и постоянным DNS-стендом"]
async fn production_helper_fake_dns_after_resolver_restart_and_ttl() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::ResolverRestartAfterTtl).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая VM с установленным helper и обоими движками"]
async fn production_helper_fake_dns_rejects_old_addresses_after_engine_switch() -> Result {
    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let (_owner, token) = yonik_linux::Cancellation::new();
    let policy = scoped_fake_dns_proxy_policy()?;
    let mut previous: Option<([std::net::IpAddr; 2], tokio::time::Instant, u32)> = None;
    for engine in [Engine::Xray, Engine::SingBox, Engine::Xray] {
        let drain =
            start_fake_dns_in_vm(&connection, &server, engine, false, Some(&policy), &token)
                .await?;
        if let Some(([old_v4, old_v6], _, old_pid)) = previous {
            require(
                networkmanager_dhcp_worker_pid()? != old_pid,
                "Смена движка оставила прежний worker",
            )?;
            let (ipv4, ipv6) = tokio::join!(
                check_fake_flow_blocked((old_v4, 40000).into()),
                check_fake_flow_blocked((old_v6, 40000).into()),
            );
            ipv4?;
            ipv6?;
        }
        let issued_by = tokio::time::Instant::now();
        let v4 = getent_fake_dns("ahostsv4", "example.test").await?;
        let v6 = getent_fake_dns("ahostsv6", "example.test").await?;
        require(
            v4.is_ipv4() && v6.is_ipv6(),
            "NSS вернул неверные семейства",
        )?;
        if let Some(([old_v4, old_v6], old_issued_by, _)) = previous {
            require(
                issued_by - old_issued_by < yonik_linux::fake_service::MAX_FAKE_TTL
                    && v4 != old_v4
                    && v6 != old_v6,
                "Смена движка переиспользовала старый Fake-IP либо вышла за DNS TTL",
            )?;
        }
        check_tun_traffic_to([(v4, 40000).into(), (v6, 40000).into()]).await?;
        if let Some(certificate) = std::env::var_os("YONIK_FAKE_DNS_TLS_CA") {
            check_https_through_tun(&certificate, None).await?;
        }
        let worker = networkmanager_dhcp_worker_pid()?;
        call(&connection, "Stop", json!({"version":1})).await?;
        require(
            tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?,
            "Worker не завершился после Stop",
        )?;
        check_only_fake_is_filtered(v4, v6).await?;
        previous = Some(([v4, v6], issued_by, worker));
        eprintln!("{engine:?}: завершена проверка смены движка и защиты Fake-IP");
    }
    check_fallback_dns_in_vm("restored.test").await?;
    require(
        resolver_file_state()? == resolver_before,
        "Смена движка изменила /etc/resolv.conf",
    )
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с tools/fixtures/wireguard_vm.py и wg"]
async fn production_helper_fake_dns_preserves_external_wireguard() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::WireGuard).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с systemd-resolved и приватным DNS за WireGuard"]
async fn production_helper_xray_fake_dns_blocks_unbound_wireguard() -> Result {
    installed_fake_dns_blocks_unbound_wireguard(Engine::Xray).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с systemd-resolved и приватным DNS за WireGuard"]
async fn production_helper_sing_box_fake_dns_blocks_unbound_wireguard() -> Result {
    installed_fake_dns_blocks_unbound_wireguard(Engine::SingBox).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM после перезагрузки с ранее обнаруженной зоной WireGuard"]
async fn production_helper_protects_private_dns_after_reboot() -> Result {
    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let policy = scoped_fake_dns_proxy_policy()?;
    let (_owner, token) = yonik_linux::Cancellation::new();
    for engine in [Engine::Xray, Engine::SingBox] {
        let drain = start_fake_dns_in_vm_with_domains(
            &connection,
            &server,
            engine,
            false,
            Some(&policy),
            &token,
            &["test".to_owned(), "wg.test".to_owned()],
        )
        .await?;
        let marker = private_zone_test_marker()?;
        for tcp in [false, true] {
            let public = ask_fixture_dns(marker, "example.test", 1, tcp).await?;
            require(
                matches!(public, std::net::IpAddr::V4(v4) if matches!(v4.octets(), [198, 19, 224..=255, _])),
                "Публичное имя не получило Fake-IP",
            )?;
            require(
                ask_fixture_dns(marker, "rebooted.wg.test", 1, tcp)
                    .await
                    .is_err(),
                "Приватное имя получило ответ Fake DNS после перезагрузки",
            )?;
        }
        call(&connection, "Stop", json!({"version":1})).await?;
        require(
            tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?,
            "Не остановлен worker",
        )?;
        eprintln!("{engine:?}: YONIK_PRIVATE_DNS_AFTER_REBOOT");
    }
    require(
        resolver_file_state()? == resolver_before,
        "Проверка изменила /etc/resolv.conf",
    )
}

#[cfg(feature = "test-support")]
async fn installed_fake_dns_blocks_unbound_wireguard(engine: Engine) -> Result {
    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let policy = yonik_engine::policy_wire::SystemPolicy::parse(
        r#"{"version":1,"default_action":"proxy","user_rules":[],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}"#,
    )?;
    let (_owner, token) = yonik_linux::Cancellation::new();
    control_fixture_wireguard("connect")?;
    control_fixture_wireguard("split-dns")?;
    check_wireguard_traffic().await?;
    require(
        ask_fixture_dns("10.42.1.2:53".parse()?, "before.wg.test", 1, false).await?
            == std::net::Ipv4Addr::new(10, 42, 1, 2),
        "DNS-сервер стенда WireGuard не ответил напрямую",
    )?;
    check_wireguard_dns("before.wg.test").await?;
    eprintln!("{engine:?}: приватные DNS и трафик доступны до запуска Fake DNS");

    let drain = start_fake_dns_in_vm_with_domains(
        &connection,
        &server,
        engine,
        false,
        Some(&policy),
        &token,
        &["test".to_owned(), "wg.test".to_owned()],
    )
    .await?;
    let v4 = getent_fake_dns("ahostsv4", "example.test").await?;
    let v6 = getent_fake_dns("ahostsv6", "example.test").await?;
    check_tun_traffic_to([(v4, 40000).into(), (v6, 40000).into()]).await?;
    let marker = private_zone_test_marker()?;
    for tcp in [false, true] {
        require(
            ask_fixture_dns(marker, "example.test", 1, tcp).await? == v4,
            "Контрольный DNS-запрос не дошёл до Fake DNS",
        )?;
        require(
            ask_fixture_dns(marker, "hidden.wg.test", 1, tcp)
                .await
                .is_err(),
            "Прямой запрос получил Fake-IP для приватной зоны WireGuard",
        )?;
    }
    eprintln!("{engine:?}: YONIK_PRIVATE_ZONE_PRECEDENCE");
    let dns = check_wireguard_dns("active.wg.test");
    let block4 = check_fake_flow_blocked("10.42.1.2:40000".parse()?);
    let block6 = check_fake_flow_blocked("[fd42:1::2]:40000".parse()?);
    let (dns, block4, block6) = tokio::join!(dns, block4, block6);
    call(&connection, "Stop", json!({"version":1})).await?;
    require(
        tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?,
        "Не остановлен worker",
    )?;
    check_wireguard_dns("after.wg.test").await?;
    check_wireguard_traffic().await?;
    check_only_fake_is_filtered(v4, v6).await?;
    control_fixture_wireguard("stop-dns")?;
    control_fixture_wireguard("disconnect")?;
    require(
        Command::new("systemctl")
            .args(["restart", "yonik-helper.service"])
            .status()?
            .success(),
        "Не перезапущен helper",
    )?;
    let drain = start_fake_dns_in_vm_with_domains(
        &connection,
        &server,
        engine,
        false,
        Some(&policy),
        &token,
        &["test".to_owned(), "wg.test".to_owned()],
    )
    .await?;
    let marker = private_zone_test_marker()?;
    let public = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            if let Ok(address) = getent_fake_dns("ahostsv4", "example.test").await {
                break address;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await?;
    for tcp in [false, true] {
        require(
            ask_fixture_dns(marker, "example.test", 1, tcp).await? == public,
            "Fake DNS публичной зоны не восстановился после перезапуска",
        )?;
        require(
            ask_fixture_dns(marker, "missing.wg.test", 1, tcp)
                .await
                .is_err(),
            "Отсутствующий WireGuard потерял сохранённую приватную зону",
        )?;
    }
    eprintln!("{engine:?}: YONIK_PRIVATE_ZONE_RESTART_WITHOUT_WIREGUARD");
    call(&connection, "Stop", json!({"version":1})).await?;
    require(
        tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?,
        "Не остановлен worker повторной сессии",
    )?;
    require(
        resolver_file_state()? == resolver_before,
        "Проверка изменила /etc/resolv.conf",
    )?;
    block4?;
    block6?;
    require(
        dns.is_err(),
        "Приватный DNS неожиданно доступен во время Fake DNS",
    )?;
    let peer = Command::new("journalctl")
        .args([
            "-b",
            "-u",
            "yonik-dns-peer-fixture.service",
            "-o",
            "cat",
            "--no-pager",
        ])
        .output()?;
    require(peer.status.success(), "Не удалось прочитать журнал VLESS")?;
    require(
        !std::str::from_utf8(&peer.stdout)?.lines().any(|line| {
            line.contains(" accepted ")
                && (line.contains(":10.42.1.2:") || line.contains(":[fd42:1::2]:"))
        }),
        "VLESS получил пакеты приватной сети WireGuard",
    )?;
    eprintln!("{engine:?}: VLESS не получил приватный трафик. WireGuard восстановился после Stop");
    Ok(())
}

#[cfg(feature = "test-support")]
fn private_zone_test_marker() -> Result<std::net::SocketAddr> {
    let output = Command::new("resolvectl").arg("dns").output()?;
    require(output.status.success(), "Не прочитан DNS TUN")?;
    let (link, marker) = std::str::from_utf8(&output.stdout)?
        .lines()
        .filter_map(|line| line.split_once(": "))
        .find_map(|(link, entry)| {
            let name = link.split_once("(tofu")?.1.strip_suffix(')')?;
            let marker = entry.parse::<std::net::IpAddr>().ok()?;
            Some((format!("tofu{name}"), std::net::SocketAddr::new(marker, 53)))
        })
        .ok_or_else(|| io::Error::other("Не найден DNS-адрес TUN"))?;
    let output = Command::new("resolvectl")
        .args(["domain", &link])
        .output()?;
    require(output.status.success(), "Не прочитаны DNS-зоны TUN")?;
    let published = std::str::from_utf8(&output.stdout)?;
    require(
        published.split_whitespace().any(|word| word == "~test")
            && !published.split_whitespace().any(|word| word == "~wg.test"),
        "TUN опубликовал приватную зону либо потерял публичный суффикс",
    )?;
    Ok(marker)
}

#[cfg(feature = "test-support")]
async fn check_wireguard_dns(name: &str) -> Result {
    require(
        getent_fake_dns("ahostsv4", name).await? == std::net::Ipv4Addr::new(10, 42, 1, 2),
        "NSS не получил адрес от приватного DNS-сервера",
    )
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с resolvconf и двумя DNS-серверами тестового peer"]
async fn production_helper_fake_dns_after_resolvconf_update() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::Resolvconf {
        initial: "10.203.1.2".parse()?,
        updated: "10.203.1.6".parse()?,
    })
    .await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая Debian VM с сохранённой wg.test, WireGuard и двумя DNS под resolvconf"]
async fn production_helper_fake_dns_protects_zone_after_resolvconf_route_change() -> Result {
    check_saved_zone_after_resolvconf_route_change(false).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая Debian VM с сохранённой wg.test, WireGuard и двумя DNS под resolvconf"]
async fn production_helper_fake_dns_keeps_zone_between_workers_with_kill_switch() -> Result {
    check_saved_zone_after_resolvconf_route_change(true).await
}

#[cfg(feature = "test-support")]
async fn check_private_queries_blocked(address: std::net::IpAddr, name: &str) -> Result {
    let peer = (address, 53).into();
    for qtype in [1, 28] {
        let (udp, tcp) = tokio::join!(
            ask_fixture_dns(peer, name, qtype, false),
            ask_fixture_dns(peer, name, qtype, true),
        );
        require(
            udp.is_err() && tcp.is_err(),
            "Приватная зона доступна через публичный DNS",
        )?;
    }
    Ok(())
}

#[cfg(feature = "test-support")]
async fn check_saved_zone_after_resolvconf_route_change(kill_switch: bool) -> Result {
    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let connection = zbus::Connection::system().await?;
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let (_owner, token) = yonik_linux::Cancellation::new();
    let policy = scoped_fake_dns_proxy_policy()?;
    let domains = ["example.test".to_owned(), "wg.test".to_owned()];
    let initial = "10.203.1.2".parse::<std::net::IpAddr>()?;
    let updated = "10.203.1.6".parse::<std::net::IpAddr>()?;
    let private = "10.42.1.2:53".parse()?;
    let route = |operation, kind| {
        Command::new("ip")
            .args(["route", operation, kind, "10.42.1.2/32"])
            .status()
    };
    for engine in [Engine::Xray, Engine::SingBox] {
        let baseline = resolver_file_state()?;
        require(
            ask_fixture_dns(private, "before.wg.test", 1, false).await?
                == std::net::Ipv4Addr::new(10, 42, 1, 2),
            "Приватный DNS недоступен до запуска TUN",
        )?;
        let start = || {
            start_fake_dns_in_vm_with_domains(
                &connection,
                &server,
                engine,
                kill_switch,
                Some(&policy),
                &token,
                &domains,
            )
        };
        let drain = start().await?;
        let old_v4 = getent_fake_dns("ahostsv4", "example.test").await?;
        let old_v6 = getent_fake_dns("ahostsv6", "example.test").await?;
        check_fixture_resolver(initial, "192.0.2.99", old_v4, old_v6).await?;
        check_private_queries_blocked(initial, "before.wg.test").await?;
        require(
            resolver_file_state()? == baseline,
            "TUN изменил источник DNS",
        )?;
        require(
            route("add", "blackhole")?.success(),
            "Стенд не отозвал маршрут приватного DNS",
        )?;
        let stopped = tokio::time::timeout(Duration::from_secs(15), drain.drained());
        let during_stop = async {
            if kill_switch {
                check_private_queries_blocked(initial, "transition.wg.test").await?;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (stopped, during_stop) = tokio::join!(stopped, during_stop);
        during_stop?;
        require(
            stopped?,
            "Сетевой наблюдатель не остановил worker после смены маршрута",
        )?;
        let state = state_after_route_events(&connection).await?;
        require(
            if kill_switch {
                matches!(
                    state["state"].as_str(),
                    Some("recovery_required" | "verified_rules")
                )
            } else {
                state["state"] == "no_managed_policy"
            },
            "Helper не завершил предыдущую сессию",
        )?;
        if kill_switch {
            check_private_queries_blocked(initial, "stopped.wg.test").await?;
        }
        require(
            resolver_file_state()? == baseline,
            "Смена только маршрута изменила источник DNS",
        )?;
        require(
            ask_fixture_dns(private, "unreachable.wg.test", 1, false)
                .await
                .is_err(),
            "Старый приватный маршрут всё ещё доступен",
        )?;
        switch_fixture_resolver(updated)?;
        let published = resolver_file_state()?;
        require(
            published.contents != baseline.contents,
            "resolvconf не опубликовал новый адрес DNS",
        )?;
        let drain = if kill_switch {
            check_private_queries_blocked(updated, "updated.wg.test").await?;
            let (started, protection) = tokio::join!(
                start(),
                check_private_queries_blocked(updated, "prepare.wg.test")
            );
            protection?;
            let drain = started?;
            tokio::try_join!(
                check_fake_flow_blocked((old_v4, 40000).into()),
                check_fake_flow_blocked((old_v6, 40000).into()),
            )?;
            eprintln!("{engine:?}: YONIK_PRIVATE_ZONE_BETWEEN_WORKERS_OK");
            drain
        } else {
            check_only_fake_is_filtered(old_v4, old_v6).await?;
            start().await?
        };
        let v4 = getent_fake_dns("ahostsv4", "example.test").await?;
        let v6 = getent_fake_dns("ahostsv6", "example.test").await?;
        check_fixture_resolver(updated, "192.0.2.100", v4, v6).await?;
        check_private_queries_blocked(updated, "after.wg.test").await?;
        check_tun_traffic_to([(v4, 40000).into(), (v6, 40000).into()]).await?;
        call(&connection, "Stop", json!({"version":1})).await?;
        require(
            tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?,
            "Stop не завершил worker",
        )?;
        require(
            resolver_file_state()? == published,
            "Повторный запуск или Stop изменили конфигурацию resolvconf",
        )?;
        if kill_switch {
            call(&connection, "Unlock", json!({"version":1})).await?;
        }
        require(
            route("del", "blackhole")?.success(),
            "Стенд не восстановил приватный маршрут",
        )?;
        switch_fixture_resolver(initial)?;
        require(
            ask_fixture_dns(private, "restored.wg.test", 1, false).await?
                == std::net::Ipv4Addr::new(10, 42, 1, 2),
            "Приватный DNS не восстановился после возврата маршрута",
        )?;
        eprintln!("{engine:?}: YONIK_SAVED_ZONE_RESOLVCONF_ROUTE_OK");
    }
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM с OpenRC или runit, resolvconf и двумя DNS-серверами"]
async fn production_helper_native_init_after_resolvconf_update() -> Result {
    let init = StandaloneService::native()?.init();
    installed_fake_dns_after_network_change_in_vm(
        FakeDnsNetworkChange::Resolvconf {
            initial: "10.203.1.2".parse()?,
            updated: "10.203.1.6".parse()?,
        },
        init,
    )
    .await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Debian VM с resolvconf и двумя IPv6 DNS-серверами тестового peer"]
async fn production_helper_fake_dns_after_ipv6_resolvconf_update() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::Resolvconf {
        initial: "2001:db8:7472:1::2".parse()?,
        updated: "2001:db8:7472:2::2".parse()?,
    })
    .await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная Fedora VM с NetworkManager и DNS-профилем yonik-nm"]
async fn production_helper_fake_dns_after_networkmanager_dns_update() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::NetworkManagerDns).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM с DHCPv4, systemd-networkd и systemd-resolved"]
async fn production_helper_fake_dns_after_dhcp_reconnect() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::DhcpReconnect).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM с одним проверяемым DHCPv4-лизингом systemd-networkd"]
async fn production_helper_fake_dns_dhcp_renewal() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::DhcpRenewal).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM с правилом DHCP cgroupv2 в таблице стенда"]
async fn dhcp_cgroup_socket_rule_has_exact_kernel_identity() -> Result {
    guard()?;
    let _lock = vm_lock::acquire()?;
    let group = fs::metadata("/sys/fs/cgroup/system.slice/systemd-networkd.service")?;
    let namespace = fs::metadata("/proc/thread-self/ns/net")?;
    let (_owner, mut cancel) = yonik_linux::Cancellation::new();
    let (observed, matches) = yonik_linux::read_nft_socket_cgroup_matches(
        "yonik_dhcp_gate",
        "output",
        &mut cancel,
        Duration::from_secs(3),
    )
    .await?;
    require(
        observed.device == namespace.dev() && observed.inode == namespace.ino(),
        "Правило прочитано в другом сетевом пространстве имён",
    )?;
    require(
        matches.len() == 1 && matches[0].level == 2 && matches[0].cgroup_id.get() == group.ino(),
        "Ядро вернуло другой уровень или inode cgroup",
    )?;
    eprintln!("Правило DHCP совпало с cgroup сокета по данным ядра");
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая VM с DHCPv4 и nftables"]
async fn dhcp_rule_is_verified_through_durable_public_policy() -> Result {
    use std::{io::Write, os::unix::fs::DirBuilderExt, process::Stdio};
    use yonik_linux::{
        helper::dhcp_networkd::DhcpNetworkdLease,
        managed_network::{
            Journal, Ownership,
            firewall::PublicBlockPolicy,
            nft::{NftExecutor, PublicPolicyRecovery},
        },
    };

    guard()?;
    let _lock = vm_lock::acquire()?;
    let before = resolver_file_state()?;
    let (_owner, mut cancel) = yonik_linux::Cancellation::new();
    let index = fs::read_to_string("/sys/class/net/yonik-dhcp/ifindex")?
        .trim()
        .parse::<std::num::NonZeroU32>()?;
    let lo = fs::read_to_string("/sys/class/net/lo/ifindex")?
        .trim()
        .parse()?;
    check_dhcp_fixture_dns("10.203.2.1", &mut cancel).await?;
    let lease = DhcpNetworkdLease::capture(index, &mut cancel).await?;
    let path = lease
        .path()
        .ok_or_else(|| io::Error::other("Нет снимка DHCP"))?;
    let owner = Ownership::new(1000, 1, 1, path.namespace.device, path.namespace.inode)?;
    let journal_dir = std::path::Path::new("/run/yonik-dhcp-rule-test");
    fs::DirBuilder::new().mode(0o700).create(journal_dir)?;
    let mut journal = Journal::open(journal_dir, owner)?;
    let mut nft = NftExecutor::open(owner)?;
    let base = PublicBlockPolicy::new(lo, Some(index.get() + 100), vec![], vec![], vec![], vec![])?;
    let policy = base.clone().with_dhcp_renewal_rule(&lease)?;
    let initial_revision = nft
        .apply_durable_public_policy(&mut journal, 1, 5, base)
        .await?;
    let revision = nft
        .apply_durable_public_policy(&mut journal, 1, 5, policy)
        .await?;
    require(
        revision > initial_revision,
        "Правило DHCP не заменило предыдущую политику",
    )?;
    drop(journal);
    let mut journal =
        Journal::open_existing(journal_dir)?.ok_or_else(|| io::Error::other("Не открыт журнал"))?;
    require(
        nft.recover_public_policy(&mut journal).await?
            == PublicPolicyRecovery::DesiredRules { revision },
        "Правило DHCP не принято после повторного открытия журнала",
    )?;
    let table = "yonik_0000000000000005";
    let set_contains_lease = || -> Result<bool> {
        let output = Command::new(nft_test_binary())
            .args([
                "-n",
                "-j",
                "list",
                "set",
                "inet",
                table,
                "dhcp_renewal_leases",
            ])
            .output()?;
        require(output.status.success(), "Не прочитан набор DHCP")?;
        eprintln!("{}", std::str::from_utf8(&output.stdout)?);
        let listing: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let set = listing["nftables"]
            .as_array()
            .and_then(|items| items.iter().find_map(|item| item.get("set")))
            .ok_or_else(|| io::Error::other("Нет набора DHCP"))?;
        Ok(set["elem"]
            .as_array()
            .is_some_and(|elements| !elements.is_empty()))
    };
    let mut lease = DhcpNetworkdLease::capture(index, &mut cancel).await?;
    require(
        nft.refresh_dhcp_renewal(&journal, initial_revision, &mut lease, &mut cancel)
            .await
            .is_err()
            && !set_contains_lease()?,
        "Устаревшая ревизия выдала разрешение DHCP",
    )?;
    eprintln!("Проверена устаревшая ревизия DHCP");
    nft.refresh_dhcp_renewal(&journal, revision, &mut lease, &mut cancel)
        .await?;
    require(set_contains_lease()?, "Нет временного элемента DHCP")?;
    eprintln!("Установлен первый временный элемент DHCP");
    nft.refresh_dhcp_renewal(&journal, revision, &mut lease, &mut cancel)
        .await?;
    require(set_contains_lease()?, "Не обновился временный элемент DHCP")?;
    require(
        nft.recover_public_policy(&mut journal).await?
            == PublicPolicyRecovery::DesiredRules { revision },
        "Временный элемент изменил ревизию или сорвал проверку",
    )?;
    nft.revoke_dhcp_renewal(&journal, revision).await?;
    require(!set_contains_lease()?, "После отзыва остался элемент DHCP")?;
    nft.refresh_dhcp_renewal(&journal, revision, &mut lease, &mut cancel)
        .await?;
    require(
        set_contains_lease()?,
        "Нет элемента перед проверкой таймера",
    )?;
    tokio::time::sleep(std::time::Duration::from_millis(850)).await;
    require(!set_contains_lease()?, "Элемент DHCP пережил таймер ядра")?;
    eprintln!("Элемент DHCP обновлён, отозван и удалён по таймеру ядра");

    require(
        Command::new("/usr/bin/systemctl")
            .args(["start", "yonik-dhcp-fixture-change-dns.service"])
            .status()?
            .success(),
        "Стенд не сменил DNS DHCP-сервера",
    )?;
    let mut lease = DhcpNetworkdLease::capture(index, &mut cancel).await?;
    nft.refresh_dhcp_renewal(&journal, revision, &mut lease, &mut cancel)
        .await?;
    let renew = || -> Result {
        require(
            Command::new("/usr/bin/networkctl")
                .args(["renew", "yonik-dhcp"])
                .status()?
                .success(),
            "Не запрошено продление DHCP",
        )
    };
    renew()?;
    check_dhcp_fixture_dns("10.203.2.2", &mut cancel).await?;
    eprintln!("Временное разрешение пропустило продление DHCP и обновление DNS");
    nft.revoke_dhcp_renewal(&journal, revision).await?;
    renew()?;

    let chain = "dhcp_renewal";
    let output = Command::new(nft_test_binary())
        .args(["-a", "list", "chain", "inet", table, chain])
        .output()?;
    require(output.status.success(), "Не прочитана цепочка DHCP")?;
    let text = std::str::from_utf8(&output.stdout)?;
    let (expression, handle) = text
        .lines()
        .find_map(|line| {
            let (expr, handle) = line.split_once("# handle ")?;
            expr.contains("socket cgroupv2 level 2")
                .then_some((expr.trim(), handle.trim()))
        })
        .ok_or_else(|| io::Error::other("Нет правила DHCP с cgroup"))?;
    let handle = handle.parse::<u64>()?;
    let replace = |expression: &str| -> Result {
        let mut child = Command::new(nft_test_binary())
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .spawn()?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("Не открыт stdin nft"))?;
        writeln!(
            input,
            "replace rule inet {table} {chain} handle {handle} {expression}"
        )?;
        drop(input);
        require(child.wait()?.success(), "Не заменено тестовое правило DHCP")
    };
    replace(&expression.replacen("socket cgroupv2 level 2", "socket cgroupv2 level 1", 1))?;
    require(
        nft.recover_public_policy(&mut journal).await.is_err(),
        "Принят другой уровень cgroup, скрытый в JSON",
    )?;
    replace(expression)?;
    require(
        nft.recover_public_policy(&mut journal).await?
            == PublicPolicyRecovery::DesiredRules { revision },
        "Точное правило не принято после восстановления",
    )?;
    require(
        Command::new("/usr/bin/systemctl")
            .args(["stop", "systemd-networkd.service"])
            .status()?
            .success(),
        "Не остановлен DHCP-клиент стенда",
    )?;
    require(
        nft.recover_public_policy(&mut journal).await?
            == PublicPolicyRecovery::DesiredRules { revision },
        "Сверка правила не прошла после выхода DHCP-клиента",
    )?;
    require(
        nft.unlock_durable_public_policy(&mut journal, 1)
            .await?
            .is_some(),
        "Unlock не снял правило DHCP",
    )?;
    require(
        resolver_file_state()? == before,
        "Изменился /etc/resolv.conf",
    )?;
    eprintln!("Нормальная сверка правил приняла точную cgroup и отклонила изменение уровня");
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная VM с DHCP-клиентом systemd-networkd и двумя ответами DNS"]
async fn dhcp_networkd_lease_is_bound_to_kernel_socket_and_revoked_after_renewal() -> Result {
    use yonik_linux::{NetworkReadError, helper::dhcp_networkd::DhcpNetworkdLease};

    guard()?;
    let _lock = vm_lock::acquire()?;
    let resolver_before = resolver_file_state()?;
    let index = fs::read_to_string("/sys/class/net/yonik-dhcp/ifindex")?
        .trim()
        .parse()?;
    let (_owner, mut token) = yonik_linux::Cancellation::new();
    check_dhcp_fixture_dns("10.203.2.1", &mut token).await?;
    let mut original = DhcpNetworkdLease::capture(index, &mut token).await?;
    let original_path = original
        .path()
        .ok_or_else(|| io::Error::other("Недоступен путь DHCP"))?;
    let group = fs::metadata("/sys/fs/cgroup/system.slice/systemd-networkd.service")?;
    let expected_tos = std::env::var("YONIK_DHCP_EXPECTED_TOS")
        .unwrap_or_else(|_| "192".to_owned())
        .parse::<u8>()?;
    require(
        original_path.ifname == "yonik-dhcp"
            && original_path.address == std::net::Ipv4Addr::new(10, 203, 2, 10)
            && original_path.server == std::net::Ipv4Addr::new(10, 203, 2, 1)
            && original_path.cgroup_id.get() == group.ino()
            && original_path.route_tos == expected_tos
            && original_path.route_mark == 0,
        "Ядро и лизинг DHCP указывают на разные пути",
    )?;
    original.revalidate(&mut token).await?;
    require(
        original.path().is_some(),
        "Не перепроверен неизменный лизинг",
    )?;
    require(
        Command::new("/usr/bin/systemctl")
            .args(["start", "yonik-dhcp-fixture-renew.service"])
            .status()?
            .success(),
        "Стенд не обновил DHCP-лизинг",
    )?;
    check_dhcp_fixture_dns("10.203.2.2", &mut token).await?;
    require(
        original.path().is_some(),
        "Снимок истёк до проверки смены лизинга",
    )?;
    require(
        original.revalidate(&mut token).await == Err(NetworkReadError::Changed)
            && original.path().is_none(),
        "Предыдущий DHCP-лизинг принят после продления",
    )?;
    let updated = DhcpNetworkdLease::capture(index, &mut token).await?;
    require(updated.path().is_some(), "Новый DHCP-лизинг не принят")?;
    require(
        Command::new("/usr/bin/systemctl")
            .args(["stop", "systemd-networkd.service"])
            .status()?
            .success(),
        "Не удалось остановить тестовый DHCP-клиент",
    )?;
    require(
        updated.path().is_none(),
        "Снимок доступен после выхода процесса DHCP-клиента",
    )?;
    require(
        resolver_file_state()? == resolver_before,
        "Изменился /etc/resolv.conf",
    )?;
    eprintln!("Ядро подтвердило сокет DHCP, а продление и выход клиента отозвали старый снимок");
    Ok(())
}

#[cfg(feature = "test-support")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakeDnsNetworkChange {
    PeerRoute,
    ResolverLink,
    ResolverRestart,
    ResolverRestartAfterTtl,
    WireGuard,
    NetworkManagerDns,
    Resolvconf {
        initial: std::net::IpAddr,
        updated: std::net::IpAddr,
    },
    DhcpReconnect,
    DhcpRenewal,
    DhcpSuspendWithoutLogind,
    NetworkManagerSuspend(Option<Engine>),
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая Debian VM с networkd, ACPI S3, отключённым login1 и hook стенда"]
async fn production_helper_fake_dns_suspend_without_logind() -> Result {
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::DhcpSuspendWithoutLogind).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая Fedora VM с NetworkManager, ACPI S3 и hook стенда DHCP"]
async fn production_helper_fake_dns_networkmanager_suspend() -> Result {
    let engine = if std::env::var("YONIK_NM_DHCP_ENGINE").as_deref() == Ok("both") {
        None
    } else {
        Some(networkmanager_fixture_engine()?)
    };
    installed_fake_dns_after_network_change(FakeDnsNetworkChange::NetworkManagerSuspend(engine))
        .await
}

#[cfg(feature = "test-support")]
async fn installed_fake_dns_after_network_change(change: FakeDnsNetworkChange) -> Result {
    installed_fake_dns_after_network_change_in_vm(change, "systemd").await
}

#[cfg(feature = "test-support")]
async fn installed_fake_dns_after_network_change_in_vm(
    change: FakeDnsNetworkChange,
    init: &str,
) -> Result {
    guard_init(init)?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let mut resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let empty = json!({"version":1});
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let policy = yonik_engine::policy_wire::SystemPolicy::parse(
        r#"{"version":1,"default_action":"proxy","user_rules":[],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}"#,
    )?;
    if std::env::var_os("YONIK_EXPECT_CLEAN_FAKE_DNS_START").is_none() {
        tokio::time::sleep(yonik_linux::fake_service::MAX_FAKE_TTL).await;
    }
    let (_owner, mut token) = yonik_linux::Cancellation::new();
    let no_logind = change == FakeDnsNetworkChange::DhcpSuspendWithoutLogind;
    // Реестр использует BOOTTIME, поэтому сон входит в срок аренды Fake-IP.
    // В сценарии S3 подтверждаем блокировку перед новым DNS-ответом после TTL.
    let after_ttl = change == FakeDnsNetworkChange::ResolverRestartAfterTtl || no_logind;
    let resolver_restart = matches!(
        change,
        FakeDnsNetworkChange::ResolverRestart | FakeDnsNetworkChange::ResolverRestartAfterTtl
    );
    let dhcp = matches!(
        change,
        FakeDnsNetworkChange::DhcpReconnect
            | FakeDnsNetworkChange::DhcpRenewal
            | FakeDnsNetworkChange::DhcpSuspendWithoutLogind
    );
    if no_logind {
        let bus = zbus::fdo::DBusProxy::new(&connection).await?;
        require(
            !bus.name_has_owner("org.freedesktop.login1".try_into()?)
                .await?,
            "Сценарий требует отсутствия login1",
        )?;
    }
    let networkmanager_suspend = matches!(change, FakeDnsNetworkChange::NetworkManagerSuspend(_));
    let networkmanager_links = [("yonik-nm-lease", "10.233.53.10", "10.233.53.1")];
    let mut dhcp_links = vec![("yonik-dhcp", "10.203.2.10", "10.203.2.1")];
    if std::env::var_os("YONIK_DHCP_SECOND_FIXTURE").is_some() {
        dhcp_links.push(("yonik-dhcp2", "10.203.3.10", "10.203.3.1"));
    }
    for (engine, kill_switch) in [(Engine::Xray, true), (Engine::SingBox, false)] {
        if matches!(change, FakeDnsNetworkChange::NetworkManagerSuspend(Some(selected)) if selected != engine)
        {
            continue;
        }
        if dhcp {
            check_dhcp_fixture_dns("10.203.2.1", &mut token).await?;
        }
        let mut drain = start_fake_dns_in_vm(
            &connection,
            &server,
            engine,
            kill_switch,
            Some(&policy),
            &token,
        )
        .await?;
        if dhcp {
            require(
                dhcp_renewal_set()?.is_some(),
                "Нет набора DHCP в активной политике",
            )?;
        }
        if no_logind {
            require_no_dhcp_permission(false)?;
        }
        if change == FakeDnsNetworkChange::DhcpRenewal {
            check_running_dhcp_renewal(&dhcp_links).await?;
            renew_dhcp_links(&connection, &dhcp_links, None).await?;
            eprintln!(
                "{engine:?}: DHCP продлён на {} интерфейсах при работающем TUN",
                dhcp_links.len()
            );
            if dhcp_links.len() == 2 && !kill_switch {
                let signal_server = |signal: &str| {
                    Command::new("/usr/bin/systemctl")
                        .args([
                            "kill",
                            "--kill-whom=main",
                            signal,
                            "yonik-dhcp2-fixture.service",
                        ])
                        .status()
                };
                require(
                    signal_server("--signal=STOP")?.success(),
                    "Стенд не приостановил второй DHCP-сервер",
                )?;
                let renewed = renew_dhcp_links(&connection, &dhcp_links, Some("yonik-dhcp2")).await;
                let resumed = signal_server("--signal=CONT")?;
                renewed?;
                require(resumed.success(), "Стенд не восстановил второй DHCP-сервер")?;
                eprintln!("{engine:?}: первый лизинг продлён при недоступном втором DHCP-сервере");
            }
        }
        let before_query = tokio::time::Instant::now();
        let old_v4 = getent_fake_dns("ahostsv4", "example.test").await?;
        let old_v6 = getent_fake_dns("ahostsv6", "example.test").await?;
        let issued_by = tokio::time::Instant::now();
        check_tun_traffic_to([(old_v4, 40000).into(), (old_v6, 40000).into()]).await?;
        require(
            resolver_file_state()? == resolver_before,
            "Сессия изменила /etc/resolv.conf до вмешательства стенда",
        )?;
        if change == FakeDnsNetworkChange::DhcpRenewal || networkmanager_suspend {
            if networkmanager_suspend || std::env::var_os("YONIK_DHCP_SLEEP_FIXTURE").is_some() {
                let networkmanager_acks = if networkmanager_suspend {
                    wait_for_dhcp_renewal_set(&networkmanager_links, false)
                        .await
                        .map_err(|error| io::Error::other(format!("{engine:?} до S3: {error}")))?;
                    let ack_count = networkmanager_dhcp_ack_count()?;
                    eprintln!("{engine:?}: перед S3 допуск DHCP есть, DHCPACK={ack_count}");
                    Some(ack_count)
                } else {
                    None
                };
                fixture_suspend_and_check_dhcp(networkmanager_suspend, false).await?;
                if let Some(previous_acks) = networkmanager_acks {
                    wait_for_networkmanager_after_suspend(previous_acks).await?;
                    let ack_count = networkmanager_dhcp_ack_count()?;
                    eprintln!("{engine:?}: после S3 получен новый DHCPACK, DHCPACK={ack_count}");
                }
                let state = state_after_route_events(&connection).await?;
                require(
                    !networkmanager_suspend || state["state"] != "tunnel_starting",
                    "Стенд NetworkManager не остановил старую сессию после смены сети",
                )?;
                let mut current = (old_v4, old_v6);
                if state["state"] != "tunnel_starting" {
                    require(
                        if kill_switch {
                            matches!(
                                state["state"].as_str(),
                                Some("recovery_required" | "verified_rules")
                            )
                        } else {
                            state["state"] == "no_managed_policy"
                        },
                        "Возобновление нарушило выбранную политику kill switch",
                    )?;
                    require(
                        tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?,
                        "Вывод прежнего worker открыт после S3",
                    )?;
                    if kill_switch {
                        call(&connection, "Unlock", empty.clone()).await?;
                    }
                    check_only_fake_is_filtered(old_v4, old_v6).await?;
                    if networkmanager_suspend {
                        begin_fixture_ipv6_dad()?;
                    }
                    drain = start_fake_dns_in_vm(
                        &connection,
                        &server,
                        engine,
                        kill_switch,
                        Some(&policy),
                        &token,
                    )
                    .await?;
                    if networkmanager_suspend {
                        check_fixture_ipv6_dad(false)?;
                        eprintln!(
                            "{engine:?}: повторное подключение дождалось завершения IPv6 DAD"
                        );
                    }
                    current = (
                        getent_fake_dns("ahostsv4", "example.test").await?,
                        getent_fake_dns("ahostsv6", "example.test").await?,
                    );
                    require(
                        current.0 != old_v4 && current.1 != old_v6,
                        "После S3 повторно выданы старые Fake-IP",
                    )?;
                    eprintln!(
                        "{engine:?}: установлена новая сессия, прежние Fake-IP заблокированы"
                    );
                }
                if let Some(previous_acks) = networkmanager_acks {
                    wait_for_dhcp_renewal_set(&networkmanager_links, false)
                        .await
                        .map_err(|error| {
                            io::Error::other(format!("{engine:?} после S3: {error}"))
                        })?;
                    require(
                        networkmanager_dhcp_ack_count()? > previous_acks,
                        "NetworkManager не получил новый DHCPACK после S3",
                    )?;
                } else {
                    check_running_dhcp_renewal(&dhcp_links).await?;
                    renew_dhcp_links(&connection, &dhcp_links, None).await?;
                }
                check_tun_traffic_to([(current.0, 40000).into(), (current.1, 40000).into()])
                    .await?;
                eprintln!("{engine:?}: DHCP и Fake A/AAAA проверены после S3");
            }
            if !networkmanager_suspend {
                check_running_dhcp_renewal(&dhcp_links).await?;
            }
            call(&connection, "Stop", empty.clone()).await?;
            require(
                tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?,
                "Worker не остановлен после продления DHCP",
            )?;
            require(dhcp_renewal_set()?.is_none(), "Набор DHCP пережил Stop")?;
            if networkmanager_suspend && state_fixture_ipv6_dad()?.contains(FIXTURE_DAD_ADDRESS) {
                require(
                    Command::new("ip")
                        .args([
                            "-6",
                            "address",
                            "del",
                            FIXTURE_DAD_ADDRESS,
                            "dev",
                            "yonik-outer",
                        ])
                        .status()?
                        .success(),
                    "Стенд не удалил проверочный IPv6-адрес",
                )?;
            }
            if kill_switch {
                call(&connection, "Unlock", empty.clone()).await?;
            }
            require(
                resolver_file_state()? == resolver_before,
                "Продление DHCP и Stop изменили /etc/resolv.conf",
            )?;
            eprintln!("{engine:?}: Fake DNS и TUN продолжили работать после продления DHCP");
            continue;
        }
        match change {
            FakeDnsNetworkChange::PeerRoute => change_fixture_peer_route("add")?,
            FakeDnsNetworkChange::ResolverLink => revoke_fixture_link_dns(&mut token).await?,
            FakeDnsNetworkChange::ResolverRestart
            | FakeDnsNetworkChange::ResolverRestartAfterTtl => {
                restart_fixture_resolver(&connection).await?
            }
            FakeDnsNetworkChange::WireGuard => control_fixture_wireguard("connect")?,
            FakeDnsNetworkChange::NetworkManagerDns => {
                check_networkmanager_dns("192.0.2.99").await?;
                switch_networkmanager_dns("10.233.42.3")?;
            }
            FakeDnsNetworkChange::Resolvconf { initial, updated } => {
                check_fixture_resolver(initial, "192.0.2.99", old_v4, old_v6).await?;
                switch_fixture_resolver(updated)?;
                let published = resolver_file_state()?;
                require(
                    published.contents != resolver_before.contents,
                    "resolvconf не опубликовал новый адрес DNS",
                )?;
                resolver_before = published;
                eprintln!("{engine:?}: resolvconf опубликовал новый DNS-сервер");
            }
            FakeDnsNetworkChange::DhcpReconnect => control_dhcp_fixture("disconnect")?,
            FakeDnsNetworkChange::DhcpSuspendWithoutLogind => {
                fixture_suspend_and_check_dhcp(false, true).await?;
                require_no_dhcp_permission(true)?;
                eprintln!("{engine:?}: перед S3 и после пробуждения DHCP-допуск отсутствует");
                control_dhcp_fixture("disconnect")?;
            }
            FakeDnsNetworkChange::DhcpRenewal | FakeDnsNetworkChange::NetworkManagerSuspend(_) => {
                unreachable!("Сценарий продления завершён")
            }
        }
        // До закрытия вывода не обращаемся к helper по D-Bus. Только его
        // наблюдатель сетевых событий может остановить этот worker.
        let drain_timeout = if resolver_restart {
            // Смена владельца D-Bus подтверждается и плановой сверкой DNS.
            Duration::from_secs(25)
        } else {
            Duration::from_secs(10)
        };
        require(
            tokio::time::timeout(drain_timeout, drain.drained()).await?,
            "Сетевой наблюдатель не остановил worker",
        )?;
        let state =
            state_after_route_events_with_timeout(&connection, Duration::from_secs(10)).await?;
        require(
            if kill_switch {
                matches!(
                    state["state"].as_str(),
                    Some("recovery_required" | "verified_rules")
                )
            } else {
                state["state"] == "no_managed_policy"
            },
            "Изменение сети нарушило выбранную политику kill switch",
        )?;
        if !matches!(change, FakeDnsNetworkChange::Resolvconf { .. }) {
            let snapshot =
                yonik_linux::read_resolve1_snapshot(&mut token, Duration::from_secs(3)).await?;
            require(
                !snapshot
                    .domains
                    .iter()
                    .any(|domain| domain.name == "example.test"),
                "DNS-зона осталась после автоматической остановки",
            )?;
        }
        if kill_switch {
            call(&connection, "Unlock", empty.clone()).await?;
        }
        if dhcp {
            require(dhcp_renewal_set()?.is_none(), "Набор DHCP пережил Unlock")?;
            control_dhcp_fixture("10.203.2.2")?;
            check_dhcp_fixture_dns("10.203.2.2", &mut token).await?;
            let answer = Command::new("/usr/bin/resolvectl")
                .args(["query", "--cache=no", "--type=A", "real.test"])
                .output()?;
            require(
                answer.status.success()
                    && String::from_utf8_lossy(&answer.stdout).contains("192.0.2.100"),
                "Системный резолвер не получил ответ нового DHCP DNS-сервера",
            )?;
            eprintln!("{engine:?}: восстановленный линк получил новый DNS через DHCP");
        }
        check_only_fake_is_filtered(old_v4, old_v6).await?;
        if after_ttl {
            tokio::time::sleep_until(issued_by + yonik_linux::fake_service::MAX_FAKE_TTL).await;
            check_only_fake_is_filtered(old_v4, old_v6).await?;
            eprintln!("{engine:?}: после DNS TTL прежние Fake-IP закрыты на физическом выходе");
        }
        let wireguard = if change == FakeDnsNetworkChange::WireGuard {
            check_wireguard_traffic().await?;
            Some(fixture_wireguard_snapshot()?)
        } else {
            None
        };

        let drain = start_fake_dns_in_vm(
            &connection,
            &server,
            engine,
            kill_switch,
            Some(&policy),
            &token,
        )
        .await?;
        if dhcp {
            require(
                dhcp_renewal_set()?.is_some(),
                "Нет набора DHCP после переподключения",
            )?;
        }
        if no_logind {
            require_no_dhcp_permission(false)?;
        }
        if after_ttl {
            // После TTL адрес может быть выдан заново. В новой сессии проверяем
            // старые назначения до первого запроса к имени.
            for old in [old_v4, old_v6] {
                check_fake_flow_blocked((old, 40000).into()).await?;
            }
            eprintln!("{engine:?}: новая сессия блокирует прежние Fake-IP до выдачи ответа DNS");
        }
        let v4 = getent_fake_dns("ahostsv4", "example.test").await?;
        let v6 = getent_fake_dns("ahostsv6", "example.test").await?;
        if !after_ttl {
            require(
                before_query.elapsed() < yonik_linux::fake_service::MAX_FAKE_TTL,
                "Повторное подключение превысило окно TTL прежних Fake-IP",
            )?;
            require(
                v4 != old_v4 && v6 != old_v6,
                "Новая сессия повторно выдала прежний Fake-IP",
            )?;
        }
        check_tun_traffic_to([(v4, 40000).into(), (v6, 40000).into()]).await?;
        if let FakeDnsNetworkChange::Resolvconf { updated, .. } = change {
            check_fixture_resolver(updated, "192.0.2.100", v4, v6).await?;
        }
        if change == FakeDnsNetworkChange::NetworkManagerDns {
            check_networkmanager_dns("192.0.2.100").await?;
        }
        if !after_ttl {
            for old in [old_v4, old_v6] {
                check_fake_flow_blocked((old, 40000).into()).await?;
            }
        }
        if resolver_restart {
            check_fallback_dns_in_vm("real.test").await?;
        }
        if let Some(certificate) = std::env::var_os("YONIK_FAKE_DNS_TLS_CA") {
            check_https_through_tun(&certificate, None).await?;
        }
        call(&connection, "Stop", empty.clone()).await?;
        require(
            tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?,
            "Новый worker не остановлен",
        )?;
        if kill_switch {
            call(&connection, "Unlock", empty.clone()).await?;
        }
        if resolver_restart {
            check_fallback_dns_in_vm("restored.test").await?;
        }
        if change == FakeDnsNetworkChange::PeerRoute {
            change_fixture_peer_route("del")?;
        }
        if let Some(snapshot) = wireguard {
            require(
                fixture_wireguard_snapshot()? == snapshot,
                "Yonik изменил настройки внешнего WireGuard",
            )?;
            check_wireguard_traffic().await?;
            reject_overlapping_wireguard_route(&connection, &server, engine, &policy, &token)
                .await?;
            control_fixture_wireguard("disconnect")?;
        }
        require(
            resolver_file_state()? == resolver_before,
            "Изменение сети повлияло на /etc/resolv.conf",
        )?;
        if let FakeDnsNetworkChange::Resolvconf { initial, .. } = change {
            switch_fixture_resolver(initial)?;
            resolver_before = resolver_file_state()?;
        }
        if change == FakeDnsNetworkChange::NetworkManagerDns {
            switch_networkmanager_dns("10.233.42.2")?;
        }
        if dhcp {
            require(
                dhcp_renewal_set()?.is_none(),
                "Набор DHCP пережил Stop и Unlock",
            )?;
            control_dhcp_fixture("disconnect")?;
            control_dhcp_fixture("10.203.2.1")?;
            check_dhcp_fixture_dns("10.203.2.1", &mut token).await?;
        }
        eprintln!(
            "{engine:?} {change:?}: автоматическая остановка, отзыв DNS и повторное подключение подтверждены"
        );
    }
    Ok(())
}

#[cfg(feature = "test-support")]
async fn fixture_suspend_and_check_dhcp(allow_absent: bool, without_logind: bool) -> Result {
    let pre = std::path::Path::new("/run/yonik-dhcp-sleep-pre");
    let post = std::path::Path::new("/run/yonik-dhcp-sleep-post");
    for marker in [pre, post] {
        match fs::remove_file(marker) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let status = if without_logind {
        Command::new("/usr/bin/systemctl")
            .args(["start", "--no-block", "systemd-suspend.service"])
            .status()?
    } else {
        Command::new("/usr/bin/busctl")
            .args([
                "call",
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "Suspend",
                "b",
                "false",
            ])
            .status()?
    };
    require(status.success(), "Стенд отклонил запрос на сон")?;
    tokio::time::timeout(Duration::from_secs(12), async {
        while !post.exists() {
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await?;
    let state = fs::read_to_string(pre)?;
    require(
        state.trim() == "empty" || (allow_absent && state.trim() == "absent"),
        "Перед S3 сохранялось действующее DHCP-разрешение",
    )
}

#[cfg(feature = "test-support")]
fn require_no_dhcp_permission(allow_absent: bool) -> Result {
    let set = dhcp_renewal_set()?;
    require(
        set.as_ref().map_or(allow_absent, |set| {
            set.get("elem")
                .is_none_or(|entries| entries.as_array().is_some_and(Vec::is_empty))
        }),
        "Появилось DHCP-разрешение либо пропал набор активной политики",
    )
}

#[cfg(feature = "test-support")]
const FIXTURE_DAD_ADDRESS: &str = "2001:db8:7470:53::1/128";

#[cfg(feature = "test-support")]
fn state_fixture_ipv6_dad() -> Result<String> {
    let output = Command::new("ip")
        .args([
            "-6",
            "-o",
            "address",
            "show",
            "dev",
            "yonik-outer",
            "to",
            FIXTURE_DAD_ADDRESS,
        ])
        .output()?;
    require(output.status.success(), "Стенд не прочитал IPv6-адрес")?;
    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(feature = "test-support")]
fn check_fixture_ipv6_dad(pending: bool) -> Result {
    let state = state_fixture_ipv6_dad()?;
    require(
        state.contains(FIXTURE_DAD_ADDRESS)
            && state.split_whitespace().any(|field| field == "tentative") == pending
            && !state.split_whitespace().any(|field| field == "dadfailed"),
        "Состояние IPv6 DAD на проверочном интерфейсе не совпало с ожидаемым",
    )
}

#[cfg(feature = "test-support")]
fn begin_fixture_ipv6_dad() -> Result {
    fs::write("/proc/sys/net/ipv6/conf/yonik-outer/dad_transmits", "2\n")?;
    require(
        Command::new("ip")
            .args([
                "-6",
                "address",
                "add",
                FIXTURE_DAD_ADDRESS,
                "dev",
                "yonik-outer",
            ])
            .status()?
            .success(),
        "Стенд не добавил IPv6-адрес для проверки DAD",
    )?;
    check_fixture_ipv6_dad(true)
}

#[cfg(feature = "test-support")]
async fn wait_for_networkmanager_after_suspend(previous_acks: usize) -> Result {
    let monitor = yonik_linux::NetworkMonitor::start()?;
    let mut watch = monitor.watch();
    let ready = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            // Лизинг может появиться раньше последних изменений маршрутов и DNS.
            let has_lease = watch.current().fully_observed()
                && networkmanager_dhcp_ack_count()? > previous_acks;
            let quiet = if has_lease {
                Duration::from_secs(2)
            } else {
                Duration::from_millis(200)
            };
            match tokio::time::timeout(quiet, watch.changed()).await {
                Ok(change) => change?,
                Err(_) if has_lease => return Ok::<_, Box<dyn std::error::Error>>(()),
                Err(_) => {}
            }
        }
    })
    .await;
    require(monitor.shutdown().await, "Не завершён наблюдатель сети")?;
    ready.map_err(|_| io::Error::other("NetworkManager не восстановил лизинг и стабильную сеть"))?
}

#[cfg(feature = "test-support")]
fn dhcp_renewal_set() -> Result<Option<Value>> {
    let output = Command::new(nft_test_binary())
        .args(["-j", "list", "ruleset"])
        .output()?;
    require(output.status.success(), "Не прочитан ruleset nftables")?;
    let ruleset: Value = serde_json::from_slice(&output.stdout)?;
    let items = ruleset["nftables"]
        .as_array()
        .ok_or_else(|| io::Error::other("Нет списка правил nftables"))?;
    let mut sets = items
        .iter()
        .filter_map(|item| item.get("set"))
        .filter(|set| set["family"] == "inet" && set["name"] == "dhcp_renewal_leases");
    let set = sets.next().cloned();
    require(sets.next().is_none(), "Набор DHCP дублируется")?;
    Ok(set)
}

#[cfg(feature = "test-support")]
async fn check_running_dhcp_renewal(links: &[(&str, &str, &str)]) -> Result {
    wait_for_dhcp_renewal_set(links, true).await
}

#[cfg(feature = "test-support")]
async fn wait_for_dhcp_renewal_set(
    links: &[(&str, &str, &str)],
    require_exact_links: bool,
) -> Result {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(set) = dhcp_renewal_set()? {
                require(set["flags"] == json!(["timeout"]), "Нет таймера DHCP")?;
                if let Some(elements) = set["elem"].as_array() {
                    let matches =
                        |element: &Value, (name, address, server): &(&str, &str, &str)| {
                            element
                                .pointer("/elem/val/concat/0")
                                .and_then(Value::as_str)
                                == Some(*address)
                                && element
                                    .pointer("/elem/val/concat/1")
                                    .and_then(Value::as_str)
                                    == Some(*server)
                                && element
                                    .pointer("/elem/val/concat/3")
                                    .and_then(Value::as_str)
                                    == Some(*name)
                                && element.pointer("/elem/timeout") == Some(&json!(0))
                                && element.pointer("/elem/expires") == Some(&json!(0))
                        };
                    require(
                        !require_exact_links
                            || elements
                                .iter()
                                .all(|element| links.iter().any(|link| matches(element, link))),
                        "Активный DHCP-элемент содержит другой лизинг или таймер",
                    )?;
                    if (!require_exact_links || elements.len() == links.len())
                        && links
                            .iter()
                            .all(|link| elements.iter().any(|element| matches(element, link)))
                    {
                        return Ok::<_, Box<dyn std::error::Error>>(());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("Установленный helper не обновляет допуск DHCP"))?
}

#[cfg(feature = "test-support")]
async fn renew_dhcp_links(
    connection: &zbus::Connection,
    links: &[(&str, &str, &str)],
    offline: Option<&str>,
) -> Result {
    let networkd = networkd_fixture(connection).await?;
    let mut pending = std::collections::BTreeMap::new();
    for (name, _, _) in links {
        let index: i32 = fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
            .trim()
            .parse()?;
        pending.insert(
            index,
            (*name, dhcp_lease_timestamp(&networkd, index).await?),
        );
    }
    require(
        Command::new("/usr/bin/networkctl")
            .arg("renew")
            .args(links.iter().map(|(name, _, _)| name))
            .status()?
            .success(),
        "Стенд не запросил продление DHCP",
    )?;
    for (&index, &(name, original)) in &pending {
        if Some(name) == offline {
            continue;
        }
        tokio::time::timeout(Duration::from_secs(6), async {
            while dhcp_lease_timestamp(&networkd, index).await? <= original {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await
        .map_err(|_| io::Error::other(format!("Не продлён лизинг интерфейса {index}")))??;
    }
    if let Some(offline) = offline {
        tokio::time::sleep(Duration::from_millis(350)).await;
        let Some((&index, &(_, original))) = pending.iter().find(|(_, (name, _))| *name == offline)
        else {
            return Err(io::Error::other("Нет отключённого DHCP-линка в стенде").into());
        };
        require(
            dhcp_lease_timestamp(&networkd, index).await? == original,
            "Лизинг изменился при отключённом DHCP-сервере",
        )?;
    }
    Ok(())
}

#[cfg(feature = "test-support")]
async fn dhcp_lease_timestamp(networkd: &zbus::Proxy<'_>, index: i32) -> Result<u64> {
    let description: String = networkd.call("DescribeLink", &(index,)).await?;
    serde_json::from_str::<Value>(&description)?
        .pointer("/DHCPv4Client/Lease/LeaseTimestampUSec")
        .and_then(Value::as_u64)
        .ok_or_else(|| io::Error::other("networkd не вернул время DHCP-лизинга").into())
}

#[cfg(feature = "test-support")]
async fn networkd_fixture(connection: &zbus::Connection) -> zbus::Result<zbus::Proxy<'_>> {
    zbus::Proxy::new(
        connection,
        "org.freedesktop.network1",
        "/org/freedesktop/network1",
        "org.freedesktop.network1.Manager",
    )
    .await
}

#[cfg(feature = "test-support")]
async fn check_dhcp_fixture_dns(address: &str, token: &mut yonik_linux::Cancellation) -> Result {
    let index = fs::read_to_string("/sys/class/net/yonik-dhcp/ifindex")?;
    let index: u32 = index.trim().parse()?;
    let bus_index = i32::try_from(index)?;
    let address = address.parse::<std::net::Ipv4Addr>()?;
    let expected_dns = json!(address.octets());
    let connection = zbus::Connection::system().await?;
    let networkd = networkd_fixture(&connection).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        require(
            !remaining.is_zero(),
            "DHCP lease или DNS-контур не обновился",
        )?;
        let snapshot =
            yonik_linux::read_resolve1_snapshot(token, remaining.min(Duration::from_secs(3)))
                .await?;
        let mut endpoints = snapshot
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.scope == yonik_linux::Resolve1Scope::Link(index));
        if endpoints
            .next()
            .is_some_and(|endpoint| endpoint.address == address)
            && endpoints.next().is_none()
        {
            let description: String =
                tokio::time::timeout_at(deadline, networkd.call("DescribeLink", &(bus_index,)))
                    .await??;
            let link: Value = serde_json::from_str(&description)?;
            if link["DNS"].as_array().is_some_and(|servers| {
                servers.iter().any(|server| {
                    server["ConfigSource"] == "DHCPv4" && server["Address"] == expected_dns
                })
            }) {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100).min(remaining)).await;
    }
}

#[cfg(feature = "test-support")]
fn control_dhcp_fixture(action: &str) -> Result {
    require(
        Command::new("/opt/yonik-gate/dhcp-dns-change.sh")
            .arg(action)
            .status()?
            .success(),
        "Стенд не изменил состояние DHCP-линка",
    )
}

#[cfg(feature = "test-support")]
fn switch_networkmanager_dns(address: &str) -> Result {
    for args in [
        &["connection", "modify", "yonik-nm", "ipv4.dns", address][..],
        &["device", "reapply", "yonik-nm"][..],
    ] {
        require(
            Command::new("/usr/bin/nmcli")
                .args(args)
                .status()?
                .success(),
            "NetworkManager не обновил DNS на тестовом линке",
        )?;
    }
    Ok(())
}

#[cfg(feature = "test-support")]
async fn check_networkmanager_dns(expected: &str) -> Result {
    require(
        getent_fake_dns("ahostsv4", "real.test").await? == expected.parse::<std::net::IpAddr>()?,
        "Системный резолвер не получил ответ DNS с тестового линка NetworkManager",
    )
}

#[cfg(feature = "test-support")]
fn switch_fixture_resolver(address: std::net::IpAddr) -> Result {
    use std::{io::Write, process::Stdio};

    let mut manager = Command::new("/usr/sbin/resolvconf")
        .args(["-a", "yonik-outer.qa"])
        .stdin(Stdio::piped())
        .spawn()?;
    let mut input = manager
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("Нет stdin resolvconf"))?;
    writeln!(input, "nameserver {address}")?;
    drop(input);
    require(
        manager.wait()?.success(),
        "resolvconf не обновил источник DNS",
    )
}

#[cfg(feature = "test-support")]
async fn check_fixture_resolver(
    address: std::net::IpAddr,
    answer: &str,
    fake_v4: std::net::IpAddr,
    fake_v6: std::net::IpAddr,
) -> Result {
    let peer = (address, 53).into();
    let answer = answer.parse::<std::net::IpAddr>()?;
    for tcp in [false, true] {
        require(
            ask_fixture_dns(peer, "real.test", 1, tcp).await? == answer,
            "Ответ реального DNS не совпал с ответом контрольного сервера",
        )?;
        for (qtype, expected) in [(1, fake_v4), (28, fake_v6)] {
            require(
                ask_fixture_dns(peer, "example.test", qtype, tcp).await? == expected,
                "Прямой DNS-запрос не вернул Fake-IP, выданный через NSS",
            )?;
        }
    }
    Ok(())
}

#[cfg(feature = "test-support")]
const FIXTURE_WG_LINK: &str = "yonik-wg";

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная QEMU VM с WireGuard и отдельными veth для смены маршрута"]
async fn wireguard_transport_route_proof_revokes_changed_path() -> Result {
    use yonik_linux::{NetworkReadError, WireGuardUdpRouteSnapshot};

    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let resolver_before = resolver_file_state()?;
    control_fixture_wireguard("connect")?;
    let (_owner, mut cancel) = yonik_linux::Cancellation::new();
    let index = fs::read_to_string(format!("/sys/class/net/{FIXTURE_WG_LINK}/ifindex"))?
        .trim()
        .parse()?;
    let ip = |args: &[&str]| -> Result {
        let output = Command::new("/usr/bin/ip").args(args).output()?;
        require(
            output.status.success(),
            &format!(
                "Ошибка команды ip: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    };
    ip(&[
        "link",
        "add",
        "yonik-wg-alt",
        "type",
        "veth",
        "peer",
        "name",
        "yonik-wg-peer",
    ])?;
    ip(&["link", "set", "dev", "yonik-wg-alt", "addrgenmode", "none"])?;
    ip(&["link", "set", "dev", "yonik-wg-peer", "addrgenmode", "none"])?;
    ip(&["addr", "add", "192.0.2.1/24", "dev", "yonik-wg-alt"])?;
    ip(&["link", "set", "dev", "yonik-wg-alt", "up"])?;
    ip(&["link", "set", "dev", "yonik-wg-peer", "up"])?;
    eprintln!("Проверка исходного IPv4 маршрута");
    let mut original = WireGuardUdpRouteSnapshot::capture(index, &mut cancel).await?;
    let (original_end, paths) = original
        .paths()
        .ok_or_else(|| io::Error::other("Нет проверенного IPv4 пути"))?;
    require(
        paths.len() == 1
            && paths[0].source() == "10.203.0.1:24177".parse()?
            && paths[0].endpoint() == "10.203.0.2:24177".parse()?
            && paths[0].ifname() == b"yonik-outer"
            && paths[0].fwmark().get() == 24177,
        "IPv4 связка WireGuard не соответствует выбранному маршруту",
    )?;
    eprintln!("Повторная проверка неизменного маршрута");
    original.revalidate(&mut cancel).await?;
    require(
        original
            .paths()
            .is_some_and(|(deadline, _)| deadline > original_end),
        "Повторная проверка не продлила срок",
    )?;

    ip(&[
        "-4",
        "route",
        "add",
        "10.203.0.2/32",
        "dev",
        "yonik-wg-alt",
        "src",
        "192.0.2.1",
        "table",
        "24001",
    ])?;
    let rule = [
        "priority", "9050", "fwmark", "24177", "ipproto", "udp", "sport", "24177", "dport",
        "24177", "lookup", "24001",
    ];
    let mut add = vec!["-4", "rule", "add"];
    add.extend(rule);
    ip(&add)?;
    eprintln!("Проверка IPv4 маршрута с отдельным правилом RPDB");
    let alternate = WireGuardUdpRouteSnapshot::capture(index, &mut cancel).await?;
    require(
        alternate
            .paths()
            .is_some_and(|(_, paths)| paths.len() == 1 && paths[0].ifname() == b"yonik-wg-alt"),
        "Проверка проигнорировала правило RPDB по UDP-портам и метке",
    )?;
    require(
        original.revalidate(&mut cancel).await == Err(NetworkReadError::Changed)
            && original.paths().is_none(),
        "Старый маршрут WireGuard пережил переключение",
    )?;
    let mut remove = vec!["-4", "rule", "del"];
    remove.extend(rule);
    ip(&remove)?;
    require(
        original.revalidate(&mut cancel).await.is_err() && original.paths().is_none(),
        "Старая связка возобновилась после возврата маршрута",
    )?;

    let mut previous_transport = WireGuardUdpRouteSnapshot::capture(index, &mut cancel).await?;
    let keys = Command::new("/opt/yonik-gate/wg")
        .args(["show", FIXTURE_WG_LINK, "peers"])
        .output()?;
    let key = std::str::from_utf8(&keys.stdout)?.trim();
    require(
        keys.status.success() && key.len() == 44,
        "Не подтверждён peer стенда",
    )?;
    let change = Command::new("/opt/yonik-gate/wg")
        .args([
            "set",
            FIXTURE_WG_LINK,
            "listen-port",
            "24178",
            "peer",
            key,
            "endpoint",
            "[2001:db8:7470::2]:24179",
        ])
        .status()?;
    require(change.success(), "Смена endpoint WireGuard не выполнена")?;
    require(
        previous_transport.revalidate(&mut cancel).await.is_err()
            && previous_transport.paths().is_none(),
        "Старый UDP транспорт остался доступен",
    )?;
    eprintln!("Проверка маршрута после смены endpoint на IPv6");
    let current = WireGuardUdpRouteSnapshot::capture(index, &mut cancel).await?;
    let (expires, paths) = current
        .paths()
        .ok_or_else(|| io::Error::other("Нет проверенного IPv6 пути"))?;
    require(
        paths.len() == 1
            && paths[0].source() == "[2001:db8:7470::1]:24178".parse()?
            && paths[0].endpoint() == "[2001:db8:7470::2]:24179".parse()?
            && paths[0].ifname() == b"yonik-outer",
        "IPv6 связка WireGuard не соответствует выбранному маршруту",
    )?;
    tokio::time::sleep_until(expires).await;
    require(
        current.paths().is_none(),
        "Проверенный маршрут пережил срок",
    )?;
    let (stop, mut lifetime) = yonik_linux::Cancellation::new();
    let cancelled = WireGuardUdpRouteSnapshot::capture(index, &mut lifetime).await?;
    require(cancelled.paths().is_some(), "Новый IPv6 снимок недоступен")?;
    stop.send(true)?;
    require(
        cancelled.paths().is_none(),
        "Отмена не закрыла доступ к снимку",
    )?;
    require(
        Command::new("/opt/yonik-gate/wg")
            .args(["set", FIXTURE_WG_LINK, "fwmark", "0"])
            .status()?
            .success(),
        "Не сброшен fwmark WireGuard",
    )?;
    require(
        WireGuardUdpRouteSnapshot::capture(index, &mut cancel)
            .await
            .err()
            == Some(NetworkReadError::Unsupported),
        "Маршрут WireGuard без метки допущен",
    )?;
    control_fixture_wireguard("disconnect")?;
    require(
        resolver_file_state()? == resolver_before,
        "Проверка изменила /etc/resolv.conf",
    )?;
    eprintln!("WireGuard UDP: оба семейства, выбор RPDB, отзыв и истечение срока подтверждены");
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "выделенная QEMU VM с tools/fixtures/wireguard_vm.py и wg"]
async fn wireguard_netlink_observes_transport_and_multipart_allowed_ips() -> Result {
    // 2048 записей IPv6 больше предельной длины одной netlink-датаграммы.
    const PREFIX_COUNT: u16 = 2048;
    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let resolver_before = resolver_file_state()?;
    control_fixture_wireguard("connect")?;
    let (_owner, mut cancel) = yonik_linux::Cancellation::new();
    let deadline = Duration::from_secs(3);
    let topology = yonik_linux::read_topology(&mut cancel, deadline).await?;
    let link = topology
        .links
        .iter()
        .find(|link| link.name == FIXTURE_WG_LINK.as_bytes())
        .ok_or_else(|| io::Error::other("Интерфейс стенда WireGuard не найден"))?;
    let before = yonik_linux::read_wireguard_device(link.index, &mut cancel, deadline).await?;
    require(
        before.namespace == topology.namespace
            && before.ifindex == link.index
            && before.ifname == link.name
            && before.fwmark == 24177
            && before.listen_port == 24177
            && before.peers.len() == 1
            && before.peers[0].endpoint == Some("10.203.0.2:24177".parse()?)
            && before.peers[0].allowed_ips.len() == 2,
        "Снимок WireGuard не соответствует конфигурации стенда",
    )?;

    let keys = Command::new("/opt/yonik-gate/wg")
        .args(["show", FIXTURE_WG_LINK, "peers"])
        .output()?;
    let key = std::str::from_utf8(&keys.stdout)?.trim();
    require(
        keys.status.success() && key.len() == 44,
        "Не подтверждён peer стенда",
    )?;
    let prefixes: Vec<_> = (0..PREFIX_COUNT)
        .map(|number| format!("2001:db8:1200:{number:x}::/64"))
        .collect();
    let configured = Command::new("/opt/yonik-gate/wg")
        .args([
            "set",
            FIXTURE_WG_LINK,
            "listen-port",
            "24178",
            "fwmark",
            "0",
            "peer",
            key,
            "endpoint",
            "[2001:db8:7470::2]:24179",
            "allowed-ips",
            &prefixes.join(","),
        ])
        .output()?;
    require(
        configured.status.success(),
        "Не изменён транспорт стенда WireGuard",
    )?;
    let after = yonik_linux::read_wireguard_device(link.index, &mut cancel, deadline).await?;
    let expected = (0..PREFIX_COUNT).map(|number| {
        (
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0xdb8, 0x1200, number, 0, 0, 0, 0,
            )),
            64,
        )
    });
    require(
        after != before
            && after.fwmark == 0
            && after.listen_port == 24178
            && after.peers.len() == 1
            && after.peers[0].endpoint == Some("[2001:db8:7470::2]:24179".parse()?)
            && after.peers[0]
                .allowed_ips
                .iter()
                .map(|prefix| (prefix.address, prefix.length))
                .eq(expected),
        "Многочастный снимок WireGuard потерял обновлённые атрибуты",
    )?;
    require(
        after == yonik_linux::read_wireguard_device(link.index, &mut cancel, deadline).await?,
        "Стабильный транспорт WireGuard изменился между чтениями",
    )?;
    control_fixture_wireguard("disconnect")?;
    require(
        yonik_linux::read_wireguard_device(link.index, &mut cancel, deadline)
            .await
            .is_err()
            && resolver_file_state()? == resolver_before,
        "Снимок принял удалённый интерфейс или проверка изменила /etc/resolv.conf",
    )?;
    eprintln!(
        "WireGuard netlink: IPv4/IPv6 endpoint, {PREFIX_COUNT} AllowedIPs, смена порта и fwmark подтверждены"
    );
    Ok(())
}

#[cfg(feature = "test-support")]
fn control_fixture_wireguard(operation: &str) -> Result {
    require(
        Command::new("/usr/bin/python3")
            .args(["/opt/yonik-gate/tools/fixtures/wireguard_vm.py", operation])
            .status()?
            .success(),
        "Не удалось изменить состояние WireGuard в стенде",
    )
}

#[cfg(feature = "test-support")]
fn fixture_wireguard_snapshot() -> Result<Vec<Vec<u8>>> {
    [
        (
            "/usr/bin/ip",
            vec!["-j", "link", "show", "dev", FIXTURE_WG_LINK],
        ),
        (
            "/usr/bin/ip",
            vec!["-4", "-j", "route", "show", "dev", FIXTURE_WG_LINK],
        ),
        (
            "/usr/bin/ip",
            vec!["-6", "-j", "route", "show", "dev", FIXTURE_WG_LINK],
        ),
        (
            "/opt/yonik-gate/wg",
            vec!["show", FIXTURE_WG_LINK, "allowed-ips"],
        ),
        (
            "/opt/yonik-gate/wg",
            vec!["show", FIXTURE_WG_LINK, "endpoints"],
        ),
    ]
    .into_iter()
    .map(|(command, args)| {
        let result = Command::new(command).args(args).output()?;
        require(
            result.status.success(),
            "Не удалось прочитать состояние WireGuard",
        )?;
        Ok(result.stdout)
    })
    .collect()
}

#[cfg(feature = "test-support")]
async fn check_wireguard_traffic() -> Result {
    check_tun_traffic_to(["10.42.1.2:40000".parse()?, "[fd42:1::2]:40000".parse()?]).await?;
    let output = Command::new("/opt/yonik-gate/wg")
        .args(["show", FIXTURE_WG_LINK, "latest-handshakes"])
        .output()?;
    require(
        output.status.success(),
        "Не удалось проверить WireGuard handshake",
    )?;
    require(
        std::str::from_utf8(&output.stdout)?
            .split_whitespace()
            .nth(1)
            .and_then(|time| time.parse::<u64>().ok())
            .is_some_and(|time| time > 0),
        "У WireGuard нет подтверждённого handshake",
    )
}

#[cfg(feature = "test-support")]
async fn reject_overlapping_wireguard_route(
    connection: &zbus::Connection,
    server: &yonik_import::ServerIntent,
    engine: Engine,
    policy: &yonik_engine::policy_wire::SystemPolicy,
    token: &yonik_linux::Cancellation,
) -> Result {
    use yonik_linux::system_client::ClientError;

    let change_route = |action| {
        require(
            Command::new("/usr/bin/ip")
                .args([
                    "-4",
                    "route",
                    action,
                    "198.19.224.0/19",
                    "dev",
                    FIXTURE_WG_LINK,
                ])
                .status()?
                .success(),
            "Не удалось изменить маршрут, пересекающий пул Fake-IP",
        )
    };
    change_route("add")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut client =
        SystemClient::on_connection(connection.clone(), deadline, token.clone()).await?;
    let domains = ["example.test".to_owned()];
    let result = loop {
        let result = client
            .prepare_fake_dns_policy_profile(
                server,
                engine,
                false,
                &domains,
                policy,
                deadline,
                token.clone(),
            )
            .await;
        if matches!(&result, Err(ClientError::Busy | ClientError::Stale))
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        } else {
            break result;
        }
    };
    let routes = Command::new("/usr/bin/ip")
        .args([
            "-4",
            "route",
            "show",
            "exact",
            "198.19.224.0/19",
            "dev",
            FIXTURE_WG_LINK,
        ])
        .output()?;
    require(
        routes.status.success() && !routes.stdout.is_empty(),
        "Помощник снял чужой маршрут",
    )?;
    change_route("del")?;
    require(
        matches!(
            result,
            Err(ClientError::Unavailable | ClientError::Unsupported)
        ),
        "Prepare не отклонил пересечение пула Fake-IP с маршрутом WireGuard",
    )?;
    eprintln!(
        "{engine:?}: WireGuard сохранил интерфейс и маршруты, пересечение с Fake-IP отклонено"
    );
    Ok(())
}

#[cfg(feature = "test-support")]
async fn revoke_fixture_link_dns(token: &mut yonik_linux::Cancellation) -> Result {
    let snapshot = yonik_linux::read_resolve1_snapshot(token, Duration::from_secs(3)).await?;
    let mut links = snapshot
        .domains
        .iter()
        .filter_map(|domain| match domain.scope {
            yonik_linux::Resolve1Scope::Link(index)
                if domain.name == "example.test" && domain.route_only =>
            {
                Some(index)
            }
            _ => None,
        });
    let index = links
        .next()
        .ok_or_else(|| io::Error::other("DNS-зона TUN отсутствует"))?;
    require(links.next().is_none(), "DNS-зона не уникальна в стенде")?;
    require(
        Command::new("/usr/bin/busctl")
            .args([
                "call",
                "org.freedesktop.resolve1",
                "/org/freedesktop/resolve1",
                "org.freedesktop.resolve1.Manager",
                "RevertLink",
                "i",
                &index.to_string(),
            ])
            .status()?
            .success(),
        "systemd-resolved не снял конфигурацию DNS TUN",
    )
}

#[cfg(feature = "test-support")]
async fn restart_fixture_resolver(connection: &zbus::Connection) -> Result {
    let bus = zbus::fdo::DBusProxy::new(connection).await?;
    let name = zbus::names::BusName::try_from("org.freedesktop.resolve1")?;
    let before = bus.get_name_owner(name.clone()).await?;
    let status = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new("/usr/bin/systemctl")
            .args(["restart", "systemd-resolved.service"])
            .kill_on_drop(true)
            .status(),
    )
    .await??;
    require(status.success(), "Стенд не перезапустил systemd-resolved")?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match bus.get_name_owner(name.clone()).await {
                Ok(owner) if owner != before => return Ok(()),
                Ok(_) | Err(zbus::fdo::Error::NameHasNoOwner(_)) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| io::Error::other("Владелец имени systemd-resolved на D-Bus не сменился"))??;
    eprintln!("Стенд подтвердил нового владельца systemd-resolved на D-Bus");
    Ok(())
}

#[cfg(feature = "test-support")]
fn change_fixture_peer_route(operation: &str) -> Result {
    if std::env::var_os("YONIK_WIFI_ROUTE_FIXTURE").is_some() {
        return require(
            Command::new("/usr/bin/bash")
                .arg("/run/yonik-wifi-setup/switch.sh")
                .arg(operation)
                .status()?
                .success(),
            "Стенд не переключил точку доступа и маршрут тестового VLESS peer",
        );
    }
    require(
        Command::new("/usr/bin/ip")
            .args([
                "-4",
                "route",
                operation,
                "10.203.0.2/32",
                "via",
                "10.203.2.2",
                "dev",
                "yonik-alt",
            ])
            .status()?
            .success(),
        "Не удалось переключить маршрут тестового VLESS peer",
    )
}

#[cfg(feature = "test-support")]
async fn installed_fake_dns_with_domain_policy(
    witness: FakeDnsPolicyWitness,
    crash: bool,
) -> Result {
    let mut preset_rules = vec![json!({"id":2,"enabled":true,"action":"block","ip_cidr":[],
        "domain":[],"domain_suffix":["example.test"],"executable_paths":[]})];
    let literal_action = match witness {
        FakeDnsPolicyWitness::Domains => None,
        FakeDnsPolicyWitness::LiteralBlock | FakeDnsPolicyWitness::LiteralDirect => Some("block"),
        FakeDnsPolicyWitness::LiteralProxy => Some("proxy"),
        FakeDnsPolicyWitness::ResolvedCidrs | FakeDnsPolicyWitness::ResolvedMixed { .. } => {
            unreachable!("У проверок DNS политики свой профиль")
        }
    };
    if let Some(action) = literal_action {
        preset_rules.push(json!({"id":3,"enabled":true,"action":action,
            "ip_cidr":["198.18.0.2/32","2001:db8:746f::2/128"],
            "domain":[],"domain_suffix":[],"executable_paths":[]}));
    }
    if matches!(witness, FakeDnsPolicyWitness::LiteralDirect) {
        preset_rules.push(json!({"id":4,"enabled":true,"action":"direct",
            "ip_cidr":["192.0.2.192/27","2001:db8:7471::/64"],
            "domain":[],"domain_suffix":[],"executable_paths":[]}));
    }
    let policy = yonik_engine::policy_wire::SystemPolicy::parse(
        &json!({
            "version":1, "default_action":"proxy", "lan":[], "private_networks":[], "private_domains":[],
            "user_rules":[{"id":1,"enabled":true,"action":"proxy","ip_cidr":[],
                "domain":["example.test"],"domain_suffix":[],"executable_paths":[]}],
            "preset_rules":preset_rules
        })
        .to_string(),
    )?;
    installed_fake_dns(
        None,
        if crash {
            HelperLifecycle::Crash(Engine::Xray)
        } else {
            HelperLifecycle::Normal
        },
        Some(&policy),
        Some(witness),
    )
    .await
}

#[cfg(feature = "test-support")]
enum FakeDnsPolicyWitness {
    Domains,
    LiteralBlock,
    LiteralProxy,
    LiteralDirect,
    ResolvedCidrs,
    ResolvedMixed { guarded_proxy: bool },
}

#[cfg(feature = "test-support")]
#[derive(PartialEq, Eq)]
enum ResolvedDnsFixture {
    Cidrs,
    Mixed,
    PartialDirect,
    GuardedProxy,
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая Debian VM с VLESS peer и DNS для проверки CIDR"]
async fn production_helper_resolved_fake_dns_cidrs() -> Result {
    installed_resolved_fake_dns_policy(ResolvedDnsFixture::Cidrs).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая Debian VM с VLESS peer и DNS для смешанных правил"]
async fn production_helper_resolved_fake_dns_mixed() -> Result {
    installed_resolved_fake_dns_policy(ResolvedDnsFixture::Mixed).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая VM с доступным Direct echo 203.0.113.47 и неполным DNS-ответом"]
async fn production_helper_resolved_fake_dns_partial_direct() -> Result {
    installed_resolved_fake_dns_policy(ResolvedDnsFixture::PartialDirect).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая VM с WireGuard-маршрутом для DNS-ответа guarded.example.test"]
async fn production_helper_resolved_fake_dns_guarded_proxy() -> Result {
    installed_resolved_fake_dns_policy(ResolvedDnsFixture::GuardedProxy).await
}

#[cfg(feature = "test-support")]
#[tokio::test]
#[ignore = "одноразовая VM с установленными helper, worker и тестовым VLESS peer"]
async fn production_helper_rejects_private_cidrs_in_fake_dns_profile() -> Result {
    use yonik_engine::policy_wire::SystemPolicy;
    use yonik_linux::system_client::ClientError;

    guard()?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    let public = json!({
        "version": 1, "default_action": "proxy", "lan": [], "private_domains": [],
        "private_networks": [],
        "preset_rules": [{"id": 2, "enabled": true, "action": "block",
            "domain": [], "domain_suffix": [], "ip_cidr": ["203.0.113.46/32"],
            "executable_paths": []}],
        "user_rules": [{"id": 1, "enabled": true, "action": "proxy",
            "domain": ["example.test"], "domain_suffix": [], "ip_cidr": [],
            "executable_paths": []}]
    });
    let domains = ["example.test".to_owned()];
    let policy_resolver = Some("192.0.2.53:5353".parse()?);
    for engine in [Engine::Xray, Engine::SingBox] {
        for networks in [
            json!([{"cidr": "10.42.0.0/16", "vpn": 1, "available": false}]),
            json!([
                {"cidr": "10.42.0.0/16", "vpn": 1, "available": true},
                {"cidr": "172.20.0.0/16", "vpn": 2, "available": true}
            ]),
            json!([]),
        ] {
            let control = networks.as_array().is_some_and(Vec::is_empty);
            let mut request = public.clone();
            request["private_networks"] = networks;
            let policy = SystemPolicy::parse(&request.to_string())?;
            let (_owner, cancel) = yonik_linux::Cancellation::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            let mut client =
                SystemClient::on_connection(connection.clone(), deadline, cancel.clone()).await?;
            let result = client
                .prepare_fake_dns_policy_profile_with_resolver(
                    &server,
                    engine,
                    false,
                    &domains,
                    &policy,
                    policy_resolver,
                    deadline,
                    cancel,
                )
                .await;
            if control {
                result.map_err(|error| {
                    io::Error::other(format!(
                        "{engine:?}: контрольный публичный Prepare: {error}"
                    ))
                })?;
            } else {
                require(
                    matches!(result, Err(ClientError::Unsupported)),
                    &format!("{engine:?}: профиль Fake DNS с приватными CIDR должен быть отклонён"),
                )?;
            }
            require(
                call(&connection, "State", json!({"version": 1})).await?["state"]
                    == "no_managed_policy",
                "Prepare изменил состояние активной сетевой политики",
            )?;
        }
        eprintln!("{engine:?}: приватные профили отклонены, публичный Prepare прошёл");
    }
    require(
        resolver_file_state()? == resolver_before,
        "Prepare изменил /etc/resolv.conf",
    )
}

#[cfg(feature = "test-support")]
async fn installed_resolved_fake_dns_policy(fixture: ResolvedDnsFixture) -> Result {
    require(
        std::env::var("YONIK_CHECK_FAKE_DNS_POLICY_RESOLVER").is_ok(),
        "Стенду нужен DNS политики",
    )?;
    let mixed = fixture != ResolvedDnsFixture::Cidrs;
    let partial_direct = fixture == ResolvedDnsFixture::PartialDirect;
    let guarded_proxy = fixture == ResolvedDnsFixture::GuardedProxy;
    let mut proxy = vec!["2001:db8:746f::2/128"];
    let mut direct = vec!["192.0.2.201/32", "2001:db8:7471::2/128"];
    // Для D-05 имеющийся A совпадает только с младшим Direct.
    if partial_direct {
        direct.push("203.0.113.47/32");
    } else {
        proxy.push("203.0.113.47/32");
    }
    let mut rules: Vec<_> = [
        ("proxy", proxy),
        ("block", vec!["203.0.113.46/32", "2001:db8:746f::48/128"]),
        ("direct", direct),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (action, cidrs))| {
        json!({
            "id": index + 1, "enabled": true, "action": action, "ip_cidr": cidrs,
            "domain": [], "domain_suffix": [], "executable_paths": []
        })
    })
    .collect();
    let mut preset_rules = Vec::new();
    if mixed {
        // Личный Proxy для early.example.test конфликтует с младшим пресетом Direct.
        let mut early_names = vec!["early.example.test"];
        if guarded_proxy {
            early_names.push("guarded.example.test");
        }
        preset_rules.extend(rules.pop());
        rules.splice(0..0, [
            json!({"id": 4, "enabled": true, "action": "proxy", "domain": early_names,
                "domain_suffix": [], "ip_cidr": [], "executable_paths": []}),
            json!({"id": 5, "enabled": true, "action": "block", "domain": ["combined.example.test"],
                "domain_suffix": [], "ip_cidr": ["203.0.113.50/32"], "executable_paths": []}),
            json!({"id": 7, "enabled": true, "action": "direct",
                "domain": ["mixed-direct.example.test"], "domain_suffix": [],
                "ip_cidr": ["192.0.2.202/32"], "executable_paths": []}),
        ]);
        let mut fallback_names = vec!["blocked.example.test"];
        if !partial_direct {
            fallback_names.push("failed.example.test");
        }
        rules.push(json!({"id": 6, "enabled": true, "action": "proxy",
            "domain": fallback_names,
            "domain_suffix": [], "ip_cidr": [], "executable_paths": []}));
    }
    let policy = yonik_engine::policy_wire::SystemPolicy::parse(
        &json!({
            "version": 1, "default_action": "proxy", "lan": [], "private_networks": [],
            "private_domains": [], "user_rules": rules, "preset_rules": preset_rules
        })
        .to_string(),
    )?;
    installed_fake_dns(
        None,
        HelperLifecycle::Normal,
        Some(&policy),
        Some(if mixed {
            FakeDnsPolicyWitness::ResolvedMixed { guarded_proxy }
        } else {
            FakeDnsPolicyWitness::ResolvedCidrs
        }),
    )
    .await
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum HelperLifecycle {
    Normal,
    Crash(Engine),
    NetworkManagerDhcp(Engine),
    Shutdown(StandaloneService),
}

#[cfg(feature = "test-support")]
fn networkmanager_dhcp_ack_count() -> Result<usize> {
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--boot",
            "--unit=yonik-nm-lease-server.service",
            "--no-pager",
            "--output=cat",
        ])
        .output()?;
    require(output.status.success(), "Журнал DHCP-стенда недоступен")?;
    Ok(std::str::from_utf8(&output.stdout)?
        .lines()
        .filter(|line| line.ends_with("sending ACK to 10.233.53.10"))
        .count())
}

#[cfg(feature = "test-support")]
fn networkmanager_dhcp_worker_pid() -> Result<u32> {
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "--property=MainPID",
            "--value",
            "yonik-worker.service",
        ])
        .output()?;
    require(output.status.success(), "MainPID worker недоступен")?;
    let pid = std::str::from_utf8(&output.stdout)?.trim().parse()?;
    require(pid > 1, "Worker DHCP-стенда завершился")?;
    Ok(pid)
}

#[cfg(feature = "test-support")]
async fn wait_for_networkmanager_dhcp_renewal(initial_acks: usize, worker: u32) -> Result {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(28);
    loop {
        require(
            networkmanager_dhcp_worker_pid()? == worker,
            "Worker сменился во время продления DHCP",
        )?;
        if networkmanager_dhcp_ack_count()? > initial_acks {
            return Ok(());
        }
        require(
            tokio::time::Instant::now() < deadline,
            "Сервер не выдал повторный DHCPACK при активном TUN",
        )?;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum StandaloneService {
    SystemdFixture,
    OpenRc,
    Runit,
}

#[cfg(feature = "test-support")]
impl StandaloneService {
    fn native() -> Result<Self> {
        match fs::read_to_string("/proc/1/comm")?.trim() {
            "openrc-init" => Ok(Self::OpenRc),
            "runit" => Ok(Self::Runit),
            _ => Err(io::Error::other("Стенду нужен OpenRC или runit в PID 1").into()),
        }
    }

    fn init(self) -> &'static str {
        match self {
            Self::SystemdFixture => "systemd",
            Self::OpenRc => "openrc-init",
            Self::Runit => "runit",
        }
    }

    async fn manage(self, start: bool) -> Result {
        let action = if start { "start" } else { "stop" };
        let mut command = match self {
            Self::SystemdFixture => {
                let mut command = tokio::process::Command::new("/usr/bin/systemctl");
                command.args([action, "yonik-standalone-fixture.service"]);
                command
            }
            Self::OpenRc => {
                let mut command = tokio::process::Command::new("/usr/sbin/rc-service");
                command.args(["yonik-helper", action]);
                command
            }
            Self::Runit => {
                let mut command = tokio::process::Command::new("/usr/bin/sv");
                command.args([
                    "-w",
                    "65",
                    if start { "up" } else { "down" },
                    "/etc/sv/yonik-helper",
                ]);
                command
            }
        };
        let status =
            tokio::time::timeout(Duration::from_secs(70), command.kill_on_drop(true).status())
                .await??;
        require(
            status.success(),
            "Штатное управление службой завершилось ошибкой",
        )
    }
}

#[cfg(feature = "test-support")]
async fn installed_fake_dns(
    literal: Option<std::net::SocketAddr>,
    lifecycle: HelperLifecycle,
    policy: Option<&yonik_engine::policy_wire::SystemPolicy>,
    policy_witness: Option<FakeDnsPolicyWitness>,
) -> Result {
    let standalone = match lifecycle {
        HelperLifecycle::Shutdown(service) => Some(service),
        _ => None,
    };
    guard_init(standalone.map_or("systemd", StandaloneService::init))?;
    let _lock = vm_lock::acquire()?;
    wait_for_fixture_link().await?;
    let resolver_before = resolver_file_state()?;
    let connection = zbus::Connection::system().await?;
    let empty = json!({"version":1});
    if standalone.is_some() {
        require(
            call(&connection, "Capabilities", empty.clone()).await?["system_tun"] == true,
            "Автономный helper не объявляет TUN клиенту",
        )?;
        require(
            call(&connection, "NativePrepareEligibilityV1", empty.clone()).await?["can_prepare_attribution"]
                == false,
            "Автономный helper объявил недоступную атрибуцию",
        )?;
        require(
            call(&connection, "BundleCapabilitiesV1", empty.clone()).await?["canonical_fd_transport"]
                == false,
            "Автономный helper объявил недоступный транспорт ресурсов",
        )?;
    }
    let imported = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
    )?;
    let server = yonik_import::ServerIntent::from_server(&imported.servers[0])?;
    // Стенд с сохранённым журналом может повторно использовать тот же пул.
    if std::env::var_os("YONIK_EXPECT_CLEAN_FAKE_DNS_START").is_none() {
        tokio::time::sleep(yonik_linux::fake_service::MAX_FAKE_TTL).await;
    }
    let fallback_dns = std::env::var("YONIK_CHECK_FALLBACK_DNS");
    let opportunistic_dot = std::env::var_os("YONIK_CHECK_OPPORTUNISTIC_DOT").is_some();
    let invalid_fallback_dot = std::env::var_os("YONIK_CHECK_INVALID_FALLBACK_DOT").is_some();
    let strict_dot = std::env::var("YONIK_CHECK_STRICT_DOT")
        .ok()
        .map(|peer| peer.parse::<std::net::SocketAddr>())
        .transpose()?;
    let fallback_search = std::env::var_os("YONIK_CHECK_FALLBACK_SEARCH").is_some();
    let plain_dns_peer = std::env::var("YONIK_CHECK_PLAIN_DNS_PEER")
        .ok()
        .map(|peer| peer.parse::<std::net::SocketAddr>())
        .transpose()?;
    let untrusted_uplink_dot = std::env::var_os("YONIK_CHECK_UNTRUSTED_UPLINK_DOT").is_some();
    let check_unissued = std::env::var_os("YONIK_CHECK_UNISSUED_FAKE_IP").is_some();
    require(
        !untrusted_uplink_dot || plain_dns_peer.is_some(),
        "Проверка доверия DoT требует опубликованный DNS-адрес",
    )?;
    let uplink_split_peer = std::env::var("YONIK_CHECK_UPLINK_SPLIT_PEER")
        .ok()
        .map(|peer| peer.parse::<std::net::SocketAddr>())
        .transpose()?;
    let fallback_engine = match fallback_dns.as_deref() {
        Ok("xray") => Some(Engine::Xray),
        Ok("sing-box") => Some(Engine::SingBox),
        Ok("1") | Err(std::env::VarError::NotPresent) => None,
        _ => return Err(io::Error::other("Неизвестный движок стенда FallbackDNS").into()),
    };
    if let HelperLifecycle::NetworkManagerDhcp(engine) = lifecycle {
        require(
            fallback_engine.is_none_or(|selected| selected == engine),
            "Выбор движка для DHCP и FallbackDNS должен совпадать",
        )?;
    }
    for engine in [Engine::Xray, Engine::SingBox]
        .into_iter()
        .filter(|engine| {
            !matches!(lifecycle, HelperLifecycle::Crash(selected)
                | HelperLifecycle::NetworkManagerDhcp(selected) if *engine != selected)
        })
        .filter(|engine| fallback_engine.is_none_or(|selected| *engine == selected))
    {
        let crash = matches!(lifecycle, HelperLifecycle::Crash(_));
        let kill_switch = engine == Engine::Xray;
        require(
            state_after_route_events(&connection).await?["state"] == "no_managed_policy",
            "VM не чистая",
        )?;
        if fallback_search {
            check_fallback_search_in_vm("printer", true).await?;
        }
        let initial_acks = if matches!(lifecycle, HelperLifecycle::NetworkManagerDhcp(_)) {
            let count = networkmanager_dhcp_ack_count()?;
            require(count == 1, "Стенду нужен свежий лизинг с первым DHCPACK")?;
            Some(count)
        } else {
            None
        };
        let (_owner, token) = yonik_linux::Cancellation::new();
        let drain =
            start_fake_dns_in_vm(&connection, &server, engine, kill_switch, policy, &token).await?;
        let dhcp_worker = if let Some(initial_acks) = initial_acks {
            let worker = networkmanager_dhcp_worker_pid()?;
            require(
                networkmanager_dhcp_ack_count()? == initial_acks,
                "DHCPACK уже получен к началу проверки активного TUN",
            )?;
            Some((initial_acks, worker))
        } else {
            None
        };
        require(
            resolver_file_state()? == resolver_before,
            "Запуск изменил /etc/resolv.conf",
        )?;
        if opportunistic_dot {
            let result = tokio::process::Command::new("/usr/bin/resolvectl")
                .arg("reset-server-features")
                .output()
                .await?;
            require(
                result.status.success(),
                "Не удалось сбросить состояние DoT в resolved",
            )?;
            check_fallback_dns_in_vm("real.test").await?;
            eprintln!("{engine:?}: resolved повторно выбрал транспорт для opportunistic DoT");
        }
        if fallback_dns.is_ok() {
            check_fallback_dns_in_vm("real.test").await?;
            check_fallback_dns_local_names_in_vm().await?;
            eprintln!("{engine:?}: NSS получил реальный ответ от FallbackDNS");
        }
        if let Some(peer) = strict_dot {
            check_fallback_dns_in_vm("real.test").await?;
            check_strict_dot_outsider(peer).await?;
            eprintln!(
                "{engine:?}: NSS получил ответ по строгому DoT, сокет с тем же UID вне cgroup заблокирован"
            );
        }
        if invalid_fallback_dot {
            require(
                getent_fake_dns("ahostsv4", "real.test").await.is_err(),
                "Релей принял недоверенное имя сертификата FallbackDNS",
            )?;
            eprintln!("{engine:?}: релей отклонил неверное имя сертификата FallbackDNS");
        }
        if fallback_search {
            check_fallback_search_in_vm("printer-active", true).await?;
            check_fallback_search_in_vm("only-route.route.test", true).await?;
            check_fallback_search_in_vm("only-route", false).await?;
            eprintln!("{engine:?}: resolved дополнил короткое имя при активном TUN");
        }
        let (v4, v6) = if let Some(peer) = literal {
            let v4 = ask_fixture_dns(peer, "example.test", 1, false).await?;
            let v6 = ask_fixture_dns(peer, "example.test", 28, true).await?;
            for tcp in [false, true] {
                require(
                    ask_fixture_dns(peer, "real.test", 1, tcp).await?
                        == "192.0.2.99".parse::<std::net::IpAddr>()?,
                    "Тестовый real DNS получил неверный ответ",
                )?;
            }
            (v4, v6)
        } else {
            (
                getent_fake_dns("ahostsv4", "example.test").await?,
                getent_fake_dns("ahostsv6", "example.test").await?,
            )
        };
        require(
            v4.is_ipv4() && v6.is_ipv6(),
            "NSS вернул неверные семейства",
        )?;
        if let Some(peer) = plain_dns_peer {
            if untrusted_uplink_dot {
                check_fallback_dns_in_vm("real.test").await?;
            }
            for tcp in [false, true] {
                let real = ask_fixture_dns(peer, "real.test", 1, tcp).await;
                if untrusted_uplink_dot {
                    require(
                        real.is_err(),
                        "Релей принял недоверенный DoT или открыл DNS",
                    )?;
                } else {
                    require(
                        real? == std::net::Ipv4Addr::new(192, 0, 2, 99),
                        "Реальный DNS не ответил на настроенном порту",
                    )?;
                }
                require(
                    ask_fixture_dns(peer, "example.test", 1, tcp).await? == v4,
                    "Синтетический DNS не ответил на настроенном порту",
                )?;
            }
            if untrusted_uplink_dot {
                eprintln!("{engine:?}: строгий DoT отклонил недоверенный сертификат по TCP и UDP");
            } else {
                eprintln!(
                    "{engine:?}: реальный DNS и Fake DNS подтверждены по TCP и UDP на порту {}",
                    peer.port()
                );
            }
        }
        if let Some(peer) = uplink_split_peer {
            let name = match engine {
                Engine::Xray => "xray.private.test",
                Engine::SingBox => "sing-box.private.test",
            };
            require(
                getent_fake_dns("ahostsv4", name).await? == std::net::Ipv4Addr::new(192, 0, 2, 100),
                "NSS не получил ответ от приватного DoT-сервера",
            )?;
            for tcp in [false, true] {
                require(
                    ask_fixture_dns(peer, "example.test", 1, tcp).await.is_err(),
                    "Прямой запрос к неопубликованному split-DNS получил Fake-IP",
                )?;
            }
            eprintln!("{engine:?}: приватный DoT ответил через NSS, прямой DNS закрыт");
        }
        check_tun_traffic_to([(v4, 40000).into(), (v6, 40000).into()]).await?;
        if check_unissued {
            // Стенд запрашивает несколько имён, а аренды выделяются с начала пулов.
            let unissued = [
                "198.19.255.254:40000".parse()?,
                "[fd79:6f69:6b00:5c01::1ffe]:40000".parse()?,
            ];
            check_tun_routes(&unissued)?;
            tokio::try_join!(
                check_fake_flow_blocked(unissued[0]),
                check_fake_flow_blocked(unissued[1]),
            )?;
            eprintln!("{engine:?}: невыданные Fake-IP заблокированы по TCP/UDP IPv4/IPv6");
        }
        if let Some(FakeDnsPolicyWitness::ResolvedMixed {
            guarded_proxy: true,
        }) = &policy_witness
        {
            for database in ["ahostsv4", "ahostsv6"] {
                let guarded = getent_fake_dns(database, "guarded.example.test").await?;
                check_fake_flow_blocked((guarded, 40000).into()).await?;
            }
            let early_v4 = getent_fake_dns("ahostsv4", "early.example.test").await?;
            let early_v6 = getent_fake_dns("ahostsv6", "early.example.test").await?;
            check_tun_traffic_to([(early_v4, 40000).into(), (early_v6, 40000).into()]).await?;
        } else if let Some(witness) = &policy_witness {
            let mut blocked_names = vec!["blocked.example.test"];
            if matches!(
                witness,
                FakeDnsPolicyWitness::ResolvedCidrs | FakeDnsPolicyWitness::ResolvedMixed { .. }
            ) {
                blocked_names.push("failed.example.test");
            }
            if matches!(witness, FakeDnsPolicyWitness::ResolvedMixed { .. }) {
                blocked_names.push("combined.example.test");
            }
            for name in blocked_names {
                for database in ["ahostsv4", "ahostsv6"] {
                    let blocked = getent_fake_dns(database, name).await?;
                    check_fake_flow_blocked((blocked, 40000).into()).await?;
                }
            }
            match witness {
                FakeDnsPolicyWitness::ResolvedCidrs
                | FakeDnsPolicyWitness::ResolvedMixed { .. } => {
                    let direct_v4 = getent_fake_dns("ahostsv4", "direct.example.test").await?;
                    let direct_v6 = getent_fake_dns("ahostsv6", "direct.example.test").await?;
                    check_tun_traffic_to([(direct_v4, 40000).into(), (direct_v6, 40000).into()])
                        .await?;
                    eprintln!(
                        "{engine:?}: полученные по DNS адреса проверены по CIDR на TCP и UDP"
                    );
                    if matches!(witness, FakeDnsPolicyWitness::ResolvedMixed { .. }) {
                        let early_v4 = getent_fake_dns("ahostsv4", "early.example.test").await?;
                        let early_v6 = getent_fake_dns("ahostsv6", "early.example.test").await?;
                        check_tun_traffic_to([(early_v4, 40000).into(), (early_v6, 40000).into()])
                            .await?;
                        let nodata_v4 = getent_fake_dns("ahostsv4", "nodata.example.test").await?;
                        let nodata_v6 = getent_fake_dns("ahostsv6", "nodata.example.test").await?;
                        check_tun_traffic_to([
                            (nodata_v4, 40000).into(),
                            (nodata_v6, 40000).into(),
                        ])
                        .await?;
                        check_tun_traffic_to([
                            "203.0.113.50:40000".parse()?,
                            "[2001:db8:746f::2]:40000".parse()?,
                        ])
                        .await?;
                        let mixed_v4 =
                            getent_fake_dns("ahostsv4", "mixed-direct.example.test").await?;
                        let mixed_v6 =
                            getent_fake_dns("ahostsv6", "mixed-direct.example.test").await?;
                        check_tun_traffic_to([(mixed_v4, 40000).into(), (mixed_v6, 40000).into()])
                            .await?;
                        let literal = "192.0.2.202:40000".parse()?;
                        check_tun_routes(&[literal])?;
                        check_fake_flow_blocked(literal).await?;
                        eprintln!(
                            "{engine:?}: смешанные правила проверены по Fake-IP и буквальному IP"
                        );
                    }
                }
                FakeDnsPolicyWitness::Domains => {}
                FakeDnsPolicyWitness::LiteralBlock => {
                    check_literal_cidr_traffic(false).await?;
                    eprintln!("{engine:?} CIDR Block подтверждён по TCP/UDP IPv4/IPv6");
                }
                FakeDnsPolicyWitness::LiteralProxy => {
                    check_literal_cidr_traffic(true).await?;
                    eprintln!("{engine:?} CIDR Proxy пропустил те же IPv4/IPv6 по TCP/UDP");
                }
                FakeDnsPolicyWitness::LiteralDirect => {
                    check_literal_cidr_traffic(false).await?;
                    check_literal_direct_traffic().await?;
                    eprintln!("{engine:?} CIDR Direct подтверждён по TCP/UDP IPv4/IPv6");
                }
            }
            eprintln!(
                "{engine:?} Fake DNS: разрешённые и заблокированные запросы проверены по TCP и UDP"
            );
        }
        if let Some(certificate) = std::env::var_os("YONIK_FAKE_DNS_TLS_CA") {
            check_https_through_tun(&certificate, literal.map(|_| v4)).await?;
        }
        let restarted_at = if let Some(service) = standalone {
            stop_standalone_fixture(service, v4, v6, kill_switch).await?;
            wait_for_helper_name(&connection).await?;
            eprintln!("{engine:?}: служба очистила сеть и остановила worker до перезапуска");
            Some(tokio::time::Instant::now())
        } else {
            None
        };
        if crash {
            let expected_state = if kill_switch {
                "recovery_required"
            } else {
                "no_managed_policy"
            };
            kill_helper_and_wait_for_recovery(&connection, helper_pid()?, expected_state).await?;
            if !kill_switch {
                check_only_fake_is_filtered(v4, v6).await?;
            }
            if matches!(policy_witness, Some(FakeDnsPolicyWitness::LiteralDirect)) {
                require(
                    literal_direct_rule_marks()?.is_empty(),
                    "Разрешение Direct пережило аварийное восстановление",
                )?;
            }
        }
        let dhcp_renewal = if let Some((initial_acks, worker)) = dhcp_worker {
            wait_for_networkmanager_dhcp_renewal(initial_acks, worker).await
        } else {
            Ok(())
        };
        let stopped = call(&connection, "Stop", empty.clone()).await?;
        require(
            if kill_switch {
                stopped["state"] == "recovery_required" || stopped["state"] == "verified_rules"
            } else {
                stopped["state"] == "no_managed_policy"
            },
            "Stop не выполнил выбранную политику kill switch",
        )?;
        require(
            tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?,
            "Вывод worker не закрыт",
        )?;
        if matches!(policy_witness, Some(FakeDnsPolicyWitness::LiteralDirect)) {
            require(
                literal_direct_rule_marks()?.is_empty(),
                "Разрешение Direct пережило Stop",
            )?;
        }
        let mut cancel = token;
        let snapshot =
            yonik_linux::read_resolve1_snapshot(&mut cancel, Duration::from_secs(3)).await?;
        require(
            !snapshot
                .domains
                .iter()
                .any(|domain| domain.name == "example.test"),
            "Домен DNS пережил удаление TUN",
        )?;
        if kill_switch {
            call(&connection, "Unlock", empty.clone()).await?;
        }
        if fallback_dns.is_ok() {
            check_fallback_dns_in_vm("restored.test").await?;
            eprintln!("{engine:?}: NSS получил ответ от FallbackDNS после остановки");
        }
        if strict_dot.is_some() {
            check_fallback_dns_in_vm("restored.test").await?;
            eprintln!("{engine:?}: исходный DoT работает после остановки");
        }
        if fallback_search {
            check_fallback_search_in_vm("printer-restored", true).await?;
            eprintln!("{engine:?}: исходный поисковый домен работает после Stop");
        }
        if matches!(policy_witness, Some(FakeDnsPolicyWitness::LiteralDirect)) {
            check_tun_traffic_to(connected_direct_fixture()?).await?;
        }
        check_only_fake_is_filtered(v4, v6).await?;
        if crash {
            wait_for_quarantine_expiry().await?;
        } else if literal.is_none() && kill_switch {
            check_quarantine_after_firewall_reload(v4, v6).await?;
        }
        require(
            resolver_file_state()? == resolver_before,
            "Остановка изменила /etc/resolv.conf",
        )?;
        dhcp_renewal?;
        eprintln!(
            "{engine:?} установленный helper, системный DNS, TCP/UDP IPv4/IPv6 и восстановление подтверждены"
        );
        if let Some(restarted_at) =
            restarted_at.filter(|_| kill_switch && fallback_engine.is_none())
        {
            // Новый helper выдерживает максимальный TTL перед повторной выдачей Fake-IP.
            tokio::time::sleep_until(restarted_at + yonik_linux::fake_service::MAX_FAKE_TTL).await;
        }
    }
    Ok(())
}

#[cfg(feature = "test-support")]
async fn stop_standalone_fixture(
    service: StandaloneService,
    v4: std::net::IpAddr,
    v6: std::net::IpAddr,
    kill_switch: bool,
) -> Result {
    let tun_links = || -> Result<Vec<Value>> {
        let output = Command::new("/usr/sbin/ip")
            .args(["-j", "link", "show", "type", "tun"])
            .output()?;
        require(output.status.success(), "Не прочитаны интерфейсы TUN")?;
        Ok(serde_json::from_slice(&output.stdout)?)
    };
    require(tun_links()?.len() == 1, "Нет единственного TUN стенда")?;
    service.manage(false).await?;
    for role in ["check", "run"] {
        let events = fs::read_to_string(format!(
            "/sys/fs/cgroup/yonik-worker-standalone/{role}/cgroup.events"
        ))?;
        require(
            events.lines().any(|line| line == "populated 0"),
            "После остановки helper в cgroup остался worker",
        )?;
    }
    require(
        tun_links()?.is_empty(),
        "TUN остался после остановки helper",
    )?;
    require(
        quarantine_table_name(nft_test_binary())?.is_some(),
        "Остановка службы сняла карантин Fake-IP",
    )?;
    if kill_switch {
        require(
            !matches!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::net::TcpStream::connect("10.203.0.2:24443"),
                )
                .await,
                Ok(Ok(_))
            ),
            "После остановки helper отключился kill switch",
        )?;
    } else {
        check_only_fake_is_filtered(v4, v6).await?;
    }
    service.manage(true).await
}

#[cfg(feature = "test-support")]
async fn wait_for_helper_name(connection: &zbus::Connection) -> Result {
    let bus = zbus::fdo::DBusProxy::new(connection).await?;
    let name = zbus::names::BusName::try_from(SERVICE_NAME)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !bus.name_has_owner(name.clone()).await? {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<(), zbus::fdo::Error>(())
    })
    .await??;
    Ok(())
}

#[cfg(feature = "test-support")]
async fn check_fallback_search_in_vm(name: &str, expected: bool) -> Result {
    let output = tokio::time::timeout(
        Duration::from_secs(6),
        tokio::process::Command::new("/usr/bin/resolvectl")
            .args(["-4", "--protocol=dns", "--cache=no", "query", name])
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    let matched = std::str::from_utf8(&output.stdout)?
        .split_whitespace()
        .any(|field| field == "192.0.2.99");
    require(
        output.status.success() == expected && matched == expected,
        "Resolved изменил правила поиска имени или маршрутного домена",
    )
}

#[cfg(feature = "test-support")]
async fn check_fallback_dns_in_vm(domain: &str) -> Result {
    require(
        getent_fake_dns("ahostsv4", domain).await? == std::net::Ipv4Addr::new(192, 0, 2, 99),
        "NSS не получил реальный ответ от резервного DNS",
    )
}

#[cfg(feature = "test-support")]
async fn check_strict_dot_outsider(peer: std::net::SocketAddr) -> Result {
    let process = Command::new("systemctl")
        .args([
            "show",
            "--property=MainPID",
            "--value",
            "systemd-resolved.service",
        ])
        .output()?;
    require(
        process.status.success(),
        "Не удалось определить PID резолвера",
    )?;
    let pid = std::str::from_utf8(&process.stdout)?
        .trim()
        .parse::<u32>()?;
    require(pid > 1, "Некорректный PID резолвера")?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let credential = |key| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .and_then(|value| value.parse::<std::num::NonZeroU32>().ok())
            .ok_or_else(|| io::Error::other("Некорректные credentials резолвера"))
    };
    let uid = credential("Uid:")?.to_string();
    let gid = credential("Gid:")?.to_string();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("setpriv")
            .args([
                "--reuid",
                &uid,
                "--regid",
                &gid,
                "--clear-groups",
                "timeout",
                "2",
                "openssl",
                "s_client",
                "-brief",
                "-connect",
                &peer.to_string(),
            ])
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    require(
        result.status.code() == Some(124),
        "Соединение с UID резолвера вне его cgroup не заблокировано",
    )
}

#[cfg(feature = "test-support")]
async fn check_fallback_dns_local_names_in_vm() -> Result {
    for name in ["yonik-private-witness.local", "169.254.99.98"] {
        let output = tokio::time::timeout(
            Duration::from_secs(6),
            tokio::process::Command::new("/usr/bin/resolvectl")
                .args(["--protocol=dns", "query", name])
                .kill_on_drop(true)
                .output(),
        )
        .await??;
        require(
            !output.status.success(),
            "Локальное имя разрешилось по unicast DNS",
        )?;
    }
    Ok(())
}

#[cfg(feature = "test-support")]
async fn start_fake_dns_in_vm(
    connection: &zbus::Connection,
    server: &yonik_import::ServerIntent,
    engine: Engine,
    kill_switch: bool,
    policy: Option<&yonik_engine::policy_wire::SystemPolicy>,
    token: &yonik_linux::Cancellation,
) -> Result<OutputDrain> {
    start_fake_dns_in_vm_with_domains(
        connection,
        server,
        engine,
        kill_switch,
        policy,
        token,
        &["example.test".to_owned()],
    )
    .await
}

#[cfg(feature = "test-support")]
async fn start_fake_dns_in_vm_with_domains(
    connection: &zbus::Connection,
    server: &yonik_import::ServerIntent,
    engine: Engine,
    kill_switch: bool,
    policy: Option<&yonik_engine::policy_wire::SystemPolicy>,
    token: &yonik_linux::Cancellation,
    domains: &[String],
) -> Result<OutputDrain> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let retry_until = deadline - Duration::from_secs(8);
    let mut client =
        SystemClient::on_connection(connection.clone(), deadline, token.clone()).await?;
    let policy_resolver = policy
        .and_then(|_| std::env::var("YONIK_CHECK_FAKE_DNS_POLICY_RESOLVER").ok())
        .map(|address| address.parse::<std::net::SocketAddr>())
        .transpose()?;
    let prepared = loop {
        let result = if let Some(policy) = policy {
            client
                .prepare_fake_dns_policy_profile_with_resolver(
                    server,
                    engine,
                    kill_switch,
                    domains,
                    policy,
                    policy_resolver,
                    deadline,
                    token.clone(),
                )
                .await
        } else {
            client
                .prepare_fake_dns_profile(
                    server,
                    engine,
                    kill_switch,
                    domains,
                    deadline,
                    token.clone(),
                )
                .await
        };
        let now = tokio::time::Instant::now();
        if !matches!(result, Err(yonik_linux::system_client::ClientError::Busy))
            || now >= retry_until
        {
            break result;
        }
        // После restart helper выдерживает MAX_FAKE_TTL предыдущей сессии.
        tokio::time::sleep_until(retry_until.min(now + Duration::from_millis(250))).await;
    }
    .map_err(|error| io::Error::other(format!("{engine:?} Fake DNS Prepare: {error:?}")))?;
    let output = PreparedOutput::bind(
        prepared,
        engine,
        &yonik_linux::event_log::EventLog::new(),
        1,
    )?;
    let (state, drain) = client.apply_output(output, deadline, token.clone()).await;
    require(
        state.map_err(|error| {
            io::Error::other(format!("{engine:?} Fake DNS ApplyOutputV1: {error:?}"))
        })? == State::TunnelStarting,
        "Сессия Fake DNS не запущена",
    )?;
    Ok(drain.ok_or_else(|| io::Error::other("Нет потока вывода ядра"))?)
}

#[cfg(feature = "test-support")]
async fn check_literal_cidr_traffic(proxy: bool) -> Result {
    let servers = [
        "198.18.0.2:40000".parse::<std::net::SocketAddr>()?,
        "[2001:db8:746f::2]:40000".parse()?,
    ];
    check_tun_routes(&servers)?;
    if proxy {
        return check_tun_traffic_to(servers).await;
    }
    for server in servers {
        check_fake_flow_blocked(server).await?;
    }
    Ok(())
}

#[cfg(feature = "test-support")]
fn check_tun_routes(servers: &[std::net::SocketAddr]) -> Result {
    for server in servers {
        let address = server.ip().to_string();
        let route = Command::new("/usr/bin/ip")
            .args(["-j", "route", "get", &address])
            .output()?;
        require(
            route.status.success(),
            "Не удалось получить маршрут к контрольному IP",
        )?;
        let routes: Value = serde_json::from_slice(&route.stdout)?;
        require(
            routes[0]["dev"]
                .as_str()
                .is_some_and(|dev| dev.starts_with("tofu")),
            "Трафик контрольного IP не дошёл бы до TUN",
        )?;
    }
    Ok(())
}

#[cfg(feature = "test-support")]
fn literal_direct_rule_marks() -> Result<Vec<u64>> {
    let output = Command::new(nft_test_binary())
        .args(["-j", "list", "ruleset"])
        .output()?;
    require(
        output.status.success(),
        "Не удалось прочитать установленные правила",
    )?;
    let ruleset: Value = serde_json::from_slice(&output.stdout)?;
    let rules = ruleset["nftables"]
        .as_array()
        .ok_or_else(|| io::Error::other("Нет правил nft"))?;
    Ok(rules
        .iter()
        .filter_map(|entry| {
            let conditions = entry["rule"]["expr"].as_array()?;
            let direct = conditions.iter().any(|condition| {
                matches!(
                    condition
                        .pointer("/match/right/prefix/addr")
                        .and_then(Value::as_str),
                    Some("192.0.2.192" | "2001:db8:7471::")
                )
            });
            if !direct {
                return None;
            }
            conditions.iter().find_map(|condition| {
                (condition.pointer("/match/left/meta/key")?.as_str()? == "mark")
                    .then(|| condition.pointer("/match/right")?.as_u64())
                    .flatten()
            })
        })
        .collect())
}

#[cfg(feature = "test-support")]
async fn check_literal_direct_traffic() -> Result {
    let servers = [
        "192.0.2.201:40000".parse()?,
        "[2001:db8:7471::2]:40000".parse()?,
    ];
    let marks = literal_direct_rule_marks()?;
    let mark = marks
        .first()
        .ok_or_else(|| io::Error::other("Нет разрешений Direct"))?;
    require(
        marks.len() >= 4 && marks.iter().all(|observed| observed == mark),
        "Нет общей метки для TCP/UDP и обоих семейств",
    )?;
    check_tun_routes(&servers)?;
    check_tun_traffic_to(servers).await?;
    let connected = connected_direct_fixture()?;
    check_tun_routes(&connected)?;
    for server in connected {
        check_fake_flow_blocked(server).await?;
    }
    let status = Command::new("/usr/bin/python3")
        .args([
            "-c",
            r#"
import errno
import socket
import sys

for family, address in [(socket.AF_INET, '192.0.2.201'), (socket.AF_INET6, '2001:db8:7471::2')]:
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, int(sys.argv[1]))
        try:
            client.sendto(b'wrong-uid', (address, 40000))
        except OSError as error:
            if error.errno != errno.EPERM:
                raise
        else:
            raise RuntimeError('Правило Direct пропустило сокет другого UID')
"#,
            &mark.to_string(),
        ])
        .status()?;
    require(
        status.success(),
        "Метка Direct без UID worker не должна пропускать трафик",
    )
}

#[cfg(feature = "test-support")]
fn connected_direct_fixture() -> Result<[std::net::SocketAddr; 2]> {
    Ok([
        "192.0.2.202:40000".parse()?,
        "[2001:db8:7471::3]:40000".parse()?,
    ])
}

#[cfg(feature = "test-support")]
async fn state_after_route_events(connection: &zbus::Connection) -> Result<Value> {
    state_after_route_events_with_timeout(connection, Duration::from_secs(3)).await
}

#[cfg(feature = "test-support")]
async fn state_after_route_events_with_timeout(
    connection: &zbus::Connection,
    timeout: Duration,
) -> Result<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let result =
            tokio::time::timeout_at(deadline, call(connection, "State", json!({"version":1})))
                .await?;
        if !matches!(
            result.as_ref().err().and_then(|error| error.downcast_ref::<zbus::Error>()),
            Some(zbus::Error::MethodError(_, Some(body), _))
                if serde_json::from_str::<Value>(body).is_ok_and(|body| body["error"] == "busy")
        ) || tokio::time::Instant::now() >= deadline
        {
            return result;
        }
        tokio::time::sleep_until(
            deadline.min(tokio::time::Instant::now() + Duration::from_millis(50)),
        )
        .await;
    }
}

#[cfg(feature = "test-support")]
async fn check_https_through_tun(
    certificate: &std::ffi::OsStr,
    fake_ip: Option<std::net::IpAddr>,
) -> Result {
    let certificate = reqwest::Certificate::from_pem(&fs::read(certificate)?)?;
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .add_root_certificate(certificate);
    if let Some(ip) = fake_ip {
        builder = builder.resolve("example.test", (ip, 443).into());
    }
    let doh_ip = "203.0.113.45:443".parse()?;
    let client = builder.resolve("doh.test", doh_ip).build()?;
    require(
        client
            .get("https://example.test/")
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .as_ref()
            == b"YONIK_TLS_FIXTURE",
        "Системный Fake-IP не доставил HTTPS с проверкой сертификата",
    )?;
    eprintln!("HTTPS с проверкой имени сертификата прошёл через Fake-IP");

    let query =
        b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04real\x04test\x00\x00\x01\x00\x01";
    let response = client
        .post("https://doh.test/dns-query")
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .body(query.as_slice())
        .send()
        .await?
        .error_for_status()?;
    require(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            == Some("application/dns-message"),
        "Контрольный DoH вернул неожиданный Content-Type",
    )?;
    let answer = response.bytes().await?;
    require(
        answer.len() == query.len() + 16
            && answer[0..12] == b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"[..]
            && answer[12..query.len()] == query[12..]
            && answer.ends_with(&[192, 0, 2, 99]),
        "Встроенный DoH не получил реальный ответ через HTTPS",
    )?;
    eprintln!("Контрольный DoH прошёл через TUN и вернул реальный адрес");
    Ok(())
}

#[cfg(feature = "test-support")]
fn nft_test_binary() -> &'static str {
    if std::path::Path::new("/usr/bin/nft").is_file() {
        "/usr/bin/nft"
    } else {
        "/usr/sbin/nft"
    }
}

#[cfg(feature = "test-support")]
fn quarantine_table_name(nft: &str) -> Result<Option<String>> {
    let output = Command::new(nft).args(["-j", "list", "tables"]).output()?;
    require(output.status.success(), "Не прочитан список таблиц nft")?;
    let document: Value = serde_json::from_slice(&output.stdout)?;
    let tables = document["nftables"]
        .as_array()
        .ok_or_else(|| io::Error::other("Не получен список nft таблиц"))?;
    let mut owned = tables.iter().filter_map(|entry| {
        let table = &entry["table"];
        let name = table["name"].as_str()?;
        (table["family"] == "inet" && name.starts_with("yonik_q")).then_some(name)
    });
    let table = owned.next().map(str::to_owned);
    require(
        owned.next().is_none(),
        "Найдено более одной таблицы Fake-IP",
    )?;
    Ok(table)
}

#[cfg(feature = "test-support")]
async fn wait_for_quarantine_expiry() -> Result {
    let nft = nft_test_binary();
    require(
        quarantine_table_name(nft)?.is_some(),
        "После аварийного восстановления таблица Fake-IP должна действовать",
    )?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(100);
    loop {
        if quarantine_table_name(nft)?.is_none() {
            eprintln!("Таблица защиты Fake-IP снята после истечения срока в ядре");
            return Ok(());
        }
        require(
            tokio::time::Instant::now() < deadline,
            "Таблица Fake-IP осталась после истечения срока",
        )?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(feature = "test-support")]
async fn check_quarantine_after_firewall_reload(
    v4: std::net::IpAddr,
    v6: std::net::IpAddr,
) -> Result {
    let nft = nft_test_binary();
    let table =
        quarantine_table_name(nft)?.ok_or_else(|| io::Error::other("Нет таблицы Fake-IP"))?;
    require(
        Command::new(nft)
            .args(["delete", "table", "inet", &table])
            .status()?
            .success(),
        "Не воспроизведена потеря таблицы Fake-IP",
    )?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if Command::new(nft)
            .args(["-j", "list", "table", "inet", &table])
            .output()?
            .status
            .success()
        {
            break;
        }
        require(
            tokio::time::Instant::now() < deadline,
            "Таблица Fake-IP не восстановилась",
        )?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    check_only_fake_is_filtered(v4, v6).await?;
    eprintln!("Защита выданных Fake-IP восстановилась после исчезновения таблицы nft");
    Ok(())
}

#[cfg(feature = "test-support")]
#[derive(PartialEq, Eq)]
struct ResolverFileState {
    link: Option<std::path::PathBuf>,
    entry: [u64; 5],
    target: [u64; 5],
    contents: Vec<u8>,
}

#[cfg(feature = "test-support")]
fn resolver_file_state() -> Result<ResolverFileState> {
    fn identity(metadata: &fs::Metadata, track_inode: bool) -> [u64; 5] {
        [
            metadata.dev(),
            if track_inode { metadata.ino() } else { 0 },
            u64::from(metadata.mode()),
            u64::from(metadata.uid()),
            u64::from(metadata.gid()),
        ]
    }

    let path = "/etc/resolv.conf";
    let entry = fs::symlink_metadata(path)?;
    let link = entry
        .is_symlink()
        .then(|| fs::read_link(path))
        .transpose()?;
    // После снятия DNS с TUN systemd-resolved может атомарно заменить свой
    // uplink-файл. Сравниваем саму ссылку, содержимое и права файла.
    let track_target_inode =
        yonik_linux::inspect_host_resolv_conf() != yonik_linux::ResolvConfLayout::ResolvedUplink;
    Ok(ResolverFileState {
        link,
        entry: identity(&entry, true),
        target: identity(&fs::metadata(path)?, track_target_inode),
        contents: fs::read(path)?,
    })
}

#[cfg(feature = "test-support")]
async fn ask_fixture_dns(
    peer: std::net::SocketAddr,
    name: &str,
    qtype: u8,
    tcp: bool,
) -> Result<std::net::IpAddr> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
    };
    let mut query = b"\x22\x57\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00".to_vec();
    for label in name.split('.') {
        query.push(u8::try_from(label.len())?);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, qtype, 0, 1]);
    let mut reply = [0; 512];
    let count = tokio::time::timeout(Duration::from_secs(6), async {
        if tcp {
            let mut socket = TcpStream::connect(peer).await?;
            socket.write_u16(query.len() as u16).await?;
            socket.write_all(&query).await?;
            let size = usize::from(socket.read_u16().await?);
            if size > reply.len() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            socket.read_exact(&mut reply[..size]).await?;
            Ok(size)
        } else {
            let bind = if peer.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(peer).await?;
            socket.send(&query).await?;
            socket.recv(&mut reply).await
        }
    })
    .await??;
    let width = if qtype == 1 { 4 } else { 16 };
    require(
        count == query.len() + 12 + width
            && reply[..2] == query[..2]
            && reply[3] & 0xf == 0
            && reply[6..8] == [0, 1]
            && reply[12..query.len()] == query[12..],
        "Тестовый DNS вернул ответ с другими полями",
    )?;
    let data = &reply[count - width..count];
    if width == 4 {
        Ok(<[u8; 4]>::try_from(data)?.into())
    } else {
        Ok(<[u8; 16]>::try_from(data)?.into())
    }
}

#[cfg(feature = "test-support")]
async fn check_only_fake_is_filtered(v4: std::net::IpAddr, v6: std::net::IpAddr) -> Result {
    use tokio::net::{TcpStream, UdpSocket};

    // Обычный маршрут до соседа снова работает сразу после Stop/Unlock.
    tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect("10.203.0.2:24443"),
    )
    .await??;
    let ip = if std::path::Path::new("/usr/bin/ip").is_file() {
        "/usr/bin/ip"
    } else {
        "/usr/sbin/ip"
    };
    for (address, family, bind, length) in [(v4, "-4", "0.0.0.0:0", 32), (v6, "-6", "[::]:0", 128)]
    {
        let prefix = format!("{address}/{length}");
        // В отдельной VM намеренно создаём физический маршрут к старому адресу.
        require(
            Command::new(ip)
                .args([family, "route", "add", &prefix, "dev", "yonik-outer"])
                .status()?
                .success(),
            "Не создан контрольный физический маршрут",
        )?;
        let result = async {
            let socket = UdpSocket::bind(bind).await?;
            socket.send_to(b"old-fake", (address, 40_000)).await
        }
        .await;
        require(
            Command::new(ip)
                .args([family, "route", "del", &prefix, "dev", "yonik-outer"])
                .status()?
                .success(),
            "Не снят контрольный физический маршрут",
        )?;
        require(
            result.is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied),
            "Старый Fake-IP не заблокирован для физического выхода",
        )?;
    }
    Ok(())
}

#[cfg(feature = "test-support")]
async fn getent_fake_dns(database: &str, domain: &str) -> Result<std::net::IpAddr> {
    let output = tokio::time::timeout(
        Duration::from_secs(6),
        tokio::process::Command::new("/usr/bin/setpriv")
            .args([
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "/usr/bin/getent",
                database,
                domain,
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    require(
        output.status.success(),
        "NSS от имени обычного UID завершился ошибкой",
    )?;
    let output = std::str::from_utf8(&output.stdout)?;
    let first = output
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::other("Пустой ответ NSS"))?;
    Ok(first.parse()?)
}

#[cfg(feature = "test-support")]
async fn check_fake_flow_blocked(server: std::net::SocketAddr) -> Result {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
    };

    let tcp = async {
        let mut stream = TcpStream::connect(server).await?;
        stream.write_all(&[0x6d; ECHO_PAYLOAD_BYTES]).await?;
        stream.read(&mut [0; 64]).await
    };
    let udp = async {
        let socket = UdpSocket::bind(if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        socket.connect(server).await?;
        socket.send(&[0x6d; ECHO_PAYLOAD_BYTES]).await?;
        socket.recv(&mut [0; 64]).await
    };
    let bound = Duration::from_secs(2);
    let (tcp, udp) = tokio::join!(
        tokio::time::timeout(bound, tcp),
        tokio::time::timeout(bound, udp)
    );
    require(
        !matches!(tcp, Ok(Ok(bytes)) if bytes > 0),
        "Block пропустил TCP к контрольному адресу",
    )?;
    require(
        !matches!(udp, Ok(Ok(_))),
        "Block пропустил UDP к контрольному адресу",
    )
}

async fn start_with_output(
    connection: &zbus::Connection,
    engine: Engine,
    server: &yonik_import::ServerIntent,
) -> Result<OutputDrain> {
    let (_owner, cancel) = yonik_linux::Cancellation::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut client =
        SystemClient::on_connection(connection.clone(), deadline, cancel.clone()).await?;
    let prepared = client
        .prepare_profile(server, engine, true, deadline, cancel.clone())
        .await?;
    let output = PreparedOutput::bind(
        prepared,
        engine,
        &yonik_linux::event_log::EventLog::new(),
        1,
    )?;
    let (state, drain) = client.apply_output(output, deadline, cancel).await;
    require(
        state? == State::TunnelStarting,
        "ApplyOutputV1 не запустил TUN",
    )?;
    drain.ok_or_else(|| io::Error::other("Не получен поток вывода системного ядра").into())
}

async fn lifecycle(engine: Option<Engine>, with_output: bool) -> Result {
    guard()?;
    require(
        rustix::process::geteuid().is_root(),
        "Требуется VM root controller",
    )?;
    let _lock = vm_lock::acquire()?;
    let profile = engine.is_some();
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
    let server = if profile {
        let imported = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@10.203.0.2:24443?security=none".to_vec(),
        )?;
        Some(yonik_import::ServerIntent::from_server(
            &imported.servers[0],
        )?)
    } else {
        None
    };
    let drain = match (engine, server, with_output) {
        (Some(engine), Some(server), true) => {
            Some(start_with_output(&connection, engine, &server).await?)
        }
        (engine, server, false) => {
            let prepare = if let (Some(engine), Some(server)) = (engine, server) {
                let engine = match engine {
                    Engine::Xray => "xray",
                    Engine::SingBox => "sing-box",
                };
                json!({"version":1,"mode":"system_profile","engine":engine,"kill_switch":true,"server":server})
            } else {
                json!({"version":1,"mode":"public_protection","allow_lan":false})
            };
            let prepared = call(&connection, "Prepare", prepare).await?;
            require(
                prepared["handle"].as_array().is_some_and(|v| v.len() == 32),
                "Неверный handle",
            )?;
            let actual = call(
                &connection,
                "Apply",
                json!({"version":1,"handle":prepared["handle"]}),
            )
            .await?;
            let expected = if profile {
                "tunnel_starting"
            } else {
                "verified_rules"
            };
            require(actual["state"] == expected, "Apply не подтвердил policy")?;
            None
        }
        _ => return Err(io::Error::other("Нет профиля для ApplyOutputV1").into()),
    };
    if !profile {
        require(
            call(&connection, "Stop", empty.clone()).await?["state"] == "verified_rules",
            "Stop снял защиту",
        )?;
    }
    if profile {
        check_tun_traffic().await?;
        require(
            !fs::read_to_string("/sys/fs/cgroup/system.slice/yonik-worker.service/cgroup.procs")?
                .trim()
                .is_empty(),
            "Worker не работает перед SIGKILL",
        )?;
    }
    kill_helper_and_wait_for_recovery(&connection, original_pid, "recovery_required").await?;
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
    if let Some(drain) = drain {
        let drained = tokio::time::timeout(Duration::from_secs(3), drain.drained()).await?;
        require(drained, "Чтение вывода worker не завершилось")?;
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
