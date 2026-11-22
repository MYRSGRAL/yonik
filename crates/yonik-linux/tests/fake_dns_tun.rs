//! Сквозная проверка DNS wire → TUN → Fake-IP → SOCKS → VLESS → TCP/UDP echo.
//! Запуск разрешён в одноразовом network namespace либо в выделенной QEMU.
#![cfg(target_os = "linux")]

use std::{
    env,
    fs::OpenOptions,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU16,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};
use yonik_engine::{
    Engine, SystemFakeDnsBridge, SystemTun, compile_system_fake_dns_bridge,
    fake_dns::{DnsEpoch, FakeIpLeaseTable},
};
use yonik_linux::{
    Cancellation,
    fake_flow::WorkerOnlyLoopbackIsolation,
    fake_service::{FakeDnsBridgeListeners, FakeDnsLeases, MAX_FAKE_TTL},
};

const DNS_MARKER: &str = "198.18.0.2:53";
const VLESS_SERVER: &str = "10.254.247.2:24443";
const ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const DOMAIN: &str = "example.test";
const ECHO_PORT: u16 = 24081;
const LIMIT: Duration = Duration::from_secs(5);
const TUN_NAME: &str = "tofu00000001";
const TUN_ALIAS: &str = "yonik-fake-dns-tun-test";
const SERVICE_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 79, 55, 1);

struct Core(Child);

impl Core {
    fn start(binary: &Path, config: &Path) -> Self {
        let log = std::fs::File::create(config.with_extension("log")).unwrap();
        Self(
            Command::new(binary)
                .args(["run", "-c"])
                .arg(config)
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        )
    }

    async fn wait_for(&mut self, address: &str) {
        timeout(LIMIT, async {
            loop {
                assert!(self.0.try_wait().unwrap().is_none(), "Ядро завершилось");
                if TcpStream::connect(address).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("Ядро не начало принимать соединения");
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn env_path(name: &str) -> PathBuf {
    env::var_os(name).expect(name).into()
}

struct TunFixture;

impl TunFixture {
    fn create(engine: Engine) -> Self {
        let mut args = vec!["tuntap", "add", "dev", TUN_NAME, "mode", "tun"];
        if engine == Engine::Xray {
            args.push("vnet_hdr");
        }
        ip(&args);
        ip(&["link", "set", "dev", TUN_NAME, "alias", TUN_ALIAS]);
        let fixture = Self;
        ip(&["addr", "add", "198.18.0.1/30", "dev", TUN_NAME]);
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:746f::1/126",
            "dev",
            TUN_NAME,
            "nodad",
        ]);
        ip(&["link", "set", TUN_NAME, "up"]);
        ip(&["route", "add", "198.19.0.0/24", "dev", TUN_NAME]);
        ip(&["-6", "route", "add", "fd2b:746f:1::/64", "dev", TUN_NAME]);
        fixture
    }
}

impl Drop for TunFixture {
    fn drop(&mut self) {
        let output = ip_command()
            .args(["-j", "link", "show", "dev", TUN_NAME])
            .output()
            .unwrap();
        if output.status.success() {
            let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            if actual[0]["ifalias"] == TUN_ALIAS {
                ip(&["link", "delete", "dev", TUN_NAME]);
            }
        }
    }
}

fn ip_command() -> Command {
    for path in ["/usr/bin/ip", "/usr/sbin/ip"] {
        if Path::new(path).is_file() {
            return Command::new(path);
        }
    }
    panic!("iproute2 недоступен");
}

fn ip(args: &[&str]) {
    let result = ip_command().args(args).output().unwrap();
    assert!(
        result.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn verify_gate() {
    let current = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
    if let Some(parent) = env::var_os("YONIK_FAKE_TUN_PARENT_NETNS") {
        assert_ne!(current.as_os_str(), parent);
        assert!(parent.to_string_lossy().starts_with("net:["));
        let links = ip_command().args(["-j", "link", "show"]).output().unwrap();
        assert!(links.status.success());
        let links: Vec<serde_json::Value> = serde_json::from_slice(&links.stdout).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["ifname"], "lo");
    } else {
        verify_vm();
    }
}

fn verify_vm() {
    use std::os::unix::fs::MetadataExt;

    let marker = "/run/yonik-vm-gate";
    let guard = std::fs::symlink_metadata(marker).unwrap();
    assert!(guard.is_file() && guard.uid() == 0 && guard.mode() & 0o7777 == 0o600);
    assert!(rustix::process::geteuid().is_root());
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        "yonik-disposable-systemd-gate-v1\n"
    );
    assert_eq!(
        std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .unwrap()
            .trim(),
        "QEMU"
    );
}

fn request(family: u8) -> Vec<u8> {
    let mut packet =
        b"\x17\x28\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00".to_vec();
    packet.extend_from_slice(&[0, family, 0, 1]);
    packet
}

fn answer_address(packet: &[u8], request: &[u8], size: usize) -> IpAddr {
    assert_eq!(&packet[..2], &request[..2]);
    assert_eq!(packet[3] & 15, 0);
    assert_eq!(&packet[6..8], &[0, 1]);
    assert_eq!(&packet[12..request.len()], &request[12..]);
    assert_eq!(&packet[packet.len() - size - 2..][..2], &[0, size as u8]);
    assert_eq!(&packet[request.len()..request.len() + 2], &[0xc0, 12]);
    let ttl = u32::from_be_bytes(
        packet[request.len() + 6..request.len() + 10]
            .try_into()
            .unwrap(),
    );
    assert!((1..=MAX_FAKE_TTL.as_secs() as u32).contains(&ttl));
    let address = &packet[packet.len() - size..];
    match size {
        4 => IpAddr::from(<[u8; 4]>::try_from(address).unwrap()),
        16 => IpAddr::from(<[u8; 16]>::try_from(address).unwrap()),
        _ => unreachable!(),
    }
}

async fn ask_udp(family: u8, size: usize) -> IpAddr {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    socket.connect(DNS_MARKER).await.unwrap();
    let query = request(family);
    socket.send(&query).await.unwrap();
    let mut buffer = [0; 512];
    let len = socket.recv(&mut buffer).await.unwrap();
    answer_address(&buffer[..len], &query, size)
}

async fn ask_tcp(family: u8, size: usize) -> IpAddr {
    let mut stream = TcpStream::connect(DNS_MARKER).await.unwrap();
    let query = request(family);
    stream.write_u16(query.len() as u16).await.unwrap();
    stream.write_all(&query).await.unwrap();
    let size_on_wire = usize::from(stream.read_u16().await.unwrap());
    let mut response = vec![0; size_on_wire];
    stream.read_exact(&mut response).await.unwrap();
    answer_address(&response, &query, size)
}

async fn dial(address: IpAddr) -> io::Result<()> {
    let mut stream = TcpStream::connect((address, ECHO_PORT)).await?;
    stream.write_all(b"probe").await?;
    let mut answer = [0; 5];
    stream.read_exact(&mut answer).await?;
    assert_eq!(&answer, b"proof");
    Ok(())
}

async fn dial_udp(address: IpAddr) -> io::Result<()> {
    let local = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect((address, ECHO_PORT)).await?;
    socket.send(b"dg").await?;
    let mut response = [0; 32];
    let len = socket.recv(&mut response).await?;
    assert_eq!(&response[..len], b"proof-datagram");
    Ok(())
}

#[cfg(feature = "test-support")]
async fn проверить_системный_dns(address: IpAddr) {
    use yonik_linux::{apply_link_dns, prepare_link_dns};

    verify_vm();
    assert_eq!(
        std::fs::read_to_string("/sys/class/net/tofu00000001/ifalias")
            .unwrap()
            .trim(),
        TUN_ALIAS
    );
    let ifindex = std::fs::read_to_string("/sys/class/net/tofu00000001/ifindex")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let resolved = prepare_link_dns(
        ifindex,
        DNS_MARKER.parse::<SocketAddr>().unwrap().ip(),
        &[DOMAIN.to_owned()],
        LIMIT,
    )
    .await
    .expect("Системный resolved не подтвердил новое TUN-устройство");
    apply_link_dns(&resolved, LIMIT)
        .await
        .expect("Системный resolved не подтвердил настройку DNS");
    let output = tokio::process::Command::new("/usr/bin/getent")
        .args(["ahostsv4", DOMAIN])
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(output.status.success(), "NSS не разрешил тестовое имя");
    let data = String::from_utf8(output.stdout).unwrap();
    assert!(!data.is_empty());
    for line in data.lines() {
        assert_eq!(
            line.split_ascii_whitespace()
                .next()
                .unwrap()
                .parse::<IpAddr>()
                .unwrap(),
            address
        );
    }
    eprintln!("Системный NSS через resolved получил Fake-IP своего TUN");
}

fn peer_config() -> serde_json::Value {
    let upstream: SocketAddr = VLESS_SERVER.parse().unwrap();
    json!({
        "log":{"loglevel":"warning"},
        "inbounds":[{"tag":"peer","listen":upstream.ip().to_string(),"port":upstream.port(),"protocol":"vless",
            "settings":{"decryption":"none","clients":[{"id":ID}]}}],
        "outbounds":[
            {"tag":"reject","protocol":"blackhole"},
            {"tag":"echo","protocol":"freedom","settings":{
                "redirect":"127.0.0.1:24081","finalRules":[{
                    "action":"allow","ip":["127.0.0.1/32"],"port":"24081"
                }]
            }}
        ],
        "routing":{"domainStrategy":"AsIs","rules":[{
            "type":"field","domain":["full:example.test"],"outboundTag":"echo"
        }]}
    })
}

#[tokio::test]
#[ignore = "отдельный network namespace и закреплённые ядра"]
async fn сквозной_fake_dns_через_оба_ядра() {
    assert_eq!(env::var("YONIK_FAKE_TUN_TEST").as_deref(), Ok("1"));
    verify_gate();
    let log_dir = env_path("YONIK_FAKE_TUN_OUTPUT");
    let xray = env_path("YONIK_FAKE_TUN_XRAY");
    let sing = env_path("YONIK_FAKE_TUN_SING");
    let imported = yonik_import::import_bytes(
        format!("vless://{ID}@{VLESS_SERVER}?security=none").into_bytes(),
    )
    .unwrap();
    let config = log_dir.join("peer.json");
    std::fs::write(&config, peer_config().to_string()).unwrap();
    let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, ECHO_PORT))
        .await
        .unwrap();
    let echo_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, ECHO_PORT))
        .await
        .unwrap();
    let mut peer = Core::start(&xray, &config);
    peer.wait_for(VLESS_SERVER).await;
    let leases = FakeDnsLeases::new(
        FakeIpLeaseTable::new(
            [
                "198.19.0.2",
                "198.19.0.3",
                "fd2b:746f:1::2",
                "fd2b:746f:1::3",
            ]
            .map(|address| address.parse::<IpAddr>().unwrap()),
        )
        .unwrap(),
    );
    sleep(MAX_FAKE_TTL).await;
    let isolated = WorkerOnlyLoopbackIsolation::verified_by(|| {
        verify_gate();
        true
    })
    .unwrap();
    let mut previous = Vec::new();
    for (index, (engine, binary)) in [(Engine::Xray, xray), (Engine::SingBox, sing)]
        .into_iter()
        .enumerate()
    {
        let _device = TunFixture::create(engine);
        let epoch = DnsEpoch {
            network: 1,
            engine: index as u64 + 1,
            resolver: 1,
        };
        leases.advance_epoch(epoch).unwrap();
        let listeners = FakeDnsBridgeListeners::bind(SERVICE_ADDRESS).await.unwrap();
        let [dns_port, lookup_port] = listeners.ports().unwrap();
        let bridge = SystemFakeDnsBridge::new(
            DNS_MARKER.parse::<SocketAddr>().unwrap().ip(),
            ["198.19.0.0/24", "fd2b:746f:1::/64"]
                .map(|pool| pool.parse().unwrap())
                .to_vec(),
            dns_port,
            lookup_port,
            NonZeroU16::new(24083).unwrap(),
        )
        .unwrap()
        .with_isolated_loopback(SERVICE_ADDRESS)
        .unwrap();
        let tun = SystemTun::new(
            1,
            1500,
            77,
            ["198.18.0.1/30", "2001:db8:746f::1/126"]
                .map(|address| address.parse().unwrap())
                .to_vec(),
        )
        .unwrap();
        let generated = compile_system_fake_dns_bridge(
            &imported.servers[0],
            engine,
            NonZeroU16::new(24084).unwrap(),
            &tun,
            &bridge,
        )
        .unwrap();
        let config = log_dir.join(format!("client-{engine:?}.json"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config)
            .unwrap();
        generated.write_sensitive(file).unwrap();
        let mut core = Core::start(&binary, &config);
        core.wait_for(&bridge.reinject_endpoint().to_string()).await;
        let (_stop, cancel) = Cancellation::new();
        let approve =
            |question: &yonik_engine::fake_dns::FakeDnsQuestion| question.name().as_str() == DOMAIN;
        let dns_server = listeners.serve(&bridge, &isolated, &leases, epoch, &approve, cancel);
        let echo_server = async {
            loop {
                let (mut stream, _) = echo.accept().await.unwrap();
                let mut request = [0; 5];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"probe");
                stream.write_all(b"proof").await.unwrap();
            }
        };
        let echo_datagram_server = async {
            let mut buffer = [0; 32];
            loop {
                let (len, client) = echo_udp.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..len], b"dg");
                echo_udp.send_to(b"proof-datagram", client).await.unwrap();
            }
        };
        let client = async {
            eprintln!("{engine:?} DNS UDP A/AAAA");
            let v4 = ask_udp(1, 4).await;
            let v6 = ask_udp(28, 16).await;
            assert_eq!(ask_tcp(1, 4).await, v4);
            assert_eq!(ask_tcp(28, 16).await, v6);
            eprintln!("{engine:?} TUN TCP v4/v6");
            dial(v4).await.unwrap();
            dial(v6).await.unwrap();
            eprintln!("{engine:?} TUN UDP v4/v6");
            timeout(LIMIT, dial_udp(v4))
                .await
                .expect("Нет IPv4/UDP ответа")
                .unwrap();
            timeout(LIMIT, dial_udp(v6))
                .await
                .expect("Нет IPv6/UDP ответа")
                .unwrap();
            assert_ne!(v4, "198.19.0.250".parse::<IpAddr>().unwrap());
            for stale in previous.drain(..).chain(["198.19.0.250".parse().unwrap()]) {
                assert!(!matches!(
                    timeout(Duration::from_secs(1), dial(stale)).await,
                    Ok(Ok(()))
                ));
            }
            #[cfg(feature = "test-support")]
            if engine == Engine::SingBox && env::var_os("YONIK_FAKE_TUN_RESOLVED").is_some() {
                проверить_системный_dns(v4).await;
            }
            previous.extend([v4, v6]);
        };
        timeout(LIMIT * 3, async {
            tokio::select! {
                error = dns_server => panic!("DNS listener завершился: {error:?}"),
                () = echo_server => unreachable!(),
                () = echo_datagram_server => unreachable!(),
                () = client => {},
            }
        })
        .await
        .expect("Не подтверждён сквозной трафик Fake DNS");
        eprintln!(
            "{engine:?} DNS A/AAAA UDP/TCP, TUN v4/v6 TCP/UDP, неизвестные и старые адреса проверены"
        );
    }
}
