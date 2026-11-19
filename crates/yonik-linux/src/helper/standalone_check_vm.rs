//! Проверка установленных Check и Run вне socket-активации systemd.

use super::{WorkerCgroups, WorkerMode, WorkerPayload, WorkerStatus, require_cgroup_fixture_vm};
use crate::helper::{
    TrustedRegistry,
    standalone_launcher::{
        STANDALONE_PARENT, STANDALONE_RUNTIME, WORKER_IMAGE, group, socket_name,
    },
    standalone_worker_argument,
    worker_identity::{WorkerCredentials, WorkerProcess},
};
use crate::worker::WorkerAck;
use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    num::NonZeroU16,
    os::{
        fd::OwnedFd,
        unix::{
            fs::{DirBuilderExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const HELPER_IMAGE: &str = "/usr/lib/yonik/yonik-helper";
const LIMIT: Duration = Duration::from_secs(8);

fn require_private_network() {
    assert_ne!(
        inode("/proc/self/ns/net").unwrap(),
        inode("/proc/1/ns/net").unwrap()
    );
}

struct Fixture {
    root: String,
    socket_dir: PathBuf,
    mode: WorkerMode,
    child: Option<Child>,
}
impl Fixture {
    fn start(mode: WorkerMode) -> Self {
        let root = STANDALONE_PARENT.to_owned();
        let cgroup = Path::new("/sys/fs/cgroup").join(&root);
        let socket_dir = PathBuf::from(STANDALONE_RUNTIME);
        fs::create_dir(&cgroup).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&socket_dir)
            .unwrap();
        let mut fixture = Self {
            root,
            socket_dir,
            mode,
            child: None,
        };
        fs::create_dir(cgroup.join(group(mode))).unwrap();
        let listener = UnixListener::bind(fixture.socket()).unwrap();
        fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o600)).unwrap();
        require_denied(
            Command::new(HELPER_IMAGE)
                .arg(standalone_worker_argument(mode))
                .stdin(Stdio::null()),
        );
        listener.set_nonblocking(true).unwrap();
        require_denied(
            Command::new(HELPER_IMAGE)
                .arg(standalone_worker_argument(mode))
                .stdin(Stdio::from(OwnedFd::from(listener.try_clone().unwrap()))),
        );
        listener.set_nonblocking(false).unwrap();
        require_denied(
            Command::new("/bin/sh")
                .args([
                    "-c",
                    "exec 3</dev/null; exec \"$@\"",
                    "sh",
                    HELPER_IMAGE,
                    standalone_worker_argument(mode),
                ])
                .stdin(Stdio::from(OwnedFd::from(listener.try_clone().unwrap()))),
        );
        fixture.child = Some(
            Command::new(HELPER_IMAGE)
                .arg(standalone_worker_argument(mode))
                .stdin(Stdio::from(OwnedFd::from(listener)))
                .spawn()
                .unwrap(),
        );
        fixture
    }

    fn socket(&self) -> PathBuf {
        self.socket_dir.join(socket_name(self.mode))
    }

    fn await_image(&mut self, image: (u64, u64)) -> WorkerProcess {
        let child = self.child.as_mut().unwrap();
        let pid = child.id();
        let process = WorkerProcess::capture(pid).unwrap();
        let deadline = Instant::now() + LIMIT;
        while inode(format!("/proc/{pid}/exe")).ok() != Some(image) {
            assert!(
                Instant::now() < deadline && child.try_wait().unwrap().is_none(),
                "Worker не запущен"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        process
    }

    fn verify(
        &self,
        process: &WorkerProcess,
        image: (u64, u64),
        credentials: WorkerCredentials,
    ) -> io::Result<()> {
        verify_worker(self.mode, &self.root, credentials, process, image)
    }

    fn send(
        &self,
        process: &WorkerProcess,
        payload: &WorkerPayload,
        credentials: WorkerCredentials,
    ) -> WorkerAck {
        let stream = UnixStream::connect(self.socket()).unwrap();
        process
            .transfer(
                credentials,
                &format!("/{}/{}", self.root, group(self.mode)),
                || {
                    payload
                        .send(&stream, self.mode)
                        .map_err(|_| super::WorkerSupervisorError::Protocol)
                },
            )
            .unwrap()
    }

    fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let child = self.child.as_mut().unwrap();
        let deadline = Instant::now() + LIMIT;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "Worker не остановился");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let cgroup = Path::new("/sys/fs/cgroup").join(&self.root);
        if let Some(child) = self.child.as_mut() {
            if let Ok(groups) = WorkerCgroups::open(&self.root) {
                let _ = groups.kill_group(group(self.mode));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_file(self.socket());
        let _ = fs::remove_dir(&self.socket_dir);
        let _ = fs::remove_dir(cgroup.join(group(self.mode)));
        let _ = fs::remove_dir(cgroup);
    }
}

fn require_denied(command: &mut Command) {
    let mut child = command.stderr(Stdio::null()).spawn().unwrap();
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(1));
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("Launcher не отклонил вход до запуска worker");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn inode(path: impl AsRef<Path>) -> io::Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim)
}

fn verify_worker(
    mode: WorkerMode,
    root: &str,
    credentials: WorkerCredentials,
    process: &WorkerProcess,
    image: (u64, u64),
) -> io::Result<()> {
    process
        .verify(credentials, &format!("/{root}/{}", group(mode)))
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
    let process = PathBuf::from(format!("/proc/{}", process.pid));
    let status = fs::read_to_string(process.join("status"))?;
    let check = mode == WorkerMode::Check;
    let capabilities = if check { 0 } else { 1 << 12 };
    if inode(process.join("exe"))? != image
        || field(&status, "Groups:") != Some("")
        || field(&status, "NoNewPrivs:") != Some("1")
        || ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
            .into_iter()
            .any(|name| {
                field(&status, name).and_then(|value| u64::from_str_radix(value, 16).ok())
                    != Some(capabilities)
            })
        || (inode(process.join("ns/net"))? == inode("/proc/self/ns/net")?) == check
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Личность или изоляция worker не подтверждена",
        ));
    }
    Ok(())
}

fn installed_id(option: &str) -> u32 {
    let output = Command::new("/usr/bin/id")
        .args([option, "yonik-worker"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value = std::str::from_utf8(&output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_ne!(value, 0);
    value
}

#[test]
#[ignore = "Только одноразовая QEMU VM, установленный worker и доверенные ядра"]
fn installed_standalone_check_on_both_engines() {
    require_cgroup_fixture_vm();
    let credentials = WorkerCredentials {
        uid: installed_id("-u"),
        gid: installed_id("-g"),
    };
    let image = inode(WORKER_IMAGE).unwrap();
    let wrong_image = inode("/usr/bin/sleep").unwrap();
    let registry = TrustedRegistry::system().unwrap();
    let server = yonik_import::import_bytes(b"socks5://127.0.0.1:10999".to_vec())
        .unwrap()
        .servers
        .remove(0);

    for engine in [yonik_engine::Engine::Xray, yonik_engine::Engine::SingBox] {
        let mut fixture = Fixture::start(WorkerMode::Check);
        let process = fixture.await_image(image);
        fixture.verify(&process, image, credentials).unwrap();
        assert_eq!(
            fixture
                .verify(&process, wrong_image, credentials)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let config =
            yonik_engine::compile(&server, engine, NonZeroU16::new(10808).unwrap()).unwrap();
        let payload = WorkerPayload::new(registry.snapshot(engine).unwrap(), config).unwrap();
        let ack = fixture.send(&process, &payload, credentials);
        assert_eq!((ack.pid, ack.status), (process.pid, WorkerStatus::Checked));
        assert!(fixture.wait_for_exit().success());
        assert!(
            WorkerCgroups::open(&fixture.root)
                .unwrap()
                .empty("check")
                .unwrap()
        );
        eprintln!("{engine:?}: установленный Check подтвердил конфигурацию, cgroup пуста");
    }
}

const TUN_TARGET: &str = "198.18.0.2:18181";
const WITNESS: &[u8] = b"yonik-run-tun";

fn ip(arguments: &[&str]) -> std::process::Output {
    Command::new("/usr/sbin/ip")
        .args(arguments)
        .output()
        .unwrap()
}

fn require_ip(arguments: &[&str]) {
    let output = ip(arguments);
    assert!(
        output.status.success(),
        "ip {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn socks_peer(listener: TcpListener) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + LIMIT;
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    };
    stream.set_read_timeout(Some(LIMIT))?;
    stream.set_write_timeout(Some(LIMIT))?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting)?;
    let mut methods = vec![0; usize::from(greeting[1])];
    stream.read_exact(&mut methods)?;
    assert!(greeting[0] == 5 && methods.contains(&0));
    stream.write_all(&[5, 0])?;
    let mut request = [0; 10];
    stream.read_exact(&mut request)?;
    assert_eq!(request, [5, 1, 0, 1, 198, 18, 0, 2, 0x47, 0x05]);
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
    let mut payload = [0; WITNESS.len()];
    stream.read_exact(&mut payload)?;
    assert_eq!(payload, WITNESS);
    stream.write_all(&payload)?;
    Ok(())
}

fn link_packets(name: &str) -> [u64; 2] {
    let output = ip(&["-j", "-s", "link", "show", "dev", name]);
    assert!(output.status.success());
    let state: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    ["rx", "tx"].map(|direction| state[0]["stats64"][direction]["packets"].as_u64().unwrap())
}

#[test]
#[ignore = "Только одноразовая QEMU VM с отдельным сетевым namespace для TUN"]
fn installed_standalone_run_passes_tcp_through_tun_on_both_engines() {
    use yonik_engine::{Engine, SystemTun, compile_system};
    require_cgroup_fixture_vm();
    require_private_network();
    require_ip(&["link", "set", "lo", "up"]);
    let credentials = WorkerCredentials {
        uid: installed_id("-u"),
        gid: installed_id("-g"),
    };
    let image = inode(WORKER_IMAGE).unwrap();
    let registry = TrustedRegistry::system().unwrap();
    let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
    let name = tun.interface_name();
    let local = "127.0.0.1:10808".parse().unwrap();
    let destination = TUN_TARGET.parse().unwrap();

    for engine in [Engine::Xray, Engine::SingBox] {
        require_ip(&[
            "tuntap",
            "add",
            "dev",
            &name,
            "mode",
            "tun",
            "user",
            "yonik-worker",
        ]);
        require_ip(&["address", "add", "198.18.0.1/30", "dev", &name]);
        require_ip(&["link", "set", &name, "up"]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("socks5://{}", listener.local_addr().unwrap());
        let server = yonik_import::import_bytes(endpoint.into_bytes())
            .unwrap()
            .servers
            .remove(0);
        let config =
            compile_system(&server, engine, NonZeroU16::new(10808).unwrap(), &tun).unwrap();
        let payload = WorkerPayload::new(registry.snapshot(engine).unwrap(), config).unwrap();
        let mut fixture = Fixture::start(WorkerMode::Run);
        let process = fixture.await_image(image);
        fixture.verify(&process, image, credentials).unwrap();
        assert_eq!(
            verify_worker(
                WorkerMode::Check,
                &fixture.root,
                credentials,
                &process,
                image
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        let ack = fixture.send(&process, &payload, credentials);
        assert_eq!((ack.pid, ack.status), (process.pid, WorkerStatus::Accepted));
        let deadline = Instant::now() + LIMIT;
        while TcpStream::connect_timeout(&local, Duration::from_millis(100)).is_err() {
            assert!(
                Instant::now() < deadline
                    && fixture
                        .child
                        .as_mut()
                        .unwrap()
                        .try_wait()
                        .unwrap()
                        .is_none()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let before = link_packets(&name);
        let peer = std::thread::spawn(move || socks_peer(listener));
        let mut client = TcpStream::connect_timeout(&destination, LIMIT).unwrap();
        client.set_read_timeout(Some(LIMIT)).unwrap();
        client.set_write_timeout(Some(LIMIT)).unwrap();
        client.write_all(WITNESS).unwrap();
        let mut echoed = [0; WITNESS.len()];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, WITNESS);
        peer.join().unwrap().unwrap();
        let after = link_packets(&name);
        assert!(
            before
                .into_iter()
                .zip(after)
                .all(|(start, end)| end > start)
        );
        let groups = WorkerCgroups::open(&fixture.root).unwrap();
        assert!(!groups.empty("run").unwrap());
        groups.kill_group("run").unwrap();
        assert!(!fixture.wait_for_exit().success());
        assert!(groups.empty("run").unwrap());
        require_ip(&["tuntap", "del", "dev", &name, "mode", "tun"]);
        assert!(!ip(&["link", "show", "dev", &name]).status.success());
        eprintln!("{engine:?}: TCP через TUN подтверждён, worker остановлен и cgroup пуста");
    }
}
