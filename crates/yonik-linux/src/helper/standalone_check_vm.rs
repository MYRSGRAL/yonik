//! Проверка установленных Check и Run вне socket-активации systemd.

use super::{WorkerCgroups, WorkerMode, WorkerPayload, WorkerStatus, require_cgroup_fixture_vm};
use crate::helper::TrustedRegistry;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    num::NonZeroU16,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            fs::{DirBuilderExt, MetadataExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const PREFIX: &str = "yonik-standalone-worker-";
const ROOT_ENV: &str = "YONIK_STANDALONE_WORKER_FIXTURE";
const MODE_ENV: &str = "YONIK_STANDALONE_WORKER_MODE";
const CHILD: &str = "helper::systemd_worker::tests::standalone_check_vm::exec_worker_child";
const IMAGE: &str = "/usr/lib/yonik/yonik-worker";
const LIMIT: Duration = Duration::from_secs(8);

fn group(mode: WorkerMode) -> &'static str {
    match mode {
        WorkerMode::Check => "check",
        WorkerMode::Run => "run",
    }
}

fn require_private_network() {
    assert_ne!(
        inode("/proc/self/ns/net").unwrap(),
        inode("/proc/1/ns/net").unwrap()
    );
}

#[test]
#[ignore = "Внутренний subprocess одноразовой QEMU VM"]
fn exec_worker_child() {
    require_cgroup_fixture_vm();
    let root = std::env::var(ROOT_ENV).unwrap();
    assert!(
        root.strip_prefix(PREFIX)
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|pid| pid > 1)
    );
    let (mode, capabilities, argument, mut command) =
        match std::env::var(MODE_ENV).unwrap().as_str() {
            "check" => {
                let mut command = Command::new("/usr/bin/unshare");
                command.args(["--net", "--", "/usr/bin/setpriv"]);
                (WorkerMode::Check, "-all", "--check", command)
            }
            "run" => {
                require_private_network();
                (
                    WorkerMode::Run,
                    "-all,+net_admin",
                    "--run",
                    Command::new("/usr/bin/setpriv"),
                )
            }
            _ => panic!("Неизвестная роль worker"),
        };
    WorkerCgroups::open(&root)
        .unwrap()
        .join_current(group(mode))
        .unwrap();
    let error = command
        .args([
            "--reuid=yonik-worker",
            "--regid=yonik-worker",
            "--clear-groups",
        ])
        .arg(format!("--inh-caps={capabilities}"))
        .arg(format!("--ambient-caps={capabilities}"))
        .arg(format!("--bounding-set={capabilities}"))
        .args(["--no-new-privs", "--", IMAGE, argument])
        .exec();
    panic!("Не удалось запустить worker: {error}");
}

struct Fixture {
    root: String,
    socket_dir: PathBuf,
    mode: WorkerMode,
    child: Option<Child>,
}
impl Fixture {
    fn start(mode: WorkerMode) -> Self {
        let root = format!("{PREFIX}{}", std::process::id());
        let cgroup = Path::new("/sys/fs/cgroup").join(&root);
        let socket_dir = Path::new("/run").join(&root);
        let mut fixture = Self {
            root,
            socket_dir,
            mode,
            child: None,
        };
        fs::create_dir(&cgroup).unwrap();
        fs::create_dir(cgroup.join(group(mode))).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&fixture.socket_dir)
            .unwrap();
        let listener = UnixListener::bind(fixture.socket()).unwrap();
        fixture.child = Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", CHILD])
                .env(ROOT_ENV, &fixture.root)
                .env(MODE_ENV, group(mode))
                .stdin(Stdio::from(OwnedFd::from(listener)))
                .spawn()
                .unwrap(),
        );
        fixture
    }

    fn socket(&self) -> PathBuf {
        self.socket_dir.join("worker.sock")
    }

    fn await_image(&mut self, image: (u64, u64)) -> (u32, OwnedFd) {
        let child = self.child.as_mut().unwrap();
        let pid = child.id();
        let pidfd = pidfd_open(Pid::from_raw(pid as i32).unwrap(), PidfdFlags::empty()).unwrap();
        let deadline = Instant::now() + LIMIT;
        while inode(format!("/proc/{pid}/exe")).ok() != Some(image) {
            assert!(
                Instant::now() < deadline && child.try_wait().unwrap().is_none(),
                "Worker не запущен"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        (pid, pidfd)
    }

    fn verify(
        &self,
        pid: u32,
        pidfd: &OwnedFd,
        image: (u64, u64),
        uid: u32,
        gid: u32,
    ) -> io::Result<()> {
        verify_worker(self.mode, &self.root, (uid, gid), pid, pidfd, image)
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

fn inode(path: impl AsRef<Path>) -> io::Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim)
}

fn has_ids(status: &str, name: &str, expected: u32) -> bool {
    field(status, name).is_some_and(|value| {
        value
            .split_whitespace()
            .map(|id| id.parse::<u32>().ok())
            .eq([Some(expected); 4])
    })
}

fn verify_worker(
    mode: WorkerMode,
    root: &str,
    (uid, gid): (u32, u32),
    pid: u32,
    pidfd: &OwnedFd,
    image: (u64, u64),
) -> io::Result<()> {
    let process = PathBuf::from(format!("/proc/{pid}"));
    let descriptor = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
    let status = fs::read_to_string(process.join("status"))?;
    let member = fs::read_to_string(process.join("cgroup"))?;
    let check = mode == WorkerMode::Check;
    let capabilities = if check { 0 } else { 1 << 12 };
    if field(&descriptor, "Pid:").and_then(|pid| pid.parse().ok()) != Some(pid)
        || inode(process.join("exe"))? != image
        || member != format!("0::/{root}/{}\n", group(mode))
        || !has_ids(&status, "Uid:", uid)
        || !has_ids(&status, "Gid:", gid)
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
    let uid = installed_id("-u");
    let gid = installed_id("-g");
    let image = inode(IMAGE).unwrap();
    let wrong_image = inode("/usr/bin/sleep").unwrap();
    let registry = TrustedRegistry::system().unwrap();
    let server = yonik_import::import_bytes(b"socks5://127.0.0.1:10999".to_vec())
        .unwrap()
        .servers
        .remove(0);

    for engine in [yonik_engine::Engine::Xray, yonik_engine::Engine::SingBox] {
        let mut fixture = Fixture::start(WorkerMode::Check);
        let (pid, pidfd) = fixture.await_image(image);
        fixture.verify(pid, &pidfd, image, uid, gid).unwrap();
        assert_eq!(
            fixture
                .verify(pid, &pidfd, wrong_image, uid, gid)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let config =
            yonik_engine::compile(&server, engine, NonZeroU16::new(10808).unwrap()).unwrap();
        let payload = WorkerPayload::new(registry.snapshot(engine).unwrap(), config).unwrap();
        let stream = UnixStream::connect(fixture.socket()).unwrap();
        let ack = payload.send(&stream, WorkerMode::Check).unwrap();
        assert_eq!((ack.pid, ack.status), (pid, WorkerStatus::Checked));
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
    let uid = installed_id("-u");
    let gid = installed_id("-g");
    let image = inode(IMAGE).unwrap();
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
        let (pid, pidfd) = fixture.await_image(image);
        fixture.verify(pid, &pidfd, image, uid, gid).unwrap();
        assert_eq!(
            verify_worker(
                WorkerMode::Check,
                &fixture.root,
                (uid, gid),
                pid,
                &pidfd,
                image
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        let stream = UnixStream::connect(fixture.socket()).unwrap();
        let ack = payload.send(&stream, WorkerMode::Run).unwrap();
        assert_eq!((ack.pid, ack.status), (pid, WorkerStatus::Accepted));
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
