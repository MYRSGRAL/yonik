//! Проверка установленного Check worker вне socket-активации systemd.

use super::{WorkerCgroups, WorkerMode, WorkerPayload, WorkerStatus, require_cgroup_fixture_vm};
use crate::helper::TrustedRegistry;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::{
    fs, io,
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

const PREFIX: &str = "yonik-standalone-check-";
const ROOT_ENV: &str = "YONIK_STANDALONE_CHECK_FIXTURE";
const CHILD: &str = "helper::systemd_worker::tests::standalone_check_vm::exec_check_child";
const IMAGE: &str = "/usr/lib/yonik/yonik-worker";
const LIMIT: Duration = Duration::from_secs(8);

#[test]
#[ignore = "Внутренний subprocess одноразовой QEMU VM"]
fn exec_check_child() {
    require_cgroup_fixture_vm();
    let root = std::env::var(ROOT_ENV).unwrap();
    assert!(
        root.strip_prefix(PREFIX)
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|pid| pid > 1)
    );
    WorkerCgroups::open(&root)
        .unwrap()
        .join_current("check")
        .unwrap();
    let error = Command::new("/usr/bin/unshare")
        .args([
            "--net",
            "--",
            "/usr/bin/setpriv",
            "--reuid=yonik-worker",
            "--regid=yonik-worker",
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "--",
            IMAGE,
            "--check",
        ])
        .exec();
    panic!("Не удалось запустить Check worker: {error}");
}

struct Fixture {
    root: String,
    socket_dir: PathBuf,
    child: Option<Child>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let cgroup = Path::new("/sys/fs/cgroup").join(&self.root);
        if let Some(child) = self.child.as_mut() {
            if let Ok(groups) = WorkerCgroups::open(&self.root) {
                let _ = groups.kill_group("check");
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_file(self.socket_dir.join("check.sock"));
        let _ = fs::remove_dir(&self.socket_dir);
        let _ = fs::remove_dir(cgroup.join("check"));
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

fn verify_check(
    pid: u32,
    pidfd: &OwnedFd,
    image: (u64, u64),
    root: &str,
    uid: u32,
    gid: u32,
) -> io::Result<()> {
    let process = PathBuf::from(format!("/proc/{pid}"));
    let descriptor = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
    let status = fs::read_to_string(process.join("status"))?;
    let member = fs::read_to_string(process.join("cgroup"))?;
    if field(&descriptor, "Pid:").and_then(|pid| pid.parse().ok()) != Some(pid)
        || inode(process.join("exe"))? != image
        || member != format!("0::/{root}/check\n")
        || !has_ids(&status, "Uid:", uid)
        || !has_ids(&status, "Gid:", gid)
        || field(&status, "Groups:") != Some("")
        || field(&status, "NoNewPrivs:") != Some("1")
        || ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
            .into_iter()
            .any(|name| {
                field(&status, name).and_then(|value| u64::from_str_radix(value, 16).ok())
                    != Some(0)
            })
        || inode(process.join("ns/net"))? == inode("/proc/self/ns/net")?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Личность или изоляция Check не подтверждена",
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
        let root = format!("{PREFIX}{}", std::process::id());
        let cgroup = Path::new("/sys/fs/cgroup").join(&root);
        let socket_dir = Path::new("/run").join(&root);
        let mut fixture = Fixture {
            root,
            socket_dir,
            child: None,
        };
        fs::create_dir(&cgroup).unwrap();
        fs::create_dir(cgroup.join("check")).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&fixture.socket_dir)
            .unwrap();
        let socket = fixture.socket_dir.join("check.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fixture.child = Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", CHILD])
                .env(ROOT_ENV, &fixture.root)
                .stdin(Stdio::from(OwnedFd::from(listener)))
                .spawn()
                .unwrap(),
        );
        let child = fixture.child.as_mut().unwrap();
        let pid = child.id();
        let pidfd = pidfd_open(Pid::from_raw(pid as i32).unwrap(), PidfdFlags::empty()).unwrap();
        let deadline = Instant::now() + LIMIT;
        while inode(format!("/proc/{pid}/exe")).ok() != Some(image) {
            assert!(
                Instant::now() < deadline && child.try_wait().unwrap().is_none(),
                "Check worker не запущен"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        verify_check(pid, &pidfd, image, &fixture.root, uid, gid).unwrap();
        assert_eq!(
            verify_check(pid, &pidfd, wrong_image, &fixture.root, uid, gid)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let config =
            yonik_engine::compile(&server, engine, NonZeroU16::new(10808).unwrap()).unwrap();
        let payload = WorkerPayload::new(registry.snapshot(engine).unwrap(), config).unwrap();
        let stream = UnixStream::connect(socket).unwrap();
        let ack = payload.send(&stream, WorkerMode::Check).unwrap();
        assert_eq!((ack.pid, ack.status), (pid, WorkerStatus::Checked));
        let deadline = Instant::now() + LIMIT;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            WorkerCgroups::open(&fixture.root)
                .unwrap()
                .empty("check")
                .unwrap()
        );
        eprintln!("{engine:?}: установленный Check подтвердил конфигурацию, cgroup пуста");
    }
}
