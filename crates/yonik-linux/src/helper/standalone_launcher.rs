//! Одноразовый вход для выделенного процесса, запускаемого helper.

use super::{
    WorkerSupervisorError,
    systemd_worker::installed_worker_credentials,
    worker_paths::{FILE_FLAGS, WorkerCgroups, child, read_bounded, root, trusted},
};
use crate::worker::WorkerMode;
use rustix::{
    fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, fcntl_getfl, flock, openat, statat},
    net::{SocketAddrUnix, SocketType, getsockname, sockopt},
    process::{geteuid, umask},
};
use std::{
    fs::File,
    os::unix::{fs::MetadataExt, process::CommandExt},
    process::Command,
};

type Result<T> = std::result::Result<T, WorkerSupervisorError>;
pub(super) const STANDALONE_PARENT: &str = "yonik-worker-standalone";
pub(super) const STANDALONE_RUNTIME: &str = "/run/yonik-worker-standalone";
pub(super) const WORKER_IMAGE: &str = "/usr/lib/yonik/yonik-worker";

pub(super) fn group(mode: WorkerMode) -> &'static str {
    match mode {
        WorkerMode::Check => "check",
        WorkerMode::Run => "run",
    }
}

pub(super) fn socket_name(mode: WorkerMode) -> &'static str {
    match mode {
        WorkerMode::Check => "check.sock",
        WorkerMode::Run => "run.sock",
    }
}

pub fn standalone_worker_argument(mode: WorkerMode) -> &'static str {
    match mode {
        WorkerMode::Check => "--standalone-worker-check",
        WorkerMode::Run => "--standalone-worker-run",
    }
}

/// После успешной проверки заменяет текущий процесс установленным worker.
/// Сокет и cgroup принадлежат управляющему процессу и открываются заранее.
/// Контроллер удерживает привязку pathname от bind до остановки worker.
pub fn launch_standalone_worker(mode: WorkerMode) -> Result<std::convert::Infallible> {
    if !geteuid().is_root() {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let system_root = root()?;
    let runtime = child(&child(&system_root, "run")?, STANDALONE_PARENT)?;
    if runtime.metadata().map_err(unavailable)?.mode() & 0o777 != 0o700 {
        return Err(WorkerSupervisorError::Untrusted);
    }
    flock(&runtime, FlockOperation::NonBlockingLockExclusive).map_err(unavailable)?;
    verify_listener(mode, &runtime)?;
    verify_inherited_descriptors()?;

    let usr = child(&system_root, "usr")?;
    let tools = child(&usr, "bin")?;
    verify_executable(&tools, "setpriv")?;
    let installed = child(&child(&usr, "lib")?, "yonik")?;
    verify_executable(&installed, "yonik-worker")?;
    let (capabilities, argument, mut command) = match mode {
        WorkerMode::Check => {
            verify_executable(&tools, "unshare")?;
            let mut command = Command::new("/usr/bin/unshare");
            command.args(["--net", "--", "/usr/bin/setpriv"]);
            ("-all", "--check", command)
        }
        WorkerMode::Run => ("-all,+net_admin", "--run", Command::new("/usr/bin/setpriv")),
    };
    let credentials = installed_worker_credentials()?;
    let cgroups = WorkerCgroups::open(STANDALONE_PARENT)?;
    if !cgroups.empty(group(mode))? {
        return Err(WorkerSupervisorError::Busy);
    }
    cgroups.join_current(group(mode))?;

    umask(Mode::from_bits_truncate(0o077));
    let error = command
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("LANG", "C")
        .current_dir("/")
        .arg(format!("--reuid={}", credentials.uid))
        .arg(format!("--regid={}", credentials.gid))
        .arg("--clear-groups")
        .arg(format!("--inh-caps={capabilities}"))
        .arg(format!("--ambient-caps={capabilities}"))
        .arg(format!("--bounding-set={capabilities}"))
        .args(["--no-new-privs", "--", WORKER_IMAGE, argument])
        .exec();
    Err(unavailable(error))
}

fn verify_listener(mode: WorkerMode, runtime: &File) -> Result<()> {
    let socket = std::io::stdin();
    if sockopt::socket_type(&socket).map_err(unavailable)? != SocketType::STREAM
        || !sockopt::socket_acceptconn(&socket).map_err(unavailable)?
        || fcntl_getfl(&socket)
            .map_err(unavailable)?
            .contains(OFlags::NONBLOCK)
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let address =
        SocketAddrUnix::try_from(getsockname(socket).map_err(unavailable)?).map_err(unavailable)?;
    let name = socket_name(mode);
    let expected = format!("{STANDALONE_RUNTIME}/{name}");
    let stat = statat(runtime, name, AtFlags::SYMLINK_NOFOLLOW).map_err(unavailable)?;
    if address.path_bytes() != Some(expected.as_bytes())
        || !matches!(FileType::from_raw_mode(stat.st_mode), FileType::Socket)
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o777 != 0o600
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}

fn verify_inherited_descriptors() -> Result<()> {
    // Launcher вызывается до запуска Tokio. Открытые им FD имеют CLOEXEC.
    for entry in std::fs::read_dir("/proc/self/fd").map_err(unavailable)? {
        let entry = entry.map_err(unavailable)?;
        let name = entry.file_name();
        let fd = name
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(WorkerSupervisorError::Untrusted)?;
        if fd < 3 {
            continue;
        }
        let info = File::open(format!("/proc/self/fdinfo/{fd}")).map_err(unavailable)?;
        let info = read_bounded(info)?;
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| u64::from_str_radix(value.trim(), 8).ok())
            .ok_or(WorkerSupervisorError::Untrusted)?;
        if flags & u64::from(OFlags::CLOEXEC.bits()) == 0 {
            return Err(WorkerSupervisorError::Untrusted);
        }
    }
    Ok(())
}

fn verify_executable(parent: &File, name: &str) -> Result<()> {
    let file = File::from(openat(parent, name, FILE_FLAGS, Mode::empty()).map_err(unavailable)?);
    trusted(&file, false)?;
    let mode = file.metadata().map_err(unavailable)?.mode();
    if mode & 0o111 == 0 || mode & 0o6000 != 0 {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}

fn unavailable<T>(_: T) -> WorkerSupervisorError {
    WorkerSupervisorError::Unavailable
}
