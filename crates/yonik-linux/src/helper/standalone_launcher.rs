//! Одноразовый вход для выделенного процесса, запускаемого helper.

use super::{
    WorkerSupervisorError, standalone_mounts,
    systemd_worker::installed_worker_credentials,
    worker_paths::{FILE_FLAGS, WorkerCgroups, child, read_bounded, root, trusted},
};
use crate::worker::WorkerMode;
use rustix::{
    fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, fcntl_getfl, flock, openat, statat},
    net::{SocketAddrUnix, SocketType, getsockname, sockopt},
    process::{geteuid, getppid, umask},
};
use std::{
    fs::{self, File},
    os::unix::{fs::MetadataExt, process::CommandExt},
    process::Command,
};

type Result<T> = std::result::Result<T, WorkerSupervisorError>;
pub(super) const HELPER_IMAGE: &str = "/usr/lib/yonik/yonik-helper";
pub(super) const STANDALONE_PARENT: &str = "yonik-worker-standalone";
pub(super) const STANDALONE_RUNTIME: &str = "/run/yonik-worker-standalone";
pub(super) const WORKER_IMAGE: &str = "/usr/lib/yonik/yonik-worker";
pub(super) const CONTROLLER_PID: &str = "YONIK_WORKER_CONTROLLER_PID";

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

pub fn standalone_sandbox_argument(mode: WorkerMode) -> &'static str {
    match mode {
        WorkerMode::Check => "--standalone-sandbox-check",
        WorkerMode::Run => "--standalone-sandbox-run",
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
    let controller = verify_controller()?;
    verify_listener(mode, &runtime)?;
    verify_inherited_descriptors()?;

    let usr = child(&system_root, "usr")?;
    let tools = child(&usr, "bin")?;
    verify_executable(&tools, "unshare")?;
    let installed = child(&child(&usr, "lib")?, "yonik")?;
    verify_executable(&installed, "yonik-helper")?;
    let cgroups = WorkerCgroups::open(STANDALONE_PARENT)?;
    if !cgroups.empty(group(mode))? {
        return Err(WorkerSupervisorError::Busy);
    }
    cgroups.join_current(group(mode))?;

    let mut command = Command::new("/usr/bin/unshare");
    command.args(["--mount", "--propagation", "private"]);
    if mode == WorkerMode::Check {
        command.arg("--net");
    }
    let error = clean_command(&mut command)
        .env(CONTROLLER_PID, controller.to_string())
        .args(["--", HELPER_IMAGE, standalone_sandbox_argument(mode)])
        .exec();
    Err(unavailable(error))
}

/// Второй вход выполняется после входа в cgroup и создания namespace.
pub fn launch_standalone_sandbox(mode: WorkerMode) -> Result<std::convert::Infallible> {
    if !geteuid().is_root() {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let controller = verify_controller()?;
    let check = mode == WorkerMode::Check;
    if same_controller_namespace(controller, "mnt")?
        || same_controller_namespace(controller, "net")? == check
        || read_bounded(File::open("/proc/self/cgroup").map_err(unavailable)?)?.trim_end()
            != format!("0::/{STANDALONE_PARENT}/{}", group(mode))
    {
        return Err(WorkerSupervisorError::Untrusted);
    }

    let system_root = root()?;
    let runtime = child(&child(&system_root, "run")?, STANDALONE_PARENT)?;
    verify_listener(mode, &runtime)?;
    let usr = child(&system_root, "usr")?;
    let tools = child(&usr, "bin")?;
    // В штатной поставке util-linux mount может иметь setuid root.
    // На этой стадии и real UID, и effective UID уже равны 0.
    if !rustix::process::getuid().is_root() {
        return Err(WorkerSupervisorError::Untrusted);
    }
    verify_executable_mode(&tools, "mount", 0o2000)?;
    verify_executable(&tools, "setpriv")?;
    let installed = child(&child(&usr, "lib")?, "yonik")?;
    verify_executable(&installed, "yonik-worker")?;
    verify_inherited_descriptors()?;
    let credentials = installed_worker_credentials()?;
    standalone_mounts::setup(mode)?;

    let (capabilities, argument) = match mode {
        WorkerMode::Check => ("-all", "--check"),
        WorkerMode::Run => ("-all,+net_admin", "--run"),
    };
    umask(Mode::from_bits_truncate(0o077));
    let error = clean_command(&mut Command::new("/usr/bin/setpriv"))
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

fn clean_command(command: &mut Command) -> &mut Command {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("LANG", "C")
        .current_dir("/")
}

fn verify_controller() -> Result<i32> {
    let controller = std::env::var(CONTROLLER_PID)
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|&pid| pid > 1)
        .ok_or(WorkerSupervisorError::Untrusted)?;
    if getppid().map(|pid| pid.as_raw_pid()) != Some(controller) {
        return Err(WorkerSupervisorError::Stale);
    }
    Ok(controller)
}

fn same_controller_namespace(controller: i32, kind: &str) -> Result<bool> {
    let current = fs::metadata(format!("/proc/self/ns/{kind}")).map_err(unavailable)?;
    let parent = fs::metadata(format!("/proc/{controller}/ns/{kind}")).map_err(unavailable)?;
    Ok((current.dev(), current.ino()) == (parent.dev(), parent.ino()))
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

pub(super) fn verify_executable(parent: &File, name: &str) -> Result<()> {
    verify_executable_mode(parent, name, 0o6000)
}

fn verify_executable_mode(parent: &File, name: &str, forbidden_mode: u32) -> Result<()> {
    let file = File::from(openat(parent, name, FILE_FLAGS, Mode::empty()).map_err(unavailable)?);
    trusted(&file, false)?;
    let mode = file.metadata().map_err(unavailable)?.mode();
    if mode & 0o111 == 0 || mode & forbidden_mode != 0 {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}

fn unavailable<T>(_: T) -> WorkerSupervisorError {
    WorkerSupervisorError::Unavailable
}
