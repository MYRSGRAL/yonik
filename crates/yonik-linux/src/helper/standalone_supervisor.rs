//! Владение автономным worker и его сетевым жизненным циклом.

use super::{
    WorkerLiveness, WorkerSupervisorError as Error, WorkerTicket,
    standalone_launcher::{
        CONTROLLER_PID, HELPER_IMAGE, STANDALONE_PARENT, STANDALONE_RUNTIME, WORKER_IMAGE, group,
        socket_name, verify_executable,
    },
    standalone_seccomp::filter_count,
    standalone_worker_argument,
    systemd_worker::{installed_worker_credentials, wait_owned},
    worker_identity::{WorkerCredentials, WorkerProcess},
    worker_paths::{FILE_FLAGS, WorkerCgroups, child, ensure_directory, root, trusted},
};
use crate::{
    Cancellation,
    output_transport::ValidatedWriters,
    worker::{WorkerAck, WorkerMode, WorkerPayload, WorkerStatus},
};
use rustix::{
    fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, flock, openat, statat, unlinkat},
    io::Errno,
};
use std::{
    fs::{self, File},
    os::{
        fd::OwnedFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixListener,
        },
    },
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    task::JoinHandle,
    time::Instant,
};

type Result<T> = std::result::Result<T, Error>;
const LIMIT: Duration = Duration::from_secs(15);
const ROLES: [WorkerMode; 2] = [WorkerMode::Check, WorkerMode::Run];

pub(super) struct StandaloneSupervisor {
    runtime: File,
    owner: File,
    cgroups: WorkerCgroups,
    job: Option<Job>,
    clean: bool,
}

struct Job {
    child: Child,
    identity: Option<Arc<WorkerProcess>>,
    ticket: WorkerTicket,
    credentials: WorkerCredentials,
    mode: WorkerMode,
    _payload: Arc<WorkerPayload>,
    transfer: Option<JoinHandle<Result<WorkerAck>>>,
}

impl StandaloneSupervisor {
    pub(super) fn open() -> Result<Self> {
        let system_root = root()?;
        let run = child(&system_root, "run")?;
        ensure_directory(&run, STANDALONE_PARENT, Mode::from_bits_truncate(0o700))?;
        let runtime = open_runtime()?;
        let owner = File::from(
            openat(
                &runtime,
                "owner.lock",
                (FILE_FLAGS - OFlags::RDONLY) | OFlags::RDWR | OFlags::CREATE,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(unavailable)?,
        );
        trusted(&owner, false)?;
        if owner.metadata().map_err(unavailable)?.mode() & 0o777 != 0o600 {
            return Err(Error::Untrusted);
        }
        flock(&owner, FlockOperation::NonBlockingLockExclusive).map_err(unavailable)?;
        let installed = child(&child(&child(&system_root, "usr")?, "lib")?, "yonik")?;
        verify_executable(&installed, "yonik-helper")?;
        verify_executable(&installed, "yonik-worker")?;
        let names = ROLES.map(group);
        let cgroups = WorkerCgroups::prepare(STANDALONE_PARENT, &names)?;
        Ok(Self {
            runtime,
            owner,
            cgroups,
            job: None,
            clean: false,
        })
    }

    pub(super) async fn check(
        &mut self,
        payload: Arc<WorkerPayload>,
        cancel: &mut Cancellation,
    ) -> Result<()> {
        let deadline = Instant::now() + LIMIT;
        let ack = self
            .start(WorkerMode::Check, payload, None, cancel, deadline)
            .await?;
        if ack.status != WorkerStatus::Checked {
            return Err(Error::Protocol);
        }
        let child = &mut self.job.as_mut().ok_or(Error::Stale)?.child;
        if !bounded(cancel, deadline, async {
            child.wait().await.map_err(unavailable)
        })
        .await?
        .success()
        {
            return Err(Error::Protocol);
        }
        self.recover(cancel).await
    }

    pub(super) async fn start_output(
        &mut self,
        payload: Arc<WorkerPayload>,
        output: Option<ValidatedWriters>,
        cancel: &mut Cancellation,
    ) -> Result<WorkerTicket> {
        let ack = self
            .start(
                WorkerMode::Run,
                payload,
                output,
                cancel,
                Instant::now() + LIMIT,
            )
            .await?;
        let job = self.job.as_ref().ok_or(Error::Stale)?;
        if ack.status != WorkerStatus::Accepted || ack.pid != job.ticket.pid {
            return Err(Error::Protocol);
        }
        job.identity
            .as_ref()
            .ok_or(Error::Stale)?
            .verify(job.credentials, &cgroup(job.mode))?;
        Ok(WorkerTicket {
            pid: job.ticket.pid,
            invocation: job.ticket.invocation,
        })
    }

    async fn start(
        &mut self,
        mode: WorkerMode,
        payload: Arc<WorkerPayload>,
        output: Option<ValidatedWriters>,
        cancel: &mut Cancellation,
        deadline: Instant,
    ) -> Result<WorkerAck> {
        cancel.check().map_err(|_| Error::Cancelled)?;
        if !self.clean || self.job.is_some() || payload.needs_tmpfs_assets() {
            return Err(Error::RecoveryRequired);
        }
        self.verify_runtime()?;
        let credentials = installed_worker_credentials()?;
        let controller_netns = inode("/proc/self/ns/net")?;
        let controller_mountns = inode("/proc/self/ns/mnt")?;
        let controller_filters =
            filter_count(&fs::read_to_string("/proc/thread-self/status").map_err(unavailable)?)?;
        let image = inode(WORKER_IMAGE)?;
        let mut invocation = [0; 16];
        getrandom::getrandom(&mut invocation).map_err(unavailable)?;
        let socket = socket(mode);
        self.clean = false;
        let listener = UnixListener::bind(&socket).map_err(unavailable)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(unavailable)?;
        let child = Command::new(HELPER_IMAGE)
            .arg(standalone_worker_argument(mode))
            .env_clear()
            .env(CONTROLLER_PID, std::process::id().to_string())
            .stdin(Stdio::from(OwnedFd::from(listener)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(unavailable)?;
        let pid = child.id().unwrap_or(0);
        let job = self.job.insert(Job {
            child,
            identity: None,
            ticket: WorkerTicket { pid, invocation },
            credentials,
            mode,
            _payload: Arc::clone(&payload),
            transfer: None,
        });
        let identity = Arc::new(WorkerProcess::capture(pid)?);
        job.identity = Some(Arc::clone(&identity));

        loop {
            self.verify_runtime()?;
            if inode(&format!("/proc/{pid}/exe")).ok() == Some(image) {
                verify_setup(
                    pid,
                    mode,
                    controller_netns,
                    controller_mountns,
                    controller_filters,
                )?;
                break;
            }
            if self
                .job
                .as_mut()
                .ok_or(Error::Stale)?
                .child
                .try_wait()
                .map_err(unavailable)?
                .is_some()
            {
                return Err(Error::Protocol);
            }
            bounded(cancel, deadline, async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(())
            })
            .await?;
        }
        let stream = bounded(cancel, deadline, async {
            tokio::net::UnixStream::connect(socket)
                .await
                .map_err(unavailable)
        })
        .await?
        .into_std()
        .map_err(unavailable)?;
        stream.set_nonblocking(false).map_err(unavailable)?;
        let job = self.job.as_mut().ok_or(Error::Stale)?;
        job.transfer = Some(tokio::task::spawn_blocking(move || {
            identity.transfer(credentials, &cgroup(mode), || {
                payload
                    .send_output_before(&stream, mode, output, deadline.into_std())
                    .map_err(|_| Error::Protocol)
            })
        }));
        wait_owned(&mut job.transfer, cancel, deadline).await?
    }

    pub(super) fn observe(&self, ticket: &WorkerTicket) -> Result<WorkerLiveness> {
        let job = self
            .job
            .as_ref()
            .filter(|job| &job.ticket == ticket)
            .ok_or(Error::Stale)?;
        if self.cgroups.empty(group(job.mode))? {
            return Ok(WorkerLiveness::Stopped);
        }
        job.identity
            .as_ref()
            .ok_or(Error::Stale)?
            .verify(job.credentials, &cgroup(job.mode))?;
        Ok(WorkerLiveness::Running)
    }

    pub(super) async fn recover(&mut self, cancel: &mut Cancellation) -> Result<()> {
        self.clean = false;
        let deadline = Instant::now() + LIMIT;
        if let Some(job) = self.job.as_mut() {
            if job.child.try_wait().map_err(unavailable)?.is_none() {
                job.child.start_kill().map_err(unavailable)?;
            }
        }
        self.verify_runtime()?;
        let _launch_lock = loop {
            let runtime = self.runtime.try_clone().map_err(unavailable)?;
            match flock(&runtime, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break LaunchLock(runtime),
                Err(Errno::WOULDBLOCK) => {
                    bounded(cancel, deadline, async {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Ok(())
                    })
                    .await?;
                }
                Err(_) => return Err(Error::Unavailable),
            }
        };
        for role in ROLES {
            if !self.cgroups.empty(group(role))? {
                self.cgroups.kill_group(group(role))?;
            }
        }
        loop {
            if self.cgroups.empty("check")? && self.cgroups.empty("run")? {
                break;
            }
            bounded(cancel, deadline, async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(())
            })
            .await?;
        }
        if let Some(job) = self.job.as_mut() {
            bounded(cancel, deadline, async {
                job.child.wait().await.map_err(unavailable)
            })
            .await?;
            if job.transfer.is_some() {
                let result = wait_owned(&mut job.transfer, cancel, deadline).await;
                // Только незавершённая передача удерживает восстановление.
                if job.transfer.is_some() {
                    let _ = result?;
                }
            }
        }
        self.verify_runtime()?;
        for role in ROLES {
            let name = socket_name(role);
            match statat(&self.runtime, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat)
                    if FileType::from_raw_mode(stat.st_mode) == FileType::Socket
                        && stat.st_uid == 0
                        && stat.st_gid == 0 =>
                {
                    unlinkat(&self.runtime, name, AtFlags::empty()).map_err(unavailable)?;
                }
                Err(Errno::NOENT) => {}
                _ => return Err(Error::Untrusted),
            }
        }
        self.job = None;
        self.clean = true;
        Ok(())
    }

    pub(super) fn confirm_profile_rules_retired(&self) -> Result<()> {
        if !self.clean || self.job.is_some() {
            return Err(Error::RecoveryRequired);
        }
        Ok(())
    }

    fn verify_runtime(&self) -> Result<()> {
        let current = open_runtime()?.metadata().map_err(unavailable)?;
        let retained = self.runtime.metadata().map_err(unavailable)?;
        if (current.dev(), current.ino()) != (retained.dev(), retained.ino()) {
            return Err(Error::Stale);
        }
        let current_owner =
            statat(&self.runtime, "owner.lock", AtFlags::SYMLINK_NOFOLLOW).map_err(unavailable)?;
        let owner = self.owner.metadata().map_err(unavailable)?;
        if (current_owner.st_dev, current_owner.st_ino) != (owner.dev(), owner.ino()) {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

struct LaunchLock(File);
impl Drop for LaunchLock {
    fn drop(&mut self) {
        let _ = flock(&self.0, FlockOperation::Unlock);
    }
}

fn open_runtime() -> Result<File> {
    let runtime = child(&child(&root()?, "run")?, STANDALONE_PARENT)?;
    if runtime.metadata().map_err(unavailable)?.mode() & 0o777 != 0o700 {
        return Err(Error::Untrusted);
    }
    Ok(runtime)
}

fn socket(mode: WorkerMode) -> PathBuf {
    PathBuf::from(STANDALONE_RUNTIME).join(socket_name(mode))
}

fn cgroup(mode: WorkerMode) -> String {
    format!("/{STANDALONE_PARENT}/{}", group(mode))
}

fn inode(path: &str) -> Result<(u64, u64)> {
    let metadata = fs::metadata(path).map_err(unavailable)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn verify_setup(
    pid: u32,
    mode: WorkerMode,
    controller_netns: (u64, u64),
    controller_mountns: (u64, u64),
    controller_filters: u32,
) -> Result<()> {
    let process = format!("/proc/{pid}");
    let info = fs::read_to_string(format!("{process}/status")).map_err(unavailable)?;
    let field = |key: &str| {
        info.lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
    };
    let check = mode == WorkerMode::Check;
    let allowed = if check { 0 } else { 1 << 12 };
    if field("Groups:") != Some("")
        || field("NoNewPrivs:") != Some("1")
        || ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
            .into_iter()
            .any(|key| {
                field(key).and_then(|value| u64::from_str_radix(value, 16).ok()) != Some(allowed)
            })
        || (inode(&format!("{process}/ns/net"))? == controller_netns) == check
        || inode(&format!("{process}/ns/mnt"))? == controller_mountns
        || controller_filters.checked_add(1) != Some(filter_count(&info)?)
    {
        return Err(Error::Untrusted);
    }
    Ok(())
}

async fn bounded<T>(
    cancel: &mut Cancellation,
    deadline: Instant,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Error::Cancelled),
        () = tokio::time::sleep_until(deadline) => Err(Error::Timeout),
        result = future => result,
    }
}

fn unavailable<T>(_: T) -> Error {
    Error::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn completed_transfer_error_is_consumed_once() {
        let (_owner, mut cancel) = Cancellation::new();
        let mut task = Some(tokio::spawn(async { Err(Error::Protocol) }));
        let deadline = Instant::now() + LIMIT;
        assert!(matches!(
            wait_owned(&mut task, &mut cancel, deadline).await,
            Ok(Err::<WorkerAck, _>(Error::Protocol))
        ));
        assert!(task.is_none());
    }
}
