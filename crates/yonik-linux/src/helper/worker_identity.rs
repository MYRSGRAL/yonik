//! Проверка живого worker, привязанного к одному pidfd.

use super::WorkerSupervisorError;
use crate::worker::WorkerAck;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::os::fd::{AsRawFd, OwnedFd};

type Result<T> = std::result::Result<T, WorkerSupervisorError>;

#[derive(Clone, Copy)]
pub(super) struct WorkerCredentials {
    pub(super) uid: u32,
    pub(super) gid: u32,
}

pub(super) struct WorkerProcess {
    pub(super) pid: u32,
    start: u64,
    pidfd: OwnedFd,
}

impl WorkerProcess {
    pub(super) fn capture(pid: u32) -> Result<Self> {
        let id = Pid::from_raw(i32::try_from(pid).map_err(unavailable)?)
            .ok_or(WorkerSupervisorError::Untrusted)?;
        let pidfd = pidfd_open(id, PidfdFlags::NONBLOCK).map_err(unavailable)?;
        let start = process_start(pid)?;
        Ok(Self { pid, start, pidfd })
    }

    pub(super) fn verify(&self, credentials: WorkerCredentials, cgroup: &str) -> Result<()> {
        verify_process(
            &self.pidfd,
            self.pid,
            self.start,
            credentials,
            cgroup,
            read_proc,
        )
    }

    pub(super) fn transfer(
        &self,
        credentials: WorkerCredentials,
        cgroup: &str,
        send: impl FnOnce() -> Result<WorkerAck>,
    ) -> Result<WorkerAck> {
        self.verify(credentials, cgroup)?;
        let ack = send()?;
        if ack.pid != self.pid {
            return Err(WorkerSupervisorError::Stale);
        }
        Ok(ack)
    }
}

pub(super) fn process_start(pid: u32) -> Result<u64> {
    parse_start(&read_proc(&format!("/proc/{pid}/stat"))?)
}

pub(super) fn verify_process(
    pidfd: &OwnedFd,
    pid: u32,
    start: u64,
    credentials: WorkerCredentials,
    cgroup: &str,
    read: impl Fn(&str) -> Result<String>,
) -> Result<()> {
    let descriptor = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let verify_pidfd = || {
        let info = read(&descriptor)?;
        if field(&info, "Pid:").and_then(|value| value.parse::<u32>().ok()) != Some(pid) {
            return Err(WorkerSupervisorError::Stale);
        }
        Ok(())
    };
    verify_pidfd()?;
    let prefix = format!("/proc/{pid}");
    if parse_start(&read(&format!("{prefix}/stat"))?)? != start {
        return Err(WorkerSupervisorError::Stale);
    }
    let status = read(&format!("{prefix}/status"))?;
    if !all_ids_match(&status, "Uid:", credentials.uid)?
        || !all_ids_match(&status, "Gid:", credentials.gid)?
        || read(&format!("{prefix}/cgroup"))? != format!("0::{cgroup}\n")
    {
        return Err(WorkerSupervisorError::Stale);
    }
    // PID в fdinfo сохраняется и у ещё не убранного zombie.
    if parse_start(&read(&format!("{prefix}/stat"))?)? != start {
        return Err(WorkerSupervisorError::Stale);
    }
    verify_pidfd()
}

fn all_ids_match(status: &str, key: &str, expected: u32) -> Result<bool> {
    let ids = field(status, key).ok_or(WorkerSupervisorError::Untrusted)?;
    let mut ids = ids.split_whitespace();
    for _ in 0..4 {
        let value = ids.next().ok_or(WorkerSupervisorError::Stale)?;
        if value.parse::<u32>().map_err(unavailable)? != expected {
            return Ok(false);
        }
    }
    Ok(ids.next().is_none())
}

fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .map(str::trim)
}

fn parse_start(stat: &str) -> Result<u64> {
    let (_, tail) = stat
        .rsplit_once(')')
        .ok_or(WorkerSupervisorError::Untrusted)?;
    let mut fields = tail.split_whitespace();
    let state = fields.next().ok_or(WorkerSupervisorError::Untrusted)?;
    if matches!(state, "Z" | "X" | "x") {
        return Err(WorkerSupervisorError::Stale);
    }
    fields
        .nth(18)
        .and_then(|value| value.parse().ok())
        .ok_or(WorkerSupervisorError::Untrusted)
}

fn read_proc(path: &str) -> Result<String> {
    std::fs::read_to_string(path).map_err(unavailable)
}

fn unavailable<T>(_: T) -> WorkerSupervisorError {
    WorkerSupervisorError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::WorkerStatus;

    #[test]
    fn exited_child_cannot_receive_payload_even_before_wait() {
        use rustix::process::{WaitId, WaitIdOptions, waitid};
        use std::process::{Command, Stdio};

        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let process = WorkerProcess::capture(child.id()).unwrap();
        let credentials = WorkerCredentials {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
        };
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let cgroup = cgroup.strip_prefix("0::").unwrap().trim_end();
        drop(child.stdin.take());
        let exited = waitid(
            WaitId::Pid(Pid::from_raw(child.id() as i32).unwrap()),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        );
        let result = process.verify(credentials, cgroup);
        assert!(child.wait().unwrap().success());
        assert!(exited.unwrap().is_some());
        assert_eq!(result, Err(WorkerSupervisorError::Stale));
    }

    #[test]
    fn rejected_process_never_sends_and_ack_must_belong_to_captured_pid() {
        let process = WorkerProcess::capture(std::process::id()).unwrap();
        let credentials = WorkerCredentials {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
        };
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let cgroup = cgroup.strip_prefix("0::").unwrap().trim_end();
        assert!(matches!(
            process.transfer(credentials, "/yonik-unrelated-worker", || panic!(
                "Передача чужому worker"
            )),
            Err(WorkerSupervisorError::Stale)
        ));
        assert!(matches!(
            process.transfer(credentials, cgroup, || Ok(WorkerAck {
                pid: process.pid + 1,
                status: WorkerStatus::Checked,
            })),
            Err(WorkerSupervisorError::Stale)
        ));
        let ack = process
            .transfer(credentials, cgroup, || {
                Ok(WorkerAck {
                    pid: process.pid,
                    status: WorkerStatus::Checked,
                })
            })
            .unwrap();
        assert_eq!(ack.pid, process.pid);
    }
}
