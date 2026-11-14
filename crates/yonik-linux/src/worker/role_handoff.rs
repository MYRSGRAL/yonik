//! Private role transport. Успешный roundtrip не является kernel admission.
use super::WorkerError;
use rustix::net::{
    self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use std::{
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, OwnedFd},
    time::Instant,
};

pub const OFFER: &[u8; 8] = b"YNKANC02";
pub const FRAME: usize = 192;

/// Trusted binding задаёт issuer, а не native RPC. Не admission proof.
pub struct Binding {
    pub nonce: [u8; 32],
    pub digest: [u8; 32],
    pub epoch: u64,
    pub session: [u8; 16],
    pub generation: u64,
    pub invocation: [u8; 16],
    pub server_pid: u32,
    pub server_start: u64,
}
impl Binding {
    pub fn record(&self) -> Result<[u8; FRAME], WorkerError> {
        if self.nonce == [0; 32]
            || self.digest == [0; 32]
            || self.epoch == 0
            || self.session == [0; 16]
            || self.generation == 0
            || self.invocation == [0; 16]
            || self.server_pid == 0
            || self.server_start == 0
        {
            return Err(WorkerError::Protocol);
        }
        let mut b = [0; FRAME];
        b[..8].copy_from_slice(b"YNKROLE1");
        b[8..40].copy_from_slice(&self.nonce);
        b[40..72].copy_from_slice(&self.digest);
        b[72..80].copy_from_slice(&self.epoch.to_be_bytes());
        b[80..96].copy_from_slice(&self.session);
        b[96..104].copy_from_slice(&self.generation.to_be_bytes());
        b[104..120].copy_from_slice(&self.invocation);
        b[120..124].copy_from_slice(&self.server_pid.to_be_bytes());
        b[128..136].copy_from_slice(&self.server_start.to_be_bytes());
        b[144..146].copy_from_slice(&2u16.to_be_bytes());
        b[146..148].copy_from_slice(&1u16.to_be_bytes());
        b[148..150].copy_from_slice(&2u16.to_be_bytes());
        Ok(b)
    }
}
/// Владеет только channel/pidfd; error/drop закрывают оба. Env не authority.
pub struct Roles {
    pub channel: OwnedFd,
    pub server_pidfd: OwnedFd,
    pub record: [u8; FRAME],
}

fn setup(socket: &OwnedFd, deadline: Instant) -> Result<(), WorkerError> {
    if net::sockopt::socket_type(socket).map_err(|_| WorkerError::Peer)?
        != net::SocketType::SEQPACKET
        || !net::sockopt::socket_passcred(socket).map_err(|_| WorkerError::Peer)?
    {
        return Err(WorkerError::Peer);
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(WorkerError::Timeout)?
        .min(std::time::Duration::from_secs(1));
    for kind in [net::sockopt::Timeout::Recv, net::sockopt::Timeout::Send] {
        net::sockopt::set_socket_timeout(socket, kind, Some(remaining))
            .map_err(|_| WorkerError::Io)?;
    }
    Ok(())
}
fn send(
    socket: &OwnedFd,
    bytes: &[u8; FRAME],
    fds: &[std::os::fd::BorrowedFd<'_>],
) -> Result<(), WorkerError> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(WorkerError::Protocol);
    }
    if net::sendmsg(
        socket,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(|_| WorkerError::Io)?
        != FRAME
    {
        return Err(WorkerError::Protocol);
    }
    Ok(())
}
fn receive(
    socket: &OwnedFd,
    expected: &[u8; FRAME],
    pid: u32,
    uid: u32,
    count: usize,
    deadline: Instant,
) -> Result<Vec<OwnedFd>, WorkerError> {
    setup(socket, deadline)?;
    let mut bytes = [0; FRAME + 1];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let msg = net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| WorkerError::Io)?;
    let mut fds = Vec::new();
    let mut cred = None;
    let mut rights = false;
    for part in ancillary.drain() {
        match part {
            RecvAncillaryMessage::ScmRights(r) if !rights => {
                rights = true;
                fds.extend(r);
            }
            RecvAncillaryMessage::ScmCredentials(c) if cred.is_none() => cred = Some(c),
            _ => return Err(WorkerError::Protocol),
        }
    }
    let c = cred.ok_or(WorkerError::Peer)?;
    if Instant::now() >= deadline
        || msg.bytes != FRAME
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || bytes[..FRAME] != expected[..]
        || fds.len() != count
        || c.pid.as_raw_pid() as u32 != pid
        || c.uid.as_raw() != uid
    {
        return Err(WorkerError::Peer);
    }
    Ok(fds)
}
fn live_server(pidfd: &OwnedFd, binding: &Binding) -> Result<(), WorkerError> {
    use std::os::fd::AsRawFd;
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(|_| WorkerError::Peer)?;
    let pid = info.lines().find_map(|s| {
        s.strip_prefix("Pid:")
            .and_then(|s| s.trim().parse::<u32>().ok())
    });
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", binding.server_pid))
        .map_err(|_| WorkerError::Peer)?;
    let start = stat
        .rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .and_then(|s| s.parse::<u64>().ok());
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata(format!("/proc/{}", binding.server_pid))
        .map_err(|_| WorkerError::Peer)?
        .uid();
    if uid != 0 || pid != Some(binding.server_pid) || start != Some(binding.server_start) {
        return Err(WorkerError::Peer);
    }
    Ok(())
}
/// Только transport observation; caller не может превратить его в VerifiedWorkerUnit.
pub fn receive_roles(
    socket: &OwnedFd,
    binding: &Binding,
    deadline: Instant,
) -> Result<Roles, WorkerError> {
    let deadline = deadline.min(Instant::now() + std::time::Duration::from_secs(1));
    let record = binding.record()?;
    let fds = receive(socket, &record, binding.server_pid, 0, 2, deadline)?;
    let [channel, server_pidfd]: [OwnedFd; 2] =
        fds.try_into().map_err(|_| WorkerError::Protocol)?;
    setup(&channel, deadline)?;
    let peer = net::sockopt::socket_peercred(&channel).map_err(|_| WorkerError::Peer)?;
    if peer.pid.as_raw_pid() as u32 != binding.server_pid || !peer.uid.is_root() {
        return Err(WorkerError::Peer);
    }
    live_server(&server_pidfd, binding)?;
    let mut ack = record;
    ack[..8].copy_from_slice(b"YNKRACK1");
    setup(socket, deadline)?;
    send(socket, &ack, &[])?;
    Ok(Roles {
        channel,
        server_pidfd,
        record,
    })
}
/// Run хранит exact роли до exec; любой ранний возврат закрывает owned FD.
pub(crate) struct RunHandoff {
    permit: ProductionPermit,
    transport: VerifiedTransport,
}

/// Одноразовое владение проверенным transport, не kernel admission и не permit.
struct VerifiedTransport {
    roles: Roles,
    binding: Binding,
}
impl RunHandoff {
    pub(crate) fn exec(self, command: &mut std::process::Command) -> Result<(), WorkerError> {
        self.permit.exec_run(self.transport, command)
    }
}

fn bound_record(
    record: &[u8; FRAME],
    challenge: &[u8; 128],
    helper_pid: u32,
) -> Result<Binding, WorkerError> {
    let binding = Binding {
        nonce: record[8..40]
            .try_into()
            .map_err(|_| WorkerError::Protocol)?,
        digest: record[40..72]
            .try_into()
            .map_err(|_| WorkerError::Protocol)?,
        epoch: u64::from_be_bytes(
            record[72..80]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ),
        session: record[80..96]
            .try_into()
            .map_err(|_| WorkerError::Protocol)?,
        generation: u64::from_be_bytes(
            record[96..104]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ),
        invocation: record[104..120]
            .try_into()
            .map_err(|_| WorkerError::Protocol)?,
        server_pid: u32::from_be_bytes(
            record[120..124]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ),
        server_start: u64::from_be_bytes(
            record[128..136]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ),
    };
    if binding.record()? != *record
        || record[8..72] != challenge[8..72]
        || record[80..96] != challenge[72..88]
        || record[96..104] != challenge[88..96]
        || record[104..120] != challenge[96..112]
        || binding.server_pid != helper_pid
    {
        return Err(WorkerError::Peer);
    }
    Ok(binding)
}

pub(crate) fn receive_run_handoff(
    socket: &OwnedFd,
    challenge: &[u8; 128],
    helper_pid: u32,
    deadline: Instant,
) -> Result<RunHandoff, WorkerError> {
    // Gate предшествует чтению ролей и payload. Kernel proof пока не разрешён.
    let permit = ProductionPermit::mint()?;
    let transport = receive_verified_transport(socket, challenge, helper_pid, deadline)?;
    Ok(RunHandoff { permit, transport })
}

#[cfg(all(
    target_arch = "x86_64",
    target_pointer_width = "64",
    target_env = "gnu"
))]
pub(super) fn receive_v4_handoff(
    socket: &OwnedFd,
    challenge: &[u8; 128],
    helper_pid: u32,
    deadline: Instant,
    produced: super::native_data::ProducedV4,
) -> Result<RunHandoff, WorkerError> {
    let transport = receive_verified_transport(socket, challenge, helper_pid, deadline)?;
    produced.matches(&transport.binding)?;
    Ok(RunHandoff {
        permit: ProductionPermit { _private: () },
        transport,
    })
}

/// Единственный receiver-конструктор: caller bytes и Roles сами по себе не proof.
fn receive_verified_transport(
    socket: &OwnedFd,
    challenge: &[u8; 128],
    helper_pid: u32,
    deadline: Instant,
) -> Result<VerifiedTransport, WorkerError> {
    setup(socket, deadline)?;
    let mut record = [0; FRAME];
    let (size, _) = net::recv(socket, &mut record, RecvFlags::PEEK).map_err(|_| WorkerError::Io)?;
    if size != FRAME {
        return Err(WorkerError::Protocol);
    }
    let binding = bound_record(&record, challenge, helper_pid)?;
    let roles = receive_roles(socket, &binding, deadline)?;
    Ok(VerifiedTransport { roles, binding })
}

/// Неподделываемый production gate: конструкторов и caller bool нет.
pub struct ProductionPermit {
    _private: (),
}
impl ProductionPermit {
    pub fn mint() -> Result<Self, WorkerError> {
        Err(WorkerError::Peer)
    }
    /// Только protected Run producer. При failed exec owned roles закрываются.
    fn exec_run(
        self,
        transport: VerifiedTransport,
        command: &mut std::process::Command,
    ) -> Result<(), WorkerError> {
        use std::os::{fd::AsRawFd, unix::process::CommandExt};
        let VerifiedTransport { roles, binding } = transport;
        if roles.record != binding.record()? {
            return Err(WorkerError::Protocol);
        }
        live_server(&roles.server_pidfd, &binding)?;
        let mut hex = String::with_capacity(FRAME * 2);
        use std::fmt::Write;
        for byte in roles.record {
            write!(&mut hex, "{byte:02x}").map_err(|_| WorkerError::Protocol)?;
        }
        command
            .env_clear()
            .env(
                "YONIK_NATIVE_BROKER_FD",
                roles.channel.as_raw_fd().to_string(),
            )
            .env(
                "YONIK_NATIVE_BROKER_SERVER_PIDFD",
                roles.server_pidfd.as_raw_fd().to_string(),
            )
            .env("YONIK_NATIVE_BROKER_BINDING", hex);
        for fd in [&roles.channel, &roles.server_pidfd] {
            let flags = rustix::io::fcntl_getfd(fd).map_err(|_| WorkerError::Io)?;
            rustix::io::fcntl_setfd(fd, flags & !rustix::io::FdFlags::CLOEXEC)
                .map_err(|_| WorkerError::Io)?;
        }
        let _error = command.exec();
        Err(WorkerError::Io)
    }
    pub fn handoff(
        self,
        socket: &OwnedFd,
        roles: Roles,
        binding: &Binding,
        worker_pid: u32,
        worker_uid: u32,
        deadline: Instant,
    ) -> Result<(), WorkerError> {
        transport_send(socket, roles, binding, worker_pid, worker_uid, deadline)
    }
}
/// Consuming sender сохраняет owning stamp у supervisor до первой отправки.
#[allow(clippy::too_many_arguments)] // Frozen роли, binding и authenticated peer остаются раздельными.
pub(crate) fn handoff_verified_run(
    run: crate::helper::native_bootstrap::RunRole,
    socket: &OwnedFd,
    roles: Roles,
    binding: &Binding,
    pid: u32,
    uid: u32,
    deadline: Instant,
    retain: impl FnOnce(crate::helper::native_bootstrap::RuntimeScopeStamp),
) -> Result<(), WorkerError> {
    run.validate().map_err(|_| WorkerError::Peer)?;
    let (nonce, session, generation, invocation, epoch, digest) =
        run.context().map_err(|_| WorkerError::Peer)?;
    if nonce != binding.nonce
        || session != binding.session
        || generation != binding.generation
        || invocation != binding.invocation
        || epoch != binding.epoch
        || digest != binding.digest
    {
        return Err(WorkerError::Peer);
    }
    retain(run.into_guard());
    transport_send(socket, roles, binding, pid, uid, deadline)
}
fn transport_send(
    socket: &OwnedFd,
    roles: Roles,
    binding: &Binding,
    pid: u32,
    uid: u32,
    deadline: Instant,
) -> Result<(), WorkerError> {
    let deadline = deadline.min(Instant::now() + std::time::Duration::from_secs(1));
    let record = binding.record()?;
    if record != roles.record {
        return Err(WorkerError::Protocol);
    }
    live_server(&roles.server_pidfd, binding)?;
    setup(socket, deadline)?;
    send(
        socket,
        &record,
        &[roles.channel.as_fd(), roles.server_pidfd.as_fd()],
    )?;
    let mut ack = record;
    ack[..8].copy_from_slice(b"YNKRACK1");
    receive(socket, &ack, pid, uid, 0, deadline)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Требуется разрешённый uid_map в собственном userns; отдельный runtime gate"]
    fn verified_transport_userns_roundtrip() {
        let result = std::process::Command::new("unshare")
            .args(["-Ur"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "worker::role_handoff::tests::verified_transport_child",
            ])
            .env("YONIK_VERIFIED_TRANSPORT_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
    }

    #[test]
    fn verified_transport_child() {
        if std::env::var_os("YONIK_VERIFIED_TRANSPORT_CHILD").is_none() {
            return;
        }
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let baseline = count();
        // Изолированный собственный userns: никаких foreign UID или kernel admission.
        for case in 0..8 {
            {
                let pair = || {
                    let (a, b) = net::socketpair(
                        net::AddressFamily::UNIX,
                        net::SocketType::SEQPACKET,
                        net::SocketFlags::CLOEXEC,
                        None,
                    )
                    .unwrap();
                    net::sockopt::set_socket_passcred(&a, true).unwrap();
                    net::sockopt::set_socket_passcred(&b, true).unwrap();
                    (a, b)
                };
                let (rx, tx) = pair();
                let (channel, _peer) = pair();
                let pidfd = rustix::process::pidfd_open(
                    rustix::process::getpid(),
                    rustix::process::PidfdFlags::NONBLOCK,
                )
                .unwrap();
                let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
                let start = stat
                    .rsplit_once(')')
                    .unwrap()
                    .1
                    .split_whitespace()
                    .nth(19)
                    .unwrap()
                    .parse()
                    .unwrap();
                let binding = Binding {
                    nonce: [1; 32],
                    digest: [2; 32],
                    epoch: 3,
                    session: [4; 16],
                    generation: 5,
                    invocation: [6; 16],
                    server_pid: std::process::id(),
                    server_start: start,
                };
                let mut record = binding.record().unwrap();
                let mut challenge = [0; 128];
                challenge[8..72].copy_from_slice(&record[8..72]);
                challenge[72..88].copy_from_slice(&record[80..96]);
                challenge[88..96].copy_from_slice(&record[96..104]);
                challenge[96..112].copy_from_slice(&record[104..120]);
                match case {
                    1 => challenge[8] ^= 1, // replay чужого challenge
                    2 => record[191] ^= 1,  // exact bytes, включая reserved
                    3 => record[128..136].copy_from_slice(&(start + 1).to_be_bytes()),
                    _ => {}
                }
                let null = std::fs::File::open("/dev/null").unwrap();
                let identity = if case == 4 {
                    null.as_fd()
                } else {
                    pidfd.as_fd()
                };
                let channel_fd = if case == 7 {
                    null.as_fd()
                } else {
                    channel.as_fd()
                };
                send(&tx, &record, &[channel_fd, identity]).unwrap();
                let deadline = if case == 5 {
                    Instant::now()
                } else {
                    Instant::now() + std::time::Duration::from_secs(1)
                };
                let helper = binding.server_pid + u32::from(case == 6);
                let result = receive_verified_transport(&rx, &challenge, helper, deadline);
                if case == 0 {
                    let verified = result.expect("реальный transport должен пройти");
                    assert_eq!(verified.binding.record().unwrap(), record);
                    assert_eq!(verified.roles.record, record);
                    let mut ack = record;
                    ack[..8].copy_from_slice(b"YNKRACK1");
                    receive(&tx, &ack, binding.server_pid, 0, 0, deadline).unwrap();
                    drop(verified);
                } else {
                    assert!(result.is_err(), "case {case}");
                }
            }
            assert_eq!(count(), baseline, "FD cleanup case {case}");
        }
    }

    #[test]
    fn run_gate_refuses_before_reading_roles() {
        let (rx, _tx) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        // Пустой канал: чтение зависло бы, gate должен отказать немедленно.
        assert!(matches!(
            receive_run_handoff(&rx, &[0; 128], std::process::id(), Instant::now()),
            Err(WorkerError::Peer)
        ));
    }

    #[test]
    fn run_record_is_bound_to_closed_challenge_and_helper() {
        let binding = Binding {
            nonce: [1; 32],
            digest: [2; 32],
            epoch: 1,
            session: [3; 16],
            generation: 2,
            invocation: [4; 16],
            server_pid: 42,
            server_start: 7,
        };
        let record = binding.record().unwrap();
        let mut challenge = [0; 128];
        challenge[8..72].copy_from_slice(&record[8..72]);
        challenge[72..88].copy_from_slice(&record[80..96]);
        challenge[88..96].copy_from_slice(&record[96..104]);
        challenge[96..112].copy_from_slice(&record[104..120]);
        assert!(bound_record(&record, &challenge, 42).is_ok());
        assert!(bound_record(&record, &challenge, 43).is_err());
        for index in [8, 40, 72, 88, 96] {
            let mut forged = challenge;
            forged[index] ^= 1;
            assert!(bound_record(&record, &forged, 42).is_err());
        }
        for index in [0, 124, 136, 144, 191] {
            let mut forged = record;
            forged[index] ^= 1;
            assert!(bound_record(&forged, &challenge, 42).is_err());
        }
    }

    #[test]
    fn actual_exact_two_fd_roundtrip_and_cleanup() {
        let (rx, tx) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        net::sockopt::set_socket_passcred(&rx, true).unwrap();
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/proc/self/ns/net").unwrap();
        let bytes = [42; FRAME];
        send(&tx, &bytes, &[first.as_fd(), second.as_fd()]).unwrap();
        let fds = receive(
            &rx,
            &bytes,
            std::process::id(),
            rustix::process::getuid().as_raw(),
            2,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(fds.len(), 2);
        assert_eq!(
            rustix::fs::fstat(&fds[0]).unwrap().st_rdev,
            rustix::fs::fstat(&first).unwrap().st_rdev
        );
        assert_eq!(
            rustix::fs::fstat(&fds[1]).unwrap().st_ino,
            rustix::fs::fstat(&second).unwrap().st_ino
        );
        for fd in &fds {
            assert!(
                rustix::io::fcntl_getfd(fd)
                    .unwrap()
                    .contains(rustix::io::FdFlags::CLOEXEC)
            );
        }
        drop(fds);
        for count in [0, 1, 3] {
            send(&tx, &bytes, &[first.as_fd(), second.as_fd()]).unwrap();
            assert!(
                receive(
                    &rx,
                    &bytes,
                    std::process::id(),
                    rustix::process::getuid().as_raw(),
                    count,
                    Instant::now() + std::time::Duration::from_secs(1)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn rejected_fd_packets_do_not_leak() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "worker::role_handoff::tests::cleanup_child"])
            .env("YONIK_ROLE_CLEANUP_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
    }
    #[test]
    fn cleanup_child() {
        if std::env::var_os("YONIK_ROLE_CLEANUP_CHILD").is_none() {
            return;
        }
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let baseline = count();
        for _ in 0..32 {
            {
                let (rx, tx) = net::socketpair(
                    net::AddressFamily::UNIX,
                    net::SocketType::SEQPACKET,
                    net::SocketFlags::CLOEXEC,
                    None,
                )
                .unwrap();
                net::sockopt::set_socket_passcred(&rx, true).unwrap();
                let file = std::fs::File::open("/dev/null").unwrap();
                send(&tx, &[42; FRAME], &[file.as_fd(), file.as_fd()]).unwrap();
                assert!(
                    receive(
                        &rx,
                        &[42; FRAME],
                        std::process::id() + 1,
                        rustix::process::getuid().as_raw(),
                        2,
                        Instant::now() + std::time::Duration::from_secs(1)
                    )
                    .is_err()
                );
            }
            assert_eq!(count(), baseline);
        }
    }
    #[test]
    fn frozen_offsets_and_failclosed_mint() {
        let b = Binding {
            nonce: [1; 32],
            digest: [2; 32],
            epoch: 3,
            session: [4; 16],
            generation: 5,
            invocation: [6; 16],
            server_pid: 7,
            server_start: 8,
        };
        let r = b.record().unwrap();
        assert_eq!(r.len(), 192);
        assert_eq!(&r[..8], b"YNKROLE1");
        assert_eq!(&r[144..150], &[0, 2, 0, 1, 0, 2]);
        assert!(r[150..].iter().all(|b| *b == 0));
        assert!(ProductionPermit::mint().is_err());
    }
    #[test]
    fn every_binding_byte_is_fenced() {
        let b = Binding {
            nonce: [1; 32],
            digest: [2; 32],
            epoch: 3,
            session: [4; 16],
            generation: 5,
            invocation: [6; 16],
            server_pid: 7,
            server_start: 8,
        };
        for index in 0..FRAME {
            let (rx, tx) = net::socketpair(
                net::AddressFamily::UNIX,
                net::SocketType::SEQPACKET,
                net::SocketFlags::CLOEXEC,
                None,
            )
            .unwrap();
            net::sockopt::set_socket_passcred(&rx, true).unwrap();
            let expected = b.record().unwrap();
            let mut bad = expected;
            bad[index] ^= 1;
            send(&tx, &bad, &[]).unwrap();
            assert!(
                receive(
                    &rx,
                    &expected,
                    std::process::id(),
                    rustix::process::getuid().as_raw(),
                    0,
                    Instant::now() + std::time::Duration::from_secs(1)
                )
                .is_err()
            );
        }
    }
}
