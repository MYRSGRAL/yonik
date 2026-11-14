//! Опциональный private bootstrap transport, до untrusted payload и assets.
//! NamespaceObservation не является proof/admission authority.
use super::{TIMEOUT, WorkerError, WorkerMode};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::{
    fs::File,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const OFFER: &[u8; 8] = b"YNKANC01";
const V3_OFFER: &[u8; 8] = b"YNKANC03";
const FRAME: usize = 128;
const _: () = assert!(FRAME <= 256);
const DEADLINE: Duration = Duration::from_secs(1);

/// Helper binding: поля не декодируются из caller RPC.
pub struct Challenge {
    bytes: [u8; FRAME],
    deadline: Instant,
}
impl Challenge {
    pub fn new(
        digest: [u8; 32],
        session: [u8; 16],
        generation: u64,
        invocation: [u8; 16],
    ) -> Result<Self, WorkerError> {
        if digest == [0; 32] || session == [0; 16] || generation == 0 || invocation == [0; 16] {
            return Err(WorkerError::Protocol);
        }
        let mut bytes = [0; FRAME];
        bytes[..8].copy_from_slice(b"YNKNS001");
        getrandom::getrandom(&mut bytes[8..40]).map_err(|_| WorkerError::Io)?;
        bytes[40..72].copy_from_slice(&digest);
        bytes[72..88].copy_from_slice(&session);
        bytes[88..96].copy_from_slice(&generation.to_be_bytes());
        bytes[96..112].copy_from_slice(&invocation);
        Ok(Self {
            bytes,
            deadline: Instant::now() + DEADLINE,
        })
    }
    /// Только opaque owner token; это transport binding, не namespace admission.
    pub(crate) fn for_authorization(
        authorization: &crate::helper::run_authorization::RunAuthorization,
        digest: [u8; 32],
        invocation: [u8; 16],
    ) -> Result<Self, WorkerError> {
        let (nonce, session, generation) = authorization
            .challenge_context()
            .map_err(|_| WorkerError::Protocol)?;
        if digest == [0; 32] || invocation == [0; 16] {
            return Err(WorkerError::Protocol);
        }
        let mut bytes = [0; FRAME];
        bytes[..8].copy_from_slice(b"YNKNS001");
        bytes[8..40].copy_from_slice(&nonce);
        bytes[40..72].copy_from_slice(&digest);
        bytes[72..88].copy_from_slice(&session);
        bytes[88..96].copy_from_slice(&generation.to_be_bytes());
        bytes[96..112].copy_from_slice(&invocation);
        Ok(Self {
            bytes,
            deadline: Instant::now() + DEADLINE,
        })
    }
    /// Вызывается только helper для уже проверенного fixed unit PID/UID.
    /// Возвращаемое наблюдение само по себе НЕ разрешает admission.
    pub fn exchange(
        self,
        stream: &UnixStream,
        pid: u32,
        uid: u32,
    ) -> Result<NamespaceObservation, WorkerError> {
        self.exchange_marker(stream, pid, uid, OFFER)
    }
    /// Отдельное ожидаемое v3 состояние: legacy fallback здесь невозможен.
    pub(crate) fn exchange_kernel(
        mut self,
        stream: &UnixStream,
        pid: u32,
        uid: u32,
    ) -> Result<NamespaceObservation, WorkerError> {
        self.bytes[..8].copy_from_slice(b"YNKNS003");
        self.exchange_marker(stream, pid, uid, V3_OFFER)
    }
    /// Только UNIT: существующий report slot, без production caller.
    #[cfg(test)]
    pub(crate) fn exchange_v4(
        mut self,
        stream: &UnixStream,
        pid: u32,
        uid: u32,
        deadline: Instant,
    ) -> Result<(NamespaceObservation, [u8; 512]), WorkerError> {
        self.deadline = self.deadline.min(deadline);
        self.bytes[..8].copy_from_slice(b"YNKNS003");
        let observation = self.exchange_marker(stream, pid, uid, b"YNKANC04")?;
        let data = observation
            .custody
            .data_v4
            .lock()
            .map_err(|_| WorkerError::Protocol)?
            .as_ref()
            .copied()
            .ok_or(WorkerError::Protocol)?;
        Ok((observation, data))
    }
    /// Production DATA carrier: epoch задаёт owner, не ответ worker.
    pub(crate) fn exchange_v4_bound(
        mut self,
        stream: &UnixStream,
        pid: u32,
        uid: u32,
        deadline: Instant,
        epoch: u64,
    ) -> Result<(NamespaceObservation, [u8; 512]), WorkerError> {
        if epoch == 0 {
            return Err(WorkerError::Protocol);
        }
        self.deadline = self.deadline.min(deadline);
        self.bytes[..8].copy_from_slice(b"YNKCH004");
        self.bytes[112..120].copy_from_slice(&epoch.to_be_bytes());
        let observation = self.exchange_marker(stream, pid, uid, b"YNKANC04")?;
        let data = observation
            .custody
            .data_v4
            .lock()
            .map_err(|_| WorkerError::Protocol)?
            .as_ref()
            .copied()
            .ok_or(WorkerError::Protocol)?;
        Ok((observation, data))
    }
    /// Binding формируется из уже свежего namespace challenge. Поля server остаются
    /// наблюдением issuer до отдельного canonical PID1/kernel admission.
    pub fn role_binding(
        &self,
        epoch: u64,
        server_pid: u32,
        server_start: u64,
    ) -> Result<super::role_handoff::Binding, WorkerError> {
        let binding = super::role_handoff::Binding {
            nonce: self.bytes[8..40]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
            digest: self.bytes[40..72]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
            epoch,
            session: self.bytes[72..88]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
            generation: u64::from_be_bytes(
                self.bytes[88..96]
                    .try_into()
                    .map_err(|_| WorkerError::Protocol)?,
            ),
            invocation: self.bytes[96..112]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
            server_pid,
            server_start,
        };
        binding.record()?;
        Ok(binding)
    }
    /// Private v2 negotiation доступна только за непроизводимым production gate.
    pub fn exchange_for_handoff(
        self,
        _permit: &super::role_handoff::ProductionPermit,
        binding: &super::role_handoff::Binding,
        stream: &UnixStream,
        pid: u32,
        uid: u32,
    ) -> Result<NamespaceObservation, WorkerError> {
        let expected =
            self.role_binding(binding.epoch, binding.server_pid, binding.server_start)?;
        if expected.record()? != binding.record()? {
            return Err(WorkerError::Protocol);
        }
        self.exchange_marker(stream, pid, uid, super::role_handoff::OFFER)
    }
    fn exchange_marker(
        self,
        stream: &UnixStream,
        pid: u32,
        uid: u32,
        offer: &[u8; 8],
    ) -> Result<NamespaceObservation, WorkerError> {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
        stream
            .set_write_timeout(Some(
                self.deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(WorkerError::Timeout)?,
            ))
            .map_err(|_| WorkerError::Io)?;
        let (rx, tx) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| WorkerError::Io)?;
        for socket in [&rx, &tx] {
            rustix::net::sockopt::set_socket_passcred(socket, true).map_err(|_| WorkerError::Io)?;
        }
        timeout(&rx, self.deadline)?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let rights = [tx.as_fd()];
        if !ancillary.push(SendAncillaryMessage::ScmRights(&rights)) {
            return Err(WorkerError::Protocol);
        }
        if sendmsg(
            stream,
            &[IoSlice::new(offer)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .map_err(|_| WorkerError::Io)?
            != offer.len()
        {
            return Err(WorkerError::Protocol);
        }
        drop(tx);
        send(&rx, &self.bytes, &[])?;
        let data_v4 = if offer == b"YNKANC04" {
            let (bytes, fds, credentials) = receive_sized::<512>(&rx, self.deadline)?;
            if !fds.is_empty()
                || credentials.pid.as_raw_pid() as u32 != pid
                || credentials.uid.as_raw() != uid
            {
                return Err(WorkerError::Peer);
            }
            Some(bytes)
        } else {
            None
        };
        let report = if offer == V3_OFFER {
            let (bytes, fds, credentials) = receive(&rx, self.deadline)?;
            if !fds.is_empty()
                || credentials.pid.as_raw_pid() as u32 != pid
                || credentials.uid.as_raw() != uid
            {
                return Err(WorkerError::Peer);
            }
            Some(KernelObservation::decode(bytes, &self.bytes)?)
        } else {
            None
        };
        let (bytes, mut fds, credentials) = receive(&rx, self.deadline)?;
        if bytes != self.bytes
            || fds.len() != 3
            || credentials.pid.as_raw_pid() as u32 != pid
            || credentials.uid.as_raw() != uid
        {
            return Err(WorkerError::Peer);
        }
        for (fd, kind) in fds.iter().zip([
            yonik_nsfs::NamespaceType::Net,
            yonik_nsfs::NamespaceType::Pid,
            yonik_nsfs::NamespaceType::Mount,
        ]) {
            if yonik_nsfs::namespace_type(fd).map_err(|_| WorkerError::Protocol)? != kind {
                return Err(WorkerError::Protocol);
            }
            if rustix::fs::fcntl_getfl(fd)
                .map_err(|_| WorkerError::Protocol)?
                .intersects(rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR)
            {
                return Err(WorkerError::Protocol);
            }
        }
        let mut identities = [(0, 0); 3];
        for (fd, identity) in fds.iter().zip(&mut identities) {
            let st = rustix::fs::fstat(fd).map_err(|_| WorkerError::Io)?;
            *identity = (st.st_dev, st.st_ino);
        }
        if identities[0] == identities[1]
            || identities[0] == identities[2]
            || identities[1] == identities[2]
        {
            return Err(WorkerError::Protocol);
        }
        // SCM_RIGHTS уже материализованы. mnt закрыт до ACK и до возврата caller,
        // который только после exchange может отправить payload.
        drop(fds.pop().ok_or(WorkerError::Protocol)?);
        let mut closed = self.bytes;
        closed[..8].copy_from_slice(b"YNKCLOSE");
        let (ack, extra, credentials) = receive(&rx, self.deadline)?;
        if ack != closed
            || !extra.is_empty()
            || credentials.pid.as_raw_pid() as u32 != pid
            || credentials.uid.as_raw() != uid
        {
            return Err(WorkerError::Peer);
        }
        send(&rx, &closed, &[])?;
        let net_pid: [OwnedFd; 2] = fds.try_into().map_err(|_| WorkerError::Protocol)?;
        let observation = NamespaceObservation::new(net_pid, identities, self.deadline)?;
        {
            let fds = observation
                .custody
                .fds
                .lock()
                .map_err(|_| WorkerError::Protocol)?;
            if fds.is_none() || Instant::now() >= self.deadline {
                return Err(WorkerError::Timeout);
            }
            *observation
                .custody
                .kernel
                .lock()
                .map_err(|_| WorkerError::Protocol)? = report;
        }
        {
            *observation
                .custody
                .data_v4
                .lock()
                .map_err(|_| WorkerError::Protocol)? = data_v4;
        }
        if offer == b"YNKANC04" {
            *observation
                .custody
                .handoff
                .lock()
                .map_err(|_| WorkerError::Protocol)? = Some(rx);
        }
        Ok(observation)
    }
}

/// Opaque authenticated observation, никогда не admission authority.
struct KernelObservation([u8; FRAME], Option<u64>);
impl KernelObservation {
    fn encode(challenge: &[u8; FRAME], report: yonik_nsfs::kernel_probe::Report) -> [u8; FRAME] {
        let mut bytes = *challenge;
        bytes[..8].copy_from_slice(b"YNKPR003");
        for (offset, errno) in [
            (112, report.unshare),
            (116, report.setns),
            (120, report.clone3),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&errno.to_be_bytes());
        }
        bytes[124..].fill(0);
        bytes
    }
    fn decode(bytes: [u8; FRAME], challenge: &[u8; FRAME]) -> Result<Self, WorkerError> {
        if &challenge[..8] != b"YNKNS003"
            || challenge[112..] != [0; 16]
            || &bytes[..8] != b"YNKPR003"
            || bytes[8..112] != challenge[8..112]
            || bytes[124..] != [0; 4]
        {
            return Err(WorkerError::Protocol);
        }
        for (offset, allowed) in [
            (112, &[1, 22][..]),
            (116, &[1, 9][..]),
            (120, &[1, 22, 38][..]),
        ] {
            let errno = i32::from_be_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| WorkerError::Protocol)?,
            );
            if !allowed.contains(&errno) {
                return Err(WorkerError::Protocol);
            }
        }
        Ok(Self(bytes, None))
    }
}
impl Drop for KernelObservation {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
        self.1 = None;
    }
}

/// Только observation. Даже с NS_GET_NSTYPE без opaque unit/kernel proof нельзя
/// преобразовать в WorkerChannelAnchor. В этом объекте нет mount namespace FD.
pub struct NamespaceObservation {
    custody: Arc<NamespaceCustody>,
    identities: NamespaceIdentity,
}
/// Opaque observation identity; не доказательство unit/kernel enforcement.
#[derive(PartialEq, Eq)]
pub struct NamespaceIdentity([(u64, u64); 3]);

struct NamespaceCustody {
    fds: Mutex<Option<[OwnedFd; 2]>>,
    expires: Mutex<Option<Instant>>,
    kernel: Mutex<Option<KernelObservation>>,
    handoff: Mutex<Option<OwnedFd>>,
    revoked: std::sync::atomic::AtomicBool,
    data_v4: Mutex<Option<[u8; 512]>>,
    bound_v4: Mutex<bool>,
}
pub(crate) struct NamespaceRevocation(Arc<NamespaceCustody>);
/// Только lifetime FD: не предоставляет lookup/admission/use authority.
pub(crate) struct NamespaceRetention {
    _custody: Arc<NamespaceCustody>,
}

impl NamespaceRevocation {
    pub(crate) fn revoke(&self) {
        self.0.deny();
    }
}
impl NamespaceCustody {
    fn deny(&self) {
        self.revoked
            .store(true, std::sync::atomic::Ordering::Release);
        self.kernel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.data_v4
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.handoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
    fn expired(&self) -> bool {
        self.revoked.load(std::sync::atomic::Ordering::Acquire)
            || self
                .expires
                .lock()
                .map_or(true, |expiry| expiry.is_some_and(|e| Instant::now() >= e))
    }
    fn close(&self) {
        // При poisoning возможен только отказ: извлекаем и закрываем custody.
        let mut fds = self
            .fds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fds.take();
        self.data_v4
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.kernel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}
impl NamespaceObservation {
    fn new(
        net_pid: [OwnedFd; 2],
        identities: [(u64, u64); 3],
        expires: Instant,
    ) -> Result<Self, WorkerError> {
        if Instant::now() >= expires {
            return Err(WorkerError::Timeout);
        }
        let custody = Arc::new(NamespaceCustody {
            fds: Mutex::new(Some(net_pid)),
            expires: Mutex::new(Some(expires)),
            kernel: Mutex::new(None),
            handoff: Mutex::new(None),
            revoked: std::sync::atomic::AtomicBool::new(false),
            data_v4: Mutex::new(None),
            bound_v4: Mutex::new(false),
        });
        Ok(Self {
            custody,
            identities: NamespaceIdentity(identities),
        })
    }
    #[cfg(test)]
    pub(crate) fn test_kernel_observation(session: [u8; 16], generation: u64) -> Self {
        let mut challenge = Challenge::new([1; 32], session, generation, [3; 16])
            .unwrap()
            .bytes;
        challenge[..8].copy_from_slice(b"YNKNS003");
        challenge[8..40].copy_from_slice(&[4; 32]);
        let report = KernelObservation::decode(
            KernelObservation::encode(
                &challenge,
                yonik_nsfs::kernel_probe::Report {
                    unshare: 22,
                    setns: 9,
                    clone3: 22,
                },
            ),
            &challenge,
        )
        .unwrap();
        let observation = Self::new(
            ["net", "pid"]
                .map(|kind| OwnedFd::from(File::open(format!("/proc/self/ns/{kind}")).unwrap())),
            [(1, 1); 3],
            Instant::now() + DEADLINE,
        )
        .unwrap();
        *observation.custody.kernel.lock().unwrap() = Some(report);
        observation
    }
    pub(crate) fn retention(&self) -> NamespaceRetention {
        NamespaceRetention {
            _custody: Arc::clone(&self.custody),
        }
    }
    pub(crate) fn same_custody(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.custody, &other.custody)
    }
    pub(crate) fn take_handoff(&self) -> Result<OwnedFd, WorkerError> {
        if self.custody.expired() {
            return Err(WorkerError::Timeout);
        }
        self.custody
            .handoff
            .lock()
            .map_err(|_| WorkerError::Protocol)?
            .take()
            .ok_or(WorkerError::Protocol)
    }
    pub(crate) fn promote_runtime(
        &self,
        stamp: &crate::helper::native_bootstrap::RuntimeScopeStamp,
    ) -> Result<(), WorkerError> {
        stamp.validate_admission().map_err(|_| WorkerError::Peer)?;
        if !stamp.owns_observation(self) {
            return Err(WorkerError::Peer);
        }
        let fds = self.custody.fds.lock().map_err(|_| WorkerError::Protocol)?;
        let mut expiry = self
            .custody
            .expires
            .lock()
            .map_err(|_| WorkerError::Protocol)?;
        if fds.is_none() || expiry.is_none_or(|e| Instant::now() >= e) {
            return Err(WorkerError::Timeout);
        }
        *expiry = None;
        Ok(())
    }
    pub(crate) fn bind_run(
        &self,
        nonce: [u8; 32],
        session: [u8; 16],
        generation: u64,
        epoch: u64,
    ) -> Result<(), WorkerError> {
        let fds = self.custody.fds.lock().map_err(|_| WorkerError::Protocol)?;
        if fds.is_none() || self.custody.expired() || epoch == 0 {
            return Err(WorkerError::Timeout);
        }
        if let Some(data) = self
            .custody
            .data_v4
            .lock()
            .map_err(|_| WorkerError::Protocol)?
            .as_ref()
        {
            if data[8..40] != nonce
                || data[72..88] != session
                || data[88..96] != generation.to_be_bytes()
                || data[112..120] != epoch.to_be_bytes()
                || std::mem::replace(
                    &mut *self
                        .custody
                        .bound_v4
                        .lock()
                        .map_err(|_| WorkerError::Protocol)?,
                    true,
                )
            {
                return Err(WorkerError::Protocol);
            }
            return Ok(());
        }
        let mut kernel = self
            .custody
            .kernel
            .lock()
            .map_err(|_| WorkerError::Protocol)?;
        let report = kernel.as_mut().ok_or(WorkerError::Protocol)?;
        if report.0[8..40] != nonce
            || report.1.is_some()
            || report.0[72..88] != session
            || report.0[88..96] != generation.to_be_bytes()
        {
            return Err(WorkerError::Protocol);
        }
        report.1 = Some(epoch);
        Ok(())
    }
    pub(crate) fn revocation(&self) -> NamespaceRevocation {
        NamespaceRevocation(Arc::clone(&self.custody))
    }
    pub fn identity(&self) -> &NamespaceIdentity {
        &self.identities
    }
    pub fn retained_namespace_count(&self) -> usize {
        if self
            .custody
            .revoked
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return 0;
        }
        if self.custody.expired() {
            self.custody.close()
        }
        self.custody
            .fds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(0, |fds| fds.len())
    }
    pub fn revoke(&self) {
        self.custody.deny()
    }
}
impl Drop for NamespaceObservation {
    fn drop(&mut self) {
        self.revoke()
    }
}

fn timeout(socket: &OwnedFd, deadline: Instant) -> Result<(), WorkerError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(WorkerError::Timeout)?;
    for kind in [
        rustix::net::sockopt::Timeout::Recv,
        rustix::net::sockopt::Timeout::Send,
    ] {
        rustix::net::sockopt::set_socket_timeout(socket, kind, Some(remaining))
            .map_err(|_| WorkerError::Io)?;
    }
    Ok(())
}
fn send(
    socket: &OwnedFd,
    bytes: &[u8],
    fds: &[std::os::fd::BorrowedFd<'_>],
) -> Result<(), WorkerError> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(WorkerError::Protocol);
    }
    if sendmsg(
        socket,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(|_| WorkerError::Io)?
        != bytes.len()
    {
        return Err(WorkerError::Protocol);
    }
    Ok(())
}
fn receive(
    socket: &OwnedFd,
    deadline: Instant,
) -> Result<([u8; FRAME], Vec<OwnedFd>, rustix::net::UCred), WorkerError> {
    receive_sized::<FRAME>(socket, deadline)
}
fn receive_sized<const N: usize>(
    socket: &OwnedFd,
    deadline: Instant,
) -> Result<([u8; N], Vec<OwnedFd>, rustix::net::UCred), WorkerError> {
    timeout(socket, deadline)?;
    let mut bytes = [0; N];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let msg = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| WorkerError::Io)?;
    let mut fds = Vec::with_capacity(3);
    let mut credentials = None;
    let mut rights = false;
    for part in ancillary.drain() {
        match part {
            RecvAncillaryMessage::ScmRights(r) if !rights => {
                rights = true;
                fds.extend(r)
            }
            RecvAncillaryMessage::ScmCredentials(c) if credentials.is_none() => {
                credentials = Some(c)
            }
            _ => return Err(WorkerError::Protocol),
        }
    }
    if Instant::now() >= deadline
        || msg.bytes != N
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(WorkerError::Protocol);
    }
    Ok((
        bytes[..N].try_into().map_err(|_| WorkerError::Protocol)?,
        fds,
        credentials.ok_or(WorkerError::Peer)?,
    ))
}

pub(crate) fn bootstrap(
    stream: &UnixStream,
    mode: WorkerMode,
) -> Result<Option<super::role_handoff::RunHandoff>, WorkerError> {
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|_| WorkerError::Io)?;
    let mut marker = [0; 8];
    let n = rustix::net::recv(stream, &mut marker, RecvFlags::PEEK | RecvFlags::WAITALL)
        .map_err(|_| WorkerError::Io)?;
    if n.0 != 8 {
        return Err(WorkerError::Protocol);
    }
    let v2 = &marker == super::role_handoff::OFFER;
    let v3 = &marker == V3_OFFER;
    let v4 = &marker == b"YNKANC04";
    if &marker != OFFER && !v2 && !v3 && !v4 {
        return Ok(None);
    }
    if mode != WorkerMode::Run {
        return Err(WorkerError::Protocol);
    }
    let peer = rustix::net::sockopt::socket_peercred(stream).map_err(|_| WorkerError::Peer)?;
    if !peer.uid.is_root() {
        return Err(WorkerError::Peer);
    }
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|_| WorkerError::Peer)?;
    let deadline = Instant::now() + DEADLINE;
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let msg = recvmsg(
        stream,
        &mut [IoSliceMut::new(&mut marker)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| WorkerError::Io)?;
    let mut sockets = Vec::with_capacity(1);
    for part in ancillary.drain() {
        match part {
            RecvAncillaryMessage::ScmRights(fds) => sockets.extend(fds),
            _ => return Err(WorkerError::Protocol),
        }
    }
    if msg.bytes != 8
        || &marker
            != if v4 {
                b"YNKANC04"
            } else if v3 {
                V3_OFFER
            } else if v2 {
                super::role_handoff::OFFER
            } else {
                OFFER
            }
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || sockets.len() != 1
    {
        return Err(WorkerError::Protocol);
    }
    let socket = sockets.pop().ok_or(WorkerError::Protocol)?;
    if rustix::net::sockopt::socket_type(&socket).map_err(|_| WorkerError::Protocol)?
        != rustix::net::SocketType::SEQPACKET
        || !rustix::net::sockopt::socket_passcred(&socket).map_err(|_| WorkerError::Protocol)?
    {
        return Err(WorkerError::Protocol);
    }
    let (challenge, extra, c) = receive(&socket, deadline)?;
    if !extra.is_empty()
        || c.pid != peer.pid
        || !c.uid.is_root()
        || &challenge[..8]
            != if v4 {
                b"YNKCH004"
            } else if v3 {
                b"YNKNS003"
            } else {
                b"YNKNS001"
            }
        || (!v4 && challenge[112..] != [0; 16])
    {
        return Err(WorkerError::Peer);
    }
    #[cfg(all(
        target_arch = "x86_64",
        target_pointer_width = "64",
        target_env = "gnu"
    ))]
    let produced = if v4 {
        let data = super::native_data::ProducedV4::produce(
            &challenge,
            peer.pid.as_raw_pid() as u32,
            deadline,
        )?;
        send(&socket, data.report()?, &[])?;
        Some(data)
    } else {
        None
    };
    #[cfg(not(all(
        target_arch = "x86_64",
        target_pointer_width = "64",
        target_env = "gnu"
    )))]
    if v4 {
        return Err(WorkerError::Peer);
    }
    if v3 {
        let report = yonik_nsfs::kernel_probe::observe().map_err(|_| WorkerError::Protocol)?;
        let bytes = KernelObservation::encode(&challenge, report);
        KernelObservation::decode(bytes, &challenge)?;
        timeout(&socket, deadline)?;
        send(&socket, &bytes, &[])?;
    }
    let files = [
        File::open("/proc/self/ns/net"),
        File::open("/proc/self/ns/pid"),
        File::open("/proc/self/ns/mnt"),
    ];
    let files = files
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| WorkerError::Io)?;
    timeout(&socket, deadline)?;
    send(
        &socket,
        &challenge,
        &files.iter().map(AsFd::as_fd).collect::<Vec<_>>(),
    )?;
    // Все sender copies закрываются до closed-ACK и до receive_payload/assets.
    drop(files);
    let mut closed = challenge;
    closed[..8].copy_from_slice(b"YNKCLOSE");
    timeout(&socket, deadline)?;
    send(&socket, &closed, &[])?;
    let (ack, extra, c) = receive(&socket, deadline)?;
    if ack != closed || !extra.is_empty() || c.pid != peer.pid || !c.uid.is_root() {
        return Err(WorkerError::Peer);
    }
    #[cfg(all(
        target_arch = "x86_64",
        target_pointer_width = "64",
        target_env = "gnu"
    ))]
    if let Some(produced) = produced {
        return super::role_handoff::receive_v4_handoff(
            &socket,
            &challenge,
            peer.pid.as_raw_pid() as u32,
            deadline,
            produced,
        )
        .map(Some);
    }
    if v2 {
        return super::role_handoff::receive_run_handoff(
            &socket,
            &challenge,
            peer.pid.as_raw_pid() as u32,
            deadline,
        )
        .map(Some);
    }
    Ok(None)
}

/// UNIT peer: не исполняет kernel probes и не требует root/foreign UID.
#[cfg(test)]
pub(crate) fn unit_v4_peer(stream: UnixStream, make: impl FnOnce(&[u8; 128]) -> (Vec<u8>, usize)) {
    let mut marker = [0; 8];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let msg = recvmsg(
        &stream,
        &mut [IoSliceMut::new(&mut marker)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .unwrap();
    assert_eq!(msg.bytes, 8);
    assert_eq!(&marker, b"YNKANC04");
    let socket = ancillary
        .drain()
        .find_map(|p| match p {
            RecvAncillaryMessage::ScmRights(mut fds) => fds.next(),
            _ => None,
        })
        .unwrap();
    let deadline = Instant::now() + DEADLINE;
    let (challenge, extra, _) = receive(&socket, deadline).unwrap();
    assert!(extra.is_empty());
    let (data, fd_count) = make(&challenge);
    let file = File::open("/dev/null").unwrap();
    let rights = vec![file.as_fd(); fd_count];
    if send(&socket, &data, &rights).is_err() {
        return;
    }
    let files = ["net", "pid", "mnt"].map(|k| File::open(format!("/proc/self/ns/{k}")).unwrap());
    if send(
        &socket,
        &challenge,
        &files.iter().map(AsFd::as_fd).collect::<Vec<_>>(),
    )
    .is_err()
    {
        return;
    }
    drop(files);
    let mut closed = challenge;
    closed[..8].copy_from_slice(b"YNKCLOSE");
    if send(&socket, &closed, &[]).is_err() {
        return;
    }
    let _ = receive(&socket, deadline);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v3_peer(stream: UnixStream, attack: &'static str) {
        let mut marker = [0; 8];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let msg = recvmsg(
            &stream,
            &mut [IoSliceMut::new(&mut marker)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )
        .unwrap();
        assert_eq!(msg.bytes, 8);
        assert_eq!(&marker, V3_OFFER);
        let socket = ancillary
            .drain()
            .find_map(|part| match part {
                RecvAncillaryMessage::ScmRights(mut fds) => fds.next(),
                _ => None,
            })
            .unwrap();
        let deadline = Instant::now() + DEADLINE;
        let (challenge, extra, _) = receive(&socket, deadline).unwrap();
        assert!(extra.is_empty());
        let mut report =
            KernelObservation::encode(&challenge, yonik_nsfs::kernel_probe::observe().unwrap());
        match attack {
            "nonce" => report[8] ^= 1,
            "digest" => report[40] ^= 1,
            "session" => report[72] ^= 1,
            "generation" => report[88] ^= 1,
            "invocation" => report[96] ^= 1,
            "reserved" => report[127] = 1,
            "unknown" => report[112..116].copy_from_slice(&1234i32.to_be_bytes()),
            "success" => report[112..116].fill(0),
            "version" => report[7] = b'2',
            "missing" => report = challenge,
            "late" => std::thread::sleep(DEADLINE + Duration::from_millis(30)),
            _ => (),
        }
        let file = File::open("/dev/null").unwrap();
        let rights = [file.as_fd()];
        if attack == "short" || attack == "long" {
            let mut bytes = report.to_vec();
            if attack == "short" {
                bytes.pop();
            } else {
                bytes.push(0);
            }
            let mut space = [];
            let _ = sendmsg(
                &socket,
                &[IoSlice::new(&bytes)],
                &mut SendAncillaryBuffer::new(&mut space),
                SendFlags::NOSIGNAL,
            );
            return;
        }
        if send(&socket, &report, if attack == "fd" { &rights } else { &[] }).is_err() {
            return;
        }
        if attack == "duplicate" {
            let _ = send(&socket, &report, &[]);
        }
        let files =
            ["net", "pid", "mnt"].map(|kind| File::open(format!("/proc/self/ns/{kind}")).unwrap());
        if send(
            &socket,
            &challenge,
            &files.iter().map(AsFd::as_fd).collect::<Vec<_>>(),
        )
        .is_err()
        {
            return;
        }
        drop(files);
        let mut closed = challenge;
        closed[..8].copy_from_slice(b"YNKCLOSE");
        if send(&socket, &closed, &[]).is_err() {
            return;
        }
        let result = receive(&socket, deadline);
        if attack == "valid" {
            assert!(result.is_ok());
        }
    }
    #[test]
    fn authorized_challenge_uses_owner_nonce_and_rejects_revoke() {
        let owner = crate::helper::run_authorization::RunAuthority::new([2; 16], 7, 9).unwrap();
        let auth = owner.authorize([4; 32]).unwrap();
        let challenge = Challenge::for_authorization(&auth, [1; 32], [3; 16]).unwrap();
        assert_eq!(&challenge.bytes[8..40], &[4; 32]);
        assert_eq!(&challenge.bytes[72..88], &[2; 16]);
        assert_eq!(&challenge.bytes[88..96], &7u64.to_be_bytes());
        owner.revoke();
        assert!(Challenge::for_authorization(&auth, [1; 32], [3; 16]).is_err());
    }

    #[test]
    fn actual_v3_bound_report_channel() {
        const CHILD: &str = "YONIK_V3_REPORT_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // FD oracle охватывает весь процесс; соседние lib-тесты меняют его FD.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "worker::anchor_exchange::tests::actual_v3_bound_report_channel",
                    "--exact",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "изолированный v3 FD oracle");
            return;
        }
        for attack in [
            "valid",
            "nonce",
            "digest",
            "session",
            "generation",
            "invocation",
            "reserved",
            "unknown",
            "success",
            "version",
            "missing",
            "fd",
            "duplicate",
            "late",
            "pid",
            "uid",
            "short",
            "long",
        ] {
            let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
            let (helper, worker) = UnixStream::pair().unwrap();
            let peer = std::thread::spawn(move || v3_peer(worker, attack));
            let result = Challenge::new([1; 32], [2; 16], 7, [3; 16])
                .unwrap()
                .exchange_kernel(
                    &helper,
                    std::process::id() + u32::from(attack == "pid"),
                    rustix::process::getuid().as_raw() + u32::from(attack == "uid"),
                );
            if attack == "valid" {
                let observation = result.unwrap();
                assert_eq!(observation.retained_namespace_count(), 2);
                assert!(observation.custody.kernel.lock().unwrap().is_some());
                observation.revoke();
                assert_eq!(observation.retained_namespace_count(), 0);
                assert!(observation.custody.kernel.lock().unwrap().is_none());
            } else {
                assert!(result.is_err(), "{attack}");
            }
            drop(helper);
            peer.join().unwrap();
            assert_eq!(
                std::fs::read_dir("/proc/self/fd").unwrap().count(),
                before,
                "{attack}"
            );
        }
    }
    #[test]
    fn kernel_report_expiry_discards_evidence_and_descriptors() {
        let observation = NamespaceObservation::test_kernel_observation([2; 16], 7);
        observation.bind_run([4; 32], [2; 16], 7, 9).unwrap();
        std::thread::sleep(DEADLINE + Duration::from_millis(30));
        assert_eq!(observation.retained_namespace_count(), 0);
        assert!(observation.custody.kernel.lock().unwrap().is_none());
        assert!(observation.bind_run([4; 32], [2; 16], 7, 10).is_err());
    }
    #[test]
    fn v3_report_exact_binding_and_closed_errno_set() {
        let mut challenge = Challenge::new([1; 32], [2; 16], 7, [3; 16]).unwrap().bytes;
        challenge[..8].copy_from_slice(b"YNKNS003");
        for unshare in [1, 22] {
            for setns in [1, 9] {
                for clone3 in [1, 22, 38] {
                    let report = KernelObservation::encode(
                        &challenge,
                        yonik_nsfs::kernel_probe::Report {
                            unshare,
                            setns,
                            clone3,
                        },
                    );
                    assert!(KernelObservation::decode(report, &challenge).is_ok());
                    for index in 0..FRAME {
                        let mut malformed = report;
                        malformed[index] ^= 128;
                        assert!(
                            KernelObservation::decode(malformed, &challenge).is_err(),
                            "{index}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn check_rejects_v2_before_accepting_descriptors() {
        use std::io::Write;
        let (worker, mut helper) = UnixStream::pair().unwrap();
        helper.write_all(super::super::role_handoff::OFFER).unwrap();
        assert!(matches!(
            bootstrap(&worker, WorkerMode::Check),
            Err(WorkerError::Protocol)
        ));
    }
    #[test]
    fn unbound_challenge_is_rejected() {
        assert!(Challenge::new([0; 32], [1; 16], 1, [2; 16]).is_err());
        assert!(Challenge::new([1; 32], [0; 16], 1, [2; 16]).is_err());
        assert!(Challenge::new([1; 32], [1; 16], 0, [2; 16]).is_err());
        assert!(Challenge::new([1; 32], [1; 16], 1, [0; 16]).is_err());
    }
    #[test]
    fn bootstrap_fixture_child() {
        if std::env::var_os("YONIK_ANCHOR_BOOTSTRAP_CHILD").is_none() {
            return;
        }
        let socket = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
        if let Ok(attack) = std::env::var("YONIK_ANCHOR_ATTACK") {
            forged_worker(&socket, &attack);
            return;
        }
        bootstrap(&socket, WorkerMode::Run).unwrap();
        for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
            let entry = entry.unwrap();
            if let Ok(target) = std::fs::read_link(entry.path()) {
                assert!(
                    !target.as_os_str().as_encoded_bytes().starts_with(b"mnt:["),
                    "bootstrap удержал mnt FD"
                );
            }
        }

        use std::io::{Read, Write};
        let mut socket = socket;
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [42]);
        socket.write_all(&byte).unwrap();
    }
    fn forged_worker(stream: &UnixStream, attack: &str) {
        let mut marker = [0; 8];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let msg = recvmsg(
            stream,
            &mut [IoSliceMut::new(&mut marker)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )
        .unwrap();
        assert_eq!(msg.bytes, 8);
        assert_eq!(&marker, OFFER);
        let mut sockets = Vec::new();
        for part in ancillary.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = part {
                sockets.extend(fds)
            } else {
                panic!("Неожиданный ancillary")
            }
        }
        assert_eq!(sockets.len(), 1);
        let socket = sockets.pop().unwrap();
        let deadline = Instant::now() + DEADLINE;
        let (mut challenge, extra, _) = receive(&socket, deadline).unwrap();
        assert!(extra.is_empty());
        match attack {
            "nonce" => challenge[8] ^= 1,
            "generation" => challenge[88] ^= 1,
            "invocation" => challenge[96] ^= 1,
            _ => (),
        }
        let mut files = vec![
            File::open("/proc/self/ns/net").unwrap(),
            File::open("/proc/self/ns/pid").unwrap(),
            File::open("/proc/self/ns/mnt").unwrap(),
        ];
        match attack {
            "generic-fd" => files[0] = File::open("/dev/null").unwrap(),
            "swapped-types" => files.swap(0, 1),
            "wrong-type" => files[2] = File::open("/proc/self/ns/uts").unwrap(),
            "duplicate-fd" => files[1] = File::open("/proc/self/ns/net").unwrap(),
            "extra-fd" => files.push(File::open("/dev/null").unwrap()),
            _ => (),
        }
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
        let rights: Vec<_> = files.iter().map(AsFd::as_fd).collect();
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        sendmsg(
            &socket,
            &[IoSlice::new(&challenge)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        drop(rights);
        drop(files);
        assert!(receive(&socket, deadline).is_err());
    }
    #[test]
    fn actual_foreign_forgery_rejections_close_all_received_fds() {
        if std::env::var_os("YONIK_ANCHOR_BOOTSTRAP_VM").is_none() {
            return;
        }
        use std::{
            os::unix::process::CommandExt,
            process::{Command, Stdio},
        };
        assert!(rustix::process::getuid().is_root());
        for attack in [
            "nonce",
            "generation",
            "invocation",
            "generic-fd",
            "duplicate-fd",
            "swapped-types",
            "wrong-type",
            "extra-fd",
            "sender-pid",
            "sender-uid",
        ] {
            let baseline = std::fs::read_dir("/proc/self/fd").unwrap().count();
            {
                let (helper, worker) = UnixStream::pair().unwrap();
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "worker::anchor_exchange::tests::bootstrap_fixture_child",
                        "--nocapture",
                    ])
                    .env("YONIK_ANCHOR_BOOTSTRAP_CHILD", "1")
                    .env("YONIK_ANCHOR_ATTACK", attack)
                    .uid(65534)
                    .gid(65534)
                    .stdin(Stdio::from(OwnedFd::from(worker)))
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap();
                let pid = child.id() + u32::from(attack == "sender-pid");
                let uid = if attack == "sender-uid" { 65533 } else { 65534 };
                assert!(
                    Challenge::new([1; 32], [2; 16], 7, [3; 16])
                        .unwrap()
                        .exchange(&helper, pid, uid)
                        .is_err(),
                    "{attack}"
                );
                assert!(child.wait().unwrap().success(), "{attack}");
            }
            assert_eq!(
                std::fs::read_dir("/proc/self/fd").unwrap().count(),
                baseline,
                "{attack}"
            );
        }
    }
    #[test]
    fn actual_foreign_bootstrap_releases_mount_before_payload() {
        if std::env::var_os("YONIK_ANCHOR_BOOTSTRAP_VM").is_none() {
            return;
        }
        assert!(rustix::process::getuid().is_root());
        use std::{
            io::{Read, Write},
            os::unix::process::CommandExt,
            process::{Command, Stdio},
        };
        let (mut helper, worker) = UnixStream::pair().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "worker::anchor_exchange::tests::bootstrap_fixture_child",
                "--nocapture",
            ])
            .env("YONIK_ANCHOR_BOOTSTRAP_CHILD", "1")
            .uid(65534)
            .gid(65534)
            .stdin(Stdio::from(OwnedFd::from(worker)))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let witness = Challenge::new([1; 32], [2; 16], 7, [3; 16])
            .unwrap()
            .exchange(&helper, child.id(), 65534)
            .unwrap();
        assert_eq!(witness.retained_namespace_count(), 2);
        let custody = witness.custody.fds.lock().unwrap();
        for fd in custody.as_ref().unwrap() {
            assert_ne!(
                rustix::fs::fstat(fd).unwrap().st_ino,
                witness.identities.0[2].1
            );
        }
        drop(custody);
        helper.write_all(&[42]).unwrap();
        let mut ack = [0];
        helper.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [42]);
        assert!(child.wait().unwrap().success());
    }
    #[test]
    fn observation_custody_expiry_and_revoke_close_descriptors() {
        let fds = || {
            [
                OwnedFd::from(File::open("/proc/self/ns/net").unwrap()),
                OwnedFd::from(File::open("/proc/self/ns/pid").unwrap()),
            ]
        };
        assert!(matches!(
            NamespaceObservation::new(fds(), [(1, 1); 3], Instant::now()),
            Err(WorkerError::Timeout)
        ));
        let witness =
            NamespaceObservation::new(fds(), [(1, 1); 3], Instant::now() + DEADLINE).unwrap();
        assert_eq!(witness.retained_namespace_count(), 2);
        witness.revoke();
        assert_eq!(witness.retained_namespace_count(), 0);
    }
    #[test]
    fn revoked_custody_denies_use_but_retains_owned_fds_until_drop() {
        use std::os::fd::AsRawFd;
        let observation = NamespaceObservation::new(
            [
                OwnedFd::from(File::open("/dev/null").unwrap()),
                OwnedFd::from(File::open("/dev/null").unwrap()),
            ],
            [(1, 1); 3],
            Instant::now() + DEADLINE,
        )
        .unwrap();
        let fd = observation.custody.fds.lock().unwrap().as_ref().unwrap()[0].as_raw_fd();
        observation.revoke();
        assert_eq!(observation.retained_namespace_count(), 0);
        assert!(observation.bind_run([1; 32], [1; 16], 1, 1).is_err());
        assert!(std::fs::metadata(format!("/proc/self/fd/{fd}")).is_ok());
        assert!(observation.same_custody(&observation));
        let retained = observation.retention();
        drop(observation);
        assert!(std::fs::metadata(format!("/proc/self/fd/{fd}")).is_ok());
        drop(retained);
        assert!(std::fs::metadata(format!("/proc/self/fd/{fd}")).is_err());
    }
    #[test]
    fn legacy_rights_remain_queued_after_bootstrap_peek() {
        let (peer, worker) = UnixStream::pair().unwrap();
        let file = File::open("/dev/null").unwrap();
        let rights = [file.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        sendmsg(
            &peer,
            &[IoSlice::new(b"YNKWRK\0\x02")],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        bootstrap(&worker, WorkerMode::Run).unwrap();
        let mut bytes = [0; 8];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let msg = recvmsg(
            &worker,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )
        .unwrap();
        assert_eq!(msg.bytes, 8);
        assert_eq!(&bytes, b"YNKWRK\0\x02");
        let mut fds = Vec::new();
        for part in ancillary.drain() {
            match part {
                RecvAncillaryMessage::ScmRights(rights) => fds.extend(rights),
                _ => panic!("Неожиданный ancillary"),
            }
        }
        assert_eq!(fds.len(), 1);
        assert_eq!(
            rustix::fs::fstat(&fds[0]).unwrap().st_rdev,
            rustix::fs::fstat(&file).unwrap().st_rdev
        );
    }
    #[test]
    fn legacy_bytes_are_not_consumed() {
        use std::io::{Read, Write};
        let (mut peer, mut worker) = UnixStream::pair().unwrap();
        peer.write_all(b"YNKWRK\0\x02").unwrap();
        bootstrap(&worker, WorkerMode::Run).unwrap();
        let mut marker = [0; 8];
        worker.read_exact(&mut marker).unwrap();
        assert_eq!(&marker, b"YNKWRK\0\x02");
    }
}
