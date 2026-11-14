//! Ограниченный последовательный transport; ошибки всегда отзывают custody.
use super::super::broker::ProjectedLookup;
use super::{Header, Kind, OwnedFd, Session, Unavailable, wire};
use rustix::net::{
    self, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendAncillaryBuffer, SendAncillaryMessage,
    SendFlags,
};
use std::{
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::AsFd,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const TICK: Duration = Duration::from_millis(1);

fn fence(deadline: Instant, cancel: &AtomicBool) -> Result<(), Unavailable> {
    if cancel.load(Ordering::Acquire) {
        return Err(Unavailable::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(Unavailable::Timeout);
    }
    Ok(())
}
fn receive(
    socket: &OwnedFd,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, Unavailable> {
    receive_inner(socket, Some(deadline), cancel)
}
fn receive_inner(
    socket: &OwnedFd,
    deadline: Option<Instant>,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, Unavailable> {
    loop {
        if let Some(deadline) = deadline {
            fence(deadline, cancel)?;
        } else if cancel.load(Ordering::Acquire) {
            return Err(Unavailable::Cancelled);
        }
        let mut bytes = [0; wire::MAX_FRAME + 1];
        let mut space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1), ScmCredentials(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        match net::recvmsg(
            socket,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
        ) {
            Ok(msg) => {
                // drain владеет полученными FD и закрывает их даже при отказе.
                let unexpected = ancillary.drain().count() != 0;
                if unexpected
                    || msg
                        .flags
                        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
                    || msg.bytes > wire::MAX_FRAME
                {
                    return Err(Unavailable::Malformed);
                }
                if msg.bytes == 0 {
                    return Err(Unavailable::Disconnected);
                }
                if let Some(deadline) = deadline {
                    fence(deadline, cancel)?;
                } else if cancel.load(Ordering::Acquire) {
                    return Err(Unavailable::Cancelled);
                }
                return Ok(bytes[..msg.bytes].to_vec());
            }
            Err(rustix::io::Errno::AGAIN) => std::thread::sleep(TICK),
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err(Unavailable::Disconnected),
        }
    }
}
fn send_once(socket: &OwnedFd, bytes: &[u8], fd: Option<&OwnedFd>) -> Result<bool, Unavailable> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let rights = fd.map(|f| [f.as_fd()]);
    if let Some(rights) = &rights {
        if !ancillary.push(SendAncillaryMessage::ScmRights(rights)) {
            return Err(Unavailable::Limit);
        }
    }
    match net::sendmsg(
        socket,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
    ) {
        Ok(n) if n == bytes.len() => Ok(true),
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(false),
        _ => Err(Unavailable::Disconnected),
    }
}
fn send(
    socket: &OwnedFd,
    bytes: &[u8],
    fd: Option<&OwnedFd>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), Unavailable> {
    loop {
        fence(deadline, cancel)?;
        if send_once(socket, bytes, fd)? {
            return fence(deadline, cancel);
        }
        std::thread::sleep(TICK);
    }
}
fn send_reply(
    socket: &OwnedFd,
    bytes: &mut [u8],
    snapshot_expiry: Option<Instant>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), Unavailable> {
    if bytes.get(96) != Some(&1) {
        return send(socket, bytes, None, deadline, cancel);
    }
    // Очередь не создаёт новый observation interval для уже проверенного owner.
    let deadline = deadline.min(snapshot_expiry.ok_or(Unavailable::Authority)?);
    loop {
        fence(deadline, cancel)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Unavailable::Timeout);
        }
        bytes
            .get_mut(104..112)
            .ok_or(Unavailable::Malformed)?
            .copy_from_slice(
                &(remaining.as_nanos().min(u128::from(wire::OWNER_TTL_NS)) as u64).to_be_bytes(),
            );
        if send_once(socket, bytes, None)? {
            return fence(deadline, cancel);
        }
        std::thread::sleep(TICK);
    }
}

#[cfg(test)]
type LookupHook = Box<dyn FnOnce(&mut Session) -> Result<(), Unavailable>>;
#[cfg(test)]
thread_local! {
    static BEFORE_LOOKUP: std::cell::RefCell<Option<LookupHook>> =
        std::cell::RefCell::new(None);
}

impl Session {
    /// Потребляет все роли. metadata — только от helper resource owner.
    /// cancel не является authority и может только отозвать существующую сессию.
    pub fn serve(mut self, cancel: &AtomicBool) -> Result<(), Unavailable> {
        let result = self.serve_inner(cancel, || Ok(()));
        self.close();
        result
    }
    pub fn serve_with_ready(
        mut self,
        cancel: &AtomicBool,
        on_ready: impl FnOnce() -> Result<(), Unavailable>,
    ) -> Result<(), Unavailable> {
        let result = self.serve_inner(cancel, on_ready);
        self.close();
        result
    }
    fn serve_inner(
        &mut self,
        cancel: &AtomicBool,
        on_ready: impl FnOnce() -> Result<(), Unavailable>,
    ) -> Result<(), Unavailable> {
        let socket = rustix::io::fcntl_dupfd_cloexec(
            &self.roles.as_ref().ok_or(Unavailable::Authority)?.worker,
            0,
        )
        .map_err(|_| Unavailable::Disconnected)?;
        if net::sockopt::socket_type(&socket).map_err(|_| Unavailable::Malformed)?
            != net::SocketType::SEQPACKET
        {
            return Err(Unavailable::Malformed);
        }
        let expires = Instant::now() + Duration::from_nanos(wire::BOOTSTRAP_NS);
        let hello = self.hello().map_err(|_| Unavailable::Malformed)?;
        send(&socket, &hello, None, expires, cancel)?;
        let features = receive(&socket, expires, cancel)?;
        let (attach, fd) = self.attach(&features).map_err(|_| Unavailable::Malformed)?;
        send(&socket, &attach, Some(&fd), expires, cancel)?;
        drop(fd);
        let ack = receive(&socket, expires, cancel)?;
        self.acknowledge(&ack).map_err(|_| Unavailable::Malformed)?;
        on_ready()?;
        loop {
            let bytes = receive_inner(&socket, None, cancel)?;
            let header = self.header(&bytes).map_err(|_| Unavailable::Malformed)?;
            if header.kind == Kind::Revoke {
                self.revoke(&bytes).map_err(|_| Unavailable::Malformed)?;
                return Ok(());
            }
            let deadline = Instant::now() + Duration::from_nanos(wire::OWNER_TTL_NS);
            #[cfg(test)]
            BEFORE_LOOKUP.with(|hook| {
                if let Some(callback) = hook.borrow_mut().take() {
                    callback(self)?;
                }
                Ok(())
            })?;
            let lookup = self
                .lookup_and_project(&bytes)
                .map_err(|_| Unavailable::Malformed)?;
            let snapshot_expiry = match &lookup {
                ProjectedLookup::Known(projection) => Some(projection.expiry()?),
                _ => None,
            };
            fence(deadline, cancel)?;
            let mut reply = self.reply(header.request_id, lookup)?;
            send_reply(&socket, &mut reply, snapshot_expiry, deadline, cancel)?;
        }
    }
    fn reply(&self, id: u64, lookup: ProjectedLookup) -> Result<Vec<u8>, Unavailable> {
        let mut bytes = vec![0; 160];
        Header {
            kind: Kind::Reply,
            request_id: id,
            epoch: self.epoch,
            digest: self.digest,
        }
        .write(&mut bytes)
        .map_err(|_| Unavailable::Malformed)?;
        bytes[64..96].copy_from_slice(&self.nonce);
        let (status, reason) = match lookup {
            ProjectedLookup::Unknown => (2, 0),
            ProjectedLookup::Known(projection) => {
                let (owner, path, ttl) = projection.into_parts();
                bytes.resize(160 + path.len(), 0);
                Header {
                    kind: Kind::Reply,
                    request_id: id,
                    epoch: self.epoch,
                    digest: self.digest,
                }
                .write(&mut bytes)
                .map_err(|_| Unavailable::Malformed)?;
                bytes[100..102].copy_from_slice(&(path.len() as u16).to_be_bytes());
                bytes[104..112].copy_from_slice(&(ttl.as_nanos() as u64).to_be_bytes());
                bytes[112..120].copy_from_slice(&owner.cookie.to_be_bytes());
                bytes[120..124].copy_from_slice(&owner.pid.to_be_bytes());
                bytes[128..136].copy_from_slice(&owner.start_time.to_be_bytes());
                bytes[136..144].copy_from_slice(&owner.executable.0.to_be_bytes());
                bytes[144..152].copy_from_slice(&owner.executable.1.to_be_bytes());
                bytes[160..].copy_from_slice(path.as_bytes());
                (1, 0)
            }
            ProjectedLookup::Unavailable(reason) => (
                3,
                match reason {
                    Unavailable::Authority => 1,
                    Unavailable::Revoked | Unavailable::Cancelled | Unavailable::Disconnected => 2,
                    Unavailable::Timeout => 3,
                    Unavailable::Coverage | Unavailable::WorkerViewUnavailable => 4,
                    Unavailable::Limit | Unavailable::ReceiveOverflow => 5,
                    Unavailable::Malformed => 6,
                    Unavailable::AmbiguousSocket => 7,
                },
            ),
        };
        bytes[96] = status;
        bytes[97] = reason;
        Header::decode(&bytes, 0).map_err(|_| Unavailable::Malformed)?;
        Ok(bytes)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    fn fixture() -> (Session, OwnedFd, [u8; 32]) {
        let (mut session, _) = super::super::tests::fixture();
        let (worker, peer) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        session.roles.as_mut().unwrap().worker = worker;
        let mut metadata = [0; 32];
        metadata[..4].copy_from_slice(&1u32.to_be_bytes());
        metadata[4..8].copy_from_slice(&1u32.to_be_bytes());
        metadata[8..12].copy_from_slice(&0x1001u32.to_be_bytes());
        metadata[12..16].copy_from_slice(&1500u32.to_be_bytes());
        metadata[16..20].copy_from_slice(b"tun0");
        (session, peer, metadata)
    }
    pub(crate) fn bound_terminal_controls(
        bound: std::sync::Arc<crate::managed_network::tun::BoundTun>,
    ) {
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let baseline = count();
        let owners = std::sync::Arc::strong_count(&bound);
        for mode in 0..3 {
            let (mut session, peer, _) = fixture();
            session.roles.as_mut().unwrap().tun = super::super::TunRole::Bound(bound.clone());
            let cancel = std::sync::Arc::new(AtomicBool::new(mode == 0));
            let flag = cancel.clone();
            let thread = std::thread::spawn(move || session.serve(&flag));
            if mode != 0 {
                let hello = handshake(&peer, true);
                if mode == 1 {
                    cancel.store(true, Ordering::Release);
                } else {
                    let mut revoke = hello[..104].to_vec();
                    Header {
                        kind: Kind::Revoke,
                        request_id: 0,
                        epoch: 1,
                        digest: [2; 32],
                    }
                    .write(&mut revoke)
                    .unwrap();
                    revoke[96..104].fill(0);
                    revoke[99] = 1;
                    send(
                        &peer,
                        &revoke,
                        None,
                        Instant::now() + Duration::from_secs(1),
                        &AtomicBool::new(false),
                    )
                    .unwrap();
                }
            }
            assert_eq!(
                thread.join().unwrap(),
                if mode == 2 {
                    Ok(())
                } else {
                    Err(Unavailable::Cancelled)
                }
            );
            drop(peer);
            assert_eq!(count(), baseline);
            assert_eq!(std::sync::Arc::strong_count(&bound), owners);
            assert!(bound.attach_metadata().is_ok());
        }
    }
    fn handshake(peer: &OwnedFd, acknowledge: bool) -> Vec<u8> {
        handshake_delayed(peer, acknowledge, Duration::ZERO)
    }
    fn handshake_delayed(peer: &OwnedFd, acknowledge: bool, delay: Duration) -> Vec<u8> {
        handshake_until(
            peer,
            acknowledge,
            delay,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap()
    }
    fn handshake_until(
        peer: &OwnedFd,
        acknowledge: bool,
        delay: Duration,
        deadline: Instant,
    ) -> Result<Vec<u8>, Unavailable> {
        let cancel = AtomicBool::new(false);
        let hello = receive(peer, deadline, &cancel)?;
        let mut features = hello[..112].to_vec();
        Header {
            kind: Kind::Features,
            request_id: 0,
            epoch: 1,
            digest: [2; 32],
        }
        .write(&mut features)
        .unwrap();
        features[96..104].copy_from_slice(&wire::FEATURES.to_be_bytes());
        features[104..112].copy_from_slice(&wire::OWNED_TUN.to_be_bytes());
        send(peer, &features, None, deadline, &cancel)?;
        let mut bytes = [0; 128];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        loop {
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            match net::recvmsg(
                peer,
                &mut [IoSliceMut::new(&mut bytes)],
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
            ) {
                Ok(msg) => {
                    assert_eq!(msg.bytes, 128);
                    let fds: Vec<_> = ancillary
                        .drain()
                        .flat_map(|c| match c {
                            net::RecvAncillaryMessage::ScmRights(r) => r.collect::<Vec<_>>(),
                            _ => panic!("лишний ancillary"),
                        })
                        .collect();
                    assert_eq!(fds.len(), 1);
                    assert!(
                        rustix::io::fcntl_getfd(&fds[0])
                            .unwrap()
                            .contains(rustix::io::FdFlags::CLOEXEC)
                    );
                    assert_eq!(Header::decode(&bytes, 1).unwrap().kind, Kind::Attach);
                    break;
                }
                Err(rustix::io::Errno::AGAIN) => {
                    fence(deadline, &cancel)?;
                    std::thread::sleep(TICK);
                }
                e => panic!("{e:?}"),
            }
        }
        let mut ack = hello[..104].to_vec();
        Header {
            kind: Kind::AttachAck,
            request_id: 0,
            epoch: 1,
            digest: [2; 32],
        }
        .write(&mut ack)
        .unwrap();
        ack[96..104].fill(0);
        ack[99] = 1;
        std::thread::sleep(delay);
        if acknowledge {
            send(peer, &ack, None, deadline, &cancel)?;
        }
        Ok(hello)
    }
    pub(in crate::attribution) fn known_roundtrip(
        broker: super::super::super::broker::Broker,
        prepare: impl FnOnce(&mut super::super::super::broker::Broker) -> Result<(), Unavailable>
        + Send
        + 'static,
        flow: super::super::super::broker::Flow,
        deadline: Instant,
    ) -> Result<(), Unavailable> {
        known_roundtrip_inner(broker, prepare, flow, deadline, false)
    }
    pub(in crate::attribution) fn cold_roundtrip(
        broker: super::super::super::broker::Broker,
        prepare: impl FnOnce(&mut super::super::super::broker::Broker) -> Result<(), Unavailable>
        + Send
        + 'static,
        flow: super::super::super::broker::Flow,
        deadline: Instant,
    ) -> Result<(), Unavailable> {
        known_roundtrip_inner(broker, prepare, flow, deadline, true)
    }
    fn known_roundtrip_inner(
        broker: super::super::super::broker::Broker,
        prepare: impl FnOnce(&mut super::super::super::broker::Broker) -> Result<(), Unavailable>
        + Send
        + 'static,
        flow: super::super::super::broker::Flow,
        deadline: Instant,
        cold: bool,
    ) -> Result<(), Unavailable> {
        let (mut session, peer, _metadata) = fixture();
        session.roles.as_mut().unwrap().broker = Some(broker);
        let thread = std::thread::spawn(move || {
            BEFORE_LOOKUP.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |session| {
                    prepare(session.roles.as_mut().unwrap().broker.as_mut().unwrap())
                }));
            });
            let result = session.serve(&AtomicBool::new(false));
            if cold {
                crate::attribution::broker::report_cold_witnesses();
            }
            result
        });
        // Задержка bootstrap заведомо превышает owner TTL; наблюдение ещё не начато.
        let exchange = (|| {
            let hello = handshake_until(&peer, true, Duration::from_millis(30), deadline)?;
            let mut lookup = vec![0; 144];
            Header {
                kind: Kind::Lookup,
                request_id: 43,
                epoch: 1,
                digest: [2; 32],
            }
            .write(&mut lookup)
            .unwrap();
            lookup[64..96].copy_from_slice(&hello[64..96]);
            lookup[96] = if flow.family == 2 { 4 } else { 6 };
            lookup[97] = flow.protocol;
            lookup[100..102].copy_from_slice(&flow.local_port.to_be_bytes());
            lookup[102..104].copy_from_slice(&flow.remote_port.to_be_bytes());
            lookup[104..120].copy_from_slice(&flow.local);
            lookup[120..136].copy_from_slice(&flow.remote);
            let cancel = AtomicBool::new(false);
            let begun = Instant::now();
            send(&peer, &lookup, None, deadline, &cancel)?;
            let reply = receive(&peer, deadline, &cancel)?;
            if cold {
                assert!(begun.elapsed() < super::super::super::broker::DEADLINE);
                eprintln!("cold RPC elapsed={:?}", begun.elapsed());
            }
            Ok(reply)
        })();
        drop(peer);
        let worker = thread.join().unwrap();
        eprintln!("retained wire worker: {worker:?}");
        let reply = known_exchange_result(exchange, worker)?;
        assert_eq!(Header::decode(&reply, 0).unwrap().request_id, 43);
        if reply[96..98] == [3, 3] {
            return Err(Unavailable::Timeout);
        }
        assert_eq!(&reply[96..98], &[1, 0]);
        let ttl = u64::from_be_bytes(reply[104..112].try_into().unwrap());
        assert!(ttl > 0 && ttl <= 20_000_000);
        eprintln!("retained wire Known ttl_ns={ttl}");
        assert_eq!(
            &reply[160..],
            std::fs::read_link("/proc/self/exe")
                .unwrap()
                .to_str()
                .unwrap()
                .as_bytes()
        );
        Ok(())
    }
    fn known_exchange_result(
        exchange: Result<Vec<u8>, Unavailable>,
        worker: Result<(), Unavailable>,
    ) -> Result<Vec<u8>, Unavailable> {
        match (exchange, worker) {
            (Err(error), _)
                if error != Unavailable::Timeout && error != Unavailable::Disconnected =>
            {
                Err(error)
            }
            (result, Err(Unavailable::Disconnected)) => result,
            (_, Err(error)) => Err(error),
            (_, Ok(())) => Err(Unavailable::Malformed),
        }
    }
    #[test]
    fn known_exchange_does_not_hide_malformed_behind_worker_timeout() {
        assert_eq!(
            known_exchange_result(Err(Unavailable::Malformed), Err(Unavailable::Timeout)),
            Err(Unavailable::Malformed)
        );
        assert_eq!(
            known_exchange_result(Err(Unavailable::Disconnected), Err(Unavailable::Timeout)),
            Err(Unavailable::Timeout)
        );
        assert_eq!(
            known_exchange_result(Err(Unavailable::Timeout), Err(Unavailable::Authority)),
            Err(Unavailable::Authority)
        );
        assert_eq!(
            known_exchange_result(Ok(vec![1]), Err(Unavailable::Disconnected)),
            Ok(vec![1])
        );
    }
    #[test]
    fn socket_handshake_reply_correlation_and_replay_retire() {
        let (session, peer, _metadata) = fixture();
        let thread = std::thread::spawn(move || session.serve(&AtomicBool::new(false)));
        let hello = handshake(&peer, true);
        let mut lookup = vec![0; 144];
        Header {
            kind: Kind::Lookup,
            request_id: 42,
            epoch: 1,
            digest: [2; 32],
        }
        .write(&mut lookup)
        .unwrap();
        lookup[64..96].copy_from_slice(&hello[64..96]);
        lookup[96] = 4;
        lookup[97] = 6;
        lookup[101] = 1;
        lookup[103] = 1;
        let deadline = Instant::now() + Duration::from_secs(1);
        let cancel = AtomicBool::new(false);
        send(&peer, &lookup, None, deadline, &cancel).unwrap();
        let reply = receive(&peer, deadline, &cancel).unwrap();
        assert_eq!(Header::decode(&reply, 0).unwrap().request_id, 42);
        assert_eq!(&reply[96..98], &[3, 1]);
        send(&peer, &lookup, None, deadline, &cancel).unwrap();
        assert_eq!(thread.join().unwrap(), Err(Unavailable::Malformed));
        assert_eq!(
            receive(&peer, deadline, &cancel),
            Err(Unavailable::Disconnected)
        );
    }
    #[test]
    fn socket_negative_controls_and_cleanup() {
        for mode in 0..5 {
            let (session, peer, _metadata) = fixture();
            let cancel = std::sync::Arc::new(AtomicBool::new(false));
            let flag = cancel.clone();
            let thread = std::thread::spawn(move || session.serve(&flag));
            if mode == 0 {
                drop(peer);
                assert_eq!(thread.join().unwrap(), Err(Unavailable::Disconnected));
                continue;
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            receive(&peer, deadline, &AtomicBool::new(false)).unwrap();
            if mode == 1 {
                cancel.store(true, Ordering::Release);
            }
            if mode >= 2 {
                let data = if mode == 2 {
                    vec![0; wire::MAX_FRAME + 20]
                } else {
                    vec![0; 112]
                };
                let file = std::fs::File::open("/dev/null").unwrap();
                let fd: OwnedFd = file.into();
                send(
                    &peer,
                    &data,
                    if mode == 3 { Some(&fd) } else { None },
                    deadline,
                    &AtomicBool::new(false),
                )
                .unwrap();
            }
            let expected = if mode == 1 {
                Unavailable::Cancelled
            } else {
                Unavailable::Malformed
            };
            assert_eq!(thread.join().unwrap(), Err(expected));
            assert_eq!(
                receive(&peer, deadline, &AtomicBool::new(false)),
                Err(Unavailable::Disconnected)
            );
        }
    }
    #[test]
    fn expired_send_backpressure_and_wrong_socket_fail_closed() {
        let (session, _peer) = super::super::tests::fixture();
        assert_eq!(
            session.serve(&AtomicBool::new(false)),
            Err(Unavailable::Malformed)
        );
        let (session, peer, _) = fixture();
        let worker = &session.roles.as_ref().unwrap().worker;
        let cancel = AtomicBool::new(false);
        assert_eq!(
            send(worker, &[0], None, Instant::now(), &cancel),
            Err(Unavailable::Timeout)
        );
        loop {
            match net::send(worker, &[0; 768], SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
                Ok(_) => (),
                Err(rustix::io::Errno::AGAIN) => break,
                e => panic!("{e:?}"),
            }
        }
        assert_eq!(
            send(
                worker,
                &[0; 768],
                None,
                Instant::now() + Duration::from_millis(5),
                &cancel
            ),
            Err(Unavailable::Timeout)
        );
        drop(peer);
    }
    #[test]
    fn known_reply_backpressure_cannot_extend_snapshot_expiry() {
        let (session, peer, _) = fixture();
        let worker = &session.roles.as_ref().unwrap().worker;
        loop {
            match net::send(worker, &[0; 768], SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
                Ok(_) => (),
                Err(rustix::io::Errno::AGAIN) => break,
                e => panic!("{e:?}"),
            }
        }
        let expiry = Instant::now() + Duration::from_millis(5);
        let reader = std::thread::spawn(move || {
            // Освобождаем очередь после исходного expiry, но до request deadline.
            std::thread::sleep(Duration::from_millis(30));
            let mut bytes = [0; 2048];
            while net::recv(&peer, &mut bytes, RecvFlags::DONTWAIT).is_ok() {}
            peer
        });
        let mut bytes = vec![0; 162];
        bytes[96] = 1;
        bytes[104..112].copy_from_slice(&5_000_000u64.to_be_bytes());
        let result = send_reply(
            worker,
            &mut bytes,
            Some(expiry),
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        );
        let peer = reader.join().unwrap();
        assert_eq!(result, Err(Unavailable::Timeout));
        let mut bytes = [0; 2048];
        assert_eq!(
            net::recv(&peer, &mut bytes, RecvFlags::DONTWAIT),
            Err(rustix::io::Errno::AGAIN)
        );
    }
    #[test]
    fn known_reply_ttl_uses_remaining_snapshot_budget() {
        let (session, peer, _) = fixture();
        let mut bytes = vec![0; 162];
        bytes[96] = 1;
        bytes[104..112].copy_from_slice(&wire::OWNER_TTL_NS.to_be_bytes());
        let expiry = Instant::now() + Duration::from_millis(10);
        send_reply(
            &session.roles.as_ref().unwrap().worker,
            &mut bytes,
            Some(expiry),
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .unwrap();
        let received = receive(
            &peer,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .unwrap();
        let ttl = u64::from_be_bytes(received[104..112].try_into().unwrap());
        assert!(ttl > 0 && ttl <= 10_000_000);
    }
    #[test]
    fn foreign_epoch_and_wrong_phase_rejected_over_socket() {
        for kind in [Kind::Lookup, Kind::AttachAck] {
            let (session, peer, _metadata) = fixture();
            let thread = std::thread::spawn(move || session.serve(&AtomicBool::new(false)));
            let hello = handshake(&peer, true);
            let mut bytes = vec![0; kind.fixed_bytes().unwrap()];
            Header {
                kind,
                request_id: if kind == Kind::Lookup { 1 } else { 0 },
                epoch: 2,
                digest: [2; 32],
            }
            .write(&mut bytes)
            .unwrap();
            bytes[64..96].copy_from_slice(&hello[64..96]);
            send(
                &peer,
                &bytes,
                None,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(thread.join().unwrap(), Err(Unavailable::Malformed));
        }
    }
    #[test]
    fn owned_ipc_ready_after_ack_runtime_survives_bootstrap_deadline() {
        let (session, peer, _) = fixture();
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&cancel);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            session.serve_with_ready(&flag, || {
                ready_tx.send(()).map_err(|_| Unavailable::Disconnected)
            })
        });
        handshake(&peer, true);
        ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        std::thread::sleep(Duration::from_nanos(wire::BOOTSTRAP_NS) + Duration::from_millis(30));
        assert!(!thread.is_finished());
        cancel.store(true, Ordering::Release);
        assert_eq!(thread.join().unwrap(), Err(Unavailable::Cancelled));
    }
    #[test]
    fn owned_ipc_missing_ack_never_signals_ready() {
        let (session, peer, _) = fixture();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            session.serve_with_ready(&AtomicBool::new(false), || {
                ready_tx.send(()).map_err(|_| Unavailable::Disconnected)
            })
        });
        handshake(&peer, false);
        assert_eq!(thread.join().unwrap(), Err(Unavailable::Timeout));
        assert!(ready_rx.try_recv().is_err());
    }
    #[test]
    fn socket_ack_timeout_and_revoke() {
        let (session, peer, _metadata) = fixture();
        let thread = std::thread::spawn(move || session.serve(&AtomicBool::new(false)));
        handshake(&peer, false);
        // ATTACH отправлен; отсутствие ACK завершает роли по общему deadline.
        assert_eq!(thread.join().unwrap(), Err(Unavailable::Timeout));
        drop(peer);
        let (session, peer, _metadata) = fixture();
        let thread = std::thread::spawn(move || session.serve(&AtomicBool::new(false)));
        let hello = handshake(&peer, true);
        let mut revoke = hello[..104].to_vec();
        Header {
            kind: Kind::Revoke,
            request_id: 0,
            epoch: 1,
            digest: [2; 32],
        }
        .write(&mut revoke)
        .unwrap();
        revoke[96..104].fill(0);
        revoke[99] = 1;
        send(
            &peer,
            &revoke,
            None,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(thread.join().unwrap(), Ok(()));
    }
}
