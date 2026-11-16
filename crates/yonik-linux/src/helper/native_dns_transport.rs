//! Retained DirectSocket DNS custody. DATA records и TCP ingress не являются proof.
use super::super::memory::{ByteBudget, ByteLease};
#[cfg(test)]
use super::SidebandCredits;
use super::{
    Authority, Channel, HistoryCredit, Issuer, Peer, ServiceError, SocketFacts, Target,
    unavailable, wire,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    net::SocketAddr,
    os::fd::OwnedFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use wire::dns_v2::{Operation, Record, View};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Binding {
    pub bundle: u64,
    pub revision: u64,
    pub root: u64,
    pub query: u64,
    pub epoch: u64,
    pub source: u64,
    pub source_revision: u64,
    pub resolver: u16,
    pub subject: u16,
    pub scope: u16,
    pub branch: u8,
    pub qtype: u16,
    pub options: u16,
    pub payload: u16,
    pub base: [u8; 32],
    pub name: Target,
    pub peer: Target,
    pub ticket: Option<u64>,
    pub expires: Instant,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Facts {
    local: SocketAddr,
    remote: SocketAddr,
    protocol: u8,
    cookie: u64,
    inode: u64,
    uid: u32,
    mark: u32,
    namespace: (u64, u64),
}
impl Facts {
    pub(crate) fn local(&self) -> SocketAddr {
        self.local
    }
    pub(crate) fn remote(&self) -> SocketAddr {
        self.remote
    }
    pub(crate) fn protocol(&self) -> u8 {
        self.protocol
    }
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
    pub(crate) fn mark(&self) -> u32 {
        self.mark
    }
    #[cfg(test)]
    pub(super) fn namespace(&self) -> (u64, u64) {
        self.namespace
    }
    fn capture(fd: &OwnedFd, namespace: &OwnedFd) -> Result<Self, ServiceError> {
        let facts = SocketFacts::capture(fd)?;
        let stat = rustix::fs::fstat(fd).map_err(unavailable)?;
        let ns = rustix::fs::fstat(namespace).map_err(unavailable)?;
        Ok(Self {
            local: facts.local,
            remote: facts.remote.ok_or(ServiceError::Unsupported)?,
            protocol: facts.protocol,
            cookie: facts.cookie,
            inode: facts.inode,
            uid: stat.st_uid,
            mark: yonik_nsfs::socket_namespace::profile_socket_mark(fd).map_err(unavailable)?,
            namespace: (ns.st_dev, ns.st_ino),
        })
    }
    fn eligible(self) -> bool {
        self.cookie != 0
            && self.cookie != u64::MAX
            && self.inode != 0
            && self.local.port() != 0
            && !self.local.ip().is_unspecified()
            && !self.local.ip().is_multicast()
            && self.namespace != (0, 0)
    }
}
enum Handle {
    Kernel {
        fd: Option<OwnedFd>,
        namespace: Option<OwnedFd>,
        // Peer владеет inbox: strong Arc здесь создал бы custody cycle.
        peer: std::sync::Weak<Peer>,
    },
    #[cfg(test)]
    Fake {
        state: Arc<std::sync::Mutex<Facts>>,
        valid: Arc<AtomicBool>,
        closed: Arc<std::sync::atomic::AtomicUsize>,
        consumed: bool,
    },
}
impl Drop for Handle {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Self::Fake {
            closed,
            consumed: false,
            ..
        } = self
        {
            closed.fetch_add(1, Ordering::AcqRel);
        }
    }
}
pub(super) struct Evidence {
    handle: Handle,
    facts: Facts,
}
impl Evidence {
    pub(super) fn capture(fd: OwnedFd, peer: Arc<Peer>) -> Result<Self, ServiceError> {
        peer.validate()?;
        let namespace = yonik_nsfs::socket_namespace::socket_namespace(&fd)
            .map_err(|_| ServiceError::Unsupported)?;
        let facts = Facts::capture(&fd, &namespace)?;
        let expected = if let Some(scope) = &peer.system_scope {
            scope.validate().map_err(unavailable)?;
            scope.lookup_binding().2.namespace()
        } else {
            // Local не получает System attribution; EPERM не обходится UID/proc claim.
            let ns = File::open("/proc/thread-self/ns/net").map_err(unavailable)?;
            let stat = rustix::fs::fstat(&ns).map_err(unavailable)?;
            (stat.st_dev, stat.st_ino)
        };
        if !facts.eligible() || facts.uid != peer.uid || facts.namespace != expected {
            return Err(ServiceError::Unavailable);
        }
        let out = Self {
            handle: Handle::Kernel {
                fd: Some(fd),
                namespace: Some(namespace),
                peer: Arc::downgrade(&peer),
            },
            facts,
        };
        out.validate()?;
        Ok(out)
    }
    fn validate(&self) -> Result<Facts, ServiceError> {
        let current = match &self.handle {
            Handle::Kernel {
                fd,
                namespace,
                peer,
            } => {
                let peer = peer.upgrade().ok_or(ServiceError::Unavailable)?;
                peer.validate()?;
                Facts::capture(
                    fd.as_ref().ok_or(ServiceError::Unavailable)?,
                    namespace.as_ref().ok_or(ServiceError::Unavailable)?,
                )?
            }
            #[cfg(test)]
            Handle::Fake { state, valid, .. } => {
                if !valid.load(Ordering::Acquire) {
                    return Err(ServiceError::Unavailable);
                }
                *state.lock().map_err(unavailable)?
            }
        };
        if current != self.facts || !current.eligible() {
            return Err(ServiceError::Unavailable);
        }
        Ok(current)
    }
    fn consume_close(&mut self) -> Result<(), ServiceError> {
        match &mut self.handle {
            Handle::Kernel { fd, namespace, .. } => {
                // Отсутствующий handle не превращается в повторный raw close.
                let fd = fd.take().ok_or(ServiceError::Unavailable)?;
                let ns = namespace.take().ok_or(ServiceError::Unavailable)?;
                yonik_nsfs::socket_namespace::close_profile_socket(fd, ns).map_err(unavailable)
            }
            #[cfg(test)]
            Handle::Fake {
                closed,
                consumed,
                valid,
                ..
            } => {
                if *consumed {
                    return Err(ServiceError::Unavailable);
                }
                *consumed = true;
                closed.fetch_add(1, Ordering::AcqRel);
                if valid.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err(ServiceError::Unavailable)
                }
            }
        }
    }
}
pub(super) struct Incoming {
    raw: [u8; 192],
    evidence: Evidence,
    pending: Option<ByteLease>,
    _fds: ByteLease,
    _memory: ByteLease,
    history: Option<HistoryCredit>,
}
impl Incoming {
    pub(super) fn captured(
        raw: [u8; 192],
        evidence: Evidence,
        pending: ByteLease,
        fds: ByteLease,
        memory: ByteLease,
        history: Option<HistoryCredit>,
    ) -> Self {
        Self {
            raw,
            evidence,
            pending: Some(pending),
            _fds: fds,
            _memory: memory,
            history,
        }
    }
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)] // Pure fake повторяет precredits actual receiver до materialization.
    pub(super) fn fake(
        raw: [u8; 192],
        neg: &wire::dns_v2::Negotiated,
        slots: &SidebandCredits,
        budget: &ByteBudget,
        history: Option<Arc<std::sync::Mutex<super::InvocationHistory>>>,
        facts: Arc<std::sync::Mutex<Facts>>,
        valid: Arc<AtomicBool>,
        closed: Arc<std::sync::atomic::AtomicUsize>,
        materialize: impl FnOnce(),
    ) -> Result<Self, ServiceError> {
        let history = history.map(HistoryCredit::claim).transpose()?;
        let (pending, mut fds) = slots.read_credit(16)?;
        let memory = budget.reserve(2048).map_err(unavailable)?;
        wire::dns_v2::PhysicalPacket::decode(&raw, neg, 1, 1).map_err(unavailable)?;
        materialize();
        let snapshot = *facts.lock().map_err(unavailable)?;
        fds.resize(2).map_err(unavailable)?;
        Ok(Self::captured(
            raw,
            Evidence {
                handle: Handle::Fake {
                    state: facts,
                    valid,
                    closed,
                    consumed: false,
                },
                facts: snapshot,
            },
            pending,
            fds,
            memory,
            history,
        ))
    }
}
#[cfg(test)]
pub(super) fn fake_facts(
    local: SocketAddr,
    remote: SocketAddr,
    protocol: u8,
    namespace: (u64, u64),
) -> Facts {
    Facts {
        local,
        remote,
        protocol,
        cookie: 101,
        inode: 102,
        uid: 997,
        mark: 42,
        namespace,
    }
}
struct Reservation {
    binding: Binding,
    role: u8,
    request: u64,
    exchange: u64,
    parent: u64,
    expires: Instant,
    published: bool,
    resource: Option<u64>,
    pending: Option<ByteLease>,
    _memory: ByteLease,
    physical_credit: Option<ByteLease>,
    future_history: bool,
}
struct Resource {
    release_acked: bool,
    retired: Option<bool>,
    cleanup_until: Instant,
    binding: Binding,
    reservation: u64,
    exchange: u64,
    expires: Instant,
    incoming: Incoming,
    acked: bool,
    proof: Option<u64>,
}
struct DirectProof {
    release_acked: bool,
    retired: Option<bool>,
    acked: bool,
    binding: Binding,
    exchange: u64,
    resource: u64,
    expires: Instant,
    revision: u64,
    producer_sequence: u64,
    _memory: ByteLease,
}
struct ProducerReleasedDirectDns {
    proof: u64,
    resource: u64,
    binding: Binding,
    revision: u64,
}
impl ProducerReleasedDirectDns {
    fn release_ref(self, proof: &mut DirectProof) -> Result<(), ServiceError> {
        if self.proof == 0
            || self.resource != proof.resource
            || self.binding != proof.binding
            || self.revision != proof.revision
            || !proof.acked
            || proof.retired.is_some()
        {
            return Err(ServiceError::Unavailable);
        }
        proof.retired = Some(true);
        Ok(())
    }
}
pub(super) struct Transport {
    closed_exchanges: [Option<(u64, Instant)>; 256],
    closed_count: usize,
    reservations: BTreeMap<u64, Reservation>,
    incoming: BTreeMap<u64, Incoming>,
    resources: BTreeMap<u64, Resource>,
    proofs: BTreeMap<u64, DirectProof>,
    next_reservation: u64,
    next_exchange: u64,
    next_resource: u64,
    next_proof: u64,
    seen: [Option<(u64, u64)>; 256],
    seen_count: usize,
    _memory: ByteLease,
}
impl Transport {
    #[cfg(test)]
    pub(super) fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.reservations.len(),
            self.incoming.len(),
            self.resources.len(),
            self.proofs.len(),
        )
    }
    pub(super) fn new(budget: &ByteBudget) -> Result<Self, ServiceError> {
        let credit = budget
            .reserve(std::mem::size_of::<Self>())
            .map_err(unavailable)?;
        Ok(Self {
            closed_exchanges: [None; 256],
            closed_count: 0,
            reservations: BTreeMap::new(),
            incoming: BTreeMap::new(),
            resources: BTreeMap::new(),
            proofs: BTreeMap::new(),
            next_reservation: 0,
            next_exchange: 0,
            next_resource: 0,
            next_proof: 0,
            seen: [None; 256],
            seen_count: 0,
            _memory: credit,
        })
    }
    pub(super) fn references(&self, bundle: u64) -> bool {
        self.reservations
            .values()
            .any(|v| v.binding.bundle == bundle)
            || self.resources.values().any(|v| v.binding.bundle == bundle)
            || self.incoming.values().any(|v| n64(&v.raw, 144) == bundle)
    }
    pub(super) fn holds_root_cleanup(&self, root: u64, now: Instant) -> bool {
        self.resources
            .values()
            .any(|r| r.binding.root == root && now < r.cleanup_until)
    }
    pub(super) fn cancel_bundle(&mut self, bundle: u64) -> Result<(), ServiceError> {
        if self
            .resources
            .values()
            .any(|r| r.binding.bundle == bundle && (r.retired != Some(true) || !r.release_acked))
            || self.incoming.values().any(|v| n64(&v.raw, 144) == bundle)
            || self
                .reservations
                .values()
                .any(|r| r.binding.bundle == bundle && r.role == 2 && r.published)
        {
            return Err(ServiceError::Unavailable);
        }
        self.reservations.retain(|_, r| r.binding.bundle != bundle);
        Ok(())
    }
    fn cancel_reservation(&mut self, id: u64) -> Result<(), ServiceError> {
        let Some(r) = self.reservations.get(&id) else {
            return if id <= self.next_reservation {
                Ok(())
            } else {
                Err(ServiceError::InvalidRequest)
            };
        };
        if self.incoming.contains_key(&id) || r.resource.is_some() || r.role == 2 && r.published {
            return Err(ServiceError::Unavailable);
        }
        if r.role == 1 {
            if self.incoming.values().any(|p| n64(&p.raw, 128) == id) {
                return Err(ServiceError::Unavailable);
            }
            if self
                .reservations
                .values()
                .any(|p| p.parent == id && (p.published || p.resource.is_some()))
            {
                return Err(ServiceError::Unavailable);
            }
            if self.closed_count == self.closed_exchanges.len() {
                return Err(ServiceError::Busy);
            }
            let until = self
                .resources
                .values()
                .filter(|resource| resource.exchange == r.exchange)
                .fold(r.expires + Duration::from_secs(1), |until, resource| {
                    until.min(resource.cleanup_until)
                });
            self.closed_exchanges[self.closed_count] = Some((r.exchange, until));
            self.closed_count += 1;
            self.reservations.retain(|_, p| p.parent != id);
        }
        self.reservations.remove(&id);
        Ok(())
    }
    pub(super) fn cancel_request(&mut self, request: u64) -> Result<(), ServiceError> {
        let id = self
            .reservations
            .iter()
            .find(|(_, r)| r.request == request)
            .map(|(id, _)| *id);
        if let Some(id) = id {
            self.cancel_reservation(id)?;
        }
        Ok(())
    }
}
fn n64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(std::array::from_fn(|i| b[at + i]))
}
fn n16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
fn set64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_be_bytes());
}
pub(super) struct Reply {
    operation: Operation,
    body: [u8; 64],
    len: usize,
    request: u64,
    binding: Option<Binding>,
    expires: Instant,
    commit: Commit,
}
enum Commit {
    ReleasedProof(u64),
    ClosedResource(u64),
    None,
    Reserved(u64),
    Physical(u64),
    Logical(u64),
}
impl Reply {
    fn denied(operation: Operation, request: u64, until: Instant) -> Self {
        let mut body = [0; 64];
        body[..2].copy_from_slice(&2u16.to_be_bytes());
        body[2] = 2;
        let len = if operation == Operation::Retired {
            40
        } else {
            64
        };
        Self {
            operation,
            body,
            len,
            request,
            binding: None,
            expires: until,
            commit: Commit::None,
        }
    }
    fn allow(
        operation: Operation,
        request: u64,
        binding: Binding,
        expires: Instant,
        commit: Commit,
    ) -> Self {
        let mut r = Self::denied(operation, request, expires);
        r.body[2] = 1;
        r.binding = Some(binding);
        r.commit = commit;
        r
    }
}
impl<A: Authority> Issuer<A> {
    fn retire_dns(
        &mut self,
        view: View<'_, 45>,
        request: u64,
        session: Instant,
    ) -> Result<Reply, ServiceError> {
        let b = view.bytes();
        let id = n64(b, 8);
        let revision = n64(b, 16);
        let (resource, already) = match b[2] {
            4 => {
                let p = self
                    .transport
                    .proofs
                    .get(&id)
                    .ok_or(ServiceError::Unavailable)?;
                if revision != p.revision {
                    return Err(ServiceError::InvalidRequest);
                }
                (p.resource, p.retired)
            }
            3 if revision == 0 => {
                let r = self
                    .transport
                    .resources
                    .get(&id)
                    .ok_or(ServiceError::Unavailable)?;
                (id, r.retired)
            }
            _ => return Err(ServiceError::InvalidRequest),
        };
        let r = self
            .transport
            .resources
            .get(&resource)
            .ok_or(ServiceError::Unavailable)?;
        let until = r.cleanup_until.min(session);
        if self.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        let mut reply = Reply::denied(Operation::Retired, request, until);
        let mut result = already;
        if result.is_none() && !self.unknown {
            let anchor = self
                .dns_release
                .as_ref()
                .ok_or(ServiceError::Unsupported)
                .and_then(|p| p.bound(self.record));
            if anchor.is_err() {
                result = Some(false);
            } else if b[2] == 4 {
                let p = self
                    .transport
                    .proofs
                    .get(&id)
                    .ok_or(ServiceError::Unavailable)?;
                // Direct count1 имеет ровно один retained ref. Новые consumers
                // появятся отдельным cut: здесь отсутствуют hidden task/alias APIs.
                let parent = self
                    .transport
                    .reservations
                    .values()
                    .find(|p| p.role == 1 && p.exchange == r.exchange);
                let physical = self.transport.reservations.get(&r.reservation);
                if !p.acked
                    || !r.acked
                    || r.retired.is_some()
                    || r.proof != Some(id)
                    || p.binding != r.binding
                    || p.exchange != r.exchange
                    || parent.is_none_or(|v| v.pending.is_some() || v.binding != r.binding)
                    || physical.is_none_or(|v| v.pending.is_some() || v.resource != Some(resource))
                {
                    return Ok(reply);
                }
                let released = ProducerReleasedDirectDns {
                    proof: id,
                    resource,
                    binding: p.binding,
                    revision,
                };
                released.release_ref(
                    self.transport
                        .proofs
                        .get_mut(&id)
                        .ok_or(ServiceError::Unavailable)?,
                )?;
                result = Some(true);
            } else {
                if !r.acked
                    || r.proof
                        .and_then(|p| self.transport.proofs.get(&p))
                        .is_none_or(|p| p.retired != Some(true) || !p.release_acked)
                {
                    return Ok(reply);
                }
                if self.transport.incoming.contains_key(&r.reservation)
                    || self
                        .transport
                        .reservations
                        .get(&r.reservation)
                        .is_none_or(|p| p.pending.is_some())
                {
                    return Ok(reply);
                }
                // Terminal state pre-paid в Resource. Mark Unknown ДО close;
                // ни retry ACK, ни raw FD после uncertain close не повторяют effect.
                let r = self
                    .transport
                    .resources
                    .get_mut(&resource)
                    .ok_or(ServiceError::Unavailable)?;
                r.retired = Some(false);
                result = Some(r.incoming.evidence.consume_close().is_ok());
            }
        }
        let success = result == Some(true);
        if b[2] == 4 {
            self.transport
                .proofs
                .get_mut(&id)
                .ok_or(ServiceError::Unavailable)?
                .retired = Some(success);
        } else {
            self.transport
                .resources
                .get_mut(&id)
                .ok_or(ServiceError::Unavailable)?
                .retired = Some(success);
        }
        reply.body[2] = if success { 1 } else { 3 };
        reply.body[3] = b[2];
        set64(&mut reply.body, 8, id);
        set64(&mut reply.body, 16, revision);
        if success {
            reply.body[28] = 1;
            reply.commit = if b[2] == 4 {
                Commit::ReleasedProof(id)
            } else {
                Commit::ClosedResource(id)
            };
        } else {
            reply.body[26..28].copy_from_slice(&1u16.to_be_bytes());
            self.unknown = true;
            self.authority.revoke();
        }
        Ok(reply)
    }
    fn reserve_dns(
        &mut self,
        view: View<'_, 35>,
        request: u64,
        socket: &impl Channel,
        session: Instant,
    ) -> Result<Reply, ServiceError> {
        self.fence()?;
        if self.retired.iter().any(|(id, _)| *id == request) {
            return Err(ServiceError::Unavailable);
        }
        let b = view.bytes();
        let binding = self.direct_dns_binding(n64(b, 16))?;
        if !matches!(b[2], 1 | 2)
            || b[74] != 1
            || b[75] != 1
            || b[77] != 3
            || b[78] != 1
            || n64(b, 8) != binding.query
            || n64(b, 24) != binding.root
            || n64(b, 32) != binding.source
            || n64(b, 40) != binding.source_revision
            || n64(b, 48) != binding.epoch
            || n16(b, 64) != binding.resolver
            || n16(b, 66) != binding.subject
            || n16(b, 68) != u16::MAX
            || n16(b, 70) != binding.scope
            || n16(b, 72) != binding.qtype
            || b[76] != binding.peer.protocol
            || b[79] != binding.branch
            || view.original() != binding.name.wire().bytes
            || view.query_name() != binding.name.wire().bytes
            || <[u8; 32]>::from(Sha256::digest(view.base())) != binding.base
        {
            return Err(ServiceError::Unsupported);
        }
        if self.transport.reservations.len() >= 64 {
            return Err(ServiceError::Busy);
        }
        let now = self.authority.now();
        let mut expires = binding
            .expires
            .min(session)
            .min(now + Duration::from_nanos(n64(b, 56)));
        let parent = if b[2] == 2 { n64(b, 88) } else { 0 };
        let exchange = if b[2] == 1 {
            if n16(b, 88) != binding.options
                || n16(b, 90) != binding.payload
                || self.transport.seen[..self.transport.seen_count]
                    .contains(&Some((binding.bundle, binding.query)))
                || self.transport.seen_count == 256
            {
                return Err(ServiceError::InvalidRequest);
            }
            Self::id(&mut self.transport.next_exchange)?
        } else {
            let p = self
                .transport
                .reservations
                .get(&parent)
                .ok_or(ServiceError::Unavailable)?;
            if p.role != 1 || !p.published || p.binding != binding || now >= p.expires {
                return Err(ServiceError::InvalidRequest);
            }
            expires = expires.min(p.expires);
            p.exchange
        };
        if now >= expires {
            return Err(ServiceError::Unavailable);
        }
        let memory = self
            .budget
            .dynamic
            .reserve(std::mem::size_of::<Reservation>() + 80)
            .map_err(unavailable)?;
        let physical_credit = if b[2] == 2 {
            Some(socket.dns_slots()?.fds.reserve(18).map_err(unavailable)?)
        } else {
            None
        };
        // Reservation и будущий Resource/Proof history оплачены до ACK/effects.
        self.bundle_history(2)?;
        let pending = socket.take_dns_credit(request)?;
        // Physical credits оплачены до Reserved ACK и создания child socket.
        // На syscall scratch16 также отдельно debit-ится общий FD ledger.
        let id = Self::id(&mut self.transport.next_reservation)?;
        if b[2] == 1 {
            self.transport.seen[self.transport.seen_count] = Some((binding.bundle, binding.query));
            self.transport.seen_count += 1;
        }
        self.transport.reservations.insert(
            id,
            Reservation {
                binding,
                role: b[2],
                request,
                exchange,
                parent,
                expires,
                published: false,
                resource: None,
                pending: Some(pending),
                _memory: memory,
                physical_credit,
                future_history: true,
            },
        );
        let mut reply = Reply::allow(
            Operation::Reserved,
            request,
            binding,
            expires,
            Commit::Reserved(id),
        );
        for (at, value) in [
            (8, id),
            (16, binding.query),
            (24, binding.bundle),
            (32, if b[2] == 1 { exchange } else { parent }),
            (40, binding.epoch),
        ] {
            set64(&mut reply.body, at, value);
        }
        // 2 held FD +16 receive scratch; capacity не обещает 64 resources.
        reply.body[56..58].copy_from_slice(&(if b[2] == 2 { 18u16 } else { 0 }).to_be_bytes());
        reply.body[58..60].copy_from_slice(&1u16.to_be_bytes());
        reply.body[60] = b[2];
        Ok(reply)
    }
    fn validate_dns_resource(&mut self, id: u64) -> Result<(), ServiceError> {
        if !self.transport.resources.contains_key(&id) {
            return Err(ServiceError::InvalidRequest);
        }
        let result = (|| {
            let resource = self
                .transport
                .resources
                .get(&id)
                .ok_or(ServiceError::Unavailable)?;
            if resource.retired.is_some()
                || resource.proof.is_some_and(|id| {
                    self.transport
                        .proofs
                        .get(&id)
                        .is_some_and(|p| p.retired.is_some())
                })
                || self.direct_dns_binding(resource.binding.bundle)? != resource.binding
                || self.authority.now() >= resource.expires
            {
                return Err(ServiceError::Unavailable);
            }
            let facts = resource.incoming.evidence.validate()?;
            if facts.remote != endpoint(resource.binding.peer)?
                || facts.protocol != resource.binding.peer.protocol
            {
                return Err(ServiceError::Unavailable);
            }
            let binding = resource.binding;
            let expires = resource.expires;
            self.authority.dns_socket(binding.ticket, &facts)?;
            // Backend fence может блокироваться: Known deadline не продлевается им.
            if self.authority.now() >= expires
                || self.direct_dns_binding(binding.bundle)? != binding
            {
                return Err(ServiceError::Unavailable);
            }
            Ok(())
        })();
        if result.is_err() {
            self.unknown = true;
            self.authority.revoke();
        }
        result
    }
    fn match_dns_physical(&mut self, physical: u64) -> Result<Option<Reply>, ServiceError> {
        let Some(reservation) = self.transport.reservations.get(&physical) else {
            return Ok(None);
        };
        if reservation.role != 2
            || !reservation.published
            || reservation.resource.is_some()
            || !reservation.future_history
        {
            return Err(ServiceError::InvalidRequest);
        }
        let Some(incoming) = self.transport.incoming.get(&physical) else {
            return Ok(None);
        };
        let b = &incoming.raw;
        let binding = reservation.binding;
        let parent = self
            .transport
            .reservations
            .get(&reservation.parent)
            .ok_or(ServiceError::Unavailable)?;
        if parent.role != 1
            || !parent.published
            || parent.binding != binding
            || parent.exchange != reservation.exchange
            || self.authority.now() >= parent.expires
            || self.authority.now() >= reservation.expires
            || self.direct_dns_binding(binding.bundle)? != binding
            || n64(b, 128) != reservation.parent
            || n64(b, 136) != binding.query
            || n64(b, 144) != binding.bundle
            || n16(b, 160) != binding.resolver
            || n16(b, 162) != 0
            || b[164] != binding.peer.protocol
            || b[165] != if binding.peer.protocol == 6 { 1 } else { 2 }
            || !destination_matches(&b[168..192], binding.peer)
        {
            return Err(ServiceError::InvalidRequest);
        }
        let facts = incoming.evidence.validate()?;
        if facts.remote != endpoint(binding.peer)? || facts.protocol != binding.peer.protocol {
            return Err(ServiceError::InvalidRequest);
        }
        if self.transport.resources.values().any(|r| {
            r.incoming.evidence.facts.cookie == facts.cookie
                && r.incoming.evidence.facts.namespace == facts.namespace
        }) {
            return Err(ServiceError::InvalidRequest);
        }
        self.authority.dns_socket(binding.ticket, &facts)?;
        let id = Self::id(&mut self.transport.next_resource)?;
        let reservation = self
            .transport
            .reservations
            .get_mut(&physical)
            .ok_or(ServiceError::Unavailable)?;
        let (request, exchange, expires) = (
            reservation.request,
            reservation.exchange,
            reservation.expires,
        );
        reservation.resource = Some(id);
        reservation.future_history = false;
        let mut incoming = self
            .transport
            .incoming
            .remove(&physical)
            .ok_or(ServiceError::Unavailable)?;
        incoming.pending.take(); // runtime pending35 остаётся ровно до PhysicalAck.
        let mut paid = reservation
            .physical_credit
            .take()
            .ok_or(ServiceError::Unavailable)?;
        paid.resize(2).map_err(unavailable)?;
        incoming._fds = paid;
        self.transport.resources.insert(
            id,
            Resource {
                release_acked: false,
                retired: None,
                cleanup_until: expires + Duration::from_secs(1),
                binding,
                reservation: physical,
                exchange,
                expires,
                incoming,
                acked: false,
                proof: None,
            },
        );
        let mut reply = Reply::allow(
            Operation::PhysicalAck,
            request,
            binding,
            expires,
            Commit::Physical(id),
        );
        for (at, value) in [
            (8, physical),
            (16, id),
            (24, binding.query),
            (32, binding.bundle),
            (40, binding.epoch),
        ] {
            set64(&mut reply.body, at, value);
        }
        Ok(Some(reply))
    }
    fn logical_dns(
        &mut self,
        view: View<'_, 38>,
        request: u64,
        session: Instant,
    ) -> Result<Reply, ServiceError> {
        let b = view.bytes();
        if b[2] != 1 || n16(b, 4) != 1 || n64(b, 40) != 0 {
            return Err(ServiceError::Unsupported);
        }
        let parent = n64(b, 8);
        let p = self
            .transport
            .reservations
            .get(&parent)
            .ok_or(ServiceError::Unavailable)?;
        if p.role != 1
            || !p.published
            || !p.future_history
            || p.exchange != n64(b, 32)
            || p.binding.query != n64(b, 16)
            || p.binding.bundle != n64(b, 24)
            || self.authority.now() >= p.expires
        {
            return Err(ServiceError::InvalidRequest);
        }
        let binding = p.binding;
        let exchange = p.exchange;
        let expires = p
            .expires
            .min(session)
            .min(self.authority.now() + Duration::from_nanos(n64(b, 56)));
        let id = n64(b, 64);
        self.validate_dns_resource(id)?;
        let r = self
            .transport
            .resources
            .get(&id)
            .ok_or(ServiceError::Unavailable)?;
        if !r.acked
            || r.proof.is_some()
            || r.binding != binding
            || r.exchange != exchange
            || self
                .transport
                .proofs
                .values()
                .any(|p| p.exchange == exchange)
        {
            return Err(ServiceError::InvalidRequest);
        }
        let expires = expires.min(r.expires);
        let memory = self
            .budget
            .dynamic
            .reserve(std::mem::size_of::<DirectProof>() + 80)
            .map_err(unavailable)?;
        let proof = Self::id(&mut self.transport.next_proof)?;
        self.transport
            .reservations
            .get_mut(&parent)
            .ok_or(ServiceError::Unavailable)?
            .future_history = false;
        self.transport
            .resources
            .get_mut(&id)
            .ok_or(ServiceError::Unavailable)?
            .proof = Some(proof);
        self.transport.proofs.insert(
            proof,
            DirectProof {
                release_acked: false,
                retired: None,
                acked: false,
                binding,
                exchange,
                resource: id,
                expires,
                revision: 1,
                producer_sequence: n64(b, 48),
                _memory: memory,
            },
        );
        let mut reply = Reply::allow(
            Operation::LogicalAck,
            request,
            binding,
            expires,
            Commit::Logical(proof),
        );
        for (at, value) in [
            (8, exchange),
            (16, proof),
            (24, binding.query),
            (32, binding.bundle),
            (40, 1),
        ] {
            set64(&mut reply.body, at, value);
        }
        reply.body[56..58].copy_from_slice(&1u16.to_be_bytes());
        reply.body[58] = 1;
        Ok(reply)
    }
}
fn endpoint(target: Target) -> Result<SocketAddr, ServiceError> {
    let mut address = [0; 16];
    let d = target.wire();
    if !matches!(d.family, 4 | 6) {
        return Err(ServiceError::Unsupported);
    }
    address[..d.bytes.len()].copy_from_slice(d.bytes);
    super::endpoint(d.family, address, d.port)
}
fn destination_matches(raw: &[u8], target: Target) -> bool {
    let d = target.wire();
    let n = d.bytes.len();
    raw[0] == d.family
        && raw[1] == d.protocol
        && n16(raw, 2) == d.port
        && raw[4] as usize == n
        && raw[5..7] == [0, 0]
        && raw[7..7 + n] == *d.bytes
        && raw[7 + n..].iter().all(|b| *b == 0)
}

pub(super) fn handle<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    request: u64,
    record: Record<'_>,
    session: Instant,
) -> Result<Reply, ServiceError> {
    let operation = match record {
        Record::Reserve(_) => Operation::Reserved,
        Record::LogicalBind(_) => Operation::LogicalAck,
        Record::Retire(_) => Operation::Retired,
        _ => return Err(ServiceError::Unsupported),
    };
    if issuer.retired.iter().any(|(id, _)| *id == request) {
        return Ok(Reply::denied(operation, request, session));
    }
    let result = match record {
        Record::Reserve(v) => issuer.reserve_dns(v, request, socket, session),
        Record::LogicalBind(v) => issuer.logical_dns(v, request, session),
        Record::Retire(v) => issuer.retire_dns(v, request, session),
        _ => Err(ServiceError::Unsupported),
    };
    Ok(result.unwrap_or_else(|_| {
        let mut reply = Reply::denied(operation, request, session);
        if issuer.unknown {
            reply.body[2] = 3;
        }
        reply
    }))
}

pub(super) fn send_reply<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    sequence: u64,
    mut reply: Reply,
) -> Result<(), ServiceError> {
    let neg = issuer.negotiated.ok_or(ServiceError::Unavailable)?;
    loop {
        let now = issuer.authority.now();
        if stop.load(Ordering::Acquire) || now >= reply.expires {
            return Err(ServiceError::Unavailable);
        }
        let missing = match reply.commit {
            Commit::Reserved(id) => !issuer.transport.reservations.contains_key(&id),
            Commit::Physical(id) => !issuer.transport.resources.contains_key(&id),
            Commit::Logical(id) => !issuer.transport.proofs.contains_key(&id),
            Commit::ReleasedProof(id) => !issuer.transport.proofs.contains_key(&id),
            Commit::ClosedResource(id) => !issuer.transport.resources.contains_key(&id),
            Commit::None => false,
        };
        if missing || issuer.retired.iter().any(|(id, _)| *id == reply.request) {
            reply = Reply::denied(reply.operation, reply.request, reply.expires);
        }
        if issuer.unknown && reply.operation != Operation::Retired {
            reply = Reply::denied(reply.operation, reply.request, reply.expires);
            reply.body[2] = 3;
        }
        if let Some(binding) = reply.binding {
            if issuer.direct_dns_binding(binding.bundle)? != binding {
                return Err(ServiceError::Unavailable);
            }
            match reply.commit {
                Commit::Physical(id) => issuer.validate_dns_resource(id)?,
                Commit::Logical(id) => {
                    let p = issuer
                        .transport
                        .proofs
                        .get(&id)
                        .ok_or(ServiceError::Unavailable)?;
                    if p.binding != binding
                        || p.expires <= now
                        || p.producer_sequence == 0
                        || p.producer_sequence == u64::MAX
                    {
                        return Err(ServiceError::Unavailable);
                    }
                    issuer.validate_dns_resource(p.resource)?;
                }
                _ => {}
            }
            let checked = issuer.authority.now();
            if checked >= reply.expires {
                return Err(ServiceError::Unavailable);
            }
            set64(
                &mut reply.body,
                48,
                (reply.expires - checked).as_nanos().min(1_000_000_000) as u64,
            );
        } else if !issuer.unknown && reply.operation != Operation::Retired {
            issuer.fence()?;
        }
        let mut out = [0; 192];
        let frame = wire::dns_v2::DnsFrame {
            header: wire::dns_v2::Envelope {
                sequence,
                reply_to: reply.request,
                binding: issuer.record.binding,
            },
            record: Record::decode(reply.operation, &reply.body[..reply.len])
                .map_err(unavailable)?,
        };
        let n = frame.encode(&neg, &mut out).map_err(unavailable)?;
        if socket.write(&out[..n])? {
            match reply.commit {
                Commit::ReleasedProof(id) => {
                    issuer
                        .transport
                        .proofs
                        .get_mut(&id)
                        .ok_or(ServiceError::Unavailable)?
                        .release_acked = true;
                }
                Commit::ClosedResource(id) => {
                    let r = issuer
                        .transport
                        .resources
                        .get_mut(&id)
                        .ok_or(ServiceError::Unavailable)?;
                    if !r.release_acked {
                        r.incoming._fds.resize(0).map_err(unavailable)?;
                        r.release_acked = true;
                        let reservation = issuer
                            .transport
                            .reservations
                            .get_mut(&r.reservation)
                            .ok_or(ServiceError::Unavailable)?;
                        reservation.resource = None;
                        reservation.published = false;
                    }
                }
                Commit::Reserved(id) => {
                    issuer
                        .transport
                        .reservations
                        .get_mut(&id)
                        .ok_or(ServiceError::Unavailable)?
                        .published = true;
                }
                Commit::Physical(id) => {
                    let r = issuer
                        .transport
                        .resources
                        .get_mut(&id)
                        .ok_or(ServiceError::Unavailable)?;
                    r.acked = true;
                    issuer
                        .transport
                        .reservations
                        .get_mut(&r.reservation)
                        .ok_or(ServiceError::Unavailable)?
                        .pending
                        .take();
                }
                Commit::Logical(id) => {
                    let p = issuer
                        .transport
                        .proofs
                        .get_mut(&id)
                        .ok_or(ServiceError::Unavailable)?;
                    p.acked = true;
                    let parent = issuer
                        .transport
                        .reservations
                        .iter_mut()
                        .find(|(_, r)| r.role == 1 && r.exchange == p.exchange)
                        .ok_or(ServiceError::Unavailable)?
                        .1;
                    parent.pending.take();
                }
                Commit::None => {}
            }
            return Ok(());
        }
        socket.writable_until(reply.expires);
    }
}

pub(super) fn ingest<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
) -> Result<bool, ServiceError> {
    let mut changed = false;
    for _ in 0..64 {
        let Some(mut incoming) = socket.take_dns()? else {
            break;
        };
        changed = true;
        let physical = n64(&incoming.raw, 152);
        let binding = match issuer.direct_dns_binding(n64(&incoming.raw, 144)) {
            Ok(binding) => binding,
            Err(error) => {
                issuer.unknown = true;
                issuer.authority.revoke();
                return Err(error);
            }
        };
        if incoming.raw[165] == 3
            || n64(&incoming.raw, 136) != binding.query
            || n16(&incoming.raw, 160) != binding.resolver
            || issuer.transport.incoming.contains_key(&physical)
            || issuer
                .transport
                .resources
                .values()
                .any(|r| r.reservation == physical)
            || physical <= issuer.transport.next_reservation
                && !issuer.transport.reservations.contains_key(&physical)
        {
            issuer.unknown = true;
            issuer.authority.revoke();
            return Err(ServiceError::InvalidRequest);
        }
        if let Err(error) = incoming.evidence.validate() {
            issuer.unknown = true;
            issuer.authority.revoke();
            return Err(error);
        }
        if let Some(credit) = incoming.history.take() {
            credit.commit(4, physical)?;
        } else {
            issuer.bundle_history(1)?;
        }
        issuer.transport.incoming.insert(physical, incoming);
    }
    Ok(changed)
}
pub(super) fn progress<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    outgoing: &mut u64,
    mut drain: impl FnMut(&mut Issuer<A>) -> Result<(), ServiceError>,
) -> Result<bool, ServiceError> {
    let mut changed = ingest(issuer, socket)?;
    if !issuer.transport.incoming.is_empty() {
        drain(issuer)?;
    }
    let mut ids = [0; 64];
    let mut n = 0;
    for id in issuer.transport.incoming.keys() {
        if n == 64 {
            return Err(ServiceError::Busy);
        }
        ids[n] = *id;
        n += 1;
    }
    for id in &ids[..n] {
        let reply = match issuer.match_dns_physical(*id) {
            Ok(reply) => reply,
            Err(e) => {
                issuer.transport.incoming.remove(id);
                issuer.unknown = true;
                issuer.authority.revoke();
                return Err(e);
            }
        };
        if let Some(reply) = reply {
            *outgoing = outgoing
                .checked_add(1)
                .filter(|n| *n != u64::MAX)
                .ok_or(ServiceError::Unavailable)?;
            send_reply(issuer, socket, stop, *outgoing, reply)?;
            changed = true;
        }
    }
    Ok(changed)
}
pub(super) fn cancel<A: Authority>(
    issuer: &mut Issuer<A>,
    target: u8,
    id: u64,
) -> Result<(), ServiceError> {
    if cleanup_deadline(issuer, target, id).is_some_and(|until| issuer.authority.now() >= until) {
        issuer.unknown = true;
        issuer.authority.revoke();
        return Err(ServiceError::Unavailable);
    }
    let result = match target {
        7 => issuer.transport.cancel_reservation(id),
        2 => {
            if issuer.transport.closed_exchanges[..issuer.transport.closed_count]
                .iter()
                .any(|v| {
                    v.is_some_and(|(exchange, until)| {
                        exchange == id && issuer.authority.now() < until
                    })
                })
            {
                return Ok(());
            }
            let r = issuer
                .transport
                .reservations
                .iter()
                .find(|(_, r)| r.role == 1 && r.exchange == id)
                .map(|(id, _)| *id)
                .ok_or(ServiceError::Unavailable)?;
            issuer.transport.cancel_reservation(r)
        }
        3 if issuer.transport.resources.contains_key(&id) => Err(ServiceError::Unavailable),
        4 if issuer.transport.proofs.contains_key(&id) => Err(ServiceError::Unavailable),
        _ => return Err(ServiceError::InvalidRequest),
    };
    if result.is_err() {
        issuer.unknown = true;
        issuer.authority.revoke();
    }
    result
}

pub(super) fn cleanup_deadline<A: Authority>(
    issuer: &Issuer<A>,
    target: u8,
    id: u64,
) -> Option<Instant> {
    let exchange = if target == 7 {
        issuer.transport.reservations.get(&id).map(|r| r.exchange)
    } else if target == 2 {
        Some(id)
    } else {
        None
    }?;
    issuer
        .transport
        .resources
        .values()
        .filter(|r| r.exchange == exchange)
        .map(|r| r.cleanup_until)
        .chain(
            issuer.transport.closed_exchanges[..issuer.transport.closed_count]
                .iter()
                .filter_map(|entry| {
                    entry
                        .filter(|(e, _)| *e == exchange)
                        .map(|(_, until)| until)
                }),
        )
        .min()
}
