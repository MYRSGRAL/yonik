//! Custody и переходы frozen ABI. Caller FD и окружение не создают authority.
#[cfg(test)]
use super::broker::Broker;
use super::{
    broker::{Lookup, Unavailable},
    native_wire::{self as wire, Header, Kind, Malformed, Sequence},
};
use crate::managed_network::tun::BoundTun;
use crate::profile_channel::ReceiptKind;
use std::{collections::VecDeque, time::Instant};
use std::{os::fd::OwnedFd, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnerReference {
    pub kind: ReceiptKind,
    pub id: u64,
}
impl OwnerReference {
    pub(crate) const NONE: Self = Self {
        kind: ReceiptKind::None,
        id: 0,
    };
}
struct OwnerObservation<T> {
    value: T,
    expiry: Instant,
}
struct OwnerReceiptEntry<T> {
    reference: OwnerReference,
    flow: super::broker::Flow,
    source_flow: Option<u64>,
    value: Arc<T>,
    expiry: Instant,
}
struct OwnerProof<T> {
    reference: OwnerReference,
    value: Arc<T>,
    expiry: Instant,
}
struct OwnerQueries<T> {
    entries: VecDeque<OwnerReceiptEntry<T>>,
    next_operation: u64,
    last_frozen: u64,
    revoked: bool,
}
impl<T> OwnerQueries<T> {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            next_operation: 0,
            last_frozen: 0,
            revoked: false,
        }
    }
    fn insert(&mut self, entry: OwnerReceiptEntry<T>, now: Instant) -> Result<(), Unavailable> {
        if self.revoked {
            return Err(Unavailable::Revoked);
        }
        if entry.expiry <= now {
            return Err(Unavailable::Timeout);
        }
        if entry.expiry > now + super::broker::DEADLINE {
            return Err(Unavailable::Malformed);
        }
        self.entries.retain(|entry| entry.expiry > now);
        if self.entries.len() == 64 {
            self.entries.pop_front();
        }
        if self.entries.capacity() < 64 {
            self.entries
                .try_reserve_exact(64 - self.entries.len())
                .map_err(|_| Unavailable::Limit)?;
        }
        self.entries.push_back(entry);
        Ok(())
    }
    /// Вызывается transport только ПОСЛЕ successful actual send_reply.
    fn sent_frozen(
        &mut self,
        id: u64,
        flow: super::broker::Flow,
        observation: OwnerObservation<T>,
        now: Instant,
    ) -> Result<(), Unavailable> {
        if id == 0 || id <= self.last_frozen {
            return Err(Unavailable::Malformed);
        }
        self.last_frozen = id;
        self.insert(
            OwnerReceiptEntry {
                reference: OwnerReference {
                    kind: ReceiptKind::FrozenSent,
                    id,
                },
                flow,
                source_flow: None,
                value: Arc::new(observation.value),
                expiry: observation.expiry,
            },
            now,
        )
    }
    fn resolve(
        &mut self,
        source_flow: u64,
        flow: super::broker::Flow,
        reference: OwnerReference,
        clock: impl Fn() -> Instant,
        lookup: impl FnOnce() -> Result<OwnerObservation<T>, Unavailable>,
    ) -> Result<OwnerProof<T>, Unavailable> {
        if self.revoked {
            return Err(Unavailable::Revoked);
        }
        if source_flow == 0 || (reference.kind == ReceiptKind::None) != (reference.id == 0) {
            return Err(Unavailable::Malformed);
        }
        let now = clock();
        self.entries.retain(|entry| entry.expiry > now);
        if reference.kind != ReceiptKind::None {
            if let Some(entry) = self
                .entries
                .iter_mut()
                .find(|entry| entry.reference == reference)
            {
                if entry.flow != flow || entry.source_flow.is_some_and(|id| id != source_flow) {
                    return Err(Unavailable::Authority);
                }
                entry.source_flow = Some(source_flow);
                return Ok(OwnerProof {
                    reference,
                    value: Arc::clone(&entry.value),
                    expiry: entry.expiry,
                });
            }
        }
        // Резервируем monotonic ID до RPC/allocations; неудачная операция может
        // оставить gap, но не переиспользует ID и не выдаёт synthetic receipt.
        self.next_operation = match self.next_operation.checked_add(1) {
            Some(id) => id,
            None => {
                self.revoke();
                return Err(Unavailable::Limit);
            }
        };
        let reference = OwnerReference {
            kind: ReceiptKind::SidebandOperation,
            id: self.next_operation,
        };
        // Unknown/evicted reference: ровно один real backend lookup.
        let observation = lookup()?;
        let now = clock();
        if observation.expiry <= now {
            return Err(Unavailable::Timeout);
        }
        let value = Arc::new(observation.value);
        let expiry = observation.expiry;
        self.insert(
            OwnerReceiptEntry {
                reference,
                flow,
                source_flow: Some(source_flow),
                value: Arc::clone(&value),
                expiry,
            },
            now,
        )?;
        Ok(OwnerProof {
            reference,
            value,
            expiry,
        })
    }
    fn cancel_source(&mut self, id: u64) {
        self.entries.retain(|entry| entry.source_flow != Some(id));
    }
    fn revoke(&mut self) {
        self.revoked = true;
        self.entries = VecDeque::new();
    }
}

struct OwnerRecord {
    owner: super::broker::OwnerSnapshot,
    path: String,
    _credit: Option<OwnerCredit>,
}
const OWNER_BUDGET_BYTES: usize = 512 * 1024;
struct OwnerBudget {
    _memory: crate::helper::memory::ByteLease,
    bytes: crate::helper::memory::ByteBudget,
}
struct OwnerCredit {
    _budget: Arc<OwnerBudget>,
    _bytes: crate::helper::memory::ByteLease,
}
impl OwnerBudget {
    fn new() -> Result<Arc<Self>, Unavailable> {
        let memory = crate::helper::memory::config_budget()
            .reserve(OWNER_BUDGET_BYTES)
            .map_err(|_| Unavailable::Limit)?;
        Ok(Arc::new(Self {
            _memory: memory,
            bytes: crate::helper::memory::ByteBudget::new(OWNER_BUDGET_BYTES - 64 * 1024),
        }))
    }
    fn reserve(self: &Arc<Self>) -> Result<OwnerCredit, Unavailable> {
        // MAX_PATH=512 + OwnerSnapshot/Arc/allocator overhead; reservation
        // предшествует backend RPC и остаётся с shared proof до последнего Drop.
        let bytes = self.bytes.reserve(2048).map_err(|_| Unavailable::Limit)?;
        Ok(OwnerCredit {
            _budget: Arc::clone(self),
            _bytes: bytes,
        })
    }
}
enum OwnerOperation {
    Lookup {
        source_flow: u64,
        flow: super::broker::Flow,
        reference: OwnerReference,
        deadline: Instant,
        reply: std::sync::mpsc::SyncSender<Result<OwnerProof<OwnerRecord>, Unavailable>>,
    },
    CancelSource(u64),
}
/// Только from_verified Session выпускает endpoint. Он не владеет RemoteLookup.
pub(crate) struct OwnerEndpoint {
    sender: std::sync::mpsc::SyncSender<OwnerOperation>,
    scope: crate::helper::native_bootstrap::RuntimeScopeStamp,
}
pub(crate) struct KnownOwnerProof {
    proof: OwnerProof<OwnerRecord>,
    source_flow: u64,
    flow: super::broker::Flow,
    scope: crate::helper::native_bootstrap::RuntimeScopeStamp,
}
impl KnownOwnerProof {
    pub(crate) fn original_expiry(&self) -> Instant {
        self.proof.expiry
    }
    pub(crate) fn checked(
        &self,
        scope: &crate::helper::native_bootstrap::RuntimeScopeStamp,
        source_flow: u64,
        flow: super::broker::Flow,
    ) -> Result<
        (
            &super::broker::OwnerSnapshot,
            &str,
            std::time::Duration,
            OwnerReference,
        ),
        Unavailable,
    > {
        if !self.scope.same_scope(scope) || self.source_flow != source_flow || self.flow != flow {
            return Err(Unavailable::Authority);
        }
        if self.proof.value._credit.is_none() {
            return Err(Unavailable::Authority);
        }
        self.scope.validate().map_err(|_| Unavailable::Revoked)?;
        let remaining = self.proof.expiry.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Unavailable::Timeout);
        }
        Ok((
            &self.proof.value.owner,
            &self.proof.value.path,
            remaining.min(super::broker::DEADLINE),
            self.proof.reference,
        ))
    }
}
impl OwnerEndpoint {
    pub(crate) fn lookup(
        &self,
        source_flow: u64,
        flow: super::broker::Flow,
        reference: OwnerReference,
        deadline: Instant,
    ) -> Result<KnownOwnerProof, Unavailable> {
        if source_flow == 0 || (reference.kind == ReceiptKind::None) != (reference.id == 0) {
            return Err(Unavailable::Malformed);
        }
        self.scope.validate().map_err(|_| Unavailable::Revoked)?;
        let deadline = deadline.min(Instant::now() + super::broker::DEADLINE);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Unavailable::Timeout);
        }
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        self.sender
            .try_send(OwnerOperation::Lookup {
                source_flow,
                flow,
                reference,
                deadline,
                reply: sender,
            })
            .map_err(|e| match e {
                std::sync::mpsc::TrySendError::Full(_) => Unavailable::Limit,
                std::sync::mpsc::TrySendError::Disconnected(_) => Unavailable::Disconnected,
            })?;
        let proof = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|e| match e {
                std::sync::mpsc::RecvTimeoutError::Timeout => Unavailable::Timeout,
                std::sync::mpsc::RecvTimeoutError::Disconnected => Unavailable::Disconnected,
            })??;
        let proof = KnownOwnerProof {
            proof,
            source_flow,
            flow,
            scope: self.scope.fork_lookup(),
        };
        proof.checked(&self.scope, source_flow, flow)?;
        Ok(proof)
    }
    pub(crate) fn cancel_source(&self, source_flow: u64) -> Result<(), Unavailable> {
        if source_flow == 0 {
            return Err(Unavailable::Malformed);
        }
        self.sender
            .try_send(OwnerOperation::CancelSource(source_flow))
            .map_err(|e| match e {
                std::sync::mpsc::TrySendError::Full(_) => Unavailable::Limit,
                std::sync::mpsc::TrySendError::Disconnected(_) => Unavailable::Disconnected,
            })
    }
}

#[cfg(test)]
#[path = "native_session/owner_tests.rs"]
mod owner_tests;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Hello,
    Features,
    Ack,
    Active,
    Closed,
}

/// Не имеет публичного конструктора: только verified helper bootstrap может
/// передать уже привязанный TUN и собственные endpoint роли.
pub struct Session {
    phase: Phase,
    epoch: u64,
    digest: [u8; 32],
    nonce: [u8; 32],
    session: [u8; 16],
    generation: u64,
    invocation: [u8; 16],
    app_required: bool,
    roles: Option<Roles>,
    sequence: Sequence,
    scope: Option<crate::helper::native_bootstrap::RuntimeScopeStamp>,
    owner_queries: OwnerQueries<OwnerRecord>,
    owner_receiver: Option<std::sync::mpsc::Receiver<OwnerOperation>>,
    owner_budget: Option<Arc<OwnerBudget>>,
}
struct Roles {
    tun: TunRole,
    worker: OwnedFd,
    #[cfg(test)]
    broker: Option<Broker>,
    remote: Option<super::broker::RemoteLookup>,
}

impl Roles {
    fn lookup(&mut self, flow: super::broker::Flow) -> Lookup {
        if let Some(remote) = self.remote.as_mut() {
            return remote.lookup(flow);
        }
        #[cfg(test)]
        if let Some(local) = self.broker.as_mut() {
            return local.lookup(flow);
        }
        Lookup::MechanismUnavailable(Unavailable::Authority)
    }
    fn project(&mut self, flow: super::broker::Flow, epoch: u64) -> super::broker::ProjectedLookup {
        if let Some(remote) = self.remote.as_mut() {
            return remote.lookup_and_project(flow, epoch);
        }
        #[cfg(test)]
        if let Some(local) = self.broker.as_mut() {
            return local.lookup_and_project(flow, epoch);
        }
        super::broker::ProjectedLookup::Unavailable(Unavailable::Authority)
    }
}

// Production хранит только helper-owned queue; raw FD доступен лишь fixture.
#[cfg_attr(not(test), allow(dead_code))]
enum TunRole {
    Bound(Arc<BoundTun>),
    #[cfg(test)]
    Fixture {
        fd: Arc<OwnedFd>,
        metadata: [u8; 32],
    },
}
impl TunRole {
    fn metadata(&self) -> Result<[u8; 32], Malformed> {
        match self {
            Self::Bound(bound) => bound.attach_metadata().map_err(|_| Malformed),
            #[cfg(test)]
            Self::Fixture { metadata, .. } => Ok(*metadata),
        }
    }
    fn duplicate(&self) -> Result<OwnedFd, Malformed> {
        match self {
            Self::Bound(bound) => bound.duplicate_for_attach().map_err(|_| Malformed),
            #[cfg(test)]
            Self::Fixture { fd, .. } => {
                rustix::io::fcntl_dupfd_cloexec(fd.as_ref(), 0).map_err(|_| Malformed)
            }
        }
    }
}

impl Session {
    pub(crate) fn owner_endpoint(&mut self) -> Result<OwnerEndpoint, Unavailable> {
        if self.phase != Phase::Hello || !self.app_required || self.owner_receiver.is_some() {
            return Err(Unavailable::Authority);
        }
        let scope = self.scope.as_ref().ok_or(Unavailable::Authority)?;
        scope
            .validate_admission()
            .map_err(|_| Unavailable::Authority)?;
        let memory = OwnerBudget::new()?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(64);
        let endpoint = OwnerEndpoint {
            sender,
            scope: scope.fork_lookup(),
        };
        self.owner_receiver = Some(receiver);
        self.owner_budget = Some(memory);
        Ok(endpoint)
    }
    fn poll_owner_operation(&mut self) -> Result<(), Unavailable> {
        let Some(receiver) = self.owner_receiver.as_ref() else {
            return Ok(());
        };
        let operation = match receiver.try_recv() {
            Ok(operation) => operation,
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(Unavailable::Disconnected);
            }
        };
        self.scope
            .as_ref()
            .ok_or(Unavailable::Authority)?
            .validate()
            .map_err(|_| Unavailable::Revoked)?;
        match operation {
            OwnerOperation::CancelSource(id) => self.owner_queries.cancel_source(id),
            OwnerOperation::Lookup {
                source_flow,
                flow,
                reference,
                deadline,
                reply,
            } => {
                let result = if Instant::now() >= deadline {
                    Err(Unavailable::Timeout)
                } else {
                    let roles = self.roles.as_mut().ok_or(Unavailable::Authority)?;
                    let epoch = self.epoch;
                    let budget = self.owner_budget.as_ref().ok_or(Unavailable::Authority)?;
                    self.owner_queries
                        .resolve(source_flow, flow, reference, Instant::now, || {
                            let credit = budget.reserve()?;
                            match roles.project(flow, epoch) {
                                super::broker::ProjectedLookup::Known(projection) => {
                                    let expiry = projection.expiry()?;
                                    let (owner, path, _) = projection.into_parts();
                                    Ok(OwnerObservation {
                                        value: OwnerRecord {
                                            owner,
                                            path,
                                            _credit: Some(credit),
                                        },
                                        expiry,
                                    })
                                }
                                super::broker::ProjectedLookup::Unknown => {
                                    Err(Unavailable::Authority)
                                }
                                super::broker::ProjectedLookup::Unavailable(reason) => Err(reason),
                            }
                        })
                };
                let result = result.and_then(|proof| {
                    self.scope
                        .as_ref()
                        .ok_or(Unavailable::Authority)?
                        .validate()
                        .map_err(|_| Unavailable::Revoked)?;
                    if Instant::now() >= deadline || Instant::now() >= proof.expiry {
                        return Err(Unavailable::Timeout);
                    }
                    Ok(proof)
                });
                // Receiver может уже отменить operation. Не блокируем owner actor
                // и не публикуем grant: endpoint получает только owner proof.
                match reply.try_send(result) {
                    Ok(()) | Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
                    Err(std::sync::mpsc::TrySendError::Full(_)) => {
                        return Err(Unavailable::Malformed);
                    }
                }
            }
        }
        Ok(())
    }
    pub(crate) fn from_verified(
        role: crate::helper::native_bootstrap::SessionRole,
        remote: super::broker::RemoteLookup,
    ) -> Result<Self, Unavailable> {
        let (scope, queue, worker) = role.into_parts();
        scope.validate().map_err(|_| Unavailable::Authority)?;
        remote.validate_scope(&scope)?;

        let (nonce, session, generation, invocation, epoch, digest) = scope.context();
        Ok(Self {
            phase: Phase::Hello,
            epoch,
            digest,
            nonce,
            session,
            generation,
            invocation,
            app_required: true,
            roles: Some(Roles {
                tun: TunRole::Bound(queue),
                worker,
                #[cfg(test)]
                broker: None,
                remote: Some(remote),
            }),
            sequence: Sequence::default(),
            scope: Some(scope),
            owner_queries: OwnerQueries::new(),
            owner_receiver: None,
            owner_budget: None,
        })
    }

    /// Пока kernel/unit proof не может быть выпущен, raw caller входы
    /// безусловно отвергаются. Этот gate не принимает fd, env или proof bytes.
    pub fn verified_helper_bootstrap() -> Result<Self, Unavailable> {
        Err(Unavailable::Authority)
    }
    pub fn close(&mut self) {
        if let Some(scope) = self.scope.take() {
            scope.revoke();
        }
        self.owner_queries.revoke();
        self.owner_receiver.take();
        self.owner_budget.take();
        self.phase = Phase::Closed;
        self.sequence.retire();
        if let Some(mut roles) = self.roles.take() {
            if let Some(remote) = roles.remote.as_mut() {
                remote.revoke();
            }
            #[cfg(test)]
            if let Some(broker) = roles.broker.as_mut() {
                broker.revoke();
            }
            drop(roles);
        }
    }
    /// EOF, timeout и transport error завершают все helper-owned роли.
    pub fn eof(&mut self) {
        self.close();
    }
    fn header(&self, frame: &[u8]) -> Result<Header, Malformed> {
        if let Some(scope) = &self.scope {
            scope.validate().map_err(|_| Malformed)?;
        }
        let header = Header::decode(frame, 0)?;
        if header.epoch != self.epoch || header.digest != self.digest || frame[64..96] != self.nonce
        {
            return Err(Malformed);
        }
        Ok(header)
    }
    fn frame(&self, kind: Kind) -> Result<Vec<u8>, Malformed> {
        if let Some(scope) = &self.scope {
            scope.validate().map_err(|_| Malformed)?;
        }
        let mut bytes = vec![0; kind.fixed_bytes().ok_or(Malformed)?];
        Header {
            kind,
            request_id: 0,
            epoch: self.epoch,
            digest: self.digest,
        }
        .write(&mut bytes)?;
        bytes[64..96].copy_from_slice(&self.nonce);
        Ok(bytes)
    }
    pub fn hello(&mut self) -> Result<Vec<u8>, Malformed> {
        let result = self.hello_inner();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn hello_inner(&mut self) -> Result<Vec<u8>, Malformed> {
        if self.phase != Phase::Hello || self.roles.is_none() {
            return Err(Malformed);
        }
        let mut bytes = self.frame(Kind::Hello)?;
        bytes[96..112].copy_from_slice(&self.session);
        bytes[112..120].copy_from_slice(&self.generation.to_be_bytes());
        bytes[120..136].copy_from_slice(&self.invocation);
        bytes[136..140].copy_from_slice(&(wire::MAX_FRAME as u32).to_be_bytes());
        bytes[140..142].copy_from_slice(&1u16.to_be_bytes());
        bytes[144..152].copy_from_slice(&wire::OWNER_TTL_NS.to_be_bytes());
        bytes[152..160].copy_from_slice(&wire::BOOTSTRAP_NS.to_be_bytes());
        bytes[160..168].copy_from_slice(&wire::FEATURES.to_be_bytes());
        bytes[168..176].copy_from_slice(&u64::from(self.app_required).to_be_bytes());
        Header::decode(&bytes, 0)?;
        self.phase = Phase::Features;
        Ok(bytes)
    }
    /// ATTACH metadata предоставляется только resource owner. Ровно один
    /// duplicate создаётся здесь; при ошибке сессия целиком отзывается.
    pub fn attach(&mut self, features: &[u8]) -> Result<(Vec<u8>, OwnedFd), Malformed> {
        let result = self.attach_inner(features);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn attach_inner(&mut self, features: &[u8]) -> Result<(Vec<u8>, OwnedFd), Malformed> {
        if self.phase != Phase::Features || self.header(features)?.kind != Kind::Features {
            return Err(Malformed);
        }
        wire::selected_features(features, self.app_required)?;
        let mut bytes = self.frame(Kind::Attach)?;
        let roles = self.roles.as_ref().ok_or(Malformed)?;
        bytes[96..128].copy_from_slice(&roles.tun.metadata()?);
        Header::decode(&bytes, 1)?;
        let fd = roles.tun.duplicate()?;
        self.phase = Phase::Ack;
        Ok((bytes, fd))
    }
    pub fn acknowledge(&mut self, bytes: &[u8]) -> Result<(), Malformed> {
        if self.phase != Phase::Ack || self.header(bytes).map(|h| h.kind) != Ok(Kind::AttachAck) {
            self.close();
            return Err(Malformed);
        }
        self.phase = Phase::Active;
        Ok(())
    }
    /// Canonical tuple передаётся существующему app-UID broker, без caller PID.
    pub fn lookup(&mut self, bytes: &[u8]) -> Result<Lookup, Malformed> {
        let result = self.lookup_inner(bytes);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn lookup_inner(&mut self, bytes: &[u8]) -> Result<Lookup, Malformed> {
        if self.phase != Phase::Active {
            return Err(Malformed);
        }
        let header = self.header(bytes)?;
        if header.kind != Kind::Lookup {
            return Err(Malformed);
        }
        let flow = wire::lookup_flow(bytes)?;
        self.sequence.begin(header.request_id)?;
        let result = self.roles.as_mut().map_or(
            Lookup::MechanismUnavailable(Unavailable::Authority),
            |roles| roles.lookup(flow),
        );
        self.sequence.complete(header.request_id)?;
        Ok(result)
    }
    fn lookup_and_project(
        &mut self,
        bytes: &[u8],
        denial: Option<Unavailable>,
    ) -> Result<super::broker::ProjectedLookup, Malformed> {
        let result = (|| {
            if self.phase != Phase::Active {
                return Err(Malformed);
            }
            let header = self.header(bytes)?;
            if header.kind != Kind::Lookup {
                return Err(Malformed);
            }
            let flow = wire::lookup_flow(bytes)?;
            self.sequence.begin(header.request_id)?;
            let result = if let Some(reason) = denial {
                super::broker::ProjectedLookup::Unavailable(reason)
            } else {
                self.roles.as_mut().map_or(
                    super::broker::ProjectedLookup::Unavailable(Unavailable::Authority),
                    |roles| roles.project(flow, self.epoch),
                )
            };
            self.sequence.complete(header.request_id)?;
            Ok(result)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn revoke(&mut self, bytes: &[u8]) -> Result<(), Malformed> {
        let valid = self.header(bytes).map(|h| h.kind) == Ok(Kind::Revoke);
        self.close();
        if valid { Ok(()) } else { Err(Malformed) }
    }
}
// Транспорт не создаёт authority: Session по-прежнему выпускает только helper.
mod transport;
#[cfg(test)]
pub(crate) use transport::tests::bound_terminal_controls;
#[cfg(test)]
pub(super) use transport::tests::{cold_roundtrip, known_roundtrip};

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}
impl Drop for Roles {
    fn drop(&mut self) {
        // shutdown затрагивает также уже выданные transport duplicates.
        let _shutdown = rustix::net::shutdown(&self.worker, rustix::net::Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    pub(super) fn metadata() -> [u8; 32] {
        let mut metadata = [0; 32];
        metadata[..4].copy_from_slice(&1u32.to_be_bytes());
        metadata[4..8].copy_from_slice(&1u32.to_be_bytes());
        metadata[8..12].copy_from_slice(&0x1001u32.to_be_bytes());
        metadata[12..16].copy_from_slice(&1500u32.to_be_bytes());
        metadata[16..20].copy_from_slice(b"tun0");
        metadata
    }
    pub(super) fn fixture() -> (Session, UnixStream) {
        let (worker, peer) = UnixStream::pair().unwrap();
        let tun = std::fs::File::open("/dev/null").unwrap();
        (
            Session {
                phase: Phase::Hello,
                epoch: 1,
                digest: [2; 32],
                nonce: [3; 32],
                session: [4; 16],
                generation: 1,
                invocation: [5; 16],
                app_required: false,
                roles: Some(Roles {
                    tun: TunRole::Fixture {
                        fd: Arc::new(tun.into()),
                        metadata: metadata(),
                    },
                    worker: worker.into(),
                    broker: None,
                    remote: None,
                }),
                scope: None,
                owner_queries: OwnerQueries::new(),
                owner_receiver: None,
                owner_budget: None,
                sequence: Sequence::new(),
            },
            peer,
        )
    }
    #[test]
    fn bootstrap_never_accepts_caller_authority() {
        assert!(matches!(
            Session::verified_helper_bootstrap(),
            Err(Unavailable::Authority)
        ));
    }
    #[test]
    fn closed_fixture_handshake_and_eof() {
        let (mut s, mut peer) = fixture();
        assert_eq!(
            Header::decode(&s.hello().unwrap(), 0).unwrap().kind,
            Kind::Hello
        );
        let mut features = s.frame(Kind::Features).unwrap();
        features[96..104].copy_from_slice(&wire::FEATURES.to_be_bytes());
        features[104..112].copy_from_slice(&wire::OWNED_TUN.to_be_bytes());
        let (attach, duplicate) = s.attach(&features).unwrap();
        assert_eq!(Header::decode(&attach, 1).unwrap().kind, Kind::Attach);
        drop(duplicate);
        let mut ack = s.frame(Kind::AttachAck).unwrap();
        ack[96..100].copy_from_slice(&1u32.to_be_bytes());
        s.acknowledge(&ack).unwrap();
        s.eof();
        assert!(s.roles.is_none());
        use std::io::Read;
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn attach_duplicate_and_close_preserve_original_owner() {
        use std::os::fd::AsRawFd;
        let (mut session, _) = fixture();
        let original = match &session.roles.as_ref().unwrap().tun {
            TunRole::Fixture { fd, .. } => Arc::clone(fd),
            _ => unreachable!(),
        };
        session.hello().unwrap();
        let mut features = session.frame(Kind::Features).unwrap();
        features[96..104].copy_from_slice(&wire::FEATURES.to_be_bytes());
        features[104..112].copy_from_slice(&wire::OWNED_TUN.to_be_bytes());
        let (_, duplicate) = session.attach(&features).unwrap();
        assert_ne!(duplicate.as_raw_fd(), original.as_raw_fd());
        assert!(
            rustix::io::fcntl_getfd(&duplicate)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        session.close();
        assert_eq!(Arc::strong_count(&original), 1);
        assert!(rustix::io::fcntl_getfd(original.as_ref()).is_ok());
        drop(duplicate);
        assert!(rustix::io::fcntl_getfd(original.as_ref()).is_ok());
    }
    #[test]
    fn malformed_owner_metadata_closes_session_before_duplicate() {
        let (mut session, _) = fixture();
        if let TunRole::Fixture { metadata, .. } = &mut session.roles.as_mut().unwrap().tun {
            metadata[8..12].copy_from_slice(&0x5001u32.to_be_bytes());
        }
        session.hello().unwrap();
        let mut features = session.frame(Kind::Features).unwrap();
        features[96..104].copy_from_slice(&wire::FEATURES.to_be_bytes());
        features[104..112].copy_from_slice(&wire::OWNED_TUN.to_be_bytes());
        assert!(session.attach(&features).is_err());
        assert!(session.roles.is_none());
    }
    #[test]
    fn malformed_features_retire_and_release_descriptors() {
        let (mut s, mut peer) = fixture();
        s.hello().unwrap();
        assert!(s.attach(&[]).is_err());
        assert_eq!(s.phase, Phase::Closed);
        assert!(s.roles.is_none());
        use std::io::Read;
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn lookup_before_ack_and_bad_revoke_close_session() {
        let (mut s, _) = fixture();
        assert!(s.lookup(&[]).is_err());
        assert!(s.roles.is_none());
        let (mut s, _) = fixture();
        assert!(s.revoke(&[]).is_err());
        assert!(s.roles.is_none());
    }
    #[test]
    fn replay_and_foreign_identity_close_roles() {
        for foreign in [false, true] {
            let (mut s, _) = fixture();
            let hello = s.hello().unwrap();
            let mut bytes = hello;
            if foreign {
                bytes[24..32].copy_from_slice(&2u64.to_be_bytes());
            }
            assert!(s.acknowledge(&bytes).is_err());
            assert!(s.roles.is_none());
            assert!(s.hello().is_err());
        }
    }
}

#[cfg(test)]
mod consumer_fixture;
#[cfg(test)]
pub(crate) use consumer_fixture::run as bound_consumer_fixture;
