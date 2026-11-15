//! Full-profile issuer. Env/DTO/manifest DATA не создают runtime authority.
use super::ServiceError;
use super::native_bootstrap::RuntimeScopeStamp;
use crate::attribution::native_session::{KnownOwnerProof, OwnerEndpoint, OwnerReference};
use crate::profile_channel::{self as wire, LaunchRecord, Mode, Tuple};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use std::{
    fs::File,
    io::Read,
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::fs::MetadataExt,
    sync::Arc,
};

pub(crate) trait RouteAuthority: Send {
    fn check(
        &mut self,
        scope: &RuntimeScopeStamp,
        request: RouteRequest<'_>,
        proof: &KnownOwnerProof,
        source: u64,
        flow: crate::attribution::broker::Flow,
    ) -> Result<Option<u64>, ServiceError>;
    fn release(&mut self, scope: &RuntimeScopeStamp, ticket: u64) -> Result<(), ServiceError>;
}
pub(crate) enum RouteRequest<'a> {
    Static(wire::Destination<'a>),
    Chain,
    Direct(wire::Destination<'a>),
    Dns(wire::Destination<'a>),
}

struct ChannelBudget {
    _memory: super::memory::ByteLease,
    dynamic: super::memory::ByteBudget,
}
impl ChannelBudget {
    fn new(
        capsule: &wire::OwnedCapsule,
        system: bool,
        digest: &[u8; 32],
    ) -> Result<Arc<Self>, ServiceError> {
        let decoded = wire::Capsule::decode(capsule.bytes(), digest).map_err(unavailable)?;
        let remaining = decoded.buffer_credit().map_err(unavailable)?;
        let bytes = 8usize * 1024 * 1024
            - usize::from(system) * (512 + 384) * 1024
            - 64 * 1024
            - capsule.bytes().len();
        Ok(Arc::new(Self {
            _memory: super::memory::config_budget()
                .reserve(bytes)
                .map_err(unavailable)?,
            dynamic: super::memory::ByteBudget::new(remaining),
        }))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Target {
    protocol: u8,
    family: u8,
    port: u16,
    length: u16,
    bytes: [u8; 253],
}
impl Target {
    fn copy(d: wire::Destination<'_>) -> Result<Self, ServiceError> {
        if d.bytes.len() > 253 {
            return Err(ServiceError::InvalidRequest);
        }
        let mut bytes = [0; 253];
        bytes[..d.bytes.len()].copy_from_slice(d.bytes);
        Ok(Self {
            protocol: d.protocol,
            family: d.family,
            port: d.port,
            length: d.bytes.len() as u16,
            bytes,
        })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Subject {
    pid: u32,
    start: u64,
    executable: (u64, u64),
    cookie: u64,
    epoch: u64,
    path: [u8; 32],
}
impl Subject {
    fn checked(
        proof: &KnownOwnerProof,
        scope: &RuntimeScopeStamp,
        source: u64,
        flow: crate::attribution::broker::Flow,
    ) -> Result<Self, ServiceError> {
        let (owner, path, _, _) = proof.checked(scope, source, flow).map_err(unavailable)?;
        if path.is_empty() || owner.cookie == 0 {
            return Err(ServiceError::Unavailable);
        }
        Ok(Self {
            pid: owner.pid,
            start: owner.start_time,
            executable: owner.executable,
            cookie: owner.cookie,
            epoch: owner.epoch,
            path: Sha256::digest(path.as_bytes()).into(),
        })
    }
}
trait Authority: Send {
    type Proof: Send;
    type Ingress: Send;
    fn mode(&self) -> Mode;
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn fence(&self) -> Result<(), ServiceError>;
    fn revoke(&self);
    fn ingress(
        &mut self,
        capsule: &wire::Capsule<'_>,
        message: &wire::Message<'_>,
        budget: &Arc<ChannelBudget>,
    ) -> Result<Self::Ingress, ServiceError>;
    fn check_ingress(&self, proof: &Self::Ingress) -> Result<(), ServiceError>;
    fn owner(
        &mut self,
        source: u64,
        tuple: Tuple,
        reference: OwnerReference,
    ) -> Result<Self::Proof, ServiceError>;
    fn subject(
        &self,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<Option<Subject>, ServiceError>;
    fn expiry(&self, proof: &Self::Proof) -> Option<Instant>;
    fn receipt(
        &self,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<wire::Receipt, ServiceError>;
    fn route(
        &mut self,
        request: RouteRequest<'_>,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<Option<u64>, ServiceError>;
    fn release(&mut self, ticket: u64) -> Result<(), ServiceError>;
    fn cancel_source(&mut self, source: u64) -> Result<(), ServiceError>;
}
struct SourceFlow<I> {
    tuple: Tuple,
    original: Target,
    subject: Option<Subject>,
    socket: I,
    root: Option<(u16, Target)>,
    request: u64,
}
struct Grant {
    source: u64,
    subject: u16,
    scope: u16,
    branch: u8,
    chain: u16,
    stream: u16,
    class: u8,
    effective: Target,
    resolver: u16,
    query: Box<str>,
    expires: Instant,
    request: u64,
    ticket: Option<u64>,
    next: Option<(u16, u8, u16)>,
    _query_credit: super::memory::ByteLease,
}
struct Issuer<A: Authority> {
    authority: A,
    capsule: Arc<wire::OwnedCapsule>,
    record: LaunchRecord,
    flows: BTreeMap<u64, Box<SourceFlow<A::Ingress>>>,
    grants: BTreeMap<u64, Box<Grant>>,
    frontier: BTreeMap<(u64, u16, u8, u16), u16>,
    retired: VecDeque<(u64, Instant)>,
    next_flow: u64,
    next_grant: u64,
    unknown: bool,
    budget: Arc<ChannelBudget>,
}
impl<A: Authority> Issuer<A> {
    fn new(
        authority: A,
        capsule: Arc<wire::OwnedCapsule>,
        record: LaunchRecord,
    ) -> Result<Self, ServiceError> {
        let decoded =
            wire::Capsule::decode(capsule.bytes(), &record.binding.digest).map_err(unavailable)?;
        if authority.mode() != record.mode
            || decoded.mode != record.mode
            || decoded.manifest != record.manifest
            || std::mem::size_of::<SourceFlow<A::Ingress>>() + 80 > 768
            || std::mem::size_of::<Grant>() + 80 > 576
        {
            return Err(ServiceError::Unsupported);
        }
        authority.fence()?;
        let budget = ChannelBudget::new(&capsule, record.mode.required(), &record.binding.digest)?;
        Ok(Self {
            authority,
            capsule,
            record,
            flows: BTreeMap::new(),
            grants: BTreeMap::new(),
            frontier: BTreeMap::new(),
            retired: VecDeque::new(),
            next_flow: 0,
            next_grant: 0,
            unknown: false,
            budget,
        })
    }
    fn capsule(&self) -> Result<wire::Capsule<'_>, ServiceError> {
        wire::Capsule::decode(self.capsule.bytes(), &self.record.binding.digest)
            .map_err(unavailable)
    }
    fn fence(&self) -> Result<(), ServiceError> {
        if self.unknown {
            return Err(ServiceError::Unavailable);
        }
        self.authority.fence()
    }
    fn id(counter: &mut u64) -> Result<u64, ServiceError> {
        *counter = counter
            .checked_add(1)
            .filter(|id| *id != u64::MAX)
            .ok_or(ServiceError::Unavailable)?;
        Ok(*counter)
    }
    fn open(
        &mut self,
        request: u64,
        message: &wire::Message<'_>,
    ) -> Result<(u64, A::Proof), ServiceError> {
        self.fence()?;
        let wire::Message::OpenIngress {
            tuple, original, ..
        } = message
        else {
            return Err(ServiceError::InvalidRequest);
        };
        let owned = Arc::clone(&self.capsule);
        let capsule = wire::Capsule::decode(owned.bytes(), &self.record.binding.digest)
            .map_err(unavailable)?;
        if self.flows.len() >= capsule.limits()[6] as usize
            || self.retired.len() >= capsule.limits()[7] as usize
        {
            return Err(ServiceError::Busy);
        }
        let socket = self.authority.ingress(&capsule, message, &self.budget)?;
        let source = Self::id(&mut self.next_flow)?;
        let proof = self.authority.owner(source, *tuple, OwnerReference::NONE)?;
        let subject = self.authority.subject(&proof, source, *tuple)?;
        if self.authority.mode().required() != subject.is_some() {
            return Err(ServiceError::Unavailable);
        }
        self.fence()?;
        self.flows.insert(
            source,
            Box::new(SourceFlow {
                tuple: *tuple,
                original: Target::copy(*original)?,
                subject,
                socket,
                root: None,
                request,
            }),
        );
        Ok((source, proof))
    }
    fn authorize(
        &mut self,
        request: u64,
        refresh: u64,
        a: &wire::Authorize<'_>,
    ) -> Result<(u64, A::Proof), ServiceError> {
        self.fence()?;
        if a.class != 1 {
            return Err(ServiceError::Unsupported);
        }
        let owned = Arc::clone(&self.capsule);
        let capsule = wire::Capsule::decode(owned.bytes(), &self.record.binding.digest)
            .map_err(unavailable)?;
        capsule
            .validate_request(&wire::Message::Authorize(*a))
            .map_err(unavailable)?;
        if refresh == 0
            && (self.grants.len() >= capsule.limits()[0] as usize
                || self.retired.len() >= capsule.limits()[7] as usize)
        {
            return Err(ServiceError::Busy);
        }
        let source = self
            .flows
            .get(&a.source_flow)
            .ok_or(ServiceError::Unavailable)?;
        if source.original != Target::copy(a.original)? {
            return Err(ServiceError::InvalidRequest);
        }
        self.authority.check_ingress(&source.socket)?;
        let tuple = source.tuple;
        let source_subject = source.subject;
        let effective = Target::copy(a.effective)?;
        if refresh != 0 {
            let old = self.grants.get(&refresh).ok_or(ServiceError::Unavailable)?;
            if self.authority.now() >= old.expires
                || old.source != a.source_flow
                || old.subject != a.subject
                || old.scope != a.scope
                || old.branch != a.branch
                || old.chain != a.chain
                || old.stream != a.transport
                || old.class != a.class
                || old.effective != effective
                || old.resolver != a.resolver
                || old.query.as_ref() != a.query
            {
                return Err(ServiceError::InvalidRequest);
            }
        }
        let dial = if a.class == 1 {
            Some(capsule.dial_scope(a.scope, a.branch).map_err(unavailable)?)
        } else {
            None
        };
        if let Some(dial) = &dial {
            if let Some((root, target)) = source.root {
                if a.scope == root {
                    if target != effective {
                        return Err(ServiceError::InvalidRequest);
                    }
                } else if !self.frontier.iter().any(|((id, s, b, e), n)| {
                    *id == a.source_flow
                        && *s == a.scope
                        && *b == a.branch
                        && *n > 0
                        && capsule.endpoint(*e).is_ok_and(|d| d == a.effective)
                }) {
                    return Err(ServiceError::InvalidRequest);
                }
            } else if dial.input != source.original.protocol {
                return Err(ServiceError::InvalidRequest);
            }
        }
        let reference = OwnerReference {
            kind: a.receipt.kind,
            id: a.receipt.id,
        };
        let mut proof = self.authority.owner(a.source_flow, tuple, reference)?;
        if self.authority.subject(&proof, a.source_flow, tuple)? != source_subject {
            return Err(ServiceError::Unavailable);
        }
        let route = if let Some(dial) = &dial {
            match dial.action {
                1 => RouteRequest::Static(dial.endpoint.ok_or(ServiceError::InvalidRequest)?),
                2 => RouteRequest::Chain,
                3 => RouteRequest::Direct(a.effective),
                _ => return Err(ServiceError::InvalidRequest),
            }
        } else {
            RouteRequest::Dns(capsule.resolver_peer(a.resolver).map_err(unavailable)?)
        };
        let grant = if refresh == 0 {
            Self::id(&mut self.next_grant)?
        } else {
            refresh
        };
        let query_credit = self
            .budget
            .dynamic
            .reserve((a.query.len() + 15) & !15)
            .map_err(unavailable)?;
        let old_ticket = if refresh == 0 {
            None
        } else {
            self.grants.get(&grant).and_then(|g| g.ticket)
        };
        let ticket = self.authority.route(route, &proof, a.source_flow, tuple)?;
        let result = (|| {
            if self
                .authority
                .expiry(&proof)
                .is_some_and(|until| until <= self.authority.now())
            {
                proof = self
                    .authority
                    .owner(a.source_flow, tuple, OwnerReference::NONE)?;
            }
            if self.authority.subject(&proof, a.source_flow, tuple)? != source_subject {
                return Err(ServiceError::Unavailable);
            }
            let now = self.authority.now();
            let expires = self
                .authority
                .expiry(&proof)
                .unwrap_or(now + Duration::from_secs(1))
                .min(now + Duration::from_secs(1));
            let next = dial
                .as_ref()
                .and_then(|d| d.next.map(|(s, m)| (s, m, d.endpoint_index)));
            self.fence()?;
            let entry = Grant {
                source: a.source_flow,
                subject: a.subject,
                scope: a.scope,
                branch: a.branch,
                chain: a.chain,
                stream: a.transport,
                class: a.class,
                effective,
                resolver: a.resolver,
                query: a.query.into(),
                expires,
                request,
                ticket,
                next,
                _query_credit: query_credit,
            };
            if refresh == 0 {
                if let Some((scope, mask, endpoint)) = next {
                    for branch in 0..2 {
                        if mask & (1 << branch) != 0 {
                            let count = self
                                .frontier
                                .entry((a.source_flow, scope, branch, endpoint))
                                .or_default();
                            *count = count.checked_add(1).ok_or(ServiceError::Busy)?;
                        }
                    }
                }
            }
            self.grants.insert(grant, Box::new(entry));
            if a.class == 1 {
                self.flows
                    .get_mut(&a.source_flow)
                    .ok_or(ServiceError::Unavailable)?
                    .root
                    .get_or_insert((a.scope, effective));
            }
            Ok((grant, proof))
        })();
        match result {
            Ok(value) => {
                if let Some(old) = old_ticket {
                    if self.authority.release(old).is_err() {
                        self.unknown = true;
                        self.authority.revoke();
                        return Err(ServiceError::Unavailable);
                    }
                }
                Ok(value)
            }
            Err(error) => {
                if let Some(ticket) = ticket {
                    if self.authority.release(ticket).is_err() {
                        self.unknown = true;
                        self.authority.revoke();
                    }
                }
                Err(error)
            }
        }
    }
    fn cancel_grant(&mut self, id: u64) -> Result<(), ServiceError> {
        let Some(grant) = self.grants.remove(&id) else {
            return Ok(());
        };
        if let Some(ticket) = grant.ticket {
            if self.authority.release(ticket).is_err() {
                self.unknown = true;
                self.authority.revoke();
                self.grants.insert(id, grant);
                return Err(ServiceError::Unavailable);
            }
        }
        if let Some((scope, mask, endpoint)) = grant.next {
            for branch in 0..2 {
                if mask & (1 << branch) != 0 {
                    let key = (grant.source, scope, branch, endpoint);
                    if let Some(count) = self.frontier.get_mut(&key) {
                        *count -= 1;
                        if *count == 0 {
                            self.frontier.remove(&key);
                        }
                    }
                }
            }
        }
        // Уже обработанный request не может прийти повторно: sequence строгий,
        // grant IDs не переиспользуются. Tombstone нужен только queued request;
        // иначе cancel одного flow с >256 grants отозвал бы соседние flow.
        Ok(())
    }
    fn cancel_matching(&mut self, predicate: impl Fn(&Grant) -> bool) -> Result<(), ServiceError> {
        let mut ids = [0; 4096];
        let mut count = 0;
        for (id, grant) in &self.grants {
            if predicate(grant) {
                *ids.get_mut(count).ok_or(ServiceError::Busy)? = *id;
                count += 1;
            }
        }
        for id in &ids[..count] {
            self.cancel_grant(*id)?;
        }
        Ok(())
    }
    fn cancel_flow(&mut self, id: u64) -> Result<(), ServiceError> {
        if id > self.next_flow {
            return Err(ServiceError::InvalidRequest);
        }
        self.cancel_matching(|grant| grant.source == id)?;
        self.flows.remove(&id);
        self.authority.cancel_source(id)
    }
    fn cancel_request(&mut self, request: u64) -> Result<(), ServiceError> {
        if let Some((id, _)) = self.flows.iter().find(|(_, f)| f.request == request) {
            let id = *id;
            return self.cancel_flow(id);
        }
        if let Some((id, _)) = self.grants.iter().find(|(_, g)| g.request == request) {
            let id = *id;
            return self.cancel_grant(id);
        }
        if !self.retired.iter().any(|(id, _)| *id == request) {
            if self.retired.len() >= self.capsule()?.limits()[7] as usize {
                return Err(ServiceError::Busy);
            }
            self.retired
                .push_back((request, self.authority.now() + Duration::from_secs(2)));
        }
        Ok(())
    }
}
struct SocketHold {
    proof: SocketProof,
    _credit: super::memory::ByteLease,
}
struct SystemAuthority {
    scope: RuntimeScopeStamp,
    owner: OwnerEndpoint,
    peer: Arc<Peer>,
    routes: Box<dyn RouteAuthority>,
}
impl Authority for SystemAuthority {
    type Proof = KnownOwnerProof;
    type Ingress = Option<Box<SocketHold>>;
    fn mode(&self) -> Mode {
        Mode::System
    }
    fn fence(&self) -> Result<(), ServiceError> {
        self.scope.validate().map_err(unavailable)?;
        self.peer.validate()
    }
    fn revoke(&self) {
        self.scope.revoke();
    }
    fn ingress(
        &mut self,
        capsule: &wire::Capsule<'_>,
        message: &wire::Message<'_>,
        budget: &Arc<ChannelBudget>,
    ) -> Result<Self::Ingress, ServiceError> {
        let wire::Message::OpenIngress {
            tuple, provenance, ..
        } = message
        else {
            return Err(ServiceError::InvalidRequest);
        };
        if *provenance == 1 {
            capsule.validate_request(message).map_err(unavailable)?;
            return Ok(None);
        }
        let credit = budget
            .dynamic
            .reserve(std::mem::size_of::<SocketHold>() + 32)
            .map_err(unavailable)?;
        let proof = self.peer.socket(*tuple, *provenance)?;
        if *provenance == 3 {
            capsule
                .validate_associated_request(message, &proof)
                .map_err(unavailable)?;
        } else {
            capsule.validate_request(message).map_err(unavailable)?;
        }
        Ok(Some(Box::new(SocketHold {
            proof,
            _credit: credit,
        })))
    }
    fn check_ingress(&self, proof: &Self::Ingress) -> Result<(), ServiceError> {
        if let Some(proof) = proof {
            proof.proof.validate()?;
        }
        self.fence()
    }
    fn owner(
        &mut self,
        source: u64,
        tuple: Tuple,
        reference: OwnerReference,
    ) -> Result<Self::Proof, ServiceError> {
        self.owner
            .lookup(
                source,
                tuple.owner_flow().map_err(unavailable)?,
                reference,
                Instant::now() + Duration::from_millis(20),
            )
            .map_err(unavailable)
    }
    fn subject(
        &self,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<Option<Subject>, ServiceError> {
        let subject = Subject::checked(
            proof,
            &self.scope,
            source,
            tuple.owner_flow().map_err(unavailable)?,
        )?;
        if subject.pid == self.peer.pid {
            return Err(ServiceError::Unavailable);
        }
        Ok(Some(subject))
    }
    fn expiry(&self, proof: &Self::Proof) -> Option<Instant> {
        Some(proof.original_expiry())
    }
    fn receipt(
        &self,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<wire::Receipt, ServiceError> {
        let (_, _, _, reference) = proof
            .checked(
                &self.scope,
                source,
                tuple.owner_flow().map_err(unavailable)?,
            )
            .map_err(unavailable)?;
        Ok(wire::Receipt {
            kind: reference.kind,
            id: reference.id,
        })
    }
    fn route(
        &mut self,
        request: RouteRequest<'_>,
        proof: &Self::Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<Option<u64>, ServiceError> {
        self.routes.check(
            &self.scope,
            request,
            proof,
            source,
            tuple.owner_flow().map_err(unavailable)?,
        )
    }
    fn release(&mut self, ticket: u64) -> Result<(), ServiceError> {
        self.routes.release(&self.scope, ticket)
    }
    fn cancel_source(&mut self, source: u64) -> Result<(), ServiceError> {
        self.owner.cancel_source(source).map_err(unavailable)
    }
}
struct LocalAuthority {
    peer: Arc<Peer>,
    revoked: Arc<AtomicBool>,
    prepared: Arc<crate::host::local_profile_channel::Prepared>,
}
impl Authority for LocalAuthority {
    type Proof = ();
    type Ingress = Option<Box<SocketHold>>;
    fn mode(&self) -> Mode {
        Mode::Local
    }
    fn fence(&self) -> Result<(), ServiceError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(ServiceError::Unavailable);
        }
        let (_keep, cancel) = crate::Cancellation::new();
        self.prepared.revalidate(&cancel).map_err(unavailable)?;
        self.peer.validate()
    }
    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }
    fn ingress(
        &mut self,
        capsule: &wire::Capsule<'_>,
        message: &wire::Message<'_>,
        budget: &Arc<ChannelBudget>,
    ) -> Result<Self::Ingress, ServiceError> {
        let wire::Message::OpenIngress {
            tuple, provenance, ..
        } = message
        else {
            return Err(ServiceError::InvalidRequest);
        };
        if *provenance == 1 {
            return Err(ServiceError::Unsupported);
        }
        let credit = budget
            .dynamic
            .reserve(std::mem::size_of::<SocketHold>() + 32)
            .map_err(unavailable)?;
        let proof = self.peer.socket(*tuple, *provenance)?;
        if *provenance == 3 {
            capsule
                .validate_associated_request(message, &proof)
                .map_err(unavailable)?;
        } else {
            capsule.validate_request(message).map_err(unavailable)?;
        }
        Ok(Some(Box::new(SocketHold {
            proof,
            _credit: credit,
        })))
    }
    fn check_ingress(&self, proof: &Self::Ingress) -> Result<(), ServiceError> {
        proof
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .proof
            .validate()?;
        self.fence()
    }
    fn owner(&mut self, _: u64, _: Tuple, reference: OwnerReference) -> Result<(), ServiceError> {
        if reference != OwnerReference::NONE {
            return Err(ServiceError::InvalidRequest);
        }
        self.fence()
    }
    fn subject(&self, _: &(), _: u64, _: Tuple) -> Result<Option<Subject>, ServiceError> {
        self.fence()?;
        Ok(None)
    }
    fn expiry(&self, _: &()) -> Option<Instant> {
        None
    }
    fn receipt(&self, _: &(), _: u64, _: Tuple) -> Result<wire::Receipt, ServiceError> {
        Ok(wire::Receipt {
            kind: wire::ReceiptKind::None,
            id: 0,
        })
    }
    fn route(
        &mut self,
        _: RouteRequest<'_>,
        _: &(),
        _: u64,
        _: Tuple,
    ) -> Result<Option<u64>, ServiceError> {
        self.fence()?;
        Ok(None)
    }
    fn release(&mut self, _: u64) -> Result<(), ServiceError> {
        Err(ServiceError::InvalidRequest)
    }
    fn cancel_source(&mut self, _: u64) -> Result<(), ServiceError> {
        Ok(())
    }
}

pub(crate) struct ProfileRuntime {
    stop: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    task: Option<std::thread::JoinHandle<Box<dyn Send>>>,
    known_closed: bool,
}
impl ProfileRuntime {
    pub(crate) fn start_local(
        record: LaunchRecord,
        peer: Arc<Peer>,
        prepared: Arc<crate::host::local_profile_channel::Prepared>,
        channel: OwnedFd,
    ) -> Result<Self, ServiceError> {
        if record.mode != Mode::Local {
            return Err(ServiceError::Unsupported);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_ready = Arc::clone(&ready);
        let authority = LocalAuthority {
            peer: Arc::clone(&peer),
            revoked: Arc::clone(&stop),
            prepared: Arc::clone(&prepared),
        };
        let issuer = Issuer::new(authority, Arc::clone(&prepared.capsule), record)?;
        let task = std::thread::Builder::new()
            .name("yonik-profile-local".into())
            .spawn(move || {
                let mut resources = (issuer, channel, prepared);
                let _result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    hello(&resources.1, record, peer.pid, peer.uid, &thread_stop)?;
                    run_issuer(
                        &mut resources.0,
                        &resources.1,
                        peer.pid,
                        peer.uid,
                        &thread_stop,
                        &thread_ready,
                    )
                }));
                thread_stop.store(true, Ordering::Release);
                thread_ready.store(false, Ordering::Release);
                let _shutdown = rustix::net::shutdown(&resources.1, rustix::net::Shutdown::Both);
                Box::new(resources) as Box<dyn Send>
            })
            .map_err(unavailable)?;
        Ok(Self {
            stop,
            ready,
            task: Some(task),
            known_closed: false,
        })
    }
    pub(crate) fn start_system(
        scope: RuntimeScopeStamp,
        owner: OwnerEndpoint,
        payload: Arc<crate::worker::WorkerPayload>,
        uid: u32,
        routes: Box<dyn RouteAuthority>,
    ) -> Result<(Self, OwnedFd), ServiceError> {
        let profile = payload.full_profile().ok_or(ServiceError::Unsupported)?;
        let capsule = Arc::clone(profile.capsule());
        let record = scope.profile_launch_record(&capsule).map_err(unavailable)?;
        let (host, worker) = channel_pair()?;
        let stop = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_ready = Arc::clone(&ready);
        let task = std::thread::Builder::new()
            .name("yonik-profile-system".into())
            .spawn(move || {
                let mut resources = SystemResources {
                    scope,
                    owner: Some(owner),
                    payload,
                    channel: host,
                    routes: Some(routes),
                    issuer: None,
                };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    hello(
                        &resources.channel,
                        record,
                        record.child_pid,
                        uid,
                        &thread_stop,
                    )?;
                    let peer = Peer::system(record, uid, resources.payload.image_hash())?;
                    let authority = SystemAuthority {
                        scope: resources.scope.fork_lookup(),
                        owner: resources.owner.take().ok_or(ServiceError::Unavailable)?,
                        peer,
                        routes: resources.routes.take().ok_or(ServiceError::Unavailable)?,
                    };
                    resources.issuer = Some(Issuer::new(authority, capsule, record)?);
                    run_issuer(
                        resources.issuer.as_mut().ok_or(ServiceError::Unavailable)?,
                        &resources.channel,
                        record.child_pid,
                        uid,
                        &thread_stop,
                        &thread_ready,
                    )
                }));
                if result.is_err() {
                    resources.scope.revoke();
                }
                resources.scope.revoke();
                let _shutdown =
                    rustix::net::shutdown(&resources.channel, rustix::net::Shutdown::Both);
                Box::new(resources) as Box<dyn Send>
            })
            .map_err(unavailable)?;
        Ok((
            Self {
                stop,
                ready,
                task: Some(task),
                known_closed: false,
            },
            worker,
        ))
    }
    pub(crate) fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire) && self.task.as_ref().is_some_and(|t| !t.is_finished())
    }
    pub(crate) fn revoke(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub(crate) fn confirmed_closed(&mut self) {
        self.known_closed = true;
        self.revoke();
    }
}
impl Drop for ProfileRuntime {
    fn drop(&mut self) {
        self.revoke();
        if let Some(task) = self.task.take() {
            match task.join() {
                Ok(resources) if self.known_closed => drop(resources),
                Ok(resources) => std::mem::forget(resources),
                Err(_) => {
                    self.known_closed = false;
                }
            }
        }
    }
}
struct SystemResources {
    scope: RuntimeScopeStamp,
    owner: Option<OwnerEndpoint>,
    payload: Arc<crate::worker::WorkerPayload>,
    channel: OwnedFd,
    routes: Option<Box<dyn RouteAuthority>>,
    issuer: Option<Issuer<SystemAuthority>>,
}
pub(crate) fn channel_pair() -> Result<(OwnedFd, OwnedFd), ServiceError> {
    use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
    let (a, b) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(unavailable)?;
    for fd in [&a, &b] {
        net::sockopt::set_socket_passcred(fd, true).map_err(unavailable)?;
    }
    Ok((a, b))
}
fn receive(
    socket: &OwnedFd,
    pid: u32,
    uid: u32,
    out: &mut [u8; 1153],
) -> Result<Option<usize>, ServiceError> {
    use rustix::net::{self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};
    let mut control =
        [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(16), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut control);
    let msg = match net::recvmsg(
        socket,
        &mut [std::io::IoSliceMut::new(out)],
        &mut ancillary,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    ) {
        Ok(msg) => msg,
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => return Ok(None),
        Err(_) => return Err(ServiceError::Unavailable),
    };
    let mut credentials = None;
    let mut bad = false;
    for part in ancillary.drain() {
        match part {
            RecvAncillaryMessage::ScmCredentials(c) if credentials.is_none() => {
                credentials = Some(c)
            }
            RecvAncillaryMessage::ScmRights(rights) => {
                bad = true;
                for fd in rights {
                    drop(fd);
                }
            }
            _ => bad = true,
        }
    }
    let c = credentials.ok_or(ServiceError::Unavailable)?;
    if bad
        || msg.bytes == 0
        || msg.bytes > 1152
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || c.pid.as_raw_pid() as u32 != pid
        || c.uid.as_raw() != uid
    {
        return Err(ServiceError::Unavailable);
    }
    Ok(Some(msg.bytes))
}
trait Channel {
    fn read(&self, pid: u32, uid: u32, out: &mut [u8; 1153])
    -> Result<Option<usize>, ServiceError>;
    fn write(&self, bytes: &[u8]) -> Result<bool, ServiceError>;
    fn pause(&self) {
        std::thread::sleep(Duration::from_millis(1));
    }
}
impl Channel for OwnedFd {
    fn read(
        &self,
        pid: u32,
        uid: u32,
        out: &mut [u8; 1153],
    ) -> Result<Option<usize>, ServiceError> {
        receive(self, pid, uid, out)
    }
    fn write(&self, bytes: &[u8]) -> Result<bool, ServiceError> {
        match rustix::net::send(
            self,
            bytes,
            rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
        ) {
            Ok(sent) if sent == bytes.len() => Ok(true),
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(false),
            _ => Err(ServiceError::Unavailable),
        }
    }
}
fn hello(
    socket: &OwnedFd,
    record: LaunchRecord,
    pid: u32,
    uid: u32,
    stop: &AtomicBool,
) -> Result<(), ServiceError> {
    let until = Instant::now() + Duration::from_secs(1);
    let mut bytes = [0; 1153];
    loop {
        if stop.load(Ordering::Acquire) || Instant::now() >= until {
            return Err(ServiceError::Unavailable);
        }
        if let Some(n) = receive(socket, pid, uid, &mut bytes)? {
            let frame = wire::Frame::decode(&bytes[..n], record.binding, record.mode, false)
                .map_err(unavailable)?;
            if frame.header.sequence != 1
                || !matches!(frame.message,wire::Message::Hello{nonce,mode} if nonce==record.nonce && mode==record.mode)
            {
                return Err(ServiceError::Unavailable);
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[allow(clippy::too_many_arguments)] // Header routing и исходный deadline остаются явными.
fn send_message<A: Authority>(
    issuer: &Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    sequence: u64,
    reply_to: u64,
    object: u64,
    message: &wire::Message<'_>,
    until: Instant,
) -> Result<(), ServiceError> {
    let mut bytes = [0; 65536];
    let kind = match message {
        wire::Message::Admit(_) => wire::Kind::Admit,
        wire::Message::IngressReply { .. } => wire::Kind::IngressReply,
        wire::Message::Grant { .. } => wire::Kind::Grant,
        wire::Message::CloseAck { .. } => wire::Kind::CloseAck,
        wire::Message::Deny { .. } => wire::Kind::Deny,
        _ => return Err(ServiceError::InvalidRequest),
    };
    loop {
        issuer.fence()?;
        if stop.load(Ordering::Acquire) || issuer.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        let remaining = until.saturating_duration_since(issuer.authority.now());
        let refreshed = if let wire::Message::Grant {
            status,
            class,
            required,
            grant,
            flow,
            revision,
            receipt,
            ..
        } = message
        {
            Some(wire::Message::Grant {
                status: *status,
                class: *class,
                required: *required,
                grant: *grant,
                flow: *flow,
                lease: remaining.as_millis().min(1000) as u32,
                revision: *revision,
                fresh: if *required {
                    remaining.as_nanos().min(20_000_000) as u64
                } else {
                    0
                },
                receipt: *receipt,
            })
        } else {
            None
        };
        let n = wire::Frame::encode(
            wire::Header {
                kind,
                sequence,
                reply_to,
                binding: issuer.record.binding,
                object_id: object,
            },
            refreshed.as_ref().unwrap_or(message),
            &mut bytes,
        )
        .map_err(unavailable)?;
        if socket.write(&bytes[..n])? {
            return Ok(());
        }
        socket.pause();
    }
}
struct Queued {
    bytes: [u8; 1153],
    length: usize,
    sequence: u64,
}
#[derive(Clone, Copy)]
struct CancelReply {
    request: u64,
    target: u8,
    id: u64,
    status: wire::CloseStatus,
}
#[allow(clippy::too_many_arguments)] // Единственный reader сохраняет ordering и pending holes.
fn drain_before_publication<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    pid: u32,
    uid: u32,
    incoming: &mut wire::Sequence,
    queued: &mut VecDeque<Queued>,
    acks: &mut VecDeque<CancelReply>,
) -> Result<(), ServiceError> {
    for _ in 0..64 {
        if queued.len() + acks.len() >= 64 {
            return Err(ServiceError::Busy);
        }
        let mut bytes = [0; 1153];
        let Some(length) = socket.read(pid, uid, &mut bytes)? else {
            return Ok(());
        };
        let frame = wire::Frame::decode(
            &bytes[..length],
            issuer.record.binding,
            issuer.record.mode,
            false,
        )
        .map_err(unavailable)?;
        incoming
            .accept(frame.header.sequence)
            .map_err(unavailable)?;
        if let wire::Message::Cancel { target, id, .. } = frame.message {
            let result = cancel(issuer, frame.header.sequence, target, id);
            acks.push_back(CancelReply {
                request: frame.header.sequence,
                target,
                id,
                status: if result.is_ok() {
                    wire::CloseStatus::KnownClosed
                } else {
                    wire::CloseStatus::Unknown
                },
            });
            if issuer.unknown {
                return Err(ServiceError::Unavailable);
            }
        } else {
            queued.push_back(Queued {
                bytes,
                length,
                sequence: frame.header.sequence,
            });
        }
    }
    Err(ServiceError::Busy)
}
fn cancel<A: Authority>(
    issuer: &mut Issuer<A>,
    sequence: u64,
    target: u8,
    id: u64,
) -> Result<(), ServiceError> {
    match target {
        1 if id < sequence => issuer.cancel_request(id),
        2 => issuer.cancel_flow(id),
        3 if id <= issuer.next_grant => issuer.cancel_grant(id),
        4 => {
            issuer.authority.revoke();
            Err(ServiceError::Unavailable)
        }
        _ => Err(ServiceError::InvalidRequest),
    }
}
fn run_issuer<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    pid: u32,
    uid: u32,
    stop: &AtomicBool,
    ready: &AtomicBool,
) -> Result<(), ServiceError> {
    let mut incoming = wire::Sequence::new();
    incoming.accept(1).map_err(unavailable)?;
    let mut outgoing = 1u64;
    let mut admission = issuer.capsule()?.admission_id;
    let manifest = issuer.record.manifest;
    let lease = Duration::from_millis(u64::from(issuer.capsule()?.lease_ms));
    let mut expires = issuer.authority.now() + lease.saturating_sub(Duration::from_secs(1));
    let mut awaiting = Some((
        outgoing,
        admission,
        issuer.authority.now() + Duration::from_secs(1),
        expires,
    ));
    send_message(
        issuer,
        socket,
        stop,
        outgoing,
        1,
        0,
        &wire::Message::Admit(issuer.capsule.bytes()),
        awaiting.ok_or(ServiceError::Unavailable)?.2,
    )?;
    let mut bytes = [0; 1153];
    let mut queued = VecDeque::<Queued>::with_capacity(64);
    let mut acks = VecDeque::<CancelReply>::with_capacity(64);
    loop {
        issuer.fence()?;
        let now = issuer.authority.now();
        while issuer.retired.front().is_some_and(|(request, until)| {
            now >= *until
                && queued
                    .front()
                    .is_none_or(|pending| *request < pending.sequence)
        }) {
            issuer.retired.pop_front();
        }
        if stop.load(Ordering::Acquire) || now >= expires || awaiting.is_some_and(|a| now >= a.2) {
            return Err(ServiceError::Unavailable);
        }
        issuer.cancel_matching(|grant| now >= grant.expires)?;
        let (n, sequenced) = if let Some(pending) = queued.pop_front() {
            bytes = pending.bytes;
            (pending.length, true)
        } else {
            let Some(n) = socket.read(pid, uid, &mut bytes)? else {
                socket.pause();
                continue;
            };
            (n, false)
        };
        let frame = wire::Frame::decode(
            &bytes[..n],
            issuer.record.binding,
            issuer.record.mode,
            false,
        )
        .map_err(unavailable)?;
        if !sequenced {
            incoming
                .accept(frame.header.sequence)
                .map_err(unavailable)?;
        }
        if let wire::Message::AdmitAck {
            manifest: hash,
            admission: id,
            status,
        } = frame.message
        {
            let Some((sent, expected, _, next_expiry)) = awaiting else {
                return Err(ServiceError::InvalidRequest);
            };
            if frame.header.reply_to != sent
                || hash != manifest
                || id != expected
                || status != wire::Status::Allow
            {
                return Err(ServiceError::Unavailable);
            }
            expires = next_expiry;
            awaiting = None;
            ready.store(true, Ordering::Release);
            continue;
        }
        if awaiting.is_some() {
            return Err(ServiceError::Unavailable);
        }
        outgoing = outgoing
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(ServiceError::Unavailable)?;
        let reply = frame.header.sequence;
        if issuer.retired.iter().any(|(id, _)| *id == reply) {
            send_message(
                issuer,
                socket,
                stop,
                outgoing,
                reply,
                0,
                &wire::Message::Deny {
                    status: wire::Status::Deny,
                    reason: 4,
                },
                expires.min(now + Duration::from_secs(1)),
            )?;
            continue;
        }
        match &frame.message {
            wire::Message::Renew {
                admission: id,
                manifest: hash,
            } => {
                if *id != admission || *hash != manifest {
                    return Err(ServiceError::InvalidRequest);
                }
                admission = admission.checked_add(1).ok_or(ServiceError::Unavailable)?;
                let mut body = issuer.capsule.bytes().to_vec();
                body[32..64].copy_from_slice(&manifest);
                body[64..72].copy_from_slice(&admission.to_be_bytes());
                let until = Instant::now() + Duration::from_secs(1);
                let next_expiry = Instant::now() + lease.saturating_sub(Duration::from_secs(1));
                send_message(
                    issuer,
                    socket,
                    stop,
                    outgoing,
                    reply,
                    0,
                    &wire::Message::Admit(&body),
                    until,
                )?;
                awaiting = Some((outgoing, admission, until, next_expiry));
            }
            wire::Message::OpenIngress { .. } => match issuer.open(reply, &frame.message) {
                Ok((flow, proof)) => {
                    drain_before_publication(
                        issuer,
                        socket,
                        pid,
                        uid,
                        &mut incoming,
                        &mut queued,
                        &mut acks,
                    )?;
                    if !issuer.flows.contains_key(&flow) {
                        send_message(
                            issuer,
                            socket,
                            stop,
                            outgoing,
                            reply,
                            0,
                            &wire::Message::Deny {
                                status: wire::Status::Deny,
                                reason: 4,
                            },
                            expires.min(now + Duration::from_secs(1)),
                        )?;
                    } else {
                        let source = issuer.flows.get(&flow).ok_or(ServiceError::Unavailable)?;
                        issuer.authority.subject(&proof, flow, source.tuple)?;
                        let until = issuer
                            .authority
                            .expiry(&proof)
                            .unwrap_or(now + Duration::from_secs(1))
                            .min(expires);
                        send_message(
                            issuer,
                            socket,
                            stop,
                            outgoing,
                            reply,
                            0,
                            &wire::Message::IngressReply {
                                status: wire::Status::Allow,
                                required: issuer.record.mode.required(),
                                flow,
                                revision: issuer.capsule()?.policy_revision,
                            },
                            until,
                        )?;
                    }
                }
                Err(_) => send_message(
                    issuer,
                    socket,
                    stop,
                    outgoing,
                    reply,
                    0,
                    &wire::Message::Deny {
                        status: wire::Status::Unknown,
                        reason: 1,
                    },
                    expires.min(now + Duration::from_secs(1)),
                )?,
            },
            wire::Message::Authorize(a) => {
                match issuer.authorize(reply, frame.header.object_id, a) {
                    Ok((id, proof)) => {
                        drain_before_publication(
                            issuer,
                            socket,
                            pid,
                            uid,
                            &mut incoming,
                            &mut queued,
                            &mut acks,
                        )?;
                        if !issuer.grants.contains_key(&id) {
                            send_message(
                                issuer,
                                socket,
                                stop,
                                outgoing,
                                reply,
                                0,
                                &wire::Message::Deny {
                                    status: wire::Status::Deny,
                                    reason: 4,
                                },
                                expires.min(now + Duration::from_secs(1)),
                            )?;
                        } else {
                            let g = issuer.grants.get(&id).ok_or(ServiceError::Unavailable)?;
                            let flow = issuer
                                .flows
                                .get(&g.source)
                                .ok_or(ServiceError::Unavailable)?;
                            let receipt = issuer.authority.receipt(&proof, g.source, flow.tuple)?;
                            let fresh = issuer.authority.expiry(&proof).map_or(0, |until| {
                                until
                                    .saturating_duration_since(Instant::now())
                                    .as_nanos()
                                    .min(20_000_000) as u64
                            });
                            let until = g.expires.min(expires);
                            let duration = until.saturating_duration_since(Instant::now());
                            send_message(
                                issuer,
                                socket,
                                stop,
                                outgoing,
                                reply,
                                id,
                                &wire::Message::Grant {
                                    status: wire::Status::Allow,
                                    class: g.class,
                                    required: issuer.record.mode.required(),
                                    grant: id,
                                    flow: g.source,
                                    lease: duration.as_millis().min(1000) as u32,
                                    revision: issuer.capsule()?.policy_revision,
                                    fresh,
                                    receipt,
                                },
                                until,
                            )?;
                        }
                    }
                    Err(_) => send_message(
                        issuer,
                        socket,
                        stop,
                        outgoing,
                        reply,
                        0,
                        &wire::Message::Deny {
                            status: wire::Status::Unknown,
                            reason: 2,
                        },
                        expires.min(now + Duration::from_secs(1)),
                    )?,
                }
            }
            wire::Message::Cancel { target, id, .. } => {
                let result = cancel(issuer, reply, *target, *id);
                let status = if result.is_ok() {
                    wire::CloseStatus::KnownClosed
                } else {
                    wire::CloseStatus::Unknown
                };
                send_message(
                    issuer,
                    socket,
                    stop,
                    outgoing,
                    reply,
                    0,
                    &wire::Message::CloseAck {
                        target: *target,
                        status,
                        id: *id,
                    },
                    expires.min(now + Duration::from_secs(1)),
                )?;
            }
            wire::Message::Probe { .. } => {
                issuer
                    .capsule()?
                    .validate_request(&frame.message)
                    .map_err(unavailable)?;
                send_message(
                    issuer,
                    socket,
                    stop,
                    outgoing,
                    reply,
                    0,
                    &wire::Message::Deny {
                        status: wire::Status::Deny,
                        reason: 3,
                    },
                    expires.min(now + Duration::from_secs(1)),
                )?;
            }
            _ => return Err(ServiceError::InvalidRequest),
        }
        while let Some(ack) = acks.pop_front() {
            outgoing = outgoing.checked_add(1).ok_or(ServiceError::Unavailable)?;
            send_message(
                issuer,
                socket,
                stop,
                outgoing,
                ack.request,
                0,
                &wire::Message::CloseAck {
                    target: ack.target,
                    status: ack.status,
                    id: ack.id,
                },
                expires.min(Instant::now() + Duration::from_secs(1)),
            )?;
        }
    }
}

/// Gate не имеет caller constructor или UI bool. Go a004e92 ещё не содержит
/// physical pools/DNS/service enforcement; launch ACK этого не доказывает.
pub(crate) struct ConsumerReady {
    _private: (),
}
pub(crate) fn require_consumer() -> Result<ConsumerReady, ServiceError> {
    Err(ServiceError::Unsupported)
}

fn unavailable<T>(_: T) -> ServiceError {
    ServiceError::Unavailable
}
fn proc_text(path: String) -> Result<String, ServiceError> {
    let mut text = String::new();
    File::open(path)
        .map_err(unavailable)?
        .take(16385)
        .read_to_string(&mut text)
        .map_err(unavailable)?;
    if text.len() > 16384 {
        return Err(ServiceError::Unavailable);
    }
    Ok(text)
}
pub(crate) fn process_start(pid: u32) -> Result<u64, ServiceError> {
    proc_text(format!("/proc/{pid}/stat"))?
        .rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .and_then(|s| s.parse().ok())
        .filter(|n| *n != 0)
        .ok_or(ServiceError::Unavailable)
}
fn process_parent(pid: u32) -> Result<u32, ServiceError> {
    proc_text(format!("/proc/{pid}/stat"))?
        .rsplit_once(')')
        .and_then(|(_, s)| s.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(ServiceError::Unavailable)
}
pub(crate) struct Peer {
    pid: u32,
    start: u64,
    uid: u32,
    pidfd: OwnedFd,
    image: File,
    identity: (u64, u64),
    _memory: super::memory::ByteLease,
}
impl Peer {
    pub(crate) fn local(
        record: LaunchRecord,
        child: &tokio::process::Child,
        binary: &crate::BinarySnapshot,
    ) -> Result<Arc<Self>, ServiceError> {
        let uid = rustix::process::geteuid().as_raw();
        let pid = child.id().ok_or(ServiceError::Unavailable)?;
        if record.mode != Mode::Local
            || uid == 0
            || uid != rustix::process::getuid().as_raw()
            || record.owner_pid != std::process::id()
            || record.owner_start != process_start(record.owner_pid)?
            || process_parent(pid)? != record.owner_pid
        {
            return Err(ServiceError::Unsupported);
        }
        Self::capture(pid, process_start(pid)?, uid, binary.trusted_hash())
    }
    fn system(record: LaunchRecord, uid: u32, image: [u8; 32]) -> Result<Arc<Self>, ServiceError> {
        if record.mode != Mode::System || uid == 0 {
            return Err(ServiceError::Unsupported);
        }
        Self::capture(record.child_pid, record.child_start, uid, image)
    }
    fn capture(
        pid: u32,
        start: u64,
        uid: u32,
        expected: [u8; 32],
    ) -> Result<Arc<Self>, ServiceError> {
        let memory = super::memory::config_budget()
            .reserve(64 * 1024)
            .map_err(unavailable)?;
        let id = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or(ServiceError::Unavailable)?;
        let pidfd = rustix::process::pidfd_open(id, rustix::process::PidfdFlags::NONBLOCK)
            .map_err(unavailable)?;
        let image = File::open(format!("/proc/{pid}/exe")).map_err(unavailable)?;
        let before = image.metadata().map_err(unavailable)?;
        let seals = rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SEAL;
        if !before.is_file()
            || before.len() == 0
            || before.len() > crate::BinarySnapshot::MAX_SIZE
            || !rustix::fs::fcntl_get_seals(&image)
                .map_err(unavailable)?
                .contains(seals)
        {
            return Err(ServiceError::Unsupported);
        }
        use std::os::unix::fs::FileExt;
        let mut hash = Sha256::new();
        let mut bytes = [0; 16384];
        let mut offset = 0;
        while offset < before.len() {
            let n = image
                .read_at(
                    &mut bytes[..(before.len() - offset).min(16384) as usize],
                    offset,
                )
                .map_err(unavailable)?;
            if n == 0 {
                return Err(ServiceError::Unavailable);
            }
            hash.update(&bytes[..n]);
            offset += n as u64;
        }
        if <[u8; 32]>::from(hash.finalize()) != expected {
            return Err(ServiceError::Unsupported);
        }
        let peer = Arc::new(Self {
            pid,
            start,
            uid,
            pidfd,
            image,
            identity: (before.dev(), before.ino()),
            _memory: memory,
        });
        peer.validate()?;
        Ok(peer)
    }
    pub(crate) fn validate(&self) -> Result<(), ServiceError> {
        let text = proc_text(format!("/proc/self/fdinfo/{}", self.pidfd.as_raw_fd()))?;
        let pid = text.lines().find_map(|l| {
            l.strip_prefix("Pid:")
                .and_then(|s| s.trim().parse::<u32>().ok())
        });
        let current = std::fs::metadata(format!("/proc/{}/exe", self.pid)).map_err(unavailable)?;
        if pid != Some(self.pid)
            || process_start(self.pid)? != self.start
            || std::fs::metadata(format!("/proc/{}", self.pid))
                .map_err(unavailable)?
                .uid()
                != self.uid
            || (current.dev(), current.ino()) != self.identity
            || (
                self.image.metadata().map_err(unavailable)?.dev(),
                self.image.metadata().map_err(unavailable)?.ino(),
            ) != self.identity
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
    fn socket(self: &Arc<Self>, tuple: Tuple, provenance: u8) -> Result<SocketProof, ServiceError> {
        // Actual child socket FD ещё не связывает ephemeral UDP socket с
        // конкретным SOCKS control association. TCP proof этого не заменяет.
        if tuple.protocol == 17 || provenance == 3 {
            return Err(ServiceError::Unsupported);
        }
        self.validate()?;
        let _flow = tuple.owner_flow().map_err(unavailable)?;
        let mut found = None;
        let mut count = 0;
        for entry in std::fs::read_dir(format!("/proc/{}/fd", self.pid)).map_err(unavailable)? {
            count += 1;
            if count > 8192 {
                return Err(ServiceError::Unavailable);
            }
            let entry = entry.map_err(unavailable)?;
            let Some(number) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            else {
                continue;
            };
            let link = std::fs::read_link(entry.path()).map_err(unavailable)?;
            let Some(inode) = link
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            // Ни новых capabilities, ни fallback по UID. EPERM/unsupported => deny.
            let fd = rustix::process::pidfd_getfd(
                &self.pidfd,
                number,
                rustix::process::PidfdGetfdFlags::empty(),
            )
            .map_err(|_| ServiceError::Unsupported)?;
            let facts = match SocketFacts::capture(&fd) {
                Ok(facts) => facts,
                Err(ServiceError::Unsupported) => continue,
                Err(error) => return Err(error),
            };
            if facts.inode != inode || !facts.matches(tuple, provenance) {
                continue;
            }
            if found.is_some() {
                return Err(ServiceError::Unavailable);
            }
            found = Some(SocketProof {
                peer: Arc::clone(self),
                fd,
                number,
                facts,
                tuple,
                provenance,
            });
        }
        let proof = found.ok_or(ServiceError::Unsupported)?;
        proof.validate()?;
        Ok(proof)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct SocketFacts {
    local: SocketAddr,
    remote: Option<SocketAddr>,
    protocol: u8,
    cookie: u64,
    inode: u64,
}
fn endpoint(family: u8, address: [u8; 16], port: u16) -> Result<SocketAddr, ServiceError> {
    match family {
        4 => Ok(SocketAddr::new(
            std::net::Ipv4Addr::new(address[0], address[1], address[2], address[3]).into(),
            port,
        )),
        6 => Ok(SocketAddr::new(
            std::net::Ipv6Addr::from(address).into(),
            port,
        )),
        _ => Err(ServiceError::Unavailable),
    }
}
impl SocketFacts {
    fn capture(fd: &OwnedFd) -> Result<Self, ServiceError> {
        use rustix::net::{self, sockopt};
        let protocol = match sockopt::socket_type(fd).map_err(unavailable)? {
            net::SocketType::STREAM => 6,
            net::SocketType::DGRAM => 17,
            _ => return Err(ServiceError::Unsupported),
        };
        if sockopt::socket_protocol(fd).map_err(unavailable)?
            != Some(if protocol == 6 {
                net::ipproto::TCP
            } else {
                net::ipproto::UDP
            })
        {
            return Err(ServiceError::Unsupported);
        }
        let local = SocketAddr::try_from(net::getsockname(fd).map_err(unavailable)?)
            .map_err(unavailable)?;
        let remote = net::getpeername(fd)
            .map_err(unavailable)?
            .map(SocketAddr::try_from)
            .transpose()
            .map_err(unavailable)?;
        let cookie = sockopt::socket_cookie(fd).map_err(unavailable)?;
        let inode = rustix::fs::fstat(fd).map_err(unavailable)?.st_ino;
        Ok(Self {
            local,
            remote,
            protocol,
            cookie,
            inode,
        })
    }
    fn matches(self, tuple: Tuple, provenance: u8) -> bool {
        let Ok(local) = endpoint(tuple.family, tuple.remote, tuple.remote_port) else {
            return false;
        };
        let Ok(remote) = endpoint(tuple.family, tuple.local, tuple.local_port) else {
            return false;
        };
        self.cookie != 0
            && self.inode != 0
            && self.protocol == tuple.protocol
            && self.local == local
            && match provenance {
                2 => self.protocol == 6 && self.remote == Some(remote),
                3 => self.protocol == 17 && self.remote.is_none_or(|peer| peer == remote),
                _ => false,
            }
    }
}
pub(crate) struct SocketProof {
    peer: Arc<Peer>,
    fd: OwnedFd,
    number: i32,
    facts: SocketFacts,
    tuple: Tuple,
    provenance: u8,
}
impl SocketProof {
    pub(crate) fn validate_association(&self, tuple: Tuple) -> Result<(), ServiceError> {
        if self.provenance != 3
            || tuple.protocol != 17
            || tuple.owner_flow().map_err(unavailable)?
                != self.tuple.owner_flow().map_err(unavailable)?
        {
            return Err(ServiceError::Unsupported);
        }
        self.validate()
    }
    fn validate(&self) -> Result<(), ServiceError> {
        self.peer.validate()?;
        let current = rustix::process::pidfd_getfd(
            &self.peer.pidfd,
            self.number,
            rustix::process::PidfdGetfdFlags::empty(),
        )
        .map_err(|_| ServiceError::Unsupported)?;
        if SocketFacts::capture(&current)? != self.facts
            || SocketFacts::capture(&self.fd)? != self.facts
            || !self.facts.matches(self.tuple, self.provenance)
        {
            return Err(ServiceError::Unavailable);
        }
        self.peer.validate()
    }
}

#[cfg(test)]
#[path = "native_profile_channel_tests.rs"]
mod issuer_tests;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_accepted_socket_and_owner_flow_have_distinct_verified_orientation() {
        let mut local = [0; 16];
        local[..4].copy_from_slice(&[192, 0, 2, 1]);
        let mut remote = [0; 16];
        remote[..4].copy_from_slice(&[127, 0, 0, 1]);
        let tcp = Tuple {
            protocol: 6,
            family: 4,
            local_port: 32001,
            remote_port: 1080,
            local,
            remote,
        };
        let facts = SocketFacts {
            local: "127.0.0.1:1080".parse().unwrap(),
            remote: Some("192.0.2.1:32001".parse().unwrap()),
            protocol: 6,
            cookie: 101,
            inode: 102,
        };
        assert!(facts.matches(tcp, 2));
        let owner = tcp.owner_flow().unwrap();
        assert_eq!(
            (owner.family, owner.local_port, owner.remote_port),
            (2, 32001, 1080)
        );
        let reversed = Tuple {
            local: tcp.remote,
            remote: tcp.local,
            local_port: 1080,
            remote_port: 32001,
            ..tcp
        };
        assert!(!facts.matches(reversed, 2));
        let udp = Tuple {
            protocol: 17,
            remote_port: 49152,
            ..tcp
        };
        let association = SocketFacts {
            local: "127.0.0.1:49152".parse().unwrap(),
            protocol: 17,
            ..facts
        };
        assert!(association.matches(udp, 3));
        assert!(!facts.matches(udp, 3));
        assert!(!association.matches(
            Tuple {
                remote_port: 49153,
                ..udp
            },
            3
        ));
        assert!(
            !SocketFacts {
                cookie: 0,
                ..association
            }
            .matches(udp, 3)
        );
        assert!(!association.matches(udp, 2));
        // Только факты в fixture: production proof дополнительно удерживает FD,
        // проверяет actual child PID/start/image и повторный pidfd_getfd+cookie.
    }
}
