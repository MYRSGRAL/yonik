//! Единственный private CODEC4 mint: protected producer + exec/source custody.
use super::dns_bundle::roots::{HostsChoice, Member, Parent, Question, Source};
use super::{
    BootstrapDnsReceipt, BootstrapDnsTranscript, BootstrapReleaseProof, ChannelBudget,
    LaunchRecord, Mode, Peer, ServiceError, Target, VerifiedBootstrapDnsProducer, unavailable,
    wire,
};
use crate::helper::profile_intent::{LookupFamily, LookupStep, ResolverLookupPlan};
use crate::helper::registry::{BootstrapCapability, BootstrapScope, ImageContract};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) enum Sources {
    Local(Arc<crate::host::local_profile_channel::Prepared>),
    System(Arc<crate::helper::profile_intent::PreparedFullProfile>),
}
trait SourceOwner: Send + Sync {
    fn mode(&self) -> Mode;
    fn capsule(&self) -> &wire::OwnedCapsule;
    fn reference(&self) -> Result<wire::SnapshotRef, ServiceError>;
    fn validate(&self) -> Result<(), ServiceError>;
    fn plan<'a>(
        &'a self,
        original: &'a str,
        epoch: u64,
        family: LookupFamily,
        budget: &crate::helper::memory::ByteBudget,
    ) -> Result<ResolverLookupPlan<'a>, ServiceError>;
}
impl Sources {
    fn snapshot(
        &self,
    ) -> Result<&crate::helper::profile_intent::PinnedResolverSnapshot, ServiceError> {
        match self {
            Self::Local(p) => p.resolver_snapshot(),
            Self::System(p) => p.resolver(),
        }
        .ok_or(ServiceError::Unsupported)
    }
}
impl SourceOwner for Sources {
    fn mode(&self) -> Mode {
        match self {
            Self::Local(_) => Mode::Local,
            Self::System(_) => Mode::System,
        }
    }
    fn capsule(&self) -> &wire::OwnedCapsule {
        match self {
            Self::Local(p) => &p.capsule,
            Self::System(p) => p.capsule(),
        }
    }
    fn reference(&self) -> Result<wire::SnapshotRef, ServiceError> {
        Ok(self.snapshot()?.reference())
    }
    fn validate(&self) -> Result<(), ServiceError> {
        let (_keep, cancel) = crate::Cancellation::new();
        match self {
            Self::Local(p) => p.revalidate(&cancel).map_err(unavailable),
            Self::System(p) => p.revalidate(&cancel).map_err(unavailable),
        }
    }
    fn plan<'a>(
        &'a self,
        original: &'a str,
        epoch: u64,
        family: LookupFamily,
        budget: &crate::helper::memory::ByteBudget,
    ) -> Result<ResolverLookupPlan<'a>, ServiceError> {
        self.snapshot()?
            .retained_lookup_data(original, epoch, family, budget)
            .map_err(unavailable)
    }
}
trait PeerCustody: Send + Sync {
    fn validation_credit(&self) -> Result<crate::helper::memory::ByteLease, ServiceError>;
    fn validate(&self) -> Result<(), ServiceError>;
    fn launch(&self) -> Option<LaunchRecord>;
    fn image(&self) -> [u8; 32];
    fn config(&self) -> [u8; 32];
    fn producer(&self) -> Option<&ImageContract>;
    fn now(&self) -> Instant {
        Instant::now()
    }
}
struct RetainedPeer(Arc<Peer>);
impl PeerCustody for RetainedPeer {
    fn validation_credit(&self) -> Result<crate::helper::memory::ByteLease, ServiceError> {
        self.0
            .proofs
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .lock()
            .map_err(unavailable)?
            .slots
            .fds
            .reserve(16)
            .map_err(unavailable)
    }
    fn validate(&self) -> Result<(), ServiceError> {
        self.0.validate()
    }
    fn launch(&self) -> Option<LaunchRecord> {
        self.0.bound_launch
    }
    fn image(&self) -> [u8; 32] {
        self.0.image_hash
    }
    fn config(&self) -> [u8; 32] {
        self.0.config_hash
    }
    fn producer(&self) -> Option<&ImageContract> {
        self.0.producer.as_ref()
    }
}
fn same_ref(a: wire::SnapshotRef, b: wire::SnapshotRef) -> bool {
    (a.source, a.asset, a.bytes, a.flags) == (b.source, b.asset, b.bytes, b.flags)
}
struct Query {
    capture: Option<CaptureStamp>,
    id: u64,
    root: wire::dns_v2::Root,
    selector: wire::dns_v2::BootstrapSelector,
    original: Target,
    path: Box<[(u16, u8)]>,
    expires: Instant,
    _memory: crate::helper::memory::ByteLease,
}
// Только pointer slots оплачены при factory; большие capture records — перед Box.
struct QuerySlot(Box<Query>);
impl std::ops::Deref for QuerySlot {
    type Target = Query;
    fn deref(&self) -> &Query {
        &self.0
    }
}
impl std::ops::DerefMut for QuerySlot {
    fn deref_mut(&mut self) -> &mut Query {
        &mut self.0
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct CaptureStamp {
    binding: super::dns_transport::Binding,
    proof: u64,
    revision: u64,
    exchange: u64,
    sequence: u64,
    request: [u8; 32],
    response: [u8; 32],
    anchor: Instant,
}
impl Query {
    fn matches(&self, p: &Parent<'_>) -> bool {
        self.root == p.root
            && self.selector == p.selector
            && self.original.wire() == p.original
            && self.path.as_ref() == p.path
    }
}
pub(super) struct BootstrapBinding {
    peer: Arc<dyn PeerCustody>,
    owner: Arc<dyn SourceOwner>,
    capsule: Arc<wire::OwnedCapsule>,
    launch: LaunchRecord,
    capabilities: [Option<BootstrapCapability>; 3],
    created: Instant,
    until: Instant,
    invalid: AtomicBool,
    limit: usize,
    queries: std::sync::Mutex<Vec<QuerySlot>>,
    budget: Arc<ChannelBudget>,
    _memory: crate::helper::memory::ByteLease,
}
impl BootstrapBinding {
    pub(super) fn prepare(
        peer: Arc<Peer>,
        owner: Sources,
        capsule: Arc<wire::OwnedCapsule>,
        launch: LaunchRecord,
        budget: Arc<ChannelBudget>,
    ) -> Result<Option<Arc<Self>>, ServiceError> {
        Self::create(
            Arc::new(RetainedPeer(peer)),
            Arc::new(owner),
            capsule,
            launch,
            budget,
        )
    }
    fn create(
        peer: Arc<dyn PeerCustody>,
        owner: Arc<dyn SourceOwner>,
        capsule: Arc<wire::OwnedCapsule>,
        launch: LaunchRecord,
        budget: Arc<ChannelBudget>,
    ) -> Result<Option<Arc<Self>>, ServiceError> {
        let _fds = peer.validation_credit()?;
        peer.validate()?;
        launch.encode().map_err(unavailable)?;
        if peer.launch() != Some(launch)
            || peer.config() != launch.binding.digest
            || owner.mode() != launch.mode
            || owner.capsule().bytes() != capsule.bytes()
        {
            return Err(ServiceError::Unavailable);
        }
        let cap = wire::Capsule::decode(capsule.bytes(), &peer.config()).map_err(unavailable)?;
        if cap.mode != launch.mode || cap.manifest != launch.manifest {
            return Err(ServiceError::Unavailable);
        }
        let Some(record) = peer.producer() else {
            return Ok(None);
        };
        let capabilities = [
            record
                .bootstrap_channel(peer.image(), BootstrapScope::Source)
                .map_err(unavailable)?,
            record
                .bootstrap_channel(peer.image(), BootstrapScope::Wire)
                .map_err(unavailable)?,
            record
                .bootstrap_channel(peer.image(), BootstrapScope::Release)
                .map_err(unavailable)?,
        ];
        if capabilities.iter().all(Option::is_none) {
            return Ok(None);
        }
        owner.validate()?;
        let snapshot = match cap.bootstrap_snapshot() {
            Ok(s) => s,
            Err(wire::Error::Reference) => return Ok(None),
            Err(e) => return Err(unavailable(e)),
        };
        if !snapshot.bootstrap() {
            return Ok(None);
        }
        if !same_ref(snapshot.asset_reference(), owner.reference()?) {
            return Err(ServiceError::Unavailable);
        }
        let limit = (cap.limits()[7] as usize).min(256);
        let memory = budget
            .dynamic
            .reserve(std::mem::size_of::<Self>() + limit * std::mem::size_of::<QuerySlot>() + 128)
            .map_err(unavailable)?;
        let created = peer.now();
        let until = created + Duration::from_millis(u64::from(cap.lease_ms));
        owner.validate()?;
        peer.validate()?;
        Ok(Some(Arc::new(Self {
            peer,
            owner,
            capsule,
            launch,
            capabilities,
            created,
            until,
            invalid: AtomicBool::new(false),
            limit,
            queries: std::sync::Mutex::new(Vec::with_capacity(limit)),
            budget,
            _memory: memory,
        })))
    }
    fn scope_index(scope: BootstrapScope) -> usize {
        match scope {
            BootstrapScope::Source => 0,
            BootstrapScope::Wire => 1,
            BootstrapScope::Release => 2,
        }
    }
    pub(super) fn check(
        &self,
        scope: BootstrapScope,
        launch: LaunchRecord,
    ) -> Result<(), ServiceError> {
        if launch != self.launch
            || self.peer.launch() != Some(launch)
            || self.peer.config() != launch.binding.digest
        {
            return Err(ServiceError::Unavailable);
        }
        self.capabilities[Self::scope_index(scope)]
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .check(self.peer.image(), scope)
            .map_err(unavailable)?;
        if self.invalid.load(Ordering::Acquire) || self.peer.now() >= self.until {
            return Err(ServiceError::Unavailable);
        }
        let _fds = self.peer.validation_credit()?;
        let valid = self
            .peer
            .validate()
            .and_then(|()| self.owner.validate())
            .and_then(|()| self.peer.validate())
            .and_then(|()| {
                if self.peer.now() < self.until {
                    Ok(())
                } else {
                    Err(ServiceError::Unavailable)
                }
            });
        if valid.is_err() {
            self.invalid.store(true, Ordering::Release);
        }
        valid
    }
    pub(super) fn source(self: &Arc<Self>) -> Option<Arc<dyn Source>> {
        self.capabilities[0]
            .as_ref()
            .map(|_| Arc::clone(self) as Arc<dyn Source>)
    }
    pub(super) fn transcript(self: &Arc<Self>) -> Option<Arc<dyn BootstrapDnsTranscript>> {
        self.capabilities[1]
            .as_ref()
            .map(|_| Arc::clone(self) as Arc<dyn BootstrapDnsTranscript>)
    }
    pub(super) fn release(self: &Arc<Self>) -> Option<Arc<VerifiedBootstrapDnsProducer>> {
        self.capabilities[2].as_ref().map(|_| {
            Arc::new(VerifiedBootstrapDnsProducer {
                launch: self.launch,
                schema: Sha256::digest(wire::dns_v2::SCHEMA).into(),
                proof: BootstrapReleaseProof::Installed(Arc::clone(self)),
            })
        })
    }
    fn parent_lease(&self, p: Parent<'_>) -> Result<Instant, ServiceError> {
        // Live parent/conjunction гарантирует только принятый consuming contract.
        // Проверка graph ниже не является независимым наблюдением Go operation.
        let p = p.checked()?;
        self.check(BootstrapScope::Source, p.launch)?;
        if p.original.protocol != 6 || p.path.len() != 1 || p.path[0].1 != 0 {
            return Err(ServiceError::Unsupported);
        }
        let _scratch = self.budget.dynamic.reserve(2048).map_err(unavailable)?;
        let cap = wire::Capsule::decode(self.capsule.bytes(), &self.launch.binding.digest)
            .map_err(unavailable)?;
        if cap.endpoint(p.selector.endpoint).map_err(unavailable)? != p.original {
            return Err(ServiceError::InvalidRequest);
        }
        let mut expected = None;
        let mut input = None;
        let mut seen = [[false; 2]; 512];
        for (i, (scope, branch)) in p.path.iter().copied().enumerate() {
            let d = cap.dial_scope(scope, branch).map_err(unavailable)?;
            if cap.stream_shape(d.stream).map_err(unavailable)? != (1, 0) {
                return Err(ServiceError::Unsupported);
            }
            if seen[usize::from(scope)][usize::from(branch)]
                || expected.is_some_and(|(next, mask): (u16, u8)| {
                    next != scope || mask & (1 << branch) == 0
                })
                || input.is_some_and(|carrier| carrier != d.input)
                || (i + 1 < p.path.len()) != d.next.is_some()
            {
                return Err(ServiceError::InvalidRequest);
            }
            if i + 1 == p.path.len()
                && (d.action != 1
                    || d.subject != p.selector.subject
                    || d.endpoint_index != p.selector.endpoint
                    || d.carrier != p.original.protocol)
            {
                return Err(ServiceError::InvalidRequest);
            }
            seen[usize::from(scope)][usize::from(branch)] = true;
            expected = d.next;
            input = Some(d.carrier);
        }
        let mut queries = self.queries.lock().map_err(unavailable)?;
        let until = if let Some(q) = queries.iter().find(|q| q.id == p.query) {
            if !q.matches(&p) {
                return Err(ServiceError::InvalidRequest);
            }
            q.expires
        } else {
            if queries.len() >= self.limit {
                return Err(ServiceError::Busy);
            }
            let credit = self
                .budget
                .dynamic
                .reserve(std::mem::size_of::<Query>() + p.path.len() * 4 + 160)
                .map_err(unavailable)?;
            let until = self.until.min(self.peer.now() + Duration::from_secs(1));
            queries.push(QuerySlot(Box::new(Query {
                capture: None,
                id: p.query,
                root: p.root,
                selector: p.selector,
                original: Target::copy(p.original)?,
                path: p.path.into(),
                expires: until,
                _memory: credit,
            })));
            until
        };
        drop(queries);
        self.check(BootstrapScope::Source, p.launch)?;
        if self.peer.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        Ok(until)
    }
    fn host_choice(
        &self,
        p: Parent<'_>,
        r: wire::SnapshotRef,
    ) -> Result<HostsChoice, ServiceError> {
        self.snapshot(p.launch, r)?;
        let until = self.parent_lease(Parent {
            root: p.root,
            launch: p.launch,
            query: p.query,
            selector: p.selector,
            original: p.original,
            path: p.path,
        })?;
        let original = std::str::from_utf8(p.original.bytes).map_err(unavailable)?;
        let plan = self.owner.plan(
            original,
            self.launch.binding.epoch,
            LookupFamily::Any,
            &self.budget.dynamic,
        )?;
        let Some(LookupStep::Hosts(host)) = plan.steps().first() else {
            return Err(ServiceError::Unsupported);
        };
        if host.members().is_empty() || host.members().len() > 256 || plan.lookup_key().len() > 253
        {
            return Err(ServiceError::Unsupported);
        }
        let mut choice = HostsChoice {
            row: host.row(),
            members: [0; 256],
            count: host.members().len() as u16,
            key: [0; 253],
            key_len: plan.lookup_key().len() as u16,
            expires: until,
        };
        choice.key[..usize::from(choice.key_len)].copy_from_slice(plan.lookup_key().as_bytes());
        for (i, m) in host.members().iter().enumerate() {
            choice.members[i] = m.index;
        }
        self.check(BootstrapScope::Source, p.launch)?;
        if self.peer.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        Ok(choice)
    }
}
impl Source for BootstrapBinding {
    fn parent(&self, p: Parent<'_>) -> Result<Instant, ServiceError> {
        self.parent_lease(p)
    }
    fn snapshot(
        &self,
        launch: LaunchRecord,
        r: wire::SnapshotRef,
    ) -> Result<Instant, ServiceError> {
        if launch != self.launch || !same_ref(r, self.owner.reference()?) {
            return Err(ServiceError::InvalidRequest);
        }
        self.check(BootstrapScope::Source, launch)?;
        Ok(self.until)
    }
    fn hosts(&self, p: Parent<'_>, r: wire::SnapshotRef) -> Result<HostsChoice, ServiceError> {
        self.host_choice(p, r)
    }
    fn member(
        &self,
        p: Parent<'_>,
        r: wire::SnapshotRef,
        row: u16,
        index: u16,
    ) -> Result<Member, ServiceError> {
        let choice = self.host_choice(
            Parent {
                root: p.root,
                launch: p.launch,
                query: p.query,
                selector: p.selector,
                original: p.original,
                path: p.path,
            },
            r,
        )?;
        if choice.row != row || !choice.members[..usize::from(choice.count)].contains(&index) {
            return Err(ServiceError::InvalidRequest);
        }
        let original = std::str::from_utf8(p.original.bytes).map_err(unavailable)?;
        let plan = self.owner.plan(
            original,
            self.launch.binding.epoch,
            LookupFamily::Any,
            &self.budget.dynamic,
        )?;
        let Some(LookupStep::Hosts(host)) = plan.steps().first() else {
            return Err(ServiceError::Unsupported);
        };
        let address = host
            .members()
            .iter()
            .find(|m| m.index == index)
            .ok_or(ServiceError::InvalidRequest)?
            .address;
        self.check(BootstrapScope::Source, p.launch)?;
        if self.peer.now() >= choice.expires {
            return Err(ServiceError::Unavailable);
        }
        Ok(Member {
            address,
            expires: choice.expires,
        })
    }
    fn question(
        &self,
        p: Parent<'_>,
        r: wire::SnapshotRef,
        qtype: u16,
        options: u16,
        payload: u16,
    ) -> Result<Question, ServiceError> {
        self.snapshot(p.launch, r)?;
        let until = self.parent_lease(Parent {
            root: p.root,
            launch: p.launch,
            query: p.query,
            selector: p.selector,
            original: p.original,
            path: p.path,
        })?;
        let family = match qtype {
            1 => LookupFamily::Ipv4,
            28 => LookupFamily::Ipv6,
            _ => return Err(ServiceError::Unsupported),
        };
        let plan = self.owner.plan(
            std::str::from_utf8(p.original.bytes).map_err(unavailable)?,
            self.launch.binding.epoch,
            family,
            &self.budget.dynamic,
        )?;
        let Some(LookupStep::Network(n)) = plan.steps().first() else {
            return Err(ServiceError::Unsupported);
        };
        if options != n.options().query_options || payload != n.options().udp_payload {
            return Err(ServiceError::InvalidRequest);
        }
        let cap = wire::Capsule::decode(self.capsule.bytes(), &self.launch.binding.digest)
            .map_err(unavailable)?;
        let peer = cap
            .resolver_scope(p.selector.resolver.ok_or(ServiceError::InvalidRequest)?)
            .map_err(unavailable)?
            .peer;
        let found = n.peers().iter().any(|p| {
            p.port() == peer.port
                && match p.ip() {
                    std::net::IpAddr::V4(ip) => peer.family == 4 && peer.bytes == ip.octets(),
                    std::net::IpAddr::V6(ip) => peer.family == 6 && peer.bytes == ip.octets(),
                }
        });
        if !found {
            return Err(ServiceError::InvalidRequest);
        }
        let name = n
            .questions()
            .next()
            .ok_or(ServiceError::Unsupported)?
            .canonical();
        if name.is_empty() || name.len() > 253 {
            return Err(ServiceError::Unsupported);
        }
        let mut q = Question {
            bytes: [0; 253],
            len: name.len() as u16,
            expires: until,
        };
        q.bytes[..name.len()].copy_from_slice(name.as_bytes());
        self.check(BootstrapScope::Source, p.launch)?;
        if self.peer.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        Ok(q)
    }
}
impl BootstrapDnsTranscript for BootstrapBinding {
    fn observed(
        &self,
        launch: LaunchRecord,
        r: BootstrapDnsReceipt<'_>,
    ) -> Result<Instant, ServiceError> {
        self.check(BootstrapScope::Wire, launch)?;
        if !r.binding.bootstrap
            || r.binding.epoch != launch.binding.epoch
            || r.binding.source != 0
            || r.binding.source_revision != 0
            || [r.proof, r.revision, r.exchange, r.producer_sequence]
                .iter()
                .any(|v| *v == 0 || *v == u64::MAX)
            || r.lifetime_anchor < self.created
            || r.lifetime_anchor > self.peer.now()
            || r.lifetime_anchor >= self.until
        {
            return Err(ServiceError::InvalidRequest);
        }
        let _scratch = self
            .budget
            .dynamic
            .reserve(super::dns_rrset::SCRATCH + 2048)
            .map_err(unavailable)?;
        let mut path = [(0, 0); 256];
        let (root, id, selector, original, count, expires) = {
            let queries = self.queries.lock().map_err(unavailable)?;
            let q = queries
                .iter()
                .find(|q| q.id == r.binding.query)
                .ok_or(ServiceError::Unavailable)?;
            if !matches!(q.root,wire::dns_v2::Root::BootstrapService(id) if id.get()==r.binding.root)
                || q.selector.resolver != Some(r.binding.resolver)
                || q.selector.endpoint != r.binding.physical_endpoint
                || q.selector.subject != r.binding.subject
                || q.original.protocol != r.binding.parent_carrier
                || q.path.last() != Some(&(r.binding.scope, r.binding.branch))
                || self.peer.now() >= q.expires
            {
                return Err(ServiceError::InvalidRequest);
            }
            let cap = wire::Capsule::decode(self.capsule.bytes(), &launch.binding.digest)
                .map_err(unavailable)?;
            let resolver = cap
                .resolver_scope(r.binding.resolver)
                .map_err(unavailable)?;
            let mut base = [0; 8];
            for (i, v) in [
                2,
                q.selector.endpoint,
                q.selector.subject,
                r.binding.resolver,
            ]
            .into_iter()
            .enumerate()
            {
                base[i * 2..i * 2 + 2].copy_from_slice(&v.to_be_bytes());
            }
            if r.binding.base != <[u8; 32]>::from(Sha256::digest(base))
                || r.binding.proxied
                || r.binding.peer.wire() != resolver.peer
                || r.binding.physical_peer != r.binding.peer
                || resolver.source != self.owner.reference()?.source
                || resolver.subject != u16::MAX
                || resolver.scope.is_some()
                || r.binding.physical_scope != r.binding.scope
                || r.binding.physical_branch != r.binding.branch
                || r.binding.physical_subject != r.binding.subject
                || usize::from(r.binding.physical_hop) + 1 != q.path.len()
                || r.binding.expires > q.expires
                || r.binding.expires <= self.peer.now()
                || [r.binding.bundle, r.binding.revision]
                    .iter()
                    .any(|n| *n == 0 || *n == u64::MAX)
            {
                return Err(ServiceError::InvalidRequest);
            }
            path[..q.path.len()].copy_from_slice(&q.path);
            (
                q.root,
                q.id,
                q.selector,
                q.original,
                q.path.len(),
                q.expires.min(r.binding.expires),
            )
        };
        let question = self.question(
            Parent {
                root,
                launch,
                query: id,
                selector,
                original: original.wire(),
                path: &path[..count],
            },
            self.owner.reference()?,
            r.binding.qtype,
            r.binding.options,
            r.binding.payload,
        )?;
        if r.binding.name.wire().bytes != &question.bytes[..usize::from(question.len)] {
            return Err(ServiceError::InvalidRequest);
        }
        super::dns_rrset::verify_bootstrap_capture(
            r.request,
            r.response,
            r.binding.name.wire().bytes,
            r.binding.qtype,
            r.binding.options,
            r.binding.payload,
        )?;
        let stamp = CaptureStamp {
            binding: r.binding,
            proof: r.proof,
            revision: r.revision,
            exchange: r.exchange,
            sequence: r.producer_sequence,
            request: Sha256::digest(r.request).into(),
            response: Sha256::digest(r.response).into(),
            anchor: r.lifetime_anchor,
        };
        let mut queries = self.queries.lock().map_err(unavailable)?;
        let q = queries
            .iter_mut()
            .find(|q| q.id == id)
            .ok_or(ServiceError::Unavailable)?;
        if q.capture.is_some_and(|old| old != stamp) || self.peer.now() >= expires {
            return Err(ServiceError::InvalidRequest);
        }
        q.capture = Some(stamp);
        drop(queries);
        self.check(BootstrapScope::Wire, launch)?;
        if self.peer.now() >= expires {
            return Err(ServiceError::Unavailable);
        }
        Ok(r.lifetime_anchor)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    pub(in crate::helper::native_profile_channel) fn interop_status(
        b: &BootstrapBinding,
        query: u64,
    ) -> String {
        let queries = b.queries.lock().unwrap();
        format!(
            "invalid={} now={:?} created={:?} until={:?} peer={:?} owner={:?} ids={:?} wanted={query} used={} limit={} requested={}",
            b.invalid.load(Ordering::Acquire),
            b.peer.now(),
            b.created,
            b.until,
            b.peer.validate(),
            b.owner.validate(),
            queries
                .iter()
                .map(|q| (q.id, q.expires))
                .collect::<Vec<_>>(),
            b.budget.dynamic.used(),
            wire::Capsule::decode(b.capsule.bytes(), &b.launch.binding.digest)
                .unwrap()
                .buffer_credit()
                .unwrap()
                - 128 * 1024,
            super::super::dns_rrset::SCRATCH + 2048
        )
    }
    struct FakePeer {
        record: LaunchRecord,
        image: [u8; 32],
        config: [u8; 32],
        producer: Option<ImageContract>,
        valid: AtomicBool,
        clock: AtomicU64,
        start: Instant,
        fds: crate::helper::memory::ByteBudget,
    }
    impl PeerCustody for FakePeer {
        fn validation_credit(&self) -> Result<crate::helper::memory::ByteLease, ServiceError> {
            self.fds.reserve(16).map_err(unavailable)
        }
        fn validate(&self) -> Result<(), ServiceError> {
            if self.valid.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(ServiceError::Unavailable)
            }
        }
        fn launch(&self) -> Option<LaunchRecord> {
            Some(self.record)
        }
        fn image(&self) -> [u8; 32] {
            self.image
        }
        fn config(&self) -> [u8; 32] {
            self.config
        }
        fn producer(&self) -> Option<&ImageContract> {
            self.producer.as_ref()
        }
        fn now(&self) -> Instant {
            self.start + Duration::from_nanos(self.clock.load(Ordering::Acquire))
        }
    }
    struct FakeOwner {
        mode: Mode,
        capsule: Arc<wire::OwnedCapsule>,
        reference: wire::SnapshotRef,
        asset: Vec<u8>,
        peers: Vec<std::net::SocketAddr>,
        valid: AtomicBool,
        fail_plan: AtomicBool,
    }
    pub(in crate::helper::native_profile_channel) fn interop_binding(
        capsule: Arc<wire::OwnedCapsule>,
        launch: LaunchRecord,
        asset: Vec<u8>,
        reference: wire::SnapshotRef,
        budget: Arc<ChannelBudget>,
        scopes: &[BootstrapScope],
        start: Instant,
    ) -> Arc<BootstrapBinding> {
        let peer = Arc::new(FakePeer {
            record: launch,
            image: [17; 32],
            config: launch.binding.digest,
            producer: Some(crate::helper::registry::fake_bootstrap_image(
                [17; 32], scopes,
            )),
            valid: AtomicBool::new(true),
            clock: AtomicU64::new(0),
            start,
            fds: crate::helper::memory::ByteBudget::new(64),
        });
        let owner = Arc::new(FakeOwner {
            mode: launch.mode,
            capsule: capsule.clone(),
            reference,
            asset,
            peers: vec!["192.0.2.53:53".parse().unwrap()],
            valid: AtomicBool::new(true),
            fail_plan: AtomicBool::new(false),
        });
        BootstrapBinding::create(peer, owner, capsule, launch, budget)
            .unwrap()
            .unwrap()
    }
    impl SourceOwner for FakeOwner {
        fn mode(&self) -> Mode {
            self.mode
        }
        fn capsule(&self) -> &wire::OwnedCapsule {
            &self.capsule
        }
        fn reference(&self) -> Result<wire::SnapshotRef, ServiceError> {
            Ok(self.reference)
        }
        fn validate(&self) -> Result<(), ServiceError> {
            if !self.valid.load(Ordering::Acquire) {
                return Err(ServiceError::Unavailable);
            }
            wire::verify_resolver_asset(&self.asset, self.reference).map_err(unavailable)
        }
        fn plan<'a>(
            &'a self,
            original: &'a str,
            epoch: u64,
            family: LookupFamily,
            budget: &crate::helper::memory::ByteBudget,
        ) -> Result<ResolverLookupPlan<'a>, ServiceError> {
            let plan = crate::helper::profile_intent::PinnedResolverSnapshot::fixture_lookup_data(
                &self.asset,
                &self.peers,
                self.reference,
                original,
                epoch,
                family,
                budget,
            )
            .map_err(unavailable)?;
            if self.fail_plan.load(Ordering::Acquire) {
                self.valid.store(false, Ordering::Release);
            }
            Ok(plan)
        }
    }
    struct Fixture {
        peer: Arc<FakePeer>,
        owner: Arc<FakeOwner>,
        path: Vec<(u16, u8)>,
        endpoint: u16,
        budget: Arc<ChannelBudget>,
        network_root: wire::dns_v2::Root,
        subject: u16,
    }
    fn fixture(mode: Mode, order: u8, scopes: &[BootstrapScope]) -> Fixture {
        let (cap, launch, asset, reference, path, endpoint, budget, network_root) =
            super::super::dns_bundle::roots::tests::binding_fixture(mode, order);
        let subject = wire::Capsule::decode(cap.bytes(), &launch.binding.digest)
            .unwrap()
            .dial_scope(path[0].0, path[0].1)
            .unwrap()
            .subject;
        Fixture {
            peer: Arc::new(FakePeer {
                record: launch,
                image: [17; 32],
                config: launch.binding.digest,
                producer: Some(crate::helper::registry::fake_bootstrap_image(
                    [17; 32], scopes,
                )),
                valid: AtomicBool::new(true),
                clock: AtomicU64::new(0),
                start: Instant::now(),
                fds: crate::helper::memory::ByteBudget::new(64),
            }),
            owner: Arc::new(FakeOwner {
                mode,
                capsule: cap,
                reference,
                asset,
                peers: vec!["192.0.2.53:53".parse().unwrap()],
                valid: AtomicBool::new(true),
                fail_plan: AtomicBool::new(false),
            }),
            path,
            endpoint,
            budget,
            network_root,
            subject,
        }
    }
    fn create(f: &Fixture) -> Result<Option<Arc<BootstrapBinding>>, ServiceError> {
        BootstrapBinding::create(
            f.peer.clone(),
            f.owner.clone(),
            f.owner.capsule.clone(),
            f.peer.record,
            f.budget.clone(),
        )
    }
    fn parent(f: &Fixture, network: bool, query: u64) -> Parent<'_> {
        Parent {
            root: if network {
                f.network_root
            } else {
                wire::dns_v2::Root::HostsPath
            },
            launch: f.peer.record,
            query,
            selector: wire::dns_v2::BootstrapSelector {
                endpoint: f.endpoint,
                subject: f.subject,
                resolver: network.then_some(1),
            },
            original: wire::Destination {
                family: 3,
                protocol: 6,
                port: 8443,
                bytes: b"physical.invalid",
            },
            path: &f.path,
        }
    }
    #[test]
    fn bootstrap_binding_local_system_shared_planner_scope_and_hosts_indices() {
        for mode in [Mode::Local, Mode::System] {
            let f = fixture(mode, 1, &[BootstrapScope::Source]);
            f.owner.validate().unwrap();
            let cap = wire::Capsule::decode(f.owner.capsule.bytes(), &f.peer.config).unwrap();
            assert_eq!(cap.mode as u8, f.peer.record.mode as u8);
            assert_eq!(cap.manifest, f.peer.record.manifest);
            assert!(cap.bootstrap_snapshot().unwrap().bootstrap());
            assert!(same_ref(
                cap.bootstrap_snapshot().unwrap().asset_reference(),
                f.owner.reference
            ));
            assert!(
                f.peer
                    .producer()
                    .unwrap()
                    .bootstrap_channel(f.peer.image, BootstrapScope::Source)
                    .unwrap()
                    .is_some()
            );
            let b = create(&f).unwrap().unwrap();
            assert!(b.source().is_some() && b.transcript().is_none() && b.release().is_none());
            let first = b.parent(parent(&f, false, 9)).unwrap();
            let h = b.hosts(parent(&f, false, 9), f.owner.reference).unwrap();
            assert_eq!(h.row, 0);
            assert_eq!(&h.members[..usize::from(h.count)], &[0]);
            let m = b
                .member(parent(&f, false, 9), f.owner.reference, 0, 0)
                .unwrap();
            assert_eq!(
                m.address,
                "203.0.113.80".parse::<std::net::IpAddr>().unwrap()
            );
            f.peer.clock.store(500_000_000, Ordering::Release);
            assert_eq!(b.parent(parent(&f, false, 9)).unwrap(), first);
            assert_eq!(
                b.member(parent(&f, false, 9), f.owner.reference, 0, 0)
                    .unwrap()
                    .expires,
                h.expires
            );
            assert!(
                b.member(parent(&f, false, 9), f.owner.reference, 0, 1)
                    .is_err()
            );
            f.peer.clock.store(1_000_000_001, Ordering::Release);
            assert!(b.parent(parent(&f, false, 9)).is_err());
        }
    }
    #[test]
    fn bootstrap_binding_dns_first_hosts_and_second_question_are_not_invented() {
        let f = fixture(Mode::System, 4, &[BootstrapScope::Source]);
        let b = create(&f).unwrap().unwrap();
        assert!(b.hosts(parent(&f, false, 9), f.owner.reference).is_err());
        let q = b
            .question(parent(&f, true, 10), f.owner.reference, 1, 9, 1232)
            .unwrap();
        assert_eq!(&q.bytes[..usize::from(q.len)], b"physical.invalid");
        assert!(
            b.question(parent(&f, true, 10), f.owner.reference, 1, 0, 0)
                .is_err()
        );
        let mut foreign = parent(&f, true, 10);
        foreign.original.bytes = b"second.invalid";
        assert!(b.parent(foreign).is_err());
        assert!(b.parent(parent(&f, true, 10)).is_ok());
    }
    #[test]
    fn bootstrap_binding_no_pins_or_direct3_udp_never_mint_and_identity_mismatches_deny() {
        let mut f = fixture(Mode::Local, 1, &[]);
        assert!(create(&f).unwrap().is_none());
        Arc::get_mut(&mut f.peer).unwrap().producer =
            Some(crate::helper::registry::fake_dns_wire_image([17; 32]));
        assert!(create(&f).unwrap().is_none());
        for fault in 0..5 {
            let mut f = fixture(
                Mode::System,
                1,
                &[
                    BootstrapScope::Source,
                    BootstrapScope::Wire,
                    BootstrapScope::Release,
                ],
            );
            match fault {
                0 => Arc::get_mut(&mut f.peer).unwrap().image[0] ^= 1,
                1 => Arc::get_mut(&mut f.peer).unwrap().config[0] ^= 1,
                2 => Arc::get_mut(&mut f.peer).unwrap().record.manifest[0] ^= 1,
                3 => Arc::get_mut(&mut f.owner).unwrap().mode = Mode::Local,
                _ => Arc::get_mut(&mut f.owner).unwrap().reference.asset[0] ^= 1,
            }
            assert!(create(&f).is_err(), "fault {fault}");
        }
    }
    #[test]
    fn bootstrap_binding_source_peer_epoch_and_post_plan_failure_are_sticky() {
        for fault in 0..3 {
            let f = fixture(
                Mode::System,
                1,
                &[BootstrapScope::Source, BootstrapScope::Release],
            );
            let b = create(&f).unwrap().unwrap();
            match fault {
                0 => f.owner.valid.store(false, Ordering::Release),
                1 => f.peer.valid.store(false, Ordering::Release),
                _ => f.owner.fail_plan.store(true, Ordering::Release),
            }
            assert!(b.hosts(parent(&f, false, 9), f.owner.reference).is_err());
            f.owner.valid.store(true, Ordering::Release);
            f.peer.valid.store(true, Ordering::Release);
            f.owner.fail_plan.store(false, Ordering::Release);
            assert!(b.parent(parent(&f, false, 9)).is_err());
            assert!(b.release().unwrap().bound(f.peer.record).is_err());
        }
        let f = fixture(Mode::Local, 1, &[BootstrapScope::Source]);
        let b = create(&f).unwrap().unwrap();
        let mut wrong = parent(&f, false, 9);
        wrong.launch.binding.epoch += 1;
        assert!(b.parent(wrong).is_err());
        assert!(b.parent(parent(&f, false, 9)).is_ok());
    }
    #[test]
    fn bootstrap_binding_three_views_anchor_and_frozen_capture_are_independent() {
        for mode in [Mode::Local, Mode::System] {
            let f = fixture(
                mode,
                4,
                &[
                    BootstrapScope::Source,
                    BootstrapScope::Wire,
                    BootstrapScope::Release,
                ],
            );
            let b = create(&f).unwrap().unwrap();
            let until = b.parent(parent(&f, true, 9)).unwrap();
            assert!(b.release().unwrap().bound(f.peer.record).is_ok());
            let cap = wire::Capsule::decode(f.owner.capsule.bytes(), &f.peer.config).unwrap();
            let (scope, branch) = f.path[0];
            let d = cap.dial_scope(scope, branch).unwrap();
            let peer = Target::copy(cap.resolver_scope(1).unwrap().peer).unwrap();
            let mut base = [0; 8];
            for (i, v) in [2, f.endpoint, f.subject, 1].into_iter().enumerate() {
                base[i * 2..i * 2 + 2].copy_from_slice(&v.to_be_bytes());
            }
            let binding = super::super::dns_transport::Binding {
                bootstrap: true,
                parent_carrier: 6,
                proxied: false,
                physical_peer: peer,
                physical_scope: scope,
                physical_subject: d.subject,
                physical_endpoint: f.endpoint,
                physical_branch: branch,
                physical_hop: 0,
                bundle: 1,
                revision: 1,
                root: 1,
                query: 9,
                epoch: f.peer.record.binding.epoch,
                source: 0,
                source_revision: 0,
                resolver: 1,
                subject: f.subject,
                scope,
                branch,
                qtype: 1,
                options: 9,
                payload: 1232,
                base: Sha256::digest(base).into(),
                name: Target::host("physical.invalid", 53).unwrap(),
                peer,
                ticket: None,
                expires: until,
            };
            let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1];
            q.extend_from_slice(b"\x08physical\x07invalid\0\0\x01\0\x01");
            let mut r = q.clone();
            r[2] = 0x81;
            r[3] = 0x80;
            r[7] = 1;
            r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 80]);
            let opt = [0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0];
            q.extend_from_slice(&opt);
            r.extend_from_slice(&opt);
            let observed = |sequence, revision, anchor, request: &[u8], response: &[u8]| {
                b.observed(
                    f.peer.record,
                    BootstrapDnsReceipt {
                        lifetime_anchor: anchor,
                        binding,
                        proof: 1,
                        revision,
                        exchange: 1,
                        producer_sequence: sequence,
                        request,
                        response,
                    },
                )
            };
            let anchor = f.peer.start;
            f.peer.clock.store(100_000_000, Ordering::Release);
            assert_eq!(observed(1, 1, anchor, &q, &r).unwrap(), anchor);
            f.peer.clock.store(200_000_000, Ordering::Release);
            assert_eq!(observed(1, 1, anchor, &q, &r).unwrap(), anchor);
            assert!(observed(2, 1, anchor, &q, &r).is_err());
            assert!(observed(1, 2, anchor, &q, &r).is_err());
            assert!(observed(1, 1, anchor + Duration::from_millis(1), &q, &r).is_err());
            let mut changed = r.clone();
            *changed.last_mut().unwrap() = 1;
            assert!(observed(1, 1, anchor, &q, &changed).is_err());
            assert_eq!(observed(1, 1, anchor, &q, &r).unwrap(), anchor);
            let f = fixture(mode, 4, &[BootstrapScope::Wire]);
            let b = create(&f).unwrap().unwrap();
            assert!(b.source().is_none() && b.transcript().is_some() && b.release().is_none());
            assert!(b.parent(parent(&f, true, 9)).is_err());
        }
    }
    #[test]
    fn bootstrap_binding_caps_and_single_raw_frontier_before_allocation() {
        let f = fixture(Mode::System, 1, &[BootstrapScope::Source]);
        let b = create(&f).unwrap().unwrap();
        let held = f.peer.fds.reserve(64).unwrap();
        assert!(b.parent(parent(&f, false, 9)).is_err());
        drop(held);
        assert!(b.parent(parent(&f, false, 9)).is_ok());
        let mut wrong = parent(&f, false, 10);
        let extra = [f.path[0], f.path[0]];
        wrong.path = &extra;
        assert!(b.parent(wrong).is_err());
        assert_eq!(b.queries.lock().unwrap().len(), 1);
        let credit = f.budget.dynamic.reserve(1).unwrap();
        drop(credit);
        let limit = b.limit;
        for query in 10..(9 + limit as u64) {
            if b.parent(parent(&f, false, query)).is_err() {
                break;
            }
        }
        let count = b.queries.lock().unwrap().len();
        assert!(count <= limit);
        assert!(b.parent(parent(&f, false, 999)).is_err());
        assert_eq!(b.queries.lock().unwrap().len(), count);
    }
}
