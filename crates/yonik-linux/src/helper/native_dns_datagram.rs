//! CODEC5: USER datagram lineage отдельно от TCP/service/DNS authority.
use super::*;

const CONTRACT: &[u8] = b"udp-bootstrap-consumed-parent-member-send-v1\0";

/// Три независимых scope5: Source/parent не создаёт wire или release authority.
struct NetworkScope {
    installed: Option<Arc<bootstrap_binding::BootstrapBinding>>,
    #[cfg(test)]
    injected: Option<Box<InjectedScope>>,
}
#[cfg(test)]
struct InjectedScope {
    launch: LaunchRecord,
    schema: [u8; 32],
    contract: [u8; 32],
}
impl NetworkScope {
    fn check(&self, launch: LaunchRecord, contract: &[u8]) -> Result<(), ServiceError> {
        if let Some(binding) = &self.installed {
            let scope = if contract == NETWORK_WIRE {
                super::super::registry::BootstrapScope::Wire
            } else if contract == NETWORK_RELEASE {
                super::super::registry::BootstrapScope::Release
            } else if contract == CONTRACT {
                super::super::registry::BootstrapScope::Source
            } else {
                return Err(ServiceError::Unsupported);
            };
            return binding.datagram_check(scope, launch);
        }
        #[cfg(test)]
        if let Some(p) = &self.injected {
            if p.launch == launch
                && p.schema == <[u8; 32]>::from(Sha256::digest(wire::dns_v2::DATAGRAM_SCHEMA))
                && p.contract == <[u8; 32]>::from(Sha256::digest(contract))
            {
                return Ok(());
            }
        }
        Err(ServiceError::Unsupported)
    }
    #[cfg(test)]
    fn fake(launch: LaunchRecord, contract: &[u8]) -> Self {
        Self {
            installed: None,
            injected: Some(Box::new(InjectedScope {
                launch,
                schema: Sha256::digest(wire::dns_v2::DATAGRAM_SCHEMA).into(),
                contract: Sha256::digest(contract).into(),
            })),
        }
    }
    fn installed(
        binding: Arc<bootstrap_binding::BootstrapBinding>,
        _launch: LaunchRecord,
        _contract: &[u8],
    ) -> Self {
        Self {
            installed: Some(binding),
            #[cfg(test)]
            injected: None,
        }
    }
}
const NETWORK_WIRE: &[u8] = b"udp-bootstrap-bound-dns-transcript-v1\0";
const NETWORK_RELEASE: &[u8] = b"udp-bootstrap-dns-consuming-close-join-v1\0";
pub(super) struct NetworkWire {
    scope: NetworkScope,
    transcript: Arc<dyn BootstrapDnsTranscript>,
}
pub(super) struct NetworkRelease {
    scope: NetworkScope,
}
impl NetworkWire {
    pub(super) fn installed(
        binding: Arc<bootstrap_binding::BootstrapBinding>,
        launch: LaunchRecord,
    ) -> Arc<Self> {
        Arc::new(Self {
            scope: NetworkScope::installed(binding.clone(), launch, NETWORK_WIRE),
            transcript: binding,
        })
    }
    fn check(&self, launch: LaunchRecord) -> Result<(), ServiceError> {
        self.scope.check(launch, NETWORK_WIRE)
    }
    fn observed(
        &self,
        launch: LaunchRecord,
        receipt: BootstrapDnsReceipt<'_>,
    ) -> Result<Instant, ServiceError> {
        self.check(launch)?;
        if !receipt.binding.bootstrap
            || receipt.binding.proxied
            || receipt.binding.parent_carrier != 17
        {
            return Err(ServiceError::Unsupported);
        }
        let anchor = receipt.lifetime_anchor;
        let observed = self.transcript.observed(launch, receipt)?;
        if observed != anchor {
            return Err(ServiceError::Unavailable);
        }
        Ok(anchor)
    }
    #[cfg(test)]
    pub(super) fn fake(
        launch: LaunchRecord,
        transcript: Arc<dyn BootstrapDnsTranscript>,
    ) -> Arc<Self> {
        Arc::new(Self {
            scope: NetworkScope::fake(launch, NETWORK_WIRE),
            transcript,
        })
    }
}
impl NetworkRelease {
    pub(super) fn installed(
        binding: Arc<bootstrap_binding::BootstrapBinding>,
        launch: LaunchRecord,
    ) -> Arc<Self> {
        Arc::new(Self {
            scope: NetworkScope::installed(binding, launch, NETWORK_RELEASE),
        })
    }
    fn check(&self, launch: LaunchRecord) -> Result<(), ServiceError> {
        self.scope.check(launch, NETWORK_RELEASE)
    }
    #[cfg(test)]
    pub(super) fn fake(launch: LaunchRecord) -> Arc<Self> {
        Arc::new(Self {
            scope: NetworkScope::fake(launch, NETWORK_RELEASE),
        })
    }
}

/// Закрытый scope5: installed constructor требует checked Binding5.
/// Source4/descriptor/child metadata не могут создать этот тип.
pub(super) struct Producer {
    scope: NetworkScope,
    source: Arc<dyn dns_bundle::roots::Source>,
}
impl Producer {
    pub(super) fn installed(
        binding: Arc<bootstrap_binding::BootstrapBinding>,
        launch: LaunchRecord,
    ) -> Arc<Self> {
        Arc::new(Self {
            scope: NetworkScope::installed(binding.clone(), launch, CONTRACT),
            source: binding,
        })
    }
    pub(super) fn check(&self, launch: LaunchRecord) -> Result<(), ServiceError> {
        self.scope.check(launch, CONTRACT)
    }
    pub(super) fn source(
        &self,
        launch: LaunchRecord,
    ) -> Result<&dyn dns_bundle::roots::Source, ServiceError> {
        self.check(launch)?;
        Ok(self.source.as_ref())
    }
    #[cfg(test)]
    pub(super) fn fake(
        launch: LaunchRecord,
        source: Arc<dyn dns_bundle::roots::Source>,
    ) -> Arc<Self> {
        Arc::new(Self {
            scope: NetworkScope::fake(launch, CONTRACT),
            source,
        })
    }
}

pub(super) struct Lineage {
    pub(super) binding: Arc<UdpBinding>,
    pub(super) launch: LaunchRecord,
    pub(super) namespace: (u64, u64),
}
impl Lineage {
    fn check(
        &self,
        launch: LaunchRecord,
        source: u64,
        tuple: Tuple,
        original: Target,
        now: Instant,
    ) -> Result<Instant, ServiceError> {
        let b = &self.binding;
        if self.launch != launch
            || self.namespace.0 == 0
            || self.namespace.1 == 0
            || !b.live.load(Ordering::Acquire)
            || b.source.load(Ordering::Acquire) != source
            || tuple.protocol != 17
            || original.protocol != 17
            || b.record.original != original
            || b.record.packet.tuple != tuple
            || now >= b.record.expires
            || b.record.packet.association == 0
            || b.record.packet.packet == 0
            || b.record.packet.permit == 0
            || b.record.packet.cookie == 0
            || b.record.packet.fingerprint == [0; 32]
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(b.record.expires)
    }
}
#[derive(PartialEq, Eq)]
enum ParentState {
    Preparing,
    Active,
    Closed,
    Unknown,
}
struct ParentBinding {
    grant: u64,
    source: u64,
    revision: u64,
    scope: u16,
    branch: u8,
    query: u64,
    request: u64,
    parent_request: u64,
    expires: Instant,
    state: ParentState,
    context: Option<u64>,
    lineage: Option<Lineage>,
    _memory: super::super::memory::ByteLease,
}
pub(super) struct Datagrams {
    pub(super) producer: Option<Arc<Producer>>,
    pub(super) wire: Option<Arc<NetworkWire>>,
    pub(super) release: Option<Arc<NetworkRelease>>,
    parents: Parents,
    next: u64,
}
impl Datagrams {
    pub(super) fn new() -> Self {
        Self {
            producer: None,
            wire: None,
            release: None,
            parents: Parents(Vec::new()),
            next: 0,
        }
    }
}
// IDs — последовательные nonreuse slots. Один ledger вместо двух BTreeMap:
// нет map nodes/дублирующего query index; query scan жёстко ограничен history256.
struct Parents(Vec<ParentBinding>);
impl Parents {
    fn get(&self, id: &u64) -> Option<&ParentBinding> {
        self.0.get(usize::try_from(id.checked_sub(1)?).ok()?)
    }
    fn get_mut(&mut self, id: &u64) -> Option<&mut ParentBinding> {
        self.0.get_mut(usize::try_from(id.checked_sub(1)?).ok()?)
    }
    fn query(&self, q: u64) -> Option<u64> {
        self.0
            .iter()
            .position(|p| p.query == q)
            .map(|i| i as u64 + 1)
    }
    fn reserve(&mut self) -> Result<(), ServiceError> {
        self.0.try_reserve_exact(1).map_err(unavailable)
    }
    fn iter(&self) -> impl Iterator<Item = (u64, &ParentBinding)> {
        self.0.iter().enumerate().map(|(i, p)| (i as u64 + 1, p))
    }
}
impl<A: Authority> Issuer<A> {
    pub(super) fn datagram_network_ready(&self, query: u64) -> Result<(), ServiceError> {
        self.datagram_query(query)?;
        self.datagrams
            .wire
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .check(self.record)?;
        self.datagram_network_release()
    }
    pub(super) fn datagram_network_release(&self) -> Result<(), ServiceError> {
        self.datagrams
            .release
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .check(self.record)
    }
    pub(super) fn datagram_response_observed(
        &self,
        receipt: BootstrapDnsReceipt<'_>,
    ) -> Result<Instant, ServiceError> {
        self.datagram_network_ready(receipt.binding.query)?;
        self.datagrams
            .wire
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .observed(self.record, receipt)
    }
    pub(super) fn datagram_parent_live(
        &self,
        id: u64,
        acked: bool,
    ) -> Result<Instant, ServiceError> {
        self.fence()?;
        self.datagrams
            .producer
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .source(self.record)?;
        let p = self
            .datagrams
            .parents
            .get(&id)
            .ok_or(ServiceError::Unavailable)?;
        if (acked && p.state != ParentState::Active)
            || matches!(p.state, ParentState::Closed | ParentState::Unknown)
            || self.authority.now() >= p.expires
            || self.retired.iter().any(|(r, _)| *r == p.request)
        {
            return Err(ServiceError::Unavailable);
        }
        let g = self.grants.get(&p.grant).ok_or(ServiceError::Unavailable)?;
        let f = self.flows.get(&p.source).ok_or(ServiceError::Unavailable)?;
        if !g.sent.load(Ordering::Acquire)
            || g.class != 1
            || g.numeric.is_some()
            || f.numeric_only
            || g.source != p.source
            || g.request != p.parent_request
            || g.scope != p.scope
            || g.branch != p.branch
            || p.revision != self.capsule()?.policy_revision
            || f.tuple.protocol != 17
            || f.original.protocol != 17
            || self.authority.now() >= g.expires
        {
            return Err(ServiceError::Unavailable);
        }
        self.authority.check_ingress(&f.socket)?;
        if p.lineage
            .as_ref()
            .is_none_or(|l| l.binding.principal != f.subject)
        {
            return Err(ServiceError::Unavailable);
        }
        let until = p.lineage.as_ref().ok_or(ServiceError::Unavailable)?.check(
            self.record,
            p.source,
            f.tuple,
            f.original,
            self.authority.now(),
        )?;
        Ok(p.expires.min(g.expires).min(until))
    }
    pub(super) fn bind_datagram_parent(
        &mut self,
        request: u64,
        view: wire::dns_v2::View<'_, 57>,
        session: Instant,
    ) -> Result<u64, ServiceError> {
        self.fence()?;
        if !self.negotiated.is_some_and(|n| n.datagram())
            || self.retired.iter().any(|(r, _)| *r == request)
        {
            return Err(ServiceError::Unavailable);
        }
        self.datagrams
            .producer
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .check(self.record)?;
        let b = view.bytes();
        let query = u64::from_be_bytes(b[8..16].try_into().map_err(unavailable)?);
        let grant = u64::from_be_bytes(b[16..24].try_into().map_err(unavailable)?);
        let source = u64::from_be_bytes(b[24..32].try_into().map_err(unavailable)?);
        let revision = u64::from_be_bytes(b[32..40].try_into().map_err(unavailable)?);
        let epoch = u64::from_be_bytes(b[40..48].try_into().map_err(unavailable)?);
        let scope = u16::from_be_bytes([b[48], b[49]]);
        let branch = b[50];
        if epoch != self.record.binding.epoch
            || revision != self.capsule()?.policy_revision
            || self.datagrams.parents.query(query).is_some()
            || self.datagrams.next >= 256
        {
            return Err(ServiceError::InvalidRequest);
        }
        let memory = self
            .budget
            .dynamic
            // Один contiguous slot, без map nodes/второго index/Box allocation.
            .reserve(std::mem::size_of::<ParentBinding>() + 16)
            .map_err(unavailable)?;
        self.bundle_history_available(1)?;
        let g = self
            .grants
            .get(&grant)
            .ok_or(ServiceError::InvalidRequest)?;
        let f = self
            .flows
            .get(&source)
            .ok_or(ServiceError::InvalidRequest)?;
        let cap = self.capsule()?;
        let d = cap.dial_scope(scope, branch).map_err(unavailable)?;
        if !g.sent.load(Ordering::Acquire)
            || g.class != 1
            || g.numeric.is_some()
            || f.numeric_only
            || g.source != source
            || g.scope != scope
            || g.branch != branch
            || g.subject != d.subject
            || cap.subject_kind(d.subject).map_err(unavailable)? != 2
            || g.stream != d.stream
            || g.chain != d.chain
            || g.next.is_some()
            || d.input != 17
            || d.carrier != 17
            || d.action != 1
            || d.next.is_some()
            // Raw SS UDP не применяет TCP stream: canonical projection хранит FFFF.
            || d.stream != u16::MAX
            || f.tuple.protocol != 17
            || f.original.protocol != 17
            || self.authority.now() >= g.expires
        {
            return Err(ServiceError::Unsupported);
        }
        self.authority.check_ingress(&f.socket)?;
        let lineage = self.authority.datagram_lineage(&f.socket, source)?;
        if lineage.binding.principal != f.subject {
            return Err(ServiceError::Unavailable);
        }
        let until = lineage.check(
            self.record,
            source,
            f.tuple,
            f.original,
            self.authority.now(),
        )?;
        let expires = until.min(g.expires).min(session).min(
            self.authority.now()
                + Duration::from_millis(u32::from_be_bytes(
                    b[52..56].try_into().map_err(unavailable)?,
                ) as u64),
        );
        let parent_request = g.request;
        if expires.saturating_duration_since(self.authority.now()) < Duration::from_millis(1) {
            return Err(ServiceError::Unavailable);
        }
        self.bundle_history(1)?;
        self.datagrams.parents.reserve()?;
        let id = Self::id(&mut self.datagrams.next)?;
        self.datagrams.parents.0.push(ParentBinding {
            grant,
            source,
            revision,
            scope,
            branch,
            query,
            request,
            parent_request,
            expires,
            state: ParentState::Preparing,
            context: None,
            lineage: Some(lineage),
            _memory: memory,
        });
        Ok(id)
    }
    pub(super) fn ack_datagram_parent(&mut self, id: u64) -> Result<(), ServiceError> {
        self.datagram_parent_live(id, false)?;
        let p = self
            .datagrams
            .parents
            .get_mut(&id)
            .ok_or(ServiceError::Unavailable)?;
        if p.state != ParentState::Preparing {
            return Err(ServiceError::Unavailable);
        }
        p.state = ParentState::Active;
        Ok(())
    }
    pub(super) fn cancel_datagram_parent(&mut self, id: u64) -> Result<(), ServiceError> {
        if let Some(context) = self.datagrams.parents.get(&id).and_then(|p| p.context) {
            self.cancel_dns_bundle(context)?;
        }
        let p = self
            .datagrams
            .parents
            .get_mut(&id)
            .ok_or(ServiceError::InvalidRequest)?;
        if p.state == ParentState::Unknown || self.unknown {
            p.state = ParentState::Unknown;
            return Err(ServiceError::Unavailable);
        }
        // Пока downstream context/permission не выданы, binding не владеет route/FD.
        // Query tombstone остаётся: ACK/cancel не разрешает повторное binding.
        p.state = ParentState::Closed;
        p.lineage.take();
        Ok(())
    }
    pub(super) fn cancel_datagram_matching(
        &mut self,
        grant: Option<u64>,
        request: Option<u64>,
    ) -> Result<(), ServiceError> {
        let mut ids = [0; 256];
        let mut count = 0;
        for (id, p) in self.datagrams.parents.iter() {
            if grant == Some(p.grant)
                || request == Some(p.request)
                || request == Some(p.parent_request)
            {
                *ids.get_mut(count).ok_or(ServiceError::Busy)? = id;
                count += 1;
            }
        }
        for id in &ids[..count] {
            self.cancel_datagram_parent(*id)?;
        }
        Ok(())
    }
    pub(super) fn datagram_bind_ready(&self, view: wire::dns_v2::View<'_, 57>) -> bool {
        view.parent_grant().is_ok_and(|id| {
            self.grants
                .get(&id.get())
                .is_some_and(|g| g.sent.load(Ordering::Acquire))
        })
    }
    pub(super) fn datagram_query(&self, query: u64) -> Result<u64, ServiceError> {
        let id = self
            .datagrams
            .parents
            .query(query)
            .ok_or(ServiceError::Unsupported)?;
        self.datagram_parent_live(id, true)?;
        if self
            .datagrams
            .parents
            .get(&id)
            .is_none_or(|p| p.query != query)
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(id)
    }
    pub(super) fn datagram_context(
        &self,
        query: u64,
        path: &[(u16, u8)],
        renewing: Option<u64>,
    ) -> Result<Instant, ServiceError> {
        let id = self.datagram_query(query)?;
        let p = self
            .datagrams
            .parents
            .get(&id)
            .ok_or(ServiceError::Unavailable)?;
        if path != [(p.scope, p.branch)] || p.context != renewing {
            return Err(ServiceError::InvalidRequest);
        }
        self.datagram_parent_live(id, true)
    }
    pub(super) fn datagram_context_committed(
        &mut self,
        query: u64,
        context: u64,
    ) -> Result<(), ServiceError> {
        let id = self.datagram_query(query)?;
        let p = self
            .datagrams
            .parents
            .get_mut(&id)
            .ok_or(ServiceError::Unavailable)?;
        if p.context.is_some_and(|old| old != context) {
            return Err(ServiceError::InvalidRequest);
        }
        p.context = Some(context);
        Ok(())
    }
    pub(super) fn datagram_source(
        &self,
        query: u64,
    ) -> Result<&dyn dns_bundle::roots::Source, ServiceError> {
        self.datagram_query(query)?;
        self.datagrams
            .producer
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .source(self.record)
    }
    pub(super) fn datagram_permission(
        &self,
        query: u64,
    ) -> Result<BootstrapDatagramPermission, ServiceError> {
        let parent = self.datagram_query(query)?;
        let p = self
            .datagrams
            .parents
            .get(&parent)
            .ok_or(ServiceError::Unavailable)?;
        if p.context.is_none()
            || p.lineage
                .as_ref()
                .is_none_or(|l| l.binding.bootstrap_spent.load(Ordering::Acquire))
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(BootstrapDatagramPermission {
            parent,
            query,
            source: p.source,
            epoch: self.record.binding.epoch,
        })
    }
    pub(super) fn datagram_permission_live(
        &self,
        p: &BootstrapDatagramPermission,
    ) -> Result<Instant, ServiceError> {
        if p.epoch != self.record.binding.epoch
            || self.datagram_query(p.query)? != p.parent
            || self
                .datagrams
                .parents
                .get(&p.parent)
                .is_none_or(|b| b.source != p.source)
        {
            return Err(ServiceError::Unavailable);
        }
        self.datagram_parent_live(p.parent, true)
    }
    pub(super) fn spend_datagram(
        &self,
        p: &BootstrapDatagramPermission,
    ) -> Result<(), ServiceError> {
        self.datagram_permission_live(p)?;
        let parent = self
            .datagrams
            .parents
            .get(&p.parent)
            .ok_or(ServiceError::Unavailable)?;
        parent
            .lineage
            .as_ref()
            .ok_or(ServiceError::Unavailable)?
            .binding
            .bootstrap_spent
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(unavailable)?;
        Ok(())
    }
}
/// Не TCP permission и не право DNS transport. Только один Consumed packet;
/// member/selector/source/frontier удерживаются immutable permission origin.
pub(super) struct BootstrapDatagramPermission {
    parent: u64,
    query: u64,
    source: u64,
    epoch: u64,
}
