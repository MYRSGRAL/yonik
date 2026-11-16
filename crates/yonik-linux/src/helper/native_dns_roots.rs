//! CODEC4 source scope: actual parent/retained snapshot, отдельно от Direct wire.
use super::super::LaunchRecord;
use super::*;
pub(in crate::helper::native_profile_channel) struct Parent<'a> {
    pub root: wire::dns_v2::Root,
    pub launch: LaunchRecord,
    pub query: u64,
    pub selector: wire::dns_v2::BootstrapSelector,
    pub original: wire::Destination<'a>,
    pub path: &'a [(u16, u8)],
}
impl Parent<'_> {
    // Ограничивает callback DATA; actual parent/custody проверяет только Source.
    fn checked(self) -> Result<Self, ServiceError> {
        self.launch.encode().map_err(unavailable)?;
        let kind_matches = match self.root {
            wire::dns_v2::Root::BootstrapService(_) => self.selector.resolver.is_some(),
            wire::dns_v2::Root::HostsPath => self.selector.resolver.is_none(),
            wire::dns_v2::Root::UserDns(_) => false,
        };
        if !kind_matches
            || self.query == 0
            || self.query == u64::MAX
            || self.selector.endpoint == u16::MAX
            || self.selector.subject == u16::MAX
            || self.original.family != 3
            || !matches!(self.original.protocol, 6 | 17)
            || self.original.port == 0
            || !(1..=253).contains(&self.original.bytes.len())
            || !(1..=256).contains(&self.path.len())
            || self
                .path
                .iter()
                .any(|(scope, branch)| *scope >= 512 || *branch > 1)
        {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(self)
    }
}
pub(in crate::helper::native_profile_channel) struct HostsChoice {
    pub row: u16,
    pub members: [u16; 256],
    pub count: u16,
    pub key: [u8; 253],
    pub key_len: u16,
    pub expires: Instant,
}
pub(in crate::helper::native_profile_channel) struct Question {
    pub bytes: [u8; 253],
    pub len: u16,
    pub expires: Instant,
}
/// Trusted CODEC4 bootstrap/choice + retained source custody. Production factory
/// пока None: DirectUserDns record не разрешает реализацию этого scope.
pub(in crate::helper::native_profile_channel) trait Source:
    Send + Sync
{
    fn parent(&self, parent: Parent<'_>) -> Result<Instant, ServiceError>;
    fn snapshot(
        &self,
        launch: LaunchRecord,
        reference: wire::SnapshotRef,
    ) -> Result<Instant, ServiceError>;
    fn hosts(
        &self,
        parent: Parent<'_>,
        reference: wire::SnapshotRef,
    ) -> Result<HostsChoice, ServiceError>;
    fn question(
        &self,
        parent: Parent<'_>,
        reference: wire::SnapshotRef,
        qtype: u16,
        options: u16,
        payload: u16,
    ) -> Result<Question, ServiceError>;
}
pub(super) struct DirectSystemTransportPermit {
    pub(super) peer: Target,
    pub(super) ticket: Option<u64>,
}
pub(super) struct Context {
    pub(super) acked: bool,
    invalid: AtomicBool,
    selector: wire::dns_v2::BootstrapSelector,
    reference: wire::SnapshotRef,
    original: Target,
    question: Option<Target>,
    pub(super) permit: Option<DirectSystemTransportPermit>,
}
pub(super) struct Observation {
    reservation: u64,
    context: u64,
    revision: u64,
    request: u64,
    expires: Instant,
    revoked: bool,
    acked: bool,
    choice: HostsChoice,
    // Полный path/source остаётся retained и после cancel/context teardown.
    _parent: Box<[DnsHopPermit]>,
    _reference: wire::SnapshotRef,
    _original: Target,
    pending: Option<super::super::super::memory::ByteLease>,
    _memory: super::super::super::memory::ByteLease,
}
impl<A: Authority> Issuer<A> {
    fn source_result<T>(
        &self,
        context: u64,
        result: Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        if result.is_err() {
            if let Some(c) = self
                .dns
                .live
                .get(&context)
                .and_then(|b| b.bootstrap.as_ref())
            {
                c.invalid.store(true, Ordering::Release);
            }
        }
        result
    }
    pub(in crate::helper::native_profile_channel) fn dns_reservation_original(
        &self,
        binding: super::super::dns_transport::Binding,
    ) -> Result<Target, ServiceError> {
        if !binding.bootstrap {
            return Ok(binding.name);
        }
        self.dns
            .live
            .get(&binding.bundle)
            .and_then(|b| b.bootstrap.as_ref())
            .map(|c| c.original)
            .ok_or(ServiceError::Unavailable)
    }
    fn root_source(&self) -> Result<&dyn Source, ServiceError> {
        self.bootstrap_source
            .as_deref()
            .ok_or(ServiceError::Unsupported)
    }
    pub(in crate::helper::native_profile_channel) fn context_reply_live(
        &self,
        id: u64,
    ) -> Result<Instant, ServiceError> {
        if self
            .dns
            .live
            .get(&id)
            .is_some_and(|b| b.bootstrap.is_some())
        {
            self.bootstrap_live(id, false)
        } else {
            self.bundle_live(id)
        }
    }
    pub(in crate::helper::native_profile_channel) fn context_ready_at_arrival(
        &self,
        r: Record<'_>,
    ) -> bool {
        let Record::Reserve(v) = r else {
            return true;
        };
        if v.base().len() != 8 {
            return true;
        }
        let id = if u64_at(v.bytes(), 16) != 0 {
            u64_at(v.bytes(), 16)
        } else {
            let Some((id, _)) = self.dns.live.iter().find(|(_, b)| {
                b.query == u64_at(v.bytes(), 8) && b.root_kind == wire::dns_v2::Root::HostsPath
            }) else {
                return false;
            };
            *id
        };
        self.dns
            .live
            .get(&id)
            .and_then(|b| b.bootstrap.as_ref())
            .is_some_and(|c| c.acked)
    }
    pub(in crate::helper::native_profile_channel) fn bootstrap_live(
        &self,
        id: u64,
        acked: bool,
    ) -> Result<Instant, ServiceError> {
        self.fence()?;
        let b = self.dns.live.get(&id).ok_or(ServiceError::Unavailable)?;
        let c = b.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        if c.invalid.load(Ordering::Acquire)
            || acked && !c.acked
            || self.authority.now() >= b.expires
        {
            return Err(ServiceError::Unavailable);
        }
        if let wire::dns_v2::Root::BootstrapService(root) = b.root_kind {
            let g = self
                .services
                .get(&root.get())
                .ok_or(ServiceError::Unavailable)?;
            if g.selector
                != [
                    2,
                    c.selector.endpoint,
                    c.selector.subject,
                    c.selector.resolver.ok_or(ServiceError::InvalidRequest)?,
                ]
                || self.authority.now() >= g.expires
            {
                return Err(ServiceError::Unavailable);
            }
        }
        let mut path = [(0, 0); 256];
        for (i, h) in b.hops.iter().enumerate() {
            path[i] = (h.scope, h.branch);
        }
        let source = self.root_source()?;
        let checked = source.snapshot(self.record, c.reference).and_then(|until| {
            source
                .parent(
                    Parent {
                        root: b.root_kind,
                        launch: self.record,
                        query: b.query,
                        selector: c.selector,
                        original: c.original.wire(),
                        path: &path[..b.hops.len()],
                    }
                    .checked()?,
                )
                .map(|parent| until.min(parent))
        });
        match checked {
            Ok(until) if self.authority.now() < until => Ok(b.expires.min(until)),
            _ => {
                c.invalid.store(true, Ordering::Release);
                Err(ServiceError::Unavailable)
            }
        }
    }
    pub(in crate::helper::native_profile_channel) fn acquire_bootstrap(
        &mut self,
        request: u64,
        v: View<'_, 55>,
        session: Instant,
    ) -> Result<u64, ServiceError> {
        self.fence()?;
        let now = self.authority.now();
        let b = v.bytes();
        let kind = v.root().map_err(unavailable)?;
        let selector = v
            .selector()
            .map_err(unavailable)?
            .ok_or(ServiceError::InvalidRequest)?;
        if u64_at(b, 24) != self.record.binding.epoch
            || self.retired.iter().any(|(id, _)| *id == request)
        {
            return Err(ServiceError::Unavailable);
        }
        let count = usize::from(u16_at(b, 50));
        let memory = self
            .budget
            .dynamic
            .reserve(
                std::mem::size_of::<Bundle>()
                    + std::mem::size_of::<Context>()
                    + 80
                    + count * std::mem::size_of::<DnsHopPermit>(),
            )
            .map_err(unavailable)?;
        let route_credit = self
            .budget
            .routes
            .reserve(usize::from(selector.resolver.is_some()))
            .map_err(unavailable)?;
        self.bundle_history(count + 1)?;
        let owned = Arc::clone(&self.capsule);
        let cap = wire::Capsule::decode(owned.bytes(), &self.record.binding.digest)
            .map_err(unavailable)?;
        let snapshot = cap.bootstrap_snapshot().map_err(unavailable)?;
        if !snapshot.bootstrap() {
            return Err(ServiceError::Unsupported);
        }
        let reference = snapshot.asset_reference();
        let original = Target::copy(cap.endpoint(selector.endpoint).map_err(unavailable)?)?;
        if original.family != 3 || original.wire().bytes != v.original() {
            return Err(ServiceError::InvalidRequest);
        }
        let mut path = [(0, 0); 256];
        let mut expected = None;
        let mut input = None;
        let mut seen = [[false; 2]; 512];
        let mut hops = Vec::with_capacity(count);
        for (i, (scope, branch)) in v.path().enumerate() {
            if let Some((next, mask)) = expected {
                if scope != next || mask & (1 << branch) == 0 {
                    return Err(ServiceError::InvalidRequest);
                }
            }
            let d = cap.dial_scope(scope, branch).map_err(unavailable)?;
            if seen[usize::from(scope)][usize::from(branch)] || input.is_some_and(|n| n != d.input)
            {
                return Err(ServiceError::InvalidRequest);
            }
            seen[usize::from(scope)][usize::from(branch)] = true;
            path[i] = (scope, branch);
            if (i + 1 < count) != d.next.is_some() {
                return Err(ServiceError::InvalidRequest);
            }
            if i + 1 == count
                && (d.action != 1
                    || d.subject != selector.subject
                    || d.endpoint_index != selector.endpoint
                    || d.carrier != original.protocol)
            {
                return Err(ServiceError::InvalidRequest);
            }
            expected = d.next;
            input = Some(d.carrier);
            hops.push(DnsHopPermit {
                bundle: 0,
                index: i as u16,
                expires: now,
                scope,
                branch,
                subject: d.subject,
                chain: d.chain,
                stream: d.stream,
                carrier: d.carrier,
                endpoint: d.endpoint_index,
                ticket: None,
            });
        }
        let source = self.root_source()?;
        let mut expires = source
            .snapshot(self.record, reference)?
            .min(
                source.parent(
                    Parent {
                        root: kind,
                        launch: self.record,
                        query: u64_at(b, 16),
                        selector,
                        original: original.wire(),
                        path: &path[..count],
                    }
                    .checked()?,
                )?,
            )
            .min(session)
            .min(now + Duration::from_nanos(u64_at(b, 40)));
        let mut peer = None;
        let mut question = None;
        match kind {
            wire::dns_v2::Root::BootstrapService(root) => {
                let grant = self
                    .services
                    .get(&root.get())
                    .ok_or(ServiceError::Unavailable)?;
                let resolver = selector.resolver.ok_or(ServiceError::InvalidRequest)?;
                if grant.selector != [2, selector.endpoint, selector.subject, resolver]
                    || now >= grant.expires
                {
                    return Err(ServiceError::InvalidRequest);
                }
                let row = cap.resolver_scope(resolver).map_err(unavailable)?;
                cap.bootstrap_query(selector.endpoint, selector.subject, resolver)
                    .map_err(unavailable)?;
                if row.source != reference.source
                    || row.subject != u16::MAX
                    || row.scope.is_some()
                    || row.peer.family == 3
                {
                    return Err(ServiceError::Unsupported);
                }
                reject_unproved_stub(row.peer)?;
                expires = expires.min(grant.expires);
                peer = Some(Target::copy(row.peer)?);
                let selected = source.question(
                    Parent {
                        root: kind,
                        launch: self.record,
                        query: u64_at(b, 16),
                        selector,
                        original: original.wire(),
                        path: &path[..count],
                    }
                    .checked()?,
                    reference,
                    u16_at(b, 52),
                    u16_at(b, 54),
                    u16_at(b, 56),
                )?;
                if selected.len == 0 || selected.len > 253 {
                    return Err(ServiceError::InvalidRequest);
                }
                let key = std::str::from_utf8(&selected.bytes[..usize::from(selected.len)])
                    .map_err(unavailable)?;
                wire::resolver_name(key, false, true).map_err(unavailable)?;
                question = Some(Target::host(key, 53)?);
                expires = expires.min(selected.expires);
            }
            wire::dns_v2::Root::HostsPath => {}
            _ => return Err(ServiceError::InvalidRequest),
        }
        let mut hash = Sha256::new();
        hash.update(b"YNK-CODEC4-ROOT\0");
        hash.update(self.record.manifest);
        hash.update(&b[..32]);
        hash.update(&b[48..64]);
        hash.update(&b[72..]);
        hash.update(reference.source);
        hash.update(reference.asset);
        if let Some(q) = question {
            hash.update(q.wire().bytes);
        }
        let fingerprint = hash.finalize().into();
        let (id, revision) =
            if let Some((context, revision)) = v.context_renewal().map_err(unavailable)? {
                let id = match context {
                    wire::dns_v2::DnsContext::Network(id) => id.get(),
                    wire::dns_v2::DnsContext::HostsPath(id) => id.get(),
                };
                let old = self.dns.live.get(&id).ok_or(ServiceError::Unavailable)?;
                if old.root_kind != kind
                    || old.revision != revision.get()
                    || old.fingerprint != fingerprint
                    || old.previous.is_some()
                    || self.transport.references(id)
                    || self.dns.observations.values().any(|o| o.context == id)
                {
                    return Err(ServiceError::InvalidRequest);
                }
                self.bootstrap_live(id, true)?;
                expires = expires.min(old.expires);
                (
                    id,
                    old.revision
                        .checked_add(1)
                        .filter(|n| *n != u64::MAX)
                        .ok_or(ServiceError::Busy)?,
                )
            } else {
                if self.dns.live.len() + self.grants.len() + self.services.len()
                    >= cap.limits()[0] as usize
                {
                    return Err(ServiceError::Busy);
                }
                (self.dns.allocate(kind, u64_at(b, 16))?, 1)
            };
        if self.authority.now() >= expires {
            return Err(ServiceError::Unavailable);
        }
        for h in &mut hops {
            h.bundle = id;
            h.expires = expires;
        }
        let previous = self.dns.live.remove(&id);
        self.dns.live.insert(
            id,
            Box::new(Bundle {
                root_kind: kind,
                bootstrap: Some(Box::new(Context {
                    acked: false,
                    invalid: AtomicBool::new(false),
                    selector,
                    reference,
                    original,
                    question,
                    permit: peer.map(|peer| DirectSystemTransportPermit { peer, ticket: None }),
                })),
                base_hash: Sha256::digest(v.base()).into(),
                qtype: u16_at(b, 52),
                options: u16_at(b, 54),
                payload: u16_at(b, 56),
                resolver: u16_at(b, 60),
                root: u64_at(b, 8),
                query: u64_at(b, 16),
                request,
                revision,
                fingerprint,
                expires,
                hops,
                previous,
                _memory: memory,
                _routes: route_credit,
            }),
        );
        if let Some(peer) = peer {
            match self
                .authority
                .service(cap.manifest, RouteRequest::Dns(peer.wire()))
            {
                Ok(ticket) => {
                    self.dns
                        .live
                        .get_mut(&id)
                        .and_then(|b| b.bootstrap.as_mut())
                        .and_then(|c| c.permit.as_mut())
                        .ok_or(ServiceError::Unavailable)?
                        .ticket = ticket
                }
                Err(e) => {
                    self.unknown = true;
                    self.authority.revoke();
                    return Err(e);
                }
            }
        }
        if let Err(error) = self.bootstrap_live(id, false) {
            let mut current = self.dns.live.remove(&id).ok_or(ServiceError::Unavailable)?;
            let old = current.previous.take();
            if self.retire_bundle_value(&mut current).is_err() {
                current.previous = old;
                self.dns.live.insert(id, current);
                return Err(ServiceError::Unavailable);
            }
            if let Some(old) = old {
                self.dns.live.insert(id, old);
            }
            return Err(error);
        }
        let mut current = self.dns.live.remove(&id).ok_or(ServiceError::Unavailable)?;
        if let Some(old) = current.previous.as_mut() {
            if let Err(e) = self.retire_bundle_value(old) {
                self.dns.live.insert(id, current);
                return Err(e);
            }
        }
        current.previous = None;
        self.dns.live.insert(id, current);
        Ok(id)
    }
    pub(in crate::helper::native_profile_channel) fn bootstrap_binding(
        &self,
        id: u64,
        expires: Instant,
    ) -> Result<super::super::dns_transport::Binding, ServiceError> {
        let b = self.dns.live.get(&id).ok_or(ServiceError::Unavailable)?;
        let c = b.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        let permit = c.permit.as_ref().ok_or(ServiceError::Unsupported)?;
        let terminal = b.hops.last().ok_or(ServiceError::Unavailable)?;
        Ok(super::super::dns_transport::Binding {
            bootstrap: true,
            parent_carrier: c.original.protocol,
            proxied: false,
            physical_peer: permit.peer,
            physical_scope: terminal.scope,
            physical_subject: terminal.subject,
            physical_endpoint: c.selector.endpoint,
            physical_branch: terminal.branch,
            physical_hop: terminal.index,
            bundle: id,
            revision: b.revision,
            root: b.root,
            query: b.query,
            epoch: self.record.binding.epoch,
            source: 0,
            source_revision: 0,
            resolver: b.resolver,
            subject: c.selector.subject,
            scope: terminal.scope,
            branch: terminal.branch,
            qtype: b.qtype,
            options: b.options,
            payload: b.payload,
            base: b.base_hash,
            name: c.question.ok_or(ServiceError::Unsupported)?,
            peer: permit.peer,
            ticket: permit.ticket,
            expires,
        })
    }
    pub(in crate::helper::native_profile_channel) fn cancel_host_observations(
        &mut self,
        context: u64,
    ) {
        for o in self
            .dns
            .observations
            .values_mut()
            .filter(|o| o.context == context)
        {
            o.revoked = true;
            o.pending.take();
        }
    }
    pub(in crate::helper::native_profile_channel) fn cancel_host_request(&mut self, request: u64) {
        for o in self
            .dns
            .observations
            .values_mut()
            .filter(|o| o.request == request)
        {
            o.revoked = true;
            o.pending.take();
        }
    }
    pub(in crate::helper::native_profile_channel) fn cancel_host_reservation(
        &mut self,
        reservation: u64,
    ) -> bool {
        let mut found = false;
        for o in self
            .dns
            .observations
            .values_mut()
            .filter(|o| o.reservation == reservation)
        {
            o.revoked = true;
            o.pending.take();
            found = true;
        }
        found
    }
    pub(in crate::helper::native_profile_channel) fn host_observation_live(
        &self,
        id: u64,
    ) -> Result<Instant, ServiceError> {
        let o = self
            .dns
            .observations
            .get(&id)
            .ok_or(ServiceError::Unavailable)?;
        let b = self
            .dns
            .live
            .get(&o.context)
            .ok_or(ServiceError::Unavailable)?;
        if o.revoked
            || b.root_kind != wire::dns_v2::Root::HostsPath
            || b.revision != o.revision
            || self.authority.now() >= o.expires
            || o.choice.count == 0
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(o.expires.min(self.bootstrap_live(o.context, true)?))
    }
    pub(in crate::helper::native_profile_channel) fn ack_host_observation(
        &mut self,
        id: u64,
    ) -> Result<(), ServiceError> {
        self.host_observation_live(id)?;
        let o = self
            .dns
            .observations
            .get_mut(&id)
            .ok_or(ServiceError::Unavailable)?;
        o.acked = true;
        o.pending.take();
        Ok(())
    }
    pub(in crate::helper::native_profile_channel) fn deny_host_observation(&mut self, id: u64) {
        if let Some(o) = self.dns.observations.get_mut(&id) {
            o.revoked = true;
            o.pending.take();
        }
    }
    pub(in crate::helper::native_profile_channel) fn reserve_hosts(
        &mut self,
        v: View<'_, 35>,
        request: u64,
        socket: &impl Channel,
        session: Instant,
    ) -> Result<super::super::dns_transport::Reply, ServiceError> {
        self.fence()?;
        let bytes = v.bytes();
        let query = u64_at(bytes, 8);
        let mut matches = self
            .dns
            .live
            .iter()
            .filter(|(_, b)| b.query == query && b.root_kind == wire::dns_v2::Root::HostsPath);
        let (context, b) = matches.next().ok_or(ServiceError::Unavailable)?;
        if matches.next().is_some() {
            return Err(ServiceError::InvalidRequest);
        }
        let context = *context;
        let c = b.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        let terminal = b.hops.last().ok_or(ServiceError::Unavailable)?;
        if v.bootstrap_selector().map_err(unavailable)? != Some(c.selector)
            || u64_at(bytes, 48) != self.record.binding.epoch
            || u16_at(bytes, 66) != c.selector.subject
            || u16_at(bytes, 68) != c.selector.endpoint
            || u16_at(bytes, 70) != terminal.scope
            || bytes[79] != terminal.branch
            || bytes[76] != c.original.protocol
            || v.original() != c.original.wire().bytes
        {
            return Err(ServiceError::InvalidRequest);
        }
        let mut expires = self
            .bootstrap_live(context, true)?
            .min(session)
            .min(self.authority.now() + Duration::from_nanos(u64_at(bytes, 56)));
        if self.dns.observations.len() >= 64 {
            return Err(ServiceError::Busy);
        }
        let (revision, reference, original, selector, root) =
            (b.revision, c.reference, c.original, c.selector, b.root_kind);
        let memory = self
            .budget
            .dynamic
            .reserve(
                std::mem::size_of::<Observation>()
                    + 80
                    + b.hops.len() * std::mem::size_of::<DnsHopPermit>(),
            )
            .map_err(unavailable)?;
        let scratch = self.budget.dynamic.reserve(8192).map_err(unavailable)?;
        let mut path = [(0, 0); 256];
        for (i, h) in b.hops.iter().enumerate() {
            path[i] = (h.scope, h.branch);
        }
        let count = b.hops.len();
        self.bundle_history(1)?;
        let pending = socket.take_dns_credit(request)?;
        let parent = self
            .dns
            .live
            .get(&context)
            .ok_or(ServiceError::Unavailable)?
            .hops
            .clone()
            .into_boxed_slice();
        let source = self.root_source()?;
        expires =
            expires.min(self.source_result(context, source.snapshot(self.record, reference))?);
        let choice = self.source_result(
            context,
            source.hosts(
                Parent {
                    root,
                    launch: self.record,
                    query,
                    selector,
                    original: original.wire(),
                    path: &path[..count],
                }
                .checked()?,
                reference,
            ),
        )?;
        if choice.count == 0
            || choice.count > 256
            || choice.key_len == 0
            || choice.key_len > 253
            || choice.row >= 4096
        {
            return self.source_result(context, Err(ServiceError::InvalidRequest));
        }
        let key = self.source_result(
            context,
            std::str::from_utf8(&choice.key[..usize::from(choice.key_len)]).map_err(unavailable),
        )?;
        self.source_result(
            context,
            wire::resolver_name(key, key.contains('.'), true).map_err(unavailable),
        )?;
        let mut seen = [0u64; 1024];
        for index in &choice.members[..usize::from(choice.count)] {
            let word = usize::from(*index) / 64;
            let bit = 1u64 << (*index % 64);
            if seen[word] & bit != 0 {
                return self.source_result(context, Err(ServiceError::InvalidRequest));
            }
            seen[word] |= bit;
        }
        expires = expires
            .min(choice.expires)
            .min(self.source_result(context, source.snapshot(self.record, reference))?)
            .min(self.bootstrap_live(context, true)?);
        if self.authority.now() >= expires || self.retired.iter().any(|(id, _)| *id == request) {
            return Err(ServiceError::Unavailable);
        }
        let reservation = self.host_reservation_id()?;
        let id = Self::id(&mut self.dns.next_observation)?;
        self.dns.observations.insert(
            id,
            Box::new(Observation {
                reservation,
                context,
                revision,
                request,
                expires,
                revoked: false,
                acked: false,
                choice,
                _parent: parent,
                _reference: reference,
                _original: original,
                pending: Some(pending),
                _memory: memory,
            }),
        );
        drop(scratch);
        Ok(super::super::dns_transport::Reply::hosts(
            request,
            expires,
            reservation,
            id,
            query,
            self.record.binding.epoch,
        ))
    }
}
#[cfg(test)]
#[path = "native_dns_roots_tests.rs"]
mod tests;
