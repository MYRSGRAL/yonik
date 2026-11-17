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
    pub(in crate::helper::native_profile_channel) fn checked(self) -> Result<Self, ServiceError> {
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
pub(in crate::helper::native_profile_channel) struct Member {
    pub address: std::net::IpAddr,
    pub expires: Instant,
}
/// Trusted CODEC4 choice/parent contract + retained source custody.
/// Production binding требует отдельного protected Source record/review pin.
pub(in crate::helper::native_profile_channel) trait Source:
    Send + Sync
{
    // Только held asset/source custody, не caller IP/hash или decoded DATA.
    fn member(
        &self,
        _: Parent<'_>,
        _: wire::SnapshotRef,
        _: u16,
        _: u16,
    ) -> Result<Member, ServiceError> {
        Err(ServiceError::Unsupported)
    }
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
    publish: Option<u64>,
    waiter: Option<u64>,
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
pub(super) struct HostsProducer {
    observation: u64,
    request: u64,
    expires: Instant,
    acked: bool,
    revoked: bool,
    _memory: super::super::super::memory::ByteLease,
}
pub(super) struct HostsWaiter {
    numeric_once: Option<(u64, u64)>,
    observation: u64,
    producer: u64,
    request: u64,
    expires: Instant,
    acked: bool,
    revoked: bool,
    _memory: super::super::super::memory::ByteLease,
}
impl<A: Authority> Issuer<A> {
    pub(in crate::helper::native_profile_channel) fn bootstrap_dns_data(
        &self,
        binding: super::super::dns_transport::Binding,
    ) -> Result<(wire::SnapshotRef, Instant), ServiceError> {
        if !binding.bootstrap || self.dns_transport_binding(binding.bundle)? != binding {
            return Err(ServiceError::Unavailable);
        }
        let b = self
            .dns
            .live
            .get(&binding.bundle)
            .ok_or(ServiceError::Unavailable)?;
        let c = b.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        let mut path = [(0, 0); 256];
        for (i, h) in b.hops.iter().enumerate() {
            path[i] = (h.scope, h.branch);
        }
        let source = self.root_source(b.query, c.original.protocol)?;
        let q = self.source_result(
            binding.bundle,
            source.question(
                Parent {
                    root: b.root_kind,
                    launch: self.record,
                    query: b.query,
                    selector: c.selector,
                    original: c.original.wire(),
                    path: &path[..b.hops.len()],
                }
                .checked()?,
                c.reference,
                b.qtype,
                b.options,
                b.payload,
            ),
        )?;
        if q.len == 0
            || usize::from(q.len) > q.bytes.len()
            || &q.bytes[..usize::from(q.len)] != binding.name.wire().bytes
        {
            return self.source_result(binding.bundle, Err(ServiceError::Unavailable));
        }
        let until = binding
            .expires
            .min(q.expires)
            .min(self.bootstrap_live(binding.bundle, true)?);
        if self.authority.now() >= until {
            return self.source_result(binding.bundle, Err(ServiceError::Unavailable));
        }
        Ok((c.reference, until))
    }
    pub(in crate::helper::native_profile_channel) fn bootstrap_dns_same_data(
        &self,
        a: u64,
        b: u64,
    ) -> Result<(), ServiceError> {
        self.bootstrap_live(a, true)?;
        self.bootstrap_live(b, true)?;
        let a = self.dns.live.get(&a).ok_or(ServiceError::Unavailable)?;
        let b = self.dns.live.get(&b).ok_or(ServiceError::Unavailable)?;
        let x = a.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        let y = b.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        if a.root_kind == wire::dns_v2::Root::HostsPath
            || b.root_kind == wire::dns_v2::Root::HostsPath
            || (
                x.reference.source,
                x.reference.asset,
                x.reference.bytes,
                x.reference.flags,
            ) != (
                y.reference.source,
                y.reference.asset,
                y.reference.bytes,
                y.reference.flags,
            )
            || x.selector != y.selector
            || x.original != y.original
            || x.question != y.question
            || a.hops.len() != b.hops.len()
            || a.hops.iter().zip(&b.hops).any(|(x, y)| {
                (
                    x.index, x.scope, x.branch, x.subject, x.chain, x.stream, x.carrier, x.endpoint,
                ) != (
                    y.index, y.scope, y.branch, y.subject, y.chain, y.stream, y.carrier, y.endpoint,
                )
            })
        {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(())
    }
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
    fn root_source(&self, query: u64, carrier: u8) -> Result<&dyn Source, ServiceError> {
        if carrier == 17 {
            return self.datagram_source(query);
        }
        if carrier != 6 {
            return Err(ServiceError::Unsupported);
        }
        if self.negotiated.is_some_and(|n| n.datagram()) {
            return self
                .bootstrap_tcp5
                .as_ref()
                .ok_or(ServiceError::Unsupported)?
                .source(self.record);
        }
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
        match r {
            Record::DatagramParentBind(v) => return self.datagram_bind_ready(v),
            Record::BundleAcquire(v) => {
                if let Ok(Some(selector)) = v.selector() {
                    if self
                        .capsule()
                        .and_then(|cap| {
                            cap.endpoint(selector.endpoint)
                                .map(|d| d.protocol)
                                .map_err(unavailable)
                        })
                        .is_ok_and(|p| p == 17)
                    {
                        return self.datagram_query(u64_at(v.bytes(), 16)).is_ok();
                    }
                }
            }
            Record::Publish(v) if v.bytes()[137] == 2 => {
                return self
                    .dns
                    .observations
                    .get(&u64_at(v.bytes(), 144 + 88))
                    .is_some_and(|o| {
                        o.acked && !o.revoked && o.publish.is_none() && o.waiter.is_none()
                    });
            }
            Record::WaiterBind(v) if self.is_hosts_reservation(u64_at(v.bytes(), 8)) => {
                return self.dns.observations.values().any(|o| {
                    o.reservation == u64_at(v.bytes(), 8)
                        && o.acked
                        && !o.revoked
                        && o.publish.is_none()
                        && o.waiter.is_none()
                }) && self
                    .dns
                    .hosts_producers
                    .get(&u64_at(v.bytes(), 16))
                    .is_some_and(|p| p.acked && !p.revoked);
            }
            _ => {}
        }
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
        let source = self.root_source(b.query, c.original.protocol)?;
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
        let fingerprint_for = |question: Option<Target>| {
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
            <[u8; 32]>::from(hash.finalize())
        };
        // Ошибка чужого renewal не должна инвалидировать существующий context.
        let renewing =
            if let Some((context, revision)) = v.context_renewal().map_err(unavailable)? {
                let id = match context {
                    wire::dns_v2::DnsContext::Network(id) => id.get(),
                    wire::dns_v2::DnsContext::HostsPath(id) => id.get(),
                };
                let old = self.dns.live.get(&id).ok_or(ServiceError::Unavailable)?;
                let c = old.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
                if old.root_kind != kind
                    || old.revision != revision.get()
                    || old.fingerprint != fingerprint_for(c.question)
                    || old.previous.is_some()
                    || self.transport.references(id)
                    || self.dns.observations.values().any(|o| o.context == id)
                {
                    return Err(ServiceError::InvalidRequest);
                }
                if c.invalid.load(Ordering::Acquire) || !c.acked || now >= old.expires {
                    return Err(ServiceError::Unavailable);
                }
                Some(id)
            } else {
                None
            };
        let context = renewing.unwrap_or(0);
        let datagram_until = if original.protocol == 17 {
            Some(self.datagram_context(u64_at(b, 16), &path[..count], renewing)?)
        } else {
            None
        };
        let source =
            self.source_result(context, self.root_source(u64_at(b, 16), original.protocol))?;
        let mut expires = self
            .source_result(context, source.snapshot(self.record, reference))?
            .min(
                self.source_result(
                    context,
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
                    ),
                )?,
            )
            .min(session)
            .min(now + Duration::from_nanos(u64_at(b, 40)));
        if let Some(until) = datagram_until {
            expires = expires.min(until);
        }
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
                let selected = self.source_result(
                    context,
                    source.question(
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
                    ),
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
        let fingerprint = fingerprint_for(question);
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
                if self.dns.live.len()
                    + self.grants.len()
                    + self.services.len()
                    + self.hosts_permission_count()
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
        if original.protocol == 17 {
            self.datagram_context_committed(u64_at(b, 16), id)?;
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
        if c.original.protocol == 17 {
            self.datagram_network_ready(b.query)?;
        }
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
        for p in self
            .dns
            .hosts_producers
            .values_mut()
            .filter(|p| p.request == request)
        {
            p.revoked = true;
        }
        for w in self
            .dns
            .hosts_waiters
            .values_mut()
            .filter(|w| w.request == request)
        {
            w.revoked = true;
        }
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
        let source = self.root_source(query, original.protocol)?;
        expires =
            expires.min(self.source_result(context, source.snapshot(self.record, reference))?);
        let choice = {
            // Path существует только во время Source. Seen materializes позже;
            // его credit не должен перекрывать независимый parser/planner.
            let _path = self
                .budget
                .dynamic
                .reserve(std::mem::size_of::<[(u16, u8); 256]>())
                .map_err(unavailable)?;
            let mut path = [(0, 0); 256];
            for (i, h) in parent.iter().enumerate() {
                path[i] = (h.scope, h.branch);
            }
            self.source_result(
                context,
                source.hosts(
                    Parent {
                        root,
                        launch: self.record,
                        query,
                        selector,
                        original: original.wire(),
                        path: &path[..parent.len()],
                    }
                    .checked()?,
                    reference,
                ),
            )?
        };
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
        let scratch = self
            .budget
            .dynamic
            .reserve(std::mem::size_of::<[u64; 1024]>())
            .map_err(unavailable)?;
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
                publish: None,
                waiter: None,
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
// Hosts DATA хранит provenance observation, а не фиктивный DNS transport Binding.
impl<A: Authority> Issuer<A> {
    pub(in crate::helper::native_profile_channel) fn is_hosts_reservation(&self, id: u64) -> bool {
        self.dns.observations.values().any(|o| o.reservation == id)
    }
    fn revalidate_host_data(&self, id: u64) -> Result<Instant, ServiceError> {
        let _scratch = self.budget.dynamic.reserve(2048).map_err(unavailable)?;
        let until = self.host_observation_live(id)?;
        let o = self
            .dns
            .observations
            .get(&id)
            .ok_or(ServiceError::Unavailable)?;
        if !o.acked {
            return Err(ServiceError::Unavailable);
        }
        let b = self
            .dns
            .live
            .get(&o.context)
            .ok_or(ServiceError::Unavailable)?;
        let c = b.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        let mut path = [(0, 0); 256];
        for (i, h) in o._parent.iter().enumerate() {
            path[i] = (h.scope, h.branch);
        }
        let source = self.root_source(b.query, o._original.protocol)?;
        let choice = self.source_result(
            o.context,
            source.hosts(
                Parent {
                    root: b.root_kind,
                    launch: self.record,
                    query: b.query,
                    selector: c.selector,
                    original: o._original.wire(),
                    path: &path[..o._parent.len()],
                }
                .checked()?,
                o._reference,
            ),
        )?;
        if choice.count != o.choice.count
            || choice.key_len != o.choice.key_len
            || choice.row != o.choice.row
            || choice.key[..usize::from(choice.key_len)]
                != o.choice.key[..usize::from(o.choice.key_len)]
            || choice.members[..usize::from(choice.count)]
                != o.choice.members[..usize::from(o.choice.count)]
        {
            return self.source_result(o.context, Err(ServiceError::Unavailable));
        }
        let until = until
            .min(choice.expires)
            .min(self.source_result(o.context, source.snapshot(self.record, o._reference))?)
            .min(self.bootstrap_live(o.context, true)?);
        if self.authority.now() >= until {
            return self.source_result(o.context, Err(ServiceError::Unavailable));
        }
        Ok(until)
    }
    pub(in crate::helper::native_profile_channel) fn publish_hosts(
        &mut self,
        v: View<'_, 40>,
        request: u64,
        session: Instant,
    ) -> Result<u64, ServiceError> {
        self.fence()?;
        let start = self.authority.now();
        let b = v.bytes();
        let t = &b[144..];
        let host = v
            .hosts()
            .map_err(unavailable)?
            .ok_or(ServiceError::InvalidRequest)?;
        let observation = host.observation().map_err(unavailable)?.get();
        let o = self
            .dns
            .observations
            .get(&observation)
            .ok_or(ServiceError::Unavailable)?;
        let context = self
            .dns
            .live
            .get(&o.context)
            .ok_or(ServiceError::Unavailable)?;
        let c = context
            .bootstrap
            .as_ref()
            .ok_or(ServiceError::Unavailable)?;
        let terminal = o._parent.last().ok_or(ServiceError::Unavailable)?;
        let original = o._original.wire();
        let key = host.lookup_key().map_err(unavailable)?;
        let original_at = 128 + usize::from(u16_at(t, 110));
        if context.root_kind != wire::dns_v2::Root::HostsPath
            || !o.acked
            || o.revoked
            || o.publish.is_some()
            || o.waiter.is_some()
            || u64_at(b, 12) != context.query
            || u64_at(b, 36) != self.record.binding.epoch
            || t[16..48] != o._reference.source
            || t[48..80] != o._reference.asset
            || u16_at(t, 104) != 0
            || u16_at(t, 106) != o.choice.row
            || u16_at(t, 108) != o.choice.count
            || key.as_bytes() != &o.choice.key[..usize::from(o.choice.key_len)]
            || &t[original_at..original_at + usize::from(u16_at(t, 112))] != original.bytes
            || u16_at(t, 114) != c.selector.subject
            || u16_at(t, 116) != c.selector.endpoint
            || u16_at(t, 118) != terminal.scope
            || t[120] != terminal.branch
            || t[121] != original.protocol
            || u16_at(t, 122) != original.port
            || !host
                .member_indices()
                .eq(o.choice.members[..usize::from(o.choice.count)]
                    .iter()
                    .copied())
        {
            return Err(ServiceError::InvalidRequest);
        }
        if self.dns.hosts_producers.len() + self.rrsets.counts().0 >= 64 {
            return Err(ServiceError::Busy);
        }
        let expires = o
            .expires
            .min(session)
            .min(start + Duration::from_nanos(u64_at(t, 96)));
        let memory = self
            .budget
            .dynamic
            .reserve(std::mem::size_of::<HostsProducer>() + 80)
            .map_err(unavailable)?;
        self.bundle_history(1)?;
        let expires = expires.min(self.revalidate_host_data(observation)?);
        if self.authority.now() >= expires || self.retired.iter().any(|(n, _)| *n == request) {
            return Err(ServiceError::Unavailable);
        }
        let id = self.rrsets.host_id::<A>(Operation::Published)?;
        self.dns
            .observations
            .get_mut(&observation)
            .ok_or(ServiceError::Unavailable)?
            .publish = Some(id);
        self.dns.hosts_producers.insert(
            id,
            Box::new(HostsProducer {
                observation,
                request,
                expires,
                acked: false,
                revoked: false,
                _memory: memory,
            }),
        );
        Ok(id)
    }
    fn same_hosts_data(&self, a: u64, b: u64) -> Result<bool, ServiceError> {
        let a = self
            .dns
            .observations
            .get(&a)
            .ok_or(ServiceError::Unavailable)?;
        let b = self
            .dns
            .observations
            .get(&b)
            .ok_or(ServiceError::Unavailable)?;
        Ok(a._reference.source == b._reference.source
            && a._reference.asset == b._reference.asset
            && a._reference.bytes == b._reference.bytes
            && a._reference.flags == b._reference.flags
            && a._original == b._original
            && a.choice.row == b.choice.row
            && a.choice.key_len == b.choice.key_len
            && a.choice.key[..usize::from(a.choice.key_len)]
                == b.choice.key[..usize::from(b.choice.key_len)]
            && a.choice.count == b.choice.count
            && a.choice.members[..usize::from(a.choice.count)]
                == b.choice.members[..usize::from(b.choice.count)]
            && a._parent.len() == b._parent.len()
            && a._parent.iter().zip(b._parent.iter()).all(|(a, b)| {
                (
                    a.index, a.scope, a.branch, a.subject, a.chain, a.stream, a.carrier, a.endpoint,
                ) == (
                    b.index, b.scope, b.branch, b.subject, b.chain, b.stream, b.carrier, b.endpoint,
                )
            }))
    }
    fn hosts_producer_live(&self, id: u64, acked: bool) -> Result<Instant, ServiceError> {
        let p = self
            .dns
            .hosts_producers
            .get(&id)
            .ok_or(ServiceError::Unavailable)?;
        if p.revoked || acked && !p.acked || self.authority.now() >= p.expires {
            return Err(ServiceError::Unavailable);
        }
        let until = p.expires.min(self.revalidate_host_data(p.observation)?);
        if self.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        Ok(until)
    }
    pub(in crate::helper::native_profile_channel) fn hosts_waiter_live(
        &self,
        id: u64,
        acked: bool,
    ) -> Result<Instant, ServiceError> {
        let w = self
            .dns
            .hosts_waiters
            .get(&id)
            .ok_or(ServiceError::Unavailable)?;
        if w.revoked || acked && !w.acked || self.authority.now() >= w.expires {
            return Err(ServiceError::Unavailable);
        }
        let until = w
            .expires
            .min(self.revalidate_host_data(w.observation)?)
            .min(self.hosts_producer_live(w.producer, true)?);
        if self.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        Ok(until)
    }
    pub(in crate::helper::native_profile_channel) fn bind_hosts_waiter(
        &mut self,
        v: View<'_, 53>,
        request: u64,
        session: Instant,
    ) -> Result<u64, ServiceError> {
        self.fence()?;
        let start = self.authority.now();
        let b = v.bytes();
        let reservation = u64_at(b, 8);
        let producer = u64_at(b, 16);
        let (observation, o) = self
            .dns
            .observations
            .iter()
            .find(|(_, o)| o.reservation == reservation)
            .ok_or(ServiceError::Unavailable)?;
        let observation = *observation;
        let context = self
            .dns
            .live
            .get(&o.context)
            .ok_or(ServiceError::Unavailable)?;
        let p = self
            .dns
            .hosts_producers
            .get(&producer)
            .ok_or(ServiceError::Unavailable)?;
        let source = self
            .dns
            .observations
            .get(&p.observation)
            .ok_or(ServiceError::Unavailable)?;
        let parent = self
            .dns
            .live
            .get(&source.context)
            .ok_or(ServiceError::Unavailable)?;
        if !o.acked
            || o.revoked
            || o.publish.is_some()
            || o.waiter.is_some()
            || !p.acked
            || p.revoked
            || context.root_kind != wire::dns_v2::Root::HostsPath
            || o.context == source.context
            || context.query == parent.query
            || u64_at(b, 24) != 0
            || u64_at(b, 32) != context.query
            || u64_at(b, 40) != 0
            || u64_at(b, 48) != 0
            || self.dns.hosts_waiters.values().any(|w| {
                self.dns
                    .observations
                    .get(&w.observation)
                    .is_some_and(|prior| prior.context == o.context)
            })
            || !self.same_hosts_data(observation, p.observation)?
        {
            return Err(ServiceError::InvalidRequest);
        }
        if self.dns.hosts_waiters.len() + self.rrsets.counts().1 >= 256 {
            return Err(ServiceError::Busy);
        }
        let expires = o
            .expires
            .min(p.expires)
            .min(session)
            .min(start + Duration::from_nanos(u64_at(b, 56)));
        let memory = self
            .budget
            .dynamic
            .reserve(std::mem::size_of::<HostsWaiter>() + 80)
            .map_err(unavailable)?;
        self.bundle_history(1)?;
        let expires = expires
            .min(self.revalidate_host_data(observation)?)
            .min(self.hosts_producer_live(producer, true)?);
        if self.authority.now() >= expires || self.retired.iter().any(|(n, _)| *n == request) {
            return Err(ServiceError::Unavailable);
        }
        let id = self.rrsets.host_id::<A>(Operation::WaiterBound)?;
        self.dns
            .observations
            .get_mut(&observation)
            .ok_or(ServiceError::Unavailable)?
            .waiter = Some(id);
        self.dns.hosts_waiters.insert(
            id,
            Box::new(HostsWaiter {
                numeric_once: None,
                observation,
                producer,
                request,
                expires,
                acked: false,
                revoked: false,
                _memory: memory,
            }),
        );
        Ok(id)
    }
    pub(in crate::helper::native_profile_channel) fn hosts_rrset_reply(
        &self,
        op: Operation,
        id: u64,
        out: &mut [u8; 64],
    ) -> Result<Option<Instant>, ServiceError> {
        let (until, observation) = match op {
            Operation::Published => match self.dns.hosts_producers.get(&id) {
                Some(p) => (self.hosts_producer_live(id, false)?, p.observation),
                None => return Ok(None),
            },
            Operation::WaiterBound => match self.dns.hosts_waiters.get(&id) {
                Some(w) => (self.hosts_waiter_live(id, false)?, w.observation),
                None => return Ok(None),
            },
            _ => return Err(ServiceError::InvalidRequest),
        };
        let o = self
            .dns
            .observations
            .get(&observation)
            .ok_or(ServiceError::Unavailable)?;
        let context = self
            .dns
            .live
            .get(&o.context)
            .ok_or(ServiceError::Unavailable)?;
        let checked = self.authority.now();
        if checked >= until {
            return Err(ServiceError::Unavailable);
        }
        out[8..16].copy_from_slice(&id.to_be_bytes());
        if op == Operation::Published {
            out[24..32].copy_from_slice(&self.record.binding.epoch.to_be_bytes());
            out[32..40].copy_from_slice(
                &((until - checked).as_nanos().min(1_000_000_000) as u64).to_be_bytes(),
            );
            out[40..42].copy_from_slice(&o.choice.count.to_be_bytes());
        } else {
            let w = self
                .dns
                .hosts_waiters
                .get(&id)
                .ok_or(ServiceError::Unavailable)?;
            for (at, value) in [
                (16, w.producer),
                (24, o.reservation),
                (32, context.query),
                (40, self.record.binding.epoch),
                (48, (until - checked).as_nanos().min(1_000_000_000) as u64),
            ] {
                out[at..at + 8].copy_from_slice(&value.to_be_bytes());
            }
            out[56..58].copy_from_slice(&o.choice.count.to_be_bytes());
            out[58] = 2;
            out[59] = 3;
        }
        Ok(Some(until))
    }
    pub(in crate::helper::native_profile_channel) fn ack_hosts_data(
        &mut self,
        op: Operation,
        id: u64,
    ) -> Result<bool, ServiceError> {
        match op {
            Operation::Published if self.dns.hosts_producers.contains_key(&id) => {
                self.hosts_producer_live(id, false)?;
                self.dns
                    .hosts_producers
                    .get_mut(&id)
                    .ok_or(ServiceError::Unavailable)?
                    .acked = true;
                Ok(true)
            }
            Operation::WaiterBound if self.dns.hosts_waiters.contains_key(&id) => {
                self.hosts_waiter_live(id, false)?;
                self.dns
                    .hosts_waiters
                    .get_mut(&id)
                    .ok_or(ServiceError::Unavailable)?
                    .acked = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    pub(in crate::helper::native_profile_channel) fn cancel_hosts_data(
        &mut self,
        target: u8,
        id: u64,
    ) -> Result<bool, ServiceError> {
        match target {
            5 => {
                if let Some(p) = self.dns.hosts_producers.get_mut(&id) {
                    p.revoked = true;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            6 => {
                if let Some(w) = self.dns.hosts_waiters.get_mut(&id) {
                    w.revoked = true;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(ServiceError::InvalidRequest),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermissionState {
    Preparing,
    Active,
    Closed,
    Unknown,
}
enum PermissionOrigin {
    Hosts(u16),
    Network(Box<super::super::dns_rrset::NetworkNumericProof>),
}
pub(super) struct BootstrapPhysicalPermission {
    datagram: Option<super::super::dns_datagram::BootstrapDatagramPermission>,
    waiter: u64,
    member: u16,
    origin: PermissionOrigin,
    target: Target,
    request: u64,
    expires: Instant,
    state: PermissionState,
    acked: bool,
    ticket: Option<u64>,
    routes: Option<super::super::super::memory::ByteLease>,
    _memory: super::super::super::memory::ByteLease,
}
impl BootstrapPhysicalPermission {
    pub(super) fn wakeup(&self) -> Option<Instant> {
        (self.state == PermissionState::Active).then_some(self.expires)
    }
}
fn target_ip(target: Target) -> Result<std::net::IpAddr, ServiceError> {
    match target.wire() {
        wire::Destination {
            family: 4, bytes, ..
        } => Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(unavailable)?,
        ))),
        wire::Destination {
            family: 6, bytes, ..
        } => Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(unavailable)?,
        ))),
        _ => Err(ServiceError::InvalidRequest),
    }
}
impl<A: Authority> Issuer<A> {
    pub(in crate::helper::native_profile_channel) fn network_numeric_original(
        &self,
        binding: super::super::dns_transport::Binding,
        selector: wire::dns_v2::BootstrapSelector,
    ) -> Result<Target, ServiceError> {
        let b = self
            .dns
            .live
            .get(&binding.bundle)
            .ok_or(ServiceError::Unavailable)?;
        let c = b.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        if !binding.bootstrap
            || !matches!(b.root_kind, wire::dns_v2::Root::BootstrapService(_))
            || selector.resolver.is_none()
            || selector != c.selector
            || self.bootstrap_binding(binding.bundle, b.expires)? != binding
        {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(c.original)
    }
    fn authorize_network_numeric(
        &mut self,
        request: u64,
        v: View<'_, 42>,
        session: Instant,
    ) -> Result<u64, ServiceError> {
        self.fence()?;
        if self.retired.iter().any(|(n, _)| *n == request) {
            return Err(ServiceError::Unavailable);
        }
        let started = self.authority.now();
        if self.hosts_permission_count()
            + self.grants.len()
            + self.services.len()
            + self.dns.live.len()
            >= self.capsule()?.limits()[0] as usize
        {
            return Err(ServiceError::Busy);
        }
        let memory = self
            .budget
            .dynamic
            .reserve(
                std::mem::size_of::<BootstrapPhysicalPermission>()
                    + std::mem::size_of::<super::super::dns_rrset::NetworkNumericProof>()
                    + 80,
            )
            .map_err(unavailable)?;
        let routes = self.budget.routes.reserve(1).map_err(unavailable)?;
        self.bundle_history_available(1)?;
        let (proof, until) = self.checked_network_numeric(v)?;
        let waiter = v.waiter().map_err(unavailable)?.get();
        let member = u16_at(v.bytes(), 2);
        let target = Target::copy(v.numeric_destination())?;
        let datagram = if target.protocol == 17 {
            Some(self.datagram_permission(self.network_numeric_query(proof)?)?)
        } else {
            None
        };
        let expires = until.min(session).min(started + Duration::from_secs(1));
        let expires = if let Some(p) = &datagram {
            expires.min(self.datagram_permission_live(p)?)
        } else {
            expires
        };
        if expires.saturating_duration_since(self.authority.now()) < Duration::from_millis(1) {
            return Err(ServiceError::Unavailable);
        }
        self.bundle_history(1)?;
        if let Some(p) = &datagram {
            self.spend_datagram(p)?;
        }
        let id = Self::id(&mut self.next_grant)?;
        self.consume_network_numeric(proof, request, id)?;
        self.dns.permissions.insert(
            id,
            Box::new(BootstrapPhysicalPermission {
                datagram,
                waiter,
                member,
                origin: PermissionOrigin::Network(Box::new(proof)),
                target,
                request,
                expires,
                state: PermissionState::Preparing,
                acked: false,
                ticket: None,
                routes: Some(routes),
                _memory: memory,
            }),
        );
        match self
            .authority
            .service(self.record.manifest, RouteRequest::Direct(target.wire()))
        {
            Ok(ticket) => {
                let p = self
                    .dns
                    .permissions
                    .get_mut(&id)
                    .ok_or(ServiceError::Unavailable)?;
                p.ticket = ticket;
                p.state = PermissionState::Active;
            }
            Err(error) => {
                self.dns
                    .permissions
                    .get_mut(&id)
                    .ok_or(ServiceError::Unavailable)?
                    .state = PermissionState::Unknown;
                self.unknown = true;
                self.authority.revoke();
                return Err(error);
            }
        }
        if let Err(error) = self.hosts_permission_live(id, false) {
            self.close_hosts_permission(id)?;
            return Err(error);
        }
        Ok(id)
    }
    pub(in crate::helper::native_profile_channel) fn hosts_permission_count(&self) -> usize {
        self.dns
            .permissions
            .values()
            .filter(|p| p.state != PermissionState::Closed)
            .count()
    }
    fn host_member(&self, waiter: u64, member: u16) -> Result<(Member, u16), ServiceError> {
        let _scratch = self.budget.dynamic.reserve(2048).map_err(unavailable)?;
        let until = self.hosts_waiter_live(waiter, true)?;
        let w = self
            .dns
            .hosts_waiters
            .get(&waiter)
            .ok_or(ServiceError::Unavailable)?;
        let o = self
            .dns
            .observations
            .get(&w.observation)
            .ok_or(ServiceError::Unavailable)?;
        if member >= o.choice.count {
            return Err(ServiceError::InvalidRequest);
        }
        let index = o.choice.members[usize::from(member)];
        let b = self
            .dns
            .live
            .get(&o.context)
            .ok_or(ServiceError::Unavailable)?;
        let c = b.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        let mut path = [(0, 0); 256];
        for (i, h) in o._parent.iter().enumerate() {
            path[i] = (h.scope, h.branch);
        }
        let source = self.root_source(b.query, o._original.protocol)?;
        let mut selected = self.source_result(
            o.context,
            source.member(
                Parent {
                    root: b.root_kind,
                    launch: self.record,
                    query: b.query,
                    selector: c.selector,
                    original: o._original.wire(),
                    path: &path[..o._parent.len()],
                }
                .checked()?,
                o._reference,
                o.choice.row,
                index,
            ),
        )?;
        selected.expires = selected
            .expires
            .min(until)
            .min(self.source_result(o.context, source.snapshot(self.record, o._reference))?)
            .min(self.bootstrap_live(o.context, true)?);
        if self.authority.now() >= selected.expires {
            return self.source_result(o.context, Err(ServiceError::Unavailable));
        }
        Ok((selected, index))
    }
    fn authorize_hosts_numeric(
        &mut self,
        request: u64,
        v: View<'_, 42>,
        session: Instant,
    ) -> Result<u64, ServiceError> {
        self.fence()?;
        let started = self.authority.now();
        if self.retired.iter().any(|(n, _)| *n == request) {
            return Err(ServiceError::Unavailable);
        }
        let b = v.bytes();
        let waiter = v.waiter().map_err(unavailable)?.get();
        let member = u16_at(b, 2);
        let selector = v
            .bootstrap_selector()
            .map_err(unavailable)?
            .ok_or(ServiceError::InvalidRequest)?;
        if selector.resolver.is_some() {
            return self.authorize_network_numeric(request, v, session);
        }
        let w = self
            .dns
            .hosts_waiters
            .get(&waiter)
            .ok_or(ServiceError::Unavailable)?;
        let o = self
            .dns
            .observations
            .get(&w.observation)
            .ok_or(ServiceError::Unavailable)?;
        let context = self
            .dns
            .live
            .get(&o.context)
            .ok_or(ServiceError::Unavailable)?;
        let c = context
            .bootstrap
            .as_ref()
            .ok_or(ServiceError::Unavailable)?;
        let target = Target::copy(v.numeric_destination())?;
        if b[14] != 2
            || b[15] != 3
            || selector.resolver.is_some()
            || selector != c.selector
            || context.root_kind != wire::dns_v2::Root::HostsPath
            || !w.acked
            || w.revoked
            || w.numeric_once.is_some()
            || member >= o.choice.count
            || target.port != o._original.port
            || target.protocol != o._original.protocol
            || !matches!(target.protocol, 6 | 17)
            || !super::super::dns_rrset::numeric_ip_allowed(target_ip(target)?)
        {
            return Err(ServiceError::InvalidRequest);
        }
        if self.hosts_permission_count()
            + self.grants.len()
            + self.services.len()
            + self.dns.live.len()
            >= self.capsule()?.limits()[0] as usize
        {
            return Err(ServiceError::Busy);
        }
        let memory = self
            .budget
            .dynamic
            .reserve(std::mem::size_of::<BootstrapPhysicalPermission>() + 80)
            .map_err(unavailable)?;
        let routes = self.budget.routes.reserve(1).map_err(unavailable)?;
        self.bundle_history_available(1)?;
        let (selected, source_index) = self.host_member(waiter, member)?;
        if selected.address != target_ip(target)? {
            return Err(ServiceError::InvalidRequest);
        }
        let expires = selected
            .expires
            .min(session)
            .min(started + Duration::from_secs(1));
        let datagram = if target.protocol == 17 {
            Some(self.datagram_permission(context.query)?)
        } else {
            None
        };
        let expires = if let Some(p) = &datagram {
            expires.min(self.datagram_permission_live(p)?)
        } else {
            expires
        };
        if expires.saturating_duration_since(self.authority.now()) < Duration::from_millis(1) {
            return Err(ServiceError::Unavailable);
        }
        self.bundle_history(1)?;
        if let Some(p) = &datagram {
            self.spend_datagram(p)?;
        }
        let id = Self::id(&mut self.next_grant)?;
        self.dns
            .hosts_waiters
            .get_mut(&waiter)
            .ok_or(ServiceError::Unavailable)?
            .numeric_once = Some((request, id));
        self.dns.permissions.insert(
            id,
            Box::new(BootstrapPhysicalPermission {
                datagram,
                waiter,
                member,
                origin: PermissionOrigin::Hosts(source_index),
                target,
                request,
                expires,
                state: PermissionState::Preparing,
                acked: false,
                ticket: None,
                routes: Some(routes),
                _memory: memory,
            }),
        );
        match self
            .authority
            .service(self.record.manifest, RouteRequest::Direct(target.wire()))
        {
            Ok(ticket) => {
                let p = self
                    .dns
                    .permissions
                    .get_mut(&id)
                    .ok_or(ServiceError::Unavailable)?;
                p.ticket = ticket;
                p.state = PermissionState::Active;
            }
            Err(error) => {
                self.dns
                    .permissions
                    .get_mut(&id)
                    .ok_or(ServiceError::Unavailable)?
                    .state = PermissionState::Unknown;
                self.unknown = true;
                self.authority.revoke();
                return Err(error);
            }
        }
        if let Err(error) = self.hosts_permission_live(id, false) {
            self.close_hosts_permission(id)?;
            return Err(error);
        }
        Ok(id)
    }
    pub(in crate::helper::native_profile_channel) fn hosts_permission_live(
        &self,
        id: u64,
        acked: bool,
    ) -> Result<Instant, ServiceError> {
        self.fence()?;
        let p = self
            .dns
            .permissions
            .get(&id)
            .ok_or(ServiceError::Unavailable)?;
        if p.state != PermissionState::Active
            || acked && !p.acked
            || self.authority.now() >= p.expires
        {
            return Err(ServiceError::Unavailable);
        }
        let datagram_until = match (&p.datagram, p.target.protocol) {
            (None, 6) => p.expires,
            (Some(proof), 17) => self.datagram_permission_live(proof)?.min(p.expires),
            _ => return Err(ServiceError::Unavailable),
        };
        let index = match &p.origin {
            PermissionOrigin::Network(proof) => {
                let until = self
                    .network_permission_live(**proof, p.request, id, p.waiter, p.member, p.target)?
                    .min(datagram_until);
                if self.authority.now() >= until {
                    return Err(ServiceError::Unavailable);
                }
                return Ok(until);
            }
            PermissionOrigin::Hosts(index) => *index,
        };
        let w = self
            .dns
            .hosts_waiters
            .get(&p.waiter)
            .ok_or(ServiceError::Unavailable)?;
        if w.numeric_once != Some((p.request, id)) {
            return Err(ServiceError::Unavailable);
        }
        let (selected, actual_index) = self.host_member(p.waiter, p.member)?;
        if actual_index != index || selected.address != target_ip(p.target)? {
            let context = self
                .dns
                .observations
                .get(&w.observation)
                .ok_or(ServiceError::Unavailable)?
                .context;
            return self.source_result(context, Err(ServiceError::Unavailable));
        }
        let until = datagram_until.min(selected.expires);
        if self.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        Ok(until)
    }
    pub(in crate::helper::native_profile_channel) fn close_hosts_permission(
        &mut self,
        id: u64,
    ) -> Result<bool, ServiceError> {
        let Some(p) = self.dns.permissions.get_mut(&id) else {
            return Ok(false);
        };
        match p.state {
            PermissionState::Closed => return Ok(true),
            PermissionState::Unknown | PermissionState::Preparing => {
                return Err(ServiceError::Unavailable);
            }
            PermissionState::Active => {}
        }
        p.state = PermissionState::Unknown;
        if let Some(ticket) = p.ticket {
            if self.authority.release(ticket).is_err() {
                self.unknown = true;
                self.authority.revoke();
                return Err(ServiceError::Unavailable);
            }
        }
        p.ticket = None;
        p.state = PermissionState::Closed;
        p.routes.take();
        Ok(true)
    }
    pub(in crate::helper::native_profile_channel) fn close_hosts_request(
        &mut self,
        request: u64,
    ) -> Result<(), ServiceError> {
        let id = self
            .dns
            .permissions
            .iter()
            .find(|(_, p)| p.request == request)
            .map(|(id, _)| *id);
        if let Some(id) = id {
            self.close_hosts_permission(id)?;
        }
        Ok(())
    }
    pub(in crate::helper::native_profile_channel) fn retire_hosts_permissions(
        &mut self,
    ) -> Result<(), ServiceError> {
        let mut ids = [0; 256];
        let mut count = 0;
        for (id, p) in &self.dns.permissions {
            if p.state == PermissionState::Active && self.hosts_permission_live(*id, false).is_err()
            {
                *ids.get_mut(count).ok_or(ServiceError::Busy)? = *id;
                count += 1;
            }
        }
        for id in &ids[..count] {
            self.close_hosts_permission(*id)?;
        }
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)] // Exact Numeric pending, one reader, original deadline.
pub(in crate::helper::native_profile_channel) fn dispatch_hosts_numeric<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    sequence: u64,
    request: u64,
    view: View<'_, 42>,
    session: Instant,
    mut drain: impl FnMut(&mut Issuer<A>) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let response_until = session.min(issuer.authority.now() + Duration::from_secs(1));
    if !issuer.unknown {
        drain(issuer)?;
    }
    let outcome = issuer.authorize_hosts_numeric(request, view, session);
    loop {
        if !issuer.unknown {
            drain(issuer)?;
        }
        let live = outcome.as_ref().ok().and_then(|id| {
            if stop.load(Ordering::Acquire) || issuer.retired.iter().any(|(n, _)| *n == request) {
                return None;
            }
            issuer
                .hosts_permission_live(*id, false)
                .ok()
                .and_then(|until| {
                    let remaining = until.saturating_duration_since(issuer.authority.now());
                    (remaining >= Duration::from_millis(1)).then_some((*id, until, remaining))
                })
        });
        if live.is_none() {
            if let Ok(id) = &outcome {
                if !issuer.unknown {
                    issuer.close_hosts_permission(*id)?;
                }
            }
        }
        if stop.load(Ordering::Acquire) || issuer.authority.now() >= response_until {
            return Err(ServiceError::Unavailable);
        }
        let (object, message) = if let Some((id, _, remaining)) = live {
            (
                id,
                wire::Message::Grant {
                    status: wire::Status::Allow,
                    class: 3,
                    required: false,
                    grant: id,
                    flow: 0,
                    lease: remaining.as_millis().min(1000) as u32,
                    revision: issuer.capsule()?.policy_revision,
                    fresh: 0,
                    receipt: wire::Receipt {
                        kind: wire::ReceiptKind::None,
                        id: 0,
                    },
                },
            )
        } else {
            (
                0,
                wire::Message::Grant {
                    status: if issuer.unknown {
                        wire::Status::Unknown
                    } else {
                        wire::Status::Deny
                    },
                    class: 3,
                    required: false,
                    grant: 0,
                    flow: 0,
                    lease: 0,
                    revision: 0,
                    fresh: 0,
                    receipt: wire::Receipt {
                        kind: wire::ReceiptKind::None,
                        id: 0,
                    },
                },
            )
        };
        let mut bytes = [0; 184];
        let n = wire::Frame::encode(
            wire::Header {
                kind: wire::Kind::Grant,
                sequence,
                reply_to: request,
                binding: issuer.record.binding,
                object_id: object,
            },
            &message,
            &mut bytes,
        )
        .map_err(unavailable)?;
        match socket.write(&bytes[..n]) {
            Ok(true) => {
                if let Some((id, _, _)) = live {
                    if issuer.hosts_permission_live(id, false).is_err() {
                        issuer
                            .dns
                            .permissions
                            .get_mut(&id)
                            .ok_or(ServiceError::Unavailable)?
                            .state = PermissionState::Unknown;
                        issuer.unknown = true;
                        issuer.authority.revoke();
                        return Err(ServiceError::Unavailable);
                    }
                    issuer
                        .dns
                        .permissions
                        .get_mut(&id)
                        .ok_or(ServiceError::Unavailable)?
                        .acked = true;
                }
                return Ok(());
            }
            Ok(false) => {}
            Err(error) => {
                if let Ok(id) = &outcome {
                    if let Some(p) = issuer.dns.permissions.get_mut(id) {
                        if p.state == PermissionState::Active {
                            p.state = PermissionState::Unknown;
                        }
                    }
                }
                issuer.unknown = true;
                issuer.authority.revoke();
                return Err(error);
            }
        }
        socket
            .writable_until(live.map_or(response_until, |(_, until, _)| until.min(response_until)));
    }
}
#[cfg(test)]
#[path = "native_dns_roots_tests.rs"]
pub(in crate::helper::native_profile_channel) mod tests;
