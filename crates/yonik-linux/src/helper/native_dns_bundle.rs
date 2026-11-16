//! CODEC2 authority живёт в serialized issuer, отдельно от ServiceGrant IDs.
use super::reject_unproved_stub;
use super::{
    Authority, Channel, Issuer, RUNTIME_PACKET, RouteRequest, ServiceError, Target, unavailable,
    wire,
};
use crate::attribution::native_session::OwnerReference;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use wire::dns_v2::{Direction, DnsFrame, Envelope, Negotiated, Operation, Record, View};

pub(super) struct Bundles {
    live: BTreeMap<u64, Box<Bundle>>,
    next: u64,
    history: usize,
}
struct DnsHopPermit {
    bundle: u64,
    index: u16,
    expires: Instant,
    scope: u16,
    branch: u8,
    subject: u16,
    chain: u16,
    stream: u16,
    carrier: u8,
    endpoint: u16,
    ticket: Option<u64>,
}
struct Bundle {
    root: u64,
    query: u64,
    request: u64,
    revision: u64,
    fingerprint: [u8; 32],
    expires: Instant,
    hops: Vec<DnsHopPermit>,
    previous: Option<Box<Bundle>>,
    _memory: super::super::memory::ByteLease,
    _routes: super::super::memory::ByteLease,
}
impl Bundles {
    pub(super) fn new() -> Self {
        Self {
            live: BTreeMap::new(),
            next: 0,
            history: 0,
        }
    }
    #[cfg(test)]
    pub(super) fn count(&self) -> usize {
        self.live.len()
    }
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(std::array::from_fn(|i| b[at + i]))
}
fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
pub(super) fn is_dns(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && u16_at(bytes, 10) >= 35
}
pub(super) fn decode<'a>(
    bytes: &'a [u8],
    neg: &Negotiated,
    direction: Direction,
) -> Result<DnsFrame<'a>, ServiceError> {
    let reply = if direction == Direction::Issuer && bytes.len() >= 32 {
        Some(u64_at(bytes, 24))
    } else {
        None
    };
    DnsFrame::decode(bytes, neg, direction, 0, 0, reply).map_err(unavailable)
}
impl<A: Authority> Issuer<A> {
    // Не извлекаем authority из номера row: manifest/path independently checked.
    fn bundle_root(
        &mut self,
        view: View<'_, 55>,
    ) -> Result<(u64, A::Proof, Instant), ServiceError> {
        self.fence()?;
        let b = view.bytes();
        let root = u64_at(b, 8);
        let a = view.authorization().map_err(unavailable)?;
        self.capsule()?
            .validate_request(&wire::Message::Authorize(a))
            .map_err(unavailable)?;
        let grant = self.grants.get(&root).ok_or(ServiceError::Unavailable)?;
        let flow = self
            .flows
            .get(&a.source_flow)
            .ok_or(ServiceError::Unavailable)?;
        if a.class != 3
            || grant.class != 3
            || grant.source != a.source_flow
            || grant.subject != a.subject
            || grant.chain != a.chain
            || grant.stream != a.transport
            || grant.scope != a.scope
            || grant.branch != a.branch
            || grant.resolver != a.resolver
            || grant.query.as_ref() != a.query
            || grant.effective != Target::copy(a.effective)?
            || flow.original != Target::copy(a.original)?
            || view.original() != a.query.as_bytes()
            || u16_at(b, 60) != a.resolver
            || u64_at(b, 24) != self.record.binding.epoch
            || self.authority.now() >= grant.expires
        {
            return Err(ServiceError::InvalidRequest);
        }
        self.authority.check_ingress(&flow.socket)?;
        let proof = self.authority.owner(
            a.source_flow,
            flow.tuple,
            OwnerReference {
                kind: a.receipt.kind,
                id: a.receipt.id,
            },
        )?;
        if self.authority.subject(&proof, a.source_flow, flow.tuple)? != flow.subject {
            return Err(ServiceError::Unavailable);
        }
        let expiry = self
            .authority
            .expiry(&proof)
            .unwrap_or(grant.expires)
            .min(grant.expires);
        if expiry <= self.authority.now() {
            return Err(ServiceError::Unavailable);
        }
        Ok((a.source_flow, proof, expiry))
    }
    fn retire_bundle_value(&mut self, bundle: &mut Bundle) -> Result<(), ServiceError> {
        if let Some(previous) = bundle.previous.as_mut() {
            self.retire_bundle_value(previous)?;
        }
        bundle.previous = None;
        for hop in &mut bundle.hops {
            if let Some(ticket) = hop.ticket {
                if self.authority.release(ticket).is_err() {
                    self.unknown = true;
                    self.authority.revoke();
                    return Err(ServiceError::Unavailable);
                }
                hop.ticket = None;
            }
        }
        Ok(())
    }
    pub(super) fn cancel_dns_bundle(&mut self, id: u64) -> Result<(), ServiceError> {
        if self.unknown {
            return Err(ServiceError::Unavailable);
        }
        let Some(mut bundle) = self.dns.live.remove(&id) else {
            return if id > self.dns.next {
                Err(ServiceError::InvalidRequest)
            } else {
                Ok(())
            };
        };
        if let Err(e) = self.retire_bundle_value(&mut bundle) {
            self.dns.live.insert(id, bundle);
            return Err(e);
        }
        Ok(())
    }
    pub(super) fn cancel_dns_root(&mut self, root: u64) -> Result<(), ServiceError> {
        let mut ids = [0; 256];
        let mut n = 0;
        for (id, b) in &self.dns.live {
            if b.root == root {
                *ids.get_mut(n).ok_or(ServiceError::Busy)? = *id;
                n += 1;
            }
        }
        for id in &ids[..n] {
            self.cancel_dns_bundle(*id)?;
        }
        Ok(())
    }
    pub(super) fn cancel_dns_request(&mut self, request: u64) -> Result<(), ServiceError> {
        let id = self
            .dns
            .live
            .iter()
            .find(|(_, b)| b.request == request)
            .map(|(id, _)| *id);
        if let Some(id) = id {
            self.cancel_dns_bundle(id)?;
        }
        Ok(())
    }
    pub(super) fn expire_dns(&mut self) -> Result<(), ServiceError> {
        let now = self.authority.now();
        let mut ids = [0; 256];
        let mut n = 0;
        for (id, b) in &self.dns.live {
            if now >= b.expires || !self.grants.contains_key(&b.root) {
                *ids.get_mut(n).ok_or(ServiceError::Busy)? = *id;
                n += 1;
            }
        }
        for id in &ids[..n] {
            self.cancel_dns_bundle(*id)?;
        }
        Ok(())
    }
    fn bundle_history(&mut self, count: usize) -> Result<(), ServiceError> {
        let limit = (self.capsule()?.limits()[7] as usize).min(256);
        if self
            .dns
            .history
            .checked_add(count)
            .is_none_or(|n| n > limit)
        {
            return Err(ServiceError::Busy);
        }
        if let Some(history) = &self.history {
            // Отдельные kind/id namespaces, без eviction/reuse.
            let mut h = history.lock().map_err(unavailable)?;
            if h.len.checked_add(count).is_none_or(|n| n > h.limit) {
                return Err(ServiceError::Busy);
            }
            for i in 0..count {
                h.reserve(3, (self.dns.history + i + 1) as u64)?;
            }
        }
        self.dns.history += count;
        Ok(())
    }
    fn acquire_bundle(
        &mut self,
        request: u64,
        view: View<'_, 55>,
        session: Instant,
    ) -> Result<u64, ServiceError> {
        let started = self.authority.now();
        let (source, proof, root_expiry) = self.bundle_root(view)?;
        let b = view.bytes();
        let root = u64_at(b, 8);
        let query = u64_at(b, 16);
        let mut hash = Sha256::new();
        hash.update(b"YNK-DNS-BUNDLE-CODEC2\0");
        hash.update(self.record.manifest);
        hash.update(&b[..32]);
        hash.update(&b[48..64]);
        hash.update(&b[72..]);
        let fingerprint: [u8; 32] = hash.finalize().into();
        let count = usize::from(u16_at(b, 50));
        let (id, revision) = if let Some((id, expected)) = view.renewal().map_err(unavailable)? {
            let id = id.get();
            let old = self.dns.live.get(&id).ok_or(ServiceError::Unavailable)?;
            if old.revision != expected.get()
                || old.fingerprint != fingerprint
                || old.root != root
                || old.query != query
                || old.expires <= started
                || old.previous.is_some()
            {
                return Err(ServiceError::InvalidRequest);
            }
            (
                id,
                old.revision
                    .checked_add(1)
                    .filter(|v| *v != u64::MAX)
                    .ok_or(ServiceError::Busy)?,
            )
        } else {
            if self.dns.live.len() >= 256
                || self.dns.live.len() + self.grants.len() + self.services.len()
                    >= self.capsule()?.limits()[0] as usize
            {
                return Err(ServiceError::Busy);
            }
            (Self::id(&mut self.dns.next)?, 1)
        };
        // Все allocation/route/history credits до backend effects.
        let memory = self
            .budget
            .dynamic
            .reserve(
                std::mem::size_of::<Bundle>() + 80 + count * std::mem::size_of::<DnsHopPermit>(),
            )
            .map_err(unavailable)?;
        self.bundle_history(count + 1)?;
        let owned = Arc::clone(&self.capsule);
        let cap = wire::Capsule::decode(owned.bytes(), &self.record.binding.digest)
            .map_err(unavailable)?;
        let resolver = cap.resolver_scope(u16_at(b, 60)).map_err(unavailable)?;
        reject_unproved_stub(resolver.peer)?;
        let (mut expected_scope, mut mask) = resolver.scope.ok_or(ServiceError::Unsupported)?;
        let mut input = resolver.peer.protocol;
        let mut target = resolver.peer;
        let expires = root_expiry
            .min(session)
            .min(started + Duration::from_nanos(u64_at(b, 40)));
        let mut seen = [[false; 2]; 512];
        let mut plans = [None; 256];
        let mut hops = Vec::with_capacity(count);
        for (i, (scope, branch)) in view.path().enumerate() {
            if scope != expected_scope || mask & (1 << branch) == 0 {
                return Err(ServiceError::InvalidRequest);
            }
            let seen = seen
                .get_mut(usize::from(scope))
                .ok_or(ServiceError::InvalidRequest)?;
            if seen[usize::from(branch)] {
                return Err(ServiceError::InvalidRequest);
            }
            seen[usize::from(branch)] = true;
            let dial = cap.dial_scope(scope, branch).map_err(unavailable)?;
            if dial.input != input {
                return Err(ServiceError::InvalidRequest);
            }
            plans[i] = Some(match dial.action {
                1 => {
                    let d = dial.endpoint.ok_or(ServiceError::InvalidRequest)?;
                    if d.family == 3 {
                        return Err(ServiceError::Unsupported);
                    }
                    RouteRequest::Static(d)
                }
                2 => RouteRequest::Chain,
                3 if target.family != 3 => RouteRequest::Direct(wire::Destination {
                    protocol: dial.carrier,
                    ..target
                }),
                _ => return Err(ServiceError::Unsupported),
            });
            hops.push(DnsHopPermit {
                bundle: id,
                index: i as u16,
                expires,
                scope,
                branch,
                subject: dial.subject,
                chain: dial.chain,
                stream: dial.stream,
                carrier: dial.carrier,
                endpoint: dial.endpoint_index,
                ticket: None,
            });
            if let Some((next, next_mask)) = dial.next {
                if i + 1 == count {
                    return Err(ServiceError::InvalidRequest);
                }
                expected_scope = next;
                mask = next_mask;
                input = dial.carrier;
                target = dial.endpoint.ok_or(ServiceError::InvalidRequest)?;
            } else if i + 1 != count {
                return Err(ServiceError::InvalidRequest);
            }
        }
        // Chain проверяет mandatory route context, но не создаёт physical exception.
        let physical = plans[..count]
            .iter()
            .flatten()
            .filter(|p| !matches!(p, RouteRequest::Chain))
            .count();
        let routes = self.budget.routes.reserve(physical).map_err(unavailable)?;
        let previous = self.dns.live.remove(&id);
        self.dns.live.insert(
            id,
            Box::new(Bundle {
                root,
                query,
                request,
                revision,
                fingerprint,
                expires,
                hops,
                previous,
                _memory: memory,
                _routes: routes,
            }),
        );
        let result = (|| {
            let flow = self.flows.get(&source).ok_or(ServiceError::Unavailable)?;
            let tuple = flow.tuple;
            let subject = flow.subject;
            for (i, plan) in plans[..count].iter().enumerate() {
                let ticket = self.authority.route(
                    plan.ok_or(ServiceError::InvalidRequest)?,
                    &proof,
                    source,
                    tuple,
                )?;
                self.dns
                    .live
                    .get_mut(&id)
                    .ok_or(ServiceError::Unavailable)?
                    .hops[i]
                    .ticket = ticket;
            }
            self.authority.check_ingress(
                &self
                    .flows
                    .get(&source)
                    .ok_or(ServiceError::Unavailable)?
                    .socket,
            )?;
            if self.authority.subject(&proof, source, tuple)? != subject
                || self.authority.now() >= expires
            {
                return Err(ServiceError::Unavailable);
            }
            self.fence()?;
            Ok(())
        })();
        if let Err(e) = result {
            if self.authority.fence().is_err() {
                self.unknown = true;
                self.authority.revoke();
                return Err(e);
            }
            self.cancel_dns_bundle(id)?;
            return Err(e);
        }
        // До публикации новой revision старые tickets должны быть KnownClosed.
        let mut current = self.dns.live.remove(&id).ok_or(ServiceError::Unavailable)?;
        let retired = if let Some(old) = current.previous.as_mut() {
            self.retire_bundle_value(old)
        } else {
            Ok(())
        };
        if retired.is_ok() {
            current.previous = None;
        }
        self.dns.live.insert(id, current);
        retired?;
        Ok(id)
    }
    fn bundle_live(&self, id: u64) -> Result<Instant, ServiceError> {
        self.fence()?;
        let b = self.dns.live.get(&id).ok_or(ServiceError::Unavailable)?;
        let g = self.grants.get(&b.root).ok_or(ServiceError::Unavailable)?;
        let source = self.flows.get(&g.source).ok_or(ServiceError::Unavailable)?;
        self.authority.check_ingress(&source.socket)?;
        if g.class != 3
            || self.authority.now() >= b.expires
            || self.authority.now() >= g.expires
            || b.previous.is_some()
        {
            return Err(ServiceError::Unavailable);
        }
        let cap = self.capsule()?;
        for (i, hop) in b.hops.iter().enumerate() {
            let d = cap.dial_scope(hop.scope, hop.branch).map_err(unavailable)?;
            if hop.bundle != id
                || usize::from(hop.index) != i
                || self.authority.now() >= hop.expires
                || (d.subject, d.chain, d.stream, d.carrier, d.endpoint_index)
                    != (
                        hop.subject,
                        hop.chain,
                        hop.stream,
                        hop.carrier,
                        hop.endpoint,
                    )
            {
                return Err(ServiceError::Unavailable);
            }
        }
        Ok(b.expires.min(g.expires))
    }
}

pub(super) fn negotiate<A: Authority>(
    issuer: &Issuer<A>,
    socket: &impl Channel,
    pid: u32,
    uid: u32,
    stop: &AtomicBool,
    until: Instant,
) -> Result<Negotiated, ServiceError> {
    let mut b = [0; RUNTIME_PACKET];
    let descriptor = loop {
        issuer.fence()?;
        if stop.load(Ordering::Acquire) || issuer.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        if let Some(n) = socket.setup_read(pid, uid, &mut b)? {
            if n != 272 {
                return Err(ServiceError::Unavailable);
            }
            let mut d = [0; 272];
            d.copy_from_slice(&b[..272]);
            break d;
        }
        socket.pause_until(until);
    };
    let expected = Negotiated::descriptor(issuer.record).map_err(unavailable)?;
    if descriptor.as_slice() != expected {
        return Err(ServiceError::Unavailable);
    }
    let ack = Negotiated::ack(&descriptor).map_err(unavailable)?;
    loop {
        issuer.fence()?;
        if stop.load(Ordering::Acquire) || issuer.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        if socket.setup_write(&ack)? {
            break;
        }
        socket.writable_until(until);
    }
    let neg =
        Negotiated::accept(&descriptor, &ack, issuer.record, [(0, 0); 2]).map_err(unavailable)?;
    socket.dns_committed(neg)?;
    Ok(neg)
}

#[allow(clippy::too_many_arguments)] // Exact pending reply и общий initial deadline.
pub(super) fn dispatch<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    sequence: u64,
    bytes: &[u8],
    session: Instant,
    mut drain: impl FnMut(&mut Issuer<A>) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let neg = issuer.negotiated.ok_or(ServiceError::Unavailable)?;
    let frame = decode(bytes, &neg, Direction::Producer)?;
    let reply = frame.header.sequence;
    let mut body = [0; 64];
    body[..2].copy_from_slice(&2u16.to_be_bytes());
    let op = match frame.record {
        Record::BundleAcquire(view) => {
            let acquired = if issuer.retired.iter().any(|(request, _)| *request == reply) {
                Err(ServiceError::Unavailable)
            } else {
                issuer.acquire_bundle(reply, view, session)
            };
            match acquired {
                Ok(id) => {
                    let bundle = issuer.dns.live.get(&id).ok_or(ServiceError::Unavailable)?;
                    body[2] = 1;
                    for (at, value) in [
                        (8, id),
                        (16, bundle.root),
                        (24, bundle.query),
                        (32, issuer.record.binding.epoch),
                        (56, bundle.revision),
                    ] {
                        body[at..at + 8].copy_from_slice(&value.to_be_bytes());
                    }
                    body[48..50].copy_from_slice(&(bundle.hops.len() as u16).to_be_bytes());
                }
                Err(_) => body[2] = if issuer.unknown { 3 } else { 2 },
            }
            Operation::BundleGranted
        }
        Record::Cancel(view) if matches!(view.bytes()[2], 1 | 8) => {
            let (target, id) = cancel_fields(view);
            body[2] = if cancel(issuer, reply, target, id).is_ok() {
                1
            } else if issuer.unknown {
                3
            } else {
                2
            };
            if body[2] == 1 {
                body[8..16].copy_from_slice(&id.to_be_bytes());
                body[16..24].copy_from_slice(&reply.to_be_bytes());
            }
            Operation::Canceled
        }
        _ => return Err(ServiceError::Unsupported),
    };
    if !issuer.unknown {
        drain(issuer)?;
    }
    loop {
        if stop.load(Ordering::Acquire) || issuer.authority.now() >= session {
            return Err(ServiceError::Unavailable);
        }
        // Unknown cleanup report не превращается в KnownClosed/Allow.
        if !issuer.unknown {
            issuer.fence()?;
        }
        if op == Operation::BundleGranted && body[2] == 1 {
            let id = u64_at(&body, 8);
            let now = issuer.authority.now();
            if let Ok(until) = issuer.bundle_live(id) {
                body[40..48].copy_from_slice(
                    &((until - now).as_nanos().min(1_000_000_000) as u64).to_be_bytes(),
                );
            } else {
                issuer.cancel_dns_bundle(id)?;
                body[2..].fill(0);
                body[2] = 2;
            }
        }
        let len = if op == Operation::Canceled { 32 } else { 64 };
        let record = Record::decode(op, &body[..len]).map_err(unavailable)?;
        let mut out = [0; 192];
        let n = DnsFrame {
            header: Envelope {
                sequence,
                reply_to: reply,
                binding: issuer.record.binding,
            },
            record,
        }
        .encode(&neg, &mut out)
        .map_err(unavailable)?;
        if socket.write(&out[..n])? {
            return Ok(());
        }
        socket.writable_until(session.min(issuer.authority.now() + Duration::from_millis(20)));
    }
}
pub(super) fn cancel_fields(view: View<'_, 47>) -> (u8, u64) {
    (view.bytes()[2], u64_at(view.bytes(), 8))
}
pub(super) fn cancel<A: Authority>(
    issuer: &mut Issuer<A>,
    sequence: u64,
    target: u8,
    id: u64,
) -> Result<(), ServiceError> {
    match target {
        8 => issuer.cancel_dns_bundle(id),
        1 if id < sequence => issuer.cancel_request(id),
        _ => Err(ServiceError::InvalidRequest),
    }
}
#[allow(clippy::too_many_arguments)] // Exact ACK и абсолютный deadline текущего pending.
pub(super) fn send_canceled<A: Authority>(
    issuer: &Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    sequence: u64,
    reply: u64,
    id: u64,
    status: wire::CloseStatus,
    until: Instant,
) -> Result<(), ServiceError> {
    let neg = issuer.negotiated.ok_or(ServiceError::Unavailable)?;
    let mut body = [0; 32];
    body[..2].copy_from_slice(&2u16.to_be_bytes());
    body[2] = if status == wire::CloseStatus::KnownClosed {
        1
    } else {
        3
    };
    if body[2] == 1 {
        body[8..16].copy_from_slice(&id.to_be_bytes());
        body[16..24].copy_from_slice(&reply.to_be_bytes());
    }
    let record = Record::decode(Operation::Canceled, &body).map_err(unavailable)?;
    let mut out = [0; 160];
    let n = DnsFrame {
        header: Envelope {
            sequence,
            reply_to: reply,
            binding: issuer.record.binding,
        },
        record,
    }
    .encode(&neg, &mut out)
    .map_err(unavailable)?;
    loop {
        if stop.load(Ordering::Acquire) || issuer.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        if !issuer.unknown {
            issuer.fence()?;
        }
        if socket.write(&out[..n])? {
            return Ok(());
        }
        socket.writable_until(until);
    }
}
