//! Immutable DNS DATA, отдельный fresh waiter и checked USER numeric authority.
use super::super::memory::ByteLease;
use super::dns_transport::Binding;
use super::{
    Authority, Channel, Grant, Issuer, OwnerReference, RouteRequest, ServiceError, Target,
    unavailable, wire,
};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use wire::dns_v2::{Operation, Record, View};

const MEMBERS: usize = 256;
const CHAIN: usize = 32;
const RECORDS: usize = 512;
#[derive(Clone, Copy, PartialEq, Eq)]
struct Name {
    bytes: [u8; 253],
    len: usize,
}
impl Name {
    fn empty() -> Self {
        Self {
            bytes: [0; 253],
            len: 0,
        }
    }
    fn lookup(bytes: &[u8]) -> Result<Self, ServiceError> {
        let bytes = bytes.strip_suffix(b".").unwrap_or(bytes);
        if bytes.is_empty() || bytes.len() > 253 {
            return Err(ServiceError::InvalidRequest);
        }
        let mut name = Self::empty();
        for label in bytes.split(|b| *b == b'.') {
            name.label(label)?;
        }
        Ok(name)
    }
    fn label(&mut self, label: &[u8]) -> Result<(), ServiceError> {
        if label.is_empty()
            || label.len() > 63
            || self.len + usize::from(self.len > 0) + label.len() > 253
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_'))
        {
            return Err(ServiceError::InvalidRequest);
        }
        if self.len > 0 {
            self.bytes[self.len] = b'.';
            self.len += 1;
        }
        for b in label {
            self.bytes[self.len] = b.to_ascii_lowercase();
            self.len += 1;
        }
        Ok(())
    }
}
fn u16_at(b: &[u8], at: usize) -> Result<u16, ServiceError> {
    let b = b.get(at..at + 2).ok_or(ServiceError::InvalidRequest)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
fn n16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
fn n64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(std::array::from_fn(|i| b[at + i]))
}
fn put(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_be_bytes());
}
fn name(packet: &[u8], offset: &mut usize) -> Result<Name, ServiceError> {
    let mut result = Name::empty();
    let mut pos = *offset;
    let mut jumped = false;
    let mut pointers = 0;
    loop {
        let first = *packet.get(pos).ok_or(ServiceError::InvalidRequest)?;
        if first & 0xc0 == 0xc0 {
            let target = usize::from(u16_at(packet, pos)? & 0x3fff);
            pointers += 1;
            if pointers > 16 || target >= pos || target < 12 {
                return Err(ServiceError::InvalidRequest);
            }
            if !jumped {
                *offset = pos + 2;
                jumped = true;
            }
            pos = target;
            continue;
        }
        if first & 0xc0 != 0 {
            return Err(ServiceError::InvalidRequest);
        }
        pos += 1;
        if first == 0 {
            if !jumped {
                *offset = pos;
            }
            return Ok(result);
        }
        let end = pos + usize::from(first);
        result.label(packet.get(pos..end).ok_or(ServiceError::InvalidRequest)?)?;
        pos = end;
    }
}
struct Rr {
    owner: Name,
    kind: u16,
    class: u16,
    ttl: u32,
    start: usize,
    end: usize,
}
fn rr(packet: &[u8], offset: &mut usize) -> Result<Rr, ServiceError> {
    let owner = name(packet, offset)?;
    let header = packet
        .get(*offset..*offset + 10)
        .ok_or(ServiceError::InvalidRequest)?;
    let kind = n16(header, 0);
    let class = n16(header, 2);
    let ttl = u32::from_be_bytes(header[4..8].try_into().map_err(unavailable)?);
    let start = *offset + 10;
    let end = start + usize::from(n16(header, 8));
    packet.get(start..end).ok_or(ServiceError::InvalidRequest)?;
    *offset = end;
    if kind == 1 && end - start != 4 || kind == 28 && end - start != 16 {
        return Err(ServiceError::InvalidRequest);
    }
    if kind == 5 {
        let mut at = start;
        name(packet, &mut at)?;
        if at != end {
            return Err(ServiceError::InvalidRequest);
        }
    }
    Ok(Rr {
        owner,
        kind,
        class,
        ttl,
        start,
        end,
    })
}
fn question(packet: &[u8], expected: Name, qtype: u16) -> Result<usize, ServiceError> {
    if packet.len() < 12 || n16(packet, 4) != 1 {
        return Err(ServiceError::InvalidRequest);
    }
    let mut at = 12;
    if name(packet, &mut at)? != expected
        || u16_at(packet, at)? != qtype
        || u16_at(packet, at + 2)? != 1
    {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(at + 4)
}
fn opt(
    packet: &[u8],
    rr: &Rr,
    payload: u16,
    options: u16,
    request: bool,
) -> Result<(), ServiceError> {
    if rr.owner.len != 0
        || rr.kind != 41
        || !(512..=4096).contains(&rr.class)
        || request && rr.class != payload
        || rr.ttl & !0x8000 != 0
        || (rr.ttl & 0x8000 != 0) != (options & 4 != 0)
        || rr.start != rr.end
    {
        return Err(ServiceError::Unsupported);
    }
    packet
        .get(rr.start..rr.end)
        .ok_or(ServiceError::InvalidRequest)?;
    Ok(())
}
struct Answer {
    members: [IpAddr; MEMBERS],
    count: usize,
    ttl: u32,
}
fn unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && ip != Ipv4Addr::BROADCAST
                && ip.octets()[0] != 0
                && ip.octets()[0] < 240
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none()
        }
    }
}
pub(super) fn numeric_ip_allowed(ip: IpAddr) -> bool {
    unicast(ip)
        && !ip.is_loopback()
        && !matches!(ip,IpAddr::V4(ip) if ip.is_link_local())
        && !matches!(ip,IpAddr::V6(ip) if ip.is_unicast_link_local())
}
// Все scratch buffers заранее учтены caller; parser не аллоцирует.
pub(super) const SCRATCH: usize =
    std::mem::size_of::<Answer>() + (CHAIN + 4) * std::mem::size_of::<Name>() + 4096;
fn parse(
    request: &[u8],
    response: &[u8],
    lookup: &[u8],
    qtype: u16,
    options: u16,
    payload: u16,
) -> Result<Answer, ServiceError> {
    if !(12..=512).contains(&request.len())
        || !(12..=32768).contains(&response.len())
        || !matches!(qtype, 1 | 28)
    {
        return Err(ServiceError::InvalidRequest);
    }
    let expected = Name::lookup(lookup)?;
    let flags = (if options & 1 != 0 { 0x100 } else { 0 })
        | (if options & 2 != 0 { 0x10 } else { 0 })
        | (if options & 16 != 0 { 0x20 } else { 0 });
    if n16(request, 2) != flags
        || n16(request, 6) != 0
        || n16(request, 8) != 0
        || n16(request, 10) != u16::from(options & 8 != 0)
    {
        return Err(ServiceError::InvalidRequest);
    }
    let mut at = question(request, expected, qtype)?;
    if options & 8 != 0 {
        let record = rr(request, &mut at)?;
        opt(request, &record, payload, options, true)?;
    }
    if at != request.len()
        || request[..2] != response[..2]
        || n16(response, 2) & 0xf != 0
        || n16(response, 2) & 0xf800 != 0x8000
        || n16(response, 2) & 0x0240 != 0
        || n16(response, 2) & 0x110 != flags & 0x110
    {
        return Err(ServiceError::InvalidRequest);
    }
    let answer_start = question(response, expected, qtype)?;
    let answers = usize::from(n16(response, 6));
    let total = answers + usize::from(n16(response, 8)) + usize::from(n16(response, 10));
    if answers == 0 || total > RECORDS {
        return Err(ServiceError::InvalidRequest);
    }
    let mut cursor = answer_start;
    let mut opts = 0;
    for index in 0..total {
        let record = rr(response, &mut cursor)?;
        if record.kind == 41 {
            opts += 1;
            if options & 8 == 0 || index < answers + usize::from(n16(response, 8)) || opts > 1 {
                return Err(ServiceError::InvalidRequest);
            }
            opt(response, &record, payload, options, false)?;
        } else if record.class != 1 {
            return Err(ServiceError::InvalidRequest);
        }
    }
    if cursor != response.len() {
        return Err(ServiceError::InvalidRequest);
    }
    let mut path = [Name::empty(); CHAIN];
    let mut depth = 1;
    path[0] = expected;
    let mut current = expected;
    let mut ttl = u32::MAX;
    loop {
        let mut next = None;
        let mut cursor = answer_start;
        let mut address = false;
        for _ in 0..answers {
            let record = rr(response, &mut cursor)?;
            if record.owner != current {
                continue;
            }
            if matches!(record.kind, 1 | 28) {
                address = true;
            }
            if record.kind == 5 {
                let mut offset = record.start;
                let target = name(response, &mut offset)?;
                if next.is_some_and(|n| n != target) {
                    return Err(ServiceError::InvalidRequest);
                }
                next = Some(target);
                ttl = ttl.min(record.ttl);
            }
        }
        let Some(next) = next else { break };
        if address || depth == CHAIN || path[..depth].contains(&next) {
            return Err(ServiceError::InvalidRequest);
        }
        path[depth] = next;
        depth += 1;
        current = next;
    }
    let mut result = Answer {
        members: [IpAddr::V4(Ipv4Addr::UNSPECIFIED); MEMBERS],
        count: 0,
        ttl,
    };
    let mut cursor = answer_start;
    for _ in 0..answers {
        let record = rr(response, &mut cursor)?;
        if !path[..depth].contains(&record.owner) {
            return Err(ServiceError::InvalidRequest);
        }
        if matches!(record.kind, 1 | 28) {
            if record.owner != current || record.kind != qtype {
                return Err(ServiceError::InvalidRequest);
            }
            let bytes = &response[record.start..record.end];
            let ip = if record.kind == 1 {
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(bytes).map_err(unavailable)?,
                ))
            } else {
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(bytes).map_err(unavailable)?,
                ))
            };
            if !unicast(ip) {
                return Err(ServiceError::InvalidRequest);
            }
            result.ttl = result.ttl.min(record.ttl);
            if !result.members[..result.count].contains(&ip) {
                if result.count == MEMBERS {
                    return Err(ServiceError::Busy);
                }
                result.members[result.count] = ip;
                result.count += 1;
            }
        }
    }
    if result.count == 0 || result.ttl == 0 {
        return Err(ServiceError::Unavailable);
    }
    Ok(result)
}

pub(super) fn verify_bootstrap_capture(
    request: &[u8],
    response: &[u8],
    lookup: &[u8],
    qtype: u16,
    options: u16,
    payload: u16,
) -> Result<(), ServiceError> {
    parse(request, response, lookup, qtype, options, payload).map(|_| ())
}
struct Producer {
    bootstrap: Option<Box<BootstrapPublication>>,
    binding: Binding,
    proof: u64,
    revision: u64,
    exchange: u64,
    request: u64,
    expires: Instant,
    answer: Answer,
    acked: bool,
    revoked: bool,
    _memory: ByteLease,
}
struct BootstrapPublication {
    raw: Box<[u8]>,
    observed: Instant,
}
struct Waiter {
    numeric_once: Option<(u64, u64)>,
    binding: Binding,
    producer: u64,
    reservation: u64,
    request: u64,
    expires: Instant,
    acked: bool,
    revoked: bool,
    _memory: ByteLease,
}
pub(super) struct State {
    producers: BTreeMap<u64, Box<Producer>>,
    waiters: BTreeMap<u64, Box<Waiter>>,
    next_producer: u64,
    next_waiter: u64,
}
impl State {
    pub(super) fn counts(&self) -> (usize, usize) {
        (self.producers.len(), self.waiters.len())
    }
    pub(super) fn host_id<A: Authority>(&mut self, op: Operation) -> Result<u64, ServiceError> {
        let counter = match op {
            Operation::Published => &mut self.next_producer,
            Operation::WaiterBound => &mut self.next_waiter,
            _ => return Err(ServiceError::InvalidRequest),
        };
        Issuer::<A>::id(counter)
    }
    #[cfg(test)]
    pub(super) fn waiter_flags(&self) -> Vec<bool> {
        self.waiters
            .values()
            .map(|w| w.acked && !w.revoked)
            .collect()
    }
    #[cfg(test)]
    pub(super) fn producer_flags(&self) -> Vec<bool> {
        self.producers
            .values()
            .map(|p| p.acked && !p.revoked)
            .collect()
    }
    #[cfg(test)]
    pub(super) fn data_lifetime(&self) -> Option<(Instant, Instant)> {
        self.producers
            .values()
            .next()
            .map(|p| (p.binding.expires, p.expires))
    }
    pub(super) fn new() -> Self {
        Self {
            producers: BTreeMap::new(),
            waiters: BTreeMap::new(),
            next_producer: 0,
            next_waiter: 0,
        }
    }
    pub(super) fn cancel_bundle(&mut self, bundle: u64) {
        for p in self.producers.values_mut() {
            if p.binding.bootstrap && p.binding.bundle == bundle {
                p.revoked = true;
            }
        }
        for w in self.waiters.values_mut() {
            if w.binding.bundle == bundle {
                w.revoked = true;
            }
        }
    }
    pub(super) fn cancel_reservation(&mut self, reservation: u64) {
        for waiter in self.waiters.values_mut() {
            if waiter.reservation == reservation {
                waiter.revoked = true;
            }
        }
    }
    pub(super) fn cancel_request(&mut self, request: u64) {
        for p in self.producers.values_mut() {
            if p.request == request {
                p.revoked = true;
            }
        }
        for w in self.waiters.values_mut() {
            if w.request == request {
                w.revoked = true;
            }
        }
    }
    pub(super) fn cancel(&mut self, target: u8, id: u64) -> Result<(), ServiceError> {
        match target {
            5 => {
                let p = self
                    .producers
                    .get_mut(&id)
                    .ok_or(ServiceError::InvalidRequest)?;
                p.revoked = true;
                for w in self.waiters.values_mut() {
                    if w.producer == id {
                        w.revoked = true;
                    }
                }
            }
            6 => {
                self.waiters
                    .get_mut(&id)
                    .ok_or(ServiceError::InvalidRequest)?
                    .revoked = true
            }
            _ => return Err(ServiceError::InvalidRequest),
        }
        Ok(())
    }
}
fn same_data(a: Binding, b: Binding) -> bool {
    if a.bootstrap != b.bootstrap || a.parent_carrier != b.parent_carrier {
        return false;
    }
    let (Ok(a_name), Ok(b_name)) = (
        Name::lookup(a.name.wire().bytes),
        Name::lookup(b.name.wire().bytes),
    ) else {
        return false;
    };
    (
        a.epoch,
        a.resolver,
        a.subject,
        a.scope,
        a.branch,
        a.qtype,
        a.options,
        a.payload,
        a.source_revision,
        a.peer,
    ) == (
        b.epoch,
        b.resolver,
        b.subject,
        b.scope,
        b.branch,
        b.qtype,
        b.options,
        b.payload,
        b.source_revision,
        b.peer,
    ) && a_name == b_name
}
impl<A: Authority> Issuer<A> {
    fn bootstrap_reply_fence(&mut self, op: Operation, id: u64) -> Result<(), ServiceError> {
        let bootstrap = if op == Operation::Published {
            self.rrsets
                .producers
                .get(&id)
                .is_some_and(|p| p.binding.bootstrap)
        } else {
            self.rrsets
                .waiters
                .get(&id)
                .is_some_and(|w| w.binding.bootstrap)
        };
        if bootstrap {
            self.rrset_reply(op, id, &mut [0; 64])?;
        }
        Ok(())
    }
    fn bootstrap_response_observed(
        &self,
        binding: Binding,
        b: &[u8],
    ) -> Result<Instant, ServiceError> {
        let q = usize::from(n16(b, 108));
        let r = usize::from(n16(b, 110));
        let receipt = super::BootstrapDnsReceipt {
            lifetime_anchor: self.dns_lifetime_anchor(
                n64(b, 120),
                n64(b, 128),
                n64(b, 28),
                binding,
            )?,
            binding,
            proof: n64(b, 120),
            revision: n64(b, 128),
            exchange: n64(b, 28),
            producer_sequence: self.dns_producer_sequence(n64(b, 120))?,
            request: &b[144 + q..144 + q + r],
            response: &b[144 + q + r..],
        };
        // DATA sanity до trusted endpoint; числа и transcript hash не mint.
        if !receipt.binding.bootstrap
            || [
                receipt.proof,
                receipt.revision,
                receipt.exchange,
                receipt.producer_sequence,
            ]
            .iter()
            .any(|v| *v == 0 || *v == u64::MAX)
            || !(12..=512).contains(&receipt.request.len())
            || !(12..=32768).contains(&receipt.response.len())
        {
            return Err(ServiceError::InvalidRequest);
        }
        self.bootstrap_transcript
            .as_ref()
            .ok_or(ServiceError::Unsupported)?
            .observed(self.record, receipt)
    }
    fn bootstrap_rrset_live(&self, p: &Producer) -> Result<Instant, ServiceError> {
        let capture = p.bootstrap.as_ref().ok_or(ServiceError::Unavailable)?;
        let (_, until) = self.bootstrap_dns_data(p.binding)?;
        if self.bootstrap_response_observed(p.binding, &capture.raw)? != capture.observed {
            return Err(ServiceError::Unavailable);
        }
        let until = p
            .expires
            .min(until)
            .min(self.bootstrap_dns_data(p.binding)?.1);
        if self.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        Ok(until)
    }
    fn rrset_data_matches(&self, a: Binding, b: Binding) -> Result<(), ServiceError> {
        if !same_data(a, b) {
            return Err(ServiceError::InvalidRequest);
        }
        if a.bootstrap {
            self.bootstrap_dns_same_data(a.bundle, b.bundle)?;
        }
        Ok(())
    }
    fn publish_dns(
        &mut self,
        v: View<'_, 40>,
        request: u64,
        session: Instant,
    ) -> Result<u64, ServiceError> {
        self.fence()?;
        let b = v.bytes();
        if b[137] == 2 {
            return self.publish_hosts(v, request, session);
        }
        if !matches!(b[136], 1 | 2) || b[137] != 1 {
            return Err(ServiceError::Unsupported);
        }
        self.bundle_history_available(1)?;
        let (binding, published) =
            self.dns_publication_metadata(n64(b, 120), n64(b, 128), n64(b, 28))?;
        if published {
            return Err(ServiceError::InvalidRequest);
        }
        let q = usize::from(n16(b, 108));
        let r = usize::from(n16(b, 110));
        if binding.peer.protocol == 17
            && b.len() - 144 - q - r
                > usize::from(if binding.options & 8 != 0 {
                    binding.payload
                } else {
                    512
                })
        {
            return Err(ServiceError::InvalidRequest);
        }
        if n16(b, 4) != binding.resolver
            || n16(b, 6) != binding.subject
            || n16(b, 10) != binding.qtype
            || n64(b, 12) != binding.query
            || n64(b, 20) != binding.root
            || n64(b, 36) != binding.epoch
            || b[136] != if binding.bootstrap { 2 } else { 1 }
            || b[142]
                != if binding.bootstrap {
                    binding.parent_carrier
                } else {
                    binding.peer.protocol
                }
            || n16(b, 8)
                != if binding.bootstrap {
                    binding.physical_endpoint
                } else {
                    u16::MAX
                }
            || n16(b, 140)
                != if binding.bootstrap {
                    binding.physical_scope
                } else {
                    u16::MAX
                }
            || &b[144..144 + q] != binding.name.wire().bytes
            || self.rrsets.producers.len() + self.dns.hosts_counts().0 >= 64
        {
            return Err(ServiceError::InvalidRequest);
        }
        let reference = if binding.bootstrap {
            Some(
                self.capsule()?
                    .bootstrap_snapshot()
                    .map_err(unavailable)?
                    .asset_reference(),
            )
        } else {
            None
        };
        if let Some(reference) = reference {
            if b[44..76] != reference.source || b[76..108] != reference.asset {
                return Err(ServiceError::InvalidRequest);
            }
        } else if b[44..108].iter().any(|v| *v != 0)
            || self
                .capsule()?
                .resolver_scope(binding.resolver)
                .map_err(unavailable)?
                .source
                != [0; 32]
        {
            return Err(ServiceError::Unsupported);
        }
        let (_, started, _) = self.dns_publish_binding(n64(b, 120), n64(b, 128), n64(b, 28))?;
        let memory = self
            .budget
            .dynamic
            .reserve(
                std::mem::size_of::<Producer>()
                    + 80
                    + if binding.bootstrap {
                        std::mem::size_of::<BootstrapPublication>() + b.len()
                    } else {
                        0
                    },
            )
            .map_err(unavailable)?;
        let answer = {
            let _scratch = self.budget.dynamic.reserve(SCRATCH).map_err(unavailable)?;
            parse(
                &b[144 + q..144 + q + r],
                &b[144 + q + r..],
                &b[144..144 + q],
                binding.qtype,
                binding.options,
                binding.payload,
            )?
        };
        let observed = if binding.bootstrap {
            self.bootstrap_response_observed(binding, b)?
        } else {
            started
        };
        if observed < started || observed > self.authority.now() {
            return Err(ServiceError::Unavailable);
        }
        let mut expires = observed
            .checked_add(Duration::from_secs(u64::from(answer.ttl)))
            .ok_or(ServiceError::Unavailable)?
            .min(session);
        if binding.bootstrap {
            expires = expires.min(self.bootstrap_dns_data(binding)?.1);
        }
        if self.authority.now() >= expires {
            return Err(ServiceError::Unavailable);
        }
        self.dns_publish_binding(n64(b, 120), n64(b, 128), n64(b, 28))?;
        self.bundle_history(1)?;
        let id = Self::id(&mut self.rrsets.next_producer)?;
        self.dns_freeze_publish(n64(b, 120))?;
        self.rrsets.producers.insert(
            id,
            Box::new(Producer {
                bootstrap: binding.bootstrap.then(|| {
                    Box::new(BootstrapPublication {
                        raw: b.into(),
                        observed,
                    })
                }),
                binding,
                proof: n64(b, 120),
                revision: n64(b, 128),
                exchange: n64(b, 28),
                request,
                expires,
                answer,
                acked: false,
                revoked: false,
                _memory: memory,
            }),
        );
        Ok(id)
    }
    fn fresh_waiter(&mut self, binding: Binding) -> Result<Instant, ServiceError> {
        if binding.bootstrap {
            return self.bootstrap_dns_data(binding).map(|(_, until)| until);
        }
        if self.dns_transport_binding(binding.bundle)? != binding {
            return Err(ServiceError::Unavailable);
        }
        let flow = self
            .flows
            .get(&binding.source)
            .ok_or(ServiceError::Unavailable)?;
        self.authority.check_ingress(&flow.socket)?;
        let tuple = flow.tuple;
        let subject = flow.subject;
        let proof = self
            .authority
            .owner(binding.source, tuple, OwnerReference::NONE)?;
        if self.authority.subject(&proof, binding.source, tuple)? != subject {
            return Err(ServiceError::Unavailable);
        }
        let expiry = binding
            .expires
            .min(self.authority.expiry(&proof).unwrap_or(binding.expires));
        if self.authority.now() >= expiry {
            return Err(ServiceError::Unavailable);
        }
        Ok(expiry)
    }
    fn bind_dns_waiter(
        &mut self,
        v: View<'_, 53>,
        request: u64,
        session: Instant,
    ) -> Result<u64, ServiceError> {
        self.fence()?;
        let b = v.bytes();
        let reservation = n64(b, 8);
        if self.is_hosts_reservation(reservation) {
            return self.bind_hosts_waiter(v, request, session);
        }
        let producer = n64(b, 16);
        let (binding, reservation_expires) = self.dns_waiter_binding(reservation)?;
        let p = self
            .rrsets
            .producers
            .get(&producer)
            .ok_or(ServiceError::Unavailable)?;
        if !p.acked
            || p.revoked
            || p.expires <= self.authority.now()
            || self.rrset_data_matches(binding, p.binding).is_err()
            || binding.bootstrap && binding.root == p.binding.root
            || binding.bundle == p.binding.bundle
            || n64(b, 24) != binding.root
            || n64(b, 32) != binding.query
            || n64(b, 40) != binding.source
            || n64(b, 48) != binding.source_revision
            || self.rrsets.waiters.values().any(|w| {
                w.reservation == reservation
                    || w.binding.bundle == binding.bundle
                    || w.binding.root == binding.root && w.binding.bootstrap == binding.bootstrap
            })
            || self.rrsets.waiters.len() + self.dns.hosts_counts().1 >= 256
        {
            return Err(ServiceError::InvalidRequest);
        }
        let source_until = if binding.bootstrap {
            self.bootstrap_rrset_live(p)?
        } else {
            p.expires
        };
        let expires = p
            .expires
            .min(source_until)
            .min(reservation_expires)
            .min(session)
            .min(self.authority.now() + Duration::from_nanos(n64(b, 56)));
        let memory = self
            .budget
            .dynamic
            .reserve(std::mem::size_of::<Waiter>() + 80)
            .map_err(unavailable)?;
        self.bundle_history(1)?;
        let expires = expires.min(self.fresh_waiter(binding)?);
        let id = Self::id(&mut self.rrsets.next_waiter)?;
        self.rrsets.waiters.insert(
            id,
            Box::new(Waiter {
                numeric_once: None,
                binding,
                producer,
                reservation,
                request,
                expires,
                acked: false,
                revoked: false,
                _memory: memory,
            }),
        );
        Ok(id)
    }
    fn rrset_reply(
        &mut self,
        operation: Operation,
        id: u64,
        out: &mut [u8; 64],
    ) -> Result<Instant, ServiceError> {
        self.fence()?;
        if let Some(until) = self.hosts_rrset_reply(operation, id, out)? {
            return Ok(until);
        }
        if operation == Operation::Published {
            let p = self
                .rrsets
                .producers
                .get(&id)
                .ok_or(ServiceError::Unavailable)?;
            if p.revoked || p.expires <= self.authority.now() {
                return Err(ServiceError::Unavailable);
            }
            let source_until = if p.binding.bootstrap {
                self.bootstrap_rrset_live(p)?
            } else {
                p.expires
            };
            if !p.acked {
                let (proof, revision, exchange, binding) =
                    (p.proof, p.revision, p.exchange, p.binding);
                if self.dns_publish_binding(proof, revision, exchange)?.0 != binding {
                    return Err(ServiceError::Unavailable);
                }
            }
            let p = self
                .rrsets
                .producers
                .get(&id)
                .ok_or(ServiceError::Unavailable)?;
            let now = self.authority.now();
            let expires = p.expires.min(source_until);
            if now >= expires {
                return Err(ServiceError::Unavailable);
            }
            put(out, 8, id);
            put(out, 16, p.exchange);
            put(out, 24, p.binding.epoch);
            put(
                out,
                32,
                (expires - now)
                    .as_nanos()
                    .min(u128::from(u32::MAX) * 1_000_000_000) as u64,
            );
            out[40..42].copy_from_slice(&(p.answer.count as u16).to_be_bytes());
            Ok(expires)
        } else {
            let w = self
                .rrsets
                .waiters
                .get(&id)
                .ok_or(ServiceError::Unavailable)?;
            let p = self
                .rrsets
                .producers
                .get(&w.producer)
                .ok_or(ServiceError::Unavailable)?;
            if w.revoked || p.revoked || self.authority.now() >= w.expires.min(p.expires) {
                return Err(ServiceError::Unavailable);
            }
            let binding = w.binding;
            let source_until = if binding.bootstrap {
                self.rrset_data_matches(binding, p.binding)?;
                self.bootstrap_rrset_live(p)?
            } else {
                p.expires
            };
            let expiry = w.expires.min(p.expires).min(source_until);
            let (producer, reservation, count) = (w.producer, w.reservation, p.answer.count);
            let (current_binding, reservation_expires) = self.dns_waiter_binding(reservation)?;
            if current_binding != binding {
                return Err(ServiceError::Unavailable);
            }
            let until = self
                .fresh_waiter(binding)?
                .min(expiry)
                .min(reservation_expires);
            let now = self.authority.now();
            if now >= until {
                return Err(ServiceError::Unavailable);
            }
            put(out, 8, id);
            put(out, 16, producer);
            put(out, 24, reservation);
            put(out, 32, binding.query);
            put(out, 40, binding.epoch);
            put(out, 48, (until - now).as_nanos().min(1_000_000_000) as u64);
            out[56..58].copy_from_slice(&(count as u16).to_be_bytes());
            out[58] = 1;
            out[59] = if binding.bootstrap { 2 } else { 1 };
            Ok(until)
        }
    }
}
/// Только checked_numeric создаёт такой token; caller/class3 DATA не конструкторы.
struct CheckedNumeric<'a> {
    base: wire::Authorize<'a>,
    target: Target,
    waiter: u64,
    member: u16,
    expires: Instant,
}
pub(super) struct NumericBinding {
    waiter: u64,
    member: u16,
    _memory: ByteLease,
}
/// Только checked_network_numeric создаёт этот private NETWORK variant.
/// Binding удерживается immutable waiter/producer, а не копируется в permission.
/// Их ID монотонны до overflow-denial, записи не заменяются и не удаляются.
/// network_permission_live повторяет полный candidate/Source/transcript check
/// по retained записям и сравнивает exact IDs, revision, selector/member/target.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct NetworkNumericProof {
    waiter: u64,
    producer: u64,
    reservation: u64,
    proof: u64,
    revision: u64,
    exchange: u64,
    selector: wire::dns_v2::BootstrapSelector,
    member: u16,
    target: Target,
}
#[cfg(test)]
#[test]
fn network_numeric_proof_retains_ids_instead_of_duplicate_binding() {
    // Ограничение на реальные inline данные, а не только на budget debit.
    assert!(std::mem::size_of::<NetworkNumericProof>() <= 512);
    assert!(std::mem::size_of::<NetworkNumericProof>() < std::mem::size_of::<Binding>());
}
impl<A: Authority> Issuer<A> {
    pub(super) fn network_numeric_query(
        &self,
        proof: NetworkNumericProof,
    ) -> Result<u64, ServiceError> {
        let w = self
            .rrsets
            .waiters
            .get(&proof.waiter)
            .ok_or(ServiceError::Unavailable)?;
        if w.producer != proof.producer || w.reservation != proof.reservation {
            return Err(ServiceError::Unavailable);
        }
        Ok(w.binding.query)
    }
    fn network_numeric_candidate(
        &self,
        waiter: u64,
        member: u16,
        target: Target,
        selector: wire::dns_v2::BootstrapSelector,
    ) -> Result<(NetworkNumericProof, Instant), ServiceError> {
        self.fence()?;
        let w = self
            .rrsets
            .waiters
            .get(&waiter)
            .ok_or(ServiceError::Unavailable)?;
        let p = self
            .rrsets
            .producers
            .get(&w.producer)
            .ok_or(ServiceError::Unavailable)?;
        if !w.acked
            || w.revoked
            || !p.acked
            || p.revoked
            || !w.binding.bootstrap
            || !p.binding.bootstrap
            || p.bootstrap.is_none()
            || !same_data(w.binding, p.binding)
            || w.binding.root == p.binding.root
            || w.binding.source != 0
            || w.binding.source_revision != 0
        {
            return Err(ServiceError::InvalidRequest);
        }
        let original = self.network_numeric_original(w.binding, selector)?;
        if target.protocol != original.protocol
            || target.port != original.port
            || !matches!(target.protocol, 6 | 17)
        {
            return Err(ServiceError::Unsupported);
        }
        if target.protocol == 17 {
            self.datagram_query(w.binding.query)?;
        }
        // Все immutable поля/member/address проверены ДО Source и history debit.
        self.numeric_member(waiter, member, target)?;
        let (binding, reservation_until) = self.dns_waiter_binding(w.reservation)?;
        if binding != w.binding {
            return Err(ServiceError::Unavailable);
        }
        self.rrset_data_matches(binding, p.binding)?;
        self.dns_frozen_revision(p.proof, p.revision, p.exchange, p.binding)?;
        let until = w
            .expires
            .min(p.expires)
            .min(reservation_until)
            .min(binding.expires)
            .min(self.bootstrap_rrset_live(p)?)
            .min(self.bootstrap_dns_data(binding)?.1);
        if self.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        Ok((
            NetworkNumericProof {
                waiter,
                producer: w.producer,
                reservation: w.reservation,
                proof: p.proof,
                revision: p.revision,
                exchange: p.exchange,
                selector,
                member,
                target,
            },
            until,
        ))
    }
    pub(super) fn checked_network_numeric(
        &self,
        v: View<'_, 42>,
    ) -> Result<(NetworkNumericProof, Instant), ServiceError> {
        let b = v.bytes();
        if b[14] != 2 || b[15] != 3 {
            return Err(ServiceError::Unsupported);
        }
        let waiter = v.waiter().map_err(unavailable)?.get();
        if self
            .rrsets
            .waiters
            .get(&waiter)
            .is_none_or(|w| w.numeric_once.is_some())
        {
            return Err(ServiceError::InvalidRequest);
        }
        self.network_numeric_candidate(
            waiter,
            n16(b, 2),
            Target::copy(v.numeric_destination())?,
            v.bootstrap_selector()
                .map_err(unavailable)?
                .ok_or(ServiceError::InvalidRequest)?,
        )
    }
    pub(super) fn consume_network_numeric(
        &mut self,
        proof: NetworkNumericProof,
        request: u64,
        id: u64,
    ) -> Result<(), ServiceError> {
        let w = self
            .rrsets
            .waiters
            .get_mut(&proof.waiter)
            .ok_or(ServiceError::Unavailable)?;
        if w.numeric_once.is_some()
            || w.reservation != proof.reservation
            || w.producer != proof.producer
        {
            return Err(ServiceError::Unavailable);
        }
        w.numeric_once = Some((request, id));
        Ok(())
    }
    pub(super) fn network_permission_live(
        &self,
        proof: NetworkNumericProof,
        request: u64,
        id: u64,
        waiter: u64,
        member: u16,
        target: Target,
    ) -> Result<Instant, ServiceError> {
        if (waiter, member, target) != (proof.waiter, proof.member, proof.target)
            || self
                .rrsets
                .waiters
                .get(&waiter)
                .is_none_or(|w| w.numeric_once != Some((request, id)))
        {
            return Err(ServiceError::Unavailable);
        }
        let (current, until) =
            self.network_numeric_candidate(waiter, member, target, proof.selector)?;
        if current != proof {
            return Err(ServiceError::Unavailable);
        }
        Ok(until)
    }
    fn numeric_parent(&self, waiter: u64) -> Result<(Binding, Instant), ServiceError> {
        self.fence()?;
        let w = self
            .rrsets
            .waiters
            .get(&waiter)
            .ok_or(ServiceError::Unavailable)?;
        let p = self
            .rrsets
            .producers
            .get(&w.producer)
            .ok_or(ServiceError::Unavailable)?;
        if !w.acked || w.revoked || !p.acked || p.revoked || !same_data(w.binding, p.binding) {
            return Err(ServiceError::Unavailable);
        }
        let (binding, reservation_expires) = self.dns_waiter_binding(w.reservation)?;
        let expires = w
            .expires
            .min(p.expires)
            .min(reservation_expires)
            .min(binding.expires);
        if binding != w.binding || self.authority.now() >= expires {
            return Err(ServiceError::Unavailable);
        }
        Ok((binding, expires))
    }
    fn numeric_member(&self, waiter: u64, index: u16, target: Target) -> Result<(), ServiceError> {
        let w = self
            .rrsets
            .waiters
            .get(&waiter)
            .ok_or(ServiceError::Unavailable)?;
        let p = self
            .rrsets
            .producers
            .get(&w.producer)
            .ok_or(ServiceError::Unavailable)?;
        let member = p
            .answer
            .members
            .get(usize::from(index))
            .filter(|_| usize::from(index) < p.answer.count)
            .ok_or(ServiceError::InvalidRequest)?;
        let d = target.wire();
        let equal = match member {
            IpAddr::V4(ip) => d.family == 4 && d.bytes == ip.octets(),
            IpAddr::V6(ip) => d.family == 6 && d.bytes == ip.octets(),
        };
        if !equal || !numeric_ip_allowed(*member) {
            return Err(ServiceError::InvalidRequest);
        }
        Ok(())
    }
    fn checked_numeric<'a>(
        &self,
        v: View<'a, 42>,
        session: Instant,
    ) -> Result<CheckedNumeric<'a>, ServiceError> {
        let b = v.bytes();
        if b[14] != 1 || b[15] != 1 {
            return Err(ServiceError::Unsupported);
        }
        let waiter = v.waiter().map_err(unavailable)?.get();
        let (binding, expires) = self.numeric_parent(waiter)?;
        let w = self
            .rrsets
            .waiters
            .get(&waiter)
            .ok_or(ServiceError::Unavailable)?;
        if w.numeric_once.is_some() {
            return Err(ServiceError::InvalidRequest);
        }
        let base = v.authorization().map_err(unavailable)?;
        let flow = self
            .flows
            .get(&base.source_flow)
            .ok_or(ServiceError::Unavailable)?;
        let cap = self.capsule()?;
        cap.validate_request(&wire::Message::Authorize(base))
            .map_err(unavailable)?;
        let original = Target::copy(base.original)?;
        let target = Target::copy(v.numeric_destination())?;
        let dial = cap
            .dial_scope(base.scope, base.branch)
            .map_err(unavailable)?;
        if base.class != 1
            || base.source_flow != binding.source
            || binding.source_revision != cap.policy_revision
            || flow.numeric_only
            || flow.root.is_some()
            || flow.original != original
            || original.family != 3
            || Target::copy(base.effective)? != original
            || Name::lookup(original.wire().bytes)? != Name::lookup(binding.name.wire().bytes)?
            || target.protocol != original.protocol
            || target.port != original.port
            || dial.input != original.protocol
            || dial.carrier != original.protocol
            || dial.action != 3
            || dial.next.is_some()
            || dial.subject != base.subject
            || dial.chain != base.chain
            || dial.stream != base.transport
        {
            return Err(ServiceError::InvalidRequest);
        }
        self.numeric_member(waiter, n16(b, 2), target)?;
        Ok(CheckedNumeric {
            base,
            target,
            waiter,
            member: n16(b, 2),
            expires: expires
                .min(session)
                .min(self.authority.now() + Duration::from_secs(1)),
        })
    }
    fn authorize_numeric(
        &mut self,
        request: u64,
        v: View<'_, 42>,
        session: Instant,
    ) -> Result<(u64, A::Proof), ServiceError> {
        if self.retired.iter().any(|(n, _)| *n == request) {
            return Err(ServiceError::Unavailable);
        }
        let checked = self.checked_numeric(v, session)?;
        if self.grants.len() + self.services.len() + self.hosts_permission_count()
            >= self.capsule()?.limits()[0] as usize
        {
            return Err(ServiceError::Busy);
        }
        let memory = self
            .budget
            .dynamic
            .reserve(std::mem::size_of::<Grant>() + std::mem::size_of::<NumericBinding>() + 96)
            .map_err(unavailable)?;
        let query_credit = self.budget.dynamic.reserve(24).map_err(unavailable)?;
        let routes = self.budget.routes.reserve(1).map_err(unavailable)?;
        self.bundle_history(1)?;
        let mut tickets = Vec::with_capacity(1);
        let a = checked.base;
        let flow = self
            .flows
            .get(&a.source_flow)
            .ok_or(ServiceError::Unavailable)?;
        self.authority.check_ingress(&flow.socket)?;
        let (tuple, subject) = (flow.tuple, flow.subject);
        let proof = self.authority.owner(
            a.source_flow,
            tuple,
            OwnerReference {
                kind: a.receipt.kind,
                id: a.receipt.id,
            },
        )?;
        if self.authority.subject(&proof, a.source_flow, tuple)? != subject {
            return Err(ServiceError::Unavailable);
        }
        let expires = checked
            .expires
            .min(self.authority.expiry(&proof).unwrap_or(checked.expires));
        if expires.saturating_duration_since(self.authority.now()) < Duration::from_millis(1) {
            return Err(ServiceError::Unavailable);
        }
        let id = Self::id(&mut self.next_grant)?;
        self.rrsets
            .waiters
            .get_mut(&checked.waiter)
            .ok_or(ServiceError::Unavailable)?
            .numeric_once = Some((request, id));
        self.flows
            .get_mut(&a.source_flow)
            .ok_or(ServiceError::Unavailable)?
            .numeric_only = true;
        // Placeholder удерживает custody/credits при uncertain backend effect.
        self.grants.insert(
            id,
            Box::new(Grant {
                sent: AtomicBool::new(false),
                numeric: Some(NumericBinding {
                    waiter: checked.waiter,
                    member: checked.member,
                    _memory: memory,
                }),
                source: a.source_flow,
                subject: a.subject,
                scope: a.scope,
                branch: a.branch,
                chain: a.chain,
                stream: a.transport,
                class: 1,
                effective: checked.target,
                resolver: u16::MAX,
                query: "".into(),
                expires,
                request,
                tickets: Box::new([]),
                next: None,
                _query_credit: query_credit,
                _routes: routes,
            }),
        );
        match self.authority.route(
            RouteRequest::Direct(checked.target.wire()),
            &proof,
            a.source_flow,
            tuple,
        ) {
            Ok(Some(ticket)) => tickets.push(ticket),
            Ok(None) => {}
            Err(error) => {
                self.unknown = true;
                self.authority.revoke();
                return Err(error);
            }
        }
        self.grants
            .get_mut(&id)
            .ok_or(ServiceError::Unavailable)?
            .tickets = tickets.into_boxed_slice();
        self.flows
            .get_mut(&a.source_flow)
            .ok_or(ServiceError::Unavailable)?
            .root = Some((a.scope, checked.target));
        let valid = self.numeric_live(id).and_then(|_| {
            if self.authority.subject(&proof, a.source_flow, tuple)? != subject
                || self
                    .authority
                    .expiry(&proof)
                    .is_some_and(|until| self.authority.now() >= until)
            {
                return Err(ServiceError::Unavailable);
            }
            Ok(())
        });
        if let Err(error) = valid {
            if !self.unknown {
                self.cancel_grant(id)?;
            }
            return Err(error);
        }
        Ok((id, proof))
    }
    fn numeric_live(&self, id: u64) -> Result<Instant, ServiceError> {
        let grant = self.grants.get(&id).ok_or(ServiceError::Unavailable)?;
        let numeric = grant.numeric.as_ref().ok_or(ServiceError::Unavailable)?;
        let (binding, expires) = self.numeric_parent(numeric.waiter)?;
        let w = self
            .rrsets
            .waiters
            .get(&numeric.waiter)
            .ok_or(ServiceError::Unavailable)?;
        let flow = self
            .flows
            .get(&grant.source)
            .ok_or(ServiceError::Unavailable)?;
        let cap = self.capsule()?;
        let dial = cap
            .dial_scope(grant.scope, grant.branch)
            .map_err(unavailable)?;
        if w.numeric_once != Some((grant.request, id))
            || grant.class != 1
            || grant.source != binding.source
            || binding.source_revision != cap.policy_revision
            || !flow.numeric_only
            || flow.original.family != 3
            || flow.root != Some((grant.scope, grant.effective))
            || Name::lookup(flow.original.wire().bytes)? != Name::lookup(binding.name.wire().bytes)?
            || grant.effective.protocol != flow.original.protocol
            || grant.effective.port != flow.original.port
            || dial.action != 3
            || dial.next.is_some()
            || dial.input != flow.original.protocol
            || dial.carrier != flow.original.protocol
            || dial.subject != grant.subject
            || dial.chain != grant.chain
            || dial.stream != grant.stream
        {
            return Err(ServiceError::Unavailable);
        }
        self.authority.check_ingress(&flow.socket)?;
        self.numeric_member(numeric.waiter, numeric.member, grant.effective)?;
        let until = grant.expires.min(expires);
        if self.authority.now() >= until {
            return Err(ServiceError::Unavailable);
        }
        Ok(until)
    }
    pub(super) fn cancel_numeric_dependents(&mut self) -> Result<(), ServiceError> {
        if self.unknown {
            return Err(ServiceError::Unavailable);
        }
        self.retire_hosts_permissions()?;
        let mut ids = [0; 4096];
        let mut count = 0;
        for (id, grant) in &self.grants {
            if grant.numeric.is_some() && self.numeric_live(*id).is_err() {
                *ids.get_mut(count).ok_or(ServiceError::Busy)? = *id;
                count += 1;
            }
        }
        for id in &ids[..count] {
            self.cancel_grant(*id)?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)] // Exact sequence, original owner proof/deadline, единый reader.
pub(super) fn dispatch_numeric<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    sequence: u64,
    request: u64,
    view: View<'_, 42>,
    session: Instant,
    mut drain: impl FnMut(&mut Issuer<A>) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    if view.bootstrap_selector().map_err(unavailable)?.is_some() {
        return super::dns_bundle::roots::dispatch_hosts_numeric(
            issuer, socket, stop, sequence, request, view, session, drain,
        );
    }
    let response_until = session.min(issuer.authority.now() + Duration::from_secs(1));
    let outcome = issuer.authorize_numeric(request, view, session);
    loop {
        if !issuer.unknown {
            drain(issuer)?;
        }
        let now = issuer.authority.now();
        let mut live = None;
        if !stop.load(Ordering::Acquire)
            && now < response_until
            && !issuer.retired.iter().any(|(n, _)| *n == request)
        {
            if let Ok((id, proof)) = &outcome {
                if let Ok(until) = issuer.numeric_live(*id) {
                    let g = issuer.grants.get(id).ok_or(ServiceError::Unavailable)?;
                    let flow = issuer
                        .flows
                        .get(&g.source)
                        .ok_or(ServiceError::Unavailable)?;
                    if issuer
                        .authority
                        .subject(proof, g.source, flow.tuple)
                        .is_ok_and(|subject| subject == flow.subject)
                    {
                        if let Ok(receipt) = issuer.authority.receipt(proof, g.source, flow.tuple) {
                            let until = until.min(issuer.authority.expiry(proof).unwrap_or(until));
                            let now = issuer.authority.now();
                            let remaining = until.saturating_duration_since(now);
                            if remaining >= Duration::from_millis(1) {
                                live = Some((*id, g.source, until, receipt, remaining));
                            }
                        }
                    }
                }
            }
        }
        if live.is_none() {
            if let Ok((id, _)) = &outcome {
                if issuer.grants.contains_key(id) && !issuer.unknown {
                    issuer.cancel_grant(*id)?;
                }
            }
            if stop.load(Ordering::Acquire) || issuer.authority.now() >= response_until {
                return Err(ServiceError::Unavailable);
            }
        }
        let (object, message) = if let Some((id, source, _until, receipt, remaining)) = live {
            (
                id,
                wire::Message::Grant {
                    status: wire::Status::Allow,
                    class: 1,
                    required: issuer.record.mode.required(),
                    grant: id,
                    flow: source,
                    lease: remaining.as_millis().min(1000) as u32,
                    revision: issuer.capsule()?.policy_revision,
                    fresh: if issuer.record.mode.required() {
                        remaining.as_nanos().min(20_000_000) as u64
                    } else {
                        0
                    },
                    receipt,
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
                    class: 1,
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
                if let Some(g) = issuer.grants.get(&object) {
                    g.sent.store(true, Ordering::Release);
                }
                return Ok(());
            }
            Ok(false) => {}
            Err(error) => {
                issuer.unknown = true;
                issuer.authority.revoke();
                return Err(error);
            }
        }
        socket.writable_until(live.map_or(response_until, |(_, _, until, _, _)| {
            until.min(response_until)
        }));
    }
}

#[allow(clippy::too_many_arguments)] // Exact pending sequence и original deadline.
pub(super) fn dispatch<A: Authority>(
    issuer: &mut Issuer<A>,
    socket: &impl Channel,
    stop: &AtomicBool,
    sequence: u64,
    request: u64,
    record: Record<'_>,
    session: Instant,
    mut drain: impl FnMut(&mut Issuer<A>) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let operation = if matches!(record, Record::Publish(_)) {
        Operation::Published
    } else {
        Operation::WaiterBound
    };
    let result = if issuer.retired.iter().any(|(n, _)| *n == request) {
        Err(ServiceError::Unavailable)
    } else {
        match record {
            Record::Publish(v) => issuer.publish_dns(v, request, session),
            Record::WaiterBind(v) => issuer.bind_dns_waiter(v, request, session),
            _ => Err(ServiceError::Unsupported),
        }
    };
    if !issuer.unknown {
        drain(issuer)?;
    }
    let mut deadline = session;
    loop {
        if !issuer.unknown {
            drain(issuer)?;
        }
        if stop.load(Ordering::Acquire) || issuer.authority.now() >= deadline {
            return Err(ServiceError::Unavailable);
        }
        let mut body = [0; 64];
        body[1] = 2;
        body[2] = if let Ok(id) = result {
            if issuer.retired.iter().any(|(n, _)| *n == request) {
                2
            } else if let Ok(until) = issuer.rrset_reply(operation, id, &mut body) {
                deadline = deadline.min(until);
                1
            } else {
                body[3..].fill(0);
                if issuer.unknown { 3 } else { 2 }
            }
        } else if issuer.unknown {
            3
        } else {
            2
        };
        let length = if operation == Operation::Published {
            48
        } else {
            64
        };
        let mut bytes = [0; 192];
        let frame = wire::dns_v2::DnsFrame {
            header: wire::dns_v2::Envelope {
                sequence,
                reply_to: request,
                binding: issuer.record.binding,
            },
            record: Record::decode(operation, &body[..length]).map_err(unavailable)?,
        };
        let n = frame
            .encode(
                &issuer.negotiated.ok_or(ServiceError::Unavailable)?,
                &mut bytes,
            )
            .map_err(unavailable)?;
        let sent = match socket.write(&bytes[..n]) {
            Ok(sent) => sent,
            Err(error) => {
                issuer.unknown = true;
                issuer.authority.revoke();
                return Err(error);
            }
        };
        if sent {
            if body[2] == 1 {
                let id = result?;
                if issuer.ack_hosts_data(operation, id)? {
                    return Ok(());
                }
                if let Err(e) = issuer.bootstrap_reply_fence(operation, id) {
                    issuer.unknown = true;
                    issuer.authority.revoke();
                    return Err(e);
                }
                if operation == Operation::Published {
                    issuer
                        .rrsets
                        .producers
                        .get_mut(&id)
                        .ok_or(ServiceError::Unavailable)?
                        .acked = true;
                } else {
                    issuer
                        .rrsets
                        .waiters
                        .get_mut(&id)
                        .ok_or(ServiceError::Unavailable)?
                        .acked = true;
                }
            }
            return Ok(());
        }
        socket.writable_until(deadline);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> (Vec<u8>, Vec<u8>) {
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x05query\x07invalid\0\0\x01\0\x01");
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 80]);
        (q, r)
    }
    #[test]
    fn dns_rrset_parser_exact_question_flags_id_class_and_truncation() {
        let (q, r) = pair();
        let a = parse(&q, &r, b"QUERY.invalid.", 1, 1, 0).unwrap();
        assert_eq!(a.count, 1);
        assert_eq!(a.ttl, 30);
        for at in [0, 2, 3, 5, 13, r.len() - 5] {
            let mut bad = r.clone();
            bad[at] ^= 1;
            assert!(parse(&q, &bad, b"query.invalid", 1, 1, 0).is_err());
        }
        for end in 0..r.len() {
            assert!(parse(&q, &r[..end], b"query.invalid", 1, 1, 0).is_err());
        }
        assert!(parse(&q, &r, b"other.invalid", 1, 1, 0).is_err());
        assert!(parse(&q, &vec![0; 32769], b"query.invalid", 1, 1, 0).is_err());
    }
    #[test]
    fn dns_rrset_parser_only_related_unicast_members_and_minimum_ttl() {
        let (q, r) = pair();
        for ip in [[0, 0, 0, 0], [224, 0, 0, 1], [255, 255, 255, 255]] {
            let mut bad = r.clone();
            let n = bad.len();
            bad[n - 4..].copy_from_slice(&ip);
            assert!(parse(&q, &bad, b"query.invalid", 1, 1, 0).is_err());
        }
        let mut duplicate = r.clone();
        duplicate[7] = 2;
        let mut last = r[q.len()..].to_vec();
        last[9] = 10;
        duplicate.extend_from_slice(&last);
        let a = parse(&q, &duplicate, b"query.invalid", 1, 1, 0).unwrap();
        assert_eq!((a.count, a.ttl), (1, 10));
        let mut bad = r.clone();
        bad[q.len() + 6..q.len() + 10].fill(0);
        assert!(parse(&q, &bad, b"query.invalid", 1, 1, 0).is_err());
        let mut bad = r.clone();
        bad[q.len() + 1] = 31;
        assert!(parse(&q, &bad, b"query.invalid", 1, 1, 0).is_err());
    }
    fn record(out: &mut Vec<u8>, owner: &[u8], kind: u16, ttl: u32, data: &[u8]) {
        out.extend_from_slice(owner);
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    #[test]
    fn dns_rrset_parser_cname_answer_ownership_and_cycle() {
        let (q, mut r) = pair();
        r.truncate(q.len());
        r[7] = 2;
        let alias = b"\x05alias\x07invalid\0";
        record(&mut r, &[0xc0, 12], 5, 10, alias);
        record(&mut r, alias, 1, 60, &[203, 0, 113, 80]);
        let a = parse(&q, &r, b"query.invalid", 1, 1, 0).unwrap();
        assert_eq!((a.count, a.ttl), (1, 10));
        let mut bad = r.clone();
        bad[q.len() + 12 + 1] = b'x';
        assert!(parse(&q, &bad, b"query.invalid", 1, 1, 0).is_err());
        let mut cycle = q.clone();
        cycle[2] = 0x81;
        cycle[3] = 0x80;
        cycle[7] = 1;
        record(&mut cycle, &[0xc0, 12], 5, 30, &[0xc0, 12]);
        assert!(parse(&q, &cycle, b"query.invalid", 1, 1, 0).is_err());
    }
    #[test]
    fn dns_rrset_parser_pointer_depth_and_edns_options() {
        let mut bytes = vec![0; 12];
        bytes.extend_from_slice(b"\x01a\0");
        let mut target = 12usize;
        for _ in 0..17 {
            let at = bytes.len();
            bytes.extend_from_slice(&(0xc000 | target as u16).to_be_bytes());
            target = at;
        }
        assert!(name(&bytes, &mut target).is_err());
        let (mut q, mut r) = pair();
        q[11] = 1;
        r[11] = 1;
        let opt = [0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&opt);
        r.extend_from_slice(&opt);
        assert!(parse(&q, &r, b"query.invalid", 1, 9, 1232).is_ok());
        assert!(parse(&q, &r, b"query.invalid", 1, 9, 512).is_err());
    }
}
