use super::issuer_tests::{Fake, bundle_fixture, bundle_fixture_network, dns_neg, dns_packet};
use super::*;
use std::{
    cell::{Cell, RefCell},
    sync::{Mutex, atomic::AtomicUsize},
};
use wire::dns_v2::Operation;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyFault {
    None,
    NoLineage,
    WrongLaunch,
    WrongPeer,
    WrongNamespace,
    WrongFrontier,
    LogicalQuery,
    LogicalBundle,
    LogicalKind,
    AppendRevision,
    AppendSequence,
    AppendDuplicate,
    AppendForeign,
    AppendReplay,
    AppendCancel,
    AppendLostAck,
    AppendSlow,
    PublishBeforeAck,
    PhysicalBeforeAck,
    AppendAfterPublish,
    Retire,
    RetirePartial,
    HistoryFull,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NumericFault {
    None,
    Two,
    Member,
    Address,
    Port,
    Carrier,
    Name,
    Source,
    Waiter,
    Scope,
    Receipt,
    Effective,
    Class,
    Use,
    Replay,
    Cancel,
    CancelRequest,
    CancelProducer,
    CancelBundle,
    CancelSource,
    Expired,
    ShortReservation,
    ReservationExpired,
    SlowWrite,
    HistoryFull,
    RouteFull,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Proxy,
    None,
    Peer,
    Namespace,
    Source,
    Changed,
    Cancel,
    Retire,
    CrossQuery,
    CrossBundle,
    Duplicate,
    RetiredRequest,
    Scope,
    DuringAdmission,
    EarlyLogical,
    ReplayLogical,
    Expired,
    ControlClose,
    CancelExchangeEarly,
    Release,
    ReleaseRetry,
    ReleaseRetryResource,
    ReleaseReverse,
    ReleaseRevision,
    ReleaseUnknownClose,
    ReleaseExpired,
    ReleaseTooLate,
    ReleaseWrongLaunch,
    Publish,
    Waiters,
    WaitersKeep,
    Numeric,
    WaiterShortReservation,
    WaiterWrongSource,
    WaiterWrongRoot,
    WaiterCancelQueued,
    PublishNoAuthority,
    PublishRevision,
    PublishQuestion,
    PublishAddress,
    PublishCancel,
    PublishReplay,
    PublishExpired,
    PublishLarge,
    PublishExhausted,
}
impl Fault {
    fn waitering(self) -> bool {
        matches!(
            self,
            Self::Waiters
                | Self::Numeric
                | Self::WaitersKeep
                | Self::WaiterShortReservation
                | Self::WaiterWrongSource
                | Self::WaiterWrongRoot
                | Self::WaiterCancelQueued
        )
    }
    fn publishing(self) -> bool {
        self == Self::Proxy
            || self.waitering()
            || matches!(
                self,
                Self::Publish
                    | Self::Waiters
                    | Self::WaitersKeep
                    | Self::WaiterWrongSource
                    | Self::WaiterWrongRoot
                    | Self::WaiterCancelQueued
                    | Self::PublishNoAuthority
                    | Self::PublishRevision
                    | Self::PublishQuestion
                    | Self::PublishAddress
                    | Self::PublishCancel
                    | Self::PublishReplay
                    | Self::PublishExpired
                    | Self::PublishLarge
                    | Self::PublishExhausted
            )
    }
    fn releasing(self) -> bool {
        matches!(
            self,
            Self::Release
                | Self::ReleaseRetry
                | Self::ReleaseRetryResource
                | Self::ReleaseReverse
                | Self::ReleaseRevision
                | Self::ReleaseUnknownClose
                | Self::ReleaseExpired
                | Self::ReleaseTooLate
                | Self::ReleaseWrongLaunch
        )
    }
}
struct Driver {
    proxy_fault: Cell<ProxyFault>,
    physical_peer: Target,
    physical_path: (u16, u16, u16, u8, u16),
    record: LaunchRecord,
    acquire: Vec<u8>,
    peer: Target,
    budget: super::super::memory::ByteBudget,
    slots: Arc<SidebandCredits>,
    history: Arc<Mutex<InvocationHistory>>,
    input: RefCell<VecDeque<Vec<u8>>>,
    raw: RefCell<VecDeque<dns_transport::Incoming>>,
    credits: RefCell<BTreeMap<u64, super::super::memory::ByteLease>>,
    output: RefCell<Vec<Vec<u8>>>,
    created: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    valid: Arc<AtomicBool>,
    elapsed: Arc<std::sync::atomic::AtomicU64>,
    reverse: bool,
    fault: Fault,
    finished: Cell<bool>,
    one_empty: Cell<bool>,
    control_close: Cell<bool>,
    blocked: Cell<bool>,
    extra_acquires: RefCell<VecDeque<Vec<u8>>>,
    current_acquire: RefCell<Option<Vec<u8>>>,
    next_dns: Cell<u64>,
    user_dial: (u16, u16, u16, u16),
    numeric_fault: Cell<NumericFault>,
    current_bundle: Cell<u64>,
    route_budget: super::super::memory::ByteBudget,
    pressure: RefCell<Vec<super::super::memory::ByteLease>>,
}
fn n64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().unwrap())
}
fn n16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(b[at..at + 2].try_into().unwrap())
}
fn p64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_be_bytes());
}
fn p16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}
impl Driver {
    fn new(issuer: &Issuer<Fake>, acquire: Vec<u8>, reverse: bool, fault: Fault) -> Self {
        let cap = issuer.capsule().unwrap();
        let path = wire::dns_v2::View::<55>::decode(&acquire).unwrap();
        let hops: Vec<_> = path.path().collect();
        let (scope, branch) = *hops.last().unwrap();
        let dial = cap.dial_scope(scope, branch).unwrap();
        let mut endpoint_index = u16::MAX;
        let mut physical_peer = Target::copy(cap.resolver_peer(0).unwrap()).unwrap();
        if fault == Fault::Proxy {
            for (scope, branch) in &hops {
                let d = cap.dial_scope(*scope, *branch).unwrap();
                if let Some(endpoint) = d.endpoint {
                    physical_peer = Target::copy(endpoint).unwrap();
                    endpoint_index = d.endpoint_index;
                }
                if d.next.is_none() {
                    physical_peer.protocol = d.carrier;
                }
            }
        }
        let mut input = VecDeque::from([dns_packet(
            issuer.record,
            3,
            Operation::BundleAcquire,
            &acquire,
        )]);
        let history = Arc::new(Mutex::new(
            InvocationHistory::new(256, &issuer.budget.dynamic).unwrap(),
        ));
        let out = Self {
            proxy_fault: Cell::new(ProxyFault::None),
            physical_peer,
            physical_path: (
                scope,
                dial.subject,
                endpoint_index,
                branch,
                (hops.len() - 1) as u16,
            ),
            record: issuer.record,
            peer: Target::copy(issuer.capsule().unwrap().resolver_peer(0).unwrap()).unwrap(),
            acquire,
            budget: issuer.budget.dynamic.clone(),
            slots: SidebandCredits::new(),
            history,
            input: Default::default(),
            raw: Default::default(),
            credits: Default::default(),
            output: Default::default(),
            created: Default::default(),
            closed: Default::default(),
            valid: Arc::new(AtomicBool::new(true)),
            elapsed: Arc::clone(&issuer.authority.elapsed),
            reverse,
            fault,
            finished: Cell::new(false),
            one_empty: Cell::new(false),
            control_close: Cell::new(false),
            blocked: Cell::new(false),
            extra_acquires: Default::default(),
            current_acquire: Default::default(),
            next_dns: Cell::new(8),
            user_dial: (0..512u16)
                .find_map(|scope| {
                    issuer
                        .capsule()
                        .unwrap()
                        .dial_scope(scope, 0)
                        .ok()
                        .filter(|d| d.input == 6 && d.action == 3 && d.next.is_none())
                        .map(|d| (scope, d.subject, d.chain, d.stream))
                })
                .unwrap_or((u16::MAX, 0, 0, 0)),
            numeric_fault: Cell::new(NumericFault::None),
            current_bundle: Cell::new(0),
            route_budget: issuer.budget.routes.clone(),
            pressure: Default::default(),
        };
        if fault == Fault::RetiredRequest {
            input.push_back(dns_packet(
                out.record,
                4,
                Operation::Reserve,
                &out.reserve(1, 0),
            ));
            let mut cancel = [0; 24];
            p16(&mut cancel, 0, 2);
            cancel[2] = 1;
            p64(&mut cancel, 8, 4);
            input.push_back(dns_packet(out.record, 5, Operation::Cancel, &cancel));
        }
        *out.input.borrow_mut() = input;
        out
    }
    fn reserve(&self, role: u8, parent: u64) -> Vec<u8> {
        self.reserve_for(&self.acquire, role, parent, 1)
    }
    fn reserve_for(&self, a: &[u8], role: u8, parent: u64, bundle: u64) -> Vec<u8> {
        let base = &a[72..72 + usize::from(n16(a, 48))];
        let name = &a[72 + base.len()..72 + base.len() + usize::from(n16(a, 58))];
        let mut b = vec![0; 96];
        p16(&mut b, 0, 2);
        b[2] = role;
        for (at, v) in [
            (8, n64(a, 16)),
            (16, bundle),
            (24, n64(a, 8)),
            (32, n64(base, 0)),
            (40, 1),
            (48, 5),
            (56, 1_000_000_000),
        ] {
            p64(&mut b, at, v);
        }
        for (at, v) in [
            (64, 0),
            (66, 0),
            (68, u16::MAX),
            (70, n16(a, a.len() - 4)),
            (72, n16(a, 52)),
            (80, name.len() as u16),
            (82, name.len() as u16),
            (84, base.len() as u16),
        ] {
            p16(&mut b, at, v);
        }
        b[74] = 1;
        b[75] = 1;
        b[76] = self.peer.protocol;
        b[77] = 3;
        b[78] = 1;
        if self.fault == Fault::Proxy {
            p16(&mut b, 66, if role == 2 { self.physical_path.1 } else { 0 });
            p16(
                &mut b,
                70,
                if role == 2 {
                    self.physical_path.0
                } else {
                    n16(a, a.len() - usize::from(n16(a, 50)) * 4)
                },
            );
            if role == 2 {
                p16(&mut b, 68, self.physical_path.2);
                b[76] = self.physical_peer.protocol;
                b[79] = self.physical_path.3;
            }
        }
        if role == 2 {
            p64(&mut b, 88, parent);
        } else {
            p16(&mut b, 88, n16(a, 54));
            p16(&mut b, 90, n16(a, 56));
        }
        b.extend_from_slice(name);
        b.extend_from_slice(name);
        b.extend_from_slice(base);
        b
    }
    fn raw_record(&self, physical: u64) -> [u8; 192] {
        let mut b = [0; 192];
        b[..8].copy_from_slice(b"DNSPHY02");
        p16(&mut b, 8, 2);
        p16(&mut b, 10, 192);
        b[16..48].copy_from_slice(&self.record.binding.digest);
        b[48..64].copy_from_slice(&self.record.binding.session);
        b[64..80].copy_from_slice(&self.record.binding.invocation);
        p64(&mut b, 80, self.record.binding.generation);
        p64(&mut b, 88, self.record.binding.epoch);
        b[96..128].copy_from_slice(&self.record.nonce);
        for (at, v) in [
            (128, 1),
            (136, n64(&self.acquire, 16)),
            (144, 1),
            (152, physical),
        ] {
            p64(&mut b, at, v);
        }
        if self.fault == Fault::Proxy {
            p16(
                &mut b,
                162,
                if self.proxy_fault.get() == ProxyFault::WrongFrontier {
                    0
                } else {
                    self.physical_path.4
                },
            );
        }
        b[164] = self.physical_peer.protocol;
        b[165] = if self.physical_peer.protocol == 6 {
            1
        } else {
            2
        };
        b[166] = self.record.mode as u8;
        let d = self.physical_peer.wire();
        b[168] = d.family;
        b[169] = d.protocol;
        p16(&mut b, 170, d.port);
        b[172] = d.bytes.len() as u8;
        b[175..175 + d.bytes.len()].copy_from_slice(d.bytes);
        b
    }
    fn physical(&self, id: u64) -> Result<(), ServiceError> {
        let peer = if self.proxy_fault.get() == ProxyFault::WrongPeer {
            "192.0.2.53:53".parse().unwrap()
        } else if self.fault == Fault::Proxy {
            endpoint(
                self.physical_peer.wire().family,
                {
                    let mut b = [0; 16];
                    b[..self.physical_peer.wire().bytes.len()]
                        .copy_from_slice(self.physical_peer.wire().bytes);
                    b
                },
                self.physical_peer.port,
            )
            .unwrap()
        } else if self.fault == Fault::Peer {
            "203.0.113.99:53".parse().unwrap()
        } else {
            "192.0.2.53:53".parse().unwrap()
        };
        let source = if self.fault == Fault::Source {
            "192.0.2.11:40001"
        } else {
            "192.0.2.10:40001"
        };
        let ns = if self.fault == Fault::Namespace
            || self.proxy_fault.get() == ProxyFault::WrongNamespace
        {
            (9, 9)
        } else {
            (4, 5)
        };
        let facts = Arc::new(Mutex::new(
            dns_transport::fake_facts(
                source.parse().unwrap(),
                peer,
                self.physical_peer.protocol,
                ns,
            )
            .with_cookie(100 + id),
        ));
        let raw = dns_transport::Incoming::fake(
            self.raw_record(id),
            &dns_neg(self.record),
            &self.slots,
            &self.budget,
            Some(Arc::clone(&self.history)),
            facts,
            Arc::clone(&self.valid),
            Arc::clone(&self.closed),
            || {
                assert!(self.slots.fds.used() >= 16);
                assert!(self.slots.pending.used() > 0);
                self.created.fetch_add(1, Ordering::AcqRel);
            },
        )?;
        self.raw.borrow_mut().push_back(raw);
        if self.fault == Fault::ControlClose {
            self.control_close.set(true);
        }
        Ok(())
    }
    fn queue(&self, sequence: u64, kind: Operation, body: &[u8]) {
        self.input
            .borrow_mut()
            .push_back(dns_packet(self.record, sequence, kind, body));
    }
    fn logical(&self, sequence: u64, resource: u64) {
        let mut logical = [0; 72];
        p16(&mut logical, 0, 2);
        logical[2] = if self.fault == Fault::Proxy { 2 } else { 1 };
        if self.proxy_fault.get() == ProxyFault::LogicalKind {
            logical[2] = 1;
        }
        p16(&mut logical, 4, 1);
        for (at, v) in [
            (8, 1),
            (
                16,
                if self.fault == Fault::CrossQuery {
                    10
                } else {
                    n64(&self.acquire, 16)
                },
            ),
            (
                24,
                if self.fault == Fault::CrossBundle {
                    999
                } else {
                    1
                },
            ),
            (32, 1),
            (48, 1),
            (56, 1_000_000_000),
            (64, resource),
        ] {
            p64(&mut logical, at, v);
        }
        match self.proxy_fault.get() {
            ProxyFault::LogicalQuery => p64(&mut logical, 16, 999),
            ProxyFault::LogicalBundle => p64(&mut logical, 24, 999),
            _ => {}
        }
        self.queue(sequence, Operation::LogicalBind, &logical);
    }
    fn publish(&self) -> Vec<u8> {
        let name = b"query.invalid";
        let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split(|b| *b == b'.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label);
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        let mut response = query.clone();
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 80]);
        if self.fault == Fault::PublishLarge {
            response[11] = 1;
            let remaining = 32768 - response.len() - 11;
            response.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 0]);
            response.extend_from_slice(&(remaining as u16).to_be_bytes());
            response.resize(32768, 0);
        }
        let mut b = vec![0; 144];
        p16(&mut b, 0, 2);
        p16(&mut b, 6, 0);
        p16(&mut b, 8, u16::MAX);
        p16(&mut b, 10, 1);
        for (at, value) in [(12, 9), (20, 1), (28, 1), (36, 5), (120, 1), (128, 1)] {
            p64(&mut b, at, value);
        }
        p16(&mut b, 108, name.len() as u16);
        p16(&mut b, 110, query.len() as u16);
        b[112..116].copy_from_slice(&(response.len() as u32).to_be_bytes());
        b[136] = 1;
        b[137] = 1;
        p16(&mut b, 140, u16::MAX);
        b[142] = self.peer.protocol;
        b.extend_from_slice(name);
        b.extend_from_slice(&query);
        b.extend_from_slice(&response);
        match self.fault {
            Fault::PublishRevision => p64(&mut b, 128, 2),
            Fault::PublishQuestion => b[144] = b'x',
            Fault::PublishAddress => {
                let n = b.len();
                b[n - 4] = 224;
            }
            _ => {}
        }
        b
    }
    fn next_queue(&self, kind: Operation, body: &[u8]) {
        let n = self.next_dns.get();
        self.next_dns.set(n + 1);
        self.queue(n, kind, body);
    }
    fn next_waiter(&self) {
        if let Some(a) = self.extra_acquires.borrow_mut().pop_front() {
            self.next_queue(Operation::BundleAcquire, &a);
            *self.current_acquire.borrow_mut() = Some(a);
        } else {
            if self.fault == Fault::WaitersKeep {
                self.finished.set(true);
                return;
            }
            let mut c = [0; 24];
            p16(&mut c, 0, 2);
            c[2] = 6;
            p64(&mut c, 8, 1);
            self.next_queue(Operation::Cancel, &c);
        }
    }
    fn numeric(&self, waiter: u64) -> Vec<u8> {
        let a = self.current_acquire.borrow();
        let a = a.as_ref().unwrap();
        let old = wire::dns_v2::View::<55>::decode(a)
            .unwrap()
            .authorization()
            .unwrap();
        let (scope, subject, chain, transport) = self.user_dial;
        let mut base = wire::Authorize {
            class: 1,
            scope,
            subject,
            chain,
            transport,
            branch: 0,
            effective: old.original,
            resolver: u16::MAX,
            query: "",
            ..old
        };
        match self.numeric_fault.get() {
            NumericFault::Source => base.source_flow = 1,
            NumericFault::Name => {
                base.original = wire::Destination {
                    bytes: b"other.invalid",
                    ..base.original
                };
                base.effective = base.original;
            }
            NumericFault::Scope => base.scope = n16(a, a.len() - 4),
            NumericFault::Receipt => {
                base.receipt = wire::Receipt {
                    kind: wire::ReceiptKind::FrozenSent,
                    id: 999,
                }
            }
            NumericFault::Effective => {
                base.effective = wire::Destination {
                    family: 4,
                    bytes: &[203, 0, 113, 81],
                    ..base.original
                }
            }
            NumericFault::Class => base = old,
            _ => {}
        }
        let mut raw = [0; 1152];
        let n = wire::Frame::encode(
            wire::Header {
                kind: wire::Kind::Authorize,
                sequence: 1,
                reply_to: 0,
                binding: self.record.binding,
                object_id: 0,
            },
            &wire::Message::Authorize(base),
            &mut raw,
        )
        .unwrap();
        let mut body = vec![0; 16];
        p16(&mut body, 0, 2);
        p64(&mut body, 4, waiter);
        p16(&mut body, 12, (n - 128) as u16);
        body[14] = 1;
        body[15] = 1;
        body.extend_from_slice(&raw[128..n]);
        let tail = body.len();
        body.extend_from_slice(&[4, 6, 1, 187, 4, 0, 0, 203, 0, 113, 80]);
        match self.numeric_fault.get() {
            NumericFault::Member => p16(&mut body, 2, 1),
            NumericFault::Waiter => p64(&mut body, 4, 999),
            NumericFault::Address => body[tail + 10] = 81,
            NumericFault::Port => p16(&mut body, tail + 2, 444),
            NumericFault::Carrier => body[tail + 1] = 17,
            NumericFault::Class => body[15] = 3,
            NumericFault::Use => body[14] = 2,
            _ => {}
        }
        body
    }
}
impl Channel for Driver {
    fn dns_logical_producer(
        &self,
        mut launch: LaunchRecord,
    ) -> Result<Option<VerifiedDnsLogicalProducer>, ServiceError> {
        if self.proxy_fault.get() == ProxyFault::WrongLaunch {
            launch.nonce[0] ^= 1;
        }
        Ok(
            (self.fault == Fault::Proxy && self.proxy_fault.get() != ProxyFault::NoLineage)
                .then_some(VerifiedDnsLogicalProducer { launch }),
        )
    }
    fn dns_wire_producer(
        &self,
        record: LaunchRecord,
    ) -> Result<Option<VerifiedDnsWireProducer>, ServiceError> {
        if !self.fault.publishing() || self.fault == Fault::PublishNoAuthority {
            return Ok(None);
        }
        let proof = super::super::registry::fake_dns_wire_image([17; 32]);
        Ok(Some(VerifiedDnsWireProducer::mint(
            &proof,
            [17; 32],
            record.binding.digest,
            record.manifest,
            record,
        )?))
    }
    fn dns_producer(
        &self,
        record: LaunchRecord,
    ) -> Result<Option<VerifiedDnsProducer>, ServiceError> {
        if !self.fault.releasing() {
            return Ok(None);
        }
        let proof = super::super::registry::fake_dns_image([17; 32]);
        let mut record = record;
        if self.fault == Fault::ReleaseWrongLaunch {
            record.nonce[0] ^= 1;
        }
        Ok(Some(VerifiedDnsProducer::mint(
            &proof,
            [17; 32],
            record.binding.digest,
            record.manifest,
            record,
        )?))
    }
    fn maintain(
        &self,
        cancel: &mut dyn FnMut(u64) -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        if self.control_close.replace(false) {
            cancel(1)?;
        }
        Ok(())
    }
    fn history(&self) -> Option<Arc<Mutex<InvocationHistory>>> {
        Some(Arc::clone(&self.history))
    }
    fn dns_slots(&self) -> Result<Arc<SidebandCredits>, ServiceError> {
        Ok(Arc::clone(&self.slots))
    }
    fn take_dns_credit(
        &self,
        sequence: u64,
    ) -> Result<super::super::memory::ByteLease, ServiceError> {
        self.credits
            .borrow_mut()
            .remove(&sequence)
            .ok_or(ServiceError::Unavailable)
    }
    fn take_dns(&self) -> Result<Option<dns_transport::Incoming>, ServiceError> {
        Ok(self.raw.borrow_mut().pop_front())
    }
    fn processed(&self, sequence: u64) -> Result<(), ServiceError> {
        self.credits.borrow_mut().remove(&sequence);
        Ok(())
    }
    fn setup_read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        out[..272].copy_from_slice(&wire::dns_v2::Negotiated::descriptor(self.record).unwrap());
        Ok(Some(272))
    }
    fn setup_write(&self, b: &[u8]) -> Result<bool, ServiceError> {
        assert_eq!(
            b,
            wire::dns_v2::Negotiated::ack(
                &wire::dns_v2::Negotiated::descriptor(self.record).unwrap()
            )
            .unwrap()
        );
        Ok(true)
    }
    fn read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        let credit = self.slots.pending.reserve(1).map_err(unavailable)?;
        if let Some(b) = self.input.borrow_mut().pop_front() {
            let seq = n64(&b, 16);
            self.credits.borrow_mut().insert(seq, credit);
            out[..b.len()].copy_from_slice(&b);
            Ok(Some(b.len()))
        } else if self.finished.get() {
            if self.fault == Fault::DuringAdmission && !self.one_empty.replace(true) {
                Ok(None)
            } else {
                Err(ServiceError::Unavailable)
            }
        } else {
            Ok(None)
        }
    }
    fn write(&self, bytes: &[u8]) -> Result<bool, ServiceError> {
        if !dns_bundle::is_dns(bytes) {
            let frame = wire::Frame::decode(bytes, self.record.binding, self.record.mode, true)
                .map_err(unavailable)?;
            if let wire::Message::Grant { status, .. } = frame.message {
                if self.numeric_fault.get() == NumericFault::SlowWrite
                    && !self.blocked.replace(true)
                {
                    self.elapsed.fetch_add(25_000_000, Ordering::AcqRel);
                    return Ok(false);
                }
                self.output.borrow_mut().push(bytes.to_vec());
                if status == wire::Status::Allow
                    && self.numeric_fault.get() == NumericFault::Two
                    && !self.extra_acquires.borrow().is_empty()
                {
                    self.next_waiter();
                } else if status == wire::Status::Allow
                    && self.numeric_fault.get() == NumericFault::Replay
                {
                    let body = self.numeric(1);
                    self.next_queue(Operation::NumericAuthorize, &body);
                } else {
                    self.finished.set(true);
                }
                return Ok(true);
            }
            if let wire::Message::CloseAck { .. } = frame.message {
                self.output.borrow_mut().push(bytes.to_vec());
                self.finished.set(true);
                return Ok(true);
            }
            let wire::Message::Admit(raw) = frame.message else {
                return Err(ServiceError::InvalidRequest);
            };
            let c = wire::Capsule::decode(raw, &self.record.binding.digest).map_err(unavailable)?;
            if c.admission_id > 1 && self.fault == Fault::DuringAdmission {
                self.physical(2)?;
                self.finished.set(true);
                return Ok(true);
            }
            let mut out = [0; RUNTIME_PACKET];
            let n = wire::Frame::encode(
                wire::Header {
                    kind: wire::Kind::AdmitAck,
                    sequence: 2,
                    reply_to: frame.header.sequence,
                    binding: self.record.binding,
                    object_id: 0,
                },
                &wire::Message::AdmitAck {
                    manifest: c.manifest,
                    admission: c.admission_id,
                    status: wire::Status::Allow,
                },
                &mut out,
            )
            .map_err(unavailable)?;
            self.input.borrow_mut().push_front(out[..n].to_vec());
            return Ok(true);
        }
        let f = dns_bundle::decode(
            bytes,
            &dns_neg(self.record),
            wire::dns_v2::Direction::Issuer,
        )?;
        if self.fault == Fault::Proxy
            && self.proxy_fault.get() == ProxyFault::PhysicalBeforeAck
            && f.record.operation() == Operation::PhysicalAck
            && n64(bytes, 144) == 2
            && !self.blocked.replace(true)
        {
            let mut b = [0; 56];
            p16(&mut b, 0, 2);
            p16(&mut b, 4, 1);
            for (at, v) in [
                (8, 1),
                (16, 1),
                (24, 1),
                (32, 1),
                (40, 1_000_000_000),
                (48, 2),
            ] {
                p64(&mut b, at, v);
            }
            self.queue(8, Operation::Append, &b);
            return Ok(false);
        }
        if f.record.operation() == Operation::AppendAck
            && self.fault == Fault::Proxy
            && bytes[130] == 1
            && !self.blocked.replace(true)
        {
            match self.proxy_fault.get() {
                ProxyFault::AppendLostAck => return Err(ServiceError::Unavailable),
                ProxyFault::AppendSlow => {
                    self.elapsed.fetch_add(25_000_000, Ordering::AcqRel);
                    return Ok(false);
                }
                ProxyFault::PublishBeforeAck => {
                    let mut b = self.publish();
                    p64(&mut b, 128, 2);
                    self.queue(9, Operation::Publish, &b);
                    return Ok(false);
                }
                _ => {}
            }
        }
        if (self.fault == Fault::ReleaseRetry
            || self.fault == Fault::ReleaseRetryResource && bytes[131] == 3)
            && f.record.operation() == Operation::Retired
            && !self.blocked.replace(true)
        {
            assert_eq!(self.slots.fds.used(), 2);
            assert_eq!(
                self.closed.load(Ordering::Acquire),
                usize::from(bytes[131] == 3)
            );
            return Ok(false);
        }
        self.output.borrow_mut().push(bytes.to_vec());
        let b = &bytes[128..];
        if self.fault == Fault::RetiredRequest {
            if f.record.operation() == Operation::Reserved {
                self.finished.set(true);
            }
            return Ok(true);
        }
        if b[2] != 1 {
            self.finished.set(true);
            return Ok(true);
        }
        match f.record.operation() {
            Operation::BundleGranted if self.current_acquire.borrow().is_some() => {
                self.current_bundle.set(n64(b, 8));
                let a = self.current_acquire.borrow();
                let mut body = self.reserve_for(a.as_ref().unwrap(), 3, 0, n64(b, 8));
                if self.fault == Fault::WaiterShortReservation
                    || matches!(
                        self.numeric_fault.get(),
                        NumericFault::ShortReservation | NumericFault::ReservationExpired
                    )
                {
                    p64(&mut body, 56, 5_000_000);
                }
                self.next_queue(Operation::Reserve, &body);
            }
            Operation::BundleGranted => {
                let mut b = self.reserve(1, 0);
                if self.fault == Fault::Scope {
                    p16(&mut b, 70, if self.peer.protocol == 17 { 0 } else { 1 });
                }
                self.queue(4, Operation::Reserve, &b);
            }
            Operation::Reserved if b[60] == 3 => {
                if self.fault == Fault::WaiterShortReservation {
                    self.elapsed.fetch_add(3_000_000, Ordering::AcqRel);
                }
                let a = self.current_acquire.borrow();
                let a = a.as_ref().unwrap();
                let base = &a[72..72 + usize::from(n16(a, 48))];
                let mut body = [0; 64];
                p16(&mut body, 0, 2);
                for (at, value) in [
                    (8, n64(b, 8)),
                    (16, 1),
                    (24, n64(a, 8)),
                    (32, n64(a, 16)),
                    (40, n64(base, 0)),
                    (48, 1),
                    (56, 1_000_000_000),
                ] {
                    p64(&mut body, at, value);
                }
                if self.fault == Fault::WaiterWrongSource {
                    p64(&mut body, 40, 1);
                }
                if self.fault == Fault::WaiterWrongRoot {
                    p64(&mut body, 24, 1);
                }
                let request = self.next_dns.get();
                self.next_queue(Operation::WaiterBind, &body);
                if self.fault == Fault::WaiterCancelQueued {
                    let mut c = [0; 24];
                    p16(&mut c, 0, 2);
                    c[2] = 1;
                    p64(&mut c, 8, request);
                    self.next_queue(Operation::Cancel, &c);
                }
            }
            Operation::Reserved if b[60] == 1 => {
                if self.reverse {
                    self.physical(2)?;
                }
                if self.fault == Fault::CancelExchangeEarly {
                    let mut c = [0; 24];
                    p16(&mut c, 0, 2);
                    c[2] = 7;
                    p64(&mut c, 8, 1);
                    self.queue(5, Operation::Cancel, &c);
                    return Ok(true);
                }
                self.queue(5, Operation::Reserve, &self.reserve(2, n64(b, 8)));
            }
            Operation::Reserved => {
                if self.fault == Fault::Expired {
                    self.elapsed.fetch_add(21_000_000, Ordering::AcqRel);
                }
                if self.fault == Fault::EarlyLogical {
                    self.logical(6, 1);
                    return Ok(true);
                }
                if self.fault == Fault::DuringAdmission {
                    let mut out = [0; RUNTIME_PACKET];
                    let n = wire::Frame::encode(
                        wire::Header {
                            kind: wire::Kind::Renew,
                            sequence: 6,
                            reply_to: 0,
                            binding: self.record.binding,
                            object_id: 0,
                        },
                        &wire::Message::Renew {
                            admission: 1,
                            manifest: self.record.manifest,
                        },
                        &mut out,
                    )
                    .map_err(unavailable)?;
                    self.input.borrow_mut().push_back(out[..n].to_vec());
                    return Ok(true);
                }
                if !self.reverse || self.fault == Fault::Proxy && n64(b, 8) != 2 {
                    self.physical(n64(b, 8))?;
                }
                if self.fault == Fault::Duplicate {
                    self.physical(n64(b, 8))?;
                }
                if self.fault == Fault::Cancel {
                    let mut c = [0; 24];
                    p16(&mut c, 0, 2);
                    c[2] = 7;
                    p64(&mut c, 8, n64(b, 8));
                    self.queue(6, Operation::Cancel, &c);
                }
            }
            Operation::PhysicalAck => {
                if self.fault == Fault::Proxy && n64(b, 16) == 2 {
                    if self.proxy_fault.get() == ProxyFault::PhysicalBeforeAck {
                        return Ok(true);
                    }
                    let mut append = [0; 56];
                    p16(&mut append, 0, 2);
                    p16(&mut append, 4, 1);
                    for (at, v) in [
                        (8, 1),
                        (16, 1),
                        (24, 1),
                        (32, 1),
                        (40, 1_000_000_000),
                        (48, 2),
                    ] {
                        p64(&mut append, at, v);
                    }
                    match self.proxy_fault.get() {
                        ProxyFault::AppendRevision => p64(&mut append, 24, 2),
                        ProxyFault::AppendSequence => p64(&mut append, 32, 2),
                        ProxyFault::AppendDuplicate => p64(&mut append, 48, 1),
                        ProxyFault::AppendForeign => p64(&mut append, 48, 999),
                        ProxyFault::HistoryFull => {
                            let mut h = self.history.lock().unwrap();
                            h.limit = h.len;
                        }
                        _ => {}
                    }
                    self.queue(8, Operation::Append, &append);
                    if self.proxy_fault.get() == ProxyFault::AppendCancel {
                        let mut b = [0; 24];
                        p16(&mut b, 0, 2);
                        b[2] = 1;
                        p64(&mut b, 8, 8);
                        self.queue(9, Operation::Cancel, &b);
                    }
                    return Ok(true);
                }
                if self.fault == Fault::Changed {
                    self.valid.store(false, Ordering::Release);
                }
                self.logical(6, n64(b, 16));
            }
            Operation::LogicalAck => {
                if self.fault == Fault::Proxy {
                    self.queue(7, Operation::Reserve, &self.reserve(2, 1));
                    return Ok(true);
                }
                if self.fault.publishing() {
                    if self.fault == Fault::PublishExpired {
                        self.elapsed.fetch_add(21_000_000, Ordering::AcqRel);
                    }
                    if self.fault == Fault::PublishExhausted {
                        let mut h = self.history.lock().unwrap();
                        h.limit = h.len;
                    }
                    self.queue(7, Operation::Publish, &self.publish());
                    if self.fault == Fault::PublishCancel {
                        let mut c = [0; 24];
                        p16(&mut c, 0, 2);
                        c[2] = 1;
                        p64(&mut c, 8, 7);
                        self.queue(8, Operation::Cancel, &c);
                    }
                } else if self.fault == Fault::Retire || self.fault.releasing() {
                    let mut r = [0; 24];
                    p16(&mut r, 0, 2);
                    r[2] = 4;
                    p64(&mut r, 8, n64(b, 16));
                    p64(&mut r, 16, 1);
                    match self.fault {
                        Fault::ReleaseReverse => {
                            r[2] = 3;
                            p64(&mut r, 16, 0);
                        }
                        Fault::ReleaseRevision => p64(&mut r, 16, 2),
                        Fault::ReleaseUnknownClose => self.valid.store(false, Ordering::Release),
                        Fault::ReleaseExpired => {
                            self.elapsed.fetch_add(21_000_000, Ordering::AcqRel);
                        }
                        Fault::ReleaseTooLate => {
                            self.elapsed.fetch_add(1_100_000_000, Ordering::AcqRel);
                        }
                        _ => {}
                    }
                    self.queue(7, Operation::Retire, &r);
                } else if self.fault == Fault::ReplayLogical {
                    self.logical(7, 1);
                } else {
                    self.finished.set(true);
                }
            }
            Operation::Published if self.fault.waitering() => self.next_waiter(),
            Operation::AppendAck => {
                if self.proxy_fault.get() == ProxyFault::AppendReplay {
                    let mut a = [0; 56];
                    p16(&mut a, 0, 2);
                    p16(&mut a, 4, 1);
                    for (at, v) in [
                        (8, 1),
                        (16, 1),
                        (24, 1),
                        (32, 1),
                        (40, 1_000_000_000),
                        (48, 2),
                    ] {
                        p64(&mut a, at, v);
                    }
                    self.queue(9, Operation::Append, &a);
                } else if matches!(
                    self.proxy_fault.get(),
                    ProxyFault::Retire | ProxyFault::RetirePartial
                ) {
                    let mut r = [0; 24];
                    p16(&mut r, 0, 2);
                    r[2] = 4;
                    p64(&mut r, 8, 1);
                    p64(&mut r, 16, 2);
                    self.queue(9, Operation::Retire, &r);
                } else if self.proxy_fault.get() != ProxyFault::PublishBeforeAck {
                    let mut b = self.publish();
                    p64(&mut b, 128, 2);
                    self.queue(9, Operation::Publish, &b);
                }
            }
            Operation::Published if self.proxy_fault.get() == ProxyFault::AppendAfterPublish => {
                let mut a = [0; 56];
                p16(&mut a, 0, 2);
                p16(&mut a, 4, 1);
                for (at, v) in [
                    (8, 1),
                    (16, 1),
                    (24, 2),
                    (32, 2),
                    (40, 1_000_000_000),
                    (48, 1),
                ] {
                    p64(&mut a, at, v);
                }
                self.queue(10, Operation::Append, &a);
            }
            Operation::Retired if self.fault == Fault::Proxy => {
                assert_eq!(
                    self.closed.load(Ordering::Acquire),
                    if b[3] == 3 { n64(b, 8) as usize } else { 0 }
                );
                if b[3] == 3 && n64(b, 8) == 2 {
                    self.finished.set(true);
                } else {
                    let mut r = [0; 24];
                    p16(&mut r, 0, 2);
                    r[2] = 3;
                    p64(&mut r, 8, if b[3] == 4 { 1 } else { 2 });
                    if b[3] == 3 && self.proxy_fault.get() == ProxyFault::RetirePartial {
                        self.valid.store(false, Ordering::Release);
                    }
                    self.queue(if b[3] == 4 { 10 } else { 11 }, Operation::Retire, &r);
                }
            }
            Operation::Published if self.fault == Fault::PublishReplay => {
                self.queue(8, Operation::Publish, &self.publish())
            }
            Operation::WaiterBound if self.fault == Fault::Numeric => {
                match self.numeric_fault.get() {
                    NumericFault::Expired => {
                        self.elapsed.fetch_add(21_000_000, Ordering::AcqRel);
                    }
                    NumericFault::ReservationExpired => {
                        self.elapsed.fetch_add(6_000_000, Ordering::AcqRel);
                    }
                    NumericFault::HistoryFull => {
                        let mut h = self.history.lock().unwrap();
                        h.limit = h.len;
                    }
                    NumericFault::RouteFull => self.pressure.borrow_mut().push(
                        self.route_budget
                            .reserve(4096 - self.route_budget.used())
                            .unwrap(),
                    ),
                    _ => {}
                }
                let request = self.next_dns.get();
                let body = self.numeric(n64(b, 8));
                self.next_queue(Operation::NumericAuthorize, &body);
                let target = match self.numeric_fault.get() {
                    NumericFault::Cancel => Some((6, n64(b, 8))),
                    NumericFault::CancelRequest => Some((1, request)),
                    NumericFault::CancelProducer => Some((5, 1)),
                    NumericFault::CancelBundle => Some((8, self.current_bundle.get())),
                    _ => None,
                };
                if let Some((target, id)) = target {
                    let mut c = [0; 24];
                    p16(&mut c, 0, 2);
                    c[2] = target;
                    p64(&mut c, 8, id);
                    self.next_queue(Operation::Cancel, &c);
                }
                if self.numeric_fault.get() == NumericFault::CancelSource {
                    let seq = self.next_dns.get();
                    self.next_dns.set(seq + 1);
                    let mut raw = [0; 184];
                    let n = wire::Frame::encode(
                        wire::Header {
                            kind: wire::Kind::Cancel,
                            sequence: seq,
                            reply_to: 0,
                            binding: self.record.binding,
                            object_id: 0,
                        },
                        &wire::Message::Cancel {
                            target: 2,
                            id: 2,
                            reason: 0,
                        },
                        &mut raw,
                    )
                    .unwrap();
                    self.input.borrow_mut().push_back(raw[..n].to_vec());
                }
            }
            Operation::WaiterBound if self.fault.waitering() => self.next_waiter(),
            Operation::Retired if self.fault.releasing() => {
                let mut r = [0; 24];
                p16(&mut r, 0, 2);
                if b[3] == 4 {
                    assert_eq!(self.closed.load(Ordering::Acquire), 0);
                    r[2] = 3;
                    p64(&mut r, 8, 1);
                    self.queue(8, Operation::Retire, &r);
                } else {
                    assert_eq!(self.closed.load(Ordering::Acquire), 1);
                    r[2] = 7;
                    p64(&mut r, 8, 2);
                    self.queue(9, Operation::Cancel, &r);
                }
            }
            Operation::Canceled if self.fault.releasing() => {
                let reply = n64(bytes, 24);
                if reply == 9 {
                    let mut r = [0; 24];
                    p16(&mut r, 0, 2);
                    r[2] = 7;
                    p64(&mut r, 8, 1);
                    self.queue(10, Operation::Cancel, &r);
                } else if reply == 10 {
                    let mut r = [0; 24];
                    p16(&mut r, 0, 2);
                    r[2] = 2;
                    p64(&mut r, 8, 1);
                    self.queue(11, Operation::Cancel, &r);
                } else {
                    self.finished.set(true);
                }
            }
            _ => self.finished.set(true),
        }
        Ok(true)
    }
    fn writable_until(&self, _: Instant) {
        if self.fault == Fault::Proxy
            && matches!(
                self.proxy_fault.get(),
                ProxyFault::AppendSlow
                    | ProxyFault::PublishBeforeAck
                    | ProxyFault::PhysicalBeforeAck
            )
        {
            assert!(self.blocked.get());
            return;
        }
        if self.numeric_fault.get() == NumericFault::SlowWrite {
            assert!(self.blocked.get());
            return;
        }
        assert!(matches!(
            self.fault,
            Fault::ReleaseRetry | Fault::ReleaseRetryResource
        ));
        assert!(self.blocked.get());
    }
    fn pause_until(&self, _: Instant) {
        if self.fault != Fault::DuringAdmission {
            panic!("pure transport driver не должен ждать OS");
        }
    }
}
fn run(issuer: &mut Issuer<Fake>, driver: &Driver) {
    assert!(
        run_issuer(
            issuer,
            driver,
            8,
            997,
            &AtomicBool::new(false),
            &AtomicBool::new(false)
        )
        .is_err()
    );
}
#[test]
fn dns_proxy_driver_append_revision_then_publish() {
    for mode in [Mode::Local, Mode::System] {
        for reverse in [false, true] {
            for tcp in [false, true] {
                let (mut issuer, acquire) = bundle_fixture_network(mode, true, tcp);
                let driver = Driver::new(&issuer, acquire, reverse, Fault::Proxy);
                run(&mut issuer, &driver);
                assert!(
                    statuses(&driver).contains(&(39, 1, 6)),
                    "{:?}",
                    statuses(&driver)
                );
                assert!(
                    statuses(&driver).contains(&(44, 1, 8)),
                    "{:?}",
                    statuses(&driver)
                );
                assert!(
                    statuses(&driver).contains(&(41, 1, 9)),
                    "{:?}",
                    statuses(&driver)
                );
                assert_eq!(
                    issuer.transport.proof_state(1),
                    Some((2, 2, 2, true, false, true))
                );
                assert!(!issuer.unknown);
                assert_eq!(driver.created.load(Ordering::Acquire), 2);
                assert_eq!(driver.slots.fds.used(), 4);
            }
        }
    }
}
#[test]
fn dns_proxy_driver_lineage_manifest_and_actual_first_hop_are_distinct() {
    for fault in [
        ProxyFault::NoLineage,
        ProxyFault::WrongLaunch,
        ProxyFault::WrongPeer,
        ProxyFault::WrongNamespace,
        ProxyFault::WrongFrontier,
        ProxyFault::LogicalQuery,
        ProxyFault::LogicalBundle,
        ProxyFault::LogicalKind,
    ] {
        let (mut issuer, a) = bundle_fixture_network(Mode::System, true, true);
        let io = Driver::new(&issuer, a, false, Fault::Proxy);
        io.proxy_fault.set(fault);
        run(&mut issuer, &io);
        assert!(
            !statuses(&io)
                .iter()
                .any(|(kind, status, _)| *kind == 39 && *status == 1),
            "{fault:?}"
        );
        assert!(issuer.transport.proof_state(1).is_none(), "{fault:?}");
    }
}
#[test]
fn dns_proxy_driver_append_rejects_revision_sequence_foreign_duplicate_and_caps() {
    for fault in [
        ProxyFault::AppendRevision,
        ProxyFault::AppendSequence,
        ProxyFault::AppendDuplicate,
        ProxyFault::AppendForeign,
        ProxyFault::AppendCancel,
        ProxyFault::HistoryFull,
        ProxyFault::PhysicalBeforeAck,
    ] {
        let (mut issuer, a) = bundle_fixture_network(Mode::Local, true, true);
        let io = Driver::new(&issuer, a, false, Fault::Proxy);
        io.proxy_fault.set(fault);
        run(&mut issuer, &io);
        assert!(
            !statuses(&io)
                .iter()
                .any(|(kind, status, _)| *kind == 44 && *status == 1),
            "{fault:?}"
        );
        assert_eq!(
            issuer.transport.proof_state(1),
            Some((2, 1, 1, true, false, false)),
            "{fault:?}"
        );
    }
}
#[test]
fn dns_proxy_driver_pending_ack_never_authorizes_early_publication_or_extends_owner() {
    for fault in [
        ProxyFault::AppendLostAck,
        ProxyFault::AppendSlow,
        ProxyFault::PublishBeforeAck,
    ] {
        let (mut issuer, a) = bundle_fixture_network(Mode::System, true, true);
        let io = Driver::new(&issuer, a, false, Fault::Proxy);
        io.proxy_fault.set(fault);
        run(&mut issuer, &io);
        assert!(
            !statuses(&io)
                .iter()
                .any(|(kind, status, _)| *kind == 41 && *status == 1),
            "{fault:?}"
        );
        if fault == ProxyFault::PublishBeforeAck {
            assert_eq!(
                issuer.transport.proof_state(1),
                Some((2, 2, 2, true, false, false))
            );
        } else {
            assert_eq!(
                issuer.transport.proof_state(1),
                Some((2, 2, 1, false, true, false))
            );
        }
        assert_eq!(io.slots.fds.used(), 4);
        assert_eq!(io.closed.load(Ordering::Acquire), 0);
        if fault == ProxyFault::AppendLostAck {
            assert!(issuer.unknown);
        }
    }
}
#[test]
fn dns_proxy_driver_replay_and_frozen_publication_cannot_change_union() {
    for fault in [ProxyFault::AppendReplay, ProxyFault::AppendAfterPublish] {
        let (mut issuer, a) = bundle_fixture_network(Mode::Local, true, true);
        let io = Driver::new(&issuer, a, false, Fault::Proxy);
        io.proxy_fault.set(fault);
        run(&mut issuer, &io);
        let state = issuer.transport.proof_state(1).unwrap();
        assert_eq!((state.0, state.1, state.2), (2, 2, 2));
        assert_eq!(state.5, fault == ProxyFault::AppendAfterPublish);
        assert_eq!(
            statuses(&io)
                .iter()
                .filter(|(k, s, _)| *k == 44 && *s == 1)
                .count(),
            1
        );
    }
}
#[test]
fn dns_proxy_driver_retirement_joins_all_refs_before_consuming_receiver_once() {
    for fault in [ProxyFault::Retire, ProxyFault::RetirePartial] {
        let (mut issuer, a) = bundle_fixture_network(Mode::System, true, true);
        let io = Driver::new(&issuer, a, false, Fault::Proxy);
        io.proxy_fault.set(fault);
        run(&mut issuer, &io);
        assert!(statuses(&io).contains(&(46, 1, 9)));
        assert!(statuses(&io).contains(&(46, 1, 10)));
        assert_eq!(io.closed.load(Ordering::Acquire), 2);
        assert_eq!(issuer.unknown, fault == ProxyFault::RetirePartial);
        assert_eq!(
            io.slots.fds.used(),
            if fault == ProxyFault::Retire { 0 } else { 2 }
        );
        if fault == ProxyFault::Retire {
            let before = issuer.authority.live.len();
            issuer.cancel_dns_bundle(1).unwrap();
            assert_eq!(issuer.authority.live.len(), before - 2);
        }
    }
}
#[test]
fn dns_proxy_driver_known_bundle_cleanup_preserves_neighbor_source_and_route() {
    let (mut issuer, a) = bundle_fixture_network(Mode::System, true, true);
    let (source, _) = issuer
        .open(52, &issuer_tests::open(Mode::System, 32002))
        .unwrap();
    let base = wire::dns_v2::View::<55>::decode(&a)
        .unwrap()
        .authorization()
        .unwrap();
    let (neighbor, _) = issuer
        .authorize(
            53,
            0,
            &wire::Authorize {
                source_flow: source,
                query: "neighbor.invalid",
                ..base
            },
        )
        .unwrap();
    let io = Driver::new(&issuer, a, false, Fault::Proxy);
    io.proxy_fault.set(ProxyFault::Retire);
    run(&mut issuer, &io);
    assert!(!issuer.unknown);
    issuer.cancel_flow(1).unwrap();
    assert!(issuer.flows.contains_key(&source));
    assert!(issuer.grants.contains_key(&neighbor));
    assert!(!issuer.authority.live.is_empty());
    assert_eq!(io.closed.load(Ordering::Acquire), 2);
}
#[test]
fn dns_proxy_driver_static_first_hop_needs_captured_route_not_dynamic_ticket() {
    let (mut issuer, a) = bundle_fixture_network(Mode::System, true, true);
    issuer.authority.static_dns_peer = Some("203.0.113.11:8443".parse().unwrap());
    let io = Driver::new(&issuer, a, false, Fault::Proxy);
    run(&mut issuer, &io);
    assert!(statuses(&io).contains(&(41, 1, 9)));
    assert!(!issuer.unknown);
}
fn statuses(driver: &Driver) -> Vec<(u16, u8, u64)> {
    driver
        .output
        .borrow()
        .iter()
        .map(|b| {
            (
                n16(b, 10),
                b[if n16(b, 10) == 19 { 128 } else { 130 }],
                n64(b, 24),
            )
        })
        .collect()
}

#[test]
fn dns_transport_driver_reserve_scm_logical_both_orders_and_exact_pending() {
    for tcp in [false, true] {
        for reverse in [false, true] {
            let (mut issuer, a) = bundle_fixture_network(Mode::System, false, tcp);
            let io = Driver::new(&issuer, a, reverse, Fault::None);
            run(&mut issuer, &io);
            assert_eq!(
                statuses(&io),
                [(56, 1, 3), (36, 1, 4), (36, 1, 5), (37, 1, 5), (39, 1, 6)]
            );
            assert_eq!(issuer.transport.counts(), (2, 0, 1, 1));
            assert_eq!(io.slots.pending.used(), 0);
            assert_eq!(io.slots.fds.used(), 2);
            assert_eq!(io.created.load(Ordering::Acquire), 1);
            assert_eq!(io.closed.load(Ordering::Acquire), 0);
            assert!(!issuer.unknown);
            assert_eq!(io.history.lock().unwrap().reserved, 0);
        }
    }
}

#[test]
fn dns_transport_driver_publish_uses_bound_transport_and_returns_data_only() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, false, Fault::Publish);
    run(&mut issuer, &io);
    assert_eq!(statuses(&io).last(), Some(&(41, 1, 7)));
    assert_eq!(issuer.authority.live.len(), 2);
    assert!(!issuer.unknown);
}

fn additional_query(issuer: &mut Issuer<Fake>, first: &[u8], port: u16, query: u64) -> Vec<u8> {
    let (flow, _) = issuer
        .open(
            100 + query,
            &super::issuer_tests::open(issuer.record.mode, port),
        )
        .unwrap();
    let n = usize::from(n16(first, 48));
    let old = wire::dns_v2::View::<55>::decode(first)
        .unwrap()
        .authorization()
        .unwrap();
    let a = wire::Authorize {
        source_flow: flow,
        receipt: wire::Receipt {
            kind: wire::ReceiptKind::None,
            id: 0,
        },
        ..old
    };
    let (root, _) = issuer.authorize(200 + query, 0, &a).unwrap();
    let mut bytes = [0; 1152];
    let size = wire::Frame::encode(
        wire::Header {
            kind: wire::Kind::Authorize,
            sequence: 1,
            reply_to: 0,
            binding: issuer.record.binding,
            object_id: 0,
        },
        &wire::Message::Authorize(a),
        &mut bytes,
    )
    .unwrap();
    assert_eq!(size - 128, n);
    let mut body = first.to_vec();
    p64(&mut body, 8, root);
    p64(&mut body, 16, query);
    body[72..72 + n].copy_from_slice(&bytes[128..size]);
    body
}

fn numeric_query(issuer: &mut Issuer<Fake>, first: &[u8], port: u16, query: u64) -> Vec<u8> {
    let mut open = super::issuer_tests::open(Mode::Local, port);
    let wire::Message::OpenIngress {
        ref mut original, ..
    } = open
    else {
        panic!("SOCKS source fixture")
    };
    *original = wire::Destination {
        protocol: 6,
        family: 3,
        port: 443,
        bytes: b"query.invalid",
    };
    let (source, _) = issuer.open(100 + query, &open).unwrap();
    let old = wire::dns_v2::View::<55>::decode(first)
        .unwrap()
        .authorization()
        .unwrap();
    let a = wire::Authorize {
        source_flow: source,
        original: wire::Destination {
            protocol: 6,
            family: 3,
            port: 443,
            bytes: b"query.invalid",
        },
        ..old
    };
    let (root, _) = issuer.authorize(200 + query, 0, &a).unwrap();
    let mut raw = [0; 1152];
    let n = wire::Frame::encode(
        wire::Header {
            kind: wire::Kind::Authorize,
            sequence: 1,
            reply_to: 0,
            binding: issuer.record.binding,
            object_id: 0,
        },
        &wire::Message::Authorize(a),
        &mut raw,
    )
    .unwrap();
    let mut body = first[..72].to_vec();
    p64(&mut body, 8, root);
    p64(&mut body, 16, query);
    p16(&mut body, 48, (n - 128) as u16);
    body.extend_from_slice(&raw[128..n]);
    body.extend_from_slice(&first[72 + usize::from(n16(first, 48))..]);
    body
}

#[test]
fn dns_numeric_driver_full_publish_waiter_to_durable_user_grant() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, a) = bundle_fixture(mode, false);
        let next = numeric_query(&mut issuer, &a, 32002, 10);
        let io = Driver::new(&issuer, a, false, Fault::Numeric);
        io.extra_acquires.borrow_mut().push_back(next);
        run(&mut issuer, &io);
        assert_eq!(statuses(&io).last(), Some(&(19, 1, 11)));
        assert!(!issuer.unknown);
        assert_eq!(issuer.authority.live.len(), 5);
        let outputs = io.output.borrow();
        let raw = outputs.last().unwrap();
        let frame = wire::Frame::decode(raw, issuer.record.binding, mode, true).unwrap();
        let wire::Message::Grant {
            class,
            flow,
            required,
            fresh,
            receipt,
            lease,
            ..
        } = frame.message
        else {
            panic!("GRANT19")
        };
        assert_eq!((class, flow, required), (1, 2, mode.required()));
        assert!(lease > 0);
        if mode.required() {
            assert!(fresh > 0 && fresh <= 20_000_000);
            assert_eq!(receipt.kind, wire::ReceiptKind::SidebandOperation);
        } else {
            assert_eq!(fresh, 0);
            assert_eq!(receipt.kind, wire::ReceiptKind::None);
        }
        drop(outputs);
        let body = io.numeric(1);
        let base = wire::dns_v2::View::<42>::decode(&body)
            .unwrap()
            .authorization()
            .unwrap();
        assert!(issuer.authorize(50, 0, &base).is_err());
        assert_eq!(issuer.authority.live.len(), 5);
    }
}

fn numeric_fixture(
    fault: NumericFault,
    delay: Duration,
    unknown_release: bool,
) -> (Issuer<Fake>, Driver) {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let next = numeric_query(&mut issuer, &a, 32002, 10);
    issuer.authority.numeric_delay = delay;
    issuer.authority.unknown_release = unknown_release;
    let io = Driver::new(&issuer, a, false, Fault::Numeric);
    io.numeric_fault.set(fault);
    io.extra_acquires.borrow_mut().push_back(next);
    (issuer, io)
}

#[test]
fn dns_numeric_driver_invalid_binding_narrowing_and_authority_before_route() {
    for fault in [
        NumericFault::Member,
        NumericFault::Address,
        NumericFault::Port,
        NumericFault::Carrier,
        NumericFault::Name,
        NumericFault::Source,
        NumericFault::Waiter,
        NumericFault::Scope,
        NumericFault::Receipt,
        NumericFault::Effective,
        NumericFault::Class,
        NumericFault::Use,
    ] {
        let (mut issuer, io) = numeric_fixture(fault, Duration::ZERO, false);
        run(&mut issuer, &io);
        assert_eq!(statuses(&io).last(), Some(&(19, 2, 11)), "{fault:?}");
        assert_eq!(issuer.authority.route_count, 4, "{fault:?}");
        assert_eq!(issuer.authority.live.len(), 4);
        assert!(!issuer.unknown);
    }
}

#[test]
fn dns_numeric_driver_replay_is_not_reusable_waiter_authority() {
    let (mut issuer, io) = numeric_fixture(NumericFault::Replay, Duration::ZERO, false);
    run(&mut issuer, &io);
    assert_eq!(
        statuses(&io)
            .iter()
            .filter(|(kind, status, _)| *kind == 19 && *status == 1)
            .count(),
        1
    );
    assert_eq!(statuses(&io).last(), Some(&(19, 2, 12)));
    assert_eq!(issuer.authority.route_count, 5);
}

#[test]
fn dns_numeric_driver_cancel_fences_release_own_ticket_before_denial() {
    for fault in [
        NumericFault::Cancel,
        NumericFault::CancelRequest,
        NumericFault::CancelProducer,
        NumericFault::CancelBundle,
        NumericFault::CancelSource,
    ] {
        let (mut issuer, io) = numeric_fixture(fault, Duration::ZERO, false);
        run(&mut issuer, &io);
        assert!(
            !statuses(&io)
                .iter()
                .any(|(kind, status, _)| *kind == 19 && *status == 1),
            "{fault:?}"
        );
        assert_eq!(issuer.authority.route_count, 5);
        assert!(!issuer.authority.live.contains(&5));
        assert!(!issuer.unknown);
    }
}

#[test]
fn dns_numeric_driver_original_owner_and_reservation_deadlines_survive_backend() {
    for (fault, delay) in [
        (NumericFault::None, Duration::from_millis(25)),
        (NumericFault::ShortReservation, Duration::from_millis(6)),
        (NumericFault::SlowWrite, Duration::ZERO),
    ] {
        let (mut issuer, io) = numeric_fixture(fault, delay, false);
        run(&mut issuer, &io);
        assert!(
            !statuses(&io)
                .iter()
                .any(|(kind, status, _)| *kind == 19 && *status == 1),
            "{fault:?}"
        );
        assert_eq!(issuer.authority.route_count, 5);
        assert!(!issuer.authority.live.contains(&5));
        assert!(!issuer.unknown);
    }
}

#[test]
fn dns_numeric_driver_expiry_and_caps_reject_before_effect() {
    for fault in [
        NumericFault::Expired,
        NumericFault::ReservationExpired,
        NumericFault::HistoryFull,
        NumericFault::RouteFull,
    ] {
        let (mut issuer, io) = numeric_fixture(fault, Duration::ZERO, false);
        run(&mut issuer, &io);
        assert!(
            !statuses(&io)
                .iter()
                .any(|(kind, status, _)| *kind == 19 && *status == 1)
        );
        assert_eq!(issuer.authority.route_count, 4, "{fault:?}");
    }
}

#[test]
fn dns_numeric_driver_partial_durable_cleanup_retains_unknown_ticket_and_credit() {
    let (mut issuer, io) = numeric_fixture(NumericFault::None, Duration::from_millis(25), true);
    run(&mut issuer, &io);
    assert!(
        !statuses(&io)
            .iter()
            .any(|(kind, status, _)| *kind == 19 && *status == 1)
    );
    assert!(issuer.unknown);
    assert!(issuer.authority.live.contains(&5));
    assert!(issuer.grants.values().any(|g| g.numeric.is_some()));
    assert_eq!(io.route_budget.used(), 5);
}

#[test]
fn dns_numeric_driver_two_cached_waiters_have_independent_user_tickets() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let first = numeric_query(&mut issuer, &a, 32002, 10);
    let second = numeric_query(&mut issuer, &a, 32003, 11);
    let io = Driver::new(&issuer, a, false, Fault::Numeric);
    io.numeric_fault.set(NumericFault::Two);
    io.extra_acquires.borrow_mut().extend([first, second]);
    run(&mut issuer, &io);
    assert_eq!(
        statuses(&io)
            .iter()
            .filter(|(kind, status, _)| *kind == 19 && *status == 1)
            .count(),
        2
    );
    assert_eq!(issuer.authority.live.len(), 8);
    dns_bundle::cancel(&mut issuer, 100, 6, 1).unwrap();
    assert_eq!(issuer.authority.live.len(), 7);
    assert!(
        !issuer
            .grants
            .values()
            .any(|g| g.numeric.is_some() && g.source == 2)
    );
    assert!(
        issuer
            .grants
            .values()
            .any(|g| g.numeric.is_some() && g.source == 3)
    );
    assert!(!issuer.unknown);
}

#[test]
fn dns_transport_driver_waiter_receipt_keeps_original_reservation_deadline() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let second = additional_query(&mut issuer, &a, 32002, 10);
    let io = Driver::new(&issuer, a, false, Fault::WaiterShortReservation);
    io.extra_acquires.borrow_mut().push_back(second);
    run(&mut issuer, &io);
    let out = io.output.borrow();
    let receipt = out.iter().find(|b| n16(b, 10) == 54).unwrap();
    assert_eq!(receipt[130], 1);
    assert!(
        n64(receipt, 128 + 48) <= 2_000_000,
        "receipt exceeds reservation deadline"
    );
    assert!(n64(receipt, 128 + 48) > 0);
}
#[test]
fn dns_transport_driver_publish_two_private_waiters_cancel_one_preserves_sibling() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, a) = bundle_fixture(mode, false);
        let second = additional_query(&mut issuer, &a, 32002, 10);
        let third = additional_query(&mut issuer, &a, 32003, 11);
        let io = Driver::new(&issuer, a, false, Fault::Waiters);
        io.extra_acquires.borrow_mut().extend([second, third]);
        run(&mut issuer, &io);
        assert_eq!(statuses(&io).last(), Some(&(48, 1, 14)));
        assert_eq!(
            statuses(&io)
                .iter()
                .filter(|(kind, status, _)| *kind == 54 && *status == 1)
                .count(),
            2
        );
        assert_eq!(issuer.rrsets.waiter_flags(), [false, true]);
        let (owner, data) = issuer.rrsets.data_lifetime().unwrap();
        assert!(data > owner);
        issuer.cancel_flow(2).unwrap();
        assert_eq!(issuer.rrsets.waiter_flags(), [false, true]);
        assert!(!issuer.unknown);
    }
}

#[test]
fn dns_transport_driver_waiter_crossflow_root_and_queued_cancel_never_authorize() {
    for fault in [
        Fault::WaiterWrongSource,
        Fault::WaiterWrongRoot,
        Fault::WaiterCancelQueued,
    ] {
        let (mut issuer, a) = bundle_fixture(Mode::System, false);
        let next = additional_query(&mut issuer, &a, 32002, 10);
        let io = Driver::new(&issuer, a, false, fault);
        io.extra_acquires.borrow_mut().push_back(next);
        run(&mut issuer, &io);
        assert!(
            !statuses(&io)
                .iter()
                .any(|(op, status, _)| *op == 54 && *status == 1)
        );
        assert!(issuer.rrsets.waiter_flags().iter().all(|live| !*live));
        assert!(!issuer.unknown);
        assert_eq!(issuer.authority.live.len(), 4);
    }
}

#[test]
fn dns_transport_driver_live_waiters_flow_and_reservation_cancel_are_isolated() {
    for cancel_flow in [false, true] {
        let (mut issuer, a) = bundle_fixture(Mode::System, false);
        let next = additional_query(&mut issuer, &a, 32002, 10);
        let other = additional_query(&mut issuer, &a, 32003, 11);
        let io = Driver::new(&issuer, a, false, Fault::WaitersKeep);
        io.extra_acquires.borrow_mut().extend([next, other]);
        run(&mut issuer, &io);
        assert_eq!(issuer.rrsets.waiter_flags(), [true, true]);
        if cancel_flow {
            issuer.cancel_flow(2).unwrap();
        } else {
            issuer.cancel_request(9).unwrap();
        }
        assert_eq!(issuer.rrsets.waiter_flags(), [false, true]);
        assert!(!issuer.unknown);
    }
}

#[test]
fn dns_transport_driver_each_waiter_requires_new_private_root_bundle() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let next = additional_query(&mut issuer, &a, 32002, 10);
    let io = Driver::new(&issuer, a, false, Fault::WaitersKeep);
    io.extra_acquires.borrow_mut().extend([next.clone(), next]);
    run(&mut issuer, &io);
    assert_eq!(
        statuses(&io)
            .iter()
            .filter(|(op, status, _)| *op == 54 && *status == 1)
            .count(),
        1
    );
    assert!(!issuer.unknown);
}

#[test]
fn dns_transport_driver_waiter_partial_route_cleanup_keeps_unknown_custody() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let next = additional_query(&mut issuer, &a, 32002, 10);
    let io = Driver::new(&issuer, a, false, Fault::Waiters);
    io.extra_acquires.borrow_mut().push_back(next);
    run(&mut issuer, &io);
    issuer.authority.unknown_release = true;
    assert!(issuer.cancel_flow(2).is_err());
    assert!(issuer.unknown);
    assert_eq!(issuer.authority.live.len(), 4);
    assert_eq!(io.slots.fds.used(), 2);
}

#[test]
fn dns_transport_driver_publish_rejects_untrusted_mismatched_expired_and_replay() {
    for fault in [
        Fault::PublishNoAuthority,
        Fault::PublishRevision,
        Fault::PublishQuestion,
        Fault::PublishAddress,
        Fault::PublishExpired,
        Fault::PublishExhausted,
        Fault::PublishCancel,
        Fault::PublishReplay,
    ] {
        let (mut issuer, a) = bundle_fixture(Mode::System, false);
        let io = Driver::new(&issuer, a, false, fault);
        run(&mut issuer, &io);
        let allows = statuses(&io)
            .iter()
            .filter(|(kind, status, _)| *kind == 41 && *status == 1)
            .count();
        assert_eq!(allows, usize::from(fault == Fault::PublishReplay));
        if fault == Fault::PublishReplay {
            assert_eq!(statuses(&io).last(), Some(&(41, 2, 8)));
        }
        assert_eq!(io.closed.load(Ordering::Acquire), 0);
    }
}

#[test]
fn dns_transport_driver_publish_full_tcp_frame_is_bounded_without_cap_growth() {
    let (mut issuer, a) = bundle_fixture_network(Mode::System, false, true);
    let io = Driver::new(&issuer, a, false, Fault::PublishLarge);
    assert!(io.publish().len() > 2293);
    run(&mut issuer, &io);
    assert_eq!(statuses(&io).last(), Some(&(41, 1, 7)));
    assert!(!issuer.unknown);
}
#[test]
fn dns_transport_driver_wrong_peer_namespace_source_never_physical_ack() {
    for fault in [Fault::Peer, Fault::Namespace, Fault::Source] {
        let (mut issuer, a) = bundle_fixture(Mode::System, false);
        let io = Driver::new(&issuer, a, false, fault);
        run(&mut issuer, &io);
        assert_eq!(statuses(&io), [(56, 1, 3), (36, 1, 4), (36, 1, 5)]);
        assert!(issuer.unknown);
        assert_eq!(io.closed.load(Ordering::Acquire), 1);
        assert_eq!(issuer.transport.counts().2, 0);
        assert_eq!(io.slots.fds.used(), 18);
    }
}
#[test]
fn dns_transport_driver_changed_fd_is_sticky_unknown_and_crossquery_is_denied() {
    for fault in [Fault::Changed, Fault::CrossQuery, Fault::CrossBundle] {
        let (mut issuer, a) = bundle_fixture(Mode::System, false);
        let io = Driver::new(&issuer, a, false, fault);
        run(&mut issuer, &io);
        let out = statuses(&io);
        assert_eq!(out.len(), 5);
        assert_eq!(out[4], (39, if fault == Fault::Changed { 3 } else { 2 }, 6));
        assert_eq!(issuer.transport.counts().3, 0);
        assert_eq!(io.slots.fds.used(), 2);
        assert_eq!(issuer.unknown, fault == Fault::Changed);
        assert_eq!(io.closed.load(Ordering::Acquire), 0);
    }
}
#[test]
fn dns_transport_driver_cancel_late_scm_and_duplicate_retain_unknown_custody() {
    for fault in [Fault::Cancel, Fault::Duplicate] {
        let (mut issuer, a) = bundle_fixture(Mode::System, false);
        let io = Driver::new(&issuer, a, false, fault);
        run(&mut issuer, &io);
        assert!(issuer.unknown);
        assert!(
            !statuses(&io)
                .iter()
                .any(|(kind, _, _)| *kind == 37 || *kind == 39)
        );
        assert_eq!(issuer.authority.live.len(), 2);
        assert!(io.slots.fds.used() >= 18);
        assert_eq!(io.closed.load(Ordering::Acquire), 1);
    }
}
#[test]
fn dns_transport_driver_retire_cannot_invent_go_duplicate_closed() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, false, Fault::Retire);
    run(&mut issuer, &io);
    assert_eq!(statuses(&io).last(), Some(&(46, 3, 7)));
    assert!(issuer.unknown);
    assert_eq!(issuer.transport.counts(), (2, 0, 1, 1));
    assert_eq!(io.slots.fds.used(), 2);
    assert_eq!(io.closed.load(Ordering::Acquire), 0);
    assert!(issuer.cancel_dns_bundle(1).is_err());
    assert_eq!(io.slots.fds.used(), 2);
    assert_eq!(issuer.authority.live.len(), 2);
}

#[test]
fn dns_transport_driver_release_proof_then_resource_before_reservation_cleanup() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, false, Fault::Release);
    run(&mut issuer, &io);
    assert_eq!(
        statuses(&io),
        [
            (56, 1, 3),
            (36, 1, 4),
            (36, 1, 5),
            (37, 1, 5),
            (39, 1, 6),
            (46, 1, 7),
            (46, 1, 8),
            (48, 1, 9),
            (48, 1, 10),
            (48, 1, 11)
        ]
    );
    assert_eq!(io.closed.load(Ordering::Acquire), 1);
    assert_eq!(io.slots.fds.used(), 0);
    assert!(!issuer.unknown);
    assert_eq!(issuer.authority.live.len(), 2);
    issuer.cancel_dns_bundle(1).unwrap();
    assert_eq!(issuer.authority.live.len(), 1);
}

#[test]
fn dns_transport_driver_release_retry_local_system_and_expired_owner_never_reclose() {
    for mode in [Mode::Local, Mode::System] {
        for fault in [
            Fault::Release,
            Fault::ReleaseRetry,
            Fault::ReleaseRetryResource,
            Fault::ReleaseExpired,
        ] {
            let (mut issuer, a) = bundle_fixture(mode, false);
            let io = Driver::new(&issuer, a, false, fault);
            run(&mut issuer, &io);
            assert_eq!(statuses(&io).last(), Some(&(48, 1, 11)), "{mode:?}");
            assert!(!issuer.unknown);
            assert_eq!(io.closed.load(Ordering::Acquire), 1);
            assert_eq!(io.slots.fds.used(), 0);
            let mut r = [0; 24];
            p16(&mut r, 0, 2);
            r[2] = 3;
            p64(&mut r, 8, 1);
            let reply = dns_transport::handle(
                &mut issuer,
                &io,
                11,
                wire::dns_v2::Record::decode(Operation::Retire, &r).unwrap(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            dns_transport::send_reply(
                &mut issuer,
                &io,
                &AtomicBool::new(false),
                100,
                reply,
                |_| Ok(()),
            )
            .unwrap();
            assert_eq!(io.closed.load(Ordering::Acquire), 1);
        }
    }
}

#[test]
fn dns_transport_driver_release_wrong_revision_reverse_order_and_launch_no_close() {
    for fault in [
        Fault::ReleaseReverse,
        Fault::ReleaseRevision,
        Fault::ReleaseWrongLaunch,
        Fault::ReleaseTooLate,
    ] {
        let (mut issuer, a) = bundle_fixture(Mode::System, false);
        let io = Driver::new(&issuer, a, false, fault);
        run(&mut issuer, &io);
        assert!(
            !statuses(&io)
                .iter()
                .any(|(op, status, _)| *op == 46 && *status == 1)
        );
        assert_eq!(io.closed.load(Ordering::Acquire), 0);
        assert_eq!(io.slots.fds.used(), 2);
    }
}

#[test]
fn dns_transport_driver_release_uncertain_close_retains_credits_and_tickets() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, false, Fault::ReleaseUnknownClose);
    run(&mut issuer, &io);
    assert_eq!(statuses(&io).last(), Some(&(46, 3, 8)));
    assert_eq!(io.closed.load(Ordering::Acquire), 1);
    assert_eq!(io.slots.fds.used(), 2);
    assert!(issuer.unknown);
    assert!(issuer.cancel_dns_bundle(1).is_err());
    assert_eq!(issuer.authority.live.len(), 2);
}

#[test]
fn dns_transport_driver_closed_socket_does_not_claim_durable_ticket_closed() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, false, Fault::Release);
    run(&mut issuer, &io);
    assert!(!issuer.unknown);
    assert_eq!(io.slots.fds.used(), 0);
    issuer.authority.unknown_release = true;
    assert!(issuer.cancel_dns_bundle(1).is_err());
    assert!(issuer.unknown);
    assert_eq!(issuer.authority.live.len(), 2);
    assert_eq!(io.closed.load(Ordering::Acquire), 1);
}

#[test]
fn dns_transport_driver_dns_record_does_not_replace_image_config_manifest_binding() {
    let (issuer, _) = bundle_fixture(Mode::System, false);
    let record = issuer.record;
    let proof = super::super::registry::fake_dns_image([17; 32]);
    for (image, config, manifest) in [
        ([18; 32], record.binding.digest, record.manifest),
        ([17; 32], [18; 32], record.manifest),
        ([17; 32], record.binding.digest, [18; 32]),
    ] {
        assert!(VerifiedDnsProducer::mint(&proof, image, config, manifest, record).is_err());
    }
}
#[test]
fn dns_transport_driver_retired_request_fence_and_wrong_scope_before_materialization() {
    for fault in [Fault::RetiredRequest, Fault::Scope] {
        let (mut issuer, a) = bundle_fixture(Mode::System, false);
        let io = Driver::new(&issuer, a, false, fault);
        run(&mut issuer, &io);
        assert!(statuses(&io).contains(&(36, 2, 4)));
        assert_eq!(io.created.load(Ordering::Acquire), 0);
        assert_eq!(issuer.transport.counts(), (0, 0, 0, 0));
        assert!(!issuer.unknown);
        assert_eq!(issuer.authority.live.len(), 2);
        assert_eq!(io.slots.pending.used(), 0);
    }
}
#[test]
fn dns_transport_driver_fd_memory_history_credits_precede_fake_materialization() {
    let (issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, false, Fault::None);
    let called = Cell::new(false);
    let facts = Arc::new(Mutex::new(dns_transport::fake_facts(
        "192.0.2.10:40001".parse().unwrap(),
        "192.0.2.53:53".parse().unwrap(),
        17,
        (4, 5),
    )));
    for which in 0..3 {
        let slots = SidebandCredits::new();
        let bytes = super::super::memory::ByteBudget::new(if which == 1 { 2047 } else { 8192 });
        let history = Arc::new(Mutex::new(
            InvocationHistory::new(if which == 2 { 0 } else { 256 }, &io.budget).unwrap(),
        ));
        let held = if which == 0 {
            Some(slots.fds.reserve(49).unwrap())
        } else {
            None
        };
        assert!(
            dns_transport::Incoming::fake(
                io.raw_record(2),
                &dns_neg(io.record),
                &slots,
                &bytes,
                Some(Arc::clone(&history)),
                Arc::clone(&facts),
                Arc::clone(&io.valid),
                Arc::clone(&io.closed),
                || called.set(true)
            )
            .is_err()
        );
        assert!(!called.get());
        assert_eq!(slots.pending.used(), 0);
        assert_eq!(history.lock().unwrap().reserved, 0);
        drop(held);
        assert_eq!(slots.fds.used(), 0);
    }
}
#[test]
fn dns_transport_driver_pending_admission_never_publishes_physical_authority() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, false, Fault::DuringAdmission);
    run(&mut issuer, &io);
    assert!(
        !statuses(&io)
            .iter()
            .any(|(kind, status, _)| *kind == 37 && *status == 1),
        "PhysicalAck появился до нового ADMIT_ACK"
    );
    assert_eq!(issuer.transport.counts().2, 0);
    assert_eq!(io.created.load(Ordering::Acquire), 1);
}
#[test]
fn dns_transport_driver_final_kernel_check_cannot_extend_owner_deadline() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    issuer.authority.dns_delay_on = Some(2);
    let io = Driver::new(&issuer, a, false, Fault::None);
    run(&mut issuer, &io);
    assert!(
        !statuses(&io)
            .iter()
            .any(|(kind, status, _)| *kind == 37 && *status == 1),
        "PhysicalAck использовал freshness до blocking route fence"
    );
}
#[test]
fn dns_transport_driver_reordered_and_replayed_logical_bind_never_mints_second_proof() {
    for fault in [Fault::EarlyLogical, Fault::ReplayLogical] {
        let (mut issuer, a) = bundle_fixture(Mode::System, false);
        let io = Driver::new(&issuer, a, false, fault);
        run(&mut issuer, &io);
        let out = statuses(&io);
        assert_eq!(out.last().unwrap().0, 39);
        assert_eq!(out.last().unwrap().1, 2);
        assert_eq!(
            issuer.transport.counts().3,
            usize::from(fault == Fault::ReplayLogical)
        );
        assert_eq!(
            io.created.load(Ordering::Acquire),
            usize::from(fault == Fault::ReplayLogical)
        );
        assert!(!issuer.unknown);
    }
}
#[test]
fn dns_transport_driver_late_fd_cannot_refresh_expired_owner() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, false, Fault::Expired);
    run(&mut issuer, &io);
    assert!(
        !statuses(&io)
            .iter()
            .any(|(kind, _, _)| *kind == 37 || *kind == 39)
    );
    assert!(issuer.unknown);
    assert_eq!(issuer.transport.counts().2, 0);
    assert!(io.slots.fds.used() >= 18);
}
#[test]
fn dns_transport_driver_control_close_sees_already_received_scm_before_known_cleanup() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, true, Fault::ControlClose);
    run(&mut issuer, &io);
    assert!(issuer.unknown);
    assert_eq!(issuer.flows.len(), 1);
    assert_eq!(issuer.authority.live.len(), 2);
    assert_eq!(issuer.transport.counts().1, 1);
    assert_eq!(io.closed.load(Ordering::Acquire), 0);
    assert!(!statuses(&io).iter().any(|(kind, _, _)| *kind == 37));
}
#[test]
fn dns_transport_driver_cancel_exchange_sees_early_child_scm_before_known_cleanup() {
    let (mut issuer, a) = bundle_fixture(Mode::System, false);
    let io = Driver::new(&issuer, a, true, Fault::CancelExchangeEarly);
    run(&mut issuer, &io);
    assert!(issuer.unknown);
    assert_eq!(statuses(&io).last(), Some(&(48, 3, 5)));
    assert_eq!(issuer.transport.counts().1, 1);
    assert_eq!(io.closed.load(Ordering::Acquire), 0);
    assert_eq!(issuer.authority.live.len(), 2);
}
