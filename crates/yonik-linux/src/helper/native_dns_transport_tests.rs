use super::issuer_tests::{Fake, bundle_fixture, bundle_fixture_network, dns_neg, dns_packet};
use super::*;
use std::{
    cell::{Cell, RefCell},
    sync::{Mutex, atomic::AtomicUsize},
};
use wire::dns_v2::Operation;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
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
                | Self::WaitersKeep
                | Self::WaiterWrongSource
                | Self::WaiterWrongRoot
                | Self::WaiterCancelQueued
        )
    }
    fn publishing(self) -> bool {
        matches!(
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
        b[164] = self.peer.protocol;
        b[165] = if self.peer.protocol == 6 { 1 } else { 2 };
        b[166] = self.record.mode as u8;
        let d = self.peer.wire();
        b[168] = d.family;
        b[169] = d.protocol;
        p16(&mut b, 170, d.port);
        b[172] = d.bytes.len() as u8;
        b[175..175 + d.bytes.len()].copy_from_slice(d.bytes);
        b
    }
    fn physical(&self, id: u64) -> Result<(), ServiceError> {
        let peer = if self.fault == Fault::Peer {
            "203.0.113.99:53".parse().unwrap()
        } else {
            "192.0.2.53:53".parse().unwrap()
        };
        let source = if self.fault == Fault::Source {
            "192.0.2.11:40001"
        } else {
            "192.0.2.10:40001"
        };
        let ns = if self.fault == Fault::Namespace {
            (9, 9)
        } else {
            (4, 5)
        };
        let facts = Arc::new(Mutex::new(dns_transport::fake_facts(
            source.parse().unwrap(),
            peer,
            self.peer.protocol,
            ns,
        )));
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
        logical[2] = 1;
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
}
impl Channel for Driver {
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
                let a = self.current_acquire.borrow();
                let body = self.reserve_for(a.as_ref().unwrap(), 3, 0, n64(b, 8));
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
                if !self.reverse {
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
                if self.fault == Fault::Changed {
                    self.valid.store(false, Ordering::Release);
                }
                self.logical(6, n64(b, 16));
            }
            Operation::LogicalAck => {
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
            Operation::Published if self.fault == Fault::PublishReplay => {
                self.queue(8, Operation::Publish, &self.publish())
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
fn statuses(driver: &Driver) -> Vec<(u16, u8, u64)> {
    driver
        .output
        .borrow()
        .iter()
        .map(|b| (n16(b, 10), b[130], n64(b, 24)))
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
            dns_transport::send_reply(&mut issuer, &io, &AtomicBool::new(false), 100, reply)
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
