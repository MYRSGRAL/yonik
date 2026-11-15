use super::*;
use std::collections::BTreeSet;
#[derive(Clone)]
struct Proof {
    source: u64,
    tuple: Tuple,
    subject: Option<Subject>,
    expiry: Instant,
    receipt: wire::Receipt,
}
struct Fake {
    mode: Mode,
    now: Instant,
    elapsed: Arc<std::sync::atomic::AtomicU64>,
    known: bool,
    revoked: AtomicBool,
    owner_count: u64,
    route_count: u64,
    released: Vec<u64>,
    live: BTreeSet<u64>,
    route_delay: Duration,
    unknown_release: bool,
    fail_after_route: bool,
}
impl Fake {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            now: Instant::now(),
            elapsed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            known: true,
            revoked: AtomicBool::new(false),
            owner_count: 0,
            route_count: 0,
            released: Vec::new(),
            live: BTreeSet::new(),
            route_delay: Duration::ZERO,
            unknown_release: false,
            fail_after_route: false,
        }
    }
}
impl Authority for Fake {
    type Proof = Proof;
    type Ingress = ();
    fn mode(&self) -> Mode {
        self.mode
    }
    fn now(&self) -> Instant {
        self.now + Duration::from_nanos(self.elapsed.load(Ordering::Acquire))
    }
    fn fence(&self) -> Result<(), ServiceError> {
        if self.revoked.load(Ordering::Acquire) {
            Err(ServiceError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }
    fn ingress(
        &mut self,
        capsule: &wire::Capsule<'_>,
        message: &wire::Message<'_>,
        _: &Arc<ChannelBudget>,
    ) -> Result<(), ServiceError> {
        capsule.validate_request(message).map_err(unavailable)
    }
    fn check_ingress(&self, _: &()) -> Result<(), ServiceError> {
        self.fence()
    }
    fn owner(
        &mut self,
        source: u64,
        tuple: Tuple,
        reference: OwnerReference,
    ) -> Result<Proof, ServiceError> {
        self.fence()?;
        if self.mode == Mode::System && !self.known {
            return Err(ServiceError::Unavailable);
        }
        if reference != OwnerReference::NONE {
            return Err(ServiceError::Unavailable);
        }
        self.owner_count += 1;
        Ok(Proof {
            source,
            tuple,
            subject: self.mode.required().then_some(Subject {
                pid: 100,
                start: 101,
                executable: (102, 103),
                cookie: 104,
                epoch: 5,
                path: [105; 32],
            }),
            expiry: self.now() + Duration::from_millis(20),
            receipt: wire::Receipt {
                kind: if self.mode.required() {
                    wire::ReceiptKind::SidebandOperation
                } else {
                    wire::ReceiptKind::None
                },
                id: if self.mode.required() {
                    self.owner_count
                } else {
                    0
                },
            },
        })
    }
    fn subject(
        &self,
        proof: &Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<Option<Subject>, ServiceError> {
        self.fence()?;
        if proof.source != source
            || proof.tuple != tuple
            || self.mode.required() && self.now() >= proof.expiry
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(proof.subject)
    }
    fn expiry(&self, proof: &Proof) -> Option<Instant> {
        self.mode.required().then_some(proof.expiry)
    }
    fn receipt(
        &self,
        proof: &Proof,
        source: u64,
        tuple: Tuple,
    ) -> Result<wire::Receipt, ServiceError> {
        self.subject(proof, source, tuple)?;
        Ok(proof.receipt)
    }
    fn route(
        &mut self,
        _: RouteRequest<'_>,
        _: &Proof,
        _: u64,
        _: Tuple,
    ) -> Result<Option<u64>, ServiceError> {
        self.route_count += 1;
        self.live.insert(self.route_count);
        self.now += self.route_delay;
        if self.fail_after_route {
            self.known = false;
        }
        Ok(Some(self.route_count))
    }
    fn release(&mut self, ticket: u64) -> Result<(), ServiceError> {
        if self.unknown_release {
            return Err(ServiceError::Unavailable);
        }
        assert!(self.live.remove(&ticket));
        self.released.push(ticket);
        Ok(())
    }
    fn cancel_source(&mut self, _: u64) -> Result<(), ServiceError> {
        Ok(())
    }
}
fn issuer(mode: Mode) -> Issuer<Fake> {
    use yonik_engine::native_profile::{OwnedRuntimePlan, ProfileIntent};
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/xray-profile-channel-v3/local-minimal.json"
    ))
    .unwrap();
    let intent = ProfileIntent::decode(&fixture["profile"].to_string()).unwrap();
    let mut plan =
        OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
    if mode == Mode::System {
        plan = plan.with_system(
            yonik_engine::SystemTun::new(
                1,
                1500,
                42,
                vec![
                    yonik_engine::SystemTunAddress::new("198.18.0.1".parse().unwrap(), 30).unwrap(),
                ],
            )
            .unwrap(),
        );
    }
    let capsule = Arc::new(wire::OwnedCapsule::build(&intent, &plan, None, [3; 32], 1, 1).unwrap());
    let manifest = wire::Capsule::decode(capsule.bytes(), &[3; 32])
        .unwrap()
        .manifest;
    let record = LaunchRecord {
        mode,
        nonce: [6; 32],
        binding: wire::Binding {
            digest: [3; 32],
            session: [1; 16],
            invocation: [2; 16],
            generation: 4,
            epoch: 5,
        },
        owner_pid: 7,
        owner_start: 9,
        child_pid: if mode.required() { 8 } else { 0 },
        child_start: if mode.required() { 10 } else { 0 },
        manifest,
    };
    Issuer::new(Fake::new(mode), capsule, record).unwrap()
}
fn original() -> wire::Destination<'static> {
    wire::Destination {
        protocol: 6,
        family: 4,
        port: 443,
        bytes: &[203, 0, 113, 9],
    }
}
fn open(mode: Mode, port: u16) -> wire::Message<'static> {
    let mut local = [0; 16];
    local[..4].copy_from_slice(&[192, 0, 2, 1]);
    let mut remote = [0; 16];
    remote[..4].copy_from_slice(if mode.required() {
        &[203, 0, 113, 9]
    } else {
        &[127, 0, 0, 1]
    });
    wire::Message::OpenIngress {
        ingress: if mode.required() { 2 } else { 0 },
        provenance: if mode.required() { 1 } else { 2 },
        tuple: Tuple {
            protocol: 6,
            family: 4,
            local_port: port,
            remote_port: if mode.required() { 443 } else { 1080 },
            local,
            remote,
        },
        original: original(),
    }
}
fn authorize(source: u64) -> wire::Authorize<'static> {
    wire::Authorize {
        source_flow: source,
        class: 1,
        subject: 0,
        chain: u16::MAX,
        transport: 0,
        scope: 0,
        branch: 0,
        original: original(),
        effective: original(),
        resolver: u16::MAX,
        query: "",
        receipt: wire::Receipt {
            kind: wire::ReceiptKind::None,
            id: 0,
        },
    }
}

#[test]
fn local_required_false_and_system_unknown_never_allow() {
    for mode in [Mode::Local, Mode::System] {
        let mut issuer = issuer(mode);
        issuer.authority.known = false;
        let opened = issuer.open(2, &open(mode, 32001));
        assert_eq!(opened.is_ok(), mode == Mode::Local);
        if let Ok((id, proof)) = opened {
            assert!(
                issuer
                    .authority
                    .subject(&proof, id, issuer.flows[&id].tuple)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                issuer
                    .authority
                    .receipt(&proof, id, issuer.flows[&id].tuple)
                    .unwrap()
                    .kind,
                wire::ReceiptKind::None
            );
        }
    }
}
#[test]
fn original_flow_mutation_and_wrong_receipt_namespace_are_denied_before_route() {
    let mut issuer = issuer(Mode::System);
    let (id, _) = issuer.open(2, &open(Mode::System, 32001)).unwrap();
    let mut request = authorize(id);
    request.original.port = 80;
    assert!(issuer.authorize(3, 0, &request).is_err());
    request = authorize(id);
    request.receipt = wire::Receipt {
        kind: wire::ReceiptKind::FrozenSent,
        id: 1,
    };
    assert!(issuer.authorize(4, 0, &request).is_err());
    assert_eq!(issuer.authority.route_count, 0);
}
#[test]
fn cancel_one_flow_preserves_neighbor_and_ids_never_resurrect() {
    let mut issuer = issuer(Mode::System);
    let (first, _) = issuer.open(2, &open(Mode::System, 32001)).unwrap();
    let (second, _) = issuer.open(3, &open(Mode::System, 32002)).unwrap();
    let (one, _) = issuer.authorize(4, 0, &authorize(first)).unwrap();
    let (two, _) = issuer.authorize(5, 0, &authorize(second)).unwrap();
    issuer.cancel_flow(first).unwrap();
    assert!(!issuer.grants.contains_key(&one));
    assert!(issuer.grants.contains_key(&two));
    assert!(!issuer.unknown);
    assert!(!issuer.authority.revoked.load(Ordering::Acquire));
    assert!(issuer.authorize(6, 0, &authorize(first)).is_err());
    assert!(issuer.cancel_flow(second + 1).is_err());
    let (third, _) = issuer.open(7, &open(Mode::System, 32003)).unwrap();
    assert!(third > second);
}
#[test]
fn cancel_many_grants_does_not_overflow_request_tombstones_or_revoke_neighbor() {
    let mut issuer = issuer(Mode::System);
    let (first, _) = issuer.open(2, &open(Mode::System, 32001)).unwrap();
    let (second, _) = issuer.open(3, &open(Mode::System, 32002)).unwrap();
    for request in 4..304 {
        issuer.authorize(request, 0, &authorize(first)).unwrap();
    }
    let (neighbor, _) = issuer.authorize(304, 0, &authorize(second)).unwrap();
    issuer.cancel_flow(first).unwrap();
    assert_eq!(issuer.grants.len(), 1);
    assert!(issuer.grants.contains_key(&neighbor));
    assert!(issuer.retired.is_empty());
    assert!(!issuer.unknown);
    assert!(!issuer.authority.revoked.load(Ordering::Acquire));
}
#[test]
fn queued_request_cancel_is_retained_and_refresh_rechecks_route() {
    let mut issuer = issuer(Mode::System);
    let (flow, _) = issuer.open(2, &open(Mode::System, 32001)).unwrap();
    let (grant, _) = issuer.authorize(3, 0, &authorize(flow)).unwrap();
    issuer.authorize(4, grant, &authorize(flow)).unwrap();
    assert_eq!(issuer.authority.route_count, 2);
    assert_eq!(issuer.authority.released, vec![1]);
    cancel(&mut issuer, 8, 1, 6).unwrap();
    assert!(issuer.retired.iter().any(|(request, _)| *request == 6));
    assert!(cancel(&mut issuer, 8, 1, 9).is_err());
}
#[test]
fn owner_expiry_during_durable_route_requires_new_observation_and_rolls_back_on_unknown() {
    let mut issuer = issuer(Mode::System);
    let (flow, _) = issuer.open(2, &open(Mode::System, 32001)).unwrap();
    issuer.authority.route_delay = Duration::from_millis(21);
    let (grant, proof) = issuer.authorize(3, 0, &authorize(flow)).unwrap();
    assert_eq!(issuer.authority.owner_count, 3);
    assert_eq!(issuer.grants[&grant].expires, proof.expiry);
    assert_eq!(proof.receipt.id, 3);
    issuer.authority.fail_after_route = true;
    assert!(issuer.authorize(4, 0, &authorize(flow)).is_err());
    assert_eq!(issuer.authority.live.len(), 1);
    assert!(issuer.authority.released.contains(&2));
}
#[test]
fn unknown_retirement_keeps_custody_and_blocks_every_new_open() {
    let mut issuer = issuer(Mode::System);
    let (flow, _) = issuer.open(2, &open(Mode::System, 32001)).unwrap();
    let (grant, _) = issuer.authorize(3, 0, &authorize(flow)).unwrap();
    issuer.authority.unknown_release = true;
    assert!(issuer.cancel_grant(grant).is_err());
    assert!(issuer.unknown);
    assert!(issuer.grants.contains_key(&grant));
    assert!(issuer.authority.live.contains(&1));
    assert!(issuer.open(4, &open(Mode::System, 32002)).is_err());
}

struct FakeIo {
    record: LaunchRecord,
    state: std::cell::RefCell<IoState>,
    wrong_ack: bool,
}
#[derive(Default)]
struct IoState {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    finished: bool,
}
impl FakeIo {
    fn push(
        &self,
        state: &mut IoState,
        sequence: u64,
        reply_to: u64,
        kind: wire::Kind,
        message: wire::Message<'_>,
    ) {
        let mut bytes = [0; 1153];
        let length = wire::Frame::encode(
            wire::Header {
                kind,
                sequence,
                reply_to,
                binding: self.record.binding,
                object_id: 0,
            },
            &message,
            &mut bytes,
        )
        .unwrap();
        state.incoming.push_back(bytes[..length].to_vec());
    }
}
impl Channel for FakeIo {
    fn read(
        &self,
        pid: u32,
        uid: u32,
        out: &mut [u8; 1153],
    ) -> Result<Option<usize>, ServiceError> {
        assert_eq!((pid, uid), (8, 997));
        let mut state = self.state.borrow_mut();
        if let Some(bytes) = state.incoming.pop_front() {
            out[..bytes.len()].copy_from_slice(&bytes);
            Ok(Some(bytes.len()))
        } else if state.finished {
            Err(ServiceError::Unavailable)
        } else {
            Ok(None)
        }
    }
    fn write(&self, bytes: &[u8]) -> Result<bool, ServiceError> {
        let frame = wire::Frame::decode(bytes, self.record.binding, Mode::System, true).unwrap();
        let mut state = self.state.borrow_mut();
        state.sent.push(bytes.to_vec());
        match frame.message {
            wire::Message::Admit(body) => {
                let capsule = wire::Capsule::decode(body, &self.record.binding.digest).unwrap();
                self.push(
                    &mut state,
                    2,
                    frame.header.sequence,
                    wire::Kind::AdmitAck,
                    wire::Message::AdmitAck {
                        manifest: if self.wrong_ack {
                            [77; 32]
                        } else {
                            capsule.manifest
                        },
                        admission: capsule.admission_id,
                        status: wire::Status::Allow,
                    },
                );
                self.push(
                    &mut state,
                    3,
                    0,
                    wire::Kind::OpenIngress,
                    open(Mode::System, 32001),
                );
                self.push(
                    &mut state,
                    4,
                    0,
                    wire::Kind::OpenIngress,
                    open(Mode::System, 32002),
                );
                self.push(
                    &mut state,
                    5,
                    0,
                    wire::Kind::Authorize,
                    wire::Message::Authorize(authorize(1)),
                );
                self.push(
                    &mut state,
                    6,
                    0,
                    wire::Kind::Authorize,
                    wire::Message::Authorize(authorize(2)),
                );
                self.push(
                    &mut state,
                    7,
                    0,
                    wire::Kind::Cancel,
                    wire::Message::Cancel {
                        target: 2,
                        reason: 1,
                        id: 1,
                    },
                );
            }
            wire::Message::Grant { flow: 2, .. } => self.push(
                &mut state,
                8,
                0,
                wire::Kind::Cancel,
                wire::Message::Cancel {
                    target: 2,
                    reason: 1,
                    id: 2,
                },
            ),
            wire::Message::CloseAck {
                target: 2, id: 2, ..
            } => state.finished = true,
            _ => {}
        }
        Ok(true)
    }
    fn pause(&self) {
        panic!("fake transport не должен ожидать OS или wall-clock");
    }
}
#[test]
fn actual_driver_commits_exact_ack_drains_cancel_and_preserves_neighbor() {
    let mut issuer = issuer(Mode::System);
    let io = FakeIo {
        record: issuer.record,
        state: Default::default(),
        wrong_ack: false,
    };
    let ready = AtomicBool::new(false);
    assert!(run_issuer(&mut issuer, &io, 8, 997, &AtomicBool::new(false), &ready).is_err());
    assert!(ready.load(Ordering::Acquire));
    assert!(issuer.flows.is_empty());
    assert!(issuer.grants.is_empty());
    assert_eq!(issuer.authority.released, vec![1]);
    assert!(!issuer.unknown);
    let state = io.state.borrow();
    let mut sequence = wire::Sequence::new();
    let mut allowed = Vec::new();
    for bytes in &state.sent {
        let frame = wire::Frame::decode(bytes, issuer.record.binding, Mode::System, true).unwrap();
        sequence.accept(frame.header.sequence).unwrap();
        if let wire::Message::Grant {
            flow,
            required,
            receipt,
            ..
        } = frame.message
        {
            assert!(required);
            assert_eq!(receipt.kind, wire::ReceiptKind::SidebandOperation);
            allowed.push(flow);
        }
    }
    assert_eq!(allowed, vec![2]);
}
#[test]
fn wrong_manifest_ack_never_commits_or_mints() {
    let mut issuer = issuer(Mode::System);
    let io = FakeIo {
        record: issuer.record,
        state: Default::default(),
        wrong_ack: true,
    };
    let ready = AtomicBool::new(false);
    assert!(run_issuer(&mut issuer, &io, 8, 997, &AtomicBool::new(false), &ready).is_err());
    assert!(!ready.load(Ordering::Acquire));
    assert!(issuer.flows.is_empty());
    assert_eq!(issuer.authority.owner_count, 0);
}
struct Backpressure {
    elapsed: Arc<std::sync::atomic::AtomicU64>,
    delay: u64,
    attempts: std::cell::Cell<usize>,
    sent: std::cell::RefCell<Vec<u8>>,
}
impl Channel for Backpressure {
    fn read(&self, _: u32, _: u32, _: &mut [u8; 1153]) -> Result<Option<usize>, ServiceError> {
        panic!("send не читает канал");
    }
    fn write(&self, bytes: &[u8]) -> Result<bool, ServiceError> {
        let n = self.attempts.get();
        self.attempts.set(n + 1);
        if n == 0 {
            self.elapsed.fetch_add(self.delay, Ordering::AcqRel);
            return Ok(false);
        }
        self.sent.borrow_mut().extend_from_slice(bytes);
        Ok(true)
    }
    fn pause(&self) {}
}
#[test]
fn send_backpressure_never_extends_original_owner_expiry_or_encoded_freshness() {
    for delay in [5_000_000, 21_000_000] {
        let issuer = issuer(Mode::System);
        let until = issuer.authority.now() + Duration::from_millis(20);
        let io = Backpressure {
            elapsed: Arc::clone(&issuer.authority.elapsed),
            delay,
            attempts: Default::default(),
            sent: Default::default(),
        };
        let message = wire::Message::Grant {
            status: wire::Status::Allow,
            class: 1,
            required: true,
            grant: 1,
            flow: 1,
            lease: 20,
            revision: 1,
            fresh: 20_000_000,
            receipt: wire::Receipt {
                kind: wire::ReceiptKind::SidebandOperation,
                id: 1,
            },
        };
        let result = send_message(
            &issuer,
            &io,
            &AtomicBool::new(false),
            2,
            3,
            1,
            &message,
            until,
        );
        assert_eq!(result.is_ok(), delay < 20_000_000);
        if result.is_ok() {
            let bytes = io.sent.borrow();
            let frame =
                wire::Frame::decode(&bytes, issuer.record.binding, Mode::System, true).unwrap();
            let wire::Message::Grant { fresh, lease, .. } = frame.message else {
                panic!("GRANT")
            };
            assert_eq!(fresh, 15_000_000);
            assert_eq!(lease, 15);
        } else {
            assert!(io.sent.borrow().is_empty());
            assert_eq!(io.attempts.get(), 1);
        }
    }
}
