use super::*;
use std::collections::BTreeSet;

struct CancelProofIo {
    inbox: std::cell::RefCell<Rendezvous<u8>>,
    packets: std::cell::RefCell<VecDeque<Queued>>,
}
impl Channel for CancelProofIo {
    fn discard_ingress(&self, request: u64) -> Result<(), ServiceError> {
        self.inbox.borrow_mut().discard(request);
        Ok(())
    }
    fn read(&self, _: u32, _: u32, out: &mut [u8; 1153]) -> Result<Option<usize>, ServiceError> {
        Ok(self.packets.borrow_mut().pop_front().map(|packet| {
            out[..packet.length].copy_from_slice(&packet.bytes[..packet.length]);
            packet.length
        }))
    }
    fn write(&self, _: &[u8]) -> Result<bool, ServiceError> {
        panic!("drain не пишет ответы")
    }
}

#[test]
fn canceled_queued_open_discards_ready_proof_without_expiring_neighbor() {
    let mut issuer = issuer(Mode::System);
    let (neighbor, _) = issuer.open(1, &open(Mode::System, 32002)).unwrap();
    let now = Instant::now();
    let (packet, proof) = rendezvous_open(issuer.record, 2);
    let mut inbox = Rendezvous::new().unwrap();
    inbox.proof(proof, 42, now).unwrap();
    inbox.runtime(packet, now).unwrap();
    let packet = inbox.next(issuer.record, now).unwrap().unwrap();
    let mut bytes = [0; 1153];
    let length = wire::Frame::encode(
        wire::Header {
            kind: wire::Kind::Cancel,
            sequence: 3,
            reply_to: 0,
            binding: issuer.record.binding,
            object_id: 0,
        },
        &wire::Message::Cancel {
            target: 1,
            id: 2,
            reason: 0,
        },
        &mut bytes,
    )
    .unwrap();
    let io = CancelProofIo {
        inbox: std::cell::RefCell::new(inbox),
        packets: std::cell::RefCell::new(VecDeque::from([
            packet,
            Queued {
                bytes,
                length,
                sequence: 3,
            },
        ])),
    };
    let mut incoming = wire::Sequence::new();
    incoming.accept(1).unwrap();
    let mut queued = VecDeque::new();
    let mut acks = VecDeque::new();
    drain_before_publication(
        &mut issuer,
        &io,
        8,
        997,
        &mut incoming,
        &mut queued,
        &mut acks,
    )
    .unwrap();
    assert_eq!(queued.len(), 1);
    assert!(issuer.retired.iter().any(|(id, _)| *id == 2));
    let mut inbox = io.inbox.borrow_mut();
    inbox.check(now + Duration::from_secs(2)).unwrap();
    assert!(inbox.proof(proof, 43, now).is_err());
    assert!(issuer.flows.contains_key(&neighbor));
    issuer.fence().unwrap();
}
fn rendezvous_open(record: LaunchRecord, sequence: u64) -> (Queued, wire::SocketRecord) {
    let message = open(Mode::Local, 32001);
    let wire::Message::OpenIngress { tuple, ingress, .. } = message else {
        unreachable!()
    };
    let mut bytes = [0; 1153];
    let length = wire::Frame::encode(
        wire::Header {
            kind: wire::Kind::OpenIngress,
            sequence,
            reply_to: 0,
            binding: record.binding,
            object_id: 0,
        },
        &message,
        &mut bytes,
    )
    .unwrap();
    (
        Queued {
            bytes,
            length,
            sequence,
        },
        wire::SocketRecord {
            request: sequence,
            proof: sequence,
            ingress,
            tuple,
        },
    )
}
#[test]
fn socket_proof_rendezvous_accepts_both_channel_orders_without_early_authority() {
    let record = issuer(Mode::System).record;
    for proof_first in [false, true] {
        let mut inbox = Rendezvous::<u8>::new().unwrap();
        let now = Instant::now();
        let (packet, proof) = rendezvous_open(record, 2);
        if proof_first {
            inbox.proof(proof, 42, now).unwrap();
            assert!(inbox.next(record, now).unwrap().is_none());
            assert!(inbox.take(2, proof.tuple, proof.ingress).is_err());
            inbox.runtime(packet, now).unwrap();
        } else {
            inbox.runtime(packet, now).unwrap();
            assert!(inbox.next(record, now).unwrap().is_none());
            inbox.proof(proof, 42, now).unwrap();
        }
        assert_eq!(inbox.next(record, now).unwrap().unwrap().sequence, 2);
        assert_eq!(inbox.take(2, proof.tuple, proof.ingress).unwrap(), 42);
        assert!(inbox.take(2, proof.tuple, proof.ingress).is_err());
        assert!(inbox.proof(proof, 43, now).is_err());
    }
}
#[test]
fn socket_proof_rendezvous_rejects_wrong_listener_duplicate_wrap_and_original_deadline() {
    let record = issuer(Mode::System).record;
    let now = Instant::now();
    let (packet, proof) = rendezvous_open(record, 2);
    let mut inbox = Rendezvous::<u8>::new().unwrap();
    inbox.runtime(packet, now).unwrap();
    inbox
        .proof(
            wire::SocketRecord {
                tuple: Tuple {
                    remote_port: 1081,
                    ..proof.tuple
                },
                ..proof
            },
            1,
            now,
        )
        .unwrap();
    assert!(inbox.next(record, now).is_err());
    let mut inbox = Rendezvous::<u8>::new().unwrap();
    inbox.proof(proof, 1, now).unwrap();
    assert!(
        inbox
            .proof(wire::SocketRecord { proof: 3, ..proof }, 2, now)
            .is_err()
    );
    assert!(
        inbox
            .proof(
                wire::SocketRecord {
                    request: 3,
                    proof: u64::MAX,
                    ..proof
                },
                2,
                now
            )
            .is_err()
    );
    assert!(
        inbox
            .proof(
                wire::SocketRecord {
                    request: u64::MAX,
                    proof: 3,
                    ..proof
                },
                2,
                now
            )
            .is_err()
    );
    assert_eq!(
        inbox.deadline(now + Duration::from_secs(5)),
        now + Duration::from_secs(1)
    );
    assert!(inbox.check(now + Duration::from_secs(1)).is_err());
}
#[test]
fn socket_proof_pending_cap_and_custody_close_every_owned_handle() {
    use std::sync::atomic::AtomicUsize;
    struct Handle(Arc<AtomicUsize>);
    impl Drop for Handle {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let record = issuer(Mode::System).record;
    let (_, proof) = rendezvous_open(record, 2);
    let now = Instant::now();
    let mut inbox = Rendezvous::<Handle>::new().unwrap();
    for id in 2..66 {
        inbox
            .proof(
                wire::SocketRecord {
                    request: id,
                    proof: id,
                    ..proof
                },
                Handle(Arc::clone(&drops)),
                now,
            )
            .unwrap();
    }
    assert!(inbox.proof_capacity().is_err());
    assert!(
        inbox
            .proof(
                wire::SocketRecord {
                    request: 66,
                    proof: 66,
                    ..proof
                },
                Handle(Arc::clone(&drops)),
                now
            )
            .is_err()
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    drop(inbox);
    assert_eq!(drops.load(Ordering::SeqCst), 65);
}
#[test]
fn socket_proof_missing_open_can_be_canceled_without_authority_or_resurrection() {
    let record = issuer(Mode::System).record;
    let (packet, proof) = rendezvous_open(record, 2);
    let now = Instant::now();
    let mut inbox = Rendezvous::<u8>::new().unwrap();
    inbox.runtime(packet, now).unwrap();
    assert!(inbox.next(record, now).unwrap().is_none());
    let mut bytes = [0; 1153];
    let length = wire::Frame::encode(
        wire::Header {
            kind: wire::Kind::Cancel,
            sequence: 3,
            reply_to: 0,
            binding: record.binding,
            object_id: 0,
        },
        &wire::Message::Cancel {
            target: 1,
            id: 2,
            reason: 0,
        },
        &mut bytes,
    )
    .unwrap();
    inbox
        .runtime(
            Queued {
                bytes,
                length,
                sequence: 3,
            },
            now,
        )
        .unwrap();
    assert_eq!(inbox.next(record, now).unwrap().unwrap().sequence, 2);
    assert!(inbox.take(2, proof.tuple, proof.ingress).is_err());
    assert_eq!(inbox.next(record, now).unwrap().unwrap().sequence, 3);
    assert!(inbox.proof(proof, 1, now).is_err());
}
#[derive(Clone)]
struct Proof {
    source: u64,
    tuple: Tuple,
    subject: Option<Subject>,
    expiry: Instant,
    receipt: wire::Receipt,
}
struct Fake {
    service_trusted: bool,
    mode: Mode,
    now: Instant,
    elapsed: Arc<std::sync::atomic::AtomicU64>,
    known: bool,
    revoked: AtomicBool,
    owner_count: u64,
    route_count: u64,
    service_routes: Vec<Target>,
    released: Vec<u64>,
    live: BTreeSet<u64>,
    route_delay: Duration,
    unknown_release: bool,
    release_attempts: usize,
    fail_after_route: bool,
}
impl Fake {
    fn new(mode: Mode) -> Self {
        Self {
            service_trusted: false,
            mode,
            now: Instant::now(),
            elapsed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            known: true,
            revoked: AtomicBool::new(false),
            owner_count: 0,
            route_count: 0,
            service_routes: Vec::new(),
            released: Vec::new(),
            live: BTreeSet::new(),
            route_delay: Duration::ZERO,
            unknown_release: false,
            release_attempts: 0,
            fail_after_route: false,
        }
    }
}
impl Authority for Fake {
    fn service(
        &mut self,
        _: [u8; 32],
        route: RouteRequest<'_>,
    ) -> Result<Option<u64>, ServiceError> {
        self.fence()?;
        if !self.service_trusted {
            return Err(ServiceError::Unavailable);
        }
        match route {
            RouteRequest::Static(d) | RouteRequest::Direct(d) | RouteRequest::Dns(d) => {
                self.service_routes.push(Target::copy(d)?)
            }
            RouteRequest::Chain => panic!("service chain должен быть выведен до terminal leaf"),
        }
        self.route_count += 1;
        self.live.insert(self.route_count);
        self.now += self.route_delay;
        Ok(Some(self.route_count))
    }
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
        _request: u64,
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
        self.release_attempts += 1;
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
    issuer_profile(mode, false)
}
fn issuer_profile(mode: Mode, service: bool) -> Issuer<Fake> {
    use yonik_engine::native_profile::{OwnedRuntimePlan, ProfileIntent};
    let mut fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/xray-profile-channel-v3/local-minimal.json"
    ))
    .unwrap();
    if service {
        fixture["profile"]["graph"]["observatory"] = serde_json::json!({"probeURL":"https://203.0.113.9/probe?token=fixture","subjectSelector":["direct"]});
    }
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
fn probe() -> wire::Message<'static> {
    wire::Message::Probe {
        purpose: 1,
        index: 0,
        subject: 0,
        resolver: u16::MAX,
    }
}
#[test]
fn service_constructor_rejects_wrong_probe_resolver_even_without_wire_decoder() {
    let mut issuer = issuer_profile(Mode::System, true);
    issuer.authority.service_trusted = true;
    assert!(
        issuer
            .service(
                2,
                0,
                &wire::Message::Probe {
                    purpose: 1,
                    index: 0,
                    subject: 0,
                    resolver: 0
                }
            )
            .is_err()
    );
    assert_eq!(issuer.authority.route_count, 0);
}
#[test]
fn trusted_service_probe_is_distinct_from_user_and_rejects_missing_authority() {
    for mode in [Mode::Local, Mode::System] {
        let mut issuer = issuer_profile(mode, true);
        issuer.authority.known = false;
        assert!(issuer.service(2, 0, &probe()).is_err());
        assert_eq!(issuer.authority.route_count, 0);
        issuer.authority.service_trusted = true;
        let grant = issuer.service(3, 0, &probe()).unwrap();
        assert!(issuer.flows.is_empty());
        assert_eq!(issuer.authority.owner_count, 0);
        assert!(issuer.authorize(4, 0, &authorize(grant)).is_err());
        assert!(issuer.services.contains_key(&grant));
        assert!(
            issuer
                .service(
                    5,
                    grant,
                    &wire::Message::Probe {
                        purpose: 1,
                        index: 0,
                        subject: 1,
                        resolver: u16::MAX
                    }
                )
                .is_err()
        );
        assert_eq!(issuer.service(6, grant, &probe()).unwrap(), grant);
        issuer.cancel_request(6).unwrap();
        assert!(issuer.services.is_empty());
        assert!(issuer.service(7, grant, &probe()).is_err());
        let next = issuer.service(8, 0, &probe()).unwrap();
        assert!(next > grant);
        issuer.authority.unknown_release = true;
        assert!(issuer.cancel_grant(next).is_err());
        assert!(issuer.services.contains_key(&next));
        assert!(issuer.unknown);
        assert!(issuer.service(9, 0, &probe()).is_err());
    }
}
#[test]
fn service_caps_precede_effects_and_route_latency_never_restarts_lease() {
    let mut limited = issuer_profile(Mode::System, true);
    limited.authority.service_trusted = true;
    Arc::get_mut(&mut limited.budget).unwrap().dynamic = super::super::memory::ByteBudget::new(1);
    assert!(limited.service(2, 0, &probe()).is_err());
    assert_eq!(limited.authority.route_count, 0);
    assert!(limited.services.is_empty());
    let mut issuer = issuer_profile(Mode::System, true);
    issuer.authority.service_trusted = true;
    let started = issuer.authority.now();
    issuer.authority.route_delay = Duration::from_millis(999);
    let id = issuer.service(2, 0, &probe()).unwrap();
    assert_eq!(
        issuer.services[&id].expires,
        started + Duration::from_secs(1)
    );
    issuer.authority.now = started + Duration::from_secs(1);
    assert!(issuer.service(3, id, &probe()).is_err());
    issuer.authority.route_delay = Duration::from_secs(1);
    assert!(issuer.service(4, 0, &probe()).is_err());
    assert_eq!(issuer.authority.live.len(), 1);
}
#[test]
fn service_unknown_retirement_does_not_retry_cleanup_or_free_custody() {
    let mut issuer = issuer_profile(Mode::System, true);
    issuer.authority.service_trusted = true;
    let id = issuer.service(2, 0, &probe()).unwrap();
    issuer.authority.unknown_release = true;
    assert!(issuer.cancel_grant(id).is_err());
    assert_eq!(issuer.authority.release_attempts, 1);
    assert!(issuer.cancel_grant(id).is_err());
    assert_eq!(issuer.authority.release_attempts, 1);
    assert!(issuer.services.contains_key(&id));
    assert_eq!(issuer.authority.live.len(), 1);
}
#[test]
fn user_dns_requires_private_flow_fresh_owner_exact_peer_query_and_class() {
    let mut issuer = issuer(Mode::System);
    let (flow, _) = issuer.open(2, &open(Mode::System, 32001)).unwrap();
    let peer = Target::copy(issuer.capsule().unwrap().resolver_peer(0).unwrap()).unwrap();
    let mut request = wire::Authorize {
        source_flow: flow,
        class: 3,
        subject: u16::MAX,
        chain: u16::MAX,
        transport: u16::MAX,
        scope: u16::MAX,
        branch: 0,
        original: original(),
        effective: peer.wire(),
        resolver: 0,
        query: "query.invalid",
        receipt: wire::Receipt {
            kind: wire::ReceiptKind::None,
            id: 0,
        },
    };
    issuer.authority.known = false;
    assert!(issuer.authorize(3, 0, &request).is_err());
    assert_eq!(issuer.authority.route_count, 0);
    issuer.authority.known = true;
    let (grant, _) = issuer.authorize(4, 0, &request).unwrap();
    assert!(issuer.services.is_empty());
    request.query = "foreign.invalid";
    assert!(issuer.authorize(5, grant, &request).is_err());
    request.query = "query.invalid";
    request.effective.port = 54;
    assert!(issuer.authorize(6, 0, &request).is_err());
    request.effective.port = 53;
    request.subject = 0;
    assert!(issuer.authorize(7, 0, &request).is_err());
    request.subject = u16::MAX;
    request.receipt = wire::Receipt {
        kind: wire::ReceiptKind::SidebandOperation,
        id: 1,
    };
    assert!(issuer.authorize(8, 0, &request).is_err());
    assert!(issuer.service(9, grant, &probe()).is_err());
    issuer.cancel_flow(flow).unwrap();
    assert!(issuer.grants.is_empty());
}
#[test]
fn unproved_dns_stub_is_not_approved_by_numeric_row_or_namespace_claim() {
    for address in [[127, 0, 0, 53], [0, 0, 0, 0], [224, 0, 0, 1]] {
        assert!(
            reject_unproved_stub(wire::Destination {
                protocol: 17,
                family: 4,
                port: 53,
                bytes: &address
            })
            .is_err()
        );
    }
}
#[test]
fn service_bootstrap_requires_owning_endpoint_and_exact_system_snapshot_row() {
    use yonik_engine::native_profile::{OwnedRuntimePlan, ProfileIntent, VerifiedSystemResolver};
    struct Snapshot;
    impl VerifiedSystemResolver for Snapshot {
        fn snapshot_digest(&self) -> [u8; 32] {
            [8; 32]
        }
        fn servers(&self) -> Vec<std::net::SocketAddr> {
            vec!["192.0.2.53:53".parse().unwrap()]
        }
    }
    let mut fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/xray-profile-channel-v3/system-chain-probe.json"
    ))
    .unwrap();
    fixture["profile"]["graph"]
        .as_object_mut()
        .unwrap()
        .remove("inbounds");
    fixture["profile"]["graph"]["outbounds"][0]["settings"]["servers"][0]["address"] =
        serde_json::json!("proxy.invalid");
    fixture["profile"]["graph"]["dns"] = serde_json::json!({"servers":["localhost"]});
    let intent = ProfileIntent::decode(&fixture["profile"].to_string()).unwrap();
    let plan = OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap())
        .unwrap()
        .bind_system_resolver(&Snapshot)
        .unwrap();
    let capsule = Arc::new(
        wire::OwnedCapsule::build(
            &intent,
            &plan,
            Some(wire::SnapshotRef {
                source: [8; 32],
                asset: [9; 32],
                bytes: 120,
                flags: 0,
            }),
            [3; 32],
            1,
            1,
        )
        .unwrap(),
    );
    let decoded = wire::Capsule::decode(capsule.bytes(), &[3; 32]).unwrap();
    let index = decoded.dial_scope(0, 0).unwrap().endpoint_index;
    let record = LaunchRecord {
        manifest: decoded.manifest,
        ..issuer(Mode::Local).record
    };
    let mut issuer = Issuer::new(Fake::new(Mode::Local), capsule, record).unwrap();
    issuer.authority.service_trusted = true;
    let request = wire::Message::Probe {
        purpose: 2,
        index,
        subject: 0,
        resolver: 0,
    };
    let grant = issuer.service(2, 0, &request).unwrap();
    assert_eq!(issuer.services[&grant].selector, [2, index, 0, 0]);
    assert!(
        issuer
            .service(
                3,
                grant,
                &wire::Message::Probe {
                    purpose: 2,
                    index,
                    subject: 1,
                    resolver: 0
                }
            )
            .is_err()
    );
    assert!(
        issuer
            .service(
                4,
                grant,
                &wire::Message::Probe {
                    purpose: 2,
                    index,
                    subject: 0,
                    resolver: 1
                }
            )
            .is_err()
    );
    assert!(issuer.services.contains_key(&grant));
    assert!(issuer.flows.is_empty());
    assert_eq!(issuer.authority.owner_count, 0);
    let before = issuer.authority.service_routes.len();
    issuer
        .service(
            5,
            0,
            &wire::Message::Probe {
                purpose: 1,
                index: 0,
                subject: 0,
                resolver: u16::MAX,
            },
        )
        .unwrap();
    let leaves = &issuer.authority.service_routes[before..];
    assert_eq!(leaves.len(), 1);
    assert_eq!((leaves[0].family, leaves[0].port), (4, 8443));
    assert_eq!(&leaves[0].bytes[..4], &[192, 0, 2, 2]);
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
    service: bool,
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
                if self.service {
                    self.push(&mut state, 3, 0, wire::Kind::Probe, probe());
                    self.push(&mut state, 4, 0, wire::Kind::Probe, probe());
                    self.push(
                        &mut state,
                        5,
                        0,
                        wire::Kind::Cancel,
                        wire::Message::Cancel {
                            target: 1,
                            reason: 1,
                            id: 3,
                        },
                    );
                    return Ok(true);
                }
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
            wire::Message::Grant {
                flow: 0,
                grant,
                class: 2,
                required: false,
                fresh: 0,
                receipt:
                    wire::Receipt {
                        kind: wire::ReceiptKind::None,
                        id: 0,
                    },
                ..
            } if self.service => self.push(
                &mut state,
                6,
                0,
                wire::Kind::Cancel,
                wire::Message::Cancel {
                    target: 3,
                    reason: 1,
                    id: grant,
                },
            ),
            wire::Message::CloseAck { target: 3, .. } if self.service => state.finished = true,
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
        service: false,
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
        service: false,
    };
    let ready = AtomicBool::new(false);
    assert!(run_issuer(&mut issuer, &io, 8, 997, &AtomicBool::new(false), &ready).is_err());
    assert!(!ready.load(Ordering::Acquire));
    assert!(issuer.flows.is_empty());
    assert_eq!(issuer.authority.owner_count, 0);
}
#[test]
fn actual_driver_service_dispatch_drains_cancel_before_allow_and_retires_grant() {
    let mut issuer = issuer_profile(Mode::System, true);
    issuer.authority.service_trusted = true;
    issuer.authority.known = false;
    let io = FakeIo {
        record: issuer.record,
        state: Default::default(),
        wrong_ack: false,
        service: true,
    };
    assert!(
        run_issuer(
            &mut issuer,
            &io,
            8,
            997,
            &AtomicBool::new(false),
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(issuer.services.is_empty());
    assert!(issuer.flows.is_empty());
    assert_eq!(issuer.authority.owner_count, 0);
    let state = io.state.borrow();
    let mut sequence = wire::Sequence::new();
    let mut allowed = Vec::new();
    for bytes in &state.sent {
        let frame = wire::Frame::decode(bytes, issuer.record.binding, Mode::System, true).unwrap();
        sequence.accept(frame.header.sequence).unwrap();
        if let wire::Message::Grant {
            flow: 0,
            class: 2,
            required: false,
            fresh: 0,
            receipt:
                wire::Receipt {
                    kind: wire::ReceiptKind::None,
                    id: 0,
                },
            ..
        } = frame.message
        {
            allowed.push(frame.header.reply_to);
        }
    }
    assert_eq!(allowed, vec![4]);
    assert_eq!(issuer.authority.released, vec![1, 2]);
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
