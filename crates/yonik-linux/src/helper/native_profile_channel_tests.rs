use super::*;
#[test]
fn dns_schema_provenance_direct3_never_mints_descriptor4_channel() {
    let issuer = issuer(Mode::Local);
    let launch = issuer.record;
    let record = super::super::registry::fake_dns_wire_image([17; 32]);
    assert!(
        VerifiedDnsWireProducer::mint(
            &record,
            [17; 32],
            launch.binding.digest,
            launch.manifest,
            launch
        )
        .is_err()
    );
    assert!(
        VerifiedDnsProducer::mint(
            &record,
            [17; 32],
            launch.binding.digest,
            launch.manifest,
            launch
        )
        .is_err()
    );
}
#[test]
fn dns_schema_provenance_explicit_record4_channel_retains_exact_launch_and_image() {
    for mode in [Mode::Local, Mode::System] {
        let launch = issuer(mode).record;
        let record = super::super::registry::fake_dns4_image([17; 32]);
        let wire = VerifiedDnsWireProducer::mint(
            &record,
            [17; 32],
            launch.binding.digest,
            launch.manifest,
            launch,
        )
        .unwrap();
        let release = VerifiedDnsProducer::mint(
            &record,
            [17; 32],
            launch.binding.digest,
            launch.manifest,
            launch,
        )
        .unwrap();
        assert!(wire.bound(launch).is_ok());
        assert!(release.bound(launch).is_ok());
        let mut wrong = launch;
        wrong.nonce[0] ^= 1;
        assert!(wire.bound(wrong).is_err());
        assert!(release.bound(wrong).is_err());
        for (image, config, manifest) in [
            ([18; 32], launch.binding.digest, launch.manifest),
            ([17; 32], [18; 32], launch.manifest),
            ([17; 32], launch.binding.digest, [18; 32]),
        ] {
            assert!(
                VerifiedDnsWireProducer::mint(&record, image, config, manifest, launch).is_err()
            );
            assert!(VerifiedDnsProducer::mint(&record, image, config, manifest, launch).is_err());
        }
    }
}
use std::collections::BTreeSet;

#[test]
fn dns_rrset_queue_credit_precedes_materialization_and_rx_bound_is_fixed() {
    let budget = super::super::memory::ByteBudget::new(128);
    assert!(Queued::new(&[0; 129], 1, &budget).is_err());
    assert_eq!(budget.used(), 0);
    let packet = Queued::new(&[0; 100], 1, &budget).unwrap();
    assert_eq!(budget.used(), 116);
    drop(packet);
    assert_eq!(budget.used(), 0);
    assert!(Queued::new(&[0; RUNTIME_PACKET], 1, &budget).is_err());
    assert_eq!(RX_BYTES, 256 * 1024);
}

// Весь driver below — in-memory: ни OS endpoint, ни runtime wrappers.
struct BundleIo {
    record: LaunchRecord,
    input: std::cell::RefCell<VecDeque<Vec<u8>>>,
    output: std::cell::RefCell<Vec<Vec<u8>>>,
    descriptor: [u8; 272],
    done: std::cell::Cell<bool>,
    stop_after: usize,
    history: Option<Arc<std::sync::Mutex<InvocationHistory>>>,
    delayed_send: std::cell::RefCell<Option<Arc<std::sync::atomic::AtomicU64>>>,
}
pub(super) fn dns_neg(record: LaunchRecord) -> wire::dns_v2::Negotiated {
    let d = wire::dns_v2::Negotiated::descriptor(record).unwrap();
    wire::dns_v2::Negotiated::accept(
        &d,
        &wire::dns_v2::Negotiated::ack(&d).unwrap(),
        record,
        [(0, 0); 2],
    )
    .unwrap()
}
pub(super) fn dns_packet(
    record: LaunchRecord,
    sequence: u64,
    kind: wire::dns_v2::Operation,
    body: &[u8],
) -> Vec<u8> {
    let frame = wire::dns_v2::DnsFrame {
        header: wire::dns_v2::Envelope {
            sequence,
            reply_to: 0,
            binding: record.binding,
        },
        record: wire::dns_v2::Record::decode(kind, body).unwrap(),
    };
    let mut bytes = [0; RUNTIME_PACKET];
    let n = frame.encode(&dns_neg(record), &mut bytes).unwrap();
    bytes[..n].to_vec()
}
impl BundleIo {
    fn new(record: LaunchRecord, requests: Vec<Vec<u8>>) -> Self {
        Self {
            record,
            input: std::cell::RefCell::new(requests.into()),
            output: Default::default(),
            descriptor: wire::dns_v2::Negotiated::descriptor(record).unwrap(),
            done: Default::default(),
            stop_after: 1,
            history: None,
            delayed_send: Default::default(),
        }
    }
}
impl Channel for BundleIo {
    fn history(&self) -> Option<Arc<std::sync::Mutex<InvocationHistory>>> {
        self.history.clone()
    }
    fn setup_read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        out[..272].copy_from_slice(&self.descriptor);
        Ok(Some(272))
    }
    fn setup_write(&self, b: &[u8]) -> Result<bool, ServiceError> {
        assert_eq!(b, wire::dns_v2::Negotiated::ack(&self.descriptor).unwrap());
        Ok(true)
    }
    fn read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        if let Some(b) = self.input.borrow_mut().pop_front() {
            out[..b.len()].copy_from_slice(&b);
            return Ok(Some(b.len()));
        }
        if self.done.get() {
            Err(ServiceError::Unavailable)
        } else {
            Ok(None)
        }
    }
    fn write(&self, b: &[u8]) -> Result<bool, ServiceError> {
        if dns_bundle::is_dns(b) {
            if let Some(elapsed) = self.delayed_send.borrow_mut().take() {
                elapsed.fetch_add(25_000_000, Ordering::AcqRel);
                return Ok(false);
            }
            dns_bundle::decode(b, &dns_neg(self.record), wire::dns_v2::Direction::Issuer)?;
            self.output.borrow_mut().push(b.to_vec());
            self.done.set(self.output.borrow().len() >= self.stop_after);
            return Ok(true);
        }
        let f = wire::Frame::decode(b, self.record.binding, self.record.mode, true)
            .map_err(unavailable)?;
        let wire::Message::Admit(raw) = f.message else {
            return Err(ServiceError::InvalidRequest);
        };
        let cap = wire::Capsule::decode(raw, &self.record.binding.digest).map_err(unavailable)?;
        let mut ack = [0; RUNTIME_PACKET];
        let n = wire::Frame::encode(
            wire::Header {
                kind: wire::Kind::AdmitAck,
                sequence: 2,
                reply_to: f.header.sequence,
                binding: self.record.binding,
                object_id: 0,
            },
            &wire::Message::AdmitAck {
                manifest: cap.manifest,
                admission: cap.admission_id,
                status: wire::Status::Allow,
            },
            &mut ack,
        )
        .map_err(unavailable)?;
        self.input.borrow_mut().push_front(ack[..n].to_vec());
        Ok(true)
    }
    fn pause_until(&self, _: Instant) {
        panic!("pure BundleIo не ожидает OS");
    }
    fn writable_until(&self, _: Instant) {}
}
pub(super) fn bundle_fixture(mode: Mode, chain: bool) -> (Issuer<Fake>, Vec<u8>) {
    bundle_fixture_network(mode, chain, false)
}
pub(super) fn bundle_fixture_network(
    mode: Mode,
    chain: bool,
    tcp: bool,
) -> (Issuer<Fake>, Vec<u8>) {
    use yonik_engine::native_profile::{OwnedRuntimePlan, ProfileIntent};
    let mut graph = if chain {
        serde_json::json!({"outbounds":[{"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":"203.0.113.10","port":8388,"method":"aes-128-gcm","password":"fixture"}]},"proxySettings":{"tag":"direct","transportLayer":true}},{"tag":"direct","protocol":"vless","settings":{"vnext":[{"address":"203.0.113.11","port":8443,"users":[{"id":"00000000-0000-0000-0000-000000000001","encryption":"none"}]}]}}],"dns":{"tag":"proxy","servers":["192.0.2.53"]}})
    } else {
        serde_json::json!({"outbounds":[{"tag":"direct","protocol":"freedom"}],"dns":{"tag":"direct","servers":["192.0.2.53"]}})
    };
    if tcp {
        graph["dns"]["servers"] = serde_json::json!(["tcp://192.0.2.53:53"]);
    }
    let intent =
        ProfileIntent::decode(&serde_json::json!({"version":1,"graph":graph}).to_string()).unwrap();
    let mut plan =
        OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
    if mode.required() {
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
    let cap = wire::Capsule::decode(capsule.bytes(), &[3; 32]).unwrap();
    let record = LaunchRecord {
        manifest: cap.manifest,
        ..issuer(mode).record
    };
    let mut issuer = Issuer::new(Fake::new(mode), capsule, record).unwrap();
    let (flow, _) = issuer.open(50, &open(mode, 32001)).unwrap();
    let peer = Target::copy(issuer.capsule().unwrap().resolver_peer(0).unwrap()).unwrap();
    let a = wire::Authorize {
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
    let (root, _) = issuer.authorize(51, 0, &a).unwrap();
    let mut encoded = [0; 1152];
    let size = wire::Frame::encode(
        wire::Header {
            kind: wire::Kind::Authorize,
            sequence: 51,
            reply_to: 0,
            binding: record.binding,
            object_id: 0,
        },
        &wire::Message::Authorize(a),
        &mut encoded,
    )
    .unwrap();
    let base = &encoded[128..size];
    let n = base.len();
    let cap = issuer.capsule().unwrap();
    let (mut scope, _) = cap.resolver_scope(0).unwrap().scope.unwrap();
    let mut path = Vec::new();
    loop {
        path.extend_from_slice(&scope.to_be_bytes());
        path.extend_from_slice(&[0, 0]);
        let d = cap.dial_scope(scope, 0).unwrap();
        if let Some((next, _)) = d.next {
            scope = next;
        } else {
            break;
        }
    }
    let mut b = vec![0; 72];
    b[..2].copy_from_slice(&2u16.to_be_bytes());
    for (at, v) in [(8, root), (16, 9), (24, 5), (40, 1_000_000_000)] {
        b[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }
    for (at, v) in [
        (48, n as u16),
        (50, (path.len() / 4) as u16),
        (52, 1),
        (54, 1),
        (58, 13),
    ] {
        b[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    b.extend_from_slice(&base[..n]);
    b.extend_from_slice(b"query.invalid");
    b.extend_from_slice(&path);
    wire::dns_v2::View::<55>::decode(&b).unwrap();
    (issuer, b)
}
fn bundle_run(issuer: &mut Issuer<Fake>, body: &[u8]) -> Vec<Vec<u8>> {
    let io = BundleIo::new(
        issuer.record,
        vec![dns_packet(
            issuer.record,
            3,
            wire::dns_v2::Operation::BundleAcquire,
            body,
        )],
    );
    let ready = AtomicBool::new(false);
    let result = run_issuer(issuer, &io, 8, 997, &AtomicBool::new(false), &ready);
    assert!(result.is_err());
    assert!(
        ready.load(Ordering::Acquire),
        "issuer before ready: {result:?}"
    );
    io.output.into_inner()
}
fn allowed_bundle(output: &[Vec<u8>]) -> bool {
    output.first().is_some_and(|b| b[130] == 1)
}
#[test]
fn dns_bundle_driver_local_system_exact_path_and_cancel_isolation() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, b) = bundle_fixture(mode, true);
        let before = issuer.authority.live.len();
        let out = bundle_run(&mut issuer, &b);
        assert!(allowed_bundle(&out));
        assert_eq!(issuer.dns.count(), 1);
        let id = u64::from_be_bytes(out[0][136..144].try_into().unwrap());
        issuer.cancel_dns_bundle(id).unwrap();
        assert_eq!(issuer.authority.live.len(), before);
        assert_eq!(issuer.dns.count(), 0);
        assert!(issuer.cancel_dns_bundle(id).is_ok());
        let out = bundle_run(&mut issuer, &b);
        assert!(allowed_bundle(&out));
        let neighbor = u64::from_be_bytes(out[0][136..144].try_into().unwrap());
        assert_ne!(id, neighbor);
        issuer.cancel_dns_bundle(id).unwrap();
        assert_eq!(issuer.dns.count(), 1);
        issuer.cancel_dns_bundle(neighbor).unwrap();
    }
}
#[test]
fn dns_bundle_driver_wrong_scope_branch_root_query_and_epoch_before_effects() {
    for change in 0..6 {
        let (mut issuer, mut b) = bundle_fixture(Mode::System, true);
        let before = issuer.authority.route_count;
        let last = b.len() - 4;
        match change {
            0 => b[last..last + 2].copy_from_slice(&0u16.to_be_bytes()),
            1 => b[last + 2] = 1,
            2 => b[8..16].copy_from_slice(&999u64.to_be_bytes()),
            3 => {
                let at = 72 + u16::from_be_bytes([b[48], b[49]]) as usize;
                b[at] = b'x';
            }
            4 => b[72..80].copy_from_slice(&999u64.to_be_bytes()),
            _ => issuer.authority.known = false,
        }
        let out = bundle_run(&mut issuer, &b);
        assert!(!allowed_bundle(&out));
        assert_eq!(issuer.authority.route_count, before);
        assert_eq!(issuer.dns.count(), 0);
    }
}
#[test]
fn dns_bundle_driver_stale_fence_partial_failure_and_unknown_custody() {
    for unknown in [false, true] {
        let (mut issuer, b) = bundle_fixture(Mode::System, true);
        let before = issuer.authority.route_count;
        issuer.authority.fail_route_at = Some(before + 2);
        issuer.authority.unknown_release = unknown;
        let out = bundle_run(&mut issuer, &b);
        assert!(!allowed_bundle(&out));
        assert_eq!(issuer.dns.count(), usize::from(unknown));
        assert_eq!(issuer.unknown, unknown);
        if unknown {
            let attempts = issuer.authority.release_attempts;
            assert!(issuer.cancel_dns_bundle(1).is_err());
            assert_eq!(attempts, issuer.authority.release_attempts);
        }
    }
    let (mut issuer, b) = bundle_fixture(Mode::System, true);
    issuer.authority.route_delay = Duration::from_millis(11);
    assert!(!allowed_bundle(&bundle_run(&mut issuer, &b)));
    assert_eq!(issuer.dns.count(), 0);
}
#[test]
fn dns_bundle_driver_renewal_revision_caps_and_no_resurrection() {
    let (mut issuer, mut b) = bundle_fixture(Mode::Local, false);
    let out = bundle_run(&mut issuer, &b);
    assert!(allowed_bundle(&out));
    let id = u64::from_be_bytes(out[0][136..144].try_into().unwrap());
    b[32..40].copy_from_slice(&id.to_be_bytes());
    b[64..72].copy_from_slice(&1u64.to_be_bytes());
    let out = bundle_run(&mut issuer, &b);
    assert!(allowed_bundle(&out));
    assert_eq!(&out[0][184..192], &2u64.to_be_bytes());
    let before = issuer.authority.route_count;
    assert!(!allowed_bundle(&bundle_run(&mut issuer, &b)));
    assert_eq!(before, issuer.authority.route_count);
    issuer.cancel_dns_bundle(id).unwrap();
    b[64..72].copy_from_slice(&2u64.to_be_bytes());
    assert!(!allowed_bundle(&bundle_run(&mut issuer, &b)));
    let (mut issuer, b) = bundle_fixture(Mode::Local, false);
    let held = issuer.budget.routes.reserve(4095).unwrap();
    let before = issuer.authority.route_count;
    assert!(!allowed_bundle(&bundle_run(&mut issuer, &b)));
    assert_eq!(before, issuer.authority.route_count);
    drop(held);
}
#[test]
fn dns_bundle_driver_descriptor_codecone_or_wrong_launch_never_ready() {
    let (issuer, _) = bundle_fixture(Mode::Local, false);
    let io = BundleIo::new(issuer.record, vec![]);
    assert!(
        dns_bundle::negotiate(
            &issuer,
            &io,
            8,
            997,
            &AtomicBool::new(false),
            issuer.authority.now() + Duration::from_secs(1)
        )
        .is_ok()
    );
    for at in [16, 208, 240, 248] {
        let (mut issuer, b) = bundle_fixture(Mode::Local, false);
        let mut io = BundleIo::new(
            issuer.record,
            vec![dns_packet(
                issuer.record,
                3,
                wire::dns_v2::Operation::BundleAcquire,
                &b,
            )],
        );
        io.descriptor[at] ^= 1;
        let ready = AtomicBool::new(false);
        assert!(run_issuer(&mut issuer, &io, 8, 997, &AtomicBool::new(false), &ready).is_err());
        assert!(!ready.load(Ordering::Acquire));
        assert!(io.output.borrow().is_empty());
    }
}
#[test]
fn dns_bundle_driver_queued_cancel_is_drained_before_allow_and_neighbor_survives() {
    for target in [1, 8] {
        let (mut issuer, b) = bundle_fixture(Mode::System, false);
        let mut cancel = [0; 24];
        cancel[..2].copy_from_slice(&2u16.to_be_bytes());
        cancel[2] = target;
        cancel[8..16].copy_from_slice(&(if target == 1 { 3u64 } else { 1u64 }).to_be_bytes());
        let io = BundleIo::new(
            issuer.record,
            vec![
                dns_packet(issuer.record, 3, wire::dns_v2::Operation::BundleAcquire, &b),
                dns_packet(issuer.record, 4, wire::dns_v2::Operation::Cancel, &cancel),
            ],
        );
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
        let out = io.output.borrow();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][130], 2);
        assert_eq!(out[1][130], 1);
        assert_eq!(&out[0][24..32], &3u64.to_be_bytes());
        assert_eq!(&out[1][24..32], &4u64.to_be_bytes());
        assert_eq!(issuer.dns.count(), 0);
        assert_eq!(issuer.flows.len(), 1);
        assert_eq!(issuer.grants.len(), 1);
        assert_eq!(issuer.authority.live.len(), 1);
    }
}
#[test]
fn dns_bundle_driver_one_stream_initial_renewal_and_history_exhaustion() {
    let (mut issuer, b) = bundle_fixture(Mode::System, false);
    let mut renewal = b.clone();
    renewal[32..40].copy_from_slice(&1u64.to_be_bytes());
    renewal[64..72].copy_from_slice(&1u64.to_be_bytes());
    let mut io = BundleIo::new(
        issuer.record,
        vec![
            dns_packet(issuer.record, 3, wire::dns_v2::Operation::BundleAcquire, &b),
            dns_packet(
                issuer.record,
                4,
                wire::dns_v2::Operation::BundleAcquire,
                &renewal,
            ),
        ],
    );
    io.stop_after = 2;
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
    let out = io.output.borrow();
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|b| b[130] == 1));
    assert_eq!(&out[1][184..192], &2u64.to_be_bytes());
    assert_eq!(issuer.dns.count(), 1);
    let (mut issuer, b) = bundle_fixture(Mode::System, false);
    let before = issuer.authority.route_count;
    let mut io = BundleIo::new(
        issuer.record,
        vec![dns_packet(
            issuer.record,
            3,
            wire::dns_v2::Operation::BundleAcquire,
            &b,
        )],
    );
    io.history = Some(Arc::new(std::sync::Mutex::new(
        InvocationHistory::new(2, &issuer.budget.dynamic).unwrap(),
    )));
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
    assert!(!allowed_bundle(&io.output.borrow()));
    assert_eq!(before, issuer.authority.route_count);
}
#[test]
fn dns_bundle_driver_expired_setup_and_wrong_epoch_fail_without_fallback() {
    let (issuer, _) = bundle_fixture(Mode::System, false);
    let mut io = BundleIo::new(issuer.record, vec![]);
    io.descriptor[208..240].copy_from_slice(&Sha256::digest(b"YONIK-DNS-V2-CODEC-1\0"));
    assert!(
        dns_bundle::negotiate(
            &issuer,
            &io,
            8,
            997,
            &AtomicBool::new(false),
            issuer.authority.now() + Duration::from_secs(1)
        )
        .is_err()
    );
    let io = BundleIo::new(issuer.record, vec![]);
    assert!(
        dns_bundle::negotiate(
            &issuer,
            &io,
            8,
            997,
            &AtomicBool::new(false),
            issuer.authority.now()
        )
        .is_err()
    );
    let (mut issuer, b) = bundle_fixture(Mode::System, false);
    let before = issuer.authority.route_count;
    let mut packet = dns_packet(issuer.record, 3, wire::dns_v2::Operation::BundleAcquire, &b);
    packet[128 + 31] ^= 1;
    let io = BundleIo::new(issuer.record, vec![packet]);
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
    assert!(io.output.borrow().is_empty());
    assert_eq!(before, issuer.authority.route_count);
}
#[test]
fn dns_bundle_driver_blocked_send_cannot_extend_owner_and_renewal_unknown_keeps_credits() {
    let (mut issuer, b) = bundle_fixture(Mode::System, false);
    let io = BundleIo::new(
        issuer.record,
        vec![dns_packet(
            issuer.record,
            3,
            wire::dns_v2::Operation::BundleAcquire,
            &b,
        )],
    );
    *io.delayed_send.borrow_mut() = Some(Arc::clone(&issuer.authority.elapsed));
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
    assert!(!allowed_bundle(&io.output.borrow()));
    assert_eq!(issuer.dns.count(), 0);
    let (mut issuer, mut b) = bundle_fixture(Mode::Local, false);
    assert!(allowed_bundle(&bundle_run(&mut issuer, &b)));
    b[32..40].copy_from_slice(&1u64.to_be_bytes());
    b[64..72].copy_from_slice(&1u64.to_be_bytes());
    issuer.authority.unknown_release = true;
    let out = bundle_run(&mut issuer, &b);
    assert_eq!(out[0][130], 3);
    assert!(issuer.unknown);
    assert_eq!(issuer.dns.count(), 1);
    assert_eq!(issuer.budget.routes.used(), 3);
    let attempts = issuer.authority.release_attempts;
    assert!(issuer.cancel_dns_bundle(1).is_err());
    assert_eq!(attempts, issuer.authority.release_attempts);
    assert_eq!(issuer.budget.routes.used(), 3);
}
#[test]
fn dns_bundle_driver_canceled_queued_acquire_never_creates_route_authority() {
    let (mut issuer, b) = bundle_fixture(Mode::System, false);
    let before = issuer.authority.route_count;
    let mut cancel = [0; 24];
    cancel[..2].copy_from_slice(&2u16.to_be_bytes());
    cancel[2] = 1;
    cancel[8..16].copy_from_slice(&4u64.to_be_bytes());
    let mut io = BundleIo::new(
        issuer.record,
        vec![
            dns_packet(issuer.record, 3, wire::dns_v2::Operation::BundleAcquire, &b),
            dns_packet(issuer.record, 4, wire::dns_v2::Operation::BundleAcquire, &b),
            dns_packet(issuer.record, 5, wire::dns_v2::Operation::Cancel, &cancel),
        ],
    );
    io.stop_after = 3;
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
    let out = io.output.borrow();
    assert_eq!(out.len(), 3);
    assert_eq!(&out[1][24..32], &5u64.to_be_bytes());
    assert_eq!(out[1][130], 1);
    assert_eq!(&out[2][24..32], &4u64.to_be_bytes());
    assert_eq!(
        out[2][130], 2,
        "queued acquire must be denied after KnownClosed cancel"
    );
    assert_eq!(issuer.dns.count(), 1);
    assert_eq!(issuer.authority.route_count, before + 1);
}
#[test]
fn dns_bundle_driver_cancel_one_bundle_does_not_cancel_queued_sibling() {
    let (mut issuer, b) = bundle_fixture(Mode::System, false);
    let mut other = b.clone();
    other[16..24].copy_from_slice(&10u64.to_be_bytes());
    let mut cancel = [0; 24];
    cancel[..2].copy_from_slice(&2u16.to_be_bytes());
    cancel[2] = 8;
    cancel[8..16].copy_from_slice(&1u64.to_be_bytes());
    let mut io = BundleIo::new(
        issuer.record,
        vec![
            dns_packet(issuer.record, 3, wire::dns_v2::Operation::BundleAcquire, &b),
            dns_packet(
                issuer.record,
                4,
                wire::dns_v2::Operation::BundleAcquire,
                &other,
            ),
            dns_packet(issuer.record, 5, wire::dns_v2::Operation::Cancel, &cancel),
        ],
    );
    io.stop_after = 3;
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
    let out = io.output.borrow();
    assert_eq!(out.len(), 3);
    assert_eq!(out[0][130], 2);
    assert_eq!(out[1][130], 1);
    assert_eq!(out[2][130], 1);
    assert_eq!(&out[2][136..144], &2u64.to_be_bytes());
    assert_eq!(issuer.dns.count(), 1);
    assert_eq!(issuer.authority.live.len(), 2);
}

#[test]
fn udp_packet_and_runtime_open_share_immutable_original_name_grammar() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Case {
        name: String,
        allowed: bool,
    }
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/xray-profile-channel-v3/udp-original-destination-v1.json"
    ))
    .unwrap();
    let record = issuer(Mode::System).record;
    for case in cases {
        let name = case.name.as_bytes();
        let mut packet = vec![0, 0, 0, 3, name.len() as u8];
        packet.extend_from_slice(name);
        packet.extend_from_slice(&53u16.to_be_bytes());
        packet.extend_from_slice(b"data");
        let parsed = udp_original(&packet);
        assert_eq!(parsed.is_ok(), case.allowed, "packet name={:?}", case.name);
        let mut local = [0; 16];
        local[..4].copy_from_slice(&[192, 0, 2, 10]);
        let mut remote = [0; 16];
        remote[..4].copy_from_slice(&[127, 0, 0, 1]);
        let message = wire::Message::OpenIngress {
            ingress: 0,
            provenance: 3,
            tuple: Tuple {
                family: 4,
                protocol: 17,
                local_port: 32001,
                remote_port: 49152,
                local,
                remote,
            },
            original: wire::Destination {
                family: 3,
                protocol: 17,
                port: 53,
                bytes: b"valid.invalid",
            },
        };
        let mut bytes = [0; RUNTIME_PACKET];
        let header = wire::Header {
            kind: wire::Kind::OpenIngress,
            sequence: 2,
            reply_to: 0,
            binding: record.binding,
            object_id: 0,
        };
        wire::Frame::encode(header, &message, &mut bytes).unwrap();
        // Canonical encoder отвергает malformed destination: меняем только
        // name bytes/length в otherwise valid frame, чтобы проверить decoder.
        const DESTINATION: usize = 128 + 4 + 40;
        const NAME: usize = DESTINATION + 8;
        let n = NAME + name.len();
        bytes[DESTINATION + 4..DESTINATION + 6].copy_from_slice(&(name.len() as u16).to_be_bytes());
        bytes[NAME..n].copy_from_slice(name);
        bytes[..128].copy_from_slice(&header.encode(n - 128).unwrap());
        let decoded = wire::Frame::decode(&bytes[..n], record.binding, record.mode, false);
        assert_eq!(decoded.is_ok(), case.allowed, "OPEN name={:?}", case.name);
        if let Ok(wire::Frame {
            message: wire::Message::OpenIngress { original, .. },
            ..
        }) = decoded
        {
            assert_eq!(original.bytes, name);
        }
        if let Ok((target, header)) = parsed {
            assert_eq!(target.wire().bytes, name);
            assert_eq!(target.wire().family, 3);
            assert_eq!(target.wire().protocol, 17);
            assert_eq!(target.wire().port, 53);
            assert_eq!(usize::from(header), 7 + name.len());
        }
    }
}

#[test]
fn runtime_receive_reserves_rights_scratch_before_call_and_releases_on_error() {
    let slots = SidebandCredits::new();
    let occupied = slots.fds.reserve(49).unwrap();
    let called = std::cell::Cell::new(false);
    assert!(
        slots
            .receive_runtime(|| {
                called.set(true);
                Ok(Some(1))
            })
            .is_err()
    );
    assert!(
        !called.get(),
        "receive недопустим без всех scratch FD credits"
    );
    assert_eq!(slots.pending.used(), 0);
    drop(occupied);
    let occupied = slots.fds.reserve(48).unwrap();
    let (frame, pending) = slots
        .receive_runtime(|| {
            assert_eq!(slots.fds.used(), 64);
            assert_eq!(slots.pending.used(), 1);
            Ok(Some(7))
        })
        .unwrap();
    assert_eq!(frame, Some(7));
    assert_eq!(slots.fds.used(), 48);
    assert_eq!(slots.pending.used(), 1);
    drop(pending);
    assert!(
        slots
            .receive_runtime(|| {
                assert_eq!(slots.fds.used(), 64);
                Err(ServiceError::InvalidRequest)
            })
            .is_err()
    );
    assert_eq!(slots.pending.used(), 0);
    assert_eq!(slots.fds.used(), 48);
    drop(occupied);
}

#[test]
fn udp_open_waits_for_consumed_before_real_driver_publication() {
    let record = issuer(Mode::System).record;
    let (mut packet, _) = rendezvous_open(record, 2);
    let mut message = open(Mode::Local, 32001);
    let wire::Message::OpenIngress {
        ref mut provenance,
        ref mut tuple,
        ref mut original,
        ..
    } = message
    else {
        unreachable!()
    };
    *provenance = 3;
    tuple.protocol = 17;
    tuple.remote_port = 49152;
    original.protocol = 17;
    packet.length = wire::Frame::encode(
        wire::Header {
            kind: wire::Kind::OpenIngress,
            sequence: 2,
            reply_to: 0,
            binding: record.binding,
            object_id: 0,
        },
        &message,
        &mut packet.bytes,
    )
    .unwrap();
    let mut inbox = Rendezvous::<u8>::new().unwrap();
    let now = Instant::now();
    inbox.runtime(packet, now).unwrap();
    assert!(inbox.next(record, now).unwrap().is_none());
}

fn udp_packet(record: LaunchRecord, sequence: u64, now: Instant) -> (Queued, UdpIngressRecord) {
    let (mut packet, _) = rendezvous_open(record, sequence);
    let mut message = open(Mode::Local, 32001);
    let wire::Message::OpenIngress {
        ref mut provenance,
        ref mut tuple,
        ref mut original,
        ..
    } = message
    else {
        unreachable!()
    };
    *provenance = 3;
    tuple.protocol = 17;
    tuple.remote_port = 49152;
    original.protocol = 17;
    let udp = UdpIngressRecord {
        sequence,
        ingress: 0,
        packet: wire::udp_v2::Packet {
            association: 1,
            packet: 3,
            permit: 4,
            cookie: 102,
            tuple: *tuple,
            bytes: 11,
            header: 10,
            flags: 0,
            fingerprint: [7; 32],
        },
        original: Target::copy(*original).unwrap(),
        expires: now + Duration::from_secs(1),
    };
    packet.length = wire::Frame::encode(
        wire::Header {
            kind: wire::Kind::OpenIngress,
            sequence,
            reply_to: 0,
            binding: record.binding,
            object_id: 0,
        },
        &message,
        &mut packet.bytes,
    )
    .unwrap();
    (packet, udp)
}
#[test]
fn udp_rendezvous_both_orders_cancel_and_shared_credits() {
    let record = issuer(Mode::System).record;
    let now = Instant::now();
    for proof_first in [true, false] {
        let mut inbox = Rendezvous::new().unwrap();
        let (packet, proof) = udp_packet(record, 2, now);
        if proof_first {
            let slot = inbox.slots.pending.reserve(1).unwrap();
            inbox.udp_proof(proof, 42u8, slot, now).unwrap();
        }
        inbox.runtime(packet, now).unwrap();
        if !proof_first {
            assert!(inbox.next(record, now).unwrap().is_none());
            let slot = inbox.slots.pending.reserve(1).unwrap();
            inbox.udp_proof(proof, 42u8, slot, now).unwrap();
        }
        assert_eq!(inbox.next(record, now).unwrap().unwrap().sequence, 2);
        assert_eq!(inbox.take(2, proof.packet.tuple, 0).unwrap(), 42);
        inbox.processed(2);
        assert_eq!(inbox.slots.pending.used(), 0);
        let slot = inbox.slots.pending.reserve(1).unwrap();
        assert!(inbox.udp_proof(proof, 43, slot, now).is_err());
    }
    let mut inbox = Rendezvous::new().unwrap();
    let (packet, proof) = udp_packet(record, 2, now);
    let slot = inbox.slots.pending.reserve(1).unwrap();
    inbox.udp_proof(proof, 42u8, slot, now).unwrap();
    inbox.runtime(packet, now).unwrap();
    inbox.discard_association(1);
    assert_eq!(inbox.next(record, now).unwrap().unwrap().sequence, 2);
    assert!(inbox.take(2, proof.packet.tuple, 0).is_err());
    inbox.processed(2);
    assert_eq!(inbox.slots.pending.used(), 0);
    let slots = SidebandCredits::new();
    let held = slots.pending.reserve(64).unwrap();
    assert!(slots.read_credit(16).is_err());
    assert_eq!(slots.fds.used(), 0);
    drop(held);
    let held = slots.fds.reserve(64).unwrap();
    assert!(slots.read_credit(16).is_err());
    assert_eq!(slots.pending.used(), 0);
    drop(held);
}
struct UdpDriver {
    inbox: Arc<std::sync::Mutex<Rendezvous<u8>>>,
    record: LaunchRecord,
    proof_first: bool,
    delayed: std::cell::RefCell<Option<UdpIngressRecord>>,
    allowed: std::cell::Cell<usize>,
    finished: std::cell::Cell<bool>,
}
impl Channel for UdpDriver {
    fn setup_read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        let d = wire::dns_v2::Negotiated::descriptor(self.record).map_err(unavailable)?;
        out[..272].copy_from_slice(&d);
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
    fn processed(&self, sequence: u64) -> Result<(), ServiceError> {
        self.inbox.lock().map_err(unavailable)?.processed(sequence);
        Ok(())
    }
    fn read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        let mut inbox = self.inbox.lock().map_err(unavailable)?;
        if let Some(packet) = inbox.next(self.record, Instant::now())? {
            out[..packet.length].copy_from_slice(&packet.bytes[..packet.length]);
            return Ok(Some(packet.length));
        }
        if let Some(proof) = self.delayed.borrow_mut().take() {
            let slot = inbox.slots.pending.reserve(1).map_err(unavailable)?;
            inbox.udp_proof(proof, 42, slot, Instant::now())?;
            return Ok(None);
        }
        if self.finished.get() {
            Err(ServiceError::Unavailable)
        } else {
            Ok(None)
        }
    }
    fn discard_ingress(&self, id: u64) -> Result<(), ServiceError> {
        self.inbox.lock().map_err(unavailable)?.discard(id);
        Ok(())
    }
    fn write(&self, bytes: &[u8]) -> Result<bool, ServiceError> {
        let frame = wire::Frame::decode(bytes, self.record.binding, Mode::System, true).unwrap();
        match frame.message {
            wire::Message::Admit(body) => {
                let capsule = wire::Capsule::decode(body, &self.record.binding.digest).unwrap();
                let mut raw = [0; RUNTIME_PACKET];
                let n = wire::Frame::encode(
                    wire::Header {
                        kind: wire::Kind::AdmitAck,
                        sequence: 2,
                        reply_to: frame.header.sequence,
                        binding: self.record.binding,
                        object_id: 0,
                    },
                    &wire::Message::AdmitAck {
                        manifest: capsule.manifest,
                        admission: capsule.admission_id,
                        status: wire::Status::Allow,
                    },
                    &mut raw,
                )
                .unwrap();
                let now = Instant::now();
                let mut inbox = self.inbox.lock().unwrap();
                inbox.runtime(Queued::fixture(&raw[..n], 2), now).unwrap();
                let (packet, proof) = udp_packet(self.record, 3, now);
                if self.proof_first {
                    let slot = inbox.slots.pending.reserve(1).unwrap();
                    inbox.udp_proof(proof, 42, slot, now).unwrap();
                } else {
                    *self.delayed.borrow_mut() = Some(proof);
                }
                inbox.runtime(packet, now).unwrap();
            }
            wire::Message::IngressReply {
                status: wire::Status::Allow,
                ..
            } => {
                self.allowed.set(self.allowed.get() + 1);
                self.finished.set(true);
            }
            wire::Message::Deny { .. } => self.finished.set(true),
            wire::Message::Grant { .. } => panic!("Без AUTHORIZE нельзя выдать GRANT"),
            _ => {}
        }
        Ok(true)
    }
    fn pause(&self) {}
}
#[test]
fn real_issuer_loop_udp_open_consumed_both_orders_publish_one_private_flow() {
    for proof_first in [false, true] {
        let mut issuer = issuer(Mode::System);
        let inbox = Arc::new(std::sync::Mutex::new(Rendezvous::new().unwrap()));
        issuer.authority.udp_inbox = Some(Arc::clone(&inbox));
        let driver = UdpDriver {
            inbox,
            record: issuer.record,
            proof_first,
            delayed: std::cell::RefCell::new(None),
            allowed: std::cell::Cell::new(0),
            finished: std::cell::Cell::new(false),
        };
        assert!(
            run_issuer(
                &mut issuer,
                &driver,
                8,
                997,
                &AtomicBool::new(false),
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert_eq!(driver.allowed.get(), 1);
        assert_eq!(issuer.flows.len(), 1);
        assert!(issuer.grants.is_empty());
    }
}

struct CancelProofIo {
    inbox: std::cell::RefCell<Rendezvous<u8>>,
    packets: std::cell::RefCell<VecDeque<Queued>>,
}
impl Channel for CancelProofIo {
    fn discard_ingress(&self, request: u64) -> Result<(), ServiceError> {
        self.inbox.borrow_mut().discard(request);
        Ok(())
    }
    fn read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
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
    let mut bytes = [0; RUNTIME_PACKET];
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
            Queued::fixture(&bytes[..length], 3),
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
    // Retired main-loop skip завершает delivered credit отдельно от proof.
    inbox.processed(2);
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
    let mut bytes = [0; RUNTIME_PACKET];
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
        Queued::fixture(&bytes[..length], sequence),
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
    let mut bytes = [0; RUNTIME_PACKET];
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
        .runtime(Queued::fixture(&bytes[..length], 3), now)
        .unwrap();
    assert_eq!(inbox.next(record, now).unwrap().unwrap().sequence, 2);
    assert!(inbox.take(2, proof.tuple, proof.ingress).is_err());
    assert_eq!(inbox.next(record, now).unwrap().unwrap().sequence, 3);
    assert!(inbox.proof(proof, 1, now).is_err());
}
#[derive(Clone)]
pub(super) struct Proof {
    source: u64,
    tuple: Tuple,
    subject: Option<Subject>,
    expiry: Instant,
    receipt: wire::Receipt,
}
pub(super) struct Fake {
    pub(super) static_dns_peer: Option<std::net::SocketAddr>,
    pub(super) numeric_delay: Duration,
    pub(super) dns_delay_on: Option<usize>,
    dns_checks: usize,
    udp_inbox: Option<Arc<std::sync::Mutex<Rendezvous<u8>>>>,
    service_trusted: bool,
    mode: Mode,
    now: Instant,
    pub(super) elapsed: Arc<std::sync::atomic::AtomicU64>,
    known: bool,
    revoked: AtomicBool,
    owner_count: u64,
    pub(super) route_count: u64,
    service_routes: Vec<Target>,
    released: Vec<u64>,
    pub(super) live: BTreeSet<u64>,
    route_delay: Duration,
    pub(super) unknown_release: bool,
    release_attempts: usize,
    fail_after_route: bool,
    fail_route_at: Option<u64>,
}
impl Fake {
    fn new(mode: Mode) -> Self {
        Self {
            static_dns_peer: None,
            numeric_delay: Duration::ZERO,
            udp_inbox: None,
            dns_delay_on: None,
            dns_checks: 0,
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
            fail_route_at: None,
        }
    }
}
impl Authority for Fake {
    fn dns_socket(
        &mut self,
        ticket: Option<u64>,
        facts: &dns_transport::Facts,
    ) -> Result<(), ServiceError> {
        self.fence()?;
        self.dns_checks += 1;
        if self.dns_delay_on == Some(self.dns_checks) {
            self.elapsed.fetch_add(25_000_000, Ordering::AcqRel);
        }
        let allowed = if ticket.is_none() {
            self.static_dns_peer.is_some_and(|peer| {
                super::dns_route_socket_matches(
                    peer.ip(),
                    peer.port(),
                    if facts.protocol() == 6 {
                        crate::TransportProtocol::Tcp
                    } else {
                        crate::TransportProtocol::Udp
                    },
                    Some("192.0.2.10".parse().unwrap()),
                    997,
                    42,
                    facts,
                )
            })
        } else {
            ticket.is_some_and(|id| self.live.contains(&id))
        };
        if !allowed
            || facts.local().ip() != "192.0.2.10".parse::<std::net::IpAddr>().unwrap()
            || facts.uid() != 997
            || facts.mark() != 42
            || facts.namespace() != (4, 5)
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
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
        request: u64,
        capsule: &wire::Capsule<'_>,
        message: &wire::Message<'_>,
        _: &Arc<ChannelBudget>,
    ) -> Result<(), ServiceError> {
        if let (
            Some(inbox),
            wire::Message::OpenIngress {
                provenance: 3,
                tuple,
                ingress,
                ..
            },
        ) = (&self.udp_inbox, message)
        {
            capsule
                .validate_udp_control(
                    *ingress,
                    Tuple {
                        protocol: 6,
                        remote_port: 1080,
                        ..*tuple
                    },
                )
                .map_err(unavailable)?;
            if inbox
                .lock()
                .map_err(unavailable)?
                .take(request, *tuple, *ingress)?
                != 42
            {
                return Err(ServiceError::Unavailable);
            }
            return Ok(());
        }
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
        request: RouteRequest<'_>,
        _: &Proof,
        _: u64,
        _: Tuple,
    ) -> Result<Option<u64>, ServiceError> {
        if matches!(request, RouteRequest::Static(_)) && self.static_dns_peer.is_some() {
            return Ok(None);
        }
        if self.fail_route_at == Some(self.route_count + 1) {
            return Err(ServiceError::Busy);
        }
        self.route_count += 1;
        self.live.insert(self.route_count);
        self.now += self.route_delay;
        if matches!(request,RouteRequest::Direct(d) if d.port==443) {
            self.now += self.numeric_delay;
        }
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
pub(super) fn issuer(mode: Mode) -> Issuer<Fake> {
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
pub(super) fn open(mode: Mode, port: u16) -> wire::Message<'static> {
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
pub(super) fn authorize(source: u64) -> wire::Authorize<'static> {
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
        serde_json::json!("remote.invalid");
    fixture["profile"]["graph"]["outbounds"][1]["settings"]["vnext"][0]["address"] =
        serde_json::json!("physical.invalid");
    fixture["profile"]["graph"]["dns"] = serde_json::json!({"servers":["localhost"]});
    let intent = ProfileIntent::decode(&fixture["profile"].to_string()).unwrap();
    let plan = OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap())
        .unwrap()
        .bind_system_resolver(&Snapshot)
        .unwrap();
    let asset = wire::ResolverData {
        source: [8; 32],
        source_flags: 0,
        nss_hash: [1; 32],
        hosts_hash: Sha256::digest([]).into(),
        resolv_hash: [2; 32],
        order: 2,
        ndots: 1,
        attempts: 2,
        timeout_ms: 5000,
        flags: 16,
        hostname: "fixture".into(),
        search: vec![],
        peers: vec!["192.0.2.53:53".parse().unwrap()],
        hosts: vec![],
        _memory: super::super::memory::config_budget().reserve(4096).unwrap(),
    }
    .encode()
    .unwrap();
    let reference = wire::SnapshotRef {
        source: [8; 32],
        asset: Sha256::digest(&asset).into(),
        bytes: asset.len() as u32,
        flags: 0,
    };
    wire::verify_resolver_asset(&asset, reference).unwrap();
    let capsule = Arc::new(
        wire::OwnedCapsule::build(&intent, &plan, Some(reference), [3; 32], 1, 1).unwrap(),
    );
    let decoded = wire::Capsule::decode(capsule.bytes(), &[3; 32]).unwrap();
    let (scope, mask) = decoded.subject_scope(1, 6).unwrap();
    let branch = u8::from(mask & 1 == 0);
    let index = decoded.dial_scope(scope, branch).unwrap().endpoint_index;
    let record = LaunchRecord {
        manifest: decoded.manifest,
        ..issuer(Mode::Local).record
    };
    let mut issuer = Issuer::new(Fake::new(Mode::Local), capsule, record).unwrap();
    issuer.authority.service_trusted = true;
    let request = wire::Message::Probe {
        purpose: 2,
        index,
        subject: 1,
        resolver: 0,
    };
    let grant = issuer.service(2, 0, &request).unwrap();
    assert_eq!(issuer.services[&grant].selector, [2, index, 1, 0]);
    assert!(
        issuer
            .service(
                3,
                grant,
                &wire::Message::Probe {
                    purpose: 2,
                    index,
                    subject: 0,
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
                    subject: 1,
                    resolver: 1
                }
            )
            .is_err()
    );
    assert!(issuer.services.contains_key(&grant));
    assert!(issuer.flows.is_empty());
    assert_eq!(issuer.authority.owner_count, 0);
    drop(issuer);
    fixture["profile"]["graph"]["outbounds"][0]["settings"]["servers"][0]["address"] =
        serde_json::json!("192.0.2.1");
    fixture["profile"]["graph"]["outbounds"][1]["settings"]["vnext"][0]["address"] =
        serde_json::json!("192.0.2.2");
    let intent = ProfileIntent::decode(&fixture["profile"].to_string()).unwrap();
    let capsule = Arc::new(
        wire::OwnedCapsule::build(&intent, &plan, Some(reference), [3; 32], 1, 1).unwrap(),
    );
    let manifest = wire::Capsule::decode(capsule.bytes(), &[3; 32])
        .unwrap()
        .manifest;
    let mut issuer = Issuer::new(
        Fake::new(Mode::Local),
        capsule,
        LaunchRecord { manifest, ..record },
    )
    .unwrap();
    issuer.authority.service_trusted = true;
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
    user_dns: bool,
}
#[derive(Default)]
struct IoState {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    finished: bool,
    dns_private: Option<(u64, u64)>,
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
        let mut bytes = [0; RUNTIME_PACKET];
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
    fn setup_read(
        &self,
        _: u32,
        _: u32,
        out: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
        let d = wire::dns_v2::Negotiated::descriptor(self.record).map_err(unavailable)?;
        out[..272].copy_from_slice(&d);
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
        pid: u32,
        uid: u32,
        out: &mut [u8; RUNTIME_PACKET],
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
                if self.user_dns {
                    self.push(
                        &mut state,
                        3,
                        0,
                        wire::Kind::OpenIngress,
                        open(Mode::System, 32001),
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
            wire::Message::IngressReply {
                status: wire::Status::Allow,
                flow,
                revision,
                required: true,
            } if self.user_dns => {
                state.dns_private = Some((flow, revision));
                self.push(
                    &mut state,
                    4,
                    0,
                    wire::Kind::Authorize,
                    wire::Message::Authorize(wire::Authorize {
                        source_flow: flow,
                        class: 3,
                        subject: u16::MAX,
                        chain: u16::MAX,
                        transport: u16::MAX,
                        scope: u16::MAX,
                        branch: 0,
                        original: original(),
                        effective: wire::Destination {
                            protocol: 17,
                            family: 4,
                            port: 53,
                            bytes: &[192, 0, 2, 53],
                        },
                        resolver: 0,
                        query: "query.invalid",
                        receipt: wire::Receipt {
                            kind: wire::ReceiptKind::None,
                            id: 0,
                        },
                    }),
                );
            }
            wire::Message::Grant {
                class: 3,
                flow,
                revision,
                required: true,
                fresh,
                receipt,
                ..
            } if self.user_dns => {
                assert_eq!(Some((flow, revision)), state.dns_private);
                assert!(fresh > 0 && fresh <= 20_000_000);
                assert_eq!(receipt.kind, wire::ReceiptKind::SidebandOperation);
                assert_ne!(receipt.id, 0);
                self.push(
                    &mut state,
                    5,
                    0,
                    wire::Kind::Cancel,
                    wire::Message::Cancel {
                        target: 2,
                        reason: 1,
                        id: flow,
                    },
                );
            }
            wire::Message::CloseAck { target: 2, .. } if self.user_dns => state.finished = true,
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
        user_dns: false,
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
        user_dns: false,
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
        user_dns: false,
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
#[test]
fn r14_actual_system_user_dns_producer_preserves_private_flow_revision_and_owner_tail() {
    let mut issuer = issuer(Mode::System);
    let io = FakeIo {
        record: issuer.record,
        state: Default::default(),
        wrong_ack: false,
        service: false,
        user_dns: true,
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
    let state = io.state.borrow();
    assert!(state.finished);
    let private = state.dns_private.unwrap();
    let mut grants = 0;
    for bytes in &state.sent {
        let frame = wire::Frame::decode(bytes, issuer.record.binding, Mode::System, true).unwrap();
        if let wire::Message::Grant {
            class: 3,
            flow,
            revision,
            required,
            fresh,
            receipt,
            grant,
            ..
        } = frame.message
        {
            grants += 1;
            assert_eq!((flow, revision), private);
            assert!(required);
            assert!(fresh > 0 && fresh <= 20_000_000);
            assert_eq!((frame.header.reply_to, frame.header.object_id), (4, grant));
            assert_eq!(receipt.kind, wire::ReceiptKind::SidebandOperation);
            assert_ne!(receipt.id, 0);
        }
    }
    assert_eq!(grants, 1);
    assert!(issuer.services.is_empty());
    assert!(issuer.grants.is_empty());
    assert!(issuer.flows.is_empty());
}
struct Backpressure {
    elapsed: Arc<std::sync::atomic::AtomicU64>,
    delay: u64,
    attempts: std::cell::Cell<usize>,
    sent: std::cell::RefCell<Vec<u8>>,
}
impl Channel for Backpressure {
    fn read(
        &self,
        _: u32,
        _: u32,
        _: &mut [u8; RUNTIME_PACKET],
    ) -> Result<Option<usize>, ServiceError> {
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
