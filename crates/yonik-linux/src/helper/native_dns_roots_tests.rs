use super::super::super::{
    Mode,
    issuer_tests::{self, BundleIo, Fake, dns_packet},
    run_issuer,
};
use super::*;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
struct Facts {
    launch: LaunchRecord,
    reference: wire::SnapshotRef,
    asset: Vec<u8>,
    path: Vec<(u16, u8)>,
    endpoint: u16,
    expiry: Instant,
    checked: AtomicUsize,
    observed: AtomicUsize,
    invalid_source: AtomicBool,
    change_after_choice: AtomicBool,
}
impl Source for Facts {
    fn question(
        &self,
        p: Parent<'_>,
        r: wire::SnapshotRef,
        qtype: u16,
        options: u16,
        payload: u16,
    ) -> Result<Question, ServiceError> {
        self.parent(p)?;
        self.snapshot(self.launch, r)?;
        if ![1, 28].contains(&qtype) || options != 0 || payload != 0 {
            return Err(ServiceError::InvalidRequest);
        }
        let mut bytes = [0; 253];
        bytes[..16].copy_from_slice(b"physical.invalid");
        Ok(Question {
            bytes,
            len: 16,
            expires: self.expiry,
        })
    }
    fn parent(&self, p: Parent<'_>) -> Result<Instant, ServiceError> {
        if p.launch != self.launch
            || match p.root {
                wire::dns_v2::Root::HostsPath => p.selector.resolver.is_some(),
                wire::dns_v2::Root::BootstrapService(id) => {
                    id.get() != 1 || p.selector.resolver != Some(1)
                }
                wire::dns_v2::Root::UserDns(_) => true,
            }
            || ![9, 10].contains(&p.query)
            || p.selector.endpoint != self.endpoint
            || p.selector.subject != 1
            || p.path != self.path
            || p.original.bytes != b"physical.invalid"
            || p.original.port != 8443
            || p.original.protocol != 6
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(self.expiry)
    }
    fn snapshot(
        &self,
        launch: LaunchRecord,
        r: wire::SnapshotRef,
    ) -> Result<Instant, ServiceError> {
        if self.invalid_source.load(Ordering::Acquire)
            || launch != self.launch
            || (r.source, r.asset, r.bytes, r.flags)
                != (
                    self.reference.source,
                    self.reference.asset,
                    self.reference.bytes,
                    self.reference.flags,
                )
        {
            return Err(ServiceError::Unavailable);
        }
        wire::verify_resolver_asset(&self.asset, r).map_err(unavailable)?;
        self.checked.fetch_add(1, Ordering::AcqRel);
        Ok(self.expiry)
    }
    fn hosts(&self, p: Parent<'_>, r: wire::SnapshotRef) -> Result<HostsChoice, ServiceError> {
        self.parent(p)?;
        self.snapshot(self.launch, r)?;
        assert!(self.checked.load(Ordering::Acquire) > 0);
        self.observed.fetch_add(1, Ordering::AcqRel);
        if self.change_after_choice.load(Ordering::Acquire) {
            self.invalid_source.store(true, Ordering::Release);
        }
        let mut key = [0; 253];
        key[..17].copy_from_slice(b"physical.invalid.");
        Ok(HostsChoice {
            row: 0,
            members: [0; 256],
            count: 1,
            key,
            key_len: 17,
            expires: self.expiry,
        })
    }
}
fn fixture(mode: Mode) -> (Issuer<Fake>, Arc<Facts>) {
    use yonik_engine::native_profile::{OwnedRuntimePlan, ProfileIntent, VerifiedSystemResolver};
    struct Snapshot;
    impl VerifiedSystemResolver for Snapshot {
        fn snapshot_digest(&self) -> [u8; 32] {
            [8; 32]
        }
        fn servers(&self) -> Vec<SocketAddr> {
            vec!["192.0.2.53:53".parse().unwrap()]
        }
    }
    let graph = serde_json::json!({"outbounds":[{"tag":"a","protocol":"shadowsocks","settings":{"servers":[{"address":"remote.invalid","port":8388,"method":"aes-128-gcm","password":"fixture"}]},"proxySettings":{"tag":"b","transportLayer":true}},{"tag":"b","protocol":"vless","settings":{"vnext":[{"address":"physical.invalid","port":8443,"users":[{"id":"00000000-0000-0000-0000-000000000001","encryption":"none"}]}]}}]});
    let intent =
        ProfileIntent::decode(&serde_json::json!({"version":1,"graph":graph}).to_string()).unwrap();
    let mut plan = OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap())
        .unwrap()
        .bind_system_resolver(&Snapshot)
        .unwrap();
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
    let asset = wire::ResolverData {
        source: [8; 32],
        source_flags: 0,
        nss_hash: [1; 32],
        hosts_hash: [2; 32],
        resolv_hash: [3; 32],
        order: 1,
        ndots: 1,
        attempts: 2,
        timeout_ms: 5000,
        flags: 16,
        hostname: "fixture".into(),
        search: vec![],
        peers: vec!["192.0.2.53:53".parse().unwrap()],
        hosts: vec![wire::ResolverHost {
            alias: "physical.invalid.".into(),
            addresses: vec!["203.0.113.80".parse().unwrap()],
        }],
        _memory: super::super::super::super::memory::config_budget()
            .reserve(4096)
            .unwrap(),
    }
    .encode()
    .unwrap();
    let reference = wire::SnapshotRef {
        source: [8; 32],
        asset: Sha256::digest(&asset).into(),
        bytes: asset.len() as u32,
        flags: 0,
    };
    let capsule = Arc::new(
        wire::OwnedCapsule::build(&intent, &plan, Some(reference), [3; 32], 1, 1).unwrap(),
    );
    let cap = wire::Capsule::decode(capsule.bytes(), &[3; 32]).unwrap();
    let (mut scope, mut mask) = cap.subject_scope(0, 6).unwrap();
    let mut path = vec![];
    let endpoint = loop {
        let branch = u8::from(mask & 1 == 0);
        path.push((scope, branch));
        let d = cap.dial_scope(scope, branch).unwrap();
        if let Some(next) = d.next {
            (scope, mask) = next;
        } else {
            break d.endpoint_index;
        }
    };
    let launch = LaunchRecord {
        manifest: cap.manifest,
        ..issuer_tests::issuer(mode).record
    };
    let mut issuer = Issuer::new(Fake::new(mode), capsule, launch).unwrap();
    issuer.authority.service_trusted = true;
    issuer.authority.owner_forbidden = true;
    let facts = Arc::new(Facts {
        launch,
        reference,
        asset,
        path,
        endpoint,
        expiry: issuer.authority.now() + Duration::from_secs(1),
        checked: AtomicUsize::new(0),
        observed: AtomicUsize::new(0),
        invalid_source: AtomicBool::new(false),
        change_after_choice: AtomicBool::new(false),
    });
    (issuer, facts)
}
fn acquire(f: &Facts, hosts: bool, root: u64, query: u64) -> Vec<u8> {
    let mut b = vec![0; 72];
    b[..2].copy_from_slice(&2u16.to_be_bytes());
    for (at, v) in [
        (8, root),
        (16, query),
        (24, f.launch.binding.epoch),
        (40, 1_000_000_000),
    ] {
        b[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }
    for (at, v) in [
        (48, 8),
        (50, f.path.len() as u16),
        (52, if hosts { 0 } else { 1 }),
        (58, 16),
        (60, if hosts { u16::MAX } else { 1 }),
    ] {
        b[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    for v in [2, f.endpoint, 1, if hosts { u16::MAX } else { 1 }] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    b.extend_from_slice(b"physical.invalid");
    for (scope, branch) in &f.path {
        b.extend_from_slice(&scope.to_be_bytes());
        b.extend_from_slice(&[*branch, 0]);
    }
    b
}
#[test]
fn codec4_roots_driver_bootstrap_and_hosts_are_not_user_authority() {
    for mode in [Mode::Local, Mode::System] {
        for hosts in [false, true] {
            let (mut issuer, f) = fixture(mode);
            let root = if hosts {
                0
            } else {
                issuer
                    .service(
                        50,
                        0,
                        &wire::Message::Probe {
                            purpose: 2,
                            index: f.endpoint,
                            subject: 1,
                            resolver: 1,
                        },
                    )
                    .unwrap()
            };
            let a = acquire(&f, hosts, root, 9);
            let mut io = BundleIo::new(
                issuer.record,
                vec![dns_packet(issuer.record, 3, Operation::BundleAcquire, &a)],
            );
            io.source = Some(f.clone());
            io.stop_after = 1;
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
            assert_eq!(out.len(), 1);
            assert_eq!(out[0][130], 1);
            assert_eq!(u64_at(&out[0], 144), root);
            assert_eq!(issuer.authority.owner_count, 0);
            assert_eq!(issuer.authority.route_count, if hosts { 0 } else { 2 });
        }
    }
}

fn reserve(f: &Facts, hosts: bool, role: u8, query: u64) -> Vec<u8> {
    let mut b = vec![0; 96];
    b[..2].copy_from_slice(&2u16.to_be_bytes());
    b[2] = role;
    for (at, v) in [
        (8, query),
        (16, u64::from(!hosts)),
        (24, u64::from(!hosts)),
        (48, f.launch.binding.epoch),
        (56, 1_000_000_000),
    ] {
        b[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }
    let (scope, branch) = *f.path.last().unwrap();
    for (at, v) in [
        (64, if hosts { u16::MAX } else { 1 }),
        (66, 1),
        (68, f.endpoint),
        (70, scope),
        (72, u16::from(!hosts)),
        (80, 16),
        (82, if hosts { 0 } else { 16 }),
        (84, 8),
    ] {
        b[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    b[74..80].copy_from_slice(&[
        if hosts { 3 } else { 2 },
        if hosts { 2 } else { 1 },
        if role == 2 { 17 } else { 6 },
        3,
        2,
        branch,
    ]);
    if role == 2 {
        b[88..96].copy_from_slice(&1u64.to_be_bytes());
    }
    b.extend_from_slice(b"physical.invalid");
    if !hosts {
        b.extend_from_slice(b"physical.invalid");
    }
    for v in [2, f.endpoint, 1, if hosts { u16::MAX } else { 1 }] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    b
}
fn service(issuer: &mut Issuer<Fake>, f: &Facts) -> u64 {
    issuer
        .service(
            50,
            0,
            &wire::Message::Probe {
                purpose: 2,
                index: f.endpoint,
                subject: 1,
                resolver: 1,
            },
        )
        .unwrap()
}
fn drive(issuer: &mut Issuer<Fake>, io: &BundleIo) {
    assert!(
        run_issuer(
            issuer,
            io,
            8,
            997,
            &AtomicBool::new(false),
            &AtomicBool::new(false)
        )
        .is_err()
    );
}
fn append(io: &BundleIo, packets: Vec<Vec<u8>>) {
    io.after_reply.borrow_mut().push_back(packets);
}
fn cancel(f: &Facts, sequence: u64, id: u64) -> Vec<u8> {
    let mut body = [0; 24];
    body[..2].copy_from_slice(&2u16.to_be_bytes());
    body[2] = 8;
    body[8..16].copy_from_slice(&id.to_be_bytes());
    dns_packet(f.launch, sequence, Operation::Cancel, &body)
}
#[test]
fn codec4_roots_driver_hosts_full_path_observation_after_source_no_network() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, f) = fixture(mode);
        assert!(f.path.len() > 1);
        let mut io = BundleIo::new(
            f.launch,
            vec![dns_packet(
                f.launch,
                3,
                Operation::BundleAcquire,
                &acquire(&f, true, 0, 9),
            )],
        );
        io.source = Some(f.clone());
        io.stop_after = 2;
        append(
            &io,
            vec![dns_packet(
                f.launch,
                4,
                Operation::Reserve,
                &reserve(&f, true, 3, 9),
            )],
        );
        drive(&mut issuer, &io);
        let output = io.output.borrow();
        assert_eq!(output.len(), 2);
        assert_eq!((output[0][130], output[1][130]), (1, 1));
        assert_eq!(u64_at(&output[1], 152), 0);
        assert_eq!(u64_at(&output[1], 160), 1);
        let observation = &issuer.dns.observations[&1];
        assert!(observation.acked && observation.pending.is_none());
        assert_eq!(observation._parent.len(), f.path.len());
        assert_eq!(
            (observation.choice.row, observation.choice.members[0]),
            (0, 0)
        );
        assert!(observation.expires <= f.expiry);
        assert_eq!(f.observed.load(Ordering::Acquire), 1);
        assert_eq!(
            (issuer.authority.owner_count, issuer.authority.route_count),
            (0, 0)
        );
        assert_eq!(io.dns_slots().unwrap().pending.used(), 0);
    }
}
#[test]
fn codec4_roots_driver_actual_service_probe_then_network_roles_keep_dual_carrier() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, f) = fixture(mode);
        let mut packet = [0; 256];
        let n = wire::Frame::encode(
            wire::Header {
                kind: wire::Kind::Probe,
                sequence: 3,
                reply_to: 0,
                binding: f.launch.binding,
                object_id: 0,
            },
            &wire::Message::Probe {
                purpose: 2,
                index: f.endpoint,
                subject: 1,
                resolver: 1,
            },
            &mut packet,
        )
        .unwrap();
        let mut io = BundleIo::new(f.launch, vec![packet[..n].to_vec()]);
        io.source = Some(f.clone());
        io.stop_after = 5;
        append(
            &io,
            vec![dns_packet(
                f.launch,
                4,
                Operation::BundleAcquire,
                &acquire(&f, false, 1, 9),
            )],
        );
        append(
            &io,
            vec![dns_packet(
                f.launch,
                5,
                Operation::Reserve,
                &reserve(&f, false, 1, 9),
            )],
        );
        append(
            &io,
            vec![dns_packet(
                f.launch,
                6,
                Operation::Reserve,
                &reserve(&f, false, 2, 9),
            )],
        );
        append(
            &io,
            vec![dns_packet(
                f.launch,
                7,
                Operation::Reserve,
                &reserve(&f, false, 3, 9),
            )],
        );
        drive(&mut issuer, &io);
        let output = io.output.borrow();
        assert_eq!(output.len(), 5);
        for b in &output[1..] {
            assert_eq!(b[130], 1, "reply to {}", u64_at(b, 24));
        }
        let binding = issuer.dns_transport_binding(1).unwrap();
        assert_eq!(
            (binding.parent_carrier, binding.physical_peer.protocol),
            (6, 17)
        );
        assert_eq!(binding.physical_peer.wire().bytes, [192, 0, 2, 53]);
        assert!(!binding.proxied && binding.bootstrap);
        assert_eq!(issuer.authority.owner_count, 0);
        assert_eq!(issuer.authority.route_count, 2);
        assert_eq!(issuer.dns.live[&1].hops.len(), f.path.len());
        assert!(issuer.dns.live[&1].hops.iter().all(|h| h.ticket.is_none()));
    }
}
#[test]
fn codec4_roots_driver_missing_source_wrong_full_path_epoch_and_selector_deny() {
    for fault in 0..7 {
        let (mut issuer, f) = fixture(Mode::System);
        let mut a = acquire(&f, true, 0, 9);
        match fault {
            0 => {}
            1 => {}
            2 => a[75] ^= 1,
            3 => {
                let end = a.len();
                a[end - 2] ^= 1;
            }
            4 => a[80] = b'x',
            5 => {
                let path = 72 + 8 + 16;
                a.drain(path..path + 4);
                let count = (f.path.len() - 1) as u16;
                a[50..52].copy_from_slice(&count.to_be_bytes());
            }
            6 => f.invalid_source.store(true, Ordering::Release),
            _ => unreachable!(),
        }
        let mut packet = dns_packet(f.launch, 3, Operation::BundleAcquire, &a);
        if fault == 1 {
            packet[128 + 31] ^= 1;
        }
        let mut io = BundleIo::new(f.launch, vec![packet]);
        if fault != 0 {
            io.source = Some(f.clone());
        }
        drive(&mut issuer, &io);
        if fault == 1 {
            assert!(io.output.borrow().is_empty());
        } else {
            assert_eq!(io.output.borrow()[0][130], 2, "fault {fault}");
        }
        assert_eq!(issuer.authority.route_count, 0);
        assert!(issuer.dns.live.is_empty());
        assert_eq!(f.observed.load(Ordering::Acquire), 0);
    }
}
#[test]
fn codec4_roots_driver_unacked_context_and_changed_source_never_observation() {
    for fault in 0..4 {
        let (mut issuer, f) = fixture(Mode::System);
        let a = dns_packet(
            f.launch,
            3,
            Operation::BundleAcquire,
            &acquire(&f, true, 0, 9),
        );
        let mut r = reserve(&f, true, 3, 9);
        if fault == 2 {
            r[76] = 17;
        }
        if fault == 3 {
            r[71] ^= 1;
        }
        let r = dns_packet(f.launch, 4, Operation::Reserve, &r);
        let mut io = BundleIo::new(
            f.launch,
            if fault == 0 {
                vec![a, r.clone()]
            } else {
                vec![a]
            },
        );
        io.source = Some(f.clone());
        io.stop_after = 2;
        if fault != 0 {
            append(&io, vec![r]);
        }
        if fault == 1 {
            f.change_after_choice.store(true, Ordering::Release);
        }
        drive(&mut issuer, &io);
        assert_eq!(io.output.borrow().len(), 2);
        assert_eq!(io.output.borrow()[1][130], 2, "fault {fault}");
        assert!(issuer.dns.observations.is_empty());
        assert_eq!(issuer.authority.route_count, 0);
        assert_eq!(f.observed.load(Ordering::Acquire), usize::from(fault == 1));
        if fault == 1 {
            f.invalid_source.store(false, Ordering::Release);
            assert!(issuer.bootstrap_live(1, true).is_err());
        }
    }
}
#[test]
fn codec4_roots_driver_context_cancel_is_typed_nonreusing_and_neighbor_survives() {
    let (mut issuer, f) = fixture(Mode::System);
    service(&mut issuer, &f);
    let mut io = BundleIo::new(
        f.launch,
        vec![dns_packet(
            f.launch,
            3,
            Operation::BundleAcquire,
            &acquire(&f, false, 1, 9),
        )],
    );
    io.source = Some(f.clone());
    io.stop_after = 5;
    append(
        &io,
        vec![dns_packet(
            f.launch,
            4,
            Operation::BundleAcquire,
            &acquire(&f, true, 0, 10),
        )],
    );
    append(&io, vec![cancel(&f, 5, 1)]);
    append(
        &io,
        vec![dns_packet(
            f.launch,
            6,
            Operation::Reserve,
            &reserve(&f, true, 3, 10),
        )],
    );
    append(
        &io,
        vec![dns_packet(
            f.launch,
            7,
            Operation::BundleAcquire,
            &acquire(&f, true, 0, 9),
        )],
    );
    drive(&mut issuer, &io);
    let output = io.output.borrow();
    assert_eq!(output.len(), 5);
    assert_eq!(u64_at(&output[0], 136), 1);
    assert_eq!(u64_at(&output[1], 136), 2);
    assert_eq!(output[3][130], 1);
    assert_eq!(output[4][130], 2);
    assert!(!issuer.dns.live.contains_key(&1));
    assert_eq!(issuer.dns.live[&2].root_kind, wire::dns_v2::Root::HostsPath);
    assert!(issuer.dns.observations[&1].acked);
    assert!(!issuer.unknown);
}
#[test]
fn codec4_roots_driver_renew_exact_revision_does_not_extend_deadline() {
    for wrong in [false, true] {
        let (mut issuer, f) = fixture(Mode::System);
        let mut renewal = acquire(&f, true, 0, 9);
        renewal[32..40].copy_from_slice(&1u64.to_be_bytes());
        renewal[64..72].copy_from_slice(&(if wrong { 2u64 } else { 1 }).to_be_bytes());
        let mut io = BundleIo::new(
            f.launch,
            vec![dns_packet(
                f.launch,
                3,
                Operation::BundleAcquire,
                &acquire(&f, true, 0, 9),
            )],
        );
        io.source = Some(f.clone());
        io.stop_after = 3;
        append(
            &io,
            vec![dns_packet(f.launch, 4, Operation::BundleAcquire, &renewal)],
        );
        append(
            &io,
            vec![dns_packet(
                f.launch,
                5,
                Operation::Reserve,
                &reserve(&f, true, 3, 9),
            )],
        );
        drive(&mut issuer, &io);
        let output = io.output.borrow();
        assert_eq!(output.len(), 3);
        assert_eq!(output[1][130], if wrong { 2 } else { 1 });
        assert_eq!(output[2][130], 1);
        assert_eq!(issuer.dns.live[&1].revision, if wrong { 1 } else { 2 });
        assert!(issuer.dns.live[&1].expires <= f.expiry);
        assert!(issuer.dns.observations[&1].expires <= f.expiry);
    }
}
#[test]
fn codec4_roots_driver_credits_precede_source_and_expiry_after_route_rolls_back() {
    for fault in 0..3 {
        let (mut issuer, f) = fixture(Mode::System);
        let root = if fault == 2 {
            service(&mut issuer, &f)
        } else {
            0
        };
        match fault {
            0 => {
                Arc::get_mut(&mut issuer.budget).unwrap().dynamic =
                    super::super::super::super::memory::ByteBudget::new(1)
            }
            1 => issuer.dns.history = 256,
            2 => issuer.authority.route_delay = Duration::from_secs(1),
            _ => unreachable!(),
        }
        let mut io = BundleIo::new(
            f.launch,
            vec![dns_packet(
                f.launch,
                3,
                Operation::BundleAcquire,
                &acquire(&f, fault != 2, root, 9),
            )],
        );
        io.source = Some(f.clone());
        drive(&mut issuer, &io);
        if fault == 2 {
            // Backend не начинает новый lease: поздний Allow запрещён.
            assert!(io.output.borrow().iter().all(|b| b[130] != 1));
            assert!(issuer.authority.live.is_empty());
            assert_eq!(issuer.authority.release_attempts, 2);
        } else {
            assert_eq!(io.output.borrow()[0][130], 2);
            assert_eq!(f.checked.load(Ordering::Acquire), 0);
        }
        assert!(issuer.dns.live.is_empty());
        assert_eq!(f.observed.load(Ordering::Acquire), 0);
    }
}
#[test]
fn codec4_roots_driver_unknown_cleanup_retains_permit_and_never_retries_close() {
    let (mut issuer, f) = fixture(Mode::System);
    service(&mut issuer, &f);
    issuer.authority.unknown_release = true;
    let mut io = BundleIo::new(
        f.launch,
        vec![dns_packet(
            f.launch,
            3,
            Operation::BundleAcquire,
            &acquire(&f, false, 1, 9),
        )],
    );
    io.source = Some(f.clone());
    io.stop_after = 2;
    append(&io, vec![cancel(&f, 4, 1)]);
    drive(&mut issuer, &io);
    assert_eq!(io.output.borrow()[1][130], 3);
    assert!(issuer.unknown);
    assert_eq!(issuer.authority.live.len(), 2);
    assert!(
        issuer.dns.live[&1]
            .bootstrap
            .as_ref()
            .unwrap()
            .permit
            .as_ref()
            .unwrap()
            .ticket
            .is_some()
    );
    assert_eq!(issuer.authority.release_attempts, 1);
    assert!(issuer.cancel_dns_bundle(1).is_err());
    assert_eq!(issuer.authority.release_attempts, 1);
}

#[test]
fn codec4_roots_driver_equal_raw_user_service_id_never_aliases_or_calls_owner() {
    let (mut issuer, f) = fixture(Mode::System);
    assert_eq!(service(&mut issuer, &f), 1);
    let (_, mut user) = issuer_tests::bundle_fixture(Mode::System, false);
    assert_eq!(u64_at(&user, 8), 1);
    user[24..32].copy_from_slice(&f.launch.binding.epoch.to_be_bytes());
    let mut io = BundleIo::new(
        f.launch,
        vec![dns_packet(
            f.launch,
            3,
            Operation::BundleAcquire,
            &acquire(&f, false, 1, 9),
        )],
    );
    io.source = Some(f.clone());
    io.stop_after = 3;
    append(
        &io,
        vec![dns_packet(f.launch, 4, Operation::BundleAcquire, &user)],
    );
    append(
        &io,
        vec![dns_packet(
            f.launch,
            5,
            Operation::BundleAcquire,
            &acquire(&f, true, 0, 10),
        )],
    );
    drive(&mut issuer, &io);
    let output = io.output.borrow();
    assert_eq!((output[0][130], output[1][130], output[2][130]), (1, 2, 1));
    assert_eq!(issuer.authority.owner_count, 0);
    assert_eq!(issuer.dns.live.len(), 2);
    assert!(matches!(
        issuer.dns.live[&1].root_kind,
        wire::dns_v2::Root::BootstrapService(_)
    ));
    assert_eq!(issuer.dns.live[&2].root_kind, wire::dns_v2::Root::HostsPath);
}

#[test]
fn codec4_roots_driver_blocked_context_ack_never_refreshes_expired_source() {
    let (mut issuer, mut f) = fixture(Mode::System);
    Arc::get_mut(&mut f).unwrap().expiry = issuer.authority.now() + Duration::from_millis(5);
    let mut io = BundleIo::new(
        f.launch,
        vec![dns_packet(
            f.launch,
            3,
            Operation::BundleAcquire,
            &acquire(&f, true, 0, 9),
        )],
    );
    io.source = Some(f.clone());
    *io.delayed_send.borrow_mut() = Some(issuer.authority.elapsed.clone());
    drive(&mut issuer, &io);
    assert_eq!(io.output.borrow().len(), 1);
    assert_eq!(io.output.borrow()[0][130], 2);
    assert!(issuer.dns.live.is_empty());
    assert!(issuer.dns.observations.is_empty());
    assert_eq!(f.observed.load(Ordering::Acquire), 0);
    assert_eq!(issuer.authority.owner_count, 0);
}
