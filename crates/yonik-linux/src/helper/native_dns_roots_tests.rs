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
    addresses: Vec<std::net::IpAddr>,
    member_calls: AtomicUsize,
    path: Vec<(u16, u8)>,
    endpoint: u16,
    expiry: Instant,
    checked: AtomicUsize,
    observed: AtomicUsize,
    invalid_source: AtomicBool,
    change_after_choice: AtomicBool,
    failed_operation: AtomicUsize,
}
impl Source for Facts {
    fn member(
        &self,
        p: Parent<'_>,
        r: wire::SnapshotRef,
        row: u16,
        index: u16,
    ) -> Result<Member, ServiceError> {
        self.member_calls.fetch_add(1, Ordering::AcqRel);
        if self.failed_operation.load(Ordering::Acquire) == 4 {
            return Err(ServiceError::Unavailable);
        }
        self.parent(p)?;
        self.snapshot(self.launch, r)?;
        if row != 0 {
            return Err(ServiceError::InvalidRequest);
        }
        let address = *self
            .addresses
            .get(usize::from(index))
            .ok_or(ServiceError::InvalidRequest)?;
        Ok(Member {
            address,
            expires: self.expiry,
        })
    }
    fn question(
        &self,
        p: Parent<'_>,
        r: wire::SnapshotRef,
        qtype: u16,
        options: u16,
        payload: u16,
    ) -> Result<Question, ServiceError> {
        if self.failed_operation.load(Ordering::Acquire) == 3 {
            return Err(ServiceError::Unavailable);
        }
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
        if self.failed_operation.load(Ordering::Acquire) == 1
            || p.launch != self.launch
            || match p.root {
                wire::dns_v2::Root::HostsPath => p.selector.resolver.is_some(),
                wire::dns_v2::Root::BootstrapService(id) => {
                    !(1..=3).contains(&id.get()) || p.selector.resolver != Some(1)
                }
                wire::dns_v2::Root::UserDns(_) => true,
            }
            || !(9..=12).contains(&p.query)
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
        if self.failed_operation.load(Ordering::Acquire) == 2
            || self.invalid_source.load(Ordering::Acquire)
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
    fixture_address(mode, "203.0.113.80".parse().unwrap())
}
fn fixture_address(mode: Mode, address: std::net::IpAddr) -> (Issuer<Fake>, Arc<Facts>) {
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
            addresses: vec![address],
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
        addresses: vec![address],
        member_calls: AtomicUsize::new(0),
        path,
        endpoint,
        expiry: issuer.authority.now() + Duration::from_secs(1),
        checked: AtomicUsize::new(0),
        observed: AtomicUsize::new(0),
        invalid_source: AtomicBool::new(false),
        change_after_choice: AtomicBool::new(false),
        failed_operation: AtomicUsize::new(0),
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
        io.bootstrap_producer = Some(Arc::new(
            super::super::super::VerifiedBootstrapDnsProducer {
                launch: f.launch,
                schema: Sha256::digest(wire::dns_v2::SCHEMA).into(),
            },
        ));
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
fn codec4_roots_renewal_source_failure_is_sticky_after_recovery() {
    for hosts in [true, false] {
        for fault in 1..=if hosts { 2 } else { 3 } {
            let (mut issuer, f) = fixture(Mode::System);
            let root = if hosts { 0 } else { service(&mut issuer, &f) };
            let mut io = BundleIo::new(
                f.launch,
                vec![dns_packet(
                    f.launch,
                    3,
                    Operation::BundleAcquire,
                    &acquire(&f, hosts, root, 9),
                )],
            );
            io.source = Some(f.clone());
            drive(&mut issuer, &io);
            assert_eq!(io.output.borrow()[0][130], 1);
            let mut renewal = acquire(&f, hosts, root, 9);
            renewal[32..40].copy_from_slice(&1u64.to_be_bytes());
            renewal[64..72].copy_from_slice(&1u64.to_be_bytes());
            let Record::BundleAcquire(view) =
                Record::decode(Operation::BundleAcquire, &renewal).unwrap()
            else {
                panic!("renewal")
            };
            f.failed_operation.store(fault, Ordering::Release);
            let mut foreign = renewal.clone();
            foreign[16..24].copy_from_slice(&10u64.to_be_bytes());
            let Record::BundleAcquire(foreign) =
                Record::decode(Operation::BundleAcquire, &foreign).unwrap()
            else {
                panic!("foreign renewal")
            };
            assert!(issuer.acquire_bootstrap(4, foreign, f.expiry).is_err());
            assert!(
                !issuer.dns.live[&1]
                    .bootstrap
                    .as_ref()
                    .unwrap()
                    .invalid
                    .load(Ordering::Acquire)
            );
            assert!(issuer.acquire_bootstrap(4, view, f.expiry).is_err());
            f.failed_operation.store(0, Ordering::Release);
            assert!(
                issuer.bootstrap_live(1, true).is_err(),
                "Source recovery не оживляет context"
            );
            assert!(issuer.dns.live.contains_key(&1), "Custody сохраняется");
            if hosts {
                let body = reserve(&f, true, 3, 9);
                let Record::Reserve(view) = Record::decode(Operation::Reserve, &body).unwrap()
                else {
                    panic!("reserve")
                };
                assert!(issuer.reserve_hosts(view, 5, &io, f.expiry).is_err());
                assert!(issuer.dns.observations.is_empty());
            }
        }
    }
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

// Независимый field packer: не вызывает Rust Hosts encoder для body.
fn hosts_publish(f: &Facts, observation: u64, query: u64) -> Vec<u8> {
    let key = b"physical.invalid.";
    let original = b"physical.invalid";
    let mut b = vec![0; 144 + 128];
    b[..2].copy_from_slice(&2u16.to_be_bytes());
    for (at, v) in [
        (4, u16::MAX),
        (6, 1),
        (8, f.endpoint),
        (140, f.path.last().unwrap().0),
    ] {
        b[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    for (at, v) in [(12, query), (36, f.launch.binding.epoch)] {
        b[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }
    b[44..76].copy_from_slice(&f.reference.source);
    b[76..108].copy_from_slice(&f.reference.asset);
    b[136] = 3;
    b[137] = 2;
    b[142] = 6;
    let t = &mut b[144..];
    t[..8].copy_from_slice(b"DNHOST02");
    t[8..10].copy_from_slice(&2u16.to_be_bytes());
    let len = (128 + key.len() + original.len() + 2) as u16;
    t[10..12].copy_from_slice(&len.to_be_bytes());
    t[16..48].copy_from_slice(&f.reference.source);
    t[48..80].copy_from_slice(&f.reference.asset);
    for (at, v) in [
        (80, f.launch.binding.epoch),
        (88, observation),
        (96, 1_000_000_000),
    ] {
        t[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }
    for (at, v) in [
        (108, 1),
        (110, key.len() as u16),
        (112, original.len() as u16),
        (114, 1),
        (116, f.endpoint),
        (118, f.path.last().unwrap().0),
        (122, 8443),
    ] {
        t[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    t[120] = f.path.last().unwrap().1;
    t[121] = 6;
    b.extend_from_slice(key);
    b.extend_from_slice(original);
    b.extend_from_slice(&0u16.to_be_bytes());
    b
}
fn hosts_bind(reservation: u64, producer: u64, query: u64) -> Vec<u8> {
    let mut b = vec![0; 64];
    b[..2].copy_from_slice(&2u16.to_be_bytes());
    for (at, v) in [
        (8, reservation),
        (16, producer),
        (32, query),
        (56, 1_000_000_000),
    ] {
        b[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }
    b
}
fn hosts_script(f: &Facts) -> Vec<(Operation, Vec<u8>)> {
    vec![
        (Operation::BundleAcquire, acquire(f, true, 0, 9)),
        (Operation::Reserve, reserve(f, true, 3, 9)),
        (Operation::Publish, hosts_publish(f, 1, 9)),
        (Operation::BundleAcquire, acquire(f, true, 0, 10)),
        (Operation::Reserve, reserve(f, true, 3, 10)),
        (Operation::WaiterBind, hosts_bind(2, 1, 10)),
    ]
}
fn scripted(
    issuer: &mut Issuer<Fake>,
    f: &Arc<Facts>,
    script: &[(Operation, Vec<u8>)],
) -> Vec<Vec<u8>> {
    let packets: Vec<_> = script
        .iter()
        .enumerate()
        .map(|(i, (kind, b))| dns_packet(f.launch, 3 + i as u64, *kind, b))
        .collect();
    let mut io = BundleIo::new(f.launch, vec![packets[0].clone()]);
    io.source = Some(f.clone());
    io.stop_after = script.len();
    for p in &packets[1..] {
        append(&io, vec![p.clone()]);
    }
    drive(issuer, &io);
    io.output.into_inner()
}
fn cancel_body(target: u8, id: u64) -> Vec<u8> {
    let mut b = vec![0; 24];
    b[..2].copy_from_slice(&2u16.to_be_bytes());
    b[2] = target;
    b[8..16].copy_from_slice(&id.to_be_bytes());
    b
}
#[test]
fn codec4_hosts_driver_publish_then_independent_waiter_are_not_numeric_authority() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, f) = fixture(mode);
        let output = scripted(&mut issuer, &f, &hosts_script(&f));
        assert_eq!(output.len(), 6);
        for b in &output {
            assert_eq!(b[130], 1, "reply {}", u64_at(b, 24));
        }
        assert_eq!(output[2].len(), 176);
        assert_eq!(u64_at(&output[2], 144), 0);
        assert_eq!(u64_at(&output[5], 136), 1);
        assert_eq!(u64_at(&output[5], 152), 2);
        assert_eq!(&output[5][186..188], &[2, 3]);
        assert_eq!(
            (issuer.authority.owner_count, issuer.authority.route_count),
            (0, 0)
        );
        assert!(issuer.hosts_waiter_live(1, true).is_ok());
        assert!(issuer.grants.is_empty() && issuer.services.is_empty());
    }
}

#[test]
fn codec4_hosts_driver_two_waiters_cancel_one_preserves_neighbor_and_data() {
    let (mut issuer, f) = fixture(Mode::System);
    let mut script = hosts_script(&f);
    script.extend([
        (Operation::BundleAcquire, acquire(&f, true, 0, 11)),
        (Operation::Reserve, reserve(&f, true, 3, 11)),
        (Operation::WaiterBind, hosts_bind(3, 1, 11)),
        (Operation::Cancel, cancel_body(6, 1)),
    ]);
    let output = scripted(&mut issuer, &f, &script);
    assert_eq!(output.len(), 10);
    for b in &output {
        assert_eq!(b[130], 1);
    }
    assert!(issuer.hosts_waiter_live(1, true).is_err());
    assert!(issuer.hosts_waiter_live(2, true).is_ok());
    assert!(issuer.hosts_producer_live(1, true).is_ok());
    assert_eq!(
        (issuer.authority.owner_count, issuer.authority.route_count),
        (0, 0)
    );
}
#[test]
fn codec4_hosts_driver_observation_publish_and_waiter_are_single_consumers() {
    for fault in 0..3 {
        let (mut issuer, f) = fixture(Mode::System);
        let mut script = hosts_script(&f);
        match fault {
            0 => {
                script.truncate(3);
                script.push((Operation::Publish, hosts_publish(&f, 1, 9)));
            }
            1 => {
                script.truncate(3);
                script.push((Operation::WaiterBind, hosts_bind(1, 1, 9)));
            }
            2 => script.push((Operation::WaiterBind, hosts_bind(2, 1, 10))),
            _ => unreachable!(),
        }
        let output = scripted(&mut issuer, &f, &script);
        assert_eq!(output.len(), script.len());
        assert_eq!(output.last().unwrap()[130], 2);
        assert!(issuer.hosts_producer_live(1, true).is_ok());
        assert_eq!(issuer.authority.route_count, 0);
    }
}
#[test]
fn codec4_hosts_driver_foreign_publish_fields_cannot_poison_source_context() {
    for fault in 0..6 {
        let (mut issuer, f) = fixture(Mode::System);
        let mut p = hosts_publish(&f, 1, 9);
        match fault {
            0 => p[19] = 10,
            1 => p[144 + 107] = 1,
            2 => {
                let end = p.len();
                p[end - 1] = 1;
            }
            3 => {
                p[144 + 128] = b'x';
                p[144 + 128 + 17] = b'x';
            }
            4 => p[144 + 123] ^= 1,
            5 => {
                p[44] ^= 1;
                p[144 + 16] ^= 1;
            }
            _ => unreachable!(),
        }
        let mut script = hosts_script(&f);
        script.truncate(3);
        script[2].1 = p;
        let packets: Vec<_> = script
            .iter()
            .enumerate()
            .map(|(i, (kind, b))| dns_packet(f.launch, i as u64 + 3, *kind, b))
            .collect();
        let mut io = BundleIo::new(f.launch, vec![packets[0].clone()]);
        io.source = Some(f.clone());
        io.stop_after = 3;
        for p in &packets[1..] {
            append(&io, vec![p.clone()]);
        }
        let source = f.clone();
        io.on_request = Some(Box::new(move |n| {
            if n == 5 {
                source.failed_operation.store(2, Ordering::Release);
            }
        }));
        drive(&mut issuer, &io);
        assert_eq!(io.output.borrow().len(), 3);
        assert_eq!(io.output.borrow()[2][130], 2, "fault {fault}");
        f.failed_operation.store(0, Ordering::Release);
        assert!(issuer.bootstrap_live(1, true).is_ok(), "fault {fault}");
        assert!(issuer.dns.hosts_producers.is_empty());
    }
}
#[test]
fn codec4_hosts_driver_source_change_at_publish_or_waiter_is_sticky() {
    for fault in 0..2 {
        let (mut issuer, f) = fixture(Mode::System);
        let mut script = hosts_script(&f);
        if fault == 0 {
            script.truncate(3);
        }
        let packets: Vec<_> = script
            .iter()
            .enumerate()
            .map(|(i, (kind, b))| dns_packet(f.launch, i as u64 + 3, *kind, b))
            .collect();
        let mut io = BundleIo::new(f.launch, vec![packets[0].clone()]);
        io.source = Some(f.clone());
        io.stop_after = script.len();
        for p in &packets[1..] {
            append(&io, vec![p.clone()]);
        }
        let source = f.clone();
        io.on_request = Some(Box::new(move |n| {
            if n == if fault == 0 { 5 } else { 8 } {
                source.failed_operation.store(2, Ordering::Release);
            }
        }));
        drive(&mut issuer, &io);
        assert_eq!(io.output.borrow().len(), script.len());
        assert_eq!(io.output.borrow().last().unwrap()[130], 2);
        f.failed_operation.store(0, Ordering::Release);
        assert!(
            issuer
                .bootstrap_live(if fault == 0 { 1 } else { 2 }, true)
                .is_err()
        );
        assert!(issuer.dns.hosts_waiters.is_empty());
    }
}
#[test]
fn codec4_hosts_driver_publish_received_before_observation_ack_is_denied() {
    let (mut issuer, f) = fixture(Mode::System);
    let script = hosts_script(&f);
    let mut io = BundleIo::new(
        f.launch,
        vec![dns_packet(f.launch, 3, script[0].0, &script[0].1)],
    );
    io.source = Some(f.clone());
    io.stop_after = 3;
    append(
        &io,
        vec![
            dns_packet(f.launch, 4, script[1].0, &script[1].1),
            dns_packet(f.launch, 5, script[2].0, &script[2].1),
        ],
    );
    drive(&mut issuer, &io);
    let output = io.output.borrow();
    assert_eq!(output.len(), 3);
    assert_eq!(output[1][130], 1);
    assert_eq!(output[2][130], 2);
    assert!(issuer.dns.hosts_producers.is_empty());
}

#[test]
fn codec4_hosts_driver_lost_reply_retains_metadata_and_pending_without_authority() {
    for fault in [3, 6] {
        let (mut issuer, f) = fixture(Mode::System);
        let script = hosts_script(&f);
        let packets: Vec<_> = script
            .iter()
            .enumerate()
            .map(|(i, (kind, b))| dns_packet(f.launch, i as u64 + 3, *kind, b))
            .collect();
        let mut io = BundleIo::new(f.launch, vec![packets[0].clone()]);
        io.source = Some(f.clone());
        io.stop_after = script.len();
        io.fail_write_at = Some(fault);
        for p in &packets[1..] {
            append(&io, vec![p.clone()]);
        }
        drive(&mut issuer, &io);
        assert!(issuer.unknown);
        assert_eq!(io.output.borrow().len(), fault - 1);
        assert_eq!(io.dns_slots().unwrap().pending.used(), 1);
        assert_eq!(issuer.dns.hosts_producers.len(), 1);
        if fault == 3 {
            assert!(!issuer.dns.hosts_producers[&1].acked);
        } else {
            assert_eq!(issuer.dns.hosts_waiters.len(), 1);
            assert!(!issuer.dns.hosts_waiters[&1].acked);
        }
        assert!(issuer.grants.is_empty() && issuer.services.is_empty());
    }
}
#[test]
fn codec4_hosts_driver_blocked_send_never_renews_observation_lease() {
    for step in [3, 6] {
        let (mut issuer, mut f) = fixture(Mode::System);
        Arc::get_mut(&mut f).unwrap().expiry = issuer.authority.now() + Duration::from_millis(5);
        let script = hosts_script(&f);
        let packets: Vec<_> = script
            .iter()
            .enumerate()
            .map(|(i, (kind, b))| dns_packet(f.launch, i as u64 + 3, *kind, b))
            .collect();
        let mut io = BundleIo::new(f.launch, vec![packets[0].clone()]);
        io.source = Some(f.clone());
        io.stop_after = script.len();
        io.delay_write_at = step;
        *io.delayed_send.borrow_mut() = Some(issuer.authority.elapsed.clone());
        for p in &packets[1..] {
            append(&io, vec![p.clone()]);
        }
        drive(&mut issuer, &io);
        assert_eq!(io.output.borrow().len(), step - 1);
        assert!(issuer.hosts_producer_live(1, true).is_err());
        assert!(issuer.hosts_waiter_live(1, true).is_err());
        assert!(issuer.grants.is_empty());
        assert_eq!(io.dns_slots().unwrap().pending.used(), 1);
    }
}
#[test]
fn codec4_hosts_driver_cancel_queued_publish_is_drained_before_data_ack() {
    let (mut issuer, f) = fixture(Mode::System);
    let script = hosts_script(&f);
    let mut io = BundleIo::new(
        f.launch,
        vec![dns_packet(f.launch, 3, script[0].0, &script[0].1)],
    );
    io.source = Some(f.clone());
    io.stop_after = 4;
    append(
        &io,
        vec![dns_packet(f.launch, 4, script[1].0, &script[1].1)],
    );
    append(
        &io,
        vec![
            dns_packet(f.launch, 5, script[2].0, &script[2].1),
            dns_packet(f.launch, 6, Operation::Cancel, &cancel_body(1, 5)),
        ],
    );
    drive(&mut issuer, &io);
    let output = io.output.borrow();
    assert_eq!(output.len(), 4);
    assert_eq!(output[2][130], 2);
    assert!(issuer.hosts_producer_live(1, true).is_err());
    assert!(issuer.dns.hosts_producers.values().all(|p| !p.acked));
    assert!(issuer.bootstrap_live(1, true).is_ok());
}
#[test]
fn codec4_hosts_driver_waiter_requires_own_acked_reservation_and_exact_query() {
    for fault in 0..3 {
        let (mut issuer, f) = fixture(Mode::System);
        let mut script = hosts_script(&f);
        match fault {
            0 => script[5].1[39] = 9,
            1 => script[5].1[31] = 1,
            2 => script[5].1[47] = 1,
            _ => unreachable!(),
        }
        // class3 service flow0 допускает только source/revision оба0;
        // malformed pair кодируется как оба1, а затем отвергается issuer.
        if fault == 2 {
            script[5].1[55] = 1;
        }
        let output = scripted(&mut issuer, &f, &script);
        assert_eq!(output.len(), 6);
        assert_eq!(output[5][130], 2);
        assert!(issuer.dns.hosts_waiters.is_empty());
        assert!(issuer.bootstrap_live(2, true).is_ok());
    }
}

#[test]
fn codec4_hosts_driver_history_credit_precedes_publish_and_waiter_source_capture() {
    for waiter in [false, true] {
        let (mut issuer, f) = fixture(Mode::System);
        let mut script = hosts_script(&f);
        if !waiter {
            script.truncate(3);
        }
        let prior = if waiter {
            2 * f.path.len() + 5
        } else {
            f.path.len() + 2
        };
        issuer.dns.history = 256 - prior;
        let packets: Vec<_> = script
            .iter()
            .enumerate()
            .map(|(i, (kind, b))| dns_packet(f.launch, i as u64 + 3, *kind, b))
            .collect();
        let mut io = BundleIo::new(f.launch, vec![packets[0].clone()]);
        io.source = Some(f.clone());
        io.stop_after = script.len();
        for p in &packets[1..] {
            append(&io, vec![p.clone()]);
        }
        let source = f.clone();
        io.on_request = Some(Box::new(move |seq| {
            if seq == if waiter { 8 } else { 5 } {
                source.failed_operation.store(2, Ordering::Release);
            }
        }));
        drive(&mut issuer, &io);
        assert_eq!(io.output.borrow().len(), script.len());
        assert_eq!(io.output.borrow().last().unwrap()[130], 2);
        f.failed_operation.store(0, Ordering::Release);
        assert!(
            issuer
                .bootstrap_live(if waiter { 2 } else { 1 }, true)
                .is_ok()
        );
        assert!(issuer.dns.hosts_waiters.is_empty());
        if !waiter {
            assert!(issuer.dns.hosts_producers.is_empty());
        }
        assert_eq!(issuer.authority.route_count, 0);
    }
}

#[test]
fn codec4_hosts_driver_typed_cancel_namespaces_and_source_derivatives_are_isolated() {
    for (target, id, neighbor_live) in [(7, 2, true), (8, 2, true), (5, 1, false), (7, 1, false)] {
        let (mut issuer, f) = fixture(Mode::System);
        let mut script = hosts_script(&f);
        script.extend([
            (Operation::BundleAcquire, acquire(&f, true, 0, 11)),
            (Operation::Reserve, reserve(&f, true, 3, 11)),
            (Operation::WaiterBind, hosts_bind(3, 1, 11)),
            (Operation::Cancel, cancel_body(target, id)),
        ]);
        let output = scripted(&mut issuer, &f, &script);
        assert_eq!(output.len(), 10);
        assert_eq!(output.last().unwrap()[130], 1);
        assert!(issuer.hosts_waiter_live(1, true).is_err());
        assert_eq!(issuer.hosts_waiter_live(2, true).is_ok(), neighbor_live);
        assert_eq!(issuer.authority.route_count, 0);
    }
}

fn numeric_body(f: &Facts, waiter: u64, ip: [u8; 4]) -> Vec<u8> {
    numeric_ip_body(f, waiter, std::net::IpAddr::V4(ip.into()))
}
fn numeric_ip_body(f: &Facts, waiter: u64, ip: std::net::IpAddr) -> Vec<u8> {
    let mut b = vec![0; 16];
    b[..2].copy_from_slice(&2u16.to_be_bytes());
    b[4..12].copy_from_slice(&waiter.to_be_bytes());
    b[12..14].copy_from_slice(&8u16.to_be_bytes());
    b[14] = 2;
    b[15] = 3;
    for v in [2, f.endpoint, 1, u16::MAX] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    let (family, bytes) = match ip {
        std::net::IpAddr::V4(ip) => (4, ip.octets().to_vec()),
        std::net::IpAddr::V6(ip) => (6, ip.octets().to_vec()),
    };
    b.extend_from_slice(&[family, 6]);
    b.extend_from_slice(&8443u16.to_be_bytes());
    b.extend_from_slice(&[bytes.len() as u8, 0, 0]);
    b.extend_from_slice(&bytes);
    b
}
#[test]
fn codec4_hosts_numeric_wrong_address_preserves_history_and_neighbor() {
    let (mut issuer, f) = fixture(Mode::System);
    let mut setup = hosts_script(&f);
    setup.extend([
        (Operation::BundleAcquire, acquire(&f, true, 0, 11)),
        (Operation::Reserve, reserve(&f, true, 3, 11)),
        (Operation::WaiterBind, hosts_bind(3, 1, 11)),
    ]);
    let output = scripted(&mut issuer, &f, &setup);
    assert!(output.iter().all(|b| b[130] == 1));
    let history = issuer.dns.history;
    let wrong = numeric_body(&f, 1, [203, 0, 113, 81]);
    let Record::NumericAuthorize(wrong) =
        Record::decode(Operation::NumericAuthorize, &wrong).unwrap()
    else {
        panic!("numeric")
    };
    for request in 100..360 {
        assert!(matches!(
            issuer.authorize_hosts_numeric(request, wrong, f.expiry),
            Err(ServiceError::InvalidRequest)
        ));
        assert_eq!(
            issuer.dns.history, history,
            "wrong address не расходует history"
        );
    }
    assert!(issuer.dns.hosts_waiters[&1].numeric_once.is_none());
    let good = numeric_body(&f, 2, [203, 0, 113, 80]);
    let Record::NumericAuthorize(good) =
        Record::decode(Operation::NumericAuthorize, &good).unwrap()
    else {
        panic!("numeric")
    };
    assert!(issuer.authorize_hosts_numeric(400, good, f.expiry).is_ok());
    assert_eq!(issuer.authority.route_count, 1);
    assert_eq!(issuer.dns.history, history + 1);
}

#[test]
fn codec4_hosts_numeric_driver_grant_is_separate_flow0_permission_after_durable_route() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, f) = fixture(mode);
        let mut script = hosts_script(&f);
        script.push((
            Operation::NumericAuthorize,
            numeric_body(&f, 1, [203, 0, 113, 80]),
        ));
        let output = scripted(&mut issuer, &f, &script);
        assert_eq!(output.len(), 7);
        let frame = wire::Frame::decode(&output[6], f.launch.binding, mode, true).unwrap();
        assert_eq!(frame.header.reply_to, 9);
        assert!(matches!(
            frame.message,
            wire::Message::Grant {
                status: wire::Status::Allow,
                class: 3,
                flow: 0,
                required: false,
                fresh: 0,
                receipt: wire::Receipt {
                    kind: wire::ReceiptKind::None,
                    id: 0
                },
                ..
            }
        ));
        assert_eq!(issuer.authority.route_count, 1);
        assert_eq!(issuer.authority.owner_count, 0);
        assert!(issuer.grants.is_empty() && issuer.services.is_empty());
        assert!(
            issuer
                .hosts_permission_live(frame.header.object_id, true)
                .is_ok()
        );
    }
}

fn numeric_script(f: &Facts) -> Vec<(Operation, Vec<u8>)> {
    let mut script = hosts_script(f);
    script.push((
        Operation::NumericAuthorize,
        numeric_body(f, 1, [203, 0, 113, 80]),
    ));
    script
}
fn grant_status(output: &[u8], f: &Facts) -> wire::Status {
    match wire::Frame::decode(output, f.launch.binding, f.launch.mode, true)
        .unwrap()
        .message
    {
        wire::Message::Grant { status, .. } => status,
        _ => panic!("ожидается GRANT19"),
    }
}
fn packets(f: &Facts, script: &[(Operation, Vec<u8>)]) -> Vec<Vec<u8>> {
    script
        .iter()
        .enumerate()
        .map(|(i, (kind, b))| dns_packet(f.launch, 3 + i as u64, *kind, b))
        .collect()
}
fn io_script(f: &Arc<Facts>, packets: &[Vec<u8>]) -> BundleIo {
    let mut io = BundleIo::new(f.launch, vec![packets[0].clone()]);
    io.source = Some(f.clone());
    io.stop_after = packets.len();
    for p in &packets[1..] {
        append(&io, vec![p.clone()]);
    }
    io
}
#[test]
fn codec4_hosts_numeric_driver_wrong_member_parent_port_carrier_and_namespace_before_effect() {
    for fault in 0..7 {
        let (mut issuer, f) = fixture(Mode::System);
        let mut script = numeric_script(&f);
        let b = &mut script[6].1;
        match fault {
            0 => {
                let end = b.len();
                b[end - 1] = 81;
            }
            1 => b[3] = 1,
            2 => b[27] ^= 1,
            3 => b[25] = 17,
            4 => b[19] ^= 1,
            5 => b[21] = 0,
            6 => b[11] = 2,
            _ => unreachable!(),
        }
        let output = scripted(&mut issuer, &f, &script);
        assert_eq!(output.len(), 7);
        assert_eq!(
            grant_status(&output[6], &f),
            wire::Status::Deny,
            "fault {fault}"
        );
        assert_eq!(issuer.authority.route_count, 0);
        assert!(issuer.dns.permissions.is_empty());
        assert!(issuer.bootstrap_live(2, true).is_ok());
        if fault != 0 {
            assert_eq!(f.member_calls.load(Ordering::Acquire), 0);
        }
    }
}
#[test]
fn codec4_hosts_numeric_driver_changed_parent_source_epoch_or_expiry_never_route() {
    for fault in 0..4 {
        let (mut issuer, f) = fixture(Mode::System);
        let mut p = packets(&f, &numeric_script(&f));
        if fault == 3 {
            p[6][111] ^= 1;
        }
        let mut io = io_script(&f, &p);
        let source = f.clone();
        let elapsed = issuer.authority.elapsed.clone();
        io.on_request = Some(Box::new(move |seq| {
            if seq == 9 {
                match fault {
                    0 => source.failed_operation.store(1, Ordering::Release),
                    1 => source.failed_operation.store(4, Ordering::Release),
                    2 => {
                        elapsed.fetch_add(2_000_000_000, Ordering::AcqRel);
                    }
                    _ => {}
                }
            }
        }));
        drive(&mut issuer, &io);
        if fault == 3 {
            assert_eq!(io.output.borrow().len(), 6);
        } else {
            assert_eq!(io.output.borrow().len(), 7);
            assert_eq!(grant_status(&io.output.borrow()[6], &f), wire::Status::Deny);
        }
        assert_eq!(issuer.authority.route_count, 0);
        assert!(issuer.dns.permissions.is_empty());
    }
}
#[test]
fn codec4_hosts_numeric_driver_backend_latency_and_source_change_cleanup_once() {
    for fault in 0..3 {
        let (mut issuer, mut f) = fixture(Mode::System);
        if fault == 0 {
            Arc::get_mut(&mut f).unwrap().expiry =
                issuer.authority.now() + Duration::from_millis(20);
            issuer.authority.route_delay = Duration::from_millis(25);
        } else {
            let source = f.clone();
            issuer.authority.service_hook = Some(Arc::new(move || {
                source.failed_operation.store(4, Ordering::Release)
            }));
            issuer.authority.unknown_release = fault == 2;
        }
        let output = scripted(&mut issuer, &f, &numeric_script(&f));
        assert_eq!(output.len(), 7);
        assert_eq!(
            grant_status(&output[6], &f),
            if fault == 2 {
                wire::Status::Unknown
            } else {
                wire::Status::Deny
            }
        );
        assert_eq!(issuer.authority.route_count, 1);
        assert_eq!(issuer.authority.release_attempts, 1);
        assert_eq!(issuer.authority.live.len(), usize::from(fault == 2));
        assert_eq!(issuer.unknown, fault == 2);
        assert_eq!(
            issuer.dns.permissions[&1].state,
            if fault == 2 {
                PermissionState::Unknown
            } else {
                PermissionState::Closed
            }
        );
        let attempts = issuer.authority.release_attempts;
        let _closed = issuer.cancel_grant(1);
        assert_eq!(issuer.authority.release_attempts, attempts);
    }
}
#[test]
fn codec4_hosts_numeric_driver_replay_and_numeric_request_cancel_are_one_shot() {
    for cancel in [false, true] {
        let (mut issuer, f) = fixture(Mode::System);
        let mut p = packets(&f, &numeric_script(&f));
        if cancel {
            p.push(dns_packet(
                f.launch,
                10,
                Operation::Cancel,
                &cancel_body(1, 9),
            ));
        } else {
            p.push(dns_packet(
                f.launch,
                10,
                Operation::NumericAuthorize,
                &numeric_body(&f, 1, [203, 0, 113, 80]),
            ));
        }
        let io = io_script(&f, &p);
        if cancel {
            // Numeric9 и Cancel10 одновременно готовы: drain до install.
            io.after_reply.borrow_mut().pop_back();
            let mut batches = io.after_reply.borrow_mut();
            batches.back_mut().unwrap().push(p[7].clone());
        }
        drive(&mut issuer, &io);
        let output = io.output.borrow();
        assert_eq!(output.len(), 8);
        if cancel {
            assert_eq!(grant_status(&output[6], &f), wire::Status::Deny);
            assert_eq!(issuer.authority.route_count, 0);
        } else {
            assert_eq!(grant_status(&output[7], &f), wire::Status::Deny);
            assert_eq!(issuer.authority.route_count, 1);
        }
    }
}
#[test]
fn codec4_hosts_numeric_driver_cancel_after_backend_retires_before_reply() {
    let (mut issuer, f) = fixture(Mode::System);
    let p = packets(&f, &numeric_script(&f));
    let mut io = io_script(&f, &p);
    io.stop_after = 8;
    // Пакет появляется только после effectful backend call.
    let deferred = Arc::new(std::sync::Mutex::new(Vec::new()));
    let arrival = deferred.clone();
    let cancel = dns_packet(f.launch, 10, Operation::Cancel, &cancel_body(1, 9));
    issuer.authority.service_hook = Some(Arc::new(move || {
        arrival.lock().unwrap().push(cancel.clone())
    }));
    io.deferred = Some(deferred);
    drive(&mut issuer, &io);
    let output = io.output.borrow();
    assert_eq!(output.len(), 8);
    assert_eq!(grant_status(&output[6], &f), wire::Status::Deny);
    assert_eq!(issuer.authority.route_count, 1);
    assert_eq!(issuer.authority.release_attempts, 1);
    assert!(issuer.authority.live.is_empty());
    assert!(!issuer.dns.permissions[&1].acked);
}

fn legacy_close(f: &Facts, seq: u64, id: u64) -> Vec<u8> {
    let mut out = [0; 160];
    let n = wire::Frame::encode(
        wire::Header {
            kind: wire::Kind::Cancel,
            sequence: seq,
            reply_to: 0,
            binding: f.launch.binding,
            object_id: 0,
        },
        &wire::Message::Cancel {
            target: 3,
            id,
            reason: 0,
        },
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}
#[test]
fn codec4_hosts_numeric_driver_close32_retires_only_permission_and_retry_is_immutable() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, f) = fixture(mode);
        let mut p = packets(&f, &numeric_script(&f));
        p.push(legacy_close(&f, 10, 1));
        p.push(legacy_close(&f, 11, 1));
        let io = io_script(&f, &p);
        drive(&mut issuer, &io);
        let output = io.output.borrow();
        assert_eq!(output.len(), 9);
        assert_eq!(grant_status(&output[6], &f), wire::Status::Allow);
        for b in &output[7..] {
            assert!(matches!(
                wire::Frame::decode(b, f.launch.binding, mode, true)
                    .unwrap()
                    .message,
                wire::Message::CloseAck {
                    target: 3,
                    id: 1,
                    status: wire::CloseStatus::KnownClosed
                }
            ));
        }
        assert_eq!(issuer.dns.permissions[&1].state, PermissionState::Closed);
        assert!(issuer.dns.permissions[&1].routes.is_none());
        assert_eq!(issuer.authority.release_attempts, 1);
        assert!(issuer.authority.live.is_empty());
        assert!(issuer.bootstrap_live(1, true).is_ok() && issuer.bootstrap_live(2, true).is_ok());
        assert!(issuer.grants.is_empty() && issuer.services.is_empty());
        assert!(
            issuer
                .service(
                    50,
                    1,
                    &wire::Message::Probe {
                        purpose: 2,
                        index: f.endpoint,
                        subject: 1,
                        resolver: 1
                    }
                )
                .is_err()
        );
    }
}
#[test]
fn codec4_hosts_numeric_driver_waiter_cancel_preserves_neighbor_ticket() {
    let (mut issuer, f) = fixture(Mode::System);
    let mut script = numeric_script(&f);
    script.extend([
        (Operation::BundleAcquire, acquire(&f, true, 0, 11)),
        (Operation::Reserve, reserve(&f, true, 3, 11)),
        (Operation::WaiterBind, hosts_bind(3, 1, 11)),
        (
            Operation::NumericAuthorize,
            numeric_body(&f, 2, [203, 0, 113, 80]),
        ),
        (Operation::Cancel, cancel_body(6, 1)),
    ]);
    let output = scripted(&mut issuer, &f, &script);
    assert_eq!(output.len(), 12);
    assert_eq!(issuer.authority.route_count, 2);
    assert_eq!(issuer.authority.release_attempts, 1);
    assert_eq!(issuer.dns.permissions[&1].state, PermissionState::Closed);
    assert!(issuer.hosts_permission_live(2, true).is_ok());
    assert!(issuer.authority.live.contains(&2));
}
#[test]
fn codec4_hosts_numeric_driver_pending_send_failure_retains_unknown_ticket_and_credits() {
    let (mut issuer, f) = fixture(Mode::System);
    let p = packets(&f, &numeric_script(&f));
    let mut io = io_script(&f, &p);
    io.fail_write_at = Some(7);
    drive(&mut issuer, &io);
    assert_eq!(io.output.borrow().len(), 6);
    assert!(issuer.unknown);
    assert_eq!(issuer.dns.permissions[&1].state, PermissionState::Unknown);
    assert!(!issuer.dns.permissions[&1].acked);
    assert!(
        issuer.dns.permissions[&1].ticket.is_some() && issuer.dns.permissions[&1].routes.is_some()
    );
    assert_eq!(io.dns_slots().unwrap().pending.used(), 1);
    assert_eq!(issuer.authority.release_attempts, 0);
}
#[test]
fn codec4_hosts_numeric_driver_blocked_send_cannot_extend_original_source_deadline() {
    let (mut issuer, mut f) = fixture(Mode::System);
    Arc::get_mut(&mut f).unwrap().expiry = issuer.authority.now() + Duration::from_millis(20);
    let p = packets(&f, &numeric_script(&f));
    let mut io = io_script(&f, &p);
    io.delay_write_at = 7;
    *io.delayed_send.borrow_mut() = Some(issuer.authority.elapsed.clone());
    drive(&mut issuer, &io);
    assert_eq!(io.output.borrow().len(), 7);
    assert_eq!(grant_status(&io.output.borrow()[6], &f), wire::Status::Deny);
    assert_eq!(issuer.dns.permissions[&1].state, PermissionState::Closed);
    assert!(!issuer.dns.permissions[&1].acked);
    assert_eq!(issuer.authority.release_attempts, 1);
    assert!(issuer.authority.live.is_empty());
}
#[test]
fn codec4_hosts_numeric_driver_history_credit_precedes_member_capture_and_backend() {
    let (mut issuer, f) = fixture(Mode::System);
    issuer.dns.history = 256 - (2 * f.path.len() + 6);
    let output = scripted(&mut issuer, &f, &numeric_script(&f));
    assert_eq!(output.len(), 7);
    assert_eq!(grant_status(&output[6], &f), wire::Status::Deny);
    assert_eq!(f.member_calls.load(Ordering::Acquire), 0);
    assert_eq!(issuer.authority.route_count, 0);
    assert!(issuer.dns.permissions.is_empty());
}
#[test]
fn codec4_hosts_numeric_driver_ipv6_and_literal_data_never_skip_numeric_policy() {
    for address in ["2001:db8::80", "0.0.0.0", "127.0.0.1"] {
        let ip = address.parse().unwrap();
        let (mut issuer, f) = fixture_address(Mode::System, ip);
        let mut script = hosts_script(&f);
        let eligible = address == "2001:db8::80";
        let target = if eligible {
            ip
        } else {
            "203.0.113.80".parse().unwrap()
        };
        script.push((Operation::NumericAuthorize, numeric_ip_body(&f, 1, target)));
        let output = scripted(&mut issuer, &f, &script);
        assert_eq!(output.len(), 7);
        assert_eq!(output[2][130], 1);
        assert_eq!(
            grant_status(&output[6], &f),
            if eligible {
                wire::Status::Allow
            } else {
                wire::Status::Deny
            }
        );
        assert_eq!(issuer.authority.route_count, u64::from(eligible));
    }
}

#[test]
fn codec4_hosts_numeric_driver_after_send_uncertainty_retains_custody_not_known_closed() {
    let (mut issuer, f) = fixture(Mode::System);
    let p = packets(&f, &numeric_script(&f));
    let mut io = io_script(&f, &p);
    let source = f.clone();
    io.after_sent = Some(Box::new(move |n| {
        if n == 7 {
            source.failed_operation.store(4, Ordering::Release);
        }
    }));
    drive(&mut issuer, &io);
    assert!(issuer.unknown);
    assert_eq!(io.output.borrow().len(), 7);
    assert_eq!(issuer.dns.permissions[&1].state, PermissionState::Unknown);
    assert!(!issuer.dns.permissions[&1].acked);
    assert!(issuer.dns.permissions[&1].ticket.is_some());
    assert_eq!(issuer.authority.release_attempts, 0);
    assert_eq!(io.dns_slots().unwrap().pending.used(), 1);
}
#[test]
fn codec4_hosts_numeric_driver_backend_failure_keeps_prepaid_one_shot_state() {
    let (mut issuer, f) = fixture(Mode::System);
    issuer.authority.fail_route_at = Some(1);
    let output = scripted(&mut issuer, &f, &numeric_script(&f));
    assert_eq!(output.len(), 7);
    assert_eq!(grant_status(&output[6], &f), wire::Status::Unknown);
    assert_eq!(issuer.dns.permissions[&1].state, PermissionState::Unknown);
    assert!(issuer.dns.permissions[&1].routes.is_some());
    assert!(issuer.dns.hosts_waiters[&1].numeric_once.is_some());
    assert_eq!(issuer.authority.route_count, 0);
    assert!(issuer.cancel_grant(1).is_err());
}

fn bootstrap_raw(f: &Facts) -> [u8; 192] {
    let mut b = [0; 192];
    b[..8].copy_from_slice(b"DNSPHY02");
    b[8..10].copy_from_slice(&2u16.to_be_bytes());
    b[10..12].copy_from_slice(&192u16.to_be_bytes());
    b[16..48].copy_from_slice(&f.launch.binding.digest);
    b[48..64].copy_from_slice(&f.launch.binding.session);
    b[64..80].copy_from_slice(&f.launch.binding.invocation);
    b[80..88].copy_from_slice(&f.launch.binding.generation.to_be_bytes());
    b[88..96].copy_from_slice(&f.launch.binding.epoch.to_be_bytes());
    b[96..128].copy_from_slice(&f.launch.nonce);
    for (at, value) in [(128, 1u64), (136, 9), (144, 1), (152, 2)] {
        b[at..at + 8].copy_from_slice(&value.to_be_bytes());
    }
    b[160..162].copy_from_slice(&1u16.to_be_bytes());
    b[162..164].copy_from_slice(&((f.path.len() - 1) as u16).to_be_bytes());
    b[164] = 17;
    b[165] = 2;
    b[166] = f.launch.mode as u8;
    b[168..175].copy_from_slice(&[4, 17, 0, 53, 4, 0, 0]);
    b[175..179].copy_from_slice(&[192, 0, 2, 53]);
    b
}
fn bootstrap_logical() -> Vec<u8> {
    let mut b = vec![0; 72];
    b[..2].copy_from_slice(&2u16.to_be_bytes());
    b[2] = 1;
    b[4..6].copy_from_slice(&1u16.to_be_bytes());
    for (at, value) in [
        (8, 1u64),
        (16, 9),
        (24, 1),
        (32, 1),
        (48, 1),
        (56, 1_000_000_000),
        (64, 1),
    ] {
        b[at..at + 8].copy_from_slice(&value.to_be_bytes());
    }
    b
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum BootstrapTransportFault {
    None,
    LateFd,
    NoProducer,
    Schema3,
    WrongLaunch,
    NoPermit,
    LostPermit,
    NoCredits,
    SourceInvalid,
    WrongPeer,
    WrongNamespace,
    Retire,
    ExpiredCleanup,
    UnknownClose,
    Publish(NetworkFault),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum NetworkFault {
    Good,
    NoTranscript,
    WrongCapture,
    WrongQuestion,
    WrongSource,
    WrongRevision,
    WrongCarrier,
    ZeroTtl,
    FutureObservation,
    SourceAtSend,
    AfterSendSource,
    TwoWaiters,
    WrongWaiterRoot,
    WaiterExpiry,
    WaiterReplay,
    CancelWaiter,
}
fn bootstrap_publish(f: &Facts) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x08physical\x07invalid\0\0\x01\0\x01");
    let mut r = q.clone();
    r[2] = 0x80;
    r[7] = 1;
    r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 80]);
    let mut b = vec![0; 144];
    b[1] = 2;
    for (at, v) in [
        (4, 1u16),
        (6, 1),
        (8, f.endpoint),
        (10, 1),
        (108, 16),
        (110, q.len() as u16),
        (140, f.path.last().unwrap().0),
    ] {
        b[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    for (at, v) in [
        (12, 9u64),
        (20, 1),
        (28, 1),
        (36, f.launch.binding.epoch),
        (120, 1),
        (128, 1),
    ] {
        b[at..at + 8].copy_from_slice(&v.to_be_bytes());
    }
    b[44..76].copy_from_slice(&f.reference.source);
    b[76..108].copy_from_slice(&f.reference.asset);
    b[112..116].copy_from_slice(&(r.len() as u32).to_be_bytes());
    b[136] = 2;
    b[137] = 1;
    b[142] = 6;
    b.extend_from_slice(b"physical.invalid");
    b.extend_from_slice(&q);
    b.extend_from_slice(&r);
    b
}
struct CapturedBootstrapResponse {
    facts: Arc<Facts>,
    raw: Vec<u8>,
    observed: Instant,
    invalidate: bool,
    calls: AtomicUsize,
}
impl super::super::super::BootstrapDnsTranscript for CapturedBootstrapResponse {
    fn observed(
        &self,
        launch: LaunchRecord,
        r: super::super::super::BootstrapDnsReceipt<'_>,
    ) -> Result<Instant, ServiceError> {
        let f = &self.facts;
        let b = &self.raw;
        let q = usize::from(u16_at(b, 108));
        let n = usize::from(u16_at(b, 110));
        if launch != f.launch
            || !r.binding.bootstrap
            || r.binding.query != 9
            || r.binding.root != 1
            || r.binding.bundle != 1
            || r.binding.epoch != launch.binding.epoch
            || r.binding.source != 0
            || r.binding.source_revision != 0
            || r.binding.physical_endpoint != f.endpoint
            || r.binding.physical_scope != f.path.last().unwrap().0
            || r.binding.parent_carrier != 6
            || r.binding.peer.protocol != 17
            || r.binding.peer.wire().bytes != [192, 0, 2, 53]
            || r.binding.peer.port != 53
            || r.binding.qtype != 1
            || r.binding.options != 0
            || r.binding.payload != 0
            || r.binding.resolver != 1
            || r.proof != 1
            || r.revision != 1
            || r.exchange != 1
            || r.producer_sequence != 1
            || r.request != &b[144 + q..144 + q + n]
            || r.response != &b[144 + q + n..]
        {
            return Err(ServiceError::Unavailable);
        }
        if self.invalidate && self.calls.fetch_add(1, Ordering::AcqRel) == 1 {
            self.facts.invalid_source.store(true, Ordering::Release);
        }
        Ok(self.observed)
    }
}
fn bootstrap_transport_driver(fault: BootstrapTransportFault) {
    let (mut issuer, f) = fixture(Mode::System);
    service(&mut issuer, &f);
    if matches!(
        fault,
        BootstrapTransportFault::Publish(
            NetworkFault::TwoWaiters
                | NetworkFault::WrongWaiterRoot
                | NetworkFault::WaiterExpiry
                | NetworkFault::WaiterReplay
                | NetworkFault::CancelWaiter
        )
    ) {
        service(&mut issuer, &f);
        service(&mut issuer, &f);
    }
    let inbox = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
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
    io.dns_inbox = Some(inbox.clone());
    io.stop_after = 5;
    if let BootstrapTransportFault::Publish(case) = fault {
        let mut raw = bootstrap_publish(&f);
        if case == NetworkFault::WrongCapture {
            let end = raw.len();
            raw[end - 1] ^= 1;
        }
        if case != NetworkFault::NoTranscript {
            io.bootstrap_transcript = Some(Arc::new(CapturedBootstrapResponse {
                facts: f.clone(),
                raw,
                observed: issuer.authority.now()
                    + if case == NetworkFault::FutureObservation {
                        Duration::from_millis(1)
                    } else {
                        Duration::ZERO
                    },
                invalidate: case == NetworkFault::SourceAtSend,
                calls: AtomicUsize::new(0),
            }));
        }
    }
    let mut launch = f.launch;
    if fault == BootstrapTransportFault::WrongLaunch {
        launch.nonce[0] ^= 1;
    }
    io.bootstrap_producer = if fault == BootstrapTransportFault::NoProducer {
        None
    } else {
        Some(Arc::new(
            super::super::super::VerifiedBootstrapDnsProducer {
                launch,
                schema: if fault == BootstrapTransportFault::Schema3 {
                    [3; 32]
                } else {
                    Sha256::digest(wire::dns_v2::SCHEMA).into()
                },
            },
        ))
    };
    append(
        &io,
        vec![dns_packet(
            f.launch,
            4,
            Operation::Reserve,
            &reserve(&f, false, 1, 9),
        )],
    );
    append(
        &io,
        vec![dns_packet(
            f.launch,
            5,
            Operation::Reserve,
            &reserve(&f, false, 2, 9),
        )],
    );
    append(&io, vec![]);
    append(
        &io,
        vec![dns_packet(
            f.launch,
            6,
            Operation::LogicalBind,
            &bootstrap_logical(),
        )],
    );
    if let BootstrapTransportFault::Publish(case) = fault {
        io.stop_after = 6;
        let mut b = bootstrap_publish(&f);
        match case {
            NetworkFault::WrongQuestion => b[144] = b'x',
            NetworkFault::WrongSource => b[44] ^= 1,
            NetworkFault::WrongRevision => b[135] = 2,
            NetworkFault::WrongCarrier => b[142] = 17,
            NetworkFault::ZeroTtl => {
                let at = b.len() - 10;
                b[at..at + 4].fill(0);
            }
            _ => {}
        }
        append(&io, vec![dns_packet(f.launch, 7, Operation::Publish, &b)]);
        if matches!(
            case,
            NetworkFault::TwoWaiters
                | NetworkFault::WrongWaiterRoot
                | NetworkFault::WaiterExpiry
                | NetworkFault::WaiterReplay
                | NetworkFault::CancelWaiter
        ) {
            let waiter = |reservation: u64, root: u64, query: u64| {
                let mut b = vec![0; 64];
                b[1] = 2;
                for (at, v) in [
                    (8, reservation),
                    (16, 1),
                    (24, root),
                    (32, query),
                    (56, 1_000_000_000),
                ] {
                    b[at..at + 8].copy_from_slice(&v.to_be_bytes());
                }
                b
            };
            for (sequence, context, query, root, reservation) in
                [(8, 2u64, 10u64, 2u64, 3u64), (11, 3, 11, 3, 4)]
            {
                let mut r = reserve(&f, false, 3, query);
                r[16..24].copy_from_slice(&context.to_be_bytes());
                r[24..32].copy_from_slice(&root.to_be_bytes());
                if case == NetworkFault::WaiterExpiry {
                    r[56..64].copy_from_slice(&1_000_000u64.to_be_bytes());
                }
                append(
                    &io,
                    vec![dns_packet(
                        f.launch,
                        sequence,
                        Operation::BundleAcquire,
                        &acquire(&f, false, root, query),
                    )],
                );
                append(
                    &io,
                    vec![dns_packet(f.launch, sequence + 1, Operation::Reserve, &r)],
                );
                append(
                    &io,
                    vec![dns_packet(
                        f.launch,
                        sequence + 2,
                        Operation::WaiterBind,
                        &waiter(
                            reservation,
                            if case == NetworkFault::WrongWaiterRoot {
                                1
                            } else {
                                root
                            },
                            query,
                        ),
                    )],
                );
                if matches!(
                    case,
                    NetworkFault::WrongWaiterRoot
                        | NetworkFault::WaiterExpiry
                        | NetworkFault::WaiterReplay
                ) {
                    break;
                }
            }
            io.stop_after = if matches!(
                case,
                NetworkFault::WrongWaiterRoot | NetworkFault::WaiterExpiry
            ) {
                9
            } else if case == NetworkFault::WaiterReplay {
                10
            } else {
                12
            };
            if case == NetworkFault::WaiterReplay {
                append(
                    &io,
                    vec![dns_packet(
                        f.launch,
                        11,
                        Operation::WaiterBind,
                        &waiter(3, 2, 10),
                    )],
                );
            }
            if case == NetworkFault::CancelWaiter {
                io.stop_after = 13;
                append(
                    &io,
                    vec![dns_packet(
                        f.launch,
                        14,
                        Operation::Cancel,
                        &cancel_body(6, 1),
                    )],
                );
            }
        }
    }
    let raw = bootstrap_raw(&f);
    let neg = issuer_tests::dns_neg(f.launch);
    let slots = io.dns_slots().unwrap();
    let _fd_limit = if fault == BootstrapTransportFault::NoCredits {
        Some(slots.fds.reserve(64).unwrap())
    } else {
        None
    };
    if fault == BootstrapTransportFault::LostPermit {
        issuer.authority.bootstrap_revoke_on = Some(2);
    }
    let budget = issuer.budget.dynamic.clone();
    let facts = Arc::new(std::sync::Mutex::new(
        super::super::super::dns_transport::fake_facts(
            "192.0.2.10:32001".parse().unwrap(),
            if fault == BootstrapTransportFault::WrongPeer {
                "192.0.2.54:53"
            } else {
                "192.0.2.53:53"
            }
            .parse()
            .unwrap(),
            17,
            if fault == BootstrapTransportFault::WrongNamespace {
                (4, 6)
            } else {
                (4, 5)
            },
        ),
    ));
    let valid = Arc::new(AtomicBool::new(true));
    let closed = Arc::new(AtomicUsize::new(0));
    let close_count = closed.clone();
    let validity = valid.clone();
    let permit = issuer.authority.bootstrap_permit_live.clone();
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let calls = factory_calls.clone();
    let source = f.clone();
    let clock = issuer.authority.elapsed.clone();
    let factory = move || {
        calls.fetch_add(1, Ordering::AcqRel);
        let incoming = super::super::super::dns_transport::Incoming::fake(
            raw,
            &neg,
            &slots,
            &budget,
            None,
            facts.clone(),
            valid.clone(),
            closed.clone(),
            || {},
        )
        .unwrap();
        inbox.lock().unwrap().push_back(incoming);
    };
    if fault == BootstrapTransportFault::Publish(NetworkFault::AfterSendSource) {
        let source = f.clone();
        io.after_sent = Some(Box::new(move |n| {
            if n == 6 {
                source.invalid_source.store(true, Ordering::Release);
            }
        }));
        io.on_request = Some(Box::new(move |seq| {
            if seq == 5 {
                factory();
            }
        }));
    } else if fault == BootstrapTransportFault::LateFd {
        io.after_sent = Some(Box::new(move |n| {
            if n == 3 {
                factory();
            }
        }));
    } else {
        io.on_request = Some(Box::new(move |seq| {
            if seq == 10 && fault == BootstrapTransportFault::Publish(NetworkFault::WaiterExpiry) {
                clock.fetch_add(2_000_000, Ordering::AcqRel);
            }
            if seq == 7 && fault == BootstrapTransportFault::ExpiredCleanup {
                clock.fetch_add(1_100_000_000, Ordering::AcqRel);
            }
            if seq == 5 {
                if fault == BootstrapTransportFault::NoPermit {
                    permit.store(false, Ordering::Release);
                } else if fault == BootstrapTransportFault::SourceInvalid {
                    source.invalid_source.store(true, Ordering::Release);
                } else if !matches!(
                    fault,
                    BootstrapTransportFault::NoCredits | BootstrapTransportFault::LostPermit
                ) {
                    factory();
                }
            }
            if seq == 8 && fault == BootstrapTransportFault::UnknownClose {
                validity.store(false, Ordering::Release);
            }
        }));
    }
    if matches!(
        fault,
        BootstrapTransportFault::Retire
            | BootstrapTransportFault::ExpiredCleanup
            | BootstrapTransportFault::UnknownClose
    ) {
        io.stop_after = 11;
        let retire = |kind, id, rev| {
            let mut b = vec![0; 24];
            b[..2].copy_from_slice(&2u16.to_be_bytes());
            b[2] = kind;
            b[8..16].copy_from_slice(&u64::to_be_bytes(id));
            b[16..24].copy_from_slice(&u64::to_be_bytes(rev));
            b
        };
        append(
            &io,
            vec![dns_packet(f.launch, 7, Operation::Retire, &retire(4, 1, 1))],
        );
        append(
            &io,
            vec![dns_packet(f.launch, 8, Operation::Retire, &retire(3, 1, 0))],
        );
        append(
            &io,
            vec![dns_packet(f.launch, 9, Operation::Retire, &retire(3, 1, 0))],
        );
        for (sequence, target, id) in [(10, 7, 2), (11, 7, 1), (12, 8, 1)] {
            append(
                &io,
                vec![dns_packet(
                    f.launch,
                    sequence,
                    Operation::Cancel,
                    &cancel_body(target, id),
                )],
            );
        }
    }
    if matches!(
        fault,
        BootstrapTransportFault::NoProducer
            | BootstrapTransportFault::Schema3
            | BootstrapTransportFault::WrongLaunch
    ) {
        io.stop_after = 2;
        io.after_reply.borrow_mut().truncate(1);
    } else if matches!(
        fault,
        BootstrapTransportFault::NoPermit
            | BootstrapTransportFault::LostPermit
            | BootstrapTransportFault::NoCredits
            | BootstrapTransportFault::SourceInvalid
    ) {
        io.stop_after = 3;
        io.after_reply.borrow_mut().truncate(2);
    }
    drive(&mut issuer, &io);
    let out = io.output.borrow();
    if matches!(
        fault,
        BootstrapTransportFault::NoProducer
            | BootstrapTransportFault::Schema3
            | BootstrapTransportFault::WrongLaunch
    ) {
        assert_eq!(out[1][130], 2);
        assert_eq!(issuer.authority.dns_checks, 0);
        return;
    }
    if matches!(
        fault,
        BootstrapTransportFault::NoPermit
            | BootstrapTransportFault::LostPermit
            | BootstrapTransportFault::NoCredits
            | BootstrapTransportFault::SourceInvalid
    ) {
        assert_eq!(out[2][130], 2);
        assert_eq!(factory_calls.load(Ordering::Acquire), 0);
        assert_eq!(issuer.authority.dns_checks, 0);
        return;
    }
    if matches!(
        fault,
        BootstrapTransportFault::WrongPeer | BootstrapTransportFault::WrongNamespace
    ) {
        assert!(out.len() < 5 || out[3][130] != 1);
        assert_eq!(issuer.authority.owner_count, 0);
        return;
    }
    if matches!(
        fault,
        BootstrapTransportFault::Retire
            | BootstrapTransportFault::ExpiredCleanup
            | BootstrapTransportFault::UnknownClose
    ) {
        assert_eq!(
            out.len(),
            if fault != BootstrapTransportFault::UnknownClose {
                11
            } else {
                7
            }
        );
        assert_eq!(out[5][130], 1);
        assert_eq!(
            out[6][130],
            if fault != BootstrapTransportFault::UnknownClose {
                1
            } else {
                3
            }
        );
        if fault != BootstrapTransportFault::UnknownClose {
            assert_eq!(out[7][130], out[6][130]);
            for b in &out[8..] {
                assert_eq!(b[130], 1);
            }
            assert_eq!(issuer.authority.release_attempts, 1);
            assert_eq!(issuer.authority.live.len(), 1);
            assert!(issuer.authority.live.contains(&1));
            assert_eq!(io.dns_slots().unwrap().fds.used(), 0);
        } else {
            assert_eq!(issuer.authority.release_attempts, 0);
            assert_eq!(issuer.authority.live.len(), 2);
            assert!(io.dns_slots().unwrap().fds.used() > 0);
        }
        assert_eq!(close_count.load(Ordering::Acquire), 1);
        assert_eq!(
            issuer.unknown,
            fault == BootstrapTransportFault::UnknownClose
        );
    } else if let BootstrapTransportFault::Publish(case) = fault {
        let allowed = matches!(
            case,
            NetworkFault::Good
                | NetworkFault::AfterSendSource
                | NetworkFault::TwoWaiters
                | NetworkFault::WrongWaiterRoot
                | NetworkFault::WaiterExpiry
                | NetworkFault::WaiterReplay
                | NetworkFault::CancelWaiter
        );
        assert_eq!(
            out[5][130],
            if allowed { 1 } else { 2 },
            "network case {}",
            case as u8
        );
        if allowed {
            assert_eq!(u64_at(&out[5], 136), 1);
            assert_eq!(u64_at(&out[5], 144), 1);
        }
        if matches!(case, NetworkFault::TwoWaiters | NetworkFault::CancelWaiter) {
            assert_eq!(out[8][130], 1);
            assert_eq!(out[11][130], 1);
            assert_eq!(out[8][187], 2);
            assert_eq!(out[11][187], 2);
            assert_eq!(
                issuer.rrsets.waiter_flags(),
                if case == NetworkFault::CancelWaiter {
                    vec![false, true]
                } else {
                    vec![true, true]
                }
            );
        }
        if matches!(
            case,
            NetworkFault::WrongWaiterRoot | NetworkFault::WaiterExpiry | NetworkFault::WaiterReplay
        ) {
            assert_eq!(out.last().unwrap()[130], 2);
        }
        if !allowed {
            let retained = usize::from(case == NetworkFault::SourceAtSend);
            assert_eq!(issuer.rrsets.counts(), (retained, 0));
            assert_eq!(issuer.dns.history, f.path.len() + 6 + retained);
        }
        if case == NetworkFault::AfterSendSource {
            assert!(issuer.unknown);
            assert_eq!(issuer.rrsets.producer_flags(), vec![false]);
            assert_eq!(io.dns_slots().unwrap().pending.used(), 1);
        }
        assert!(issuer.grants.is_empty());
    } else {
        assert_eq!(out.len(), 5);
    }
    for b in out.iter().take(5) {
        assert_eq!(b[130], 1);
    }
    assert_eq!(u64_at(&out[3], 24), 5);
    assert_eq!(u64_at(&out[4], 168), 1);
    assert_eq!(issuer.authority.owner_count, 0);
}
#[test]
fn codec4_bootstrap_rrset_driver_publish_data_not_user_authority() {
    bootstrap_transport_driver(BootstrapTransportFault::Publish(NetworkFault::Good));
}
#[test]
fn codec4_bootstrap_rrset_driver_closed_transcript_exact_source_question_and_ttl() {
    for case in [
        NetworkFault::NoTranscript,
        NetworkFault::WrongCapture,
        NetworkFault::WrongQuestion,
        NetworkFault::WrongSource,
        NetworkFault::WrongRevision,
        NetworkFault::WrongCarrier,
        NetworkFault::ZeroTtl,
        NetworkFault::FutureObservation,
        NetworkFault::SourceAtSend,
        NetworkFault::AfterSendSource,
    ] {
        bootstrap_transport_driver(BootstrapTransportFault::Publish(case));
    }
}
#[test]
fn codec4_bootstrap_rrset_driver_fresh_waiters_and_cancel_are_independent() {
    for case in [
        NetworkFault::TwoWaiters,
        NetworkFault::WrongWaiterRoot,
        NetworkFault::WaiterExpiry,
        NetworkFault::WaiterReplay,
        NetworkFault::CancelWaiter,
    ] {
        bootstrap_transport_driver(BootstrapTransportFault::Publish(case));
    }
}
#[test]
fn codec4_bootstrap_transport_driver_raw_fd_then_distinct_logical_proof() {
    for f in [
        BootstrapTransportFault::None,
        BootstrapTransportFault::LateFd,
    ] {
        bootstrap_transport_driver(f);
    }
}
#[test]
fn codec4_bootstrap_transport_driver_producer_scope_and_permit_before_factory() {
    for f in [
        BootstrapTransportFault::NoProducer,
        BootstrapTransportFault::Schema3,
        BootstrapTransportFault::WrongLaunch,
        BootstrapTransportFault::NoPermit,
        BootstrapTransportFault::LostPermit,
        BootstrapTransportFault::NoCredits,
        BootstrapTransportFault::SourceInvalid,
    ] {
        bootstrap_transport_driver(f);
    }
}
#[test]
fn codec4_bootstrap_transport_driver_kernel_peer_namespace_fail_closed() {
    for f in [
        BootstrapTransportFault::WrongPeer,
        BootstrapTransportFault::WrongNamespace,
    ] {
        bootstrap_transport_driver(f);
    }
}
#[test]
fn codec4_bootstrap_transport_driver_consuming_close_once_and_unknown_sticky() {
    for f in [
        BootstrapTransportFault::Retire,
        BootstrapTransportFault::ExpiredCleanup,
        BootstrapTransportFault::UnknownClose,
    ] {
        bootstrap_transport_driver(f);
    }
}
