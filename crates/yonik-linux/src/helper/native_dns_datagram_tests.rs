//! USER admission и kernel Consumed matcher здесь preseed leaf facts.
//! Dispatcher57/58, Source/Hosts/waiter/Numeric/retirement — actual issuer.
use super::super::super::super::{
    SourceFlow, Target, UdpBinding, UdpIngressRecord, dns_datagram, send_message,
};
use super::*;
#[path = "native_dns_datagram_network_tests.rs"]
mod network;

fn fixture5(mode: Mode) -> (Issuer<Fake>, Arc<Facts>) {
    fixture5_order(mode, 1)
}
fn fixture5_order(mode: Mode, order: u8) -> (Issuer<Fake>, Arc<Facts>) {
    let (mut issuer, f) = fixture_carrier(
        mode,
        "203.0.113.80".parse().unwrap(),
        order,
        true,
        [3; 32],
        17,
    );
    issuer.authority.owner_forbidden = false;
    let mut tuple = match issuer_tests::open(mode, 32001) {
        wire::Message::OpenIngress { tuple, .. } => tuple,
        _ => unreachable!(),
    };
    tuple.protocol = 17;
    tuple.remote_port = 1082;
    let original = Target::copy(wire::Destination {
        protocol: 17,
        family: 4,
        port: 443,
        bytes: &[203, 0, 113, 9],
    })
    .unwrap();
    let proof = issuer
        .authority
        .owner(
            1,
            tuple,
            crate::attribution::native_session::OwnerReference::NONE,
        )
        .unwrap();
    let subject = issuer.authority.subject(&proof, 1, tuple).unwrap();
    issuer.flows.insert(
        1,
        Box::new(SourceFlow {
            numeric_only: false,
            tuple,
            original,
            subject,
            socket: (),
            root: None,
            request: 1,
        }),
    );
    issuer.next_flow = 1;
    let owned = issuer.capsule.clone();
    let cap = wire::Capsule::decode(owned.bytes(), &issuer.record.binding.digest).unwrap();
    let (scope, branch) = f.path[0];
    let d = cap.dial_scope(scope, branch).unwrap();
    let a = wire::Authorize {
        source_flow: 1,
        class: 1,
        subject: d.subject,
        chain: d.chain,
        transport: d.stream,
        scope,
        branch,
        original: original.wire(),
        effective: cap.endpoint(f.endpoint).unwrap(),
        resolver: u16::MAX,
        query: "",
        receipt: wire::Receipt {
            kind: wire::ReceiptKind::None,
            id: 0,
        },
    };
    let (grant, proof) = issuer.authorize(2, 0, &a).unwrap();
    assert_eq!(grant, 1);
    let mut ack = BundleIo::new(f.launch, vec![]);
    ack.source = Some(f.clone());
    send_message(
        &issuer,
        &ack,
        &AtomicBool::new(false),
        1,
        2,
        grant,
        &wire::Message::Grant {
            status: wire::Status::Allow,
            class: 1,
            required: mode.required(),
            grant,
            flow: 1,
            lease: 20,
            revision: 1,
            fresh: if mode.required() { 20_000_000 } else { 0 },
            receipt: issuer.authority.receipt(&proof, 1, tuple).unwrap(),
        },
        issuer.grants[&grant].expires,
    )
    .unwrap();
    assert!(issuer.grants[&grant].sent.load(Ordering::Acquire));
    let binding = Arc::new(UdpBinding {
        bootstrap_spent: AtomicBool::new(false),
        record: UdpIngressRecord {
            sequence: 1,
            ingress: 0,
            packet: wire::udp_v2::Packet {
                association: 1,
                packet: 1,
                permit: 1,
                cookie: 1,
                tuple,
                bytes: 12,
                header: 10,
                flags: 0,
                fingerprint: [9; 32],
            },
            original,
            expires: issuer.authority.now() + Duration::from_secs(1),
        },
        principal: subject,
        source: std::sync::atomic::AtomicU64::new(1),
        live: AtomicBool::new(true),
        _memory: issuer.budget.dynamic.reserve(512).unwrap(),
    });
    issuer
        .authority
        .datagram_bindings
        .insert(1, (f.launch, binding));
    issuer.authority.owner_forbidden = true;
    (issuer, f)
}
fn parent(f: &Facts, query: u64) -> Vec<u8> {
    let mut b = vec![0; 64];
    b[..2].copy_from_slice(&2u16.to_be_bytes());
    for (at, n) in [
        (8, query),
        (16, 1),
        (24, 1),
        (32, 1),
        (40, f.launch.binding.epoch),
    ] {
        b[at..at + 8].copy_from_slice(&n.to_be_bytes());
    }
    b[48..50].copy_from_slice(&f.path[0].0.to_be_bytes());
    b[50] = f.path[0].1;
    b[52..56].copy_from_slice(&1000u32.to_be_bytes());
    b
}
fn script5(f: &Facts) -> Vec<(Operation, Vec<u8>)> {
    let mut s = hosts_script(f);
    s.insert(0, (Operation::DatagramParentBind, parent(f, 9)));
    s.insert(4, (Operation::DatagramParentBind, parent(f, 10)));
    s.push((
        Operation::NumericAuthorize,
        numeric_body(f, 1, [203, 0, 113, 80]),
    ));
    s
}
fn io5(f: &Arc<Facts>, s: &[(Operation, Vec<u8>)]) -> BundleIo {
    let d = wire::dns_v2::Negotiated::datagram_descriptor(f.launch).unwrap();
    let neg = wire::dns_v2::Negotiated::accept_datagram(
        &d,
        &wire::dns_v2::Negotiated::ack(&d).unwrap(),
        f.launch,
        [(0, 0); 2],
    )
    .unwrap();
    let mut packets = vec![];
    for (i, (op, body)) in s.iter().enumerate() {
        let mut b = vec![0; super::super::super::super::RUNTIME_PACKET];
        let n = wire::dns_v2::DnsFrame {
            header: wire::dns_v2::Envelope {
                sequence: 3 + i as u64,
                reply_to: 0,
                binding: f.launch.binding,
            },
            record: Record::decode_datagram(*op, body).unwrap(),
        }
        .encode(&neg, &mut b)
        .unwrap();
        b.truncate(n);
        packets.push(b);
    }
    let mut io = BundleIo::new(f.launch, vec![packets[0].clone()]);
    io.datagram(dns_datagram::Producer::fake(f.launch, f.clone()));
    io.source = Some(f.clone());
    io.stop_after = packets.len();
    for p in &packets[1..] {
        append(&io, vec![p.clone()]);
    }
    io
}
#[test]
fn codec5_datagram_driver_hosts_member_route_permission_and_parent_cancel() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, f) = fixture5(mode);
        let script = script5(&f);
        let io = io5(&f, &script);
        drive(&mut issuer, &io);
        let out = io.output.borrow();
        assert_eq!(out.len(), 9);
        for (n, b) in out[..8].iter().enumerate() {
            assert_eq!(b[130], 1, "reply {n}");
        }
        assert_eq!(grant_status(&out[8], &f), wire::Status::Allow);
        let frame = wire::Frame::decode(&out[8], f.launch.binding, mode, true).unwrap();
        let permission = frame.header.object_id;
        assert_eq!(issuer.dns.permissions[&permission].target.protocol, 17);
        assert!(issuer.dns.permissions[&permission].datagram.is_some());
        assert!(issuer.hosts_permission_live(permission, true).is_ok());
        assert_eq!(issuer.authority.route_count, 2); // USER parent + отдельный numeric member.
        let owners = issuer.authority.owner_count;
        issuer.cancel_datagram_parent(2).unwrap();
        assert!(issuer.hosts_permission_live(permission, true).is_err());
        assert_eq!(issuer.authority.live.len(), 1);
        assert_eq!(issuer.authority.owner_count, owners);
        assert!(issuer.grants.contains_key(&1));
    }
}
#[test]
fn scope5_factory_hosts_local_system_uses_retained_planner_and_consumed_parent() {
    for mode in [Mode::Local, Mode::System] {
        let (mut issuer, f) = fixture5(mode);
        let binding = super::super::super::super::bootstrap_binding::tests::datagram_binding(
            issuer.capsule.clone(),
            f.launch,
            f.asset.clone(),
            f.reference,
            issuer.budget.clone(),
            issuer.authority.now(),
        );
        let mut script = script5(&f);
        // Payload DATA использует key того же captured planner; issuer проверит сам.
        let peers = ["192.0.2.53:53".parse().unwrap()];
        let plan = crate::helper::profile_intent::PinnedResolverSnapshot::fixture_lookup_data(
            &f.asset,
            &peers,
            f.reference,
            "physical.invalid",
            f.launch.binding.epoch,
            crate::helper::profile_intent::LookupFamily::Any,
            &issuer.budget.dynamic,
        )
        .unwrap();
        let key = plan.lookup_key().as_bytes();
        let body = &mut script[3].1;
        let old = usize::from(u16_at(body, 144 + 110));
        let old_end = 144 + 128 + old;
        body.splice(144 + 128..old_end, key.iter().copied());
        let tail_len = (body.len() - 144) as u16;
        body[144 + 10..144 + 12].copy_from_slice(&tail_len.to_be_bytes());
        body[144 + 110..144 + 112].copy_from_slice(&(key.len() as u16).to_be_bytes());
        drop(plan);
        let mut io = io5(&f, &script);
        io.datagram(binding.datagram_source(f.launch).unwrap().unwrap());
        drive(&mut issuer, &io);
        let out = io.output.borrow();
        assert_eq!(out.len(), 9);
        assert_eq!(
            grant_status(&out[8], &f),
            wire::Status::Allow,
            "{:?}",
            out.iter()
                .map(|p| (u16_at(p, 10), p[130]))
                .collect::<Vec<_>>()
        );
    }
}
#[test]
fn scope5_factory_reviewed_source_does_not_replace_consumed_lineage_or_user_ack() {
    for fault in 0..3 {
        let (mut issuer, f) = fixture5(Mode::System);
        let binding = super::super::super::super::bootstrap_binding::tests::datagram_binding(
            issuer.capsule.clone(),
            f.launch,
            f.asset.clone(),
            f.reference,
            issuer.budget.clone(),
            issuer.authority.now(),
        );
        match fault {
            0 => issuer.authority.datagram_bindings.clear(),
            1 => {
                issuer
                    .authority
                    .datagram_bindings
                    .get_mut(&1)
                    .unwrap()
                    .0
                    .nonce[0] ^= 1
            }
            _ => issuer.grants[&1].sent.store(false, Ordering::Release),
        }
        let mut io = io5(&f, &[(Operation::DatagramParentBind, parent(&f, 9))]);
        io.datagram(binding.datagram_source(f.launch).unwrap().unwrap());
        drive(&mut issuer, &io);
        assert_eq!(io.output.borrow()[0][130], 2);
        assert_eq!(issuer.authority.route_count, 1);
    }
}
#[test]
fn codec5_datagram_binding_exact_ss_parent_before_context() {
    let (mut issuer, f) = fixture5(Mode::Local);
    let d = wire::dns_v2::Negotiated::datagram_descriptor(f.launch).unwrap();
    issuer.negotiated = Some(
        wire::dns_v2::Negotiated::accept_datagram(
            &d,
            &wire::dns_v2::Negotiated::ack(&d).unwrap(),
            f.launch,
            [(0, 0); 2],
        )
        .unwrap(),
    );
    issuer.datagrams.producer = Some(dns_datagram::Producer::fake(f.launch, f.clone()));
    let cap = issuer.capsule().unwrap();
    let scope = cap.dial_scope(f.path[0].0, f.path[0].1).unwrap();
    assert_eq!(scope.stream, u16::MAX);
    assert_eq!((scope.input, scope.carrier, scope.action), (17, 17, 1));
    let b = parent(&f, 9);
    assert!(
        issuer
            .bind_datagram_parent(
                3,
                View::decode(&b).unwrap(),
                issuer.authority.now() + Duration::from_secs(1)
            )
            .is_ok()
    );
}
#[test]
fn codec5_datagram_driver_wrong_member_replay_and_mixed_carrier_do_not_spend_packet() {
    for fault in 0..4 {
        let (mut issuer, f) = fixture5(Mode::System);
        let mut script = script5(&f);
        let mut wrong = script[8].1.clone();
        match fault {
            0 => wrong[26..28].copy_from_slice(&1u16.to_be_bytes()),
            1 => *wrong.last_mut().unwrap() = 81,
            2 => wrong[25] = 6,
            3 => wrong[4..12].copy_from_slice(&99u64.to_be_bytes()),
            _ => unreachable!(),
        }
        script.insert(8, (Operation::NumericAuthorize, wrong));
        script.push(script[9].clone());
        let io = io5(&f, &script);
        drive(&mut issuer, &io);
        let out = io.output.borrow();
        assert_eq!(out.len(), 11);
        assert_eq!(
            grant_status(&out[8], &f),
            wire::Status::Deny,
            "fault {fault}"
        );
        assert_eq!(
            grant_status(&out[9], &f),
            wire::Status::Allow,
            "fault {fault}"
        );
        assert_eq!(grant_status(&out[10], &f), wire::Status::Deny);
        assert_eq!(issuer.authority.route_count, 2);
        assert!(
            issuer.authority.datagram_bindings[&1]
                .1
                .bootstrap_spent
                .load(Ordering::Acquire)
        );
    }
}
#[test]
fn codec5_datagram_driver_foreign_parent_and_missing_scope_fail_before_source() {
    for fault in 0..5 {
        let (mut issuer, f) = fixture5(Mode::System);
        let mut b = parent(&f, 9);
        match fault {
            0 => b[16..24].copy_from_slice(&2u64.to_be_bytes()),
            1 => b[24..32].copy_from_slice(&2u64.to_be_bytes()),
            2 => b[32..40].copy_from_slice(&2u64.to_be_bytes()),
            3 => {
                issuer
                    .authority
                    .elapsed
                    .store(25_000_000, Ordering::Release);
            }
            4 => b[48..50].copy_from_slice(&0u16.to_be_bytes()),
            _ => unreachable!(),
        }
        let script = vec![(Operation::DatagramParentBind, b)];
        let io = io5(&f, &script);
        drive(&mut issuer, &io);
        assert_eq!(io.output.borrow().len(), 1);
        assert_eq!(io.output.borrow()[0][130], 2, "fault {fault}");
        assert_eq!(f.checked.load(Ordering::Acquire), 0);
        assert_eq!(issuer.authority.route_count, 1);
    }
    let (mut issuer, f) = fixture5(Mode::Local);
    let mut io = io5(&f, &[(Operation::DatagramParentBind, parent(&f, 9))]);
    io.datagram_producer = None;
    drive(&mut issuer, &io);
    assert!(io.output.borrow().is_empty());
    assert_eq!(issuer.authority.route_count, 1);
}
#[test]
fn codec5_datagram_driver_expiry_after_backend_and_unknown_retirement_retain_fences() {
    let (mut issuer, f) = fixture5(Mode::System);
    let elapsed = issuer.authority.elapsed.clone();
    issuer.authority.service_hook = Some(Arc::new(move || {
        elapsed.store(25_000_000, Ordering::Release);
    }));
    let io = io5(&f, &script5(&f));
    drive(&mut issuer, &io);
    assert_ne!(
        grant_status(io.output.borrow().last().unwrap(), &f),
        wire::Status::Allow
    );
    assert_eq!(issuer.authority.live.len(), 0); // Original Known и его ticket тоже истекли.
    assert!(issuer.hosts_permission_live(2, true).is_err());
    let (mut issuer, f) = fixture5(Mode::Local);
    let io = io5(&f, &script5(&f));
    drive(&mut issuer, &io);
    assert_eq!(
        grant_status(io.output.borrow().last().unwrap(), &f),
        wire::Status::Allow
    );
    issuer.authority.unknown_release = true;
    let before = issuer.budget.dynamic.used();
    assert!(issuer.cancel_datagram_parent(2).is_err());
    assert!(issuer.unknown);
    assert_eq!(issuer.authority.live.len(), 2);
    assert_eq!(issuer.budget.dynamic.used(), before);
    let calls = issuer.authority.release_attempts;
    assert!(issuer.cancel_datagram_parent(2).is_err());
    assert_eq!(issuer.authority.release_attempts, calls);
}
#[test]
fn codec5_datagram_driver_source_revalidation_budget_and_consumed_control_fences() {
    let (mut issuer, f) = fixture5(Mode::Local);
    Arc::get_mut(&mut issuer.budget).unwrap().dynamic =
        super::super::super::super::super::memory::ByteBudget::new(1);
    let io = io5(&f, &[(Operation::DatagramParentBind, parent(&f, 9))]);
    drive(&mut issuer, &io);
    assert_eq!(io.output.borrow()[0][130], 2);
    assert_eq!(issuer.authority.route_count, 1);
    assert_eq!(f.checked.load(Ordering::Acquire), 0);
    for fault in 0..3 {
        let (mut issuer, f) = fixture5(Mode::Local);
        let source = f.clone();
        let binding = issuer.authority.datagram_bindings[&1].1.clone();
        issuer.authority.service_hook = Some(Arc::new(move || match fault {
            0 => source.invalid_source.store(true, Ordering::Release),
            1 => binding.live.store(false, Ordering::Release),
            _ => {
                binding.source.store(99, Ordering::Release);
            }
        }));
        let io = io5(&f, &script5(&f));
        drive(&mut issuer, &io);
        let out = io.output.borrow();
        assert_eq!(grant_status(out.last().unwrap(), &f), wire::Status::Deny);
        assert_eq!(issuer.authority.live.len(), 1);
        assert_eq!(issuer.authority.release_attempts, 1);
    }
}
#[test]
fn codec5_datagram_driver_cancel_one_source_preserves_independent_neighbor() {
    let (mut issuer, f) = fixture5(Mode::System);
    let first = &issuer.flows[&1];
    let mut tuple = first.tuple;
    tuple.local_port += 1;
    let (original, subject) = (first.original, first.subject);
    issuer.flows.insert(
        2,
        Box::new(SourceFlow {
            numeric_only: false,
            tuple,
            original,
            subject,
            socket: (),
            root: None,
            request: 1,
        }),
    );
    issuer.next_flow = 2;
    issuer.authority.owner_forbidden = false;
    let owned = issuer.capsule.clone();
    let cap = wire::Capsule::decode(owned.bytes(), &f.launch.binding.digest).unwrap();
    let (scope, branch) = f.path[0];
    let d = cap.dial_scope(scope, branch).unwrap();
    let a = wire::Authorize {
        source_flow: 2,
        class: 1,
        subject: d.subject,
        chain: d.chain,
        transport: d.stream,
        scope,
        branch,
        original: original.wire(),
        effective: cap.endpoint(f.endpoint).unwrap(),
        resolver: u16::MAX,
        query: "",
        receipt: wire::Receipt {
            kind: wire::ReceiptKind::None,
            id: 0,
        },
    };
    let (grant, proof) = issuer.authorize(2, 0, &a).unwrap();
    assert_eq!(grant, 2);
    let mut ack = BundleIo::new(f.launch, vec![]);
    ack.source = Some(f.clone());
    send_message(
        &issuer,
        &ack,
        &AtomicBool::new(false),
        1,
        2,
        grant,
        &wire::Message::Grant {
            status: wire::Status::Allow,
            class: 1,
            required: true,
            grant,
            flow: 2,
            lease: 20,
            revision: 1,
            fresh: 20_000_000,
            receipt: issuer.authority.receipt(&proof, 2, tuple).unwrap(),
        },
        issuer.grants[&grant].expires,
    )
    .unwrap();
    let first = &issuer.authority.datagram_bindings[&1].1;
    let mut record = first.record;
    record.packet.tuple = tuple;
    record.packet.association = 2;
    record.packet.packet = 2;
    record.packet.permit = 2;
    record.packet.cookie = 2;
    let second = Arc::new(UdpBinding {
        bootstrap_spent: AtomicBool::new(false),
        record,
        principal: subject,
        source: std::sync::atomic::AtomicU64::new(2),
        live: AtomicBool::new(true),
        _memory: issuer.budget.dynamic.reserve(512).unwrap(),
    });
    issuer
        .authority
        .datagram_bindings
        .insert(2, (f.launch, second));
    issuer.authority.owner_forbidden = true;
    let mut script = script5(&f);
    script[4].1[16..24].copy_from_slice(&2u64.to_be_bytes());
    script[4].1[24..32].copy_from_slice(&2u64.to_be_bytes());
    let io = io5(&f, &script);
    drive(&mut issuer, &io);
    assert_eq!(
        grant_status(io.output.borrow().last().unwrap(), &f),
        wire::Status::Allow
    );
    assert_eq!(issuer.authority.live.len(), 3);
    issuer.cancel_flow(2).unwrap();
    assert_eq!(issuer.authority.live.len(), 1);
    assert!(issuer.flows.contains_key(&1) && issuer.grants.contains_key(&1));
    assert!(issuer.datagram_parent_live(1, true).is_ok());
    assert!(issuer.hosts_producer_live(1, true).is_ok());
    assert!(
        !issuer.authority.datagram_bindings[&1]
            .1
            .bootstrap_spent
            .load(Ordering::Acquire)
    );
    assert!(
        issuer.authority.datagram_bindings[&2]
            .1
            .bootstrap_spent
            .load(Ordering::Acquire)
    );
}
#[test]
fn codec5_datagram_driver_wire_cancel9_closes_member_before_known_ack() {
    let (mut issuer, f) = fixture5(Mode::Local);
    let mut script = script5(&f);
    script.push((Operation::Cancel, cancel_body(9, 2)));
    let io = io5(&f, &script);
    drive(&mut issuer, &io);
    let out = io.output.borrow();
    assert_eq!(out.len(), 10);
    assert_eq!(grant_status(&out[8], &f), wire::Status::Allow);
    assert_eq!(
        u16::from_be_bytes([out[9][10], out[9][11]]),
        Operation::Canceled as u16
    );
    assert_eq!(out[9][130], 1);
    assert_eq!(issuer.authority.live.len(), 1);
    assert!(issuer.hosts_permission_live(2, true).is_err());
    assert!(issuer.grants.contains_key(&1));
}
