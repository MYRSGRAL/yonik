//! Actual serialized NETWORK actors; kernel/IO/capture/protected scopes — leaf fakes.
use super::super::super::super::super::{
    BootstrapDnsReceipt, BootstrapDnsTranscript, BootstrapReleaseProof,
    VerifiedBootstrapDnsProducer, dns_transport,
};
use super::*;
use std::sync::Mutex;

struct Capture {
    launch: LaunchRecord,
    raw: Vec<u8>,
    anchor: Instant,
}
impl BootstrapDnsTranscript for Capture {
    fn observed(
        &self,
        launch: LaunchRecord,
        r: BootstrapDnsReceipt<'_>,
    ) -> Result<Instant, ServiceError> {
        let q = usize::from(u16_at(&self.raw, 108));
        let n = usize::from(u16_at(&self.raw, 110));
        if launch != self.launch
            || r.binding.parent_carrier != 17
            || !r.binding.bootstrap
            || r.binding.proxied
            || r.binding.query != 9
            || r.binding.root != 2
            || r.binding.bundle != 1
            || r.binding.epoch != launch.binding.epoch
            || r.binding.peer.protocol != 17
            || r.binding.peer.port != 53
            || r.binding.peer.wire().bytes != [192, 0, 2, 53]
            || r.binding.source != 0
            || r.binding.source_revision != 0
            || r.binding.qtype != 1
            || r.binding.options != 0
            || r.proof != 1
            || r.revision != 1
            || r.exchange != 1
            || r.producer_sequence != 1
            || r.request != &self.raw[144 + q..144 + q + n]
            || r.response != &self.raw[144 + q + n..]
        {
            return Err(ServiceError::Unavailable);
        }
        Ok(self.anchor)
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    Good,
    NoWire,
    NoRelease,
    WrongLaunch,
    WrongResponse,
    WrongQuestion,
    FutureAnchor,
    ForeignQuery,
    MixedCarrier,
    WrongMember,
    NoPermit,
    Peer,
    Namespace,
    Cancel(u8),
    LateAck,
    Backend,
    Expiry,
    History,
    UnknownClose,
}
fn retire(kind: u8, id: u64, revision: u64) -> Vec<u8> {
    let mut b = vec![0; 24];
    b[1] = 2;
    b[2] = kind;
    b[8..16].copy_from_slice(&id.to_be_bytes());
    b[16..24].copy_from_slice(&revision.to_be_bytes());
    b
}
fn waiter() -> Vec<u8> {
    let mut b = hosts_bind(3, 1, 10);
    b[24..32].copy_from_slice(&3u64.to_be_bytes());
    b
}
fn run(mode: Mode, fault: Fault) {
    let (mut issuer, f) = fixture5_order(mode, 2);
    assert_eq!(service(&mut issuer, &f), 2);
    assert_eq!(service(&mut issuer, &f), 3);
    let mut reserve1 = reserve(&f, false, 1, 9);
    reserve1[24..32].copy_from_slice(&2u64.to_be_bytes());
    let mut reserve2 = reserve(&f, false, 2, 9);
    reserve2[24..32].copy_from_slice(&2u64.to_be_bytes());
    let mut reserve3 = reserve(&f, false, 3, 10);
    reserve3[16..24].copy_from_slice(&2u64.to_be_bytes());
    reserve3[24..32].copy_from_slice(&3u64.to_be_bytes());
    let mut publish = bootstrap_publish(&f);
    publish[20..28].copy_from_slice(&2u64.to_be_bytes());
    if fault == Fault::WrongResponse {
        let at = 144 + 16 + usize::from(u16_at(&publish, 110));
        publish[at] ^= 1;
    }
    if fault == Fault::WrongQuestion {
        let at = 144 + 16 + usize::from(u16_at(&publish, 110)) + 13;
        publish[at] = b'x';
    }
    let capture = Arc::new(Capture {
        launch: f.launch,
        raw: publish.clone(),
        anchor: issuer.authority.now()
            + if fault == Fault::FutureAnchor {
                Duration::from_millis(1)
            } else {
                Duration::ZERO
            },
    });
    if fault == Fault::ForeignQuery {
        publish[12..20].copy_from_slice(&10u64.to_be_bytes());
    }
    let mut numeric = numeric_body(&f, 1, [203, 0, 113, 80]);
    numeric[22..24].copy_from_slice(&1u16.to_be_bytes());
    if fault == Fault::MixedCarrier {
        numeric[25] = 6;
    }
    if fault == Fault::WrongMember {
        *numeric.last_mut().unwrap() = 81;
    }
    let mut script = vec![
        (Operation::DatagramParentBind, parent(&f, 9)),
        (Operation::BundleAcquire, acquire(&f, false, 2, 9)),
        (Operation::Reserve, reserve1),
        (Operation::Reserve, reserve2),
        (Operation::LogicalBind, bootstrap_logical()),
        (Operation::Publish, publish),
        (Operation::DatagramParentBind, parent(&f, 10)),
        (Operation::BundleAcquire, acquire(&f, false, 3, 10)),
        (Operation::Reserve, reserve3),
        (Operation::WaiterBind, waiter()),
    ];
    if let Fault::Cancel(target) = fault {
        script.push((
            Operation::Cancel,
            cancel_body(
                target,
                match target {
                    5 => 1,
                    7 => 3,
                    8 | 9 => 2,
                    _ => unreachable!(),
                },
            ),
        ));
    }
    script.push((Operation::NumericAuthorize, numeric));
    let numeric_index = script.len(); // PhysicalAck добавляет одну reply перед Numeric.
    if matches!(fault, Fault::WrongMember | Fault::MixedCarrier) {
        let mut good = numeric_body(&f, 1, [203, 0, 113, 80]);
        good[22..24].copy_from_slice(&1u16.to_be_bytes());
        script.push((Operation::NumericAuthorize, good));
    }
    if matches!(fault, Fault::Good | Fault::UnknownClose) {
        script.extend([
            (Operation::Retire, retire(4, 1, 1)),
            (Operation::Retire, retire(3, 1, 0)),
            (Operation::Cancel, cancel_body(7, 2)),
            (Operation::Cancel, cancel_body(7, 1)),
            (Operation::Cancel, cancel_body(7, 3)),
            (Operation::Cancel, cancel_body(8, 1)),
            (Operation::Cancel, cancel_body(8, 2)),
            (Operation::Cancel, cancel_body(9, 1)),
            (Operation::Cancel, cancel_body(9, 2)),
        ]);
    }
    let mut io = io5(&f, &script);
    io.after_reply.borrow_mut().insert(3, vec![]);
    io.stop_after += 1;
    io.bootstrap_transcript = Some(capture.clone()); // Old field не выдаёт scope5.
    io.datagram_wire = if fault == Fault::NoWire {
        None
    } else {
        Some(dns_datagram::NetworkWire::fake(f.launch, capture))
    };
    let mut launch = f.launch;
    if fault == Fault::WrongLaunch {
        launch.nonce[0] ^= 1;
    }
    io.datagram_release = if fault == Fault::NoRelease {
        None
    } else {
        Some(dns_datagram::NetworkRelease::fake(launch))
    };
    // Old reviewed4 release должен оставаться бесполезным при отсутствии release5.
    io.bootstrap_producer = Some(Arc::new(VerifiedBootstrapDnsProducer {
        launch: f.launch,
        schema: Sha256::digest(wire::dns_v2::SCHEMA).into(),
        proof: BootstrapReleaseProof::Injected,
    }));
    let inbox = Arc::new(Mutex::new(std::collections::VecDeque::new()));
    io.dns_inbox = Some(inbox.clone());
    let d = wire::dns_v2::Negotiated::datagram_descriptor(f.launch).unwrap();
    let neg = wire::dns_v2::Negotiated::accept_datagram(
        &d,
        &wire::dns_v2::Negotiated::ack(&d).unwrap(),
        f.launch,
        [(0, 0); 2],
    )
    .unwrap();
    let raw = bootstrap_raw(&f);
    let slots = io.dns_slots().unwrap();
    let budget = issuer.budget.dynamic.clone();
    let facts = Arc::new(Mutex::new(
        dns_transport::fake_facts(
            "192.0.2.10:32001".parse().unwrap(),
            if fault == Fault::Peer {
                "192.0.2.54:53"
            } else {
                "192.0.2.53:53"
            }
            .parse()
            .unwrap(),
            17,
            if fault == Fault::Namespace {
                (4, 6)
            } else {
                (4, 5)
            },
        )
        .with_test_mark(if mode.required() { 42 } else { 0 }),
    ));
    let live = Arc::new(AtomicBool::new(true));
    let closed = Arc::new(AtomicUsize::new(0));
    let factories = Arc::new(AtomicUsize::new(0));
    let factory_count = factories.clone();
    let close_count = closed.clone();
    let valid = live.clone();
    io.after_packet = Some(Box::new(move |packet| {
        if u16_at(packet, 10) == Operation::Reserved as u16
            && u64_at(packet, 24) == 6
            && packet[130] == 1
        {
            factory_count.fetch_add(1, Ordering::AcqRel);
            inbox.lock().unwrap().push_back(
                dns_transport::Incoming::fake(
                    raw,
                    &neg,
                    &slots,
                    &budget,
                    None,
                    facts.clone(),
                    valid.clone(),
                    close_count.clone(),
                    || {},
                )
                .unwrap(),
            );
        }
    }));
    if fault == Fault::NoPermit {
        issuer
            .authority
            .bootstrap_permit_live
            .store(false, Ordering::Release);
    }
    if fault == Fault::Backend {
        issuer.authority.fail_route_at = Some(6);
    }
    if fault == Fault::LateAck {
        io.delay_write_at = 6;
        *io.delayed_send.borrow_mut() = Some(issuer.authority.elapsed.clone());
    }
    let held = Arc::new(Mutex::new(None));
    let hold = held.clone();
    let route_budget = issuer.budget.routes.clone();
    let clock = issuer.authority.elapsed.clone();
    let valid = live.clone();
    io.on_request = Some(Box::new(move |seq| {
        if seq == 13 && fault == Fault::Expiry {
            clock.store(25_000_000, Ordering::Release);
        }
        if seq == 13 && fault == Fault::History {
            *hold.lock().unwrap() = Some(route_budget.reserve(4096 - route_budget.used()).unwrap());
        }
        if seq == 15 && fault == Fault::UnknownClose {
            valid.store(false, Ordering::Release);
        }
    }));
    if matches!(
        fault,
        Fault::NoWire | Fault::NoRelease | Fault::WrongLaunch | Fault::NoPermit
    ) {
        io.stop_after = 3;
        io.after_reply.borrow_mut().truncate(2);
    }
    if matches!(fault, Fault::Good | Fault::UnknownClose) {
        for (seq, id) in [(23, 2), (24, 3), (25, 1)] {
            append(&io, vec![legacy_close(&f, seq, id)]);
            io.stop_after += 1;
        }
    }
    let completed =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drive(&mut issuer, &io)));
    assert!(
        completed.is_ok(),
        "actual replies {:?}; factories {}",
        io.output
            .borrow()
            .iter()
            .map(|p| (u16_at(p, 10), p[130], u64_at(p, 24)))
            .collect::<Vec<_>>(),
        factories.load(Ordering::Acquire)
    );
    let out = io.output.borrow();
    if matches!(
        fault,
        Fault::NoWire | Fault::NoRelease | Fault::WrongLaunch | Fault::NoPermit
    ) {
        assert_eq!(out[2][130], 2, "{fault:?}");
        assert_eq!(factories.load(Ordering::Acquire), 0);
        return;
    }
    if matches!(fault, Fault::Peer | Fault::Namespace | Fault::LateAck) {
        assert!(
            out.iter()
                .all(|p| u16_at(p, 10) != wire::Kind::Grant as u16)
        );
        return;
    }
    if matches!(
        fault,
        Fault::WrongResponse | Fault::WrongQuestion | Fault::FutureAnchor | Fault::ForeignQuery
    ) {
        assert_eq!(out[6][130], 2, "{fault:?}");
    }
    if fault == Fault::Good || fault == Fault::UnknownClose {
        assert_eq!(
            grant_status(&out[numeric_index], &f),
            wire::Status::Allow,
            "trace {:?}",
            out.iter()
                .map(|p| (u16_at(p, 10), p[130]))
                .collect::<Vec<_>>()
        );
        assert_eq!(factories.load(Ordering::Acquire), 1);
        if fault == Fault::Good {
            let expected = [
                58, 56, 36, 36, 37, 39, 41, 58, 56, 36, 54, 19, 46, 46, 48, 48, 48, 48, 48, 48, 48,
                34, 34, 34,
            ];
            assert_eq!(
                out.iter().map(|p| u16_at(p, 10)).collect::<Vec<_>>(),
                expected
            );
            assert_eq!(out.len(), io.stop_after);
            assert_eq!(closed.load(Ordering::Acquire), 1);
            assert!(issuer.authority.live.is_empty());
            assert!(!issuer.unknown);
            for p in &out[numeric_index + 1..numeric_index + 10] {
                assert_eq!(p[130], 1);
            }
            for p in &out[21..] {
                assert!(matches!(
                    wire::Frame::decode(p, f.launch.binding, mode, true)
                        .unwrap()
                        .message,
                    wire::Message::CloseAck {
                        status: wire::CloseStatus::KnownClosed,
                        ..
                    }
                ));
            }
        } else {
            assert!(issuer.unknown);
            assert_eq!(closed.load(Ordering::Acquire), 1);
        }
    } else if matches!(fault, Fault::WrongMember | Fault::MixedCarrier) {
        assert_eq!(grant_status(&out[numeric_index], &f), wire::Status::Deny);
        assert_eq!(
            grant_status(&out[numeric_index + 1], &f),
            wire::Status::Allow
        );
        assert_eq!(issuer.authority.route_count, 6);
    } else {
        assert!(
            out.iter().all(|p| u16_at(p, 10) != wire::Kind::Grant as u16
                || grant_status(p, &f) != wire::Status::Allow),
            "{fault:?}"
        );
        assert!(
            !issuer.authority.datagram_bindings[&1]
                .1
                .bootstrap_spent
                .load(Ordering::Acquire)
                || fault == Fault::Backend
        );
    }
}
#[test]
fn codec5_network_udp_driver_publish_waiter_numeric_and_known_cleanup() {
    for mode in [Mode::Local, Mode::System] {
        run(mode, Fault::Good);
    }
}
#[test]
fn codec5_network_udp_driver_scope5_independence_and_permit_before_factory() {
    for fault in [
        Fault::NoWire,
        Fault::NoRelease,
        Fault::WrongLaunch,
        Fault::NoPermit,
    ] {
        run(Mode::System, fault);
    }
}
#[test]
fn codec5_network_udp_driver_strict_capture_query_member_and_tcp_alias_denied() {
    for fault in [
        Fault::WrongResponse,
        Fault::WrongQuestion,
        Fault::FutureAnchor,
        Fault::ForeignQuery,
        Fault::MixedCarrier,
        Fault::WrongMember,
        Fault::Peer,
        Fault::Namespace,
    ] {
        run(Mode::System, fault);
    }
}
#[test]
fn codec5_network_udp_driver_cancellation_expiry_backend_and_unknown_custody() {
    for fault in [
        Fault::Cancel(5),
        Fault::Cancel(7),
        Fault::Cancel(8),
        Fault::Cancel(9),
        Fault::LateAck,
        Fault::Backend,
        Fault::Expiry,
        Fault::History,
        Fault::UnknownClose,
    ] {
        run(Mode::System, fault);
    }
}
