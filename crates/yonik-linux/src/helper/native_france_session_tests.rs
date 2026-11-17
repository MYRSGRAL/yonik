//! Полный imported SS intent, одна capsule/launch/negotiation5 и actual issuer.
//! USER/Consumed и reviewed image records — injected leaf facts, не Go interop.
use super::super::super::super::super::bootstrap_binding;
use super::*;

fn france() -> yonik_engine::native_profile::ProfileIntent {
    let report = yonik_import::import_profiles(
        include_bytes!("../../../../tests/fixtures/xray-full-profile-seven.json").to_vec(),
    )
    .unwrap();
    let profile = report
        .entries
        .iter()
        .find_map(|e| match e {
            yonik_import::ProfileEntry::Xray(p) if p.name() == "FranceSS" => Some(p),
            _ => None,
        })
        .unwrap();
    yonik_engine::native_profile::ProfileIntent::from_profile(profile).unwrap()
}
fn stream(f: &Facts, cap: &wire::Capsule<'_>) -> Facts {
    let (scope, mask) = cap.subject_scope(0, 6).unwrap();
    assert_eq!(mask, 1);
    let endpoint = cap.dial_scope(scope, 0).unwrap().endpoint_index;
    Facts {
        compiled: f.compiled.clone(),
        original: Target::copy(cap.endpoint(endpoint).unwrap()).unwrap(),
        carrier: 6,
        subject: 0,
        launch: f.launch,
        reference: f.reference,
        asset: f.asset.clone(),
        addresses: f.addresses.clone(),
        member_calls: AtomicUsize::new(0),
        path: vec![(scope, 0)],
        endpoint,
        expiry: f.expiry,
        checked: AtomicUsize::new(0),
        observed: AtomicUsize::new(0),
        invalid_source: AtomicBool::new(false),
        change_after_choice: AtomicBool::new(false),
        failed_operation: AtomicUsize::new(0),
    }
}
fn script(tcp: &Facts, udp: &Facts) -> Vec<(Operation, Vec<u8>)> {
    let mut s = numeric_script(tcp);
    s.extend([
        (Operation::DatagramParentBind, parent(udp, 11)),
        (Operation::BundleAcquire, acquire(udp, true, 0, 11)),
        (Operation::Reserve, reserve(udp, true, 3, 11)),
        (Operation::Publish, hosts_publish(udp, 3, 11)),
        (Operation::DatagramParentBind, parent(udp, 12)),
        (Operation::BundleAcquire, acquire(udp, true, 0, 12)),
        (Operation::Reserve, reserve(udp, true, 3, 12)),
        (Operation::WaiterBind, hosts_bind(4, 2, 12)),
        (
            Operation::NumericAuthorize,
            numeric_body(udp, 2, [203, 0, 113, 80]),
        ),
    ]);
    s
}
#[test]
fn france_same_launch_schema5_tcp_udp_hosts_actual_issuer_independent_scopes() {
    for mode in [Mode::Local, Mode::System] {
        for fault in 0..5 {
            let tcp_authority = fault != 0;
            let (mut issuer, udp) = fixture_intent_flags(
                mode,
                "203.0.113.80".parse().unwrap(),
                1,
                true,
                [3; 32],
                17,
                16,
                Some(france()),
            );
            seed_parent(&mut issuer, &udp);
            let cap = wire::Capsule::decode(issuer.capsule.bytes(), &issuer.record.binding.digest)
                .unwrap();
            let tcp = stream(&udp, &cap);
            assert_eq!(cap.subject_kind(0).unwrap(), 2);
            assert_eq!(tcp.original.wire().bytes, b"fr.example.invalid");
            assert_eq!(udp.original.wire().port, 443);
            assert_ne!(
                issuer.record.binding.digest, [3; 32],
                "digest actual compiled full config, не synthetic старого fixture"
            );
            assert_ne!(tcp.path, udp.path);
            let start = issuer.authority.now();
            let b = bootstrap_binding::tests::datagram_binding(
                issuer.capsule.clone(),
                issuer.record,
                udp.asset.clone(),
                udp.reference,
                issuer.budget.clone(),
                start,
            );
            let t = bootstrap_binding::tests::tcp5_binding(
                issuer.capsule.clone(),
                issuer.record,
                tcp.asset.clone(),
                tcp.reference,
                issuer.budget.clone(),
                start,
            );
            assert!(b.source().is_none() && t.source().is_none());
            assert!(t.datagram_source(issuer.record).unwrap().is_none());
            let mut operations = if tcp_authority {
                script(&tcp, &udp)
            } else {
                numeric_script(&tcp)
            };
            match fault {
                2 => operations.insert(
                    15,
                    (
                        Operation::NumericAuthorize,
                        numeric_body(&udp, 2, [203, 0, 113, 81]),
                    ),
                ),
                3 => operations.push((
                    Operation::NumericAuthorize,
                    numeric_body(&udp, 2, [203, 0, 113, 80]),
                )),
                4 => operations.extend([
                    (Operation::Cancel, cancel_body(9, 2)),
                    (
                        Operation::NumericAuthorize,
                        numeric_body(&udp, 2, [203, 0, 113, 80]),
                    ),
                ]),
                _ => {}
            }
            let mut io = io5(&udp, &operations);
            io.datagram(b.datagram_source(issuer.record).unwrap().unwrap());
            io.datagram_wire = b.datagram_wire(issuer.record).unwrap();
            io.datagram_release = b.datagram_release(issuer.record).unwrap();
            // Legacy source намеренно присутствует: под5 его использовать нельзя.
            io.source = Some(Arc::new(tcp));
            if tcp_authority {
                io.tcp5 = t.tcp5_views(issuer.record).unwrap();
            }
            let owner_calls = issuer.authority.owner_count;
            drive(&mut issuer, &io);
            let out = io.output.borrow();
            assert_eq!(out.len(), operations.len());
            let tcp_frame =
                wire::Frame::decode(&out[6], issuer.record.binding, mode, true).unwrap();
            assert!(
                matches!(tcp_frame.message,wire::Message::Grant { status, .. } if status == if tcp_authority { wire::Status::Allow } else { wire::Status::Deny })
            );
            if tcp_authority {
                let udp_frame = wire::Frame::decode(
                    &out[if fault == 2 { 16 } else { 15 }],
                    issuer.record.binding,
                    mode,
                    true,
                )
                .unwrap();
                assert!(
                    matches!(
                        udp_frame.message,
                        wire::Message::Grant {
                            status: wire::Status::Allow,
                            class: 3,
                            flow: 0,
                            required: false,
                            fresh: 0,
                            ..
                        }
                    ),
                    "ответы (kind,reply,status)={:?}; contexts={:?} waiters={:?}; source={}",
                    out.iter()
                        .map(|b| (u16_at(b, 10), u64_at(b, 24), b[130]))
                        .collect::<Vec<_>>(),
                    issuer.dns.live.keys().collect::<Vec<_>>(),
                    issuer.dns.hosts_waiters.keys().collect::<Vec<_>>(),
                    bootstrap_binding::tests::interop_status(&b, 11)
                );
                assert!(issuer.negotiated.unwrap().datagram());
                assert!(
                    issuer
                        .hosts_permission_live(tcp_frame.header.object_id, true)
                        .is_ok()
                );
                assert_eq!(
                    issuer
                        .hosts_permission_live(udp_frame.header.object_id, true)
                        .is_ok(),
                    fault != 4
                );
                if fault == 2 {
                    assert_eq!(grant_status(&out[15], &udp), wire::Status::Deny);
                }
                if fault >= 3 {
                    assert_eq!(grant_status(out.last().unwrap(), &udp), wire::Status::Deny);
                }
                assert_ne!(tcp_frame.header.object_id, udp_frame.header.object_id);
                assert!(
                    issuer.dns.permissions[&tcp_frame.header.object_id]
                        .datagram
                        .is_none()
                );
                assert!(
                    issuer.dns.permissions[&udp_frame.header.object_id]
                        .datagram
                        .is_some()
                );
                assert_eq!(issuer.dns.permissions.len(), 2);
                assert_eq!(
                    issuer.authority.route_count, 3,
                    "USER + две независимые physical permission"
                );
                assert_eq!(issuer.authority.live.len(), if fault == 4 { 2 } else { 3 });
                assert!(!issuer.unknown);
            } else {
                assert_eq!(out[0][130], 2, "Source4/UDP5 не mint TCP5 context");
                assert!(issuer.dns.permissions.is_empty());
            }
            assert_eq!(
                issuer.authority.owner_count, owner_calls,
                "bootstrap не получает USER attribution"
            );
        }
    }
}
