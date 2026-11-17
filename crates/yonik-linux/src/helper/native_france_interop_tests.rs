//! Один imported config/capsule/launch; bootstrap ACK только actual run_issuer.
//! USER admission и kernel Consumed/Peer/route факты — общий explicit preseed.
use super::super::super::super::super::{SourceFlow, bootstrap_binding};
use super::*;

fn intent() -> yonik_engine::native_profile::ProfileIntent {
    let imported = yonik_import::import_profiles(
        include_bytes!("../../../../tests/fixtures/xray-full-profile-seven.json").to_vec(),
    )
    .unwrap();
    let p = imported
        .entries
        .iter()
        .find_map(|p| match p {
            yonik_import::ProfileEntry::Xray(p) if p.name() == "FranceSS" => Some(p),
            _ => None,
        })
        .unwrap();
    yonik_engine::native_profile::ProfileIntent::from_profile(p).unwrap()
}
fn seed_tcp(issuer: &mut Issuer<Fake>) -> Vec<(u16, u8)> {
    use super::super::super::super::super::Target;
    let mode = issuer.record.mode;
    let cap = issuer.capsule().unwrap();
    let (scope, mask) = cap.subject_scope(0, 6).unwrap();
    assert_eq!(mask, 1);
    let d = cap.dial_scope(scope, 0).unwrap();
    let endpoint = Target::copy(d.endpoint.unwrap()).unwrap();
    let (subject_id, chain, stream) = (d.subject, d.chain, d.stream);
    let mut tuple = match issuer_tests::open(mode, 32002) {
        wire::Message::OpenIngress { tuple, .. } => tuple,
        _ => unreachable!(),
    };
    tuple.protocol = 6;
    let original = Target::copy(wire::Destination {
        protocol: 6,
        family: 4,
        port: 443,
        bytes: &[203, 0, 113, 9],
    })
    .unwrap();
    issuer.authority.owner_forbidden = false;
    let owner = issuer
        .authority
        .owner(
            2,
            tuple,
            crate::attribution::native_session::OwnerReference::NONE,
        )
        .unwrap();
    let subject = issuer.authority.subject(&owner, 2, tuple).unwrap();
    issuer.flows.insert(
        2,
        Box::new(SourceFlow {
            numeric_only: false,
            tuple,
            original,
            subject,
            socket: (),
            root: None,
            request: 2,
        }),
    );
    issuer.next_flow = 2;
    let (grant, _) = issuer
        .authorize(
            2,
            0,
            &wire::Authorize {
                source_flow: 2,
                class: 1,
                subject: subject_id,
                chain,
                transport: stream,
                scope,
                branch: 0,
                original: original.wire(),
                effective: endpoint.wire(),
                resolver: u16::MAX,
                query: "",
                receipt: wire::Receipt {
                    kind: wire::ReceiptKind::None,
                    id: 0,
                },
            },
        )
        .unwrap();
    assert_eq!(grant, 2);
    let g = issuer.grants.get_mut(&2).unwrap();
    // USER admission skipped: IDs watermark2 отдельно от wire (ADMIT_ACK2).
    // request2 — reserved preseed marker обоих USER facts, не relayed AUTHORIZE.
    g.effective = original;
    g.sent.store(true, Ordering::Release);
    issuer.authority.owner_forbidden = true;
    vec![(scope, 0)]
}
pub(super) fn run(case: &str) {
    let mode = if case.starts_with("system-") {
        Mode::System
    } else {
        Mode::Local
    };
    let intent = intent();
    let (mut issuer, f) = fixture_intent_flags(
        mode,
        "203.0.113.80".parse().unwrap(),
        1,
        true,
        [3; 32],
        17,
        16,
        Some(intent),
    );
    // Тот же compiler result/probe credentials, не повторная компиляция intent.
    let bytes = f.compiled.as_ref().unwrap();
    assert_eq!(
        issuer.record.binding.digest,
        <[u8; 32]>::from(Sha256::digest(bytes))
    );
    let start = issuer.authority.now();
    let roles = [
        crate::helper::registry::BootstrapScope::Source,
        crate::helper::registry::BootstrapScope::Wire,
        crate::helper::registry::BootstrapScope::Release,
    ];
    let missing_udp = case.ends_with("missing-udp-scope");
    let missing_tcp = case.ends_with("missing-tcp-scope");
    let tcp_path = if missing_udp {
        vec![(issuer.capsule().unwrap().subject_scope(0, 6).unwrap().0, 0)]
    } else {
        super::super::datagram::seed_parent(&mut issuer, &f);
        issuer.grants.get_mut(&1).unwrap().effective = issuer.flows[&1].original;
        seed_tcp(&mut issuer)
    };
    let owners = issuer.authority.owner_count;
    let d = bootstrap_binding::tests::scoped5_binding(
        issuer.capsule.clone(),
        issuer.record,
        f.asset.clone(),
        f.reference,
        issuer.budget.clone(),
        start,
        (false, if missing_udp { &roles[1..] } else { &roles }),
    );
    let t = bootstrap_binding::tests::scoped5_binding(
        issuer.capsule.clone(),
        issuer.record,
        f.asset.clone(),
        f.reference,
        issuer.budget.clone(),
        start,
        (true, if missing_tcp { &roles[1..] } else { &roles }),
    );
    let consumed=issuer.flows.get(&1).map(|flow| { let tuple=flow.tuple; let original=flow.original;
        serde_json::json!({"protocol":tuple.protocol,"family":tuple.family,"local_port":tuple.local_port,"remote_port":tuple.remote_port,"local":hex(&tuple.local),"remote":hex(&tuple.remote),"original_port":original.port,"original":hex(original.wire().bytes)})
    });
    emit(serde_json::json!({"init":{
        "launch":hex(&issuer.record.encode().unwrap()),"snapshot":hex(&f.asset),"config":hex(bytes),"udp_path":f.path,"tcp_path":tcp_path,"subject":0,"watermark":2,"user_watermark":2,
        "owner_kind":if mode.required(){2}else{0},"owner_id":if mode.required(){77}else{0},"known_ns":if mode.required(){20_000_000}else{0},
        "consumed":consumed
    }}));
    let io = Stdio {
        tcp5: if missing_tcp {
            assert!(matches!(
                t.tcp5_views(issuer.record),
                Err(ServiceError::Unsupported)
            ));
            None
        } else {
            t.tcp5_views(issuer.record).unwrap()
        },
        diagnostic: d.clone(),
        record: issuer.record,
        budget: issuer.budget.clone(),
        source: None,
        datagram: d.datagram_source(issuer.record).unwrap(),
        datagram_wire: d.datagram_wire(issuer.record).unwrap(),
        datagram_release: d.datagram_release(issuer.record).unwrap(),
        dns_protocol: 17,
        descriptor: RefCell::new(None),
        negotiated: RefCell::new(None),
        inbox: Default::default(),
        transcript: None,
        producer: None,
        closed: Arc::new(AtomicUsize::new(0)),
        permit: issuer.authority.bootstrap_permit_live.clone(),
        no_permit: false,
        before_reply: Cell::new(false),
        slots: SidebandCredits::new(),
        credits: Default::default(),
    };
    let result = run_issuer(
        &mut issuer,
        &io,
        8,
        997,
        &AtomicBool::new(false),
        &AtomicBool::new(false),
    );
    if missing_udp {
        assert!(result.is_err());
        assert!(issuer.negotiated.is_none());
        assert_eq!(
            issuer.authority.route_count, 0,
            "factory отказ до USER seed/effects"
        );
        assert!(issuer.authority.live.is_empty());
        assert_eq!(issuer.dns.count(), 0);
        emit(
            serde_json::json!({"rust_done":true,"france":true,"setup_denied":true,"routes":0,"retained_routes":issuer.authority.live,"contexts":0,"flows":issuer.flows.len(),"services":0,"unknown":issuer.unknown}),
        );
        return;
    }
    eprintln!(
        "France issuer exit={result:?} used={}",
        issuer.budget.dynamic.used()
    );
    assert_eq!(issuer.authority.owner_count, owners);
    assert!(!issuer.unknown);
    assert!(
        issuer.authority.live.is_empty(),
        "включая обе USER seed routes"
    );
    assert_eq!(issuer.dns.count(), 0);
    assert!(issuer.flows.is_empty() && issuer.services.is_empty());
    emit(
        serde_json::json!({"rust_done":true,"france":true,"owners":owners,"routes":issuer.authority.route_count,"retained_routes":issuer.authority.live,"contexts":issuer.dns.count(),"flows":issuer.flows.len(),"services":issuer.services.len(),"unknown":issuer.unknown,"release_attempts":issuer.authority.release_attempts}),
    );
}
