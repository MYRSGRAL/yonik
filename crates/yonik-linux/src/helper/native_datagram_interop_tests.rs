//! Только test transport и preseed USER/Consumed; все UDP bootstrap ответы — issuer.
use super::*;

pub(super) fn run(case: &str) {
    let mode = if case.starts_with("system-") {
        Mode::System
    } else {
        Mode::Local
    };
    let digest = Sha256::digest(b"{}").into();
    let network = case.contains("udp-network-");
    let tcp = network && case.contains("-tcp-");
    let (mut issuer, f) = super::super::datagram::fixture5_snapshot(
        mode,
        if network { 2 } else { 1 },
        digest,
        if tcp { 20 } else { 16 },
    );
    let binding = super::super::super::super::super::bootstrap_binding::tests::datagram_binding(
        issuer.capsule.clone(),
        f.launch,
        f.asset.clone(),
        f.reference,
        issuer.budget.clone(),
        issuer.authority.now(),
    );
    let original = issuer.flows[&1].original;
    // Общий USER preseed описывает requested logical destination, не SS server.
    issuer.grants.get_mut(&1).unwrap().effective = original;
    let tuple = issuer.flows[&1].tuple;
    let preseed_owners = issuer.authority.owner_count;
    emit(serde_json::json!({"init":{
        "launch":hex(&f.launch.encode().unwrap()),"snapshot":hex(&f.asset),"config":"7b7d",
        "path":f.path,"subject":f.subject,
        "user":{"grant":1,"flow":1,"revision":1,"owner_kind":if mode.required(){2}else{0},
            "owner_id":if mode.required(){77}else{0},"known_ns":if mode.required(){20_000_000}else{0}},
        "consumed":{"protocol":tuple.protocol,"family":tuple.family,"local_port":tuple.local_port,
            "remote_port":tuple.remote_port,"local":hex(&tuple.local),"remote":hex(&tuple.remote),
            "original_port":original.port,"original":hex(original.wire().bytes)}
    }}));
    let io = Stdio {
        tcp5: None,
        diagnostic: binding.clone(),
        record: f.launch,
        budget: issuer.budget.clone(),
        source: None,
        datagram: binding.datagram_source(f.launch).unwrap(),
        datagram_wire: if network {
            binding.datagram_wire(f.launch).unwrap()
        } else {
            None
        },
        datagram_release: if network {
            binding.datagram_release(f.launch).unwrap()
        } else {
            None
        },
        dns_protocol: if tcp { 6 } else { 17 },
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
    let _closed = run_issuer(
        &mut issuer,
        &io,
        8,
        997,
        &AtomicBool::new(false),
        &AtomicBool::new(false),
    );
    eprintln!(
        "interop issuer exit: {_closed:?}; dynamic={}",
        issuer.budget.dynamic.used()
    );
    if _closed.is_err() {
        for (id, b) in &issuer.dns.live {
            eprintln!(
                "interop retained context{id}: query={} hops={:?}",
                b.query,
                b.hops
                    .iter()
                    .map(|h| (h.index, h.scope, h.branch, h.carrier))
                    .collect::<Vec<_>>()
            );
        }
        eprintln!(
            "interop retained custody: routes={:?}; services={:?}; unknown={}",
            issuer.authority.live,
            issuer.services.keys().collect::<Vec<_>>(),
            issuer.unknown
        );
    }
    assert_eq!(issuer.authority.owner_count, preseed_owners); // Никаких flow0 owner calls.
    assert_eq!(
        issuer.authority.live.len(),
        usize::from(!case.ends_with("parent-cancel")),
        "bootstrap route retired; USER seed остаётся live"
    );
    assert!(!issuer.unknown);
    emit(
        serde_json::json!({"rust_done":true,"datagram":true,"routes":issuer.authority.route_count,
        "owners":issuer.authority.owner_count,"retained_routes":issuer.authority.live,
        "release_attempts":issuer.authority.release_attempts,"contexts":issuer.dns.count(),
        "services":issuer.services.keys().copied().collect::<Vec<_>>(),"unknown":issuer.unknown,
        "preseed_user_routes":usize::from(!case.ends_with("parent-cancel")),"preseed_owners":preseed_owners,
        "network":network,"resolver_protocol":if tcp{6}else{17},"receiver_consumed_closes":io.closed.load(Ordering::Acquire)}),
    );
}
