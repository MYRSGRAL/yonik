use serde_json::{Value, json};
use std::num::NonZeroU16;
use yonik_engine::{SystemTun, native_profile::*};
use yonik_import::{NativeProfile, ProfileEntry, import_profiles};
fn profiles() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/xray-full-profile-native-schema.json"
    ))
    .unwrap()
}
fn profile(v: &Value) -> NativeProfile {
    match import_profiles(serde_json::to_vec(v).unwrap())
        .unwrap()
        .entries
        .remove(0)
    {
        ProfileEntry::Xray(p) => p,
        _ => panic!("Нужен native profile"),
    }
}
fn plan() -> OwnedRuntimePlan {
    OwnedRuntimePlan::new(
        NonZeroU16::new(10808).unwrap(),
        NonZeroU16::new(10809).unwrap(),
    )
    .unwrap()
}
fn emitted(c: &yonik_engine::CompiledConfig) -> Value {
    let mut b = Vec::new();
    c.write_sensitive(&mut b).unwrap();
    serde_json::from_slice(&b).unwrap()
}
#[test]
fn seven_graphs_preserve_provider_semantics_in_both_modes() {
    for v in profiles() {
        let p = profile(&v);
        let g = validate_profile(&p).unwrap();
        assert!(!g.egress().physical().is_empty());
        let c = compile_profile_local(&p, &plan()).unwrap();
        let local = emitted(&c);
        assert_eq!(local["outbounds"], v["outbounds"]);
        assert_eq!(local["routing"], v["routing"]);
        assert_eq!(local["dns"], v["dns"]);
        assert_eq!(local["observatory"], v["observatory"]);
        assert_eq!(
            local["inbounds"][1]["settings"]["accounts"][0]["pass"],
            c.probe_auth().unwrap().password()
        );
        let tun = SystemTun::new(1, 1500, 42, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let system = compile_profile_system(&p, &plan().with_system(tun)).unwrap();
        let s = emitted(system.config());
        assert_eq!(s["inbounds"][2]["protocol"], "tun");
        assert_eq!(s["routing"], local["routing"]);
        assert_eq!(s["outbounds"][0]["streamSettings"]["sockopt"]["mark"], 42);
    }
}
#[test]
fn ordered_rules_prefix_sets_and_physical_chains() {
    let mut v = profiles().remove(0);
    v["outbounds"][0]["proxySettings"] = json!({"tag":"edge-b","transportLayer":true});
    let g = validate_profile(&profile(&v)).unwrap();
    assert_eq!(g.selector_sets()[0].1, vec!["edge-a", "edge-b"]);
    assert_eq!(g.egress().physical().len(), 1);
    assert_eq!(g.egress().physical()[0].host(), "192.0.2.2");
    assert_eq!(g.egress().subject_endpoints()[0].0, "edge-a");
    assert_eq!(g.egress().subject_endpoints()[0].1.host(), "192.0.2.1");
    assert_eq!(g.egress().chains(), &[("edge-a".into(), "edge-b".into())]);
    v["outbounds"][1]["proxySettings"] = json!({"tag":"edge-a","transportLayer":true});
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::Cycle
    );
}
#[test]
fn protocol_and_security_effects_are_closed() {
    let base = profiles().remove(5);
    for (path, value, error) in [
        (
            "/outbounds/0/streamSettings/finalmask/quicParams/congestion",
            json!("unknown"),
            ProfileCompileError::UnsupportedCongestion,
        ),
        (
            "/outbounds/0/streamSettings/finalmask/quicParams/bbrProfile",
            json!("unknown"),
            ProfileCompileError::UnsupportedCongestion,
        ),
        (
            "/outbounds/0/protocol",
            json!("unknown"),
            ProfileCompileError::UnsupportedProtocol,
        ),
    ] {
        let mut v = base.clone();
        *v.pointer_mut(path).unwrap() = value;
        assert_eq!(validate_profile(&profile(&v)).unwrap_err(), error);
    }
    for (key, value) in [
        ("api", json!({"listen":"0.0.0.0:1"})),
        ("policy", json!({})),
        ("unknown", json!(true)),
    ] {
        let mut v = base.clone();
        v[key] = value;
        assert_eq!(
            validate_profile(&profile(&v)).unwrap_err(),
            ProfileCompileError::UnsupportedField
        );
    }
    let mut v = base;
    v["outbounds"][0]["streamSettings"]["tlsSettings"]["certificateFile"] = json!("/secret");
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::UnsupportedField
    );
}
#[test]
fn owned_listener_mapping_is_explicit_and_references_checked() {
    let mut v = profiles().remove(3);
    v["inbounds"] = json!([{"tag":"provider","port":1234,"listen":"0.0.0.0","protocol":"socks"}]);
    v["routing"] =
        json!({"rules":[{"type":"field","inboundTag":["provider"],"outboundTag":"edge"}]});
    assert!(matches!(
        compile_profile_local(&profile(&v), &plan()),
        Err(ProfileCompileError::Ownership)
    ));
    let p = plan().map_ingress("provider", OwnedIngress::Local).unwrap();
    let c = emitted(&compile_profile_local(&profile(&v), &p).unwrap());
    assert_eq!(
        c["routing"]["rules"][0]["inboundTag"],
        json!(["yonik-owned-local", "yonik-owned-probe"])
    );
    v["routing"]["rules"][0]["outboundTag"] = json!("missing");
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::Reference
    );
}
#[test]
fn resources_scripts_and_masks_do_not_gain_authority() {
    let mut v = profiles().remove(0);
    v["routing"]["rules"][0]["domain"] = json!(["geosite:private"]);
    assert_eq!(
        compile_profile_local(&profile(&v), &plan()).unwrap_err(),
        ProfileCompileError::ResourceRequired
    );
    v = profiles().remove(1);
    v["outbounds"][0]["streamSettings"]["finalmask"]["tcp"][0]["type"] = json!("noise");
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::UnsupportedMask
    );
    v = profiles().remove(0);
    v["routing"]["script"] = json!("script");
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::UnsupportedField
    );
}
#[test]
fn egress_protocol_bootstrap_and_direct_are_separate() {
    let mut v = profiles().remove(5);
    v["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIP"}}));
    let g = validate_profile(&profile(&v)).unwrap();
    assert_eq!(g.egress().physical()[0].protocol(), TransportProtocol::Udp);
    assert!(g.egress().physical()[0].requires_bootstrap());
    assert_eq!(g.egress().direct_subjects(), &["direct"]);
}

#[test]
fn owned_resources_are_explicit_pinned_and_scoped_to_matchers() {
    struct Catalog;
    impl VerifiedNativeResources for Catalog {
        fn lookup(
            &self,
            r: &OwnedResourceRequirement,
        ) -> Option<yonik_engine::resource_bundle::ExternalRef> {
            Some(yonik_engine::resource_bundle::ExternalRef {
                engine: yonik_engine::Engine::Xray,
                digest: [1; 32],
                bytes: 100,
                records: 1,
                kind: r.kind(),
                format_version: 1,
            })
        }
    }
    let mut v = profiles().remove(0);
    v["routing"]["rules"][0]["domain"] = json!(["geosite:synthetic"]);
    v["outbounds"][0]["settings"]["servers"][0]["password"] = json!("geosite:credential-must-stay");
    let p = profile(&v);
    let graph = validate_profile(&p).unwrap();
    assert_eq!(graph.resources().len(), 1);
    let runtime = plan().bind_resources(&graph, &Catalog).unwrap();
    let value = emitted(&compile_profile_local(&p, &runtime).unwrap());
    assert!(
        value["routing"]["rules"][0]["domain"][0]
            .as_str()
            .unwrap()
            .starts_with("ext:r-0101")
    );
    assert_eq!(
        value["outbounds"][0]["settings"]["servers"][0]["password"],
        "geosite:credential-must-stay"
    );
    assert_eq!(graph.probe().unwrap().subjects(), &["edge-a", "edge-b"]);
    assert_eq!(
        graph.egress().resolvers()[0].endpoint().host(),
        "192.0.2.53"
    );
}
#[test]
fn bounded_graph_and_duplicate_keys_fail_before_emission() {
    assert!(
        import_profiles(
            br#"{"outbounds":[{"tag":"a","protocol":"freedom","protocol":"dns"}]}"#.to_vec()
        )
        .is_err()
    );
    let mut v = json!({"outbounds":[]});
    for i in 0..257 {
        v["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"tag":format!("edge-{i}"),"protocol":"freedom"}));
    }
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::Budget
    );
    let mut v = profiles().remove(0);
    v["outbounds"][1]["tag"] = v["outbounds"][0]["tag"].clone();
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::Reference
    );
}
#[test]
fn runtime_bytes_bind_ports_semantics_and_random_probe_credentials() {
    let v = profiles().remove(3);
    let p = profile(&v);
    let c = compile_profile_local(&p, &plan()).unwrap();
    let a = emitted(&c);
    let runtime = OwnedRuntimePlan::new(
        NonZeroU16::new(12000).unwrap(),
        NonZeroU16::new(12001).unwrap(),
    )
    .unwrap();
    let b = emitted(&compile_profile_local(&p, &runtime).unwrap());
    assert_ne!(a["inbounds"][0]["port"], b["inbounds"][0]["port"]);
    assert_ne!(a["inbounds"][1]["port"], b["inbounds"][1]["port"]);
    let mut changed = v;
    changed["outbounds"][0]["settings"]["servers"][0]["port"] = json!(8443);
    let b = emitted(&compile_profile_local(&profile(&changed), &plan()).unwrap());
    assert_ne!(a["outbounds"], b["outbounds"]);
    assert!(!format!("{c:?}").contains("synthetic"));
}
#[test]
fn malformed_native_values_fail_before_runtime() {
    let mut v = profiles().remove(0);
    v["observatory"]["probeInterval"] = json!("0s");
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::Budget
    );
    v = profiles().remove(0);
    v["routing"]["rules"][0]["port"] = json!("65536");
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::Schema
    );
    v = profiles().remove(5);
    v["outbounds"][0]["mux"] = json!({"enabled":true,"concurrency":-1,"xudpConcurrency":16});
    assert!(validate_profile(&profile(&v)).is_ok());
    v["outbounds"][0]["mux"]["concurrency"] = json!(-2);
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::Budget
    );
}
#[test]
fn system_probe_follows_checked_system_ingress() {
    let mut v = profiles().remove(3);
    v["inbounds"] = json!([{"tag":"provider","protocol":"socks","sniffing":{"enabled":true,"routeOnly":true,"destOverride":["tls"]}}]);
    v["routing"] =
        json!({"rules":[{"type":"field","inboundTag":["provider"],"outboundTag":"edge"}]});
    let tun = SystemTun::new(1, 1500, 42, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
    let plan = plan()
        .with_system(tun)
        .map_ingress("provider", OwnedIngress::System)
        .unwrap();
    let compiled = compile_profile_system(&profile(&v), &plan).unwrap();
    let value = emitted(compiled.config());
    assert_eq!(
        value["routing"]["rules"][0]["inboundTag"],
        json!(["system-tun", "yonik-owned-probe"])
    );
    assert_eq!(
        value["inbounds"][1]["sniffing"],
        value["inbounds"][2]["sniffing"]
    );
}
