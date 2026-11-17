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
fn unbound_plan() -> OwnedRuntimePlan {
    OwnedRuntimePlan::new(
        NonZeroU16::new(10808).unwrap(),
        NonZeroU16::new(10809).unwrap(),
    )
    .unwrap()
}
fn plan() -> OwnedRuntimePlan {
    // SYNTHETIC: даже отсутствие DNS app включает native localdns fallback.
    unbound_plan()
        .bind_system_resolver(&SyntheticBindings)
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
    assert_eq!(g.egress().physical().len(), 2);
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
fn pinned_chain_emits_dialer_proxy_without_removed_proxy_settings() {
    for existing_stream in [false, true] {
        let mut value = profiles().remove(0);
        value["outbounds"][0]["proxySettings"] = json!({"tag":"edge-b","transportLayer":true});
        if !existing_stream {
            value["outbounds"][0]
                .as_object_mut()
                .unwrap()
                .remove("streamSettings");
        }
        let p = profile(&value);
        let compiled = compile_profile_local(&p, &plan()).unwrap();
        let config = emitted(&compiled);
        assert!(config["outbounds"][0].get("proxySettings").is_none());
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"],
            "edge-b"
        );
        let tun = SystemTun::new(1, 1500, 42, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        let system = compile_profile_system(&p, &plan().with_system(tun)).unwrap();
        let system = emitted(system.config());
        assert!(system["outbounds"][0].get("proxySettings").is_none());
        assert_eq!(
            system["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"],
            "edge-b"
        );
        assert_eq!(
            system["outbounds"][0]["streamSettings"]["sockopt"]["mark"],
            42
        );
        assert_eq!(
            validate_profile(&p).unwrap().egress().chains(),
            &[("edge-a".into(), "edge-b".into())]
        );
    }
}

#[test]
fn pinned_xhttp_h3_has_udp_physical_transport() {
    let mut value = profiles().remove(4);
    value["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] = json!(["h3"]);
    let graph = validate_profile(&profile(&value)).unwrap();
    assert_eq!(
        graph.egress().physical()[0].protocol(),
        TransportProtocol::Udp
    );
    value["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] = json!(["h3", "h2"]);
    let graph = validate_profile(&profile(&value)).unwrap();
    assert_eq!(
        graph.egress().physical()[0].protocol(),
        TransportProtocol::Tcp
    );
}

#[test]
fn pinned_shadowsocks_udp_bypasses_configured_grpc_transport() {
    let value = json!({"outbounds":[{"tag":"edge","protocol":"shadowsocks","settings":{"servers":[{"address":"192.0.2.3","port":443,"method":"aes-128-gcm","password":"synthetic"}]},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"fixture"}}}]});
    let graph = validate_profile(&profile(&value)).unwrap();
    let endpoints = graph.egress().physical();
    assert_eq!(endpoints.len(), 2);
    assert!(
        endpoints
            .iter()
            .any(|endpoint| endpoint.protocol() == TransportProtocol::Tcp)
    );
    assert!(
        endpoints
            .iter()
            .any(|endpoint| endpoint.protocol() == TransportProtocol::Udp)
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
    v["outbounds"][0]["settings"]["servers"][0]["method"] = json!("aes-128-gcm");
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
    .unwrap()
    .bind_system_resolver(&SyntheticBindings)
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

struct SyntheticBindings;
impl VerifiedNativeResources for SyntheticBindings {
    fn lookup(
        &self,
        r: &OwnedResourceRequirement,
    ) -> Option<yonik_engine::resource_bundle::ExternalRef> {
        Some(yonik_engine::resource_bundle::ExternalRef {
            engine: yonik_engine::Engine::Xray,
            digest: if r.kind() == yonik_engine::resource_bundle::ResourceKind::Domains {
                [1; 32]
            } else {
                [2; 32]
            },
            bytes: 100,
            records: 1,
            kind: r.kind(),
            format_version: 1,
        })
    }
}
impl VerifiedSystemResolver for SyntheticBindings {
    fn snapshot_digest(&self) -> [u8; 32] {
        [3; 32]
    }
    fn servers(&self) -> Vec<std::net::SocketAddr> {
        vec![std::net::SocketAddr::from(([192, 0, 2, 53], 53))]
    }
}
fn provider_shape(mut v: Value) -> Value {
    let sniff = json!({"enabled":true,"routeOnly":true,"destOverride":["http","tls","quic"]});
    v["inbounds"] = json!([
        {"tag":"fixture-socks","protocol":"socks","listen":"0.0.0.0","port":1000,"settings":{"udp":true,"auth":"noauth"},"sniffing":sniff},
        {"tag":"fixture-http","protocol":"http","listen":"0.0.0.0","port":1001,"sniffing":sniff}
    ]);
    let domains: Vec<_> = (0..11)
        .map(|n| format!("geosite:fixture-category-{n}"))
        .collect();
    v["dns"] = json!({"hosts":{"dns.fixture.invalid":"192.0.2.53"},"queryStrategy":"UseIP","disableFallbackIfMatch":true,"servers":[
        {"address":"localhost","domains":["domain:fixture.invalid"],"skipFallback":true},
        {"tag":"fixture-dns-a","address":"https://dns.fixture.invalid/query","domains":domains[..6],"finalQuery":true},
        {"tag":"fixture-dns-b","address":"https://backup.fixture.invalid/query","domains":domains[6..],"skipFallback":true}
    ]});
    let primary = v["outbounds"][0]["tag"].clone();
    v["outbounds"].as_array_mut().unwrap().extend([
        json!({"tag":"fixture-direct","protocol":"freedom","settings":{"domainStrategy":"UseIP"}}),
        json!({"tag":"fixture-dns","protocol":"dns"}),
        json!({"tag":"fixture-block","protocol":"blackhole"}),
    ]);
    if v.get("routing").is_none() {
        v["routing"] = json!({"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","network":"tcp,udp","outboundTag":primary}]});
    }
    let mut rules = vec![
        json!({"type":"field","inboundTag":["fixture-dns-a"],"outboundTag":"fixture-direct"}),
        json!({"type":"field","inboundTag":["fixture-dns-b"],"outboundTag":primary}),
        json!({"type":"field","inboundTag":["fixture-socks","fixture-http"],"port":"53","outboundTag":"fixture-dns"}),
        json!({"type":"field","ip":["geoip:fixture-private"],"outboundTag":"fixture-direct"}),
        json!({"type":"field","domain":["geosite:fixture-route"],"outboundTag":"fixture-block"}),
    ];
    rules.extend(v["routing"]["rules"].as_array().unwrap().iter().cloned());
    v["routing"]["rules"] = json!(rules);
    v["meta"] = json!({"display":"synthetic-only"});
    v
}
fn bound_plan(graph: &ValidatedGraph, system: bool) -> OwnedRuntimePlan {
    let mut p = plan()
        .bind_resources(graph, &SyntheticBindings)
        .unwrap()
        .bind_system_resolver(&SyntheticBindings)
        .unwrap();
    if system {
        p = p.with_system(
            SystemTun::new(1, 1500, 42, vec!["198.18.0.1/30".parse().unwrap()]).unwrap(),
        );
    }
    for i in graph.ingresses() {
        p = p
            .map_ingress(
                i.tag(),
                if system {
                    OwnedIngress::System
                } else {
                    OwnedIngress::Local
                },
            )
            .unwrap();
    }
    p
}
#[test]
fn seven_full_provider_shapes_preserve_dns_routing_and_owned_aliases() {
    // SYNTHETIC_BINDING_NO_DAT_PROOF: ни lookup, ни OS resolver не исполняются.
    for v in profiles().into_iter().map(provider_shape) {
        let p = profile(&v);
        let graph = validate_profile(&p).unwrap();
        assert_eq!(graph.resources().len(), 13);
        assert_eq!(graph.ingresses().len(), 2);
        assert_eq!(graph.egress().system_resolvers().len(), 1);
        assert_eq!(graph.egress().resolvers().len(), 2);
        assert_eq!(
            graph.ingresses()[0].protocol(),
            ProviderIngressProtocol::Socks
        );
        assert_eq!(
            graph.ingresses()[1].protocol(),
            ProviderIngressProtocol::Http
        );
        assert!(matches!(
            compile_profile_local(&p, &unbound_plan()),
            Err(ProfileCompileError::ResourceRequired)
        ));
        for system in [false, true] {
            let runtime = bound_plan(&graph, system);
            let value = if system {
                emitted(compile_profile_system(&p, &runtime).unwrap().config())
            } else {
                emitted(&compile_profile_local(&p, &runtime).unwrap())
            };
            assert_eq!(value["observatory"], v["observatory"]);
            assert_eq!(value["routing"]["balancers"], v["routing"]["balancers"]);
            assert_eq!(value["dns"]["servers"][0], v["dns"]["servers"][0]);
            assert_eq!(value["dns"]["disableFallbackIfMatch"], true);
            assert_eq!(
                value["routing"]["rules"].as_array().unwrap().len(),
                v["routing"]["rules"].as_array().unwrap().len()
            );
            for (before, after) in v["routing"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .zip(value["routing"]["rules"].as_array().unwrap())
            {
                assert_eq!(before["outboundTag"], after["outboundTag"]);
                assert_eq!(before["balancerTag"], after["balancerTag"]);
            }
            assert_eq!(
                value["routing"]["rules"][2]["inboundTag"],
                json!([
                    if system {
                        "system-tun"
                    } else {
                        "yonik-owned-local"
                    },
                    "yonik-owned-probe"
                ])
            );
            assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
            assert_eq!(
                value["inbounds"][1]["sniffing"],
                value["inbounds"][if system { 2 } else { 0 }]["sniffing"]
            );
        }
    }
}
#[test]
fn alias_conflicts_are_checked_per_rule_and_sniffing() {
    let mut v = provider_shape(profiles().remove(3));
    v["routing"]["rules"][2]["inboundTag"] = json!(["fixture-socks"]);
    let p = profile(&v);
    let g = validate_profile(&p).unwrap();
    assert!(matches!(
        compile_profile_local(&p, &bound_plan(&g, false)),
        Err(ProfileCompileError::Ownership)
    ));
    v = provider_shape(profiles().remove(3));
    v["inbounds"][1]["sniffing"]["routeOnly"] = json!(false);
    let p = profile(&v);
    let g = validate_profile(&p).unwrap();
    assert!(matches!(
        compile_profile_local(&p, &bound_plan(&g, false)),
        Err(ProfileCompileError::Ownership)
    ));
}
#[test]
fn ss2022_checks_every_psk_without_flattening_identity_chain() {
    let mut v = profiles().remove(3);
    let p = profile(&v);
    let g = validate_profile(&p).unwrap();
    assert_eq!(g.egress().physical().len(), 2);
    assert_eq!(g.egress().physical()[0].protocol(), TransportProtocol::Tcp);
    assert_eq!(g.egress().physical()[1].protocol(), TransportProtocol::Udp);
    let value = emitted(&compile_profile_local(&p, &plan()).unwrap());
    assert_eq!(value["outbounds"], v["outbounds"]);
    v["outbounds"][0]["settings"]["servers"][0]["password"] =
        json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:invalid");
    assert_eq!(
        validate_profile(&profile(&v)).unwrap_err(),
        ProfileCompileError::Schema
    );
}
#[test]
fn system_resolver_binding_is_required_without_replacing_provider_dns() {
    let mut v = profiles().remove(3);
    v["dns"] = json!({"servers":["localhost"]});
    let p = profile(&v);
    assert!(matches!(
        compile_profile_local(&p, &unbound_plan()),
        Err(ProfileCompileError::ResourceRequired)
    ));
    let rt = plan().bind_system_resolver(&SyntheticBindings).unwrap();
    assert_eq!(
        rt.system_resolver_binding().unwrap().snapshot_digest(),
        &[3; 32]
    );
    assert_eq!(
        emitted(&compile_profile_local(&p, &rt).unwrap())["dns"],
        v["dns"]
    );
}

#[test]
fn external_matchers_and_inverted_geoip_require_explicit_ownership() {
    for (field, matcher) in [
        ("domain", "ext-site:provider.dat:TEST"),
        ("domain", "ext-domain:provider.dat:TEST"),
        ("domain", "ext:provider.dat:TEST"),
        ("ip", "ext-ip:provider.dat:TEST"),
        ("ip", "!ext:provider.dat:TEST"),
        ("ip", "!!!ext-ip:provider.dat:TEST"),
        ("ip", "!geoip:TEST"),
        ("ip", "!!geoip:TEST"),
    ] {
        let mut v = profiles().remove(3);
        v["routing"] = json!({"rules":[{"type":"field",field:[matcher],"outboundTag":"edge"}]});
        assert_eq!(
            validate_profile(&profile(&v)).unwrap_err(),
            ProfileCompileError::ResourceRequired
        );
    }
    for matcher in [
        "ext-site:provider.dat:TEST",
        "ext-domain:provider.dat:TEST",
        "ext:provider.dat:TEST",
    ] {
        let mut v = profiles().remove(3);
        v["dns"] = json!({"servers":[{"address":"192.0.2.53","domains":[matcher]}]});
        assert_eq!(
            validate_profile(&profile(&v)).unwrap_err(),
            ProfileCompileError::ResourceRequired
        );
        v["dns"] = json!({"hosts":{matcher:"192.0.2.1"},"servers":["192.0.2.53"]});
        assert_eq!(
            validate_profile(&profile(&v)).unwrap_err(),
            ProfileCompileError::ResourceRequired
        );
    }
    let mut v = profiles().remove(3);
    v["routing"] = json!({"rules":[{"type":"field","domain":["regexp:^ext-site:literal$","!geoip:literal"],"outboundTag":"edge"}]});
    let p = profile(&v);
    assert!(validate_profile(&p).unwrap().resources().is_empty());
    assert_eq!(
        emitted(&compile_profile_local(&p, &plan()).unwrap())["routing"],
        v["routing"]
    );
}

#[test]
fn implicit_system_dns_requires_binding_in_both_modes() {
    for dns in [
        None,
        Some(json!({})),
        Some(json!({"servers":[]})),
        Some(json!({"tag":"dns-owned","servers":[]})),
    ] {
        let mut v = profiles().remove(3);
        if let Some(dns) = dns {
            v["dns"] = dns;
        } else {
            v.as_object_mut().unwrap().remove("dns");
        }
        let p = profile(&v);
        let graph = validate_profile(&p).unwrap();
        assert_eq!(graph.egress().system_resolvers().len(), 1);
        assert_eq!(
            compile_profile_local(&p, &unbound_plan()).unwrap_err(),
            ProfileCompileError::ResourceRequired
        );
        let tun = || SystemTun::new(1, 1500, 42, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        assert!(matches!(
            compile_profile_system(&p, &unbound_plan().with_system(tun())),
            Err(ProfileCompileError::ResourceRequired)
        ));
        let rt = plan().bind_system_resolver(&SyntheticBindings).unwrap();
        let local = emitted(&compile_profile_local(&p, &rt).unwrap());
        assert_eq!(local.get("dns"), v.get("dns"));
        let system = compile_profile_system(&p, &rt.with_system(tun())).unwrap();
        assert_eq!(emitted(system.config()).get("dns"), v.get("dns"));
    }
}
#[test]
fn resource_budget_counts_unique_dats_and_rejects_conflicting_descriptors() {
    struct Catalog {
        conflict: bool,
    }
    impl VerifiedNativeResources for Catalog {
        fn lookup(
            &self,
            r: &OwnedResourceRequirement,
        ) -> Option<yonik_engine::resource_bundle::ExternalRef> {
            let mut reference = SyntheticBindings.lookup(r)?;
            reference.bytes = 100 * 1024 * 1024;
            if self.conflict {
                reference.digest = [1; 32];
            }
            Some(reference)
        }
    }
    let graph = validate_profile(&profile(&provider_shape(profiles().remove(3)))).unwrap();
    assert!(
        plan()
            .bind_resources(&graph, &Catalog { conflict: false })
            .is_ok()
    );
    assert!(matches!(
        plan().bind_resources(&graph, &Catalog { conflict: true }),
        Err(ProfileCompileError::ResourceRequired)
    ));
}
#[test]
fn system_resolver_binding_rejects_empty_or_unbounded_snapshots() {
    struct Resolver {
        count: usize,
        digest: [u8; 32],
    }
    impl VerifiedSystemResolver for Resolver {
        fn snapshot_digest(&self) -> [u8; 32] {
            self.digest
        }
        fn servers(&self) -> Vec<std::net::SocketAddr> {
            vec![std::net::SocketAddr::from(([192, 0, 2, 53], 53)); self.count]
        }
    }
    for (count, digest) in [(0, [1; 32]), (17, [1; 32]), (1, [0; 32])] {
        assert!(matches!(
            plan().bind_system_resolver(&Resolver { count, digest }),
            Err(ProfileCompileError::ResourceRequired)
        ));
    }
}

#[test]
fn france_ss2022_keeps_full_provider_graph_through_intent_and_compile() {
    let source = include_str!("../../../tests/fixtures/xray-full-profile-france-synthetic.json");
    let mut original: Vec<Value> = serde_json::from_str(source).unwrap();
    let mut expected = original.remove(0);
    let report = import_profiles(source.as_bytes().to_vec()).expect("Импорт массива France");
    let [ProfileEntry::Xray(profile)] = report.entries.as_slice() else {
        panic!("Ожидался один профиль Xray");
    };
    assert_eq!(profile.ordinal(), 0);
    let graph = validate_profile(profile).expect("Валидация исходного France");
    let intent = ProfileIntent::from_profile(profile).expect("Типизация исходного France");
    let mut wire = Vec::new();
    intent.write_sensitive(&mut wire).unwrap();
    let envelope: Value = serde_json::from_slice(&wire).unwrap();
    expected.as_object_mut().unwrap().remove("remarks");
    assert_eq!(envelope["graph"], expected);
    let decoded = ProfileIntent::decode(std::str::from_utf8(&wire).unwrap())
        .expect("Декодирование и повторная валидация France");
    let mut roundtrip = Vec::new();
    decoded.write_sensitive(&mut roundtrip).unwrap();
    assert_eq!(roundtrip, wire);

    assert_eq!(graph.subjects(), ["edge", "direct", "block", "dns-out"]);
    // Эти имена обозначают внутренний DNS ingress и сохраняются в правилах.
    assert_eq!(
        graph
            .egress()
            .resolvers()
            .iter()
            .map(|r| r.subject())
            .collect::<Vec<_>>(),
        [Some("dns-via-edge"), Some("dns-via-direct")]
    );
    assert_eq!(graph.egress().system_resolvers().len(), 1);
    assert_eq!(graph.egress().system_resolvers()[0].subject(), None);
    assert_eq!(
        decoded
            .branch_mask("edge", WireNetwork::Tcp, Some(443))
            .unwrap(),
        1
    );
    assert_eq!(
        decoded
            .branch_mask("edge", WireNetwork::Udp, Some(443))
            .unwrap(),
        2
    );
    let mut before = Vec::new();
    let mut after = Vec::new();
    intent
        .write_transport_sensitive("edge", &mut before)
        .unwrap();
    decoded
        .write_transport_sensitive("edge", &mut after)
        .unwrap();
    assert_eq!(before, after);

    for system in [false, true] {
        let plan = bound_plan(&graph, system);
        decoded.validate_ingress_mapping(&plan).unwrap();
        let (config, owned_tag) = if system {
            (
                emitted(
                    decoded
                        .compile_system(&plan)
                        .expect("Компиляция System")
                        .config(),
                ),
                "system-tun",
            )
        } else {
            (
                emitted(&decoded.compile_local(&plan).expect("Компиляция Local")),
                "yonik-owned-local",
            )
        };
        assert_eq!(config["dns"], expected["dns"]);
        let mut routing = expected["routing"].clone();
        routing["rules"][2]["inboundTag"] = json!([owned_tag, "yonik-owned-probe"]);
        assert_eq!(config["routing"], routing);

        let mut outbounds = expected["outbounds"].clone();
        if system {
            for outbound in outbounds.as_array_mut().unwrap() {
                if outbound["protocol"] != "blackhole" {
                    outbound["streamSettings"]["sockopt"]["mark"] = json!(42);
                }
            }
        }
        assert_eq!(config["outbounds"], outbounds);
        for tag in [owned_tag, "yonik-owned-probe"] {
            let inbound = config["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|inbound| inbound["tag"] == tag)
                .unwrap();
            assert_eq!(inbound["sniffing"], expected["inbounds"][0]["sniffing"]);
        }
    }
}
