use super::*;
use serde_json::json;
use yonik_engine::native_profile::{TransportProtocol, validate_profile};
use yonik_import::{NativeProfile, ProfileEntry, import_profiles};

fn profile(count: usize) -> NativeProfile {
    from_value(&document(count))
}
fn document(count: usize) -> serde_json::Value {
    let outbounds: Vec<_> = (0..count)
        .map(|i| {
            json!({"tag":format!("edge-{i}"),"protocol":"shadowsocks",
            "settings":{"servers":[{"address":"192.0.2.1","port":1000+i,
            "method":"aes-128-gcm","password":"synthetic"}]}})
        })
        .collect();
    json!({"outbounds":outbounds})
}

#[test]
fn synthetic_dat_checks_category_kind_hash_count_and_nested_records() {
    use yonik_engine::resource_bundle::{ExternalRef, ResourceKind};
    let mut value = document(1);
    value["routing"] =
        json!({"rules":[{"type":"field","domain":["geosite:test@ads"],"outboundTag":"edge-0"}]});
    let graph = validate_profile(&from_value(&value)).unwrap();
    // GeoSiteList(entry: GeoSite(code=TEST, domain(type=Domain,value=example.invalid))).
    let mut domain = vec![8, 2, 18, 15];
    domain.extend(b"example.invalid");
    let mut entry = vec![10, 4];
    entry.extend(b"TEST");
    entry.extend([18, domain.len() as u8]);
    entry.extend(&domain);
    let mut bytes = vec![10, entry.len() as u8];
    bytes.extend(entry);
    let mut reference = ExternalRef {
        engine: yonik_engine::Engine::Xray,
        digest: Sha256::digest(&bytes).into(),
        bytes: bytes.len() as u64,
        records: 1,
        kind: ResourceKind::Domains,
        format_version: 1,
    };
    let (_keep, cancel) = Cancellation::new();
    verify_dat_content(&bytes, &reference, graph.resources(), &cancel).unwrap();
    reference.kind = ResourceKind::Cidrs;
    assert!(verify_dat_content(&bytes, &reference, graph.resources(), &cancel).is_err());
    reference.kind = ResourceKind::Domains;
    reference.records = 2;
    assert!(verify_dat_content(&bytes, &reference, graph.resources(), &cancel).is_err());
    reference.records = 1;
    reference.digest = [0; 32];
    assert!(verify_dat_content(&bytes, &reference, graph.resources(), &cancel).is_err());
    reference.digest = Sha256::digest(&bytes).into();
    let mut alias = bytes.clone();
    alias[1] += 1;
    alias[3] = 0x84;
    alias.insert(4, 0);
    let mut ambiguous = reference.clone();
    ambiguous.bytes = alias.len() as u64;
    ambiguous.digest = Sha256::digest(&alias).into();
    assert!(verify_dat_content(&alias, &ambiguous, graph.resources(), &cancel).is_err());
    for cut in 0..bytes.len() {
        assert!(verify_dat_content(&bytes[..cut], &reference, graph.resources(), &cancel).is_err());
    }
    let mut bad = bytes.clone();
    bad[2] = 18;
    let mut changed = reference.clone();
    changed.digest = Sha256::digest(&bad).into();
    assert!(verify_dat_content(&bad, &changed, graph.resources(), &cancel).is_err());
    let mut value = document(1);
    value["routing"] =
        json!({"rules":[{"type":"field","domain":["geosite:missing"],"outboundTag":"edge-0"}]});
    let absent = validate_profile(&from_value(&value)).unwrap();
    assert!(verify_dat_content(&bytes, &reference, absent.resources(), &cancel).is_err());
}

#[test]
fn resolver_sources_are_exact_and_no_live_fallback_grammar_is_accepted() {
    let bytes = b"nameserver 192.0.2.53\nnameserver 2001:db8::53\n";
    let (servers, digest) = resolver_content(bytes, b"hosts: dns\n").unwrap();
    assert_eq!(servers.len(), 2);
    assert_ne!(
        resolver_content(bytes, b"# changed\nhosts: dns\n")
            .unwrap()
            .1,
        digest
    );
    assert_ne!(
        resolver_content(b"nameserver 192.0.2.54\n", b"hosts: dns\n")
            .unwrap()
            .1,
        digest
    );
    for nss in [
        "hosts: files dns",
        "hosts: resolve dns",
        "hosts: dns [NOTFOUND=return]",
        "hosts: dns\nhosts: dns",
        "hosts: mdns",
    ] {
        assert!(resolver_content(bytes, nss.as_bytes()).is_err());
    }
    for resolv in [
        "",
        "nameserver 0.0.0.0",
        "search example.invalid\nnameserver 192.0.2.53",
        "options rotate\nnameserver 192.0.2.53",
        "nameserver 192.0.2.53 extra",
    ] {
        assert!(resolver_content(resolv.as_bytes(), b"hosts: dns").is_err());
    }
}

#[test]
fn full_request_roundtrip_and_cancel_do_not_open_sources() {
    use yonik_engine::native_profile::ProfileIntent;
    let intent = ProfileIntent::from_profile(&profile(1)).unwrap();
    let request = FullProfileRequest::new(intent, 7, [3; 32], true).unwrap();
    let mut bytes = Vec::new();
    request.write_sensitive(&mut bytes).unwrap();
    let request = FullProfileRequest::decode(std::str::from_utf8(&bytes).unwrap()).unwrap();
    let (stop, cancel) = Cancellation::new();
    request.preflight(&cancel).unwrap();
    drop(stop);
    assert_eq!(
        request.preflight(&cancel),
        Err(super::super::ServiceError::Cancelled)
    );
}
fn from_value(value: &serde_json::Value) -> NativeProfile {
    let bytes = serde_json::to_vec(value).unwrap();
    match import_profiles(bytes).unwrap().entries.remove(0) {
        ProfileEntry::Xray(profile) => profile,
        _ => panic!("Требуется native fixture"),
    }
}

#[test]
fn chains_and_direct_subjects_never_add_remote_exceptions() {
    let mut value = document(2);
    value["outbounds"][0]["proxySettings"] = json!({"tag":"edge-1","transportLayer":true});
    value["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"tag":"direct","protocol":"freedom"}));
    let graph = validate_profile(&from_value(&value)).unwrap();
    let requirements = PhysicalRequirements::new(graph.egress()).unwrap();
    assert_eq!(requirements.endpoints().len(), 2);
    assert!(requirements.endpoints().iter().all(|e| e.port() == 1001));
    assert_eq!(graph.egress().direct_subjects(), &["direct"]);
}

#[test]
fn all_numeric_routes_are_captured_and_revalidated() {
    let graph = validate_profile(&profile(2)).unwrap();
    let requirements = PhysicalRequirements::new(graph.egress()).unwrap();
    let (_keep, cancel) = Cancellation::new();
    let mut calls = Vec::new();
    let mut captured = requirements
        .capture_numeric(969, 42, &cancel, |endpoint, protocol| {
            calls.push((endpoint, protocol));
            Ok((7, calls.len()))
        })
        .unwrap();
    assert_eq!(calls.len(), 4);
    let transports: Vec<_> = captured.transports().unwrap().collect();
    for (transport, (endpoint, protocol)) in transports.iter().zip(calls) {
        assert_eq!(
            *transport,
            BoundTransport::new(endpoint.ip(), protocol, endpoint.port(), 7, 969, 42).unwrap()
        );
    }
    let mut verified = Vec::new();
    captured
        .revalidate(&cancel, |snapshot| {
            verified.push(*snapshot);
            Ok(())
        })
        .unwrap();
    assert_eq!(verified, [1, 2, 3, 4]);
    assert_eq!(
        captured.revalidate(&cancel, |snapshot| {
            if *snapshot == 4 {
                Err(EgressError::Stale)
            } else {
                Ok(())
            }
        }),
        Err(EgressError::Stale)
    );
    assert!(captured.transports().is_err());
    assert_eq!(
        captured.revalidate(&cancel, |_| panic!("Нельзя оживить stale набор")),
        Err(EgressError::Stale)
    );
}

#[test]
fn bootstrap_and_non_unicast_fail_before_any_host_query() {
    for (host, error) in [
        ("edge.invalid", EgressError::BootstrapRequired),
        ("127.0.0.1", EgressError::InvalidEndpoint),
        ("0.0.0.0", EgressError::InvalidEndpoint),
        ("224.0.0.1", EgressError::InvalidEndpoint),
        ("169.254.1.1", EgressError::InvalidEndpoint),
        ("::ffff:192.0.2.1", EgressError::InvalidEndpoint),
    ] {
        let mut value = document(2);
        value["outbounds"][1]["settings"]["servers"][0]["address"] = host.into();
        let graph = validate_profile(&from_value(&value)).unwrap();
        let (_keep, cancel) = Cancellation::new();
        let result = PhysicalRequirements::new(graph.egress())
            .unwrap()
            .capture_numeric::<()>(969, 42, &cancel, |_, _| panic!("Нет provenance"));
        assert!(matches!(result, Err(e) if e == error));
    }
}

#[test]
fn cancellation_during_last_capture_drops_all_partial_observations() {
    use std::{cell::Cell, rc::Rc};
    struct Snapshot(Rc<Cell<usize>>);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let graph = validate_profile(&profile(2)).unwrap();
    let (stop, cancel) = Cancellation::new();
    let dropped = Rc::new(Cell::new(0));
    let mut calls = 0;
    let result = PhysicalRequirements::new(graph.egress())
        .unwrap()
        .capture_numeric(969, 42, &cancel, |_, _| {
            calls += 1;
            if calls == 4 {
                stop.send(true).unwrap();
            }
            Ok((7, Snapshot(Rc::clone(&dropped))))
        });
    assert!(matches!(result, Err(EgressError::Cancelled)));
    assert_eq!(calls, 4);
    assert_eq!(dropped.get(), 4);
}

#[test]
fn cancelled_revalidation_is_sticky() {
    let graph = validate_profile(&profile(1)).unwrap();
    let (stop, cancel) = Cancellation::new();
    let mut captured = PhysicalRequirements::new(graph.egress())
        .unwrap()
        .capture_numeric(969, 42, &cancel, |_, _| Ok((7, ())))
        .unwrap();
    assert_eq!(
        captured.revalidate(&cancel, |_| {
            stop.send(true).unwrap();
            Ok(())
        }),
        Err(EgressError::Cancelled)
    );
    assert!(captured.transports().is_err());
}

#[test]
fn zero_bindings_and_cancelled_owner_do_not_query_host() {
    let graph = validate_profile(&profile(1)).unwrap();
    let requirements = PhysicalRequirements::new(graph.egress()).unwrap();
    let (stop, cancel) = Cancellation::new();
    for (uid, mark) in [(0, 42), (u32::MAX, 42), (969, 0)] {
        assert!(matches!(
            requirements
                .capture_numeric::<()>(uid, mark, &cancel, |_, _| panic!("Некорректный binding")),
            Err(EgressError::InvalidBinding)
        ));
    }
    drop(stop);
    assert!(matches!(
        requirements.capture_numeric::<()>(969, 42, &cancel, |_, _| panic!("Владелец потерян")),
        Err(EgressError::Cancelled)
    ));
}

#[test]
fn sealed_runtime_retains_exact_bytes_and_rejects_forged_binding() {
    use std::num::NonZeroU16;
    use yonik_engine::{
        SystemTun,
        native_profile::{OwnedRuntimePlan, compile_profile_system},
    };
    let mut value = document(1);
    value["dns"] = json!({"servers":["192.0.2.53"]});
    let plan = OwnedRuntimePlan::new(
        NonZeroU16::new(10808).unwrap(),
        NonZeroU16::new(10809).unwrap(),
    )
    .unwrap()
    .with_system(SystemTun::new(1, 1500, 42, vec!["198.18.0.1/30".parse().unwrap()]).unwrap());
    let compiled = compile_profile_system(&from_value(&value), &plan).unwrap();
    let mut before = Vec::new();
    compiled.config().write_sensitive(&mut before).unwrap();
    let retained = RetainedSystemProfile::seal(compiled, 7, [3; 32]).unwrap();
    let digest: [u8; 32] = Sha256::digest(&before).into();
    assert_eq!(retained.digest(), &digest);
    assert!(retained.matches(7, [3; 32], digest));
    assert!(!retained.matches(8, [3; 32], digest));
    assert!(!retained.matches(7, [4; 32], digest));
    assert!(!retained.matches(7, [3; 32], [0; 32]));
    let mut after = Vec::new();
    retained
        .compiled()
        .config()
        .write_sensitive(&mut after)
        .unwrap();
    assert_eq!(before, after);
    let compiled = retained.into_compiled();
    assert!(matches!(
        RetainedSystemProfile::seal(compiled, 0, [3; 32]),
        Err(EgressError::InvalidBinding)
    ));
}

#[test]
fn physical_budget_precedes_materialization() {
    let graph = validate_profile(&profile(65)).unwrap();
    assert!(matches!(
        PhysicalRequirements::new(graph.egress()),
        Err(EgressError::Budget)
    ));
}

#[test]
fn exact_physical_budget_accepts_128_protocol_specific_leaves() {
    let graph = validate_profile(&profile(64)).unwrap();
    assert_eq!(
        PhysicalRequirements::new(graph.egress())
            .unwrap()
            .endpoints()
            .len(),
        128
    );
}

#[test]
fn provider_dns_is_separate_from_transport_exceptions() {
    let mut value = document(1);
    value["dns"] = json!({"servers":["192.0.2.53"]});
    let graph = validate_profile(&from_value(&value)).unwrap();
    let requirements = PhysicalRequirements::new(graph.egress()).unwrap();
    assert!(!requirements.provider_resolvers().is_empty());
    assert!(requirements.system_resolvers().is_empty());
    assert!(requirements.endpoints().iter().all(|e| e.port() == 1000));
}

#[test]
fn digest_writer_rejects_overflow_before_hashing_extra_bytes() {
    let mut writer = DigestWriter {
        digest: Sha256::new(),
        bytes: super::super::MAX_ARTIFACT_BYTES,
    };
    assert!(writer.write(b"x").is_err());
    assert_eq!(writer.bytes, super::super::MAX_ARTIFACT_BYTES);
    assert_eq!(
        writer.digest.finalize().as_slice(),
        Sha256::digest([]).as_slice()
    );
    let mut writer = DigestWriter {
        digest: Sha256::new(),
        bytes: usize::MAX,
    };
    assert!(writer.write(b"x").is_err());
}

#[test]
fn tcp_and_udp_are_separate_and_dns_is_not_promoted() {
    let graph = validate_profile(&profile(2)).unwrap();
    let requirements = PhysicalRequirements::new(graph.egress()).unwrap();
    assert_eq!(requirements.endpoints().len(), 4);
    assert_eq!(
        requirements.endpoints()[0].protocol(),
        TransportProtocol::Tcp
    );
    assert_eq!(
        requirements.endpoints()[1].protocol(),
        TransportProtocol::Udp
    );
    assert!(!graph.egress().system_resolvers().is_empty());
}
