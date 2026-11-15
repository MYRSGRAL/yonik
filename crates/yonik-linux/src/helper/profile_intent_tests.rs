use super::*;
use serde_json::json;
use yonik_engine::native_profile::{TransportProtocol, validate_profile};
use yonik_import::{NativeProfile, ProfileEntry, import_profiles};

#[test]
fn failed_source_identity_check_is_sticky_and_never_recaptures_as_fresh() {
    let invalid = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        revalidate_source(&invalid, || Err(EgressError::Stale)),
        Err(EgressError::Stale)
    );
    assert_eq!(
        revalidate_source(&invalid, || panic!(
            "Не перечитывать утраченную source authority"
        )),
        Err(EgressError::Stale)
    );
}

#[test]
fn netgo_snapshot_matches_independent_binary_golden_and_checks_hash_before_layout() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/xray-profile-channel-v3/resolver-snapshot-v1.json"
    ))
    .unwrap();
    let get = |name: &str| vector[name].as_str().unwrap();
    let hex = |value: &str| {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let data = resolver_snapshot_data(
        get("nss").as_bytes(),
        get("resolv").as_bytes(),
        Some(get("hosts").as_bytes()),
        get("hostname").as_bytes(),
    )
    .unwrap();
    let wire = data.encode().unwrap();
    assert_eq!(wire, hex(get("wireHex")));
    assert_eq!(data.source.as_slice(), hex(get("sourceSha256")));
    let mut reference = crate::profile_channel::SnapshotRef {
        source: data.source,
        asset: hex(get("assetSha256")).try_into().unwrap(),
        bytes: wire.len() as u32,
        flags: 0,
    };
    crate::profile_channel::verify_resolver_asset(&wire, reference).unwrap();
    reference.asset[0] ^= 1;
    assert_eq!(
        crate::profile_channel::verify_resolver_asset(&wire, reference),
        Err(crate::profile_channel::Error::Hash)
    );
    for (offset, value) in [
        (8, 1),
        (112, 1),
        (152, 5),
        (153, 16),
        (154, 6),
        (155, 1),
        (162, 255),
        (203, 0),
    ] {
        let mut bad = wire.clone();
        bad[offset] = value;
        assert!(
            crate::profile_channel::validate_resolver_asset(&bad, data.source, 0).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn netgo_snapshot_preserves_order_defaults_duplicates_search_and_hosts() {
    let nss = b"passwd: files\nhosts: files resolve [!UNAVAIL=return] dns\n";
    let resolv = b"nameserver invalid\nnameserver 127.0.0.53\nnameserver ::1\nnameserver 127.0.0.53\nnameserver 192.0.2.4\nsearch Example.INVALID . internal\noptions ndots:3 timeout:2 attempts:4 rotate single-request-reopen trust-ad use-vc\n";
    let hosts = b"127.0.0.1 LOCALHOST Example.Invalid\n::1 localhost\n127.0.0.1 localhost\ninvalid ignored\n";
    let snapshot =
        resolver_snapshot_data(nss, resolv, Some(hosts), b"host.example.invalid").unwrap();
    assert_eq!(snapshot.order, 3);
    assert_eq!(
        (
            snapshot.ndots,
            snapshot.timeout_ms,
            snapshot.attempts,
            snapshot.flags
        ),
        (3, 2000, 4, 31)
    );
    assert_eq!(
        snapshot.peers,
        [
            "127.0.0.53:53".parse().unwrap(),
            "[::1]:53".parse().unwrap(),
            "127.0.0.53:53".parse().unwrap()
        ]
    );
    assert_eq!(snapshot.search, ["Example.INVALID.", "internal."]);
    assert_eq!(snapshot.hosts[0].alias, "localhost");
    assert_eq!(snapshot.hosts[0].addresses.len(), 3);
    assert_eq!(snapshot.hosts[1].alias, "example.invalid.");
    let bytes = snapshot.encode().unwrap();
    crate::profile_channel::validate_resolver_asset(&bytes, snapshot.source, snapshot.source_flags)
        .unwrap();
    for length in 0..bytes.len() {
        assert!(
            crate::profile_channel::validate_resolver_asset(
                &bytes[..length],
                snapshot.source,
                snapshot.source_flags
            )
            .is_err()
        );
    }
    let empty = resolver_snapshot_data(b"", b"nameserver invalid\n", None, b"host.example.invalid")
        .unwrap();
    assert_eq!(empty.order, 3);
    assert_eq!(
        empty.peers,
        ["127.0.0.1:53".parse().unwrap(), "[::1]:53".parse().unwrap()]
    );
    assert_eq!(empty.search, ["example.invalid."]);
    assert_eq!(empty.source_flags, 1);
    let blocked = resolver_snapshot_data(
        b"hosts: files dns\n",
        b"",
        Some(b"0.0.0.0 blocked.invalid\n"),
        b"host",
    )
    .unwrap();
    assert!(blocked.hosts[0].addresses[0].is_unspecified());
    blocked.encode().unwrap();
    assert_ne!(
        empty.source,
        resolver_snapshot_data(
            b"",
            b"nameserver invalid\n",
            Some(b""),
            b"host.example.invalid"
        )
        .unwrap()
        .source
    );
}

#[test]
fn netgo_snapshot_rejects_unrepresentable_semantics_before_materialization() {
    for resolv in [
        b"nameserver fe80::1%lo\n".as_slice(),
        b"options attempts:6\n",
        b"options timeout:31\n",
        b"options unknown\n",
        b"search a b c d e f g\n",
        b"search example.invalid # inline-comment\n",
        b"search example.invalid..\n",
    ] {
        assert!(resolver_snapshot_data(b"hosts: files dns\n", resolv, Some(b""), b"host").is_err());
    }
    for (nss, order) in [
        ("hosts: dns files", 4),
        ("hosts: resolve files", 4),
        ("hosts: files resolve", 3),
        ("hosts: files resolve dns", 3),
        ("hosts: files", 1),
        ("hosts: dns", 2),
    ] {
        assert_eq!(
            resolver_snapshot_data(nss.as_bytes(), b"", Some(b""), b"host")
                .unwrap()
                .order,
            order
        );
    }
    assert!(resolver_snapshot_data(b"hosts: files\nhosts: dns\n", b"", None, b"host").is_err());
    assert!(resolver_snapshot_data(b"hosts: files [oops]\n", b"", None, b"host").is_err());
    assert!(resolver_snapshot_data(b"", b"", None, b"host\n").is_err());
    assert!(resolver_snapshot_data(b"", b"", Some(&vec![0; 1024 * 1024 + 1]), b"host").is_err());
    let mut hosts = String::new();
    for _ in 0..17 {
        hosts.push_str("127.0.0.1 localhost\n");
    }
    assert!(resolver_snapshot_data(b"", b"", Some(hosts.as_bytes()), b"host").is_err());
}

#[test]
fn native_catalog_is_closed_bounded_and_uses_only_digest_basenames() {
    let hash = [1u8; 32];
    let basename = format!("{}.dat", "01".repeat(32));
    let valid = json!({"version":1,"resources":[{"kind":"geoip","sha256":hash,"bytes":32,"records":1,"basename":basename}]});
    assert!(parse_native_catalog(&serde_json::to_vec(&valid).unwrap()).is_ok());
    for bad in [
        json!({"version":2,"resources":[]}),
        json!({"version":1,"resources":[],"url":"https://example.invalid"}),
        json!({"version":1,"resources":[valid["resources"][0].clone(),valid["resources"][0].clone()]}),
        json!({"version":1,"resources":vec![valid["resources"][0].clone();17]}),
    ] {
        assert!(parse_native_catalog(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    for name in [
        "../01.dat",
        "/tmp/01.dat",
        "01.dat",
        "https://example.invalid/data.dat",
    ] {
        let mut bad = valid.clone();
        bad["resources"][0]["basename"] = json!(name);
        assert!(parse_native_catalog(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let encoded = serde_json::to_string(&valid).unwrap();
    assert!(parse_native_catalog(format!("{{\"version\":1,{}", &encoded[1..]).as_bytes()).is_err());
    assert!(parse_native_catalog(&vec![b' '; 65537]).is_err());
}

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
    assert_eq!(
        resolver_content(bytes, b"hosts \t: dns\n").unwrap().0,
        servers
    );
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
        "hosts : files\nhosts: dns\n",
        "hosts\t: resolve dns\nhosts: dns\n",
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

#[test]
fn full_request_wrapper_budget_counts_partial_writes() {
    use yonik_engine::native_profile::{MAX_INTENT_BYTES, ProfileIntent};
    struct PartialSink {
        accepted: usize,
    }
    impl std::io::Write for PartialSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let count = bytes.len().min(7);
            self.accepted += count;
            assert!(self.accepted <= super::super::MAX_REQUEST);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let small = FullProfileRequest::new(
        ProfileIntent::from_profile(&profile(1)).unwrap(),
        7,
        [3; 32],
        true,
    )
    .unwrap();
    let mut exact = Vec::new();
    small.write_sensitive(&mut exact).unwrap();
    let mut partial = PartialSink { accepted: 0 };
    small.write_sensitive(&mut partial).unwrap();
    assert_eq!(partial.accepted, exact.len());

    let mut wire = json!({"version":1,"graph":{"outbounds":[{"tag":"x","protocol":"freedom","streamSettings":{"network":"grpc","grpcSettings":{"serviceName":""}}}]}});
    let padding = MAX_INTENT_BYTES - 16 - wire.to_string().len();
    wire["graph"]["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"] =
        json!("a".repeat(padding));
    let intent = ProfileIntent::decode(&wire.to_string()).unwrap();
    let mut intent_bytes = Vec::new();
    intent.write_sensitive(&mut intent_bytes).unwrap();
    assert_eq!(intent_bytes.len(), MAX_INTENT_BYTES - 16);
    let request = FullProfileRequest::new(intent, 7, [3; 32], true).unwrap();
    let mut partial = PartialSink { accepted: 0 };
    assert_eq!(
        request.write_sensitive(&mut partial),
        Err(super::super::ServiceError::InvalidRequest)
    );
    assert!(partial.accepted < super::super::MAX_REQUEST);
    let oversized =
        json!({"version":1,"generation":7,"selection":vec![3u8;32],"kill_switch":true,"intent":wire})
            .to_string();
    assert!(oversized.len() > super::super::MAX_REQUEST);
    assert!(matches!(
        FullProfileRequest::decode(&oversized),
        Err(super::super::ServiceError::InvalidRequest)
    ));
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
    // Numeric/provider-DNS fixture: prepare не открывает catalog/resolver sources.
    let request = FullProfileRequest::new(
        yonik_engine::native_profile::ProfileIntent::from_profile(&from_value(&value)).unwrap(),
        7,
        [3; 32],
        true,
    )
    .unwrap();
    let (_keep, cancel) = Cancellation::new();
    let prepared = request.prepare_system(plan, 1, 1, &cancel).unwrap();
    let mut exact = Vec::new();
    prepared
        .retained()
        .compiled()
        .config()
        .write_sensitive(&mut exact)
        .unwrap();
    assert_eq!(
        prepared.retained().digest(),
        &<[u8; 32]>::from(Sha256::digest(exact))
    );
    crate::profile_channel::Capsule::decode(prepared.capsule_bytes(), prepared.retained().digest())
        .unwrap();
    assert!(prepared.resolver().is_none());
    prepared.revalidate(&cancel).unwrap();
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
