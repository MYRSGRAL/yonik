use std::num::NonZeroU16;
use yonik_domain::{Action, Conditions, DomainPattern, Policy, PrivateNetwork, Rule, VpnId};
use yonik_engine::{Engine, PolicyCapability, PolicyCompileError, PolicyMode, compile_policy};

fn compile(
    engine: Engine,
    policy: &Policy,
    mode: PolicyMode,
) -> Result<serde_json::Value, PolicyCompileError> {
    let report = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.1:24443".to_vec(),
    )
    .unwrap();
    let config = compile_policy(
        &report.servers[0],
        engine,
        NonZeroU16::new(10808).unwrap(),
        NonZeroU16::new(10809).unwrap(),
        policy,
        mode,
    )?;
    assert_eq!(config.probe_port().get(), 10809);
    let auth = config.probe_auth().unwrap();
    assert_eq!(auth.password().len(), 64);
    assert!(!format!("{config:?}").contains(auth.password()));
    let mut bytes = Vec::new();
    config.write_sensitive(&mut bytes).unwrap();
    Ok(serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn native_policy_keeps_order_and_authenticated_probe_override() {
    let mut policy = Policy {
        default_action: Action::Block,
        ..Default::default()
    };
    policy.user_rules.push(Rule {
        id: 1,
        enabled: true,
        conditions: Conditions {
            domains: vec![DomainPattern::Suffix("ПРИМЕР.РФ".parse().unwrap())],
            ..Default::default()
        },
        action: Action::Direct,
    });
    for engine in [Engine::Xray, Engine::SingBox] {
        let value = compile(engine, &policy, PolicyMode::Names).unwrap();
        assert_eq!(value["inbounds"].as_array().unwrap().len(), 2);
        assert!(value.to_string().contains("xn--e1afmkfd.xn--p1ai"));
        assert!(value.to_string().contains("probe"));
        assert!(!value.to_string().contains("IPOnDemand"));
        let accounts = if engine == Engine::Xray {
            &value["inbounds"][1]["settings"]["accounts"]
        } else {
            &value["inbounds"][1]["users"]
        };
        assert_eq!(accounts.as_array().unwrap().len(), 1);
    }
}

#[test]
fn unproven_native_combinations_are_errors_not_semantic_changes() {
    for engine in [Engine::Xray, Engine::SingBox] {
        let mut policy = Policy::default();
        policy.lan.push("192.0.2.0/24".parse().unwrap());
        assert_eq!(
            compile(engine, &policy, PolicyMode::Names),
            Err(PolicyCompileError::Unsupported(
                PolicyCapability::RequiredRealResolution
            ))
        );
        policy.lan.clear();
        policy.user_rules.push(Rule {
            id: 1,
            enabled: true,
            conditions: Conditions {
                executables: vec!["/usr/bin/app".into()],
                ..Default::default()
            },
            action: Action::Direct,
        });
        assert_eq!(
            compile(engine, &policy, PolicyMode::Names),
            Err(PolicyCompileError::Unsupported(
                PolicyCapability::ProcessAttribution
            ))
        );
        policy.user_rules.clear();
        policy.private_networks.push(PrivateNetwork {
            network: "10.0.0.0/8".parse().unwrap(),
            available: true,
            vpn: VpnId::new(1).unwrap(),
        });
        assert_eq!(
            compile(engine, &policy, PolicyMode::IpOnly),
            Err(PolicyCompileError::Unsupported(
                PolicyCapability::PrivateNetworkBinding
            ))
        );
    }
}

#[test]
fn ip_only_has_domain_rejection_and_private_protection_first() {
    let mut policy = Policy {
        default_action: Action::Direct,
        ..Default::default()
    };
    policy.private_networks.push(PrivateNetwork {
        network: "10.0.0.0/8".parse().unwrap(),
        available: false,
        vpn: VpnId::new(1).unwrap(),
    });
    policy.lan.push("10.0.0.0/8".parse().unwrap());
    for engine in [Engine::Xray, Engine::SingBox] {
        let value = compile(engine, &policy, PolicyMode::IpOnly).unwrap();
        let rules = if engine == Engine::Xray {
            &value["routing"]["rules"]
        } else {
            &value["route"]["rules"]
        };
        assert!(rules[0].to_string().contains("probe"));
        assert!(
            rules[1].to_string().contains("regexp:.")
                || rules[1].to_string().contains("domain_regex")
        );
        assert!(rules[2].to_string().contains("10.0.0.0/8"));
        assert!(rules[2].to_string().contains("block") || rules[2].to_string().contains("reject"));
    }
}

#[test]
fn probe_cannot_bypass_known_protected_destinations() {
    let mut policy = Policy::default();
    policy.private_networks.push(PrivateNetwork {
        network: "10.0.0.0/8".parse().unwrap(),
        available: false,
        vpn: VpnId::new(1).unwrap(),
    });
    let server = yonik_import::import_bytes(b"socks5://127.0.0.1:24443".to_vec()).unwrap();
    let config = compile_policy(
        &server.servers[0],
        Engine::Xray,
        NonZeroU16::new(10808).unwrap(),
        NonZeroU16::new(10809).unwrap(),
        &policy,
        PolicyMode::IpOnly,
    )
    .unwrap();
    let access = config.into_probe_access();
    assert!(!access.allows_host("10.1.2.3"));
    assert!(!access.allows_host("::ffff:10.1.2.3"));
    assert!(!access.allows_host("[::ffff:10.1.2.3]"));
    assert!(access.allows_host("192.0.2.1"));
    policy.private_networks.clear();
    policy.private_domains.push(yonik_domain::PrivateDomain {
        domain: DomainPattern::Suffix("corp.test".parse().unwrap()),
        available: false,
        vpn: VpnId::new(1).unwrap(),
    });
    let config = compile_policy(
        &server.servers[0],
        Engine::Xray,
        NonZeroU16::new(10808).unwrap(),
        NonZeroU16::new(10809).unwrap(),
        &policy,
        PolicyMode::Names,
    )
    .unwrap();
    let access = config.into_probe_access();
    assert!(!access.allows_host("ONE.CORP.TEST."));
    assert!(access.allows_host("notcorp.test"));
}

#[test]
fn p07_both_compilers_refuse_before_routes() {
    use yonik_domain::{AndroidPackageId, PlatformSource};
    let mut policy = Policy::default();
    policy.user_rules.push(Rule {
        id: 41,
        enabled: true,
        action: Action::Direct,
        conditions: Conditions {
            platform_sources: vec![PlatformSource::AndroidPackage {
                package: AndroidPackageId::parse("org.example.app").unwrap(),
            }],
            ..Default::default()
        },
    });
    for engine in [Engine::Xray, Engine::SingBox] {
        assert_eq!(
            compile(engine, &policy, PolicyMode::IpOnly).unwrap_err(),
            PolicyCompileError::UnsupportedSelector(41)
        );
    }
    policy.user_rules[0].enabled = false;
    for engine in [Engine::Xray, Engine::SingBox] {
        assert!(compile(engine, &policy, PolicyMode::IpOnly).is_ok());
    }
}

#[test]
fn transport_system_refuses_enabled_while_local_lowers_and_disabled_preserved() {
    let report = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.1:24443".to_vec(),
    )
    .unwrap();
    let tun =
        yonik_engine::SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
    let mut policy = Policy::default();
    policy.user_rules.push(Rule {
        id: 51,
        enabled: true,
        action: Action::Block,
        conditions: Conditions {
            transport: yonik_domain::TransportConditions::parse(Some(&["tcp"]), None).unwrap(),
            ..Default::default()
        },
    });
    for engine in [Engine::Xray, Engine::SingBox] {
        let result = yonik_engine::compile_system_policy(
            &report.servers[0],
            engine,
            NonZeroU16::new(10808).unwrap(),
            NonZeroU16::new(10809).unwrap(),
            &policy,
            &tun,
        );
        assert_eq!(
            result.unwrap_err(),
            PolicyCompileError::UnsupportedTransport(51)
        );
        assert!(compile(engine, &policy, PolicyMode::IpOnly).is_ok());
    }
    policy.user_rules[0].enabled = false;
    for engine in [Engine::Xray, Engine::SingBox] {
        assert!(compile(engine, &policy, PolicyMode::IpOnly).is_ok());
        assert!(
            yonik_engine::compile_system_policy(
                &report.servers[0],
                engine,
                NonZeroU16::new(10808).unwrap(),
                NonZeroU16::new(10809).unwrap(),
                &policy,
                &tun,
            )
            .is_ok()
        );
    }
}
