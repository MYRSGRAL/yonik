use serde_json::{Value, json};
use std::num::NonZeroU16;
use yonik_domain::{
    Action, Conditions, DestinationPorts, DomainPattern, Policy, Rule, TransportConditions,
};
use yonik_engine::{
    Engine, PolicyCapability, PolicyCompileError, PolicyMode, SystemTun, compile_policy,
    compile_system_policy,
};

fn policy(protocols: Option<&[&str]>) -> Policy {
    Policy {
        default_action: Action::Direct,
        user_rules: vec![Rule {
            id: 71,
            enabled: true,
            action: Action::Block,
            conditions: Conditions {
                transport: TransportConditions::parse(
                    protocols,
                    Some(
                        DestinationPorts::parse(&[(1, 1), (80, 90), (443, 443), (65535, 65535)])
                            .unwrap(),
                    ),
                )
                .unwrap(),
                ..Default::default()
            },
        }],
        ..Default::default()
    }
}
fn compile(
    engine: Engine,
    policy: &Policy,
    mode: PolicyMode,
    system: bool,
) -> Result<Value, PolicyCompileError> {
    let report = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.1:24443".to_vec(),
    )
    .unwrap();
    let port = NonZeroU16::new(10808).unwrap();
    let probe = NonZeroU16::new(10809).unwrap();
    let config = if system {
        let tun = SystemTun::new(1, 1500, 99, vec!["198.18.0.1/30".parse().unwrap()]).unwrap();
        compile_system_policy(&report.servers[0], engine, port, probe, policy, &tun)
    } else {
        compile_policy(&report.servers[0], engine, port, probe, policy, mode)
    }?;
    let mut bytes = Vec::new();
    config.write_sensitive(&mut bytes).unwrap();
    Ok(serde_json::from_slice(&bytes).unwrap())
}
fn rules(engine: Engine, value: &Value) -> &Vec<Value> {
    value[if engine == Engine::Xray {
        "routing"
    } else {
        "route"
    }]["rules"]
        .as_array()
        .unwrap()
}
#[test]
fn протоколы_границы_и_пробелы_в_native_json() {
    for protocols in [
        None,
        Some(&["tcp"][..]),
        Some(&["udp"][..]),
        Some(&["tcp", "udp"][..]),
        Some(&["udp", "tcp"][..]),
    ] {
        for engine in [Engine::Xray, Engine::SingBox] {
            let p = policy(protocols);
            let value = compile(engine, &p, PolicyMode::IpOnly, false).unwrap();
            let all = rules(engine, &value);
            let rule = &all[all.len() - 2];
            if engine == Engine::Xray {
                assert_eq!(rule["port"], json!("1,80-90,443,65535"));
                assert_eq!(
                    rule["network"],
                    json!(protocols.unwrap_or(&["tcp", "udp"]).join(","))
                );
                assert_eq!(rule["outboundTag"], "block");
            } else {
                assert_eq!(rule["action"], "reject");
                assert_eq!(rule["port"], json!([1, 443, 65535]));
                assert_eq!(rule["port_range"], json!(["80:90"]));
                assert_eq!(rule.get("network"), protocols.map(|p| json!(p)).as_ref());
                assert!(rule.get("rules").is_none());
            }
            assert_eq!(
                compile(engine, &p, PolicyMode::IpOnly, true).unwrap_err(),
                PolicyCompileError::UnsupportedTransport(71)
            );
            assert_eq!(p.user_rules[0].id, 71);
        }
    }
}
#[test]
fn destination_conjunct_order_disabled_и_отказы_режимов() {
    for engine in [Engine::Xray, Engine::SingBox] {
        let mut p = policy(Some(&["udp"]));
        p.user_rules[0].conditions.domains =
            vec![DomainPattern::Suffix("example.org".parse().unwrap())];
        let value = compile(engine, &p, PolicyMode::Names, false).unwrap();
        let all = rules(engine, &value);
        let rule = &all[all.len() - 2];
        if engine == Engine::Xray {
            assert_eq!(rule["domain"], json!(["domain:example.org"]));
        } else {
            assert_eq!(rule["rules"][0]["domain_suffix"], json!(["example.org"]));
        }
        assert!(compile(engine, &p, PolicyMode::IpOnly, false).is_err());
        p.user_rules[0].conditions.domains.clear();
        p.user_rules[0].conditions.destinations = vec!["192.0.2.0/24".parse().unwrap()];
        assert!(compile(engine, &p, PolicyMode::Names, false).is_err());
        let value = compile(engine, &p, PolicyMode::IpOnly, false).unwrap();
        let before = rules(engine, &value).len();
        p.user_rules[0]
            .conditions
            .executables
            .push("/usr/bin/app".into());
        assert_eq!(
            compile(engine, &p, PolicyMode::IpOnly, false).unwrap_err(),
            PolicyCompileError::Unsupported(PolicyCapability::ProcessAttribution)
        );
        p.user_rules[0].enabled = false;
        let value = compile(engine, &p, PolicyMode::IpOnly, false).unwrap();
        assert_eq!(rules(engine, &value).len(), before - 1);
        assert_eq!(p.user_rules[0].id, 71);
        assert!(p.user_rules[0].conditions.transport.constrained());
    }
}

#[test]
fn malformed_transport_и_native_wire_не_обходят_отказ() {
    let valid = json!({"version":3,"user_rules":[{"id":71,"action":"block","conditions":{"platform_sources":[],"transport":{"transport_protocols":["tcp"]}}}]}).to_string();
    assert!(yonik_engine::policy_input::read_policy(valid.as_bytes()).is_ok());
    for transport in [
        json!({"transport_protocols":[]}),
        json!({"transport_protocols":["icmp"]}),
        json!({"destination_ports":[[0,1]]}),
        json!({"destination_ports":[[2,1]]}),
        json!({"destination_ports":[[1,4],[4,8]]}),
        json!({"destination_ports":null}),
    ] {
        let raw = json!({"version":3,"user_rules":[{"id":71,"action":"block","conditions":{"platform_sources":[],"transport":transport}}]}).to_string();
        assert!(yonik_engine::policy_input::read_policy(raw.as_bytes()).is_err());
    }
    let wire = json!({"version":3,"default_action":"proxy","user_rules":[{"id":71,"enabled":true,"action":"block","platform_sources":[],"domain":[],"domain_suffix":[],"ip_cidr":[],"executable_paths":[],"transport":{"transport_protocols":["tcp"]}}],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}).to_string();
    assert!(matches!(
        yonik_engine::policy_wire::SystemPolicy::parse(&wire),
        Err(yonik_engine::policy_input::PolicyInputError::UnsupportedTransport(71))
    ));
}

#[test]
fn first_match_порядок_user_preset_default_сохранён() {
    for engine in [Engine::Xray, Engine::SingBox] {
        let mut p = policy(Some(&["tcp"]));
        let mut next = policy(Some(&["tcp"])).user_rules.remove(0);
        next.id = 72;
        next.action = Action::Proxy;
        p.preset_rules.push(next);
        let before = format!("{p:?}");
        let value = compile(engine, &p, PolicyMode::IpOnly, false).unwrap();
        let all = rules(engine, &value);
        let key = if engine == Engine::Xray {
            "outboundTag"
        } else {
            "outbound"
        };
        assert_eq!(
            all[all.len() - 3][if engine == Engine::Xray {
                key
            } else {
                "action"
            }],
            if engine == Engine::Xray {
                "block"
            } else {
                "reject"
            }
        );
        assert_eq!(all[all.len() - 2][key], "proxy");
        assert_eq!(all[all.len() - 1][key], "direct");
        assert_eq!(format!("{p:?}"), before);
    }
}
