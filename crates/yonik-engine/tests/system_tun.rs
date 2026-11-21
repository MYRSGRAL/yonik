use std::num::NonZeroU16;
use yonik_domain::{Action, Conditions, DomainPattern, Policy, Rule};
use yonik_engine::{
    CompileError, Engine, SystemTun, SystemTunAddress, compile_system, compile_system_policy,
};

fn settings() -> SystemTun {
    SystemTun::new(
        1,
        1500,
        99,
        vec![
            "198.18.0.1/30".parse().unwrap(),
            "2001:db8:746f::1/126".parse().unwrap(),
        ],
    )
    .unwrap()
}
fn source() -> yonik_import::ImportReport {
    yonik_import::import_bytes(b"vless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.1:24443?security=tls&sni=secret.example".to_vec()).unwrap()
}
fn value(config: yonik_engine::CompiledConfig) -> serde_json::Value {
    assert!(!format!("{config:?}").contains("00112233"));
    let mut bytes = Vec::new();
    config.write_sensitive(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn system_proxy_dials_pinned_ip_and_preserves_tls_and_websocket_names() {
    let report = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@edge.example:24443?security=tls&type=ws&host=front.example\ntrojan://fixture@edge.example:24443?security=tls&sni=tls.example"
            .to_vec(),
    )
    .unwrap();
    assert_eq!(report.servers.len(), 2);
    for engine in [Engine::Xray, Engine::SingBox] {
        for (index, server) in report.servers.iter().enumerate() {
            let (address, sni) = [
                ("192.0.2.10", "edge.example"),
                ("2001:db8::10", "tls.example"),
            ][index];
            let config = value(
                compile_system(server, engine, NonZeroU16::new(10808).unwrap(), &settings())
                    .unwrap()
                    .bind_system_proxy_address(server, address.parse().unwrap())
                    .unwrap(),
            );
            let proxy = &config["outbounds"][0];
            match engine {
                Engine::Xray => {
                    let field = ["vnext", "servers"][index];
                    assert_eq!(proxy["settings"][field][0]["address"], address);
                    assert_eq!(proxy["settings"][field][0]["port"], 24443);
                    assert_eq!(proxy["streamSettings"]["tlsSettings"]["serverName"], sni);
                    if index == 0 {
                        assert_eq!(
                            proxy["streamSettings"]["wsSettings"]["host"],
                            "front.example"
                        );
                    }
                }
                Engine::SingBox => {
                    assert_eq!(proxy["server"], address);
                    assert_eq!(proxy["server_port"], 24443);
                    assert_eq!(proxy["tls"]["server_name"], sni);
                    if index == 0 {
                        assert_eq!(proxy["transport"]["headers"]["Host"], "front.example");
                    }
                }
            }
        }
    }
}

#[test]
fn system_proxy_binding_rejects_a_different_port_or_host() {
    let report = source();
    let other = yonik_import::import_bytes(
        b"vless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.1:24444?security=tls\nvless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.2:24443?security=tls"
            .to_vec(),
    )
    .unwrap();
    assert_eq!(other.servers.len(), 2);
    for engine in [Engine::Xray, Engine::SingBox] {
        for server in &other.servers {
            let config = compile_system(
                &report.servers[0],
                engine,
                NonZeroU16::new(10808).unwrap(),
                &settings(),
            )
            .unwrap();
            assert!(matches!(
                config.bind_system_proxy_address(server, server.endpoint().host().parse().unwrap()),
                Err(CompileError::InvalidParameter)
            ));
        }
    }
}

#[test]
fn system_inbound_retains_profile_and_never_enables_automatic_network_control() {
    let report = source();
    for engine in [Engine::Xray, Engine::SingBox] {
        let config = value(
            compile_system(
                &report.servers[0],
                engine,
                NonZeroU16::new(10808).unwrap(),
                &settings(),
            )
            .unwrap(),
        );
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][1]["tag"], "system-tun");
        match engine {
            Engine::Xray => {
                assert_eq!(config["inbounds"][1]["settings"]["name"], "tofu00000001");
                assert_eq!(
                    config["inbounds"][1]["settings"]["autoSystemRoutingTable"],
                    serde_json::json!([])
                );
                assert_eq!(
                    config["inbounds"][1]["settings"]["autoSystemDnsToGateway"],
                    false
                );
                assert!(config["inbounds"][1]["settings"].get("gateway").is_none());
                assert_eq!(
                    config["outbounds"][0]["streamSettings"]["sockopt"]["mark"],
                    99
                );
                assert_eq!(
                    config["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"],
                    "secret.example"
                );
            }
            Engine::SingBox => {
                assert_eq!(config["inbounds"][1]["interface_name"], "tofu00000001");
                assert_eq!(config["inbounds"][1]["auto_route"], false);
                assert_eq!(config["inbounds"][1]["auto_redirect"], false);
                assert_eq!(config["inbounds"][1]["dns_mode"], "disabled");
                assert_eq!(config["inbounds"][1]["external_configuration"], true);
                assert_eq!(
                    config["inbounds"][1]["address"].as_array().unwrap().len(),
                    2
                );
                assert_eq!(config["outbounds"][0]["routing_mark"], 99);
                assert_eq!(
                    config["outbounds"][0]["tls"]["server_name"],
                    "secret.example"
                );
            }
        }
    }
}
#[test]
fn system_policy_preserves_authenticated_probe_and_rejects_unproven_domain_input() {
    let report = source();
    let mut policy = Policy::default();
    for engine in [Engine::Xray, Engine::SingBox] {
        let config = compile_system_policy(
            &report.servers[0],
            engine,
            NonZeroU16::new(10808).unwrap(),
            NonZeroU16::new(10809).unwrap(),
            &policy,
            &settings(),
        )
        .unwrap();
        assert!(config.probe_auth().is_some());
        assert_eq!(config.probe_port().get(), 10809);
    }
    policy.user_rules.push(Rule {
        id: 1,
        enabled: true,
        conditions: Conditions {
            domains: vec![DomainPattern::Suffix("secret.example".parse().unwrap())],
            ..Default::default()
        },
        action: Action::Direct,
    });
    for engine in [Engine::Xray, Engine::SingBox] {
        assert!(
            compile_system_policy(
                &report.servers[0],
                engine,
                NonZeroU16::new(10808).unwrap(),
                NonZeroU16::new(10809).unwrap(),
                &policy,
                &settings()
            )
            .is_err()
        );
    }
}
#[test]
fn malformed_runtime_settings_are_rejected_before_configuration() {
    for text in [
        "0.0.0.0/24",
        "127.0.0.1/8",
        "ff02::1/64",
        "fe80::1/64",
        "198.18.0.1/0",
        "198.18.0.1/33",
        "::1/128",
        "::ffff:127.0.0.1/128",
        "::192.0.2.1/128",
    ] {
        assert!(text.parse::<SystemTunAddress>().is_err());
    }
    for (id, mtu, mark) in [
        (0, 1500, 1),
        (1, 1279, 1),
        (1, 9001, 1),
        (1, 1500, 0),
        (1, 1500, u32::MAX),
    ] {
        assert!(matches!(
            SystemTun::new(id, mtu, mark, vec!["198.18.0.1/30".parse().unwrap()]),
            Err(CompileError::InvalidParameter)
        ));
    }
    assert!(SystemTun::new(1, 1500, 1, vec![]).is_err());
    assert!(
        SystemTun::new(
            1,
            1500,
            1,
            vec![
                "198.18.0.1/30".parse().unwrap(),
                "198.18.1.1/30".parse().unwrap()
            ]
        )
        .is_err()
    );
    assert_eq!(format!("{:?}", settings()), "SystemTun(<скрыто>)");
}
