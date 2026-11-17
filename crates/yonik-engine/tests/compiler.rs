use std::num::NonZeroU16;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use yonik_engine::{CompileError, Engine, compile};
use yonik_import::import_bytes;

const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";

fn config(engine: Engine, uri: &str) -> Result<Value, CompileError> {
    let report = import_bytes(uri.as_bytes().to_vec()).expect("fixture импортируется");
    assert!(report.issues.is_empty());
    let config = compile(&report.servers[0], engine, NonZeroU16::new(10808).unwrap())?;
    assert_eq!(config.engine(), engine);
    assert_eq!(config.listen_port().get(), 10808);
    let debug = format!("{config:?}");
    assert!(!debug.contains(UUID));
    assert!(!debug.contains("secret.example"));
    let mut bytes = Vec::new();
    config.write_sensitive(&mut bytes).unwrap();
    Ok(serde_json::from_slice(&bytes).unwrap())
}

#[test]
fn vless_is_loopback_only_and_has_no_direct_fallback() {
    let uri = format!("vless://{UUID}@secret.example:443?encryption=none&security=tls");
    for engine in [Engine::Xray, Engine::SingBox] {
        let value = config(engine, &uri).unwrap();
        assert_eq!(value["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(value["outbounds"].as_array().unwrap().len(), 1);
        assert!(!value.to_string().contains("direct"));
        assert!(value.to_string().contains(UUID));
        assert!(value.to_string().contains("secret.example"));
    }
}

#[test]
fn tls_websocket_preserves_host_path_alpn_and_fingerprint() {
    let uri = format!(
        "vless://{UUID}@secret.example:443?security=tls&type=ws&sni=verify.example&host=edge.example&path=%2Fsocket&alpn=http%2F1.1&fp=chrome"
    );
    let xray = config(Engine::Xray, &uri).unwrap();
    let stream = &xray["outbounds"][0]["streamSettings"];
    assert_eq!(stream["wsSettings"]["path"], "/socket");
    assert_eq!(stream["wsSettings"]["host"], "edge.example");
    assert_eq!(stream["tlsSettings"]["serverName"], "verify.example");
    assert_eq!(stream["tlsSettings"]["allowInsecure"], false);
    assert_eq!(stream["tlsSettings"]["useSystemCA"], true);
    assert_eq!(stream["tlsSettings"]["alpn"], json!(["http/1.1"]));
    let sing = config(Engine::SingBox, &uri).unwrap();
    let outbound = &sing["outbounds"][0];
    assert_eq!(outbound["transport"]["headers"]["Host"], "edge.example");
    assert_eq!(outbound["tls"]["insecure"], false);
    assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
}

#[test]
fn six_protocols_and_credentials_survive_compilation() {
    let vmess = json!({"v":"2","add":"secret.example","port":"443","id":UUID,
        "aid":"0","scy":"auto","net":"tcp","tls":""});
    let sources = [
        format!("vless://{UUID}@secret.example:443?security=tls"),
        format!("vmess://{}", STANDARD.encode(vmess.to_string())),
        "trojan://secret-pass@secret.example:443?sni=verify.example".into(),
        "ss://aes-128-gcm:secret-pass@secret.example:443".into(),
        "https://user:secret-pass@secret.example:443".into(),
        "socks5://user:secret-pass@secret.example:1080".into(),
    ];
    for engine in [Engine::Xray, Engine::SingBox] {
        for uri in &sources {
            let value = config(engine, uri).unwrap();
            assert!(value.to_string().contains("secret.example"));
        }
    }
}

#[test]
fn unsafe_unknown_and_inapplicable_options_never_silently_disappear() {
    let queries = [
        "unknown=secret",
        "allowInsecure=1",
        "encryption=unsupported",
        "flow=unknown",
        "headerType=http",
        "seed=1",
        "type=quic",
        "type=h2",
        "security=unknown",
        "host=unused.example",
        "path=%2Funused",
        "sni=unused.example",
        "fp=chrome",
        "pbk=unused",
        "sid=abcd",
        "mode=auto",
        "serviceName=unused",
        "spx=%2F",
        "security=tls&fp=unknown",
        "security=tls&alpn=h2,,http%2F1.1",
        "security=tls&sni=bad%0Aname",
        "type=ws&path=relative",
        "flow=xtls-rprx-vision",
        "packetEncoding=unknown",
    ];
    for engine in [Engine::Xray, Engine::SingBox] {
        for query in queries {
            assert!(
                config(engine, &format!("vless://{UUID}@127.0.0.1:443?{query}")).is_err(),
                "{engine:?}: {query}"
            );
        }
    }
}

#[test]
fn reality_validates_key_short_id_and_transport() {
    let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let base = format!(
        "vless://{UUID}@secret.example:443?security=reality&sni=verify.example&fp=chrome&pbk={key}&sid=ab12&flow=xtls-rprx-vision"
    );
    for engine in [Engine::Xray, Engine::SingBox] {
        assert!(config(engine, &base).is_ok());
        for suffix in ["&type=ws", "&alpn=h2"] {
            assert!(config(engine, &format!("{base}{suffix}")).is_err());
        }
        for bad in [
            base.replace(key, "bad"),
            base.replace("sid=ab12", "sid=abc"),
            base.replace("sid=ab12", "sid=zz"),
            base.replace("&fp=chrome", ""),
        ] {
            assert!(config(engine, &bad).is_err());
        }
    }
}

#[test]
fn invalid_shadowsocks_2022_key_and_vmess_options_are_rejected() {
    for engine in [Engine::Xray, Engine::SingBox] {
        assert!(
            config(
                engine,
                "ss://2022-blake3-aes-128-gcm:bad@secret.example:443"
            )
            .is_err()
        );
        for extra in [
            json!({"aid":1}),
            json!({"scy":"none"}),
            json!({"type":"http"}),
            json!({"unknown":true}),
            json!({"host":123}),
        ] {
            let mut value = json!({"add":"secret.example","port":443,"id":UUID,"net":"tcp"});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let uri = format!("vmess://{}", STANDARD.encode(value.to_string()));
            assert!(config(engine, &uri).is_err());
        }
    }
}

#[test]
fn grpc_and_xhttp_have_engine_specific_capabilities() {
    let grpc = format!("vless://{UUID}@secret.example:443?type=grpc&serviceName=svc&security=tls");
    for engine in [Engine::Xray, Engine::SingBox] {
        assert!(config(engine, &grpc).is_ok());
    }
    let xhttp = format!(
        "vless://{UUID}@secret.example:443?type=xhttp&path=%2Fstream&mode=auto&security=tls"
    );
    assert!(config(Engine::Xray, &xhttp).is_ok());
    assert_eq!(
        config(Engine::SingBox, &xhttp),
        Err(CompileError::UnsupportedTransport)
    );
}

#[test]
fn recursive_listener_and_public_xray_plaintext_are_rejected() {
    for engine in [Engine::Xray, Engine::SingBox] {
        assert_eq!(
            config(engine, &format!("vless://{UUID}@127.0.0.1:10808")),
            Err(CompileError::ListenerConflict)
        );
    }
    assert_eq!(
        config(Engine::Xray, &format!("vless://{UUID}@1.1.1.1:443")),
        Err(CompileError::UnsupportedSecurity)
    );
    assert!(config(Engine::Xray, &format!("vless://{UUID}@10.0.0.1:443")).is_ok());
}

#[test]
fn mapped_ipv4_and_localhost_dot_cannot_create_self_proxy() {
    for engine in [Engine::Xray, Engine::SingBox] {
        for address in ["[::ffff:127.0.0.1]", "localhost.", "LOCALHOST"] {
            assert_eq!(
                config(engine, &format!("socks5://{address}:10808")),
                Err(CompileError::ListenerConflict)
            );
        }
        assert!(config(engine, "socks5://[::ffff:127.0.0.1]:10809").is_ok());
    }
}

fn json_vless(network: &str, security: &str, options: Value) -> Value {
    let mut stream = json!({"network":network,"security":security});
    if network == "grpc" {
        stream["grpcSettings"] = options;
        stream["tlsSettings"] = json!({"serverName":"verify.example"});
    } else {
        stream["realitySettings"] = options;
    }
    json!({"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"secret.example","port":443,"users":[{"id":UUID,"encryption":"none"}]}]},"streamSettings":stream}]})
}

#[test]
fn json_grpc_defaults_authority_and_blocking_options() {
    for engine in [Engine::Xray, Engine::SingBox] {
        for mode in [None, Some("gun")] {
            for authority in [None, Some(""), Some("grpc.example:8443"), Some("[::1]:443")] {
                let mut options = json!({"serviceName":"service/a"});
                if let Some(mode) = mode {
                    options["mode"] = json!(mode);
                }
                if let Some(authority) = authority {
                    options["authority"] = json!(authority);
                }
                let source = json_vless("grpc", "tls", options).to_string();
                let result = config(engine, &source);
                if engine == Engine::SingBox && authority.is_some_and(|v| !v.is_empty()) {
                    assert_eq!(result, Err(CompileError::UnsupportedOption));
                } else {
                    let result = result.unwrap();
                    if engine == Engine::Xray {
                        let grpc = &result["outbounds"][0]["streamSettings"]["grpcSettings"];
                        assert_eq!(grpc["serviceName"], "service/a");
                        assert!(grpc.get("mode").is_none());
                        assert!(grpc.get("multiMode").is_none());
                        assert_eq!(
                            grpc.get("authority").and_then(Value::as_str),
                            authority.filter(|v| !v.is_empty())
                        );
                    }
                }
            }
        }
        for extra in [
            json!({"mode":"multi"}),
            json!({"mode":"auto"}),
            json!({"mode":""}),
            json!({"multiMode":false}),
            json!({"unknown":true}),
        ] {
            assert_eq!(
                config(engine, &json_vless("grpc", "tls", extra).to_string()),
                Err(CompileError::UnsupportedOption)
            );
        }
        for authority in [
            "bad\nname",
            "user@host",
            "host/path",
            "host?query",
            "host#fragment",
            "host\\path",
            "host:bad",
            "host name",
        ] {
            assert!(
                config(
                    engine,
                    &json_vless("grpc", "tls", json!({"mode":"gun","authority":authority}))
                        .to_string()
                )
                .is_err()
            );
        }
        let mut unsafe_node = json_vless("grpc", "tls", json!({"mode":"gun"}));
        unsafe_node["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] = json!(true);
        assert_eq!(
            config(engine, &unsafe_node.to_string()),
            Err(CompileError::UnsupportedOption)
        );
    }
}

#[test]
fn json_reality_spider_path_preserves_query_and_defaults() {
    for engine in [Engine::Xray, Engine::SingBox] {
        for spider in [None, Some(""), Some("/"), Some("/a?b=c&x=%2F")] {
            let mut options = json!({"serverName":"verify.example","fingerprint":"chrome","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"ab12"});
            if let Some(spider) = spider {
                options["spiderX"] = json!(spider);
            }
            let source = json_vless("tcp", "reality", options.clone()).to_string();
            let result = config(engine, &source);
            if engine == Engine::SingBox && spider.is_some_and(|v| !matches!(v, "" | "/")) {
                assert_eq!(result, Err(CompileError::UnsupportedOption));
            } else {
                let result = result.unwrap();
                if engine == Engine::Xray && spider == Some("/a?b=c&x=%2F") {
                    assert_eq!(
                        result["outbounds"][0]["streamSettings"]["realitySettings"]["spiderX"],
                        spider.unwrap()
                    );
                }
            }
            for bad in [
                "relative",
                "https://other/",
                "//other/path",
                "/a\nb",
                "/a b",
                "/a#fragment",
                "/a\\b",
            ] {
                options["spiderX"] = json!(bad);
                assert!(
                    config(
                        engine,
                        &json_vless("tcp", "reality", options.clone()).to_string()
                    )
                    .is_err()
                );
            }
            options["spiderX"] = json!("/");
            options["unknown"] = json!(true);
            assert_eq!(
                config(
                    engine,
                    &json_vless("tcp", "reality", options.clone()).to_string()
                ),
                Err(CompileError::UnsupportedOption)
            );
            options.as_object_mut().unwrap().remove("unknown");
            options["publicKey"] = json!("bad");
            assert!(config(engine, &json_vless("tcp", "reality", options).to_string()).is_err());
        }
    }
}

#[test]
fn shadowsocks_2022_preserves_exact_method_and_key() {
    let method = "2022-blake3-aes-128-gcm";
    let key = STANDARD.encode(b"0123456789abcdef");
    for engine in [Engine::Xray, Engine::SingBox] {
        let value = config(engine, &format!("ss://{method}:{key}@secret.example:443")).unwrap();
        let outbound = &value["outbounds"][0];
        let credentials = if engine == Engine::Xray {
            &outbound["settings"]["servers"][0]
        } else {
            outbound
        };
        assert_eq!(credentials["method"], method);
        assert_eq!(credentials["password"], key);
        let wrong = STANDARD.encode(b"0123456789abcde");
        assert_eq!(
            config(engine, &format!("ss://{method}:{wrong}@secret.example:443")),
            Err(CompileError::InvalidCredentials)
        );
    }
    let key = STANDARD.encode([0_u8; 32]);
    assert_eq!(
        config(
            Engine::Xray,
            &format!("ss://2022-blake3-chacha20-poly1305:{key}@secret.example:443")
        ),
        Err(CompileError::UnsupportedOption)
    );
}

#[test]
fn reality_uri_shapes_compile_for_local_xray() {
    let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let base = format!(
        "vless://{UUID}@secret.example:443?encryption=none&security=reality&sni=verify.example&fp=chrome&pbk={key}&sid=ab12"
    );
    let cases = [
        (
            "type=tcp&flow=xtls-rprx-vision&packetEncoding=xudp",
            "tcp",
            Value::Null,
        ),
        (
            "type=grpc&serviceName=service%2Fa&mode=gun&authority=edge.example%3A8443",
            "grpc",
            json!({"serviceName":"service/a","authority":"edge.example:8443"}),
        ),
        (
            "type=grpc&serviceName=svc",
            "grpc",
            json!({"serviceName":"svc"}),
        ),
        (
            "type=xhttp&host=edge.example&path=%2Fstream%3Fa%3Db&mode=stream-up",
            "xhttp",
            json!({"host":"edge.example","path":"/stream?a=b","mode":"stream-up"}),
        ),
    ];
    for (query, network, settings) in cases {
        let uri = format!("{base}&{query}");
        let value = config(Engine::Xray, &uri).unwrap();
        assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(value["inbounds"][0]["settings"]["udp"], true);
        let outbound = &value["outbounds"][0];
        let user = &outbound["settings"]["vnext"][0]["users"][0];
        assert_eq!(user["id"], UUID);
        assert_eq!(user["encryption"], "none");
        assert!(user.get("packetEncoding").is_none());
        assert!(outbound.get("mux").is_none());
        assert_eq!(
            user["flow"],
            if network == "tcp" {
                "xtls-rprx-vision"
            } else {
                ""
            }
        );
        let stream = &outbound["streamSettings"];
        assert_eq!(stream["network"], network);
        assert_eq!(stream["security"], "reality");
        assert_eq!(
            stream["realitySettings"],
            json!({"serverName":"verify.example","fingerprint":"chrome","password":key,"shortId":"ab12"})
        );
        assert_eq!(stream[format!("{network}Settings")], settings);
        assert!(config(Engine::SingBox, &uri).is_err(), "{query}");
    }
}

#[test]
fn reality_uri_rejects_unmapped_packet_encoding_and_transport_options() {
    let base = format!(
        "vless://{UUID}@secret.example:443?encryption=none&security=reality&sni=verify.example&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12"
    );
    for query in [
        "type=tcp&packetEncoding=xudp",
        "type=tcp&flow=xtls-rprx-vision&packetEncoding=packetaddr",
        "type=tcp&flow=xtls-rprx-vision&packetEncoding=",
        "type=grpc&serviceName=svc&packetEncoding=packetaddr",
        "type=grpc&serviceName=svc&flow=xtls-rprx-vision",
        "type=grpc&serviceName=svc&mode=multi",
        "type=xhttp&path=%2Fstream&flow=xtls-rprx-vision",
        "type=xhttp&path=%2Fstream&extra=%7B%7D",
        "type=ws&path=%2Fstream",
    ] {
        assert!(
            config(Engine::Xray, &format!("{base}&{query}")).is_err(),
            "{query}"
        );
    }
    assert_eq!(
        config(
            Engine::Xray,
            &format!(
                "vless://{UUID}@secret.example:443?security=tls&flow=xtls-rprx-vision&packetEncoding=xudp"
            )
        ),
        Err(CompileError::UnsupportedOption)
    );
}

#[test]
fn third_subscription_reality_shapes_preserve_explicit_xudp() {
    let base = format!(
        "vless://{UUID}@secret.example:443?encryption=none&security=reality&sni=verify.example&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab12&packetEncoding=xudp"
    );
    let tcp = config(
        Engine::Xray,
        &format!("{base}&type=tcp&flow=xtls-rprx-vision"),
    )
    .unwrap();
    assert!(tcp["outbounds"][0].get("mux").is_none());

    for (shape, settings_key, settings) in [
        (
            "type=xhttp&mode=auto&path=%2Fstream",
            "xhttpSettings",
            json!({"host":"","path":"/stream","mode":"auto"}),
        ),
        (
            "type=grpc&mode=gun&serviceName=sample&spx=%2Fprobe",
            "grpcSettings",
            json!({"serviceName":"sample"}),
        ),
    ] {
        let uri = format!("{base}&{shape}&alpn=");
        let value = config(Engine::Xray, &uri).unwrap();
        let outbound = &value["outbounds"][0];
        assert_eq!(
            outbound["mux"],
            json!({"enabled":true,"concurrency":-1,"xudpConcurrency":1})
        );
        assert_eq!(outbound["settings"]["vnext"][0]["users"][0]["flow"], "");
        let stream = &outbound["streamSettings"];
        assert_eq!(stream[settings_key], settings);
        if settings_key == "grpcSettings" {
            assert_eq!(stream["realitySettings"]["spiderX"], "/probe");
        }
        assert!(config(Engine::SingBox, &uri).is_err());
        assert_eq!(
            config(Engine::Xray, &format!("{uri}h2")),
            Err(CompileError::UnsupportedOption)
        );
    }
}

#[test]
fn hysteria2_uri_compiles_to_xray_quic_with_transport_auth() {
    let uri = "hysteria2://unit:sample%40value@secret.example:8443?sni=verify.example";
    let value = config(Engine::Xray, uri).unwrap();
    assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
    assert_eq!(value["inbounds"][0]["settings"]["udp"], true);
    assert_eq!(
        value["outbounds"],
        json!([{
            "tag":"proxy","protocol":"hysteria",
            "settings":{"version":2,"address":"secret.example","port":8443},
            "streamSettings":{
                "network":"hysteria","security":"tls",
                "hysteriaSettings":{"version":2,"auth":"unit:sample@value"},
                "tlsSettings":{"serverName":"verify.example","allowInsecure":false,"useSystemCA":true}
            }
        }])
    );
    assert_eq!(
        config(Engine::SingBox, uri),
        Err(CompileError::UnsupportedTransport)
    );
    for extra in [
        "obfs=salamander",
        "insecure=1",
        "allowInsecure=0",
        "type=quic",
        "alpn=h3",
        "security=tls",
    ] {
        assert_eq!(
            config(Engine::Xray, &format!("{uri}&{extra}")),
            Err(CompileError::UnsupportedOption)
        );
    }
    assert_eq!(
        config(Engine::Xray, &uri.replace("verify.example", "bad%0Aname")),
        Err(CompileError::InvalidParameter)
    );
}
