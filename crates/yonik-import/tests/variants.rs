use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use yonik_import::{Credentials, Protocol, Security, import_bytes};

#[test]
fn ipv6_idna_and_default_ports_are_normalized() {
    let report = import_bytes(
        "trojan://pass@пример.рф:443\nsocks5://[::1]\nhttps://example.test"
            .as_bytes()
            .to_vec(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(report.issues.is_empty());
    assert_eq!(report.servers[0].endpoint().host(), "xn--e1afmkfd.xn--p1ai");
    assert_eq!(report.servers[1].endpoint().host(), "::1");
    assert_eq!(report.servers[1].endpoint().port(), 1080);
    assert_eq!(report.servers[2].endpoint().port(), 443);
    assert_eq!(report.servers[2].security(), Security::Tls);
}

#[test]
fn shadowsocks_legacy_and_escaped_userinfo_keep_password_exact() {
    let legacy = STANDARD.encode("aes-128-gcm:pass@word:?@example.test:8388");
    let report = import_bytes(
        format!("ss://{legacy}\nss://aes-128-gcm:pass%40word%3A%3F@example.test:8388").into_bytes(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(report.issues.is_empty());
    assert_eq!(report.servers.len(), 2);
    for server in report.servers {
        match server.credentials() {
            Credentials::Shadowsocks { method, password } => {
                assert_eq!(method.expose(), "aes-128-gcm");
                assert_eq!(password.expose(), "pass@word:?");
            }
            other => panic!("Неожиданный вид credentials: {other:?}"),
        }
    }
}

#[test]
fn urlsafe_unpadded_envelope_and_bom_are_supported() {
    let text = "\u{feff}\nsocks5://127.0.0.1:1080\n";
    let encoded = URL_SAFE_NO_PAD.encode(text);
    let report =
        import_bytes(format!(" \n{encoded}\n").into_bytes()).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(report.base64_envelope);
    assert_eq!(report.servers[0].protocol(), Protocol::Socks5);
}

#[test]
fn json_brackets_in_strings_do_not_consume_nesting_budget() {
    let text = serde_json::json!({"label": "[".repeat(100)}).to_string();
    let report = import_bytes(text.into_bytes()).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(report.native_json.is_some());
}

#[test]
fn hysteria2_authority_is_one_auth_value_and_part_of_identity() {
    use yonik_import::{ReviewFlag, Transport};

    let report = import_bytes(
        b"hysteria2://unit:sample%40value@127.0.0.1:8443?sni=verify.example#a\n\
          hysteria2://unit%3Asample%40value@127.0.0.1:8443?sni=verify.example#b\n\
          hysteria2://unit:changed@127.0.0.1:8443?sni=verify.example\n\
          hysteria2://unit:sample%40value@127.0.0.1:8443?sni=other.example\n\
          hysteria2://unit:sample%40value@127.0.0.1:8443?sni=verify.example&obfs=salamander"
            .to_vec(),
    )
    .unwrap();
    assert!(report.issues.is_empty());
    assert_eq!(report.servers.len(), 5);
    let first = &report.servers[0];
    assert_eq!(first.protocol().as_str(), "hysteria2");
    assert_eq!(first.transport(), Transport::Quic);
    assert_eq!(first.security(), Security::Tls);
    assert!(first.review_flags().is_empty());
    let Credentials::Password(auth) = first.credentials() else {
        panic!("Ожидается один auth из authority");
    };
    assert_eq!(auth.expose(), "unit:sample@value");
    assert!(!format!("{first:?}").contains("sample"));
    let base = first.identity_material().unwrap();
    assert_eq!(
        base.expose(),
        report.servers[1].identity_material().unwrap().expose()
    );
    for server in &report.servers[2..] {
        assert_ne!(base.expose(), server.identity_material().unwrap().expose());
    }
    assert_eq!(
        report.servers[4].review_flags(),
        [ReviewFlag::UnknownParameter]
    );
}

#[test]
fn hysteria2_rejects_invalid_authority_and_duplicate_options() {
    use yonik_import::IssueCode;

    let report = import_bytes(
        b"hysteria2://@127.0.0.1:8443?sni=verify.example\n\
          hysteria2://unit%0Av@127.0.0.1:8443?sni=verify.example\n\
          hysteria2://unit@127.0.0.1:8443?sni=a.example&sni=b.example"
            .to_vec(),
    )
    .unwrap();
    assert!(report.servers.is_empty());
    assert_eq!(
        report
            .issues
            .iter()
            .map(|issue| issue.code)
            .collect::<Vec<_>>(),
        [
            IssueCode::InvalidCredentials,
            IssueCode::InvalidCredentials,
            IssueCode::DuplicateParameter
        ]
    );
}
