use base64::{Engine as _, engine::general_purpose::STANDARD};
use yonik_import::{FatalError, ProfileEngine, ProfileEntry, import_bytes, import_profiles};

const FIXTURE: &str = include_str!("../../../tests/fixtures/xray-full-profile-seven.json");

#[test]
fn seven_independent_roots_keep_bytes_order_and_names() {
    let roots: Vec<&serde_json::value::RawValue> = serde_json::from_str(FIXTURE).unwrap();
    let report = import_profiles(FIXTURE.as_bytes().to_vec()).unwrap();
    assert_eq!(report.original().expose(), FIXTURE);
    assert_eq!(report.entries.len(), 7);
    assert!(report.issues.is_empty());
    for (ordinal, (entry, root)) in report.entries.iter().zip(roots).enumerate() {
        let ProfileEntry::Xray(profile) = entry else {
            panic!("Полный профиль превратился в сервер")
        };
        let value: serde_json::Value = serde_json::from_str(root.get()).unwrap();
        assert_eq!(profile.ordinal(), ordinal);
        assert_eq!(profile.engine(), ProfileEngine::Xray);
        assert_eq!(profile.name(), value["remarks"].as_str().unwrap());
        assert_eq!(profile.source().expose(), root.get());
        let mut bytes = Vec::new();
        profile.write_sensitive(&mut bytes).unwrap();
        assert_eq!(bytes, root.get().as_bytes());
    }
    assert!(!format!("{report:?}").contains("synthetic"));
    assert!(!format!("{report:?}").contains("example.invalid"));
}

#[test]
fn uri_and_single_base64_keep_server_api() {
    let uri = "trojan://synthetic-password@node.example.invalid:443#test";
    for text in [uri.to_owned(), STANDARD.encode(uri)] {
        let old = import_bytes(text.as_bytes().to_vec()).unwrap();
        let new = import_profiles(text.as_bytes().to_vec()).unwrap();
        assert_eq!(new.original().expose(), text);
        assert_eq!(new.entries.len(), old.servers.len());
        let ProfileEntry::Server(server) = &new.entries[0] else {
            panic!("Неверный вид")
        };
        assert_eq!(server.source().expose(), old.servers[0].source().expose());
        assert_eq!(new.base64_envelope, old.base64_envelope);
    }
    let encoded = STANDARD.encode(FIXTURE);
    let report = import_profiles(encoded.as_bytes().to_vec()).unwrap();
    assert!(report.base64_envelope);
    assert_eq!(report.original().expose(), encoded);
    assert_eq!(report.entries.len(), 7);
    assert!(import_profiles(STANDARD.encode(encoded).into_bytes()).is_err());
}

#[test]
fn unrecognized_and_invalid_documents_never_become_profiles() {
    for text in [
        "",
        "[]",
        "{}",
        "null",
        "42",
        "\"secret\"",
        "[1]",
        "[{}]",
        "{",
        "{\"outbounds\":[]}",
        "{\"outbounds\":[{\"type\":\"vless\"}]}",
        "{\"outbounds\":[{\"protocol\":\"vless\",\"type\":\"vless\"}]}",
        "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"password\":1,\"password\":2}}]}",
        "{\"outbounds\":[{\"protocol\":\"vless\"}],\"outbounds\":[]}",
    ] {
        let failure = import_profiles(text.as_bytes().to_vec()).unwrap_err();
        assert_eq!(failure.input(), text.as_bytes());
        assert!(failure.input_is_complete());
        assert!(!format!("{failure:?}").contains("password"));
    }
}

#[test]
fn boundaries_are_fatal_and_preserve_original() {
    let large = vec![b' '; yonik_import::MAX_INPUT_BYTES + 1];
    assert_eq!(
        import_profiles(large).unwrap_err().kind(),
        FatalError::TooLarge
    );
    let root = format!(
        "{{\"outbounds\":[{{\"protocol\":\"vless\"}}],\"opaque\":\"{}\"}}",
        "x".repeat(yonik_import::MAX_ENTRY_BYTES)
    );
    assert_eq!(
        import_profiles(root.into_bytes()).unwrap_err().kind(),
        FatalError::TooLarge
    );
    let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert_eq!(
        import_profiles(deep.into_bytes()).unwrap_err().kind(),
        FatalError::JsonTooDeep
    );
    let many = format!(
        "[{}]",
        vec!["{\"outbounds\":[{\"protocol\":\"freedom\"}]}"; yonik_import::MAX_RECORDS + 1]
            .join(",")
    );
    assert_eq!(
        import_profiles(many.into_bytes()).unwrap_err().kind(),
        FatalError::TooManyRecords
    );
}

#[test]
fn unsupported_effects_remain_data_and_debug_hides_labels() {
    let text = "{ \"remarks\":\"synthetic-password\", \"outbounds\":[{\"protocol\":\"future-extension\"}], \"log\":{\"access\":\"/secret/path\"}, \"unknown\":1e999 }";
    let report = import_profiles(text.as_bytes().to_vec()).unwrap();
    let ProfileEntry::Xray(profile) = &report.entries[0] else {
        panic!("Неверный вид")
    };
    assert_eq!(profile.source().expose(), text);
    assert!(!format!("{report:?}").contains("synthetic-password"));
    // Прежняя проекция по-прежнему доступна отдельно и не меняет смысл.
    assert!(import_bytes(FIXTURE.as_bytes().to_vec()).is_ok());
}
