use yonik_desktop::editor::{Draft, RuleInput};

#[test]
fn составной_dto_сохраняет_таблицу_истинности_после_сериализации() {
    use yonik_domain::{
        Destination, DestinationFlow, Evaluation, EvaluationContext, Route, RuleOrigin,
    };
    let mut draft = Draft::default();
    draft
        .put(
            RuleInput {
                transport: None,
                platform_sources: None,
                id: 41,
                enabled: true,
                executables: vec!["/fixture/one".into(), "/fixture/two".into()],
                domains: vec!["EXAMPLE.ORG.".into(), "*.ПРИМЕР.РФ".into()],
                destinations: vec!["192.0.2.1".into(), "2001:db8::/32".into()],
                action: "block".into(),
            },
            false,
        )
        .expect("составной DTO");
    let restored = Draft::parse(&draft.json()).expect("сохранённый DTO");
    let policy = restored.policy().expect("общая политика");
    // Oracle — полная таблица трёх независимых признаков, без вызова matcher.
    for (source, source_matches) in [(Some("/fixture/two"), true), (None, false)] {
        for (host, domain_matches) in [
            ("example.org", true),
            ("a.xn--e1afmkfd.xn--p1ai", true),
            ("notexample.org", false),
        ] {
            let name = host.parse().expect("fixture domain");
            for (address, network_matches) in [
                ("192.0.2.1", true),
                ("2001:db8::1", true),
                ("192.0.2.2", false),
            ] {
                let result = policy.evaluate_destination(
                    &DestinationFlow {
                        executable: source,
                        destination: Destination::Ip {
                            address: address.parse().expect("fixture IP"),
                            name: Some(&name),
                        },
                    },
                    &EvaluationContext::default(),
                );
                let Evaluation::Decided { decision, .. } = result else {
                    panic!("literal должен дать решение: {result:?}")
                };
                let expected = if source_matches && domain_matches && network_matches {
                    (Route::Block, RuleOrigin::User(41))
                } else {
                    (Route::Proxy, RuleOrigin::Default)
                };
                assert_eq!(
                    (decision.action, decision.origin),
                    expected,
                    "{source:?} {host} {address}"
                );
            }
        }
    }
}

#[test]
fn обновление_id_сохраняет_порядок_и_решения_при_десятикратном_росте() {
    use yonik_domain::{Flow, Route, RuleOrigin};
    for count in [10_u64, 100] {
        let mut draft = Draft {
            default_action: "direct".into(),
            ..Draft::default()
        };
        for id in 1..=count {
            draft
                .put(
                    RuleInput {
                        transport: None,
                        platform_sources: None,
                        id,
                        enabled: true,
                        executables: vec![format!("/fixture/app{id}")],
                        domains: vec![],
                        destinations: vec!["192.0.2.1".into()],
                        action: "block".into(),
                    },
                    false,
                )
                .expect("добавление");
        }
        // Последнее широкое правило делает потерю/перестановку ID наблюдаемой.
        draft
            .put(
                RuleInput {
                    transport: None,
                    platform_sources: None,
                    id: count + 1,
                    enabled: true,
                    executables: vec![],
                    domains: vec![],
                    destinations: vec![],
                    action: "proxy".into(),
                },
                true,
            )
            .expect("fallback");
        let mut replacement = draft.rules[0].clone();
        replacement.action = "direct".into();
        draft.put(replacement, false).expect("обновление на месте");
        let saved = draft.json();
        let restored = Draft::parse(&saved).expect("чтение сохранённого DTO");
        let policy = restored.policy().expect("преобразование");
        assert_eq!(policy.default_action, yonik_domain::Action::Direct);
        assert_eq!(
            policy.user_rules.iter().map(|r| r.id).collect::<Vec<_>>(),
            (1..=count + 1).collect::<Vec<_>>()
        );
        for id in 1..=count {
            let path = format!("/fixture/app{id}");
            for (address, expected, origin) in [
                (
                    "192.0.2.1",
                    if id == 1 { Route::Direct } else { Route::Block },
                    RuleOrigin::User(id),
                ),
                ("192.0.2.2", Route::Proxy, RuleOrigin::User(count + 1)),
            ] {
                let decision = policy.evaluate(&Flow {
                    executable: Some(&path),
                    destination: address.parse().expect("fixture IP"),
                });
                assert_eq!((decision.action, decision.origin), (expected, origin));
            }
        }
        let mut invalid = draft.rules[0].clone();
        invalid.destinations = vec!["192.0.2.1/24".into()];
        assert!(draft.put(invalid, false).is_err());
        assert_eq!(draft.json(), saved);
        assert_eq!(restored.json(), saved);
    }
}
#[test]
fn compound_roundtrip_and_invalid_input_preserve_draft() {
    let mut draft = Draft::default();
    let rule = RuleInput {
        transport: None,
        platform_sources: None,
        id: 1,
        enabled: true,
        executables: vec!["/usr/bin/browser".into()],
        domains: vec!["*.example.org".into()],
        destinations: vec!["192.0.2.0/24".into()],
        action: "direct".into(),
    };
    draft.put(rule.clone(), false).expect("составное правило");
    let json = draft.json();
    let restored = Draft::parse(&json).expect("roundtrip");
    assert_eq!(restored.json(), json);
    assert_eq!(restored.policy().expect("Policy").user_rules.len(), 1);
    let mut invalid = rule;
    invalid.domains = vec!["bad domain".into()];
    assert!(draft.put(invalid, false).is_err());
    assert_eq!(draft.json(), json);
}
#[test]
fn broad_confirmation_ids_and_limits() {
    let mut draft = Draft::default();
    let mut rule = RuleInput {
        transport: None,
        platform_sources: None,
        id: 1,
        enabled: true,
        executables: vec![],
        domains: vec![],
        destinations: vec![],
        action: "block".into(),
    };
    assert!(draft.put(rule.clone(), false).is_err());
    draft.put(rule.clone(), true).expect("подтверждение");
    rule.id = 0;
    assert!(draft.put(rule.clone(), true).is_err());
    rule.id = 2;
    rule.executables = vec!["/bin/a".into(); 65];
    assert!(draft.put(rule, true).is_err());
    assert!(Draft::parse("{broken").is_err());
}

#[tokio::test]
async fn encrypted_draft_roundtrip_and_cas() {
    let dir = std::env::temp_dir().join(format!("yonik-editor-db-{}", std::process::id()));
    std::fs::create_dir(&dir).expect("fixture");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("права");
    let repo = yonik_linux::EncryptedSubscriptionRepository::open(
        dir.join("draft.sqlite"),
        zeroize::Zeroizing::new([17; 32]),
    )
    .await
    .expect("БД");
    assert!(repo.routing_draft().await.expect("чтение").is_none());
    let raw = Draft::default().json().into_bytes();
    assert_eq!(
        repo.save_routing_draft(0, raw.clone())
            .await
            .expect("запись"),
        1
    );
    assert!(repo.save_routing_draft(0, b"stale".to_vec()).await.is_err());
    let (revision, restored) = repo.routing_draft().await.expect("чтение").expect("draft");
    assert_eq!(revision, 1);
    assert_eq!(*restored, raw);
    repo.close().await.expect("закрытие");
    let repo = yonik_linux::EncryptedSubscriptionRepository::open(
        dir.join("draft.sqlite"),
        zeroize::Zeroizing::new([17; 32]),
    )
    .await
    .expect("повторный запуск");
    let (_, bytes) = repo.routing_draft().await.expect("чтение").expect("запись");
    assert!(Draft::parse(std::str::from_utf8(&bytes).expect("UTF8")).is_ok());
    repo.save_routing_draft(1, b"{broken".to_vec())
        .await
        .expect("синтетическое повреждение");
    let (_, bytes) = repo
        .routing_draft()
        .await
        .expect("исходник")
        .expect("запись");
    assert!(Draft::parse(std::str::from_utf8(&bytes).expect("UTF8")).is_err());
    assert_eq!(bytes.as_slice(), b"{broken");
    repo.close().await.expect("закрытие");
    std::fs::remove_dir_all(dir).expect("очистка fixture");
}

#[test]
fn pid_is_not_a_persistent_selector() {
    assert!(Draft::parse(r#"{"version":1,"default_action":"proxy","rules":[{"id":1,"enabled":true,"executables":[],"domains":[],"destinations":[],"action":"direct","pid":1234}]}"#).is_err());
}

#[test]
fn bounded_diagnostics_keep_identity_and_disabled_semantics() {
    let mut draft = Draft::default();
    for id in 1..=3 {
        draft
            .put(
                RuleInput {
                    transport: None,
                    platform_sources: None,
                    id,
                    enabled: id != 3,
                    executables: vec![],
                    domains: vec!["example.org".into()],
                    destinations: vec![],
                    action: "direct".into(),
                },
                false,
            )
            .expect("правило");
    }
    let report = draft.diagnostics();
    assert_eq!(report["warnings"][0]["rule_id"], 2);
    assert_eq!(report["warnings"][0]["kind"], "shadowed");
    assert_eq!(report["warnings"].as_array().expect("массив").len(), 1);
    assert_eq!(report["incomplete"], false);
    draft.rules[0].destinations = vec!["192.0.2.0/24".into()];
    assert_eq!(
        draft.diagnostics()["warnings"][0]["kind"],
        "potential_overlap"
    );
    draft.rules[0].domains = (0..33).map(|i| format!("a{i}.example.org")).collect();
    assert_eq!(draft.diagnostics()["incomplete"], true);
    assert!(
        draft.diagnostics()["warnings"]
            .as_array()
            .expect("массив")
            .is_empty()
    );
}

#[test]
fn explanation_uses_evaluator_without_claiming_runtime_witness() {
    let mut draft = Draft::default();
    assert_eq!(draft.explain("192.0.2.1").expect("IP")["origin"], "Default");
    assert_eq!(
        draft.explain("example.org").expect("имя")["status"],
        "unknown"
    );
    draft
        .put(
            RuleInput {
                transport: None,
                platform_sources: None,
                id: 7,
                enabled: true,
                executables: vec![],
                domains: vec![],
                destinations: vec!["192.0.2.0/24".into()],
                action: "block".into(),
            },
            false,
        )
        .expect("правило");
    let before = draft.json();
    assert_eq!(draft.explain("192.0.2.1").expect("IP")["origin"], "User(7)");
    assert_eq!(draft.explain("192.0.2.1").expect("IP")["action"], "Block");
    assert!(draft.explain("bad domain").is_err());
    assert_eq!(draft.json(), before);
    draft.rules[0].executables.push("/fixture/app".into());
    assert_eq!(
        draft.explain("192.0.2.1").expect("нет атрибуции")["reason"],
        "application_witness_missing"
    );
}

#[test]
fn truncated_report_is_explicit_and_preserves_policy() {
    let mut draft = Draft::default();
    for id in 1..=25 {
        draft
            .put(
                RuleInput {
                    transport: None,
                    platform_sources: None,
                    id,
                    enabled: true,
                    executables: vec![],
                    domains: vec![],
                    destinations: vec![],
                    action: "proxy".into(),
                },
                true,
            )
            .expect("широкое правило");
    }
    let before = draft.json();
    let report = draft.diagnostics();
    assert_eq!(report["incomplete"], true);
    assert_eq!(report["warnings"].as_array().expect("массив").len(), 256);
    assert_eq!(draft.json(), before);
}

#[test]
fn p07_closed_v2_preserves_disabled_and_rejects_enabled_before_witness() {
    let raw = r#"{"version":2,"default_action":"direct","ru_direct":null,"rules":[{"id":41,"enabled":false,"executables":["/usr/bin/client"],"domains":[],"destinations":[],"action":"proxy","platform_sources":[{"kind":"android_package","package":"org.Example_app"}]}]}"#;
    let draft = Draft::parse(raw).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&draft.json()).unwrap(),
        serde_json::from_str::<serde_json::Value>(raw).unwrap()
    );
    assert_eq!(
        draft.policy().unwrap().user_rules[0]
            .conditions
            .platform_sources
            .len(),
        1
    );
    assert!(draft.system_policy().is_ok());
    let enabled = Draft::parse(&raw.replace("false", "true")).unwrap();
    assert!(matches!(
        enabled.system_policy(),
        Err(yonik_engine::policy_input::PolicyInputError::UnsupportedSelector(41))
    ));
    assert_eq!(
        enabled.explain("1.1.1.1").unwrap()["reason"],
        "unsupported_selector"
    );
    assert_eq!(enabled.explain("1.1.1.1").unwrap()["rule_id"], 41);
    for invalid in [
        raw.replace("org.Example_app", "org.1app"),
        raw.replace("android_package", "future"),
        raw.replace("\"version\":2", "\"version\":4"),
        raw.replace("\"package\":", "\"extra\":true,\"package\":"),
    ] {
        assert!(Draft::parse(&invalid).is_err());
    }
    let mut v1 = Draft::default();
    let rule = draft.rules[0].clone();
    v1.put(rule, false).unwrap();
    assert_eq!(v1.version, 2);
    assert_eq!(Draft::parse(&v1.json()).unwrap().json(), v1.json());
}

#[tokio::test]
async fn p07_migration_cas_reopen() {
    let dir = std::env::temp_dir().join(format!("yonik-p07-migration-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("draft.sqlite");
    let repo = yonik_linux::EncryptedSubscriptionRepository::open(
        path.clone(),
        zeroize::Zeroizing::new([29; 32]),
    )
    .await
    .unwrap();
    assert!(repo.routing_draft().await.unwrap().is_none());
    let mut draft = Draft::default();
    let original = draft.json().into_bytes();
    assert_eq!(
        repo.save_routing_draft(0, original.clone()).await.unwrap(),
        1
    );
    draft
        .put(
            RuleInput {
                transport: None,
                id: 41,
                enabled: false,
                executables: vec![],
                domains: vec![],
                destinations: vec![],
                action: "proxy".into(),
                platform_sources: Some(vec![
                    yonik_engine::platform_source::PlatformSourceInput::AndroidPackage {
                        package: "org.example.app".into(),
                    },
                ]),
            },
            false,
        )
        .unwrap();
    repo.close().await.unwrap();
    let backup = dir.join("v3-backup.sqlite");
    yonik_linux::EncryptedSubscriptionRepository::backup_closed(
        path.clone(),
        backup.clone(),
        zeroize::Zeroizing::new([29; 32]),
    )
    .await
    .unwrap();
    let repo = yonik_linux::EncryptedSubscriptionRepository::open(
        path.clone(),
        zeroize::Zeroizing::new([29; 32]),
    )
    .await
    .unwrap();
    let migrated = draft.json().into_bytes();
    assert!(
        repo.save_routing_draft_v2(0, migrated.clone(), Some(backup.clone()))
            .await
            .is_err()
    );
    let (revision, bytes) = repo.routing_draft().await.unwrap().unwrap();
    assert_eq!(revision, 1);
    assert_eq!(*bytes, original);
    assert_eq!(
        repo.save_routing_draft_v2(1, migrated.clone(), Some(backup.clone()))
            .await
            .unwrap(),
        2
    );
    repo.close().await.unwrap();
    let repo =
        yonik_linux::EncryptedSubscriptionRepository::open(path, zeroize::Zeroizing::new([29; 32]))
            .await
            .unwrap();
    let (revision, bytes) = repo.routing_draft().await.unwrap().unwrap();
    assert_eq!(revision, 2);
    assert_eq!(*bytes, migrated);
    assert_eq!(
        Draft::parse(std::str::from_utf8(&bytes).unwrap())
            .unwrap()
            .version,
        2
    );
    repo.close().await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn p07_bounds_and_v2_required_field() {
    use yonik_engine::platform_source::PlatformSourceInput;
    let rule = RuleInput {
        transport: None,
        id: 1,
        enabled: false,
        executables: vec![],
        domains: vec![],
        destinations: vec![],
        action: "direct".into(),
        platform_sources: Some(
            (0..16)
                .map(|n| PlatformSourceInput::AndroidPackage {
                    package: format!("org.app{n}"),
                })
                .collect(),
        ),
    };
    let mut draft = Draft {
        ru_direct: None,
        local_vpn_direct: false,
        version: 2,
        rules: vec![rule.clone()],
        default_action: "direct".into(),
    };
    assert!(draft.policy().is_ok());
    draft.rules[0]
        .platform_sources
        .as_mut()
        .unwrap()
        .push(PlatformSourceInput::AndroidPackage {
            package: "org.extra".into(),
        });
    assert!(draft.policy().is_err());
    draft.rules = (1..=256)
        .map(|id| {
            let mut r = rule.clone();
            r.id = id;
            r
        })
        .collect();
    assert!(draft.policy().is_ok());
    draft.rules.push({
        let mut r = rule;
        r.id = 257;
        r
    });
    assert!(draft.policy().is_err());
    assert!(Draft::parse(r#"{"version":2,"rules":[{"id":1,"enabled":false,"executables":[],"domains":[],"destinations":[],"action":"direct"}],"default_action":"direct"}"#).is_err());
}

#[test]
fn explain_использует_разрешённый_preset_и_p07_guard() {
    use yonik_domain::{Action, AndroidPackageId, Conditions, PlatformSource, Rule};
    let draft = Draft::parse(
        &serde_json::json!({"version":2,"rules":[],"default_action":"proxy",
        "ru_direct":{"snapshot":"a".repeat(64),"enabled":true}})
        .to_string(),
    )
    .unwrap();
    assert!(draft.policy().is_err());
    let resolved = || {
        let mut policy = draft.base_policy().unwrap();
        policy.preset_rules.push(Rule {
            id: 77,
            enabled: true,
            action: Action::Direct,
            conditions: Conditions {
                destinations: vec!["192.0.2.0/24".parse().unwrap()],
                ..Conditions::default()
            },
        });
        policy
    };
    let result = draft.explain_with_policy("192.0.2.1", resolved()).unwrap();
    assert_eq!(result["status"], "fixture");
    assert_eq!(result["action"], "Direct");
    assert_eq!(result["origin"], "Preset(77)");
    let mut policy = resolved();
    policy.preset_rules[0]
        .conditions
        .platform_sources
        .push(PlatformSource::AndroidPackage {
            package: AndroidPackageId::parse("org.example.app").unwrap(),
        });
    let result = draft.explain_with_policy("192.0.2.1", policy).unwrap();
    assert_eq!(result["status"], "unsupported");
    assert_eq!(result["reason"], "unsupported_selector");
    assert_eq!(result["rule_id"], 77);
}

#[test]
fn транспорт_v3_редактор_roundtrip_и_отказ_активации() {
    let raw = r#"{"version":3,"default_action":"proxy","rules":[{"id":1,"enabled":false,"executables":["/fixture/app"],"domains":["example.org"],"destinations":["192.0.2.0/24"],"action":"block","platform_sources":[],"transport":{"transport_protocols":["tcp"],"destination_ports":[[443,443]]}}]}"#;
    let mut draft = Draft::parse(raw).unwrap();
    let before: serde_json::Value = serde_json::from_str(&draft.json()).unwrap();
    let mut rule = draft.rules[0].clone();
    rule.domains = vec!["other.example".into()];
    draft.put(rule, false).unwrap();
    let wire = draft.system_policy().unwrap();
    assert!(
        wire.policy().user_rules[0]
            .conditions
            .transport
            .constrained()
    );
    let after = Draft::parse(&draft.json()).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&after.json()).unwrap()["rules"][0]["transport"],
        before["rules"][0]["transport"]
    );
    draft.rules[0].enabled = true;
    assert!(matches!(
        draft.system_policy(),
        Err(yonik_engine::policy_input::PolicyInputError::UnsupportedTransport(1))
    ));
    assert!(Draft::parse(&raw.replace("\"version\":3", "\"version\":2")).is_err());
}
