use super::*;
use crate::{IpPrefix, NetworkAttribute};

fn fixture(ipv6: bool) -> LinuxRule {
    let address = if ipv6 { "::" } else { "0.0.0.0" }.parse().unwrap();
    LinuxRule {
        family: if ipv6 { 10 } else { 2 },
        destination: IpPrefix { address, length: 0 },
        source: IpPrefix { address, length: 0 },
        tos: 0,
        table: 1001,
        action: 1,
        flags: 2,
        priority: Some(100),
        goto: None,
        fwmark: Some(47),
        fwmask: Some(u32::MAX),
        uid_range: None,
        input_interface: None,
        output_interface: None,
        protocol: Some(253),
        ip_protocol: None,
        source_ports: None,
        destination_ports: None,
        suppress_prefix_len: Some(u32::MAX),
        suppress_interface_group: None,
        l3mdev: None,
        unknown: Vec::new(),
    }
}
#[test]
fn rule_ranges_are_closed() {
    for (priority, table, mark) in [
        (0, 1001, 47),
        (32766, 1001, 47),
        (100, 255, 47),
        (100, u32::MAX, 47),
        (100, 1001, 0),
        (100, 1001, i32::MAX as u32 + 1),
    ] {
        assert!(TunRule::new(priority, table, mark, false).is_err());
    }
    assert!(TunRule::new(1, 256, 1, false).is_ok());
    assert!(TunRule::new(32765, u32::MAX - 1, i32::MAX as u32, true).is_ok());
}
#[test]
fn matcher_rejects_every_additional_selector_and_metadata() {
    for ipv6 in [false, true] {
        let expected = TunRule::new(100, 1001, 47, ipv6).unwrap();
        let original = fixture(ipv6);
        assert!(rule_matches(&original, expected));
        let changes: [fn(&mut LinuxRule); 25] = [
            |r| r.family ^= 8,
            |r| r.destination.length = 1,
            |r| r.source.length = 1,
            |r| r.source.address = "192.0.2.1".parse().unwrap(),
            |r| r.destination.address = "192.0.2.1".parse().unwrap(),
            |r| r.tos = 1,
            |r| r.table += 1,
            |r| r.action = 2,
            |r| r.flags = 0,
            |r| r.flags |= 4,
            |r| r.priority = None,
            |r| r.goto = Some(1),
            |r| r.fwmark = Some(48),
            |r| r.fwmask = None,
            |r| r.uid_range = Some((0, 0)),
            |r| r.input_interface = Some(b"lo".to_vec()),
            |r| r.output_interface = Some(b"lo".to_vec()),
            |r| r.protocol = None,
            |r| r.ip_protocol = Some(6),
            |r| r.source_ports = Some((1, 1)),
            |r| r.destination_ports = Some((1, 1)),
            |r| r.suppress_prefix_len = Some(0),
            |r| r.suppress_interface_group = Some(0),
            |r| r.l3mdev = Some(false),
            |r| {
                r.unknown.push(NetworkAttribute {
                    kind: 99,
                    value: vec![],
                })
            },
        ];
        for (index, change) in changes.iter().enumerate() {
            let mut changed = original.clone();
            change(&mut changed);
            assert!(!rule_matches(&changed, expected), "поле {index}");
        }
    }
}

struct Area(std::path::PathBuf);
impl Area {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "yonik-rpdb-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Area {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn topology() -> LinuxTopology {
    LinuxTopology {
        namespace: crate::NetworkNamespace {
            device: 4,
            inode: 99,
        },
        links: vec![],
        addresses: vec![],
        routes: vec![],
        rules: vec![],
        nexthops: vec![],
    }
}
#[test]
fn priority_conflicts_include_other_tables_and_duplicates() {
    let expected = TunRule::new(100, 1001, 47, false).unwrap();
    let mut snapshot = topology();
    snapshot.rules.push(fixture(true));
    assert_eq!(observe_rule(&snapshot, expected), Ok(false));
    snapshot.rules.push(fixture(false));
    assert_eq!(observe_rule(&snapshot, expected), Ok(true));
    snapshot.rules.push(fixture(false));
    assert_eq!(observe_rule(&snapshot, expected), Err(TunError::Foreign));
    snapshot.rules.remove(1);
    snapshot.rules[1].table = 2001;
    assert_eq!(observe_rule(&snapshot, expected), Err(TunError::Foreign));
}
fn owned_fixture(area: &Area) -> (Journal, LinuxTopology) {
    let owner = crate::managed_network::Ownership::new(1000, 7, 9, 4, 99).unwrap();
    let mut journal = Journal::open(&area.0.join("state"), owner).unwrap();
    journal
        .intent(owner, Scope::Session, 1, Resource::Tun { name_id: 7 })
        .unwrap();
    journal.reconcile(owner, 1, Reconciled::Owned).unwrap();
    let mut snapshot = topology();
    snapshot.links.push(crate::LinuxLink {
        index: 7,
        link_type: 65534,
        flags: 1,
        name: b"tofu00000007".to_vec(),
        alias: Some(super::super::alias(owner, 1).unwrap()),
        mtu: Some(1400),
        master: None,
        parent: None,
        kind: Some(b"tun".to_vec()),
        operational_state: None,
        unknown: vec![],
    });
    (journal, snapshot)
}
#[test]
fn references_require_confirmed_rule_and_complete_parent_anchor() {
    let area = Area::new();
    let (mut journal, mut snapshot) = owned_fixture(&area);
    let owner = journal.ownership();
    snapshot.rules.push(fixture(false));
    let resource = Resource::TunRule {
        tun_id: 1,
        ifindex: 7,
        priority: 100,
        table: 1001,
        mark: 47,
        ipv6: false,
    };
    journal.intent(owner, Scope::Session, 2, resource).unwrap();
    assert_eq!(
        check_references(&snapshot, &journal, 7, 1001, None),
        Err(TunError::Foreign)
    );
    journal.reconcile(owner, 2, Reconciled::Owned).unwrap();
    assert!(check_references(&snapshot, &journal, 7, 1001, None).is_ok());
    snapshot.links[0].index = 8;
    assert_eq!(
        check_references(&snapshot, &journal, 7, 1001, None),
        Err(TunError::Foreign)
    );
    snapshot.links[0].index = 7;
    snapshot.links[0].alias.as_mut().unwrap().push(b'x');
    assert_eq!(
        check_references(&snapshot, &journal, 7, 1001, None),
        Err(TunError::Foreign)
    );
    snapshot.links[0].alias = Some(super::super::alias(owner, 1).unwrap());
    journal.mark_update(owner, 1).unwrap();
    assert_eq!(
        check_references(&snapshot, &journal, 7, 1001, None),
        Err(TunError::Foreign)
    );
}
#[test]
fn table_requires_actual_confirmed_default_for_correct_family_and_no_foreign_route() {
    let area = Area::new();
    let (mut journal, mut snapshot) = owned_fixture(&area);
    let expected = TunRule::new(100, 1001, 47, false).unwrap();
    assert_eq!(
        check_table(&snapshot, &journal, 1, 7, expected, true),
        Err(TunError::Evidence)
    );
    let route = crate::LinuxRoute {
        family: 2,
        destination: IpPrefix {
            address: "0.0.0.0".parse().unwrap(),
            length: 0,
        },
        source: IpPrefix {
            address: "0.0.0.0".parse().unwrap(),
            length: 0,
        },
        table: 1001,
        preferred_source: None,
        gateway: None,
        output_interface: Some(7),
        input_interface: None,
        priority: Some(47),
        protocol: 253,
        kind: 1,
        scope: 253,
        tos: 0,
        flags: 0,
        multipath: vec![],
        nexthop_id: None,
        unknown: vec![],
    };
    snapshot.routes.push(route);
    assert_eq!(
        check_table(&snapshot, &journal, 1, 7, expected, true),
        Err(TunError::Foreign)
    );
    let owner = journal.ownership();
    journal
        .intent(
            owner,
            Scope::Session,
            2,
            Resource::Route {
                table: 1001,
                destination: "0.0.0.0".parse().unwrap(),
                prefix_len: 0,
                priority: 47,
                protocol: 253,
                ifindex: 7,
            },
        )
        .unwrap();
    assert_eq!(
        check_table(&snapshot, &journal, 1, 7, expected, true),
        Err(TunError::Foreign)
    );
    journal.reconcile(owner, 2, Reconciled::Owned).unwrap();
    assert!(check_table(&snapshot, &journal, 1, 7, expected, true).is_ok());
    assert_eq!(
        check_table(
            &snapshot,
            &journal,
            1,
            7,
            TunRule::new(100, 1001, 47, true).unwrap(),
            true
        ),
        Err(TunError::Evidence)
    );
    let mut foreign = snapshot.routes[0].clone();
    foreign.priority = Some(48);
    snapshot.routes.push(foreign);
    assert_eq!(
        check_table(&snapshot, &journal, 1, 7, expected, true),
        Err(TunError::Foreign)
    );
}
fn ip(args: &[&str]) -> serde_json::Value {
    let output = std::process::Command::new("/usr/bin/ip")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&output.stdout).unwrap()
    }
}
#[tokio::test]
#[ignore = "Требует отдельные user/net/mount/pid namespaces и приватные /run, /tmp"]
async fn real_namespace_owned_rpdb_and_cleanup() {
    use super::super::{TunAddress, TunRoute};
    let namespace = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
    let (device, inode) = super::super::namespace(&namespace).unwrap();
    let owner = crate::managed_network::Ownership::new(
        rustix::process::getuid().as_raw(),
        7,
        9,
        device,
        inode,
    )
    .unwrap();
    let mut executor = TunExecutor::isolated_fixture(owner).unwrap();
    let area = Area::new();
    let mut journal = Journal::open(&area.0.join("state"), owner).unwrap();
    let index = executor.ensure_tun(&mut journal, 1, 7).await.unwrap();
    executor
        .configure_link(&mut journal, 1, 1400)
        .await
        .unwrap();
    executor
        .ensure_address(
            &mut journal,
            1,
            2,
            TunAddress::new("198.18.0.1".parse().unwrap(), 30).unwrap(),
        )
        .await
        .unwrap();
    executor
        .ensure_address(
            &mut journal,
            1,
            3,
            TunAddress::new("2001:db8:746f::1".parse().unwrap(), 126).unwrap(),
        )
        .await
        .unwrap();
    let r4 = TunRoute::new("0.0.0.0".parse().unwrap(), 0, 1001, 47).unwrap();
    let r6 = TunRoute::new("::".parse().unwrap(), 0, 1001, 47).unwrap();
    executor.ensure_route(&mut journal, 1, 4, r4).await.unwrap();
    executor.ensure_route(&mut journal, 1, 5, r6).await.unwrap();
    let rule4 = TunRule::new(10001, 1001, 47, false).unwrap();
    let rule6 = TunRule::new(10001, 1001, 47, true).unwrap();
    if let Err(error) = executor.ensure_rule(&mut journal, 1, 6, rule4).await {
        let snapshot = executor.configuration_snapshot().await.unwrap();
        let details: Vec<_> = snapshot
            .rules
            .iter()
            .filter(|r| r.priority == Some(10001))
            .map(|r| {
                (
                    r.flags,
                    r.action,
                    r.protocol,
                    r.suppress_prefix_len,
                    r.suppress_interface_group,
                    r.l3mdev,
                    r.unknown
                        .iter()
                        .map(|a| (a.kind, a.value.clone()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        panic!(
            "{error:?}: {details:?} {}",
            ip(&["-4", "-j", "-d", "rule", "show"])
        );
    }
    executor
        .ensure_rule(&mut journal, 1, 7, rule6)
        .await
        .unwrap();
    // Общая очистка помечает обе семьи до первого удаления: оставшееся
    // CleanupRemaining rule всё ещё должно распознаваться как собственное.
    for id in [6, 7] {
        journal.mark_cleanup(owner, id).unwrap();
    }
    for id in [6, 7] {
        executor.remove_rule(&mut journal, 1, id).await.unwrap();
    }
    executor
        .ensure_rule(&mut journal, 1, 6, rule4)
        .await
        .unwrap();
    executor
        .ensure_rule(&mut journal, 1, 7, rule6)
        .await
        .unwrap();
    // Отдельный нормальный путь нужен для проверки обхода инверсного правила.
    ip(&["link", "add", "rpdb-normal", "type", "dummy"]);
    ip(&["link", "set", "rpdb-normal", "up"]);
    ip(&["address", "add", "192.0.2.1/24", "dev", "rpdb-normal"]);
    ip(&[
        "-6",
        "address",
        "add",
        "2001:db8:1::1/64",
        "dev",
        "rpdb-normal",
        "nodad",
    ]);
    for family in ["-4", "-6"] {
        ip(&[family, "route", "add", "default", "dev", "rpdb-normal"]);
    }
    for (family, target) in [("-4", "203.0.113.1"), ("-6", "2001:db8:ffff::2")] {
        assert_eq!(
            ip(&[family, "-j", "route", "get", target])[0]["dev"],
            "tofu00000007"
        );
        assert_eq!(
            ip(&[family, "-j", "route", "get", target, "mark", "47"])[0]["dev"],
            "rpdb-normal"
        );
    }
    // Собственные confirmed ссылки разрешают сверку существующих маршрутов.
    executor.ensure_route(&mut journal, 1, 4, r4).await.unwrap();
    assert!(executor.remove_route(&mut journal, 1, 4).await.is_err());
    // Чужой приоритет конфликтует даже при другой таблице.
    ip(&["-4", "rule", "add", "priority", "10010", "lookup", "1002"]);
    assert!(
        executor
            .ensure_rule(
                &mut journal,
                1,
                10,
                TunRule::new(10010, 1001, 47, false).unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        executor
            .configuration_snapshot()
            .await
            .unwrap()
            .rules
            .iter()
            .any(|r| r.priority == Some(10010) && r.table == 1002)
    );
    // Точное, но неподтверждённое намерение нельзя присвоить или удалить.
    journal
        .intent(
            owner,
            Scope::Session,
            8,
            Resource::TunRule {
                tun_id: 1,
                ifindex: index,
                priority: 10002,
                table: 1001,
                mark: 47,
                ipv6: false,
            },
        )
        .unwrap();
    ip(&[
        "-4",
        "rule",
        "add",
        "not",
        "fwmark",
        "47/0xffffffff",
        "priority",
        "10002",
        "table",
        "1001",
        "protocol",
        "253",
    ]);
    drop(journal);
    let mut journal = Journal::open(&area.0.join("state"), owner).unwrap();
    assert!(
        executor
            .ensure_rule(
                &mut journal,
                1,
                8,
                TunRule::new(10002, 1001, 47, false).unwrap()
            )
            .await
            .is_err()
    );
    assert!(executor.remove_rule(&mut journal, 1, 8).await.is_err());
    assert!(executor.remove_rule(&mut journal, 1, 6).await.is_err());
    assert!(executor.remove_tun(&mut journal, 1).await.is_err());
    ip(&[
        "-4",
        "rule",
        "del",
        "not",
        "fwmark",
        "47/0xffffffff",
        "priority",
        "10002",
        "table",
        "1001",
        "protocol",
        "253",
    ]);
    executor.remove_rule(&mut journal, 1, 8).await.unwrap();
    // Изменённый selector собственной записи сохраняется при cleanup.
    ip(&[
        "-4",
        "rule",
        "del",
        "not",
        "fwmark",
        "47/0xffffffff",
        "priority",
        "10001",
        "table",
        "1001",
        "protocol",
        "253",
    ]);
    ip(&[
        "-4",
        "rule",
        "add",
        "not",
        "fwmark",
        "48/0xffffffff",
        "priority",
        "10001",
        "table",
        "1001",
        "protocol",
        "253",
    ]);
    assert!(executor.remove_rule(&mut journal, 1, 6).await.is_err());
    ip(&[
        "-4",
        "rule",
        "del",
        "not",
        "fwmark",
        "48/0xffffffff",
        "priority",
        "10001",
        "table",
        "1001",
        "protocol",
        "253",
    ]);
    // Подтверждённое, но отсутствующее правило не создаётся повторно.
    assert!(
        executor
            .ensure_rule(&mut journal, 1, 6, rule4)
            .await
            .is_err()
    );
    executor.remove_rule(&mut journal, 1, 6).await.unwrap();
    executor
        .ensure_rule(&mut journal, 1, 7, rule6)
        .await
        .unwrap();
    assert!(!journal.needs_reconciliation(7));
    ip(&[
        "-6",
        "route",
        "del",
        "default",
        "table",
        "1001",
        "dev",
        "tofu00000007",
        "metric",
        "47",
        "proto",
        "253",
    ]);
    assert!(
        executor
            .ensure_rule(&mut journal, 1, 7, rule6)
            .await
            .is_err()
    );
    assert!(journal.needs_reconciliation(7));
    // Начатый общий cleanup сохраняет доказательство владения родителем и
    // маршрутом: CleanupRemaining должен разрешать удаление, но не Apply.
    for id in [1, 4] {
        journal.reconcile(owner, id, Reconciled::Owned).unwrap();
        journal.mark_cleanup(owner, id).unwrap();
    }
    executor.remove_rule(&mut journal, 1, 7).await.unwrap();
    executor.remove_route(&mut journal, 1, 5).await.unwrap();
    executor.remove_route(&mut journal, 1, 4).await.unwrap();
    executor.remove_address(&mut journal, 1, 3).await.unwrap();
    executor.remove_address(&mut journal, 1, 2).await.unwrap();
    executor.remove_tun(&mut journal, 1).await.unwrap();
    assert!(journal.records().is_empty());
    let snapshot = executor.configuration_snapshot().await.unwrap();
    assert!(!snapshot.links.iter().any(|l| l.index == index));
    assert!(snapshot.links.iter().any(|l| l.name == b"rpdb-normal"));
    assert!(
        snapshot
            .rules
            .iter()
            .any(|r| r.priority == Some(10010) && r.table == 1002)
    );
    assert!(
        snapshot
            .routes
            .iter()
            .any(|r| r.table == 254 && r.destination.length == 0)
    );
}
