use super::*;
use crate::{NetworkNamespace, managed_network::Reconciled};
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
struct Area(PathBuf);
impl Drop for Area {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn owner() -> Ownership {
    Ownership::new(1000, 1, 1, 1, 1).unwrap()
}
fn baseline() -> LinuxTopology {
    LinuxTopology {
        namespace: NetworkNamespace {
            device: 1,
            inode: 1,
        },
        links: vec![],
        addresses: vec![],
        routes: vec![],
        rules: vec![],
        nexthops: vec![],
    }
}
fn test_rule(table: u32, priority: Option<u32>) -> crate::LinuxRule {
    crate::LinuxRule {
        family: 2,
        destination: crate::IpPrefix {
            address: Ipv4Addr::UNSPECIFIED.into(),
            length: 0,
        },
        source: crate::IpPrefix {
            address: Ipv4Addr::UNSPECIFIED.into(),
            length: 0,
        },
        tos: 0,
        table,
        action: 1,
        flags: 0,
        priority,
        goto: None,
        fwmark: None,
        fwmask: None,
        uid_range: None,
        input_interface: None,
        output_interface: None,
        protocol: None,
        ip_protocol: None,
        source_ports: None,
        destination_ports: None,
        suppress_prefix_len: None,
        suppress_interface_group: None,
        l3mdev: None,
        unknown: vec![],
    }
}
#[test]
fn reserved_descriptors_are_helper_chosen_and_compiler_uses_same_tun() {
    let mut topology = baseline();
    let plan = SessionNetworkPlan::reserve(owner(), &topology).unwrap();
    assert_eq!(
        plan.compiler_tun().unwrap().interface_name(),
        format!("tofu{:08x}", plan.name)
    );
    assert!(plan.available(&topology));
    let mut rule = test_rule(plan.table, None);
    topology.rules.push(rule.clone());
    assert!(!plan.available(&topology));
    rule.table = 254;
    rule.priority = Some(plan.priority);
    topology.rules[0] = rule;
    assert!(!plan.available(&topology));
    topology.namespace.inode = 2;
    assert!(matches!(
        SessionNetworkPlan::reserve(owner(), &topology),
        Err(TunError::Namespace)
    ));
}
#[test]
fn exact_generation_and_all_seven_resources_required_before_external_verification() {
    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!(
        "yonik-session-plan-{}-{}",
        std::process::id(),
        u64::from_le_bytes(nonce)
    ));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let _area = Area(path.clone());
    let plan = SessionNetworkPlan::candidate(owner(), [1; 24]).unwrap();
    let mut journal = Journal::open(&path.join("network"), owner()).unwrap();
    assert!(plan.check_records(&journal, 7, Some(7)).is_err());
    let mut records = plan.resources(7);
    records.sort_unstable_by_key(|(id, _)| *id);
    for (id, resource) in records {
        journal
            .intent(owner(), Scope::Session, id, resource)
            .unwrap();
        journal.reconcile(owner(), id, Reconciled::Owned).unwrap();
    }
    plan.check_records(&journal, 7, Some(7)).unwrap();
    assert!(plan.check_records(&journal, 8, Some(7)).is_err());
    let other = SessionNetworkPlan::candidate(owner(), [2; 24]).unwrap();
    assert!(other.check_records(&journal, 7, Some(7)).is_err());
    journal.require_reconciliation(owner(), RULES + 1).unwrap();
    // Старый Confirmed не заменяет свежую сверку executor после отмены/ошибки.
    assert!(journal.needs_reconciliation(RULES + 1));
    assert!(plan.check_records(&journal, 7, Some(7)).is_err());
    drop(journal);
}
#[test]
fn prefix_collision_handles_both_families_and_different_lengths() {
    assert!(overlaps(
        "198.18.1.1".parse().unwrap(),
        30,
        "198.18.0.0".parse().unwrap(),
        15
    ));
    assert!(!overlaps(
        "198.18.1.1".parse().unwrap(),
        30,
        "198.18.2.0".parse().unwrap(),
        24
    ));
    assert!(overlaps(
        "fd79:6f6e::1".parse().unwrap(),
        126,
        "fd79:6f6e::".parse().unwrap(),
        32
    ));
    assert!(!overlaps(
        "198.18.1.1".parse().unwrap(),
        30,
        "fd79:6f6e::".parse().unwrap(),
        32
    ));
}

#[test]
fn session_ids_do_not_collide_with_existing_public_protection_record() {
    let plan = SessionNetworkPlan::candidate(owner(), [1; 24]).unwrap();
    // Действующий SystemProtectionHost использует record ID 1 для public policy.
    assert!(plan.resources(7).iter().all(|(id, _)| *id != 1));
}

#[test]
fn маршруты_resolved_ограничены_сокетом_и_свободным_диапазоном_приоритетов() {
    let mut topology = baseline();
    let v4 = "192.0.2.53:1853".parse().unwrap();
    let v6 = "[2001:db8::53]:853".parse().unwrap();
    let candidate = || SessionNetworkPlan::candidate(owner(), [1; 24]).unwrap();
    let plan = candidate()
        .with_resolver_routes(
            &topology,
            991,
            &[
                (v6, TransportProtocol::Tcp, 254),
                (v4, TransportProtocol::Tcp, 254),
                (v4, TransportProtocol::Tcp, 254),
            ],
        )
        .unwrap();
    assert_eq!(plan.configured_count(), 5);
    assert_eq!(plan.captured_count(), 9);
    assert_eq!(plan.resolver_rules[0].endpoint(), v4);
    assert_eq!(plan.resolver_rules[1].endpoint(), v6);
    assert_eq!(plan.resolver_rules[0].priority(), plan.priority - 1);
    assert_eq!(plan.resolver_rules[1].priority(), plan.priority - 2);
    assert_eq!(plan.resolver_rules[0].uid(), 991);
    assert!(matches!(
        candidate().with_resolver_routes(
            &topology,
            991,
            &[
                (v4, TransportProtocol::Tcp, 254),
                (v4, TransportProtocol::Tcp, 253)
            ]
        ),
        Err(TunError::Foreign)
    ));
    assert!(matches!(
        candidate().with_resolver_routes(
            &topology,
            991,
            &[(v4, TransportProtocol::Tcp, plan.table)]
        ),
        Err(TunError::Invalid)
    ));
    topology.rules.push(test_rule(254, Some(plan.priority - 2)));
    assert!(matches!(
        candidate().with_resolver_routes(
            &topology,
            991,
            &[
                (v4, TransportProtocol::Tcp, 254),
                (v6, TransportProtocol::Tcp, 254)
            ]
        ),
        Err(TunError::Foreign)
    ));
}

#[tokio::test]
#[ignore = "Требует отдельную network namespace и тестовые маршруты IPv4 и IPv6"]
async fn план_tun_устанавливает_и_снимает_точные_маршруты_resolved() {
    use crate::{Cancellation, RouteQuery, lookup_route, read_topology};
    use std::time::Duration;

    let (_operation, mut cancel) = Cancellation::new();
    let timeout = Duration::from_secs(3);
    let baseline = read_topology(&mut cancel, timeout).await.unwrap();
    let owner = Ownership::new(
        1000,
        7,
        9,
        baseline.namespace.device,
        baseline.namespace.inode,
    )
    .unwrap();
    let mut executor = TunExecutor::isolated_fixture(owner).unwrap();
    let endpoints: [(SocketAddr, TransportProtocol); 4] = [
        ("192.0.2.53:1853".parse().unwrap(), TransportProtocol::Tcp),
        (
            "[2001:db8::53]:853".parse().unwrap(),
            TransportProtocol::Tcp,
        ),
        ("192.0.2.53:53".parse().unwrap(), TransportProtocol::Udp),
        ("[2001:db8::53]:53".parse().unwrap(), TransportProtocol::Udp),
    ];
    let plan = SessionNetworkPlan::reserve(owner, &baseline)
        .unwrap()
        .with_resolver_routes(
            &baseline,
            991,
            &endpoints.map(|(endpoint, protocol)| (endpoint, protocol, 254)),
        )
        .unwrap();
    let path = std::env::temp_dir().join(format!("yonik-plan-dot-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let _area = Area(path.clone());
    let mut journal = Journal::open(&path.join("network"), owner).unwrap();
    let index = plan.configure(&mut executor, &mut journal).await.unwrap();
    assert_eq!(journal.records().len(), plan.configured_count());
    assert!(
        journal
            .records()
            .iter()
            .all(|record| record.id() < FIRST_RESOLVER_RULE)
    );
    plan.capture(&mut executor, &mut journal, index)
        .await
        .unwrap();
    assert_eq!(journal.records().len(), plan.captured_count());
    plan.verify_external(
        &baseline,
        read_topology(&mut cancel, timeout).await.unwrap(),
        &journal,
        index,
    )
    .unwrap();
    for (endpoint, protocol) in endpoints {
        let socket = |uid, port, protocol| {
            RouteQuery::new(endpoint.ip(), uid).with_transport(protocol, None, Some(port))
        };
        let other_protocol = match protocol {
            TransportProtocol::Tcp => TransportProtocol::Udp,
            TransportProtocol::Udp => TransportProtocol::Tcp,
        };
        let resolved = lookup_route(socket(991, endpoint.port(), protocol), &mut cancel, timeout)
            .await
            .unwrap();
        assert_eq!(resolved.table, Some(254));
        for query in [
            socket(992, endpoint.port(), protocol),
            socket(991, endpoint.port() + 1, protocol),
            socket(991, endpoint.port(), other_protocol),
        ] {
            let caught = lookup_route(query, &mut cancel, timeout).await.unwrap();
            assert_eq!(
                caught.output_interface.map(|value| value.get()),
                Some(index)
            );
        }
    }
    plan.cleanup_after_worker(&mut executor, &mut journal, index)
        .await
        .unwrap();
    assert!(journal.records().is_empty());
    let after = read_topology(&mut cancel, timeout).await.unwrap();
    assert!(crate::network::same_external_topology(&baseline, &after));
}
