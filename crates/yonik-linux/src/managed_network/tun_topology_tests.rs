use super::*;
use crate::managed_network::tun::TunRoute;
use crate::managed_network::{Ownership, Reconciled};
use crate::{IpPrefix, LinuxAddress, LinuxLink, LinuxRoute, LinuxRule, NetworkNamespace};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Fixture {
    journal: Journal,
    path: PathBuf,
    topology: LinuxTopology,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_file(self.path.join("journal.json")).ok();
        fs::remove_dir(&self.path).ok();
    }
}
fn prefix(value: &str, length: u8) -> IpPrefix {
    IpPrefix {
        address: value.parse().unwrap(),
        length,
    }
}
fn route(
    value: &str,
    length: u8,
    table: u32,
    kind: u8,
    protocol: u8,
    priority: Option<u32>,
) -> LinuxRoute {
    LinuxRoute {
        family: if value.contains(':') { 10 } else { 2 },
        destination: prefix(value, length),
        source: prefix(if value.contains(':') { "::" } else { "0.0.0.0" }, 0),
        table,
        preferred_source: None,
        gateway: None,
        output_interface: Some(7),
        input_interface: None,
        priority,
        protocol,
        kind,
        scope: 0,
        tos: 0,
        flags: 0,
        multipath: vec![],
        nexthop_id: None,
        unknown: vec![],
    }
}
fn fixture() -> Fixture {
    let path = std::env::temp_dir().join(format!(
        "yonik-projection-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let owner = Ownership::new(rustix::process::getuid().as_raw(), 7, 9, 3, 11).unwrap();
    let mut journal = Journal::open(&path, owner).unwrap();
    for (id, resource) in [
        (1, Resource::Tun { name_id: 7 }),
        (
            2,
            Resource::Address {
                tun_id: 1,
                ifindex: 7,
                address: "2001:db8::1".parse().unwrap(),
                prefix_len: 126,
            },
        ),
        (
            3,
            Resource::Route {
                table: 1001,
                destination: "::".parse().unwrap(),
                prefix_len: 0,
                priority: 47,
                protocol: 253,
                ifindex: 7,
            },
        ),
        (
            4,
            Resource::TunRule {
                tun_id: 1,
                ifindex: 7,
                priority: 100,
                table: 1001,
                mark: 47,
                ipv6: true,
            },
        ),
    ] {
        journal.intent(owner, Scope::Session, id, resource).unwrap();
        journal.reconcile(owner, id, Reconciled::Owned).unwrap();
    }
    let topology = LinuxTopology {
        namespace: NetworkNamespace {
            device: 3,
            inode: 11,
        },
        links: vec![LinuxLink {
            index: 7,
            link_type: 65534,
            flags: 0x1091,
            name: b"tofu00000007".to_vec(),
            alias: Some(alias(owner, 1).unwrap()),
            mtu: Some(1400),
            master: None,
            parent: None,
            kind: Some(b"tun".to_vec()),
            operational_state: Some(0),
            unknown: vec![],
        }],
        addresses: vec![LinuxAddress {
            family: 10,
            index: 7,
            address: "2001:db8::1".parse().unwrap(),
            local: None,
            prefix_len: 126,
            scope: 0,
            flags: 0x282,
            unknown: vec![],
        }],
        routes: vec![route("::", 0, 1001, 1, 253, Some(47))],
        rules: vec![LinuxRule {
            family: 10,
            destination: prefix("::", 0),
            source: prefix("::", 0),
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
            suppress_prefix_len: None,
            suppress_interface_group: None,
            l3mdev: None,
            unknown: vec![],
        }],
        nexthops: vec![],
    };
    Fixture {
        journal,
        path,
        topology,
    }
}
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[test]
fn projection_removes_exact_confirmed_session_and_preserves_external_facts() {
    let f = fixture();
    let mut external = f.topology.links[0].clone();
    external.index = 42;
    external.name = b"external".to_vec();
    external.alias = None;
    external.kind = None;
    let mut topology = f.topology.clone();
    topology.links.insert(0, external.clone());
    let result = session_external_topology(topology, &f.journal, 1, 1400).unwrap();
    assert_eq!(result.links, vec![external]);
    assert!(result.addresses.is_empty());
    assert!(result.routes.is_empty());
    assert!(result.rules.is_empty());
}
#[test]
fn projection_rejects_foreign_mutations_missing_and_duplicate_resources() {
    let f = fixture();
    let mutations: &[fn(&mut LinuxTopology)] = &[
        |t| t.links[0].mtu = Some(1500),
        |t| t.links[0].parent = Some(42),
        |t| t.links[0].alias = None,
        |t| {
            t.addresses.clear();
        },
        |t| t.addresses.push(t.addresses[0].clone()),
        |t| t.addresses[0].flags = 0,
        |t| {
            t.routes.clear();
        },
        |t| t.routes.push(t.routes[0].clone()),
        |t| t.routes[0].gateway = Some("2001:db8::2".parse().unwrap()),
        |t| {
            t.rules.clear();
        },
        |t| t.rules.push(t.rules[0].clone()),
        |t| t.rules[0].fwmark = Some(48),
        |t| {
            let mut l = t.links[0].clone();
            l.index = 8;
            l.name = b"child".to_vec();
            l.parent = Some(7);
            t.links.push(l);
        },
    ];
    for change in mutations {
        let mut t = f.topology.clone();
        change(&mut t);
        assert!(session_external_topology(t, &f.journal, 1, 1400).is_err());
    }
}
#[test]
fn projection_removes_only_proven_ipv6_kernel_derivatives() {
    let f = fixture();
    let mut t = f.topology.clone();
    t.addresses.push(LinuxAddress {
        family: 10,
        index: 7,
        address: "fe80::1234".parse().unwrap(),
        local: None,
        prefix_len: 64,
        scope: 253,
        flags: 0x880,
        unknown: vec![crate::NetworkAttribute {
            kind: 11,
            value: vec![3],
        }],
    });
    t.routes.extend([
        route("fe80::", 64, 254, 1, 2, Some(256)),
        route("fe80::1234", 128, 255, 2, 2, Some(0)),
        route("ff00::", 8, 255, 5, 2, Some(256)),
        route("2001:db8::1", 128, 255, 2, 2, Some(0)),
    ]);
    let result = session_external_topology(t.clone(), &f.journal, 1, 1400).unwrap();
    assert!(result.addresses.is_empty());
    assert!(result.routes.is_empty());
    t.routes.last_mut().unwrap().destination = prefix("2001:db8::2", 128);
    assert!(session_external_topology(t, &f.journal, 1, 1400).is_err());
}

#[tokio::test]
#[ignore = "Требует отдельный user/net namespace и YONIK_NFT_TEST_HOST_NETNS"]
async fn real_namespace_projection_matches_external_baseline() {
    use super::super::{TunExecutor, namespace};
    let netns = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
    let (device, inode) = namespace(&netns).unwrap();
    let owner = Ownership::new(rustix::process::getuid().as_raw(), 7, 9, device, inode).unwrap();
    // Guard проверяет netns относительно явно переданного host namespace.
    let mut executor = TunExecutor::isolated_fixture(owner).unwrap();
    let path = std::env::temp_dir().join(format!("yonik-real-projection-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = Journal::open(&path, owner).unwrap();
    let baseline = executor.configuration_snapshot().await.unwrap();
    executor.ensure_tun(&mut journal, 1, 7).await.unwrap();
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
            TunAddress::new("2001:db8::1".parse().unwrap(), 126).unwrap(),
        )
        .await
        .unwrap();
    executor
        .ensure_route(
            &mut journal,
            1,
            4,
            TunRoute::new("0.0.0.0".parse().unwrap(), 0, 1001, 47).unwrap(),
        )
        .await
        .unwrap();
    executor
        .ensure_route(
            &mut journal,
            1,
            5,
            TunRoute::new("::".parse().unwrap(), 0, 1001, 47).unwrap(),
        )
        .await
        .unwrap();
    executor
        .ensure_rule(
            &mut journal,
            1,
            6,
            TunRule::new(100, 1001, 47, false).unwrap(),
        )
        .await
        .unwrap();
    executor
        .ensure_rule(
            &mut journal,
            1,
            7,
            TunRule::new(100, 1001, 47, true).unwrap(),
        )
        .await
        .unwrap();
    let topology = executor.configuration_snapshot().await.unwrap();
    assert_eq!(
        session_external_topology(topology, &journal, 1, 1400).unwrap(),
        baseline
    );
    executor.remove_rule(&mut journal, 1, 7).await.unwrap();
    executor.remove_rule(&mut journal, 1, 6).await.unwrap();
    executor.remove_route(&mut journal, 1, 5).await.unwrap();
    executor.remove_route(&mut journal, 1, 4).await.unwrap();
    executor.remove_address(&mut journal, 1, 3).await.unwrap();
    executor.remove_address(&mut journal, 1, 2).await.unwrap();
    executor.remove_tun(&mut journal, 1).await.unwrap();
    drop(journal);
    fs::remove_file(path.join("journal.json")).unwrap();
    fs::remove_dir(path).unwrap();
}

#[test]
fn projection_rejects_unconfirmed_cleanup_and_unsupported_journal_state() {
    for mutation in 0..5 {
        let mut f = fixture();
        let owner = f.journal.ownership();
        match mutation {
            0 => f.journal.require_reconciliation(owner, 2).unwrap(),
            1 => f.journal.mark_cleanup(owner, 2).unwrap(),
            2 => {
                f.journal
                    .intent(
                        owner,
                        Scope::Session,
                        20,
                        Resource::Dns {
                            ifindex: 7,
                            settings_digest: [1; 32],
                        },
                    )
                    .unwrap();
                f.journal.reconcile(owner, 20, Reconciled::Owned).unwrap();
            }
            3 => {
                f.journal
                    .intent(owner, Scope::Session, 20, Resource::Tun { name_id: 8 })
                    .unwrap();
                f.journal.reconcile(owner, 20, Reconciled::Owned).unwrap();
            }
            _ => {
                f.journal
                    .intent(
                        owner,
                        Scope::Session,
                        20,
                        Resource::Address {
                            tun_id: 1,
                            ifindex: 8,
                            address: "2001:db8::2".parse().unwrap(),
                            prefix_len: 126,
                        },
                    )
                    .unwrap();
                f.journal.reconcile(owner, 20, Reconciled::Owned).unwrap();
            }
        }
        assert!(session_external_topology(f.topology.clone(), &f.journal, 1, 1400).is_err());
    }
}
#[test]
fn projection_rejects_foreign_address_table_reference_and_nexthop() {
    let f = fixture();
    let mutations: &[fn(&mut LinuxTopology)] = &[
        |t| {
            let mut a = t.addresses[0].clone();
            a.address = "2001:db8::2".parse().unwrap();
            t.addresses.push(a);
        },
        |t| {
            let mut r = t.routes[0].clone();
            r.output_interface = Some(8);
            r.destination = prefix("2001:db8::", 32);
            t.routes.push(r);
        },
        |t| {
            let mut r = t.rules[0].clone();
            r.priority = Some(101);
            t.rules.push(r);
        },
        |t| {
            t.nexthops.push(crate::LinuxNexthop {
                id: 1,
                family: 10,
                scope: 0,
                protocol: 99,
                flags: 0,
                blackhole: false,
                output_interface: Some(7),
                gateway: None,
                group_type: None,
                group: vec![],
                unknown: vec![],
            })
        },
        |t| {
            let mut r = t.routes[0].clone();
            r.table = 254;
            r.output_interface = None;
            r.multipath.push(crate::RouteNexthop {
                flags: 0,
                weight: 1,
                output_interface: 7,
                gateway: None,
                unknown: vec![],
            });
            t.routes.push(r);
        },
    ];
    for mutation in mutations {
        let mut t = f.topology.clone();
        mutation(&mut t);
        assert!(session_external_topology(t, &f.journal, 1, 1400).is_err());
    }
}
#[test]
fn projection_preserves_unrelated_routes_rules_and_address_changes() {
    let f = fixture();
    let mut t = f.topology.clone();
    let mut route = t.routes[0].clone();
    route.table = 254;
    route.output_interface = Some(42);
    t.routes.insert(0, route.clone());
    let mut rule = t.rules[0].clone();
    rule.table = 254;
    rule.priority = Some(32766);
    t.rules.insert(0, rule.clone());
    let mut address = t.addresses[0].clone();
    address.index = 42;
    address.address = "2001:db8:abcd::5".parse().unwrap();
    t.addresses.insert(0, address.clone());
    let result = session_external_topology(t, &f.journal, 1, 1400).unwrap();
    assert_eq!(result.routes, vec![route]);
    assert_eq!(result.rules, vec![rule]);
    assert_eq!(result.addresses, vec![address]);
}
#[test]
fn projection_proves_ipv4_local_and_directed_broadcast_from_confirmed_prefix() {
    let mut f = fixture();
    let owner = f.journal.ownership();
    f.journal
        .intent(
            owner,
            Scope::Session,
            20,
            Resource::Address {
                tun_id: 1,
                ifindex: 7,
                address: "198.18.0.1".parse().unwrap(),
                prefix_len: 30,
            },
        )
        .unwrap();
    f.journal.reconcile(owner, 20, Reconciled::Owned).unwrap();
    let mut t = f.topology.clone();
    t.addresses.push(LinuxAddress {
        family: 2,
        index: 7,
        address: "198.18.0.1".parse().unwrap(),
        local: Some("198.18.0.1".parse().unwrap()),
        prefix_len: 30,
        scope: 0,
        flags: 0x280,
        unknown: vec![],
    });
    let mut local = route("198.18.0.1", 32, 255, 2, 2, None);
    local.scope = 254;
    local.preferred_source = Some("198.18.0.1".parse().unwrap());
    let mut broadcast = local.clone();
    broadcast.destination = prefix("198.18.0.3", 32);
    broadcast.kind = 3;
    broadcast.scope = 253;
    t.routes.extend([local, broadcast]);
    assert!(
        session_external_topology(t.clone(), &f.journal, 1, 1400)
            .unwrap()
            .routes
            .is_empty()
    );
    t.routes.last_mut().unwrap().destination = prefix("198.18.0.7", 32);
    assert!(session_external_topology(t, &f.journal, 1, 1400).is_err());
}

#[tokio::test]
#[ignore = "Требует отдельный user/net namespace и YONIK_NFT_TEST_HOST_NETNS"]
async fn real_namespace_session_plan_configure_capture_verify_cleanup() {
    use super::super::{TunExecutor, namespace};
    use crate::helper::SessionNetworkPlan;
    let netns = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
    let (device, inode) = namespace(&netns).unwrap();
    let owner = Ownership::new(rustix::process::getuid().as_raw(), 77, 99, device, inode).unwrap();
    let mut executor = TunExecutor::isolated_fixture(owner).unwrap();
    let baseline = executor.configuration_snapshot().await.unwrap();
    let plan = SessionNetworkPlan::reserve(owner, &baseline).unwrap();
    let path = std::env::temp_dir().join(format!("yonik-real-plan-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = Journal::open(&path, owner).unwrap();
    let index = plan.configure(&mut executor, &mut journal).await.unwrap();
    plan.capture(&mut executor, &mut journal, index)
        .await
        .unwrap();
    plan.verify_external(
        &baseline,
        executor.configuration_snapshot().await.unwrap(),
        &journal,
        index,
    )
    .unwrap();
    // В этом gate worker не запускался: нет его процессов или унаследованных TUN FD.
    plan.cleanup_after_worker(&mut executor, &mut journal, index)
        .await
        .unwrap();
    assert!(journal.records().is_empty());
    assert_eq!(executor.configuration_snapshot().await.unwrap(), baseline);
    drop(journal);
    fs::remove_file(path.join("journal.json")).unwrap();
    fs::remove_dir(path).unwrap();
}
