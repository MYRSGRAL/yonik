use super::*;
use crate::managed_network::Ownership;
use std::{fs::File, path::Path};

#[test]
fn typed_configuration_rejects_unsafe_ranges_and_noncanonical_routes() {
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "169.254.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
    ] {
        assert!(TunAddress::new(address.parse().unwrap(), 24).is_err());
    }
    assert!(TunAddress::new("198.18.0.1".parse().unwrap(), 0).is_err());
    assert!(TunAddress::new("198.18.0.1".parse().unwrap(), 33).is_err());
    for mapped in ["::ffff:127.0.0.1", "::192.0.2.1"] {
        assert!(TunAddress::new(mapped.parse().unwrap(), 128).is_err());
    }
    assert!(TunRoute::new("198.18.0.1".parse().unwrap(), 24, 1001, 47).is_err());
    for table in [0, 253, 254, 255, u32::MAX] {
        assert!(TunRoute::new("0.0.0.0".parse().unwrap(), 0, table, 47).is_err());
    }
    assert!(TunRoute::new("::".parse().unwrap(), 0, 1001, 0).is_err());
    assert!(TunRoute::new("::".parse().unwrap(), 0, 1001, 47).is_ok());
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
struct Queue(std::process::Child);
impl Drop for Queue {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn kernel_link_local_fixture(executor: &TunExecutor, index: u32) {
    use std::io::BufRead;
    ip(&[
        "-6",
        "link",
        "set",
        "dev",
        "tofu00000007",
        "addrgenmode",
        "random",
    ]);
    let script = "import os,fcntl,struct,sys\nfd=os.open('/dev/net/tun',os.O_RDWR)\nfcntl.ioctl(fd,0x400454ca,struct.pack('16sH',b'tofu00000007',0x1001))\nprint('ready',flush=True)\nsys.stdin.buffer.read()\nos.close(fd)\n";
    let mut queue = Queue(
        std::process::Command::new("/usr/bin/python3")
            .args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let output = queue.0.stdout.take().unwrap();
    let ready = tokio::task::spawn_blocking(move || {
        let mut line = String::new();
        std::io::BufReader::new(output)
            .read_line(&mut line)
            .unwrap();
        line
    });
    assert_eq!(
        tokio::time::timeout(DEADLINE, ready)
            .await
            .unwrap()
            .unwrap()
            .trim(),
        "ready"
    );
    tokio::time::timeout(DEADLINE, async {
        loop {
            let snapshot = executor.configuration_snapshot().await.unwrap();
            if snapshot
                .addresses
                .iter()
                .any(|address| kernel_link_local(address, index))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // Stop worker закрывает очередь, но интерфейс и его kernel LL остаются
    // собственными. При последующем DEL они не должны блокировать cleanup.
    drop(queue.0.stdin.take());
    tokio::time::timeout(DEADLINE, async {
        loop {
            if queue.0.try_wait().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
#[ignore = "Требует отдельные user/net/mount/pid namespaces и приватные /run, /tmp"]
async fn real_namespace_owned_addresses_routes_and_cleanup() {
    let ns = File::open("/proc/thread-self/ns/net").unwrap();
    let (device, inode) = super::super::namespace(&ns).unwrap();
    let owner = Ownership::new(rustix::process::getuid().as_raw(), 7, 9, device, inode).unwrap();
    let mut executor = TunExecutor::isolated_fixture(owner).unwrap();
    let path = Path::new("/tmp/yonik-owned-tun-config");
    let mut journal = Journal::open(path, owner).unwrap();
    let index = executor.ensure_tun(&mut journal, 1, 7).await.unwrap();
    assert_eq!(
        executor
            .configure_link(&mut journal, 1, 1400)
            .await
            .unwrap(),
        index
    );
    let a4 = TunAddress::new("198.18.0.1".parse().unwrap(), 30).unwrap();
    let a6 = TunAddress::new("2001:db8:746f::1".parse().unwrap(), 126).unwrap();
    executor
        .ensure_address(&mut journal, 1, 2, a4)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "{error:?}: {}",
                ip(&["-j", "-d", "address", "show", "dev", "tofu00000007"])
            )
        });
    executor
        .ensure_address(&mut journal, 1, 3, a6)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "{error:?}: {}",
                ip(&["-j", "-d", "address", "show", "dev", "tofu00000007"])
            )
        });
    let snapshot = executor.configuration_snapshot().await.unwrap();
    assert!(observe_address(&snapshot, index, a4).unwrap());
    assert!(observe_address(&snapshot, index, a6).unwrap());
    assert!(!snapshot.routes.iter().any(|r| r.table == 254
        && (r.destination.address == "198.18.0.0".parse::<IpAddr>().unwrap()
            || r.destination.address == "2001:db8:746f::".parse::<IpAddr>().unwrap())));
    let r4 = TunRoute::new("198.18.0.0".parse().unwrap(), 30, 1001, 47).unwrap();
    let r6 = TunRoute::new("2001:db8:746f::".parse().unwrap(), 126, 1001, 47).unwrap();
    if let Err(error) = executor.ensure_route(&mut journal, 1, 4, r4).await {
        let snapshot = executor.configuration_snapshot().await.unwrap();
        let details: Vec<_> = snapshot
            .routes
            .iter()
            .filter(|r| r.table == 1001)
            .map(|r| {
                (
                    r.flags,
                    r.scope,
                    r.protocol,
                    r.priority,
                    r.unknown
                        .iter()
                        .map(|a| (a.kind, a.value.clone()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        panic!(
            "{error:?}: {details:?} {}",
            ip(&["-4", "-j", "-d", "route", "show", "table", "1001"])
        );
    }
    executor.ensure_route(&mut journal, 1, 5, r6).await.unwrap();
    ip(&["link", "set", "lo", "up"]);
    // Селектор принадлежит только fixture: production RPDB ещё не подключён.
    for family in ["-4", "-6"] {
        ip(&[family, "rule", "add", "priority", "10000", "lookup", "1001"]);
    }
    for (family, target) in [("-4", "198.18.0.2"), ("-6", "2001:db8:746f::2")] {
        let lookup = ip(&[family, "-j", "route", "get", target]);
        assert_eq!(lookup[0]["dev"], "tofu00000007");
        let table = &lookup[0]["table"];
        assert_eq!(
            table
                .as_u64()
                .or_else(|| table.as_str().and_then(|v| v.parse().ok())),
            Some(1001)
        );
    }
    for family in ["-4", "-6"] {
        ip(&[family, "rule", "del", "priority", "10000", "lookup", "1001"]);
    }
    drop(journal);
    let mut journal = Journal::open(path, owner).unwrap();
    executor
        .ensure_address(&mut journal, 1, 2, a4)
        .await
        .unwrap();
    executor.ensure_route(&mut journal, 1, 4, r4).await.unwrap();
    assert_eq!(
        executor.remove_tun(&mut journal, 1).await,
        Err(TunError::Journal(JournalError::Conflict))
    );
    assert!(
        executor
            .links()
            .await
            .unwrap()
            .iter()
            .any(|link| link.index == index)
    );
    // Чужая запись того же prefix даже с другой metric не удаляется broad delete.
    ip(&[
        "-4",
        "route",
        "add",
        "198.18.0.0/30",
        "dev",
        "lo",
        "table",
        "1001",
        "metric",
        "48",
        "proto",
        "99",
    ]);
    assert_eq!(
        executor.remove_route(&mut journal, 1, 4).await,
        Err(TunError::Foreign)
    );
    assert_eq!(
        ip(&["-4", "-j", "route", "show", "table", "1001"])
            .as_array()
            .unwrap()
            .len(),
        2
    );
    ip(&[
        "-4",
        "route",
        "del",
        "198.18.0.0/30",
        "dev",
        "lo",
        "table",
        "1001",
        "metric",
        "48",
        "proto",
        "99",
    ]);
    ip(&[
        "-4",
        "route",
        "add",
        "203.0.113.0/24",
        "dev",
        "lo",
        "metric",
        "42",
    ]);
    ip(&[
        "-4",
        "route",
        "add",
        "203.0.112.0/24",
        "dev",
        "lo",
        "table",
        "1001",
        "metric",
        "60",
        "proto",
        "99",
    ]);
    assert_eq!(
        executor.ensure_route(&mut journal, 1, 4, r4).await,
        Err(TunError::Foreign)
    );
    let blocked = TunRoute::new("203.0.114.0".parse().unwrap(), 24, 1001, 47).unwrap();
    assert_eq!(
        executor.ensure_route(&mut journal, 1, 9, blocked).await,
        Err(TunError::Foreign)
    );
    executor.remove_route(&mut journal, 1, 9).await.unwrap();
    assert!(
        ip(&["-4", "-j", "route", "show", "table", "1001"])
            .to_string()
            .contains("203.0.112.0/24")
    );
    ip(&[
        "-4",
        "route",
        "del",
        "203.0.112.0/24",
        "dev",
        "lo",
        "table",
        "1001",
        "metric",
        "60",
        "proto",
        "99",
    ]);
    // Пустая таблица тоже чужая, если RPDB уже ссылается на неё.
    ip(&["-4", "rule", "add", "priority", "10002", "lookup", "1002"]);
    let foreign_table = TunRoute::new("203.0.115.0".parse().unwrap(), 24, 1002, 47).unwrap();
    assert_eq!(
        executor
            .ensure_route(&mut journal, 1, 10, foreign_table)
            .await,
        Err(TunError::Foreign)
    );
    assert!(!journal.records().iter().any(|r| r.id() == 10));
    assert!(
        executor
            .configuration_snapshot()
            .await
            .unwrap()
            .routes
            .iter()
            .all(|r| r.table != 1002)
    );
    assert!(
        ip(&["-4", "-j", "rule", "show"])
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["priority"] == 10002)
    );
    ip(&["-4", "rule", "del", "priority", "10002", "lookup", "1002"]);
    executor
        .ensure_route(&mut journal, 1, 10, foreign_table)
        .await
        .unwrap();
    executor.remove_route(&mut journal, 1, 10).await.unwrap();
    // Совпавший неподтверждённый intent не является доказательством ACK.
    ip(&[
        "-4",
        "route",
        "add",
        "192.0.2.0/24",
        "dev",
        "tofu00000007",
        "table",
        "1002",
        "metric",
        "88",
        "proto",
        "253",
    ]);
    journal
        .intent(
            owner,
            Scope::Session,
            6,
            Resource::Route {
                table: 1002,
                destination: "192.0.2.0".parse().unwrap(),
                prefix_len: 24,
                priority: 88,
                protocol: 253,
                ifindex: index,
            },
        )
        .unwrap();
    let unknown = TunRoute::new("192.0.2.0".parse().unwrap(), 24, 1002, 88).unwrap();
    assert_eq!(
        executor.ensure_route(&mut journal, 1, 6, unknown).await,
        Err(TunError::Evidence)
    );
    assert_eq!(
        executor.remove_route(&mut journal, 1, 6).await,
        Err(TunError::Evidence)
    );
    assert_eq!(
        ip(&["-4", "-j", "route", "show", "table", "1002"])
            .as_array()
            .unwrap()
            .len(),
        1
    );
    ip(&[
        "-4",
        "route",
        "del",
        "192.0.2.0/24",
        "dev",
        "tofu00000007",
        "table",
        "1002",
        "metric",
        "88",
        "proto",
        "253",
    ]);
    executor.remove_route(&mut journal, 1, 6).await.unwrap();
    // Неподтверждённый адрес не присваивается даже на собственном TUN.
    ip(&[
        "-4",
        "address",
        "add",
        "198.19.0.1/30",
        "dev",
        "tofu00000007",
        "noprefixroute",
    ]);
    let unknown_address = TunAddress::new("198.19.0.1".parse().unwrap(), 30).unwrap();
    journal
        .intent(
            owner,
            Scope::Session,
            7,
            Resource::Address {
                tun_id: 1,
                ifindex: index,
                address: unknown_address.address(),
                prefix_len: 30,
            },
        )
        .unwrap();
    assert_eq!(
        executor
            .ensure_address(&mut journal, 1, 7, unknown_address)
            .await,
        Err(TunError::Evidence)
    );
    assert_eq!(
        executor.remove_address(&mut journal, 1, 7).await,
        Err(TunError::Evidence)
    );
    ip(&[
        "-4",
        "address",
        "del",
        "198.19.0.1/30",
        "dev",
        "tofu00000007",
    ]);
    executor.remove_address(&mut journal, 1, 7).await.unwrap();
    // Коллизия чужого адреса не меняет его и не оставляет ложный наш address.
    ip(&["-4", "address", "add", "198.20.0.1/32", "dev", "lo"]);
    let collision = TunAddress::new("198.20.0.1".parse().unwrap(), 32).unwrap();
    assert_eq!(
        executor.ensure_address(&mut journal, 1, 8, collision).await,
        Err(TunError::Foreign)
    );
    executor.remove_address(&mut journal, 1, 8).await.unwrap();
    assert!(
        ip(&["-4", "-j", "address", "show", "dev", "lo"])
            .to_string()
            .contains("198.20.0.1")
    );
    executor.remove_route(&mut journal, 1, 5).await.unwrap();
    executor.remove_route(&mut journal, 1, 4).await.unwrap();
    executor.remove_address(&mut journal, 1, 3).await.unwrap();
    executor.remove_address(&mut journal, 1, 2).await.unwrap();
    // DEL link автоматически убрал бы чужой route/address на нашем ifindex.
    // Полная метка TUN не даёт права уничтожать такие незарегистрированные дети.
    ip(&[
        "-4",
        "route",
        "add",
        "203.0.116.0/24",
        "dev",
        "tofu00000007",
        "table",
        "1002",
        "metric",
        "99",
        "proto",
        "99",
    ]);
    assert_eq!(
        executor.remove_tun(&mut journal, 1).await,
        Err(TunError::Foreign)
    );
    assert!(journal.records().iter().any(|record| record.id() == 1));
    assert!(
        ip(&["-4", "-j", "route", "show", "table", "1002"])
            .to_string()
            .contains("203.0.116.0/24")
    );
    ip(&[
        "-4",
        "route",
        "del",
        "203.0.116.0/24",
        "dev",
        "tofu00000007",
        "table",
        "1002",
        "metric",
        "99",
        "proto",
        "99",
    ]);
    ip(&[
        "-4",
        "address",
        "add",
        "198.21.0.1/30",
        "dev",
        "tofu00000007",
        "noprefixroute",
    ]);
    assert_eq!(
        executor.remove_tun(&mut journal, 1).await,
        Err(TunError::Foreign)
    );
    assert!(journal.records().iter().any(|record| record.id() == 1));
    assert!(
        ip(&["-4", "-j", "address", "show", "dev", "tofu00000007"])
            .to_string()
            .contains("198.21.0.1")
    );
    ip(&[
        "-4",
        "address",
        "del",
        "198.21.0.1/30",
        "dev",
        "tofu00000007",
    ]);
    kernel_link_local_fixture(&executor, index).await;
    executor.remove_tun(&mut journal, 1).await.unwrap();
    assert!(journal.records().is_empty());
    let routes = ip(&["-4", "-j", "route", "show", "203.0.113.0/24"]);
    assert_eq!(routes[0]["dev"], "lo");
    assert_eq!(routes[0]["metric"], 42);
    assert!(
        executor
            .configuration_snapshot()
            .await
            .unwrap()
            .links
            .iter()
            .all(|l| l.index != index)
    );
}

#[test]
fn metadata_normalization_does_not_hide_routing_selectors() {
    let destination = "198.18.0.0".parse().unwrap();
    let route = TunRoute::new(destination, 30, 1001, 47).unwrap();
    let mut value = LinuxRoute {
        family: 2,
        destination: crate::IpPrefix {
            address: destination,
            length: 30,
        },
        source: crate::IpPrefix {
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
    assert!(route_matches(&value, 7, None, route));
    value.flags = 16;
    assert!(route_matches(&value, 7, None, route));
    value.flags = 17;
    assert!(!route_matches(&value, 7, None, route));
    value.flags = 0;
    value.gateway = Some("198.18.0.2".parse().unwrap());
    assert!(!route_matches(&value, 7, None, route));
    value.gateway = None;
    value.unknown.push(crate::NetworkAttribute {
        kind: 999,
        value: vec![0],
    });
    assert!(!route_matches(&value, 7, None, route));
    value.unknown = vec![crate::NetworkAttribute {
        kind: 12,
        value: vec![0; 32],
    }];
    assert!(route_matches(&value, 7, None, route));
    value.unknown[0].value[8] = 1;
    assert!(!route_matches(&value, 7, None, route));
    assert_eq!(format!("{route:?}"), "TunRoute(<скрыто>)");
}
#[test]
fn address_flags_and_lifetimes_are_not_silently_discarded() {
    let address = TunAddress::new("198.18.0.1".parse().unwrap(), 30).unwrap();
    let mut value = LinuxAddress {
        family: 2,
        index: 7,
        address: address.address(),
        local: Some(address.address()),
        prefix_len: 30,
        scope: 0,
        flags: 0x280,
        unknown: vec![],
    };
    assert!(address_matches(&value, 7, address));
    value.flags = 0x80;
    assert!(!address_matches(&value, 7, address));
    value.flags = 0x280;
    let mut cache = vec![255; 8];
    cache.extend([0; 8]);
    value.unknown.push(crate::NetworkAttribute {
        kind: 6,
        value: cache,
    });
    assert!(address_matches(&value, 7, address));
    value.unknown[0].value[0] = 0;
    assert!(!address_matches(&value, 7, address));
    value.unknown = vec![crate::NetworkAttribute {
        kind: 6 | 0x8000,
        value: vec![0; 16],
    }];
    assert!(!address_matches(&value, 7, address));
    assert_eq!(format!("{address:?}"), "TunAddress(<скрыто>)");
}

fn derived_topology() -> LinuxTopology {
    let link_local: IpAddr = "fe80::1234".parse().unwrap();
    let mut lifetime = vec![255; 8];
    lifetime.extend([0; 8]);
    let address = LinuxAddress {
        family: 10,
        index: 7,
        address: link_local,
        local: None,
        prefix_len: 64,
        scope: 253,
        flags: 0x880,
        unknown: vec![
            crate::NetworkAttribute {
                kind: 11,
                value: vec![3],
            },
            crate::NetworkAttribute {
                kind: 6,
                value: lifetime,
            },
        ],
    };
    let route = |table, kind, destination: &str, length, priority| LinuxRoute {
        family: 10,
        destination: crate::IpPrefix {
            address: destination.parse().unwrap(),
            length,
        },
        source: crate::IpPrefix {
            address: "::".parse().unwrap(),
            length: 0,
        },
        table,
        preferred_source: None,
        gateway: None,
        output_interface: Some(7),
        input_interface: None,
        priority: Some(priority),
        protocol: 2,
        kind,
        scope: 0,
        tos: 0,
        flags: 0,
        multipath: vec![],
        nexthop_id: None,
        unknown: vec![crate::NetworkAttribute {
            kind: 20,
            value: vec![0],
        }],
    };
    LinuxTopology {
        namespace: crate::NetworkNamespace {
            device: 3,
            inode: 11,
        },
        links: vec![crate::LinuxLink {
            index: 7,
            link_type: 65534,
            flags: 0x1001,
            name: b"tofu00000007".to_vec(),
            alias: Some(b"fixture-owner".to_vec()),
            mtu: Some(1400),
            master: None,
            parent: None,
            kind: Some(b"tun".to_vec()),
            operational_state: Some(6),
            unknown: vec![],
        }],
        addresses: vec![address],
        routes: vec![
            route(254, 1, "fe80::", 64, 256),
            route(255, 2, "fe80::1234", 128, 0),
            route(255, 5, "ff00::", 8, 256),
        ],
        rules: vec![],
        nexthops: vec![],
    }
}
#[test]
fn teardown_accepts_only_exact_kernel_link_local_dependencies() {
    let topology = derived_topology();
    assert_eq!(check_tun_teardown(&topology, 7), Ok(()));
    let mut foreign = topology.clone();
    foreign.addresses[0].address = "2001:db8::1234".parse().unwrap();
    foreign.addresses[0].scope = 0;
    assert_eq!(check_tun_teardown(&foreign, 7), Err(TunError::Foreign));
    let mut foreign = topology.clone();
    foreign.addresses[0].unknown[0].value = vec![0]; // manual LL, не kernel LL.
    assert_eq!(check_tun_teardown(&foreign, 7), Err(TunError::Foreign));
    for protocol in [2, 99] {
        let mut foreign = topology.clone();
        foreign.routes[0].destination.address = "2001:db8::".parse().unwrap();
        foreign.routes[0].protocol = protocol;
        assert_eq!(check_tun_teardown(&foreign, 7), Err(TunError::Foreign));
    }
    let mut foreign = topology.clone();
    foreign.routes[1].destination.address = "fe80::4321".parse().unwrap();
    assert_eq!(check_tun_teardown(&foreign, 7), Err(TunError::Foreign));
    let mut foreign = topology.clone();
    foreign.routes[2].unknown.push(crate::NetworkAttribute {
        kind: 999,
        value: vec![0],
    });
    assert_eq!(check_tun_teardown(&foreign, 7), Err(TunError::Foreign));
    let mut foreign = topology;
    foreign.routes[0].output_interface = None;
    foreign.routes[0].multipath.push(crate::RouteNexthop {
        flags: 0,
        weight: 1,
        output_interface: 7,
        gateway: None,
        unknown: vec![],
    });
    assert_eq!(check_tun_teardown(&foreign, 7), Err(TunError::Foreign));
}
