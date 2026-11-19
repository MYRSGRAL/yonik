use super::*;
use crate::managed_network::firewall::{
    BoundTransport, IpPrefix, LanException, PrivateRoute, TransportProtocol,
};

fn policy() -> PublicBlockPolicy {
    PublicBlockPolicy::new(1, None, vec![], vec![], vec![], vec![]).unwrap()
}
fn owner() -> Ownership {
    Ownership::new(1000, 7, 9, 3, 11).unwrap()
}
fn listing(table: &Table, policy: &PublicBlockPolicy) -> Value {
    let mut items = vec![
        json!({"metainfo":{}}),
        json!({"table":{"family":table.family,"name":table.name,"comment":table.comment,"handle":1}}),
    ];
    for (index, command) in policy.commands(&table.name).into_iter().enumerate() {
        let mut item = command["add"].clone();
        let object = item.as_object_mut().unwrap().values_mut().next().unwrap();
        object["handle"] = json!(index + 2);
        items.push(item);
    }
    json!({"nftables":items})
}
fn check(value: &Value, table: &Table, policy: &PublicBlockPolicy) -> Result<(), NftError> {
    verify_rules(&serde_json::to_vec(value).unwrap(), table, policy, |name| {
        if name == "lo" {
            Ok(1)
        } else {
            Err(NftError::Evidence)
        }
    })
}

#[test]
fn dhcp_anchor_is_inert_and_rejects_unexpected_kernel_contents() {
    let prefix = IpPrefix::new("192.0.2.0".parse().expect("Префикс"), 24).expect("CIDR");
    let route = PrivateRoute::new(prefix, None).expect("Защита приватной сети");
    let active = PublicBlockPolicy::new(1, Some(8), vec![route], vec![], vec![], vec![])
        .expect("Активная политика");
    let mut wire = serde_json::to_value(&active).expect("Запись политики");
    assert!(wire.get("dhcp_renewal_anchor").is_none());
    wire["dhcp_renewal_anchor"] = json!(true);
    let reserved = serde_json::from_value::<PublicBlockPolicy>(wire.clone())
        .expect("Политика с пустой DHCP-цепочкой");
    assert_ne!(active.digest(), reserved.digest());
    assert_eq!(
        reserved
            .with_additional_transport(&[])
            .expect("Пересобранная политика"),
        reserved
    );
    let table = block_table(owner(), 2, 5, &reserved);
    let original = listing(&table, &reserved);
    assert_eq!(check(&original, &table, &reserved), Ok(()));
    let data = original["nftables"].as_array().expect("Список nftables");
    let set = data
        .iter()
        .position(|object| object.get("set").is_some())
        .expect("Пустой набор DHCP");
    let position = |verdict: &str| {
        data.iter()
            .position(|entry| {
                entry
                    .pointer("/rule/expr")
                    .and_then(Value::as_array)
                    .is_some_and(|expr| expr.iter().any(|item| item.get(verdict).is_some()))
            })
            .expect("Вердикт output")
    };
    assert!(position("drop") < position("jump"));
    let mut populated = original.clone();
    populated["nftables"][set]["set"]["elem"] = json!(["192.0.2.10"]);
    assert_eq!(
        check(&populated, &table, &reserved),
        Err(NftError::Evidence)
    );
    let mut unexpected_rule = original;
    unexpected_rule["nftables"].as_array_mut().expect("Список nftables").push(json!({
        "rule":{"family":"inet","table":table.name,"chain":"dhcp_renewal","handle":200,"expr":[{"accept":null}]}
    }));
    assert_eq!(
        check(&unexpected_rule, &table, &reserved),
        Err(NftError::Evidence)
    );
    wire["tun_ifindex"] = Value::Null;
    assert!(serde_json::from_value::<PublicBlockPolicy>(wire).is_err());
}

#[test]
fn applied_requires_exact_rules_not_only_ownership_comment() {
    let policy = policy();
    let table = block_table(owner(), 2, 5, &policy);
    let original = listing(&table, &policy);
    assert_eq!(check(&original, &table, &policy), Ok(()));
    for changed in 0..5 {
        let mut value = original.clone();
        match changed {
            0 => value["nftables"][2]["chain"]["policy"] = json!("accept"),
            1 => value["nftables"][3]["rule"]["expr"][1] = json!({"drop":null}),
            2 => {
                value["nftables"].as_array_mut().unwrap().pop();
            }
            3 => {
                let duplicate = value["nftables"][3].clone();
                value["nftables"].as_array_mut().unwrap().push(duplicate);
            }
            _ => value["nftables"][1]["table"]["comment"] = json!("foreign"),
        }
        assert!(check(&value, &table, &policy).is_err());
    }
    let mut named = original;
    named["nftables"][3]["rule"]["expr"][0]["match"]["right"] = json!("lo");
    assert_eq!(check(&named, &table, &policy), Ok(()));
}

#[test]
fn marker_binds_policy_and_every_resource_identity_field() {
    let policy = policy();
    let original = block_table(owner(), 2, 5, &policy);
    assert!(original.comment.len() <= 128);
    for changed in [
        block_table(Ownership::new(1001, 7, 9, 3, 11).unwrap(), 2, 5, &policy),
        block_table(Ownership::new(1000, 8, 9, 3, 11).unwrap(), 2, 5, &policy),
        block_table(Ownership::new(1000, 7, 10, 3, 11).unwrap(), 2, 5, &policy),
        block_table(Ownership::new(1000, 7, 9, 4, 11).unwrap(), 2, 5, &policy),
        block_table(Ownership::new(1000, 7, 9, 3, 12).unwrap(), 2, 5, &policy),
        block_table(owner(), 3, 5, &policy),
        block_table(owner(), 2, 6, &policy),
        block_table(
            owner(),
            2,
            5,
            &PublicBlockPolicy::new(1, Some(2), vec![], vec![], vec![], vec![]).unwrap(),
        ),
    ] {
        assert_ne!(original.comment, changed.comment);
    }
}

#[test]
fn normalization_preserves_opposite_protocol_and_extra_predicates() {
    let policy = PublicBlockPolicy::new(
        1,
        None,
        vec![],
        vec![
            LanException::new(IpPrefix::new("10.0.0.2".parse().unwrap(), 32).unwrap(), 2).unwrap(),
        ],
        vec![],
        vec![],
    )
    .unwrap();
    let table = block_table(owner(), 2, 5, &policy);
    let mut value = listing(&table, &policy);
    assert_eq!(check(&value, &table, &policy), Ok(()));
    value["nftables"][4]["rule"]["expr"][0]["match"]["right"] = json!("ipv6");
    assert_eq!(check(&value, &table, &policy), Err(NftError::Evidence));
}

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/public_block_fixture.py")
}
pub(crate) fn fixture(arguments: &[&str]) -> Value {
    let output = std::process::Command::new("/usr/bin/python3")
        .arg(fixture_path())
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
pub(crate) fn probe(address: &str, protocol: &str, mark: Option<&str>, port: &str) -> bool {
    let mut args = vec![
        "probe",
        "--address",
        address,
        "--protocol",
        protocol,
        "--port",
        port,
    ];
    if let Some(mark) = mark {
        args.extend(["--mark", mark]);
    }
    fixture(&args)["reachable"].as_bool().unwrap()
}
pub(crate) struct Peer(std::process::Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _kill = self.0.kill();
        let _wait = self.0.wait();
    }
}
pub(crate) fn peer() -> Peer {
    use std::io::BufRead;
    let mut peer = Peer(
        std::process::Command::new("/usr/bin/ip")
            .args(["netns", "exec", "yonik-peer", "/usr/bin/python3"])
            .arg(fixture_path())
            .arg("peer")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = peer.0.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout)
            .read_line(&mut line)
            .map(|_| line);
        let _send = send.send(result);
    });
    let ready = receive.recv_timeout(Duration::from_secs(5));
    if ready.is_err() {
        let _kill = peer.0.kill();
        let _wait = peer.0.wait();
    }
    reader.join().unwrap();
    assert_eq!(ready.unwrap().unwrap().trim(), "READY");
    peer
}

#[tokio::test]
#[ignore = "Требует isolated user/net/mount/pid namespace с приватными /tmp, /run, proc и sysfs"]
async fn real_public_block_tcp_udp_dual_stack_and_lifetime() {
    let host = std::env::var("YONIK_NFT_TEST_HOST_NETNS").expect("Передайте host netns до unshare");
    let netns = File::open("/proc/thread-self/ns/net").unwrap();
    let current = namespace(&netns).unwrap();
    assert_ne!(host, format!("{}:{}", current.0, current.1));
    let topology = fixture(&["setup"]);
    let uplink = topology["uplink"].as_u64().unwrap() as u32;
    let vpn = topology["vpn"].as_u64().unwrap() as u32;
    let loopback = topology["loopback"].as_u64().unwrap() as u32;
    let _peer = peer();
    let public = ["198.18.1.2", "2001:db8:1::2"];
    let lan = ["10.42.0.2", "fd42::2"];
    let private = ["10.42.1.2", "fd42:1::2"];
    for address in public.iter().chain(&lan).chain(&private) {
        for protocol in ["tcp", "udp"] {
            assert!(
                probe(address, protocol, None, "24081"),
                "Baseline {address}/{protocol}"
            );
        }
    }
    let prefix = |address: &str, length| IpPrefix::new(address.parse().unwrap(), length).unwrap();
    let policy = PublicBlockPolicy::new(
        loopback,
        None,
        vec![
            PrivateRoute::new(prefix("10.42.1.0", 24), Some(vpn)).unwrap(),
            PrivateRoute::new(prefix("fd42:1::", 64), Some(vpn)).unwrap(),
        ],
        vec![
            LanException::new(prefix("10.42.0.0", 16), uplink).unwrap(),
            LanException::new(prefix("fd42::", 16), uplink).unwrap(),
            LanException::new(prefix("ff02::", 16), uplink).unwrap(),
            LanException::new(prefix("ff02::", 16), vpn).unwrap(),
        ],
        vec![
            BoundTransport::new(
                public[0].parse().unwrap(),
                TransportProtocol::Tcp,
                24081,
                uplink,
                0,
                42,
            )
            .unwrap(),
        ],
        vec![
            BoundTransport::new(
                public[1].parse().unwrap(),
                TransportProtocol::Udp,
                24081,
                uplink,
                0,
                42,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let without_control = policy.clone();
    fixture(&["nat-redirect"]);
    for address in lan {
        assert!(
            probe(address, "tcp", None, "24082"),
            "Foreign DNAT baseline"
        );
    }
    let policy = policy.with_link_control(vec![uplink, vpn]).unwrap();
    let owner = Ownership::new(1000, 7, 9, current.0, current.1).unwrap();
    let make_executor = || NftExecutor {
        executable: File::open("/usr/bin/nft").unwrap(),
        netns: File::open("/proc/thread-self/ns/net").unwrap(),
        owner,
        gate: Arc::new(Semaphore::new(1)),
    };
    let mut executor = make_executor();
    let path = std::path::PathBuf::from(format!("/tmp/yonik-public-block-{}", std::process::id()));
    let mut journal = Journal::open(&path, owner).unwrap();
    assert_eq!(
        fixture(&["neighbor-control"])["resolved"],
        true,
        "NDP baseline without firewall"
    );
    let expected = block_table(owner, 8, 8, &policy);
    let foreign = Table {
        family: expected.family,
        name: expected.name.clone(),
        comment: "foreign-fixture".into(),
    };
    executor.run(Action::Create(&foreign)).await.unwrap();
    assert_eq!(
        executor.run(Action::InstallBlock(&expected, &policy)).await,
        Err(NftError::Rejected)
    );
    let foreign_listing = executor.run(Action::ListTable(&foreign)).await.unwrap();
    // Ошибка exclusive create откатывает и последующие chain/rules batch.
    assert!(matches!(
        observe_json(&foreign_listing, &foreign).unwrap(),
        Observation::Owned(_)
    ));
    executor
        .ensure_public_block(&mut journal, 2, 5, &without_control)
        .await
        .unwrap();
    assert_eq!(
        fixture(&["neighbor-control"])["resolved"],
        false,
        "Negative control without explicit ND rules"
    );
    executor
        .replace_public_block(&mut journal, 2, &without_control, &policy)
        .await
        .unwrap();
    let neighbor = fixture(&["neighbor-control"]);
    assert_eq!(
        neighbor["resolved"], true,
        "NDP/NA must work without a warm neighbour cache: {neighbor}"
    );
    fixture(&["cold-neighbors"]);
    executor
        .ensure_public_block(&mut journal, 2, 5, &policy)
        .await
        .unwrap();
    let binary = std::mem::replace(&mut executor.executable, File::open("/dev/null").unwrap());
    assert_eq!(
        executor
            .ensure_public_block(&mut journal, 2, 5, &policy)
            .await,
        Err(NftError::Io)
    );
    assert!(journal.needs_reconciliation(2));
    executor.executable = binary;
    executor
        .ensure_public_block(&mut journal, 2, 5, &policy)
        .await
        .unwrap();
    for address in public {
        for protocol in ["tcp", "udp"] {
            assert!(
                !probe(address, protocol, None, "24081"),
                "Public must drop {address}/{protocol}"
            );
        }
    }
    for address in lan.iter().chain(&private) {
        for protocol in ["tcp", "udp"] {
            assert!(
                probe(address, protocol, None, "24081"),
                "Bound exception {address}/{protocol}"
            );
        }
    }
    for address in lan {
        assert!(
            !probe(address, "tcp", None, "24082"),
            "DNAT must not turn a LAN exemption into public egress"
        );
    }
    assert!(probe(public[0], "tcp", Some("42"), "24081"));
    assert!(probe(public[1], "udp", Some("42"), "24081"));
    for (address, protocol) in [(public[0], "tcp"), (public[1], "udp")] {
        assert!(!probe(address, protocol, Some("43"), "24081"));
        assert!(!probe(address, protocol, Some("42"), "24082"));
    }
    assert!(!probe("198.18.1.3", "tcp", Some("42"), "24081"));
    assert!(!probe("2001:db8:1::3", "udp", Some("42"), "24081"));
    executor
        .ensure_table(&mut journal, Scope::Session, 3, 6, NftFamily::Inet)
        .await
        .unwrap();
    executor
        .remove_table(&mut journal, Scope::Session, 3)
        .await
        .unwrap();
    drop(executor);
    drop(journal);
    let mut executor = make_executor();
    let mut journal = Journal::open(&path, owner).unwrap();
    executor
        .ensure_public_block(&mut journal, 2, 5, &policy)
        .await
        .unwrap();
    for address in public {
        for protocol in ["tcp", "udp"] {
            assert!(!probe(address, protocol, None, "24081"));
        }
    }
    fixture(&["reroute-private"]);
    for address in private {
        for protocol in ["tcp", "udp"] {
            assert!(
                !probe(address, protocol, None, "24081"),
                "Private must not fall back to LAN {address}"
            );
        }
    }
    let stopped = PublicBlockPolicy::new(
        loopback,
        None,
        vec![],
        vec![
            LanException::new(prefix("10.42.0.0", 16), uplink).unwrap(),
            LanException::new(prefix("fd42::", 16), uplink).unwrap(),
            LanException::new(prefix("ff02::", 16), uplink).unwrap(),
        ],
        vec![],
        vec![],
    )
    .unwrap()
    .with_link_control(vec![uplink])
    .unwrap();
    executor
        .replace_public_block(&mut journal, 2, &policy, &stopped)
        .await
        .unwrap();
    assert_eq!(
        executor
            .ensure_public_block(&mut journal, 2, 5, &policy)
            .await,
        Err(NftError::Foreign)
    );
    // Полная остановка снимает сессионные private guards, но сохраняет
    // публичный kill switch. Теперь приватные назначения обслуживает ОС/LAN.
    for address in private {
        for protocol in ["tcp", "udp"] {
            assert!(probe(address, protocol, None, "24081"));
        }
    }
    for address in public {
        for protocol in ["tcp", "udp"] {
            assert!(!probe(address, protocol, None, "24081"));
        }
    }
    drop(executor);
    drop(journal);
    let mut executor = make_executor();
    let mut journal = Journal::open(&path, owner).unwrap();
    executor
        .ensure_public_block(&mut journal, 2, 5, &stopped)
        .await
        .unwrap();
    executor
        .remove_public_block(&mut journal, 2, &stopped)
        .await
        .unwrap();
    for address in public {
        for protocol in ["tcp", "udp"] {
            assert!(
                probe(address, protocol, None, "24081"),
                "Unlock restores normal network {address}"
            );
        }
    }
    assert!(journal.records().is_empty());
    for address in lan {
        assert!(
            probe(address, "tcp", None, "24082"),
            "Foreign DNAT preserved after Unlock"
        );
    }
    let Observation::Owned(handle) = executor.observe(&foreign).await.unwrap() else {
        panic!("Чужая таблица сохранена после Unlock");
    };
    executor
        .run(Action::Delete(&foreign, handle))
        .await
        .unwrap();
    drop(journal);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn cancellation_of_recheck_invalidates_previous_evidence() {
    use futures_util::FutureExt;
    let netns = File::open("/proc/thread-self/ns/net").unwrap();
    let ns = namespace(&netns).unwrap();
    let owner = Ownership::new(1000, 7, 9, ns.0, ns.1).unwrap();
    let gate = Arc::new(Semaphore::new(1));
    let mut executor = NftExecutor {
        executable: File::open("/dev/null").unwrap(),
        netns,
        owner,
        gate: Arc::clone(&gate),
    };
    let path = std::env::temp_dir().join(format!("yonik-block-recheck-{}", std::process::id()));
    let mut journal = Journal::open(&path, owner).unwrap();
    journal
        .intent(
            owner,
            Scope::PublicBlock,
            2,
            Resource::NftTable {
                table_id: 5,
                family: NftFamily::Inet,
            },
        )
        .unwrap();
    journal.reconcile(owner, 2, Reconciled::Owned).unwrap();
    assert!(!journal.needs_reconciliation(2));
    let _busy = gate.acquire().await.unwrap();
    assert!(
        executor
            .ensure_public_block(&mut journal, 2, 5, &policy())
            .now_or_never()
            .is_none()
    );
    assert!(journal.needs_reconciliation(2));
    drop(journal);
    std::fs::remove_dir_all(path).unwrap();
}
