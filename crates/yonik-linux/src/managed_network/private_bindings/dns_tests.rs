use super::{BindingError, BindingRequest, IpPrefix, PrivateBindings, PrivateDnsCompileError};
use crate::{
    Cancellation,
    network::{NetworkMonitor, TransportProtocol, read_topology},
    resolver::ResolverError,
};
use std::{
    num::NonZeroU16,
    time::{Duration, Instant},
};
use yonik_engine::{
    Engine, PolicyCapability, PolicyCompileError, PolicyMode,
    private_dns::{
        DnsEpoch, DnsPolicy, DomainPattern, Policy, PrivateDnsRoute, PrivateDomain, VpnId,
    },
};

#[tokio::test]
#[ignore = "Private WireGuard namespace + private bus runner"]
async fn private_dns_exchange_uses_confirmed_interface_and_scope() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};

    assert!(
        std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tools/private_bindings_fixture.py"
            ))
            .status()
            .unwrap()
            .success()
    );
    let bus = zbus::Connection::system().await.unwrap();
    bus.request_name("org.freedesktop.resolve1").await.unwrap();
    bus.request_name("org.freedesktop.NetworkManager")
        .await
        .unwrap();
    let monitor = NetworkMonitor::start().unwrap();
    let mut watch = monitor.watch();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !watch.current().fully_observed() {
            watch.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let (_keep, mut cancel) = Cancellation::new();
    let topology = read_topology(&mut cancel, Duration::from_secs(3))
        .await
        .unwrap();
    let vpn = topology
        .links
        .iter()
        .find(|link| link.name == b"vpn")
        .unwrap()
        .index;
    let requests = [("10.42.1.0", 24), ("fd42:1::", 64)]
        .into_iter()
        .map(|(prefix, length)| BindingRequest {
            prefix: IpPrefix::new(prefix.parse().unwrap(), length).unwrap(),
            ifindex: vpn,
            table: 254,
            wireguard: true,
        })
        .collect();
    let binding = PrivateBindings::capture(&watch, &mut cancel, requests)
        .await
        .unwrap();
    let mut peer = tokio::process::Command::new("ip")
        .args([
            "netns",
            "exec",
            "yonik-peer",
            "python3",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tools/private_dns_fixture.py"
            ),
            "relay-peer",
        ])
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut witnessed = BufReader::new(peer.stdout.take().unwrap()).lines();
    let mut next = async || {
        tokio::time::timeout(Duration::from_secs(3), witnessed.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    };
    assert_eq!(next().await, "READY");
    let zone = PrivateDomain {
        domain: DomainPattern::Suffix("corp.test".parse().unwrap()),
        vpn: VpnId::new(7).unwrap(),
        available: true,
    };
    let epoch = DnsEpoch {
        network: 1,
        engine: 2,
        resolver: 3,
    };
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x04corp\x04test\0\0\x01\0\x01";
    let service = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01\x04_svc\x04corp\x04test\0\0\x01\0\x01\
        \0\0\x29\x04\xd0\0\0\x80\0\0\x05\xfd\xe9\0\x01x";
    let dotted_label = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x09corp.test\0\0\x01\0\x01";
    let mut foreign_record = query.to_vec();
    foreign_record[11] = 1;
    foreign_record
        .extend_from_slice(b"\x04open\x04test\0\0\x01\0\x01\0\0\0\x3c\0\x04\xc0\0\x02\x01");
    for (endpoint, address) in [
        ("10.42.1.2:1053", "10.42.1.2"),
        ("[fd42:1::2]:1053", "fd42:1::2"),
    ] {
        let route = PrivateDnsRoute::new(&zone, endpoint.parse().unwrap(), "vpn").unwrap();
        let mut resolver = binding
            .verify_private_resolver(
                route,
                Instant::now() + Duration::from_secs(10),
                epoch,
                0,
                0x5100_0001,
                &watch,
                &mut cancel,
            )
            .await
            .unwrap();
        let mut unrelated = *query;
        unrelated[13..17].copy_from_slice(b"open");
        assert!(matches!(
            resolver
                .exchange(
                    &unrelated,
                    TransportProtocol::Udp,
                    epoch,
                    &watch,
                    &mut cancel
                )
                .await,
            Err(ResolverError::Untrusted)
        ));
        for rejected in [dotted_label.as_slice(), foreign_record.as_slice()] {
            assert!(matches!(
                resolver
                    .exchange(rejected, TransportProtocol::Udp, epoch, &watch, &mut cancel)
                    .await,
                Err(ResolverError::Unsupported)
            ));
        }
        for (transport, expected) in [
            (TransportProtocol::Udp, "SOCK_DGRAM"),
            (TransportProtocol::Tcp, "SOCK_STREAM"),
        ] {
            let response = resolver
                .exchange(service, transport, epoch, &watch, &mut cancel)
                .await
                .unwrap();
            assert_eq!(&response.packet()[..2], &[0x12, 0x34]);
            assert!(response.packet().ends_with(&[10, 42, 1, 2]));
            assert_eq!(next().await, format!("{expected} {address}"));
            eprintln!("YONIK_PRIVATE_DNS_WIREGUARD {expected} {address}");
        }
    }
    let route = PrivateDnsRoute::new(&zone, "10.42.1.2:1053".parse().unwrap(), "vpn").unwrap();
    let mut resolver = binding
        .verify_private_resolver(
            route,
            Instant::now() + Duration::from_secs(10),
            epoch,
            0,
            0,
            &watch,
            &mut cancel,
        )
        .await
        .unwrap();
    let hold = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x04hold\x04corp\x04test\0\0\x01\0\x01";
    let (interrupted, ()) = tokio::join!(
        resolver.exchange(hold, TransportProtocol::Udp, epoch, &watch, &mut cancel),
        async {
            assert_eq!(next().await, "HOLD 10.42.1.2");
            assert!(monitor.shutdown().await);
        },
    );
    assert!(matches!(interrupted, Err(ResolverError::Untrusted)));
    eprintln!("YONIK_PRIVATE_DNS_WIREGUARD_REVOKED_IN_FLIGHT");
    assert!(matches!(
        resolver
            .exchange(query, TransportProtocol::Tcp, epoch, &watch, &mut cancel)
            .await,
        Err(ResolverError::Untrusted)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), next())
            .await
            .is_err()
    );
    peer.kill().await.unwrap();
}

#[tokio::test]
#[ignore = "Private namespace + private bus runner"]
async fn verified_dns_lease_actual_route_epochs_and_unsupported_native_hooks() {
    assert!(
        std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tools/private_bindings_fixture.py"
            ))
            .status()
            .unwrap()
            .success()
    );
    let resolver_service = zbus::Connection::system().await.unwrap();
    let manager_service = zbus::Connection::system().await.unwrap();
    resolver_service
        .request_name("org.freedesktop.resolve1")
        .await
        .unwrap();
    manager_service
        .request_name("org.freedesktop.NetworkManager")
        .await
        .unwrap();
    let monitor = NetworkMonitor::start().unwrap();
    let mut watch = monitor.watch();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !watch.current().fully_observed() {
            watch.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let (_sender, mut cancel) = Cancellation::new();
    let topo = read_topology(&mut cancel, Duration::from_secs(3))
        .await
        .unwrap();
    let vpn = topo.links.iter().find(|l| l.name == b"vpn").unwrap().index;
    let request = || {
        vec![BindingRequest {
            prefix: IpPrefix::new("10.42.1.0".parse().unwrap(), 24).unwrap(),
            ifindex: vpn,
            table: 254,
            wireguard: true,
        }]
    };
    let private = PrivateDomain {
        domain: DomainPattern::Suffix("corp.test".parse().unwrap()),
        vpn: VpnId::new(7).unwrap(),
        available: true,
    };
    let route =
        || PrivateDnsRoute::new(&private, "10.42.1.2:1053".parse().unwrap(), "vpn").unwrap();
    let mut epoch = DnsEpoch {
        network: 11,
        engine: 22,
        resolver: 33,
    };
    let source = yonik_import::import_bytes(b"socks5://127.0.0.1:24082".to_vec()).unwrap();
    let dns = DnsPolicy {
        mode: yonik_engine::private_dns::NativeDnsMode::Real,
        upstream: "127.0.0.1:1153".parse().unwrap(),
        ipv4: true,
        ipv6: false,
        fake_exclusions: Vec::new(),
        require_mapping_lease: false,
        listen_port: NonZeroU16::new(1054).unwrap(),
    };
    for engine in [Engine::Xray, Engine::SingBox] {
        let binding = PrivateBindings::capture(&watch, &mut cancel, request())
            .await
            .unwrap();
        let token = binding
            .verify_private_resolver(
                route(),
                Instant::now() + Duration::from_secs(10),
                epoch,
                0,
                0,
                &watch,
                &mut cancel,
            )
            .await
            .unwrap();
        assert!(matches!(
            token
                .compile(
                    epoch,
                    &watch,
                    &mut cancel,
                    &source.servers[0],
                    engine,
                    NonZeroU16::new(10808).unwrap(),
                    NonZeroU16::new(10809).unwrap(),
                    &Policy::default(),
                    PolicyMode::Names,
                    &dns
                )
                .await,
            Err(PrivateDnsCompileError::Compiler(
                PolicyCompileError::Unsupported(PolicyCapability::DnsContract)
            ))
        ));
    }
    let binding = PrivateBindings::capture(&watch, &mut cancel, request())
        .await
        .unwrap();
    let mut first = binding
        .verify_private_resolver(
            route(),
            Instant::now() + Duration::from_secs(10),
            epoch,
            0,
            0,
            &watch,
            &mut cancel,
        )
        .await
        .unwrap();
    let mut second = binding
        .verify_private_resolver(
            route(),
            Instant::now() + Duration::from_secs(10),
            epoch,
            0,
            0,
            &watch,
            &mut cancel,
        )
        .await
        .unwrap();
    let (_parallel_sender, mut parallel_cancel) = Cancellation::new();
    let (first_result, second_result) = tokio::join!(
        biased;
        first.revalidate(epoch, &watch, &mut cancel),
        second.revalidate(
            DnsEpoch {
                engine: epoch.engine + 1,
                ..epoch
            },
            &watch,
            &mut parallel_cancel
        )
    );
    assert!(first_result.is_err());
    assert!(second_result.is_err());
    let baseline = std::env::temp_dir().join("private-dns-native");
    std::fs::create_dir(&baseline).unwrap();
    for (engine, name) in [(Engine::Xray, "xray"), (Engine::SingBox, "sing-box")] {
        let fake_dns = DnsPolicy {
            mode: yonik_engine::private_dns::NativeDnsMode::FakeIp,
            ..dns.clone()
        };
        let config = yonik_engine::compile_native_dns(
            &source.servers[0],
            engine,
            NonZeroU16::new(10808).unwrap(),
            NonZeroU16::new(10809).unwrap(),
            &Policy::default(),
            PolicyMode::Names,
            &fake_dns,
        )
        .unwrap();
        let mut file = std::fs::File::create(baseline.join(format!("{name}.json"))).unwrap();
        config.write_sensitive(&mut file).unwrap();
    }
    let native = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tools/private_dns_fixture.py"
        ))
        .arg("run")
        .arg("--baseline")
        .arg(&baseline)
        .output()
        .unwrap();
    eprintln!("{}", String::from_utf8_lossy(&native.stdout));
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    // Native diagnostic сделал down/up, пока current-thread executor ждал child.
    // Сначала действительно принимаем событие existing monitor, затем capture.
    tokio::time::timeout(Duration::from_secs(3), watch.changed())
        .await
        .unwrap()
        .unwrap();
    epoch.network += 1;
    for changed in [
        DnsEpoch {
            network: 13,
            ..epoch
        },
        DnsEpoch {
            engine: 23,
            ..epoch
        },
        DnsEpoch {
            resolver: 34,
            ..epoch
        },
    ] {
        let binding = PrivateBindings::capture(&watch, &mut cancel, request())
            .await
            .unwrap();
        let mut token = binding
            .verify_private_resolver(
                route(),
                Instant::now() + Duration::from_secs(10),
                epoch,
                0,
                0,
                &watch,
                &mut cancel,
            )
            .await
            .unwrap();
        assert!(
            token
                .revalidate(changed, &watch, &mut cancel)
                .await
                .is_err()
        );
        assert!(token.revalidate(epoch, &watch, &mut cancel).await.is_err());
    }
    let binding = PrivateBindings::capture(&watch, &mut cancel, request())
        .await
        .unwrap();
    let mut token = binding
        .verify_private_resolver(
            route(),
            Instant::now() + Duration::from_secs(1),
            epoch,
            0,
            0,
            &watch,
            &mut cancel,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1050)).await;
    assert!(token.revalidate(epoch, &watch, &mut cancel).await.is_err());
    let binding = PrivateBindings::capture(&watch, &mut cancel, request())
        .await
        .unwrap();
    let mut token = binding
        .verify_private_resolver(
            route(),
            Instant::now() + Duration::from_secs(10),
            epoch,
            0,
            0,
            &watch,
            &mut cancel,
        )
        .await
        .unwrap();
    resolver_service
        .release_name("org.freedesktop.resolve1")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while watch.current().fully_observed() {
            watch.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(token.revalidate(epoch, &watch, &mut cancel).await.is_err());
    resolver_service
        .request_name("org.freedesktop.resolve1")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !watch.current().fully_observed() {
            watch.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(token.revalidate(epoch, &watch, &mut cancel).await.is_err());
    // Более приоритетный чужой RPDB путь: prefix остаётся на WG, но actual lookup
    // уходит в другую таблицу/интерфейс — такой resolver lease запрещён.
    assert!(
        std::process::Command::new("ip")
            .args([
                "route",
                "add",
                "10.42.1.2/32",
                "dev",
                "uplink",
                "table",
                "300"
            ])
            .status()
            .unwrap()
            .success()
    );
    // Отдельно подтверждаем route event, затем rule event: watch объединяет
    // снимки, и один changed() не обещает обработку двух разных сообщений.
    tokio::time::timeout(Duration::from_secs(3), watch.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(
        std::process::Command::new("ip")
            .args([
                "rule",
                "add",
                "priority",
                "100",
                "to",
                "10.42.1.2/32",
                "lookup",
                "300"
            ])
            .status()
            .unwrap()
            .success()
    );
    tokio::time::timeout(Duration::from_secs(3), watch.changed())
        .await
        .unwrap()
        .unwrap();
    let binding = PrivateBindings::capture(&watch, &mut cancel, request())
        .await
        .unwrap();
    let rejected = binding
        .verify_private_resolver(
            route(),
            Instant::now() + Duration::from_secs(10),
            epoch,
            0,
            0,
            &watch,
            &mut cancel,
        )
        .await;
    assert!(matches!(rejected, Err(BindingError::MissingPath)));
    assert!(
        std::process::Command::new("ip")
            .args(["rule", "del", "priority", "100"])
            .status()
            .unwrap()
            .success()
    );
    tokio::time::timeout(Duration::from_secs(3), watch.changed())
        .await
        .unwrap()
        .unwrap();
    let binding = PrivateBindings::capture(&watch, &mut cancel, request())
        .await
        .unwrap();
    let mut token = binding
        .verify_private_resolver(
            route(),
            Instant::now() + Duration::from_secs(10),
            epoch,
            0,
            0,
            &watch,
            &mut cancel,
        )
        .await
        .unwrap();
    assert!(monitor.shutdown().await);
    assert_eq!(
        token.revalidate(epoch, &watch, &mut cancel).await,
        Err(BindingError::Stale)
    );
}
