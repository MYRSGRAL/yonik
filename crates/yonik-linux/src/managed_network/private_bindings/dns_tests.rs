use super::{BindingError, BindingRequest, IpPrefix, PrivateBindings, PrivateDnsCompileError};
use crate::{
    Cancellation,
    network::{NetworkMonitor, read_topology},
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
