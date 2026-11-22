use yonik_domain::{DestinationPorts, TransportConditions, TransportWitness};

#[test]
fn destination_transport_boundaries() {
    assert!(DestinationPorts::parse(&[(0, 443)]).is_err());
    assert!(DestinationPorts::parse(&[(443, 443), (443, 444)]).is_err());
    let ports = DestinationPorts::parse(&[(444, 444), (443, 443)]).unwrap();
    let conditions = TransportConditions::parse(Some(&["tcp"]), Some(ports)).unwrap();
    assert_eq!(
        conditions.matches(TransportWitness::KnownTcp(443)),
        Ok(true)
    );
    assert_eq!(
        conditions.matches(TransportWitness::KnownTcp(8443)),
        Ok(false)
    );
    assert_eq!(
        conditions.matches(TransportWitness::KnownUdp(443)),
        Ok(false)
    );
    assert_eq!(conditions.matches(TransportWitness::KnownOther), Ok(false));
    assert!(conditions.matches(TransportWitness::Unavailable).is_err());
}

#[test]
fn transport_precedes_dns_and_preserves_first_match() {
    use yonik_domain::{
        Action, Conditions, Decision, Destination, DestinationFlow, Evaluation, EvaluationContext,
        Policy, PolicyFault, Resolution, ResolverPath, Rule, RuleOrigin,
    };
    let transport = TransportConditions::parse(
        Some(&["tcp"]),
        Some(DestinationPorts::parse(&[(443, 443)]).unwrap()),
    )
    .unwrap();
    let policy = Policy {
        user_rules: vec![Rule {
            id: 1,
            enabled: true,
            action: Action::Block,
            conditions: Conditions {
                executables: vec!["/fixture/app".into()],
                destinations: vec!["192.0.2.0/24".parse().unwrap()],
                transport,
                ..Default::default()
            },
        }],
        ..Default::default()
    };
    let name = "example.org".parse().unwrap();
    let flow = DestinationFlow {
        executable: Some("/fixture/app"),
        destination: Destination::Name {
            name: &name,
            resolution: Resolution::Missing,
        },
    };
    let context = EvaluationContext::default();
    let resources = struct_resources();
    assert!(matches!(
        policy.evaluate_transport(
            &flow,
            &context,
            &resources,
            TransportWitness::KnownTcp(8443)
        ),
        Evaluation::Decided {
            decision: Decision {
                origin: RuleOrigin::Default,
                ..
            },
            ..
        }
    ));
    assert_eq!(
        policy.evaluate_transport(&flow, &context, &resources, TransportWitness::Unavailable),
        Evaluation::Rejected(PolicyFault::TransportUnavailable(1))
    );
    assert_eq!(
        policy.evaluate_transport(&flow, &context, &resources, TransportWitness::KnownTcp(443)),
        Evaluation::NeedResolution(ResolverPath::Policy)
    );
}
fn struct_resources() -> impl yonik_domain::ResourceConditions {
    struct Empty;
    impl yonik_domain::ResourceConditions for Empty {
        fn has_domains(&self, _: yonik_domain::ResourceRule) -> bool {
            false
        }
        fn matches_domain(
            &self,
            _: yonik_domain::ResourceRule,
            _: &yonik_domain::DomainName,
        ) -> bool {
            false
        }
        fn has_cidrs(&self, _: yonik_domain::ResourceRule) -> bool {
            false
        }
        fn matches_ip(&self, _: yonik_domain::ResourceRule, _: std::net::IpAddr) -> bool {
            false
        }
    }
    Empty
}

#[test]
fn закрытые_группы_и_лимиты() {
    for protocols in [
        vec![],
        vec!["any"],
        vec!["icmp"],
        vec!["tcp", "tcp"],
        vec!["tcp", "udp", "tcp"],
    ] {
        assert!(TransportConditions::parse(Some(&protocols), None).is_err());
    }
    assert!(DestinationPorts::parse(&[]).is_err());
    assert!(DestinationPorts::parse(&[(2, 1)]).is_err());
    assert!(DestinationPorts::parse(&[(1, 65535)]).is_ok());
    let ranges: Vec<_> = (1..=17).map(|n| (n * 2, n * 2)).collect();
    assert!(DestinationPorts::parse(&ranges).is_err());
    assert!(DestinationPorts::parse(&ranges[..16]).is_ok());
    let ports = DestinationPorts::parse(&[(444, 444), (443, 443)]).unwrap();
    assert_eq!(ports.ranges(), &[(443, 444)]);
    let either = TransportConditions::parse(None, Some(ports)).unwrap();
    assert_eq!(either.matches(TransportWitness::KnownUdp(444)), Ok(true));
    assert_eq!(
        TransportConditions::default().matches(TransportWitness::Unavailable),
        Ok(true)
    );
}

#[test]
fn полная_таблица_составного_destination_правила() {
    use yonik_domain::{
        Action, Conditions, Decision, Destination, DestinationFlow, DomainPattern, Evaluation,
        EvaluationContext, Policy, PolicyFault, Route, Rule, RuleOrigin,
    };
    let policy = Policy {
        user_rules: vec![Rule {
            id: 7,
            enabled: true,
            action: Action::Block,
            conditions: Conditions {
                executables: vec!["/fixture/app".into()],
                domains: vec![DomainPattern::Exact("example.org".parse().unwrap())],
                destinations: vec!["192.0.2.0/24".parse().unwrap()],
                transport: TransportConditions::parse(
                    Some(&["tcp"]),
                    Some(DestinationPorts::parse(&[(443, 443)]).unwrap()),
                )
                .unwrap(),
                ..Default::default()
            },
        }],
        ..Default::default()
    };
    for source in ["/fixture/app", "/fixture/other"] {
        for domain in ["example.org", "other.org"] {
            let name = domain.parse().unwrap();
            for address in ["192.0.2.1", "198.51.100.1"] {
                for witness in [
                    TransportWitness::KnownTcp(443),
                    TransportWitness::KnownTcp(8443),
                    TransportWitness::KnownUdp(443),
                    TransportWitness::KnownOther,
                    TransportWitness::Unavailable,
                ] {
                    let flow = DestinationFlow {
                        executable: Some(source),
                        destination: Destination::Ip {
                            address: address.parse().unwrap(),
                            name: Some(&name),
                        },
                    };
                    let result = policy.evaluate_transport(
                        &flow,
                        &EvaluationContext::default(),
                        &struct_resources(),
                        witness,
                    );
                    if source == "/fixture/app" && witness == TransportWitness::Unavailable {
                        assert_eq!(
                            result,
                            Evaluation::Rejected(PolicyFault::TransportUnavailable(7))
                        );
                    } else {
                        let matched = source == "/fixture/app"
                            && domain == "example.org"
                            && address == "192.0.2.1"
                            && witness == TransportWitness::KnownTcp(443);
                        assert_eq!(
                            result,
                            Evaluation::Decided {
                                decision: Decision {
                                    action: if matched { Route::Block } else { Route::Proxy },
                                    origin: if matched {
                                        RuleOrigin::User(7)
                                    } else {
                                        RuleOrigin::Default
                                    }
                                },
                                vpn: None,
                                selected_address: (!matched).then(|| address.parse().unwrap()),
                            }
                        );
                    }
                }
            }
        }
    }
}
