//! Только SYNTHETIC_REFERENCE: DATA не предоставляет runtime authority.
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::IpAddr};
use yonik_domain::*;
use yonik_engine::dns_policy_plan::*;

const CORPUS: &str = include_str!("../../../tests/fixtures/p14-policy-plan-oracle-v1.json");
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    classification: String,
    profiles: BTreeMap<String, Value>,
    cases: Vec<Case>,
    missing: Vec<Missing>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Missing {
    id: String,
    status: String,
    seam: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    profile: String,
    observation: Observation,
    expected: Value,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    kind: String,
    name: String,
    addresses: Vec<IpAddr>,
    a: String,
    aaaa: String,
    resolution: String,
    now: u64,
    expires_at: u64,
    epoch: [u64; 3],
    path: u64,
    mapping: String,
}
fn load(raw: &str) -> Result<Corpus, String> {
    if raw.len() > 131_072 {
        return Err("bytes".into());
    }
    let c: Corpus = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if c.version != 1
        || c.classification != "SYNTHETIC_REFERENCE"
        || c.cases.len() > 64
        || c.profiles.len() > 10
    {
        return Err("header/bounds".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    for case in &c.cases {
        let expected = case.expected.as_object().ok_or("expected object")?;
        let keys: &[&str] = match case.expected["kind"].as_str() {
            Some("decided") => &["kind", "route", "origin", "vpn"],
            Some("rejected") => &["kind", "error"],
            Some("need_resolution") => &["kind", "vpn"],
            _ => return Err("expected kind".into()),
        };
        if expected.len() != keys.len() || keys.iter().any(|k| !expected.contains_key(*k)) {
            return Err("expected fields".into());
        }
        let o = &case.observation;
        if !ids.insert(&case.id)
            || !c.profiles.contains_key(&case.profile)
            || o.addresses.len() > 64
            || o.name.len() > 253
            || o.name.parse::<DomainName>().is_err()
            || !["name", "literal", "fake"].contains(&o.kind.as_str())
            || !["answer", "failed", "missing"].contains(&o.resolution.as_str())
            || !["none", "valid", "expired", "stale"].contains(&o.mapping.as_str())
            || [&o.a, &o.aaaa].iter().any(|s| {
                !["answer", "nodata", "timeout", "servfail", "unqueried"].contains(&s.as_str())
            })
            || (o.kind == "literal" && o.addresses.len() != 1)
        {
            return Err("vector".into());
        }
        for (family, status) in [(true, &o.a), (false, &o.aaaa)] {
            let present = o.addresses.iter().any(|ip| ip.is_ipv4() == family);
            if (status == "answer") != present {
                return Err("family".into());
            }
        }
    }
    Ok(c)
}
fn action(s: &str) -> Action {
    match s {
        "direct" => Action::Direct,
        "proxy" => Action::Proxy,
        "block" => Action::Block,
        _ => panic!("action"),
    }
}
fn pattern(v: &Value) -> DomainPattern {
    let name = v["name"].as_str().unwrap().parse().unwrap();
    match v["kind"].as_str().unwrap() {
        "exact" => DomainPattern::Exact(name),
        "suffix" => DomainPattern::Suffix(name),
        _ => panic!("pattern"),
    }
}
// Декодер только структуры, без правил выбора маршрута; всю семантику исполняет domain.
fn emitted_policy(v: &Value) -> Policy {
    let rules = |key: &str| {
        v[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| Rule {
                id: r["id"].as_u64().unwrap(),
                enabled: r["enabled"].as_bool().unwrap(),
                action: action(r["action"].as_str().unwrap()),
                conditions: Conditions {
                    executables: serde_json::from_value(r["source"]["executables"].clone())
                        .unwrap(),
                    domains: r["destination"]["domains"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(pattern)
                        .collect(),
                    destinations: r["destination"]["cidrs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s.as_str().unwrap().parse().unwrap())
                        .collect(),
                    transport: serde_json::from_value::<yonik_engine::transport::TransportInput>(
                        r["transport"].clone(),
                    )
                    .unwrap()
                    .typed()
                    .unwrap(),
                    ..Conditions::default()
                },
            })
            .collect()
    };
    Policy {
        default_action: action(v["default_action"].as_str().unwrap()),
        user_rules: rules("user_rules"),
        preset_rules: rules("preset_rules"),
        lan: v["lan"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().parse().unwrap())
            .collect(),
        private_networks: v["private_networks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| PrivateNetwork {
                network: n["cidr"].as_str().unwrap().parse().unwrap(),
                vpn: VpnId::new(n["vpn"].as_u64().unwrap()).unwrap(),
                available: n["available"].as_bool().unwrap(),
            })
            .collect(),
        private_domains: v["private_domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| PrivateDomain {
                domain: pattern(&n["domain"]),
                vpn: VpnId::new(n["vpn"].as_u64().unwrap()).unwrap(),
                available: n["available"].as_bool().unwrap(),
            })
            .collect(),
    }
}
fn typed(profile: &str) -> (Policy, DnsPolicy, DesiredPlan) {
    let mut p = Policy {
        default_action: Action::Block,
        lan: vec!["192.168.0.0/16".parse().unwrap()],
        ..Policy::default()
    };
    p.user_rules.push(Rule {
        id: 10,
        enabled: true,
        action: Action::Direct,
        conditions: Conditions {
            destinations: vec!["203.0.113.0/24".parse().unwrap()],
            ..Conditions::default()
        },
    });
    p.user_rules.push(Rule {
        id: 11,
        enabled: true,
        action: Action::Proxy,
        conditions: Conditions {
            domains: vec![DomainPattern::Suffix("example.test".parse().unwrap())],
            ..Conditions::default()
        },
    });
    p.preset_rules.push(Rule {
        id: 20,
        enabled: true,
        action: Action::Direct,
        conditions: Conditions {
            destinations: vec!["2001:db8::/32".parse().unwrap()],
            ..Conditions::default()
        },
    });
    let mut x = DesiredPlan {
        version: 1,
        network_epoch: 1,
        engine_epoch: 2,
        resolver_epoch: 3,
        policy_transport: DnsTransport::Udp,
        policy_route: ServiceRoute::Proxy,
        bootstrap_route: ServiceRoute::Direct,
        bootstrap: "9.9.9.9:53".parse().unwrap(),
        bootstrap_transport: DnsTransport::Tcp,
        vpns: vec![],
        fake_pools: vec![],
        reserved_constraints: vec![],
    };
    if [
        "private",
        "unavailable",
        "zone",
        "zone_down",
        "two_vpns",
        "fake_private",
        "fake_unavailable",
    ]
    .contains(&profile)
    {
        p.private_networks.push(PrivateNetwork {
            network: "10.0.0.0/8".parse().unwrap(),
            vpn: VpnId::new(7).unwrap(),
            available: !["unavailable", "fake_unavailable"].contains(&profile),
        });
        x.vpns.push(DesiredVpn {
            vpn: 7,
            ifname: "vpn7".into(),
            table: 107,
            resolver: "10.0.0.53:53".parse().unwrap(),
            transport: DnsTransport::Tcp,
            excluded: false,
        });
    }
    if profile == "two_vpns" {
        p.private_networks.push(PrivateNetwork {
            network: "172.16.0.0/12".parse().unwrap(),
            vpn: VpnId::new(8).unwrap(),
            available: true,
        });
        x.vpns.push(DesiredVpn {
            vpn: 8,
            ifname: "vpn8".into(),
            table: 108,
            resolver: "172.16.0.53:53".parse().unwrap(),
            transport: DnsTransport::Tcp,
            excluded: false,
        });
    }
    if profile.starts_with("zone") {
        p.private_domains.push(PrivateDomain {
            domain: DomainPattern::Suffix("internal.test".parse().unwrap()),
            vpn: VpnId::new(7).unwrap(),
            available: profile != "zone_down",
        });
    }
    let fake = matches!(profile, "fake" | "fake_private" | "fake_unavailable");
    if fake {
        x.fake_pools.push("198.18.0.0/15".into());
    }
    let d = DnsPolicy {
        mode: if fake {
            NativeDnsMode::FakeIp
        } else {
            NativeDnsMode::Real
        },
        upstream: "1.1.1.1:53".parse().unwrap(),
        ipv4: true,
        ipv6: true,
        fake_exclusions: vec![DomainPattern::Suffix("internal.test".parse().unwrap())],
        require_mapping_lease: fake,
        listen_port: 5353.try_into().unwrap(),
    };
    (p, d, x)
}
fn epoch(a: [u64; 3]) -> DnsEpoch {
    DnsEpoch {
        network: a[0],
        engine: a[1],
        resolver: a[2],
    }
}
fn outcome(e: Evaluation) -> Value {
    match e {
        Evaluation::NeedResolution(path) => {
            json!({"kind":"need_resolution","vpn":match path {ResolverPath::Policy=>0,ResolverPath::Vpn(v)=>v.get()}})
        }
        Evaluation::Rejected(f) => {
            json!({"kind":"rejected","error":match f {PolicyFault::DnsPolicyUnresolved=>"dns_policy_unresolved",PolicyFault::DnsPolicyAmbiguous=>"dns_policy_ambiguous",PolicyFault::UnknownFakeMapping=>"unknown_fake_mapping",PolicyFault::WrongResolver=>"wrong_resolver",_=>panic!("unexpected fault {f:?}")}})
        }
        Evaluation::Decided { decision, vpn } => {
            json!({"kind":"decided","route":match decision.action {Route::Direct=>"direct",Route::Proxy=>"proxy",Route::Block=>"block",Route::PrivateVpn=>"private_vpn"},"origin":match decision.origin {RuleOrigin::User(id)=>format!("user:{id}"),RuleOrigin::Preset(id)=>format!("preset:{id}"),RuleOrigin::PrivateNetwork=>"private_network".into(),RuleOrigin::PrivateDomain=>"private_domain".into(),RuleOrigin::Lan=>"lan".into(),RuleOrigin::Default=>"default".into()},"vpn":vpn.map_or(0,VpnId::get)})
        }
    }
}
#[test]
fn emitted_data_oracle() {
    let c = load(CORPUS).unwrap();
    for m in &c.missing {
        assert_eq!(m.status, "NOT_IMPLEMENTED");
        assert!(!m.id.is_empty() && !m.seam.is_empty());
    }
    for (profile, expected) in &c.profiles {
        let (p, d, x) = typed(profile);
        let bytes = compile_plan(&p, &d, &x).unwrap();
        let emitted: Value = serde_json::from_slice(bytes.bytes()).unwrap();
        assert_eq!(&emitted, expected, "full DATA {profile}");
        let v = &emitted["yonik_policy"];
        let p = emitted_policy(&v["policy"]);
        let desired: DesiredPlan = serde_json::from_value(v["desired"].clone()).unwrap();
        let pools: Vec<Cidr> = desired
            .fake_pools
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let context_epoch = epoch([
            desired.network_epoch,
            desired.engine_epoch,
            desired.resolver_epoch,
        ]);
        for case in c.cases.iter().filter(|c| &c.profile == profile) {
            let o = &case.observation;
            let name = o.name.parse().unwrap();
            for reverse in [false, true] {
                let mut addresses = o.addresses.clone();
                if reverse {
                    addresses.reverse();
                }
                let resolution = match o.resolution.as_str() {
                    "missing" => Resolution::Missing,
                    "failed" => Resolution::Failed,
                    _ => Resolution::Answer(AnswerSet {
                        addresses: &addresses,
                        complete: [&o.a, &o.aaaa]
                            .iter()
                            .all(|s| ["answer", "nodata"].contains(&s.as_str())),
                        expires_at: o.expires_at,
                        epoch: epoch(o.epoch),
                        path: if o.path == 0 {
                            ResolverPath::Policy
                        } else {
                            ResolverPath::Vpn(VpnId::new(o.path).unwrap())
                        },
                    }),
                };
                let mapping = FakeMapping {
                    address: "198.18.0.1".parse().unwrap(),
                    name: o.name.parse().unwrap(),
                    expires_at: if o.mapping == "expired" { o.now } else { 10 },
                    epoch: if o.mapping == "stale" {
                        epoch([9, 9, 9])
                    } else {
                        context_epoch
                    },
                };
                let destination = match o.kind.as_str() {
                    "literal" => Destination::Ip {
                        address: addresses[0],
                        name: Some(&name),
                    },
                    "fake" => Destination::Fake {
                        address: mapping.address,
                        mapping: if o.mapping == "none" {
                            None
                        } else {
                            Some(&mapping)
                        },
                        resolution,
                    },
                    _ => Destination::Name {
                        name: &name,
                        resolution,
                    },
                };
                let got = p.evaluate_destination(
                    &DestinationFlow {
                        executable: None,
                        destination,
                    },
                    &EvaluationContext {
                        now: o.now,
                        epoch: context_epoch,
                        fake_pools: &pools,
                    },
                );
                assert_eq!(outcome(got), case.expected, "{} reverse={reverse}", case.id);
            }
        }
    }
}
#[test]
fn corpus_negative_vectors() {
    let mut v: Value = serde_json::from_str(CORPUS).unwrap();
    v["cases"][0]["observation"]["authority"] = json!(true);
    assert!(load(&v.to_string()).is_err());
    v["cases"][0]["observation"]
        .as_object_mut()
        .unwrap()
        .remove("authority");
    v["cases"][0]["observation"]["kind"] = json!("invented");
    assert!(load(&v.to_string()).is_err());
    assert!(load(&" ".repeat(131_073)).is_err());
    let mut invalid: Value = serde_json::from_str(CORPUS).unwrap();
    invalid["cases"][0]["observation"]["addresses"] = json!([]);
    assert!(load(&invalid.to_string()).is_err());
    let mut invalid: Value = serde_json::from_str(CORPUS).unwrap();
    invalid["cases"][0]["expected"]["authority"] = json!(true);
    assert!(load(&invalid.to_string()).is_err());
    let mut invalid: Value = serde_json::from_str(CORPUS).unwrap();
    invalid["cases"][0]["observation"]["addresses"] = json!(vec!["10.1.2.3"; 65]);
    assert!(load(&invalid.to_string()).is_err());
    let (mut p, d, x) = typed("public");
    p.user_rules[1].id = 10;
    assert_eq!(compile_plan(&p, &d, &x).unwrap_err(), PlanError::Invalid);
    let mut desired = serde_json::to_value(x).unwrap();
    desired["authority"] = json!(true);
    assert!(DesiredPlan::parse(&serde_json::to_vec(&desired).unwrap()).is_err());
}
