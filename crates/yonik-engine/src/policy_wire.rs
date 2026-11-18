//! Плоский закрытый DTO существующей Policy для Prepare/RPCv1, depth ≤ 5.
use serde::{Deserialize, Serialize};
use serde_json::json;
use yonik_domain::Policy;

use crate::policy_input::{PolicyInputError, read_policy};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    default_action: Action,
    user_rules: Vec<Rule>,
    preset_rules: Vec<Rule>,
    lan: Vec<String>,
    private_networks: Vec<Network>,
    private_domains: Vec<Domain>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Direct,
    Proxy,
    Block,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<crate::transport::TransportInput>,
    id: u64,
    enabled: bool,
    action: Action,
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    ip_cidr: Vec<String>,
    executable_paths: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::platform_source::deserialize_sources"
    )]
    platform_sources: Option<Vec<crate::platform_source::PlatformSourceInput>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    cidr: String,
    vpn: u64,
    available: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Domain {
    suffix: String,
    vpn: u64,
    available: bool,
}

/// Поля закрыты: requirements вычисляются из того же объекта, который компилируется.
pub struct SystemPolicy {
    wire: Wire,
    policy: Policy,
}
impl Serialize for SystemPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.wire.serialize(serializer)
    }
}
impl SystemPolicy {
    /// Явные IP-префиксы включённых Direct-правил из той же политики, что компилируется.
    pub fn enabled_direct_prefixes(&self) -> impl Iterator<Item = (std::net::IpAddr, u8)> + '_ {
        self.policy
            .user_rules
            .iter()
            .chain(&self.policy.preset_rules)
            .filter(|rule| rule.enabled && rule.action == yonik_domain::Action::Direct)
            .flat_map(|rule| &rule.conditions.destinations)
            .map(|cidr| (cidr.network(), cidr.prefix_len()))
    }

    pub fn parse(text: &str) -> Result<Self, PolicyInputError> {
        if !bounded_depth(text, 6) {
            return Err(PolicyInputError::InvalidJson);
        }
        if text.len() > 262144 {
            return Err(PolicyInputError::TooLarge);
        }
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| PolicyInputError::InvalidJson)?;
        if !value.is_object() {
            return Err(PolicyInputError::InvalidJson);
        }
        for key in [
            "user_rules",
            "preset_rules",
            "private_networks",
            "private_domains",
        ] {
            if !value
                .get(key)
                .and_then(|v| v.as_array())
                .is_some_and(|rows| rows.iter().all(|v| v.is_object()))
            {
                return Err(PolicyInputError::InvalidJson);
            }
        }
        let wire: Wire = serde_json::from_str(text).map_err(|_| PolicyInputError::InvalidJson)?;
        if wire.version < 3 && !bounded_depth(text, 5) {
            return Err(PolicyInputError::InvalidJson);
        }
        if wire.user_rules.len() + wire.preset_rules.len() > 256 {
            return Err(PolicyInputError::Limit);
        }
        if ![1, 2, 3].contains(&wire.version)
            || wire
                .user_rules
                .iter()
                .chain(&wire.preset_rules)
                .any(|r| (wire.version >= 2) != r.platform_sources.is_some())
        {
            return Err(PolicyInputError::InvalidPolicy);
        }
        if wire.version < 3
            && wire
                .user_rules
                .iter()
                .chain(&wire.preset_rules)
                .any(|r| r.transport.is_some())
        {
            return Err(PolicyInputError::InvalidPolicy);
        }
        let rules = |rows: &[Rule]| {
            rows.iter().map(|r| {
                let mut value = json!({"id":r.id,"enabled":r.enabled,"action":r.action,
                    "conditions":{"domain":r.domain,"domain_suffix":r.domain_suffix,"ip_cidr":r.ip_cidr,"executable_paths":r.executable_paths}});
                if let Some(transport) = &r.transport {
                    value["conditions"]["transport"] = json!(transport);
                }
                if let Some(sources) = &r.platform_sources {
                    value["conditions"]["platform_sources"] = json!(sources);
                }
                value
            }).collect::<Vec<_>>()
        };
        let input = json!({"version":wire.version,"default_action":wire.default_action,
            "user_rules":rules(&wire.user_rules),"preset_rules":rules(&wire.preset_rules),
            "lan":wire.lan,"private_networks":wire.private_networks,"private_domains":wire.private_domains});
        let policy = read_policy(
            serde_json::to_vec(&input)
                .map_err(|_| PolicyInputError::InvalidJson)?
                .as_slice(),
        )?;
        if let Some(id) = policy.unsupported_transport() {
            return Err(PolicyInputError::UnsupportedTransport(id));
        }
        if let Some(id) = policy.unsupported_selector() {
            return Err(PolicyInputError::UnsupportedSelector(id));
        }
        crate::source_selectors::validate(&policy).map_err(|_| PolicyInputError::InvalidPolicy)?;
        Ok(Self { wire, policy })
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn requires_attribution(&self) -> bool {
        self.policy
            .user_rules
            .iter()
            .chain(&self.policy.preset_rules)
            .any(|rule| rule.enabled && !rule.conditions.executables.is_empty())
    }
}

/// Ограничивает контейнеры до десериализации, учитывая строки и escape.
pub fn bounded_depth(text: &str, max: usize) -> bool {
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for byte in text.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > max {
                        return false;
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    const EMPTY: &str = r#"{"version":1,"default_action":"proxy","user_rules":[],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}"#;
    #[test]
    fn closed_object_roundtrip() {
        let policy = SystemPolicy::parse(EMPTY).unwrap();
        assert!(!policy.requires_attribution());
        assert!(SystemPolicy::parse(&serde_json::to_string(&policy).unwrap()).is_ok());
        for text in [
            "[]".to_owned(),
            EMPTY.replace("\"version\":1", "\"version\":1,\"version\":1"),
            EMPTY.replace("\"version\":1", "\"version\":1,\"extra\":1"),
            EMPTY.replace("\"user_rules\":[]", "\"user_rules\":[[]]"),
        ] {
            assert!(SystemPolicy::parse(&text).is_err());
        }
    }
    #[test]
    fn active_rules_and_selectors() {
        let rule = r#"{"id":1,"enabled":true,"action":"block","domain":[],"domain_suffix":[],"ip_cidr":[],"executable_paths":["/usr/bin/client"]}"#;
        let text = EMPTY.replace("\"user_rules\":[]", &format!("\"user_rules\":[{rule}]"));
        assert!(SystemPolicy::parse(&text).unwrap().requires_attribution());
        assert!(
            !SystemPolicy::parse(&text.replace("true", "false"))
                .unwrap()
                .requires_attribution()
        );
        assert!(SystemPolicy::parse(&text.replace("/usr/bin/client", "/usr/../client")).is_err());
    }
}

#[cfg(test)]
mod p07_tests {
    use super::*;
    #[test]
    fn typed_v2_wire_and_activation_guard() {
        let text = r#"{"version":2,"default_action":"direct","user_rules":[{"id":41,"enabled":false,"action":"block","domain":[],"domain_suffix":[],"ip_cidr":[],"executable_paths":[],"platform_sources":[{"kind":"android_package","package":"org.example.app"}]}],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}"#;
        let policy = SystemPolicy::parse(text).unwrap();
        assert_eq!(serde_json::to_string(&policy).unwrap(), text);
        assert!(matches!(
            SystemPolicy::parse(&text.replace("false", "true")),
            Err(PolicyInputError::UnsupportedSelector(41))
        ));
        assert!(SystemPolicy::parse(&text.replace("\"version\":2", "\"version\":1")).is_err());
        assert!(SystemPolicy::parse(&text.replace("android_package", "future")).is_err());
    }
}
