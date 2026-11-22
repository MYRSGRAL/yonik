use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportInput {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub transport_protocols: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub destination_ports: Option<Vec<(u16, u16)>>,
}
impl TransportInput {
    pub fn typed(&self) -> Result<yonik_domain::TransportConditions, &'static str> {
        let protocols = self
            .transport_protocols
            .as_ref()
            .map(|v| v.iter().map(String::as_str).collect::<Vec<_>>());
        let ports = self
            .destination_ports
            .as_ref()
            .map(|v| yonik_domain::DestinationPorts::parse(v))
            .transpose()?;
        yonik_domain::TransportConditions::parse(protocols.as_deref(), ports)
    }
    pub fn from_typed(value: &yonik_domain::TransportConditions) -> Self {
        Self {
            transport_protocols: value.protocols().map(<[String]>::to_vec),
            destination_ports: value.ports().map(|p| p.ranges().to_vec()),
        }
    }
}

fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use super::TransportInput;
    #[test]
    fn null_empty_unknown_are_not_any() {
        for raw in [
            r#"{"transport_protocols":null}"#,
            r#"{"destination_ports":null}"#,
            r#"{"future":true}"#,
        ] {
            assert!(serde_json::from_str::<TransportInput>(raw).is_err());
        }
        for raw in [
            r#"{"transport_protocols":[]}"#,
            r#"{"destination_ports":[]}"#,
            r#"{"destination_ports":[[0,1]]}"#,
        ] {
            assert!(
                serde_json::from_str::<TransportInput>(raw)
                    .unwrap()
                    .typed()
                    .is_err()
            );
        }
    }
}

/// Только LocalSocks: transport — conjunct всей destination-группы, включая OR ресурсов.
pub(crate) fn apply_local(
    engine: crate::Engine,
    rule: &mut serde_json::Value,
    transport: &yonik_domain::TransportConditions,
) {
    use serde_json::json;
    if !transport.constrained() {
        return;
    }
    if engine == crate::Engine::Xray {
        if let Some(protocols) = transport.protocols() {
            rule["network"] = json!(protocols.join(","));
        }
        if let Some(ports) = transport.ports() {
            rule["port"] = json!(
                ports
                    .ranges()
                    .iter()
                    .map(|&(first, last)| {
                        if first == last {
                            first.to_string()
                        } else {
                            format!("{first}-{last}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        return;
    }
    let mut predicate = json!({});
    if let Some(protocols) = transport.protocols() {
        predicate["network"] = json!(protocols);
    }
    if let Some(ports) = transport.ports() {
        let mut singles = Vec::new();
        let mut ranges = Vec::new();
        for &(first, last) in ports.ranges() {
            if first == last {
                singles.push(first);
            } else {
                ranges.push(format!("{first}:{last}"));
            }
        }
        if !singles.is_empty() {
            predicate["port"] = json!(singles);
        }
        if !ranges.is_empty() {
            predicate["port_range"] = json!(ranges);
        }
    }
    let mut destination = rule.take();
    let action = destination.as_object_mut().and_then(|o| o.remove("action"));
    let outbound = destination
        .as_object_mut()
        .and_then(|o| o.remove("outbound"));
    *rule = if destination.as_object().is_some_and(|o| o.is_empty()) {
        predicate
    } else {
        json!({"type":"logical", "mode":"and", "rules":[destination, predicate]})
    };
    if let Some(action) = action {
        rule["action"] = action;
    }
    if let Some(outbound) = outbound {
        rule["outbound"] = outbound;
    }
}

#[cfg(test)]
mod lowering_tests {
    use super::apply_local;
    use serde_json::json;
    #[test]
    fn transport_only_не_создаёт_пустой_destination() {
        let transport = yonik_domain::TransportConditions::parse(Some(&["udp"]), None).unwrap();
        for (action, outbound) in [
            ("route", Some("direct")),
            ("route", Some("proxy")),
            ("reject", None),
        ] {
            let mut rule = json!({"action":action});
            if let Some(outbound) = outbound {
                rule["outbound"] = json!(outbound);
            }
            apply_local(crate::Engine::SingBox, &mut rule, &transport);
            assert_eq!(rule["network"], json!(["udp"]));
            assert_eq!(rule["action"], action);
            assert_eq!(rule.get("outbound"), outbound.map(|o| json!(o)).as_ref());
            assert!(rule.get("rules").is_none());
        }
    }
    #[test]
    fn transport_охватывает_resource_or_и_сохраняет_inbound_action() {
        let destination = json!({"type":"logical","mode":"and","inbound":["local"],
            "rules":[{"type":"logical","mode":"or","rules":[{"domain":["example.org"]},{"rule_set":["domains"]}]},
                     {"type":"logical","mode":"or","rules":[{"ip_cidr":["192.0.2.0/24"]},{"rule_set":["cidrs"]}]}]});
        for (action, outbound) in [
            ("route", Some("direct")),
            ("route", Some("proxy")),
            ("reject", None),
        ] {
            let mut rule = destination.clone();
            rule["action"] = json!(action);
            if let Some(outbound) = outbound {
                rule["outbound"] = json!(outbound);
            }
            let transport = yonik_domain::TransportConditions::parse(Some(&["udp"]), None).unwrap();
            apply_local(crate::Engine::SingBox, &mut rule, &transport);
            assert_eq!(rule["rules"][0], destination);
            assert_eq!(rule["rules"][1], json!({"network":["udp"]}));
            assert_eq!(rule["action"], action);
            assert_eq!(rule.get("outbound"), outbound.map(|o| json!(o)).as_ref());
        }
    }
}
