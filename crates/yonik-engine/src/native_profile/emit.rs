use super::{OwnedIngress, OwnedRuntimePlan, ProfileCompileError as Error, ValidatedGraph};
use crate::{CompiledConfig, Engine, ProbeAccess, ProbeCredentials};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

pub(super) fn emit(
    graph: ValidatedGraph,
    runtime: &OwnedRuntimePlan,
    system: bool,
) -> Result<(CompiledConfig, ValidatedGraph), Error> {
    if system != runtime.tun.is_some() {
        return Err(Error::Ownership);
    }
    for endpoint in graph.egress.physical() {
        if (endpoint.host().eq_ignore_ascii_case("localhost")
            || endpoint
                .host()
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()))
            && [runtime.port.get(), runtime.probe_port.get()].contains(&endpoint.port())
        {
            return Err(Error::Ownership);
        }
    }
    let mut mappings = HashMap::new();
    let mut occupied = HashSet::new();
    for i in graph.value["inbounds"].as_array().into_iter().flatten() {
        let tag = i["tag"].as_str().ok_or(Error::Ownership)?;
        let target = runtime.ingress.get(tag).ok_or(Error::Ownership)?;
        if !occupied.insert(*target as u8) || (*target == OwnedIngress::System && !system) {
            return Err(Error::Ownership);
        }
        mappings.insert(
            tag.to_owned(),
            match target {
                OwnedIngress::Local => "yonik-owned-local",
                OwnedIngress::System => "system-tun",
            },
        );
    }
    if mappings.len() != runtime.ingress.len() {
        return Err(Error::Ownership);
    }
    // DNS tags являются внутренними ingress subjects и не заменяются listener.
    let mut dns_tags = HashSet::new();
    if let Some(t) = graph.value["dns"]["tag"].as_str() {
        dns_tags.insert(t.to_owned());
    }
    for s in graph.value["dns"]["servers"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(t) = s["tag"].as_str() {
            dns_tags.insert(t.to_owned());
        }
    }
    if dns_tags.iter().any(|tag| {
        tag.starts_with("yonik-owned-") || tag == "system-tun" || mappings.contains_key(tag)
    }) {
        return Err(Error::Ownership);
    }
    let mut value = graph.value.clone();
    if let Some(rules) = value
        .get_mut("routing")
        .and_then(|r| r.get_mut("rules"))
        .and_then(Value::as_array_mut)
    {
        for rule in rules {
            for key in ["domain", "ip"] {
                if let Some(list) = rule.get_mut(key) {
                    bind_resources(list, runtime)?;
                }
            }
        }
    }
    if let Some(servers) = value
        .get_mut("dns")
        .and_then(|d| d.get_mut("servers"))
        .and_then(Value::as_array_mut)
    {
        for server in servers {
            if let Some(list) = server.get_mut("domains") {
                bind_resources(list, runtime)?;
            }
        }
    }
    if let Some(rules) = value
        .get_mut("routing")
        .and_then(|r| r.get_mut("rules"))
        .and_then(Value::as_array_mut)
    {
        for r in rules {
            if let Some(tags) = r.get_mut("inboundTag").and_then(Value::as_array_mut) {
                for t in tags {
                    let tag = t.as_str().ok_or(Error::Reference)?;
                    if let Some(mapped) = mappings.get(tag) {
                        *t = json!(mapped);
                    } else if !dns_tags.contains(tag) {
                        return Err(Error::Ownership);
                    }
                }
            }
        }
    }
    let auth = ProbeCredentials::random().map_err(|_| Error::Probe)?;
    value["log"] = json!({"loglevel":"none"});
    value["inbounds"] = json!([
        {"tag":"yonik-owned-local","listen":"127.0.0.1","port":runtime.port.get(),"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}},
        {"tag":"yonik-owned-probe","listen":"127.0.0.1","port":runtime.probe_port.get(),"protocol":"socks","settings":{"auth":"password","accounts":[{"user":auth.username(),"pass":auth.password()}]}}
    ]);
    // Без override probe проходит ровно тот же ordered routing/default, что
    // пользовательский Local ingress. Это сохраняет Auto вместо fixed proxy.
    if let Some(rules) = value
        .get_mut("routing")
        .and_then(|r| r.get_mut("rules"))
        .and_then(Value::as_array_mut)
    {
        for r in rules {
            if let Some(tags) = r.get_mut("inboundTag").and_then(Value::as_array_mut) {
                if tags.iter().any(|t| {
                    t == if system {
                        "system-tun"
                    } else {
                        "yonik-owned-local"
                    }
                }) {
                    tags.push(json!("yonik-owned-probe"));
                }
            }
        }
    }
    let mut config = CompiledConfig {
        value,
        engine: Engine::Xray,
        port: runtime.port,
        probe_port: runtime.probe_port,
        probe_access: ProbeAccess::native(auth),
    };
    if system {
        config = crate::system_tun::attach(config, runtime.tun.as_ref().ok_or(Error::Ownership)?)
            .map_err(|_| Error::Ownership)?;
    }
    // TUN attach вводит новый tag: provider selectors не должны получить новый
    // outbound, поэтому outbounds сохраняют исходный порядок и имена.
    for inbound in graph.value["inbounds"].as_array().into_iter().flatten() {
        if let Some(sniffing) = inbound.get("sniffing") {
            let mapped = mappings
                .get(inbound["tag"].as_str().ok_or(Error::Ownership)?)
                .ok_or(Error::Ownership)?;
            for own in config.value["inbounds"]
                .as_array_mut()
                .ok_or(Error::Ownership)?
            {
                if own["tag"] == *mapped
                    || (*mapped
                        == if system {
                            "system-tun"
                        } else {
                            "yonik-owned-local"
                        }
                        && own["tag"] == "yonik-owned-probe")
                {
                    own["sniffing"] = sniffing.clone();
                }
            }
        }
    }
    Ok((config, graph))
}
fn bind_resources(value: &mut Value, runtime: &OwnedRuntimePlan) -> Result<(), Error> {
    match value {
        Value::String(s) => {
            if let Some(requirement) = super::validate::resource(s)? {
                let (_, reference) = runtime
                    .resources
                    .iter()
                    .find(|(r, _)| r == &requirement)
                    .ok_or(Error::ResourceRequired)?;
                *s = format!("ext:{}.dat:{}", reference.tag(), requirement.category());
            }
        }
        Value::Array(a) => {
            for v in a {
                bind_resources(v, runtime)?;
            }
        }
        Value::Object(o) => {
            for v in o.values_mut() {
                bind_resources(v, runtime)?;
            }
        }
        _ => (),
    }
    Ok(())
}
