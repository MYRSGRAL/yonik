//! Проверка селекторов процесса и компиляция в условия системного входа.
use crate::{Engine, PolicyCompileError};
use serde_json::{Value, json};
use yonik_domain::Policy;

pub(crate) fn validate(policy: &Policy) -> Result<(), PolicyCompileError> {
    validate_inner(policy, &|| Ok(()))
}
fn validate_inner(
    policy: &Policy,
    checkpoint: &dyn Fn() -> Result<(), PolicyCompileError>,
) -> Result<(), PolicyCompileError> {
    if let Some(id) = policy.unsupported_transport() {
        return Err(PolicyCompileError::UnsupportedTransport(id));
    }
    if let Some(id) = policy.unsupported_selector() {
        return Err(PolicyCompileError::UnsupportedSelector(id));
    }
    let mut bytes = 0usize;
    for rule in policy.user_rules.iter().chain(&policy.preset_rules) {
        checkpoint()?;
        if rule.conditions.executables.len() > 32 {
            return Err(PolicyCompileError::InvalidPolicy);
        }
        for path in &rule.conditions.executables {
            checkpoint()?;
            bytes = bytes.saturating_add(path.len());
            if bytes > 1_048_576 {
                return Err(PolicyCompileError::InvalidPolicy);
            }
            if yonik_domain::process_name_selector(path).is_some() {
                continue;
            }
            // Xray трактует завершающий slash как каталог и xray/ как special token.
            if path.len() > 4096
                || !path.starts_with('/')
                || path.ends_with('/')
                || path.chars().any(char::is_control)
                || path
                    .split('/')
                    .skip(1)
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err(PolicyCompileError::InvalidPolicy);
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_data(
    policy: &Policy,
    checkpoint: &crate::resource_bundle::Checkpoint<'_>,
) -> Result<(), crate::resource_bundle::BoundCompileError> {
    let result = validate_inner(policy, &|| {
        checkpoint
            .check()
            .map_err(|_| PolicyCompileError::InvalidPolicy)
    });
    checkpoint.check()?;
    result?;
    Ok(())
}

/// В data-only конфиге источник оборачивает в том числе logical OR назначения.
pub(crate) fn apply_data(engine: Engine, rule: &mut Value, selectors: &[String]) {
    if engine == Engine::Xray {
        apply(engine, rule, selectors);
    } else if !selectors.is_empty() {
        let source = sing_box_source(selectors);
        conjoin(rule, source);
    }
}

pub(crate) fn apply(engine: Engine, rule: &mut Value, selectors: &[String]) {
    if selectors.is_empty() {
        return;
    }
    match engine {
        Engine::Xray => {
            let values: Vec<_> = selectors
                .iter()
                .map(|selector| {
                    let Some(name) = yonik_domain::process_name_selector(selector) else {
                        return std::borrow::Cow::Borrowed(selector.as_str());
                    };
                    // Закреплённый Xray убирает один суффикс .exe из условия.
                    if name.ends_with(".exe") {
                        std::borrow::Cow::Owned(format!("{name}.exe"))
                    } else {
                        std::borrow::Cow::Borrowed(name)
                    }
                })
                .collect();
            rule["process"] = json!(values);
            rule["inboundTag"] = json!(["system-tun"]);
        }
        Engine::SingBox => {
            if selectors.iter().all(|value| value.starts_with('/')) {
                rule["process_path"] = json!(selectors);
                rule["inbound"] = json!(["system-tun"]);
            } else {
                conjoin(rule, sing_box_source(selectors));
            }
        }
    }
}

fn sing_box_source(selectors: &[String]) -> Value {
    let paths: Vec<_> = selectors
        .iter()
        .filter(|value| value.starts_with('/'))
        .collect();
    let names: Vec<_> = selectors
        .iter()
        .filter_map(|value| yonik_domain::process_name_selector(value))
        .collect();
    match (paths.is_empty(), names.is_empty()) {
        (true, _) => json!({"process_name": names, "inbound": ["system-tun"]}),
        (_, true) => json!({"process_path": paths, "inbound": ["system-tun"]}),
        (false, false) => json!({"type":"logical", "mode":"or", "rules":[
            {"process_path": paths, "inbound":["system-tun"]},
            {"process_name": names, "inbound":["system-tun"]}
        ]}),
    }
}

fn conjoin(rule: &mut Value, source: Value) {
    let mut destination = rule.take();
    let action = destination.as_object_mut().and_then(|o| o.remove("action"));
    let outbound = destination
        .as_object_mut()
        .and_then(|o| o.remove("outbound"));
    *rule = if destination
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
    {
        source
    } else {
        json!({"type":"logical", "mode":"and", "rules":[source, destination]})
    };
    if let Some(action) = action {
        rule["action"] = action;
    }
    if let Some(outbound) = outbound {
        rule["outbound"] = outbound;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn имя_и_точный_путь_объединяются_альтернативой() {
        let selectors = [String::from("name:client.exe"), String::from("/opt/client")];
        let mut xray = json!({"type":"field","outboundTag":"direct"});
        apply(Engine::Xray, &mut xray, &selectors);
        assert_eq!(xray["process"], json!(["client.exe.exe", "/opt/client"]));
        let mut sing_box = json!({"action":"route","outbound":"direct","ip_cidr":["192.0.2.0/24"]});
        apply(Engine::SingBox, &mut sing_box, &selectors);
        assert_eq!(
            sing_box["rules"][0]["rules"][0]["process_path"],
            json!(["/opt/client"])
        );
        assert_eq!(
            sing_box["rules"][0]["rules"][1]["process_name"],
            json!(["client.exe"])
        );
        assert_eq!(sing_box["rules"][1]["ip_cidr"], json!(["192.0.2.0/24"]));
    }
}
