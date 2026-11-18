//! DTO редактора преобразуется в общую Policy; сетевых побочных эффектов нет.
use serde::{Deserialize, Serialize};
use yonik_domain::{Action, Conditions, DomainName, DomainPattern, Policy, Rule};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<yonik_engine::transport::TransportInput>,
    pub id: u64,
    pub enabled: bool,
    pub executables: Vec<String>,
    pub domains: Vec<String>,
    pub destinations: Vec<String>,
    pub action: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "yonik_engine::platform_source::deserialize_sources"
    )]
    pub platform_sources: Option<Vec<yonik_engine::platform_source::PlatformSourceInput>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetReference {
    pub snapshot: String,
    pub enabled: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    pub version: u8,
    pub rules: Vec<RuleInput>,
    pub default_action: String,
    #[serde(default)]
    pub ru_direct: Option<PresetReference>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub local_vpn_direct: bool,
}
impl Default for Draft {
    fn default() -> Self {
        Self {
            version: 1,
            rules: vec![],
            default_action: "proxy".into(),
            ru_direct: None,
            local_vpn_direct: false,
        }
    }
}
fn action(value: &str) -> Result<Action, &'static str> {
    match value {
        "proxy" => Ok(Action::Proxy),
        "direct" => Ok(Action::Direct),
        "block" => Ok(Action::Block),
        _ => Err("action"),
    }
}
impl Draft {
    /// Ограниченный отчёт без исходных селекторов и персональных данных.
    pub fn diagnostics(&self) -> serde_json::Value {
        if let Ok(policy) = self.policy() {
            if let Some(id) = policy.unsupported_selector() {
                return serde_json::json!({"incomplete":true,"warnings":[],"error":"unsupported_selector","rule_id":id});
            }
        }
        if self.rules.iter().any(|rule| {
            rule.enabled
                && rule
                    .executables
                    .iter()
                    .any(|value| yonik_domain::process_name_selector(value).is_some())
        }) {
            return serde_json::json!({"incomplete":true,"warnings":[]});
        }
        use yonik_domain::policy_diagnostics::{Limits, WarningKind, diagnose};
        match self
            .base_policy()
            .ok()
            .and_then(|p| diagnose(&p, Limits::default()).ok())
        {
            Some(report) => {
                serde_json::json!({"incomplete": report.truncated || self.local_vpn_direct || self.ru_direct.as_ref().is_some_and(|r| r.enabled),
                "warnings": report.warnings.iter().map(|w| serde_json::json!({
                    "rule_id": w.rule_id, "earlier": format!("{:?}", w.earlier),
                    "kind": match w.kind { WarningKind::Shadowed => "shadowed", WarningKind::PotentialOverlap => "potential_overlap" }
                })).collect::<Vec<_>>()})
            }
            None => {
                serde_json::json!({"incomplete": true, "warnings": [], "error": "diagnostics_input"})
            }
        }
    }
    /// Синтетический ввод, не наблюдение потока. DNS и приложение не выдумываются.
    pub fn explain(&self, target: &str) -> Result<serde_json::Value, &'static str> {
        self.explain_with_policy(target, self.policy()?)
    }
    pub fn explain_with_policy(
        &self,
        target: &str,
        policy: Policy,
    ) -> Result<serde_json::Value, &'static str> {
        use yonik_domain::{
            Destination, DestinationFlow, Evaluation, EvaluationContext, Resolution,
        };
        if target.len() > 253 {
            return Err("limit");
        }
        if let Some(id) = policy.unsupported_selector() {
            return Ok(
                serde_json::json!({"status":"unsupported", "reason":"unsupported_selector", "rule_id":id}),
            );
        }
        if policy
            .user_rules
            .iter()
            .any(|r| r.enabled && !r.conditions.executables.is_empty())
        {
            return Ok(
                serde_json::json!({"status":"unknown", "reason":"application_witness_missing"}),
            );
        }
        if self.local_vpn_direct {
            return Ok(serde_json::json!({"status":"unknown", "reason":"vpn_topology_required"}));
        }
        let name;
        let destination = match target.parse() {
            Ok(address) => Destination::Ip {
                address,
                name: None,
            },
            Err(_) => {
                name = target.parse::<DomainName>().map_err(|_| "domain")?;
                Destination::Name {
                    name: &name,
                    resolution: Resolution::Missing,
                }
            }
        };
        Ok(
            match policy.evaluate_destination(
                &DestinationFlow {
                    executable: None,
                    destination,
                },
                &EvaluationContext::default(),
            ) {
                Evaluation::Decided { .. } if target.parse::<std::net::IpAddr>().is_err() => {
                    serde_json::json!({"status":"unknown", "reason":"dns_witness_missing"})
                }
                Evaluation::Decided { decision, .. } => {
                    serde_json::json!({"status":"fixture", "action":format!("{:?}", decision.action), "origin":format!("{:?}", decision.origin)})
                }
                Evaluation::NeedResolution(_) => {
                    serde_json::json!({"status":"unknown", "reason":"dns_missing"})
                }
                Evaluation::Rejected(_) => {
                    serde_json::json!({"status":"unknown", "reason":"evaluation_rejected"})
                }
            },
        )
    }
    /// Граница активации: storage validation не запрещает сохранение V2.
    pub fn system_policy(
        &self,
    ) -> Result<yonik_engine::policy_wire::SystemPolicy, yonik_engine::policy_input::PolicyInputError>
    {
        use yonik_engine::policy_input::PolicyInputError;
        if self.local_vpn_direct {
            return Err(PolicyInputError::InvalidPolicy);
        }
        let policy = self.policy().map_err(|_| PolicyInputError::InvalidPolicy)?;
        if let Some(id) = policy.unsupported_selector() {
            return Err(PolicyInputError::UnsupportedSelector(id));
        }
        let rules = self.rules.iter().zip(&policy.user_rules).map(|(r, typed)| {
            let (suffixes, exact): (Vec<_>, Vec<_>) = r.domains.iter().partition(|s| s.starts_with("*."));
            let mut row = serde_json::json!({"id":r.id,"enabled":r.enabled,"action":r.action,
                "domain":exact,"domain_suffix":suffixes.iter().map(|s| &s[2..]).collect::<Vec<_>>(),
                "ip_cidr":typed.conditions.destinations.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "executable_paths":r.executables});
            if let Some(transport) = &r.transport { row["transport"] = serde_json::json!(transport); }
            if let Some(sources) = &r.platform_sources { row["platform_sources"] = serde_json::json!(sources); }
            row
        }).collect::<Vec<_>>();
        yonik_engine::policy_wire::SystemPolicy::parse(&serde_json::json!({"version":self.version,
            "default_action":self.default_action,"user_rules":rules,"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}).to_string())
    }
    pub fn json(&self) -> String {
        serde_json::to_string(self).expect("DTO без fallible полей")
    }
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.len() > 262144 {
            return Err("limit");
        }
        let draft: Self = serde_json::from_str(raw).map_err(|_| "format")?;
        draft.base_policy()?;
        Ok(draft)
    }
    /// Enabled reference требует trusted resolver; пропуск preset запрещён.
    pub fn policy(&self) -> Result<Policy, &'static str> {
        if self
            .ru_direct
            .as_ref()
            .is_some_and(|reference| reference.enabled)
        {
            return Err("routing_storage");
        }
        self.base_policy()
    }
    pub fn base_policy(&self) -> Result<Policy, &'static str> {
        if self.ru_direct.as_ref().is_some_and(|reference| {
            reference.snapshot.len() != 64
                || !reference.snapshot.bytes().all(|b| b.is_ascii_hexdigit())
        }) {
            return Err("invalid_input");
        }
        if ![1, 2, 3].contains(&self.version) || self.rules.len() > 256 {
            return Err("limit");
        }
        let bytes: usize = self
            .rules
            .iter()
            .flat_map(|r| {
                r.executables
                    .iter()
                    .chain(&r.domains)
                    .chain(&r.destinations)
            })
            .map(String::len)
            .sum();
        let bytes = bytes
            + self
                .rules
                .iter()
                .flat_map(|r| r.platform_sources.iter().flatten())
                .map(|s| s.bytes())
                .sum::<usize>();
        if bytes > 200_000 {
            return Err("limit");
        }
        if self
            .rules
            .iter()
            .filter_map(|r| r.transport.as_ref())
            .filter_map(|t| t.destination_ports.as_ref())
            .map(Vec::len)
            .sum::<usize>()
            > 4096
        {
            return Err("limit");
        }
        let mut ids = std::collections::HashSet::new();
        let mut rules = Vec::with_capacity(self.rules.len());
        for input in &self.rules {
            if self.version < 3 && input.transport.is_some() {
                return Err("format");
            }
            if (self.version >= 2) != input.platform_sources.is_some() {
                return Err("format");
            }
            let sources = input.platform_sources.as_deref().unwrap_or_default();
            if sources.len() > 16 {
                return Err("limit");
            }
            let platform_sources = sources
                .iter()
                .map(|s| s.typed())
                .collect::<Result<Vec<_>, _>>()?;
            if platform_sources
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != platform_sources.len()
            {
                return Err("duplicate_parameter");
            }

            if input.id == 0 || input.id > 9_007_199_254_740_991 || !ids.insert(input.id) {
                return Err("id");
            }
            if [&input.executables, &input.domains, &input.destinations]
                .iter()
                .any(|v| v.len() > 64 || v.iter().any(|s| s.len() > 4096))
            {
                return Err("limit");
            }
            if input.executables.iter().any(|s| {
                yonik_domain::process_name_selector(s).is_none()
                    && (!s.starts_with('/')
                        || s.contains(['\0', '\n'])
                        || s.split('/').any(|c| c == ".." || c == "."))
            }) {
                return Err("executable");
            }
            let domains = input
                .domains
                .iter()
                .map(|s| {
                    let (suffix, name) = s
                        .strip_prefix("*.")
                        .map_or((false, s.as_str()), |s| (true, s));
                    let name: DomainName = name.parse().map_err(|_| "domain")?;
                    Ok(if suffix {
                        DomainPattern::Suffix(name)
                    } else {
                        DomainPattern::Exact(name)
                    })
                })
                .collect::<Result<Vec<_>, &'static str>>()?;
            let destinations = input
                .destinations
                .iter()
                .map(|s| {
                    let value = match s.parse::<std::net::IpAddr>() {
                        Ok(ip) => format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }),
                        Err(_) => s.clone(),
                    };
                    value.parse().map_err(|_| "cidr")
                })
                .collect::<Result<Vec<_>, _>>()?;
            rules.push(Rule {
                id: input.id,
                enabled: input.enabled,
                action: action(&input.action)?,
                conditions: Conditions {
                    transport: input
                        .transport
                        .as_ref()
                        .map(|v| v.typed())
                        .transpose()?
                        .unwrap_or_default(),
                    platform_sources,
                    executables: input.executables.clone(),
                    domains,
                    destinations,
                },
            });
        }
        if self.json().len() > 262144 {
            return Err("limit");
        }
        Ok(Policy {
            user_rules: rules,
            default_action: action(&self.default_action)?,
            ..Policy::default()
        })
    }
    pub fn put(&mut self, input: RuleInput, confirm_broad: bool) -> Result<(), &'static str> {
        let mut candidate = self.clone();
        if input.transport.is_some() {
            candidate.version = 3;
            for rule in &mut candidate.rules {
                if rule.platform_sources.is_none() {
                    rule.platform_sources = Some(vec![]);
                }
            }
        }
        if input
            .platform_sources
            .as_ref()
            .is_some_and(|s| !s.is_empty())
            && candidate.version == 1
        {
            candidate.version = 2;
            for rule in &mut candidate.rules {
                rule.platform_sources = Some(vec![]);
            }
        }
        let mut input = input;
        if input.transport.is_none() {
            input.transport = candidate
                .rules
                .iter()
                .find(|r| r.id == input.id)
                .and_then(|r| r.transport.clone());
        }

        if candidate.version == 1 && input.platform_sources.as_ref().is_some_and(Vec::is_empty) {
            input.platform_sources = None;
        }
        if candidate.version >= 2 && input.platform_sources.is_none() {
            input.platform_sources = Some(
                candidate
                    .rules
                    .iter()
                    .find(|r| r.id == input.id)
                    .and_then(|r| r.platform_sources.clone())
                    .unwrap_or_default(),
            );
        }

        if input.executables.is_empty()
            && input.domains.is_empty()
            && input.destinations.is_empty()
            && input.platform_sources.as_ref().is_none_or(Vec::is_empty)
            && !input
                .transport
                .as_ref()
                .is_some_and(|t| t.typed().is_ok_and(|t| t.constrained()))
            && !confirm_broad
        {
            return Err("broad");
        }
        if let Some(rule) = candidate.rules.iter_mut().find(|r| r.id == input.id) {
            *rule = input;
        } else {
            candidate.rules.push(input);
        }
        candidate.base_policy()?;
        *self = candidate;
        Ok(())
    }
}

/// Только запрос пользователя; PID остаётся диагностикой и не входит в RuleInput.
#[cfg(target_os = "linux")]
pub fn catalog(
    processes: bool,
    query: &str,
    offset: usize,
    #[cfg(feature = "test-support")] observer: Option<yonik_linux::applications::CatalogObserver>,
) -> Result<serde_json::Value, &'static str> {
    use yonik_linux::applications::{Catalog, Limits};
    if query.len() > 256 || offset > 4096 {
        return Err("limit");
    }
    let mut roots = vec![
        std::path::PathBuf::from("/usr/local/share/applications"),
        std::path::PathBuf::from("/usr/share/applications"),
    ];
    if let Some(home) = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        roots.insert(0, home.join("applications"));
    } else if let Some(home) = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        roots.insert(0, home.join(".local/share/applications"));
    }
    let catalog = Catalog::new(roots, "/proc".into(), "ru".into(), Limits::default())
        .map_err(|_| "catalog")?;
    #[cfg(feature = "test-support")]
    let catalog = catalog.with_observer(observer);
    let (items, incomplete) = if processes {
        let snapshot = catalog.process_snapshot().map_err(|_| "catalog")?;
        (snapshot.items.into_iter().map(|p| serde_json::json!({"name":p.name,"pid":p.pid,"executable":p.exe.and_then(|p| p.to_str().map(str::to_owned)), "unsupported":""})).collect::<Vec<_>>(), snapshot.incomplete)
    } else {
        let snapshot = catalog.desktop_snapshot().map_err(|_| "catalog")?;
        (
            snapshot
                .items
                .into_iter()
                .map(|p| {
                    let (path, unsupported) = match p.executable {
                        Ok(path) => (path.to_str().map(str::to_owned), String::new()),
                        Err(reason) => (None, format!("{reason:?}")),
                    };
                    serde_json::json!({"name":p.name,"executable":path,"unsupported":unsupported})
                })
                .collect::<Vec<_>>(),
            snapshot.incomplete,
        )
    };
    let query = query.to_lowercase();
    let filtered: Vec<_> = items
        .into_iter()
        .filter(|p| {
            p["name"]
                .as_str()
                .is_some_and(|name| name.to_lowercase().contains(&query))
        })
        .collect();
    Ok(
        serde_json::json!({"total":filtered.len(),"offset":offset,"incomplete":incomplete,"items":filtered.into_iter().skip(offset).take(32).collect::<Vec<_>>()}),
    )
}

#[cfg(test)]
mod preset_reference_tests {
    #[test]
    fn preset_reference_roundtrips_separately_from_user_rules() {
        let json = format!(
            r#"{{"version":1,"rules":[],"default_action":"proxy","ru_direct":{{"snapshot":"{}","enabled":true}}}}"#,
            "a".repeat(64)
        );
        let draft = super::Draft::parse(&json).expect("отдельная preset reference");
        assert!(draft.rules.is_empty());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&draft.json()).expect("json")["ru_direct"]["snapshot"],
            "a".repeat(64)
        );
    }
}
