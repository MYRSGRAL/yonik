//! Ограниченное чтение переносимой политики без раскрытия содержимого в ошибках.

use std::{collections::HashSet, fmt, io::Read};

use serde::Deserialize;
use yonik_domain::{
    Action, Cidr, Conditions, DomainName, DomainPattern, Policy, PrivateDomain, PrivateNetwork,
    Rule, VpnId,
};

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_RULES: usize = 10_000;
const MAX_SELECTORS: usize = 100_000;
const MAX_EXECUTABLE_BYTES: usize = 4096;

/// Ошибки намеренно не содержат исходный JSON и ошибки нижележащего reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyInputError {
    UnsupportedSelector(u64),
    UnsupportedTransport(u64),
    Io,
    TooLarge,
    InvalidJson,
    InvalidPolicy,
    Limit,
}

impl fmt::Display for PolicyInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedTransport(_) => "Транспортные условия не поддержаны адаптером",
            Self::UnsupportedSelector(_) => "Неприменимый платформенный селектор",
            Self::Io => "Не удалось прочитать политику",
            Self::TooLarge => "Превышен размер входной политики",
            Self::InvalidJson => "Некорректная структура JSON политики",
            Self::InvalidPolicy => "Некорректные значения политики",
            Self::Limit => "Превышен лимит правил или селекторов политики",
        })
    }
}

impl std::error::Error for PolicyInputError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputPolicy {
    version: u64,
    #[serde(default)]
    default_action: InputAction,
    #[serde(default)]
    user_rules: Vec<InputRule>,
    #[serde(default)]
    preset_rules: Vec<InputRule>,
    #[serde(default)]
    lan: Vec<String>,
    #[serde(default)]
    private_networks: Vec<InputNetwork>,
    #[serde(default)]
    private_domains: Vec<InputDomain>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum InputAction {
    #[default]
    Proxy,
    Direct,
    Block,
}

impl From<InputAction> for Action {
    fn from(value: InputAction) -> Self {
        match value {
            InputAction::Proxy => Self::Proxy,
            InputAction::Direct => Self::Direct,
            InputAction::Block => Self::Block,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputRule {
    id: u64,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    action: InputAction,
    #[serde(default)]
    conditions: InputConditions,
}

fn enabled_by_default() -> bool {
    true
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct InputConditions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<crate::transport::TransportInput>,
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    domain_suffix: Vec<String>,
    #[serde(default)]
    ip_cidr: Vec<String>,
    #[serde(default)]
    executable_paths: Vec<String>,
    #[serde(
        default,
        deserialize_with = "crate::platform_source::deserialize_sources"
    )]
    platform_sources: Option<Vec<crate::platform_source::PlatformSourceInput>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputNetwork {
    cidr: String,
    vpn: u64,
    available: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputDomain {
    suffix: String,
    vpn: u64,
    available: bool,
}

/// Читает не более 2 МиБ + один байт для определения превышения размера.
pub fn read_policy(reader: impl Read) -> Result<Policy, PolicyInputError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PolicyInputError::Io)?;
    if bytes.len() > MAX_BYTES {
        return Err(PolicyInputError::TooLarge);
    }
    let input: InputPolicy =
        serde_json::from_slice(&bytes).map_err(|_| PolicyInputError::InvalidJson)?;
    if ![1, 2, 3].contains(&input.version) {
        return Err(PolicyInputError::InvalidPolicy);
    }
    for rule in input.user_rules.iter().chain(&input.preset_rules) {
        if input.version < 3 && rule.conditions.transport.is_some() {
            return Err(PolicyInputError::InvalidPolicy);
        }
        if (input.version >= 2) != rule.conditions.platform_sources.is_some() {
            return Err(PolicyInputError::InvalidPolicy);
        }
    }
    if input.version >= 2 && bytes.len() > 262144 {
        return Err(PolicyInputError::TooLarge);
    }
    if input
        .user_rules
        .iter()
        .chain(&input.preset_rules)
        .filter_map(|r| r.conditions.transport.as_ref())
        .filter_map(|t| t.destination_ports.as_ref())
        .map(Vec::len)
        .sum::<usize>()
        > 4096
    {
        return Err(PolicyInputError::Limit);
    }
    check_limits(&input)?;
    Ok(Policy {
        default_action: input.default_action.into(),
        user_rules: convert_rules(input.user_rules)?,
        preset_rules: convert_rules(input.preset_rules)?,
        lan: input
            .lan
            .iter()
            .map(|value| parse_cidr(value))
            .collect::<Result<_, _>>()?,
        private_networks: input
            .private_networks
            .into_iter()
            .map(|value| {
                Ok(PrivateNetwork {
                    network: parse_cidr(&value.cidr)?,
                    vpn: parse_vpn(value.vpn)?,
                    available: value.available,
                })
            })
            .collect::<Result<_, PolicyInputError>>()?,
        private_domains: input
            .private_domains
            .into_iter()
            .map(|value| {
                Ok(PrivateDomain {
                    domain: DomainPattern::Suffix(parse_domain(&value.suffix)?),
                    vpn: parse_vpn(value.vpn)?,
                    available: value.available,
                })
            })
            .collect::<Result<_, PolicyInputError>>()?,
    })
}

fn check_limits(input: &InputPolicy) -> Result<(), PolicyInputError> {
    if input.user_rules.len() + input.preset_rules.len() > MAX_RULES {
        return Err(PolicyInputError::Limit);
    }
    if input.version >= 2 {
        let rules: Vec<_> = input.user_rules.iter().chain(&input.preset_rules).collect();
        if rules.len() > 256 {
            return Err(PolicyInputError::Limit);
        }
        let sources: Vec<_> = rules
            .iter()
            .flat_map(|r| r.conditions.platform_sources.iter().flatten())
            .collect();
        let bytes = sources.iter().map(|s| s.bytes()).sum::<usize>()
            + rules
                .iter()
                .map(|r| {
                    let c = &r.conditions;
                    c.domain
                        .iter()
                        .chain(&c.domain_suffix)
                        .chain(&c.ip_cidr)
                        .chain(&c.executable_paths)
                        .map(String::len)
                        .sum::<usize>()
                })
                .sum::<usize>();
        if sources.len() > 4096 || bytes > 200000 {
            return Err(PolicyInputError::Limit);
        }
    }
    let mut selectors =
        input.lan.len() + input.private_networks.len() + input.private_domains.len();
    for rule in input.user_rules.iter().chain(&input.preset_rules) {
        let conditions = &rule.conditions;
        selectors += conditions.domain.len()
            + conditions.domain_suffix.len()
            + conditions.ip_cidr.len()
            + conditions.executable_paths.len();
        if selectors > MAX_SELECTORS {
            return Err(PolicyInputError::Limit);
        }
    }
    if selectors > MAX_SELECTORS {
        return Err(PolicyInputError::Limit);
    }
    Ok(())
}

fn convert_rules(input: Vec<InputRule>) -> Result<Vec<Rule>, PolicyInputError> {
    let mut ids = HashSet::with_capacity(input.len());
    input
        .into_iter()
        .map(|rule| {
            if !ids.insert(rule.id) {
                return Err(PolicyInputError::InvalidPolicy);
            }
            let conditions = rule.conditions;
            let sources = conditions.platform_sources.as_deref().unwrap_or_default();
            if sources.len() > 16 {
                return Err(PolicyInputError::Limit);
            }
            let platform_sources = sources
                .iter()
                .map(|s| s.typed().map_err(|_| PolicyInputError::InvalidPolicy))
                .collect::<Result<Vec<_>, _>>()?;
            if platform_sources.iter().collect::<HashSet<_>>().len() != platform_sources.len() {
                return Err(PolicyInputError::InvalidPolicy);
            }

            if conditions.executable_paths.iter().any(|path| {
                yonik_domain::process_name_selector(path).is_none()
                    && (!path.starts_with('/')
                        || path.len() > MAX_EXECUTABLE_BYTES
                        || path.chars().any(char::is_control))
            }) {
                return Err(PolicyInputError::InvalidPolicy);
            }
            let domains = conditions
                .domain
                .iter()
                .map(|value| parse_domain(value).map(DomainPattern::Exact))
                .chain(
                    conditions
                        .domain_suffix
                        .iter()
                        .map(|value| parse_domain(value).map(DomainPattern::Suffix)),
                )
                .collect::<Result<_, _>>()?;
            Ok(Rule {
                id: rule.id,
                enabled: rule.enabled,
                action: rule.action.into(),
                conditions: Conditions {
                    transport: conditions
                        .transport
                        .as_ref()
                        .map(|v| v.typed())
                        .transpose()
                        .map_err(|_| PolicyInputError::InvalidPolicy)?
                        .unwrap_or_default(),
                    platform_sources,
                    executables: conditions.executable_paths,
                    destinations: conditions
                        .ip_cidr
                        .iter()
                        .map(|value| parse_cidr(value))
                        .collect::<Result<_, _>>()?,
                    domains,
                },
            })
        })
        .collect()
}

fn parse_cidr(value: &str) -> Result<Cidr, PolicyInputError> {
    value.parse().map_err(|_| PolicyInputError::InvalidPolicy)
}

fn parse_domain(value: &str) -> Result<DomainName, PolicyInputError> {
    value.parse().map_err(|_| PolicyInputError::InvalidPolicy)
}

fn parse_vpn(value: u64) -> Result<VpnId, PolicyInputError> {
    VpnId::new(value).ok_or(PolicyInputError::InvalidPolicy)
}
