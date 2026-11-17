use crate::{Cidr, DomainPattern, VpnId};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    Direct,
    #[default]
    Proxy,
    Block,
}

/// Результат содержит VPN только после проверки приватной сети.
/// Пользовательские правила ограничены Direct/Proxy/Block.
/// ```compile_fail
/// use yonik_domain::Action;
/// let invalid = Action::PrivateVpn;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Direct,
    Proxy,
    Block,
    PrivateVpn,
}

impl From<Action> for Route {
    fn from(action: Action) -> Self {
        match action {
            Action::Direct => Self::Direct,
            Action::Proxy => Self::Proxy,
            Action::Block => Self::Block,
        }
    }
}

/// Только подтверждённый host-адаптером executable, не display name/PID.
pub struct Flow<'a> {
    pub executable: Option<&'a str>,
    pub destination: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AndroidPackageId(String);
impl AndroidPackageId {
    pub fn parse(value: &str) -> Option<Self> {
        let valid = (3..=253).contains(&value.len())
            && value.contains('.')
            && value.split('.').all(|part| {
                part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                    && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            });
        valid.then(|| Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PlatformSource {
    AndroidPackage { package: AndroidPackageId },
}
impl PlatformSource {
    pub fn selector_bytes(&self) -> usize {
        match self {
            Self::AndroidPackage { package } => package.as_str().len(),
        }
    }
}
#[derive(Debug, Default)]
pub struct Conditions {
    pub transport: crate::TransportConditions,
    pub executables: Vec<String>,
    pub platform_sources: Vec<PlatformSource>,
    pub destinations: Vec<Cidr>,
    pub domains: Vec<DomainPattern>,
}

/// Имя процесса записывается отдельно от абсолютного пути.
pub fn process_name_selector(value: &str) -> Option<&str> {
    value.strip_prefix("name:").filter(|name| {
        !name.is_empty()
            && name.len() <= 255
            && !matches!(*name, "." | "..")
            && !name.contains(['/', '\\'])
            && !name.chars().any(char::is_control)
    })
}

impl Conditions {
    pub(crate) fn matches_source(&self, executable: Option<&str>) -> bool {
        self.executables.is_empty()
            || executable.is_some_and(|path| {
                self.executables.iter().any(|selector| {
                    process_name_selector(selector).map_or(selector == path, |name| {
                        path.rsplit('/').next() == Some(name)
                    })
                })
            })
    }
}

#[derive(Debug)]
pub struct Rule {
    pub id: u64,
    pub enabled: bool,
    pub conditions: Conditions,
    pub action: Action,
}

#[derive(Debug)]
pub struct PrivateNetwork {
    pub network: Cidr,
    pub available: bool,
    pub vpn: VpnId,
}

#[derive(Debug, Default)]
pub struct Policy {
    pub private_networks: Vec<PrivateNetwork>,
    pub private_domains: Vec<crate::PrivateDomain>,
    pub lan: Vec<Cidr>,
    pub user_rules: Vec<Rule>,
    pub preset_rules: Vec<Rule>,
    pub default_action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOrigin {
    PrivateNetwork,
    PrivateDomain,
    Lan,
    User(u64),
    Preset(u64),
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: Route,
    pub origin: RuleOrigin,
}

impl Policy {
    pub fn unsupported_transport(&self) -> Option<u64> {
        self.user_rules
            .iter()
            .chain(&self.preset_rules)
            .find(|r| r.enabled && r.conditions.transport.constrained())
            .map(|r| r.id)
    }
    pub fn unsupported_selector(&self) -> Option<u64> {
        self.user_rules
            .iter()
            .chain(&self.preset_rules)
            .find(|r| r.enabled && !r.conditions.platform_sources.is_empty())
            .map(|r| r.id)
    }

    /// Совместимый расчёт для literal IP без имени. Для DNS/fake и кода отказа
    /// используйте evaluate_destination; неоднозначность здесь даёт Block.
    pub fn evaluate(&self, flow: &Flow<'_>) -> Decision {
        let request = crate::DestinationFlow {
            executable: flow.executable,
            destination: crate::Destination::Ip {
                address: flow.destination,
                name: None,
            },
        };
        match self.evaluate_destination(&request, &crate::EvaluationContext::default()) {
            crate::Evaluation::Decided { decision, .. } => decision,
            _ => Decision {
                action: Route::Block,
                origin: RuleOrigin::PrivateNetwork,
            },
        }
    }
}
