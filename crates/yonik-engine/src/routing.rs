use std::{collections::HashSet, fmt, num::NonZeroU16};

use serde_json::{Value, json};
use yonik_domain::{Action, DomainPattern, Policy};
use yonik_import::ParsedServer;

use crate::resource_bundle::{BoundCompileError, Checkpoint};
use crate::{CompileError, CompiledConfig, Engine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Names,
    /// Сопоставляет имя или IP, который уже передан во входящий запрос SOCKS.
    Observed,
    IpOnly,
}
impl std::str::FromStr for PolicyMode {
    type Err = PolicyCompileError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "names" => Ok(Self::Names),
            "ip-only" => Ok(Self::IpOnly),
            _ => Err(PolicyCompileError::InvalidPolicy),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyCapability {
    DnsContract,
    RequiredRealResolution,
    ProcessAttribution,
    PrivateNetworkBinding,
    DomainsInIpOnly,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyCompileError {
    UnsupportedSelector(u64),
    UnsupportedTransport(u64),
    Server(CompileError),
    Unsupported(PolicyCapability),
    InvalidPolicy,
    ProbePort,
    Random,
}
impl fmt::Display for PolicyCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTransport(id) => {
                write!(f, "Транспорт правила {id} не поддержан адаптером")
            }
            Self::UnsupportedSelector(id) => write!(f, "Неприменимый селектор правила {id}"),
            Self::Server(error) => error.fmt(f),
            Self::Unsupported(PolicyCapability::DnsContract) => f.write_str(
                "Запрошенный DNS/Fake-IP контракт не поддерживается закреплённым адаптером",
            ),
            Self::Unsupported(PolicyCapability::RequiredRealResolution) => f.write_str(
                "Нативный режим не подтверждает обязательное DNS разрешение CIDR-политики",
            ),
            Self::Unsupported(PolicyCapability::ProcessAttribution) => {
                f.write_str("Атрибуция источника через локальный SOCKS не подтверждена")
            }
            Self::Unsupported(PolicyCapability::PrivateNetworkBinding) => {
                f.write_str("Нет подтверждённой NetworkHost привязки к приватному VPN")
            }
            Self::Unsupported(PolicyCapability::DomainsInIpOnly) => {
                f.write_str("Доменное правило недоступно в режиме только IP")
            }
            Self::InvalidPolicy => f.write_str("Некорректная или слишком большая политика"),
            Self::ProbePort => f.write_str("Нужен отдельный ненулевой порт служебной проверки"),
            Self::Random => {
                f.write_str("Не удалось получить случайную авторизацию служебной проверки")
            }
        }
    }
}
impl std::error::Error for PolicyCompileError {}

/// Случайный секрет только в памяти host/конфига. Не выводить в обычную сводку.
pub struct ProbeCredentials {
    password: String,
}
impl ProbeCredentials {
    pub(crate) fn random() -> Result<Self, PolicyCompileError> {
        let mut random = [0; 32];
        getrandom::getrandom(&mut random).map_err(|_| PolicyCompileError::Random)?;
        const HEX: &[u8] = b"0123456789abcdef";
        let mut password = String::with_capacity(64);
        for byte in random {
            password.push(char::from(HEX[usize::from(byte >> 4)]));
            password.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(Self { password })
    }
    pub fn username(&self) -> &str {
        "yonik-health"
    }
    pub fn password(&self) -> &str {
        &self.password
    }
}
impl fmt::Debug for ProbeCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProbeCredentials(<скрыто>)")
    }
}

/// Служебный probe не является разрешением отправлять известные приватные
/// зоны/адреса публичному серверу. Проверка не делает собственный DNS lookup.
#[derive(Default)]
pub struct ProbeAccess {
    auth: Option<ProbeCredentials>,
    networks: Vec<yonik_domain::Cidr>,
    domains: Vec<DomainPattern>,
}
impl ProbeAccess {
    pub(crate) fn native(auth: ProbeCredentials) -> Self {
        Self {
            auth: Some(auth),
            ..Self::default()
        }
    }
    pub fn auth(&self) -> Option<&ProbeCredentials> {
        self.auth.as_ref()
    }
    pub fn allows_host(&self, host: &str) -> bool {
        if self.networks.is_empty() && self.domains.is_empty() {
            return true;
        }
        if let Ok(address) = host.parse::<std::net::IpAddr>() {
            return !self
                .networks
                .iter()
                .any(|network| network.contains(address.to_canonical()));
        }
        match url::Host::parse(host) {
            Ok(url::Host::Ipv4(address)) => !self
                .networks
                .iter()
                .any(|network| network.contains(address.into())),
            Ok(url::Host::Ipv6(address)) => !self
                .networks
                .iter()
                .any(|network| network.contains(std::net::IpAddr::V6(address).to_canonical())),
            Ok(url::Host::Domain(domain)) => domain
                .parse::<yonik_domain::DomainName>()
                .is_ok_and(|name| !self.domains.iter().any(|pattern| pattern.matches(&name))),
            Err(_) => false,
        }
    }
}
impl fmt::Debug for ProbeAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProbeAccess(<скрыто>)")
    }
}

/// Names не содержит CIDR; IpOnly принудительно отклоняет доменные SOCKS
/// назначения. Недоказанные комбинации не опускаются и не получают fallback.
pub fn compile_policy(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    mode: PolicyMode,
) -> Result<CompiledConfig, PolicyCompileError> {
    compile_policy_inner(server, engine, port, probe_port, policy, mode, false)
}

pub(crate) fn compile_tun_policy(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
) -> Result<CompiledConfig, PolicyCompileError> {
    compile_policy_inner(
        server,
        engine,
        port,
        probe_port,
        policy,
        PolicyMode::IpOnly,
        true,
    )
}

pub(crate) fn compile_tun_policy_resources<C: crate::resource_bundle::VerifiedCatalog>(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    bound: &crate::resource_bundle::BoundPolicy<'_, C>,
) -> Result<CompiledConfig, PolicyCompileError> {
    struct WorkerRoutes<'a>(&'a dyn crate::resource_bundle::ResourceRoutes);
    impl crate::resource_bundle::ResourceRoutes for WorkerRoutes<'_> {
        fn refs(
            &self,
            rule: yonik_domain::ResourceRule,
            kind: crate::resource_bundle::ResourceKind,
        ) -> Vec<&crate::resource_bundle::ExternalRef> {
            self.0.refs(rule, kind)
        }
        fn manifest(&self) -> &[crate::resource_bundle::ExternalRef] {
            self.0.manifest()
        }
        fn worker_slot(&self, resource: &crate::resource_bundle::ExternalRef) -> Option<u32> {
            if resource.engine == Engine::Xray {
                return None;
            }
            self.0
                .manifest()
                .iter()
                .position(|r| r.digest == resource.digest)
                .map(|i| 32 + i as u32)
        }
    }
    let resources = WorkerRoutes(bound);
    compile_policy_resources_inner(
        server,
        engine,
        port,
        probe_port,
        bound.policy(),
        PolicyMode::IpOnly,
        true,
        Some(&resources),
        false,
    )
}

fn compile_policy_inner(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    mode: PolicyMode,
    tun_sources: bool,
) -> Result<CompiledConfig, PolicyCompileError> {
    compile_policy_resources_inner(
        server,
        engine,
        port,
        probe_port,
        policy,
        mode,
        tun_sources,
        None,
        false,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn compile_policy_resources(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    mode: PolicyMode,
    resources: Option<&dyn crate::resource_bundle::ResourceRoutes>,
) -> Result<CompiledConfig, PolicyCompileError> {
    compile_policy_resources_inner(
        server, engine, port, probe_port, policy, mode, false, resources, false,
    )
}
pub(crate) fn compile_xray_reality_h2_policy(
    server: &ParsedServer,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    mode: PolicyMode,
) -> Result<CompiledConfig, PolicyCompileError> {
    compile_policy_resources_inner(
        server,
        Engine::Xray,
        port,
        probe_port,
        policy,
        mode,
        false,
        None,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_policy_resources_inner(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    mode: PolicyMode,
    tun_sources: bool,
    resources: Option<&dyn crate::resource_bundle::ResourceRoutes>,
    require_reality_h2: bool,
) -> Result<CompiledConfig, PolicyCompileError> {
    if port == probe_port {
        return Err(PolicyCompileError::ProbePort);
    }
    validate_policy(policy, mode, tun_sources)?;
    if let Some(resources) = resources {
        use crate::resource_bundle::ResourceKind;
        for (rules, user) in [(&policy.user_rules, true), (&policy.preset_rules, false)] {
            for rule in rules.iter().filter(|r| r.enabled) {
                let key = if user {
                    yonik_domain::ResourceRule::User(rule.id)
                } else {
                    yonik_domain::ResourceRule::Preset(rule.id)
                };
                if mode == PolicyMode::Names && !resources.refs(key, ResourceKind::Cidrs).is_empty()
                {
                    return Err(PolicyCompileError::Unsupported(
                        PolicyCapability::RequiredRealResolution,
                    ));
                }
                if mode == PolicyMode::IpOnly
                    && !resources.refs(key, ResourceKind::Domains).is_empty()
                {
                    return Err(PolicyCompileError::Unsupported(
                        PolicyCapability::DomainsInIpOnly,
                    ));
                }
            }
        }
    }
    let checkpoint = Checkpoint::new(&|| true);
    emit_policy(
        server,
        engine,
        port,
        probe_port,
        policy,
        mode,
        tun_sources,
        resources,
        false,
        require_reality_h2,
        &checkpoint,
    )
    .map_err(|error| match error {
        BoundCompileError::Policy(error) => error,
        BoundCompileError::Cancelled => PolicyCompileError::InvalidPolicy,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compile_unadmitted_data(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    resources: &dyn crate::resource_bundle::ResourceRoutes,
    checkpoint: &Checkpoint<'_>,
) -> Result<CompiledConfig, BoundCompileError> {
    checkpoint.check()?;
    if port == probe_port {
        return Err(PolicyCompileError::ProbePort.into());
    }
    // Структура и пути сохраняют bounds; admission/DNS gates здесь не authority.
    let validation = crate::resource_bundle::validate_policy_bounds_checked(policy, &|| {
        checkpoint.check().map_err(std::io::Error::other)
    });
    checkpoint.check()?;
    validation.map_err(|_| PolicyCompileError::InvalidPolicy)?;
    crate::source_selectors::validate_data(policy, checkpoint)?;
    if policy.private_networks.iter().any(|n| n.available)
        || policy.private_domains.iter().any(|n| n.available)
    {
        return Err(
            PolicyCompileError::Unsupported(PolicyCapability::PrivateNetworkBinding).into(),
        );
    }
    emit_policy(
        server,
        engine,
        port,
        probe_port,
        policy,
        PolicyMode::Names,
        false,
        Some(resources),
        true,
        false,
        checkpoint,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_policy(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    policy: &Policy,
    mode: PolicyMode,
    tun_sources: bool,
    resources: Option<&dyn crate::resource_bundle::ResourceRoutes>,
    data_only: bool,
    require_reality_h2: bool,
    checkpoint: &Checkpoint<'_>,
) -> Result<CompiledConfig, BoundCompileError> {
    checkpoint.check()?;
    crate::validate_listener(server, probe_port).map_err(PolicyCompileError::Server)?;
    let mut config = crate::compile_server(server, engine, port, require_reality_h2)
        .map_err(PolicyCompileError::Server)?;
    let auth = ProbeCredentials::random()?;
    let inbound = match engine {
        Engine::Xray => {
            json!({"tag":"probe","listen":"127.0.0.1","port":probe_port.get(),"protocol":"socks",
            "settings":{"auth":"password","accounts":[{"user":auth.username(),"pass":auth.password()}]}})
        }
        Engine::SingBox => {
            json!({"type":"socks","tag":"probe","listen":"127.0.0.1","listen_port":probe_port.get(),
            "users":[{"username":auth.username(),"password":auth.password()}]})
        }
    };
    config.value["inbounds"]
        .as_array_mut()
        .ok_or(PolicyCompileError::InvalidPolicy)?
        .push(inbound);
    let mut rules = vec![match engine {
        Engine::Xray => json!({"type":"field","inboundTag":["probe"],"outboundTag":"proxy"}),
        Engine::SingBox => json!({"inbound":["probe"],"action":"route","outbound":"proxy"}),
    }];
    // Native matchers не выполняют IDNA и удаление root-dot. Не даём
    // некорректному wire имени обойти правило и попасть в default.
    const INVALID_NAME: &str =
        r"[^A-Za-z0-9.\-]|^\.|\.$|\.\.|(^|\.)-|-(\.|$)|(^|\.)[A-Za-z0-9\-]{64,}(\.|$)|.{254,}";
    let guard = if mode == PolicyMode::IpOnly {
        "."
    } else {
        INVALID_NAME
    };
    rules.push(route_rule(
        engine,
        Action::Block,
        Some(vec![format!("regexp:{guard}")]),
        None,
    ));
    for private in &policy.private_networks {
        checkpoint.check()?;
        rules.push(route_rule(
            engine,
            Action::Block,
            None,
            Some(vec![private.network.to_string()]),
        ));
    }
    for zone in &policy.private_domains {
        checkpoint.check()?;
        rules.push(route_rule(
            engine,
            Action::Block,
            Some(vec![xray_domain(&zone.domain)]),
            None,
        ));
    }
    if !policy.lan.is_empty() {
        rules.push(route_rule(
            engine,
            Action::Direct,
            None,
            Some(policy.lan.iter().map(ToString::to_string).collect()),
        ));
    }
    for (rule, key) in policy
        .user_rules
        .iter()
        .map(|r| (r, yonik_domain::ResourceRule::User(r.id)))
        .chain(
            policy
                .preset_rules
                .iter()
                .map(|r| (r, yonik_domain::ResourceRule::Preset(r.id))),
        )
        .filter(|(rule, _)| rule.enabled)
    {
        checkpoint.check()?;
        let domains = (!rule.conditions.domains.is_empty())
            .then(|| {
                rule.conditions
                    .domains
                    .iter()
                    .map(|domain| {
                        checkpoint.check()?;
                        Ok(xray_domain(domain))
                    })
                    .collect::<Result<Vec<_>, BoundCompileError>>()
            })
            .transpose()?;
        let cidrs = (!rule.conditions.destinations.is_empty())
            .then(|| {
                rule.conditions
                    .destinations
                    .iter()
                    .map(|cidr| {
                        checkpoint.check()?;
                        Ok(cidr.to_string())
                    })
                    .collect::<Result<Vec<_>, BoundCompileError>>()
            })
            .transpose()?;
        let mut native = if let Some(resources) = resources {
            resource_rule(engine, rule.action, domains, cidrs, key, resources)
        } else {
            route_rule(engine, rule.action, domains, cidrs)
        };
        if data_only {
            crate::source_selectors::apply_data(engine, &mut native, &rule.conditions.executables);
        } else if tun_sources {
            crate::source_selectors::apply(engine, &mut native, &rule.conditions.executables);
        }
        if !tun_sources && !data_only {
            crate::transport::apply_local(engine, &mut native, &rule.conditions.transport);
        }
        rules.push(native);
    }
    rules.push(route_rule(engine, policy.default_action, None, None));
    let direct = match engine {
        Engine::Xray => json!({"tag":"direct","protocol":"freedom"}),
        Engine::SingBox => json!({"tag":"direct","type":"direct"}),
    };
    let outbounds = config.value["outbounds"]
        .as_array_mut()
        .ok_or(PolicyCompileError::InvalidPolicy)?;
    outbounds.push(direct);
    match engine {
        Engine::Xray => {
            outbounds.push(json!({"tag":"block","protocol":"blackhole"}));
            config.value["routing"] = json!({"domainStrategy":"AsIs","rules":rules});
        }
        Engine::SingBox => config.value["route"] = json!({"final":"proxy","rules":rules}),
    }
    if engine == Engine::SingBox {
        if let Some(resources) = resources {
            config.value["route"]["rule_set"]=json!(resources.manifest().iter().map(|r|json!({"type":"local","tag":r.tag(),"format":"source","path":resources.worker_slot(r).map_or_else(||format!("{}.json",r.tag()),|slot|format!("/proc/self/fd/{slot}"))})).collect::<Vec<_>>());
        }
    }
    config.probe_port = probe_port;
    config.probe_access = ProbeAccess {
        auth: Some(auth),
        networks: policy
            .private_networks
            .iter()
            .map(|network| network.network)
            .collect(),
        domains: policy
            .private_domains
            .iter()
            .map(|domain| domain.domain.clone())
            .collect(),
    };
    checkpoint.check()?;
    Ok(config)
}

fn xray_domain(domain: &DomainPattern) -> String {
    format!(
        "{}:{}",
        match domain {
            DomainPattern::Exact(_) => "full",
            DomainPattern::Suffix(_) => "domain",
        },
        domain.name().as_str()
    )
}
fn route_rule(
    engine: Engine,
    action: Action,
    domains: Option<Vec<String>>,
    cidrs: Option<Vec<String>>,
) -> Value {
    match engine {
        Engine::Xray => {
            let mut rule = json!({"type":"field","outboundTag":match action { Action::Direct => "direct", Action::Proxy => "proxy", Action::Block => "block" }});
            let all = domains.is_none() && cidrs.is_none();
            if let Some(domains) = domains {
                rule["domain"] = json!(domains);
            }
            if let Some(cidrs) = cidrs {
                rule["ip"] = json!(cidrs);
            }
            if all {
                rule["network"] = json!("tcp,udp");
            }
            rule
        }
        Engine::SingBox => {
            let mut rule = if action == Action::Block {
                json!({"action":"reject"})
            } else {
                json!({"action":"route","outbound":if action == Action::Direct { "direct" } else { "proxy" }})
            };
            if let Some(domains) = domains {
                for (prefix, key) in [
                    ("full:", "domain"),
                    ("domain:", "domain_suffix"),
                    ("regexp:", "domain_regex"),
                ] {
                    let values: Vec<&str> = domains
                        .iter()
                        .filter_map(|domain| domain.strip_prefix(prefix))
                        .collect();
                    if !values.is_empty() {
                        rule[key] = json!(values);
                    }
                }
            }
            if let Some(cidrs) = cidrs {
                rule["ip_cidr"] = json!(cidrs);
            }
            rule
        }
    }
}

fn validate_policy(
    policy: &Policy,
    mode: PolicyMode,
    tun_sources: bool,
) -> Result<(), PolicyCompileError> {
    if tun_sources {
        if let Some(id) = policy.unsupported_transport() {
            return Err(PolicyCompileError::UnsupportedTransport(id));
        }
    }
    if let Some(id) = policy.unsupported_selector() {
        return Err(PolicyCompileError::UnsupportedSelector(id));
    }
    let transport_ranges: usize = policy
        .user_rules
        .iter()
        .chain(&policy.preset_rules)
        .filter_map(|r| r.conditions.transport.ports())
        .map(|ports| ports.ranges().len())
        .sum();
    if transport_ranges > 4096 {
        return Err(PolicyCompileError::InvalidPolicy);
    }
    let mut selectors =
        policy.lan.len() + policy.private_networks.len() + policy.private_domains.len();
    if policy.user_rules.len() + policy.preset_rules.len() > 10000 {
        return Err(PolicyCompileError::InvalidPolicy);
    }
    if tun_sources {
        crate::source_selectors::validate(policy)?;
    }
    for rules in [&policy.user_rules, &policy.preset_rules] {
        let mut ids = HashSet::with_capacity(rules.len());
        for rule in rules {
            if !ids.insert(rule.id) {
                return Err(PolicyCompileError::InvalidPolicy);
            }
            selectors = selectors
                .saturating_add(rule.conditions.executables.len())
                .saturating_add(rule.conditions.domains.len())
                .saturating_add(rule.conditions.destinations.len());
            if !tun_sources && rule.enabled && !rule.conditions.executables.is_empty() {
                return Err(PolicyCompileError::Unsupported(
                    PolicyCapability::ProcessAttribution,
                ));
            }
        }
    }
    if selectors > 100000 {
        return Err(PolicyCompileError::InvalidPolicy);
    }
    if policy
        .private_networks
        .iter()
        .any(|network| network.available)
        || policy.private_domains.iter().any(|domain| domain.available)
    {
        return Err(PolicyCompileError::Unsupported(
            PolicyCapability::PrivateNetworkBinding,
        ));
    }
    let rules = || {
        policy
            .user_rules
            .iter()
            .chain(&policy.preset_rules)
            .filter(|rule| rule.enabled)
    };
    match mode {
        PolicyMode::Observed
            if !policy.lan.is_empty()
                || !policy.private_networks.is_empty()
                || !policy.private_domains.is_empty()
                || rules().any(|rule| {
                    !rule.conditions.destinations.is_empty()
                        && (rule.action != Action::Direct || !rule.conditions.domains.is_empty())
                }) =>
        {
            Err(PolicyCompileError::Unsupported(
                PolicyCapability::RequiredRealResolution,
            ))
        }
        PolicyMode::Names
            if !policy.lan.is_empty()
                || !policy.private_networks.is_empty()
                || rules().any(|rule| !rule.conditions.destinations.is_empty()) =>
        {
            Err(PolicyCompileError::Unsupported(
                PolicyCapability::RequiredRealResolution,
            ))
        }
        PolicyMode::IpOnly
            if !policy.private_domains.is_empty()
                || rules().any(|rule| !rule.conditions.domains.is_empty()) =>
        {
            Err(PolicyCompileError::Unsupported(
                PolicyCapability::DomainsInIpOnly,
            ))
        }
        _ => Ok(()),
    }
}

fn resource_rule(
    engine: Engine,
    action: Action,
    mut domains: Option<Vec<String>>,
    mut cidrs: Option<Vec<String>>,
    key: yonik_domain::ResourceRule,
    resources: &dyn crate::resource_bundle::ResourceRoutes,
) -> Value {
    use crate::resource_bundle::ResourceKind;
    let dr = resources.refs(key, ResourceKind::Domains);
    let cr = resources.refs(key, ResourceKind::Cidrs);
    if engine == Engine::Xray {
        if !dr.is_empty() {
            domains
                .get_or_insert_with(Vec::new)
                .extend(dr.iter().map(|r| {
                    resources.worker_slot(r).map_or_else(
                        || format!("ext:{}.dat:YONIK", r.tag()),
                        |slot| format!("ext:/proc/self/fd/{slot}:YONIK"),
                    )
                }));
        }
        if !cr.is_empty() {
            cidrs
                .get_or_insert_with(Vec::new)
                .extend(cr.iter().map(|r| {
                    resources.worker_slot(r).map_or_else(
                        || format!("ext:{}.dat:YONIK", r.tag()),
                        |slot| format!("ext:/proc/self/fd/{slot}:YONIK"),
                    )
                }));
        }
        return route_rule(engine, action, domains, cidrs);
    }
    if dr.is_empty() && cr.is_empty() {
        return route_rule(engine, action, domains, cidrs);
    }
    let mut groups = Vec::new();
    for (inline, refs, domain) in [(domains, dr, true), (cidrs, cr, false)] {
        let mut choices = Vec::new();
        if let Some(inline) = inline {
            let mut v = if domain {
                route_rule(engine, action, Some(inline), None)
            } else {
                route_rule(engine, action, None, Some(inline))
            };
            if let Some(o) = v.as_object_mut() {
                o.remove("action");
                o.remove("outbound");
            }
            choices.push(v);
        }
        if !refs.is_empty() {
            choices.push(json!({"rule_set":refs.iter().map(|r|r.tag()).collect::<Vec<_>>()}));
        }
        if choices.len() == 1 {
            groups.push(choices.remove(0));
        } else if !choices.is_empty() {
            groups.push(json!({"type":"logical","mode":"or","rules":choices}));
        }
    }
    let mut native = route_rule(engine, action, None, None);
    native["type"] = json!("logical");
    native["mode"] = json!("and");
    native["rules"] = json!(groups);
    native
}
