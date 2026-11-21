//! Sidecar bindings не меняют legacy Policy и её serialization.
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};
pub use yonik_domain::{
    Action, AnswerSet, Cidr, Conditions, Destination, DestinationFlow, DomainName, DomainPattern,
    Evaluation, EvaluationContext, Policy, PolicyFault, Resolution, ResolverPath,
    ResourceConditions, ResourceRule, Route, Rule,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Domains,
    Cidrs,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRef {
    pub engine: crate::Engine,
    pub digest: [u8; 32],
    pub bytes: u64,
    pub records: u64,
    pub kind: ResourceKind,
    pub format_version: u32,
}
impl ExternalRef {
    pub fn validate(&self) -> io::Result<()> {
        if self.bytes == 0
            || self.bytes > 128 * 1024 * 1024
            || self.records == 0
            || self.records > 1_500_000
            || self.format_version
                != if self.engine == crate::Engine::Xray {
                    1
                } else {
                    3
                }
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn tag(&self) -> String {
        let mut s = String::from("r-");
        for b in self.digest {
            use std::fmt::Write;
            write!(&mut s, "{b:02x}").expect("Запись в String");
        }
        s
    }
}
#[derive(Debug, Clone)]
pub struct ResourceBinding {
    pub rule: ResourceRule,
    pub resource: usize,
}
/// Индекс выдаёт trusted store после digest/count/format validation.
pub trait VerifiedCatalog {
    fn manifest(&self) -> &[ExternalRef];
    fn matches_domain(&self, resource: usize, name: &DomainName) -> bool;
    fn matches_ip(&self, resource: usize, ip: IpAddr) -> bool;
}
pub struct BoundPolicy<'a, C> {
    pub(crate) policy: &'a Policy,
    pub(crate) catalog: &'a C,
    bindings: HashMap<ResourceRule, Vec<usize>>,
    revision: u64,
    identity: Vec<u8>,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Некорректная привязка ресурсов")
}
/// Канонический полный preimage policy digest, включая порядок и disabled rules.
pub fn policy_identity(policy: &Policy) -> Vec<u8> {
    fn pattern(p: &yonik_domain::DomainPattern) -> Value {
        json!([
            matches!(p, yonik_domain::DomainPattern::Suffix(_)),
            p.name().as_str()
        ])
    }
    fn rules(rules: &[yonik_domain::Rule]) -> Value {
        Value::Array(
            rules
                .iter()
                .map(|r| {
                    json!([
                        r.id,
                        r.enabled,
                        format!("{:?}", r.action),
                        r.conditions.executables,
                        r.conditions.domains.iter().map(pattern).collect::<Vec<_>>(),
                        r.conditions
                            .destinations
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                    ])
                })
                .collect(),
        )
    }
    serde_json::to_vec(&json!([
        "yonik-policy-v1",
        format!("{:?}", policy.default_action),
        rules(&policy.user_rules),
        rules(&policy.preset_rules),
        policy
            .lan
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        policy
            .private_networks
            .iter()
            .map(|n| json!([n.network.to_string(), n.available, n.vpn.get()]))
            .collect::<Vec<_>>(),
        policy
            .private_domains
            .iter()
            .map(|d| json!([pattern(&d.domain), d.available, d.vpn.get()]))
            .collect::<Vec<_>>()
    ]))
    .expect("JSON из ограниченных значений")
}
impl<'a, C: VerifiedCatalog> BoundPolicy<'a, C> {
    /// Borrow policy запрещает изменение policy в течение жизни bindings.
    /// expected_identity проверяется byte-exact; SHA-256 preimage проверяет host.
    pub fn bind(
        policy: &'a Policy,
        revision: u64,
        expected_identity: &[u8],
        catalog: &'a C,
        bindings: Vec<ResourceBinding>,
    ) -> io::Result<Self> {
        validate_policy_bounds(policy)?;
        let identity = policy_identity(policy);
        if revision == 0
            || identity != expected_identity
            || identity.len() > 4 * 1024 * 1024
            || catalog.manifest().len() > 16
            || bindings.len() > 160_000
        {
            return Err(invalid());
        }
        let mut bytes = 0u64;
        let mut records = 0u64;
        let mut seen = HashSet::new();
        for r in catalog.manifest() {
            r.validate()?;
            bytes = bytes.checked_add(r.bytes).ok_or_else(invalid)?;
            records = records.checked_add(r.records).ok_or_else(invalid)?;
            if bytes > 512 * 1024 * 1024 || records > 1_500_000 {
                return Err(invalid());
            }
            if !seen.insert(r.digest) {
                return Err(invalid());
            }
        }
        let valid: HashSet<_> = policy
            .user_rules
            .iter()
            .map(|r| ResourceRule::User(r.id))
            .chain(
                policy
                    .preset_rules
                    .iter()
                    .map(|r| ResourceRule::Preset(r.id)),
            )
            .collect();
        let mut edges = HashSet::new();
        let mut indexed: HashMap<ResourceRule, Vec<usize>> = HashMap::new();
        for b in &bindings {
            if b.resource >= catalog.manifest().len()
                || !valid.contains(&b.rule)
                || !edges.insert((b.rule, b.resource))
            {
                return Err(invalid());
            }
            indexed.entry(b.rule).or_default().push(b.resource);
        }
        if seen.len()
            != bindings
                .iter()
                .map(|b| b.resource)
                .collect::<HashSet<_>>()
                .len()
        {
            return Err(invalid());
        }
        Ok(Self {
            policy,
            catalog,
            bindings: indexed,
            revision,
            identity,
        })
    }
    pub fn validate_revision(&self, revision: u64, identity: &[u8]) -> io::Result<()> {
        if self.revision != revision || self.identity != identity {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn policy(&self) -> &Policy {
        self.policy
    }
    pub fn manifest(&self) -> &[ExternalRef] {
        self.catalog.manifest()
    }
    pub fn references(&self, rule: ResourceRule, kind: ResourceKind) -> Vec<&ExternalRef> {
        self.bindings
            .get(&rule)
            .into_iter()
            .flatten()
            .map(|&index| &self.catalog.manifest()[index])
            .filter(|r| r.kind == kind)
            .collect()
    }
    pub fn evaluate(
        &self,
        flow: &yonik_domain::DestinationFlow<'_>,
        context: &yonik_domain::EvaluationContext<'_>,
    ) -> yonik_domain::Evaluation {
        self.policy.evaluate_with_resources(flow, context, self)
    }
}
impl<C: VerifiedCatalog> ResourceConditions for BoundPolicy<'_, C> {
    fn has_domains(&self, r: ResourceRule) -> bool {
        !self.references(r, ResourceKind::Domains).is_empty()
    }
    fn has_cidrs(&self, r: ResourceRule) -> bool {
        !self.references(r, ResourceKind::Cidrs).is_empty()
    }
    fn matches_domain(&self, r: ResourceRule, n: &DomainName) -> bool {
        self.bindings
            .get(&r)
            .into_iter()
            .flatten()
            .filter(|&&index| self.catalog.manifest()[index].kind == ResourceKind::Domains)
            .any(|&index| self.catalog.matches_domain(index, n))
    }
    fn matches_ip(&self, r: ResourceRule, ip: IpAddr) -> bool {
        self.bindings
            .get(&r)
            .into_iter()
            .flatten()
            .filter(|&&index| self.catalog.manifest()[index].kind == ResourceKind::Cidrs)
            .any(|&index| self.catalog.matches_ip(index, ip))
    }
}

pub(crate) trait ResourceRoutes {
    fn worker_slot(&self, _resource: &ExternalRef) -> Option<u32> {
        None
    }
    fn refs(&self, rule: ResourceRule, kind: ResourceKind) -> Vec<&ExternalRef>;
    fn manifest(&self) -> &[ExternalRef];
}
impl<C: VerifiedCatalog> ResourceRoutes for BoundPolicy<'_, C> {
    fn refs(&self, rule: ResourceRule, kind: ResourceKind) -> Vec<&ExternalRef> {
        self.references(rule, kind)
    }
    fn manifest(&self) -> &[ExternalRef] {
        self.manifest()
    }
}
/// Данные для offline codec/config-check. Не принимаются activation/seal API.
pub struct UnadmittedCompiledData {
    bytes: Vec<u8>,
    manifest: Vec<ExternalRef>,
    revision: u64,
    identity: Vec<u8>,
}
impl UnadmittedCompiledData {
    pub fn write_sensitive(&self, mut writer: impl io::Write) -> io::Result<()> {
        writer.write_all(&self.bytes)
    }
    pub fn manifest(&self) -> &[ExternalRef] {
        &self.manifest
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn policy_identity(&self) -> &[u8] {
        &self.identity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundCompileError {
    Cancelled,
    Policy(crate::PolicyCompileError),
}
impl std::fmt::Display for BoundCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Компиляция отменена"),
            Self::Policy(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for BoundCompileError {}
impl From<crate::PolicyCompileError> for BoundCompileError {
    fn from(error: crate::PolicyCompileError) -> Self {
        Self::Policy(error)
    }
}
pub(crate) struct Checkpoint<'a> {
    proceed: &'a dyn Fn() -> bool,
    cancelled: std::cell::Cell<bool>,
}
impl<'a> Checkpoint<'a> {
    pub(crate) fn new(proceed: &'a dyn Fn() -> bool) -> Self {
        Self {
            proceed,
            cancelled: std::cell::Cell::new(false),
        }
    }
    pub(crate) fn check(&self) -> Result<(), BoundCompileError> {
        if self.cancelled.get() || !(self.proceed)() {
            self.cancelled.set(true);
            Err(BoundCompileError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Только compile data; host обязан заново проверить отмену перед внешним commit.
#[allow(clippy::too_many_arguments)]
pub fn compile_bound_data_cancellable<C: VerifiedCatalog>(
    server: &yonik_import::ParsedServer,
    engine: crate::Engine,
    port: std::num::NonZeroU16,
    probe_port: std::num::NonZeroU16,
    bound: &BoundPolicy<'_, C>,
    revision: u64,
    identity: &[u8],
    proceed: impl Fn() -> bool,
) -> Result<UnadmittedCompiledData, BoundCompileError> {
    let checkpoint = Checkpoint::new(&proceed);
    checkpoint.check()?;
    bound
        .validate_revision(revision, identity)
        .map_err(|_| crate::PolicyCompileError::InvalidPolicy)?;
    for reference in bound.manifest() {
        checkpoint.check()?;
        reference
            .validate()
            .map_err(|_| crate::PolicyCompileError::InvalidPolicy)?;
        if reference.engine != engine {
            return Err(crate::PolicyCompileError::InvalidPolicy.into());
        }
    }
    let config = crate::routing::compile_unadmitted_data(
        server,
        engine,
        port,
        probe_port,
        bound.policy(),
        bound,
        &checkpoint,
    )?;
    struct Writer<'a> {
        bytes: Vec<u8>,
        checkpoint: &'a Checkpoint<'a>,
    }
    impl io::Write for Writer<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.checkpoint.check().map_err(io::Error::other)?;
            if bytes.len() > (4 * 1024 * 1024usize).saturating_sub(self.bytes.len()) {
                return Err(io::Error::other("Превышен output budget"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    checkpoint.check()?;
    let mut writer = Writer {
        bytes: Vec::new(),
        checkpoint: &checkpoint,
    };
    let result = config.write_sensitive(&mut writer);
    checkpoint.check()?;
    result.map_err(|_| crate::PolicyCompileError::InvalidPolicy)?;
    let artifact = UnadmittedCompiledData {
        bytes: writer.bytes,
        manifest: bound.manifest().to_vec(),
        revision,
        identity: identity.to_vec(),
    };
    checkpoint.check()?;
    Ok(artifact)
}

pub struct CompiledResourceBundle {
    config: crate::CompiledConfig,
    manifest: Vec<ExternalRef>,
    revision: u64,
    identity: Vec<u8>,
}
#[allow(clippy::too_many_arguments)]
pub fn compile_bound_policy<C: VerifiedCatalog>(
    server: &yonik_import::ParsedServer,
    engine: crate::Engine,
    port: std::num::NonZeroU16,
    probe_port: std::num::NonZeroU16,
    bound: &BoundPolicy<'_, C>,
    revision: u64,
    identity: &[u8],
    mode: crate::PolicyMode,
    dns: &crate::DnsContract,
) -> Result<CompiledResourceBundle, crate::PolicyCompileError> {
    bound
        .validate_revision(revision, identity)
        .map_err(|_| crate::PolicyCompileError::InvalidPolicy)?;
    dns.validate()?;
    if bound.manifest().iter().any(|r| r.engine != engine) {
        return Err(crate::PolicyCompileError::InvalidPolicy);
    }
    let config = crate::routing::compile_policy_resources(
        server,
        engine,
        port,
        probe_port,
        bound.policy,
        mode,
        Some(bound),
    )?;
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(b.len());
            if self.0 > 4 * 1024 * 1024 {
                return Err(invalid());
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    config
        .write_sensitive(Budget(0))
        .map_err(|_| crate::PolicyCompileError::InvalidPolicy)?;
    Ok(CompiledResourceBundle {
        config,
        manifest: bound.manifest().to_vec(),
        revision,
        identity: identity.to_vec(),
    })
}

impl CompiledResourceBundle {
    pub fn config(&self) -> &crate::CompiledConfig {
        &self.config
    }
    pub fn manifest(&self) -> &[ExternalRef] {
        &self.manifest
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn policy_identity(&self) -> &[u8] {
        &self.identity
    }
}

pub fn validate_policy_bounds(policy: &Policy) -> io::Result<()> {
    validate_policy_bounds_checked(policy, &|| Ok(()))
}
pub(crate) fn validate_policy_bounds_checked(
    policy: &Policy,
    checkpoint: &dyn Fn() -> io::Result<()>,
) -> io::Result<()> {
    if policy
        .user_rules
        .len()
        .saturating_add(policy.preset_rules.len())
        > 10000
    {
        return Err(invalid());
    }
    let mut selectors = policy
        .lan
        .len()
        .saturating_add(policy.private_domains.len())
        .saturating_add(policy.private_networks.len());
    let mut bytes = 0usize;
    for rules in [&policy.user_rules, &policy.preset_rules] {
        let mut ids = HashSet::new();
        for r in rules {
            checkpoint()?;
            if !ids.insert(r.id) {
                return Err(invalid());
            }
            selectors = selectors
                .saturating_add(r.conditions.executables.len())
                .saturating_add(r.conditions.domains.len())
                .saturating_add(r.conditions.destinations.len());
            for p in &r.conditions.executables {
                checkpoint()?;
                if p.len() > 4096 {
                    return Err(invalid());
                }
                bytes = bytes.saturating_add(p.len());
            }
        }
    }
    if selectors > 100000 || bytes > 2 * 1024 * 1024 {
        return Err(invalid());
    }
    Ok(())
}
