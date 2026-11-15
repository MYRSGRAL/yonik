use serde_json::Value;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileCompileError {
    Budget,
    Schema,
    UnsupportedField,
    UnsupportedProtocol,
    UnsupportedTransport,
    UnsupportedCongestion,
    UnsupportedMask,
    Reference,
    Cycle,
    Ownership,
    ResourceRequired,
    Probe,
}
impl fmt::Display for ProfileCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Отказ компиляции полного профиля: {self:?}")
    }
}
impl std::error::Error for ProfileCompileError {}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PhysicalEndpoint {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) protocol: TransportProtocol,
}
impl PhysicalEndpoint {
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn protocol(&self) -> TransportProtocol {
        self.protocol
    }
    pub fn requires_bootstrap(&self) -> bool {
        self.host.parse::<std::net::IpAddr>().is_err()
    }
}
impl fmt::Debug for PhysicalEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PhysicalEndpoint(<скрыто>)")
    }
}
pub struct EgressPlan {
    pub(super) physical: Vec<PhysicalEndpoint>,
    pub(super) chains: Vec<(String, String)>,
    pub(super) direct: Vec<String>,
    pub(super) resolvers: Vec<ResolverRequirement>,
    pub(super) subject_endpoints: Vec<(String, PhysicalEndpoint)>,
}
/// Требование resolver, а не разрешение прямого обхода provider DNS routing.
pub struct ResolverRequirement {
    pub(super) endpoint: PhysicalEndpoint,
    pub(super) subject: Option<String>,
}
impl ResolverRequirement {
    pub fn endpoint(&self) -> &PhysicalEndpoint {
        &self.endpoint
    }
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }
}
impl EgressPlan {
    pub fn physical(&self) -> &[PhysicalEndpoint] {
        &self.physical
    }
    pub fn chains(&self) -> &[(String, String)] {
        &self.chains
    }
    pub fn direct_subjects(&self) -> &[String] {
        &self.direct
    }
    pub fn resolvers(&self) -> &[ResolverRequirement] {
        &self.resolvers
    }
    /// Remote destination каждого subject. Chained remote не physical exception.
    pub fn subject_endpoints(&self) -> &[(String, PhysicalEndpoint)] {
        &self.subject_endpoints
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedResourceRequirement {
    pub(super) kind: crate::resource_bundle::ResourceKind,
    pub(super) category: String,
}
impl OwnedResourceRequirement {
    pub fn kind(&self) -> crate::resource_bundle::ResourceKind {
        self.kind
    }
    pub fn category(&self) -> &str {
        &self.category
    }
}
/// Trusted store проверяет digest native DAT, наличие категории и её тип.
/// Это read-only seam, аналогичный resource_bundle::VerifiedCatalog.
pub trait VerifiedNativeResources {
    fn lookup(
        &self,
        requirement: &OwnedResourceRequirement,
    ) -> Option<crate::resource_bundle::ExternalRef>;
}
pub struct ProbeRequirement {
    pub(super) url: String,
    pub(super) subjects: Vec<String>,
}
impl ProbeRequirement {
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn subjects(&self) -> &[String] {
        &self.subjects
    }
}
pub struct ValidatedGraph {
    pub(super) value: Value,
    pub(super) egress: EgressPlan,
    pub(super) tags: Vec<String>,
    pub(super) selectors: Vec<(String, Vec<String>)>,
    pub(super) resources: Vec<OwnedResourceRequirement>,
    pub(super) probe: Option<ProbeRequirement>,
}
impl ValidatedGraph {
    pub fn egress(&self) -> &EgressPlan {
        &self.egress
    }
    pub fn subjects(&self) -> &[String] {
        &self.tags
    }
    pub fn selector_sets(&self) -> &[(String, Vec<String>)] {
        &self.selectors
    }
    pub fn resources(&self) -> &[OwnedResourceRequirement] {
        &self.resources
    }
    pub fn probe(&self) -> Option<&ProbeRequirement> {
        self.probe.as_ref()
    }
}
impl fmt::Debug for ValidatedGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedGraph(<скрыто>)")
    }
}
