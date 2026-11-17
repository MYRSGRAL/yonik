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
    pub(super) system_resolvers: Vec<SystemResolverRequirement>,
    pub(super) physical_bootstrap: Vec<PhysicalFirstHopBootstrap>,
}
/// Закрытое требование snapshot для physical leaf, отдельно от provider DNS.
pub struct PhysicalFirstHopBootstrap {
    pub(super) subject: String,
    pub(super) endpoint: PhysicalEndpoint,
}
impl PhysicalFirstHopBootstrap {
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn endpoint(&self) -> &PhysicalEndpoint {
        &self.endpoint
    }
}
/// Источник DNS внутри конфигурации Xray. Совпадение имени с outbound
/// не связывает эти пространства и не выбирает маршрут.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsIngressIdentity {
    Untagged,
    Tagged(String),
}
impl DnsIngressIdentity {
    pub(super) fn from_tag(tag: Option<&str>) -> Self {
        tag.map_or(Self::Untagged, |tag| Self::Tagged(tag.to_owned()))
    }
    pub fn tag(&self) -> Option<&str> {
        match self {
            Self::Untagged => None,
            Self::Tagged(tag) => Some(tag),
        }
    }
}
/// Native localhost использует OS resolver вне provider dispatcher.
pub struct SystemResolverRequirement {
    pub(super) dns_ingress: DnsIngressIdentity,
}
impl SystemResolverRequirement {
    pub fn dns_ingress(&self) -> &DnsIngressIdentity {
        &self.dns_ingress
    }
    /// Совместимый accessor для тега DNS ingress.
    pub fn subject(&self) -> Option<&str> {
        self.dns_ingress.tag()
    }
}
/// Trusted host удерживает exact resolver/NSS snapshot и проверенные UDP/TCP routes.
pub trait VerifiedSystemResolver {
    fn snapshot_digest(&self) -> [u8; 32];
    fn servers(&self) -> Vec<std::net::SocketAddr>;
}
pub struct SystemResolverBinding {
    pub(super) digest: [u8; 32],
    pub(super) servers: Vec<std::net::SocketAddr>,
}
impl SystemResolverBinding {
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn servers(&self) -> &[std::net::SocketAddr] {
        &self.servers
    }
}
/// Требование resolver, а не разрешение прямого обхода provider DNS routing.
pub struct ResolverRequirement {
    pub(super) endpoint: PhysicalEndpoint,
    pub(super) dns_ingress: DnsIngressIdentity,
}
impl ResolverRequirement {
    pub fn endpoint(&self) -> &PhysicalEndpoint {
        &self.endpoint
    }
    pub fn dns_ingress(&self) -> &DnsIngressIdentity {
        &self.dns_ingress
    }
    /// Совместимый accessor для тега DNS ingress.
    pub fn subject(&self) -> Option<&str> {
        self.dns_ingress.tag()
    }
}
impl EgressPlan {
    pub fn physical_bootstrap(&self) -> &[PhysicalFirstHopBootstrap] {
        &self.physical_bootstrap
    }
    /// Mapping4 table11 purpose bits. Hosts-absent bit0 принадлежит capture.
    pub fn system_resolver_roles(&self) -> u32 {
        (u32::from(!self.system_resolvers.is_empty()) * 2)
            | (u32::from(!self.physical_bootstrap.is_empty()) * 4)
    }
    pub fn requires_system_snapshot(&self) -> bool {
        self.system_resolver_roles() != 0
    }
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
    pub fn system_resolvers(&self) -> &[SystemResolverRequirement] {
        &self.system_resolvers
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
    pub(super) ingresses: Vec<IngressRequirement>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderIngressProtocol {
    Socks,
    Http,
}
pub struct IngressRequirement {
    pub(super) tag: String,
    pub(super) protocol: ProviderIngressProtocol,
}
impl IngressRequirement {
    pub fn tag(&self) -> &str {
        &self.tag
    }
    pub fn protocol(&self) -> ProviderIngressProtocol {
        self.protocol
    }
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
    pub fn ingresses(&self) -> &[IngressRequirement] {
        &self.ingresses
    }
}
impl fmt::Debug for ValidatedGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedGraph(<скрыто>)")
    }
}
