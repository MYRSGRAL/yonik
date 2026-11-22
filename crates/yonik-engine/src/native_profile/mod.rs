//! Закрытая граница native graph. Результаты компиляции не дают сетевой authority.
mod emit;
mod graph;
mod intent;
mod validate;
pub use intent::{
    BranchProjection, MAX_INTENT_BYTES, PhysicalBootstrapFrontier, ProfileIntent,
    RawTcpConsumerShape, WireAction, WireNetwork, WireSecurity, WireTransportKind,
};

use crate::{CompiledConfig, SystemTun};
pub use graph::{
    DnsIngressIdentity, EgressPlan, IngressRequirement, OwnedResourceRequirement, PhysicalEndpoint,
    PhysicalFirstHopBootstrap, ProbeRequirement, ProfileCompileError, ProviderIngressProtocol,
    ResolverRequirement, SystemResolverBinding, SystemResolverRequirement, TransportProtocol,
    ValidatedGraph, VerifiedNativeResources, VerifiedSystemResolver,
};
use std::{collections::BTreeMap, num::NonZeroU16};
use yonik_import::NativeProfile;

/// Имена принадлежат приложению; provider tags никогда не переименовываются.
pub struct OwnedRuntimePlan {
    pub(super) port: NonZeroU16,
    pub(super) probe_port: NonZeroU16,
    pub(super) local_http_port: Option<NonZeroU16>,
    pub(super) ingress: BTreeMap<String, OwnedIngress>,
    pub(super) tun: Option<SystemTun>,
    pub(super) system_resolver: Option<SystemResolverBinding>,
    pub(super) resources: Vec<(
        OwnedResourceRequirement,
        crate::resource_bundle::ExternalRef,
    )>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedIngress {
    Local,
    System,
    LocalHttp,
}
impl OwnedRuntimePlan {
    pub fn ingress_mappings(&self) -> impl Iterator<Item = (&str, OwnedIngress)> {
        self.ingress
            .iter()
            .map(|(tag, owned)| (tag.as_str(), *owned))
    }
    pub fn local_port(&self) -> NonZeroU16 {
        self.port
    }
    pub fn probe_port(&self) -> NonZeroU16 {
        self.probe_port
    }
    pub fn local_http_port(&self) -> Option<NonZeroU16> {
        self.local_http_port
    }
    pub fn is_system(&self) -> bool {
        self.tun.is_some()
    }
    pub fn new(port: NonZeroU16, probe_port: NonZeroU16) -> Result<Self, ProfileCompileError> {
        if port == probe_port {
            return Err(ProfileCompileError::Ownership);
        }
        Ok(Self {
            port,
            probe_port,
            local_http_port: None,
            ingress: BTreeMap::new(),
            tun: None,
            system_resolver: None,
            resources: Vec::new(),
        })
    }
    pub fn with_local_http(mut self, port: NonZeroU16) -> Result<Self, ProfileCompileError> {
        if self.is_system()
            || self.local_http_port.is_some()
            || port == self.port
            || port == self.probe_port
        {
            return Err(ProfileCompileError::Ownership);
        }
        self.local_http_port = Some(port);
        Ok(self)
    }
    pub fn with_system(mut self, tun: SystemTun) -> Self {
        self.tun = Some(tun);
        self
    }
    pub fn bind_system_resolver(
        mut self,
        resolver: &impl VerifiedSystemResolver,
    ) -> Result<Self, ProfileCompileError> {
        let digest = resolver.snapshot_digest();
        let servers = resolver.servers();
        if digest == [0; 32]
            || servers.is_empty()
            || servers.len() > 16
            || servers
                .iter()
                .any(|s| s.port() == 0 || s.ip().is_unspecified() || s.ip().is_multicast())
        {
            return Err(ProfileCompileError::ResourceRequired);
        }
        self.system_resolver = Some(SystemResolverBinding { digest, servers });
        Ok(self)
    }
    pub fn system_resolver_binding(&self) -> Option<&SystemResolverBinding> {
        self.system_resolver.as_ref()
    }
    pub fn bind_resources(
        mut self,
        graph: &ValidatedGraph,
        catalog: &impl VerifiedNativeResources,
    ) -> Result<Self, ProfileCompileError> {
        self.resources.clear();
        let mut bytes = 0u64;
        let mut unique = std::collections::HashMap::new();
        for requirement in graph.resources() {
            let reference = catalog
                .lookup(requirement)
                .ok_or(ProfileCompileError::ResourceRequired)?;
            reference
                .validate()
                .map_err(|_| ProfileCompileError::ResourceRequired)?;
            if let Some(previous) = unique.insert(reference.digest, reference.clone()) {
                if previous != reference {
                    return Err(ProfileCompileError::ResourceRequired);
                }
            } else {
                bytes = bytes
                    .checked_add(reference.bytes)
                    .ok_or(ProfileCompileError::Budget)?;
            }
            if bytes > 512 * 1024 * 1024 {
                return Err(ProfileCompileError::Budget);
            }
            if reference.engine != crate::Engine::Xray || reference.kind != requirement.kind() {
                return Err(ProfileCompileError::ResourceRequired);
            }
            self.resources.push((requirement.clone(), reference));
        }
        Ok(self)
    }
    pub fn resource_bindings(
        &self,
    ) -> &[(
        OwnedResourceRequirement,
        crate::resource_bundle::ExternalRef,
    )] {
        &self.resources
    }
    /// Явное сопоставление входа: compiler не угадывает назначение provider listener.
    pub fn map_ingress(
        mut self,
        tag: &str,
        ingress: OwnedIngress,
    ) -> Result<Self, ProfileCompileError> {
        if tag.is_empty()
            || tag.len() > 128
            || tag.starts_with("yonik-owned-")
            || ingress == OwnedIngress::LocalHttp
                && (self.local_http_port.is_none() || self.is_system())
            || self.ingress.len() >= 16
            || self.ingress.insert(tag.to_owned(), ingress).is_some()
        {
            return Err(ProfileCompileError::Ownership);
        }
        Ok(self)
    }
}
pub struct CompiledProfileSystem {
    config: CompiledConfig,
    graph: ValidatedGraph,
}
impl CompiledProfileSystem {
    pub fn config(&self) -> &CompiledConfig {
        &self.config
    }
    pub fn graph(&self) -> &ValidatedGraph {
        &self.graph
    }
    pub fn egress(&self) -> &EgressPlan {
        self.graph.egress()
    }
    pub fn into_config(self) -> CompiledConfig {
        self.config
    }
}
pub fn validate_profile(profile: &NativeProfile) -> Result<ValidatedGraph, ProfileCompileError> {
    validate::validate(profile)
}
pub fn compile_profile_local(
    profile: &NativeProfile,
    runtime: &OwnedRuntimePlan,
) -> Result<CompiledConfig, ProfileCompileError> {
    emit::emit(validate_profile(profile)?, runtime, false).map(|(config, _)| config)
}
pub fn compile_profile_system(
    profile: &NativeProfile,
    runtime: &OwnedRuntimePlan,
) -> Result<CompiledProfileSystem, ProfileCompileError> {
    let (config, graph) = emit::emit(validate_profile(profile)?, runtime, true)?;
    Ok(CompiledProfileSystem { config, graph })
}
