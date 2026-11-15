//! Закрытая граница native graph. Результаты компиляции не дают сетевой authority.
mod emit;
mod graph;
mod validate;

use crate::{CompiledConfig, SystemTun};
pub use graph::{
    EgressPlan, OwnedResourceRequirement, PhysicalEndpoint, ProbeRequirement, ProfileCompileError,
    ResolverRequirement, TransportProtocol, ValidatedGraph, VerifiedNativeResources,
};
use std::{collections::BTreeMap, num::NonZeroU16};
use yonik_import::NativeProfile;

/// Имена принадлежат приложению; provider tags никогда не переименовываются.
pub struct OwnedRuntimePlan {
    pub(super) port: NonZeroU16,
    pub(super) probe_port: NonZeroU16,
    pub(super) ingress: BTreeMap<String, OwnedIngress>,
    pub(super) tun: Option<SystemTun>,
    pub(super) resources: Vec<(
        OwnedResourceRequirement,
        crate::resource_bundle::ExternalRef,
    )>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedIngress {
    Local,
    System,
}
impl OwnedRuntimePlan {
    pub fn new(port: NonZeroU16, probe_port: NonZeroU16) -> Result<Self, ProfileCompileError> {
        if port == probe_port {
            return Err(ProfileCompileError::Ownership);
        }
        Ok(Self {
            port,
            probe_port,
            ingress: BTreeMap::new(),
            tun: None,
            resources: Vec::new(),
        })
    }
    pub fn with_system(mut self, tun: SystemTun) -> Self {
        self.tun = Some(tun);
        self
    }
    pub fn bind_resources(
        mut self,
        graph: &ValidatedGraph,
        catalog: &impl VerifiedNativeResources,
    ) -> Result<Self, ProfileCompileError> {
        self.resources.clear();
        let mut bytes = 0u64;
        for requirement in graph.resources() {
            let reference = catalog
                .lookup(requirement)
                .ok_or(ProfileCompileError::ResourceRequired)?;
            reference
                .validate()
                .map_err(|_| ProfileCompileError::ResourceRequired)?;
            bytes = bytes
                .checked_add(reference.bytes)
                .ok_or(ProfileCompileError::Budget)?;
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
