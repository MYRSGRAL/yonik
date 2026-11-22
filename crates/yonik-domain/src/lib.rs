//! Переносимая модель yonik: без GUI, сети и обращения к ОС.

mod cidr;
mod domain;
mod evaluation;
mod fake_ip;
mod policy;

pub use cidr::{Cidr, InvalidCidr};
pub use domain::{DomainName, DomainPattern, InvalidDomain};
pub use evaluation::{
    AnswerSet, Destination, DestinationFlow, DnsEpoch, Evaluation, EvaluationContext, FakeMapping,
    PolicyFault, PrivateDomain, Resolution, ResolverPath, VpnId,
};
pub use fake_ip::{FakeIpError, FakeIpFamily, FakeIpGrant, FakeIpLeaseTable};
pub use policy::{
    Action, AndroidPackageId, Conditions, Decision, Flow, PlatformSource, Policy, PrivateNetwork,
    Route, Rule, RuleOrigin, process_name_selector,
};

mod dns_policy;
pub use dns_policy::{DnsPolicy, NativeDnsMode};

pub mod policy_diagnostics;

mod resources;
pub use resources::{ResourceConditions, ResourceRule};

mod transport;
pub use transport::{DestinationPorts, TransportConditions, TransportWitness};
