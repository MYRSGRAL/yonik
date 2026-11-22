//! Linux host локального SOCKS. Не меняет системные маршруты, proxy или DNS.

#[cfg(target_os = "linux")]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Закрытый codec milestone; production channel callers подключаются следующим шагом"
    )
)]
pub(crate) mod profile_channel;

#[cfg(target_os = "linux")]
pub mod managed_network;

#[cfg(target_os = "linux")]
mod host;
#[cfg(target_os = "linux")]
pub use host::*;
#[cfg(target_os = "linux")]
mod fetch;
#[cfg(target_os = "linux")]
pub use fetch::*;
#[cfg(target_os = "linux")]
mod credentials;
#[cfg(target_os = "linux")]
pub use credentials::*;
#[cfg(target_os = "linux")]
mod repository;
#[cfg(target_os = "linux")]
pub use repository::*;
#[cfg(target_os = "linux")]
mod subscriptions;
#[cfg(target_os = "linux")]
pub use subscriptions::*;
#[cfg(target_os = "linux")]
mod tcp_batch;
#[cfg(target_os = "linux")]
mod tcp_probe;
#[cfg(target_os = "linux")]
pub use tcp_batch::{TcpBatchResult, TcpBatchTarget, check_tcp_batch};
#[cfg(target_os = "linux")]
pub use tcp_probe::{
    TCP_SERIES_SAMPLES, TcpProbeResult, TcpProbeSeriesResult, TcpProbeStatus, TcpProbeTarget,
    check_tcp, check_tcp_series,
};
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
pub use network::{
    IpPrefix, KernelRoute, LinuxAddress, LinuxLink, LinuxNexthop, LinuxRoute, LinuxRule,
    LinuxTopology, LookupIncomplete, NetworkAttribute, NetworkNamespace, NetworkReadError,
    NexthopMember, NftSocketCgroupMatch, RouteKind, RouteNexthop, RouteQuery, TransportProtocol,
    WireGuardDevice, WireGuardPacketLease, WireGuardPeer, WireGuardReadReceipt,
    WireGuardSocketObservation, WireGuardSocketObserver, WireGuardUdpPath,
    WireGuardUdpRouteSnapshot, local_vpn_split_cidrs, lookup_route, read_nft_socket_cgroup_matches,
    read_topology, read_wireguard_device, read_wireguard_device_observed,
};
#[cfg(target_os = "linux")]
mod resolver;
#[cfg(target_os = "linux")]
pub use network::{
    NetworkCoverage, NetworkMonitor, NetworkMonitorError, NetworkSnapshot, NetworkStamp,
    NetworkWatch,
};
#[cfg(target_os = "linux")]
pub use resolver::*;

#[cfg(target_os = "linux")]
pub mod helper;

#[cfg(target_os = "linux")]
pub mod worker;

#[cfg(target_os = "linux")]
mod subscription_scheduler;
#[cfg(target_os = "linux")]
pub use subscription_scheduler::*;

#[cfg(target_os = "linux")]
pub mod applications;

#[cfg(target_os = "linux")]
mod subscription_policy;

#[cfg(target_os = "linux")]
pub use subscription_policy::{system_subscription_policy, system_subscription_policy_until};

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub mod policy_test_support;

#[cfg(target_os = "linux")]
pub mod presets;
#[cfg(target_os = "linux")]
pub mod system_client;

#[cfg(target_os = "linux")]
pub mod attribution;
#[cfg(target_os = "linux")]
pub mod event_log;

#[cfg(target_os = "linux")]
#[path = "system_client/policy.rs"]
pub mod system_policy;

#[cfg(target_os = "linux")]
pub mod rule_set_custody;

#[cfg(target_os = "linux")]
pub mod rule_set_store;

#[cfg(target_os = "linux")]
pub mod resource_catalog;

#[cfg(target_os = "linux")]
pub mod resource_fd_receiver;

#[cfg(target_os = "linux")]
pub mod bundle_identity;

#[cfg(target_os = "linux")]
pub mod bundle_request;

// Закрытый legacy worker output transport.
#[cfg(target_os = "linux")]
mod output_transport;

#[cfg(target_os = "linux")]
pub mod fake_flow;
