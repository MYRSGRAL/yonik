//! Подтверждение числового адреса прокси по штатному DNS до запуска TUN.
use super::{DEADLINE, checked_route, stale, unavailable, valid_proxy_ip};
use crate::{
    Cancellation, KernelRoute, LinuxTopology, RouteQuery, TransportProtocol,
    helper::ServiceError,
    managed_network::Ownership,
    network::{RouteCapture, reread_changed_route, same_captured_kernel_route},
    resolver::{
        PlainResolverSnapshot, ResolvConfLayout, ResolverError,
        forward::{
            ForwardResponse, PolicyRrset, boottime_now, dns_question, forward_tcp, forward_udp,
            is_reserved_fake,
        },
        inspect_host_resolv_conf, read_system_resolv_conf,
    },
};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    os::{fd::AsFd, unix::fs::MetadataExt},
    time::{Duration, Instant},
};
use tokio::net::{TcpSocket, UdpSocket};
use yonik_engine::fake_dns::DomainName;
use yonik_nsfs::socket_namespace::bind_unconnected_private_dns_socket;

pub(super) struct BootstrapAddress {
    source: PlainResolverSnapshot,
    answers: PolicyRrset,
    routes: Vec<BoundRoute>,
}

impl BootstrapAddress {
    pub(super) async fn resolve(
        name: &DomainName,
        private: &BTreeSet<String>,
        baseline: &LinuxTopology,
        owner: Ownership,
        table: u32,
        cancel: &mut Cancellation,
    ) -> Result<Self, ServiceError> {
        if !permits_name(name, private)
            || baseline
                .links
                .iter()
                .any(|link| link.kind.as_deref() == Some(b"wireguard"))
        {
            return Err(ServiceError::Unsupported);
        }
        let mut stop = cancel.clone();
        tokio::select! {
            biased;
            _ = stop.cancelled() => Err(ServiceError::Cancelled),
            result = tokio::time::timeout(DEADLINE, async {
                let source = read_source().await?;
                let &address = source.nameservers().first().ok_or(ServiceError::Unsupported)?;
                if !valid_proxy_ip(address) || is_reserved_fake(address) {
                    return Err(ServiceError::Unsupported);
                }
                let peer = SocketAddr::new(address, 53);
                let (answers, routes) = lookup(name, peer, &source, baseline, owner, table, cancel).await?;
                let proof = Self { source, answers, routes };
                proof.verify(cancel).await?;
                Ok(proof)
            }) => result.map_err(unavailable)?,
        }
    }

    pub(super) fn addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.answers
            .addresses()
            .iter()
            .copied()
            .filter(|&ip| valid_proxy_ip(ip))
    }

    pub(super) fn check_fresh(&self) -> Result<(), ServiceError> {
        if fresh(
            self.answers.valid_until(),
            self.answers.boot_valid_until(),
            Instant::now(),
            boottime_now().ok_or_else(stale)?,
        ) {
            Ok(())
        } else {
            Err(stale())
        }
    }

    pub(super) async fn verify(&self, cancel: &mut Cancellation) -> Result<(), ServiceError> {
        self.check_fresh()?;
        if read_source().await? != self.source {
            return Err(stale());
        }
        for route in &self.routes {
            route.verify(cancel).await?;
        }
        self.check_fresh()
    }
}

fn fresh(valid_until: Instant, boot_valid_until: Duration, now: Instant, boot: Duration) -> bool {
    now < valid_until && boot < boot_valid_until
}

fn permits_name(name: &DomainName, private: &BTreeSet<String>) -> bool {
    let name = name.as_str();
    name.contains('.')
        && std::iter::once(name)
            .chain(name.match_indices('.').map(|(index, _)| &name[index + 1..]))
            .all(|suffix| {
                !matches!(suffix, "local" | "localhost" | "home.arpa" | "onion")
                    && !private.contains(suffix)
            })
}

async fn read_source() -> Result<PlainResolverSnapshot, ServiceError> {
    tokio::task::spawn_blocking(|| {
        if inspect_host_resolv_conf() != ResolvConfLayout::RegularFile {
            return Err(ServiceError::Unsupported);
        }
        read_system_resolv_conf().map_err(resolver_error)
    })
    .await
    .map_err(unavailable)?
}

struct BoundRoute {
    kernel: KernelRoute,
    capture: RouteCapture,
    index: NonZeroU32,
}

impl BoundRoute {
    async fn capture(
        peer: SocketAddr,
        protocol: TransportProtocol,
        baseline: &LinuxTopology,
        owner: Ownership,
        table: u32,
        cancel: &mut Cancellation,
    ) -> Result<Self, ServiceError> {
        let query = RouteQuery::new(peer.ip(), 0).with_transport(protocol, None, Some(peer.port()));
        let (kernel, capture) = reread_changed_route(query, cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        let index = checked_route(&kernel, owner, table)?;
        if !super::session_fake_dns::usable_resolver_link(baseline, index) {
            return Err(ServiceError::Unsupported);
        }
        let index = NonZeroU32::new(index).ok_or(ServiceError::Unsupported)?;
        Ok(Self {
            kernel,
            capture,
            index,
        })
    }

    fn bind(&self, socket: &impl AsFd) -> Result<(), ServiceError> {
        let namespace = std::fs::metadata("/proc/thread-self/ns/net").map_err(unavailable)?;
        if (namespace.dev(), namespace.ino())
            != (self.kernel.namespace.device, self.kernel.namespace.inode)
            || rustix::fs::fstat(socket).map_err(unavailable)?.st_uid != 0
        {
            return Err(ServiceError::Unsupported);
        }
        bind_unconnected_private_dns_socket(socket, self.index, 0).map_err(unavailable)
    }

    async fn verify(&self, cancel: &mut Cancellation) -> Result<(), ServiceError> {
        let (current, capture) = reread_changed_route(self.kernel.query.clone(), cancel, DEADLINE)
            .await
            .map_err(unavailable)?;
        if !same_captured_kernel_route(&self.kernel, &current, Some((self.capture, capture))) {
            return Err(stale());
        }
        Ok(())
    }
}

async fn lookup(
    name: &DomainName,
    peer: SocketAddr,
    source: &PlainResolverSnapshot,
    baseline: &LinuxTopology,
    owner: Ownership,
    table: u32,
    cancel: &mut Cancellation,
) -> Result<(PolicyRrset, Vec<BoundRoute>), ServiceError> {
    let mut routes = Vec::with_capacity(2);
    for protocol in [TransportProtocol::Udp, TransportProtocol::Tcp] {
        if source.bootstrap_tcp_only() && protocol == TransportProtocol::Udp {
            continue;
        }
        let route = BoundRoute::capture(peer, protocol, baseline, owner, table, cancel).await?;
        let first = query(name, 1, peer, protocol, &route, cancel).await?;
        if first.truncated() {
            routes.push(route);
            continue;
        }
        let second = if source.bootstrap_ipv6_enabled() {
            Some(query(name, 28, peer, protocol, &route, cancel).await?)
        } else {
            None
        };
        routes.push(route);
        if second.as_ref().is_some_and(ForwardResponse::truncated) {
            continue;
        }
        let answers = match second {
            Some(second) => first.policy_address_pair(&second),
            None => first.policy_rrset(),
        }
        .map_err(resolver_error)?;
        return Ok((answers, routes));
    }
    Err(ServiceError::Unsupported)
}

async fn query(
    name: &DomainName,
    kind: u16,
    peer: SocketAddr,
    protocol: TransportProtocol,
    route: &BoundRoute,
    cancel: &mut Cancellation,
) -> Result<ForwardResponse, ServiceError> {
    let question = dns_question(name, kind);
    let response = match protocol {
        TransportProtocol::Udp => {
            let local = if peer.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = std::net::UdpSocket::bind(local).map_err(unavailable)?;
            route.bind(&socket)?;
            socket.set_nonblocking(true).map_err(unavailable)?;
            let socket = UdpSocket::from_std(socket).map_err(unavailable)?;
            socket.connect(peer).await.map_err(unavailable)?;
            route.verify(cancel).await?;
            forward_udp(&socket, peer, &question, DEADLINE, cancel).await
        }
        TransportProtocol::Tcp => {
            let socket = if peer.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
            .map_err(unavailable)?;
            route.bind(&socket)?;
            let mut stream = socket.connect(peer).await.map_err(unavailable)?;
            route.verify(cancel).await?;
            forward_tcp(&mut stream, peer, &question, DEADLINE, cancel).await
        }
    }
    .map_err(resolver_error)?;
    response
        .reject_addresses(is_reserved_fake)
        .map_err(resolver_error)?;
    Ok(response)
}

fn resolver_error(error: ResolverError) -> ServiceError {
    match error {
        ResolverError::Cancelled => ServiceError::Cancelled,
        ResolverError::NetworkChanged => stale(),
        ResolverError::Unsupported | ResolverError::Untrusted => ServiceError::Unsupported,
        _ => ServiceError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_expires_if_either_clock_reaches_the_deadline() {
        let now = Instant::now();
        let boot = Duration::from_secs(100);
        let expires = Duration::from_secs(20);
        let until = now + expires;
        let boot_until = boot + expires;
        assert!(fresh(until, boot_until, now, boot));
        assert!(!fresh(until, boot_until, until, boot));
        assert!(!fresh(until, boot_until, now, boot_until));
    }

    #[test]
    fn bootstrap_protects_private_suffixes_and_locally_resolved_names() {
        let private = BTreeSet::from(["corp.example".to_owned()]);
        for name in [
            "host",
            "host.local",
            "host.home.arpa",
            "corp.example",
            "a.corp.example",
        ] {
            assert!(!permits_name(&name.parse().unwrap(), &private));
        }
        for name in ["proxy.example", "a.notcorp.example"] {
            assert!(permits_name(&name.parse().unwrap(), &private));
        }
    }
}
