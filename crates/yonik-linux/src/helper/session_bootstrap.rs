//! Подтверждение числового адреса прокси по штатному DNS до запуска TUN.
use super::{DEADLINE, checked_route, diagnostic_result, stale, unavailable, valid_proxy_ip};
use crate::{
    Cancellation, KernelRoute, LinuxTopology, RouteQuery, TransportProtocol,
    attribution::broker::kernel::{Listener, tcp_server_socket},
    helper::{
        ServiceError, memory::ByteBudget, resolver_stub::CaptureCredits,
        systemd_network_service::Daemon,
    },
    managed_network::Ownership,
    network::{RouteCapture, reread_changed_route, same_captured_kernel_route},
    resolver::{
        PlainResolverSnapshot, ResolvConfLayout, ResolverError,
        forward::{
            ForwardResponse, PolicyRrset, boottime_now, dns_question, forward_tcp, forward_udp,
            is_reserved_fake,
        },
        inspect_host_resolv_conf, read_system_resolv_conf,
        resolve1::{Resolve1TunSnapshot, read_bootstrap_resolve1_snapshot},
    },
};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU32,
    os::{fd::AsFd, unix::fs::MetadataExt},
    sync::{LazyLock, atomic::AtomicBool},
    time::{Duration, Instant},
};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use yonik_engine::fake_dns::DomainName;
use yonik_nsfs::socket_namespace::bind_unconnected_private_dns_socket;

pub(super) struct BootstrapAddress {
    source: ResolverSource,
    answers: PolicyRrset,
    routes: Vec<BoundRoute>,
}

#[derive(PartialEq, Eq)]
enum ResolverSource {
    Plain(PlainResolverSnapshot),
    Resolved(ResolvConfLayout, Box<Resolve1TunSnapshot>),
}

const RESOLVED_STUB: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 53), 53);
static STUB_CAPTURE_BUDGET: LazyLock<(ByteBudget, ByteBudget, ByteBudget)> = LazyLock::new(|| {
    (
        ByteBudget::new(16),
        ByteBudget::new(4),
        ByteBudget::new(4 * 65536),
    )
});

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
                let source = diagnostic_result("bootstrap_source", read_source(cancel).await)?;
                let (answers, routes) = match &source {
                    ResolverSource::Plain(plain) => {
                        let &address = plain.nameservers().first().ok_or(ServiceError::Unsupported)?;
                        if !valid_proxy_ip(address) || is_reserved_fake(address) {
                            return Err(ServiceError::Unsupported);
                        }
                        let peer = SocketAddr::new(address, 53);
                        lookup(name, peer, plain, baseline, owner, table, cancel).await?
                    }
                    ResolverSource::Resolved(_, snapshot) => {
                        let daemon = snapshot.daemon.as_ref().ok_or(ServiceError::Unsupported)?;
                        (lookup_resolved(name, owner.namespace(), daemon, cancel).await?, Vec::new())
                    }
                };
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
        if read_source(cancel).await? != self.source {
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

async fn read_source(cancel: &mut Cancellation) -> Result<ResolverSource, ServiceError> {
    let (layout, plain) = tokio::task::spawn_blocking(|| {
        let layout = inspect_host_resolv_conf();
        let plain = (layout == ResolvConfLayout::RegularFile)
            .then(read_system_resolv_conf)
            .transpose()
            .map_err(resolver_error)?;
        Ok::<_, ServiceError>((layout, plain))
    })
    .await
    .map_err(unavailable)??;
    if let Some(plain) = plain {
        if !plain.is_resolved_stub() {
            return Ok(ResolverSource::Plain(plain));
        }
    } else if !matches!(
        layout,
        ResolvConfLayout::ResolvedStub
            | ResolvConfLayout::ResolvedStaticStub
            | ResolvConfLayout::ResolvedUplink
    ) {
        return Err(ServiceError::Unsupported);
    }
    let snapshot = diagnostic_result(
        "bootstrap_resolve1_snapshot",
        read_bootstrap_resolve1_snapshot(cancel, DEADLINE).await,
    )
    .map_err(resolver_error)?;
    Ok(ResolverSource::Resolved(layout, Box::new(snapshot)))
}

async fn lookup_resolved(
    name: &DomainName,
    namespace: (u64, u64),
    daemon: &Daemon,
    cancel: &mut Cancellation,
) -> Result<PolicyRrset, ServiceError> {
    let peer = SocketAddr::V4(RESOLVED_STUB);
    let mut stream = diagnostic_result("bootstrap_stub_connect", TcpStream::connect(peer).await)
        .map_err(unavailable)?;
    let SocketAddr::V4(client) = stream.local_addr().map_err(unavailable)? else {
        return Err(ServiceError::Unsupported);
    };
    if !client.ip().is_loopback() || stream.peer_addr().map_err(unavailable)? != peer {
        return Err(ServiceError::Unsupported);
    }
    let start = Instant::now();
    let first = loop {
        if let Some(socket) = capture_stub_peer(client, namespace).await? {
            check_stub_peer(socket, daemon)?;
            break socket;
        }
        if start.elapsed() >= Duration::from_millis(150) {
            return Err(ServiceError::Unavailable);
        }
        cancel.check().map_err(|_| ServiceError::Cancelled)?;
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let a = forward_tcp(&mut stream, peer, &dns_question(name, 1), DEADLINE, cancel)
        .await
        .map_err(resolver_error)?;
    let aaaa = forward_tcp(&mut stream, peer, &dns_question(name, 28), DEADLINE, cancel)
        .await
        .map_err(resolver_error)?;
    let last = capture_stub_peer(client, namespace)
        .await?
        .ok_or_else(stale)?;
    check_stub_peer(last, daemon)?;
    if (first.inode, first.cookie) != (last.inode, last.cookie) {
        return Err(stale());
    }
    a.reject_addresses(is_reserved_fake)
        .map_err(resolver_error)?;
    aaaa.reject_addresses(is_reserved_fake)
        .map_err(resolver_error)?;
    a.policy_address_pair(&aaaa).map_err(resolver_error)
}

fn check_stub_peer(socket: Listener, daemon: &Daemon) -> Result<(), ServiceError> {
    if socket.uid != daemon.uid || socket.cgroup != daemon.group.1.get() || socket.inode == 0 {
        return Err(ServiceError::Unsupported);
    }
    Ok(())
}

async fn capture_stub_peer(
    client: SocketAddrV4,
    namespace: (u64, u64),
) -> Result<Option<Listener>, ServiceError> {
    let (fds, pending, bytes) = &*STUB_CAPTURE_BUDGET;
    let credits = CaptureCredits::reserve_shared(fds, pending, bytes).map_err(unavailable)?;
    tokio::task::spawn_blocking(move || {
        diagnostic_result(
            "bootstrap_stub_peer",
            tcp_server_socket(
                RESOLVED_STUB,
                client,
                namespace,
                Instant::now() + DEADLINE,
                &AtomicBool::new(false),
                &credits,
            ),
        )
        .map_err(unavailable)
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
