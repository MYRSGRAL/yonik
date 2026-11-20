//! Жизненный цикл DNS-тракта, привязанного к одному принадлежащему helper TUN.
use super::{
    ServiceError, SessionNetworkPlan,
    protection_host::{ARPHRD_ETHER, IFF_UP},
    session_network::MAX_RESOLVER_RULES,
    systemd_network_service::Daemon,
};
use crate::{
    Cancellation, NetworkReadError, RouteQuery, TransportProtocol,
    fake_flow::WorkerOnlyLoopbackIsolation,
    fake_service::{FakeDnsBridgeListeners, FakeDnsLeases, MAX_FAKE_TTL},
    managed_network::{Journal, firewall::BoundDirect},
    network::{LinuxTopology, reread_changed_route},
    resolver::{
        PlainResolverSnapshot, ResolvConfLayout, ResolverError, SYSTEM_RESOLV_CONF,
        dot::{DotPeer, DotPolicy, SystemDotTrust},
        file_watch::ResolverFileWatch,
        forward::forward_query_name,
        inspect_host_resolv_conf,
        plain_relay::{PlainDnsRelay, TCP_IDLE, relay_paths},
        plain_resolver_path,
        resolve1::{
            Resolve1Domain, Resolve1Endpoint, Resolve1Prepared, Resolve1Scope, Resolve1Socket,
            Resolve1Transport, Resolve1TunSnapshot, apply_link_dns, prepare_fallback_link_dns,
            prepare_link_dns, read_resolve1_tun_snapshot,
        },
    },
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    num::{NonZeroU16, NonZeroU32},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Notify,
    task::JoinHandle,
    time::timeout,
};
use yonik_engine::{
    SystemFakeDnsBridge,
    fake_dns::{
        DnsEpoch, DomainName, FakeDnsQuestion, FakeIpLeaseTable, SYSTEM_FAKE_DNS_PROBE_NAME,
    },
};

pub(super) use crate::managed_network::FAKE_POOLS as POOLS;
const LIMIT: Duration = Duration::from_secs(3);
const DNS_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
const FIRST_DYNAMIC_PORT: u16 = 49152;
const DNS_PROBE_RETRY: Duration = Duration::from_millis(200);
pub(super) const HOLD_MS: u32 = 90_000;
const REFRESH_BEFORE: Duration = Duration::from_secs(60);
const REFRESH_CHECK: Duration = Duration::from_secs(20);
const MAX_SUFFIXES: usize = 32;
const DNS_PROBE: &[u8] =
    b"\x11\x27\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05probe\x07invalid\x00\x00\x01\x00\x01";

#[derive(Clone, PartialEq, Eq)]
enum ResolverSource {
    Resolved(Option<PlainResolverSnapshot>),
    ResolvedUplink,
    Literal(PlainResolverSnapshot, &'static str),
}

impl ResolverSource {
    fn watch_file(&self) -> Result<Option<ResolverFileWatch>, ServiceError> {
        let host_entry = Path::new(SYSTEM_RESOLV_CONF);
        let source = match *self {
            Self::Literal(_, source) => Path::new(source),
            Self::ResolvedUplink => host_entry,
            Self::Resolved(_) => return Ok(None),
        };
        let paths = [host_entry, source];
        ResolverFileWatch::new(if source == host_entry {
            &paths[..1]
        } else {
            &paths
        })
        .map(Some)
        .map_err(|_| ServiceError::Unavailable)
    }
}

async fn resolver_source() -> Result<ResolverSource, ServiceError> {
    #[cfg(feature = "test-support")]
    if std::env::var("YONIK_TEST_LITERAL_DNS").as_deref() == Ok("1") {
        return tokio::task::spawn_blocking(crate::resolver::read_fixture_dns_source)
            .await
            .map_err(|_| ServiceError::Unavailable)?
            .map(|snapshot| ResolverSource::Literal(snapshot, crate::resolver::FIXTURE_DNS_SOURCE))
            .map_err(|_| ServiceError::Unsupported);
    }
    match inspect_host_resolv_conf() {
        ResolvConfLayout::ResolvedStub | ResolvConfLayout::ResolvedStaticStub => {
            Ok(ResolverSource::Resolved(None))
        }
        ResolvConfLayout::ResolvedUplink => Ok(ResolverSource::ResolvedUplink),
        layout @ (ResolvConfLayout::RegularFile
        | ResolvConfLayout::NetworkManager
        | ResolvConfLayout::Resolvconf) => {
            let result = tokio::task::spawn_blocking(move || {
                if layout == ResolvConfLayout::RegularFile {
                    crate::read_system_resolv_conf()
                } else {
                    crate::resolver::read_managed_resolv_conf(layout)
                }
            })
            .await;
            #[cfg(feature = "test-support")]
            if std::env::var("YONIK_SESSION_DIAGNOSTICS").as_deref() == Ok("1") {
                eprintln!("plain resolved stub: {result:?}");
            }
            let snapshot = result
                .map_err(|_| ServiceError::Unavailable)?
                .map_err(|_| ServiceError::Unsupported)?;
            if snapshot.is_resolved_stub() {
                Ok(ResolverSource::Resolved(Some(snapshot)))
            } else {
                let source = plain_resolver_path(layout).ok_or(ServiceError::Unsupported)?;
                Ok(ResolverSource::Literal(snapshot, source))
            }
        }
        _ => Err(ServiceError::Unsupported),
    }
}

pub(super) fn canonical_suffixes(input: &[String]) -> Result<Vec<String>, ServiceError> {
    if input.is_empty() || input.len() > MAX_SUFFIXES {
        return Err(ServiceError::InvalidRequest);
    }
    let mut names = input
        .iter()
        .map(|text| {
            text.parse::<DomainName>()
                .map(|name| name.as_str().to_owned())
                .map_err(|_| ServiceError::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_unstable();
    names.dedup();
    Ok(names)
}

pub(super) struct FakeDnsState {
    started_at: Instant,
    reuse_delay: Duration,
    leases: Option<Arc<FakeDnsLeases>>,
}

#[derive(Clone)]
pub(super) struct PublicationHorizon(Arc<Mutex<Instant>>);

impl PublicationHorizon {
    pub fn new(until: Instant) -> Self {
        Self(Arc::new(Mutex::new(until)))
    }

    fn remaining(&self) -> Duration {
        self.0
            .lock()
            .map(|until| until.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::ZERO)
    }

    fn can_issue(&self) -> bool {
        // Учитываем самый долгий путь записи ответа и округление expires в nft.
        self.remaining() >= MAX_FAKE_TTL + TCP_IDLE + Duration::from_secs(1)
    }

    pub fn needs_refresh(&self) -> bool {
        self.remaining() <= REFRESH_BEFORE
    }

    pub fn extend(&self, confirmed: Instant) -> Result<(), ServiceError> {
        *self.0.lock().map_err(|_| ServiceError::Unavailable)? = confirmed;
        Ok(())
    }

    pub fn constrain(&self, observed: Instant) -> Result<(), ServiceError> {
        let mut until = self.0.lock().map_err(|_| ServiceError::Unavailable)?;
        *until = (*until).min(observed);
        Ok(())
    }
}

impl FakeDnsState {
    pub fn new(startup_journal: Option<&Journal>) -> Self {
        // Даже незавершённый карантин сохраняет задержку после перезапуска.
        // Фиксируем её до того, как восстановление может очистить запись.
        let reuse_delay = if startup_journal.and_then(Journal::fake_quarantine).is_some() {
            MAX_FAKE_TTL
        } else {
            Duration::ZERO
        };
        Self {
            started_at: Instant::now(),
            reuse_delay,
            leases: None,
        }
    }

    pub fn check_cold_start(&self) -> Result<(), ServiceError> {
        if self.started_at.elapsed() >= self.reuse_delay {
            Ok(())
        } else {
            Err(ServiceError::Busy)
        }
    }

    pub fn leases(&mut self) -> Result<Arc<FakeDnsLeases>, ServiceError> {
        self.check_cold_start()?;
        if let Some(leases) = &self.leases {
            return Ok(Arc::clone(leases));
        }
        let leases = Arc::new(make_leases(self.started_at, self.reuse_delay)?);
        self.leases = Some(Arc::clone(&leases));
        Ok(leases)
    }
}

fn make_leases(started_at: Instant, reuse_delay: Duration) -> Result<FakeDnsLeases, ServiceError> {
    let (IpAddr::V4(v4), IpAddr::V6(v6)) = (POOLS[0].0, POOLS[1].0) else {
        return Err(ServiceError::Unavailable);
    };
    let v4_addresses = (1..(1 << (32 - POOLS[0].1)) - 1)
        .map(|offset| Ipv4Addr::from(u32::from(v4) + offset).into());
    let v6_addresses =
        (1..(1 << (128 - POOLS[1].1))).map(|offset| Ipv6Addr::from(u128::from(v6) + offset).into());
    let table = FakeIpLeaseTable::new(v4_addresses.chain(v6_addresses))
        .map_err(|_| ServiceError::Unavailable)?;
    Ok(FakeDnsLeases::with_startup_quarantine(
        table,
        started_at,
        reuse_delay,
    ))
}

pub(super) struct PreparedFakeDns {
    pub config: SystemFakeDnsBridge,
    pub loopback: Ipv4Addr,
    pub direct_egress: Vec<BoundDirect>,
    marker: IpAddr,
    suffixes: Vec<String>,
    private_dns_zones: BTreeSet<String>,
    listeners: Mutex<Option<FakeDnsBridgeListeners>>,
    source: ResolverSource,
    resolved: Option<Arc<Resolve1TunSnapshot>>,
    cidr_policy: Option<Arc<yonik_engine::policy_wire::SystemPolicy>>,
    tls_peers: Vec<ResolverPeer>,
    plain: Vec<SessionResolverRelay>,
}

struct SessionResolverRelay {
    relay: PlainDnsRelay,
    binding: ResolverBinding,
    client: SocketAddr,
}

type ResolverPeer = (SocketAddr, TransportProtocol, Option<u32>);

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct ResolverBinding {
    scope_link: Option<u32>,
    route_link: Option<u32>,
    split_only: bool,
}

impl ResolverBinding {
    fn resolved(endpoint: &Resolve1Endpoint, socket: &Resolve1Socket) -> Self {
        Self {
            scope_link: match endpoint.scope {
                Resolve1Scope::Global => None,
                Resolve1Scope::Link(index) => Some(index),
            },
            route_link: socket.route_link,
            split_only: !socket.default_route,
        }
    }

    fn permits_synthetic(self, source: &ResolverSource, name: &str) -> bool {
        // Встроенная проверка по зарезервированному имени подтверждает путь
        // релея, даже когда uplink-файл не публикует его DNS-адрес.
        !self.split_only
            || !matches!(source, ResolverSource::ResolvedUplink)
            || name == SYSTEM_FAKE_DNS_PROBE_NAME
    }
}

pub(super) fn usable_resolver_link(topology: &LinuxTopology, index: u32) -> bool {
    topology.links.iter().any(|link| {
        link.index == index
            && link.link_type == ARPHRD_ETHER
            && link.flags & IFF_UP != 0
            && matches!(
                link.kind.as_deref(),
                None | Some(b"veth" | b"vlan" | b"bridge" | b"bond" | b"team")
            )
    })
}

fn resolved_peers(
    snapshot: &Resolve1TunSnapshot,
    topology: &LinuxTopology,
) -> Vec<(SocketAddr, ResolverBinding)> {
    let mut scopes = BTreeMap::<_, BTreeSet<_>>::new();
    for (endpoint, socket) in snapshot.config.endpoints.iter().zip(&snapshot.sockets) {
        if socket.transport != Resolve1Transport::Plain {
            continue;
        }
        scopes
            .entry(SocketAddr::new(endpoint.address, endpoint.port))
            .or_default()
            .insert(ResolverBinding::resolved(endpoint, socket));
    }
    scopes
        .into_iter()
        .filter_map(|(peer, scopes)| {
            let binding = *scopes.first()?;
            let address = peer.ip();
            (scopes.len() == 1
                && !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local())
                && binding
                    .route_link
                    .is_none_or(|index| usable_resolver_link(topology, index)))
            .then_some((peer, binding))
        })
        .collect()
}

async fn fallback_peer_reachable(
    peer: SocketAddr,
    mark: u32,
    tls: bool,
    plain: Option<SocketAddr>,
    cancel: &mut Cancellation,
) -> Result<bool, ServiceError> {
    for (peer, protocol) in relay_paths(peer, tls, plain) {
        let query = RouteQuery::new(peer.ip(), 0)
            .with_mark(mark)
            .with_transport(protocol, None, Some(peer.port()));
        match reread_changed_route(query, cancel, LIMIT).await {
            Ok(_) => {}
            Err(NetworkReadError::Kernel(errno))
                if errno == rustix::io::Errno::NETUNREACH.raw_os_error() =>
            {
                return Ok(false);
            }
            Err(NetworkReadError::Cancelled) => return Err(ServiceError::Cancelled),
            Err(_) => return Err(ServiceError::Unavailable),
        }
    }
    Ok(true)
}

fn fallback_tls(snapshot: &Resolve1TunSnapshot) -> Option<Resolve1Transport> {
    let mode = snapshot.global_transport?;
    (mode != Resolve1Transport::Plain
        && snapshot.fallback_only
        && !snapshot.sockets.is_empty()
        && snapshot
            .sockets
            .iter()
            .all(|socket| socket.transport == mode))
    .then_some(mode)
}

fn plaintext_peer(endpoint: &Resolve1Endpoint) -> SocketAddr {
    let port = if endpoint.port_inferred {
        DNS_PORT
    } else {
        endpoint.port
    };
    SocketAddr::new(endpoint.address, port)
}

async fn resolver_dot_policy(mode: Resolve1Transport) -> Result<DotPolicy, ServiceError> {
    match mode {
        Resolve1Transport::StrictTls => SystemDotTrust::load()
            .await
            .map(DotPolicy::Strict)
            .map_err(|_| ServiceError::Unavailable),
        Resolve1Transport::OpportunisticTls => {
            DotPolicy::opportunistic().map_err(|_| ServiceError::Unsupported)
        }
        Resolve1Transport::Plain => Err(ServiceError::Unsupported),
    }
}

async fn tls_relay(
    loopback: Ipv4Addr,
    mark: NonZeroU32,
    endpoint: &Resolve1Endpoint,
    socket: &Resolve1Socket,
    policy: &DotPolicy,
) -> Result<PlainDnsRelay, ServiceError> {
    let peer = SocketAddr::new(endpoint.address, endpoint.port);
    let dot = DotPeer::new(policy.clone(), peer.ip(), socket.server_name())
        .map_err(|_| ServiceError::Unsupported)?;
    let plain =
        (socket.transport == Resolve1Transport::OpportunisticTls).then(|| plaintext_peer(endpoint));
    PlainDnsRelay::bind(loopback, peer, mark)
        .await
        .map(|relay| relay.with_dot(dot, plain))
        .map_err(|_| ServiceError::Unavailable)
}

async fn uplink_tls_relays(
    snapshot: &Resolve1TunSnapshot,
    loopback: Ipv4Addr,
    mark: NonZeroU32,
    remaining: usize,
) -> Result<Vec<SessionResolverRelay>, ServiceError> {
    let mut endpoints = BTreeMap::new();
    let mut candidates = Vec::new();
    for (endpoint, socket) in snapshot.config.endpoints.iter().zip(&snapshot.sockets) {
        // Uplink-файл публикует DNS на стандартном порту, даже если resolved
        // по умолчанию обращается к тому же серверу через TLS на порту 853.
        if !socket.default_route || (!endpoint.port_inferred && endpoint.port != DNS_PORT) {
            continue;
        }
        let client = SocketAddr::new(endpoint.address, DNS_PORT);
        let encrypted = socket.transport != Resolve1Transport::Plain;
        if endpoints
            .insert(client, encrypted)
            .is_some_and(|previous| previous || encrypted)
        {
            // Uplink-клиент не передаёт область DNS или имя TLS-сервера.
            return Err(ServiceError::Unsupported);
        }
        if encrypted {
            candidates.push((client, endpoint, socket));
        }
    }
    if candidates.len() > remaining {
        return Err(ServiceError::Unsupported);
    }
    let mut strict = None;
    let mut opportunistic = None;
    let mut relays = Vec::with_capacity(candidates.len());
    for (client, endpoint, socket) in candidates {
        let policy = if socket.transport == Resolve1Transport::StrictTls {
            &mut strict
        } else {
            &mut opportunistic
        };
        if policy.is_none() {
            *policy = Some(resolver_dot_policy(socket.transport).await?);
        }
        let relay = tls_relay(
            loopback,
            mark,
            endpoint,
            socket,
            policy.as_ref().ok_or(ServiceError::Unavailable)?,
        )
        .await?;
        relays.push(SessionResolverRelay {
            relay,
            binding: ResolverBinding::resolved(endpoint, socket),
            client,
        });
    }
    Ok(relays)
}

async fn verify_resolved_baseline(
    expected: &Resolve1TunSnapshot,
    own_link: Option<u32>,
) -> Result<(), ServiceError> {
    let (_owner, mut cancel) = Cancellation::new();
    let current = read_resolve1_tun_snapshot(&mut cancel, LIMIT, own_link)
        .await
        .map_err(|_| ServiceError::Unavailable)?;
    if &current != expected {
        return Err(ServiceError::Unavailable);
    }
    Ok(())
}

fn native_resolver_peers(
    snapshot: &Resolve1TunSnapshot,
) -> Result<Vec<ResolverPeer>, ServiceError> {
    use Resolve1Transport::{OpportunisticTls, Plain, StrictTls};
    let strict = snapshot
        .sockets
        .iter()
        .any(|socket| socket.transport == StrictTls);
    let opportunistic = snapshot
        .sockets
        .iter()
        .any(|socket| socket.transport == OpportunisticTls);
    if !strict && !opportunistic {
        return Ok(Vec::new());
    }
    if fallback_tls(snapshot).is_some() {
        return Ok(Vec::new());
    }
    // На старых resolved проверка сертификата зависит от глобального режима.
    // FallbackDNS теряет свою область при появлении DNS на новом линке.
    if snapshot.fallback_only
        || (strict && snapshot.global_transport != Some(StrictTls))
        || snapshot.daemon.is_none()
    {
        return Err(ServiceError::Unsupported);
    }
    let mut plain = BTreeSet::new();
    let mut tls = BTreeMap::new();
    for (endpoint, socket) in snapshot.config.endpoints.iter().zip(&snapshot.sockets) {
        let peer = SocketAddr::new(endpoint.address, endpoint.port);
        if socket.transport == Plain {
            plain.insert(peer);
            continue;
        }
        let fallback = plaintext_peer(endpoint);
        let candidates = [
            (peer, TransportProtocol::Tcp),
            (fallback, TransportProtocol::Tcp),
            (fallback, TransportProtocol::Udp),
        ];
        let count = if socket.transport == OpportunisticTls {
            candidates.len()
        } else {
            1
        };
        for &candidate in &candidates[..count] {
            if tls
                .insert(candidate, socket.route_link)
                .is_some_and(|previous| previous != socket.route_link)
            {
                return Err(ServiceError::Unsupported);
            }
        }
    }
    if tls.len() > MAX_RESOLVER_RULES || tls.keys().any(|(peer, _)| plain.contains(peer)) {
        return Err(ServiceError::Unsupported);
    }
    Ok(tls
        .into_iter()
        .map(|((peer, protocol), link)| (peer, protocol, link))
        .collect())
}

fn permits_resolver_name(domains: &[Resolve1Domain], name: &str, link: Option<u32>) -> bool {
    let scope = link.map_or(Resolve1Scope::Global, Resolve1Scope::Link);
    let mut best = None;
    let mut permitted = true;
    for domain in domains {
        let suffix = domain.name.trim_end_matches('.');
        let Some(start) = name.len().checked_sub(suffix.len()) else {
            continue;
        };
        if !suffix.is_empty()
            && !(name
                .get(start..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
                && (start == 0 || name.as_bytes()[start - 1] == b'.'))
        {
            continue;
        }
        if best.is_none_or(|length| suffix.len() > length) {
            best = Some(suffix.len());
            permitted = domain.scope == scope;
        } else if best == Some(suffix.len()) {
            permitted |= domain.scope == scope;
        }
    }
    permitted
}

fn wireguard_dns_zones(domains: &[Resolve1Domain], wireguard: &BTreeSet<u32>) -> BTreeSet<String> {
    domains
        .iter()
        .filter(|domain| matches!(domain.scope, Resolve1Scope::Link(index) if wireguard.contains(&index)))
        .map(|domain| domain.name.trim_end_matches('.'))
        // Маршрут ~. выбирает DNS по умолчанию и не объявляет внутреннюю зону.
        .filter(|name| !name.is_empty())
        .map(|name| {
            name.parse::<DomainName>()
                .map(|domain| domain.as_str().to_owned())
                .unwrap_or_else(|_| name.to_ascii_lowercase())
        })
        .collect()
}

fn name_in_dns_zone(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

impl PreparedFakeDns {
    pub async fn new(
        plan: &SessionNetworkPlan,
        topology: &LinuxTopology,
        suffixes: Vec<String>,
        direct_egress: Vec<BoundDirect>,
        policy_resolver: Option<SocketAddr>,
        cidr_policy: Option<Arc<yonik_engine::policy_wire::SystemPolicy>>,
        cancel: &mut Cancellation,
    ) -> Result<Self, ServiceError> {
        let source = resolver_source().await?;
        let mut random = [0; 3];
        getrandom::getrandom(&mut random).map_err(|_| ServiceError::Unavailable)?;
        let loopback = Ipv4Addr::new(127, 64 | (random[0] & 63), random[1], random[2]);
        let listeners = FakeDnsBridgeListeners::bind(loopback)
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        let [dns_port, lookup_port] = listeners.ports().map_err(|_| ServiceError::Unavailable)?;
        let temporary = TcpListener::bind(SocketAddrV4::new(loopback, 0))
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        let reinject_port = temporary
            .local_addr()
            .ok()
            .and_then(|address| NonZeroU16::new(address.port()))
            .ok_or(ServiceError::Unavailable)?;
        let marker = plan
            .fake_dns_marker()
            .map_err(|_| ServiceError::Unavailable)?;
        let pools = POOLS
            .iter()
            .map(|(address, length)| format!("{address}/{length}").parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ServiceError::Unavailable)?;
        let mut config =
            SystemFakeDnsBridge::new(marker, pools, dns_port, lookup_port, reinject_port)
                .and_then(|config| config.with_isolated_loopback(loopback))
                .map_err(|_| ServiceError::Unavailable)?;
        if let Some(upstream) = policy_resolver {
            config = config
                .with_policy_resolver(upstream)
                .map_err(|_| ServiceError::InvalidRequest)?;
        }
        if cidr_policy.is_some() {
            config = config
                .with_resolved_cidr_policy()
                .map_err(|_| ServiceError::Unavailable)?;
        }
        let resolved = if matches!(
            source,
            ResolverSource::Resolved(_) | ResolverSource::ResolvedUplink
        ) {
            config = config.reject_unbound_system_dns();
            let snapshot = read_resolve1_tun_snapshot(cancel, LIMIT, None)
                .await
                .map_err(|_| ServiceError::Unavailable)?;
            Some(Arc::new(snapshot))
        } else {
            None
        };
        let private_dns_zones = resolved.as_ref().map_or_else(BTreeSet::new, |snapshot| {
            let wireguard = topology
                .links
                .iter()
                .filter(|link| link.kind.as_deref() == Some(b"wireguard"))
                .map(|link| link.index)
                .collect();
            wireguard_dns_zones(&snapshot.config.domains, &wireguard)
        });
        let tls_peers = resolved
            .as_deref()
            .map(native_resolver_peers)
            .transpose()?
            .unwrap_or_default();
        let mut upstreams = match (&source, &resolved) {
            (ResolverSource::Literal(snapshot, _), _) => snapshot
                .nameservers()
                .iter()
                .map(|&address| {
                    (
                        SocketAddr::new(address, DNS_PORT),
                        ResolverBinding::default(),
                    )
                })
                .collect(),
            (_, Some(snapshot)) => resolved_peers(snapshot, topology),
            _ => return Err(ServiceError::Unavailable),
        };
        if upstreams.len() > SystemFakeDnsBridge::MAX_PLAIN_DNS_PEERS {
            return Err(ServiceError::Unsupported);
        }
        if resolved.as_ref().is_some_and(|snapshot| {
            snapshot
                .config
                .endpoints
                .iter()
                .zip(&snapshot.sockets)
                .any(|(endpoint, socket)| {
                    socket.transport == Resolve1Transport::Plain
                        && endpoint.port != DNS_PORT
                        && !upstreams.iter().any(|(peer, _)| {
                            peer.ip() == endpoint.address && peer.port() == endpoint.port
                        })
                })
        }) {
            // Обычная блокировка DNS на порту 53 не защищает такой сервер.
            return Err(ServiceError::Unsupported);
        }
        let fallback_mode = resolved.as_deref().and_then(fallback_tls);
        if let Some(snapshot) = resolved.as_ref().filter(|snapshot| snapshot.fallback_only) {
            let dot = fallback_mode.is_some();
            if (dot && snapshot.config.endpoints.len() > SystemFakeDnsBridge::MAX_PLAIN_DNS_PEERS)
                || (!dot && upstreams.len() != snapshot.config.endpoints.len())
            {
                return Err(ServiceError::Unsupported);
            }
            upstreams.clear();
            // Сохраняем исходный порядок. Неполные снимки и потеря событий
            // по-прежнему закрывают Prepare. Отбор пропускает только адреса,
            // для которых ядро подтвердило недостижимость сети.
            for endpoint in &snapshot.config.endpoints {
                let peer = SocketAddr::new(endpoint.address, endpoint.port);
                let plain = (fallback_mode != Some(Resolve1Transport::StrictTls))
                    .then(|| plaintext_peer(endpoint));
                if fallback_peer_reachable(peer, plan.socket_mark(), dot, plain, cancel).await? {
                    upstreams.push((peer, ResolverBinding::default()));
                }
            }
            if upstreams.is_empty() {
                return Err(ServiceError::Unsupported);
            }
        }
        let dot_policy = if let Some(mode) = fallback_mode {
            Some(resolver_dot_policy(mode).await?)
        } else {
            None
        };
        let mark = NonZeroU32::new(plan.socket_mark()).ok_or(ServiceError::Unavailable)?;
        let mut plain = Vec::with_capacity(upstreams.len());
        let mut client_endpoints = upstreams
            .iter()
            .map(|&(peer, _)| peer)
            .collect::<BTreeSet<_>>();
        if dot_policy.is_some() && client_endpoints.len() != upstreams.len() {
            return Err(ServiceError::Unsupported);
        }
        for (peer, binding) in upstreams {
            let mut client = peer;
            let relay = if let (Some(policy), Some(snapshot)) = (&dot_policy, &resolved) {
                let (endpoint, socket) = snapshot
                    .config
                    .endpoints
                    .iter()
                    .zip(&snapshot.sockets)
                    .find(|(endpoint, _)| SocketAddr::new(endpoint.address, endpoint.port) == peer)
                    .ok_or(ServiceError::Unavailable)?;
                client = fallback_dot_client(peer, &mut client_endpoints)?;
                tls_relay(loopback, mark, endpoint, socket, policy).await?
            } else {
                PlainDnsRelay::bind(loopback, peer, mark)
                    .await
                    .map_err(|_| ServiceError::Unavailable)?
            };
            plain.push(SessionResolverRelay {
                relay,
                binding,
                client,
            });
        }
        if let Some(snapshot) = resolved.as_deref().filter(|snapshot| {
            matches!(source, ResolverSource::ResolvedUplink) && !snapshot.fallback_only
        }) {
            let remaining = SystemFakeDnsBridge::MAX_PLAIN_DNS_PEERS - plain.len();
            plain.extend(uplink_tls_relays(snapshot, loopback, mark, remaining).await?);
        }
        let peers = plain
            .iter()
            .map(|entry| {
                Ok((
                    entry.client,
                    entry.relay.port().map_err(|_| ServiceError::Unavailable)?,
                ))
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        config = config
            .with_plain_dns_endpoints(peers)
            .map_err(|_| ServiceError::Unsupported)?;
        drop(temporary);
        Ok(Self {
            config,
            loopback,
            direct_egress,
            marker,
            suffixes,
            private_dns_zones,
            listeners: Mutex::new(Some(listeners)),
            source,
            resolved,
            cidr_policy,
            tls_peers,
            plain,
        })
    }

    fn approves(&self, name: &str) -> bool {
        name == SYSTEM_FAKE_DNS_PROBE_NAME
            || !self.is_private_dns_name(name)
                && self
                    .suffixes
                    .iter()
                    .any(|suffix| name_in_dns_zone(name, suffix))
    }

    fn is_private_dns_name(&self, name: &str) -> bool {
        name != SYSTEM_FAKE_DNS_PROBE_NAME
            && self
                .private_dns_zones
                .iter()
                .any(|zone| name_in_dns_zone(name, zone))
    }

    fn plain_clients(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.plain.iter().map(|entry| entry.client)
    }

    pub fn relay_routes(&self) -> impl Iterator<Item = ResolverPeer> + '_ {
        self.plain.iter().flat_map(|entry| {
            entry
                .relay
                .upstreams()
                .map(move |(peer, protocol)| (peer, protocol, entry.binding.route_link))
        })
    }

    pub fn uses_resolve1(&self) -> bool {
        self.resolved.is_some()
    }

    pub fn tls_daemon(&self) -> Option<&Daemon> {
        self.resolved.as_ref()?.daemon.as_ref()
    }

    pub fn tls_peers(&self) -> &[ResolverPeer] {
        &self.tls_peers
    }

    pub async fn verify_tls(&self, own_link: Option<u32>) -> Result<(), ServiceError> {
        if self.tls_peers.is_empty() {
            return Ok(());
        }
        if resolver_source().await? != self.source {
            return Err(ServiceError::Unavailable);
        }
        verify_resolved_baseline(
            self.resolved.as_deref().ok_or(ServiceError::Unavailable)?,
            own_link,
        )
        .await
    }

    pub fn suffixes(&self) -> &[String] {
        &self.suffixes
    }

    /// Вызывается после проверки worker и правил nft, но до публикации DNS.
    pub async fn start(
        self: Arc<Self>,
        ifindex: u32,
        isolation: WorkerOnlyLoopbackIsolation,
        leases: Arc<FakeDnsLeases>,
        epoch: DnsEpoch,
        horizon: PublicationHorizon,
        failed: Arc<Notify>,
    ) -> Result<ActiveFakeDns, ServiceError> {
        // Подписка предшествует повторной проверке, чтобы не пропустить
        // замену конфигурации между сверкой и запуском DNS relay.
        let file_watch = self.source.watch_file()?;
        if resolver_source().await? != self.source {
            return Err(ServiceError::Unavailable);
        }
        if let Some(expected) = &self.resolved {
            verify_resolved_baseline(expected, None).await?;
        }
        let publication_domains = self
            .suffixes
            .iter()
            .filter(|name| !self.is_private_dns_name(name))
            .cloned()
            .collect::<Vec<_>>();
        let resolved = match &self.resolved {
            Some(snapshot) if snapshot.fallback_only => {
                // Сохраняем порядок резервных серверов из resolved. Каждый адрес
                // уже имеет отдельный релей и проверенный физический маршрут.
                let servers = self.plain_clients().collect::<Vec<_>>();
                Some(
                    prepare_fallback_link_dns(
                        ifindex,
                        &servers,
                        &publication_domains,
                        &snapshot.config.domains,
                        LIMIT,
                    )
                    .await
                    .map_err(|_| ServiceError::Unsupported)?,
                )
            }
            Some(_) => Some(
                prepare_link_dns(ifindex, self.marker, &publication_domains, LIMIT)
                    .await
                    .map_err(|_| ServiceError::Unsupported)?,
            ),
            None => None,
        };
        leases
            .advance_epoch(epoch)
            .map_err(|_| ServiceError::Unavailable)?;
        let listeners = self
            .listeners
            .lock()
            .map_err(|_| ServiceError::Unavailable)?
            .take()
            .ok_or(ServiceError::Unavailable)?;
        let (stop, cancel) = Cancellation::new();
        let task_leases = Arc::clone(&leases);
        let task_horizon = horizon.clone();
        let marker = self.marker;
        let source = self.source.clone();
        let for_task = Arc::clone(&self);
        let task = tokio::spawn(async move {
            let approved = |query: &FakeDnsQuestion| {
                task_horizon.can_issue() && for_task.approves(query.name().as_str())
            };
            let synthesize = |packet: &[u8], binding: ResolverBinding| {
                let name = forward_query_name(packet)?;
                if for_task.is_private_dns_name(&name) {
                    return Err(ResolverError::Untrusted);
                }
                if !for_task.approves(&name) {
                    if for_task.resolved.as_ref().is_some_and(|snapshot| {
                        // В fallback-only ни один внешний link не имеет DNS.
                        // Его домены не участвуют в выборе области у resolved.
                        !snapshot.fallback_only
                            && !permits_resolver_name(
                                &snapshot.config.domains,
                                &name,
                                binding.scope_link,
                            )
                    }) {
                        return Err(ResolverError::Untrusted);
                    }
                    return Ok(None);
                }
                if !binding.permits_synthetic(&for_task.source, &name) {
                    return Err(ResolverError::Untrusted);
                }
                // DNSSEC или неподдержанный тип для synthetic suffix никогда
                // не пересылается установленному реальному резолверу.
                let query =
                    FakeDnsQuestion::parse(packet).map_err(|_| ResolverError::Unsupported)?;
                Ok(Some(if !query.is_supported() {
                    query.refused()
                } else if task_horizon.can_issue() {
                    task_leases.synthesize(&query, epoch)
                } else {
                    query.unavailable()
                }))
            };
            let mut real: FuturesUnordered<_> = for_task
                .plain
                .iter()
                .map(|entry| {
                    let cancel = cancel.clone();
                    async move {
                        entry
                            .relay
                            .serve(&|packet| synthesize(packet, entry.binding), cancel)
                            .await
                    }
                })
                .collect();
            let serving = listeners.serve_with_policy(
                &for_task.config,
                &isolation,
                &task_leases,
                epoch,
                &approved,
                for_task.cidr_policy.as_ref().map(|policy| policy.policy()),
                cancel,
            );
            tokio::pin!(serving);
            let mut refresh = tokio::time::interval_at(
                tokio::time::Instant::now() + REFRESH_CHECK,
                REFRESH_CHECK,
            );
            refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let result = loop {
                tokio::select! {
                    biased;
                    _ = refresh.tick() => failed.notify_one(),
                    change = async {
                        match &file_watch {
                            Some(watch) => watch.changed().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        // Во время повторного чтения relay не отправляет запросы.
                        if change.is_err() || !matches!(
                            timeout(LIMIT, resolver_source()).await,
                            Ok(Ok(current)) if current == for_task.source
                        ) {
                            break Err(std::io::ErrorKind::BrokenPipe.into());
                        }
                    }
                    result = &mut serving => break result,
                    result = real.next(), if !real.is_empty() => {
                        break result.unwrap_or_else(|| Err(std::io::ErrorKind::BrokenPipe.into()));
                    }
                }
            };
            failed.notify_one();
            result
        });
        let active = ActiveFakeDns {
            _stop: stop,
            task,
            resolved,
            original_resolved: self.resolved.clone(),
            ifindex,
            horizon,
            source,
        };
        verify_dns_path(SocketAddr::new(marker, DNS_PORT), &leases, epoch, "marker").await?;
        for peer in self.plain_clients() {
            verify_dns_path(peer, &leases, epoch, "plain").await?;
        }
        if let Some(resolved) = &active.resolved {
            apply_link_dns(resolved, LIMIT)
                .await
                .map_err(|_| ServiceError::Unavailable)?;
        }
        if active.task.is_finished() {
            return Err(ServiceError::Unavailable);
        }
        Ok(active)
    }
}

fn fallback_dot_client(
    peer: SocketAddr,
    allocated: &mut BTreeSet<SocketAddr>,
) -> Result<SocketAddr, ServiceError> {
    if peer.port() != DOT_PORT {
        return Ok(peer);
    }
    // resolved нормализует 853 в порт по умолчанию. На локальном TUN
    // отключён TLS, поэтому его порт по умолчанию здесь равен 53.
    std::iter::once(DNS_PORT)
        .chain(FIRST_DYNAMIC_PORT..=u16::MAX)
        .map(|port| SocketAddr::new(peer.ip(), port))
        .find(|&client| allocated.insert(client))
        .ok_or(ServiceError::Unsupported)
}

async fn verify_dns_path(
    address: SocketAddr,
    leases: &FakeDnsLeases,
    epoch: DnsEpoch,
    _stage: &str,
) -> Result<(), ServiceError> {
    let result = timeout(LIMIT, probe_through_tun(address, leases, epoch))
        .await
        .unwrap_or(Err(ServiceError::Unavailable));
    #[cfg(feature = "test-support")]
    if std::env::var("YONIK_SESSION_DIAGNOSTICS").as_deref() == Ok("1") {
        eprintln!("DNS probe {_stage}: {result:?}");
    }
    result
}

async fn probe_through_tun(
    marker: SocketAddr,
    leases: &FakeDnsLeases,
    epoch: DnsEpoch,
) -> Result<(), ServiceError> {
    let unavailable = |_| ServiceError::Unavailable;
    let bind = if marker.is_ipv4() {
        IpAddr::from(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::from(Ipv6Addr::UNSPECIFIED)
    };
    let socket = UdpSocket::bind((bind, 0)).await.map_err(unavailable)?;
    socket.connect(marker).await.map_err(unavailable)?;
    let mut answer = [0; 128];
    let length = loop {
        socket.send(DNS_PROBE).await.map_err(unavailable)?;
        // Открытая TUN-очередь может принять первый пакет до готовности ядра.
        if let Ok(received) = timeout(DNS_PROBE_RETRY, socket.recv(&mut answer)).await {
            break received.map_err(unavailable)?;
        }
    };
    if length != DNS_PROBE.len() + 16
        || answer[..2] != DNS_PROBE[..2]
        || answer[3] & 15 != 0
        || answer[6..8] != [0, 1]
    {
        return Err(ServiceError::Unavailable);
    }
    let ip: [u8; 4] = answer[length - 4..length]
        .try_into()
        .map_err(|_| ServiceError::Unavailable)?;
    if leases
        .lookup(Ipv4Addr::from(ip).into(), epoch)
        .is_none_or(|mapping| mapping.name.as_str() != SYSTEM_FAKE_DNS_PROBE_NAME)
    {
        return Err(ServiceError::Unavailable);
    }
    Ok(())
}

pub(super) struct ActiveFakeDns {
    _stop: tokio::sync::watch::Sender<bool>,
    task: JoinHandle<std::io::Result<()>>,
    resolved: Option<Resolve1Prepared>,
    original_resolved: Option<Arc<Resolve1TunSnapshot>>,
    ifindex: u32,
    source: ResolverSource,
    pub horizon: PublicationHorizon,
}

impl ActiveFakeDns {
    pub async fn verify(&self) -> Result<(), ServiceError> {
        if self.task.is_finished() || resolver_source().await? != self.source {
            return Err(ServiceError::Unavailable);
        }
        if let Some(expected) = &self.original_resolved {
            verify_resolved_baseline(expected, Some(self.ifindex)).await?;
        }
        if let Some(resolved) = &self.resolved {
            timeout(LIMIT, resolved.verify_active())
                .await
                .map_err(|_| ServiceError::Unavailable)?
                .map_err(|_| ServiceError::Unavailable)?;
        }
        Ok(())
    }
}

impl Drop for ActiveFakeDns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_dot_uses_plain_default_port_without_shadowing_other_endpoints() {
        let upstream = |port| SocketAddr::from(([192, 0, 2, 10], port));
        let dot = upstream(DOT_PORT);
        let mut allocated = BTreeSet::from([dot]);
        assert_eq!(
            fallback_dot_client(dot, &mut allocated).unwrap(),
            upstream(DNS_PORT)
        );
        let mut allocated = BTreeSet::from([dot, upstream(DNS_PORT), upstream(FIRST_DYNAMIC_PORT)]);
        assert_eq!(
            fallback_dot_client(dot, &mut allocated).unwrap(),
            upstream(FIRST_DYNAMIC_PORT + 1)
        );
        assert_eq!(
            fallback_dot_client(upstream(DNS_PORT), &mut allocated).unwrap(),
            upstream(DNS_PORT)
        );
    }

    #[test]
    fn исходный_split_домен_разрешён_только_на_подходящем_линке() {
        let domain = |name: &str, scope| Resolve1Domain {
            scope,
            name: name.to_owned(),
            route_only: true,
        };
        let domains = [
            domain(".", Resolve1Scope::Global),
            domain("Real.Test", Resolve1Scope::Link(2)),
            domain("more.real.test.", Resolve1Scope::Link(3)),
        ];
        assert!(permits_resolver_name(&domains, "host.real.test", Some(2)));
        assert!(!permits_resolver_name(&domains, "host.real.test", None));
        assert!(!permits_resolver_name(&domains, "more.real.test", Some(2)));
        assert!(permits_resolver_name(&domains, "more.real.test", Some(3)));
        assert!(permits_resolver_name(&domains, "notreal.test", None));
    }

    #[test]
    fn wireguard_split_zones_protect_exact_names_and_descendants() {
        let domain = |name: &str, scope| Resolve1Domain {
            scope,
            name: name.to_owned(),
            route_only: true,
        };
        let domains = [
            domain(".", Resolve1Scope::Link(2)),
            domain("Private.Test.", Resolve1Scope::Link(2)),
            domain("private.test", Resolve1Scope::Link(3)),
            domain("büro.test", Resolve1Scope::Link(3)),
            domain("public.test", Resolve1Scope::Link(4)),
        ];
        let private = wireguard_dns_zones(&domains, &BTreeSet::from([2, 3]));
        assert_eq!(
            private,
            BTreeSet::from(["private.test".to_owned(), "xn--bro-hoa.test".to_owned()])
        );
        let protected = |name| private.iter().any(|zone| name_in_dns_zone(name, zone));
        assert!(protected("private.test"));
        assert!(protected("service.private.test"));
        assert!(protected("service.xn--bro-hoa.test"));
        assert!(!protected("notprivate.test"));
        assert!(!protected("private.test.example"));
        assert!(!protected("test"));
        assert!(!protected("public.test"));
    }

    #[test]
    fn неопубликованный_uplink_dns_не_выдаёт_fake_ip_для_сайта() {
        let uplink = ResolverSource::ResolvedUplink;
        let split = ResolverBinding {
            scope_link: Some(2),
            route_link: Some(2),
            split_only: true,
        };
        assert!(!split.permits_synthetic(&uplink, "example.test"));
        assert!(split.permits_synthetic(&uplink, SYSTEM_FAKE_DNS_PROBE_NAME));
        assert!(ResolverBinding::default().permits_synthetic(&uplink, "example.test"));
    }
}
