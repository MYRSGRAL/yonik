//! Жизненный цикл DNS-тракта, привязанного к одному принадлежащему helper TUN.
use super::{
    ServiceError, SessionNetworkPlan,
    protection_host::{ARPHRD_ETHER, IFF_UP},
};
use crate::{
    Cancellation, NetworkReadError, RouteQuery, TransportProtocol,
    fake_flow::WorkerOnlyLoopbackIsolation,
    fake_service::{FakeDnsBridgeListeners, FakeDnsLeases, MAX_FAKE_TTL},
    managed_network::{Journal, firewall::BoundDirect},
    network::{LinuxTopology, reread_changed_route},
    resolver::{
        PlainResolverSnapshot, ResolvConfLayout, ResolverError, SYSTEM_RESOLV_CONF,
        file_watch::ResolverFileWatch,
        forward::forward_query_name,
        inspect_host_resolv_conf,
        plain_relay::{PlainDnsRelay, TCP_IDLE},
        plain_resolver_path,
        resolve1::{
            Resolve1Domain, Resolve1Prepared, Resolve1Scope, Resolve1Snapshot, Resolve1TunSnapshot,
            apply_link_dns, prepare_fallback_link_dns, prepare_link_dns,
            read_resolve1_tun_snapshot,
        },
    },
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4},
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
    Literal(PlainResolverSnapshot, &'static str),
}

impl ResolverSource {
    fn watch_file(&self) -> Result<Option<ResolverFileWatch>, ServiceError> {
        let Self::Literal(_, source) = *self else {
            return Ok(None);
        };
        let host_entry = Path::new(SYSTEM_RESOLV_CONF);
        let source = Path::new(source);
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
    listeners: Mutex<Option<FakeDnsBridgeListeners>>,
    source: ResolverSource,
    resolved: Option<Arc<Resolve1TunSnapshot>>,
    plain: Vec<(PlainDnsRelay, Option<u32>)>,
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
    snapshot: &Resolve1Snapshot,
    topology: &LinuxTopology,
) -> Vec<(IpAddr, Option<u32>)> {
    let mut scopes = BTreeMap::<_, BTreeSet<_>>::new();
    for endpoint in &snapshot.endpoints {
        let index = match endpoint.scope {
            Resolve1Scope::Global => None,
            Resolve1Scope::Link(index) => Some(index),
        };
        scopes.entry(endpoint.address).or_default().insert(index);
    }
    scopes
        .into_iter()
        .filter_map(|(address, scopes)| {
            let scope = *scopes.first()?;
            (scopes.len() == 1
                && !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local())
                && scope.is_none_or(|index| usable_resolver_link(topology, index)))
            .then_some((address, scope))
        })
        .collect()
}

async fn fallback_peer_reachable(
    address: IpAddr,
    mark: u32,
    cancel: &mut Cancellation,
) -> Result<bool, ServiceError> {
    for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
        let query =
            RouteQuery::new(address, 0)
                .with_mark(mark)
                .with_transport(protocol, None, Some(53));
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

impl PreparedFakeDns {
    pub async fn new(
        plan: &SessionNetworkPlan,
        topology: &LinuxTopology,
        suffixes: Vec<String>,
        direct_egress: Vec<BoundDirect>,
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
        let resolved = if matches!(source, ResolverSource::Resolved(_)) {
            config = config.reject_unbound_system_dns();
            Some(Arc::new(
                read_resolve1_tun_snapshot(cancel, LIMIT, None)
                    .await
                    .map_err(|_| ServiceError::Unavailable)?,
            ))
        } else {
            None
        };
        let mut upstreams = match (&source, &resolved) {
            (ResolverSource::Literal(snapshot, _), _) => snapshot
                .nameservers()
                .iter()
                .map(|&address| (address, None))
                .collect(),
            (_, Some(snapshot)) => resolved_peers(&snapshot.config, topology),
            _ => return Err(ServiceError::Unavailable),
        };
        if upstreams.len() > SystemFakeDnsBridge::MAX_PLAIN_DNS_PEERS {
            return Err(ServiceError::Unsupported);
        }
        if let Some(snapshot) = resolved.as_ref().filter(|snapshot| snapshot.fallback_only) {
            // При переносе fallback на линк resolved меняет набор search domains.
            if upstreams.len() != snapshot.config.endpoints.len()
                || snapshot
                    .config
                    .domains
                    .iter()
                    .any(|domain| domain.scope == Resolve1Scope::Global)
            {
                return Err(ServiceError::Unsupported);
            }
            upstreams.clear();
            // Сохраняем исходный порядок. Неполные снимки и потеря событий
            // по-прежнему закрывают Prepare. Отбор пропускает только адреса,
            // для которых ядро подтвердило недостижимость сети.
            for endpoint in &snapshot.config.endpoints {
                if fallback_peer_reachable(endpoint.address, plan.socket_mark(), cancel).await? {
                    upstreams.push((endpoint.address, None));
                }
            }
            if upstreams.is_empty() {
                return Err(ServiceError::Unsupported);
            }
        }
        let mark = NonZeroU32::new(plan.socket_mark()).ok_or(ServiceError::Unavailable)?;
        let mut plain = Vec::with_capacity(upstreams.len());
        let mut peers = Vec::with_capacity(upstreams.len());
        for (peer, link) in upstreams {
            let relay = PlainDnsRelay::bind(loopback, peer, mark)
                .await
                .map_err(|_| ServiceError::Unavailable)?;
            peers.push((peer, relay.port().map_err(|_| ServiceError::Unavailable)?));
            plain.push((relay, link));
        }
        config = config
            .with_plain_dns_peers(peers)
            .map_err(|_| ServiceError::Unsupported)?;
        drop(temporary);
        Ok(Self {
            config,
            loopback,
            direct_egress,
            marker,
            suffixes,
            listeners: Mutex::new(Some(listeners)),
            source,
            resolved,
            plain,
        })
    }

    fn approves(&self, name: &str) -> bool {
        name == SYSTEM_FAKE_DNS_PROBE_NAME
            || self.suffixes.iter().any(|suffix| {
                name == suffix
                    || name
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
    }

    pub fn plain_peers(&self) -> impl Iterator<Item = (std::net::SocketAddr, Option<u32>)> + '_ {
        self.plain.iter().map(|(relay, link)| (relay.peer(), *link))
    }

    pub fn uses_resolve1(&self) -> bool {
        self.resolved.is_some()
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
        let resolved = match &self.resolved {
            Some(snapshot) if snapshot.fallback_only => {
                // Сохраняем порядок резервных серверов из resolved. Каждый адрес
                // уже имеет отдельный релей и проверенный физический маршрут.
                let servers = self
                    .plain_peers()
                    .map(|(peer, _)| peer.ip())
                    .collect::<Vec<_>>();
                Some(
                    prepare_fallback_link_dns(ifindex, &servers, &self.suffixes, LIMIT)
                        .await
                        .map_err(|_| ServiceError::Unsupported)?,
                )
            }
            Some(_) => Some(
                prepare_link_dns(ifindex, self.marker, &self.suffixes, LIMIT)
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
            let synthesize = |packet: &[u8], link| {
                let name = forward_query_name(packet)?;
                if !for_task.approves(&name) {
                    if for_task.resolved.as_ref().is_some_and(|snapshot| {
                        !permits_resolver_name(&snapshot.config.domains, &name, link)
                    }) {
                        return Err(ResolverError::Untrusted);
                    }
                    return Ok(None);
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
                .map(|(relay, link)| {
                    let cancel = cancel.clone();
                    async move {
                        relay
                            .serve(&|packet| synthesize(packet, *link), cancel)
                            .await
                    }
                })
                .collect();
            let serving = listeners.serve(
                &for_task.config,
                &isolation,
                &task_leases,
                epoch,
                &approved,
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
        verify_dns_path(marker, &leases, epoch, "marker").await?;
        for (peer, _) in self.plain_peers() {
            verify_dns_path(peer.ip(), &leases, epoch, "plain").await?;
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

async fn verify_dns_path(
    address: IpAddr,
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
    marker: IpAddr,
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
    socket.connect((marker, 53)).await.map_err(unavailable)?;
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
}
