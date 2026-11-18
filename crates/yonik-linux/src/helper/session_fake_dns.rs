//! Жизненный цикл DNS-тракта, привязанного к одному принадлежащему helper TUN.
use super::{ServiceError, SessionNetworkPlan};
use crate::{
    Cancellation,
    fake_flow::WorkerOnlyLoopbackIsolation,
    fake_service::{FakeDnsBridgeListeners, FakeDnsLeases, MAX_FAKE_TTL},
    managed_network::{Journal, firewall::BoundDirect},
    resolver::{
        PlainResolverSnapshot, ResolvConfLayout, ResolverError,
        forward::forward_query_name,
        inspect_host_resolv_conf,
        plain_relay::{PlainDnsRelay, TCP_IDLE},
        resolve1::{Resolve1Prepared, apply_link_dns, prepare_link_dns},
    },
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4},
    num::{NonZeroU16, NonZeroU32},
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
    Literal(PlainResolverSnapshot),
}

async fn resolver_source() -> Result<ResolverSource, ServiceError> {
    #[cfg(feature = "test-support")]
    if std::env::var("YONIK_TEST_LITERAL_DNS").as_deref() == Ok("1") {
        return tokio::task::spawn_blocking(crate::resolver::read_fixture_dns_source)
            .await
            .map_err(|_| ServiceError::Unavailable)?
            .map(ResolverSource::Literal)
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
                Ok(ResolverSource::Literal(snapshot))
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
    plain: Vec<PlainDnsRelay>,
}

impl PreparedFakeDns {
    pub async fn new(
        plan: &SessionNetworkPlan,
        suffixes: Vec<String>,
        direct_egress: Vec<BoundDirect>,
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
        let mut plain = Vec::new();
        if let ResolverSource::Literal(snapshot) = &source {
            let mark = NonZeroU32::new(plan.socket_mark()).ok_or(ServiceError::Unavailable)?;
            let mut peers = Vec::with_capacity(snapshot.nameservers().len());
            for &peer in snapshot.nameservers() {
                let relay = PlainDnsRelay::bind(loopback, peer, mark)
                    .await
                    .map_err(|_| ServiceError::Unavailable)?;
                peers.push((peer, relay.port().map_err(|_| ServiceError::Unavailable)?));
                plain.push(relay);
            }
            config = config
                .with_plain_dns_peers(peers)
                .map_err(|_| ServiceError::Unsupported)?;
        }
        drop(temporary);
        Ok(Self {
            config,
            loopback,
            direct_egress,
            marker,
            suffixes,
            listeners: Mutex::new(Some(listeners)),
            source,
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

    pub fn plain_peers(&self) -> impl Iterator<Item = std::net::SocketAddr> + '_ {
        self.plain.iter().map(PlainDnsRelay::peer)
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
        if resolver_source().await? != self.source {
            return Err(ServiceError::Unavailable);
        }
        let resolved = match &self.source {
            ResolverSource::Resolved(_) => Some(
                prepare_link_dns(ifindex, self.marker, &self.suffixes, LIMIT)
                    .await
                    .map_err(|_| ServiceError::Unsupported)?,
            ),
            ResolverSource::Literal(_) => None,
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
            let synthesize = |packet: &[u8]| {
                let name = forward_query_name(packet)?;
                if !for_task.approves(&name) {
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
                .map(|relay| relay.serve(&synthesize, cancel.clone()))
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
            let result = loop {
                tokio::select! {
                    result = &mut serving => break result,
                    result = real.next(), if !real.is_empty() => {
                        break result.unwrap_or_else(|| Err(std::io::ErrorKind::BrokenPipe.into()));
                    }
                    () = tokio::time::sleep(REFRESH_CHECK) => failed.notify_one(),
                }
            };
            failed.notify_one();
            result
        });
        let active = ActiveFakeDns {
            _stop: stop,
            task,
            resolved,
            horizon,
            source,
        };
        verify_dns_path(marker, &leases, epoch, "marker").await?;
        if let Some(resolved) = &active.resolved {
            apply_link_dns(resolved, LIMIT)
                .await
                .map_err(|_| ServiceError::Unavailable)?;
        } else {
            for peer in self.plain_peers() {
                verify_dns_path(peer.ip(), &leases, epoch, "plain").await?;
            }
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
    source: ResolverSource,
    pub horizon: PublicationHorizon,
}

impl ActiveFakeDns {
    pub async fn verify(&self) -> Result<(), ServiceError> {
        if self.task.is_finished() || resolver_source().await? != self.source {
            return Err(ServiceError::Unavailable);
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
