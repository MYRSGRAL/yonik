//! Loopback-транспорт для ограниченных ответов по подтверждённой DNS-политике.

use std::{
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
    time::{Duration, Instant},
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use yonik_engine::SystemFakeDnsBridge;
use yonik_engine::fake_dns::{
    DnsEpoch, FakeDnsQuestion, FakeIpLeaseTable, FakeMapping, MAX_DNS_PACKET,
    SYSTEM_FAKE_DNS_PROBE_NAME, answer_approved,
};
use yonik_engine::resource_bundle::{
    AnswerSet, Cidr, Destination, DestinationFlow, Evaluation, EvaluationContext, Policy,
    PolicyFault, Resolution, ResolverPath, Route,
};

use crate::{
    Cancellation,
    fake_flow::{
        FakeFlowError, FlowTarget, SocksCredentials, WorkerOnlyLoopbackIsolation,
        handle_flow_with_policy,
    },
    forward::{PolicyProxyResolver, boottime_now},
    resolver::ResolverError,
};
use std::sync::Arc;

const MAX_TCP_CONNECTIONS: usize = 64;
const MAX_FLOWS: usize = 128;
const MAX_RESOLVED_UDP_FLOWS: usize = 128;
const TCP_IDLE: Duration = Duration::from_secs(5);
pub const MAX_FAKE_TTL: Duration = Duration::from_secs(30);
const POLICY_DNS_BUDGET: Duration = Duration::from_secs(3);

fn report_dns_policy_unresolved() {
    static REPORTER: OnceLock<Option<SyncSender<()>>> = OnceLock::new();
    // stderr может задержаться в сборщике журнала. Один поток пишет,
    // а DNS и TUN продолжают работать даже при заполненной очереди.
    if let Some(sender) = REPORTER.get_or_init(|| {
        let (sender, receiver) = sync_channel(1);
        std::thread::Builder::new()
            .name("yonik-dns-log".into())
            .spawn(move || {
                for () in receiver {
                    let _ = writeln!(
                        io::stderr().lock(),
                        "{}",
                        FakeFlowError::DnsPolicyUnresolved
                    );
                }
            })
            .ok()
            .map(|_| sender)
    }) {
        let _ = sender.try_send(());
    }
}

pub(crate) struct CidrFlowPolicy<'a> {
    policy: &'a Policy,
    resolver: Arc<PolicyProxyResolver>,
    leases: &'a FakeDnsLeases,
    pools: Vec<Cidr>,
    reported_unresolved: AtomicBool,
    pub(crate) direct_auth: SocksCredentials,
    pub(crate) udp_slots: tokio::sync::Semaphore,
}

impl CidrFlowPolicy<'_> {
    fn dns_policy_unresolved(&self) -> FakeFlowError {
        // Один безопасный диагноз за сессию, даже при потоке UDP-отказов.
        if !self.reported_unresolved.swap(true, Ordering::Relaxed) {
            report_dns_policy_unresolved();
        }
        FakeFlowError::DnsPolicyUnresolved
    }

    pub(crate) async fn select(
        &self,
        mapping: &FakeMapping,
        mut cancel: Cancellation,
    ) -> Result<FlowTarget, FakeFlowError> {
        if mapping.name.as_str() == SYSTEM_FAKE_DNS_PROBE_NAME {
            return Err(FakeFlowError::PolicyDenied);
        }
        let evaluate = |resolution| {
            self.policy.evaluate_destination(
                &DestinationFlow {
                    executable: None,
                    destination: Destination::Fake {
                        address: mapping.address,
                        mapping: Some(mapping),
                        resolution,
                    },
                },
                &EvaluationContext {
                    now: self.leases.tick(),
                    epoch: mapping.epoch,
                    fake_pools: &self.pools,
                },
            )
        };
        match evaluate(Resolution::Missing) {
            Evaluation::Decided {
                decision,
                selected_address: None,
                ..
            } if decision.action == Route::Proxy => {
                return Ok(FlowTarget::Name);
            }
            Evaluation::NeedResolution(ResolverPath::Policy) => {}
            _ => return Err(FakeFlowError::PolicyDenied),
        }
        let answer = self
            .resolver
            .lookup(&mapping.name, POLICY_DNS_BUDGET, &mut cancel)
            .await
            .map_err(|error| match error {
                ResolverError::Cancelled => FakeFlowError::Cancelled,
                _ => self.dns_policy_unresolved(),
            })?;
        if self.leases.lookup(mapping.address, mapping.epoch).as_ref() != Some(mapping) {
            return Err(FakeFlowError::UnknownFakeIp);
        }
        let valid_until = answer.boot_valid_until();
        let expires_at =
            u64::try_from(valid_until.as_nanos()).map_err(|_| FakeFlowError::PolicyDenied)?;
        match evaluate(Resolution::Answer(AnswerSet {
            addresses: answer.addresses(),
            complete: true,
            expires_at,
            epoch: mapping.epoch,
            path: ResolverPath::Policy,
        })) {
            Evaluation::Decided {
                decision,
                selected_address: Some(address),
                ..
            } if matches!(decision.action, Route::Proxy | Route::Direct) => {
                Ok(FlowTarget::Literal {
                    address,
                    direct: decision.action == Route::Direct,
                    valid_until,
                })
            }
            Evaluation::NeedResolution(ResolverPath::Policy)
            | Evaluation::Rejected(PolicyFault::DnsPolicyUnresolved) => {
                Err(self.dns_policy_unresolved())
            }
            _ => Err(FakeFlowError::PolicyDenied),
        }
    }
}

/// Единый реестр для DNS-сокета и восстановления имени в обратном тракте.
/// Один экземпляр используется всеми сменяющимися сессиями helper.
pub struct FakeDnsLeases {
    table: Mutex<FakeIpLeaseTable>,
    started_at: Instant,
    ready_after: Duration,
}

impl FakeDnsLeases {
    /// Холодный запуск ждёт максимальный TTL ранее опубликованных ответов.
    /// Это защищает адреса после перезапуска helper при том же пуле.
    pub fn new(table: FakeIpLeaseTable) -> Self {
        Self::with_startup_quarantine(table, Instant::now(), MAX_FAKE_TTL)
    }

    pub(crate) fn with_startup_quarantine(
        table: FakeIpLeaseTable,
        started_at: Instant,
        ready_after: Duration,
    ) -> Self {
        Self {
            table: Mutex::new(table),
            started_at,
            ready_after,
        }
    }

    pub fn advance_epoch(&self, epoch: DnsEpoch) -> io::Result<()> {
        self.table
            .lock()
            .map_err(|_| lease_state_error())?
            .advance_epoch(epoch, self.tick())
            .map_err(|_| lease_state_error())
    }

    pub fn quarantine_remaining(&self) -> Duration {
        self.ready_after.saturating_sub(self.started_at.elapsed())
    }

    pub fn lookup(&self, address: IpAddr, epoch: DnsEpoch) -> Option<FakeMapping> {
        self.table
            .lock()
            .ok()?
            .lookup(address, epoch, self.tick())
            .ok()?
    }

    fn answer(
        &self,
        packet: &[u8],
        epoch: DnsEpoch,
        approved: impl FnOnce(&FakeDnsQuestion) -> bool,
    ) -> Option<Vec<u8>> {
        let question = FakeDnsQuestion::parse(packet).ok()?;
        if !question.is_supported() || !approved(&question) {
            return Some(question.refused());
        }
        Some(self.synthesize(&question, epoch))
    }

    pub(crate) fn synthesize(&self, question: &FakeDnsQuestion, epoch: DnsEpoch) -> Vec<u8> {
        if !self.quarantine_remaining().is_zero() {
            return question.unavailable();
        }
        let answer = self.table.lock().ok().and_then(|mut table| {
            answer_approved(
                question,
                &mut table,
                epoch,
                MAX_FAKE_TTL.as_secs() as u32,
                || self.tick(),
            )
            .ok()
        });
        answer.unwrap_or_else(|| question.unavailable())
    }

    fn tick(&self) -> u64 {
        // BOOTTIME учитывает сон хоста. При недоступных часах аренды истекают.
        boottime_now()
            .and_then(|now| u64::try_from(now.as_nanos()).ok())
            .unwrap_or(u64::MAX)
    }
}

fn lease_state_error() -> io::Error {
    io::Error::other("Реестр Fake-IP недоступен")
}

/// Сокеты helper удерживаются от получения портов до окончания сессии.
pub struct FakeDnsBridgeListeners {
    dns: FakeDnsListener,
    lookup: TcpListener,
}

impl FakeDnsBridgeListeners {
    pub async fn bind(address: Ipv4Addr) -> io::Result<Self> {
        let endpoint = SocketAddrV4::new(address, 0);
        let dns = FakeDnsListener::bind_on(endpoint).await?;
        let lookup = TcpListener::bind(endpoint).await?;
        Ok(Self { dns, lookup })
    }

    pub fn ports(&self) -> io::Result<[NonZeroU16; 2]> {
        let port = |endpoint: SocketAddr| {
            NonZeroU16::new(endpoint.port())
                .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))
        };
        Ok([port(self.dns.address()?)?, port(self.lookup.local_addr()?)?])
    }

    /// Caller удерживает защиту loopback на весь срок работы listener.
    /// Завершение одной половины закрывает весь совместный тракт.
    pub async fn serve(
        self,
        bridge: &SystemFakeDnsBridge,
        isolation: &WorkerOnlyLoopbackIsolation,
        leases: &FakeDnsLeases,
        epoch: DnsEpoch,
        approved: &(impl Fn(&FakeDnsQuestion) -> bool + Sync),
        cancel: Cancellation,
    ) -> io::Result<()> {
        self.serve_with_policy(bridge, isolation, leases, epoch, approved, None, cancel)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn serve_with_policy(
        self,
        bridge: &SystemFakeDnsBridge,
        isolation: &WorkerOnlyLoopbackIsolation,
        leases: &FakeDnsLeases,
        epoch: DnsEpoch,
        approved: &(impl Fn(&FakeDnsQuestion) -> bool + Sync),
        policy: Option<&Policy>,
        cancel: Cancellation,
    ) -> io::Result<()> {
        let expected = bridge.helper_endpoints().map(SocketAddr::V4);
        if [self.dns.address()?, self.lookup.local_addr()?] != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Сокеты не совпали с конфигурацией",
            ));
        }
        let received = bridge.lookup_auth();
        let sent = bridge.reinject_auth();
        let incoming_auth = SocksCredentials::new(received.username(), received.password())
            .map_err(io::Error::other)?;
        let upstream_auth =
            SocksCredentials::new(sent.username(), sent.password()).map_err(io::Error::other)?;
        let policy = policy
            .map(|policy| -> io::Result<_> {
                let (endpoint, account) = bridge
                    .policy_resolver()
                    .ok_or(io::ErrorKind::InvalidInput)?;
                let direct = bridge
                    .resolved_direct_auth()
                    .ok_or(io::ErrorKind::InvalidInput)?;
                let auth = SocksCredentials::new(
                    SystemFakeDnsBridge::POLICY_RESOLVER_USERNAME,
                    account.password(),
                )
                .map_err(io::Error::other)?;
                let resolver =
                    PolicyProxyResolver::new(bridge.reinject_endpoint().into(), endpoint, auth)
                        .map_err(io::Error::other)?;
                let pools = crate::managed_network::FAKE_POOLS
                    .iter()
                    .map(|(address, prefix)| {
                        format!("{address}/{prefix}")
                            .parse()
                            .map_err(io::Error::other)
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                let direct_auth = SocksCredentials::new(
                    SystemFakeDnsBridge::RESOLVED_DIRECT_USERNAME,
                    direct.password(),
                )
                .map_err(io::Error::other)?;
                Ok(CidrFlowPolicy {
                    policy,
                    resolver,
                    leases,
                    pools,
                    reported_unresolved: AtomicBool::new(false),
                    direct_auth,
                    udp_slots: tokio::sync::Semaphore::new(MAX_RESOLVED_UDP_FLOWS),
                })
            })
            .transpose()?;
        let dns = self.dns.serve(leases, epoch, approved, cancel.clone());
        let lookup = async {
            let mut flows = FuturesUnordered::new();
            loop {
                tokio::select! {
                    _ = flows.next(), if !flows.is_empty() => {}
                    accepted = self.lookup.accept(), if flows.len() < MAX_FLOWS => {
                        let (stream, _) = accepted?;
                        flows.push(handle_flow_with_policy(
                            stream,
                            bridge.reinject_endpoint().into(),
                            &incoming_auth,
                            &upstream_auth,
                            Some(isolation),
                            |address| leases.lookup(address, epoch),
                            policy.as_ref(),
                            cancel.clone(),
                        ));
                    }
                }
            }
        };
        tokio::select! {
            result = dns => result,
            result = lookup => result,
        }
    }
}

/// Держит TCP и UDP на одном loopback порту до закрытия сессии.
/// Вызывающая сторона изолирует входящий трафик и подтверждает обратный тракт.
pub struct FakeDnsListener {
    tcp: TcpListener,
    udp: UdpSocket,
}

impl FakeDnsListener {
    pub async fn bind(port: u16) -> io::Result<Self> {
        Self::bind_on(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).await
    }

    pub async fn bind_on(address: SocketAddrV4) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS требует loopback",
            ));
        }
        let tcp = TcpListener::bind(address).await?;
        let udp = UdpSocket::bind(tcp.local_addr()?).await?;
        Ok(Self { tcp, udp })
    }

    pub fn address(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }

    pub async fn serve(
        self,
        leases: &FakeDnsLeases,
        epoch: DnsEpoch,
        approved: &(impl Fn(&FakeDnsQuestion) -> bool + Sync),
        mut cancel: Cancellation,
    ) -> io::Result<()> {
        let answer = |packet: &[u8]| leases.answer(packet, epoch, approved);
        let tcp = self.serve_tcp(&answer);
        let udp = self.serve_udp(&answer);
        tokio::select! {
            biased;
            () = cancel.cancelled() => Ok(()),
            result = tcp => result,
            result = udp => result,
        }
    }

    async fn serve_udp(&self, answer: &impl Fn(&[u8]) -> Option<Vec<u8>>) -> io::Result<()> {
        let mut packet = [0; MAX_DNS_PACKET + 1];
        loop {
            let (size, peer) = self.udp.recv_from(&mut packet).await?;
            if peer.ip().is_loopback() && size <= MAX_DNS_PACKET {
                if let Some(response) = answer(&packet[..size]) {
                    timeout(TCP_IDLE, self.udp.send_to(&response, peer))
                        .await
                        .map_err(|_| io::ErrorKind::TimedOut)??;
                }
            }
        }
    }

    async fn serve_tcp(&self, answer: &impl Fn(&[u8]) -> Option<Vec<u8>>) -> io::Result<()> {
        let mut handlers = FuturesUnordered::new();
        loop {
            tokio::select! {
                _ = handlers.next(), if !handlers.is_empty() => {}
                socket = self.tcp.accept() => {
                    let (stream, peer) = socket?;
                    if peer.ip().is_loopback() && handlers.len() < MAX_TCP_CONNECTIONS {
                        handlers.push(handle_tcp(stream, answer));
                    }
                }
            }
        }
    }
}

async fn handle_tcp(mut stream: TcpStream, answer: &impl Fn(&[u8]) -> Option<Vec<u8>>) {
    while let Ok(Ok(())) = timeout(TCP_IDLE, async {
        let len = usize::from(stream.read_u16().await?);
        if !(12..=MAX_DNS_PACKET).contains(&len) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut packet = vec![0; len];
        stream.read_exact(&mut packet).await?;
        let response = answer(&packet).ok_or(io::ErrorKind::InvalidData)?;
        let response_len = u16::try_from(response.len()).map_err(|_| io::ErrorKind::InvalidData)?;
        stream.write_u16(response_len).await?;
        stream.write_all(&response).await
    })
    .await
    {}
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERY: &[u8] =
        b"\x01\x23\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01";

    fn leases() -> (FakeDnsLeases, IpAddr) {
        let fake = IpAddr::V4(Ipv4Addr::new(198, 18, 4, 2));
        (
            FakeDnsLeases::new(FakeIpLeaseTable::new([fake]).unwrap()),
            fake,
        )
    }

    fn approve(question: &FakeDnsQuestion) -> bool {
        question.name().as_str() == "example.test"
    }

    fn make_epoch(engine: u64) -> DnsEpoch {
        DnsEpoch {
            network: 1,
            engine,
            resolver: 1,
        }
    }

    #[tokio::test]
    async fn старшее_доменное_proxy_правило_не_запрашивает_dns_политики() {
        use serde_json::json;
        use yonik_engine::policy_wire::SystemPolicy;

        let (mut leases, address) = leases();
        leases.ready_after = Duration::ZERO;
        let epoch = make_epoch(1);
        leases.advance_epoch(epoch).unwrap();
        leases.answer(QUERY, epoch, approve).unwrap();
        let mapping = leases.lookup(address, epoch).unwrap();
        let policy = SystemPolicy::parse(
            &json!({
                "version": 1, "default_action": "proxy", "lan": [], "private_networks": [],
                "private_domains": [],
                "user_rules": [{"id": 1, "enabled": true, "action": "proxy",
                    "domain": ["example.test"], "domain_suffix": [], "ip_cidr": [], "executable_paths": []}],
                "preset_rules": [{"id": 2, "enabled": true, "action": "direct",
                    "domain": [], "domain_suffix": [], "ip_cidr": ["192.0.2.0/24"], "executable_paths": []}]
            })
            .to_string(),
        ).unwrap();
        let socks = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let auth = || SocksCredentials::new("test-user", "test-pass").unwrap();
        let flow_policy = CidrFlowPolicy {
            policy: policy.policy(),
            resolver: PolicyProxyResolver::new(
                socks.local_addr().unwrap(),
                "192.0.2.53:5353".parse().unwrap(),
                auth(),
            )
            .unwrap(),
            leases: &leases,
            pools: vec!["198.18.4.0/24".parse().unwrap()],
            reported_unresolved: AtomicBool::new(false),
            direct_auth: auth(),
            udp_slots: tokio::sync::Semaphore::new(1),
        };
        let (_owner, cancel) = Cancellation::new();
        assert!(matches!(
            flow_policy.select(&mapping, cancel).await,
            Ok(FlowTarget::Name)
        ));
        assert!(
            timeout(Duration::from_millis(20), socks.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn выдерживает_карантин_холодного_запуска_и_отказывает_без_решения_политики() {
        let (leases, fake) = leases();
        let epoch = make_epoch(1);
        leases.advance_epoch(epoch).unwrap();
        let denied = leases.answer(QUERY, epoch, |_| false).unwrap();
        assert_eq!(denied[3] & 15, 5);
        let waiting = leases.answer(QUERY, epoch, approve).unwrap();
        assert_eq!(waiting[3] & 15, 2);
        assert!(leases.lookup(fake, epoch).is_none());
    }

    #[tokio::test]
    async fn udp_и_параллельный_tcp_используют_один_реестр() {
        let (mut leases, fake) = leases();
        leases.ready_after = Duration::ZERO;
        let epoch = make_epoch(1);
        leases.advance_epoch(epoch).unwrap();
        let listener = FakeDnsListener::bind(0).await.unwrap();
        let address = listener.address().unwrap();
        let (stop, cancel) = Cancellation::new();

        let clients = async {
            let _idle = TcpStream::connect(address).await.unwrap();
            let mut tcp = TcpStream::connect(address).await.unwrap();
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            udp.connect(address).await.unwrap();
            udp.send(QUERY).await.unwrap();
            let mut answer = [0; 512];
            let len = udp.recv(&mut answer).await.unwrap();
            assert_eq!(&answer[0..2], &QUERY[0..2]);
            assert_eq!(&answer[len - 4..len], &[198, 18, 4, 2]);
            for _ in 0..2 {
                tcp.write_u16(u16::try_from(QUERY.len()).unwrap())
                    .await
                    .unwrap();
                tcp.write_all(QUERY).await.unwrap();
                let len = usize::from(tcp.read_u16().await.unwrap());
                tcp.read_exact(&mut answer[..len]).await.unwrap();
                assert_eq!(&answer[len - 4..len], &[198, 18, 4, 2]);
            }
            let mapping = leases.lookup(fake, epoch).unwrap();
            assert_eq!(mapping.name.as_str(), "example.test");
            leases.advance_epoch(make_epoch(2)).unwrap();
            assert!(leases.lookup(fake, epoch).is_none());
            stop.send(true).unwrap();
        };
        timeout(Duration::from_secs(2), async {
            let (result, ()) =
                tokio::join!(listener.serve(&leases, epoch, &approve, cancel), clients);
            result.unwrap();
        })
        .await
        .unwrap();
    }
}
