//! Loopback-транспорт для ограниченных ответов по подтверждённой DNS-политике.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    sync::Mutex,
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
    DnsEpoch, FakeDnsQuestion, FakeIpLeaseTable, FakeMapping, MAX_DNS_PACKET, answer_approved,
};

use crate::{
    Cancellation,
    fake_flow::{SocksCredentials, WorkerOnlyLoopbackIsolation, handle_flow},
};

const MAX_TCP_CONNECTIONS: usize = 64;
const MAX_FLOWS: usize = 128;
const TCP_IDLE: Duration = Duration::from_secs(5);
pub const MAX_FAKE_TTL: Duration = Duration::from_secs(30);

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
        Self::with_started_at(table, Instant::now())
    }

    pub(crate) fn with_started_at(table: FakeIpLeaseTable, started_at: Instant) -> Self {
        Self {
            table: Mutex::new(table),
            started_at,
            ready_after: MAX_FAKE_TTL,
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
        if !self.quarantine_remaining().is_zero() {
            return Some(question.unavailable());
        }
        let answer = self.table.lock().ok().and_then(|mut table| {
            answer_approved(
                &question,
                &mut table,
                epoch,
                MAX_FAKE_TTL.as_secs() as u32,
                || self.tick(),
            )
            .ok()
        });
        Some(answer.unwrap_or_else(|| question.unavailable()))
    }

    fn tick(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_nanos()).unwrap_or(u64::MAX)
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
        let dns = self.dns.serve(leases, epoch, approved, cancel.clone());
        let lookup = async {
            let mut flows = FuturesUnordered::new();
            loop {
                tokio::select! {
                    _ = flows.next(), if !flows.is_empty() => {}
                    accepted = self.lookup.accept(), if flows.len() < MAX_FLOWS => {
                        let (stream, _) = accepted?;
                        flows.push(handle_flow(
                            stream,
                            bridge.reinject_endpoint().into(),
                            &incoming_auth,
                            &upstream_auth,
                            Some(isolation),
                            |address| leases.lookup(address, epoch).map(|mapping| mapping.name),
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
                    self.udp.send_to(&response, peer).await?;
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
