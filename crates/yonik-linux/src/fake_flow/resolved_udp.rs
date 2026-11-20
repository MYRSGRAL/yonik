//! Обратное сопоставление реального адреса с Fake-IP в выделенной ассоциации.

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
    sync::{Semaphore, mpsc},
    time::{Instant, sleep, sleep_until, timeout},
};
use yonik_engine::fake_dns::FakeMapping;

use crate::forward::boottime_now;

use super::{
    Cancellation, CidrFlowPolicy, FakeDestination, FakeFlowError, FlowTarget, HANDSHAKE_TIMEOUT,
    MAX_UDP_DESTINATIONS, MAX_UDP_PACKET_LEN, SocksCredentials, UDP_IDLE_TIMEOUT,
    UdpAssociationRequest, connect_core_udp, encode_fake_ip, parse_client_udp,
};

const QUEUED_PACKETS: usize = 4;
const LOOKUP_RETRY_DELAY: Duration = Duration::from_secs(1);

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle(
    control: TcpStream,
    relay: UdpSocket,
    request: UdpAssociationRequest,
    upstream: SocketAddr,
    proxy_auth: &SocksCredentials,
    resolve_fake_ip: &(impl Fn(IpAddr) -> Option<FakeMapping> + Sync),
    policy: &CidrFlowPolicy<'_>,
    cancellation: Cancellation,
) -> Result<(), FakeFlowError> {
    let session = Session {
        relay: &relay,
        upstream,
        proxy_auth,
        direct_auth: &policy.direct_auth,
        resolve_fake_ip,
        slots: &policy.udp_slots,
        policy,
    };
    session.serve(control, request, cancellation).await
}

trait SelectRoute: Sync {
    fn select<'a>(
        &'a self,
        mapping: &'a FakeMapping,
        cancel: Cancellation,
    ) -> impl Future<Output = Result<FlowTarget, FakeFlowError>> + Send + 'a;
}

impl SelectRoute for CidrFlowPolicy<'_> {
    fn select<'a>(
        &'a self,
        mapping: &'a FakeMapping,
        cancel: Cancellation,
    ) -> impl Future<Output = Result<FlowTarget, FakeFlowError>> + Send + 'a {
        CidrFlowPolicy::select(self, mapping, cancel)
    }
}

struct Session<'a, Lookup, Policy> {
    relay: &'a UdpSocket,
    upstream: SocketAddr,
    proxy_auth: &'a SocksCredentials,
    direct_auth: &'a SocksCredentials,
    resolve_fake_ip: &'a Lookup,
    slots: &'a Semaphore,
    policy: &'a Policy,
}

impl<Lookup, Policy> Session<'_, Lookup, Policy>
where
    Lookup: Fn(IpAddr) -> Option<FakeMapping> + Sync,
    Policy: SelectRoute,
{
    async fn serve(
        &self,
        mut control: TcpStream,
        request: UdpAssociationRequest,
        mut cancellation: Cancellation,
    ) -> Result<(), FakeFlowError> {
        let mut peer = request.exact_client;
        let mut flows = FuturesUnordered::new();
        let mut senders = HashMap::<FakeDestination, mpsc::Sender<Vec<u8>>>::new();
        let mut wire = [0; MAX_UDP_PACKET_LEN + 1];
        let mut control_byte = [0];
        let mut idle = Instant::now() + UDP_IDLE_TIMEOUT;
        loop {
            let (len, source) = tokio::select! {
                () = cancellation.cancelled() => return Err(FakeFlowError::Cancelled),
                count = control.read(&mut control_byte) => {
                    return if count? == 0 { Ok(()) } else { Err(FakeFlowError::Protocol) };
                }
                Some(destination) = flows.next(), if !flows.is_empty() => {
                    senders.remove(&destination);
                    continue;
                }
                () = sleep_until(idle), if flows.is_empty() => return Err(FakeFlowError::Timeout),
                packet = self.relay.recv_from(&mut wire) => packet?,
            };
            if source.ip() != request.client_ip || peer.is_some_and(|peer| peer != source) {
                continue;
            }
            let Some((destination, _, payload)) = parse_client_udp(&wire[..len]) else {
                continue;
            };
            if let Some(sender) = senders.get(&destination) {
                if sender.capacity() > 0 {
                    let _ = sender.try_send(payload.to_vec());
                }
                continue;
            }
            let Some(lease) = (self.resolve_fake_ip)(destination.address)
                .filter(|lease| lease.address == destination.address)
            else {
                continue;
            };
            if senders.len() >= MAX_UDP_DESTINATIONS {
                continue;
            }
            let Ok(permit) = self.slots.try_acquire() else {
                continue;
            };
            peer = Some(source);
            let (sender, receiver) = mpsc::channel(QUEUED_PACKETS);
            senders.insert(destination, sender);
            let cancellation = cancellation.clone();
            let payload = payload.to_vec();
            flows.push(async move {
                let _permit = permit;
                // Повтор ошибочного запроса ограничен временем жизни этой записи.
                if self
                    .run_flow(lease, destination, source, payload, receiver, cancellation)
                    .await
                    .is_err()
                {
                    sleep(LOOKUP_RETRY_DELAY).await;
                }
                destination
            });
            idle = Instant::now() + UDP_IDLE_TIMEOUT;
        }
    }

    async fn run_flow(
        &self,
        lease: FakeMapping,
        destination: FakeDestination,
        source: SocketAddr,
        mut payload: Vec<u8>,
        mut outgoing: mpsc::Receiver<Vec<u8>>,
        cancellation: Cancellation,
    ) -> Result<(), FakeFlowError> {
        let mut expired = None;
        let mut wire = Vec::with_capacity(MAX_UDP_PACKET_LEN);
        let mut reply = [0; MAX_UDP_PACKET_LEN + 1];
        let mut control_byte = [0];
        loop {
            if !self.lease_current(&lease) {
                return Ok(());
            }
            let target = self.policy.select(&lease, cancellation.clone()).await?;
            let FlowTarget::Literal {
                address, direct, ..
            } = target
            else {
                return Err(FakeFlowError::PolicyDenied);
            };
            let credentials = if direct {
                self.direct_auth
            } else {
                self.proxy_auth
            };
            let mut association = timeout(
                HANDSHAKE_TIMEOUT,
                connect_core_udp(self.upstream, credentials),
            )
            .await
            .map_err(|_| FakeFlowError::Timeout)??;
            // Пока новый UDP-сокет не занял порт, старый остаётся привязанным.
            // Запоздавший ответ из старой ассоциации не может попасть в новую.
            drop(expired.take());
            let Some(mut idle) = flow_deadline(&lease) else {
                return Ok(());
            };
            loop {
                if payload.len() + if address.is_ipv4() { 10 } else { 22 } <= MAX_UDP_PACKET_LEN {
                    wire.clear();
                    encode_fake_ip(&mut wire, address);
                    wire.extend_from_slice(&destination.port.to_be_bytes());
                    wire.extend_from_slice(&payload);
                    if !self
                        .send(&association.relay, &lease, target, || {
                            association.relay.try_send(&wire)
                        })
                        .await?
                    {
                        // Если DNS TTL истёк до записи, следующий пакет заново
                        // проверит маршрут.
                        if !self.lease_current(&lease) {
                            return Ok(());
                        }
                    }
                }
                let next = loop {
                    tokio::select! {
                        packet = outgoing.recv() => {
                            let Some(packet) = packet else { return Ok(()); };
                            break packet;
                        }
                        count = association.control.read(&mut control_byte) => {
                            return if count? == 0 { Ok(()) } else { Err(FakeFlowError::Protocol) };
                        }
                        () = sleep_until(idle) => return Ok(()),
                        len = association.relay.recv(&mut reply) => {
                            let Some((replied, port, message)) = parse_client_udp(&reply[..len?]) else {
                                continue;
                            };
                            if replied.address.to_canonical() != address.to_canonical() || port != destination.port {
                                continue;
                            }
                            let header = if destination.address.is_ipv4() { 10 } else { 22 };
                            if header + message.len() > MAX_UDP_PACKET_LEN {
                                continue;
                            }
                            wire.clear();
                            encode_fake_ip(&mut wire, destination.address);
                            wire.extend_from_slice(&port.to_be_bytes());
                            wire.extend_from_slice(message);
                            if self.send(self.relay, &lease, target, || {
                                self.relay.try_send_to(&wire, source)
                            }).await? {
                                let Some(deadline) = flow_deadline(&lease) else {
                                    return Ok(());
                                };
                                idle = deadline;
                            }
                        }
                    }
                };
                payload = next;
                if !self.lease_current(&lease) {
                    return Ok(());
                }
                if !target.current() {
                    expired = Some(association);
                    break;
                }
                let Some(deadline) = flow_deadline(&lease) else {
                    return Ok(());
                };
                idle = deadline;
            }
        }
    }

    fn lease_current(&self, lease: &FakeMapping) -> bool {
        (self.resolve_fake_ip)(lease.address).as_ref() == Some(lease)
    }

    async fn send(
        &self,
        socket: &UdpSocket,
        lease: &FakeMapping,
        target: FlowTarget,
        send: impl Fn() -> io::Result<usize>,
    ) -> Result<bool, FakeFlowError> {
        loop {
            socket.writable().await?;
            if !target.current() || !self.lease_current(lease) {
                return Ok(false);
            }
            match send() {
                Ok(_) => return Ok(true),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn flow_deadline(lease: &FakeMapping) -> Option<Instant> {
    let remaining = Duration::from_nanos(lease.expires_at).checked_sub(boottime_now()?)?;
    Some(Instant::now() + remaining.min(UDP_IDLE_TIMEOUT))
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use tokio::net::TcpListener;
    use yonik_engine::fake_dns::DnsEpoch;

    use super::*;
    use crate::fake_flow::{
        authenticate_request, read_udp_client_request, write_udp_associate_reply,
    };

    const A: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 4, 2));
    const B: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 4, 3));
    const SHARED: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    const REFRESHED: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54));
    const PORT: u16 = 443;

    struct Routes {
        first: Duration,
        renewed: AtomicUsize,
    }

    impl SelectRoute for Routes {
        async fn select(
            &self,
            mapping: &FakeMapping,
            _: Cancellation,
        ) -> Result<FlowTarget, FakeFlowError> {
            let first_a = mapping.address == A && self.renewed.fetch_add(1, Ordering::Relaxed) == 0;
            let address = if mapping.address == B || first_a {
                SHARED
            } else {
                REFRESHED
            };
            let valid_until = if first_a {
                self.first
            } else {
                boottime_now().unwrap() + Duration::from_secs(60)
            };
            Ok(FlowTarget::Literal {
                address,
                direct: false,
                valid_until,
            })
        }
    }

    fn lease(address: IpAddr, expires_at: Duration) -> Option<FakeMapping> {
        let name = match address {
            A => "a.example",
            B => "b.example",
            _ => return None,
        };
        Some(FakeMapping {
            address,
            name: name.parse().unwrap(),
            expires_at: u64::try_from(expires_at.as_nanos()).unwrap(),
            epoch: DnsEpoch {
                network: 1,
                resolver: 2,
                engine: 3,
            },
        })
    }

    fn packet(address: IpAddr, body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        encode_fake_ip(&mut packet, address);
        packet.extend_from_slice(&PORT.to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }

    #[tokio::test]
    async fn общий_ip_и_обновление_ttl_изолированы_в_одной_ассоциации() {
        timeout(Duration::from_secs(10), async {
            let loopback = (Ipv4Addr::LOCALHOST, 0);
            let client = UdpSocket::bind(loopback).await.unwrap();
            let bridge = UdpSocket::bind(loopback).await.unwrap();
            let bridge_addr = bridge.local_addr().unwrap();
            let core_tcp = TcpListener::bind(loopback).await.unwrap();
            let core_udp = UdpSocket::bind(loopback).await.unwrap();
            let core_sock = core_tcp.local_addr().unwrap();
            let core_relay = core_udp.local_addr().unwrap();
            let frontend_tcp = TcpListener::bind(loopback).await.unwrap();
            let _front_control = TcpStream::connect(frontend_tcp.local_addr().unwrap()).await.unwrap();
            let (bridge_control, _) = frontend_tcp.accept().await.unwrap();
            let client_addr = client.local_addr().unwrap();
            let proxy_auth = SocksCredentials::new("test-proxy", "test-key").unwrap();
            let direct_auth = SocksCredentials::new("test-direct", "test-key").unwrap();
            let verify_auth = SocksCredentials::new("test-proxy", "test-key").unwrap();
            let core = tokio::spawn(async move {
                let mut controls = Vec::new();
                for _ in 0..3 {
                    let (mut socket, source) = core_tcp.accept().await.unwrap();
                    let request = authenticate_request(&mut socket, &verify_auth).await.unwrap();
                    read_udp_client_request(&mut socket, source.ip(), request).await.unwrap();
                    write_udp_associate_reply(&mut socket, core_relay).await.unwrap();
                    controls.push(socket);
                }
                std::future::pending::<()>().await;
            });
            let now = boottime_now().unwrap();
            let policy = Routes {
                first: now + Duration::from_secs(2),
                renewed: AtomicUsize::new(0),
            };
            let b_expires = now + Duration::from_secs(4);
            let lookup = |address| {
                lease(address, if address == B { b_expires } else { now + Duration::from_secs(15) })
            };
            let slots = Semaphore::new(2);
            let session = Session {
                relay: &bridge, upstream: core_sock, proxy_auth: &proxy_auth,
                direct_auth: &direct_auth, resolve_fake_ip: &lookup, slots: &slots, policy: &policy,
            };
            let request = UdpAssociationRequest { exact_client: Some(client_addr), client_ip: client_addr.ip() };
            let (_stop, cancel) = Cancellation::new();
            let exercise = async {
                let mut seen = [0; 100];
                let mut send_and_observe = async |fake, real, body: &'static [u8]| {
                    client.send_to(&packet(fake, body), bridge_addr).await.unwrap();
                    let (len, source) = core_udp.recv_from(&mut seen).await.unwrap();
                    assert_eq!(&seen[..len], packet(real, body));
                    source
                };
                let a_src = send_and_observe(A, SHARED, b"a").await;
                let b_src = send_and_observe(B, SHARED, b"b").await;
                assert_ne!(a_src, b_src);
                let mut response = [0; 100];
                for (fake, source, body) in [(A, a_src, b"A"), (B, b_src, b"B")] {
                    core_udp.send_to(&packet(SHARED, body), source).await.unwrap();
                    let len = client.recv(&mut response).await.unwrap();
                    assert_eq!(&response[..len], packet(fake, body));
                }
                while boottime_now().unwrap() <= policy.first {
                    sleep(Duration::from_millis(20)).await;
                }
                core_udp.send_to(&packet(SHARED, b"old"), a_src).await.unwrap();
                core_udp.send_to(&packet(SHARED, b"still live"), b_src).await.unwrap();
                let len = client.recv(&mut response).await.unwrap();
                assert_eq!(&response[..len], packet(B, b"still live"));
                let updated = send_and_observe(A, REFRESHED, b"new").await;
                assert_ne!(a_src, updated);
                core_udp.send_to(&packet(REFRESHED, b"updated"), updated).await.unwrap();
                let len = client.recv(&mut response).await.unwrap();
                assert_eq!(&response[..len], packet(A, b"updated"));

                assert_eq!(slots.available_permits(), 0);
                while slots.available_permits() == 0 {
                    sleep(Duration::from_millis(20)).await;
                }
                assert!(boottime_now().unwrap() >= b_expires);
                assert_eq!(slots.available_permits(), 1);
            };
            tokio::select! {
                () = exercise => {}
                result = session.serve(bridge_control, request, cancel) => panic!("UDP bridge завершился: {result:?}"),
            }
            core.abort();
        }).await.unwrap();
    }
}
