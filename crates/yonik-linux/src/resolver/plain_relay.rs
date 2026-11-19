//! Передача реального DNS прежнему resolver через заранее проверенный маршрут.
use super::{
    ResolverError,
    dot::DotPeer,
    forward::{forward_framed, forward_tcp, forward_udp},
};
use crate::{Cancellation, managed_network::FAKE_POOLS};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    num::{NonZeroU16, NonZeroU32},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};
use yonik_engine::fake_dns::MAX_DNS_PACKET;
use yonik_nsfs::socket_namespace::mark_unconnected_dns_socket;

const LIMIT: Duration = Duration::from_secs(3);
pub(crate) const TCP_IDLE: Duration = Duration::from_secs(8);
const MAX_PENDING: usize = 64;
type PendingReply = (SocketAddr, Result<Vec<u8>, ResolverError>);
type DnsDecision = Result<Option<Vec<u8>>, ResolverError>;

pub(crate) struct PlainDnsRelay {
    tcp: TcpListener,
    udp: UdpSocket,
    peer: SocketAddr,
    mark: NonZeroU32,
    dot: Option<DotPeer>,
}

impl PlainDnsRelay {
    pub async fn bind(address: Ipv4Addr, peer: SocketAddr, mark: NonZeroU32) -> io::Result<Self> {
        if !address.is_loopback()
            || peer.ip().is_loopback()
            || peer.ip().is_unspecified()
            || peer.port() == 0
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let tcp = TcpListener::bind(SocketAddrV4::new(address, 0)).await?;
        let udp = UdpSocket::bind(tcp.local_addr()?).await?;
        Ok(Self {
            tcp,
            udp,
            peer,
            mark,
            dot: None,
        })
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn with_dot(mut self, dot: DotPeer) -> Self {
        self.dot = Some(dot);
        self
    }

    pub fn upstream_protocols(&self) -> &'static [crate::TransportProtocol] {
        use crate::TransportProtocol::{Tcp, Udp};
        if self.dot.is_some() {
            &[Tcp]
        } else {
            &[Tcp, Udp]
        }
    }

    pub fn port(&self) -> io::Result<NonZeroU16> {
        NonZeroU16::new(self.tcp.local_addr()?.port()).ok_or(io::ErrorKind::AddrNotAvailable.into())
    }

    pub async fn serve(
        &self,
        synthetic: &(impl Fn(&[u8]) -> DnsDecision + Sync),
        cancel: Cancellation,
    ) -> io::Result<()> {
        let tcp = self.serve_tcp(synthetic, &cancel);
        let udp = self.serve_udp(synthetic, &cancel);
        futures_util::pin_mut!(tcp, udp);
        let mut stopped = cancel.clone();
        tokio::select! {
            biased;
            () = stopped.cancelled() => Ok(()),
            result = &mut tcp => result,
            result = &mut udp => result,
        }
    }

    async fn serve_tcp(
        &self,
        synthetic: &(impl Fn(&[u8]) -> DnsDecision + Sync),
        cancel: &Cancellation,
    ) -> io::Result<()> {
        let mut clients = FuturesUnordered::new();
        loop {
            tokio::select! {
                _ = clients.next(), if !clients.is_empty() => {}
                accepted = self.tcp.accept(), if clients.len() < MAX_PENDING => {
                    let (client, peer) = accepted?;
                    if peer.ip().is_loopback() {
                        clients.push(self.handle_tcp(client, synthetic, cancel.clone()));
                    }
                }
            }
        }
    }

    async fn handle_tcp(
        &self,
        mut stream: TcpStream,
        synthetic: &(impl Fn(&[u8]) -> DnsDecision + Sync),
        cancel: Cancellation,
    ) {
        while let Ok(Ok(())) = timeout(TCP_IDLE, async {
            let len = usize::from(stream.read_u16().await?);
            if !(12..=MAX_DNS_PACKET).contains(&len) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut query = vec![0; len];
            stream.read_exact(&mut query).await?;
            let response = match synthetic(&query).map_err(|_| io::ErrorKind::InvalidData)? {
                Some(response) => response,
                None => self
                    .forward(&query, true, cancel.clone())
                    .await
                    .map_err(|_| io::ErrorKind::InvalidData)?,
            };
            stream
                .write_u16(u16::try_from(response.len()).map_err(|_| io::ErrorKind::InvalidData)?)
                .await?;
            stream.write_all(&response).await
        })
        .await
        {}
    }

    async fn serve_udp(
        &self,
        synthetic: &(impl Fn(&[u8]) -> DnsDecision + Sync),
        cancel: &Cancellation,
    ) -> io::Result<()> {
        let mut pending = FuturesUnordered::new();
        let mut buffer = [0; MAX_DNS_PACKET + 1];
        loop {
            tokio::select! {
                result = pending.next(), if !pending.is_empty() => {
                    let result: Option<PendingReply> = result;
                    if let Some((client, Ok(response))) = result {
                        timeout(LIMIT, self.udp.send_to(&response, client)).await
                            .map_err(|_| io::ErrorKind::TimedOut)??;
                    }
                }
                received = self.udp.recv_from(&mut buffer), if pending.len() < MAX_PENDING => {
                    let (size, client) = received?;
                    if client.ip().is_loopback() && size <= MAX_DNS_PACKET {
                        let packet = &buffer[..size];
                        match synthetic(packet) {
                            Ok(Some(response)) => {
                                timeout(LIMIT, self.udp.send_to(&response, client)).await
                                    .map_err(|_| io::ErrorKind::TimedOut)??;
                            }
                            Ok(None) => {
                                let packet = packet.to_vec();
                                let cancel = cancel.clone();
                                pending.push(async move { (client, self.forward(&packet, false, cancel).await) });
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }
    }

    async fn forward(
        &self,
        query: &[u8],
        tcp: bool,
        mut cancel: Cancellation,
    ) -> Result<Vec<u8>, ResolverError> {
        let endpoint = self.peer;
        let transport = async {
            if tcp || self.dot.is_some() {
                let socket = if endpoint.is_ipv4() {
                    TcpSocket::new_v4()
                } else {
                    TcpSocket::new_v6()
                }
                .map_err(|_| ResolverError::Unavailable)?;
                mark_unconnected_dns_socket(&socket, self.mark)
                    .map_err(|_| ResolverError::Untrusted)?;
                let mut stream = timeout(LIMIT, socket.connect(endpoint))
                    .await
                    .map_err(|_| ResolverError::Timeout)?
                    .map_err(|_| ResolverError::Unavailable)?;
                if let Some(dot) = &self.dot {
                    forward_framed(query, LIMIT, &mut cancel, async |outbound| {
                        dot.exchange(&mut stream, outbound).await
                    })
                    .await
                } else {
                    forward_tcp(&mut stream, endpoint, query, LIMIT, &mut cancel).await
                }
            } else {
                let bind = if endpoint.is_ipv4() {
                    IpAddr::from(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::from(Ipv6Addr::UNSPECIFIED)
                };
                let socket = UdpSocket::bind((bind, 0))
                    .await
                    .map_err(|_| ResolverError::Unavailable)?;
                mark_unconnected_dns_socket(&socket, self.mark)
                    .map_err(|_| ResolverError::Untrusted)?;
                socket
                    .connect(endpoint)
                    .await
                    .map_err(|_| ResolverError::Unavailable)?;
                forward_udp(&socket, endpoint, query, LIMIT, &mut cancel).await
            }
        };
        let response = timeout(LIMIT, transport)
            .await
            .map_err(|_| ResolverError::Timeout)??;
        response.reject_addresses(is_reserved_fake)?;
        Ok(response.packet)
    }
}

fn is_reserved_fake(address: IpAddr) -> bool {
    let address = address.to_canonical();
    FAKE_POOLS
        .iter()
        .any(|(network, length)| match (*network, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                u32::from(address) & (u32::MAX << (32 - length)) == u32::from(base)
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                u128::from(address) & (u128::MAX << (128 - length)) == u128::from(base)
            }
            _ => false,
        })
}
