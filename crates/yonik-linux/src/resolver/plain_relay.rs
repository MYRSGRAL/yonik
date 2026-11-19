//! Передача реального DNS прежнему resolver через заранее проверенный маршрут.
use super::{
    ResolverError,
    dot::DotPeer,
    forward::{forward_framed, forward_tcp, forward_udp},
};
use crate::{Cancellation, TransportProtocol, managed_network::FAKE_POOLS};
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
const OPPORTUNISTIC_HANDSHAKE_LIMIT: Duration = Duration::from_secs(1);
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
    plain: Option<SocketAddr>,
}

pub(crate) fn relay_paths(
    peer: SocketAddr,
    tls: bool,
    plain: Option<SocketAddr>,
) -> impl Iterator<Item = (SocketAddr, TransportProtocol)> {
    use TransportProtocol::{Tcp, Udp};
    [
        tls.then_some((peer, Tcp)),
        plain
            .filter(|&address| !tls || address != peer)
            .map(|address| (address, Tcp)),
        plain.map(|address| (address, Udp)),
    ]
    .into_iter()
    .flatten()
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
            plain: Some(peer),
        })
    }

    pub fn with_dot(mut self, dot: DotPeer, plain: Option<SocketAddr>) -> Self {
        self.dot = Some(dot);
        self.plain = plain;
        self
    }

    pub fn upstreams(&self) -> impl Iterator<Item = (SocketAddr, TransportProtocol)> {
        relay_paths(self.peer, self.dot.is_some(), self.plain)
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
        let transport = async {
            if let Some(dot) = &self.dot {
                let limit = if self.plain.is_some() {
                    OPPORTUNISTIC_HANDSHAKE_LIMIT
                } else {
                    LIMIT
                };
                let negotiated = timeout(limit, async {
                    let mut stream = self.connect_tcp(self.peer).await?;
                    let tls = dot.handshake(&mut stream).await?;
                    Ok((stream, tls))
                })
                .await
                .map_err(|_| ResolverError::Timeout)
                .and_then(std::convert::identity);
                match negotiated {
                    Ok((mut stream, tls)) => {
                        return forward_framed(query, LIMIT, &mut cancel, async |outbound| {
                            dot.exchange(&mut stream, tls, outbound).await
                        })
                        .await;
                    }
                    Err(
                        ResolverError::Unavailable
                        | ResolverError::Closed
                        | ResolverError::Timeout
                        | ResolverError::Untrusted,
                    ) if self.plain.is_some() => {}
                    Err(error) => return Err(error),
                }
            }
            let endpoint = self.plain.ok_or(ResolverError::Unavailable)?;
            if tcp {
                let mut stream = self.connect_tcp(endpoint).await?;
                forward_tcp(&mut stream, endpoint, query, LIMIT, &mut cancel).await
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

    async fn connect_tcp(&self, endpoint: SocketAddr) -> Result<TcpStream, ResolverError> {
        let socket = if endpoint.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .map_err(|_| ResolverError::Unavailable)?;
        mark_unconnected_dns_socket(&socket, self.mark)
            .map_err(|_| ResolverError::PermissionDenied)?;
        socket
            .connect(endpoint)
            .await
            .map_err(|_| ResolverError::Unavailable)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opportunistic_routes_cover_both_transports_without_duplicate_tcp() {
        use TransportProtocol::{Tcp, Udp};
        let tls = SocketAddr::from(([192, 0, 2, 1], 853));
        let plain = SocketAddr::from(([192, 0, 2, 1], 53));
        assert_eq!(
            relay_paths(tls, true, Some(plain)).collect::<Vec<_>>(),
            [(tls, Tcp), (plain, Tcp), (plain, Udp)]
        );
        assert_eq!(
            relay_paths(tls, true, Some(tls)).collect::<Vec<_>>(),
            [(tls, Tcp), (tls, Udp)]
        );
        assert_eq!(
            relay_paths(tls, true, None).collect::<Vec<_>>(),
            [(tls, Tcp)]
        );
    }
}
