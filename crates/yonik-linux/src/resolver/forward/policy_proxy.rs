//! DNS для классификации через выбранный прокси и явный адрес резолвера.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use yonik_engine::fake_dns::DomainName;

use super::{
    ForwardPeer, ForwardResponse, PolicyRrset, ResolverError, forward_tcp_for_peer,
    is_reserved_fake, run_cancellable,
};
use crate::{
    Cancellation,
    fake_flow::{FakeFlowError, SocksCredentials, connect_core_literal},
};

/// Один путь к явно выбранному DNS-over-TCP узлу за авторизованным SOCKS.
/// Helper хранит экземпляр в пределах активной сессии.
pub struct PolicyProxyResolver {
    proxy: SocketAddr,
    upstream: SocketAddr,
    credentials: SocksCredentials,
}

impl PolicyProxyResolver {
    pub fn new(
        proxy: SocketAddr,
        upstream: SocketAddr,
        credentials: SocksCredentials,
    ) -> Result<Arc<Self>, ResolverError> {
        if [proxy, upstream].into_iter().any(|address| {
            address.port() == 0 || matches!(address, SocketAddr::V6(value) if value.scope_id() != 0)
        }) {
            return Err(ResolverError::Untrusted);
        }
        let proxy = SocketAddr::new(proxy.ip().to_canonical(), proxy.port());
        let upstream = SocketAddr::new(upstream.ip().to_canonical(), upstream.port());
        if !proxy.ip().is_loopback() || !valid_upstream(upstream.ip()) {
            return Err(ResolverError::Untrusted);
        }
        Ok(Arc::new(Self {
            proxy,
            upstream,
            credentials,
        }))
    }

    pub async fn lookup(
        self: &Arc<Self>,
        name: &DomainName,
        budget: Duration,
        cancel: &mut Cancellation,
    ) -> Result<PolicyRrset, ResolverError> {
        if budget.is_zero() || budget > Duration::from_secs(10) {
            return Err(ResolverError::Limit);
        }
        let (mut cancel_a, mut cancel_aaaa) = (cancel.clone(), cancel.clone());
        run_cancellable(cancel, budget, async {
            let (a, aaaa) = tokio::try_join!(
                self.query(name, 1, budget, &mut cancel_a),
                self.query(name, 28, budget, &mut cancel_aaaa),
            )?;
            a.policy_address_pair(&aaaa)
        })
        .await
    }

    async fn query(
        self: &Arc<Self>,
        name: &DomainName,
        kind: u16,
        budget: Duration,
        cancel: &mut Cancellation,
    ) -> Result<ForwardResponse, ResolverError> {
        let mut stream = connect_core_literal(self.proxy, self.upstream, &self.credentials)
            .await
            .map_err(|error| match error {
                FakeFlowError::Io(_) => ResolverError::Unavailable,
                _ => ResolverError::Untrusted,
            })?;
        let response = forward_tcp_for_peer(
            &mut stream,
            &dns_question(name, kind),
            budget,
            cancel,
            ForwardPeer::Proxy(Arc::clone(self)),
        )
        .await?;
        response.verify_policy_status()?;
        response.reject_addresses(is_reserved_fake)?;
        Ok(response)
    }
}

fn valid_upstream(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !is_reserved_fake(address)
        && match address {
            IpAddr::V4(value) => !value.is_link_local() && (1..240).contains(&value.octets()[0]),
            IpAddr::V6(value) => !value.is_unicast_link_local(),
        }
}

fn dns_question(name: &DomainName, kind: u16) -> Vec<u8> {
    let name = name.as_str();
    let mut query = Vec::with_capacity(name.len() + 18);
    query.extend_from_slice(&[0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&kind.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    const UPSTREAM: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 5353);
    const ANSWER_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 3);
    const NAME: &[u8] = b"\x04host\x04test\x00";

    fn credentials() -> SocksCredentials {
        SocksCredentials::new(b"resolver", b"fixture").unwrap()
    }

    async fn receive_question(mut socket: TcpStream) -> (TcpStream, Vec<u8>, u16) {
        let mut greeting = [0; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        socket.write_all(&[5, 2]).await.unwrap();
        let mut auth = [0; 18];
        socket.read_exact(&mut auth).await.unwrap();
        assert_eq!(&auth, b"\x01\x08resolver\x07fixture");
        socket.write_all(&[1, 0]).await.unwrap();
        let mut connect = [0; 10];
        socket.read_exact(&mut connect).await.unwrap();
        assert_eq!(&connect[..4], &[5, 1, 0, 1]);
        assert_eq!(&connect[4..8], &[192, 0, 2, 53]);
        assert_eq!(&connect[8..10], &UPSTREAM.port().to_be_bytes());
        socket
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let size = socket.read_u16().await.unwrap();
        let mut packet = vec![0; usize::from(size)];
        socket.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet[2..12], &[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&packet[12..12 + NAME.len()], NAME);
        let suffix = &packet[12 + NAME.len()..];
        assert_eq!(&suffix[2..], &1u16.to_be_bytes());
        let kind = u16::from_be_bytes(suffix[..2].try_into().unwrap());
        (socket, packet, kind)
    }

    async fn answer(question: (TcpStream, Vec<u8>, u16)) {
        let (mut socket, mut packet, kind) = question;
        packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        let v6: std::net::Ipv6Addr = "2001:db8::9".parse().unwrap();
        let a = ANSWER_A.octets();
        let aaaa = v6.octets();
        let address: &[u8] = match kind {
            1 => &a,
            28 => &aaaa,
            _ => panic!("неподдерживаемое семейство"),
        };
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&20u32.to_be_bytes());
        packet.extend_from_slice(&(address.len() as u16).to_be_bytes());
        packet.extend_from_slice(address);
        socket.write_u16(packet.len() as u16).await.unwrap();
        socket.write_all(&packet).await.unwrap();
    }

    #[tokio::test]
    async fn пара_dns_идёт_по_авторизованному_socks_к_буквальному_узлу() {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver =
            PolicyProxyResolver::new(server.local_addr().unwrap(), UPSTREAM, credentials())
                .unwrap();
        let peer = tokio::spawn(async move {
            let (a, _) = server.accept().await.unwrap();
            let (b, _) = server.accept().await.unwrap();
            let (first, second) = tokio::join!(receive_question(a), receive_question(b));
            assert!([1, 28].contains(&first.2));
            assert_eq!(first.2 + second.2, 29);
            tokio::join!(answer(first), answer(second));
        });
        let (_owner, mut cancel) = Cancellation::new();
        let result = resolver
            .lookup(
                &"host.test".parse().unwrap(),
                Duration::from_secs(2),
                &mut cancel,
            )
            .await
            .unwrap();
        assert_eq!(
            result.addresses(),
            &[ANSWER_A.into(), "2001:db8::9".parse::<IpAddr>().unwrap()]
        );
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn servfail_одного_семейства_отклоняет_весь_набор() {
        проверить_отказ_aaaa(false).await;
    }

    #[tokio::test]
    async fn общий_дедлайн_закрывает_незавершённый_dns_поток() {
        проверить_отказ_aaaa(true).await;
    }

    #[tokio::test]
    async fn servfail_сразу_отменяет_второй_dns_запрос() {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver =
            PolicyProxyResolver::new(server.local_addr().unwrap(), UPSTREAM, credentials())
                .unwrap();
        let peer = tokio::spawn(async move {
            let (first, _) = server.accept().await.unwrap();
            let (second, _) = server.accept().await.unwrap();
            let (left, right) = tokio::join!(receive_question(first), receive_question(second));
            assert_eq!(left.2 + right.2, 29);
            let (mut refused, mut packet, _) = left;
            let (mut pending, _, _) = right;
            packet[2..4].copy_from_slice(&0x8182u16.to_be_bytes());
            refused.write_u16(packet.len() as u16).await.unwrap();
            refused.write_all(&packet).await.unwrap();
            assert_eq!(pending.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let (_owner, mut cancel) = Cancellation::new();
        let name = "host.test".parse().unwrap();
        let result = timeout(
            Duration::from_secs(1),
            resolver.lookup(&name, Duration::from_secs(5), &mut cancel),
        )
        .await
        .expect("SERVFAIL должен сразу закрыть пару");
        assert_eq!(result, Err(ResolverError::Untrusted));
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }

    async fn проверить_отказ_aaaa(ожидать_дедлайн: bool) {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver =
            PolicyProxyResolver::new(server.local_addr().unwrap(), UPSTREAM, credentials())
                .unwrap();
        let peer = tokio::spawn(async move {
            let (first, _) = server.accept().await.unwrap();
            let (second, _) = server.accept().await.unwrap();
            let (left, right) = tokio::join!(receive_question(first), receive_question(second));
            let (a, (mut socket, mut packet, kind)) = if left.2 == 1 {
                (left, right)
            } else {
                (right, left)
            };
            assert_eq!((a.2, kind), (1, 28));
            answer(a).await;
            if ожидать_дедлайн {
                assert_eq!(socket.read(&mut [0; 1]).await.unwrap(), 0);
            } else {
                packet[2..4].copy_from_slice(&0x8182u16.to_be_bytes());
                socket.write_u16(packet.len() as u16).await.unwrap();
                socket.write_all(&packet).await.unwrap();
            }
            assert!(
                timeout(Duration::from_millis(100), server.accept())
                    .await
                    .is_err()
            );
        });
        let (_owner, mut cancel) = Cancellation::new();
        let (budget, expected) = if ожидать_дедлайн {
            (Duration::from_millis(500), ResolverError::Timeout)
        } else {
            (Duration::from_secs(2), ResolverError::Untrusted)
        };
        assert_eq!(
            resolver
                .lookup(&"host.test".parse().unwrap(), budget, &mut cancel)
                .await,
            Err(expected)
        );
        timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn отклоняет_непригодные_узлы_до_открытия_сокета() {
        let proxy = "127.0.0.1:1080".parse().unwrap();
        for upstream in [
            "127.0.0.1:53",
            "192.0.2.53:0",
            "224.0.0.1:53",
            "198.19.224.2:53",
            "[::ffff:198.19.224.2]:53",
            "[fd79:6f69:6b00:5c01::2]:53",
            "[fe80::1%2]:53",
            "255.255.255.255:53",
        ] {
            assert!(
                matches!(
                    PolicyProxyResolver::new(proxy, upstream.parse().unwrap(), credentials()),
                    Err(ResolverError::Untrusted)
                ),
                "Принят непригодный DNS-узел {upstream}"
            );
        }
        assert!(matches!(
            PolicyProxyResolver::new(UPSTREAM, UPSTREAM, credentials()),
            Err(ResolverError::Untrusted)
        ));
    }
}
