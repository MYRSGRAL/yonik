//! Runtime lease: не serde, не UI DTO, без собственного DNS cache/epoch model.
use super::{BindingError, LinuxTopology, NetworkStamp, PrivateBindings};
use crate::{
    Cancellation,
    network::{
        NetworkWatch, RouteKind, RouteQuery, TransportProtocol, lookup_route, read_topology,
    },
    resolver::{
        ResolverError,
        forward::{
            ForwardResponse, boottime_now, forward_tcp, forward_udp, is_reserved_fake,
            private_forward_query,
        },
    },
};
use std::{
    future::{Future, poll_fn},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::{NonZeroU16, NonZeroU32},
    os::{fd::AsFd, unix::fs::MetadataExt},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};
use tokio::net::{TcpSocket, UdpSocket};
use yonik_engine::{
    CompiledConfig, Engine, PolicyCompileError, PolicyMode,
    private_dns::{DnsEpoch, DnsPolicy, DomainPattern, Policy, PrivateDnsRoute},
};
use yonik_import::ParsedServer;
use yonik_nsfs::socket_namespace::bind_unconnected_private_dns_socket;

const MAX_LEASE: Duration = Duration::from_secs(30);
const MAX_READ: Duration = Duration::from_secs(3);

struct ResolverDeadline {
    monotonic: Instant,
    boottime: Duration,
}

impl ResolverDeadline {
    fn new(monotonic: Instant) -> Result<Self, BindingError> {
        let started = boottime_now().ok_or(BindingError::Stale)?;
        let duration = monotonic
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero() && *duration <= MAX_LEASE)
            .ok_or(BindingError::Stale)?;
        let boottime = started.checked_add(duration).ok_or(BindingError::Stale)?;
        Ok(Self {
            monotonic,
            boottime,
        })
    }

    fn remaining_at(
        &self,
        monotonic: Instant,
        boottime: Duration,
    ) -> Result<Duration, BindingError> {
        let remaining = self
            .monotonic
            .saturating_duration_since(monotonic)
            .min(self.boottime.saturating_sub(boottime));
        if remaining.is_zero() {
            Err(BindingError::Stale)
        } else {
            Ok(remaining.min(MAX_READ))
        }
    }
}

struct Revalidation<'a> {
    revoked: &'a AtomicBool,
    verified: bool,
}

impl Drop for Revalidation<'_> {
    fn drop(&mut self) {
        if !self.verified {
            self.revoked.store(true, Ordering::Release);
        }
    }
}

pub struct VerifiedPrivateResolver {
    route: PrivateDnsRoute,
    stamp: NetworkStamp,
    topology: Arc<LinuxTopology>,
    revoked: Arc<AtomicBool>,
    expires_at: ResolverDeadline,
    epoch: DnsEpoch,
    index: u32,
    table: u32,
    uid: u32,
    mark: u32,
}
#[derive(Debug)]
pub enum PrivateDnsCompileError {
    Binding(BindingError),
    Compiler(PolicyCompileError),
}
impl PrivateBindings {
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_private_resolver(
        &self,
        route: PrivateDnsRoute,
        expires_at: Instant,
        epoch: DnsEpoch,
        uid: u32,
        mark: u32,
        watch: &NetworkWatch,
        cancel: &mut Cancellation,
    ) -> Result<VerifiedPrivateResolver, BindingError> {
        if self.invalidated.load(Ordering::Acquire) {
            return Err(BindingError::Stale);
        }
        let request =
            self.requests
                .iter()
                .find(|r| {
                    r.wireguard
                        && r.prefix.contains(route.resolver().ip())
                        && self.topology.links.iter().any(|l| {
                            l.index == r.ifindex && l.name == route.bind_ifname().as_bytes()
                        })
                })
                .ok_or(BindingError::MissingPath)?;
        let expires_at = ResolverDeadline::new(expires_at).inspect_err(|_| {
            self.invalidated.store(true, Ordering::Release);
        })?;
        let mut token = VerifiedPrivateResolver {
            route,
            stamp: self.stamp,
            topology: Arc::clone(&self.topology),
            revoked: Arc::clone(&self.invalidated),
            expires_at,
            epoch,
            index: request.ifindex,
            table: request.table,
            uid,
            mark,
        };
        token.revalidate(epoch, watch, cancel).await?;
        Ok(token)
    }
}
impl VerifiedPrivateResolver {
    /// Отправляет запрос из подтверждённой зоны одним транспортом.
    /// Закрытие watcher или истечение срока исключает выдачу ответа.
    pub async fn exchange(
        &mut self,
        query: &[u8],
        transport: TransportProtocol,
        epoch: DnsEpoch,
        watch: &NetworkWatch,
        cancel: &mut Cancellation,
    ) -> Result<ForwardResponse, ResolverError> {
        let (name, query) = private_forward_query(query)?;
        let zone = self.route.zone();
        let expected = zone.name().as_str();
        // Wire-имена сервисов могут содержать подчёркивания.
        let in_zone = name == expected
            || matches!(zone, DomainPattern::Suffix(_))
                && name
                    .strip_suffix(expected)
                    .is_some_and(|prefix| prefix.ends_with('.'));
        if !in_zone || self.uid != rustix::process::geteuid().as_raw() {
            return Err(ResolverError::Untrusted);
        }
        self.revalidate(epoch, watch, cancel)
            .await
            .map_err(|_| ResolverError::Untrusted)?;
        let remaining = |cancel: &Cancellation| {
            self.remaining(epoch, watch, cancel)
                .map_err(|_| ResolverError::Untrusted)
        };
        let budget = remaining(cancel)?;
        let mut stop = cancel.clone();
        let proof_cancel = cancel.clone();
        let transfer = async {
            // Проверяем namespace в том же потоке, который создаёт сокет.
            let namespace = std::fs::metadata("/proc/thread-self/ns/net")
                .map_err(|_| ResolverError::Untrusted)?;
            if namespace.dev() != self.topology.namespace.device
                || namespace.ino() != self.topology.namespace.inode
            {
                return Err(ResolverError::Untrusted);
            }
            let peer = self.route.resolver();
            let response = match transport {
                TransportProtocol::Udp => {
                    let local = if peer.is_ipv4() {
                        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
                    } else {
                        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
                    };
                    let socket =
                        std::net::UdpSocket::bind(local).map_err(|_| ResolverError::Unavailable)?;
                    socket
                        .set_nonblocking(true)
                        .map_err(|_| ResolverError::Unavailable)?;
                    self.prepare_socket(&socket)?;
                    let socket =
                        UdpSocket::from_std(socket).map_err(|_| ResolverError::Unavailable)?;
                    remaining(cancel)?;
                    socket
                        .connect(peer)
                        .await
                        .map_err(|_| ResolverError::Unavailable)?;
                    forward_udp(&socket, peer, &query, remaining(cancel)?, cancel).await?
                }
                TransportProtocol::Tcp => {
                    let socket = if peer.is_ipv4() {
                        TcpSocket::new_v4()
                    } else {
                        TcpSocket::new_v6()
                    }
                    .map_err(|_| ResolverError::Unavailable)?;
                    self.prepare_socket(&socket)?;
                    remaining(cancel)?;
                    let mut stream = socket
                        .connect(peer)
                        .await
                        .map_err(|_| ResolverError::Unavailable)?;
                    forward_tcp(&mut stream, peer, &query, remaining(cancel)?, cancel).await?
                }
            };
            response.reject_addresses(is_reserved_fake)?;
            Ok(response)
        };
        tokio::pin!(transfer);
        // После ожидания готовности сокета и пробуждения сверяем исходный BOOTTIME.
        let guarded = poll_fn(|cx| {
            if let Err(error) = remaining(&proof_cancel) {
                return Poll::Ready(Err(error));
            }
            transfer.as_mut().poll(cx)
        });
        let mut changes = watch.clone();
        let response = tokio::select! {
            biased;
            () = stop.cancelled() => Err(ResolverError::Cancelled),
            result = changes.run_while_current(self.stamp, tokio::time::timeout(budget, guarded)) => {
                result.ok_or(ResolverError::Untrusted)?.map_err(|_| ResolverError::Timeout)?
            }
        }?;
        remaining(&proof_cancel)?;
        Ok(response)
    }

    fn prepare_socket(&self, socket: &impl AsFd) -> Result<(), ResolverError> {
        let stat = rustix::fs::fstat(socket).map_err(|_| ResolverError::Untrusted)?;
        // Ядро назначает UID при создании сокета по FSUID вызывающего потока.
        if stat.st_uid != self.uid {
            return Err(ResolverError::Untrusted);
        }
        let index = NonZeroU32::new(self.index).ok_or(ResolverError::Untrusted)?;
        bind_unconnected_private_dns_socket(socket, index, self.mark)
            .map_err(|_| ResolverError::Untrusted)
    }

    /// Проверяет BOTH transport contexts без принудительного oif, иначе lookup
    /// мог бы скрыть конфликт RPDB. UID/mark закреплены на весь срок lease.
    pub async fn revalidate(
        &mut self,
        epoch: DnsEpoch,
        watch: &NetworkWatch,
        cancel: &mut Cancellation,
    ) -> Result<(), BindingError> {
        // Drop future между чтениями отзывает общий допуск наравне с ошибкой.
        let mut revalidation = Revalidation {
            revoked: &self.revoked,
            verified: false,
        };
        let result = watch
            .clone()
            .run_while_current(self.stamp, self.check(epoch, watch, cancel))
            .await
            .unwrap_or(Err(BindingError::Stale));
        revalidation.verified = result.is_ok();
        result
    }

    fn remaining(
        &self,
        epoch: DnsEpoch,
        watch: &NetworkWatch,
        cancel: &Cancellation,
    ) -> Result<Duration, BindingError> {
        let snapshot = watch.current();
        if self.revoked.load(Ordering::Acquire)
            || cancel.check().is_err()
            || epoch != self.epoch
            || !snapshot.fully_observed()
            || !snapshot.is_current(self.stamp)
        {
            return Err(BindingError::Stale);
        }
        self.expires_at
            .remaining_at(Instant::now(), boottime_now().ok_or(BindingError::Stale)?)
    }

    async fn check(
        &self,
        epoch: DnsEpoch,
        watch: &NetworkWatch,
        cancel: &mut Cancellation,
    ) -> Result<(), BindingError> {
        let deadline = self.remaining(epoch, watch, cancel)?;
        let topology = read_topology(cancel, deadline)
            .await
            .map_err(|_| BindingError::Stale)?;
        if !crate::network::same_external_topology(&topology, &self.topology) {
            return Err(BindingError::Stale);
        }
        for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
            let query = RouteQuery::new(self.route.resolver().ip(), self.uid)
                .with_mark(self.mark)
                .with_transport(protocol, None, Some(self.route.resolver().port()));
            let deadline = self.remaining(epoch, watch, cancel)?;
            let route = lookup_route(query, cancel, deadline)
                .await
                .map_err(|_| BindingError::MissingPath)?;
            if route.namespace != self.topology.namespace
                || route.kind != RouteKind::Unicast
                || route.output_interface.map(|i| i.get()) != Some(self.index)
                || route.table != Some(self.table)
                || !route.incomplete.is_empty()
            {
                return Err(BindingError::MissingPath);
            }
        }
        self.remaining(epoch, watch, cancel)?;
        Ok(())
    }
    /// Поглощает lease непосредственно перед compiler; повторное использование
    /// после epoch/expiry требует нового capture. Host перепроверяет перед dial.
    #[allow(clippy::too_many_arguments)]
    pub async fn compile(
        mut self,
        epoch: DnsEpoch,
        watch: &NetworkWatch,
        cancel: &mut Cancellation,
        server: &ParsedServer,
        engine: Engine,
        port: NonZeroU16,
        probe_port: NonZeroU16,
        policy: &Policy,
        mode: PolicyMode,
        dns: &DnsPolicy,
    ) -> Result<CompiledConfig, PrivateDnsCompileError> {
        self.revalidate(epoch, watch, cancel)
            .await
            .map_err(PrivateDnsCompileError::Binding)?;
        yonik_engine::private_dns::compile_native_dns_with_private(
            server,
            engine,
            port,
            probe_port,
            policy,
            mode,
            dns,
            &[self.route],
        )
        .map_err(PrivateDnsCompileError::Compiler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        task::{Context, Waker},
    };

    #[test]
    fn sleep_expires_the_resolver_lease_while_monotonic_time_stands_still() {
        let now = Instant::now();
        let before_suspend = Duration::from_secs(100);
        let deadline = ResolverDeadline {
            monotonic: now + Duration::from_secs(10),
            boottime: before_suspend + Duration::from_secs(10),
        };
        assert_eq!(deadline.remaining_at(now, before_suspend), Ok(MAX_READ));
        assert_eq!(
            deadline.remaining_at(now, before_suspend + Duration::from_secs(9)),
            Ok(Duration::from_secs(1))
        );
        assert_eq!(
            deadline.remaining_at(now, before_suspend + Duration::from_secs(10)),
            Err(BindingError::Stale)
        );
    }

    #[test]
    fn revalidation_drop_revokes_the_shared_binding() {
        let revoked = AtomicBool::new(false);
        let mut work = Box::pin(async {
            let _revalidation = Revalidation {
                revoked: &revoked,
                verified: false,
            };
            std::future::pending::<()>().await;
        });
        assert!(
            work.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert!(!revoked.load(Ordering::Acquire));
        drop(work);
        assert!(revoked.load(Ordering::Acquire));
    }
}
