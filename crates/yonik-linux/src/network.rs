//! Событийное наблюдение окружения. Не применяет маршруты, DNS или TUN.

mod bus;
mod equivalence;
#[cfg(test)]
pub(crate) use equivalence::diagnostic_class_matches;
pub(crate) use equivalence::{
    same_captured_kernel_route, same_captured_topology, same_external_topology,
};
mod lookup;
pub(crate) use equivalence::RouteCapture;
pub(crate) use lookup::lookup_route_captured;
mod read;
mod route;
mod topology;
mod wireguard;
pub use lookup::{
    KernelRoute, LookupIncomplete, RouteKind, RouteQuery, TransportProtocol, lookup_route,
};
pub use read::{NetworkAttribute, NetworkNamespace, NetworkReadError};
pub use topology::{
    IpPrefix, LinuxAddress, LinuxLink, LinuxNexthop, LinuxRoute, LinuxRule, LinuxTopology,
    NexthopMember, RouteNexthop, read_topology,
};
pub(crate) use topology::{TopologyCapture, read_topology_captured, reread_changed_topology};
pub use wireguard::{WireGuardDevice, WireGuardPeer, read_wireguard_device};

use std::fmt;
use tokio::sync::watch;

/// Покрытие источников наблюдения; доступность одного не заменяет остальные.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkCoverage {
    pub routes: bool,
    pub resolver: bool,
    pub manager: bool,
}

/// Только для проверки свежести в текущем процессе, не lease применения TUN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkStamp {
    instance: [u8; 16],
    generation: u64,
}
impl fmt::Display for NetworkStamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.instance {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ":{}", self.generation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkSnapshot {
    pub stamp: NetworkStamp,
    pub coverage: NetworkCoverage,
    pub exhausted: bool,
}
impl NetworkSnapshot {
    pub fn is_current(self, stamp: NetworkStamp) -> bool {
        !self.exhausted && self.stamp == stamp
    }
    pub fn fully_observed(self) -> bool {
        !self.exhausted && self.coverage.routes && self.coverage.resolver && self.coverage.manager
    }
}

/// Ограниченный последним значением канал. Не удерживает watch::Ref через await.
#[derive(Clone)]
pub struct NetworkWatch(watch::Receiver<NetworkSnapshot>);
impl NetworkWatch {
    pub fn current(&self) -> NetworkSnapshot {
        *self.0.borrow()
    }
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.0.changed().await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkMonitorError {
    Runtime,
    Entropy,
}
impl fmt::Display for NetworkMonitorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Runtime => "Нет асинхронного окружения",
            Self::Entropy => "Не удалось создать идентификатор наблюдения",
        })
    }
}
impl std::error::Error for NetworkMonitorError {}

/// Владелец двух задач и их отмены. Завершение ограничено общим deadline.
pub struct NetworkMonitor {
    watch: NetworkWatch,
    cancel: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<bool>>,
}
impl NetworkMonitor {
    pub fn start() -> Result<Self, NetworkMonitorError> {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| NetworkMonitorError::Runtime)?;
        let mut instance = [0; 16];
        getrandom::getrandom(&mut instance).map_err(|_| NetworkMonitorError::Entropy)?;
        let (sender, receiver) = watch::channel(NetworkSnapshot {
            stamp: NetworkStamp {
                instance,
                generation: 0,
            },
            coverage: NetworkCoverage::default(),
            exhausted: false,
        });
        let publisher = NetworkPublisher(sender);
        let (cancel, cancelled) = watch::channel(false);
        let routes = publisher.clone();
        let route_cancel = cancelled.clone();
        let route_task = runtime.spawn(async move {
            let _guard = SourceGuard(routes.clone(), vec![NetworkSource::Routes]);
            route::run(routes, route_cancel).await;
            true
        });
        let bus_task = runtime.spawn(async move {
            let _guard = SourceGuard(
                publisher.clone(),
                vec![NetworkSource::Resolver, NetworkSource::Manager],
            );
            bus::run(publisher, cancelled).await
        });
        Ok(Self {
            watch: NetworkWatch(receiver),
            cancel,
            tasks: vec![route_task, bus_task],
        })
    }
    pub fn watch(&self) -> NetworkWatch {
        self.watch.clone()
    }
    pub async fn shutdown(mut self) -> bool {
        self.cancel.send_replace(true);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut closed = true;
        for mut task in self.tasks.drain(..) {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(Ok(true)) => {}
                Ok(_) => closed = false,
                Err(_) => {
                    task.abort();
                    closed = false;
                }
            }
        }
        closed
    }
}
impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
    }
}

struct SourceGuard(NetworkPublisher, Vec<NetworkSource>);
impl Drop for SourceGuard {
    fn drop(&mut self) {
        for source in &self.1 {
            self.0.lost(*source);
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum NetworkSource {
    Routes,
    Resolver,
    Manager,
}

#[derive(Clone)]
pub(super) struct NetworkPublisher(watch::Sender<NetworkSnapshot>);

impl NetworkPublisher {
    fn ready(&self, source: NetworkSource) {
        self.availability(source, true);
    }
    fn changed(&self, _source: NetworkSource) {
        self.0.send_modify(Self::advance);
    }
    fn lost(&self, source: NetworkSource) {
        self.availability(source, false);
    }
    fn availability(&self, source: NetworkSource, available: bool) {
        self.0.send_if_modified(|state| {
            if state.exhausted {
                return false;
            }
            let previous = match source {
                NetworkSource::Routes => &mut state.coverage.routes,
                NetworkSource::Resolver => &mut state.coverage.resolver,
                NetworkSource::Manager => &mut state.coverage.manager,
            };
            if *previous == available {
                return false;
            }
            *previous = available;
            Self::advance(state);
            true
        });
    }
    fn advance(state: &mut NetworkSnapshot) {
        match state.stamp.generation.checked_add(1) {
            Some(generation) if !state.exhausted => state.stamp.generation = generation,
            _ => {
                state.exhausted = true;
                state.coverage = NetworkCoverage::default();
            }
        }
    }
}

// Синтетические source-availability inputs, НЕ наблюдения real service monitor.
#[cfg(test)]
pub(crate) fn unit_source_publisher() -> (NetworkPublisher, NetworkWatch) {
    let (tx, rx) = watch::channel(NetworkSnapshot {
        stamp: NetworkStamp {
            instance: [0x73; 16],
            generation: 0,
        },
        coverage: NetworkCoverage::default(),
        exhausted: false,
    });
    (NetworkPublisher(tx), NetworkWatch(rx))
}
#[cfg(test)]
impl NetworkPublisher {
    pub(crate) fn unit_ready(&self, source: NetworkSource) {
        self.ready(source);
    }
    pub(crate) fn unit_changed(&self, source: NetworkSource) {
        self.changed(source);
    }
    pub(crate) fn unit_lost(&self, source: NetworkSource) {
        self.lost(source);
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn shutdown_bounds_unresponsive_observer() {
        let (_, receiver) = publisher();
        let (cancel, _) = tokio::sync::watch::channel(false);
        let monitor = super::NetworkMonitor {
            watch: super::NetworkWatch(receiver),
            cancel,
            tasks: vec![tokio::spawn(std::future::pending())],
        };
        let closed = tokio::time::timeout(std::time::Duration::from_secs(4), monitor.shutdown())
            .await
            .expect("зависший observer не блокирует shutdown бессрочно");
        assert!(!closed, "timeout не подтверждает cleanup");
    }
    use super::*;

    fn publisher() -> (NetworkPublisher, watch::Receiver<NetworkSnapshot>) {
        let (tx, rx) = watch::channel(NetworkSnapshot {
            stamp: NetworkStamp {
                instance: [1; 16],
                generation: 0,
            },
            coverage: NetworkCoverage::default(),
            exhausted: false,
        });
        (NetworkPublisher(tx), rx)
    }

    #[test]
    fn readiness_and_loss_invalidate_previous_stamp() {
        let (publisher, rx) = publisher();
        let initial = *rx.borrow();
        publisher.ready(NetworkSource::Routes);
        let ready = *rx.borrow();
        assert!(ready.coverage.routes);
        assert_ne!(initial.stamp, ready.stamp);
        publisher.ready(NetworkSource::Routes);
        assert_eq!(ready, *rx.borrow());
        publisher.lost(NetworkSource::Routes);
        let lost = *rx.borrow();
        assert!(!lost.coverage.routes);
        assert_ne!(ready.stamp, lost.stamp);
    }

    #[test]
    fn coalescing_keeps_newest_generation_without_unbounded_queue() {
        let (publisher, rx) = publisher();
        publisher.ready(NetworkSource::Resolver);
        let before = rx.borrow().stamp;
        for _ in 0..10_000 {
            publisher.changed(NetworkSource::Resolver);
        }
        assert_eq!(rx.borrow().stamp.generation, before.generation + 10_000);
    }

    #[test]
    fn exhausted_generation_never_revalidates_old_stamp() {
        let (publisher, rx) = publisher();
        publisher.0.send_modify(|state| {
            state.stamp.generation = u64::MAX;
            state.coverage.routes = true;
        });
        publisher.changed(NetworkSource::Routes);
        assert!(rx.borrow().exhausted);
        assert_eq!(rx.borrow().coverage, NetworkCoverage::default());
        publisher.ready(NetworkSource::Routes);
        assert!(!rx.borrow().coverage.routes);
    }
}
