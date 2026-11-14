//! Закрытый lifecycle producer. Подключение compile/issuer требует отдельного leaf.
use super::{ServiceError, SessionArtifact};
use crate::helper::{run_authorization::RunAuthority, systemd_worker::AuthorizedRun};
use std::{collections::BTreeSet, sync::Arc};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct NativeArtifactStamp {
    session: [u8; 16],
    generation: u64,
}

/// Создаётся только consuming commit после exact record/queue проверки.
pub(in crate::helper) struct OwnerBinding {
    owner: crate::managed_network::Ownership,
    session: [u8; 16],
    generation: u64,
    epoch: u64,
}
impl OwnerBinding {
    pub(in crate::helper) fn context(&self) -> ([u8; 16], u64, u64) {
        (self.session, self.generation, self.epoch)
    }
    pub(in crate::helper) fn ownership(&self) -> crate::managed_network::Ownership {
        self.owner
    }
}
// Поля удерживают exact immutable artifact/queue и целый authorized run.
// Пока runtime caller запрещён, эти типы создаются только закрытым producer.
#[allow(dead_code)]
struct NativeOwnerLease<A, Q, R> {
    artifact: A,
    queue: Q,
    network_stamp: crate::NetworkStamp,
    network_epoch: u64,
    owner: crate::managed_network::Ownership,
    authority: RunAuthority,
    run: Option<R>,
}

pub(in super::super) struct NativeOwnerState<
    A = Arc<SessionArtifact>,
    Q = Arc<crate::managed_network::tun::BoundTun>,
    R = AuthorizedRun,
> {
    session: Option<[u8; 16]>,
    last_generation: u64,
    consumed: BTreeSet<u64>,
    lease: Option<NativeOwnerLease<A, Q, R>>,
    active: Option<NativeOwnerLease<A, Q, R>>,
}
impl<A, Q, R> NativeOwnerState<A, Q, R> {
    pub(in super::super) fn fresh() -> Self {
        let mut session = [0; 16];
        let valid = getrandom::getrandom(&mut session).is_ok() && session != [0; 16];
        Self::from_session(valid.then_some(session))
    }
    fn from_session(session: Option<[u8; 16]>) -> Self {
        Self {
            session: session.filter(|id| *id != [0; 16]),
            last_generation: 0,
            consumed: BTreeSet::new(),
            lease: None,
            active: None,
        }
    }
    // Нет production caller: legacy compile намеренно оставляет stamp=None.
    #[allow(dead_code)]
    pub(super) fn reserve(&mut self) -> Result<NativeArtifactStamp, ServiceError> {
        let session = self.session.ok_or(ServiceError::Unavailable)?;
        let Some(generation) = self.last_generation.checked_add(1) else {
            self.close();
            return Err(ServiceError::Unavailable);
        };
        self.last_generation = generation;
        Ok(NativeArtifactStamp {
            session,
            generation,
        })
    }
    #[allow(dead_code)] // Используется только будущим verified commit, не caller flags.
    fn consume(&mut self, stamp: &NativeArtifactStamp) -> Result<(), ServiceError> {
        if self.session != Some(stamp.session)
            || stamp.generation == 0
            || stamp.generation > self.last_generation
        {
            return Err(ServiceError::Unavailable);
        }
        if self.busy() {
            return Err(ServiceError::Busy);
        }
        if !self.consumed.insert(stamp.generation) {
            return Err(ServiceError::Unavailable);
        }
        Ok(())
    }
    fn activate_checked(
        &mut self,
        run: R,
        validate: impl FnOnce(&NativeOwnerLease<A, Q, R>, &R) -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        let pending = self.lease.as_ref().ok_or(ServiceError::Unavailable)?;
        if self.active.is_some() || pending.run.is_some() {
            self.revoke();
            return Err(ServiceError::Busy);
        }
        if let Err(error) = validate(pending, &run) {
            self.revoke();
            return Err(error);
        }
        // После проверки нет await/ошибок: весь lease перемещается целиком.
        let mut pending = self.lease.take().ok_or(ServiceError::Unavailable)?;
        pending.run = Some(run);
        self.active = Some(pending);
        Ok(())
    }
    pub(in super::super) fn busy(&self) -> bool {
        self.lease.is_some() || self.active.is_some()
    }
    pub(in super::super) fn revoke(&mut self) {
        for lease in self.lease.iter().chain(self.active.iter()) {
            lease.authority.revoke();
        }
        // Неизвестный stop сохраняет queue/artifact/run; Busy до confirmed recover.
    }
    pub(in super::super) fn close(&mut self) {
        self.revoke();
        self.session = None;
    }
    pub(in super::super) fn release_confirmed(&mut self) {
        self.revoke();
        self.lease = None;
        self.active = None;
    }
}
impl<A, Q, R> Drop for NativeOwnerState<A, Q, R> {
    fn drop(&mut self) {
        self.revoke();
    }
}

// Нет constructor из caller данных: record создаётся только после async проверок.
#[allow(dead_code)]
pub(super) struct VerifiedNativeNetworkCommit<
    A = SessionArtifact,
    Q = crate::managed_network::tun::BoundTun,
> {
    artifact: Arc<A>,
    queue: Arc<Q>,
    stamp: crate::NetworkStamp,
    epoch: u64,
    owner: crate::managed_network::Ownership,
}

// Общий синхронный boundary: unit fixtures проверяют эти же gates без TUN mint.
impl<A, Q> VerifiedNativeNetworkCommit<A, Q> {
    fn validate_network_binding(
        &self,
        canonical: Option<&Arc<Q>>,
        snapshot: crate::NetworkSnapshot,
        epoch: u64,
        owner: Option<crate::managed_network::Ownership>,
    ) -> Result<(), ServiceError> {
        if epoch != self.epoch
            || !snapshot.is_current(self.stamp)
            || !snapshot.fully_observed()
            || owner != Some(self.owner)
            || !canonical.is_some_and(|queue| Arc::ptr_eq(queue, &self.queue))
        {
            return Err(super::stale());
        }
        Ok(())
    }
}

// Закрытая граница: production caller и compile stamping ещё не подключаются.
#[allow(dead_code)]
impl super::Backend {
    pub(super) async fn verify_native_network(
        &mut self,
        artifact: Arc<SessionArtifact>,
        index: u32,
        link: &crate::LinuxLink,
        cancel: &mut crate::Cancellation,
    ) -> Result<VerifiedNativeNetworkCommit, ServiceError> {
        let before = self.snapshot()?;
        let epoch = self.epoch;
        let queue = Arc::clone(
            &self
                .tun_custody
                .as_ref()
                .ok_or(ServiceError::Unavailable)?
                .bound,
        );
        crate::attribution::preflight(
            artifact.attribution_required,
            artifact.peer.as_deref(),
            artifact.worker_uid,
        )
        .await
        .map_err(|_| ServiceError::Unsupported)?;
        self.verify_network_facts(&artifact, index, link, cancel)
            .await?;
        let (current, _) = crate::network::read_topology_captured(cancel, super::DEADLINE)
            .await
            .map_err(super::unavailable)?;
        let metadata = queue.attach_metadata().map_err(super::unavailable)?;
        if metadata[4..8] != index.to_be_bytes() {
            return Err(super::stale());
        }
        let journal = self.journal.as_ref().ok_or(ServiceError::Unavailable)?;
        let owner = journal.ownership();
        queue
            .project(current, journal)
            .map_err(super::unavailable)?;
        let snapshot = self.snapshot()?;
        if !snapshot.fully_observed() || !snapshot.is_current(before.stamp) || epoch != self.epoch {
            return Err(ServiceError::Unavailable);
        }
        let record = VerifiedNativeNetworkCommit {
            artifact,
            queue,
            stamp: snapshot.stamp,
            epoch: self.epoch,
            owner,
        };
        self.revalidate_native(&record)?;
        Ok(record)
    }
    fn revalidate_native(&self, record: &VerifiedNativeNetworkCommit) -> Result<(), ServiceError> {
        if self.worker_uncertain || self.active.is_some() || self.native_owner.busy() {
            return Err(ServiceError::Busy);
        }
        self.revalidate_native_context(record)
    }
    fn revalidate_native_context(
        &self,
        record: &VerifiedNativeNetworkCommit,
    ) -> Result<(), ServiceError> {
        record.validate_network_binding(
            self.tun_custody.as_ref().map(|custody| &custody.bound),
            self.snapshot()?,
            self.epoch,
            self.journal.as_ref().map(|journal| journal.ownership()),
        )?;
        if self.context(record.artifact.uid)? != record.artifact.context {
            return Err(super::stale());
        }
        record.queue.attach_metadata().map_err(super::unavailable)?;
        // UID берётся только из retained peer после identity recheck.
        let peer = record
            .artifact
            .peer
            .as_ref()
            .ok_or(ServiceError::Unsupported)?;
        if peer.verified_uid().map_err(|_| ServiceError::Unsupported)? != record.artifact.uid {
            return Err(ServiceError::Unsupported);
        }
        Ok(())
    }
    fn activate_native_owner(&mut self, run: AuthorizedRun) -> Result<(), ServiceError> {
        let validation = (|| {
            if self.worker_uncertain || self.active.is_some() {
                return Err(ServiceError::Busy);
            }
            let pending = self
                .native_owner
                .lease
                .as_ref()
                .ok_or(ServiceError::Unavailable)?;
            let record = VerifiedNativeNetworkCommit {
                artifact: Arc::clone(&pending.artifact),
                queue: Arc::clone(&pending.queue),
                stamp: pending.network_stamp,
                epoch: pending.network_epoch,
                owner: pending.owner,
            };
            self.revalidate_native_context(&record)?;
            run.validate_owner(&pending.authority, &pending.artifact.payload)
                .map_err(super::unavailable)
        })();
        if let Err(error) = validation {
            self.native_owner.revoke();
            return Err(error);
        }
        self.native_owner.activate_checked(run, |pending, run| {
            run.validate_owner(&pending.authority, &pending.artifact.payload)
                .map_err(super::unavailable)
        })
    }
    pub(super) async fn start_committed_native(
        &mut self,
        cancel: &mut crate::Cancellation,
    ) -> Result<crate::helper::systemd_worker::WorkerTicket, ServiceError> {
        self.supervisor().await?;
        let pending = self
            .native_owner
            .lease
            .as_ref()
            .ok_or(ServiceError::Unavailable)?;
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(super::unavailable)?;
        let authorization = pending
            .authority
            .authorize(nonce)
            .map_err(super::unavailable)?;
        let (topology, _) = crate::network::read_topology_captured(cancel, super::DEADLINE)
            .await
            .map_err(super::unavailable)?;
        self.worker_uncertain = true;
        self.supervisor
            .as_mut()
            .ok_or(ServiceError::Unavailable)?
            .start_native(
                Arc::clone(&pending.artifact.payload),
                &pending.authority,
                authorization,
                Arc::clone(&pending.queue),
                self.journal.as_ref().ok_or(ServiceError::Unavailable)?,
                topology,
                pending.network_epoch,
                cancel,
            )
            .await
            .map_err(super::unavailable)
    }
    pub(super) fn commit_native_owner(
        &mut self,
        record: VerifiedNativeNetworkCommit,
    ) -> Result<(), ServiceError> {
        self.revalidate_native(&record)?;
        let stamp = record
            .artifact
            .native_owner_stamp
            .as_ref()
            .ok_or(ServiceError::Unavailable)?;
        self.native_owner.consume(stamp)?;
        let authority = RunAuthority::from_bound(OwnerBinding {
            owner: record.owner,
            session: stamp.session,
            generation: stamp.generation,
            epoch: record.epoch,
        });
        self.native_owner.lease = Some(NativeOwnerLease {
            artifact: record.artifact,
            queue: record.queue,
            network_stamp: record.stamp,
            network_epoch: record.epoch,
            authority,
            owner: record.owner,
            run: None,
        });
        Ok(())
    }
}

// Вызывается только существующим isolated user/net fixture после real queue bind.
#[cfg(test)]
pub(super) async fn check_actual_boundaries_with_synthetic_inputs(
    backend: &mut super::Backend,
    index: u32,
    cancel: &mut crate::Cancellation,
    plan: crate::helper::SessionNetworkPlan,
    baseline: crate::LinuxTopology,
    baseline_capture: crate::network::TopologyCapture,
) -> crate::helper::SessionNetworkPlan {
    use crate::helper::memory::config_budget;
    use crate::network::{lookup_route_captured, read_topology_captured};
    let (current, _) = read_topology_captured(cancel, super::DEADLINE)
        .await
        .unwrap();
    let link = current
        .links
        .iter()
        .find(|link| link.index == index)
        .unwrap()
        .clone();
    let uid = rustix::process::getuid().as_raw();
    let owner = backend.journal.as_ref().unwrap().ownership();
    let endpoint = current
        .addresses
        .iter()
        .find(|address| address.index == index && address.address.is_ipv4())
        .unwrap()
        .address;
    let query = crate::RouteQuery::new(endpoint, uid)
        .with_mark(plan.socket_mark())
        .with_transport(crate::TransportProtocol::Tcp, None, Some(443));
    let (route, route_capture) = lookup_route_captured(query, cancel, super::DEADLINE)
        .await
        .unwrap();
    let artifact = Arc::new(SessionArtifact {
        bundle: None,
        payload: crate::helper::systemd_worker::unit_owner_payload(),
        plan,
        baseline,
        baseline_capture,
        route,
        route_capture,
        context: backend.context(uid).unwrap(),
        uid,
        worker_uid: uid,
        kill_switch: false,
        attribution_required: false,
        peer: Some(Arc::new(
            crate::attribution::PeerProcess::capture(std::process::id(), uid).unwrap(),
        )),
        endpoint,
        port: 443,
        protocol: crate::TransportProtocol::Tcp,
        memory: config_budget().reserve(1).unwrap(),
        native_owner_stamp: Some(backend.native_owner.reserve().unwrap()),
    });
    // Реальный producer: отсутствие peer/canonical prerequisites не выдаёт record.
    assert!(
        backend
            .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
            .await
            .is_err()
    );
    assert!(!backend.native_owner.busy());
    // Продвигаем actual producer дальше через штатный isolated nft API.
    let policy = super::compile_protection(&artifact.baseline, false).unwrap();
    backend.policy(owner, policy).await.unwrap();
    assert!(
        !backend.watch.current().fully_observed(),
        "Fixture не должен молча становиться canonical context"
    );
    assert!(
        backend
            .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
            .await
            .is_err()
    );
    assert!(!backend.native_owner.busy());
    let queue = Arc::clone(&backend.tun_custody.as_ref().unwrap().bound);
    let stamp = backend.watch.current().stamp;
    let epoch = backend.epoch;
    // Typed forged records — исключительно negative controls, не producer proof.
    for stale_epoch in [true, false] {
        let record = VerifiedNativeNetworkCommit {
            artifact: Arc::clone(&artifact),
            queue: Arc::clone(&queue),
            stamp,
            epoch: if stale_epoch { epoch + 1 } else { epoch },
            owner: if stale_epoch {
                owner
            } else {
                crate::managed_network::Ownership::new(
                    uid,
                    owner.session() + 1,
                    1,
                    owner.namespace().0,
                    owner.namespace().1,
                )
                .unwrap()
            },
        };
        assert!(backend.revalidate_native(&record).is_err());
        assert!(backend.commit_native_owner(record).is_err());
        assert!(!backend.native_owner.busy());
        assert!(backend.native_owner.consumed.is_empty());
    }
    for case in 0..4 {
        let authority = RunAuthority::new([2; 16], 7, epoch).unwrap();
        let foreign = RunAuthority::new([2; 16], 7, epoch).unwrap();
        let payload = if case == 1 {
            crate::helper::systemd_worker::unit_owner_payload()
        } else {
            Arc::clone(&artifact.payload)
        };
        assert_eq!(payload.digest(), artifact.payload.digest());
        let run = crate::helper::systemd_worker::unit_owner_result(
            if case == 0 { &foreign } else { &authority },
            payload,
        );
        if case >= 2 {
            authority.revoke();
        }
        // Полный validator реально вызван; canonical identity остаётся CLOSED.
        assert!(run.validate_owner(&authority, &artifact.payload).is_err());
        backend.native_owner.lease = Some(NativeOwnerLease {
            artifact: Arc::clone(&artifact),
            queue: Arc::clone(&queue),
            network_stamp: stamp,
            network_epoch: epoch,
            owner,
            authority,
            run: None,
        });
        if case == 3 {
            backend.worker_uncertain = true;
        }
        assert!(backend.activate_native_owner(run).is_err());
        assert!(backend.native_owner.active.is_none());
        let pending = backend.native_owner.lease.as_ref().unwrap();
        assert!(pending.authority.is_revoked());
        assert!(Arc::ptr_eq(&pending.artifact, &artifact));
        assert!(Arc::ptr_eq(&pending.queue, &queue));
        assert!(backend.native_owner.busy());
        backend.worker_uncertain = false;
        backend.native_owner.release_confirmed();
    }
    // Source availability синтетическая; topology/route/nft/peer/queue остаются real.
    let (publisher, watch) = crate::network::unit_source_publisher();
    for source in [
        crate::network::NetworkSource::Routes,
        crate::network::NetworkSource::Resolver,
        crate::network::NetworkSource::Manager,
    ] {
        publisher.unit_ready(source);
    }
    backend.watch = watch;
    let mut artifact = Arc::try_unwrap(artifact).ok().unwrap();
    artifact.context = backend.context(uid).unwrap();
    let mut artifact = Arc::new(artifact);
    assert!(backend.watch.current().fully_observed());

    // Record потребляется целиком: commit не принимает независимый artifact B.
    let artifact_b = Arc::new(SessionArtifact {
        bundle: artifact.bundle,
        payload: Arc::clone(&artifact.payload),
        plan: crate::helper::SessionNetworkPlan::reserve_for_engine(
            owner,
            &artifact.baseline,
            yonik_engine::Engine::Xray,
        )
        .unwrap(),
        baseline: artifact.baseline.clone(),
        baseline_capture: artifact.baseline_capture,
        route: artifact.route.clone(),
        route_capture: artifact.route_capture,
        context: artifact.context,
        uid,
        worker_uid: uid,
        kill_switch: false,
        attribution_required: false,
        peer: artifact.peer.clone(),
        endpoint,
        port: 443,
        protocol: artifact.protocol,
        memory: config_budget().reserve(1).unwrap(),
        native_owner_stamp: Some(NativeArtifactStamp {
            session: artifact.native_owner_stamp.as_ref().unwrap().session,
            generation: artifact.native_owner_stamp.as_ref().unwrap().generation,
        }),
    });
    assert!(!Arc::ptr_eq(&artifact, &artifact_b));
    assert_eq!(artifact.context, artifact_b.context);
    let record = backend
        .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&record.artifact, &artifact));
    backend.commit_native_owner(record).unwrap();
    let pending = backend.native_owner.lease.as_ref().unwrap();
    assert!(Arc::ptr_eq(&pending.artifact, &artifact));
    assert!(!Arc::ptr_eq(&pending.artifact, &artifact_b));
    assert_eq!(Arc::strong_count(&artifact_b), 1);
    let run = crate::helper::systemd_worker::unit_raw_identity_result(
        &pending.authority,
        Arc::clone(&artifact.payload),
    );
    run.validate_owner(&pending.authority, &artifact.payload)
        .unwrap();
    backend.activate_native_owner(run).unwrap();
    assert!(backend.native_owner.lease.is_none());
    let active = backend.native_owner.active.as_ref().unwrap();
    active
        .run
        .as_ref()
        .unwrap()
        .validate_owner(&active.authority, &artifact.payload)
        .unwrap();
    backend.invalidate().unwrap();
    let active = backend.native_owner.active.as_ref().unwrap();
    assert!(
        active
            .run
            .as_ref()
            .unwrap()
            .validate_owner(&active.authority, &artifact.payload)
            .is_err()
    );
    assert!(backend.native_owner.busy());
    backend.native_owner.release_confirmed();
    Arc::get_mut(&mut artifact).unwrap().context = backend.context(uid).unwrap();
    // Повторный actual producer может проверить A, но consume не переиздаёт generation.
    let record = backend
        .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
        .await
        .unwrap();
    assert!(backend.commit_native_owner(record).is_err());
    assert!(!backend.native_owner.busy());
    drop(artifact_b);

    // Реальный record после changed/lost не публикуется.
    for lost in [false, true] {
        let value = Arc::get_mut(&mut artifact).unwrap();
        value.native_owner_stamp = Some(backend.native_owner.reserve().unwrap());
        value.context = backend.context(uid).unwrap();
        let record = backend
            .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
            .await
            .unwrap();
        if lost {
            publisher.unit_lost(crate::network::NetworkSource::Manager);
        } else {
            publisher.unit_changed(crate::network::NetworkSource::Routes);
        }
        assert!(backend.commit_native_owner(record).is_err());
        assert!(!backend.native_owner.busy());
        publisher.unit_ready(crate::network::NetworkSource::Manager);
    }
    // Wrong canonical Arc: обе owning queues настоящие, metadata одинаковы.
    #[cfg(feature = "test-support")]
    {
        use std::os::fd::AsRawFd;
        let value = Arc::get_mut(&mut artifact).unwrap();
        value.native_owner_stamp = Some(backend.native_owner.reserve().unwrap());
        value.context = backend.context(uid).unwrap();
        let record = backend
            .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
            .await
            .unwrap();
        let duplicate = Arc::new(queue.duplicate_same_kernel_queue_for_test().unwrap());
        let fd = duplicate.queue_fd_for_test().as_raw_fd();
        assert_eq!(
            duplicate.attach_metadata().unwrap(),
            queue.attach_metadata().unwrap()
        );
        assert!(!Arc::ptr_eq(&duplicate, &queue));
        let original = backend.tun_custody.as_mut().unwrap().bound.clone();
        backend.tun_custody.as_mut().unwrap().bound = duplicate;
        assert!(backend.commit_native_owner(record).is_err());
        assert!(!backend.native_owner.busy());
        backend.tun_custody.as_mut().unwrap().bound = original;
        assert!(!std::path::Path::new(&format!("/proc/self/fd/{fd}")).exists());
        queue.attach_metadata().unwrap();
    }
    for case in 0..5 {
        let value = Arc::get_mut(&mut artifact).unwrap();
        value.native_owner_stamp = Some(backend.native_owner.reserve().unwrap());
        value.context = backend.context(uid).unwrap();
        let record = backend
            .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
            .await
            .unwrap();
        backend.commit_native_owner(record).unwrap();
        let pending = backend.native_owner.lease.as_ref().unwrap();
        let stamp = artifact.native_owner_stamp.as_ref().unwrap();
        let foreign = RunAuthority::new(stamp.session, stamp.generation, backend.epoch).unwrap();
        let payload = if case == 1 {
            crate::helper::systemd_worker::unit_owner_payload()
        } else {
            Arc::clone(&artifact.payload)
        };
        assert_eq!(payload.digest(), artifact.payload.digest());
        let run = crate::helper::systemd_worker::unit_raw_identity_result(
            if case == 0 {
                &foreign
            } else {
                &pending.authority
            },
            payload,
        );
        // Canonical raw predicates проходят до намеренного нарушения link/lifetime.
        run.ticket().unwrap();
        if case == 2 {
            pending.authority.revoke();
        }
        if case == 3 {
            backend.worker_uncertain = true;
        }
        if case == 4 {
            let mut future = Box::pin(async move {
                let _run = run;
                std::future::pending::<()>().await;
            });
            assert!(futures_util::poll!(future.as_mut()).is_pending());
            drop(future);
        } else {
            assert!(backend.activate_native_owner(run).is_err());
        }
        let retained = backend.native_owner.lease.as_ref().unwrap();
        assert!(retained.authority.is_revoked());
        assert!(Arc::ptr_eq(&retained.artifact, &artifact));
        assert!(Arc::ptr_eq(&retained.queue, &queue));
        assert!(backend.native_owner.active.is_none());
        assert!(backend.native_owner.busy());
        backend.worker_uncertain = false;
        backend.native_owner.release_confirmed();
    }
    let value = Arc::get_mut(&mut artifact).unwrap();
    value.native_owner_stamp = Some(backend.native_owner.reserve().unwrap());
    value.context = backend.context(uid).unwrap();
    let record = backend
        .verify_native_network(Arc::clone(&artifact), index, &link, cancel)
        .await
        .unwrap();
    backend.commit_native_owner(record).unwrap();
    backend.epoch = u64::MAX;
    assert!(backend.invalidate().is_err());
    assert!(
        backend
            .native_owner
            .lease
            .as_ref()
            .unwrap()
            .authority
            .is_revoked()
    );
    assert!(backend.native_owner.busy());
    assert!(backend.native_owner.reserve().is_err());
    backend.native_owner.release_confirmed();
    Arc::try_unwrap(artifact).ok().unwrap().plan
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestOwner = NativeOwnerState<Arc<()>, Arc<()>, Arc<()>>;
    #[test]
    fn failed_compile_burns_generation_and_prepared_order_is_not_authority() {
        let mut owner = TestOwner::from_session(Some([1; 16]));
        let first = owner.reserve().unwrap();
        let failed = owner.reserve().unwrap();
        let third = owner.reserve().unwrap();
        assert_eq!(
            (first.generation, failed.generation, third.generation),
            (1, 2, 3)
        );
        owner.consume(&third).unwrap();
        owner.consume(&first).unwrap();
        assert!(owner.consume(&first).is_err());
    }
    #[test]
    fn foreign_session_and_unreserved_generation_cannot_consume() {
        let mut owner = TestOwner::from_session(Some([1; 16]));
        let first = owner.reserve().unwrap();
        for stamp in [
            NativeArtifactStamp {
                session: [2; 16],
                generation: 1,
            },
            NativeArtifactStamp {
                session: [1; 16],
                generation: 0,
            },
            NativeArtifactStamp {
                session: [1; 16],
                generation: 2,
            },
        ] {
            assert!(owner.consume(&stamp).is_err());
        }
        owner.consume(&first).unwrap();
    }
    #[test]
    fn zero_entropy_and_overflow_permanently_close_admission() {
        for session in [None, Some([0; 16])] {
            assert!(TestOwner::from_session(session).reserve().is_err());
        }
        let mut owner = TestOwner::from_session(Some([1; 16]));
        owner.last_generation = u64::MAX - 1;
        let last = owner.reserve().unwrap();
        assert_eq!(last.generation, u64::MAX);
        assert!(owner.reserve().is_err());
        assert!(owner.consume(&last).is_err());
        assert!(owner.reserve().is_err());
    }
    #[tokio::test]
    async fn unknown_stop_revokes_but_retains_all_ownership_until_confirmation() {
        let mut owner = TestOwner::from_session(Some([1; 16]));
        let artifact = Arc::new(());
        let queue = Arc::new(());
        let run = Arc::new(());
        let authority = RunAuthority::new([1; 16], 1, 1).unwrap();
        let token = authority.authorize([2; 32]).unwrap();
        // NetworkStamp не proof; fixture берёт snapshot штатного monitor.
        let monitor = crate::NetworkMonitor::start().unwrap();
        owner.lease = Some(NativeOwnerLease {
            artifact: Arc::clone(&artifact),
            queue: Arc::clone(&queue),
            run: Some(Arc::clone(&run)),
            authority,
            network_stamp: monitor.watch().current().stamp,
            network_epoch: 1,
            owner: crate::managed_network::Ownership::new(1, 1, 1, 1, 1).unwrap(),
        });
        assert!(token.challenge_context().is_ok());
        owner.revoke();
        assert!(token.challenge_context().is_err());
        assert!(owner.busy());
        assert_eq!(
            (
                Arc::strong_count(&artifact),
                Arc::strong_count(&queue),
                Arc::strong_count(&run)
            ),
            (2, 2, 2)
        );
        owner.release_confirmed();
        assert!(!owner.busy());
        assert_eq!(
            (
                Arc::strong_count(&artifact),
                Arc::strong_count(&queue),
                Arc::strong_count(&run)
            ),
            (1, 1, 1)
        );
        let authority = RunAuthority::new([1; 16], 2, 1).unwrap();
        let pending_token = authority.authorize([3; 32]).unwrap();
        owner.lease = Some(NativeOwnerLease {
            artifact: Arc::clone(&artifact),
            queue: Arc::clone(&queue),
            run: None,
            authority,
            network_stamp: monitor.watch().current().stamp,
            network_epoch: 1,
            owner: crate::managed_network::Ownership::new(1, 1, 1, 1, 1).unwrap(),
        });
        drop(owner);
        assert!(pending_token.challenge_context().is_err());
        assert_eq!(
            (Arc::strong_count(&artifact), Arc::strong_count(&queue)),
            (1, 1)
        );
    }
    #[tokio::test]
    async fn final_binding_retains_artifact_a_and_rejects_wrong_queue_and_network_change() {
        let monitor = crate::NetworkMonitor::start().unwrap();
        let mut snapshot = monitor.watch().current();
        snapshot.coverage = crate::NetworkCoverage {
            routes: true,
            resolver: true,
            manager: true,
        };
        snapshot.exhausted = false;
        // Только source-backed unit boundary. Ни kernel queue, ни network proof здесь не mintятся.
        let owner = crate::managed_network::Ownership::new(1, 1, 1, 1, 1).unwrap();
        let artifact_a = Arc::new(vec![1, 2, 3]);
        let artifact_b = Arc::new(vec![1, 2, 3]);
        let queue_a = Arc::new(());
        let queue_b = Arc::new(());
        let record = VerifiedNativeNetworkCommit {
            artifact: Arc::clone(&artifact_a),
            queue: Arc::clone(&queue_a),
            stamp: snapshot.stamp,
            epoch: 1,
            owner,
        };
        drop(artifact_a);
        assert!(
            record
                .validate_network_binding(Some(&queue_a), snapshot, 1, Some(owner))
                .is_ok()
        );
        assert!(!Arc::ptr_eq(&record.artifact, &artifact_b));
        assert_eq!(Arc::strong_count(&record.artifact), 1);
        assert!(
            record
                .validate_network_binding(Some(&queue_b), snapshot, 1, Some(owner))
                .is_err()
        );
        assert!(
            record
                .validate_network_binding(None, snapshot, 1, Some(owner))
                .is_err()
        );
        assert!(
            record
                .validate_network_binding(Some(&queue_a), snapshot, 2, Some(owner))
                .is_err()
        );
        assert!(
            record
                .validate_network_binding(Some(&queue_a), snapshot, 1, None)
                .is_err()
        );
        let other_monitor = crate::NetworkMonitor::start().unwrap();
        let mut changed_snapshot = snapshot;
        changed_snapshot.stamp = other_monitor.watch().current().stamp;
        assert!(
            record
                .validate_network_binding(Some(&queue_a), changed_snapshot, 1, Some(owner))
                .is_err()
        );
        snapshot.coverage.manager = false;
        assert!(
            record
                .validate_network_binding(Some(&queue_a), snapshot, 1, Some(owner))
                .is_err()
        );
        snapshot.coverage.manager = true;
        snapshot.exhausted = true;
        assert!(
            record
                .validate_network_binding(Some(&queue_a), snapshot, 1, Some(owner))
                .is_err()
        );
    }

    #[tokio::test]
    async fn synchronous_transfer_keeps_lease_and_failed_late_result_keeps_recovery_slot() {
        let monitor = crate::NetworkMonitor::start().unwrap();
        let mut owner = TestOwner::from_session(Some([1; 16]));
        let artifact = Arc::new(());
        let queue = Arc::new(());
        let run = Arc::new(());
        let authority = RunAuthority::new([1; 16], 1, 1).unwrap();
        let token = authority.authorize([2; 32]).unwrap();
        owner.lease = Some(NativeOwnerLease {
            artifact: Arc::clone(&artifact),
            queue: Arc::clone(&queue),
            network_stamp: monitor.watch().current().stamp,
            network_epoch: 1,
            owner: crate::managed_network::Ownership::new(1, 1, 1, 1, 1).unwrap(),
            authority,
            run: None,
        });
        owner
            .activate_checked(Arc::clone(&run), |pending, _| {
                token
                    .validate_owner(&pending.authority)
                    .map_err(|_| ServiceError::Unavailable)
            })
            .unwrap();
        assert!(owner.lease.is_none());
        assert!(owner.active.is_some());
        assert!(token.validate().is_ok());
        assert_eq!(Arc::strong_count(&run), 2);
        owner.revoke();
        assert!(token.validate().is_err());
        assert!(owner.busy());
        owner.release_confirmed();
        assert_eq!(Arc::strong_count(&run), 1);
        let authority = RunAuthority::new([1; 16], 2, 1).unwrap();
        let token = authority.authorize([3; 32]).unwrap();
        authority.revoke();
        owner.lease = Some(NativeOwnerLease {
            artifact,
            queue,
            authority,
            network_stamp: monitor.watch().current().stamp,
            network_epoch: 1,
            owner: crate::managed_network::Ownership::new(1, 1, 1, 1, 1).unwrap(),
            run: None,
        });
        assert!(
            owner
                .activate_checked(run, |pending, _| {
                    token
                        .validate_owner(&pending.authority)
                        .map_err(|_| ServiceError::Unavailable)
                })
                .is_err()
        );
        assert!(owner.lease.is_some());
        assert!(owner.active.is_none());
        assert!(owner.busy());
    }
    struct UnitArtifact {
        payload: Arc<crate::worker::WorkerPayload>,
    }
    type UnitRunOwner = NativeOwnerState<Arc<UnitArtifact>, Arc<()>, AuthorizedRun>;
    fn unit_pending_owner(stamp: crate::NetworkStamp) -> UnitRunOwner {
        let mut owner = UnitRunOwner::from_session(Some([2; 16]));
        owner.lease = Some(NativeOwnerLease {
            artifact: Arc::new(UnitArtifact {
                payload: crate::helper::systemd_worker::unit_owner_payload(),
            }),
            queue: Arc::new(()),
            network_stamp: stamp,
            network_epoch: 9,
            owner: crate::managed_network::Ownership::new(1, 1, 1, 1, 1).unwrap(),
            authority: RunAuthority::new([2; 16], 7, 9).unwrap(),
            run: None,
        });
        owner
    }
    fn unit_activate(owner: &mut UnitRunOwner, run: AuthorizedRun) -> Result<(), ServiceError> {
        owner.activate_checked(run, |pending, run| {
            run.unit_validate_owner_link(&pending.authority, &pending.artifact.payload)
                .map_err(super::super::unavailable)
        })
    }
    #[tokio::test]
    async fn exact_authorized_run_moves_without_early_guard_drop_and_unknown_stop_retains_it() {
        let monitor = crate::NetworkMonitor::start().unwrap();
        let mut owner = unit_pending_owner(monitor.watch().current().stamp);
        let pending = owner.lease.as_ref().unwrap();
        let queue = Arc::clone(&pending.queue);
        let artifact = Arc::clone(&pending.artifact);
        let run = crate::helper::systemd_worker::unit_owner_result(
            &pending.authority,
            Arc::clone(&artifact.payload),
        );
        unit_activate(&mut owner, run).unwrap();
        assert!(owner.lease.is_none());
        let active = owner.active.as_ref().unwrap();
        assert!(!active.authority.is_revoked());
        assert!(
            active
                .run
                .as_ref()
                .unwrap()
                .unit_validate_owner_link(&active.authority, &artifact.payload)
                .is_ok()
        );
        assert_eq!(
            (Arc::strong_count(&artifact), Arc::strong_count(&queue)),
            (2, 2)
        );
        owner.revoke();
        let active = owner.active.as_ref().unwrap();
        assert!(
            active
                .run
                .as_ref()
                .unwrap()
                .unit_validate_owner_link(&active.authority, &artifact.payload)
                .is_err()
        );
        assert!(owner.busy());
        assert_eq!(
            (Arc::strong_count(&artifact), Arc::strong_count(&queue)),
            (2, 2)
        );
        owner.release_confirmed();
        assert_eq!(
            (Arc::strong_count(&artifact), Arc::strong_count(&queue)),
            (1, 1)
        );
    }
    #[tokio::test]
    async fn wrong_owner_and_equal_bytes_wrong_payload_revoke_without_losing_pending_slot() {
        let monitor = crate::NetworkMonitor::start().unwrap();
        for wrong_owner in [true, false] {
            let mut owner = unit_pending_owner(monitor.watch().current().stamp);
            let pending = owner.lease.as_ref().unwrap();
            let foreign = RunAuthority::new([2; 16], 7, 9).unwrap();
            let payload = if wrong_owner {
                Arc::clone(&pending.artifact.payload)
            } else {
                crate::helper::systemd_worker::unit_owner_payload()
            };
            assert_eq!(payload.digest(), pending.artifact.payload.digest());
            let run = crate::helper::systemd_worker::unit_owner_result(
                if wrong_owner {
                    &foreign
                } else {
                    &pending.authority
                },
                payload,
            );
            assert!(unit_activate(&mut owner, run).is_err());
            assert!(owner.lease.is_some());
            assert!(owner.active.is_none());
            assert!(owner.busy());
            assert!(owner.lease.as_ref().unwrap().authority.is_revoked());
        }
    }
    #[tokio::test]
    async fn cancellation_before_active_keeps_revoked_pending_recovery_ownership() {
        let monitor = crate::NetworkMonitor::start().unwrap();
        let owner = unit_pending_owner(monitor.watch().current().stamp);
        let pending = owner.lease.as_ref().unwrap();
        let run = crate::helper::systemd_worker::unit_owner_result(
            &pending.authority,
            Arc::clone(&pending.artifact.payload),
        );
        let mut future = Box::pin(async move {
            let _run = run;
            std::future::pending::<()>().await;
        });
        assert!(futures_util::poll!(future.as_mut()).is_pending());
        assert!(!pending.authority.is_revoked());
        drop(future);
        assert!(owner.lease.as_ref().unwrap().authority.is_revoked());
        assert!(owner.active.is_none());
        assert!(owner.busy());
    }
}
