//! Consuming admission: installed producer, authenticated report и owning custody.
#![allow(dead_code)]
use super::{
    BootstrapUnitObservation, SystemWorkerSupervisor, WorkerSupervisorError as Error,
    kernel_evidence::{self, Expected},
    native_profile::VerifiedInstalledProfile,
    run_authorization::{RunAuthority, RunAuthorization, RunRevocationGuard},
};
use crate::{
    Cancellation,
    worker::anchor_exchange::{Challenge, NamespaceObservation},
};
use std::os::unix::net::UnixStream;
use tokio::time::Instant as Deadline;

pub(crate) type NativeRoleContext = ([u8; 32], [u8; 16], u64, [u8; 16], u64, [u8; 32]);

type Result<T> = std::result::Result<T, Error>;

pub(crate) struct VerifiedPendingRun {
    profile: VerifiedInstalledProfile,
    authorization: RunAuthorization,
    expected: Expected,
    deadline: Deadline,
    guard: RunRevocationGuard,
}

pub(crate) struct VerifiedCoverage {
    profile: VerifiedInstalledProfile,
    authorization: RunAuthorization,
    expected: Expected,
    custody: NamespaceObservation,
    guard: RunRevocationGuard,
    deadline: Deadline,
}

impl VerifiedPendingRun {
    #[allow(clippy::too_many_arguments)] // Согласованный consuming интерфейс canonical pending context.
    pub(crate) async fn verify(
        supervisor: &SystemWorkerSupervisor,
        owner: &RunAuthority,
        authorization: RunAuthorization,
        observation: BootstrapUnitObservation,
        digest: [u8; 32],
        epoch: u64,
        cancel: &mut Cancellation,
        deadline: Deadline,
    ) -> Result<Self> {
        authorization
            .validate_owner(owner)
            .map_err(|_| Error::Untrusted)?;
        let guard = authorization.guard();
        if Deadline::now() >= deadline || epoch == 0 || digest == [0; 32] {
            return Err(Error::Stale);
        }
        let profile =
            VerifiedInstalledProfile::verify(supervisor, observation, cancel, deadline).await?;
        if profile.policy_digest() != yonik_nsfs::fixed_self_fence::PROFILE_DIGEST {
            return Err(Error::Untrusted);
        }
        let (nonce, session, generation) = authorization
            .challenge_context()
            .map_err(|_| Error::Untrusted)?;
        let observation = profile.observation();
        let mut observations = [1; 19];
        observations[2] = 38;
        let expected = Expected {
            nonce,
            digest,
            session,
            generation,
            epoch,
            invocation: observation.native_invocation(),
            task_pid: observation.native_pid(),
            task_start: observation.native_start(),
            server_pid: std::process::id(),
            server_start: own_start()?,
            profile: profile.policy_digest(),
            observations,
        };
        authorization
            .validate_owner(owner)
            .map_err(|_| Error::Untrusted)?;
        if Deadline::now() >= deadline {
            return Err(Error::Stale);
        }
        Ok(Self {
            profile,
            authorization,
            expected,
            deadline,
            guard,
        })
    }
    /// Совместимый async вход: blocking task владеет pending guard и сокетом.
    pub(crate) async fn receive(
        self,
        supervisor: &SystemWorkerSupervisor,
        owner: &RunAuthority,
        stream: &UnixStream,
        cancel: &mut Cancellation,
    ) -> Result<VerifiedCoverage> {
        self.authorization
            .validate_owner(owner)
            .map_err(|_| Error::Untrusted)?;
        let stream = stream.try_clone().map_err(|_| Error::Unavailable)?;
        let (pending, custody, frame) =
            tokio::task::spawn_blocking(move || self.receive_blocking(stream))
                .await
                .map_err(|_| Error::Unavailable)??;
        pending
            .finish_receive(supervisor, owner, custody, frame, cancel)
            .await
    }

    /// Только authenticated challenge exchange; supervisor и owner сюда не заимствуются.
    /// Pending возвращается вместе с guard: отменённый join не оставляет authority.
    pub(crate) fn receive_blocking(
        self,
        stream: UnixStream,
    ) -> Result<(Self, NamespaceObservation, [u8; 512])> {
        validate_receive_admission(&self.authorization, self.deadline)?;
        let challenge = Challenge::for_authorization(
            &self.authorization,
            self.expected.digest,
            self.expected.invocation,
        )
        .map_err(|_| Error::Protocol)?;
        let (custody, frame) = challenge
            .exchange_v4_bound(
                &stream,
                self.expected.task_pid,
                self.profile.observation().native_uid(),
                self.deadline.into_std(),
                self.expected.epoch,
            )
            .map_err(|_| Error::Protocol)?;
        validate_receive_admission(&self.authorization, self.deadline)?;
        Ok((self, custody, frame))
    }

    /// После blocking await заново проверяются canonical/profile/owner facts.
    pub(crate) async fn finish_receive(
        self,
        supervisor: &SystemWorkerSupervisor,
        owner: &RunAuthority,
        custody: NamespaceObservation,
        frame: [u8; 512],
        cancel: &mut Cancellation,
    ) -> Result<VerifiedCoverage> {
        cancel.check().map_err(|_| Error::Cancelled)?;
        self.authorization
            .validate_owner(owner)
            .map_err(|_| Error::Untrusted)?;
        validate_receive_admission(&self.authorization, self.deadline)?;
        let profile = self
            .profile
            .revalidate(supervisor, cancel, self.deadline)
            .await?;
        self.authorization
            .validate_owner(owner)
            .map_err(|_| Error::Untrusted)?;
        if Deadline::now() >= self.deadline {
            return Err(Error::Stale);
        }
        kernel_evidence::verify_fixed_report(&frame, &self.expected)
            .map_err(|_| Error::UnitProofGap)?;
        self.authorization
            .bind_custody(&custody)
            .map_err(|_| Error::UnitProofGap)?;
        Ok(VerifiedCoverage {
            profile,
            authorization: self.authorization,
            expected: self.expected,
            custody,
            guard: self.guard,
            deadline: self.deadline,
        })
    }
}

fn own_start() -> Result<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|_| Error::Unavailable)?;
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .ok_or(Error::Untrusted)
}

use crate::managed_network::{Journal, tun::BoundTun};
use std::{os::fd::OwnedFd, sync::Arc};

/// Общая owning runtime scope; constructor доступен только consuming issuer.
/// Admission deadline проверяется только при promotion, не на runtime health.
pub(crate) struct RuntimeScopeStamp {
    inner: Arc<VerifiedCoverage>,
    owner: crate::managed_network::Ownership,
    queue: Arc<BoundTun>,
}
pub(crate) struct SessionRole {
    scope: RuntimeScopeStamp,
    queue: Arc<BoundTun>,
    worker: OwnedFd,
}
pub(crate) struct RunRole {
    scope: RuntimeScopeStamp,
}
pub(crate) struct IssuedNativeRoles {
    pub(crate) session: SessionRole,
    pub(crate) run: RunRole,
}
impl RuntimeScopeStamp {
    pub(crate) fn validate_admission(&self) -> Result<()> {
        self.inner
            .authorization
            .validate()
            .map_err(|_| Error::Untrusted)?;
        if Deadline::now() >= self.inner.deadline {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub(crate) fn namespace_identity(&self) -> &crate::worker::anchor_exchange::NamespaceIdentity {
        self.inner.custody.identity()
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.inner
            .authorization
            .validate()
            .map_err(|_| Error::Untrusted)?;
        if self.inner.custody.retained_namespace_count() != 2 {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub(crate) fn context(&self) -> NativeRoleContext {
        let e = &self.inner.expected;
        (
            e.nonce,
            e.session,
            e.generation,
            e.invocation,
            e.epoch,
            e.digest,
        )
    }
    pub(crate) fn revoke(&self) {
        self.inner.custody.revoke();
    }
}
impl RunRole {
    pub(crate) fn validate(&self) -> Result<()> {
        self.scope.validate()
    }
    pub(crate) fn context(&self) -> Result<NativeRoleContext> {
        self.validate()?;
        Ok(self.scope.context())
    }
    pub(crate) fn into_guard(self) -> RuntimeScopeStamp {
        self.scope
    }
}

pub(crate) fn verify_pending(
    coverage: VerifiedCoverage,
    owner: &RunAuthority,
    queue: Arc<BoundTun>,
    journal: &Journal,
    topology: crate::LinuxTopology,
    worker: OwnedFd,
) -> Result<IssuedNativeRoles> {
    coverage
        .authorization
        .validate_owner(owner)
        .map_err(|_| Error::Untrusted)?;
    if coverage
        .authorization
        .owner_binding()
        .map_err(|_| Error::Untrusted)?
        != journal.ownership()
    {
        return Err(Error::Untrusted);
    }
    queue
        .project(topology, journal)
        .map_err(|_| Error::Untrusted)?;
    queue.attach_metadata().map_err(|_| Error::Untrusted)?;
    let stamp = RuntimeScopeStamp {
        inner: Arc::new(coverage),
        owner: journal.ownership(),
        queue: Arc::clone(&queue),
    };
    stamp.validate_admission()?;
    stamp
        .inner
        .custody
        .promote_runtime(&stamp)
        .map_err(|_| Error::UnitProofGap)?;
    stamp.validate()?;
    let run = RunRole {
        scope: RuntimeScopeStamp {
            inner: Arc::clone(&stamp.inner),
            owner: stamp.owner,
            queue: Arc::clone(&stamp.queue),
        },
    };
    Ok(IssuedNativeRoles {
        session: SessionRole {
            scope: stamp,
            queue,
            worker,
        },
        run,
    })
}

impl SessionRole {
    pub(crate) fn into_parts(self) -> (RuntimeScopeStamp, Arc<BoundTun>, OwnedFd) {
        (self.scope, self.queue, self.worker)
    }
}

impl VerifiedCoverage {
    pub(crate) fn take_handoff(&self) -> Result<OwnedFd> {
        self.custody.take_handoff().map_err(|_| Error::Protocol)
    }
}

impl RuntimeScopeStamp {
    pub(crate) fn lookup_binding(&self) -> (u32, u32, crate::managed_network::Ownership) {
        (
            self.inner.expected.task_pid,
            self.inner.profile.observation().native_uid(),
            self.owner,
        )
    }
    pub(crate) fn fork_lookup(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            owner: self.owner,
            queue: Arc::clone(&self.queue),
        }
    }
}

impl RuntimeScopeStamp {
    pub(crate) fn owns_observation(&self, observation: &NamespaceObservation) -> bool {
        self.inner.custody.same_custody(observation)
    }
}

fn validate_receive_admission(authorization: &RunAuthorization, deadline: Deadline) -> Result<()> {
    authorization.validate().map_err(|_| Error::Untrusted)?;
    if Deadline::now() >= deadline {
        return Err(Error::Stale);
    }
    Ok(())
}

#[cfg(test)]
mod split_receive_tests {
    use super::*;
    #[test]
    fn pure_receive_admission_accepts_live_token_and_rejects_expiry() {
        let owner = RunAuthority::new([1; 16], 1, 1).unwrap();
        let token = owner.authorize([2; 32]).unwrap();
        assert_eq!(
            validate_receive_admission(&token, Deadline::now() + std::time::Duration::from_secs(1)),
            Ok(())
        );
        assert_eq!(
            validate_receive_admission(&token, Deadline::now()),
            Err(Error::Stale)
        );
    }
    #[test]
    fn pure_receive_admission_revocation_precedes_deadline() {
        let owner = RunAuthority::new([1; 16], 1, 1).unwrap();
        let token = owner.authorize([2; 32]).unwrap();
        owner.revoke();
        assert_eq!(
            validate_receive_admission(&token, Deadline::now()),
            Err(Error::Untrusted)
        );
    }
    #[test]
    fn pure_pending_transfer_owns_sendable_guard() {
        fn sendable<T: Send + 'static>() {}
        sendable::<VerifiedPendingRun>();
        sendable::<(VerifiedPendingRun, NamespaceObservation, [u8; 512])>();
    }
}
