//! Одноразовое разрешение владельца helper; не является namespace admission.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunAuthorizationError {
    InvalidContext,
    Revoked,
    Consumed,
}

struct RunRevocation {
    revoked: AtomicBool,
    custody: Mutex<Option<crate::worker::anchor_exchange::NamespaceRevocation>>,
}
impl RunRevocation {
    fn new() -> Self {
        Self {
            revoked: AtomicBool::new(false),
            custody: Mutex::new(None),
        }
    }
    fn load(&self, ordering: Ordering) -> bool {
        self.revoked.load(ordering)
    }
    fn revoke(&self) {
        let mut custody = self
            .custody
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.revoked.store(true, Ordering::Release);
        if let Some(item) = custody.take() {
            item.revoke();
        }
    }
}

// Producer подключается W4 после проверки реального owner/network context.
#[allow(dead_code)]
pub(crate) struct RunAuthority {
    owner_binding: Option<super::protection_host::session_host::native_owner::OwnerBinding>,
    session: [u8; 16],
    generation: u64,
    network_epoch: u64,
    issued: AtomicBool,
    revoked: Arc<RunRevocation>,
}
#[allow(dead_code)]
impl RunAuthority {
    #[cfg(test)]
    pub(crate) fn new(
        session: [u8; 16],
        generation: u64,
        network_epoch: u64,
    ) -> Result<Self, RunAuthorizationError> {
        if session == [0; 16] || generation == 0 || network_epoch == 0 {
            return Err(RunAuthorizationError::InvalidContext);
        }
        Ok(Self {
            owner_binding: None,
            session,
            generation,
            network_epoch,
            issued: AtomicBool::new(false),
            revoked: Arc::new(RunRevocation::new()),
        })
    }
    pub(super) fn from_bound(
        binding: super::protection_host::session_host::native_owner::OwnerBinding,
    ) -> Self {
        let (session, generation, network_epoch) = binding.context();
        Self {
            owner_binding: Some(binding),
            session,
            generation,
            network_epoch,
            issued: AtomicBool::new(false),
            revoked: Arc::new(RunRevocation::new()),
        }
    }
    pub(crate) fn bound_to(&self, ownership: crate::managed_network::Ownership) -> bool {
        self.owner_binding
            .as_ref()
            .is_some_and(|binding| binding.ownership() == ownership)
    }
    pub(crate) fn authorize(
        &self,
        nonce: [u8; 32],
    ) -> Result<RunAuthorization, RunAuthorizationError> {
        if nonce == [0; 32] {
            return Err(RunAuthorizationError::InvalidContext);
        }
        if self.revoked.load(Ordering::Acquire) {
            return Err(RunAuthorizationError::Revoked);
        }
        self.issued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RunAuthorizationError::Consumed)?;
        let token = RunAuthorization {
            owner_binding: self.owner_binding.as_ref().map(|b| b.ownership()),
            session: self.session,
            nonce,
            generation: self.generation,
            network_epoch: self.network_epoch,
            revoked: Arc::clone(&self.revoked),
        };
        token.validate()?;
        Ok(token)
    }
    #[cfg(test)]
    pub(super) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
    pub(crate) fn revoke(&self) {
        self.revoked.revoke();
    }
}
impl Drop for RunAuthority {
    fn drop(&mut self) {
        self.revoke();
    }
}

pub(crate) struct RunAuthorization {
    owner_binding: Option<crate::managed_network::Ownership>,
    session: [u8; 16],
    nonce: [u8; 32],
    generation: u64,
    network_epoch: u64,
    revoked: Arc<RunRevocation>,
}
impl RunAuthorization {
    pub(crate) fn owner_binding(
        &self,
    ) -> Result<crate::managed_network::Ownership, RunAuthorizationError> {
        self.validate()?;
        self.owner_binding
            .ok_or(RunAuthorizationError::InvalidContext)
    }
    pub(super) fn validate(&self) -> Result<(), RunAuthorizationError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(RunAuthorizationError::Revoked);
        }
        if self.session == [0; 16]
            || self.nonce == [0; 32]
            || self.generation == 0
            || self.network_epoch == 0
        {
            return Err(RunAuthorizationError::InvalidContext);
        }
        Ok(())
    }
    /// Числовое совпадение не заменяет владение тем же revocation object.
    pub(super) fn validate_owner(&self, owner: &RunAuthority) -> Result<(), RunAuthorizationError> {
        self.validate()?;
        if owner.revoked.load(Ordering::Acquire) {
            return Err(RunAuthorizationError::Revoked);
        }
        if !Arc::ptr_eq(&self.revoked, &owner.revoked)
            || self.session != owner.session
            || self.generation != owner.generation
            || self.network_epoch != owner.network_epoch
        {
            return Err(RunAuthorizationError::InvalidContext);
        }
        Ok(())
    }
    pub(crate) fn challenge_context(
        &self,
    ) -> Result<([u8; 32], [u8; 16], u64), RunAuthorizationError> {
        self.validate()?;
        Ok((self.nonce, self.session, self.generation))
    }
    pub(super) fn bind_custody(
        &self,
        observation: &crate::worker::anchor_exchange::NamespaceObservation,
    ) -> Result<(), RunAuthorizationError> {
        let result = (|| {
            let mut custody = self
                .revoked
                .custody
                .lock()
                .map_err(|_| RunAuthorizationError::Revoked)?;
            self.validate()?;
            // Один Run token удерживает только один bootstrap report.
            if custody.is_some() {
                return Err(RunAuthorizationError::Consumed);
            }
            observation
                .bind_run(
                    self.nonce,
                    self.session,
                    self.generation,
                    self.network_epoch,
                )
                .map_err(|_| RunAuthorizationError::InvalidContext)?;
            *custody = Some(observation.revocation());
            Ok(())
        })();
        if result.is_err() {
            observation.revoke();
            self.revoked.revoke();
        }
        result
    }

    pub(super) fn guard(&self) -> RunRevocationGuard {
        RunRevocationGuard(Arc::clone(&self.revoked))
    }
}

/// Drop future отзывает даже token, уже переданный blocking task.
pub(super) struct RunRevocationGuard(Arc<RunRevocation>);
impl Drop for RunRevocationGuard {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

#[cfg(test)]
mod owner_tests {
    use super::*;
    #[test]
    fn exact_owner_rejects_equal_numbers_foreign_arc_and_revocation() {
        let owner = RunAuthority::new([1; 16], 7, 9).unwrap();
        let other = RunAuthority::new([1; 16], 7, 9).unwrap();
        let mut token = owner.authorize([2; 32]).unwrap();
        assert_eq!(token.validate_owner(&owner), Ok(()));
        assert_eq!(
            token.validate_owner(&other),
            Err(RunAuthorizationError::InvalidContext)
        );
        token.session = [9; 16];
        assert_eq!(
            token.validate_owner(&owner),
            Err(RunAuthorizationError::InvalidContext)
        );
        token.session = [1; 16];
        token.generation += 1;
        assert_eq!(
            token.validate_owner(&owner),
            Err(RunAuthorizationError::InvalidContext)
        );
        token.generation -= 1;
        token.network_epoch += 1;
        assert_eq!(
            token.validate_owner(&owner),
            Err(RunAuthorizationError::InvalidContext)
        );
        token.network_epoch -= 1;
        owner.revoke();
        assert_eq!(
            token.validate_owner(&owner),
            Err(RunAuthorizationError::Revoked)
        );
    }
}
