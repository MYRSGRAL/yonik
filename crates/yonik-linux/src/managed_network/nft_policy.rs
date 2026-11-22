use super::block::block_table;
use super::*;
use crate::managed_network::PublicPolicyPhase;

/// Результат сверки kernel rules, а не доказательство актуальной привязки
/// интерфейсов/маршрутов. После restart topology проверяется отдельно.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicPolicyRecovery {
    NoPolicy,
    DesiredRules { revision: u64 },
    PreviousRules { revision: u64 },
    Missing { revision: u64, unlocking: bool },
    UnlockPending { revision: u64 },
}

impl NftExecutor {
    /// Startup-сверка не создаёт/заменяет/удаляет сетевые объекты и не
    /// воспроизводит сохранённые ifindex до проверки текущего окружения.
    pub async fn recover_public_policy(
        &mut self,
        journal: &mut Journal,
    ) -> Result<PublicPolicyRecovery, NftError> {
        self.check_namespace()?;
        journal.check(self.owner)?;
        let Some(record) = journal.public_policy().cloned() else {
            return if journal
                .records()
                .iter()
                .any(|r| r.scope() == Scope::PublicBlock)
            {
                Err(NftError::Evidence)
            } else {
                Ok(PublicPolicyRecovery::NoPolicy)
            };
        };
        let id = record.id();
        let revision = record.revision();
        journal.require_reconciliation(self.owner, id)?;
        let (desired, previous) = match record.phase() {
            PublicPolicyPhase::Stable { policy } => (policy, None),
            PublicPolicyPhase::Present { desired, previous } => (desired, previous.as_ref()),
            PublicPolicyPhase::Removing { candidates } => {
                for policy in candidates {
                    let table = block_table(self.owner, id, record.table_id(), policy);
                    match self.observe(&table).await {
                        Ok(Observation::Absent) => {
                            return Ok(PublicPolicyRecovery::Missing {
                                revision,
                                unlocking: true,
                            });
                        }
                        Ok(Observation::Owned(_)) => {
                            self.verify_public_block(&table, policy).await?;
                            return Ok(PublicPolicyRecovery::UnlockPending { revision });
                        }
                        Err(NftError::Foreign) => continue,
                        Err(error) => return Err(error),
                    }
                }
                return Err(NftError::Foreign);
            }
        };
        let table = block_table(self.owner, id, record.table_id(), desired);
        match self.observe(&table).await {
            Ok(Observation::Owned(_)) => {
                self.verify_public_block(&table, desired).await?;
                journal.reconcile(self.owner, id, Reconciled::Owned)?;
                journal.confirm_public_policy(self.owner, id, revision)?;
                Ok(PublicPolicyRecovery::DesiredRules { revision })
            }
            Ok(Observation::Absent) => Ok(PublicPolicyRecovery::Missing {
                revision,
                unlocking: false,
            }),
            Err(NftError::Foreign) => {
                if let Some(previous) = previous {
                    let table = block_table(self.owner, id, record.table_id(), previous);
                    if matches!(self.observe(&table).await?, Observation::Owned(_)) {
                        self.verify_public_block(&table, previous).await?;
                        return Ok(PublicPolicyRecovery::PreviousRules { revision });
                    }
                }
                Err(NftError::Foreign)
            }
            Err(error) => Err(error),
        }
    }

    /// Доверенный helper вызывает только после свежей авторизации и проверки
    /// привязок интерфейсов. Политика и возможный previous durable до эффектов.
    pub async fn apply_durable_public_policy(
        &mut self,
        journal: &mut Journal,
        id: u64,
        table_id: u64,
        desired: PublicBlockPolicy,
    ) -> Result<u64, NftError> {
        self.check_namespace()?;
        if desired
            .dhcp_rule_identity()
            .is_some_and(|(namespace, _)| namespace != self.owner.namespace())
        {
            return Err(NftError::Namespace);
        }
        let revision = journal.begin_public_policy(self.owner, id, table_id, desired.clone())?;
        match self.recover_public_policy(journal).await? {
            PublicPolicyRecovery::DesiredRules { revision: actual } if actual == revision => {
                return Ok(revision);
            }
            PublicPolicyRecovery::PreviousRules { revision: actual } if actual == revision => {
                let Some(record) = journal.public_policy() else {
                    return Err(NftError::Evidence);
                };
                let PublicPolicyPhase::Present {
                    previous: Some(previous),
                    ..
                } = record.phase()
                else {
                    return Err(NftError::Evidence);
                };
                let previous = previous.clone();
                self.replace_public_block(journal, id, &previous, &desired)
                    .await?;
            }
            PublicPolicyRecovery::Missing {
                revision: actual,
                unlocking: false,
            } if actual == revision => {
                self.ensure_public_block(journal, id, table_id, &desired)
                    .await?;
            }
            _ => return Err(NftError::Evidence),
        }
        journal.confirm_public_policy(self.owner, id, revision)?;
        Ok(revision)
    }

    /// Fresh Unlock авторизуется внешним helper. Повтор без managed policy —
    /// NoPolicy, а legacy/неучтённые public records не объявляются очищенными.
    pub async fn unlock_durable_public_policy(
        &mut self,
        journal: &mut Journal,
        id: u64,
    ) -> Result<Option<u64>, NftError> {
        self.check_namespace()?;
        journal.check(self.owner)?;
        if journal.public_policy().is_none() {
            return if journal
                .records()
                .iter()
                .any(|r| r.scope() == Scope::PublicBlock)
            {
                Err(NftError::Evidence)
            } else {
                Ok(None)
            };
        }
        let revision = journal.begin_public_unlock(self.owner, id)?;
        let Some(record) = journal.public_policy() else {
            return Err(NftError::Evidence);
        };
        let PublicPolicyPhase::Removing { candidates } = record.phase() else {
            return Err(NftError::Evidence);
        };
        let candidates = candidates.clone();
        for policy in candidates {
            match self.remove_public_block(journal, id, &policy).await {
                Ok(()) => return Ok(Some(revision)),
                Err(NftError::Foreign) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(NftError::Foreign)
    }
}

#[cfg(test)]
#[path = "nft_policy_tests.rs"]
mod tests;
