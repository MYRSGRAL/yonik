//! Установка и восстановление отдельной таблицы с kernel timeout.
use super::{Action, NftError, NftExecutor, Observation, Table};
use crate::managed_network::{
    FAKE_POOLS, Journal, Ownership, QuarantineIntent,
    fake_quarantine::{
        FakeQuarantine, QuarantineOwner, QuarantinePrefix, QuarantineStatus, VerifiedTun,
    },
    quarantine_state::{FakeQuarantineRecord, QuarantinePhase, QuarantinePublication},
};
use rustix::time::{ClockId, clock_gettime};
use serde_json::json;
use std::time::{Duration, Instant};

const NFT_SECOND_MS: u32 = 1_000;

fn monotonic_millis() -> Result<u64, NftError> {
    let now = clock_gettime(ClockId::Monotonic);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| NftError::Io)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| NftError::Io)?;
    seconds
        .checked_mul(1_000)
        .and_then(|millis| millis.checked_add(nanos / 1_000_000))
        .ok_or(NftError::Io)
}

fn nft_horizon(remaining_ms: u32) -> u32 {
    remaining_ms.div_ceil(NFT_SECOND_MS) * NFT_SECOND_MS
}

fn table(owner: Ownership, id: u64) -> Table {
    let (device, inode) = owner.namespace();
    Table {
        family: "inet",
        name: format!("yonik_q{id:016x}"),
        comment: format!(
            "yonik:1:{:08x}:{:016x}:{:016x}:{device:016x}:{inode:016x}:{id:016x}:fake-quarantine",
            owner.owner_uid(),
            owner.session(),
            owner.generation(),
        ),
    }
}

fn compile(table: &Table, intent: &QuarantineIntent) -> Result<FakeQuarantine, NftError> {
    let owner = QuarantineOwner::new(table.name.clone(), table.comment.clone())
        .map_err(|_| NftError::Invalid)?;
    let tunnel = intent
        .tun
        .as_ref()
        .map(|tun| VerifiedTun::new(tun.ifindex, format!("tofu{:08x}", tun.name_id)))
        .transpose()
        .map_err(|_| NftError::Invalid)?;
    let pools = FAKE_POOLS
        .into_iter()
        .map(|(address, length)| QuarantinePrefix::new(address, length))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NftError::Invalid)?;
    FakeQuarantine::new(
        owner,
        Duration::from_millis(u64::from(intent.horizon_ms)),
        tunnel,
        pools,
    )
    .map_err(|_| NftError::Invalid)
}

fn verify(
    table: &Table,
    intent: &QuarantineIntent,
    snapshot: &[u8],
) -> Result<QuarantineStatus, NftError> {
    compile(table, intent)?
        .verify_readback(snapshot)
        .map_err(|_error| {
            #[cfg(feature = "test-support")]
            if std::env::var("YONIK_SESSION_DIAGNOSTICS").as_deref() == Ok("1") {
                eprintln!("fake-ip quarantine readback: {_error:?}");
            }
            NftError::Foreign
        })
}

impl NftExecutor {
    /// Сверяет таблицу, при необходимости восстанавливая только drop-правила.
    /// Срок относится к проверенной таблице и сам по себе не разрешает публикацию.
    pub(crate) async fn recover_fake_quarantine(
        &mut self,
        journal: &mut Journal,
    ) -> Result<Option<Instant>, NftError> {
        self.check_namespace()?;
        journal.check(self.owner)?;
        let Some(record) = journal.fake_quarantine().cloned() else {
            return Ok(None);
        };
        let table = table(record.owner, record.table_id);
        let Observation::Owned(handle) = self.observe(&table).await? else {
            return self
                .recover_absent_quarantine(journal, &record, &table)
                .await;
        };
        let sampled_at = Instant::now();
        let snapshot = match self.run(Action::ListTable(&table)).await {
            Err(NftError::Rejected) => match self.observe(&table).await? {
                Observation::Absent => {
                    return self
                        .recover_absent_quarantine(journal, &record, &table)
                        .await;
                }
                Observation::Owned(_) => return Err(NftError::Rejected),
            },
            result => result?,
        };
        self.check_namespace()?;
        let (status, applied) = match record.phase {
            QuarantinePhase::Present { ref policy } | QuarantinePhase::Removing { ref policy } => {
                (verify(&table, policy, &snapshot)?, None)
            }
            QuarantinePhase::Applying {
                ref previous,
                ref desired,
            } => {
                let (desired_installed, status) =
                    if let Ok(status) = verify(&table, desired, &snapshot) {
                        (true, status)
                    } else {
                        let previous = previous.as_ref().ok_or(NftError::Foreign)?;
                        (false, verify(&table, previous, &snapshot)?)
                    };
                (status, Some(desired_installed))
            }
        };
        // При незавершённой замене новый countdown не доказывает срок прежней публикации.
        let legacy_status = if applied == Some(true) {
            None
        } else {
            Some(status)
        };
        let remaining = self.publication_remaining(journal, &record, legacy_status)?;
        if let Some(desired_installed) = applied {
            journal.confirm_fake_quarantine(
                self.owner,
                record.table_id,
                record.revision,
                desired_installed,
                None,
            )?;
        }
        let record = journal.fake_quarantine().ok_or(NftError::Evidence)?.clone();
        match status {
            QuarantineStatus::Active(remaining) => {
                if matches!(record.phase, QuarantinePhase::Removing { .. }) {
                    return Err(NftError::Evidence);
                }
                Ok(Some(sampled_at + remaining))
            }
            QuarantineStatus::Expired if remaining > 0 => self
                .restore_quarantine(journal, &record, &table, Some(handle), remaining)
                .await
                .map(Some),
            QuarantineStatus::Expired => {
                self.remove_expired_quarantine(journal, &record, &table, handle)
                    .await?;
                Ok(None)
            }
        }
    }

    fn publication_remaining(
        &self,
        journal: &mut Journal,
        record: &FakeQuarantineRecord,
        status: Option<QuarantineStatus>,
    ) -> Result<u32, NftError> {
        let now = monotonic_millis()?;
        let publication = if matches!(record.publication, QuarantinePublication::Legacy) {
            // У прежней записи отсутствует привязка TTL ко времени. Сохраняем
            // консервативную границу один раз, до операции с таблицей.
            let publication = if let Some(policy) = record.previous_policy() {
                let ttl_ms = match status {
                    Some(QuarantineStatus::Active(remaining)) => {
                        let ttl_ms =
                            u32::try_from(remaining.as_millis()).map_err(|_| NftError::Invalid)?;
                        (ttl_ms + NFT_SECOND_MS).min(policy.horizon_ms)
                    }
                    _ => policy.horizon_ms,
                };
                QuarantinePublication::confirmed(now, ttl_ms)?
            } else {
                QuarantinePublication::Unpublished
            };
            journal.bind_legacy_quarantine_publication(self.owner, record, publication)?;
            publication
        } else {
            record.publication
        };
        Ok(publication.remaining_at(now)?)
    }

    async fn recover_absent_quarantine(
        &mut self,
        journal: &mut Journal,
        record: &FakeQuarantineRecord,
        table: &Table,
    ) -> Result<Option<Instant>, NftError> {
        let remaining = self.publication_remaining(journal, record, None)?;
        if remaining > 0 {
            return self
                .restore_quarantine(journal, record, table, None, remaining)
                .await
                .map(Some);
        }
        if matches!(record.phase, QuarantinePhase::Present { .. }) {
            journal.begin_remove_fake_quarantine(self.owner, record.table_id, record.revision)?;
        }
        journal.clear_fake_quarantine(self.owner, record.table_id, record.revision)?;
        Ok(None)
    }

    async fn restore_quarantine(
        &mut self,
        journal: &mut Journal,
        record: &FakeQuarantineRecord,
        table: &Table,
        handle: Option<u64>,
        remaining: u32,
    ) -> Result<Instant, NftError> {
        let intent = QuarantineIntent {
            tun: None,
            horizon_ms: nft_horizon(remaining),
        };
        let revision = journal.begin_restore_fake_quarantine(self.owner, record, intent.clone())?;
        let (deadline, _) = self.install_quarantine(table, &intent, handle).await?;
        // Повторное создание не даёт новой возможности публикации и не
        // продлевает живые TTL при повторе после сбоя или reload firewall.
        journal.confirm_fake_quarantine(self.owner, record.table_id, revision, true, None)?;
        Ok(deadline)
    }

    async fn remove_expired_quarantine(
        &mut self,
        journal: &mut Journal,
        record: &FakeQuarantineRecord,
        table: &Table,
        handle: u64,
    ) -> Result<(), NftError> {
        journal.begin_remove_fake_quarantine(self.owner, record.table_id, record.revision)?;
        self.run(Action::Delete(table, handle)).await?;
        if self.observe(table).await? != Observation::Absent {
            return Err(NftError::Evidence);
        }
        journal.clear_fake_quarantine(self.owner, record.table_id, record.revision)?;
        Ok(())
    }

    /// Продление заменяет таблицу одной nft transaction и никогда не открывает окно.
    pub(crate) async fn arm_fake_quarantine(
        &mut self,
        journal: &mut Journal,
        mut intent: QuarantineIntent,
    ) -> Result<Instant, NftError> {
        self.recover_fake_quarantine(journal).await?;
        let (owner, id) = if let Some(record) = journal.fake_quarantine() {
            (record.owner, record.table_id)
        } else {
            let mut id = [0; 8];
            getrandom::getrandom(&mut id).map_err(|_| NftError::Io)?;
            (self.owner, u64::from_le_bytes(id).max(1))
        };
        let table = table(owner, id);
        compile(&table, &intent)?;
        let handle = match (self.observe(&table).await?, journal.fake_quarantine()) {
            (Observation::Absent, None) => None,
            (Observation::Owned(handle), Some(record)) => {
                let QuarantinePhase::Present { policy } = &record.phase else {
                    return Err(NftError::Evidence);
                };
                verify(&table, policy, &self.run(Action::ListTable(&table)).await?)?;
                let remaining = record.publication.remaining_at(monotonic_millis()?)?;
                intent.horizon_ms = intent.horizon_ms.max(nft_horizon(remaining));
                Some(handle)
            }
            _ => return Err(NftError::Foreign),
        };
        let revision = journal.begin_fake_quarantine(self.owner, id, intent.clone())?;
        let (deadline, publication) = self.install_quarantine(&table, &intent, handle).await?;
        journal.confirm_fake_quarantine(self.owner, id, revision, true, Some(publication))?;
        Ok(deadline)
    }

    async fn install_quarantine(
        &mut self,
        table: &Table,
        intent: &QuarantineIntent,
        handle: Option<u64>,
    ) -> Result<(Instant, QuarantinePublication), NftError> {
        let mut commands = compile(table, intent)?.install_commands();
        commands[0] = json!({"create": {"table": {
            "family": table.family, "name": table.name, "comment": table.comment
        }}});
        if let Some(handle) = handle {
            commands.insert(
                0,
                json!({"delete": {"table": {"family": table.family, "handle": handle}}}),
            );
        }
        self.run(Action::Quarantine(commands)).await?;
        let sampled_at = Instant::now();
        let sampled_at_ms = monotonic_millis()?;
        let snapshot = self.run(Action::ListTable(table)).await?;
        self.check_namespace()?;
        let QuarantineStatus::Active(remaining) = verify(table, intent, &snapshot)? else {
            return Err(NftError::Evidence);
        };
        let ttl_ms = u32::try_from(remaining.as_millis()).map_err(|_| NftError::Invalid)?;
        let publication = if ttl_ms == 0 {
            QuarantinePublication::Unpublished
        } else {
            QuarantinePublication::confirmed(sampled_at_ms, ttl_ms)?
        };
        // CLOCK_MONOTONIC округляется вниз при записи в журнал.
        let grant = remaining.saturating_sub(Duration::from_millis(1));
        Ok((sampled_at + grant, publication))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_network::QuarantineTun;

    #[test]
    fn компилятор_принимает_имя_и_пулы_реальной_сессии() {
        let owner = Ownership::new(1000, 1, 2, 4, 5).unwrap();
        let table = table(owner, 6);
        let outcome = compile(
            &table,
            &QuarantineIntent {
                tun: Some(QuarantineTun {
                    ifindex: 17,
                    name_id: 41,
                }),
                horizon_ms: 90_000,
            },
        )
        .unwrap();
        assert_eq!(
            outcome.install_commands()[0]["add"]["table"]["name"],
            table.name
        );
    }

    #[test]
    fn ttl_восстановления_округляется_вверх_до_секунды() {
        assert_eq!(nft_horizon(0), 0);
        assert_eq!(nft_horizon(1), 1_000);
        assert_eq!(nft_horizon(89_000), 89_000);
        assert_eq!(nft_horizon(119_999), 120_000);
    }
}
