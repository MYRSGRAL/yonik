//! Независимый durable-учёт ограничения для ещё закешированных Fake-IP.
use super::{Document, Journal, JournalError, Ownership};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_HORIZON_MS: u32 = 120_000;
pub(crate) const FAKE_POOLS: [(IpAddr, u8); 2] = [
    (IpAddr::V4(Ipv4Addr::new(198, 19, 224, 0)), 19),
    (
        IpAddr::V6(Ipv6Addr::new(0xfd79, 0x6f69, 0x6b00, 0x5c01, 0, 0, 0, 0)),
        115,
    ),
];

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuarantineTun {
    pub ifindex: u32,
    pub name_id: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuarantineIntent {
    pub tun: Option<QuarantineTun>,
    pub horizon_ms: u32,
}

impl QuarantineIntent {
    fn validate(&self) -> Result<(), JournalError> {
        if !(1..=MAX_HORIZON_MS).contains(&self.horizon_ms)
            || self
                .tun
                .as_ref()
                .is_some_and(|tun| tun.ifindex == 0 || tun.name_id == 0)
        {
            return Err(JournalError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
pub(crate) enum QuarantinePhase {
    Applying {
        previous: Option<QuarantineIntent>,
        desired: QuarantineIntent,
    },
    Present {
        policy: QuarantineIntent,
    },
    Removing {
        policy: QuarantineIntent,
    },
}

/// Верхняя граница выданных TTL. Runtime-журнал находится в /run, поэтому
/// CLOCK_MONOTONIC сохраняет смысл при рестарте helper в пределах этой загрузки.
#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum QuarantinePublication {
    #[default]
    Legacy,
    Unpublished,
    Confirmed {
        sampled_at_ms: u64,
        ttl_ms: u32,
    },
}

impl QuarantinePublication {
    pub(crate) fn confirmed(sampled_at_ms: u64, ttl_ms: u32) -> Result<Self, JournalError> {
        let publication = Self::Confirmed {
            sampled_at_ms,
            ttl_ms,
        };
        publication.deadline()?;
        Ok(publication)
    }

    pub(crate) fn remaining_at(self, now_ms: u64) -> Result<u32, JournalError> {
        match self {
            Self::Legacy => Err(JournalError::Invalid),
            Self::Unpublished => Ok(0),
            Self::Confirmed {
                sampled_at_ms,
                ttl_ms,
            } if now_ms >= sampled_at_ms => {
                let elapsed = now_ms - sampled_at_ms;
                Ok(u64::from(ttl_ms).saturating_sub(elapsed) as u32)
            }
            Self::Confirmed { .. } => Err(JournalError::Invalid),
        }
    }

    fn deadline(self) -> Result<u64, JournalError> {
        match self {
            Self::Confirmed {
                sampled_at_ms,
                ttl_ms,
            } => {
                if !(1..=MAX_HORIZON_MS).contains(&ttl_ms) {
                    return Err(JournalError::Invalid);
                }
                sampled_at_ms
                    .checked_add(u64::from(ttl_ms))
                    .ok_or(JournalError::Invalid)
            }
            Self::Legacy | Self::Unpublished => Ok(0),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FakeQuarantineRecord {
    pub table_id: u64,
    pub owner: Ownership,
    pub revision: u64,
    pub phase: QuarantinePhase,
    #[serde(default)]
    pub publication: QuarantinePublication,
}

impl FakeQuarantineRecord {
    pub(crate) fn is_present_for_tun(&self, tun: &QuarantineTun) -> bool {
        matches!(&self.phase, QuarantinePhase::Present { policy } if policy.tun.as_ref() == Some(tun))
    }

    pub(crate) fn previous_policy(&self) -> Option<&QuarantineIntent> {
        match &self.phase {
            QuarantinePhase::Applying { previous, .. } => previous.as_ref(),
            QuarantinePhase::Present { policy } => Some(policy),
            QuarantinePhase::Removing { .. } => None,
        }
    }

    pub(super) fn validate(&self, document: &Document) -> Result<(), JournalError> {
        self.owner.validate()?;
        self.publication.deadline()?;
        if self.table_id == 0
            || self.revision == 0
            || self.owner.namespace() != document.ownership.namespace()
        {
            return Err(JournalError::Invalid);
        }
        match &self.phase {
            QuarantinePhase::Applying { previous, desired } => {
                if let Some(previous) = previous {
                    previous.validate()?;
                }
                desired.validate()
            }
            QuarantinePhase::Present { policy } | QuarantinePhase::Removing { policy } => {
                policy.validate()
            }
        }
    }
}

impl Journal {
    pub(crate) fn fake_quarantine(&self) -> Option<&FakeQuarantineRecord> {
        self.document.fake_quarantine.as_ref()
    }

    pub(crate) fn begin_fake_quarantine(
        &mut self,
        owner: Ownership,
        table_id: u64,
        desired: QuarantineIntent,
    ) -> Result<u64, JournalError> {
        self.check(owner)?;
        desired.validate()?;
        let (previous, revision, record_owner, publication) = match self.fake_quarantine() {
            None => (None, 1, owner, QuarantinePublication::Unpublished),
            Some(record) if record.table_id == table_id => {
                let QuarantinePhase::Present { policy } = &record.phase else {
                    return Err(JournalError::Conflict);
                };
                let revision = record.revision.checked_add(1).ok_or(JournalError::Limit)?;
                (
                    Some(policy.clone()),
                    revision,
                    record.owner,
                    record.publication,
                )
            }
            Some(_) => return Err(JournalError::Conflict),
        };
        let mut updated = self.document.clone();
        updated.version = 4;
        updated.fake_quarantine = Some(FakeQuarantineRecord {
            table_id,
            owner: record_owner,
            revision,
            phase: QuarantinePhase::Applying { previous, desired },
            publication,
        });
        self.persist(updated)?;
        Ok(revision)
    }

    /// Повторное создание после доказанного отсутствия прежних правил.
    pub(crate) fn begin_restore_fake_quarantine(
        &mut self,
        owner: Ownership,
        expected: &FakeQuarantineRecord,
        desired: QuarantineIntent,
    ) -> Result<u64, JournalError> {
        self.check(owner)?;
        let mut updated = self.document.clone();
        let record = updated
            .fake_quarantine
            .as_mut()
            .ok_or(JournalError::Missing)?;
        if record.table_id != expected.table_id || record.revision != expected.revision {
            return Err(JournalError::Conflict);
        }
        if desired.tun.is_some() {
            return Err(JournalError::Invalid);
        }
        let previous = record
            .previous_policy()
            .cloned()
            .ok_or(JournalError::Conflict)?;
        let revision = record.revision.checked_add(1).ok_or(JournalError::Limit)?;
        record.revision = revision;
        record.phase = QuarantinePhase::Applying {
            previous: Some(previous),
            desired,
        };
        self.persist(updated)?;
        Ok(revision)
    }

    pub(crate) fn bind_legacy_quarantine_publication(
        &mut self,
        owner: Ownership,
        expected: &FakeQuarantineRecord,
        publication: QuarantinePublication,
    ) -> Result<(), JournalError> {
        self.check(owner)?;
        let mut updated = self.document.clone();
        let record = updated
            .fake_quarantine
            .as_mut()
            .ok_or(JournalError::Missing)?;
        if record.table_id != expected.table_id
            || record.revision != expected.revision
            || !matches!(record.publication, QuarantinePublication::Legacy)
        {
            return Err(JournalError::Conflict);
        }
        record.publication = publication;
        self.persist(updated)
    }

    pub(crate) fn confirm_fake_quarantine(
        &mut self,
        owner: Ownership,
        table_id: u64,
        revision: u64,
        desired_installed: bool,
        publication: Option<QuarantinePublication>,
    ) -> Result<(), JournalError> {
        self.check(owner)?;
        let mut updated = self.document.clone();
        let record = updated
            .fake_quarantine
            .as_mut()
            .ok_or(JournalError::Missing)?;
        if record.table_id != table_id || record.revision != revision {
            return Err(JournalError::Conflict);
        }
        let QuarantinePhase::Applying { previous, desired } = &record.phase else {
            return Err(JournalError::Conflict);
        };
        let policy = if desired_installed {
            desired
        } else {
            previous.as_ref().ok_or(JournalError::Conflict)?
        };
        record.phase = QuarantinePhase::Present {
            policy: policy.clone(),
        };
        if let Some(publication) = publication {
            if !desired_installed {
                return Err(JournalError::Conflict);
            }
            if publication.deadline()? > record.publication.deadline()? {
                record.publication = publication;
            }
        }
        self.persist(updated)
    }

    pub(crate) fn begin_remove_fake_quarantine(
        &mut self,
        owner: Ownership,
        table_id: u64,
        revision: u64,
    ) -> Result<(), JournalError> {
        self.check(owner)?;
        let mut updated = self.document.clone();
        let record = updated
            .fake_quarantine
            .as_mut()
            .ok_or(JournalError::Missing)?;
        if record.table_id != table_id || record.revision != revision {
            return Err(JournalError::Conflict);
        }
        if let QuarantinePhase::Present { policy } = &record.phase {
            record.phase = QuarantinePhase::Removing {
                policy: policy.clone(),
            };
            self.persist(updated)?;
        } else if !matches!(record.phase, QuarantinePhase::Removing { .. }) {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }

    /// Caller подтверждает отсутствие таблицы и истечение подтверждённого TTL.
    pub(crate) fn clear_fake_quarantine(
        &mut self,
        owner: Ownership,
        table_id: u64,
        revision: u64,
    ) -> Result<(), JournalError> {
        self.check(owner)?;
        let record = self.fake_quarantine().ok_or(JournalError::Missing)?;
        if record.table_id != table_id || record.revision != revision {
            return Err(JournalError::Conflict);
        }
        if !matches!(
            record.phase,
            QuarantinePhase::Removing { .. } | QuarantinePhase::Applying { .. }
        ) {
            return Err(JournalError::Conflict);
        }
        let mut updated = self.document.clone();
        updated.fake_quarantine = None;
        updated.version = 3;
        self.persist(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let mut nonce = [0; 8];
            getrandom::getrandom(&mut nonce).unwrap();
            let dir = std::env::temp_dir().join(format!(
                "yonik-quarantine-{:016x}",
                u64::from_le_bytes(nonce)
            ));
            fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn срок_публикации_сохраняется_при_повторном_восстановлении() {
        let directory = TestDirectory::new();
        let owner = Ownership::new(1000, 1, 1, 4, 99).unwrap();
        let mut journal = Journal::open(&directory.0, owner).unwrap();
        let tun = QuarantineTun {
            ifindex: 9,
            name_id: 2,
        };
        let revision = journal
            .begin_fake_quarantine(
                owner,
                42,
                QuarantineIntent {
                    tun: Some(tun.clone()),
                    horizon_ms: 90_000,
                },
            )
            .unwrap();
        journal
            .confirm_fake_quarantine(
                owner,
                42,
                revision,
                true,
                Some(QuarantinePublication::confirmed(20_000, 88_000).unwrap()),
            )
            .unwrap();
        assert!(journal.fake_quarantine().unwrap().is_present_for_tun(&tun));

        let short_refresh = journal
            .begin_fake_quarantine(
                owner,
                42,
                QuarantineIntent {
                    tun: Some(tun.clone()),
                    horizon_ms: 10_000,
                },
            )
            .unwrap();
        journal
            .confirm_fake_quarantine(
                owner,
                42,
                short_refresh,
                true,
                Some(QuarantinePublication::confirmed(30_000, 10_000).unwrap()),
            )
            .unwrap();

        let drop_only = QuarantineIntent {
            tun: None,
            horizon_ms: 15_000,
        };
        for _ in 0..2 {
            let record = journal.fake_quarantine().unwrap().clone();
            journal
                .begin_restore_fake_quarantine(owner, &record, drop_only.clone())
                .unwrap();
            assert!(!journal.fake_quarantine().unwrap().is_present_for_tun(&tun));
            drop(journal);
            journal = Journal::open(&directory.0, owner).unwrap();
        }
        let record = journal.fake_quarantine().unwrap().clone();
        journal
            .confirm_fake_quarantine(owner, 42, record.revision, true, None)
            .unwrap();
        let record = journal.fake_quarantine().unwrap();
        assert!(!record.is_present_for_tun(&tun));
        assert_eq!(record.publication.remaining_at(107_999), Ok(1));
        assert_eq!(record.publication.remaining_at(108_000), Ok(0));
    }

    #[test]
    fn срок_публикации_ограничен_и_не_принимает_время_из_будущего() {
        assert!(QuarantinePublication::confirmed(1, MAX_HORIZON_MS + 1).is_err());
        assert!(QuarantinePublication::confirmed(u64::MAX, 1).is_err());
        assert_eq!(
            QuarantinePublication::confirmed(20_000, 1_000)
                .unwrap()
                .remaining_at(19_999),
            Err(JournalError::Invalid)
        );
    }

    #[test]
    fn карантин_переживает_нового_владельца_и_отдельное_снятие_защиты() {
        let directory = TestDirectory::new();
        let owner = Ownership::new(1000, 1, 1, 4, 99).unwrap();
        let next = Ownership::new(1001, 2, 1, 4, 99).unwrap();
        let mut journal = Journal::open(&directory.0, owner).unwrap();
        assert_eq!(journal.document.version, 3);
        let revision = journal
            .begin_fake_quarantine(
                owner,
                42,
                QuarantineIntent {
                    tun: Some(QuarantineTun {
                        ifindex: 9,
                        name_id: 2,
                    }),
                    horizon_ms: 90_000,
                },
            )
            .unwrap();
        assert_eq!(journal.document.version, 4);
        assert_eq!(
            journal.confirm_fake_quarantine(owner, 42, revision + 1, true, None),
            Err(JournalError::Conflict)
        );
        journal
            .confirm_fake_quarantine(owner, 42, revision, true, None)
            .unwrap();
        assert_eq!(
            journal.clear_fake_quarantine(owner, 42, revision),
            Err(JournalError::Conflict)
        );
        journal.reassign_empty_owner(next).unwrap();
        drop(journal);
        let mut journal = Journal::open(&directory.0, next).unwrap();
        assert!(
            journal
                .fake_quarantine()
                .is_some_and(|record| record.owner == owner)
        );
        journal
            .begin_remove_fake_quarantine(next, 42, revision)
            .unwrap();
        drop(journal);
        let mut journal = Journal::open_existing(&directory.0).unwrap().unwrap();
        journal
            .begin_remove_fake_quarantine(next, 42, revision)
            .unwrap();
        journal.clear_fake_quarantine(next, 42, revision).unwrap();
        assert_eq!(journal.document.version, 3);
        assert!(journal.fake_quarantine().is_none());
    }
}
