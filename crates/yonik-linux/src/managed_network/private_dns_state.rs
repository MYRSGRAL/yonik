//! Защищённые DNS-зоны переживают перезагрузку независимо от сетевого журнала.
use super::{Journal, JournalError, storage};
use crate::resolver::resolve1::MAX_ENTRIES as MAX_ZONES;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs::File, path::Path};

const FILE: &str = "private-dns-zones.json";
const PENDING: &str = "private-dns-zones.next";
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_USERS: usize = 64;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerZones {
    uid: u32,
    zones: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateDnsState {
    version: u32,
    users: Vec<OwnerZones>,
}

fn valid_zone(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_uppercase())
        })
}

impl PrivateDnsState {
    fn read(directory: &File) -> Result<Self, JournalError> {
        let Some(bytes) = storage::read_bounded(directory, FILE, MAX_BYTES)? else {
            return Ok(Self {
                version: 1,
                users: Vec::new(),
            });
        };
        let state: PrivateDnsState =
            serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
        if state.version != 1 {
            return Err(JournalError::Version);
        }
        if state.users.len() > MAX_USERS
            || state
                .users
                .iter()
                .any(|entry| entry.zones.len() > MAX_ZONES)
        {
            return Err(JournalError::Limit);
        }
        if state
            .users
            .windows(2)
            .any(|pair| pair[0].uid >= pair[1].uid)
            || state.users.iter().any(|entry| {
                entry.zones.is_empty()
                    || entry.zones.windows(2).any(|pair| pair[0] >= pair[1])
                    || entry.zones.iter().any(|zone| !valid_zone(zone))
            })
        {
            return Err(JournalError::Corrupt);
        }
        Ok(state)
    }

    fn merge_user(&mut self, uid: u32, observed: &BTreeSet<String>) -> Result<bool, JournalError> {
        if observed.is_empty() {
            return Ok(false);
        }
        if observed.len() > MAX_ZONES {
            return Err(JournalError::Limit);
        }
        if observed.iter().any(|zone| !valid_zone(zone)) {
            return Err(JournalError::Invalid);
        }
        match self.users.binary_search_by_key(&uid, |entry| entry.uid) {
            Ok(index) => {
                let entry = &mut self.users[index];
                let existing: BTreeSet<_> = entry.zones.iter().cloned().collect();
                if observed.is_subset(&existing) {
                    return Ok(false);
                }
                let merged: Vec<_> = existing.union(observed).cloned().collect();
                if merged.len() > MAX_ZONES {
                    return Err(JournalError::Limit);
                }
                entry.zones = merged;
            }
            Err(index) => {
                if self.users.len() == MAX_USERS {
                    return Err(JournalError::Limit);
                }
                self.users.insert(
                    index,
                    OwnerZones {
                        uid,
                        zones: observed.iter().cloned().collect(),
                    },
                );
            }
        }
        Ok(true)
    }
}

pub(crate) struct PrivateDnsJournal {
    directory: storage::LockedDirectory,
    uncertain: bool,
}

impl PrivateDnsJournal {
    pub(crate) fn open(path: &Path, legacy: Option<&Journal>) -> Result<Self, JournalError> {
        let mut journal = Self {
            directory: storage::directory(path)?,
            uncertain: false,
        };
        let mut state = journal.read()?;
        if let Some(legacy) = legacy {
            legacy.check(legacy.ownership())?;
            let mut updated = false;
            for owner in PrivateDnsState::read(&legacy.directory)?.users {
                updated |= state.merge_user(owner.uid, &owner.zones.into_iter().collect())?;
            }
            if updated {
                journal.write(&state)?;
            }
        }
        Ok(journal)
    }

    fn read(&self) -> Result<PrivateDnsState, JournalError> {
        if self.uncertain {
            return Err(JournalError::UncertainWrite);
        }
        PrivateDnsState::read(&self.directory)
    }

    pub(crate) fn saved_zones(&self, uid: u32) -> Result<BTreeSet<String>, JournalError> {
        Ok(self
            .read()?
            .users
            .into_iter()
            .find(|entry| entry.uid == uid)
            .map(|entry| entry.zones.into_iter().collect())
            .unwrap_or_default())
    }

    pub(crate) fn store_zones(
        &mut self,
        uid: u32,
        observed: &BTreeSet<String>,
    ) -> Result<(), JournalError> {
        if observed.is_empty() {
            return Ok(());
        }
        let mut state = self.read()?;
        if state.merge_user(uid, observed)? {
            self.write(&state)?;
        }
        Ok(())
    }

    fn write(&mut self, state: &PrivateDnsState) -> Result<(), JournalError> {
        let bytes = serde_json::to_vec(state).map_err(|_| JournalError::Invalid)?;
        if bytes.len() > MAX_BYTES {
            return Err(JournalError::Limit);
        }
        let result = storage::write_atomic(&self.directory, FILE, PENDING, &bytes);
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_network::Ownership;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

    struct Area(PathBuf);

    impl Area {
        fn new() -> Self {
            let mut nonce = [0; 8];
            getrandom::getrandom(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "yonik-private-dns-state-{:016x}",
                u64::from_ne_bytes(nonce)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Area {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn private_zones_survive_reopen_and_are_separate_per_uid() {
        let area = Area::new();
        let original = BTreeSet::from(["corp.test".to_owned()]);
        let additional = BTreeSet::from(["xn--bro-hoa.test".to_owned()]);
        let mut journal = PrivateDnsJournal::open(&area.0, None).unwrap();
        assert!(journal.saved_zones(1000).unwrap().is_empty());
        journal.store_zones(1000, &original).unwrap();
        journal.store_zones(1000, &additional).unwrap();
        journal.store_zones(1001, &additional).unwrap();
        drop(journal);

        let journal = PrivateDnsJournal::open(&area.0, None).unwrap();
        assert_eq!(journal.saved_zones(1000).unwrap(), &original | &additional);
        assert_eq!(journal.saved_zones(1001).unwrap(), additional);
        assert!(journal.saved_zones(1002).unwrap().is_empty());
    }

    #[test]
    fn переносит_все_uid_из_журнала_текущей_загрузки() {
        let old = Area::new();
        let new = Area::new();
        let original = BTreeSet::from(["wireguard.test".to_owned()]);
        let additional = BTreeSet::from(["new.test".to_owned()]);
        let mut previous = PrivateDnsJournal::open(&old.0, None).unwrap();
        previous.store_zones(1000, &original).unwrap();
        previous.store_zones(1001, &original).unwrap();
        drop(previous);

        let mut current = PrivateDnsJournal::open(&new.0, None).unwrap();
        current.store_zones(1000, &additional).unwrap();
        drop(current);

        let owner = Ownership::new(1001, 1, 1, 1, 1).unwrap();
        let legacy = Journal::open(&old.0, owner).unwrap();
        for _ in 0..2 {
            let imported = PrivateDnsJournal::open(&new.0, Some(&legacy)).unwrap();
            assert_eq!(imported.saved_zones(1000).unwrap(), &additional | &original);
            assert_eq!(imported.saved_zones(1001).unwrap(), original);
        }
        drop(legacy);
        drop(old);
        let after = PrivateDnsJournal::open(&new.0, None).unwrap();
        assert_eq!(after.saved_zones(1000).unwrap(), &additional | &original);
        assert_eq!(after.saved_zones(1001).unwrap(), original);
    }

    #[test]
    fn private_zone_store_rejects_corrupt_state_and_overflow() {
        let area = Area::new();
        let mut journal = PrivateDnsJournal::open(&area.0, None).unwrap();
        let maximum = (0..MAX_ZONES)
            .map(|index| format!("host{index}.test"))
            .collect();
        journal.store_zones(1000, &maximum).unwrap();
        assert!(matches!(
            journal.store_zones(1000, &BTreeSet::from(["other.test".to_owned()])),
            Err(JournalError::Limit)
        ));
        assert_eq!(journal.saved_zones(1000).unwrap(), maximum);

        fs::write(
            area.0.join(FILE),
            br#"{"version":1,"users":[{"uid":1000,"zones":["."]}]}"#,
        )
        .unwrap();
        assert!(matches!(
            journal.saved_zones(1000),
            Err(JournalError::Corrupt)
        ));
        assert!(matches!(
            journal.store_zones(1000, &maximum),
            Err(JournalError::Corrupt)
        ));
    }

    #[test]
    fn failed_private_zone_write_requires_reopening_the_journal() {
        let area = Area::new();
        let mut journal = PrivateDnsJournal::open(&area.0, None).unwrap();
        let original = BTreeSet::from(["old.test".to_owned()]);
        journal.store_zones(1000, &original).unwrap();
        std::os::unix::fs::symlink(FILE, area.0.join(PENDING)).unwrap();
        assert!(matches!(
            journal.store_zones(1000, &BTreeSet::from(["new.test".to_owned()])),
            Err(JournalError::UnsafePath)
        ));
        assert!(matches!(
            journal.saved_zones(1000),
            Err(JournalError::UncertainWrite)
        ));
        drop(journal);
        let journal = PrivateDnsJournal::open(&area.0, None).unwrap();
        assert_eq!(journal.saved_zones(1000).unwrap(), original);
    }
}
