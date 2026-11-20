//! Защищённые DNS-зоны живут отдельно от ресурсов конкретной TUN-сессии.
use super::{Journal, JournalError, Ownership, storage};
use crate::resolver::resolve1::MAX_ENTRIES as MAX_ZONES;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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

impl Journal {
    fn read_private_dns_state(&self) -> Result<PrivateDnsState, JournalError> {
        self.check(self.ownership())?;
        let Some(bytes) = storage::read_bounded(&self.directory, FILE, MAX_BYTES)? else {
            return Ok(PrivateDnsState {
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

    pub(crate) fn saved_private_dns_zones(
        &self,
        uid: u32,
    ) -> Result<BTreeSet<String>, JournalError> {
        let state = self.read_private_dns_state()?;
        Ok(state
            .users
            .into_iter()
            .find(|entry| entry.uid == uid)
            .map(|entry| entry.zones.into_iter().collect())
            .unwrap_or_default())
    }

    pub(crate) fn store_private_dns_zones(
        &mut self,
        owner: Ownership,
        observed: &BTreeSet<String>,
    ) -> Result<(), JournalError> {
        self.check(owner)?;
        if observed.is_empty() {
            return Ok(());
        }
        if observed.len() > MAX_ZONES {
            return Err(JournalError::Limit);
        }
        if observed.iter().any(|zone| !valid_zone(zone)) {
            return Err(JournalError::Invalid);
        }
        let mut state = self.read_private_dns_state()?;
        let uid = owner.owner_uid();
        match state.users.binary_search_by_key(&uid, |entry| entry.uid) {
            Ok(index) => {
                let entry = &mut state.users[index];
                let existing: BTreeSet<_> = entry.zones.iter().cloned().collect();
                if observed.is_subset(&existing) {
                    return Ok(());
                }
                let merged: Vec<_> = existing.union(observed).cloned().collect();
                if merged.len() > MAX_ZONES {
                    return Err(JournalError::Limit);
                }
                entry.zones = merged;
            }
            Err(index) => {
                if state.users.len() == MAX_USERS {
                    return Err(JournalError::Limit);
                }
                state.users.insert(
                    index,
                    OwnerZones {
                        uid,
                        zones: observed.iter().cloned().collect(),
                    },
                );
            }
        }
        let bytes = serde_json::to_vec(&state).map_err(|_| JournalError::Invalid)?;
        if bytes.len() > MAX_BYTES {
            return Err(JournalError::Limit);
        }
        let result = storage::write_atomic(&self.directory, FILE, PENDING, &bytes);
        if result.is_err() {
            self.poisoned = true;
            self.reconciled.clear();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let first = Ownership::new(1000, 1, 1, 1, 1).unwrap();
        let second = Ownership::new(1001, 2, 1, 1, 1).unwrap();
        let original = BTreeSet::from(["corp.test".to_owned()]);
        let additional = BTreeSet::from(["xn--bro-hoa.test".to_owned()]);
        let mut journal = Journal::open(&area.0, first).unwrap();
        assert!(journal.saved_private_dns_zones(1000).unwrap().is_empty());
        journal.store_private_dns_zones(first, &original).unwrap();
        assert!(
            journal
                .store_private_dns_zones(second, &additional)
                .is_err()
        );
        journal.store_private_dns_zones(first, &additional).unwrap();
        journal.reassign_empty_owner(second).unwrap();
        journal
            .store_private_dns_zones(second, &additional)
            .unwrap();
        drop(journal);

        let journal = Journal::open_existing(&area.0).unwrap().unwrap();
        assert_eq!(
            journal.saved_private_dns_zones(1000).unwrap(),
            &original | &additional
        );
        assert_eq!(journal.saved_private_dns_zones(1001).unwrap(), additional);
        assert!(journal.saved_private_dns_zones(1002).unwrap().is_empty());
    }

    #[test]
    fn private_zone_store_rejects_corrupt_state_and_overflow() {
        let area = Area::new();
        let owner = Ownership::new(1000, 1, 1, 1, 1).unwrap();
        let mut journal = Journal::open(&area.0, owner).unwrap();
        let maximum = (0..MAX_ZONES)
            .map(|index| format!("host{index}.test"))
            .collect();
        journal.store_private_dns_zones(owner, &maximum).unwrap();
        assert!(matches!(
            journal.store_private_dns_zones(owner, &BTreeSet::from(["other.test".to_owned()])),
            Err(JournalError::Limit)
        ));
        assert_eq!(journal.saved_private_dns_zones(1000).unwrap(), maximum);

        fs::write(
            area.0.join(FILE),
            br#"{"version":1,"users":[{"uid":1000,"zones":["."]}]}"#,
        )
        .unwrap();
        assert!(matches!(
            journal.saved_private_dns_zones(1000),
            Err(JournalError::Corrupt)
        ));
        assert!(matches!(
            journal.store_private_dns_zones(owner, &maximum),
            Err(JournalError::Corrupt)
        ));
    }

    #[test]
    fn failed_private_zone_write_requires_reopening_the_journal() {
        let area = Area::new();
        let owner = Ownership::new(1000, 1, 1, 1, 1).unwrap();
        let mut journal = Journal::open(&area.0, owner).unwrap();
        let original = BTreeSet::from(["old.test".to_owned()]);
        journal.store_private_dns_zones(owner, &original).unwrap();
        std::os::unix::fs::symlink(FILE, area.0.join(PENDING)).unwrap();
        assert!(matches!(
            journal.store_private_dns_zones(owner, &BTreeSet::from(["new.test".to_owned()])),
            Err(JournalError::UnsafePath)
        ));
        assert!(matches!(
            journal.saved_private_dns_zones(1000),
            Err(JournalError::UncertainWrite)
        ));
        drop(journal);
        let journal = Journal::open_existing(&area.0).unwrap().unwrap();
        assert_eq!(journal.saved_private_dns_zones(1000).unwrap(), original);
    }
}
