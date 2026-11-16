//! Закрытый resolver-policy seam. Запись — конфигурация, а не authority.
//! Внешний producer обязан закрепить root-reviewed unit bytes/allowlist,
//! authenticated system manager unique owner и текущий InvocationID, удержать
//! cgroup2/netns и проверить exclusive custody (без delegation, activation,
//! foreign FD passing). Ни worker unit, ни child ACK этот контракт не реализуют.
//! Поэтому production реализации FactsSource и установленного allowlist нет.
#![expect(
    dead_code,
    reason = "Resolver manager transport и reviewed install отсутствуют"
)]

use super::{Error, Result};
use serde::Deserialize;
use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

const MAX_RECORD: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    unit: String,
    contract: [u8; 32],
    system_view: bool,
    exclusive_cgroup: bool,
    no_delegation: bool,
    no_foreign_socket_passing: bool,
    no_socket_activation: bool,
}
impl Record {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RECORD {
            return Err(Error::Untrusted);
        }
        let r: Self = serde_json::from_slice(bytes).map_err(|_| Error::Untrusted)?;
        if r.version != 1
            || r.unit.len() > 128
            || !r.unit.ends_with(".service")
            || r.unit.len() <= 8
            || !r
                .unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || r.contract == [0; 32]
            || !r.exclusive_cgroup
            || !r.no_delegation
            || !r.no_foreign_socket_passing
            || !r.no_socket_activation
        {
            return Err(Error::Untrusted);
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
fn identity(file: &File, directory: bool) -> Result<Identity> {
    let m = file.metadata().map_err(|_| Error::Untrusted)?;
    protected_metadata(m.uid(), m.mode(), m.nlink(), m.len(), directory)?;
    Ok(Identity {
        dev: m.dev(),
        ino: m.ino(),
        size: m.len(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}
/// Чистая проверка stat facts; O_NOFOLLOW и retained identity проверяет reader.
fn protected_metadata(uid: u32, mode: u32, links: u64, size: u64, directory: bool) -> Result<()> {
    let kind = mode & 0o170000;
    if uid != 0
        || mode & 0o022 != 0
        || if directory {
            kind != 0o040000
        } else {
            kind != 0o100000 || links != 1 || size > MAX_RECORD as u64
        }
    {
        return Err(Error::Untrusted);
    }
    Ok(())
}
/// Каталог передаётся только из trusted root walk (каждый ancestor NOFOLLOW,
/// root ownership и запрет group/other write). Сам FD не доказывает ancestry.
struct RetainedRecord {
    directory: File,
    file: File,
    parent: Identity,
    original: Identity,
    record: Record,
}
impl RetainedRecord {
    fn open(directory: File) -> Result<Self> {
        let parent = identity(&directory, true)?;
        let file = Self::leaf(&directory)?;
        let original = identity(&file, false)?;
        let mut bytes = Vec::new();
        (&file)
            .take(MAX_RECORD as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Untrusted)?;
        let record = Record::parse(&bytes)?;
        let retained = Self {
            directory,
            file,
            parent,
            original,
            record,
        };
        retained.revalidate()?;
        Ok(retained)
    }
    fn leaf(directory: &File) -> Result<File> {
        use rustix::fs::{Mode, OFlags, openat};
        openat(
            directory,
            "resolver-policy-v1.json",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| Error::Untrusted)
    }
    fn revalidate(&self) -> Result<()> {
        if identity(&self.directory, true)? != self.parent
            || identity(&self.file, false)? != self.original
            || identity(&Self::leaf(&self.directory)?, false)? != self.original
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

/// Только внутренний транспорт может создавать эти факты. Не IPC DTO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Facts {
    pub(super) manager: String,
    pub(super) invocation: [u8; 16],
    pub(super) contract: [u8; 32],
    pub(super) uid: u32,
    pub(super) cgroup: (u64, u64),
    pub(super) namespace: (u64, u64),
    pub(super) epoch: u64,
    pub(super) system_view: bool,
    authenticated: bool,
    reviewed: bool,
    exclusive: bool,
    nondelegated: bool,
    no_passing: bool,
    no_activation: bool,
    retained_cgroup2: bool,
    retained_netns: bool,
    unit: String,
}
trait FactsSource {
    // В production этот source удерживает protected record + ancestor FDs,
    // manager owner, cgroup2/netns FDs и общий CaptureCredits до любых effects.
    fn revalidate(&mut self) -> Result<()>;
    fn current(&mut self) -> Result<Facts>;
}
pub(super) struct VerifiedPolicy(Facts);
impl VerifiedPolicy {
    pub(super) fn into_facts(self) -> Facts {
        self.0
    }
}
fn verify(source: &mut impl FactsSource, record: &Record) -> Result<VerifiedPolicy> {
    source.revalidate()?;
    let f = source.current()?;
    let owner = f.manager.strip_prefix(':').ok_or(Error::Untrusted)?;
    let mut components = owner.split('.');
    if ![components.next(), components.next()]
        .into_iter()
        .all(|s| s.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))
        || components.next().is_some()
        || !f.authenticated
        || !f.reviewed
        || !f.exclusive
        || !f.nondelegated
        || !f.no_passing
        || !f.no_activation
        || !f.retained_cgroup2
        || !f.retained_netns
        || f.unit != record.unit
        || f.contract != record.contract
        || f.system_view != record.system_view
        || f.invocation == [0; 16]
        || matches!(f.uid, 0 | u32::MAX)
        || f.cgroup.1 == 0
        || f.namespace.1 == 0
        || f.epoch == 0
    {
        return Err(Error::Untrusted);
    }
    source.revalidate()?;
    if source.current()? != f {
        return Err(Error::Stale);
    }
    Ok(VerifiedPolicy(f))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes() -> Vec<u8> {
        format!(r#"{{"version":1,"unit":"resolver.service","contract":{:?},"system_view":false,"exclusive_cgroup":true,"no_delegation":true,"no_foreign_socket_passing":true,"no_socket_activation":true}}"#, [7u8;32]).into_bytes()
    }
    fn facts() -> Facts {
        Facts {
            manager: ":1.4".into(),
            invocation: [1; 16],
            contract: [7; 32],
            uid: 991,
            cgroup: (3, 42),
            namespace: (4, 5),
            epoch: 7,
            system_view: false,
            authenticated: true,
            reviewed: true,
            exclusive: true,
            nondelegated: true,
            no_passing: true,
            no_activation: true,
            retained_cgroup2: true,
            retained_netns: true,
            unit: "resolver.service".into(),
        }
    }
    struct Fake {
        f: Facts,
        changed: bool,
        reads: usize,
        stale: bool,
    }
    impl FactsSource for Fake {
        fn revalidate(&mut self) -> Result<()> {
            if self.stale {
                Err(Error::Stale)
            } else {
                Ok(())
            }
        }
        fn current(&mut self) -> Result<Facts> {
            self.reads += 1;
            let mut f = self.f.clone();
            if self.changed && self.reads > 1 {
                f.invocation[0] += 1;
            }
            Ok(f)
        }
    }
    #[test]
    fn resolver_policy_fake_protected_metadata() {
        assert!(protected_metadata(0, 0o100644, 1, 4096, false).is_ok());
        assert!(protected_metadata(0, 0o040755, 2, 8192, true).is_ok());
        for (uid, mode, links, size) in [
            (991, 0o100644, 1, 12),
            (0, 0o100664, 1, 12),
            (0, 0o100646, 1, 12),
            (0, 0o100644, 2, 12),
            (0, 0o120777, 1, 12),
            (0, 0o010600, 1, 12),
            (0, 0o100644, 1, 4097),
        ] {
            assert!(protected_metadata(uid, mode, links, size, false).is_err());
        }
        assert!(protected_metadata(0, 0o040775, 2, 0, true).is_err());
        assert!(protected_metadata(0, 0o100644, 1, 0, true).is_err());
    }
    #[test]
    fn resolver_policy_bounded_strict_schema() {
        assert!(Record::parse(&bytes()).is_ok());
        for data in [
            vec![b' '; MAX_RECORD + 1],
            b"{}".to_vec(),
            bytes().into_iter().chain(b"x".iter().copied()).collect(),
        ] {
            assert!(Record::parse(&data).is_err());
        }
        let valid = String::from_utf8(bytes()).unwrap();
        for replacement in ["\"unknown\":1,\"version\":1", "\"version\":1,\"version\":1"] {
            assert!(Record::parse(valid.replace("\"version\":1", replacement).as_bytes()).is_err());
        }
        for field in [
            "exclusive_cgroup",
            "no_delegation",
            "no_foreign_socket_passing",
            "no_socket_activation",
        ] {
            assert!(
                Record::parse(
                    valid
                        .replace(&format!("\"{field}\":true"), &format!("\"{field}\":false"))
                        .as_bytes()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn resolver_policy_rejects_untrusted_and_changed_facts() {
        let r = Record::parse(&bytes()).unwrap();
        for change in 0..18 {
            let mut f = facts();
            match change {
                0 => f.authenticated = false,
                1 => f.reviewed = false,
                2 => f.exclusive = false,
                3 => f.nondelegated = false,
                4 => f.no_passing = false,
                5 => f.no_activation = false,
                6 => f.retained_cgroup2 = false,
                7 => f.retained_netns = false,
                8 => f.contract[0] += 1,
                9 => f.unit = "other.service".into(),
                10 => f.invocation = [0; 16],
                11 => f.manager = "resolver.service".into(),
                12 => f.uid = 0,
                13 => f.cgroup.1 = 0,
                14 => f.namespace.1 = 0,
                15 => f.epoch = 0,
                16 => f.system_view = true,
                _ => f.manager = ":1.".into(),
            }
            assert!(
                verify(
                    &mut Fake {
                        f,
                        changed: false,
                        reads: 0,
                        stale: false
                    },
                    &r
                )
                .is_err(),
                "change {change}"
            );
        }
        for (changed, stale) in [(true, false), (false, true)] {
            assert!(
                verify(
                    &mut Fake {
                        f: facts(),
                        changed,
                        reads: 0,
                        stale
                    },
                    &r
                )
                .is_err()
            );
        }
        let verified = verify(
            &mut Fake {
                f: facts(),
                changed: false,
                reads: 0,
                stale: false,
            },
            &r,
        )
        .unwrap();
        let _evidence = super::super::observation::UnitEvidence::from_policy(verified);
    }
}
