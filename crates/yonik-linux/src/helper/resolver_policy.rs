//! Закрытый resolver-policy seam. Запись — конфигурация, а не authority.
//! Внешний producer обязан закрепить root-reviewed unit bytes/allowlist,
//! authenticated system manager unique owner и текущий InvocationID, удержать
//! cgroup2/netns и проверить exclusive custody (без delegation, activation,
//! foreign FD passing). Ни worker unit, ни child ACK этот контракт не реализуют.
//! Production transport скомпилирован; approved installation allowlist пуст.
#![allow(dead_code, reason = "Reviewed resolver installation ещё не утверждена")]

use super::{Error, Result};
use serde::Deserialize;
use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

const MAX_RECORD: usize = 4096;

#[derive(Clone, Debug, Deserialize)]
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
    pub(super) fn bytes() -> Vec<u8> {
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

/// Production transport не экспортирует constructor для произвольной policy.
/// Единственная точка выбора — reviewed installation descriptor ниже.
pub(super) mod production {
    use super::super::CaptureCredits;
    use super::*;
    use crate::helper::memory::ByteBudget;
    use rustix::fs::{Mode, OFlags, open, openat};
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Instant,
    };

    const DIR: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK);
    const LEAF: OFlags = OFlags::RDONLY
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK);
    const MAX_DEPTH: usize = 12;
    /// Эти bytes проходят review вместе с resolver executable/custody contract.
    /// no-passing/exclusive — вывод review точного unit/code, не входные bool.
    struct Reviewed {
        policy_directory: &'static str,
        policy_bytes: &'static [u8],
        unit_path: &'static str,
        unit_bytes: &'static [u8],
        exec_path: &'static str,
        exec_args: &'static [&'static str],
        environment: &'static [&'static str],
        cgroup_path: &'static str,
        netns_path: &'static str,
        uid: u32,
        epoch: u64,
        system_view: bool,
    }
    const APPROVED: Option<&Reviewed> = None;

    struct Walk {
        directories: Vec<File>,
        names: Vec<String>,
        identities: Vec<Identity>,
    }
    impl Walk {
        fn open(path: &str) -> Result<Self> {
            let components = components(path)?;
            let root = File::from(open("/", DIR, Mode::empty()).map_err(|_| Error::Untrusted)?);
            let mut result = Self {
                identities: vec![identity(&root, true)?],
                directories: vec![root],
                names: Vec::new(),
            };
            for name in components {
                let file = File::from(
                    openat(result.last(), name, DIR, Mode::empty())
                        .map_err(|_| Error::Untrusted)?,
                );
                result.identities.push(identity(&file, true)?);
                result.directories.push(file);
                result.names.push(name.to_owned());
            }
            result.revalidate()?;
            Ok(result)
        }
        fn last(&self) -> &File {
            &self.directories[self.directories.len() - 1]
        }
        fn revalidate(&self) -> Result<()> {
            let root = File::from(open("/", DIR, Mode::empty()).map_err(|_| Error::Untrusted)?);
            same(&self.identities[0], &identity(&root, true)?)?;
            for (i, file) in self.directories.iter().enumerate() {
                same(&self.identities[i], &identity(file, true)?)?;
                if i > 0 {
                    let live = File::from(
                        openat(
                            &self.directories[i - 1],
                            self.names[i - 1].as_str(),
                            DIR,
                            Mode::empty(),
                        )
                        .map_err(|_| Error::Stale)?,
                    );
                    same(&self.identities[i], &identity(&live, true)?)?;
                }
            }
            Ok(())
        }
    }
    fn components(path: &str) -> Result<Vec<&str>> {
        if !path.starts_with('/') || path.len() > 512 {
            return Err(Error::Untrusted);
        }
        if path == "/" {
            return Ok(Vec::new());
        }
        let c: Vec<_> = path[1..].split('/').collect();
        if c.len() > MAX_DEPTH
            || c.iter().any(|s| {
                s.is_empty()
                    || matches!(*s, "." | "..")
                    || s.len() > 128
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            })
        {
            return Err(Error::Untrusted);
        }
        Ok(c)
    }
    fn same(a: &Identity, b: &Identity) -> Result<()> {
        if a == b { Ok(()) } else { Err(Error::Stale) }
    }
    struct ExactFile {
        walk: Walk,
        file: File,
        original: Identity,
        name: String,
    }
    impl ExactFile {
        fn open(path: &str, expected: &[u8]) -> Result<Self> {
            components(path)?;
            let (parent, name) = path.rsplit_once('/').ok_or(Error::Untrusted)?;
            let walk = Walk::open(if parent.is_empty() { "/" } else { parent })?;
            let file = File::from(
                openat(walk.last(), name, LEAF, Mode::empty()).map_err(|_| Error::Untrusted)?,
            );
            let original = identity(&file, false)?;
            let mut bytes = Vec::new();
            (&file)
                .take(MAX_RECORD as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Error::Untrusted)?;
            if bytes != expected {
                return Err(Error::Untrusted);
            }
            let result = Self {
                walk,
                file,
                original,
                name: name.to_owned(),
            };
            result.revalidate()?;
            Ok(result)
        }
        fn revalidate(&self) -> Result<()> {
            self.walk.revalidate()?;
            same(&self.original, &identity(&self.file, false)?)?;
            let live = File::from(
                openat(self.walk.last(), self.name.as_str(), LEAF, Mode::empty())
                    .map_err(|_| Error::Stale)?,
            );
            same(&self.original, &identity(&live, false)?)
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Service {
        owner: String,
        invocation: [u8; 16],
        uid: u32,
        cgroup: String,
    }
    type ExecCommand = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
    type ExecCommands = Vec<ExecCommand>;
    fn checked_exec(exec: &[ExecCommand], reviewed: &Reviewed) -> Result<()> {
        if exec.len() != 1
            || exec[0].0 != reviewed.exec_path
            || exec[0].1 != reviewed.exec_args
            || exec[0].2
        {
            Err(Error::Untrusted)
        } else {
            Ok(())
        }
    }
    /// Один sequential actor: никаких retry, фоновых refresh или caller facts.
    trait Manager {
        async fn sample(&mut self, reviewed: &Reviewed, record: &Record) -> Result<Service>;
    }
    /// Ограничение срабатывает ДО zbus bytes.resize(total_len). Обычный
    /// ReadHalf zbus допускает 128MiB и ancillary FDs, что не покрывает credit.
    const MAX_FRAME: usize = 8192;
    #[derive(Debug, Default)]
    struct FrameFence {
        header: [u8; 16],
        header_used: usize,
        remaining: usize,
        binary: bool,
        auth_line: usize,
        auth_total: usize,
    }
    impl FrameFence {
        fn capacity(&self) -> usize {
            if self.remaining > 0 {
                self.remaining
            } else if self.header_used > 0 {
                16 - self.header_used
            } else {
                1
            }
        }
        fn accept(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            use std::io::{Error, ErrorKind};
            let invalid =
                || Error::new(ErrorKind::InvalidData, "Неполный или oversized D-Bus frame");
            if bytes.is_empty() || bytes.len() > self.capacity() {
                return Err(invalid());
            }
            if self.remaining > 0 {
                self.remaining -= bytes.len();
                return Ok(());
            }
            if self.header_used == 0 {
                if matches!(bytes[0], b'l' | b'B') && self.auth_line == 0 {
                    self.binary = true;
                } else {
                    self.auth_line += 1;
                    self.auth_total += 1;
                    if self.binary
                        || !bytes[0].is_ascii()
                        || self.auth_line > 512
                        || self.auth_total > 4096
                    {
                        return Err(invalid());
                    }
                    if bytes[0] == b'\n' {
                        self.auth_line = 0;
                    }
                    return Ok(());
                }
            }
            let end = self.header_used + bytes.len();
            self.header[self.header_used..end].copy_from_slice(bytes);
            self.header_used = end;
            if end == 16 {
                self.remaining = frame_length(&self.header).ok_or_else(invalid)? - 16;
                self.header_used = 0;
            }
            Ok(())
        }
    }
    fn frame_length(h: &[u8; 16]) -> Option<usize> {
        let number = |bytes: [u8; 4]| match h[0] {
            b'l' => Some(u32::from_le_bytes(bytes) as usize),
            b'B' => Some(u32::from_be_bytes(bytes) as usize),
            _ => None,
        };
        if h[3] != 1 || !(1..=4).contains(&h[1]) {
            return None;
        }
        let body = number(h[4..8].try_into().ok()?)?;
        let fields = number(h[12..16].try_into().ok()?)?;
        let header = 16usize.checked_add(fields)?;
        let total = header
            .checked_add((8 - header % 8) % 8)?
            .checked_add(body)?;
        (total <= MAX_FRAME).then_some(total)
    }
    #[derive(Debug)]
    struct BoundedRead {
        io: tokio::net::unix::OwnedReadHalf,
        fence: FrameFence,
    }
    #[derive(Debug)]
    struct BoundedWrite(tokio::net::unix::OwnedWriteHalf);
    fn bounded_socket(
        stream: tokio::net::UnixStream,
    ) -> std::io::Result<zbus::connection::socket::BoxedSplit> {
        // В zbus 4.4 Split fields закрыты, constructor отсутствует. Создаём
        // штатный Split и заменяем обе половины до старта executor. Временный
        // dup того же соединения покрыт FD credit; второго connect здесь нет.
        let original = stream.into_std()?;
        let duplicate = tokio::net::UnixStream::from_std(original.try_clone()?)?;
        let mut split: zbus::connection::socket::BoxedSplit =
            tokio::net::UnixStream::from_std(original)?.into();
        let (read, write) = duplicate.into_split();
        *split.read_mut() = Box::new(BoundedRead {
            io: read,
            fence: FrameFence::default(),
        });
        *split.write_mut() = Box::new(BoundedWrite(write));
        Ok(split)
    }
    #[zbus::export::async_trait::async_trait]
    impl zbus::connection::socket::ReadHalf for BoundedRead {
        async fn recvmsg(
            &mut self,
            buf: &mut [u8],
        ) -> std::io::Result<(usize, Vec<std::os::fd::OwnedFd>)> {
            use tokio::io::AsyncReadExt;
            let limit = buf.len().min(self.fence.capacity());
            let n = self.io.read(&mut buf[..limit]).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            self.fence.accept(&buf[..n])?;
            // read(2) не устанавливает SCM_RIGHTS descriptors; transport не
            // предлагает UNIX_FD negotiation и не использует recvmsg adapter.
            Ok((n, Vec::new()))
        }
    }
    #[zbus::export::async_trait::async_trait]
    impl zbus::connection::socket::WriteHalf for BoundedWrite {
        async fn sendmsg(
            &mut self,
            buffer: &[u8],
            fds: &[std::os::fd::BorrowedFd<'_>],
        ) -> std::io::Result<usize> {
            use tokio::io::AsyncWriteExt;
            if !fds.is_empty() {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            self.0.write(buffer).await
        }
        async fn close(&mut self) -> std::io::Result<()> {
            use tokio::io::AsyncWriteExt;
            self.0.shutdown().await
        }
    }
    struct SystemBus {
        connection: zbus::Connection,
        owner: String,
        ancestry: Walk,
        socket: File,
        socket_id: (u64, u64),
    }
    impl SystemBus {
        async fn connect() -> Result<Self> {
            let ancestry = Walk::open("/run/dbus")?;
            let socket = Self::socket_at(&ancestry)?;
            let m = socket.metadata().map_err(|_| Error::Untrusted)?;
            let socket_id = (m.dev(), m.ino());
            let socket_io = tokio::net::UnixStream::connect("/run/dbus/system_bus_socket")
                .await
                .map_err(|_| Error::Untrusted)?;
            if socket_io.peer_cred().map_err(|_| Error::Untrusted)?.uid() != 0 {
                return Err(Error::Untrusted);
            }
            let connection = zbus::connection::Builder::socket(
                bounded_socket(socket_io).map_err(|_| Error::Untrusted)?,
            )
            .auth_mechanism(zbus::AuthMechanism::External)
            .max_queued(1)
            .build()
            .await
            .map_err(|_| Error::Untrusted)?;
            let proxy = zbus::fdo::DBusProxy::new(&connection)
                .await
                .map_err(|_| Error::Untrusted)?;
            let owner = proxy
                .get_name_owner(
                    zbus::names::BusName::try_from("org.freedesktop.systemd1")
                        .map_err(|_| Error::Untrusted)?,
                )
                .await
                .map_err(|_| Error::Untrusted)?
                .to_string();
            let result = Self {
                connection,
                owner,
                ancestry,
                socket,
                socket_id,
            };
            result.fence().await?;
            Ok(result)
        }
        fn socket_at(ancestry: &Walk) -> Result<File> {
            let file = File::from(
                openat(
                    ancestry.last(),
                    "system_bus_socket",
                    OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| Error::Untrusted)?,
            );
            let m = file.metadata().map_err(|_| Error::Untrusted)?;
            if m.uid() != 0 || m.mode() & 0o170000 != 0o140000 || m.nlink() != 1 {
                return Err(Error::Untrusted);
            }
            Ok(file)
        }
        async fn fence(&self) -> Result<()> {
            self.ancestry.revalidate()?;
            for f in [&self.socket, &Self::socket_at(&self.ancestry)?] {
                let m = f.metadata().map_err(|_| Error::Untrusted)?;
                if (m.dev(), m.ino()) != self.socket_id {
                    return Err(Error::Stale);
                }
            }
            let proxy = zbus::fdo::DBusProxy::new(&self.connection)
                .await
                .map_err(|_| Error::Untrusted)?;
            let owner = proxy
                .get_name_owner(
                    zbus::names::BusName::try_from("org.freedesktop.systemd1")
                        .map_err(|_| Error::Untrusted)?,
                )
                .await
                .map_err(|_| Error::Untrusted)?;
            let unique = zbus::names::BusName::try_from(self.owner.as_str())
                .map_err(|_| Error::Untrusted)?;
            if owner.as_str() != self.owner
                || proxy
                    .get_connection_unix_user(unique.clone())
                    .await
                    .map_err(|_| Error::Untrusted)?
                    != 0
                || proxy
                    .get_connection_unix_process_id(unique)
                    .await
                    .map_err(|_| Error::Untrusted)?
                    != 1
            {
                return Err(Error::Untrusted);
            }
            Ok(())
        }
        async fn property<T>(&self, path: &str, interface: &str, name: &str) -> Result<T>
        where
            T: TryFrom<zbus::zvariant::OwnedValue>,
        {
            let p = zbus::Proxy::new(
                &self.connection,
                self.owner.as_str(),
                path,
                "org.freedesktop.DBus.Properties",
            )
            .await
            .map_err(|_| Error::Untrusted)?;
            let reply = p
                .call_method("Get", &(interface, name))
                .await
                .map_err(|_| Error::Incomplete)?;
            if reply.body().len() > MAX_RECORD {
                return Err(Error::Incomplete);
            }
            let v: zbus::zvariant::OwnedValue =
                reply.body().deserialize().map_err(|_| Error::Incomplete)?;
            T::try_from(v).map_err(|_| Error::Incomplete)
        }
    }
    impl Manager for SystemBus {
        async fn sample(&mut self, reviewed: &Reviewed, record: &Record) -> Result<Service> {
            self.fence().await?;
            let manager = zbus::Proxy::new(
                &self.connection,
                self.owner.as_str(),
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
            )
            .await
            .map_err(|_| Error::Untrusted)?;
            let reply = manager
                .call_method("GetUnit", &(record.unit.as_str(),))
                .await
                .map_err(|_| Error::Incomplete)?;
            if reply.body().len() > MAX_RECORD {
                return Err(Error::Incomplete);
            }
            let path: zbus::zvariant::OwnedObjectPath =
                reply.body().deserialize().map_err(|_| Error::Incomplete)?;
            let u = "org.freedesktop.systemd1.Unit";
            let s = "org.freedesktop.systemd1.Service";
            let invocation: Vec<u8> = self.property(&path, u, "InvocationID").await?;
            let cgroup: String = self.property(&path, s, "ControlGroup").await?;
            let user: String = self.property(&path, s, "User").await?;
            let exec: ExecCommands = self.property(&path, s, "ExecStart").await?;
            checked_exec(&exec, reviewed)?;
            for name in [
                "ExecStartPre",
                "ExecStartPost",
                "ExecStop",
                "ExecStopPost",
                "ExecCondition",
            ] {
                if !self
                    .property::<ExecCommands>(&path, s, name)
                    .await?
                    .is_empty()
                {
                    return Err(Error::Untrusted);
                }
            }
            if self
                .property::<Vec<String>>(&path, s, "Environment")
                .await?
                != reviewed.environment
                || !self
                    .property::<Vec<(String, bool)>>(&path, s, "EnvironmentFiles")
                    .await?
                    .is_empty()
                || !self
                    .property::<Vec<String>>(&path, s, "PassEnvironment")
                    .await?
                    .is_empty()
            {
                return Err(Error::Untrusted);
            }
            let expected_cgroup = reviewed
                .cgroup_path
                .strip_prefix("/sys/fs/cgroup")
                .ok_or(Error::Untrusted)?;
            if self.property::<String>(&path, u, "Id").await? != record.unit
                || self.property::<String>(&path, u, "LoadState").await? != "loaded"
                || self.property::<String>(&path, u, "ActiveState").await? != "active"
                || self.property::<String>(&path, u, "FragmentPath").await? != reviewed.unit_path
                || !self
                    .property::<Vec<String>>(&path, u, "DropInPaths")
                    .await?
                    .is_empty()
                || self.property::<bool>(&path, u, "Transient").await?
                || self.property::<bool>(&path, u, "NeedDaemonReload").await?
                || !self
                    .property::<Vec<String>>(&path, u, "TriggeredBy")
                    .await?
                    .is_empty()
                || !self
                    .property::<Vec<String>>(&path, u, "JoinsNamespaceOf")
                    .await?
                    .is_empty()
                || self.property::<bool>(&path, s, "Delegate").await?
                || self.property::<bool>(&path, s, "DynamicUser").await?
                || self.property::<bool>(&path, s, "PrivateNetwork").await?
                || !self
                    .property::<String>(&path, s, "NetworkNamespacePath")
                    .await?
                    .is_empty()
                || !self
                    .property::<String>(&path, s, "RootDirectory")
                    .await?
                    .is_empty()
                || !self
                    .property::<String>(&path, s, "RootImage")
                    .await?
                    .is_empty()
                || !self
                    .property::<Vec<String>>(&path, s, "Sockets")
                    .await?
                    .is_empty()
                || self
                    .property::<u32>(&path, s, "FileDescriptorStoreMax")
                    .await?
                    != 0
                || self
                    .property::<u32>(&path, s, "NFileDescriptorStore")
                    .await?
                    != 0
                || !self.property::<bool>(&path, s, "NoNewPrivileges").await?
                || self
                    .property::<u64>(&path, s, "CapabilityBoundingSet")
                    .await?
                    != 0
                || self
                    .property::<u64>(&path, s, "AmbientCapabilities")
                    .await?
                    != 0
                || self.property::<u64>(&path, s, "RestrictNamespaces").await? != 0
                || self.property::<String>(&path, s, "StandardInput").await? != "null"
                || self.property::<String>(&path, s, "StandardOutput").await? != "null"
                || self.property::<String>(&path, s, "StandardError").await? != "null"
                || cgroup != expected_cgroup
                || user != reviewed.uid.to_string()
            {
                return Err(Error::Untrusted);
            }
            // Invocation повторно читается после property census: restart внутри
            // одного sample нельзя скрыть неизменным unique owner manager.
            if self.property::<Vec<u8>>(&path, u, "InvocationID").await? != invocation {
                return Err(Error::Stale);
            }
            self.fence().await?;
            Ok(Service {
                owner: self.owner.clone(),
                invocation: invocation.try_into().map_err(|_| Error::Incomplete)?,
                uid: reviewed.uid,
                cgroup,
            })
        }
    }
    /// Все ссылки удерживаются до уничтожения producer даже при sticky error.
    pub(in super::super) struct Producer {
        approved: &'static Reviewed,
        ancestry: Walk,
        policy: RetainedRecord,
        unit: ExactFile,
        cgroup: Walk,
        namespace: ExactNamespace,
        bus: SystemBus,
        baseline: Option<Service>,
        credit: CaptureCredits,
        deadline: Instant,
        poisoned: bool,
    }
    struct ExactNamespace {
        walk: Walk,
        file: File,
        id: (u64, u64),
        name: String,
    }
    impl ExactNamespace {
        fn open(path: &str) -> Result<Self> {
            components(path)?;
            let (parent, name) = path.rsplit_once('/').ok_or(Error::Untrusted)?;
            let walk = Walk::open(parent)?;
            let file = File::from(
                openat(walk.last(), name, LEAF, Mode::empty()).map_err(|_| Error::Untrusted)?,
            );
            let m = file.metadata().map_err(|_| Error::Untrusted)?;
            let result = Self {
                walk,
                file,
                id: (m.dev(), m.ino()),
                name: name.into(),
            };
            result.revalidate()?;
            Ok(result)
        }
        fn revalidate(&self) -> Result<()> {
            self.walk.revalidate()?;
            let live = File::from(
                openat(self.walk.last(), self.name.as_str(), LEAF, Mode::empty())
                    .map_err(|_| Error::Untrusted)?,
            );
            for file in [&self.file, &live] {
                if yonik_nsfs::namespace_type(file).map_err(|_| Error::Untrusted)?
                    != yonik_nsfs::NamespaceType::Net
                {
                    return Err(Error::Untrusted);
                }
                let m = file.metadata().map_err(|_| Error::Untrusted)?;
                if (m.dev(), m.ino()) != self.id || m.uid() != 0 {
                    return Err(Error::Stale);
                }
            }
            Ok(())
        }
    }
    async fn bounded<T>(
        deadline: Instant,
        cancel: &AtomicBool,
        future: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(Error::Stale);
        }
        tokio::select! { biased;
            _=async {loop {if cancel.load(Ordering::Acquire) {break;} tokio::time::sleep(std::time::Duration::from_millis(1)).await;}}=>Err(Error::Stale),
            result=tokio::time::timeout_at(deadline.into(),future)=>result.map_err(|_|Error::Stale)?,
        }
    }
    impl Producer {
        pub(in super::super) async fn open(
            fds: &ByteBudget,
            pending: &ByteBudget,
            bytes: &ByteBudget,
            deadline: Instant,
            cancel: &AtomicBool,
        ) -> Result<Self> {
            // 4 bounded walks, fresh path checks + D-Bus/diag/retained namespace.
            // Никаких opening effects до debit существующих invocation ledgers.
            let credit = CaptureCredits::reserve_policy_shared(fds, pending, bytes)?;
            let approved = APPROVED.ok_or(Error::PolicyUnavailable)?;
            bounded(deadline, cancel, async {
                let ancestry = Walk::open(approved.policy_directory)?;
                let policy = RetainedRecord::open(
                    ancestry.last().try_clone().map_err(|_| Error::Untrusted)?,
                )?;
                // Exact bytes сверяются отдельным descriptor, а не hash входной записи.
                let exact = ExactFile::open(
                    &format!("{}/resolver-policy-v1.json", approved.policy_directory),
                    approved.policy_bytes,
                )?;
                same(&policy.original, &exact.original)?;
                let unit = ExactFile::open(approved.unit_path, approved.unit_bytes)?;
                if approved.epoch == 0
                    || policy.record.system_view != approved.system_view
                    || matches!(approved.uid, 0 | u32::MAX)
                {
                    return Err(Error::Untrusted);
                }
                let cgroup = Walk::open(approved.cgroup_path)?;
                let namespace = ExactNamespace::open(approved.netns_path)?;
                let bus = SystemBus::connect().await?;
                let result = Self {
                    approved,
                    ancestry,
                    policy,
                    unit,
                    cgroup,
                    namespace,
                    bus,
                    baseline: None,
                    credit,
                    deadline,
                    poisoned: false,
                };
                result.revalidate_files()?;
                Ok(result)
            })
            .await
        }
        fn revalidate_files(&self) -> Result<()> {
            self.ancestry.revalidate()?;
            self.policy.revalidate()?;
            self.unit.revalidate()?;
            self.cgroup.revalidate()?;
            self.namespace.revalidate()?;
            if usize::BITS != 64
                || rustix::fs::fstatfs(self.cgroup.last())
                    .map_err(|_| Error::Untrusted)?
                    .f_type as u64
                    != 0x63677270
            {
                return Err(Error::Untrusted);
            }
            Ok(())
        }
        pub(in super::super) async fn verified(
            &mut self,
            cancel: &AtomicBool,
        ) -> Result<VerifiedPolicy> {
            if self.poisoned {
                return Err(Error::Stale);
            }
            let result = bounded(self.deadline, cancel, async {
                self.revalidate_files()?;
                let first = manager_round(
                    &mut self.bus,
                    self.approved,
                    &self.policy.record,
                    self.baseline.as_ref(),
                )
                .await?;
                self.revalidate_files()?;
                self.baseline = Some(first);
                let record = self.policy.record.clone();
                verify(self, &record)
            })
            .await;
            if result.is_err() {
                self.poisoned = true;
            }
            result
        }
        pub(in super::super) fn files(&self) -> (&File, &File, &CaptureCredits) {
            (&self.namespace.file, self.cgroup.last(), &self.credit)
        }
    }
    async fn manager_round(
        manager: &mut impl Manager,
        reviewed: &Reviewed,
        record: &Record,
        baseline: Option<&Service>,
    ) -> Result<Service> {
        let first = manager.sample(reviewed, record).await?;
        let second = manager.sample(reviewed, record).await?;
        stable_service(baseline, &first, &second)?;
        Ok(first)
    }
    fn stable_service(baseline: Option<&Service>, first: &Service, second: &Service) -> Result<()> {
        if first != second || baseline.is_some_and(|b| b != first) || first.invocation == [0; 16] {
            Err(Error::Stale)
        } else {
            Ok(())
        }
    }
    impl FactsSource for Producer {
        fn revalidate(&mut self) -> Result<()> {
            if self.poisoned || Instant::now() >= self.deadline {
                return Err(Error::Stale);
            }
            self.revalidate_files()
        }
        fn current(&mut self) -> Result<Facts> {
            self.revalidate()?;
            let service = self.baseline.as_ref().ok_or(Error::Incomplete)?;
            let group = self
                .cgroup
                .last()
                .metadata()
                .map_err(|_| Error::Untrusted)?;
            Ok(Facts {
                manager: service.owner.clone(),
                invocation: service.invocation,
                contract: self.policy.record.contract,
                uid: service.uid,
                cgroup: (group.dev(), group.ino()),
                namespace: self.namespace.id,
                epoch: self.approved.epoch,
                system_view: self.approved.system_view,
                authenticated: true,
                reviewed: true,
                // Ограничения происходят из exact approved policy/unit pair.
                // D-Bus bool сам по себе не доказывает запрет foreign FD passing.
                exclusive: self.policy.record.exclusive_cgroup,
                nondelegated: self.policy.record.no_delegation,
                no_passing: self.policy.record.no_foreign_socket_passing,
                no_activation: self.policy.record.no_socket_activation,
                retained_cgroup2: true,
                retained_netns: true,
                unit: self.policy.record.unit.clone(),
            })
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn resolver_policy_fake_bus_frame_preallocation_fence() {
            for endian in [b'l', b'B'] {
                let mut h = [0u8; 16];
                h[0] = endian;
                h[1] = 2;
                h[3] = 1;
                let encode = |n: u32| {
                    if endian == b'l' {
                        n.to_le_bytes()
                    } else {
                        n.to_be_bytes()
                    }
                };
                h[4..8].copy_from_slice(&encode(32));
                h[12..16].copy_from_slice(&encode(17));
                assert_eq!(frame_length(&h), Some(72));
                let mut fence = FrameFence::default();
                for byte in b"OK abc\r\n" {
                    fence.accept(&[*byte]).unwrap();
                }
                fence.accept(&h[..1]).unwrap();
                fence.accept(&h[1..]).unwrap();
                assert_eq!(fence.capacity(), 56);
                fence.accept(&[0; 56]).unwrap();
                assert_eq!(fence.capacity(), 1);
                h[4..8].copy_from_slice(&encode(u32::MAX));
                assert_eq!(frame_length(&h), None);
                let mut fence = FrameFence::default();
                fence.accept(&h[..1]).unwrap();
                assert!(fence.accept(&h[1..]).is_err());
            }
            let mut fence = FrameFence::default();
            for _ in 0..512 {
                fence.accept(b"x").unwrap();
            }
            assert!(fence.accept(b"x").is_err());
        }
        struct FakeBus {
            samples: std::collections::VecDeque<Result<Service>>,
        }
        impl Manager for FakeBus {
            async fn sample(&mut self, _: &Reviewed, _: &Record) -> Result<Service> {
                self.samples.pop_front().ok_or(Error::Incomplete)?
            }
        }
        #[tokio::test]
        async fn resolver_policy_fake_bus_round_partial_and_credit_failure() {
            let reviewed = Reviewed {
                policy_directory: "/unused",
                policy_bytes: b"",
                unit_path: "/unused/service",
                unit_bytes: b"",
                exec_path: "/unused/executable",
                exec_args: &["/unused/executable"],
                environment: &[],
                cgroup_path: "/unused/cgroup",
                netns_path: "/unused/netns",
                uid: 991,
                epoch: 1,
                system_view: false,
            };
            let command = (
                reviewed.exec_path.to_owned(),
                vec![reviewed.exec_path.to_owned()],
                false,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            );
            assert!(checked_exec(&[command.clone()], &reviewed).is_ok());
            assert!(checked_exec(&[], &reviewed).is_err());
            for change in 0..3 {
                let mut cmd = command.clone();
                match change {
                    0 => cmd.0.push('x'),
                    1 => cmd.1.push("unreviewed".into()),
                    _ => cmd.2 = true,
                };
                assert!(checked_exec(&[cmd], &reviewed).is_err());
            }
            let record = Record::parse(&super::super::tests::bytes()).unwrap();
            let first = Service {
                owner: ":1.4".into(),
                invocation: [1; 16],
                uid: 991,
                cgroup: "/resolver".into(),
            };
            let mut changed = first.clone();
            changed.owner = ":1.5".into();
            for second in [Ok(first.clone()), Ok(changed), Err(Error::Incomplete)] {
                let success = second.as_ref().is_ok_and(|s| s == &first);
                let mut bus = FakeBus {
                    samples: [Ok(first.clone()), second].into(),
                };
                assert_eq!(
                    manager_round(&mut bus, &reviewed, &record, None)
                        .await
                        .is_ok(),
                    success
                );
                assert!(bus.samples.is_empty());
            }
            for limits in [
                (127, 1, 65536),
                (128, 0, 65536),
                (128, 1, 65535),
                (128, 1, 65536),
            ] {
                let (fds, pending, bytes) = (
                    ByteBudget::new(limits.0),
                    ByteBudget::new(limits.1),
                    ByteBudget::new(limits.2),
                );
                let result = Producer::open(
                    &fds,
                    &pending,
                    &bytes,
                    Instant::now() + std::time::Duration::from_millis(20),
                    &AtomicBool::new(false),
                )
                .await;
                assert!(matches!(
                    result,
                    Err(Error::Budget) | Err(Error::PolicyUnavailable)
                ));
                assert_eq!((fds.used(), pending.used(), bytes.used()), (0, 0, 0));
            }
            assert_eq!(
                bounded(
                    Instant::now() + std::time::Duration::from_millis(20),
                    &AtomicBool::new(true),
                    async { Ok(()) }
                )
                .await,
                Err(Error::Stale)
            );
        }
        #[test]
        fn resolver_policy_fake_fd_ancestry_and_bounded_paths() {
            for p in ["relative", "/a/../b", "/a//b", "/a/", "/a/./b"] {
                assert!(components(p).is_err());
            }
            assert!(components("/usr/lib/resolver").is_ok());
            let id = Identity {
                dev: 1,
                ino: 2,
                size: 0,
                mtime: (1, 0),
                ctime: (1, 0),
            };
            assert!(same(&id, &id).is_ok());
            let mut changed = id.clone();
            changed.ino += 1;
            assert_eq!(same(&id, &changed), Err(Error::Stale));
        }
        #[test]
        fn resolver_policy_fake_bus_owner_restart_invocation_and_partial() {
            let first = Service {
                owner: ":1.4".into(),
                invocation: [1; 16],
                uid: 991,
                cgroup: "/resolver".into(),
            };
            assert!(stable_service(None, &first, &first).is_ok());
            for change in 0..4 {
                let mut next = first.clone();
                match change {
                    0 => next.owner = ":1.5".into(),
                    1 => next.invocation[0] += 1,
                    2 => next.uid += 1,
                    _ => next.cgroup.push('x'),
                };
                assert_eq!(
                    stable_service(Some(&first), &next, &next),
                    Err(Error::Stale)
                );
                assert_eq!(stable_service(None, &first, &next), Err(Error::Stale));
            }
            let mut partial = first.clone();
            partial.invocation = [0; 16];
            assert!(stable_service(None, &partial, &partial).is_err());
        }
    }
}
