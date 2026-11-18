//! Наблюдение раскладки resolv.conf и read-only API systemd-resolved.
//! Для снимка и подписки нужен Tokio runtime с включёнными I/O и time.
//! Снимок описывает daemon; наблюдения и peer credentials не дают права Apply.

mod config;
pub mod fake_service;
pub mod forward;
mod plain;
pub(crate) mod plain_relay;
pub(crate) mod resolve1;
mod socket;
mod wire;

#[cfg(test)]
mod host_layout_tests {
    use super::{ResolvConfLayout, inspect_resolv_conf, known_resolv_conf_target};
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, symlink},
        path::Path,
    };

    #[test]
    fn классифицирует_только_точные_системные_пути() {
        for (path, expected) in [
            (
                "/run/systemd/resolve/stub-resolv.conf",
                ResolvConfLayout::ResolvedStub,
            ),
            (
                "/run/systemd/resolve/resolv.conf",
                ResolvConfLayout::ResolvedUplink,
            ),
            (
                "/run/NetworkManager/resolv.conf",
                ResolvConfLayout::NetworkManager,
            ),
            ("/run/resolvconf/resolv.conf", ResolvConfLayout::Resolvconf),
            (
                "/tmp/run/systemd/resolve/stub-resolv.conf",
                ResolvConfLayout::UnknownSymlink,
            ),
            (
                "/run/NetworkManager/no-stub-resolv.conf",
                ResolvConfLayout::UnknownSymlink,
            ),
        ] {
            assert_eq!(known_resolv_conf_target(Path::new(path)), expected);
        }
    }

    #[test]
    fn различает_файл_битую_ссылку_и_необычный_объект() {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let nonce = u64::from_ne_bytes(nonce);
        let directory = std::env::temp_dir().join(format!("yonik-dns-host-{nonce:016x}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let target = directory.join("generated");
        let config = directory.join("resolv.conf");
        assert_eq!(inspect_resolv_conf(&config), ResolvConfLayout::Missing);
        symlink("generated", &config).unwrap();
        assert_eq!(
            inspect_resolv_conf(&config),
            ResolvConfLayout::BrokenSymlink
        );
        fs::write(&target, []).unwrap();
        assert_eq!(
            inspect_resolv_conf(&config),
            ResolvConfLayout::UnknownSymlink
        );
        assert_eq!(inspect_resolv_conf(&target), ResolvConfLayout::RegularFile);
        assert_eq!(inspect_resolv_conf(&directory), ResolvConfLayout::Other);
        fs::remove_file(config).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}

pub use config::*;
#[cfg(feature = "test-support")]
pub(crate) use plain::read_fixture_dns_source;
pub(crate) use plain::read_managed_resolv_conf;
pub use plain::{PlainResolverSnapshot, read_system_resolv_conf};
#[cfg(feature = "test-support")]
pub use resolve1::{Resolve1ApplyError, Resolve1Prepared, apply_link_dns, prepare_link_dns};
pub use resolve1::{
    Resolve1Domain, Resolve1Endpoint, Resolve1Scope, Resolve1Snapshot, read_resolve1_snapshot,
};
pub use socket::ResolverPeer;

/// Раскладка файла, которую видит процесс. Активность DNS-службы и путь
/// запросов через NSS нужно проверять отдельно.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvConfLayout {
    ResolvedStub,
    ResolvedStaticStub,
    ResolvedUplink,
    NetworkManager,
    Resolvconf,
    RegularFile,
    UnknownSymlink,
    BrokenSymlink,
    Missing,
    Other,
    Unreadable,
}

/// Читает метаданные файла и цель ссылки, не открывая DNS-конфигурацию.
pub fn inspect_host_resolv_conf() -> ResolvConfLayout {
    inspect_resolv_conf(std::path::Path::new("/etc/resolv.conf"))
}

fn inspect_resolv_conf(path: &std::path::Path) -> ResolvConfLayout {
    use std::{fs, io::ErrorKind};

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return ResolvConfLayout::Missing,
        Err(_) => return ResolvConfLayout::Unreadable,
    };
    if metadata.is_file() {
        return ResolvConfLayout::RegularFile;
    }
    if !metadata.is_symlink() {
        return ResolvConfLayout::Other;
    }
    let target = match fs::canonicalize(path) {
        Ok(target) => target,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return ResolvConfLayout::BrokenSymlink;
        }
        Err(_) => return ResolvConfLayout::Unreadable,
    };
    match fs::metadata(&target) {
        Ok(metadata) if metadata.is_file() => known_resolv_conf_target(&target),
        Ok(_) => ResolvConfLayout::Other,
        Err(error) if error.kind() == ErrorKind::NotFound => ResolvConfLayout::BrokenSymlink,
        Err(_) => ResolvConfLayout::Unreadable,
    }
}

fn known_resolv_conf_target(target: &std::path::Path) -> ResolvConfLayout {
    match target.to_str() {
        Some("/run/systemd/resolve/stub-resolv.conf") => ResolvConfLayout::ResolvedStub,
        Some("/usr/lib/systemd/resolv.conf" | "/lib/systemd/resolv.conf") => {
            ResolvConfLayout::ResolvedStaticStub
        }
        Some("/run/systemd/resolve/resolv.conf") => ResolvConfLayout::ResolvedUplink,
        Some("/run/NetworkManager/resolv.conf") => ResolvConfLayout::NetworkManager,
        Some("/run/resolvconf/resolv.conf") => ResolvConfLayout::Resolvconf,
        _ => ResolvConfLayout::UnknownSymlink,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolverError {
    Unavailable,
    Unsupported,
    PermissionDenied,
    Cancelled,
    Timeout,
    Malformed,
    Limit,
    Closed,
    Untrusted,
    Exhausted,
    NetworkChanged,
}
impl std::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "Недоступен systemd-resolved",
            Self::Unsupported => "Не поддержан DNS configuration API",
            Self::PermissionDenied => "Нет права наблюдать DNS-конфигурацию",
            Self::Cancelled => "Чтение DNS отменено",
            Self::Timeout => "Истёк срок чтения DNS",
            Self::Malformed => "Повреждена DNS-конфигурация",
            Self::Limit => "Превышен лимит DNS-конфигурации",
            Self::Closed => "Источник DNS закрыт",
            Self::Untrusted => "Не подтверждён источник DNS",
            Self::Exhausted => "Исчерпано поколение DNS",
            Self::NetworkChanged => "Окружение изменилось во время чтения DNS",
        })
    }
}
impl std::error::Error for ResolverError {}

use crate::Cancellation;
use std::time::Duration;
use tokio::time::Instant;

/// Корреляция наблюдений одного соединения; не lease Prepare/Apply.
/// Каждый разовый снимок и каждая подписка имеют отдельный случайный instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolverStamp {
    instance: [u8; 16],
    sequence: u64,
}
impl ResolverStamp {
    pub fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverSnapshot {
    pub configuration: ResolverConfiguration,
    pub peer: ResolverPeer,
    pub stamp: ResolverStamp,
    pub streamed: bool,
}

pub struct ResolverSubscription {
    wire: wire::ResolverWire,
    last: ResolverSnapshot,
}
impl ResolverSubscription {
    /// Последний принятый frame, а не проверка текущей живости daemon.
    pub fn last_observation(&self) -> &ResolverSnapshot {
        &self.last
    }
    pub fn is_closed(&self) -> bool {
        self.wire.is_closed()
    }
    pub fn close(&mut self) {
        self.wire.close();
    }
    pub async fn next(
        &mut self,
        cancel: &mut Cancellation,
    ) -> Result<&ResolverSnapshot, ResolverError> {
        let sequence = match advance_sequence(self.last.stamp.sequence) {
            Ok(value) => value,
            Err(error) => {
                self.wire.close();
                return Err(error);
            }
        };
        let configuration = self.wire.next(cancel).await?;
        self.last.configuration = configuration;
        self.last.stamp.sequence = sequence;
        Ok(&self.last)
    }
}

/// Факты daemon, не подтверждение system resolver/namespace или права Apply.
pub async fn read_resolver_snapshot(
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<ResolverSnapshot, ResolverError> {
    let deadline = startup_deadline(timeout)?;
    let connected = socket::connect(socket::Endpoint::Main, cancel, deadline).await?;
    let mut wire = wire::ResolverWire::new(connected.stream);
    let configuration = wire.snapshot(cancel, deadline).await?;
    Ok(ResolverSnapshot {
        configuration,
        peer: connected.peer,
        stamp: new_stamp()?,
        streamed: false,
    })
}
/// Подписка требует API и авторизации; интерактивная авторизация не запрашивается.
pub async fn subscribe_resolver(
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<ResolverSubscription, ResolverError> {
    let deadline = startup_deadline(timeout)?;
    let connected = socket::connect(socket::Endpoint::Monitor, cancel, deadline).await?;
    subscribe_connected(connected, cancel, deadline).await
}
async fn subscribe_connected(
    connected: socket::Connected,
    cancel: &mut Cancellation,
    deadline: Instant,
) -> Result<ResolverSubscription, ResolverError> {
    let mut wire = wire::ResolverWire::new(connected.stream);
    let configuration = wire.subscribe(cancel, deadline).await?;
    let last = ResolverSnapshot {
        configuration,
        peer: connected.peer,
        stamp: new_stamp()?,
        streamed: true,
    };
    Ok(ResolverSubscription { wire, last })
}
fn advance_sequence(sequence: u64) -> Result<u64, ResolverError> {
    sequence.checked_add(1).ok_or(ResolverError::Exhausted)
}
fn startup_deadline(timeout: Duration) -> Result<Instant, ResolverError> {
    if timeout.is_zero() || timeout > Duration::from_secs(5) {
        return Err(ResolverError::Limit);
    }
    Ok(Instant::now() + timeout)
}
fn new_stamp() -> Result<ResolverStamp, ResolverError> {
    let mut instance = [0; 16];
    getrandom::getrandom(&mut instance).map_err(|_| ResolverError::Unavailable)?;
    Ok(ResolverStamp {
        instance,
        sequence: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };
    #[tokio::test]
    async fn invalid_startup_budget_never_reaches_daemon() {
        let (_source, mut cancel) = Cancellation::new();
        for budget in [Duration::ZERO, Duration::from_secs(6)] {
            assert_eq!(
                read_resolver_snapshot(&mut cancel, budget).await.err(),
                Some(ResolverError::Limit)
            );
            assert_eq!(
                subscribe_resolver(&mut cancel, budget).await.err(),
                Some(ResolverError::Limit)
            );
        }
    }
    #[test]
    fn observation_counter_never_wraps() {
        assert_eq!(advance_sequence(0), Ok(1));
        assert_eq!(advance_sequence(u64::MAX), Err(ResolverError::Exhausted));
    }
    #[tokio::test]
    async fn subscription_preserves_source_advances_sequence_and_closes_on_cancel() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0];
            while server.read(&mut byte).await.unwrap() > 0 {
                request.push(byte[0]);
                if byte[0] == 0 {
                    break;
                }
            }
            let request: serde_json::Value =
                serde_json::from_slice(&request[..request.len() - 1]).unwrap();
            assert_eq!(
                request["method"],
                "io.systemd.Resolve.Monitor.SubscribeDNSConfiguration"
            );
            assert_eq!(
                request["parameters"]["allowInteractiveAuthentication"],
                false
            );
            server.write_all(b"{\"parameters\":{\"configuration\":[{\"resolvConfMode\":\"stub\"}]},\"continues\":true}\0{\"parameters\":{\"configuration\":[{\"resolvConfMode\":\"foreign\"}]},\"continues\":true}\0").await.unwrap();
            assert_eq!(
                server.read(&mut byte).await.unwrap(),
                0,
                "Клиент закрыл соединение"
            );
        });
        let peer = ResolverPeer {
            uid: rustix::process::getuid().as_raw(),
            pid: Some(std::process::id()),
            socket_device: 7,
            socket_inode: 9,
        };
        let (_source, mut cancel) = Cancellation::new();
        let mut subscription = subscribe_connected(
            socket::Connected {
                stream: client,
                peer,
            },
            &mut cancel,
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("subscription");
        let first = subscription.last_observation().stamp;
        assert_eq!(first.sequence(), 0);
        let second = subscription.next(&mut cancel).await.unwrap();
        assert_eq!(second.stamp.sequence(), 1);
        assert_ne!(first, second.stamp);
        assert_eq!(second.peer, peer);
        assert!(second.streamed);
        assert_eq!(
            second.configuration.entries[0].resolv_conf_mode,
            Some(Supported::Known(GlobalModeKnown::Foreign))
        );
        let (source, mut cancel) = Cancellation::new();
        source.send_replace(true);
        assert_eq!(
            subscription.next(&mut cancel).await.err(),
            Some(ResolverError::Cancelled)
        );
        assert!(subscription.is_closed());
        task.await.unwrap();
    }
}
