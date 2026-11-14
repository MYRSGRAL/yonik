//! Авторизация будущего системного helper. Сетевых эффектов здесь нет.
//!
//! Сервер передаёт только сообщение, полученное его доверенным D-Bus transport.
//! `PeerIdentity` — снимок, а не разрешение на будущий Apply: перед каждым
//! Prepare/Apply нужна новая проверка непосредственно перед эффектами.

pub mod fence;
mod kernel_evidence;
pub(crate) mod native_bootstrap;
mod native_profile;
mod protection_host;
mod session_network;
pub use session_network::SessionNetworkPlan;
pub(crate) mod run_authorization;
mod systemd_worker;
pub use protection_host::SystemProtectionHost as SystemSessionHost;
pub use protection_host::{GuardArtifact, SystemProtectionHost};
pub use systemd_worker::{
    BootstrapUnitObservation, SystemWorkerSupervisor, WorkerLiveness, WorkerSupervisorError,
    WorkerTicket,
};

pub(crate) mod memory;
pub use memory::{
    MAX_CONFIG_MEMORY_BYTES, MAX_CONFIG_STORES, MAX_EXECUTABLE_BYTES, MAX_RETAINED_CONFIG_BYTES,
    MemoryUsage, memory_usage,
};

mod prepared;
pub use prepared::{
    ClaimedArtifact, MAX_ARTIFACT_BYTES, MAX_IN_FLIGHT, MAX_PENDING, MAX_PENDING_PER_PEER,
    PREPARED_TTL, PreparedArtifact, PreparedContext, PreparedError, PreparedHandle,
    PreparedRequests,
};

mod registry;
pub use registry::{RegistryError, TrustedRegistry};

use std::{collections::HashMap, future::Future, time::Duration};

use tokio::{sync::Semaphore, time::Instant};
use zbus::{Connection, Message, message::Type, names::UniqueName, zvariant::Value};

use crate::Cancellation;

const AUTHORITY: &str = "org.freedesktop.PolicyKit1";
const PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
mod output_bus;
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(120);
const CANCEL_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_REQUEST: usize = 64 * 1024;
const MAX_REPLY: usize = 4096;
const MAX_CHECKS: usize = 4;

/// Только фиксированные действия; клиент не задаёт polkit action ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkAction {
    ManageNetwork,
    UnlockNetwork,
}
impl NetworkAction {
    pub fn id(self) -> &'static str {
        match self {
            Self::ManageNetwork => "cloud.highpriority.tofu.manage-network",
            Self::UnlockNetwork => "cloud.highpriority.tofu.unlock-network",
        }
    }
}

/// Выбирается доверенным сервером. Allow допустим только для действия пользователя.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Prompt {
    #[default]
    Never,
    Allow,
}

/// Никаких строк от D-Bus/polkit, details или temporary authorization ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidMessage,
    Unavailable,
    UntrustedAuthority,
    PeerGone,
    AuthorityChanged,
    InvalidReply,
    Denied,
    Challenge,
    Cancelled,
    Timeout,
}
impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidMessage => "Некорректное сообщение helper",
            Self::Unavailable => "Служба авторизации недоступна",
            Self::UntrustedAuthority => "Недоверенный владелец службы авторизации",
            Self::PeerGone => "Отправитель отключён",
            Self::AuthorityChanged => "Владелец службы авторизации изменился",
            Self::InvalidReply => "Некорректный ответ авторизации",
            Self::Denied => "Авторизация отклонена",
            Self::Challenge => "Требуется подтверждение авторизации",
            Self::Cancelled => "Авторизация отменена",
            Self::Timeout => "Истёк срок авторизации",
        })
    }
}
impl std::error::Error for AuthorizationError {}

/// Идентичность соединения в момент проверки; не долгоживущий authorization token.
#[derive(Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    uid: u32,
    sender: String,
}
impl PeerIdentity {
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn sender(&self) -> &str {
        &self.sender
    }
}

// polkit использует отдельный системный аккаунт на современных дистрибутивах.
// Источник фиксирован: клиент и окружение не выбирают доверенный UID.
fn system_polkit_uid() -> Result<u32, AuthorizationError> {
    trusted_polkit_uid(std::path::Path::new("/etc/passwd"))
}
fn trusted_polkit_uid(path: &std::path::Path) -> Result<u32, AuthorizationError> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    const MAX_ACCOUNT_BYTES: u64 = 1024 * 1024;
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| AuthorizationError::Unavailable)?;
    let file = std::fs::File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|_| AuthorizationError::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(AuthorizationError::UntrustedAuthority);
    }
    let mut contents = String::new();
    file.take(MAX_ACCOUNT_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|_| AuthorizationError::Unavailable)?;
    if contents.len() as u64 > MAX_ACCOUNT_BYTES {
        return Err(AuthorizationError::Unavailable);
    }
    parse_polkit_uid(&contents)
}
fn parse_polkit_uid(contents: &str) -> Result<u32, AuthorizationError> {
    const MAX_SYSTEM_ACCOUNT_UID: u32 = 999;
    let invalid = AuthorizationError::UntrustedAuthority;
    let mut polkit_uid = None;
    let mut uids = HashMap::new();
    for line in contents.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.splitn(8, ':').collect();
        if fields.len() != 7 {
            return Err(invalid);
        }
        let uid: u32 = fields[2].parse().map_err(|_| invalid)?;
        *uids.entry(uid).or_insert(0usize) += 1;
        if fields[0] == "polkitd" {
            // Поддерживаем отдельный системный UID Linux; иное требует явной настройки поставки.
            if polkit_uid.is_some() || !(1..=MAX_SYSTEM_ACCOUNT_UID).contains(&uid) {
                return Err(invalid);
            }
            polkit_uid = Some(uid);
        }
    }
    match polkit_uid {
        Some(uid) if uids.get(&uid) == Some(&1) => Ok(uid),
        Some(_) => Err(invalid),
        // Старые поставки запускают authority от root без отдельного аккаунта.
        None => Ok(0),
    }
}

/// Один экземпляр на helper server: общий предел одновременно выполняемых проверок.
/// Конструктор не читает DBUS_SYSTEM_BUS_ADDRESS и не использует session bus.
pub struct PeerAuthorizer {
    connection: Connection,
    expected_authority_uid: u32,
    checks: Semaphore,
    noninteractive_timeout: Duration,
    interactive_timeout: Duration,
}
impl PeerAuthorizer {
    pub async fn system(mut cancel: Cancellation) -> Result<Self, AuthorizationError> {
        let connection = bounded(&mut cancel, Instant::now() + SETUP_TIMEOUT, async {
            output_bus::builder(
                tokio::net::UnixStream::connect("/run/dbus/system_bus_socket")
                    .await
                    .map_err(|_| AuthorizationError::Unavailable)?,
            )
            .map_err(|_| AuthorizationError::Unavailable)?
            .build()
            .await
            .map_err(|_| AuthorizationError::Unavailable)
        })
        .await?;
        Ok(Self {
            connection,
            expected_authority_uid: system_polkit_uid()?,
            checks: Semaphore::new(MAX_CHECKS),
            noninteractive_timeout: SETUP_TIMEOUT,
            interactive_timeout: INTERACTIVE_TIMEOUT,
        })
    }

    /// `message` должен происходить из входящего вызова доверенного server transport.
    /// UID из тела сообщения никогда не используется. Details всегда пусты.
    pub async fn authorize(
        &self,
        message: &Message,
        action: NetworkAction,
        prompt: Prompt,
        mut cancel: Cancellation,
    ) -> Result<PeerIdentity, AuthorizationError> {
        let sender = sender(message)?;
        let deadline = Instant::now()
            + match prompt {
                Prompt::Never => self.noninteractive_timeout,
                Prompt::Allow => self.interactive_timeout,
            };
        let _permit = bounded(&mut cancel, deadline, async {
            self.checks
                .acquire()
                .await
                .map_err(|_| AuthorizationError::Unavailable)
        })
        .await?;
        let (uid, owner) = bounded(&mut cancel, setup_deadline(deadline), async {
            let uid = self.uid(&sender).await?;
            let owner = self.owner().await?;
            let authority_uid = self.uid(&owner).await?;
            if authority_uid != 0 && authority_uid != self.expected_authority_uid {
                return Err(AuthorizationError::UntrustedAuthority);
            }
            Ok((uid, owner))
        })
        .await?;
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| AuthorizationError::Unavailable)?;
        let cancellation_id = format!("yonik-{:032x}", u128::from_ne_bytes(random));
        let subject = (
            "system-bus-name",
            HashMap::from([("name", Value::from(sender.as_str()))]),
        );
        let details = HashMap::<&str, &str>::new();
        let flags = u32::from(prompt == Prompt::Allow);
        let body = (
            subject,
            action.id(),
            details,
            flags,
            cancellation_id.as_str(),
        );
        let result = bounded(&mut cancel, deadline, async {
            self.connection
                .call_method(
                    Some(owner.as_str()),
                    PATH,
                    Some(INTERFACE),
                    "CheckAuthorization",
                    &body,
                )
                .await
                .map_err(|_| AuthorizationError::Unavailable)
        })
        .await;
        let reply = match result {
            Err(error) => {
                // Best effort: удалённый ответ может опоздать; он больше не даёт разрешения.
                // Отмена идёт тому же unique owner, никогда новому владельцу well-known name.
                self.cancel_check(&owner, &cancellation_id).await;
                return Err(error);
            }
            Ok(reply) => reply,
        };
        if reply.header().sender().map(|name| name.as_str()) != Some(owner.as_str())
            || reply.body().len() > MAX_REPLY
        {
            // Чужой reply мог завершить только локальное ожидание: настоящий
            // CheckAuthorization у закреплённого authority ещё может выполняться.
            self.cancel_check(&owner, &cancellation_id).await;
            return Err(AuthorizationError::InvalidReply);
        }
        let ((authorized, challenge, _details),): ((bool, bool, HashMap<&str, &str>),) = reply
            .body()
            .deserialize()
            .map_err(|_| AuthorizationError::InvalidReply)?;
        if authorized && challenge {
            return Err(AuthorizationError::InvalidReply);
        }
        bounded(&mut cancel, setup_deadline(deadline), async {
            if self.uid(&sender).await? != uid {
                return Err(AuthorizationError::PeerGone);
            }
            if self.owner().await? != owner {
                return Err(AuthorizationError::AuthorityChanged);
            }
            Ok(())
        })
        .await?;
        if !authorized {
            return Err(if challenge {
                AuthorizationError::Challenge
            } else {
                AuthorizationError::Denied
            });
        }
        cancel.check().map_err(|_| AuthorizationError::Cancelled)?;
        Ok(PeerIdentity { uid, sender })
    }

    async fn cancel_check(&self, owner: &str, cancellation_id: &str) {
        let _cancel_result = tokio::time::timeout(
            CANCEL_TIMEOUT,
            self.connection.call_method(
                Some(owner),
                PATH,
                Some(INTERFACE),
                "CancelCheckAuthorization",
                &(cancellation_id,),
            ),
        )
        .await;
    }

    async fn daemon_call(&self, method: &str, name: &str) -> Result<Message, AuthorizationError> {
        let reply = self
            .connection
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                method,
                &(name,),
            )
            .await
            .map_err(|_| AuthorizationError::Unavailable)?;
        if reply.header().sender().map(|sender| sender.as_str()) != Some("org.freedesktop.DBus")
            || reply.body().len() > MAX_REPLY
        {
            return Err(AuthorizationError::InvalidReply);
        }
        Ok(reply)
    }

    async fn uid(&self, name: &str) -> Result<u32, AuthorizationError> {
        let reply = self
            .daemon_call("GetConnectionCredentials", name)
            .await
            .map_err(|error| {
                if error == AuthorizationError::Unavailable {
                    AuthorizationError::PeerGone
                } else {
                    error
                }
            })?;
        let body = reply.body();
        let (credentials,): (HashMap<&str, Value<'_>>,) = body
            .deserialize()
            .map_err(|_| AuthorizationError::InvalidReply)?;
        credentials
            .get("UnixUserID")
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(AuthorizationError::PeerGone)
    }

    async fn peer_pid(&self, name: &str, uid: u32) -> Result<u32, AuthorizationError> {
        let reply = self.daemon_call("GetConnectionCredentials", name).await?;
        let body = reply.body();
        let (credentials,): (HashMap<&str, Value<'_>>,) = body
            .deserialize()
            .map_err(|_| AuthorizationError::InvalidReply)?;
        if credentials
            .get("UnixUserID")
            .and_then(|v| u32::try_from(v).ok())
            != Some(uid)
        {
            return Err(AuthorizationError::PeerGone);
        }
        credentials
            .get("ProcessID")
            .and_then(|v| u32::try_from(v).ok())
            .filter(|pid| *pid != 0)
            .ok_or(AuthorizationError::PeerGone)
    }

    async fn owner(&self) -> Result<String, AuthorizationError> {
        let reply = self.daemon_call("GetNameOwner", AUTHORITY).await?;
        let body = reply.body();
        let (owner,): (&str,) = body
            .deserialize()
            .map_err(|_| AuthorizationError::InvalidReply)?;
        if owner.len() > 255 || UniqueName::try_from(owner).is_err() {
            return Err(AuthorizationError::InvalidReply);
        }
        Ok(owner.to_owned())
    }
}

fn sender(message: &Message) -> Result<String, AuthorizationError> {
    let header = message.header();
    if header.message_type() != Type::MethodCall || message.body().len() > MAX_REQUEST {
        return Err(AuthorizationError::InvalidMessage);
    }
    let name = header.sender().ok_or(AuthorizationError::InvalidMessage)?;
    if name.as_str().len() > 255 || UniqueName::try_from(name.as_str()).is_err() {
        return Err(AuthorizationError::InvalidMessage);
    }
    Ok(name.to_string())
}

fn setup_deadline(deadline: Instant) -> Instant {
    deadline.min(Instant::now() + SETUP_TIMEOUT)
}

async fn bounded<T>(
    cancel: &mut Cancellation,
    deadline: Instant,
    operation: impl Future<Output = Result<T, AuthorizationError>>,
) -> Result<T, AuthorizationError> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(AuthorizationError::Cancelled),
        _ = tokio::time::sleep_until(deadline) => Err(AuthorizationError::Timeout),
        result = operation => result,
    }
}

#[cfg(test)]
mod tests;

mod service;
pub use service::{
    ProtectionHost, ProtectionState, ServiceError, SystemProfileRequest, run_system_service,
};
