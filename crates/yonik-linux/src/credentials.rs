//! Ключи snapshot остаются в Secret Service; plaintext fallback отсутствует.

use futures_util::FutureExt;
use secret_service::{EncryptionType, SecretService};
use std::{
    collections::HashMap,
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    Unavailable,
    Locked,
    Missing,
    Ambiguous,
    InvalidKey,
    Random,
    Timeout,
    Busy,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "Secret Service недоступен",
            Self::Locked => "Разблокируйте хранилище секретов",
            Self::Missing => "Ключ существующей базы отсутствует в Secret Service",
            Self::Ambiguous => "Найдено несколько ключей yonik; требуется восстановление",
            Self::InvalidKey => "Неверный формат ключа yonik",
            Self::Random => "Не удалось получить случайный ключ",
            Self::Timeout => "Secret Service не ответил вовремя",
            Self::Busy => "Создание ключа yonik уже выполняется",
        })
    }
}
impl std::error::Error for CredentialError {}

/// Для существующей БД `allow_create` всегда false: потеря ключа не создаёт
/// новую криптографическую идентичность поверх старых данных.
pub async fn subscription_master_key(
    allow_create: bool,
) -> Result<Zeroizing<[u8; 32]>, CredentialError> {
    let _creation_lock = if allow_create {
        Some(
            tokio::task::spawn_blocking(creation_lock)
                .await
                .map_err(|_| CredentialError::Unavailable)??,
        )
    } else {
        None
    };
    tokio::time::timeout(Duration::from_secs(15), load_key(allow_create))
        .await
        .map_err(|_| CredentialError::Timeout)?
}

fn creation_lock() -> Result<File, CredentialError> {
    let runtime =
        PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").ok_or(CredentialError::Unavailable)?);
    if !runtime.is_absolute() {
        return Err(CredentialError::Unavailable);
    }
    let uid = rustix::process::getuid().as_raw();
    let check = |path: &std::path::Path| -> Result<(), CredentialError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| CredentialError::Unavailable)?;
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
            return Err(CredentialError::Unavailable);
        }
        Ok(())
    };
    check(&runtime)?;
    // Старый lock общий с прежними версиями: нельзя создавать два ключа параллельно.
    let path = runtime.join("tofu-key-creation");
    match DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(CredentialError::Unavailable),
    }
    check(&path)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY).bits() as i32)
        .open(path)
        .map_err(|_| CredentialError::Unavailable)?;
    rustix::fs::flock(
        &directory,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|_| CredentialError::Busy)?;
    Ok(directory)
}

fn secret_error(error: secret_service::Error) -> CredentialError {
    match error {
        secret_service::Error::Locked => CredentialError::Locked,
        secret_service::Error::Zbus(zbus::Error::MethodError(name, _, _))
            if name.as_str() == "org.freedesktop.Secret.Error.IsLocked" =>
        {
            CredentialError::Locked
        }
        _ => CredentialError::Unavailable,
    }
}

async fn load_key(allow_create: bool) -> Result<Zeroizing<[u8; 32]>, CredentialError> {
    let service = SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|_| CredentialError::Unavailable)?;
    // Атрибуты поиска сохраняются для доступа к существующему ключу в Secret Service.
    let attributes = HashMap::from([
        ("application", "cloud.highpriority.tofu"),
        ("purpose", "subscription-master-key"),
        ("schema", "1"),
    ]);
    let found = service
        .search_items(attributes.clone())
        .await
        .map_err(|_| CredentialError::Unavailable)?;
    let count = found.unlocked.len() + found.locked.len();
    if count > 1 {
        return Err(CredentialError::Ambiguous);
    }
    if !found.locked.is_empty() {
        return Err(CredentialError::Locked);
    }
    if let Some(item) = found.unlocked.first() {
        let secret = Zeroizing::new(
            // secret-service 4.0.0 паникует при неверной длине IV от сервиса.
            // Ограничиваем перехват декодированием ответа, не меняя panic hook.
            std::panic::AssertUnwindSafe(item.get_secret())
                .catch_unwind()
                .await
                .map_err(|_| CredentialError::Unavailable)?
                .map_err(secret_error)?,
        );
        let bytes: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| CredentialError::InvalidKey)?;
        return Ok(Zeroizing::new(bytes));
    }
    if !allow_create {
        return Err(CredentialError::Missing);
    }
    let collection = service
        .get_default_collection()
        .await
        .map_err(|_| CredentialError::Unavailable)?;
    if collection
        .is_locked()
        .await
        .map_err(|_| CredentialError::Unavailable)?
    {
        return Err(CredentialError::Locked);
    }
    let mut key = Zeroizing::new([0; 32]);
    getrandom::getrandom(key.as_mut()).map_err(|_| CredentialError::Random)?;
    // Никогда не заменяем найденный ключ и не создаём/разблокируем коллекции.
    collection
        .create_item(
            "yonik — ключ зашифрованных подписок",
            attributes,
            key.as_ref(),
            false,
            "application/octet-stream",
        )
        .await
        .map_err(|_| CredentialError::Unavailable)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn сообщение_о_блокировке_подходит_для_любого_окружения() {
        assert_eq!(
            CredentialError::Locked.to_string(),
            "Разблокируйте хранилище секретов"
        );
    }

    #[tokio::test]
    #[ignore = "Требует доступного Secret Service; только чтение, ключи не создаются"]
    async fn secret_service_readonly() {
        match subscription_master_key(false).await {
            Ok(key) => assert_eq!(key.len(), 32),
            Err(CredentialError::Missing) => {}
            Err(error) => panic!("Secret Service: {error}"),
        }
    }
}

/// Наблюдение реального bus/unique-owner epoch, не permit доступа к ключу.
/// secret-service 4.0 создаёт собственную connection; guard использует отдельную
/// connection к той же выбранной шине и устанавливается ДО credential call.
#[derive(Clone)]
pub struct CredentialOwnerGuard(std::sync::Arc<CredentialOwnerEpoch>);
struct CredentialOwnerEpoch {
    connection: zbus::Connection,
    address: Option<std::ffi::OsString>,
    bus_id: String,
    owner: String,
    lost: tokio::sync::watch::Receiver<bool>,
    monitor: tokio::task::JoinHandle<()>,
}
impl Drop for CredentialOwnerEpoch {
    fn drop(&mut self) {
        self.monitor.abort();
    }
}
impl CredentialOwnerGuard {
    async fn bus_string(
        connection: &zbus::Connection,
        method: &str,
        args: &(impl serde::Serialize + zbus::zvariant::DynamicType),
    ) -> Result<String, CredentialError> {
        connection
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                method,
                args,
            )
            .await
            .map_err(|_| CredentialError::Unavailable)?
            .body()
            .deserialize()
            .map_err(|_| CredentialError::Unavailable)
    }
    async fn owner(connection: &zbus::Connection) -> Result<String, CredentialError> {
        Self::bus_string(connection, "GetNameOwner", &("org.freedesktop.secrets",)).await
    }
    /// Потеря epoch необратима даже если тот же owner снова объявил well-known name.
    pub fn owner_lost(&self) -> bool {
        *self.0.lost.borrow()
            || self.0.lost.has_changed().is_err()
            || self.0.address != std::env::var_os("DBUS_SESSION_BUS_ADDRESS")
    }
    /// Наблюдает текущий реальный session bus; не создаёт credential item.
    pub async fn observe() -> Result<Self, CredentialError> {
        use futures_util::StreamExt;
        use zbus::{MatchRule, MessageStream, message::Type};
        tokio::time::timeout(Duration::from_secs(2), async {
            let address = std::env::var_os("DBUS_SESSION_BUS_ADDRESS");
            let connection = zbus::Connection::session()
                .await
                .map_err(|_| CredentialError::Unavailable)?;
            let rule = MatchRule::builder()
                .msg_type(Type::Signal)
                .sender("org.freedesktop.DBus")
                .map_err(|_| CredentialError::Unavailable)?
                .interface("org.freedesktop.DBus")
                .map_err(|_| CredentialError::Unavailable)?
                .member("NameOwnerChanged")
                .map_err(|_| CredentialError::Unavailable)?
                .path("/org/freedesktop/DBus")
                .map_err(|_| CredentialError::Unavailable)?
                .add_arg("org.freedesktop.secrets")
                .map_err(|_| CredentialError::Unavailable)?
                .build();
            let mut changes = MessageStream::for_match_rule(rule, &connection, Some(16))
                .await
                .map_err(|_| CredentialError::Unavailable)?;
            let bus_id = Self::bus_string(&connection, "GetId", &()).await?;
            let owner = Self::owner(&connection).await?;
            if !owner.starts_with(':') {
                return Err(CredentialError::Unavailable);
            }
            let (tx, lost) = tokio::sync::watch::channel(false);
            let monitor = tokio::spawn(async move {
                let _ = changes.next().await;
                tx.send_replace(true);
            });
            Ok(Self(std::sync::Arc::new(CredentialOwnerEpoch {
                connection,
                address,
                bus_id,
                owner,
                lost,
                monitor,
            })))
        })
        .await
        .map_err(|_| CredentialError::Timeout)?
    }
    /// Каждый await завершается новой проверкой необратимого owner fence.
    pub async fn check(&self) -> Result<(), CredentialError> {
        tokio::time::timeout(Duration::from_secs(2), async {
            if self.owner_lost() {
                return Err(CredentialError::Unavailable);
            }
            if Self::owner(&self.0.connection).await? != self.0.owner || self.owner_lost() {
                return Err(CredentialError::Unavailable);
            }
            // Не принимаем подменённый socket по тому же адресу за исходную шину.
            let selected = zbus::Connection::session()
                .await
                .map_err(|_| CredentialError::Unavailable)?;
            if self.owner_lost() {
                return Err(CredentialError::Unavailable);
            }
            if Self::bus_string(&selected, "GetId", &()).await? != self.0.bus_id
                || self.owner_lost()
            {
                return Err(CredentialError::Unavailable);
            }
            if Self::owner(&selected).await? != self.0.owner || self.owner_lost() {
                return Err(CredentialError::Unavailable);
            }
            Ok(())
        })
        .await
        .map_err(|_| CredentialError::Timeout)?
    }
}

/// Старые Missing/Locked/create semantics неизменны. Отсутствующий owner guard
/// не мешает ручной работе host, но запрещает startup dispatch в этом host.
pub async fn subscription_master_key_with_owner(
    allow_create: bool,
) -> Result<(Zeroizing<[u8; 32]>, Option<CredentialOwnerGuard>), CredentialError> {
    let observed = CredentialOwnerGuard::observe().await.ok();
    let key = subscription_master_key(allow_create).await?;
    let owner = match observed {
        Some(guard) if guard.check().await.is_ok() => Some(guard),
        _ => None,
    };
    Ok((key, owner))
}
