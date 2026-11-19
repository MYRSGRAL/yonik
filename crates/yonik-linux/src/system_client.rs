//! Клиент закрытого IPC v1. Потеря имени необратимо инвалидирует экземпляр.
//!
//! Отмена или deadline после отправки мутации означает неизвестный исход эффекта.
//! При неизвестном исходе controller должен явно запросить State.
//! Prepare с политикой Fake DNS повторяется только после подтверждённого отказа.
use crate::Cancellation;
use futures_util::StreamExt;
use serde::Deserialize;
use std::{fmt, time::Duration};
use tokio::{sync::watch, time::Instant};
use zbus::{Connection, MatchRule, MessageStream, message::Type};
const SERVICE_NAME: &str = "cloud.highpriority.yonik.Network1";
const SERVICE_PATH: &str = "/cloud/highpriority/yonik/Network";
const SERVICE_INTERFACE: &str = SERVICE_NAME;

const MAX_JSON: usize = 64 * 1024;

struct FakeDnsProfile<'a> {
    domains: &'a [String],
    policy: Option<&'a yonik_engine::policy_wire::SystemPolicy>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientError {
    InvalidRequest,
    Unsupported,
    Busy,
    Denied,
    InvalidHandle,
    Stale,
    Timeout,
    Cancelled,
    Unavailable,
    Deadline,
    OwnerLost,
    Protocol,
}
impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ClientError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    NoManagedPolicy,
    TunnelStarting,
    VerifiedRules,
    RecoveryRequired,
    Unknown,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    version: u32,
    pub public_protection: bool,
    pub system_tun: bool,
    pub allow_lan: bool,
}

/// Разрешает лишь попытку Prepare с attribution; не доказывает активную сессию.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePrepareEligibility {
    version: u32,
    pub can_prepare_attribution: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleCapabilities {
    version: u32,
    pub canonical_fd_transport: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundlePreparedReply {
    version: u32,
    handle: [u8; 32],
    intent_digest: [u8; 32],
    runtime_config_digest: [u8; 32],
    runtime_bundle_digest: [u8; 32],
}
pub struct PreparedBundle {
    prepared: Prepared,
    pub intent_digest: [u8; 32],
    pub runtime_config_digest: [u8; 32],
    pub runtime_bundle_digest: [u8; 32],
}
/// Одноразовый непрозрачный handle привязан к экземпляру клиента; Debug скрыт.
pub struct Prepared {
    handle: [u8; 32],
    owner: String,
    peer: String,
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Prepared(<скрыто>)")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedReply {
    version: u32,
    handle: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateReply {
    version: u32,
    state: State,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorReply {
    version: u32,
    error: String,
}
fn decode<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, ClientError> {
    if json.len() > MAX_JSON || !json.trim_start().starts_with('{') {
        return Err(ClientError::Protocol);
    }
    serde_json::from_str(json).map_err(|_| ClientError::Protocol)
}
fn version(version: u32) -> Result<(), ClientError> {
    if version == 1 {
        Ok(())
    } else {
        Err(ClientError::Protocol)
    }
}
fn remote(_error: zbus::Error) -> ClientError {
    ClientError::Unavailable
}
fn helper_error(json: &str) -> ClientError {
    let Ok(reply) = decode::<ErrorReply>(json) else {
        return ClientError::Protocol;
    };
    if version(reply.version).is_err() {
        return ClientError::Protocol;
    }
    match reply.error.as_str() {
        "invalid_request" => ClientError::InvalidRequest,
        "unsupported" => ClientError::Unsupported,
        "busy" => ClientError::Busy,
        "authorization" => ClientError::Denied,
        "invalid_handle" => ClientError::InvalidHandle,
        "stale" => ClientError::Stale,
        "timeout" => ClientError::Timeout,
        "cancelled" => ClientError::Cancelled,
        "unavailable" => ClientError::Unavailable,
        _ => ClientError::Protocol,
    }
}

pub struct SystemClient {
    connection: Connection,
    owner: String,
    lost: watch::Receiver<bool>,
    monitor: tokio::task::JoinHandle<()>,
}
impl Drop for SystemClient {
    fn drop(&mut self) {
        self.monitor.abort();
    }
}
impl SystemClient {
    /// Production использует только system bus, без session fallback.
    pub async fn system(deadline: Instant, mut cancel: Cancellation) -> Result<Self, ClientError> {
        let setup_cancel = cancel.clone();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ClientError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(ClientError::Deadline),
            result = async {
                let connection = Connection::system().await.map_err(remote)?;
                Self::on_connection(connection, deadline, setup_cancel).await
            } => result,
        }
    }
    /// Явная шина для embedding и private-bus acceptance; destination фиксирован.
    pub async fn on_connection(
        connection: Connection,
        deadline: Instant,
        mut cancel: Cancellation,
    ) -> Result<Self, ClientError> {
        let setup = async {
            let rule = MatchRule::builder()
                .msg_type(Type::Signal)
                .sender("org.freedesktop.DBus")
                .map_err(remote)?
                .interface("org.freedesktop.DBus")
                .map_err(remote)?
                .member("NameOwnerChanged")
                .map_err(remote)?
                .path("/org/freedesktop/DBus")
                .map_err(remote)?
                .add_arg(SERVICE_NAME)
                .map_err(remote)?
                .build();
            let mut changes = MessageStream::for_match_rule(rule, &connection, Some(16))
                .await
                .map_err(remote)?;
            let owner = Self::owner(&connection).await?;
            let (tx, lost) = watch::channel(false);
            let monitor = tokio::spawn(async move {
                // Любая смена owner, потеря потока или переполнение закрывает fence.
                let _ = changes.next().await;
                let _ = tx.send(true);
            });
            Ok(Self {
                connection,
                owner,
                lost,
                monitor,
            })
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ClientError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(ClientError::Deadline),
            result = setup => result,
        }
    }
    async fn owner(connection: &Connection) -> Result<String, ClientError> {
        let reply = connection
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "GetNameOwner",
                &(SERVICE_NAME,),
            )
            .await
            .map_err(remote)?;
        let owner: String = reply
            .body()
            .deserialize()
            .map_err(|_| ClientError::Protocol)?;
        if !owner.starts_with(':') {
            return Err(ClientError::Protocol);
        }
        Ok(owner)
    }
    async fn call(
        &mut self,
        method: &str,
        request: String,
        deadline: Instant,
        mut cancel: Cancellation,
    ) -> Result<String, ClientError> {
        if *self.lost.borrow() || self.lost.has_changed().is_err() {
            return Err(ClientError::OwnerLost);
        }
        if request.len() > MAX_JSON {
            return Err(ClientError::InvalidRequest);
        }
        let operation = async {
            let (reply, failed) = match self
                .connection
                .call_method(
                    Some(self.owner.as_str()),
                    SERVICE_PATH,
                    Some(SERVICE_INTERFACE),
                    method,
                    &(request,),
                )
                .await
            {
                Ok(reply) => (reply, false),
                Err(zbus::Error::MethodError(_, _, reply)) => (reply, true),
                Err(error) => return Err(remote(error)),
            };
            if reply.header().sender().map(|s| s.as_str()) != Some(self.owner.as_str())
                || reply.body().len() > MAX_JSON + 8
                || matches!(
                    method,
                    "BundleCapabilitiesV1" | "NativePrepareEligibilityV1"
                ) && (reply.header().unix_fds().unwrap_or(0) != 0
                    || reply.body().signature().as_ref().map(|s| s.as_str()) != Some("s"))
            {
                return Err(ClientError::Protocol);
            }
            if failed
                && method == "NativePrepareEligibilityV1"
                && reply.header().error_name().map(|name| name.as_str())
                    == Some("org.freedesktop.DBus.Error.UnknownMethod")
            {
                if Self::owner(&self.connection).await? != self.owner {
                    return Err(ClientError::OwnerLost);
                }
                return Ok("{\"version\":1,\"can_prepare_attribution\":false}".into());
            }
            let json: String = reply
                .body()
                .deserialize()
                .map_err(|_| ClientError::Protocol)?;
            if json.len() > MAX_JSON {
                return Err(ClientError::Protocol);
            }
            if Self::owner(&self.connection).await? != self.owner {
                return Err(ClientError::OwnerLost);
            }
            if failed {
                if reply.header().error_name().map(|name| name.as_str())
                    != Some("cloud.highpriority.yonik.Network1.Error")
                {
                    return Err(ClientError::Protocol);
                }
                return Err(helper_error(&json));
            }
            Ok(json)
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ClientError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(ClientError::Deadline),
            _ = self.lost.changed() => Err(ClientError::OwnerLost),
            result = operation => result,
        }
    }
    async fn call_with_resources(
        &mut self,
        method: &str,
        request: String,
        resources: &[std::fs::File],
        deadline: Instant,
        mut cancel: Cancellation,
    ) -> Result<String, ClientError> {
        if *self.lost.borrow() || self.lost.has_changed().is_err() {
            return Err(ClientError::OwnerLost);
        }
        if request.len() > MAX_JSON {
            return Err(ClientError::InvalidRequest);
        }
        use std::os::fd::AsFd;
        if resources.is_empty() || resources.len() > 16 {
            return Err(ClientError::InvalidRequest);
        }
        let fds: Vec<zbus::zvariant::Fd<'_>> =
            resources.iter().map(|file| file.as_fd().into()).collect();
        let operation = async {
            let (reply, failed) = match self
                .connection
                .call_method(
                    Some(self.owner.as_str()),
                    SERVICE_PATH,
                    Some(SERVICE_INTERFACE),
                    method,
                    &(request, fds),
                )
                .await
            {
                Ok(reply) => (reply, false),
                Err(zbus::Error::MethodError(_, _, reply)) => (reply, true),
                Err(error) => return Err(remote(error)),
            };
            if reply.header().sender().map(|s| s.as_str()) != Some(self.owner.as_str())
                || reply.body().len() > MAX_JSON + 8
                || reply.header().unix_fds().unwrap_or(0) != 0
                || reply.body().signature().as_ref().map(|s| s.as_str()) != Some("s")
            {
                return Err(ClientError::Protocol);
            }
            let json: String = reply
                .body()
                .deserialize()
                .map_err(|_| ClientError::Protocol)?;
            if json.len() > MAX_JSON {
                return Err(ClientError::Protocol);
            }
            if Self::owner(&self.connection).await? != self.owner {
                return Err(ClientError::OwnerLost);
            }
            if failed {
                if reply.header().error_name().map(|name| name.as_str())
                    != Some("cloud.highpriority.yonik.Network1.Error")
                {
                    return Err(ClientError::Protocol);
                }
                return Err(helper_error(&json));
            }
            Ok(json)
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ClientError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(ClientError::Deadline),
            _ = self.lost.changed() => Err(ClientError::OwnerLost),
            result = operation => result,
        }
    }
    pub async fn native_prepare_eligibility(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<NativePrepareEligibility, ClientError> {
        let json = match self
            .call(
                "NativePrepareEligibilityV1",
                "{\"version\":1}".into(),
                deadline,
                cancel,
            )
            .await
        {
            Ok(json) => json,
            Err(ClientError::Unsupported) => {
                return Ok(NativePrepareEligibility {
                    version: 1,
                    can_prepare_attribution: false,
                });
            }
            Err(error) => return Err(error),
        };
        let reply: NativePrepareEligibility = decode(&json)?;
        version(reply.version)?;
        Ok(reply)
    }
    pub async fn capabilities(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<Capabilities, ClientError> {
        let reply: Capabilities = decode(
            &self
                .call("Capabilities", "{\"version\":1}".into(), deadline, cancel)
                .await?,
        )?;
        version(reply.version)?;
        Ok(reply)
    }
    pub async fn prepare(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<Prepared, ClientError> {
        let reply: PreparedReply = decode(
            &self
                .call(
                    "Prepare",
                    "{\"version\":1,\"mode\":\"public_protection\",\"allow_lan\":false}".into(),
                    deadline,
                    cancel,
                )
                .await?,
        )?;
        version(reply.version)?;
        Ok(Prepared {
            handle: reply.handle,
            owner: self.owner.clone(),
            peer: self
                .connection
                .unique_name()
                .ok_or(ClientError::Unavailable)?
                .to_string(),
        })
    }
    /// Только проверенное переносимое намерение; native config и пути не принимаются.
    pub async fn prepare_full_profile(
        &mut self,
        request: &crate::helper::profile_intent::FullProfileRequest,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<Prepared, ClientError> {
        let mut bytes = Vec::new();
        request
            .write_sensitive(&mut bytes)
            .map_err(|_| ClientError::InvalidRequest)?;
        let request = String::from_utf8(bytes).map_err(|_| ClientError::InvalidRequest)?;
        let reply: PreparedReply = decode(
            &self
                .call("PrepareFullProfileV1", request, deadline, cancel)
                .await?,
        )?;
        version(reply.version)?;
        Ok(Prepared {
            handle: reply.handle,
            owner: self.owner.clone(),
            peer: self
                .connection
                .unique_name()
                .ok_or(ClientError::Unavailable)?
                .to_string(),
        })
    }
    /// Только проверенное переносимое намерение; native config и пути не принимаются.
    pub async fn prepare_profile(
        &mut self,
        server: &yonik_import::ServerIntent,
        engine: yonik_engine::Engine,
        kill_switch: bool,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<Prepared, ClientError> {
        self.prepare_profile_with_dns(server, engine, kill_switch, None, deadline, cancel)
            .await
    }

    /// Стенд системного DNS использует обычный admission Prepare и ApplyOutputV1.
    #[cfg(feature = "test-support")]
    pub async fn prepare_fake_dns_profile(
        &mut self,
        server: &yonik_import::ServerIntent,
        engine: yonik_engine::Engine,
        kill_switch: bool,
        domains: &[String],
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<Prepared, ClientError> {
        self.prepare_profile_with_dns(
            server,
            engine,
            kill_switch,
            Some(FakeDnsProfile {
                domains,
                policy: None,
            }),
            deadline,
            cancel,
        )
        .await
    }

    /// Системный Fake DNS для явно заданных суффиксов с проверяемой политикой.
    /// После Busy или Stale запрашивает новый Prepare в ограниченном окне.
    #[allow(clippy::too_many_arguments)] // Явные границы IPC и отмены.
    pub async fn prepare_fake_dns_policy_profile(
        &mut self,
        server: &yonik_import::ServerIntent,
        engine: yonik_engine::Engine,
        kill_switch: bool,
        domains: &[String],
        policy: &yonik_engine::policy_wire::SystemPolicy,
        deadline: Instant,
        mut cancel: Cancellation,
    ) -> Result<Prepared, ClientError> {
        let retry_window = Duration::from_secs(3);
        let mut retry_until = deadline.min(Instant::now() + retry_window);
        let mut saw_stale = false;
        loop {
            let result = self
                .prepare_profile_with_dns(
                    server,
                    engine,
                    kill_switch,
                    Some(FakeDnsProfile {
                        domains,
                        policy: Some(policy),
                    }),
                    deadline,
                    cancel.clone(),
                )
                .await;
            let now = Instant::now();
            if matches!(result, Err(ClientError::Stale)) && !saw_stale {
                // Первая проверка могла занять несколько секунд до смены сети.
                saw_stale = true;
                retry_until = deadline.min(now + retry_window);
            }
            if !matches!(result, Err(ClientError::Busy | ClientError::Stale)) || now >= retry_until
            {
                return result;
            }
            let retry_at = retry_until.min(now + Duration::from_millis(50));
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(ClientError::Cancelled),
                () = tokio::time::sleep_until(retry_at) => {}
            }
            if Instant::now() >= retry_until {
                return result;
            }
        }
    }

    async fn prepare_profile_with_dns(
        &mut self,
        server: &yonik_import::ServerIntent,
        engine: yonik_engine::Engine,
        kill_switch: bool,
        fake_dns: Option<FakeDnsProfile<'_>>,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<Prepared, ClientError> {
        #[derive(serde::Serialize)]
        struct Request<'a> {
            version: u32,
            mode: &'static str,
            engine: &'static str,
            kill_switch: bool,
            server: &'a yonik_import::ServerIntent,
            #[serde(skip_serializing_if = "Option::is_none")]
            fake_dns_domains: Option<&'a [String]>,
            #[serde(skip_serializing_if = "Option::is_none")]
            policy: Option<&'a yonik_engine::policy_wire::SystemPolicy>,
        }
        let request = serde_json::to_string(&Request {
            version: 1,
            mode: if fake_dns.is_some() {
                "system_profile_fake_dns"
            } else {
                "system_profile"
            },
            engine: match engine {
                yonik_engine::Engine::Xray => "xray",
                yonik_engine::Engine::SingBox => "sing-box",
            },
            kill_switch,
            server,
            fake_dns_domains: fake_dns.as_ref().map(|profile| profile.domains),
            policy: fake_dns.and_then(|profile| profile.policy),
        })
        .map_err(|_| ClientError::InvalidRequest)?;
        let reply: PreparedReply = decode(&self.call("Prepare", request, deadline, cancel).await?)?;
        version(reply.version)?;
        Ok(Prepared {
            handle: reply.handle,
            owner: self.owner.clone(),
            peer: self
                .connection
                .unique_name()
                .ok_or(ClientError::Unavailable)?
                .to_string(),
        })
    }
    /// Additive Prepare с закрытой проверенной переносимой policy.
    pub async fn prepare_profile_policy(
        &mut self,
        server: &yonik_import::ServerIntent,
        engine: yonik_engine::Engine,
        kill_switch: bool,
        policy: &yonik_engine::policy_wire::SystemPolicy,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<Prepared, ClientError> {
        #[derive(serde::Serialize)]
        struct Request<'a> {
            version: u32,
            mode: &'static str,
            engine: &'static str,
            kill_switch: bool,
            server: &'a yonik_import::ServerIntent,
            policy: &'a yonik_engine::policy_wire::SystemPolicy,
        }
        let request = serde_json::to_string(&Request {
            version: 1,
            mode: "system_profile_policy",
            engine: match engine {
                yonik_engine::Engine::Xray => "xray",
                yonik_engine::Engine::SingBox => "sing-box",
            },
            kill_switch,
            server,
            policy,
        })
        .map_err(|_| ClientError::InvalidRequest)?;
        let reply: PreparedReply = decode(&self.call("Prepare", request, deadline, cancel).await?)?;
        version(reply.version)?;
        Ok(Prepared {
            handle: reply.handle,
            owner: self.owner.clone(),
            peer: self
                .connection
                .unique_name()
                .ok_or(ClientError::Unavailable)?
                .to_string(),
        })
    }
    /// Синхронная проверка fence для снимков GUI между RPC.
    pub fn owner_lost(&self) -> bool {
        *self.lost.borrow() || self.lost.has_changed().is_err()
    }
    pub async fn bundle_capabilities(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<BundleCapabilities, ClientError> {
        let json = self
            .call(
                "BundleCapabilitiesV1",
                "{\"version\":1}".into(),
                deadline,
                cancel,
            )
            .await?;
        let reply: BundleCapabilities = decode(&json)?;
        version(reply.version)?;
        Ok(reply)
    }
    pub async fn prepare_bundle(
        &mut self,
        request: &crate::bundle_request::BundleRequest,
        resources: &[std::fs::File],
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<PreparedBundle, ClientError> {
        if resources.len() != request.canonical.len() {
            return Err(ClientError::InvalidRequest);
        }
        if !self
            .bundle_capabilities(deadline, cancel.clone())
            .await?
            .canonical_fd_transport
        {
            return Err(ClientError::Unsupported);
        }
        let intent = request.digest().map_err(|_| ClientError::InvalidRequest)?;
        let json = request.encode().map_err(|_| ClientError::InvalidRequest)?;
        let reply = self
            .call_with_resources("PrepareBundleV1", json, resources, deadline, cancel)
            .await?;
        let dto: BundlePreparedReply = decode(&reply)?;
        version(dto.version)?;
        if dto.intent_digest != intent {
            return Err(ClientError::Protocol);
        }
        Ok(PreparedBundle {
            prepared: Prepared {
                handle: dto.handle,
                owner: self.owner.clone(),
                peer: self
                    .connection
                    .unique_name()
                    .ok_or(ClientError::Unavailable)?
                    .to_string(),
            },
            intent_digest: intent,
            runtime_config_digest: dto.runtime_config_digest,
            runtime_bundle_digest: dto.runtime_bundle_digest,
        })
    }
    pub async fn apply_bundle(
        &mut self,
        prepared: PreparedBundle,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        self.apply(prepared.prepared, deadline, cancel).await
    }

    pub async fn apply(
        &mut self,
        prepared: Prepared,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        if prepared.owner != self.owner
            || Some(prepared.peer.as_str()) != self.connection.unique_name().map(|n| n.as_str())
        {
            return Err(ClientError::Stale);
        }
        let request = serde_json::json!({"version":1,"handle":prepared.handle}).to_string();
        self.state_call("Apply", request, deadline, cancel).await
    }
    async fn state_call(
        &mut self,
        method: &str,
        request: String,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        let reply: StateReply = decode(&self.call(method, request, deadline, cancel).await?)?;
        version(reply.version)?;
        Ok(reply.state)
    }
    pub async fn state(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        self.state_call("State", "{\"version\":1}".into(), deadline, cancel)
            .await
    }
    pub async fn stop(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        self.state_call("Stop", "{\"version\":1}".into(), deadline, cancel)
            .await
    }
    pub async fn unlock(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        self.state_call("Unlock", "{\"version\":1}".into(), deadline, cancel)
            .await
    }
}

/// Удобная граница по умолчанию для интерактивной авторизации.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(60);

pub mod output;

pub use output::PreparedOutput;
