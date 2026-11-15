//! Ограниченный versioned D-Bus transport: идентичность берётся только у daemon.

use std::{future::Future, sync::Arc, time::Duration};

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinSet,
};
use zbus::{MatchRule, Message, MessageStream, message::Type};

use super::{
    AuthorizationError, MAX_IN_FLIGHT, NetworkAction, PreparedArtifact, PreparedContext,
    PreparedError, PreparedHandle, PreparedRequests, Prompt,
};
use crate::Cancellation;

#[path = "service_peer.rs"]
mod peer_presence;
pub(crate) use peer_presence::BusPeerIdentity;
use peer_presence::PeerTracker;

pub const SERVICE_NAME: &str = "cloud.highpriority.yonik.Network1";
pub const SERVICE_PATH: &str = "/cloud/highpriority/yonik/Network";
pub const SERVICE_INTERFACE: &str = SERVICE_NAME;
const MAX_WIRE_BYTES: usize = 64 * 1024;
const INTROSPECTION: &str = r#"<node><interface name="cloud.highpriority.yonik.Network1"><method name="PrepareFullProfileV1"><arg name="request" type="s" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="Prepare"><arg name="request" type="s" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="ApplyOutputV1"><arg name="request" type="s" direction="in"/><arg name="output" type="ah" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="Apply"><arg name="request" type="s" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="Stop"><arg name="request" type="s" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="Unlock"><arg name="request" type="s" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="State"><arg name="request" type="s" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="Capabilities"><arg name="request" type="s" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="NativePrepareEligibilityV1"><arg name="request" type="s" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="BundleCapabilitiesV1"><arg name="request" type="s" direction="in"/><arg name="response" type="s" direction="out"/></method><method name="PrepareBundleV1"><arg name="request" type="s" direction="in"/><arg name="canonical" type="ah" direction="in"/><arg name="response" type="s" direction="out"/></method></interface><interface name="org.freedesktop.DBus.Introspectable"><method name="Introspect"><arg name="xml" type="s" direction="out"/></method></interface></node>"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    NoManagedPolicy,
    TunnelStarting,
    VerifiedRules,
    RecoveryRequired,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    InvalidRequest,
    Unsupported,
    Busy,
    Authorization(AuthorizationError),
    Prepared(PreparedError),
    Unavailable,
    Cancelled,
}
pub(super) const STOP_WAIT_BOUND: Duration = Duration::from_secs(30);
async fn wait_for_host<'a, H>(
    host: &'a Mutex<H>,
    cancel: &mut Cancellation,
    bound: Duration,
) -> Result<tokio::sync::MutexGuard<'a, H>, ServiceError> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(ServiceError::Cancelled),
        result = tokio::time::timeout(bound, host.lock()) => result.map_err(|_| ServiceError::Prepared(PreparedError::Timeout)),
    }
}
pub(super) fn busy_at(_stage: &str) -> ServiceError {
    #[cfg(test)]
    if std::env::var_os("YONIK_SESSION_DIAGNOSTICS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        eprintln!("session busy stage={_stage}");
    }
    ServiceError::Busy
}
impl From<PreparedError> for ServiceError {
    fn from(error: PreparedError) -> Self {
        Self::Prepared(error)
    }
}
impl From<AuthorizationError> for ServiceError {
    fn from(error: AuthorizationError) -> Self {
        Self::Authorization(error)
    }
}
impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ServiceError {}
impl ServiceError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unsupported | Self::Prepared(PreparedError::Unsupported) => "unsupported",
            Self::Busy | Self::Prepared(PreparedError::Capacity) => "busy",
            Self::Authorization(_) | Self::Prepared(PreparedError::Authorization(_)) => {
                "authorization"
            }
            Self::Prepared(PreparedError::InvalidHandle) => "invalid_handle",
            Self::Prepared(PreparedError::Stale) => "stale",
            Self::Prepared(PreparedError::Timeout) => "timeout",
            Self::Cancelled | Self::Prepared(PreparedError::Cancelled) => "cancelled",
            Self::Prepared(_) | Self::Unavailable => "unavailable",
        }
    }
}

/// Проверенные transport-поля; UID приходит только из доверенного D-Bus transport.
/// JSON разбирается закрытым bounded контрактом до создания этого значения.
pub struct SystemProfileRequest {
    pub server: yonik_import::ServerIntent,
    pub engine: yonik_engine::Engine,
    pub kill_switch: bool,
    pub policy: Option<yonik_engine::policy_wire::SystemPolicy>,
    pub(crate) peer: Option<Arc<crate::attribution::PeerProcess>>,
}
impl std::fmt::Debug for SystemProfileRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SystemProfileRequest(<скрыто>)")
    }
}

pub struct SystemBundleRequest {
    pub intent: crate::bundle_request::BundleRequest,
    pub files: Vec<std::fs::File>,
    pub(crate) owner: Option<String>,
    pub(crate) peer: Option<Arc<crate::attribution::PeerProcess>>,
}
#[derive(Clone, Copy)]
pub struct BundleDigests {
    pub intent: [u8; 32],
    pub config: [u8; 32],
    pub runtime: [u8; 32],
}
/// Единственный владелец привилегированных эффектов; dispatcher сериализует доступ.
pub trait ProtectionHost: Send + 'static {
    type Artifact: PreparedArtifact;
    fn native_prepare_eligibility(
        &mut self,
        cancel: Cancellation,
    ) -> impl Future<Output = Result<bool, ServiceError>> + Send {
        async move {
            cancel.check().map_err(|_| ServiceError::Cancelled)?;
            Ok(false)
        }
    }
    fn bundle_transport(&self) -> bool {
        false
    }
    fn prepare_bundle(
        &mut self,
        _uid: u32,
        _request: SystemBundleRequest,
        _cancel: Cancellation,
    ) -> impl Future<Output = Result<(Self::Artifact, PreparedContext), ServiceError>> + Send {
        async { Err(ServiceError::Unsupported) }
    }
    fn prepare(
        &mut self,
        uid: u32,
        allow_lan: bool,
        cancel: Cancellation,
    ) -> impl Future<Output = Result<(Self::Artifact, PreparedContext), ServiceError>> + Send;
    fn prepare_profile(
        &mut self,
        _uid: u32,
        _request: SystemProfileRequest,
        _cancel: Cancellation,
    ) -> impl Future<Output = Result<(Self::Artifact, PreparedContext), ServiceError>> + Send {
        async { Err(ServiceError::Unsupported) }
    }
    fn context(&self, uid: u32) -> Result<PreparedContext, ServiceError>;
    fn apply(
        &mut self,
        uid: u32,
        artifact: &Self::Artifact,
        cancel: Cancellation,
    ) -> impl Future<Output = Result<ProtectionState, ServiceError>> + Send;
    fn apply_output(
        &mut self,
        _uid: u32,
        _artifact: &Self::Artifact,
        _output: crate::output_transport::ValidatedWriters,
        _cancel: Cancellation,
    ) -> impl Future<Output = Result<ProtectionState, ServiceError>> + Send {
        async { Err(ServiceError::Unsupported) }
    }
    fn stop(
        &mut self,
        uid: u32,
        cancel: Cancellation,
    ) -> impl Future<Output = Result<ProtectionState, ServiceError>> + Send;
    fn unlock(
        &mut self,
        uid: u32,
        cancel: Cancellation,
    ) -> impl Future<Output = Result<ProtectionState, ServiceError>> + Send;
    fn state(
        &mut self,
        uid: u32,
        cancel: Cancellation,
    ) -> impl Future<Output = Result<ProtectionState, ServiceError>> + Send;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    version: u32,
    mode: String,
    allow_lan: bool,
}
// Первый проход выбирает только закрытую схему; второй запрещает все лишние поля.
#[derive(Deserialize)]
struct PrepareRoute {
    version: u32,
    mode: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ProfileEngine {
    Xray,
    SingBox,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfilePrepareRequest<'a> {
    version: u32,
    mode: String,
    engine: ProfileEngine,
    kill_switch: bool,
    #[serde(borrow)]
    server: &'a serde_json::value::RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyProfilePrepareRequest<'a> {
    version: u32,
    mode: String,
    engine: ProfileEngine,
    kill_switch: bool,
    #[serde(borrow)]
    server: &'a serde_json::value::RawValue,
    #[serde(borrow)]
    policy: &'a serde_json::value::RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    version: u32,
    handle: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {
    version: u32,
}

enum Request {
    PrepareFullProfile(Box<super::profile_intent::FullProfileRequest>),
    Prepare(bool),
    PrepareProfile(Box<SystemProfileRequest>),
    PrepareBundle(Box<SystemBundleRequest>),
    NativePrepareEligibility,
    BundleCapabilities,
    Apply(PreparedHandle),
    ApplyOutput(PreparedHandle, crate::output_transport::ValidatedWriters),
    Stop,
    Unlock,
    State,
    Capabilities,
    Introspect,
}
fn parse(message: &Message) -> Result<Request, ServiceError> {
    let header = message.header();
    if header.path().map(|v| v.as_str()) == Some(SERVICE_PATH)
        && header.interface().map(|v| v.as_str()) == Some("org.freedesktop.DBus.Introspectable")
        && header.member().map(|v| v.as_str()) == Some("Introspect")
        && message.body().is_empty()
    {
        return Ok(Request::Introspect);
    }
    if header.path().map(|v| v.as_str()) != Some(SERVICE_PATH)
        || header.interface().map(|v| v.as_str()) != Some(SERVICE_INTERFACE)
        || message.body().len() > MAX_WIRE_BYTES
    {
        return Err(ServiceError::InvalidRequest);
    }
    if header.member().map(|m| m.as_str()) == Some("ApplyOutputV1") {
        let decoded = crate::output_transport::decode(message.clone())
            .map_err(|_| ServiceError::InvalidRequest)?;
        let handle = PreparedHandle::try_from(decoded.handle.as_slice())
            .map_err(|_| ServiceError::InvalidRequest)?;
        return Ok(Request::ApplyOutput(handle, decoded.writers));
    }
    let body = message.body();
    if header.member().map(|m| m.as_str()) == Some("PrepareFullProfileV1") {
        if header.unix_fds().unwrap_or(0) != 0
            || body.signature().as_ref().map(|s| s.as_str()) != Some("s")
        {
            return Err(ServiceError::InvalidRequest);
        }
        let (wire,): (&str,) = body
            .deserialize()
            .map_err(|_| ServiceError::InvalidRequest)?;
        return Ok(Request::PrepareFullProfile(Box::new(
            super::profile_intent::FullProfileRequest::decode(wire)?,
        )));
    }
    if header.member().map(|m| m.as_str()) == Some("PrepareBundleV1") {
        if body.signature().as_ref().map(|s| s.as_str()) != Some("sah") {
            return Err(ServiceError::InvalidRequest);
        }
        let declared = header.unix_fds().unwrap_or(0) as usize;
        if declared == 0 || declared > 16 {
            return Err(ServiceError::InvalidRequest);
        }
        // Borrowed handles не дублируют FD до проверки bounded count/unique roles.
        let (json, fds): (&str, Vec<zbus::zvariant::Fd<'_>>) = body
            .deserialize()
            .map_err(|_| ServiceError::InvalidRequest)?;
        if fds.len() != declared {
            return Err(ServiceError::InvalidRequest);
        }
        use std::os::fd::{AsFd, AsRawFd};
        let mut roles = std::collections::HashSet::new();
        if fds.iter().any(|fd| !roles.insert(fd.as_raw_fd())) {
            return Err(ServiceError::InvalidRequest);
        }
        let intent = crate::bundle_request::BundleRequest::parse(json, fds.len())
            .map_err(|_| ServiceError::InvalidRequest)?;
        let files = fds
            .into_iter()
            .map(|fd| fd.as_fd().try_clone_to_owned().map(std::fs::File::from))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| ServiceError::Unavailable)?;
        return Ok(Request::PrepareBundle(Box::new(SystemBundleRequest {
            intent,
            files,
            owner: None,
            peer: None,
        })));
    }
    let (json,): (&str,) = body
        .deserialize()
        .map_err(|_| ServiceError::InvalidRequest)?;
    match header.member().map(|v| v.as_str()) {
        Some("Prepare") => {
            let route: PrepareRoute =
                serde_json::from_str(json).map_err(|_| ServiceError::InvalidRequest)?;
            if route.version != 1 {
                return Err(ServiceError::InvalidRequest);
            }
            match route.mode.as_str() {
                "public_protection" => {
                    let dto: PrepareRequest =
                        serde_json::from_str(json).map_err(|_| ServiceError::InvalidRequest)?;
                    if dto.version != 1 || dto.mode != "public_protection" {
                        return Err(ServiceError::InvalidRequest);
                    }
                    if dto.allow_lan {
                        return Err(ServiceError::Unsupported);
                    }
                    Ok(Request::Prepare(dto.allow_lan))
                }
                "system_profile" | "system_profile_policy" => {
                    let (dto, policy) = if route.mode == "system_profile_policy" {
                        if !yonik_engine::policy_wire::bounded_depth(json, 6)
                            || !json.trim_start().starts_with('{')
                        {
                            return Err(ServiceError::InvalidRequest);
                        }
                        let dto: PolicyProfilePrepareRequest<'_> =
                            serde_json::from_str(json).map_err(|_| ServiceError::InvalidRequest)?;
                        let policy =
                            yonik_engine::policy_wire::SystemPolicy::parse(dto.policy.get())
                                .map_err(|_| ServiceError::InvalidRequest)?;
                        (
                            ProfilePrepareRequest {
                                version: dto.version,
                                mode: dto.mode,
                                engine: dto.engine,
                                kill_switch: dto.kill_switch,
                                server: dto.server,
                            },
                            Some(policy),
                        )
                    } else {
                        let dto: ProfilePrepareRequest<'_> =
                            serde_json::from_str(json).map_err(|_| ServiceError::InvalidRequest)?;
                        (dto, None)
                    };
                    let dto: ProfilePrepareRequest<'_> = dto;
                    if dto.version != 1 || dto.mode != route.mode {
                        return Err(ServiceError::InvalidRequest);
                    }
                    let server = yonik_import::ServerIntent::parse_json(dto.server.get()).map_err(
                        |error| match error {
                            yonik_import::IntentError::Unsupported => ServiceError::Unsupported,
                            _ => ServiceError::InvalidRequest,
                        },
                    )?;
                    let engine = match dto.engine {
                        ProfileEngine::Xray => yonik_engine::Engine::Xray,
                        ProfileEngine::SingBox => yonik_engine::Engine::SingBox,
                    };
                    Ok(Request::PrepareProfile(Box::new(SystemProfileRequest {
                        server,
                        engine,
                        kill_switch: dto.kill_switch,
                        policy,
                        peer: None,
                    })))
                }
                _ => Err(ServiceError::Unsupported),
            }
        }
        Some("Apply") => {
            let dto: ApplyRequest =
                serde_json::from_str(json).map_err(|_| ServiceError::InvalidRequest)?;
            if dto.version != 1 {
                return Err(ServiceError::InvalidRequest);
            }
            Ok(Request::Apply(PreparedHandle::try_from(
                dto.handle.as_slice(),
            )?))
        }
        Some(member) => {
            let dto: EmptyRequest =
                serde_json::from_str(json).map_err(|_| ServiceError::InvalidRequest)?;
            if dto.version != 1 {
                return Err(ServiceError::InvalidRequest);
            }
            match member {
                "Stop" => Ok(Request::Stop),
                "Unlock" => Ok(Request::Unlock),
                "State" => Ok(Request::State),
                "Capabilities" => Ok(Request::Capabilities),
                "NativePrepareEligibilityV1" if header.unix_fds().unwrap_or(0) == 0 => {
                    Ok(Request::NativePrepareEligibility)
                }
                "BundleCapabilitiesV1" if header.unix_fds().unwrap_or(0) == 0 => {
                    Ok(Request::BundleCapabilities)
                }
                _ => Err(ServiceError::Unsupported),
            }
        }
        None => Err(ServiceError::InvalidRequest),
    }
}

pub async fn run_system_service(
    host: impl ProtectionHost,
    cancel: Cancellation,
) -> Result<(), ServiceError> {
    let broker = PreparedRequests::system(cancel.clone()).await?;
    serve_with_broker(host, broker, cancel).await
}

pub(super) async fn serve_with_broker<H: ProtectionHost>(
    host: H,
    broker: PreparedRequests<H::Artifact>,
    mut cancel: Cancellation,
) -> Result<(), ServiceError> {
    let broker = Arc::new(broker);
    let peers = Arc::new(PeerTracker::default());
    let connection = broker.connection().clone();
    let mut calls = MessageStream::from(&connection);
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender("org.freedesktop.DBus")
        .map_err(|_| ServiceError::Unavailable)?
        .interface("org.freedesktop.DBus")
        .map_err(|_| ServiceError::Unavailable)?
        .path("/org/freedesktop/DBus")
        .map_err(|_| ServiceError::Unavailable)?
        .member("NameOwnerChanged")
        .map_err(|_| ServiceError::Unavailable)?
        .build();
    let mut changes = MessageStream::for_match_rule(rule, &connection, Some(64))
        .await
        .map_err(|_| ServiceError::Unavailable)?;
    connection
        .request_name(SERVICE_NAME)
        .await
        .map_err(|_| ServiceError::Unavailable)?;
    let host = Arc::new(Mutex::new(host));
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let (stop, worker_cancel) = Cancellation::new();
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Ok(()),
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            changed = changes.next() => match changed {
                Some(Ok(message)) => if let Err(error) = forget_disconnected(&broker, &peers, &message) { break Err(error); },
                _ => break Err(ServiceError::Unavailable),
            },
            call = calls.next() => {
                let message = match call { Some(Ok(message)) => message, _ => break Err(ServiceError::Unavailable) };
                if message.header().message_type() != Type::MethodCall { continue; }
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => { send_result(&connection, &message, Err(busy_at("rpc_in_flight_capacity"))).await; continue; }
                };
                let broker = broker.clone(); let host = host.clone(); let peers=Arc::clone(&peers); let child_cancel = worker_cancel.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = dispatch(&broker, &host, &peers, &message, child_cancel).await;
                    send_result(broker.connection(), &message, result).await;
                });
            }
        }
    };
    peers.revoke_all();
    let _ = stop.send(true);
    while tasks.join_next().await.is_some() {}
    let _ = connection.release_name(SERVICE_NAME).await;
    result
}

fn forget_disconnected<A: PreparedArtifact>(
    broker: &PreparedRequests<A>,
    peers: &PeerTracker,
    message: &Message,
) -> Result<(), ServiceError> {
    let h = message.header();
    if h.message_type() != Type::Signal
        || h.sender().map(|v| v.as_str()) != Some("org.freedesktop.DBus")
        || h.path().map(|v| v.as_str()) != Some("/org/freedesktop/DBus")
        || h.interface().map(|v| v.as_str()) != Some("org.freedesktop.DBus")
        || h.member().map(|v| v.as_str()) != Some("NameOwnerChanged")
    {
        return Ok(());
    }
    let body = message.body();
    let (name, old, new): (&str, &str, &str) = body
        .deserialize()
        .map_err(|_| ServiceError::InvalidRequest)?;
    if name.starts_with(':') && name == old && new.is_empty() {
        peers.revoke(name)?;
        broker.forget_peer(name)?;
    }
    Ok(())
}

async fn dispatch<H: ProtectionHost>(
    broker: &PreparedRequests<H::Artifact>,
    host: &Mutex<H>,
    peers: &PeerTracker,
    message: &Message,
    mut cancel: Cancellation,
) -> Result<String, ServiceError> {
    let request = parse(message)?;
    let sender = super::sender(message)?;
    let uid = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(ServiceError::Cancelled),
        result = tokio::time::timeout(Duration::from_secs(5), broker.authorizer().uid(&sender)) =>
            result.map_err(|_| ServiceError::Unavailable)??,
    };
    let value = match request {
        Request::PrepareFullProfile(request) => {
            return deny_unadmitted_full_profile(&request, &cancel);
        }
        Request::Introspect => return Ok(INTROSPECTION.to_owned()),
        Request::Capabilities => {
            serde_json::json!({"version":1,"public_protection":true,"system_tun":false,"allow_lan":false})
        }
        Request::NativePrepareEligibility => {
            cancel.check().map_err(|_| ServiceError::Cancelled)?;
            let _presence = peers.track(&sender, uid)?;
            let mut host = host.try_lock().map_err(|_| ServiceError::Busy)?;
            let eligible = host.native_prepare_eligibility(cancel.clone()).await?;
            cancel.check().map_err(|_| ServiceError::Cancelled)?;
            if tokio::time::timeout(Duration::from_secs(1), broker.authorizer().uid(&sender))
                .await
                .map_err(|_| ServiceError::Unavailable)??
                != uid
            {
                return Err(ServiceError::Unavailable);
            }
            serde_json::json!({"version":1,"can_prepare_attribution":eligible})
        }
        Request::BundleCapabilities => {
            let host = host.try_lock().map_err(|_| ServiceError::Busy)?;
            serde_json::json!({"version":1,"canonical_fd_transport":host.bundle_transport()})
        }
        Request::PrepareBundle(mut request) => {
            let mut identities = None;
            let handle = broker
                .prepare(message, Prompt::Allow, cancel.clone(), || async {
                    let mut host = host.try_lock().map_err(|_| PreparedError::Capacity)?;
                    if !host.bundle_transport() {
                        return Err(PreparedError::Unsupported);
                    }
                    let presence = peers.track(&sender, uid)?;
                    let pid = tokio::time::timeout(
                        Duration::from_secs(1),
                        broker.authorizer().peer_pid(&sender, uid),
                    )
                    .await
                    .map_err(|_| PreparedError::Unsupported)??;
                    request.owner = Some(sender.to_string());
                    request.peer = Some(Arc::new(crate::attribution::PeerProcess::pending(
                        crate::attribution::CapturedBusPeer::capture(presence.bind(pid)?)
                            .map_err(|_| PreparedError::Unsupported)?,
                    )));
                    let (artifact, context) = host
                        .prepare_bundle(uid, *request, cancel.clone())
                        .await
                        .map_err(as_prepared)?;
                    identities = artifact.bundle_digests();
                    if identities.is_none() {
                        return Err(PreparedError::Unsupported);
                    }
                    Ok((artifact, context))
                })
                .await?;
            let identities = identities.ok_or(ServiceError::Unavailable)?;
            serde_json::json!({"version":1,"handle":handle.as_bytes(),"intent_digest":identities.intent,"runtime_config_digest":identities.config,"runtime_bundle_digest":identities.runtime})
        }
        Request::Prepare(allow_lan) => {
            let handle = broker
                .prepare(message, Prompt::Allow, cancel.clone(), || async {
                    let mut host = host.try_lock().map_err(|_| {
                        let _ = busy_at("prepare_outer_host");
                        PreparedError::Capacity
                    })?;
                    host.prepare(uid, allow_lan, cancel.clone())
                        .await
                        .map_err(as_prepared)
                })
                .await?;
            serde_json::json!({"version":1,"handle":handle.as_bytes()})
        }
        Request::PrepareProfile(mut request) => {
            let handle = broker
                .prepare(message, Prompt::Allow, cancel.clone(), || async {
                    let mut host = host.try_lock().map_err(|_| {
                        let _ = busy_at("prepare_outer_host");
                        PreparedError::Capacity
                    })?;
                    if request
                        .policy
                        .as_ref()
                        .is_some_and(|policy| policy.requires_attribution())
                    {
                        let presence = peers.track(&sender, uid)?;
                        let pid = tokio::time::timeout(
                            Duration::from_secs(1),
                            broker.authorizer().peer_pid(&sender, uid),
                        )
                        .await
                        .map_err(|_| PreparedError::Unsupported)??;
                        request.peer = Some(Arc::new(crate::attribution::PeerProcess::pending(
                            crate::attribution::CapturedBusPeer::capture(presence.bind(pid)?)
                                .map_err(|_| PreparedError::Unsupported)?,
                        )));
                    }
                    host.prepare_profile(uid, *request, cancel.clone())
                        .await
                        .map_err(as_prepared)
                })
                .await?;
            serde_json::json!({"version":1,"handle":handle.as_bytes()})
        }
        Request::Apply(handle) | Request::ApplyOutput(handle, _) => {
            let output = match request {
                Request::ApplyOutput(_, writers) => Some(writers),
                _ => None,
            };
            let mut guard = None;
            let artifact = broker
                .claim_for_apply(message, handle, Prompt::Allow, cancel.clone(), || {
                    let locked = host.try_lock().map_err(|_| {
                        let _ = busy_at("apply_outer_host");
                        PreparedError::Capacity
                    })?;
                    let context = locked.context(uid).map_err(as_prepared)?;
                    guard = Some(locked);
                    Ok(context)
                })
                .await?;
            let mut host = guard.ok_or(ServiceError::Unavailable)?;
            let state = if let Some(output) = output {
                host.apply_output(uid, artifact.as_ref(), output, cancel)
                    .await?
            } else {
                host.apply(uid, artifact.as_ref(), cancel).await?
            };
            serde_json::json!({"version":1,"state":state})
        }
        Request::State => {
            let mut host = host.try_lock().map_err(|_| busy_at("state_outer_host"))?;
            let state = host.state(uid, cancel).await?;
            serde_json::json!({"version":1,"state":state})
        }
        Request::Stop | Request::Unlock => {
            let action = if matches!(request, Request::Unlock) {
                NetworkAction::UnlockNetwork
            } else {
                NetworkAction::ManageNetwork
            };
            let peer = broker
                .authorizer()
                .authorize(message, action, Prompt::Allow, cancel.clone())
                .await?;
            if peer.uid() != uid {
                return Err(ServiceError::Authorization(AuthorizationError::PeerGone));
            }
            let mut host = wait_for_host(host, &mut cancel, STOP_WAIT_BOUND).await?;
            let state = if matches!(request, Request::Unlock) {
                host.unlock(uid, cancel).await?
            } else {
                host.stop(uid, cancel).await?
            };
            serde_json::json!({"version":1,"state":state})
        }
    };
    let json = serde_json::to_string(&value).map_err(|_| ServiceError::Unavailable)?;
    if json.len() > MAX_WIRE_BYTES {
        return Err(ServiceError::Unavailable);
    }
    Ok(json)
}
fn as_prepared(error: ServiceError) -> PreparedError {
    match error {
        ServiceError::Prepared(error) => error,
        ServiceError::Authorization(error) => PreparedError::Authorization(error),
        ServiceError::Busy => PreparedError::Capacity,
        ServiceError::Unsupported => PreparedError::Unsupported,
        ServiceError::Cancelled => PreparedError::Cancelled,
        _ => PreparedError::Unavailable,
    }
}
fn deny_unadmitted_full_profile(
    request: &super::profile_intent::FullProfileRequest,
    cancel: &Cancellation,
) -> Result<String, ServiceError> {
    request.preflight(cancel)?;
    // Native carrier и delivery source pins ещё не подключены. Никакого handle.
    Err(ServiceError::Unsupported)
}

#[cfg(test)]
mod full_profile_codec_tests {
    use super::*;
    fn frame() -> String {
        let wire=serde_json::json!({"version":1,"graph":{"outbounds":[{"tag":"direct","protocol":"freedom"}]}}).to_string();
        let intent = yonik_engine::native_profile::ProfileIntent::decode(&wire).unwrap();
        let request =
            crate::helper::profile_intent::FullProfileRequest::new(intent, 1, [3; 32], true)
                .unwrap();
        let mut bytes = Vec::new();
        request.write_sensitive(&mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    }
    fn message(wire: &str) -> Message {
        Message::method(SERVICE_PATH, "PrepareFullProfileV1")
            .unwrap()
            .interface(SERVICE_INTERFACE)
            .unwrap()
            .build(&(wire,))
            .unwrap()
    }
    #[test]
    fn versioned_parse_revalidates_closed_graph_without_native_authority() {
        let wire = frame();
        let Request::PrepareFullProfile(request) = parse(&message(&wire)).unwrap() else {
            panic!("typed branch")
        };
        let (_keep, cancel) = Cancellation::new();
        assert!(request.preflight(&cancel).is_ok());
        assert_eq!(
            deny_unadmitted_full_profile(&request, &cancel),
            Err(ServiceError::Unsupported)
        );
        let mut value: serde_json::Value = serde_json::from_str(&wire).unwrap();
        value["intent"]["graph"]["outbounds"][0]["settings"] =
            serde_json::json!({"path":"/tmp/denied"});
        assert!(parse(&message(&value.to_string())).is_err());
        assert!(parse(&message(&wire.replacen("{", "{\"uid\":0,", 1))).is_err());
        assert!(parse(&message(&wire.replacen("{", "{\"version\":1,", 1))).is_err());
        assert!(parse(&message(&" ".repeat(MAX_WIRE_BYTES))).is_err());
    }
}
async fn send_result(
    connection: &zbus::Connection,
    message: &Message,
    result: Result<String, ServiceError>,
) {
    let operation = async {
        match result {
            Ok(json) => connection.reply(message, &(json,)).await,
            Err(error) => {
                let json = serde_json::json!({"version":1,"error":error.code()}).to_string();
                connection
                    .reply_error(message, "cloud.highpriority.yonik.Network1.Error", &(json,))
                    .await
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), operation).await;
}

#[cfg(test)]
#[path = "service_tests.rs"]
pub(super) mod tests;

// Typed decode boundary не включён в parse/dispatch или D-Bus introspection.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
struct StagedApplyOutput {
    _handle: PreparedHandle,
    _writers: crate::output_transport::ValidatedWriters,
}
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
fn decode_staged_output(message: Message) -> Result<StagedApplyOutput, ServiceError> {
    let decoded =
        crate::output_transport::decode(message).map_err(|_| ServiceError::InvalidRequest)?;
    let handle = PreparedHandle::try_from(decoded.handle.as_slice())
        .map_err(|_| ServiceError::InvalidRequest)?;
    Ok(StagedApplyOutput {
        _handle: handle,
        _writers: decoded.writers,
    })
}
