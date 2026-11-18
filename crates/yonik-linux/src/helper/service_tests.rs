use super::*;
use crate::helper::{MAX_CHECKS, PeerAuthorizer};
use std::{
    collections::HashMap,
    num::NonZeroU64,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::watch;
use yonik_application::{ConfigDigest, EnvironmentStamp};

struct PrivateBus {
    child: std::process::Child,
    address: String,
}
impl PrivateBus {
    fn start() -> Self {
        use std::io::BufRead;
        let mut child = std::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self {
            child,
            address: address.trim().to_owned(),
        }
    }
    async fn connect(&self) -> zbus::Connection {
        super::super::output_bus::builder(
            tokio::net::UnixStream::connect(
                self.address
                    .strip_prefix("unix:path=")
                    .unwrap()
                    .split(',')
                    .next()
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .unwrap()
        .build()
        .await
        .unwrap()
    }
}
impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
struct Artifact;
impl PreparedArtifact for Artifact {
    fn current_digest(&self) -> ConfigDigest {
        ConfigDigest::new([7; 32])
    }
    fn byte_len(&self) -> usize {
        6
    }
    fn retained_bytes(&self) -> usize {
        6
    }
}
struct Host {
    effects: Arc<AtomicUsize>,
    profile_prepares: Arc<AtomicUsize>,
    generation: Arc<AtomicUsize>,
}
impl ProtectionHost for Host {
    type Artifact = Artifact;
    async fn prepare(
        &mut self,
        _: u32,
        _: bool,
        _: Cancellation,
    ) -> Result<(Artifact, PreparedContext), ServiceError> {
        Ok((Artifact, self.context(0)?))
    }
    async fn prepare_profile(
        &mut self,
        uid: u32,
        request: SystemProfileRequest,
        _: Cancellation,
    ) -> Result<(Artifact, PreparedContext), ServiceError> {
        assert_eq!(uid, rustix::process::getuid().as_raw());
        assert_eq!(request.engine, yonik_engine::Engine::Xray);
        assert!(request.kill_switch);
        let server = request.server.into_server().unwrap();
        assert_eq!(server.endpoint().host(), "192.0.2.1");
        self.profile_prepares.fetch_add(1, Ordering::SeqCst);
        Ok((Artifact, self.context(uid)?))
    }
    fn context(&self, _: u32) -> Result<PreparedContext, ServiceError> {
        Ok(PreparedContext::new(
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(self.generation.load(Ordering::SeqCst) as u64).unwrap(),
            EnvironmentStamp {
                network: 1,
                applications: 1,
                authorization: 1,
                engine: 1,
                authorized: true,
            },
        )?)
    }
    async fn apply_output(
        &mut self,
        uid: u32,
        artifact: &Artifact,
        _output: crate::output_transport::ValidatedWriters,
        cancel: Cancellation,
    ) -> Result<ProtectionState, ServiceError> {
        self.apply(uid, artifact, cancel).await
    }
    async fn apply(
        &mut self,
        _: u32,
        _: &Artifact,
        _: Cancellation,
    ) -> Result<ProtectionState, ServiceError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(ProtectionState::VerifiedRules)
    }
    async fn stop(&mut self, _: u32, _: Cancellation) -> Result<ProtectionState, ServiceError> {
        Ok(ProtectionState::VerifiedRules)
    }
    async fn unlock(&mut self, _: u32, _: Cancellation) -> Result<ProtectionState, ServiceError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(ProtectionState::NoManagedPolicy)
    }
    async fn state(&mut self, _: u32, _: Cancellation) -> Result<ProtectionState, ServiceError> {
        Ok(ProtectionState::Unknown)
    }
}
pub(in crate::helper) struct Fixture {
    _bus: PrivateBus,
    peer: zbus::Connection,
    stop: watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), ServiceError>>,
    auth_stop: watch::Sender<bool>,
    auth: tokio::task::JoinHandle<()>,
    checks: Arc<AtomicUsize>,
    effects: Arc<AtomicUsize>,
    allowed: Arc<AtomicBool>,
    challenge: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    gate: Arc<Semaphore>,
    generation: Arc<AtomicUsize>,
    actions: Arc<std::sync::Mutex<Vec<String>>>,
}
impl Fixture {
    async fn new() -> Self {
        let effects = Arc::new(AtomicUsize::new(0));
        let generation = Arc::new(AtomicUsize::new(1));
        let host = Host {
            effects: effects.clone(),
            profile_prepares: Arc::new(AtomicUsize::new(0)),
            generation: generation.clone(),
        };
        Self::with_host(host, effects, generation).await
    }
    pub(in crate::helper) async fn real_host(host: impl ProtectionHost) -> Self {
        Self::with_host(
            host,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(1)),
        )
        .await
    }
    async fn with_host<H: ProtectionHost>(
        host: H,
        effects: Arc<AtomicUsize>,
        generation: Arc<AtomicUsize>,
    ) -> Self {
        let bus = PrivateBus::start();
        let connection = bus.connect().await;
        let peer = bus.connect().await;
        let authority = bus.connect().await;
        authority
            .request_name(crate::helper::AUTHORITY)
            .await
            .unwrap();
        let mut stream = MessageStream::from(&authority);
        let checks = Arc::new(AtomicUsize::new(0));
        let allowed = Arc::new(AtomicBool::new(true));
        let challenge = Arc::new(AtomicBool::new(false));
        let actions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pause = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(Semaphore::new(0));
        let paused = pause.clone();
        let wait = gate.clone();
        let (auth_stop, mut auth_cancel) = Cancellation::new();
        let ac = checks.clone();
        let aa = allowed.clone();
        let ach = challenge.clone();
        let actions_copy = actions.clone();
        let auth = tokio::spawn(async move {
            loop {
                tokio::select! { _=auth_cancel.cancelled()=>break, message=stream.next()=> {
                    let Some(Ok(message))=message else {break};
                    if message.header().message_type()!=Type::MethodCall {continue;}
                    if message.header().member().map(|v|v.as_str())==Some("CheckAuthorization") {
                        type Subject=(String,HashMap<String,zbus::zvariant::OwnedValue>);
                        let (_,action,_,_,_):(Subject,String,HashMap<String,String>,u32,String)=message.body().deserialize().unwrap();
                        actions_copy.lock().unwrap().push(action);
                        ac.fetch_add(1,Ordering::SeqCst);
                        if paused.load(Ordering::SeqCst) { let permit=wait.acquire().await.unwrap(); permit.forget(); }
                        authority.reply(&message,&((aa.load(Ordering::SeqCst),ach.load(Ordering::SeqCst),HashMap::<&str,&str>::new()),)).await.unwrap();
                    }
                } }
            }
        });
        let authorizer = PeerAuthorizer {
            connection,
            expected_authority_uid: rustix::process::getuid().as_raw(),
            checks: Semaphore::new(MAX_CHECKS),
            noninteractive_timeout: Duration::from_secs(5),
            interactive_timeout: Duration::from_secs(5),
        };
        let broker = PreparedRequests::with_authorizer(authorizer).unwrap();
        let (stop, cancel) = Cancellation::new();
        let server = tokio::spawn(serve_with_broker(host, broker, cancel));
        // Барьер готовности через daemon, не фиксированная задержка.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if peer
                    .call_method(
                        Some("org.freedesktop.DBus"),
                        "/org/freedesktop/DBus",
                        Some("org.freedesktop.DBus"),
                        "GetNameOwner",
                        &(SERVICE_NAME,),
                    )
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        Self {
            _bus: bus,
            peer,
            stop,
            server,
            auth_stop,
            auth,
            checks,
            effects,
            allowed,
            challenge,
            pause,
            gate,
            generation,
            actions,
        }
    }
    pub(in crate::helper) async fn call(
        &self,
        member: &str,
        json: &str,
    ) -> Result<serde_json::Value, zbus::Error> {
        let reply = self
            .peer
            .call_method(
                Some(SERVICE_NAME),
                SERVICE_PATH,
                Some(SERVICE_INTERFACE),
                member,
                &(json,),
            )
            .await?;
        let (json,): (String,) = reply.body().deserialize()?;
        Ok(serde_json::from_str(&json).unwrap())
    }
    pub(in crate::helper) fn check_count(&self) -> usize {
        self.checks.load(Ordering::SeqCst)
    }
    pub(in crate::helper) async fn shutdown(self) {
        self.stop.send(true).unwrap();
        self.server.await.unwrap().unwrap();
        self.auth_stop.send(true).unwrap();
        self.auth.await.unwrap();
    }
}
#[tokio::test]
async fn real_bus_prepare_apply_replay_and_unlock_action() {
    let f = Fixture::new().await;
    let eligibility = f
        .call("NativePrepareEligibilityV1", r#"{"version":1}"#)
        .await
        .unwrap();
    assert_eq!(
        eligibility,
        serde_json::json!({"version":1,"can_prepare_attribution":false})
    );
    let capabilities = f.call("Capabilities", r#"{"version":1}"#).await.unwrap();
    assert_eq!(capabilities["system_tun"], false);
    assert_eq!(capabilities["allow_lan"], false);
    assert_eq!(capabilities["public_protection"], true);
    let xml = f
        .peer
        .call_method(
            Some(SERVICE_NAME),
            SERVICE_PATH,
            Some("org.freedesktop.DBus.Introspectable"),
            "Introspect",
            &(),
        )
        .await
        .unwrap();
    let (xml,): (String,) = xml.body().deserialize().unwrap();
    assert!(xml.contains("method name=\"Apply\""));

    let result = f
        .call(
            "Prepare",
            r#"{"version":1,"mode":"public_protection","allow_lan":false}"#,
        )
        .await
        .unwrap();
    assert_eq!(f.checks.load(Ordering::SeqCst), 1);
    let request = serde_json::json!({"version":1,"handle":result["handle"]}).to_string();
    assert_eq!(
        f.call("Apply", &request).await.unwrap()["state"],
        "verified_rules"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert!(f.call("Apply", &request).await.is_err());
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.call("Stop", r#"{"version":1}"#).await.unwrap()["state"],
        "verified_rules"
    );
    f.call("Unlock", r#"{"version":1}"#).await.unwrap();
    assert_eq!(f.effects.load(Ordering::SeqCst), 2);
    assert_eq!(
        f.actions.lock().unwrap().last().unwrap(),
        crate::helper::NetworkAction::UnlockNetwork.id()
    );
    assert_eq!(f.checks.load(Ordering::SeqCst), 5);
    f.shutdown().await;
}
#[tokio::test]
async fn invalid_denied_challenged_stale_and_wrong_peer_have_no_effect() {
    let f = Fixture::new().await;
    for json in [
        r#"{"version":2,"mode":"public_protection","allow_lan":false}"#,
        r#"{"version":1,"mode":"public_protection","allow_lan":false,"uid":0}"#,
        r#"{"version":1,"mode":"public_protection","allow_lan":true}"#,
    ] {
        assert!(f.call("Prepare", json).await.is_err());
    }
    assert!(
        f.peer
            .call_method(
                Some(SERVICE_NAME),
                SERVICE_PATH,
                Some(SERVICE_INTERFACE),
                "Prepare",
                &(123u32,)
            )
            .await
            .is_err()
    );
    assert_eq!(f.checks.load(Ordering::SeqCst), 0);
    let prep = r#"{"version":1,"mode":"public_protection","allow_lan":false}"#;
    f.allowed.store(false, Ordering::SeqCst);
    assert!(f.call("Prepare", prep).await.is_err());
    f.challenge.store(true, Ordering::SeqCst);
    assert!(f.call("Prepare", prep).await.is_err());
    f.allowed.store(true, Ordering::SeqCst);
    f.challenge.store(false, Ordering::SeqCst);
    let value = f.call("Prepare", prep).await.unwrap();
    let apply = serde_json::json!({"version":1,"handle":value["handle"]}).to_string();
    let other = f._bus.connect().await;
    assert!(
        other
            .call_method(
                Some(SERVICE_NAME),
                SERVICE_PATH,
                Some(SERVICE_INTERFACE),
                "Apply",
                &(apply.as_str(),)
            )
            .await
            .is_err()
    );
    f.generation.store(2, Ordering::SeqCst);
    assert!(f.call("Apply", &apply).await.is_err());
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    f.shutdown().await;
}

#[tokio::test]
async fn pending_authorization_does_not_lock_host_state() {
    for member in ["Apply", "Stop", "Unlock"] {
        let f = Fixture::new().await;
        let value = f
            .call(
                "Prepare",
                r#"{"version":1,"mode":"public_protection","allow_lan":false}"#,
            )
            .await
            .unwrap();
        let apply = if member == "Apply" {
            serde_json::json!({"version":1,"handle":value["handle"]}).to_string()
        } else {
            r#"{"version":1}"#.to_owned()
        };
        f.pause.store(true, Ordering::SeqCst);
        let peer = f.peer.clone();
        let pending = tokio::spawn(async move {
            peer.call_method(
                Some(SERVICE_NAME),
                SERVICE_PATH,
                Some(SERVICE_INTERFACE),
                member,
                &(apply,),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while f.checks.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            f.call("State", r#"{"version":1}"#),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap()["state"], "unknown");
        assert_eq!(f.effects.load(Ordering::SeqCst), 0);
        f.gate.add_permits(1);
        pending.await.unwrap().unwrap();
        f.shutdown().await;
    }
}

fn profile_frame() -> String {
    let imported = yonik_import::import_bytes(
        b"vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?security=tls".to_vec(),
    )
    .unwrap();
    serde_json::json!({"version":1,"mode":"system_profile","engine":"xray","kill_switch":true,"server":yonik_import::ServerIntent::from_server(&imported.servers[0]).unwrap()}).to_string()
}
fn prepare_message(json: &str) -> Message {
    Message::method(SERVICE_PATH, "Prepare")
        .unwrap()
        .interface(SERVICE_INTERFACE)
        .unwrap()
        .build(&(json,))
        .unwrap()
}
#[test]
fn typed_profile_prepare_uses_closed_bounded_server_frame() {
    let json = profile_frame();
    assert!(parse(&prepare_message(&json)).is_ok());
    for key in [
        "uid",
        "unit",
        "argv",
        "environment",
        "tun_id",
        "mark",
        "table",
        "raw_config",
    ] {
        let mut payload: serde_json::Value = serde_json::from_str(&json).unwrap();
        payload[key] = serde_json::json!("forbidden");
        assert!(
            parse(&prepare_message(&payload.to_string())).is_err(),
            "{key}"
        );
    }
    assert!(parse(&prepare_message(&json.replacen("{", r#"{"version":1,"#, 1))).is_err());
    let mut payload: serde_json::Value = serde_json::from_str(&json).unwrap();
    payload["engine"] = serde_json::json!("arbitrary");
    assert!(parse(&prepare_message(&payload.to_string())).is_err());
    payload["engine"] = serde_json::json!("sing-box");
    payload["server"]["credentials"]["uuid"] = serde_json::json!(123456789);
    let error = parse(&prepare_message(&payload.to_string())).err().unwrap();
    assert!(!format!("{error:?} {error}").contains("123456789"));
}

#[tokio::test]
async fn profile_prepare_and_apply_require_fresh_auth_same_peer_and_generation() {
    let effects = Arc::new(AtomicUsize::new(0));
    let generation = Arc::new(AtomicUsize::new(1));
    let prepares = Arc::new(AtomicUsize::new(0));
    let host = Host {
        effects: effects.clone(),
        generation: generation.clone(),
        profile_prepares: prepares.clone(),
    };
    let f = Fixture::with_host(host, effects.clone(), generation.clone()).await;
    let request = profile_frame();
    f.allowed.store(false, Ordering::SeqCst);
    assert!(f.call("Prepare", &request).await.is_err());
    assert_eq!(prepares.load(Ordering::SeqCst), 0);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    f.allowed.store(true, Ordering::SeqCst);
    let prepared = f.call("Prepare", &request).await.unwrap();
    assert_eq!(prepares.load(Ordering::SeqCst), 1);
    let apply = serde_json::json!({"version":1,"handle":prepared["handle"]}).to_string();
    let other = f._bus.connect().await;
    assert!(
        other
            .call_method(
                Some(SERVICE_NAME),
                SERVICE_PATH,
                Some(SERVICE_INTERFACE),
                "Apply",
                &(apply.as_str(),)
            )
            .await
            .is_err()
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    generation.store(2, Ordering::SeqCst);
    assert!(f.call("Apply", &apply).await.is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    let prepared = f.call("Prepare", &request).await.unwrap();
    let apply = serde_json::json!({"version":1,"handle":prepared["handle"]}).to_string();
    f.allowed.store(false, Ordering::SeqCst);
    assert!(f.call("Apply", &apply).await.is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    f.allowed.store(true, Ordering::SeqCst);
    let prepared = f.call("Prepare", &request).await.unwrap();
    let apply = serde_json::json!({"version":1,"handle":prepared["handle"]}).to_string();
    f.call("Apply", &apply).await.unwrap();
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert!(f.call("Apply", &apply).await.is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(prepares.load(Ordering::SeqCst), 3);
    assert_eq!(
        f.call("Capabilities", r#"{"version":1}"#).await.unwrap()["system_tun"],
        false
    );
    f.shutdown().await;
}
#[tokio::test]
async fn malformed_profile_frame_is_rejected_before_authorization_or_host() {
    let f = Fixture::new().await;
    let original = profile_frame();
    for request in [
        original.replacen("{", r#"{"uid":0,"#, 1),
        original.replacen(r#""host":"#, r#""host":"malicious","host":"#, 1),
        " ".repeat(MAX_WIRE_BYTES) + &original,
    ] {
        assert!(f.call("Prepare", &request).await.is_err());
    }
    assert_eq!(f.checks.load(Ordering::SeqCst), 0);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        as_prepared(ServiceError::Unsupported),
        PreparedError::Unsupported
    );
    assert_eq!(
        ServiceError::Prepared(PreparedError::Unsupported).code(),
        "unsupported"
    );
    f.shutdown().await;
}

#[path = "installed_session_tests.rs"]
mod installed_session;

#[tokio::test]
async fn stop_outer_wait_exposes_timeout_and_preserves_cancellation() {
    let host = Mutex::new(());
    let _held = host.lock().await;
    let (_keep, mut cancel) = Cancellation::new();
    let error = wait_for_host(&host, &mut cancel, Duration::from_millis(1))
        .await
        .expect_err("mutex удерживается");
    assert_eq!(error.code(), "timeout");
    let (signal, mut cancel) = Cancellation::new();
    signal.send_replace(true);
    assert_eq!(
        wait_for_host(&host, &mut cancel, Duration::from_secs(1))
            .await
            .expect_err("отмена до ожидания"),
        ServiceError::Cancelled
    );
}

#[test]
fn policy_profile_closed_codec() {
    let mut frame: serde_json::Value = serde_json::from_str(&profile_frame()).unwrap();
    frame["mode"] = serde_json::json!("system_profile_policy");
    frame["policy"] = serde_json::json!({"version":1,"default_action":"proxy","user_rules":[],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]});
    let text = frame.to_string();
    assert!(matches!(
        parse(&prepare_message(&text)),
        Ok(Request::PrepareProfile(_))
    ));
    for field in ["policy", "server"] {
        let mut invalid = frame.clone();
        invalid[field] = serde_json::json!([]);
        assert!(parse(&prepare_message(&invalid.to_string())).is_err());
    }
    let mut extra = frame.clone();
    extra["policy"]["unknown"] = serde_json::json!(true);
    assert!(parse(&prepare_message(&extra.to_string())).is_err());
    assert!(
        parse(&prepare_message(&text.replacen(
            "\"default_action\":",
            "\"version\":1,\"default_action\":",
            1
        )))
        .is_err()
    );
    frame["policy"]["user_rules"] = serde_json::json!([{"id":1,"enabled":true,"action":"direct","domain":[],"domain_suffix":[],"ip_cidr":[],"executable_paths":["/usr/bin/client"]}]);
    assert!(parse(&prepare_message(&frame.to_string())).is_ok());
    frame["policy"]["user_rules"][0]["executable_paths"] = serde_json::json!([["/usr/bin/client"]]);
    assert!(parse(&prepare_message(&frame.to_string())).is_err());
    assert!(parse(&prepare_message(&text.replace("proxy", &"x".repeat(65536)))).is_err());
}

#[test]
fn fake_dns_keeps_the_supplied_inline_policy_and_suffixes() {
    let mut frame: serde_json::Value = serde_json::from_str(&profile_frame()).unwrap();
    frame["mode"] = serde_json::json!("system_profile_fake_dns");
    frame["fake_dns_domains"] = serde_json::json!(["Example.test", "example.test"]);
    frame["policy"] = serde_json::json!({"version":1,"default_action":"proxy","user_rules":[],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]});
    let request = parse(&prepare_message(&frame.to_string()));
    let Ok(Request::PrepareProfile(request)) = request else {
        panic!("Допустимая политика Fake DNS должна пройти декодирование");
    };
    assert!(request.policy.is_some());
    assert_eq!(
        request.fake_dns_domains,
        Some(vec!["example.test".to_owned()])
    );

    frame["policy"]["unknown"] = serde_json::json!(true);
    assert!(matches!(
        parse(&prepare_message(&frame.to_string())),
        Err(ServiceError::InvalidRequest)
    ));
}

#[cfg(not(feature = "test-support"))]
#[test]
fn fake_dns_requires_explicit_policy_in_the_standard_build() {
    let mut frame: serde_json::Value = serde_json::from_str(&profile_frame()).unwrap();
    frame["mode"] = serde_json::json!("system_profile_fake_dns");
    frame["fake_dns_domains"] = serde_json::json!(["example.test"]);
    for policy in [None, Some(serde_json::Value::Null)] {
        if let Some(policy) = policy {
            frame["policy"] = policy;
        }
        assert!(matches!(
            parse(&prepare_message(&frame.to_string())),
            Err(ServiceError::Unsupported)
        ));
    }
}

#[tokio::test]
async fn policy_profile_private_bus_roundtrip_and_one_shot() {
    let f = Fixture::new().await;
    let mut frame: serde_json::Value = serde_json::from_str(&profile_frame()).unwrap();
    frame["mode"] = serde_json::json!("system_profile_policy");
    frame["policy"] = serde_json::json!({"version":1,"default_action":"proxy","user_rules":[],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]});
    f.allowed.store(false, Ordering::SeqCst);
    assert!(f.call("Prepare", &frame.to_string()).await.is_err());
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    f.allowed.store(true, Ordering::SeqCst);
    let prepared = f.call("Prepare", &frame.to_string()).await.unwrap();
    let apply = serde_json::json!({"version":1,"handle":prepared["handle"]}).to_string();
    assert!(f.call("Apply", &apply).await.is_ok());
    assert!(f.call("Apply", &apply).await.is_err());
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    frame["policy"]["user_rules"] = serde_json::json!([[]]);
    assert!(f.call("Prepare", &frame.to_string()).await.is_err());
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    f.shutdown().await;
}

#[test]
fn bundle_method_rejects_wrong_signature_fd_count_and_unknown_fields() {
    let wrong = Message::method(SERVICE_PATH, "PrepareBundleV1")
        .unwrap()
        .interface(SERVICE_INTERFACE)
        .unwrap()
        .build(&("{\"version\":1}",))
        .unwrap();
    assert!(matches!(parse(&wrong), Err(ServiceError::InvalidRequest)));
    let no_fds: Vec<zbus::zvariant::OwnedFd> = Vec::new();
    let empty = Message::method(SERVICE_PATH, "PrepareBundleV1")
        .unwrap()
        .interface(SERVICE_INTERFACE)
        .unwrap()
        .build(&("{\"version\":1}", no_fds))
        .unwrap();
    assert!(matches!(parse(&empty), Err(ServiceError::InvalidRequest)));
    let extra = Message::method(SERVICE_PATH, "BundleCapabilitiesV1")
        .unwrap()
        .interface(SERVICE_INTERFACE)
        .unwrap()
        .build(&("{\"version\":1,\"extra\":true}",))
        .unwrap();
    assert!(matches!(parse(&extra), Err(ServiceError::InvalidRequest)));
    let valid = Message::method(SERVICE_PATH, "BundleCapabilitiesV1")
        .unwrap()
        .interface(SERVICE_INTERFACE)
        .unwrap()
        .build(&("{\"version\":1}",))
        .unwrap();
    assert!(matches!(parse(&valid), Ok(Request::BundleCapabilities)));
}

// Только private bus и синтетический host, без systemd/engine execution.
#[tokio::test]
async fn output_dispatch_preserves_claim_owner_stale_authorization_and_replay_fences() {
    async fn output_call(peer: &zbus::Connection, request: &str) -> zbus::Result<zbus::Message> {
        use std::os::fd::AsFd;
        let (_readers, writers) = crate::output_transport::create().unwrap();
        let writers = writers.validate().unwrap();
        let roles = [
            zbus::zvariant::Fd::from(writers.stdout.as_fd()),
            zbus::zvariant::Fd::from(writers.stderr.as_fd()),
        ];
        peer.call_method(
            Some(SERVICE_NAME),
            SERVICE_PATH,
            Some(SERVICE_INTERFACE),
            "ApplyOutputV1",
            &(request, roles.as_slice()),
        )
        .await
    }
    let f = Fixture::new().await;
    let prepared = f.call("Prepare", &profile_frame()).await.unwrap();
    let request = serde_json::json!({"version":1,"handle":prepared["handle"]}).to_string();
    let other = f._bus.connect().await;
    assert!(output_call(&other, &request).await.is_err());
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    f.generation.store(2, Ordering::SeqCst);
    assert!(output_call(&f.peer, &request).await.is_err());
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    let prepared = f.call("Prepare", &profile_frame()).await.unwrap();
    let request = serde_json::json!({"version":1,"handle":prepared["handle"]}).to_string();
    f.allowed.store(false, Ordering::SeqCst);
    assert!(output_call(&f.peer, &request).await.is_err());
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    f.allowed.store(true, Ordering::SeqCst);
    let prepared = f.call("Prepare", &profile_frame()).await.unwrap();
    let request = serde_json::json!({"version":1,"handle":prepared["handle"]}).to_string();
    output_call(&f.peer, &request).await.unwrap();
    assert!(output_call(&f.peer, &request).await.is_err());
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    f.shutdown().await;
}

#[tokio::test]
async fn native_eligibility_default_host_is_data_only_and_honors_cancel() {
    let mut host = Host {
        effects: Arc::new(AtomicUsize::new(0)),
        profile_prepares: Arc::new(AtomicUsize::new(0)),
        generation: Arc::new(AtomicUsize::new(1)),
    };
    let (keep, cancel) = Cancellation::new();
    assert!(
        !host
            .native_prepare_eligibility(cancel.clone())
            .await
            .unwrap()
    );
    drop(keep);
    assert!(matches!(
        host.native_prepare_eligibility(cancel).await,
        Err(ServiceError::Cancelled)
    ));
    assert_eq!(host.effects.load(Ordering::SeqCst), 0);
    assert_eq!(host.profile_prepares.load(Ordering::SeqCst), 0);
}
