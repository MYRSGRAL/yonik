#![cfg(target_os = "linux")]
use std::{
    io::BufRead,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Mutex, time::Instant};
use yonik_linux::Cancellation;
use yonik_linux::system_client::{ClientError, SystemClient};
const SERVICE_NAME: &str = "cloud.highpriority.yonik.Network1";
const SERVICE_PATH: &str = "/cloud/highpriority/yonik/Network";
use yonik_linux::system_client::State;
struct Bus(std::process::Child, String);
impl Bus {
    fn new() -> Self {
        let mut child = std::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        Self(child, address.trim().into())
    }
    async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.1.as_str())
            .unwrap()
            .build()
            .await
            .unwrap()
    }
}
impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[derive(zbus::DBusError, Debug)]
#[zbus(prefix = "cloud.highpriority.yonik.Network1")]
enum WireError {
    Error(String),
}
struct Server {
    system_tun: bool,
    response: Arc<Mutex<String>>,
    effects: Arc<AtomicUsize>,
}
#[zbus::interface(name = "cloud.highpriority.yonik.Network1")]
impl Server {
    async fn state(&self, request: &str) -> Result<String, WireError> {
        assert_eq!(request, "{\"version\":1}");
        let response = self.response.lock().await.clone();
        if let Some(error) = response.strip_prefix("error:") {
            return Err(WireError::Error(error.into()));
        }
        Ok(response)
    }
    async fn capabilities(&self, _request: &str) -> String {
        serde_json::json!({"version":1,"public_protection":true,"system_tun":self.system_tun,"allow_lan":false}).to_string()
    }
    async fn prepare(&self, request: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(request).unwrap();
        if value["mode"] == "system_profile" {
            assert_eq!(value.as_object().unwrap().len(), 5);
            assert_eq!(value["version"], 1);
            assert!(matches!(
                value["engine"].as_str(),
                Some("xray" | "sing-box")
            ));
            assert!(value["kill_switch"].is_boolean());
            yonik_import::ServerIntent::parse_json(&value["server"].to_string()).unwrap();
        } else if value["mode"] == "system_profile_policy" {
            assert_eq!(value.as_object().unwrap().len(), 6);
            let policy =
                yonik_engine::policy_wire::SystemPolicy::parse(&value["policy"].to_string())
                    .unwrap();
            assert_eq!(policy.policy().user_rules[0].id, 77);
            assert_eq!(
                policy.policy().user_rules[0].conditions.destinations[0].to_string(),
                "192.0.2.0/24"
            );
        } else {
            assert_eq!(value["mode"], "public_protection");
        }
        serde_json::json!({"version":1,"handle":vec![42;32]}).to_string()
    }
    #[zbus(name = "BundleCapabilitiesV1")]
    async fn bundle_capabilities_v1(&self, _request: &str) -> String {
        serde_json::json!({"version":1,"canonical_fd_transport":self.system_tun}).to_string()
    }
    #[zbus(name = "PrepareBundleV1")]
    async fn prepare_bundle_v1(
        &self,
        request: &str,
        resources: Vec<zbus::zvariant::OwnedFd>,
    ) -> String {
        let request =
            yonik_linux::bundle_request::BundleRequest::parse(request, resources.len()).unwrap();
        self.effects.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(150)).await;
        let response = self.response.lock().await.clone();
        if response == "bundle_ok" {
            serde_json::json!({"version":1,"handle":vec![42;32],"intent_digest":request.intent_digest,"runtime_config_digest":vec![7;32],"runtime_bundle_digest":vec![8;32]}).to_string()
        } else {
            response
        }
    }
    async fn apply(&self, request: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(value["handle"].as_array().unwrap().len(), 32);
        "{\"version\":1,\"state\":\"verified_rules\"}".into()
    }
    #[zbus(name = "ApplyOutputV1")]
    async fn apply_output(&self, request: &str, output: Vec<zbus::zvariant::OwnedFd>) -> String {
        assert_eq!(output.len(), 2);
        let value: serde_json::Value = serde_json::from_str(request).unwrap();
        assert_eq!(value["version"], 1);
        self.effects.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(150)).await;
        self.apply(request).await
    }
    async fn stop(&self, _request: &str) -> String {
        self.effects.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(150)).await;
        "{\"version\":1,\"state\":\"verified_rules\"}".into()
    }
    async fn unlock(&self, _request: &str) -> String {
        "{\"version\":1,\"state\":\"no_managed_policy\"}".into()
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

#[tokio::test]
async fn fake_dns_prepare_retries_two_stale_replies() {
    use futures_util::StreamExt;

    let bus = Bus::new();
    let server = bus.connect().await;
    server.request_name(SERVICE_NAME).await.unwrap();
    let mut calls = zbus::MessageStream::from(&server);
    let reply_server = server.clone();
    let respond = tokio::spawn(async move {
        let mut replies = 0;
        while let Some(Ok(message)) = calls.next().await {
            let header = message.header();
            if header.member().map(|member| member.as_str()) != Some("Prepare") {
                continue;
            }
            let request: String = message.body().deserialize().unwrap();
            let request: serde_json::Value = serde_json::from_str(&request).unwrap();
            assert_eq!(request["mode"], "system_profile_fake_dns");
            replies += 1;
            if replies == 3 {
                let reply = serde_json::json!({"version":1,"handle":vec![42;32]}).to_string();
                reply_server.reply(&message, &reply).await.unwrap();
            } else {
                let error = if replies <= 2 {
                    "stale"
                } else {
                    "authorization"
                };
                let reply = serde_json::json!({"version":1,"error":error}).to_string();
                reply_server
                    .reply_error(&message, "cloud.highpriority.yonik.Network1.Error", &reply)
                    .await
                    .unwrap();
                if replies == 4 {
                    break;
                }
            }
        }
    });
    let input = yonik_import::import_bytes(
        b"vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443".to_vec(),
    )
    .unwrap();
    let intent = yonik_import::ServerIntent::from_server(&input.servers[0]).unwrap();
    let policy = yonik_engine::policy_wire::SystemPolicy::parse(
        r#"{"version":1,"default_action":"proxy","user_rules":[],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}"#,
    )
    .unwrap();
    let (_keep, cancel) = Cancellation::new();
    let mut client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    for expected in [None, Some(ClientError::Denied)] {
        let result = client
            .prepare_fake_dns_policy_profile(
                &intent,
                yonik_engine::Engine::Xray,
                false,
                &["example.test".to_owned()],
                &policy,
                deadline(),
                cancel.clone(),
            )
            .await;
        assert_eq!(result.err(), expected);
    }
    respond.await.unwrap();
}

#[tokio::test]
async fn real_bus_contract_errors_cancellation_and_owner_fence() {
    let bus = Bus::new();
    let server = bus.connect().await;
    let response = Arc::new(Mutex::new(
        "{\"version\":1,\"state\":\"verified_rules\"}".into(),
    ));
    let effects = Arc::new(AtomicUsize::new(0));
    server
        .object_server()
        .at(
            SERVICE_PATH,
            Server {
                system_tun: false,
                response: response.clone(),
                effects: effects.clone(),
            },
        )
        .await
        .unwrap();
    server.request_name(SERVICE_NAME).await.unwrap();
    let (keep, cancel) = Cancellation::new();
    let mut client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    assert_eq!(
        client.state(deadline(), cancel.clone()).await.unwrap(),
        State::VerifiedRules
    );
    assert!(
        !client
            .native_prepare_eligibility(deadline(), cancel.clone())
            .await
            .unwrap()
            .can_prepare_attribution
    );
    let caps = client
        .capabilities(deadline(), cancel.clone())
        .await
        .unwrap();
    assert!(caps.public_protection && !caps.system_tun && !caps.allow_lan);
    let prepared = client.prepare(deadline(), cancel.clone()).await.unwrap();
    assert_eq!(
        client
            .apply(prepared, deadline(), cancel.clone())
            .await
            .unwrap(),
        State::VerifiedRules
    );
    assert_eq!(
        client.unlock(deadline(), cancel.clone()).await.unwrap(),
        State::NoManagedPolicy
    );
    for json in [
        "{\"version\":2,\"state\":\"unknown\"}".into(),
        "{\"version\":1,\"state\":\"future\"}".into(),
        "{\"version\":1,\"state\":42}".into(),
        "{\"version\":1,\"state\":\"unknown\",\"extra\":true}".into(),
        "x".repeat(65537),
    ] {
        *response.lock().await = json;
        assert_eq!(
            client.state(deadline(), cancel.clone()).await,
            Err(ClientError::Protocol)
        );
    }
    for (code, expected) in [
        ("busy", ClientError::Busy),
        ("timeout", ClientError::Timeout),
        ("authorization", ClientError::Denied),
        ("future", ClientError::Protocol),
    ] {
        *response.lock().await = format!("error:{{\"version\":1,\"error\":\"{code}\"}}");
        assert_eq!(
            client.state(deadline(), cancel.clone()).await,
            Err(expected)
        );
    }
    assert_eq!(
        client
            .stop(Instant::now() + Duration::from_millis(30), cancel.clone())
            .await,
        Err(ClientError::Deadline)
    );
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let (stop, cancelled) = Cancellation::new();
    let operation = client.stop(deadline(), cancelled);
    let trigger = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        stop.send(true).unwrap();
    };
    let (result, _) = tokio::join!(operation, trigger);
    assert_eq!(result, Err(ClientError::Cancelled));
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert_eq!(effects.load(Ordering::SeqCst), 2);
    let (already_stop, already_cancelled) = Cancellation::new();
    already_stop.send(true).unwrap();
    assert_eq!(
        client.stop(deadline(), already_cancelled).await,
        Err(ClientError::Cancelled)
    );
    assert_eq!(effects.load(Ordering::SeqCst), 2);
    let loss = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        server.release_name(SERVICE_NAME).await.unwrap();
        server.request_name(SERVICE_NAME).await.unwrap();
    };
    let (result, _) = tokio::join!(client.stop(deadline(), cancel.clone()), loss);
    assert_eq!(result, Err(ClientError::OwnerLost));
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert_eq!(effects.load(Ordering::SeqCst), 3);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        client
            .capabilities(deadline(), cancel.clone())
            .await
            .unwrap_err(),
        ClientError::OwnerLost
    );
    let mut fresh = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    assert!(
        fresh
            .capabilities(deadline(), cancel)
            .await
            .unwrap()
            .public_protection
    );
    drop(keep);
}

#[tokio::test]
async fn wrong_dbus_type_is_protocol_error() {
    use futures_util::StreamExt;
    let bus = Bus::new();
    let server = bus.connect().await;
    server.request_name(SERVICE_NAME).await.unwrap();
    let mut calls = zbus::MessageStream::from(&server);
    let (keep, cancel) = Cancellation::new();
    let mut client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    let respond = async {
        while let Some(Ok(message)) = calls.next().await {
            if message.header().message_type() == zbus::message::Type::MethodCall {
                server.reply(&message, &(true,)).await.unwrap();
                break;
            }
        }
    };
    let (result, _) = tokio::join!(client.state(deadline(), cancel), respond);
    assert_eq!(result, Err(ClientError::Protocol));
    drop(keep);
}

#[tokio::test]
async fn malformed_helper_error_is_protocol_error() {
    use futures_util::StreamExt;
    let bus = Bus::new();
    let server = bus.connect().await;
    server.request_name(SERVICE_NAME).await.unwrap();
    let mut calls = zbus::MessageStream::from(&server);
    let (keep, cancel) = Cancellation::new();
    let mut client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    let respond = async {
        while let Some(Ok(message)) = calls.next().await {
            if message.header().message_type() == zbus::message::Type::MethodCall {
                server
                    .reply_error(
                        &message,
                        "cloud.highpriority.yonik.Network1.Error",
                        &("{\"version\":1,\"error\":\"busy\"}", "лишнее"),
                    )
                    .await
                    .unwrap();
                break;
            }
        }
    };
    let (result, _) = tokio::join!(client.state(deadline(), cancel), respond);
    assert_eq!(result, Err(ClientError::Protocol));
    drop(keep);
}

#[tokio::test]
async fn closed_json_replies_require_objects_and_pinned_error_sender() {
    use futures_util::StreamExt;
    let bus = Bus::new();
    let server = bus.connect().await;
    let foreign = bus.connect().await;
    server.request_name(SERVICE_NAME).await.unwrap();
    let mut calls = zbus::MessageStream::from(&server);
    let (_keep, cancel) = Cancellation::new();
    let mut client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    let mut outcomes = Vec::new();
    for (capabilities, error, foreign_sender, body) in [
        (false, false, false, "[1,\"verified_rules\"]"),
        (true, false, false, "[1,true,false,false]"),
        (false, true, false, "[1,\"busy\"]"),
        (false, true, true, "{\"version\":1,\"error\":\"busy\"}"),
    ] {
        let respond = async {
            while let Some(Ok(message)) = calls.next().await {
                if message.header().message_type() == zbus::message::Type::MethodCall {
                    let sender = if foreign_sender { &foreign } else { &server };
                    if error {
                        sender
                            .reply_error(
                                &message,
                                "cloud.highpriority.yonik.Network1.Error",
                                &(body,),
                            )
                            .await
                            .unwrap();
                    } else {
                        sender.reply(&message, &(body,)).await.unwrap();
                    }
                    break;
                }
            }
        };
        let request = async {
            if capabilities {
                client
                    .capabilities(deadline(), cancel.clone())
                    .await
                    .map(|_| ())
            } else {
                client.state(deadline(), cancel.clone()).await.map(|_| ())
            }
        };
        let (result, _) = tokio::join!(request, respond);
        outcomes.push(result);
    }
    assert_eq!(outcomes, vec![Err(ClientError::Protocol); 4]);
}

#[tokio::test]
async fn typed_profile_private_bus_pipeline() {
    let bus = Bus::new();
    let server = bus.connect().await;
    server
        .object_server()
        .at(
            SERVICE_PATH,
            Server {
                system_tun: false,
                response: Arc::new(Mutex::new("{\"version\":1,\"state\":\"unknown\"}".into())),
                effects: Arc::new(AtomicUsize::new(0)),
            },
        )
        .await
        .unwrap();
    server.request_name(SERVICE_NAME).await.unwrap();
    let (_keep, cancel) = Cancellation::new();
    let mut client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    let report = yonik_import::import_bytes(
        b"vless://11111111-1111-1111-1111-111111111111@example.org:443?security=tls".to_vec(),
    )
    .unwrap();
    let intent = yonik_import::ServerIntent::from_server(&report.servers[0]).unwrap();
    for engine in [yonik_engine::Engine::Xray, yonik_engine::Engine::SingBox] {
        let prepared = client
            .prepare_profile(&intent, engine, true, deadline(), cancel.clone())
            .await
            .unwrap();
        assert_eq!(
            client.apply(prepared, deadline(), cancel.clone()).await,
            Ok(State::VerifiedRules)
        );
    }
    let mut invalid = serde_json::to_value(&intent).unwrap();
    invalid["credentials"]["password"] = serde_json::json!("synthetic-unexpected");
    assert!(yonik_import::ServerIntent::parse_json(&invalid.to_string()).is_err());
    assert!(yonik_import::ServerIntent::parse_json("{malformed").is_err());
}

#[path = "../../yonik-desktop/src/system_session.rs"]
#[allow(dead_code)]
mod system_session;

#[tokio::test]
async fn adapter_gate_revision_and_unknown_cleanup() {
    use system_session::{ProfileRevision, SystemSession};
    for system_tun in [false, true] {
        let bus = Bus::new();
        let server = bus.connect().await;
        let effects = Arc::new(AtomicUsize::new(0));
        server
            .object_server()
            .at(
                SERVICE_PATH,
                Server {
                    system_tun,
                    response: Arc::new(Mutex::new(
                        "{\"version\":1,\"state\":\"tunnel_starting\"}".into(),
                    )),
                    effects: effects.clone(),
                },
            )
            .await
            .unwrap();
        server.request_name(SERVICE_NAME).await.unwrap();
        let (_keep, cancel) = Cancellation::new();
        let client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
            .await
            .unwrap();
        let revision = ProfileRevision {
            source: 1,
            profile: 1,
            generation: 1,
        };
        let mut adapter =
            SystemSession::new(client, revision, yonik_linux::event_log::EventLog::new());
        let report = yonik_import::import_bytes(
            b"vless://11111111-1111-1111-1111-111111111111@example.org:443?security=tls".to_vec(),
        )
        .unwrap();
        let intent = yonik_import::ServerIntent::from_server(&report.servers[0]).unwrap();
        assert_eq!(
            adapter
                .prepare(
                    revision,
                    &intent,
                    yonik_engine::Engine::Xray,
                    true,
                    deadline(),
                    cancel.clone()
                )
                .await,
            if system_tun {
                let (stop, cancelled) = Cancellation::new();
                stop.send(true).unwrap();
                assert_eq!(
                    adapter.apply(revision, deadline(), cancelled).await,
                    Err(ClientError::Cancelled)
                );
                assert_eq!(adapter.snapshot(), State::Unknown);
                adapter
                    .prepare(
                        revision,
                        &intent,
                        yonik_engine::Engine::Xray,
                        true,
                        deadline(),
                        cancel.clone(),
                    )
                    .await
                    .unwrap();
                Ok(())
            } else {
                Err(ClientError::Unsupported)
            }
        );
        if system_tun {
            assert_eq!(
                adapter.apply(revision, deadline(), cancel.clone()).await,
                Ok(State::VerifiedRules)
            );
            assert_eq!(
                adapter.apply(revision, deadline(), cancel.clone()).await,
                Err(ClientError::InvalidHandle)
            );
        }
        assert_eq!(
            adapter.state(deadline(), cancel.clone()).await,
            Ok(State::TunnelStarting)
        );
        adapter.revise(ProfileRevision {
            generation: 2,
            ..revision
        });
        assert_eq!(
            adapter.apply(revision, deadline(), cancel.clone()).await,
            Err(ClientError::Stale)
        );
        assert_eq!(
            adapter
                .stop(Instant::now() + Duration::from_millis(20), cancel.clone())
                .await,
            Err(ClientError::Deadline)
        );
        assert_eq!(adapter.snapshot(), State::Unknown);
        server.release_name(SERVICE_NAME).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            adapter.state(deadline(), cancel).await,
            Err(ClientError::OwnerLost)
        );
        assert_eq!(adapter.snapshot(), State::Unknown);
    }
}

#[tokio::test]
async fn adapter_retained_policy_can_prepare_without_unlock() {
    use system_session::{ProfileRevision, SystemSession};
    let bus = Bus::new();
    let server = bus.connect().await;
    let response = Arc::new(Mutex::new(String::new()));
    let effects = Arc::new(AtomicUsize::new(0));
    server
        .object_server()
        .at(
            SERVICE_PATH,
            Server {
                system_tun: true,
                response: response.clone(),
                effects: effects.clone(),
            },
        )
        .await
        .unwrap();
    server.request_name(SERVICE_NAME).await.unwrap();
    let (_keep, cancel) = Cancellation::new();
    let client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    let revision = ProfileRevision {
        source: 1,
        profile: 1,
        generation: 1,
    };
    let mut adapter = SystemSession::new(client, revision, yonik_linux::event_log::EventLog::new());
    let report = yonik_import::import_bytes(
        b"vless://11111111-1111-1111-1111-111111111111@example.org:443?security=tls".to_vec(),
    )
    .unwrap();
    let intent = yonik_import::ServerIntent::from_server(&report.servers[0]).unwrap();
    for (wire, state) in [
        ("verified_rules", State::VerifiedRules),
        ("recovery_required", State::RecoveryRequired),
    ] {
        *response.lock().await = serde_json::json!({"version":1,"state":wire}).to_string();
        assert_eq!(adapter.state(deadline(), cancel.clone()).await, Ok(state));
        assert_eq!(
            adapter
                .prepare(
                    revision,
                    &intent,
                    yonik_engine::Engine::Xray,
                    true,
                    deadline(),
                    cancel.clone()
                )
                .await,
            Ok(())
        );
    }
    assert_eq!(
        adapter.stop(deadline(), cancel.clone()).await,
        Ok(State::VerifiedRules)
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        adapter
            .prepare(
                revision,
                &intent,
                yonik_engine::Engine::Xray,
                true,
                deadline(),
                cancel.clone()
            )
            .await,
        Ok(())
    );
    assert_eq!(
        adapter.unlock(deadline(), cancel).await,
        Ok(State::NoManagedPolicy)
    );
}

// COMPONENT: реальный client/adapter на private bus; fixture не доказывает production helper/TUN.
#[tokio::test]
async fn inline_policy_prepare_apply_одноразовый_и_инвалидируется_ревизией() {
    use system_session::{ProfileRevision, SystemSession};
    use yonik_linux::system_policy::InlinePolicy;
    let bus = Bus::new();
    let server = bus.connect().await;
    server
        .object_server()
        .at(
            SERVICE_PATH,
            Server {
                system_tun: true,
                response: Arc::new(Mutex::new(String::new())),
                effects: Arc::new(AtomicUsize::new(0)),
            },
        )
        .await
        .unwrap();
    server.request_name(SERVICE_NAME).await.unwrap();
    let (_keep, cancel) = Cancellation::new();
    let client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    let revision = ProfileRevision {
        source: 1,
        profile: 1,
        generation: 1,
    };
    let mut session = SystemSession::new(client, revision, yonik_linux::event_log::EventLog::new());
    let report = yonik_import::import_bytes(
        b"vless://11111111-1111-1111-1111-111111111111@example.org:443?security=tls".to_vec(),
    )
    .unwrap();
    let intent = yonik_import::ServerIntent::from_server(&report.servers[0]).unwrap();
    let policy = InlinePolicy::new(yonik_engine::policy_wire::SystemPolicy::parse(r#"{"version":1,"default_action":"proxy","user_rules":[{"id":77,"enabled":true,"action":"block","domain":[],"domain_suffix":[],"ip_cidr":["192.0.2.0/24"],"executable_paths":[]}],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}"#).unwrap());
    session
        .prepare_policy(
            revision,
            &intent,
            yonik_engine::Engine::Xray,
            &policy,
            deadline(),
            cancel.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        session.apply(revision, deadline(), cancel.clone()).await,
        Ok(State::VerifiedRules)
    );
    assert_eq!(
        session.apply(revision, deadline(), cancel.clone()).await,
        Err(ClientError::InvalidHandle)
    );
    session
        .prepare_policy(
            revision,
            &intent,
            yonik_engine::Engine::Xray,
            &policy,
            deadline(),
            cancel.clone(),
        )
        .await
        .unwrap();
    let next = ProfileRevision {
        generation: 2,
        ..revision
    };
    session.revise(next);
    assert_eq!(
        session.apply(revision, deadline(), cancel.clone()).await,
        Err(ClientError::Stale)
    );
    assert_eq!(
        session.apply(next, deadline(), cancel.clone()).await,
        Err(ClientError::InvalidHandle)
    );
}

#[tokio::test]
async fn bundle_fd_transport_echo_closed_reply_and_no_mutation_retry() {
    use yonik_engine::{
        Engine,
        resource_bundle::{ExternalRef, ResourceBinding, ResourceKind, ResourceRule},
    };
    use yonik_linux::{
        bundle_identity::CompileRequirements, bundle_request::BundleRequest,
        resource_fd_receiver::CanonicalDescriptor,
    };
    let report = yonik_import::import_bytes(
        b"vless://11111111-1111-1111-1111-111111111111@example.org:443?security=tls".to_vec(),
    )
    .unwrap();
    let policy=yonik_engine::policy_wire::SystemPolicy::parse(r#"{"version":1,"default_action":"direct","user_rules":[{"id":1,"enabled":true,"action":"block","domain":[],"domain_suffix":[],"ip_cidr":[],"executable_paths":[]}],"preset_rules":[],"lan":[],"private_networks":[],"private_domains":[]}"#).unwrap();
    let mut request = BundleRequest {
        server: yonik_import::ServerIntent::from_server(&report.servers[0]).unwrap(),
        policy,
        engine: Engine::Xray,
        native_pin: [27; 32],
        revision: 1,
        intent_digest: [0; 32],
        requirements: CompileRequirements {
            kill_switch: true,
            system_tun: true,
        },
        bindings: vec![ResourceBinding {
            rule: ResourceRule::User(1),
            resource: 0,
        }],
        canonical: vec![CanonicalDescriptor {
            digest: [1; 32],
            bytes: 10,
            records: 1,
            kind: ResourceKind::Cidrs,
            format_version: 1,
        }],
        expected_native: vec![ExternalRef {
            engine: Engine::Xray,
            digest: [2; 32],
            bytes: 20,
            records: 1,
            kind: ResourceKind::Cidrs,
            format_version: 1,
        }],
    };
    request.intent_digest = request.digest().unwrap();
    let bus = Bus::new();
    let server = bus.connect().await;
    let response = Arc::new(Mutex::new("bundle_ok".to_string()));
    let effects = Arc::new(AtomicUsize::new(0));
    server
        .object_server()
        .at(
            SERVICE_PATH,
            Server {
                system_tun: true,
                response: response.clone(),
                effects: effects.clone(),
            },
        )
        .await
        .unwrap();
    server.request_name(SERVICE_NAME).await.unwrap();
    let (_keep, cancel) = Cancellation::new();
    let mut client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    // Это mock transport test: FD contents не являются production Prepare proof.
    let files = [std::fs::File::open("/dev/null").unwrap()];
    let prepared = client
        .prepare_bundle(&request, &files, deadline(), cancel.clone())
        .await
        .unwrap();
    assert_eq!(prepared.intent_digest, request.intent_digest);
    assert_eq!(prepared.runtime_config_digest, [7; 32]);
    assert_eq!(
        client
            .apply_bundle(prepared, deadline(), cancel.clone())
            .await
            .unwrap(),
        State::VerifiedRules
    );
    *response.lock().await=serde_json::json!({"version":1,"handle":vec![42;32],"intent_digest":vec![0;32],"runtime_config_digest":vec![7;32],"runtime_bundle_digest":vec![8;32]}).to_string();
    assert!(matches!(
        client
            .prepare_bundle(&request, &files, deadline(), cancel.clone())
            .await,
        Err(ClientError::Protocol)
    ));
    *response.lock().await = "bundle_ok".to_string();
    let before = effects.load(Ordering::SeqCst);
    assert!(matches!(
        client
            .prepare_bundle(
                &request,
                &files,
                Instant::now() + Duration::from_millis(30),
                cancel.clone()
            )
            .await,
        Err(ClientError::Deadline)
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(effects.load(Ordering::SeqCst), before + 1);
}

#[tokio::test]
async fn output_cancel_after_send_is_one_shot_and_foreign_prepared_is_stale() {
    use yonik_linux::{event_log::EventLog, system_client::PreparedOutput};
    let bus = Bus::new();
    let server = bus.connect().await;
    let effects = Arc::new(AtomicUsize::new(0));
    server
        .object_server()
        .at(
            SERVICE_PATH,
            Server {
                system_tun: false,
                response: Arc::new(Mutex::new(String::new())),
                effects: effects.clone(),
            },
        )
        .await
        .unwrap();
    server.request_name(SERVICE_NAME).await.unwrap();
    let (_keep, cancel) = Cancellation::new();
    let mut client = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    let prepared = client.prepare(deadline(), cancel.clone()).await.unwrap();
    let output =
        PreparedOutput::bind(prepared, yonik_engine::Engine::Xray, &EventLog::new(), 1).unwrap();
    let (stop, cancellation) = Cancellation::new();
    let observed = effects.clone();
    let signal = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(2), async {
            while observed.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        stop.send_replace(true);
    });
    let (result, drain) = client.apply_output(output, deadline(), cancellation).await;
    assert_eq!(result, Err(ClientError::Cancelled));
    signal.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), drain.unwrap().drained())
            .await
            .unwrap()
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let prepared = client.prepare(deadline(), cancel.clone()).await.unwrap();
    let output =
        PreparedOutput::bind(prepared, yonik_engine::Engine::Xray, &EventLog::new(), 2).unwrap();
    let mut foreign = SystemClient::on_connection(bus.connect().await, deadline(), cancel.clone())
        .await
        .unwrap();
    let (result, drain) = foreign.apply_output(output, deadline(), cancel).await;
    assert_eq!(result, Err(ClientError::Stale));
    assert!(drain.is_none());
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}
