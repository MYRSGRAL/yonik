//! Продуктовая проекция snapshots без URL и персональных правил.
use serde::Serialize;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};
use tokio::sync::watch;
use yonik_linux::presets::{Error, Metadata, Store};

const BUILTIN_REVISION: &str = "7e14508232595bac5881aa25d31202843a3f6021";
pub const BUILTIN_SNAPSHOT: &str =
    "78e4865cdcb1eb0800206ad11fb6a581546a9e5d20a2d55ad63d5b9944ab5404";

#[derive(Serialize)]
pub struct BuiltinSource {
    snapshot: &'static str,
    date: &'static str,
}

impl Default for BuiltinSource {
    fn default() -> Self {
        Self {
            snapshot: BUILTIN_SNAPSHOT,
            date: "2026-11-16",
        }
    }
}

pub fn builtin_policy(mut policy: yonik_domain::Policy) -> Result<yonik_domain::Policy, Error> {
    const DOMAINS: &[u8] = include_bytes!("../assets/ru-direct/ru-standard.domains.txt");
    const IPV4: &[u8] = include_bytes!("../assets/ru-direct/ru-standard.ipv4.txt");
    const IPV6: &[u8] = include_bytes!("../assets/ru-direct/ru-standard.ipv6.txt");
    policy.preset_rules = yonik_engine::presets::Candidate::parse(
        BUILTIN_REVISION,
        BUILTIN_REVISION,
        DOMAINS,
        &[IPV4, IPV6].concat(),
    )
    .map_err(|_| Error::Invalid)?
    .into_rules([1, 2], true);
    Ok(policy)
}

#[derive(Default, Serialize)]
pub struct Status {
    pub builtin: BuiltinSource,
    pub current: Option<Version>,
    pub previous: Option<Version>,
    pub current_error: bool,
    pub previous_error: bool,
    pub prepared: bool,
    pub compiler_error: Option<String>,
    pub host_validated: bool,
    pub validation_scope: Option<ValidationScope>,
    pub decision: Option<String>,
    pub activation_available: bool,
    pub busy: bool,
    pub stopping: bool,
    pub active_request_id: Option<u64>,
    pub operation_error: Option<&'static str>,
    pub ack: Option<Ack>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ValidationScope {
    pub routing_revision: i64,
    pub profile: Option<i64>,
    pub source_revision: i64,
    pub engine: &'static str,
    pub port: u16,
}
#[derive(Serialize)]
pub struct Ack {
    pub request_id: u64,
    pub error: Option<&'static str>,
}
#[derive(Serialize)]
pub struct Version {
    source: String,
    version: String,
    checked_at_unix: u64,
}
impl From<Metadata> for Version {
    fn from(value: Metadata) -> Self {
        Self {
            source: value.source_id,
            version: value.version,
            checked_at_unix: value.checked_at_unix,
        }
    }
}
pub fn store_error(error: Error) -> &'static str {
    match error {
        Error::Storage => "storage",
        Error::Busy => "busy",
        Error::Invalid => "integrity",
        Error::Fetch => "fetch",
    }
}
pub struct Controller {
    store: Store,
}
impl Controller {
    pub fn open(path: &std::path::Path) -> Result<Self, Error> {
        Ok(Self {
            store: Store::open(path)?,
        })
    }
    pub fn status(&self) -> Status {
        let current = self.store.active();
        let previous = self.store.previous();
        Status {
            activation_available: current.as_ref().is_ok_and(|value| value.is_some()),
            current_error: current.is_err(),
            previous_error: previous.is_err(),
            current: current.ok().flatten().map(|(m, _)| m.into()),
            previous: previous.ok().flatten().map(|(m, _)| m.into()),
            ..Status::default()
        }
    }
    pub fn reference(&self) -> Result<String, Error> {
        self.store.active_id()?.ok_or(Error::Invalid)
    }
    pub fn resolve(
        &self,
        reference: &crate::editor::PresetReference,
        mut policy: yonik_domain::Policy,
    ) -> Result<yonik_domain::Policy, Error> {
        if reference.enabled {
            if reference.snapshot == BUILTIN_SNAPSHOT {
                return builtin_policy(policy);
            }
            policy.preset_rules = self
                .store
                .candidate(&reference.snapshot)?
                .into_rules([1, 2], true);
        }
        Ok(policy)
    }
    pub fn compile(
        &self,
        draft: &crate::editor::Draft,
        server: &yonik_import::ParsedServer,
        engine: yonik_engine::Engine,
        port: std::num::NonZeroU16,
        probe_port: std::num::NonZeroU16,
    ) -> Result<yonik_engine::CompiledConfig, String> {
        let base = draft.base_policy().map_err(str::to_owned)?;
        let policy = match &draft.ru_direct {
            Some(reference) => self
                .resolve(reference, base)
                .map_err(|error| store_error(error).to_owned())?,
            None => base,
        };
        yonik_engine::compile_policy(
            server,
            engine,
            port,
            probe_port,
            &policy,
            super::local_policy_mode(&policy),
        )
        .map_err(|error| format!("{error:?}"))
    }
    pub fn rollback(&self) -> Result<Status, Error> {
        self.store.rollback()?;
        Ok(self.status())
    }
    /// Отдельный preset tier сохраняет приоритеты и пользовательские правила.
    pub fn prepare(&self, mut policy: yonik_domain::Policy) -> Result<yonik_domain::Policy, Error> {
        let (_, candidate) = self.store.active()?.ok_or(Error::Invalid)?;
        policy.preset_rules = candidate.into_rules([1, 2], true);
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_store_has_no_activation_and_no_prepared_policy() {
        let mut id = [0; 16];
        getrandom::getrandom(&mut id).expect("случайный путь");
        let path = std::env::temp_dir().join(format!("yonik-preset-controller-{id:x?}"));
        let controller = Controller::open(&path).expect("хранилище");
        let status = controller.status();
        assert!(status.current.is_none());
        assert!(status.previous.is_none());
        assert!(!status.activation_available);
        assert!(controller.prepare(yonik_domain::Policy::default()).is_err());
        assert!(controller.rollback().is_err());
        std::fs::remove_dir(path).expect("собственный пустой каталог");
    }
    #[test]
    fn preparation_uses_preset_tier_and_preserves_user_rules() {
        use yonik_domain::{Action, Conditions, Flow, Route, Rule, RuleOrigin};
        let mut id = [0; 16];
        getrandom::getrandom(&mut id).expect("случайный путь");
        let path = std::env::temp_dir().join(format!("yonik-preset-policy-{id:x?}"));
        let controller = Controller::open(&path).expect("store");
        let resource = |hash: &str| yonik_linux::presets::Resource {
            url: "https://example.org/list".into(),
            revision: "v1".into(),
            sha256: hash.into(),
        };
        controller
            .store
            .install(
                Metadata {
                    source_id: "fixture".into(),
                    version: "v1".into(),
                    format: "plain-domain-cidr-v1".into(),
                    checked_at_unix: 1,
                    enabled: true,
                    domains: resource(
                        "04e512879df7acb18392404d982a1b179e94c20b53ee03b75538624863d89e96",
                    ),
                    ips: resource(
                        "1056040935d29c506274717d77a7388683810fd7ae430176f81a59de1270c994",
                    ),
                },
                b"example.org\n".to_vec(),
                b"0.0.0.0/0\n".to_vec(),
            )
            .expect("install");
        let mut policy = yonik_domain::Policy::default();
        policy.user_rules.push(Rule {
            id: 42,
            enabled: true,
            conditions: Conditions {
                destinations: vec!["1.1.1.0/24".parse().expect("CIDR")],
                ..Conditions::default()
            },
            action: Action::Proxy,
        });
        let prepared = controller.prepare(policy).expect("prepare");
        assert_eq!(prepared.user_rules.len(), 1);
        for (ip, action, origin) in [
            ("1.1.1.1", Route::Proxy, RuleOrigin::User(42)),
            ("8.8.8.8", Route::Direct, RuleOrigin::Preset(2)),
        ] {
            let result = prepared.evaluate(&Flow {
                executable: None,
                destination: ip.parse().expect("IP"),
            });
            assert_eq!((result.action, result.origin), (action, origin));
        }
        let report = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.1:24443".to_vec(),
        )
        .expect("profile");
        let draft = crate::editor::Draft {
            ru_direct: Some(crate::editor::PresetReference {
                snapshot: controller.reference().expect("reference"),
                enabled: true,
            }),
            ..Default::default()
        };
        for engine in [yonik_engine::Engine::Xray, yonik_engine::Engine::SingBox] {
            controller
                .compile(
                    &draft,
                    &report.servers[0],
                    engine,
                    std::num::NonZeroU16::new(10808).expect("port"),
                    std::num::NonZeroU16::new(10809).expect("probe"),
                )
                .expect("домен и IP переданы отдельными условиями DIRECT");
        }
        std::fs::remove_dir_all(path).expect("собственная fixture");
    }
    #[test]
    fn version_projection_does_not_export_resources() {
        let resource = yonik_linux::presets::Resource {
            url: "https://private.example/secret".into(),
            revision: "v1".into(),
            sha256: "a".repeat(64),
        };
        let version = Version::from(Metadata {
            source_id: "fixture".into(),
            version: "v1".into(),
            format: "plain-domain-cidr-v1".into(),
            checked_at_unix: 10,
            enabled: true,
            domains: resource.clone(),
            ips: resource,
        });
        let json = serde_json::to_string(&version).expect("DTO");
        assert!(!json.contains("private"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("url"));
    }
}

/// CAS задаёт порядок cancel/admission. После admission отмена не подменяет I/O outcome.
#[derive(Default)]
struct Publication(AtomicU8);
impl Publication {
    const PENDING: u8 = 0;
    const CANCELLED: u8 = 1;
    const ADMITTED: u8 = 2;
    fn cancel(&self) {
        let _ = self.0.compare_exchange(
            Self::PENDING,
            Self::CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    fn admit(&self, valid: bool) -> bool {
        if !valid {
            self.cancel();
            return false;
        }
        self.0
            .compare_exchange(
                Self::PENDING,
                Self::ADMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}
pub struct Job {
    pub request_id: u64,
    cancel: watch::Sender<bool>,
    publication: Option<Arc<Publication>>,
    task: tokio::task::JoinHandle<Result<(), &'static str>>,
}
impl Job {
    pub fn start(
        controller: Arc<Controller>,
        host: Arc<super::DesktopFetch>,
        metadata: Metadata,
        route: yonik_linux::FetchRoute,
        local: bool,
        request_id: u64,
    ) -> Result<Self, &'static str> {
        yonik_linux::presets::validate_metadata(&metadata).map_err(|_| "invalid_input")?;
        let (cancel, receiver) = watch::channel(false);
        let publication = Arc::new(Publication::default());
        let admission = publication.clone();
        let task = tokio::spawn(async move {
            use yonik_linux::SubscriptionFetch;
            let mut bodies = Vec::with_capacity(2);
            for resource in [&metadata.domains, &metadata.ips] {
                let source = if local {
                    yonik_linux::Source::local(&resource.url)
                } else {
                    yonik_linux::Source::public(&resource.url)
                }
                .map_err(|_| "invalid_input")?;
                let response = host
                    .fetch(&source, route, None, receiver.clone())
                    .await
                    .map_err(|_| {
                        if *receiver.borrow() || receiver.has_changed().is_err() || host.stale() {
                            "cancelled"
                        } else {
                            "fetch"
                        }
                    })?;
                match response {
                    yonik_linux::FetchResponse::Modified { body, .. } => {
                        bodies.push(body.into_bytes())
                    }
                    _ => return Err("fetch"),
                }
            }
            if host.stale() || *receiver.borrow() || receiver.has_changed().is_err() {
                return Err("cancelled");
            }
            let ips = bodies.pop().ok_or("invalid_input")?;
            let domains = bodies.pop().ok_or("invalid_input")?;
            tokio::task::spawn_blocking(move || {
                if *receiver.borrow() || receiver.has_changed().is_err() || host.stale() {
                    return Err("cancelled");
                }
                controller
                    .store
                    .install_admitted(metadata, domains, ips, || {
                        // Read guard сериализует lease revocation с CAS admission;
                        // guard освобождается до файлового I/O rename/fsync.
                        let current = host.current.borrow();
                        let valid = (!host.proxy_used.load(Ordering::Acquire)
                            || (*current == host.lease && host.current.has_changed().is_ok()))
                            && !*receiver.borrow()
                            && receiver.has_changed().is_ok();
                        admission.admit(valid)
                    })
                    .map_err(store_error)
                    .and_then(|outcome| outcome.ok_or("cancelled"))
                    .and_then(|outcome| match outcome {
                        yonik_linux::presets::PublishOutcome::Durable => Ok(()),
                        yonik_linux::presets::PublishOutcome::PublishedDurabilityUnknown => {
                            Err("durability_unknown")
                        }
                    })
            })
            .await
            .map_err(|_| "storage")?
        });
        Ok(Self {
            request_id,
            cancel,
            publication: Some(publication),
            task,
        })
    }
    pub fn validate(
        config: yonik_engine::CompiledConfig,
        engine_dir: std::path::PathBuf,
        request_id: u64,
    ) -> Self {
        let (cancel, receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let engine = config.engine();
            // Те же доверенные версии, что используются текущим Desktop session.
            let (relative, digest) = match engine {
                yonik_engine::Engine::Xray => (
                    "xray-26.10.31/xray",
                    "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
                ),
                yonik_engine::Engine::SingBox => (
                    "sing-box-1.14.4/sing-box",
                    "1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a",
                ),
            };
            let mut cancellation = yonik_linux::Cancellation::from_receiver(receiver);
            cancellation.check().map_err(|_| "cancelled")?;
            let path = engine_dir.join(relative);
            let binary = tokio::task::spawn_blocking(move || {
                yonik_linux::BinarySnapshot::load(
                    &path,
                    digest
                        .parse()
                        .map_err(|_| yonik_linux::HostError::BinaryHash)?,
                    engine,
                )
            })
            .await
            .map_err(|_| "engine_missing")?
            .map_err(|_| "engine_missing")?;
            yonik_linux::CheckedConfig::validate(binary, config, &mut cancellation)
                .await
                .map(|_| ())
                .map_err(|error| {
                    if error == yonik_linux::HostError::Cancelled {
                        "cancelled"
                    } else {
                        "engine_config"
                    }
                })
        });
        Self {
            request_id,
            cancel,
            publication: None,
            task,
        }
    }
    pub fn stop(&self) {
        if let Some(publication) = &self.publication {
            publication.cancel();
        }
        self.cancel.send_replace(true);
    }
    pub async fn complete(&mut self) -> Ack {
        let error = match (&mut self.task).await {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(_) => Some("storage"),
        };
        Ack {
            request_id: self.request_id,
            error,
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod job_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn controller() -> (Arc<Controller>, std::path::PathBuf) {
        let mut id = [0; 16];
        getrandom::getrandom(&mut id).expect("путь");
        let path = std::env::temp_dir().join(format!("yonik-preset-job-{id:x?}"));
        (Arc::new(Controller::open(&path).expect("store")), path)
    }
    fn metadata(address: std::net::SocketAddr) -> Metadata {
        let resource = |name: &str, hash: &str| yonik_linux::presets::Resource {
            url: format!("http://{address}/{name}"),
            revision: "v1".into(),
            sha256: hash.into(),
        };
        Metadata {
            source_id: "fixture".into(),
            version: "v1".into(),
            format: "plain-domain-cidr-v1".into(),
            checked_at_unix: 1,
            enabled: false,
            domains: resource(
                "domains",
                "04e512879df7acb18392404d982a1b179e94c20b53ee03b75538624863d89e96",
            ),
            ips: resource(
                "ips",
                "1056040935d29c506274717d77a7388683810fd7ae430176f81a59de1270c994",
            ),
        }
    }
    #[tokio::test]
    async fn direct_update_publishes_consistent_snapshot_and_matching_ack() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let metadata = metadata(listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            for body in ["example.org\n", "0.0.0.0/0\n"] {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).await.expect("request") > 0);
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("response");
            }
        });
        let (controller, path) = controller();
        let (lease, _) = watch::channel(None);
        let host = super::super::DesktopFetch::new(&lease, None);
        let mut job = Job::start(
            controller.clone(),
            host,
            metadata,
            yonik_linux::FetchRoute::Direct,
            true,
            17,
        )
        .expect("job");
        let ack = job.complete().await;
        assert_eq!(ack.request_id, 17);
        assert_eq!(ack.error, None);
        assert_eq!(controller.status().current.expect("snapshot").version, "v1");
        server.await.expect("server joined");
        drop(job);
        drop(controller);
        std::fs::remove_dir_all(path).expect("fixture");
    }
    #[tokio::test]
    async fn cancel_after_install_entry_before_index_publication_preserves_current() {
        if std::env::var_os("YONIK_PRESET_CANCEL_ISOLATED").is_none() {
            let child = std::process::Command::new(std::env::current_exe().expect("libtest"))
                .args([
                    "--exact",
                    "backend::presets::job_tests::cancel_after_install_entry_before_index_publication_preserves_current",
                    "--test-threads=1",
                ])
                .env("YONIK_PRESET_CANCEL_ISOLATED", "1")
                .output()
                .expect("isolated preset fixture");
            assert!(
                child.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            );
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let metadata = metadata(listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            for body in ["example.org\n", "0.0.0.0/0\n"] {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).await.expect("request") > 0);
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("response");
            }
        });
        let (controller, path) = controller();
        for version in ["old1", "old2"] {
            let mut previous = metadata.clone();
            previous.version = version.into();
            previous.domains.revision = version.into();
            previous.ips.revision = version.into();
            controller
                .store
                .install(previous, b"example.org\n".to_vec(), b"0.0.0.0/0\n".to_vec())
                .expect("previous snapshot");
        }
        let index_before = std::fs::read(path.join("index")).expect("index");
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let hook_entered = entered.clone();
        let hook_release = release.clone();
        let store = Store::open(&path)
            .expect("store")
            .with_before_publish(Arc::new(move || {
                hook_entered.notify_one();
                let (lock, cv) = &*hook_release;
                let guard = lock.lock().expect("gate");
                let (_guard, timeout) = cv
                    .wait_timeout_while(guard, std::time::Duration::from_secs(10), |released| {
                        !*released
                    })
                    .expect("gate wait");
                assert!(!timeout.timed_out());
            }));
        drop(controller);
        let controller = Arc::new(Controller { store });
        let (lease, _) = watch::channel(None);
        let mut job = Job::start(
            controller.clone(),
            super::super::DesktopFetch::new(&lease, None),
            metadata,
            yonik_linux::FetchRoute::Direct,
            true,
            19,
        )
        .expect("job");
        tokio::time::timeout(std::time::Duration::from_secs(10), entered.notified())
            .await
            .expect("inside install");
        job.stop();
        let (lock, cv) = &*release;
        *lock.lock().expect("release") = true;
        cv.notify_all();
        let ack = job.complete().await;
        server.await.expect("server joined");
        let preserved = std::fs::read(path.join("index")).expect("index") == index_before;
        assert_eq!(
            controller.status().current.expect("current").version,
            "old2"
        );
        assert_eq!(
            controller.status().previous.expect("previous").version,
            "old1"
        );
        drop(job);
        drop(controller);
        std::fs::remove_dir_all(path).expect("fixture");
        assert_eq!(ack.error, Some("cancelled"));
        assert!(preserved);
    }
    #[test]
    fn cancellation_after_admission_keeps_truthful_publication_result() {
        let (controller, path) = controller();
        let admission = Publication::default();
        let outcome = controller
            .store
            .install_admitted(
                metadata("127.0.0.1:1".parse().expect("address")),
                b"example.org\n".to_vec(),
                b"0.0.0.0/0\n".to_vec(),
                || {
                    let permitted = admission.admit(true);
                    assert!(permitted);
                    admission.cancel();
                    permitted
                },
            )
            .expect("publication result");
        assert_eq!(outcome, Some(yonik_linux::presets::PublishOutcome::Durable));
        assert!(controller.status().current.is_some());
        drop(controller);
        std::fs::remove_dir_all(path).expect("fixture");
    }
    #[tokio::test]
    async fn proxy_without_lease_never_falls_back_to_direct() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let metadata = metadata(listener.local_addr().expect("address"));
        let (controller, path) = controller();
        let (lease, _) = watch::channel(None);
        let mut job = Job::start(
            controller.clone(),
            super::super::DesktopFetch::new(&lease, None),
            metadata,
            yonik_linux::FetchRoute::Proxy,
            true,
            18,
        )
        .expect("job");
        assert_eq!(job.complete().await.error, Some("fetch"));
        assert!(controller.status().current.is_none());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        drop(job);
        drop(controller);
        std::fs::remove_dir_all(path).expect("fixture");
    }
}

#[cfg(test)]
mod host_gate {
    use super::*;
    #[tokio::test]
    #[ignore = "Требуются существующие pinned engines, YONIK_PRESET_GATE_ENGINE_DIR"]
    async fn accepted_compiler_and_host_validate_both_engines_without_tun() {
        let root = std::env::var_os("YONIK_PRESET_GATE_ENGINE_DIR").expect("engine directory");
        let report = yonik_import::import_bytes(
            b"vless://00112233-4455-6677-8899-aabbccddeeff@127.0.0.1:24443".to_vec(),
        )
        .expect("synthetic profile");
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).expect("path");
        let directory = std::env::temp_dir().join(format!("yonik-preset-host-{random:x?}"));
        let controller = Controller::open(&directory).expect("store");
        let mut draft = crate::editor::Draft {
            ru_direct: Some(crate::editor::PresetReference {
                snapshot: "a".repeat(64),
                enabled: false,
            }),
            ..Default::default()
        };
        draft.rules.push(crate::editor::RuleInput {
            transport: None,
            platform_sources: None,
            id: 1,
            enabled: true,
            executables: vec![],
            domains: vec![],
            destinations: vec!["192.0.2.0/24".into()],
            action: "block".into(),
        });
        for engine in [yonik_engine::Engine::Xray, yonik_engine::Engine::SingBox] {
            let config = controller
                .compile(
                    &draft,
                    &report.servers[0],
                    engine,
                    std::num::NonZeroU16::new(10808).expect("port"),
                    std::num::NonZeroU16::new(10809).expect("probe"),
                )
                .expect("accepted compiler");
            let mut job = Job::validate(config, root.clone().into(), 71);
            assert_eq!(job.complete().await.error, None);
        }

        draft.rules.clear();
        draft.ru_direct = Some(crate::editor::PresetReference {
            snapshot: BUILTIN_SNAPSHOT.into(),
            enabled: true,
        });
        for engine in [yonik_engine::Engine::Xray, yonik_engine::Engine::SingBox] {
            let config = controller
                .compile(
                    &draft,
                    &report.servers[0],
                    engine,
                    std::num::NonZeroU16::new(10808).expect("port"),
                    std::num::NonZeroU16::new(10809).expect("probe"),
                )
                .expect("accepted compiler");
            let mut job = Job::validate(config, root.clone().into(), 71);
            assert_eq!(job.complete().await.error, None);
        }
        std::fs::remove_dir_all(directory).expect("fixture");
    }
}
