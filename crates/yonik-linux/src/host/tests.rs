use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use sha2::{Digest, Sha256 as Hasher};
use yonik_engine::Engine;

use super::{BinarySnapshot, Cancellation, HostError, Sha256, process};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "yonik-host-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("Удалить собственный fixture");
    }
}
fn snapshot(path: impl AsRef<Path>) -> BinarySnapshot {
    let path = path.as_ref();
    let bytes = fs::read(path).unwrap();
    let hash = Sha256(Hasher::digest(bytes).into());
    BinarySnapshot::load(path, hash, Engine::Xray).unwrap()
}

fn blocked_stdin_image() -> (Fixture, BinarySnapshot) {
    let directory = Fixture::new();
    let path = directory.0.join("host-fixture");
    let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/engines/host_fixture.rs");
    assert!(
        Command::new(compiler)
            .arg("--edition=2021")
            .arg(source)
            .arg("-o")
            .arg(&path)
            .status()
            .expect("собрать собственный ELF fixture")
            .success()
    );
    let image = snapshot(&path);
    (directory, image)
}

#[tokio::test]
async fn sealed_snapshot_executes_original_bytes_after_source_changes() {
    let directory = Fixture::new();
    let path = directory.0.join("engine");
    fs::copy("/usr/bin/true", &path).unwrap();
    let bytes = fs::read(&path).unwrap();
    let image =
        BinarySnapshot::load(&path, Sha256(Hasher::digest(bytes).into()), Engine::Xray).unwrap();
    fs::write(&path, b"changed").unwrap();
    assert!(image.file().write_all(b"changed").is_err());
    assert!(image.command().status().await.unwrap().success());
}

#[test]
fn fifo_and_oversized_regular_file_are_rejected_before_reading() {
    let directory = Fixture::new();
    let path = directory.0.join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert_eq!(
        BinarySnapshot::load(&path, Sha256([0; 32]), Engine::Xray).err(),
        Some(HostError::InvalidBinary)
    );
    let path = directory.0.join("huge");
    let file = File::create(&path).unwrap();
    file.set_len(128 * 1024 * 1024 + 1).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        BinarySnapshot::load(&path, Sha256([0; 32]), Engine::Xray).err(),
        Some(HostError::InvalidBinary)
    );
}

#[tokio::test]
async fn cancellation_of_blocked_stdin_kills_and_reaps_owned_child() {
    let (_fixture, image) = blocked_stdin_image();
    let mut child = image
        .command()
        .arg("block-stdin")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let (source, mut cancel) = Cancellation::new();
    let sender = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        source.send(true).unwrap();
    });
    let bytes = vec![0; 1024 * 1024];
    assert_eq!(
        process::write_config(&mut child, &bytes, &mut cancel).await,
        Err(HostError::Cancelled)
    );
    process::terminate(&mut child).await.unwrap();
    assert!(child.try_wait().unwrap().is_some());
    sender.await.unwrap();
}

#[tokio::test]
async fn wrong_version_is_rejected_and_reaped() {
    let image = snapshot("/usr/bin/true");
    let (_source, mut cancel) = Cancellation::new();
    assert_eq!(
        process::verify_version(&image, &mut cancel).await,
        Err(HostError::Version)
    );
}

#[tokio::test]
async fn checked_config_cannot_bind_metadata_of_another_engine() {
    let image = snapshot("/usr/bin/true");
    let imported = yonik_import::import_bytes(b"socks5://127.0.0.1:24443".to_vec()).unwrap();
    let config = yonik_engine::compile(
        &imported.servers[0],
        Engine::SingBox,
        std::num::NonZeroU16::new(10808).unwrap(),
    )
    .unwrap();
    let (_source, mut cancel) = Cancellation::new();
    assert_eq!(
        super::CheckedConfig::validate(image, config, &mut cancel)
            .await
            .err(),
        Some(HostError::ConfigRejected)
    );
}

#[tokio::test]
async fn foreign_listener_is_not_owned_by_process() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (_fixture, image) = blocked_stdin_image();
    let mut child = image.command().arg("block-stdin").spawn().unwrap();
    assert!(
        !super::session::listener_owned(child.id().unwrap(), listener.local_addr().unwrap().port())
            .unwrap()
    );
    process::terminate(&mut child).await.unwrap();
}

#[tokio::test]
async fn core_has_its_own_process_group_for_terminal_signal_isolation() {
    let (_fixture, image) = blocked_stdin_image();
    let mut child = image.command().arg("block-stdin").spawn().unwrap();
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id().unwrap()).unwrap()).unwrap();
    let group = rustix::process::getpgid(Some(pid)).unwrap();
    process::terminate(&mut child).await.unwrap();
    assert_eq!(group, pid);
}

#[tokio::test]
#[ignore = "Нужен явно заданный закреплённый YONIK_EVENT_TEST_CORE"]
async fn event_log_pinned_native_exit_status() {
    use crate::event_log::{EventCode, EventLog, EventSource, LogFilter};
    let path = std::env::var_os("YONIK_EVENT_TEST_CORE").expect("Закреплённое ядро");
    let image = snapshot(path);
    let log = EventLog::new();
    let mut child = image
        .command()
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = child.wait().await.unwrap();
    assert!(status.success());
    process::terminate_logged(&mut child, Some(&log))
        .await
        .unwrap();
    let page = log.read(0, LogFilter::default(), 1).unwrap();
    assert_eq!(page.events[0].source, EventSource::Engine);
    assert_eq!(page.events[0].code, EventCode::ProcessExited);
    assert_eq!(page.events[0].value, Some(0));
}
