use std::{process::Stdio, time::Duration};

use rustix::process::{Pid, Signal, kill_process};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Child,
    time::timeout,
};
use yonik_engine::Engine;

use super::{BinarySnapshot, Cancellation, HostError};

pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn terminate(child: &mut Child) -> Result<(), HostError> {
    if child.try_wait().map_err(|_| HostError::Cleanup)?.is_some() {
        return Ok(());
    }
    let pid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw)
        .ok_or(HostError::Cleanup)?;
    match kill_process(pid, Signal::TERM) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => {}
        Err(_) => return Err(HostError::Cleanup),
    }
    match timeout(Duration::from_secs(3), child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) => Err(HostError::Cleanup),
        Err(_) => child.kill().await.map_err(|_| HostError::Cleanup),
    }
}

pub(crate) async fn verify_version(
    binary: &BinarySnapshot,
    cancel: &mut Cancellation,
) -> Result<(), HostError> {
    cancel.check()?;
    let mut child = binary
        .command()
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| HostError::Process)?;
    let output = child.stdout.take().ok_or(HostError::Process)?;
    let operation = async {
        let mut bytes = Vec::new();
        let mut output = output.take(4097);
        let (read, status) = tokio::join!(output.read_to_end(&mut bytes), child.wait());
        if read.is_err() || !status.map_err(|_| HostError::Process)?.success() || bytes.len() > 4096
        {
            return Err(HostError::Version);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| HostError::Version)?;
        let prefix = match binary.engine {
            Engine::Xray => "Xray 26.10.31",
            Engine::SingBox => "sing-box version 1.14.4",
        };
        let line = text.lines().next().ok_or(HostError::Version)?;
        if line != prefix
            && !line
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with(' '))
        {
            return Err(HostError::Version);
        }
        Ok(())
    };
    let result = tokio::select! {
        _ = cancel.cancelled() => Err(HostError::Cancelled),
        result = timeout(OPERATION_TIMEOUT, operation) => result.unwrap_or(Err(HostError::Timeout)),
    };
    if result.is_err() {
        terminate(&mut child).await?;
    }
    result
}

pub(crate) fn spawn(binary: &BinarySnapshot, checking: bool) -> Result<Child, HostError> {
    spawn_profile(binary, checking, None, None)
}
pub(crate) fn spawn_profile(
    binary: &BinarySnapshot,
    checking: bool,
    profile: Option<&mut super::local_profile_channel::Launch>,
    assets: Option<&std::path::Path>,
) -> Result<Child, HostError> {
    let mut command = binary.command();
    if profile.is_some() && checking {
        return Err(HostError::ConfigRejected);
    }
    if let Some(assets) = assets {
        if profile.is_some() {
            return Err(HostError::ConfigRejected);
        }
        if !checking {
            return Err(HostError::ConfigRejected);
        }
        command
            .env_clear()
            .env("LANG", "C")
            .env("XRAY_LOCATION_ASSET", assets);
    }
    match binary.engine {
        Engine::Xray => {
            command.arg("run");
            if checking {
                command.arg("-test");
            }
            command.args(["-c", "stdin:"]);
        }
        Engine::SingBox => {
            command
                .arg(if checking { "check" } else { "run" })
                .args(["-c", "/dev/stdin"]);
        }
    }
    command
        .stdin(Stdio::piped())
        .stdout(if checking {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stderr(if checking {
            Stdio::null()
        } else {
            Stdio::piped()
        });
    if let Some(profile) = profile {
        binary
            .producer()
            .ok_or(HostError::Unsupported)?
            .check(binary.trusted_hash())
            .map_err(|_| HostError::Unsupported)?;
        profile.configure(command)?.spawn()
    } else {
        command.spawn().map_err(|_| HostError::Process)
    }
}

pub(crate) async fn write_config(
    child: &mut Child,
    bytes: &[u8],
    cancel: &mut Cancellation,
) -> Result<(), HostError> {
    let mut stdin = child.stdin.take().ok_or(HostError::Process)?;
    tokio::select! {
        _ = cancel.cancelled() => Err(HostError::Cancelled),
        result = timeout(OPERATION_TIMEOUT, stdin.write_all(bytes)) => result.map_err(|_| HostError::Timeout)?.map_err(|_| HostError::Process),
    }
}

pub(crate) async fn config_check(
    binary: &BinarySnapshot,
    bytes: &[u8],
    cancel: &mut Cancellation,
) -> Result<(), HostError> {
    config_check_assets(binary, bytes, None, cancel).await
}
pub(crate) async fn config_check_assets(
    binary: &BinarySnapshot,
    bytes: &[u8],
    assets: Option<&std::path::Path>,
    cancel: &mut Cancellation,
) -> Result<(), HostError> {
    cancel.check()?;
    let mut child = spawn_profile(binary, true, None, assets)?;
    let operation = async {
        #[cfg(feature = "test-support")]
        cancel.lifecycle_reach(super::LifecycleStage::Validate, child.id().ok_or(HostError::Process)?).await?;
        write_config(&mut child, bytes, cancel).await?;
        tokio::select! {
            _ = cancel.cancelled() => Err(HostError::Cancelled),
            result = timeout(OPERATION_TIMEOUT, child.wait()) => {
                let status = result.map_err(|_| HostError::Timeout)?.map_err(|_| HostError::Process)?;
                if status.success() { Ok(()) } else { Err(HostError::ConfigRejected) }
            }
        }
    }.await;
    if operation.is_err() {
        terminate(&mut child).await?;
    }
    operation
}

/// Событие Engine берётся из фактического OS exit status после reap, не из текста.
pub(crate) async fn terminate_logged(
    child: &mut Child,
    log: Option<&crate::event_log::EventLog>,
) -> Result<(), HostError> {
    terminate(child).await?;
    if let Some(log) = log {
        if let Ok(Some(status)) = child.try_wait() {
            use std::os::unix::process::ExitStatusExt;
            log.record(
                crate::event_log::EventSource::Engine,
                crate::event_log::EventCode::ProcessExited,
                status
                    .code()
                    .or_else(|| status.signal().map(|signal| -signal)),
            );
        } else {
            log.reject();
        }
    }
    Ok(())
}

/// Два независимых bounded reader; владелец существует до write_config.
pub(super) struct RuntimeReaders {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl RuntimeReaders {
    pub(super) fn attach(
        child: &mut Child,
        engine: Engine,
        log: Option<crate::event_log::EventLog>,
    ) -> Result<Self, HostError> {
        let stdout = child.stdout.take().ok_or(HostError::Process)?;
        let stderr = child.stderr.take().ok_or(HostError::Process)?;
        Ok(Self {
            tasks: vec![
                reader(stdout, engine, log.clone()),
                reader(stderr, engine, log),
            ],
        })
    }
    pub(super) async fn stop(mut self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}
impl Drop for RuntimeReaders {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
fn reader<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut output: R,
    engine: Engine,
    log: Option<crate::event_log::EventLog>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut input = log
            .clone()
            .map(|log| crate::event_log::native_details::Input::new(engine, log));
        let mut bytes = [0; 16 * 1024];
        loop {
            let n = match output.read(&mut bytes).await {
                Ok(0) => break,
                Err(_) => {
                    if let Some(log) = &log {
                        log.reject();
                    }
                    break;
                }
                Ok(n) => n,
            };
            let mut offset = 0;
            while offset < n {
                offset += input
                    .as_mut()
                    .map_or(n - offset, |input| input.feed(&bytes[offset..n]));
                // Fairness даже при flood; Stop abort не ждёт EOF или disk consumer.
                tokio::task::yield_now().await;
            }
            bytes[..n].fill(0);
        }
        // EOF не публикует незавершённый frame; Drop Framer стирает scratch.
    })
}

#[cfg(test)]
mod native_reader_tests {
    use super::*;
    use crate::event_log::{EventContext, EventLog, LogFilter, MAX_PAGE};

    #[tokio::test]
    async fn native_reader_partial_eof_stop_flood_and_old_scope() {
        let root = EventLog::new();
        let scope = root.with_context(EventContext {
            session_id: 1,
            generation: 7,
        });
        let (mut send, receive) = tokio::io::duplex(32768);
        let task = reader(receive, Engine::SingBox, Some(scope.clone()));
        send.write_all(b"INFO[0000] sing-box started (0.12s)\nCANARY partial")
            .await
            .unwrap();
        drop(send);
        task.await.unwrap();
        let page = root.read_scoped(0, LogFilter::default(), MAX_PAGE).unwrap();
        assert_eq!(
            page.contexts,
            [Some(EventContext {
                session_id: 1,
                generation: 7
            })]
        );
        assert_eq!(page.page.rejected, 1);
        assert!(!page.export().contains("CANARY"));
        let _new = scope.with_generation(8);
        let (mut send, receive) = tokio::io::duplex(32768);
        let readers = RuntimeReaders {
            tasks: vec![reader(receive, Engine::SingBox, Some(scope))],
        };
        let writer = tokio::spawn(async move {
            let flood = b"CANARY\x1b\0\r\n".repeat(4096);
            loop {
                if send.write_all(&flood).await.is_err() {
                    break;
                }
            }
        });
        tokio::task::yield_now().await;
        tokio::time::timeout(Duration::from_millis(250), readers.stop())
            .await
            .expect("Stop не ждёт flood/EOF");
        tokio::time::timeout(Duration::from_millis(250), writer)
            .await
            .unwrap()
            .unwrap();
        let before = root
            .read(0, LogFilter::default(), MAX_PAGE)
            .unwrap()
            .events
            .len();
        tokio::task::yield_now().await;
        assert_eq!(
            root.read(0, LogFilter::default(), MAX_PAGE)
                .unwrap()
                .events
                .len(),
            before
        );
    }

    #[tokio::test]
    async fn separate_streams_never_join_a_fragment_into_a_message() {
        let root = EventLog::new();
        let scope = root.session_scope().unwrap();
        let (mut out, output) = tokio::io::duplex(128);
        let (mut err, errors) = tokio::io::duplex(128);
        let a = reader(output, Engine::SingBox, Some(scope.clone()));
        let b = reader(errors, Engine::SingBox, Some(scope));
        out.write_all(b"INFO[0000] sing-box ").await.unwrap();
        err.write_all(b"started (0.00s)\n").await.unwrap();
        drop(out);
        drop(err);
        a.await.unwrap();
        b.await.unwrap();
        let page = root.read(0, LogFilter::default(), MAX_PAGE).unwrap();
        assert!(page.events.is_empty());
        assert_eq!(page.rejected, 2);
    }
}

#[cfg(test)]
mod native_disk_backpressure_tests {
    use super::*;
    use crate::event_log::{DiskFixture, LogFilter, MAX_PAGE};
    #[tokio::test]
    async fn native_reader_stop_does_not_wait_for_full_disk_queue() {
        let mut fixture = DiskFixture::new().unwrap();
        let (root, guard) = fixture.take_sink().unwrap();
        assert!(fixture.wait_opened(Duration::from_secs(3)));
        let (mut send, receive) = tokio::io::duplex(32768);
        let readers = RuntimeReaders {
            tasks: vec![reader(
                receive,
                Engine::SingBox,
                Some(root.session_scope().unwrap()),
            )],
        };
        send.write_all(&b"INFO[0000] sing-box started (0.01s)\n".repeat(300))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if root
                    .read(0, LogFilter::default(), MAX_PAGE)
                    .is_some_and(|p| p.cursor >= 256)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(fixture.stats().enqueued, 128);
        assert!(fixture.stats().dropped_full > 0);
        let writer = tokio::spawn(async move {
            let flood = b"INFO[0000] sing-box started (0.02s)\n".repeat(1024);
            loop {
                if send.write_all(&flood).await.is_err() {
                    break;
                }
            }
        });
        tokio::time::timeout(Duration::from_millis(250), readers.stop())
            .await
            .expect("Stop отделён от disk drain");
        tokio::time::timeout(Duration::from_millis(250), writer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fixture.stats().written, 0);
        fixture.release();
        guard.request_shutdown();
        assert!(fixture.wait_consumer_closed(Duration::from_secs(3)));
        let disk = std::fs::read(fixture.path().join("logs/events.log")).unwrap();
        assert!(!String::from_utf8_lossy(&disk).contains("started"));
    }
}
