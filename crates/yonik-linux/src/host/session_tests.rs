use yonik_application::{ConfigDigest, Event, Outcome, State};

use super::{HostError, LOCAL_ENV, LocalSession};

fn advance(session: &mut LocalSession, event: Option<Event>) {
    let token = session.session.begin().unwrap();
    let digest = ConfigDigest::new([0; 32]);
    let plan = session.session.prepare(token, LOCAL_ENV, digest).unwrap();
    session.active = match session.session.apply(plan, LOCAL_ENV, digest).unwrap() {
        Outcome::Applied(Some(token)) => Some(token),
        other => panic!("Ожидался Starting: {other:?}"),
    };
    session.accept(Event::NetworkApplied).unwrap();
    if let Some(event) = event {
        session.accept(event).unwrap();
    }
}

#[tokio::test]
async fn invalidated_check_preserves_live_owned_process_until_explicit_stop() {
    for event in [
        None,
        Some(Event::CheckPassed),
        Some(Event::EndpointUnavailable),
    ] {
        let mut session = LocalSession::new().unwrap();
        advance(&mut session, event);
        let mut command = tokio::process::Command::new("/usr/bin/sleep");
        command.arg("30").kill_on_drop(true).process_group(0);
        session.child = Some(command.spawn().unwrap());
        let pid = session.engine_pid().unwrap();
        let generation = session.session.applied_generation();

        session.invalidate_check().unwrap();

        assert_eq!(session.state(), State::Limited);
        assert_eq!(session.session.applied_generation(), generation);
        assert_eq!(session.engine_pid(), Some(pid));
        assert!(
            session
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none()
        );
        session.stop().await.unwrap();
        assert_eq!(session.state(), State::Disconnected);
        assert_eq!(session.engine_pid(), None);
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }
}

#[test]
fn invalidation_without_active_session_is_rejected() {
    let mut session = LocalSession::new().unwrap();
    assert_eq!(session.invalidate_check(), Err(HostError::State));
    assert_eq!(session.state(), State::Disconnected);
    assert_eq!(session.engine_pid(), None);
}

#[test]
fn config_writer_rejects_oversize_before_buffer_growth() {
    use std::io::Write;
    let mut output = super::ConfigBuffer(Vec::new());
    output.write_all(b"{}").unwrap();
    let capacity = output.0.capacity();
    let large = vec![0; crate::helper::MAX_ARTIFACT_BYTES];
    assert!(output.write_all(&large).is_err());
    assert_eq!(output.0.as_slice(), b"{}");
    assert_eq!(output.0.capacity(), capacity);
    let mut exact = super::ConfigBuffer(Vec::new());
    exact.write_all(&large).unwrap();
    assert!(exact.write_all(b"x").is_err());
    assert_eq!(exact.0.len(), crate::helper::MAX_ARTIFACT_BYTES);
    assert!(exact.0.capacity() <= crate::helper::MAX_RETAINED_CONFIG_BYTES);
}

#[tokio::test]
async fn event_log_observes_real_process_stop_and_reap() {
    use crate::event_log::{EventCode, EventLog, EventSource, LogFilter};
    let log = EventLog::new();
    let mut session = LocalSession::new().unwrap().with_event_log(log.clone());
    advance(&mut session, None);
    session.child = Some(
        tokio::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap(),
    );
    let pid = session.engine_pid().unwrap();
    session.stop().await.unwrap();
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    let page = log.read(0, LogFilter::default(), 256).unwrap();
    assert_eq!(
        page.events.iter().map(|e| e.code).collect::<Vec<_>>(),
        vec![
            EventCode::StopRequested,
            EventCode::ProcessExited,
            EventCode::CleanupConfirmed
        ]
    );
    assert_eq!(page.events[1].source, EventSource::Engine);
}

#[tokio::test]
async fn native_readers_are_joined_after_local_start_failure() {
    use crate::host::{BinarySnapshot, Cancellation, Sha256};
    use sha2::{Digest, Sha256 as Hasher};
    use std::num::NonZeroU16;
    use yonik_engine::{Engine, ProbeAccess};
    let binary = BinarySnapshot::load(
        std::path::Path::new("/usr/bin/false"),
        Sha256(Hasher::digest(std::fs::read("/usr/bin/false").unwrap()).into()),
        Engine::Xray,
    )
    .unwrap();
    let checked = super::CheckedConfig {
        profile: None,
        binary,
        bytes: b"{}".to_vec(),
        digest: ConfigDigest::new([0; 32]),
        port: NonZeroU16::new(24444).unwrap(),
        probe_port: NonZeroU16::new(24444).unwrap(),
        probe_access: ProbeAccess::default(),
    };
    let mut session = LocalSession::new()
        .unwrap()
        .with_event_log(crate::event_log::EventLog::new());
    let (_sender, mut cancel) = Cancellation::new();
    assert!(session.start(checked, &mut cancel).await.is_err());
    assert!(session.readers.is_none());
    assert!(session.child.is_none());
}
