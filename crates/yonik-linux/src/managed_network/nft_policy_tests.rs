use super::*;
use crate::managed_network::{
    PublicPolicyPhase,
    firewall::{IpPrefix, LanException},
};
use std::{
    fs,
    io::{BufRead, Write},
    path::PathBuf,
};

struct Area(PathBuf);
impl Area {
    fn new() -> Self {
        let mut bytes = [0; 8];
        getrandom::getrandom(&mut bytes).unwrap();
        Self(std::env::temp_dir().join(format!(
            "yonik-policy-runtime-{:016x}",
            u64::from_le_bytes(bytes)
        )))
    }
}
impl Drop for Area {
    fn drop(&mut self) {
        if self.0.exists() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
fn owner() -> Ownership {
    let ns = namespace(&File::open("/proc/thread-self/ns/net").unwrap()).unwrap();
    Ownership::new(1000, 7, 9, ns.0, ns.1).unwrap()
}
fn executor(network: bool) -> NftExecutor {
    NftExecutor {
        executable: File::open(if network { "/usr/bin/nft" } else { "/dev/null" }).unwrap(),
        netns: File::open("/proc/thread-self/ns/net").unwrap(),
        owner: owner(),
        gate: Arc::new(Semaphore::new(1)),
    }
}
fn deny() -> PublicBlockPolicy {
    PublicBlockPolicy::new(1, None, vec![], vec![], vec![], vec![]).unwrap()
}

#[test]
fn session_unlock_survives_restart_without_reinstalling_the_public_block() {
    let area = Area::new();
    let owner = owner();
    let mut journal = Journal::open(&area.0, owner).unwrap();
    journal.begin_session(owner, true).unwrap();
    journal.begin_public_policy(owner, 2, 5, deny()).unwrap();
    journal.confirm_authorized_session_unlock(owner).unwrap();
    drop(journal);

    let mut journal = Journal::open(&area.0, owner).unwrap();
    assert!(!journal.session_recovery().unwrap().kill_switch());
    journal.begin_public_unlock(owner, 2).unwrap();
    journal.reconcile(owner, 2, Reconciled::Absent).unwrap();
    drop(journal);

    let journal = Journal::open(&area.0, owner).unwrap();
    assert!(journal.public_policy().is_none());
    assert!(journal.session_recovery().is_none());
}

#[tokio::test]
async fn cancelled_apply_preserves_durable_payload_before_first_effect() {
    use futures_util::FutureExt;
    let area = Area::new();
    let mut journal = Journal::open(&area.0, owner()).unwrap();
    let mut executor = executor(false);
    let gate = Arc::clone(&executor.gate);
    let _busy = gate.acquire().await.unwrap();
    assert!(
        executor
            .apply_durable_public_policy(&mut journal, 2, 5, deny())
            .now_or_never()
            .is_none()
    );
    assert!(matches!(
        journal.public_policy().unwrap().phase(),
        PublicPolicyPhase::Present { previous: None, .. }
    ));
    assert!(journal.needs_reconciliation(2));
    drop(journal);
    let journal = Journal::open(&area.0, owner()).unwrap();
    let PublicPolicyPhase::Present { desired, .. } = journal.public_policy().unwrap().phase()
    else {
        panic!("Сохранён desired intent");
    };
    assert_eq!(desired.digest(), deny().digest());
}

#[tokio::test]
async fn legacy_records_are_not_reported_as_no_policy_or_unlocked() {
    let area = Area::new();
    let mut journal = Journal::open(&area.0, owner()).unwrap();
    let mut executor = executor(false);
    assert_eq!(
        executor.recover_public_policy(&mut journal).await.unwrap(),
        PublicPolicyRecovery::NoPolicy
    );
    assert_eq!(
        executor
            .unlock_durable_public_policy(&mut journal, 2)
            .await
            .unwrap(),
        None
    );
    journal
        .intent(
            owner(),
            Scope::PublicBlock,
            2,
            Resource::NftTable {
                table_id: 5,
                family: NftFamily::Inet,
            },
        )
        .unwrap();
    assert_eq!(
        executor.recover_public_policy(&mut journal).await,
        Err(NftError::Evidence)
    );
    assert_eq!(
        executor.unlock_durable_public_policy(&mut journal, 2).await,
        Err(NftError::Evidence)
    );
}

#[tokio::test]
async fn no_policy_shortcuts_reject_uncertain_journal_writes() {
    let area = Area::new();
    let mut journal = Journal::open(&area.0, owner()).unwrap();
    let mut executor = executor(false);
    // Ошибка durable-записи делает даже прежний пустой snapshot недостоверным.
    journal.poisoned = true;
    assert_eq!(
        executor.recover_public_policy(&mut journal).await,
        Err(NftError::Journal(JournalError::UncertainWrite))
    );
    assert_eq!(
        executor.unlock_durable_public_policy(&mut journal, 2).await,
        Err(NftError::Journal(JournalError::UncertainWrite))
    );
}

fn guard() {
    let host = std::env::var("YONIK_NFT_TEST_HOST_NETNS").expect("Нужен host netns до unshare");
    let ns = owner().namespace();
    assert_ne!(host, format!("{}:{}", ns.0, ns.1));
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
}
fn policies() -> (PublicBlockPolicy, PublicBlockPolicy) {
    let index = |name: &str| {
        fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap()
    };
    let uplink = index("uplink");
    let vpn = index("vpn");
    let a = deny().with_link_control(vec![uplink, vpn]).unwrap();
    let b = PublicBlockPolicy::new(
        1,
        None,
        vec![],
        vec![
            LanException::new(
                IpPrefix::new("10.42.0.0".parse().unwrap(), 16).unwrap(),
                uplink,
            )
            .unwrap(),
            LanException::new(
                IpPrefix::new("fd42::".parse().unwrap(), 16).unwrap(),
                uplink,
            )
            .unwrap(),
        ],
        vec![],
        vec![],
    )
    .unwrap()
    .with_link_control(vec![uplink, vpn])
    .unwrap();
    (a, b)
}

/// Child остаётся живым на точной durable/effect границе; родитель делает SIGKILL.
#[tokio::test]
#[ignore = "Только дочерний процесс из изолированного crash-теста"]
async fn crash_worker() {
    guard();
    let stage = std::env::var("YONIK_POLICY_CRASH_STAGE").unwrap();
    assert!(
        [
            "install-before",
            "install-after",
            "replace-before",
            "replace-after",
            "unlock-before",
            "unlock-after"
        ]
        .contains(&stage.as_str())
    );
    let path = std::env::var("YONIK_POLICY_CRASH_PATH").unwrap();
    assert!(path.starts_with("/tmp/yonik-policy-runtime-"));
    let mut journal = Journal::open(std::path::Path::new(&path), owner()).unwrap();
    let mut executor = executor(true);
    let (a, b) = policies();
    match stage.as_str() {
        "install-before" => {
            journal
                .begin_public_policy(owner(), 2, 5, a.clone())
                .unwrap();
        }
        "install-after" => {
            executor
                .ensure_public_block(&mut journal, 2, 5, &a)
                .await
                .unwrap();
        }
        "replace-before" => {
            journal
                .begin_public_policy(owner(), 2, 5, b.clone())
                .unwrap();
        }
        "replace-after" => {
            journal
                .begin_public_policy(owner(), 2, 5, a.clone())
                .unwrap();
            executor
                .replace_public_block(&mut journal, 2, &b, &a)
                .await
                .unwrap();
        }
        "unlock-before" => {
            journal.begin_public_unlock(owner(), 2).unwrap();
        }
        "unlock-after" => {
            let table = block_table(owner(), 2, 5, &a);
            let Observation::Owned(handle) = executor.observe(&table).await.unwrap() else {
                panic!("Таблица существует");
            };
            journal.reconcile(owner(), 2, Reconciled::Owned).unwrap();
            journal.mark_cleanup(owner(), 2).unwrap();
            executor.run(Action::Delete(&table, handle)).await.unwrap();
        }
        _ => unreachable!(),
    }
    let mut out = std::io::stdout().lock();
    out.write_all(b"YONIK_CRASH_READY\n").unwrap();
    out.flush().unwrap();
    drop(out);
    std::thread::park();
}
fn kill_at(path: &std::path::Path, stage: &str) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "managed_network::nft::policy::tests::crash_worker",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("YONIK_POLICY_CRASH_PATH", path)
        .env("YONIK_POLICY_CRASH_STAGE", stage)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut ready = false;
        for line in std::io::BufReader::new(stdout).lines().take(16) {
            if line.is_ok_and(|line| line.ends_with("YONIK_CRASH_READY")) {
                ready = true;
                break;
            }
        }
        let _send = send.send(ready);
    });
    let ready = receive.recv_timeout(Duration::from_secs(8));
    let _kill = child.kill();
    let status = child.wait().unwrap();
    reader.join().unwrap();
    assert!(ready.unwrap(), "Граница {stage}");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
}

#[tokio::test]
#[ignore = "Требует явно изолированный user/net/mount/pid namespace с приватными /tmp и /run"]
async fn sigkill_recovery_preserves_desired_previous_and_unlock_intents() {
    use super::super::block::tests::{fixture, peer, probe};
    guard();
    fixture(&["setup"]);
    let _peer = peer();
    let area = Area::new();
    let (a, b) = policies();
    let mut executor = executor(true);
    for address in ["198.18.1.2", "2001:db8:1::2"] {
        assert!(probe(address, "tcp", None, "24081"));
    }
    kill_at(&area.0, "install-before");
    let mut journal = Journal::open(&area.0, owner()).unwrap();
    assert!(matches!(
        executor.recover_public_policy(&mut journal).await.unwrap(),
        PublicPolicyRecovery::Missing {
            unlocking: false,
            ..
        }
    ));
    assert!(
        probe("198.18.1.2", "tcp", None, "24081"),
        "Recovery не устанавливает firewall автоматически"
    );
    drop(journal);
    kill_at(&area.0, "install-after");
    let mut journal = Journal::open(&area.0, owner()).unwrap();
    assert!(matches!(
        executor.recover_public_policy(&mut journal).await.unwrap(),
        PublicPolicyRecovery::DesiredRules { .. }
    ));
    assert!(matches!(
        journal.public_policy().unwrap().phase(),
        PublicPolicyPhase::Stable { .. }
    ));
    for address in ["198.18.1.2", "2001:db8:1::2"] {
        assert!(!probe(address, "tcp", None, "24081"));
    }
    drop(journal);
    kill_at(&area.0, "replace-before");
    let mut journal = Journal::open(&area.0, owner()).unwrap();
    assert!(matches!(
        executor.recover_public_policy(&mut journal).await.unwrap(),
        PublicPolicyRecovery::PreviousRules { .. }
    ));
    assert!(journal.needs_reconciliation(2));
    assert!(!probe("10.42.0.2", "tcp", None, "24081"));
    executor
        .apply_durable_public_policy(&mut journal, 2, 5, b.clone())
        .await
        .unwrap();
    assert!(probe("10.42.0.2", "tcp", None, "24081"));
    drop(journal);
    kill_at(&area.0, "replace-after");
    let mut journal = Journal::open(&area.0, owner()).unwrap();
    assert!(matches!(
        executor.recover_public_policy(&mut journal).await.unwrap(),
        PublicPolicyRecovery::DesiredRules { .. }
    ));
    assert!(!probe("10.42.0.2", "tcp", None, "24081"));
    drop(journal);
    kill_at(&area.0, "unlock-before");
    let mut journal = Journal::open(&area.0, owner()).unwrap();
    assert!(matches!(
        executor.recover_public_policy(&mut journal).await.unwrap(),
        PublicPolicyRecovery::UnlockPending { .. }
    ));
    assert!(!probe("198.18.1.2", "tcp", None, "24081"));
    drop(journal);
    kill_at(&area.0, "unlock-after");
    let mut journal = Journal::open(&area.0, owner()).unwrap();
    assert!(matches!(
        executor.recover_public_policy(&mut journal).await.unwrap(),
        PublicPolicyRecovery::Missing {
            unlocking: true,
            ..
        }
    ));
    assert!(journal.public_policy().is_some());
    executor
        .unlock_durable_public_policy(&mut journal, 2)
        .await
        .unwrap();
    assert!(journal.public_policy().is_none());
    assert!(journal.records().is_empty());
    assert_eq!(
        executor
            .unlock_durable_public_policy(&mut journal, 2)
            .await
            .unwrap(),
        None
    );
    for address in ["198.18.1.2", "2001:db8:1::2"] {
        assert!(probe(address, "tcp", None, "24081"));
    }
    executor
        .apply_durable_public_policy(&mut journal, 2, 5, a)
        .await
        .unwrap();
    executor
        .unlock_durable_public_policy(&mut journal, 2)
        .await
        .unwrap();
}
