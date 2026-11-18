use super::*;

fn descriptor() -> Table {
    Table::new(
        Ownership::new(1000, 7, 9, 3, 11).expect("Корректный тестовый владелец"),
        Scope::Session,
        2,
        5,
        NftFamily::Inet,
    )
}

#[test]
fn identity_requires_complete_canonical_comment() {
    let table = descriptor();
    assert_eq!(table.name, "yonik_0000000000000005");
    let owned = serde_json::json!({"nftables":[{"table":{
        "family":"inet", "name":table.name, "comment":table.comment, "handle":42
    }}]});
    assert_eq!(
        observe_json(&serde_json::to_vec(&owned).unwrap(), &table),
        Ok(Observation::Owned(42))
    );
    let mut foreign = owned;
    foreign["nftables"][0]["table"]["comment"] = "yonik".into();
    assert_eq!(
        observe_json(&serde_json::to_vec(&foreign).unwrap(), &table),
        Err(NftError::Foreign)
    );
}

#[test]
fn parser_refuses_ambiguous_or_unbounded_evidence() {
    let table = descriptor();
    for value in [
        serde_json::json!({"nftables":[{"table":{"family":"inet","name":table.name,"comment":table.comment}}]}),
        serde_json::json!({"nftables":[{"rule":{}}]}),
        serde_json::json!({"nftables":[{"table":{"family":"inet","name":table.name,"comment":table.comment,"handle":0}}]}),
    ] {
        assert!(observe_json(&serde_json::to_vec(&value).unwrap(), &table).is_err());
    }
    assert_eq!(
        observe_json(&vec![b' '; MAX_OUTPUT + 1], &table),
        Err(NftError::OutputLimit)
    );
    assert_eq!(
        observe_json(br#"{"nftables":[]}"#, &table),
        Ok(Observation::Absent)
    );
}

#[test]
fn commands_are_typed_exclusive_and_delete_only_by_handle() {
    let table = descriptor();
    let create = request(Action::Create(&table));
    assert_eq!(
        create["nftables"][0]["create"]["table"]["comment"],
        table.comment
    );
    let delete = request(Action::Delete(&table, 42));
    let target = &delete["nftables"][0]["delete"]["table"];
    assert_eq!(target["handle"], 42);
    assert!(target.get("name").is_none());
}

#[tokio::test]
async fn drain_enforces_limit_before_extending_buffer() {
    let (mut input, output) = tokio::io::duplex(MAX_OUTPUT + 1);
    let writing = tokio::spawn(async move {
        input.write_all(&vec![b'x'; MAX_OUTPUT + 1]).await.unwrap();
    });
    assert_eq!(drain(output).await, Err(NftError::OutputLimit));
    writing.await.unwrap();
}

#[test]
fn complete_identity_fits_kernel_comment_and_changes_with_each_owner_field() {
    let owner = Ownership::new(u32::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX).unwrap();
    let table = Table::new(
        owner,
        Scope::PublicBlock,
        u64::MAX,
        u64::MAX,
        NftFamily::Ip6,
    );
    assert!(table.comment.len() <= 128);
    let expected = descriptor();
    for (family, name) in [
        ("ip", expected.name.as_str()),
        ("inet", "yonik_0000000000000006"),
    ] {
        let value = json!({"nftables":[{"table":{"family":family,"name":name,"comment":expected.comment,"handle":42}}]});
        assert_eq!(
            observe_json(&serde_json::to_vec(&value).unwrap(), &expected),
            Ok(Observation::Absent)
        );
    }
    for owner in [
        Ownership::new(1001, 7, 9, 3, 11).unwrap(),
        Ownership::new(1000, 8, 9, 3, 11).unwrap(),
        Ownership::new(1000, 7, 10, 3, 11).unwrap(),
        Ownership::new(1000, 7, 9, 4, 11).unwrap(),
        Ownership::new(1000, 7, 9, 3, 12).unwrap(),
    ] {
        assert_ne!(
            Table::new(owner, Scope::Session, 2, 5, NftFamily::Inet).comment,
            expected.comment
        );
    }
}

async fn owned_test_child(
    command: &str,
    args: &[&str],
    deadline: Duration,
) -> (Running, u32, Arc<Semaphore>) {
    let child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    let gate = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&gate).acquire_owned().await.unwrap();
    let global = PROCESS_LIMIT.acquire().await.unwrap();
    (
        own_child(child, Vec::new(), permit, global, deadline).unwrap(),
        pid,
        gate,
    )
}

#[tokio::test]
async fn cancellation_reaps_child_before_releasing_executor_gate() {
    let (running, pid, gate) = owned_test_child("/usr/bin/sleep", &["30"], DEADLINE).await;
    assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
    assert_eq!(gate.available_permits(), 0);
    drop(running);
    let _ready = tokio::time::timeout(Duration::from_secs(2), gate.acquire())
        .await
        .unwrap()
        .unwrap();
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}

#[tokio::test]
async fn deadline_and_output_overflow_reap_children() {
    for (command, args, deadline, expected) in [
        (
            "/usr/bin/sleep",
            vec!["30"],
            Duration::from_millis(30),
            NftError::Timeout,
        ),
        ("/usr/bin/yes", vec![], DEADLINE, NftError::OutputLimit),
    ] {
        let (running, pid, _gate) = owned_test_child(command, &args, deadline).await;
        assert_eq!(running.wait().await, Err(expected));
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }
}

/// Запускать только внутри нового user+mount+net namespace, с tmpfs на /tmp.
/// Идентификатор host netns передаётся runner-ом ДО unshare. В production нет bypass.
#[tokio::test]
#[ignore = "Требует явно изолированный network namespace и YONIK_NFT_TEST_HOST_NETNS"]
async fn real_namespace_journal_create_reopen_foreign_and_stale_handle() {
    let host =
        std::env::var("YONIK_NFT_TEST_HOST_NETNS").expect("Явный opt-in изолированного runner");
    let host: Vec<u64> = host
        .split(':')
        .map(|part| part.parse().expect("Числовая identity host netns"))
        .collect();
    assert_eq!(host.len(), 2);
    let netns = File::open("/proc/thread-self/ns/net").unwrap();
    let current = namespace(&netns).unwrap();
    assert_ne!(
        current,
        (host[0], host[1]),
        "Запрещены эффекты в host netns"
    );
    let interfaces: Vec<_> = std::fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        interfaces,
        vec![std::ffi::OsString::from("lo")],
        "Разрешён только пустой namespace с loopback"
    );
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let owner = Ownership::new(1000, 7, 9, current.0, current.1).unwrap();
    // Только fixture: host-root бинарник отображается nobody внутри userns.
    // Production open() сохраняет строгую root ownership проверку.
    let mut executor = NftExecutor {
        executable: File::open("/usr/bin/nft").unwrap(),
        netns,
        owner,
        gate: Arc::new(Semaphore::new(1)),
    };
    let path = std::path::PathBuf::from(format!("/tmp/yonik-nft-test-{}", std::process::id()));
    let mut journal = Journal::open(&path, owner).unwrap();
    executor
        .ensure_table(&mut journal, Scope::Session, 2, 5, NftFamily::Inet)
        .await
        .unwrap();
    executor
        .ensure_table(&mut journal, Scope::Session, 2, 5, NftFamily::Inet)
        .await
        .unwrap();
    assert_eq!(journal.records().len(), 1);
    drop(journal);
    let mut journal = Journal::open(&path, owner).unwrap();
    assert!(journal.needs_reconciliation(2));
    executor
        .ensure_table(&mut journal, Scope::Session, 2, 5, NftFamily::Inet)
        .await
        .unwrap();
    assert!(!journal.needs_reconciliation(2));
    assert_eq!(
        executor
            .remove_table(&mut journal, Scope::PublicBlock, 2)
            .await,
        Err(NftError::Journal(JournalError::Missing))
    );
    journal.mark_cleanup(owner, 2).unwrap();
    let table = Table::new(owner, Scope::Session, 2, 5, NftFamily::Inet);
    let Observation::Owned(handle) = executor.observe(&table).await.unwrap() else {
        panic!("Собственная таблица существует до cleanup");
    };
    executor.run(Action::Delete(&table, handle)).await.unwrap();
    // Сбой после эффекта удаления, до сохранения результата: старый Apply
    // не должен создавать ресурс заново после durable Stop.
    drop(journal);
    let mut journal = Journal::open(&path, owner).unwrap();
    assert_eq!(
        executor
            .ensure_table(&mut journal, Scope::Session, 2, 5, NftFamily::Inet)
            .await,
        Err(NftError::Journal(JournalError::Conflict))
    );
    assert_eq!(executor.observe(&table).await.unwrap(), Observation::Absent);
    executor
        .remove_table(&mut journal, Scope::Session, 2)
        .await
        .unwrap();
    assert!(journal.records().is_empty());

    executor
        .ensure_table(&mut journal, Scope::Session, 3, 6, NftFamily::Inet)
        .await
        .unwrap();
    let table = Table::new(owner, Scope::Session, 3, 6, NftFamily::Inet);
    let Observation::Owned(old) = executor.observe(&table).await.unwrap() else {
        panic!("Собственная таблица существует");
    };
    executor.run(Action::Delete(&table, old)).await.unwrap();
    let foreign = Table {
        family: table.family,
        name: table.name.clone(),
        comment: "foreign-test".into(),
    };
    executor.run(Action::Create(&foreign)).await.unwrap();
    assert_eq!(
        executor.run(Action::Create(&table)).await,
        Err(NftError::Rejected)
    );
    assert_eq!(
        executor.run(Action::Delete(&table, old)).await,
        Err(NftError::Rejected)
    );
    assert!(matches!(
        executor.observe(&foreign).await.unwrap(),
        Observation::Owned(_)
    ));
    assert_eq!(
        executor
            .ensure_table(&mut journal, Scope::Session, 3, 6, NftFamily::Inet)
            .await,
        Err(NftError::Foreign)
    );
    assert_eq!(
        executor.remove_table(&mut journal, Scope::Session, 3).await,
        Err(NftError::Foreign)
    );
    assert_eq!(journal.records().len(), 1);
    let Observation::Owned(handle) = executor.observe(&foreign).await.unwrap() else {
        panic!("Чужая таблица должна сохраниться");
    };
    executor
        .run(Action::Delete(&foreign, handle))
        .await
        .unwrap();
    executor
        .remove_table(&mut journal, Scope::Session, 3)
        .await
        .unwrap();
    assert!(journal.records().is_empty());
    drop(journal);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn system_nft_trust_check_is_read_only() {
    // Установка nft не обязательна для запуска обычных unit-тестов.
    if ["/usr/bin/nft", "/usr/sbin/nft"]
        .iter()
        .any(|name| std::path::Path::new(name).exists())
    {
        NetworkTool::Nft
            .open()
            .expect("Установленный системный nft должен пройти строгую проверку");
    }
}

#[tokio::test]
async fn cleanup_replay_is_rejected_before_starting_any_command() {
    let netns = File::open("/proc/thread-self/ns/net").unwrap();
    let current = namespace(&netns).unwrap();
    let owner = Ownership::new(1000, 7, 9, current.0, current.1).unwrap();
    let mut executor = NftExecutor {
        // Этот fixture нельзя исполнить: любой случайный spawn даст Io,
        // а ожидаемый Conflict должен возникнуть раньше команды и наблюдения.
        executable: File::open("/dev/null").unwrap(),
        netns,
        owner,
        gate: Arc::new(Semaphore::new(1)),
    };
    let path = std::env::temp_dir().join(format!("yonik-nft-replay-{}", std::process::id()));
    let mut journal = Journal::open(&path, owner).unwrap();
    journal
        .intent(
            owner,
            Scope::Session,
            2,
            Resource::NftTable {
                table_id: 5,
                family: NftFamily::Inet,
            },
        )
        .unwrap();
    journal.reconcile(owner, 2, Reconciled::Owned).unwrap();
    journal.mark_cleanup(owner, 2).unwrap();
    for _ in 0..2 {
        assert_eq!(
            executor
                .ensure_table(&mut journal, Scope::Session, 2, 5, NftFamily::Inet)
                .await,
            Err(NftError::Journal(JournalError::Conflict))
        );
        drop(journal);
        journal = Journal::open(&path, owner).unwrap();
    }
    drop(journal);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn cancelled_generic_recheck_revokes_old_confirmation() {
    use futures_util::FutureExt;
    let netns = File::open("/proc/thread-self/ns/net").unwrap();
    let current = namespace(&netns).unwrap();
    let owner = Ownership::new(1000, 7, 9, current.0, current.1).unwrap();
    let gate = Arc::new(Semaphore::new(1));
    let mut executor = NftExecutor {
        executable: File::open("/dev/null").unwrap(),
        netns,
        owner,
        gate: Arc::clone(&gate),
    };
    let path = std::env::temp_dir().join(format!(
        "yonik-nft-cancelled-recheck-{}",
        std::process::id()
    ));
    let mut journal = Journal::open(&path, owner).unwrap();
    journal
        .intent(
            owner,
            Scope::Session,
            2,
            Resource::NftTable {
                table_id: 5,
                family: NftFamily::Inet,
            },
        )
        .unwrap();
    journal.reconcile(owner, 2, Reconciled::Owned).unwrap();
    assert!(!journal.needs_reconciliation(2));
    let _busy = gate.acquire().await.unwrap();
    assert!(
        executor
            .ensure_table(&mut journal, Scope::Session, 2, 5, NftFamily::Inet)
            .now_or_never()
            .is_none()
    );
    assert!(journal.needs_reconciliation(2));
    drop(journal);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn a_new_executor_waits_until_cancelled_command_is_reaped() {
    use futures_util::FutureExt;
    let (running, pid, _old_gate) = owned_test_child("/usr/bin/sleep", &["30"], DEADLINE).await;
    let netns = File::open("/proc/thread-self/ns/net").unwrap();
    let ns = namespace(&netns).unwrap();
    let mut next = NftExecutor {
        executable: File::open("/dev/null").unwrap(),
        netns,
        owner: Ownership::new(1000, 7, 9, ns.0, ns.1).unwrap(),
        gate: Arc::new(Semaphore::new(1)),
    };
    let mut waiting = Box::pin(next.run(Action::List));
    assert!(
        waiting.as_mut().now_or_never().is_none(),
        "Другой executor не обходит живую команду"
    );
    drop(running);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .unwrap(),
        Err(NftError::Io)
    );
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}
