//! Типизированные nftables-ресурсы с durable-учётом и проверкой владения.
//! Неоднозначность оставляет durable intent; Drop не обещает сетевую очистку.
use super::{
    Journal, JournalError, NftFamily, Ownership, Reconciled, RecordState, Resource, Scope,
};
use super::{executable::NetworkTool, firewall::PublicBlockPolicy};
use rustix::fs;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fmt, fs::File, os::fd::AsRawFd, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit, oneshot},
};

const MAX_OUTPUT: usize = 256 * 1024;
// Между executor-ами тоже нельзя обгонять отменённую команду: старый Child
// удерживает общий permit до kill/wait, даже после Drop исходного executor.
static PROCESS_LIMIT: Semaphore = Semaphore::const_new(1);
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftError {
    UnsafeExecutable,
    Namespace,
    Invalid,
    Io,
    Timeout,
    OutputLimit,
    Rejected,
    Evidence,
    Foreign,
    Journal(JournalError),
}
impl fmt::Display for NftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsafeExecutable => "Недоверенный системный nft",
            Self::Namespace => "Изменилось сетевое пространство имён",
            Self::Invalid => "Неверный дескриптор nft-таблицы",
            Self::Io => "Ошибка запуска или I/O nft",
            Self::Timeout => "Истёк срок выполнения nft",
            Self::OutputLimit => "Превышен лимит ответа nft",
            Self::Rejected => "nft отклонил операцию",
            Self::Evidence => "Неоднозначный ответ nft",
            Self::Foreign => "Владение nft-таблицей не доказано",
            Self::Journal(_) => "Ошибка durable-журнала nft",
        })
    }
}
impl std::error::Error for NftError {}
impl From<JournalError> for NftError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

struct Table {
    family: &'static str,
    name: String,
    comment: String,
}
impl Table {
    fn new(owner: Ownership, scope: Scope, id: u64, table_id: u64, family: NftFamily) -> Self {
        let (device, inode) = owner.namespace();
        let scope = match scope {
            Scope::Session => "session",
            Scope::PublicBlock => "public-block",
        };
        Self {
            family: match family {
                NftFamily::Inet => "inet",
                NftFamily::Ip => "ip",
                NftFamily::Ip6 => "ip6",
            },
            name: format!("yonik_{table_id:016x}"),
            comment: format!(
                "yonik:1:{:08x}:{:016x}:{:016x}:{device:016x}:{inode:016x}:{id:016x}:{scope}",
                owner.owner_uid(),
                owner.session(),
                owner.generation()
            ),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Observation {
    Absent,
    Owned(u64),
}
enum Action<'a> {
    List,
    Create(&'a Table),
    Delete(&'a Table, u64),
    ListTable(&'a Table),
    InstallBlock(&'a Table, &'a PublicBlockPolicy),
    CheckBlock(&'a Table, &'a PublicBlockPolicy),
    ReplaceBlock(&'a Table, u64, &'a Table, &'a PublicBlockPolicy),
    Quarantine(Vec<Value>),
}
fn request(action: Action<'_>) -> Value {
    let command = match action {
        Action::List => json!({"list":{"tables":null}}),
        Action::Create(table) => {
            json!({"create":{"table":{"family":table.family,"name":table.name,"comment":table.comment}}})
        }
        Action::Delete(table, handle) => {
            json!({"delete":{"table":{"family":table.family,"handle":handle}}})
        }
        Action::ListTable(table) => {
            json!({"list":{"table":{"family":table.family,"name":table.name}}})
        }
        Action::InstallBlock(table, policy) | Action::CheckBlock(table, policy) => {
            let mut commands = vec![request(Action::Create(table))["nftables"][0].clone()];
            commands.extend(policy.commands(&table.name));
            return json!({"nftables": commands});
        }
        Action::ReplaceBlock(old, handle, new, policy) => {
            let mut commands = vec![
                request(Action::Delete(old, handle))["nftables"][0].clone(),
                request(Action::Create(new))["nftables"][0].clone(),
            ];
            commands.extend(policy.commands(&new.name));
            return json!({"nftables": commands});
        }
        Action::Quarantine(commands) => return json!({"nftables": commands}),
    };
    json!({"nftables":[command]})
}

#[path = "nft_quarantine.rs"]
mod quarantine;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    nftables: Vec<Value>,
}
fn observe_json(bytes: &[u8], expected: &Table) -> Result<Observation, NftError> {
    if bytes.len() > MAX_OUTPUT {
        return Err(NftError::OutputLimit);
    }
    let listing: Listing = serde_json::from_slice(bytes).map_err(|_| NftError::Evidence)?;
    let mut found = None;
    for item in listing.nftables {
        let object = item.as_object().ok_or(NftError::Evidence)?;
        if object.len() != 1 {
            return Err(NftError::Evidence);
        }
        if object.contains_key("metainfo") {
            continue;
        }
        let table = object
            .get("table")
            .and_then(Value::as_object)
            .ok_or(NftError::Evidence)?;
        let family = table
            .get("family")
            .and_then(Value::as_str)
            .ok_or(NftError::Evidence)?;
        let name = table
            .get("name")
            .and_then(Value::as_str)
            .ok_or(NftError::Evidence)?;
        if family != expected.family || name != expected.name {
            continue;
        }
        if table
            .keys()
            .any(|key| !matches!(key.as_str(), "family" | "name" | "comment" | "handle"))
            || table.get("comment").and_then(Value::as_str) != Some(expected.comment.as_str())
        {
            return Err(NftError::Foreign);
        }
        let handle = table
            .get("handle")
            .and_then(Value::as_u64)
            .filter(|handle| *handle != 0)
            .ok_or(NftError::Evidence)?;
        if found.replace(handle).is_some() {
            return Err(NftError::Evidence);
        }
    }
    Ok(found.map_or(Observation::Absent, Observation::Owned))
}

fn namespace(file: &File) -> Result<(u64, u64), NftError> {
    let stat = fs::fstat(file).map_err(|_| NftError::Namespace)?;
    Ok((stat.st_dev, stat.st_ino))
}

/// Один executor закрепляет namespace FD на весь срок сессии; параллельные
/// операции через него невозможны. Никаких путей и команд от клиента API не принимает.
pub struct NftExecutor {
    executable: File,
    netns: File,
    owner: Ownership,
    gate: Arc<Semaphore>,
}
impl NftExecutor {
    pub fn open(owner: Ownership) -> Result<Self, NftError> {
        let netns = File::open("/proc/thread-self/ns/net").map_err(|_| NftError::Namespace)?;
        if namespace(&netns)? != owner.namespace() {
            return Err(NftError::Namespace);
        }
        Ok(Self {
            executable: NetworkTool::Nft
                .open()
                .map_err(|_| NftError::UnsafeExecutable)?,
            netns,
            owner,
            gate: Arc::new(Semaphore::new(1)),
        })
    }
    fn check_namespace(&self) -> Result<(), NftError> {
        let current = File::open("/proc/thread-self/ns/net").map_err(|_| NftError::Namespace)?;
        if namespace(&current)? != namespace(&self.netns)?
            || namespace(&current)? != self.owner.namespace()
        {
            return Err(NftError::Namespace);
        }
        Ok(())
    }
    async fn run(&mut self, action: Action<'_>) -> Result<Vec<u8>, NftError> {
        let check_only = matches!(&action, Action::CheckBlock(..));
        let bytes = serde_json::to_vec(&request(action)).map_err(|_| NftError::Invalid)?;
        if bytes.len() > MAX_OUTPUT {
            return Err(NftError::Invalid);
        }
        let gate = tokio::time::timeout(DEADLINE, Arc::clone(&self.gate).acquire_owned())
            .await
            .map_err(|_| NftError::Timeout)?
            .map_err(|_| NftError::Io)?;
        let global = tokio::time::timeout(DEADLINE, PROCESS_LIMIT.acquire())
            .await
            .map_err(|_| NftError::Timeout)?
            .map_err(|_| NftError::Io)?;
        self.check_namespace()?;
        let mut command = Command::new(format!("/proc/self/fd/{}", self.executable.as_raw_fd()));
        command.args(["-j", "-n"]);
        if check_only {
            command.arg("-c");
        }
        let child = command
            .args(["-f", "-"])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| NftError::Io)?;
        own_child(child, bytes, gate, global, DEADLINE)?
            .wait()
            .await
    }
    async fn observe(&mut self, table: &Table) -> Result<Observation, NftError> {
        observe_json(&self.run(Action::List).await?, table)
    }
    /// Только синтаксис/возможности kernel: -c не устанавливает таблицу.
    pub(crate) async fn check_public_policy(
        &mut self,
        policy: &PublicBlockPolicy,
    ) -> Result<(), NftError> {
        let mut bytes = [0; 8];
        getrandom::getrandom(&mut bytes).map_err(|_| NftError::Io)?;
        let id = u64::from_le_bytes(bytes).max(1);
        let table = block::block_table(self.owner, id, id, policy);
        self.run(Action::CheckBlock(&table, policy))
            .await
            .map(|_| ())
    }
    #[cfg(test)]
    pub(crate) fn isolated_fixture(owner: Ownership) -> Result<Self, NftError> {
        let netns = File::open("/proc/thread-self/ns/net").map_err(|_| NftError::Namespace)?;
        let actual = namespace(&netns)?;
        let host = std::env::var("YONIK_NFT_TEST_HOST_NETNS").map_err(|_| NftError::Namespace)?;
        if host == format!("{}:{}", actual.0, actual.1) || actual != owner.namespace() {
            return Err(NftError::Namespace);
        }
        Ok(Self {
            executable: File::open("/usr/bin/nft").map_err(|_| NftError::Io)?,
            netns,
            owner,
            gate: Arc::new(Semaphore::new(1)),
        })
    }
    /// Durable intent предшествует create. Повтор сначала сверяет ОС.
    pub async fn ensure_table(
        &mut self,
        journal: &mut Journal,
        scope: Scope,
        id: u64,
        table_id: u64,
        family: NftFamily,
    ) -> Result<(), NftError> {
        journal.intent(
            self.owner,
            scope,
            id,
            Resource::NftTable { table_id, family },
        )?;
        journal.require_reconciliation(self.owner, id)?;
        if journal
            .records()
            .iter()
            .any(|record| record.id() == id && record.state() == RecordState::CleanupRemaining)
        {
            return Err(NftError::Journal(JournalError::Conflict));
        }
        let table = Table::new(self.owner, scope, id, table_id, family);
        if self.observe(&table).await? == Observation::Absent {
            self.run(Action::Create(&table)).await?;
        }
        match self.observe(&table).await? {
            Observation::Owned(_) => journal
                .reconcile(self.owner, id, Reconciled::Owned)
                .map_err(Into::into),
            Observation::Absent => Err(NftError::Evidence),
        }
    }
    /// Отдельный id/scope исключает неявное снятие PublicBlock.
    pub async fn remove_table(
        &mut self,
        journal: &mut Journal,
        scope: Scope,
        id: u64,
    ) -> Result<(), NftError> {
        if journal.ownership() != self.owner {
            return Err(NftError::Journal(JournalError::WrongOwnership));
        }
        let record = journal
            .records()
            .iter()
            .find(|record| record.id() == id && record.scope() == scope)
            .ok_or(NftError::Journal(JournalError::Missing))?;
        let Resource::NftTable { table_id, family } = *record.resource() else {
            return Err(NftError::Invalid);
        };
        let table = Table::new(self.owner, scope, id, table_id, family);
        journal.require_reconciliation(self.owner, id)?;
        let handle = match self.observe(&table).await? {
            Observation::Absent => {
                return journal
                    .reconcile(self.owner, id, Reconciled::Absent)
                    .map_err(Into::into);
            }
            Observation::Owned(handle) => handle,
        };
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        journal.mark_cleanup(self.owner, id)?;
        self.run(Action::Delete(&table, handle)).await?;
        match self.observe(&table).await? {
            Observation::Absent => journal
                .reconcile(self.owner, id, Reconciled::Absent)
                .map_err(Into::into),
            Observation::Owned(_) => Err(NftError::Evidence),
        }
    }
}

struct Running {
    cancel: oneshot::Sender<()>,
    receive: oneshot::Receiver<Result<Vec<u8>, NftError>>,
}
impl Running {
    async fn wait(self) -> Result<Vec<u8>, NftError> {
        let result = self.receive.await.map_err(|_| NftError::Io)?;
        drop(self.cancel);
        result
    }
}
fn own_child(
    mut child: Child,
    bytes: Vec<u8>,
    gate: OwnedSemaphorePermit,
    global: SemaphorePermit<'static>,
    deadline: Duration,
) -> Result<Running, NftError> {
    let mut input = child.stdin.take().ok_or(NftError::Io)?;
    let output = child.stdout.take().ok_or(NftError::Io)?;
    let errors = child.stderr.take().ok_or(NftError::Io)?;
    let (cancel, cancelled) = oneshot::channel::<()>();
    let (send, receive) = oneshot::channel();
    // Задача сохраняет владение Child после отмены вызывающего future,
    // убивает и wait/reap-ит его; kill_on_drop страхует shutdown runtime.
    tokio::spawn(async move {
        let (_gate, _global) = (gate, global);
        let work = async {
            let write = async {
                input.write_all(&bytes).await.map_err(|_| NftError::Io)?;
                drop(input);
                Ok::<_, NftError>(())
            };
            let ((), stdout, _stderr, status) =
                tokio::try_join!(write, drain(output), drain(errors), async {
                    child.wait().await.map_err(|_| NftError::Io)
                })?;
            if !status.success() {
                return Err(NftError::Rejected);
            }
            Ok(stdout)
        };
        let result = tokio::select! {
            result = tokio::time::timeout(deadline, work) => result.unwrap_or(Err(NftError::Timeout)),
            _ = cancelled => Err(NftError::Io),
        };
        if result.is_err() {
            // kill() также выполняет wait; при уже завершённом child wait
            // безопасен. Ошибка не превращается в подтверждение cleanup.
            if child.kill().await.is_err() {
                let _reap = child.wait().await;
            }
        }
        let _receiver_gone = send.send(result);
    });
    Ok(Running { cancel, receive })
}

async fn drain(mut reader: impl AsyncRead + Unpin) -> Result<Vec<u8>, NftError> {
    let mut result = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let count = reader.read(&mut chunk).await.map_err(|_| NftError::Io)?;
        if count == 0 {
            return Ok(result);
        }
        if count > MAX_OUTPUT.saturating_sub(result.len()) {
            return Err(NftError::OutputLimit);
        }
        result.extend_from_slice(&chunk[..count]);
    }
}
#[cfg(test)]
#[path = "nft_tests.rs"]
mod tests;

#[path = "nft_block.rs"]
mod block;

#[path = "nft_policy.rs"]
mod policy;
#[cfg(test)]
pub(crate) use block::tests::{
    fixture as network_fixture, peer as network_peer, probe as network_probe,
};
pub use policy::PublicPolicyRecovery;
