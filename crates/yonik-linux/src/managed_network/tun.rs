//! Persistent single-queue TUN с durable intent и явной меткой владельца.
//! Неотмеченный интерфейс после прерванного create никогда не присваивается.
use super::executable::NetworkTool;
use super::{Journal, JournalError, Ownership, Reconciled, RecordState, Resource, Scope};
use crate::{Cancellation, LinuxLink, read_topology};
use rustix::fs;
use std::{
    fmt,
    fs::File,
    os::fd::AsRawFd,
    process::Stdio,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
};

#[path = "tun_config.rs"]
mod config;
#[path = "tun_custody.rs"]
mod custody;
#[path = "tun_resolver_rule.rs"]
mod resolver_rule;
#[path = "tun_rule.rs"]
mod rule;
#[path = "tun_topology.rs"]
mod topology;
pub(crate) use custody::BoundTun;
pub(crate) use topology::session_external_topology_with_framing;
#[cfg(test)]
#[path = "tun_session_tests.rs"]
mod session_tests;
#[cfg(test)]
#[path = "tun_tests.rs"]
mod tests;
#[path = "tun_write.rs"]
mod write;
pub use config::{TunAddress, TunRoute};
pub use resolver_rule::ResolverRouteRule;
pub use rule::TunRule;

const DEADLINE: Duration = Duration::from_secs(5);
const MAX_OUTPUT: usize = 256 * 1024;
static OPERATIONS: OnceLock<Arc<Semaphore>> = OnceLock::new();
struct OperationLease {
    _permit: OwnedSemaphorePermit,
}
async fn lease() -> Result<Arc<OperationLease>, TunError> {
    let semaphore = OPERATIONS.get_or_init(|| Arc::new(Semaphore::new(1)));
    let permit = tokio::time::timeout(DEADLINE, Arc::clone(semaphore).acquire_owned())
        .await
        .map_err(|_| TunError::Timeout)?
        .map_err(|_| TunError::Io)?;
    Ok(Arc::new(OperationLease { _permit: permit }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunError {
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
impl fmt::Display for TunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsafeExecutable => "Недоверенный системный ip",
            Self::Namespace => "Изменилось сетевое пространство TUN",
            Self::Invalid => "Неверный дескриптор TUN",
            Self::Io => "Ошибка исполнения TUN",
            Self::Timeout => "Истёк срок операции TUN",
            Self::OutputLimit => "Превышен лимит ответа TUN",
            Self::Rejected => "Ядро отклонило операцию TUN",
            Self::Evidence => "Неоднозначное состояние TUN",
            Self::Foreign => "Владение TUN не доказано",
            Self::Journal(_) => "Ошибка durable-журнала TUN",
        })
    }
}
impl std::error::Error for TunError {}
impl From<JournalError> for TunError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

fn namespace(file: &File) -> Result<(u64, u64), TunError> {
    let stat = fs::fstat(file).map_err(|_| TunError::Namespace)?;
    Ok((stat.st_dev, stat.st_ino))
}
fn name(name_id: u32) -> Result<String, TunError> {
    if name_id == 0 {
        return Err(TunError::Invalid);
    }
    Ok(format!("tofu{name_id:08x}"))
}
fn alias(owner: Ownership, id: u64) -> Result<Vec<u8>, TunError> {
    if id == 0 {
        return Err(TunError::Invalid);
    }
    let (device, inode) = owner.namespace();
    Ok(format!(
        "yonik:tun:1:{:08x}:{:016x}:{:016x}:{device:016x}:{inode:016x}:{id:016x}",
        owner.owner_uid(),
        owner.session(),
        owner.generation()
    )
    .into_bytes())
}
fn create_arguments(name_id: u32, uid: u32) -> Result<Vec<String>, TunError> {
    Ok(vec![
        "tuntap".into(),
        "add".into(),
        "dev".into(),
        name(name_id)?,
        "mode".into(),
        "tun".into(),
        "user".into(),
        uid.to_string(),
    ])
}
fn observed(links: &[LinuxLink], name_id: u32, expected: &[u8]) -> Result<Option<u32>, TunError> {
    let expected_name = name(name_id)?;
    if links.iter().any(|link| {
        link.alias.as_deref() == Some(expected) && link.name != expected_name.as_bytes()
    }) {
        // Переименование не доказывает исчезновение ресурса: нельзя удалять
        // запись журнала и объявлять cleanup успешным по отсутствию старого имени.
        return Err(TunError::Evidence);
    }
    let mut found = None;
    for link in links
        .iter()
        .filter(|link| link.name == expected_name.as_bytes())
    {
        if found.is_some()
            || link.link_type != 65534
            || link.kind.as_deref() != Some(b"tun")
            || link.alias.as_deref() != Some(expected)
        {
            return Err(TunError::Foreign);
        }
        found = Some(link.index);
    }
    Ok(found)
}

/// Метка защищает от случайной коллизии, а не от другого доверенного CAP_NET_ADMIN.
/// Caller исполняет durable I/O вне UI reactor и не считает Drop очисткой сети.
pub struct TunExecutor {
    executable: File,
    netns: File,
    owner: Ownership,
}
impl TunExecutor {
    pub fn open(owner: Ownership) -> Result<Self, TunError> {
        let netns = File::open("/proc/thread-self/ns/net").map_err(|_| TunError::Namespace)?;
        if namespace(&netns)? != owner.namespace() {
            return Err(TunError::Namespace);
        }
        Ok(Self {
            executable: NetworkTool::Ip
                .open()
                .map_err(|_| TunError::UnsafeExecutable)?,
            netns,
            owner,
        })
    }
    #[cfg(test)]
    pub(crate) fn isolated_fixture(owner: Ownership) -> Result<Self, TunError> {
        let netns = File::open("/proc/thread-self/ns/net").map_err(|_| TunError::Namespace)?;
        let actual = namespace(&netns)?;
        let host = std::env::var("YONIK_NFT_TEST_HOST_NETNS").map_err(|_| TunError::Namespace)?;
        let (device, inode) = host.split_once(':').ok_or(TunError::Namespace)?;
        let host = (
            device.parse::<u64>().map_err(|_| TunError::Namespace)?,
            inode.parse::<u64>().map_err(|_| TunError::Namespace)?,
        );
        if host == actual || actual != owner.namespace() {
            return Err(TunError::Namespace);
        }
        Ok(Self {
            executable: File::open("/usr/bin/ip").map_err(|_| TunError::Io)?,
            netns,
            owner,
        })
    }
    fn check_namespace(&self) -> Result<(), TunError> {
        let current = File::open("/proc/thread-self/ns/net").map_err(|_| TunError::Namespace)?;
        if namespace(&current)? != namespace(&self.netns)?
            || namespace(&current)? != self.owner.namespace()
        {
            return Err(TunError::Namespace);
        }
        Ok(())
    }
    async fn links(&self) -> Result<Vec<LinuxLink>, TunError> {
        self.check_namespace()?;
        let (_keep, mut cancel) = Cancellation::new();
        let snapshot = read_topology(&mut cancel, DEADLINE)
            .await
            .map_err(|_| TunError::Evidence)?;
        if (snapshot.namespace.device, snapshot.namespace.inode) != self.owner.namespace() {
            return Err(TunError::Namespace);
        }
        Ok(snapshot.links)
    }
    #[cfg(test)]
    async fn create(&self, name_id: u32, lease: Arc<OperationLease>) -> Result<(), TunError> {
        self.create_with_framing(name_id, false, lease).await
    }
    async fn create_with_framing(
        &self,
        name_id: u32,
        vnet_hdr: bool,
        lease: Arc<OperationLease>,
    ) -> Result<(), TunError> {
        self.check_namespace()?;
        let mut arguments = create_arguments(name_id, self.owner.owner_uid())?;
        if vnet_hdr {
            arguments.push("vnet_hdr".into());
        }
        let child = Command::new(format!("/proc/self/fd/{}", self.executable.as_raw_fd()))
            .args(arguments)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| TunError::Io)?;
        own_child(child, lease)?.wait().await
    }
    pub async fn ensure_tun(
        &mut self,
        journal: &mut Journal,
        id: u64,
        name_id: u32,
    ) -> Result<u32, TunError> {
        self.ensure_tun_with_framing(journal, id, name_id, false)
            .await
    }
    pub(crate) async fn ensure_tun_with_framing(
        &mut self,
        journal: &mut Journal,
        id: u64,
        name_id: u32,
        vnet_hdr: bool,
    ) -> Result<u32, TunError> {
        let operation = lease().await?;
        self.check_namespace()?;
        if journal.ownership() != self.owner {
            return Err(JournalError::WrongOwnership.into());
        }
        let marker = alias(self.owner, id)?;
        name(name_id)?;
        journal.intent(self.owner, Scope::Session, id, Resource::Tun { name_id })?;
        if journal
            .records()
            .iter()
            .any(|r| r.id() == id && r.state() == RecordState::CleanupRemaining)
        {
            return Err(JournalError::Conflict.into());
        }
        journal.require_reconciliation(self.owner, id)?;
        if let Some(index) = observed(&self.links().await?, name_id, &marker)? {
            journal.reconcile(self.owner, id, Reconciled::Owned)?;
            return Ok(index);
        }
        self.create_with_framing(name_id, vnet_hdr, Arc::clone(&operation))
            .await?;
        // Только successful create этого вызова разрешает отметить новый объект.
        // После crash его отсутствие alias не даёт права повторного присвоения.
        let links = self.links().await?;
        let expected_name = name(name_id)?;
        let candidates: Vec<_> = links
            .iter()
            .filter(|l| l.name == expected_name.as_bytes())
            .collect();
        let [link] = candidates.as_slice() else {
            return Err(TunError::Evidence);
        };
        if link.link_type != 65534
            || link.kind.as_deref() != Some(b"tun")
            || link.alias.as_ref().is_some_and(|a| !a.is_empty())
        {
            return Err(TunError::Foreign);
        }
        let index = link.index;
        self.check_namespace()?;
        write::run(
            write::Action::SetAlias {
                index,
                alias: marker.clone(),
            },
            Arc::clone(&operation),
        )
        .await?;
        if observed(&self.links().await?, name_id, &marker)? != Some(index) {
            return Err(TunError::Evidence);
        }
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        Ok(index)
    }
    pub async fn remove_tun(&mut self, journal: &mut Journal, id: u64) -> Result<(), TunError> {
        let operation = lease().await?;
        self.check_namespace()?;
        if journal.ownership() != self.owner {
            return Err(JournalError::WrongOwnership.into());
        }
        if journal
            .records()
            .iter()
            .any(|record| record.resource().parent_tun_id() == Some(id))
        {
            return Err(JournalError::Conflict.into());
        }
        let record = journal
            .records()
            .iter()
            .find(|r| r.id() == id)
            .ok_or(JournalError::Missing)?;
        let name_id = match record.resource() {
            Resource::Tun { name_id } if record.scope() == Scope::Session => *name_id,
            _ => return Err(TunError::Invalid),
        };
        let marker = alias(self.owner, id)?;
        journal.require_reconciliation(self.owner, id)?;
        let topology = self.configuration_snapshot().await?;
        let Some(index) = observed(&topology.links, name_id, &marker)? else {
            journal.reconcile(self.owner, id, Reconciled::Absent)?;
            return Ok(());
        };
        if journal.records().iter().any(|record| matches!(record.resource(), Resource::Route { ifindex, .. } | Resource::Dns { ifindex, .. } if *ifindex == index)) {
            return Err(JournalError::Conflict.into());
        }
        config::check_tun_teardown(&topology, index)?;
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        journal.mark_cleanup(self.owner, id)?;
        self.check_namespace()?;
        write::run(write::Action::Delete { index }, Arc::clone(&operation)).await?;
        if observed(&self.links().await?, name_id, &marker)?.is_some() {
            return Err(TunError::Evidence);
        }
        journal.reconcile(self.owner, id, Reconciled::Absent)?;
        Ok(())
    }
}

struct Running {
    cancel: oneshot::Sender<()>,
    receive: oneshot::Receiver<Result<(), TunError>>,
}
impl Running {
    async fn wait(self) -> Result<(), TunError> {
        let result = self.receive.await.map_err(|_| TunError::Io)?;
        drop(self.cancel);
        result
    }
}
fn own_child(mut child: Child, lease: Arc<OperationLease>) -> Result<Running, TunError> {
    let output = child.stdout.take().ok_or(TunError::Io)?;
    let errors = child.stderr.take().ok_or(TunError::Io)?;
    let (cancel, cancelled) = oneshot::channel();
    let (send, receive) = oneshot::channel();
    tokio::spawn(async move {
        let _lease = lease;
        let work = async {
            let (_, _, status) = tokio::try_join!(drain(output), drain(errors), async {
                child.wait().await.map_err(|_| TunError::Io)
            })?;
            if !status.success() {
                return Err(TunError::Rejected);
            }
            Ok(())
        };
        let result = tokio::select! {result=tokio::time::timeout(DEADLINE,work)=>result.unwrap_or(Err(TunError::Timeout)),_=cancelled=>Err(TunError::Io)};
        if result.is_err() && child.kill().await.is_err() {
            let _reaped = child.wait().await;
        }
        let _receiver = send.send(result);
    });
    Ok(Running { cancel, receive })
}
async fn drain(mut stream: impl AsyncRead + Unpin) -> Result<(), TunError> {
    let mut used = 0usize;
    let mut bytes = [0; 4096];
    loop {
        let count = stream.read(&mut bytes).await.map_err(|_| TunError::Io)?;
        if count == 0 {
            return Ok(());
        }
        used = used.checked_add(count).ok_or(TunError::OutputLimit)?;
        if used > MAX_OUTPUT {
            return Err(TunError::OutputLimit);
        }
    }
}
