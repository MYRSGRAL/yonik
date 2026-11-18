//! Одноразовые artifacts. Выдача artifact ещё не подтверждает применение сети.

use std::{
    collections::HashMap,
    future::Future,
    num::NonZeroU64,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{sync::Semaphore, time::Instant};
use yonik_application::{ConfigDigest, EnvironmentStamp};
use zbus::{Connection, Message};

use super::memory::{ByteBudget, ByteLease, MAX_RETAINED_CONFIG_BYTES, Reclaimer, config_budget};
use super::{AuthorizationError, NetworkAction, PeerAuthorizer, Prompt};
use crate::Cancellation;

pub const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PENDING: usize = 16;
pub const MAX_PENDING_PER_PEER: usize = 4;
pub const MAX_IN_FLIGHT: usize = 4;
pub const PREPARED_TTL: Duration = Duration::from_secs(60);
const FACTORY_TIMEOUT: Duration = Duration::from_secs(30);

/// Реализация вычисляет SHA-256 текущих bytes, а не возвращает сохранённый digest.
/// Доверенный factory обязан выполнить config-check до передачи artifact.
pub trait PreparedArtifact: Send + 'static {
    fn bundle_digests(&self) -> Option<super::service::BundleDigests> {
        None
    }
    fn current_digest(&self) -> ConfigDigest;
    /// Размер конфигурационного payload; память sealed binary учитывается отдельно.
    fn byte_len(&self) -> usize;
    /// Удерживаемая ёмкость payload; artifact после factory должен быть immutable.
    fn retained_bytes(&self) -> usize;
}

/// Сохраняет бюджет вместе с выданными данными до их освобождения.
/// Не предоставляет unwrapping/Clone/DerefMut, освобождающие учёт раньше данных.
pub struct ClaimedArtifact<A> {
    artifact: A,
    memory: ByteLease,
}
impl<A> std::ops::Deref for ClaimedArtifact<A> {
    type Target = A;
    fn deref(&self) -> &A {
        &self.artifact
    }
}
impl<A> AsRef<A> for ClaimedArtifact<A> {
    fn as_ref(&self) -> &A {
        &self.artifact
    }
}
impl<A> std::fmt::Debug for ClaimedArtifact<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClaimedArtifact(<скрыто>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PreparedContext {
    session: NonZeroU64,
    generation: NonZeroU64,
    environment: EnvironmentStamp,
}
impl PreparedContext {
    /// Все поколения принадлежат доверенному host; LOCAL_ENV здесь неприемлем.
    pub fn new(
        session: NonZeroU64,
        generation: NonZeroU64,
        environment: EnvironmentStamp,
    ) -> Result<Self, PreparedError> {
        if !environment.authorized
            || [
                environment.network,
                environment.applications,
                environment.authorization,
                environment.engine,
            ]
            .contains(&0)
        {
            return Err(PreparedError::Stale);
        }
        Ok(Self {
            session,
            generation,
            environment,
        })
    }
}
impl std::fmt::Debug for PreparedContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedContext(<скрыто>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PreparedHandle([u8; 32]);
impl PreparedHandle {
    /// Только wire encoding; не выводить в логи.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl TryFrom<&[u8]> for PreparedHandle {
    type Error = PreparedError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(
            bytes.try_into().map_err(|_| PreparedError::InvalidHandle)?,
        ))
    }
}
impl std::fmt::Debug for PreparedHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedHandle(<скрыто>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedError {
    Authorization(AuthorizationError),
    Capacity,
    InvalidHandle,
    Stale,
    ArtifactTooLarge,
    Unsupported,
    Unavailable,
    Cancelled,
    Timeout,
}
impl From<AuthorizationError> for PreparedError {
    fn from(error: AuthorizationError) -> Self {
        Self::Authorization(error)
    }
}
impl std::fmt::Display for PreparedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Authorization(_) => "Авторизация подготовленного запроса отклонена",
            Self::Capacity => "Достигнут предел подготовленных запросов",
            Self::InvalidHandle => "Недействительный подготовленный запрос",
            Self::Stale => "Подготовленный запрос устарел",
            Self::Unsupported => "Запрошенный режим не поддерживается",
            Self::ArtifactTooLarge => "Подготовленная конфигурация слишком велика",
            Self::Unavailable => "Подготовка недоступна",
            Self::Cancelled => "Подготовленный запрос отменён",
            Self::Timeout => "Истёк срок подготовки",
        })
    }
}
impl std::error::Error for PreparedError {}

struct Entry<A> {
    artifact: ClaimedArtifact<A>,
    uid: u32,
    sender: String,
    context: PreparedContext,
    digest: ConfigDigest,
    bytes: usize,
    expires: Instant,
}
struct State<A> {
    entries: HashMap<PreparedHandle, Entry<A>>,
    reservations: HashMap<u64, String>,
    next: u64,
}

/// Один store и одна polkit connection на dispatcher. Ограничивает работу до auth.
pub struct PreparedRequests<A: PreparedArtifact> {
    authorizer: PeerAuthorizer,
    state: Arc<Mutex<State<A>>>,
    in_flight: Semaphore,
    config_memory: ByteBudget,
    _reclaim: Arc<Reclaimer>,
    #[cfg(test)]
    clock_offset_ms: Arc<std::sync::atomic::AtomicU64>,
}
impl<A: PreparedArtifact> std::fmt::Debug for PreparedRequests<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedRequests(<скрыто>)")
    }
}
impl<A: PreparedArtifact> PreparedRequests<A> {
    pub async fn system(cancel: Cancellation) -> Result<Self, PreparedError> {
        Self::with_authorizer(PeerAuthorizer::system(cancel).await?)
    }
    pub(super) fn with_authorizer(authorizer: PeerAuthorizer) -> Result<Self, PreparedError> {
        Self::with_budget(authorizer, config_budget().clone())
    }
    fn with_budget(
        authorizer: PeerAuthorizer,
        config_memory: ByteBudget,
    ) -> Result<Self, PreparedError> {
        let state = Arc::new(Mutex::new(State {
            entries: HashMap::<PreparedHandle, Entry<A>>::new(),
            reservations: HashMap::new(),
            next: 0,
        }));
        let weak = Arc::downgrade(&state);
        #[cfg(test)]
        let clock_offset_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        #[cfg(test)]
        let clock = clock_offset_ms.clone();
        let reclaim: Arc<Reclaimer> = Arc::new(move || {
            let now = Instant::now();
            #[cfg(test)]
            let now = now + Duration::from_millis(clock.load(std::sync::atomic::Ordering::Relaxed));
            if let Some(state) = weak.upgrade() {
                // Чужой store может сейчас выполнять claim: не ждём его lock.
                if let Ok(mut state) = state.try_lock() {
                    state.entries.retain(|_, entry| entry.expires > now);
                }
            }
        });
        config_memory
            .register(&reclaim)
            .map_err(|_| PreparedError::Capacity)?;
        Ok(Self {
            authorizer,
            state,
            config_memory,
            _reclaim: reclaim,
            in_flight: Semaphore::new(MAX_IN_FLIGHT),
            #[cfg(test)]
            clock_offset_ms,
        })
    }
    pub(super) fn authorizer(&self) -> &PeerAuthorizer {
        &self.authorizer
    }
    pub fn connection(&self) -> &Connection {
        &self.authorizer.connection
    }
    fn now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(test)]
        let now = now
            + Duration::from_millis(
                self.clock_offset_ms
                    .load(std::sync::atomic::Ordering::Relaxed),
            );
        now
    }
    /// Доверенный NameOwnerChanged handler, не RPC. Удаляет также текущие reservations.
    pub fn forget_peer(&self, sender: &str) -> Result<(), PreparedError> {
        let mut state = self.state.lock().map_err(|_| PreparedError::Unavailable)?;
        state.entries.retain(|_, entry| entry.sender != sender);
        state.reservations.retain(|_, peer| peer != sender);
        Ok(())
    }
    pub async fn prepare<F, Fut>(
        &self,
        message: &Message,
        prompt: Prompt,
        mut cancel: Cancellation,
        factory: F,
    ) -> Result<PreparedHandle, PreparedError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(A, PreparedContext), PreparedError>>,
    {
        let _permit = self
            .in_flight
            .try_acquire()
            .map_err(|_| PreparedError::Capacity)?;
        let sender = super::sender(message)?;
        {
            let mut state = self.state.lock().map_err(|_| PreparedError::Unavailable)?;
            state.entries.retain(|_, entry| entry.expires > self.now());
        }
        // Максимальная ёмкость нужна до factory; после проверки освобождаем излишек.
        let mut memory = self
            .config_memory
            .reserve(MAX_RETAINED_CONFIG_BYTES)
            .map_err(|_| PreparedError::Capacity)?;
        let reservation = {
            let mut state = self.state.lock().map_err(|_| PreparedError::Unavailable)?;
            state.entries.retain(|_, entry| entry.expires > self.now());
            let count = state
                .entries
                .values()
                .filter(|entry| entry.sender == sender)
                .count()
                + state
                    .reservations
                    .values()
                    .filter(|peer| **peer == sender)
                    .count();
            if state.entries.len() + state.reservations.len() >= MAX_PENDING
                || count >= MAX_PENDING_PER_PEER
            {
                return Err(PreparedError::Capacity);
            }
            state.next = state
                .next
                .checked_add(1)
                .ok_or(PreparedError::Unavailable)?;
            let id = state.next;
            state.reservations.insert(id, sender);
            Reservation {
                state: &self.state,
                id,
            }
        };
        let peer = self
            .authorizer
            .authorize(
                message,
                NetworkAction::ManageNetwork,
                prompt,
                cancel.clone(),
            )
            .await?;
        let (artifact, context) = bounded(&mut cancel, async { factory().await }).await?;
        if artifact.byte_len() > MAX_ARTIFACT_BYTES {
            return Err(PreparedError::ArtifactTooLarge);
        }
        let retained = artifact.retained_bytes();
        if retained < artifact.byte_len() || retained > MAX_RETAINED_CONFIG_BYTES {
            return Err(PreparedError::ArtifactTooLarge);
        }
        memory
            .resize(retained)
            .map_err(|_| PreparedError::Capacity)?;
        let digest = artifact.current_digest();
        let bytes = artifact.byte_len();
        // Проверка liveness после продолжительного config-check, без повторного auth.
        let uid = bounded(&mut cancel, async {
            Ok(self.authorizer.uid(peer.sender()).await?)
        })
        .await?;
        if uid != peer.uid() {
            return Err(PreparedError::Stale);
        }
        let mut token = [0; 32];
        getrandom::getrandom(&mut token).map_err(|_| PreparedError::Unavailable)?;
        let handle = PreparedHandle(token);
        let mut state = self.state.lock().map_err(|_| PreparedError::Unavailable)?;
        cancel.check().map_err(|_| PreparedError::Cancelled)?;
        if !state.reservations.contains_key(&reservation.id) {
            return Err(PreparedError::Stale);
        }
        if state.entries.contains_key(&handle) {
            return Err(PreparedError::Unavailable);
        }
        state.reservations.remove(&reservation.id);
        state.entries.insert(
            handle,
            Entry {
                artifact: ClaimedArtifact { artifact, memory },
                uid: peer.uid(),
                sender: peer.sender().to_owned(),
                context,
                digest,
                bytes,
                expires: self.now() + PREPARED_TTL,
            },
        );
        drop(state);
        Ok(handle)
    }
    /// Trusted caller сериализует claim/effects и обновление поколений. Между этой
    /// выдачей и сетевыми эффектами нельзя допускать смену проверенного окружения.
    pub async fn claim_for_apply<F>(
        &self,
        message: &Message,
        handle: PreparedHandle,
        prompt: Prompt,
        cancel: Cancellation,
        context: F,
    ) -> Result<ClaimedArtifact<A>, PreparedError>
    where
        F: FnOnce() -> Result<PreparedContext, PreparedError>,
    {
        self.claim_for_apply_deferred(message, handle, prompt, cancel, || {
            std::future::ready(context())
        })
        .await
    }

    pub(super) async fn claim_for_apply_deferred<F, R>(
        &self,
        message: &Message,
        handle: PreparedHandle,
        prompt: Prompt,
        cancel: Cancellation,
        context: F,
    ) -> Result<ClaimedArtifact<A>, PreparedError>
    where
        F: FnOnce() -> R,
        R: Future<Output = Result<PreparedContext, PreparedError>>,
    {
        let _permit = self
            .in_flight
            .try_acquire()
            .map_err(|_| PreparedError::Capacity)?;
        let peer = self
            .authorizer
            .authorize(
                message,
                NetworkAction::ManageNetwork,
                prompt,
                cancel.clone(),
            )
            .await?;
        let current = context().await;
        let mut state = self.state.lock().map_err(|_| PreparedError::Unavailable)?;
        cancel.check().map_err(|_| PreparedError::Cancelled)?;
        state.entries.retain(|_, entry| entry.expires > self.now());
        let entry = state
            .entries
            .get(&handle)
            .ok_or(PreparedError::InvalidHandle)?;
        if entry.uid != peer.uid() || entry.sender != peer.sender() {
            return Err(PreparedError::InvalidHandle);
        }
        // С этого момента rightful попытка одноразовая, в том числе при stale context.
        let entry = state
            .entries
            .remove(&handle)
            .ok_or(PreparedError::InvalidHandle)?;
        drop(state);
        if current? != entry.context
            || entry.artifact.byte_len() != entry.bytes
            || entry.bytes > MAX_ARTIFACT_BYTES
            || entry.artifact.artifact.retained_bytes() != entry.artifact.memory.bytes()
            || entry.artifact.current_digest() != entry.digest
        {
            return Err(PreparedError::Stale);
        }
        cancel.check().map_err(|_| PreparedError::Cancelled)?;
        Ok(entry.artifact)
    }
}
struct Reservation<'a, A> {
    state: &'a Mutex<State<A>>,
    id: u64,
}
impl<A> Drop for Reservation<'_, A> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.reservations.remove(&self.id);
        }
    }
}
async fn bounded<T>(
    cancel: &mut Cancellation,
    operation: impl Future<Output = Result<T, PreparedError>>,
) -> Result<T, PreparedError> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(PreparedError::Cancelled),
        _ = tokio::time::sleep(FACTORY_TIMEOUT) => Err(PreparedError::Timeout),
        result = operation => result,
    }
}

#[cfg(test)]
#[path = "prepared_tests.rs"]
mod tests;
