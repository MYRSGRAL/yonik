//! Сериализуемый host для системного IPC; профиль не сохраняется в снимках.
use tokio::time::Instant;
use yonik_engine::Engine;
use yonik_import::ServerIntent;
use yonik_linux::{
    Cancellation,
    system_client::{ClientError, PreparedOutput, State, SystemClient},
};

pub(crate) fn ensure_engine_available(engine: Engine) -> Result<(), ClientError> {
    match engine {
        Engine::Xray => Ok(()),
        Engine::SingBox => Err(ClientError::Unsupported),
    }
}

/// Ревизии выдаёт GUI host при каждом изменении выбора или источника.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileRevision {
    pub source: u64,
    pub profile: u64,
    pub generation: u64,
}

pub struct SystemSession {
    client: SystemClient,
    revision: ProfileRevision,
    prepared: Option<PreparedOutput>,
    log: yonik_linux::event_log::EventLog,
    drains: Vec<yonik_linux::system_client::output::OutputDrain>,
    state: State,
    capability: Option<Instant>,
}
impl SystemSession {
    pub fn new(
        client: SystemClient,
        revision: ProfileRevision,
        log: yonik_linux::event_log::EventLog,
    ) -> Self {
        Self {
            client,
            log,
            drains: Vec::new(),
            revision,
            prepared: None,
            state: State::Unknown,
            capability: None,
        }
    }
    // Новый bus owner не меняет immutable контекст уже работающих readers.
    pub(crate) fn replace_client(&mut self, client: SystemClient) {
        self.client = client;
        self.prepared = None;
        self.capability = None;
        self.state = State::Unknown;
    }
    pub fn system_tun_available(&self) -> bool {
        !self.owner_lost()
            && self
                .capability
                .is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(5))
    }
    pub fn owner_lost(&self) -> bool {
        self.client.owner_lost()
    }
    pub fn snapshot(&self) -> State {
        if self.owner_lost() {
            State::Unknown
        } else {
            self.state
        }
    }
    /// Вызывается владельцем при изменении источника, профиля или его поколения.
    pub fn revise(&mut self, revision: ProfileRevision) {
        self.revision = revision;
        self.prepared = None;
    }
    fn fence(&self, revision: ProfileRevision) -> Result<(), ClientError> {
        if revision == self.revision {
            Ok(())
        } else {
            Err(ClientError::Stale)
        }
    }
    #[allow(clippy::too_many_arguments)] // Явные границы IPC и fencing без копии профиля.
    pub async fn prepare(
        &mut self,
        revision: ProfileRevision,
        server: &ServerIntent,
        engine: Engine,
        kill_switch: bool,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<(), ClientError> {
        ensure_engine_available(engine)?;
        self.fence(revision)?;
        self.prepared = None;
        // Публичная блокировка не означает активную сессию: admission проверяет helper.
        if !self
            .client
            .capabilities(deadline, cancel.clone())
            .await?
            .system_tun
        {
            return Err(ClientError::Unsupported);
        }
        let prepared = self
            .client
            .prepare_profile(server, engine, kill_switch, deadline, cancel)
            .await?;
        self.prepared = Some(
            PreparedOutput::bind(prepared, engine, &self.log, revision.generation)
                .map_err(|_| ClientError::Unavailable)?,
        );
        Ok(())
    }
    /// Inline Prepare привязан к той же ревизии и одноразовому handle.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_policy(
        &mut self,
        revision: ProfileRevision,
        server: &ServerIntent,
        engine: Engine,
        policy: &yonik_linux::system_policy::InlinePolicy,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<(), ClientError> {
        ensure_engine_available(engine)?;
        self.fence(revision)?;
        self.prepared = None;
        let legacy_available = self
            .client
            .capabilities(deadline, cancel.clone())
            .await?
            .system_tun;
        if !legacy_available
            && (!policy.policy().requires_attribution()
                || !self
                    .client
                    .native_prepare_eligibility(deadline, cancel.clone())
                    .await?
                    .can_prepare_attribution)
        {
            return Err(ClientError::Unsupported);
        }
        let prepared = self
            .client
            .prepare_inline_policy(server, engine, true, policy, deadline, cancel)
            .await?;
        self.prepared = Some(
            PreparedOutput::bind(prepared, engine, &self.log, revision.generation)
                .map_err(|_| ClientError::Unavailable)?,
        );
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // Явные границы IPC и отмены.
    pub(crate) async fn prepare_fake_dns_policy(
        &mut self,
        revision: ProfileRevision,
        server: &ServerIntent,
        engine: Engine,
        policy: &yonik_linux::system_policy::InlinePolicy,
        suffixes: &[String],
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<(), ClientError> {
        self.fence(revision)?;
        self.prepared = None;
        yonik_engine::validate_scoped_fake_dns_policy(policy.policy().policy(), suffixes)
            .map_err(|_| ClientError::Unsupported)?;
        let prepared = self
            .client
            .prepare_fake_dns_policy_profile(
                server,
                engine,
                true,
                suffixes,
                policy.policy(),
                deadline,
                cancel,
            )
            .await?;
        self.prepared = Some(
            PreparedOutput::bind(prepared, engine, &self.log, revision.generation)
                .map_err(|_| ClientError::Unavailable)?,
        );
        Ok(())
    }
    pub async fn prepare_full_profile(
        &mut self,
        revision: ProfileRevision,
        request: &yonik_linux::helper::profile_intent::FullProfileRequest,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<(), ClientError> {
        self.prepared = None;
        self.fence(revision)?;
        cancel.check().map_err(|_| ClientError::Cancelled)?;
        yonik_linux::full_profile_request_preflight(yonik_linux::FullProfileMode::System, request)
            .map_err(|_| ClientError::Unsupported)?;
        let prepared = self
            .client
            .prepare_full_profile(request, deadline, cancel.clone())
            .await?;
        cancel.check().map_err(|_| ClientError::Cancelled)?;
        self.fence(revision)?;
        self.prepared = Some(
            PreparedOutput::bind(prepared, Engine::Xray, &self.log, revision.generation)
                .map_err(|_| ClientError::Unavailable)?,
        );
        Ok(())
    }
    pub async fn apply(
        &mut self,
        revision: ProfileRevision,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        self.fence(revision)?;
        let prepared = self.prepared.take().ok_or(ClientError::InvalidHandle)?;
        // До отправки эффекта публикуем неизвестный исход: drop future безопасен.
        self.state = State::Unknown;
        let (result, drain) = self.client.apply_output(prepared, deadline, cancel).await;
        if let Some(drain) = drain {
            self.drains.push(drain);
        }
        self.record(result)
    }
    fn record(&mut self, result: Result<State, ClientError>) -> Result<State, ClientError> {
        self.state = match result {
            Ok(state) => state,
            Err(_) => State::Unknown,
        };
        result
    }
    pub async fn state(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        self.state = State::Unknown;
        self.capability = None;
        let caps = self.client.capabilities(deadline, cancel.clone()).await?;
        if caps.system_tun
            || self
                .client
                .native_prepare_eligibility(deadline, cancel.clone())
                .await
                .map(|reply| reply.can_prepare_attribution)
                .unwrap_or(false)
        {
            self.capability = Some(Instant::now());
        }
        let result = self.client.state(deadline, cancel).await;
        self.record(result)
    }
    pub async fn stop(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        self.prepared = None;
        self.state = State::Unknown;
        let result = self.client.stop(deadline, cancel).await;
        if matches!(result, Ok(State::NoManagedPolicy | State::RecoveryRequired)) {
            for drain in std::mem::take(&mut self.drains) {
                if !drain.drained().await {
                    return self.record(Err(ClientError::Unavailable));
                }
            }
        }
        self.record(result)
    }
    pub async fn drain_output(&mut self) -> bool {
        let mut complete = true;
        for drain in self.drains.drain(..) {
            complete &= drain.drained().await;
        }
        complete
    }
    pub async fn unlock(
        &mut self,
        deadline: Instant,
        cancel: Cancellation,
    ) -> Result<State, ClientError> {
        self.prepared = None;
        self.state = State::Unknown;
        let result = self.client.unlock(deadline, cancel).await;
        if matches!(result, Ok(State::NoManagedPolicy)) {
            for drain in std::mem::take(&mut self.drains) {
                if !drain.drained().await {
                    return self.record(Err(ClientError::Unavailable));
                }
            }
        }
        self.record(result)
    }
}
