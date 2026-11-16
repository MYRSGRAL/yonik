//! Startup координация обычного actor. Снимки planner не заменяют admission Connect.
use super::*;
use crate::{
    startup_identity::Identity,
    startup_policy::{self as policy, Target},
};

#[derive(Serialize)]
pub(super) struct View {
    pub start_hidden: bool,
    pub revision: String,
    pub autostart_into_tray: bool,
    pub autoconnect: bool,
    pub target: Option<String>,
    pub request_id: Option<String>,
    pub error: Option<&'static str>,
    pub save: &'static str,
    pub attempt: &'static str,
    pub xdg: &'static str,
    #[serde(skip)]
    pub owner: Option<Identity>,
    #[serde(skip)]
    pub custody: Option<yonik_linux::CredentialOwnerGuard>,
    #[serde(skip)]
    pub initialization_failed: bool,
    #[serde(skip)]
    pub xdg_root: Option<PathBuf>,
}
impl Default for View {
    fn default() -> Self {
        Self {
            start_hidden: false,
            revision: "0".into(),
            autostart_into_tray: false,
            autoconnect: false,
            target: None,
            request_id: None,
            error: None,
            save: "idle",
            attempt: "pending",
            xdg: "unchanged",
            owner: None,
            custody: None,
            initialization_failed: false,
            xdg_root: None,
        }
    }
}
pub(super) fn number(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|number| number.to_string() == value)
}
impl Actor {
    pub(super) async fn startup_select_profile(&mut self, profile: ResolvedProfile) -> Result<()> {
        self.clear_selection();
        self.state.source_id = Some(profile.profile.source_id);
        self.page()
            .await
            .map_err(|_| DesktopError("startup_binding"))?;
        if self.catalog_coordinates
            != Some((
                profile.profile.source_id,
                profile.source_generation,
                profile.snapshot_generation,
                profile.snapshot_revision,
            ))
        {
            return Err(DesktopError("startup_binding"));
        }
        self.state.selected_kind = Some("server");
        self.state.selected_profile = Some(profile.profile.id);
        self.state.selected_name = Some(profile.profile.name.clone());
        self.selected = Some(profile);
        Ok(())
    }
    pub(super) fn startup_view(&mut self) {
        self.state.startup.revision = self.preferences.revision.to_string();
        self.state.startup.autostart_into_tray = self.preferences.autostart_into_tray;
        self.state.startup.autoconnect = self.preferences.autoconnect;
        self.state.startup.target = self.preferences.autoconnect_target.as_ref().map(|target| {
            format!(
                "#{} · {:?} · {:?} · source #{} · snapshot {} · routing {}",
                target.profile_id,
                target.engine,
                target.mode,
                target.source_id,
                target.snapshot_revision,
                target.routing_revision
            )
        });
    }
    fn startup_target(&self, profile: &ResolvedProfile) -> Result<Target> {
        Ok(Target {
            source_id: profile.profile.source_id,
            profile_id: profile.profile.id,
            source_generation: profile.source_generation,
            snapshot_generation: profile.snapshot_generation,
            snapshot_revision: profile.snapshot_revision,
            routing_revision: self
                .routing_revision
                .ok_or(DesktopError("routing_storage"))?,
            engine: match self.state.engine {
                EngineChoice::Xray => policy::Engine::Xray,
                EngineChoice::SingBox => policy::Engine::SingBox,
            },
            mode: match self.state.connection_mode {
                ConnectionMode::Local => policy::Mode::Local,
                ConnectionMode::System => policy::Mode::System,
            },
        })
    }
    pub(super) fn startup_owner_current(&self) -> bool {
        self.state
            .startup
            .custody
            .as_ref()
            .is_some_and(|guard| !guard.owner_lost())
            && self.state.startup.owner.as_ref().is_some_and(|owner| {
                // Сравнение с начальным owner, а не принятие нового inode после replacement.
                owner.matches(self.preferences_store.directory())
            })
    }
    pub(super) async fn startup_revalidate(
        &self,
        control: &Control,
        generation: u64,
    ) -> Result<()> {
        if generation != control.generation.load(Ordering::SeqCst)
            || !self.startup_owner_current()
            || self.preferences.repository_identity != self.state.startup.owner
            || self.state.preferences_durability_warning
            || self.pending.is_some()
            || self.state.pending.is_some()
        {
            return Err(DesktopError("startup_binding"));
        }
        let target = self
            .preferences
            .autoconnect_target
            .as_ref()
            .ok_or(DesktopError("startup_binding"))?;
        if self
            .selected
            .as_ref()
            .and_then(|profile| self.startup_target(profile).ok())
            .as_ref()
            != Some(target)
        {
            return Err(DesktopError("startup_binding"));
        }
        let profile = self
            .service()
            .select_profile(target.profile_id, target.snapshot_revision)
            .await
            .map_err(map_subscription)?;
        if generation != control.generation.load(Ordering::SeqCst)
            || !self.startup_owner_current()
            || self.startup_target(&profile)? != *target
        {
            return Err(DesktopError("startup_binding"));
        }
        self.state
            .startup
            .custody
            .as_ref()
            .ok_or(DesktopError("startup_binding"))?
            .check()
            .await
            .map_err(|_| DesktopError("startup_binding"))?;
        if generation != control.generation.load(Ordering::SeqCst) || !self.startup_owner_current()
        {
            return Err(DesktopError("cancelled"));
        }
        Ok(())
    }
    pub(super) async fn startup_save(
        &mut self,
        request_id: String,
        revision: String,
        flags: Option<(bool, bool)>,
        control: &Control,
        generation: u64,
    ) -> Result<()> {
        self.state.startup.request_id = Some(request_id);
        self.state.startup.error = None;
        self.state.startup.save = "pending";
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            self.startup_save_inner(&revision, flags, control, generation),
        )
        .await
        .unwrap_or(Err(DesktopError("startup_timeout")));
        if let Err(error) = &result {
            self.state.startup.error = Some(error.0);
            self.state.startup.save = "error";
        }
        result
    }
    async fn startup_save_inner(
        &mut self,
        revision: &str,
        flags: Option<(bool, bool)>,
        control: &Control,
        generation: u64,
    ) -> Result<()> {
        if number(revision) != Some(self.preferences.revision) {
            return Err(DesktopError("startup_conflict"));
        }
        if self.state.preferences_warning {
            return Err(DesktopError("preferences_write"));
        }
        let mut next = self.preferences.clone();
        if let Some((autostart, autoconnect)) = flags {
            next.autostart_into_tray = autostart;
            next.autoconnect = autoconnect;
        } else {
            if self.pending.is_some() || self.state.pending.is_some() {
                return Err(DesktopError("review_required"));
            }
            if self.state.ephemeral || !self.startup_owner_current() {
                return Err(DesktopError("startup_binding"));
            }
            self.state
                .startup
                .custody
                .as_ref()
                .ok_or(DesktopError("startup_binding"))?
                .check()
                .await
                .map_err(|_| DesktopError("startup_binding"))?;
            if generation != control.generation.load(Ordering::SeqCst)
                || !self.startup_owner_current()
            {
                return Err(DesktopError("cancelled"));
            }
            let selected = self
                .selected
                .as_ref()
                .ok_or(DesktopError("profile_required"))?;
            let expected = self.startup_target(selected)?;
            let profile = tokio::time::timeout(
                Duration::from_secs(5),
                self.service()
                    .select_profile(expected.profile_id, expected.snapshot_revision),
            )
            .await
            .map_err(|_| DesktopError("startup_timeout"))?
            .map_err(map_subscription)?;
            if generation != control.generation.load(Ordering::SeqCst) {
                return Err(DesktopError("cancelled"));
            }
            if self.startup_target(&profile)? != expected || !self.startup_owner_current() {
                return Err(DesktopError("startup_binding"));
            }
            next.autoconnect_target = Some(expected);
            next.repository_identity = self.state.startup.owner.clone();
        }
        if generation != control.generation.load(Ordering::SeqCst) {
            return Err(DesktopError("cancelled"));
        }
        next.version = 3;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(DesktopError("startup_conflict"))?;
        self.save_preferences(next).map_err(|error| {
            if error.key() == "preferences_conflict" {
                DesktopError("startup_conflict")
            } else {
                error
            }
        })?;
        self.startup_view();
        if self.state.preferences_durability_warning {
            self.state.startup.save = "durability_unknown";
            self.state.startup.xdg = "not_applied";
            return Ok(());
        }
        self.state.startup.save = "durable";
        // Подтверждение target не управляет XDG и никогда не начинает Connect.
        if flags.is_some() {
            self.state.startup.xdg = match self
                .state
                .startup
                .xdg_root
                .as_deref()
                .ok_or_else(|| std::io::Error::other("XDG недоступен"))
                .and_then(|root| {
                    crate::startup_xdg::apply(root, self.preferences.autostart_into_tray)
                }) {
                Ok(crate::startup_xdg::Outcome::Durable) => "applied",
                Ok(crate::startup_xdg::Outcome::PublishedDurabilityUnknown) => "durability_unknown",
                Err(_) => "error",
            };
            if self.state.startup.xdg == "error" {
                self.state.startup.error = Some("startup_xdg");
            }
        }
        Ok(())
    }
}

/// Один barrier на Host, ограниченный общим deadline. Stop меняет generation
/// независимо от actor; после каждого await проверяем её и owner.
pub(super) async fn prepare(
    actor: &mut Actor,
    control: &Control,
    generation: u64,
) -> (Option<Envelope>, Option<SystemSession>) {
    actor.startup_view();
    if actor.preferences.autostart_into_tray
        && !actor.state.preferences_warning
        && !actor.state.preferences_durability_warning
    {
        actor.state.startup.xdg = match actor
            .state
            .startup
            .xdg_root
            .as_deref()
            .and_then(|root| crate::startup_xdg::apply(root, true).ok())
        {
            Some(crate::startup_xdg::Outcome::Durable) => "applied",
            Some(crate::startup_xdg::Outcome::PublishedDurabilityUnknown) => "durability_unknown",
            None => "error",
        };
        if actor.state.startup.xdg == "error" {
            actor.state.startup.error = Some("startup_xdg");
        }
    }
    if actor.state.startup.xdg == "durability_unknown" {
        actor.state.startup.attempt = "blocked";
        actor.state.startup.error = Some("startup_xdg_unknown");
        return (None, None);
    }
    let mut planner = policy::Planner::default();
    if !actor.preferences.autoconnect {
        actor.state.startup.attempt = "off";
        return (None, None);
    }
    actor.state.startup.attempt = "pending";
    actor.emit();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        prepare_inner(actor, control, generation, &mut planner),
    )
    .await;
    match result {
        Ok(Ok(session)) => {
            actor.state.startup.attempt = "dispatched";
            (
                Some(Envelope {
                    generation,
                    tcp_generation: *control.tcp_priority.borrow(),
                    command: Command::Connect,
                }),
                session,
            )
        }
        Ok(Err(error)) => {
            actor.state.startup.attempt = "blocked";
            actor.state.startup.error = Some(error.0);
            (None, None)
        }
        Err(_) => {
            planner.stop();
            actor.state.startup.attempt = "blocked";
            actor.state.startup.error = Some("startup_timeout");
            (None, None)
        }
    }
}
/// Drop при общем deadline также отменяет вложенный read-only Flight.
struct StateQuery(Flight);
impl Drop for StateQuery {
    fn drop(&mut self) {
        self.0.cancel.send_replace(true);
        self.0.task.abort();
    }
}
async fn prepare_inner(
    actor: &mut Actor,
    control: &Control,
    generation: u64,
    planner: &mut policy::Planner,
) -> Result<Option<SystemSession>> {
    let current = || control.generation.load(Ordering::SeqCst) == generation;
    if actor.state.startup.initialization_failed
        || !current()
        || actor.state.ephemeral
        || actor.state.preferences_warning
        || actor.state.preferences_durability_warning
        || actor.preferences.repository_identity != actor.state.startup.owner
        || !actor.startup_owner_current()
    {
        planner.stop();
        return Err(DesktopError("startup_binding"));
    }
    actor
        .state
        .startup
        .custody
        .as_ref()
        .ok_or(DesktopError("startup_binding"))?
        .check()
        .await
        .map_err(|_| DesktopError("startup_binding"))?;
    if !current() || !actor.startup_owner_current() {
        return Err(DesktopError("cancelled"));
    }
    let target = actor
        .preferences
        .autoconnect_target
        .clone()
        .ok_or(DesktopError("startup_binding"))?;
    let profile = actor
        .service()
        .select_profile(target.profile_id, target.snapshot_revision)
        .await
        .map_err(map_subscription)?;
    if !current() || !actor.startup_owner_current() {
        planner.stop();
        return Err(DesktopError("cancelled"));
    }
    // Ядро должно совпасть с preferences; mode восстанавливается только из явно
    // подтверждённого target. Альтернативный mode при отказе не выбирается.
    actor.state.connection_mode = match target.mode {
        policy::Mode::Local => ConnectionMode::Local,
        policy::Mode::System => ConnectionMode::System,
    };
    if actor.startup_target(&profile)? != target {
        return Err(DesktopError("startup_binding"));
    }
    let mut session = None;
    if target.mode == policy::Mode::System {
        // Тот же read-only State path, что у ручной команды SystemState.
        // Coordinator не создаёт SystemClient/Session и не получает native permit.
        let mut query = StateQuery(Flight::start(
            None,
            Operation::State,
            system_revision(actor),
            generation,
            actor.event_log.clone(),
        ));
        let result = tokio::time::timeout(Duration::from_secs(4), &mut query.0.task)
            .await
            .map_err(|_| DesktopError("startup_timeout"))?
            .map_err(|_| DesktopError("system_unavailable"))?;
        let (candidate, state) = result;
        let candidate = candidate.ok_or(DesktopError("system_unavailable"))?;
        if !current() || !actor.startup_owner_current() || candidate.owner_lost() {
            return Err(DesktopError("cancelled"));
        }
        if state.map_err(|_| DesktopError("system_unavailable"))? != SystemState::NoManagedPolicy {
            return Err(DesktopError("startup_admission"));
        }
        session = Some(candidate);
    }
    actor
        .state
        .startup
        .custody
        .as_ref()
        .ok_or(DesktopError("startup_binding"))?
        .check()
        .await
        .map_err(|_| DesktopError("startup_binding"))?;
    if !current() || !actor.startup_owner_current() {
        return Err(DesktopError("cancelled"));
    }
    if actor.pending.is_some()
        || actor.state.pending.is_some()
        || actor.state.can_stop
        || actor.state.system_recovery_pending
    {
        return Err(DesktopError("startup_admission"));
    }
    let decision = planner.decide(&policy::Input {
        enabled: true,
        target: Some(target.clone()),
        resolved: Some(actor.startup_target(&profile)?),
        custody: policy::Custody::Ready,
        admission: policy::Admission::Eligible,
        generation,
        current_generation: control.generation.load(Ordering::SeqCst),
    });
    if !matches!(decision, policy::Decision::Connect(_)) || !actor.startup_owner_current() {
        return Err(DesktopError("startup_binding"));
    }
    actor.startup_select_profile(profile).await?;
    if !current() || !actor.startup_owner_current() {
        return Err(DesktopError("cancelled"));
    }
    Ok(session)
}
