use super::standalone_supervisor::StandaloneSupervisor;
use super::{SystemWorkerSupervisor, WorkerLiveness, WorkerSupervisorError as Error, WorkerTicket};
use crate::{Cancellation, output_transport::ValidatedWriters, worker::WorkerPayload};
use std::sync::Arc;

type Result<T> = std::result::Result<T, Error>;

pub(super) enum SessionSupervisor {
    Systemd(Box<SystemWorkerSupervisor>),
    Standalone(Box<StandaloneSupervisor>),
}

impl SessionSupervisor {
    pub(super) fn systemd(&mut self) -> Result<&mut SystemWorkerSupervisor> {
        match self {
            Self::Systemd(supervisor) => Ok(supervisor),
            Self::Standalone(_) => Err(Error::UnitProofGap),
        }
    }

    pub(super) async fn check(
        &mut self,
        payload: Arc<WorkerPayload>,
        cancel: &mut Cancellation,
    ) -> Result<()> {
        match self {
            Self::Systemd(supervisor) => supervisor.check(payload, cancel).await,
            Self::Standalone(supervisor) => supervisor.check(payload, cancel).await,
        }
    }

    pub(super) async fn start_output(
        &mut self,
        payload: Arc<WorkerPayload>,
        output: Option<ValidatedWriters>,
        cancel: &mut Cancellation,
    ) -> Result<WorkerTicket> {
        match self {
            Self::Systemd(supervisor) => supervisor.start_output(payload, output, cancel).await,
            Self::Standalone(supervisor) => supervisor.start_output(payload, output, cancel).await,
        }
    }

    pub(super) async fn observe(&self, ticket: &WorkerTicket) -> Result<WorkerLiveness> {
        match self {
            Self::Systemd(supervisor) => supervisor.observe(ticket).await,
            Self::Standalone(supervisor) => supervisor.observe(ticket),
        }
    }

    pub(super) async fn recover(&mut self, cancel: &mut Cancellation) -> Result<()> {
        match self {
            Self::Systemd(supervisor) => supervisor.recover(cancel).await,
            Self::Standalone(supervisor) => supervisor.recover(cancel).await,
        }
    }

    pub(super) fn confirm_profile_rules_retired(&mut self) -> Result<()> {
        match self {
            Self::Systemd(supervisor) => supervisor.confirm_profile_rules_retired(),
            Self::Standalone(supervisor) => supervisor.confirm_profile_rules_retired(),
        }
    }
}
