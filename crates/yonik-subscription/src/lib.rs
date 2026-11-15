//! Staged-обновление подписки без I/O и изменения активной сессии.

pub mod scheduler;

use std::{fmt, num::NonZeroU64};
use yonik_import::{FatalError, ImportReport};

/// Профильный staging сохраняет DATA roots без извлечения outbound endpoints.
#[derive(Debug)]
pub struct ProfileStagedUpdate {
    ticket: Ticket,
    report: yonik_import::ProfileImportReport,
    summary: Summary,
}
#[derive(Debug)]
pub struct ProfileApprovedUpdate(ProfileStagedUpdate);
impl ProfileStagedUpdate {
    pub fn report(&self) -> &yonik_import::ProfileImportReport {
        &self.report
    }
    pub fn summary(&self) -> Summary {
        self.summary
    }
    pub fn accept_clean(self) -> Result<ProfileApprovedUpdate, Error> {
        if self.summary.needs_review() {
            return Err(Error::ReviewRequired);
        }
        Ok(ProfileApprovedUpdate(self))
    }
    pub fn approve_after_review(self) -> ProfileApprovedUpdate {
        ProfileApprovedUpdate(self)
    }
}
impl ProfileApprovedUpdate {
    pub fn report(&self) -> &yonik_import::ProfileImportReport {
        &self.0.report
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Stale,
    Exhausted,
    InvalidImport(FatalError),
    NoUsableRecords,
    ReviewRequired,
}

/// Ошибка совместимого staging отделена от кооперативной отмены.
#[derive(Debug)]
pub enum CancellableStageError {
    Cancelled,
    Stage(Error),
}

impl fmt::Display for CancellableStageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Обработка подписки отменена"),
            Self::Stage(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for CancellableStageError {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stale => "Обновление подписки устарело или отменено",
            Self::Exhausted => "Исчерпаны поколения подписки",
            Self::InvalidImport(_) => "Не удалось разобрать обновление подписки",
            Self::NoUsableRecords => "Обновление не содержит пригодных записей",
            Self::ReviewRequired => "Перед сохранением необходимо проверить отчёт импорта",
        })
    }
}
impl std::error::Error for Error {}

/// Correlation token. Host сериализует commit с записью Repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    controller: NonZeroU64,
    request: u64,
    source_generation: u64,
    revision: u64,
}

impl Ticket {
    pub fn source_generation(self) -> u64 {
        self.source_generation
    }

    pub fn revision(self) -> u64 {
        self.revision
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub accepted: usize,
    pub rejected: usize,
    pub flagged: usize,
    pub native_json: bool,
}

impl Summary {
    pub fn needs_review(self) -> bool {
        self.rejected != 0 || self.flagged != 0 || self.native_json
    }
}

/// Не Clone: согласие относится к единственному неизменяемому отчёту.
#[derive(Debug)]
pub struct StagedUpdate {
    ticket: Ticket,
    report: ImportReport,
    summary: Summary,
}

impl StagedUpdate {
    pub fn summary(&self) -> Summary {
        self.summary
    }

    /// Чувствительные данные: UI должен маскировать endpoint/credentials/source.
    pub fn report(&self) -> &ImportReport {
        &self.report
    }

    pub fn accept_clean(self) -> Result<ApprovedUpdate, Error> {
        if self.summary.needs_review() {
            return Err(Error::ReviewRequired);
        }
        Ok(ApprovedUpdate(self))
    }

    /// Вызывается host только после явного согласия на этот отображённый отчёт.
    /// Не является capability-check или разрешением запуска native JSON.
    pub fn approve_after_review(self) -> ApprovedUpdate {
        ApprovedUpdate(self)
    }
}

#[derive(Debug)]
pub struct ApprovedUpdate(StagedUpdate);

impl ApprovedUpdate {
    /// Для транзакционной записи Repository до публикации нового snapshot.
    pub fn report(&self) -> &ImportReport {
        &self.0.report
    }
}

/// Один writer владеет controller. ID уникален среди всех экземпляров, callbacks
/// которых ещё могут прийти, в том числе после удаления и повторного добавления
/// одной подписки. Это ID controller, а не постоянный ID записи в БД.
///
/// Здесь хранится только память. Платформенный Repository должен атомарно
/// сохранить candidate с CAS до публикации commit, не выполняя I/O в UI-потоке.
#[derive(Debug)]
pub struct Subscription {
    controller: NonZeroU64,
    source_generation: u64,
    revision: u64,
    snapshot_source_generation: Option<u64>,
    request: u64,
    active: Option<Ticket>,
    snapshot: Option<ImportReport>,
    profile_snapshot: Option<yonik_import::ProfileImportReport>,
}

impl Subscription {
    /// Переход server-only staging к v2 с тем же correlation ticket.
    /// Повторная DATA-проверка не выдаёт runtime capability.
    pub fn upgrade_staged(&self, staged: StagedUpdate) -> Result<ProfileStagedUpdate, Error> {
        self.stage_profiles_cancellable(
            staged.ticket,
            staged.report.original().expose().as_bytes().to_vec(),
            || true,
        )
        .map_err(|error| match error {
            CancellableStageError::Cancelled => Error::Stale,
            CancellableStageError::Stage(error) => error,
        })
    }

    pub fn stage_profiles_cancellable(
        &self,
        ticket: Ticket,
        body: Vec<u8>,
        proceed: impl Fn() -> bool,
    ) -> Result<ProfileStagedUpdate, CancellableStageError> {
        self.check(ticket).map_err(CancellableStageError::Stage)?;
        if !proceed() {
            return Err(CancellableStageError::Cancelled);
        }
        let report = yonik_import::import_profiles(body);
        if !proceed() {
            return Err(CancellableStageError::Cancelled);
        }
        let report = report
            .map_err(|error| CancellableStageError::Stage(Error::InvalidImport(error.kind())))?;
        if report.entries.is_empty() {
            return Err(CancellableStageError::Stage(Error::NoUsableRecords));
        }
        let mut flagged = 0;
        let mut native = false;
        for entry in &report.entries {
            if !proceed() {
                return Err(CancellableStageError::Cancelled);
            }
            match entry {
                yonik_import::ProfileEntry::Server(server) => {
                    flagged += usize::from(!server.review_flags().is_empty())
                }
                yonik_import::ProfileEntry::Xray(_) => native = true,
            }
        }
        let summary = Summary {
            accepted: report.entries.len(),
            rejected: report.issues.len(),
            flagged,
            native_json: native,
        };
        Ok(ProfileStagedUpdate {
            ticket,
            report,
            summary,
        })
    }

    /// Repository уже выполнил CAS; публикация не затрагивает активную сессию.
    pub fn commit_profiles(&mut self, approved: ProfileApprovedUpdate) -> Result<(), Error> {
        self.check(approved.0.ticket)?;
        self.revision = self.revision.checked_add(1).ok_or(Error::Exhausted)?;
        self.snapshot_source_generation = Some(approved.0.ticket.source_generation);
        self.profile_snapshot = Some(approved.0.report);
        self.snapshot = None;
        self.active = None;
        Ok(())
    }

    pub fn new(controller: NonZeroU64) -> Self {
        Self {
            controller,
            source_generation: 0,
            revision: 0,
            snapshot_source_generation: None,
            request: 0,
            active: None,
            snapshot: None,
            profile_snapshot: None,
        }
    }

    pub fn source_generation(&self) -> u64 {
        self.source_generation
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn snapshot_source_generation(&self) -> Option<u64> {
        self.snapshot_source_generation
    }

    pub fn snapshot(&self) -> Option<&ImportReport> {
        self.snapshot.as_ref()
    }

    pub fn profile_snapshot(&self) -> Option<&yonik_import::ProfileImportReport> {
        self.profile_snapshot.as_ref()
    }

    pub fn begin(&mut self) -> Result<Ticket, Error> {
        let request = self.request.checked_add(1).ok_or(Error::Exhausted)?;
        let ticket = Ticket {
            controller: self.controller,
            request,
            source_generation: self.source_generation,
            revision: self.revision,
        };
        self.request = request;
        self.active = Some(ticket);
        Ok(ticket)
    }

    pub fn source_changed(&mut self) -> Result<(), Error> {
        let generation = self
            .source_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.source_generation = generation;
        self.active = None;
        // Старый snapshot остаётся доступен офлайн и отмечен старым поколением.
        Ok(())
    }

    pub fn finish(&mut self, ticket: Ticket) -> Result<(), Error> {
        self.check(ticket)?;
        self.active = None;
        Ok(())
    }

    pub fn stage(&self, ticket: Ticket, body: Vec<u8>) -> Result<StagedUpdate, Error> {
        self.stage_cancellable(ticket, body, || true)
            .map_err(|error| match error {
                CancellableStageError::Stage(error) => error,
                CancellableStageError::Cancelled => Error::Stale,
            })
    }

    pub fn stage_cancellable(
        &self,
        ticket: Ticket,
        body: Vec<u8>,
        proceed: impl Fn() -> bool,
    ) -> Result<StagedUpdate, CancellableStageError> {
        self.check(ticket).map_err(CancellableStageError::Stage)?;
        let report =
            yonik_import::import_bytes_cancellable(body, &proceed).map_err(
                |error| match error {
                    yonik_import::CancellableImportError::Cancelled => {
                        CancellableStageError::Cancelled
                    }
                    yonik_import::CancellableImportError::Import(error) => {
                        CancellableStageError::Stage(Error::InvalidImport(error.kind()))
                    }
                },
            )?;
        if report.servers.is_empty() && report.native_json.is_none() {
            return Err(CancellableStageError::Stage(Error::NoUsableRecords));
        }
        let summary = Summary {
            accepted: report.servers.len(),
            rejected: report.issues.len(),
            flagged: report.servers.iter().try_fold(0, |count, server| {
                if !proceed() {
                    return Err(CancellableStageError::Cancelled);
                }
                Ok(count + usize::from(!server.review_flags().is_empty()))
            })?,
            native_json: report.native_json.is_some(),
        };
        if !proceed() {
            return Err(CancellableStageError::Cancelled);
        }
        Ok(StagedUpdate {
            ticket,
            report,
            summary,
        })
    }

    pub fn commit(&mut self, approved: ApprovedUpdate) -> Result<(), Error> {
        let StagedUpdate { ticket, report, .. } = approved.0;
        self.check(ticket)?;
        let revision = self.revision.checked_add(1).ok_or(Error::Exhausted)?;
        self.snapshot = Some(report);
        self.profile_snapshot = None;
        self.snapshot_source_generation = Some(ticket.source_generation);
        self.revision = revision;
        self.active = None;
        Ok(())
    }

    fn check(&self, ticket: Ticket) -> Result<(), Error> {
        if self.active != Some(ticket) {
            return Err(Error::Stale);
        }
        Ok(())
    }
}
