#[cfg(feature = "test-support")]
mod lifecycle_gate;
#[cfg(feature = "test-support")]
pub use lifecycle_gate::{LifecycleGate, LifecycleStage};
mod binary;
pub(crate) mod local_profile_channel;
mod probe;
mod process;
mod session;
#[cfg(test)]
mod tests;

pub(crate) use binary::SharedImage;
pub use binary::{BinarySnapshot, Sha256};
pub use probe::{ProbeResult, ProbeTarget};
pub use session::{CheckedConfig, LocalSession};

use std::fmt;
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullProfileMode {
    Local,
    System,
}

/// Ранний отказ до binary/config/IPC effects; не выдаёт launch authority.
/// Проверки image, источников и режима при подготовке остаются обязательными.
pub fn full_profile_preflight(mode: FullProfileMode) -> Result<(), HostError> {
    match mode {
        FullProfileMode::Local | FullProfileMode::System => {
            crate::helper::native_profile_channel::require_consumer()
                .map(|_| ())
                .map_err(|_| HostError::Unsupported)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    InvalidBinary,
    BinaryIo,
    BinaryHash,
    Snapshot,
    ResourceLimit,
    Version,
    Process,
    ConfigRejected,
    Unsupported,
    Timeout,
    Cancelled,
    EngineExited,
    Listener,
    Cleanup,
    State,
    ProbeTarget,
}
impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBinary => "Нужен исполняемый ELF regular file не больше 128 MiB",
            Self::BinaryIo => "Не удалось прочитать бинарник ядра",
            Self::BinaryHash => "SHA-256 бинарника не совпадает",
            Self::Snapshot => "Не удалось создать неизменяемый executable snapshot",
            Self::ResourceLimit => "Достигнут бюджет исполняемых снимков",
            Self::Version => "Версия ядра не соответствует контракту",
            Self::Process => "Не удалось выполнить операцию процесса",
            Self::ConfigRejected => "Ядро отклонило конфигурацию",
            Self::Unsupported => "Полный профиль недоступен для этого установленного ядра",
            Self::Timeout => "Превышено время операции",
            Self::Cancelled => "Операция отменена",
            Self::EngineExited => "Процесс ядра завершился",
            Self::Listener => "Listener не принадлежит запущенному ядру",
            Self::Cleanup => "Не подтверждено завершение процесса ядра",
            Self::State => "Нарушен порядок операций сессии",
            Self::ProbeTarget => "Некорректный HTTPS endpoint или timeout",
        })
    }
}
impl std::error::Error for HostError {}

/// Закрытие источника тоже отменяет операцию: потеря владельца не оставляет core.
#[derive(Clone, Debug)]
pub struct Cancellation(
    watch::Receiver<bool>,
    Option<watch::Receiver<bool>>,
    #[cfg(feature = "test-support")] Option<(LifecycleGate, u64)>,
);
impl Cancellation {
    #[cfg(feature = "test-support")]
    pub fn with_lifecycle_gate(mut self, gate: LifecycleGate, generation: u64) -> Self {
        self.2 = Some((gate, generation));
        self
    }
    #[cfg(feature = "test-support")]
    pub(crate) async fn lifecycle_reach(
        &mut self,
        stage: LifecycleStage,
        pid: u32,
    ) -> Result<(), HostError> {
        if let Some((gate, generation)) = self.2.clone() {
            gate.reach(stage, pid, generation, self).await?;
        }
        self.check()
    }
    pub fn new() -> (watch::Sender<bool>, Self) {
        let (sender, receiver) = watch::channel(false);
        (
            sender,
            Self(
                receiver,
                None,
                #[cfg(feature = "test-support")]
                None,
            ),
        )
    }
    pub fn check(&self) -> Result<(), HostError> {
        if *self.0.borrow()
            || self.0.has_changed().is_err()
            || self
                .1
                .as_ref()
                .is_some_and(|other| *other.borrow() || other.has_changed().is_err())
        {
            Err(HostError::Cancelled)
        } else {
            Ok(())
        }
    }
    pub async fn cancelled(&mut self) {
        while self.check().is_ok() {
            tokio::select! {
                _ = self.0.changed() => {},
                _ = async {
                    if let Some(other) = &mut self.1 { let _ = other.changed().await; }
                    else { std::future::pending::<()>().await; }
                } => {},
            }
        }
    }
}

impl Cancellation {
    /// Использует существующий watch-источник; закрытие означает отмену.
    pub fn from_receiver(receiver: watch::Receiver<bool>) -> Self {
        Self(
            receiver,
            None,
            #[cfg(feature = "test-support")]
            None,
        )
    }

    pub(crate) fn with_other(mut self, receiver: watch::Receiver<bool>) -> Self {
        self.1 = Some(receiver);
        self
    }

    /// Чтение под watch-lock — точка допуска необратимого COMMIT.
    /// send_replace до чтения запрещает допуск; после допуска worker обязан
    /// вернуть фактический результат COMMIT, даже если пришла отмена.
    pub(crate) fn admit_commit(&self) -> Result<(), HostError> {
        let cancelled = self.0.borrow();
        let other = self.1.as_ref().map(|receiver| receiver.borrow());
        if *cancelled
            || self.0.has_changed().is_err()
            || other.as_ref().is_some_and(|value| **value)
            || self
                .1
                .as_ref()
                .is_some_and(|receiver| receiver.has_changed().is_err())
        {
            Err(HostError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod full_profile_preflight_tests {
    #[test]
    fn closed_admission_refuses_both_modes_without_effects() {
        for mode in [
            super::FullProfileMode::Local,
            super::FullProfileMode::System,
        ] {
            assert_eq!(
                super::full_profile_preflight(mode),
                Err(super::HostError::Unsupported)
            );
        }
    }
}
