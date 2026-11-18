//! Только durable-решение восстановления; конфигурация и секреты сюда не входят.
use super::{Journal, JournalError, Ownership, Scope};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecoveryRecord {
    kill_switch: bool,
}

impl SessionRecoveryRecord {
    pub fn kill_switch(&self) -> bool {
        self.kill_switch
    }
}

// deserialize_with делает поле обязательным даже для Option: отсутствие поля
// в v3 не должно трактоваться как доказанное отсутствие активной сессии.
pub(super) fn deserialize_recovery<'de, D>(
    deserializer: D,
) -> Result<Option<SessionRecoveryRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<SessionRecoveryRecord>::deserialize(deserializer)
}

impl Journal {
    pub fn session_recovery(&self) -> Option<&SessionRecoveryRecord> {
        self.document.session_recovery.as_ref()
    }

    /// Вызывать до любых эффектов сессии, включая запуск worker.
    /// Повтор разрешён только с тем же решением восстановления.
    pub fn begin_session(
        &mut self,
        ownership: Ownership,
        kill_switch: bool,
    ) -> Result<(), JournalError> {
        self.check(ownership)?;
        if let Some(record) = self.session_recovery() {
            return if record.kill_switch == kill_switch {
                Ok(())
            } else {
                Err(JournalError::Conflict)
            };
        }
        let mut document = self.document.clone();
        document.session_recovery = Some(SessionRecoveryRecord { kill_switch });
        self.persist(document)
    }

    /// После явной авторизации Unlock перезапуск продолжает разблокировку.
    pub(crate) fn confirm_authorized_session_unlock(
        &mut self,
        ownership: Ownership,
    ) -> Result<(), JournalError> {
        self.check(ownership)?;
        if !self
            .session_recovery()
            .is_some_and(SessionRecoveryRecord::kill_switch)
        {
            return Ok(());
        }
        let mut document = self.document.clone();
        document.session_recovery = Some(SessionRecoveryRecord { kill_switch: false });
        self.persist(document)
    }

    /// Caller сначала доказывает пустой worker scope и завершает очистку сети.
    /// Публичная блокировка имеет независимый жизненный цикл.
    pub fn clear_session(&mut self, ownership: Ownership) -> Result<(), JournalError> {
        self.check(ownership)?;
        if self
            .document
            .records
            .iter()
            .any(|record| record.scope() == Scope::Session)
        {
            return Err(JournalError::Conflict);
        }
        if self.session_recovery().is_none() {
            return Ok(());
        }
        let mut document = self.document.clone();
        document.session_recovery = None;
        self.persist(document)
    }
}
