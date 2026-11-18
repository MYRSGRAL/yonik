//! Durable-учёт для доверенного системного helper и типизированные исполнители.
//!
//! Сначала `intent`, затем внешний эффект, затем явный `reconcile`. Возврат
//! `intent(false)` означает повтор: повторять внешний эффект вслепую нельзя.
//! После открытия ни одна запись не доказывает существование или владение.
//! Helper обязан сверить namespace, собственную метку ресурса и его атрибуты.
//! Drop/отмена не очищает сеть и не удаляет неоднозначные намерения.

mod executable;
mod fake_quarantine;
pub mod firewall;
pub mod nft;
mod policy_state;
pub mod private_bindings;
mod quarantine_state;
mod session_state;
mod storage;
pub mod tun;
pub use policy_state::{PublicPolicyPhase, PublicPolicyRecord};
pub(crate) use quarantine_state::{FAKE_POOLS, QuarantineIntent, QuarantineTun};
pub use session_state::SessionRecoveryRecord;

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
    net::IpAddr,
    path::Path,
};

pub const MAX_JOURNAL_BYTES: usize = 128 * 1024;
pub const MAX_RECORDS: usize = 128;

/// UID клиента отделён от effective UID системного helper — владельца файлов.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ownership {
    owner_uid: u32,
    session: u64,
    generation: u64,
    netns_device: u64,
    netns_inode: u64,
}

impl Ownership {
    pub fn new(
        owner_uid: u32,
        session: u64,
        generation: u64,
        netns_device: u64,
        netns_inode: u64,
    ) -> Result<Self, JournalError> {
        let value = Self {
            owner_uid,
            session,
            generation,
            netns_device,
            netns_inode,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(self) -> Result<(), JournalError> {
        if self.session == 0 || self.generation == 0 || self.netns_inode == 0 {
            return Err(JournalError::Invalid);
        }
        Ok(())
    }
    pub fn owner_uid(self) -> u32 {
        self.owner_uid
    }
    pub fn session(self) -> u64 {
        self.session
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
    pub fn namespace(self) -> (u64, u64) {
        (self.netns_device, self.netns_inode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Session,
    PublicBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NftFamily {
    Inet,
    Ip,
    Ip6,
}

/// Имена создаёт helper из numeric ID; произвольных путей/команд/строк нет.
/// Полная метка владения включает Ownership и Record::id, а не только имя.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Resource {
    /// Имя `tofu` + 8 hex-цифр name_id. При сверке нужна метка владения link alias.
    Tun { name_id: u32 },
    /// Адрес принадлежит конкретному собственному TUN, а не произвольному ifindex.
    Address {
        tun_id: u64,
        ifindex: u32,
        address: IpAddr,
        prefix_len: u8,
    },
    /// Отдельная таблица helper; chain/rules принадлежат этой таблице целиком.
    NftTable { table_id: u64, family: NftFamily },
    Route {
        table: u32,
        destination: IpAddr,
        prefix_len: u8,
        priority: u32,
        protocol: u8,
        ifindex: u32,
    },
    /// ifindex подтверждает родительский TUN, а не выход RTN_THROW.
    ThrowRoute {
        tun_id: u64,
        ifindex: u32,
        table: u32,
        destination: IpAddr,
        prefix_len: u8,
        priority: u32,
    },
    /// Фиксированное RPDB-правило собственного TUN: invert, полная маска, protocol 253.
    TunRule {
        tun_id: u64,
        ifindex: u32,
        priority: u32,
        table: u32,
        mark: u32,
        ipv6: bool,
    },
    Rule {
        priority: u32,
        table: u32,
        mark: u32,
        mask: u32,
        ipv6: bool,
        protocol: u8,
    },
    /// Digest применённых настроек, без DNS-зон, адресов серверов и конфигов.
    /// Backend обязан отдельно доказать владение перед revert link settings.
    Dns {
        ifindex: u32,
        settings_digest: [u8; 32],
    },
}

impl Resource {
    fn parent_tun_id(&self) -> Option<u64> {
        match *self {
            Self::Address { tun_id, .. }
            | Self::TunRule { tun_id, .. }
            | Self::ThrowRoute { tun_id, .. } => Some(tun_id),
            _ => None,
        }
    }

    fn route_table(&self) -> Option<u32> {
        match *self {
            Self::Route { table, .. } | Self::ThrowRoute { table, .. } => Some(table),
            _ => None,
        }
    }

    fn anchors_throw_route(&self, other: &Self) -> bool {
        matches!((self, other), (
            Self::Route { table, ifindex, destination, prefix_len: 0, .. },
            Self::ThrowRoute { table: other_table, ifindex: other_index, destination: other_destination, .. },
        ) if table == other_table && ifindex == other_index
            && destination.is_ipv4() == other_destination.is_ipv4())
    }

    fn validate(&self, scope: Scope) -> Result<(), JournalError> {
        if scope == Scope::PublicBlock && !matches!(self, Self::NftTable { .. }) {
            return Err(JournalError::Invalid);
        }
        let valid = match self {
            Self::Tun { name_id } => *name_id != 0,
            Self::Address {
                tun_id,
                ifindex,
                address,
                prefix_len,
            } => {
                *tun_id != 0
                    && *ifindex != 0
                    && *prefix_len > 0
                    && *prefix_len <= if address.is_ipv4() { 32 } else { 128 }
                    && !address.is_unspecified()
                    && !address.is_loopback()
                    && !address.is_multicast()
                    && match address {
                        IpAddr::V4(ip) => !ip.is_broadcast() && !ip.is_link_local(),
                        IpAddr::V6(ip) => !ip.is_unicast_link_local() && ip.to_ipv4().is_none(),
                    }
            }
            Self::NftTable { table_id, .. } => *table_id != 0,
            Self::Route {
                table,
                destination,
                prefix_len,
                protocol,
                ifindex,
                ..
            } => {
                let canonical = match destination {
                    IpAddr::V4(address) => {
                        *prefix_len <= 32
                            && u32::from(*address).trailing_zeros() >= 32 - u32::from(*prefix_len)
                    }
                    IpAddr::V6(address) => {
                        *prefix_len <= 128
                            && u128::from(*address).trailing_zeros() >= 128 - u32::from(*prefix_len)
                    }
                };
                *table != 0 && canonical && *protocol != 0 && *ifindex != 0
            }
            Self::ThrowRoute {
                tun_id,
                ifindex,
                table,
                destination,
                prefix_len,
                priority,
            } => {
                *tun_id != 0
                    && (1..=i32::MAX as u32).contains(ifindex)
                    && tun::TunRoute::new_throw(*destination, *prefix_len, *table, *priority)
                        .is_ok()
            }
            Self::TunRule {
                tun_id,
                ifindex,
                priority,
                table,
                mark,
                ..
            } => {
                *tun_id != 0
                    && *ifindex != 0
                    && *ifindex <= i32::MAX as u32
                    && (1..32766).contains(priority)
                    && (256..u32::MAX).contains(table)
                    && (1..=i32::MAX as u32).contains(mark)
            }
            Self::Rule {
                priority,
                table,
                mask,
                mark,
                protocol,
                ..
            } => *priority != 0 && *table != 0 && *protocol != 0 && mark & !mask == 0,
            Self::Dns {
                ifindex,
                settings_digest,
            } => *ifindex != 0 && *settings_digest != [0; 32],
        };
        if valid {
            Ok(())
        } else {
            Err(JournalError::Invalid)
        }
    }
}

impl fmt::Debug for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Resource(<скрыто>)")
    }
}
impl fmt::Debug for Ownership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ownership(<скрыто>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordState {
    Intent,
    Confirmed,
    CleanupRemaining,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    id: u64,
    scope: Scope,
    resource: Resource,
    state: RecordState,
}
impl Record {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn scope(&self) -> Scope {
        self.scope
    }
    pub fn resource(&self) -> &Resource {
        &self.resource
    }
    /// История журнала, не свидетельство фактического состояния ОС.
    pub fn state(&self) -> RecordState {
        self.state
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    ownership: Ownership,
    records: Vec<Record>,
    public_policy: Option<PublicPolicyRecord>,
    policy_sequence: u64,
    #[serde(deserialize_with = "session_state::deserialize_recovery")]
    session_recovery: Option<SessionRecoveryRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fake_quarantine: Option<quarantine_state::FakeQuarantineRecord>,
}
impl Document {
    fn validate(&self) -> Result<(), JournalError> {
        if (self.version, self.fake_quarantine.is_some()) != (3, false)
            && (self.version, self.fake_quarantine.is_some()) != (4, true)
        {
            return Err(JournalError::Version);
        }
        self.ownership.validate()?;
        if self.records.len() > MAX_RECORDS {
            return Err(JournalError::Limit);
        }
        let mut ids = BTreeSet::new();
        let mut resources = HashSet::new();
        for record in &self.records {
            if record.id == 0 || !ids.insert(record.id) {
                return Err(JournalError::Invalid);
            }
            record.resource.validate(record.scope)?;
            if !resources.insert(&record.resource) {
                return Err(JournalError::Conflict);
            }
        }
        let tun_ids: HashSet<_> = self
            .records
            .iter()
            .filter_map(|record| {
                matches!(record.resource, Resource::Tun { .. }).then_some(record.id)
            })
            .collect();
        for record in &self.records {
            if let Some(tun_id) = record.resource.parent_tun_id() {
                if !tun_ids.contains(&tun_id) {
                    return Err(JournalError::Invalid);
                }
            }
        }
        if let Some(policy) = &self.public_policy {
            policy.validate(self)?;
        }
        if let Some(record) = &self.fake_quarantine {
            record.validate(self)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    Io,
    UnsafePath,
    Busy,
    Corrupt,
    Version,
    Limit,
    Invalid,
    WrongOwnership,
    Conflict,
    Missing,
    ReconcileRequired,
    UncertainWrite,
}
impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Io => "Ошибка I/O журнала",
            Self::UnsafePath => "Небезопасное хранилище журнала",
            Self::Busy => "Журнал уже открыт для записи",
            Self::Corrupt => "Повреждённый журнал",
            Self::Version => "Неизвестная версия журнала",
            Self::Limit => "Превышен лимит журнала",
            Self::Invalid => "Неверный дескриптор журнала",
            Self::WrongOwnership => "Не совпадает владелец или поколение журнала",
            Self::Conflict => "Конфликт записей журнала",
            Self::Missing => "Запись журнала отсутствует",
            Self::ReconcileRequired => "Необходима сверка владения с ОС",
            Self::UncertainWrite => "Неопределённый результат записи; откройте журнал повторно",
        })
    }
}
impl std::error::Error for JournalError {}

/// Только результат независимой проверки доверенным backend, не данные UI.
/// Unknown/чужой ресурс: не вызывать reconcile, сохранить запись и отказать.
#[derive(Debug, Clone, Copy)]
pub enum Reconciled {
    Owned,
    Absent,
}
#[derive(Debug, Clone, Copy)]
pub struct CleanupFailed;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    pub removed: usize,
    pub remaining: usize,
}

/// Синхронный single-writer: helper выносит файловый I/O из async executor.
/// Блокировка живёт до Drop; Drop не имеет сетевых побочных эффектов.
pub struct Journal {
    directory: storage::LockedDirectory,
    document: Document,
    reconciled: BTreeSet<u64>,
    poisoned: bool,
}

impl Journal {
    /// Фиксированный helper path: восстановление читает владельца из защищённого
    /// журнала, а не принимает UID/session из клиентского сообщения.
    pub fn open_existing(path: &Path) -> Result<Option<Self>, JournalError> {
        let directory = storage::directory(path)?;
        let Some(mut document) = storage::read(&directory)? else {
            return Ok(None);
        };
        let migrated = matches!(document.version, 1 | 2);
        if migrated {
            document.version = 3;
        }
        document.validate()?;
        let mut journal = Self {
            directory,
            document,
            reconciled: BTreeSet::new(),
            poisoned: false,
        };
        if migrated {
            journal.persist(journal.document.clone())?;
        }
        Ok(Some(journal))
    }
    /// Передача пустого host-journal другому авторизованному владельцу не
    /// переносит ни ресурсы, ни старые prepared handles/поколения.
    pub fn reassign_empty_owner(&mut self, next: Ownership) -> Result<(), JournalError> {
        self.check(self.document.ownership)?;
        next.validate()?;
        if !self.document.records.is_empty()
            || self.document.public_policy.is_some()
            || self.document.session_recovery.is_some()
        {
            return Err(JournalError::Conflict);
        }
        let mut document = self.document.clone();
        document.ownership = next;
        self.persist(document)?;
        self.reconciled.clear();
        Ok(())
    }
    pub fn open(path: &Path, ownership: Ownership) -> Result<Self, JournalError> {
        ownership.validate()?;
        let directory = storage::directory(path)?;
        let loaded = storage::read(&directory)?;
        let fresh = loaded.is_none();
        let migrated = loaded
            .as_ref()
            .is_some_and(|document| matches!(document.version, 1 | 2));
        let mut document = loaded.unwrap_or(Document {
            version: 3,
            ownership,
            records: Vec::new(),
            public_policy: None,
            policy_sequence: 0,
            session_recovery: None,
            fake_quarantine: None,
        });
        if migrated {
            document.version = 3;
        }
        document.validate()?;
        if document.ownership != ownership {
            return Err(JournalError::WrongOwnership);
        }
        let mut journal = Self {
            directory,
            document,
            reconciled: BTreeSet::new(),
            poisoned: false,
        };
        if fresh || migrated {
            journal.persist(journal.document.clone())?;
        }
        Ok(journal)
    }
    pub fn ownership(&self) -> Ownership {
        self.document.ownership
    }
    pub fn records(&self) -> &[Record] {
        &self.document.records
    }
    pub fn needs_reconciliation(&self, id: u64) -> bool {
        !self.reconciled.contains(&id)
    }
    /// Старое подтверждение не переживает новую сверку: ошибка или отмена
    /// наблюдения должна оставить неизвестное, а не прежнее applied-состояние.
    pub fn require_reconciliation(
        &mut self,
        ownership: Ownership,
        id: u64,
    ) -> Result<(), JournalError> {
        self.check(ownership)?;
        if !self.document.records.iter().any(|record| record.id == id) {
            return Err(JournalError::Missing);
        }
        self.reconciled.remove(&id);
        Ok(())
    }
    fn check(&self, ownership: Ownership) -> Result<(), JournalError> {
        if self.poisoned {
            return Err(JournalError::UncertainWrite);
        }
        if ownership != self.document.ownership {
            return Err(JournalError::WrongOwnership);
        }
        Ok(())
    }
    fn persist(&mut self, document: Document) -> Result<(), JournalError> {
        document.validate()?;
        match storage::write(&self.directory, &document) {
            Ok(()) => {
                self.document = document;
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                self.reconciled.clear();
                Err(error)
            }
        }
    }
    /// Запись гарантированно durable перед возвратом true и внешним эффектом.
    pub fn intent(
        &mut self,
        ownership: Ownership,
        scope: Scope,
        id: u64,
        resource: Resource,
    ) -> Result<bool, JournalError> {
        self.check(ownership)?;
        resource.validate(scope)?;
        if let Some(record) = self.document.records.iter().find(|record| record.id == id) {
            return if record.scope == scope && record.resource == resource {
                Ok(false)
            } else {
                Err(JournalError::Conflict)
            };
        }
        if self.document.records.len() == MAX_RECORDS {
            return Err(JournalError::Limit);
        }
        let mut document = self.document.clone();
        document.records.push(Record {
            id,
            scope,
            resource,
            state: RecordState::Intent,
        });
        self.persist(document)?;
        Ok(true)
    }
    pub fn reconcile(
        &mut self,
        ownership: Ownership,
        id: u64,
        observed: Reconciled,
    ) -> Result<(), JournalError> {
        self.check(ownership)?;
        let mut document = self.document.clone();
        let index = document
            .records
            .iter()
            .position(|record| record.id == id)
            .ok_or(JournalError::Missing)?;
        match observed {
            Reconciled::Owned => {
                if document.records[index].state != RecordState::CleanupRemaining {
                    document.records[index].state = RecordState::Confirmed;
                }
                self.persist(document)?;
                self.reconciled.insert(id);
            }
            Reconciled::Absent => {
                if let Some(policy) = &document.public_policy {
                    if policy.id() == id {
                        if !matches!(policy.phase(), PublicPolicyPhase::Removing { .. }) {
                            return Err(JournalError::Conflict);
                        }
                        document.public_policy = None;
                        if document
                            .session_recovery
                            .as_ref()
                            .is_some_and(|session| !session.kill_switch())
                            && !document
                                .records
                                .iter()
                                .any(|record| record.scope == Scope::Session)
                        {
                            document.session_recovery = None;
                        }
                    }
                }
                document.records.remove(index);
                self.persist(document)?;
                self.reconciled.remove(&id);
            }
        }
        Ok(())
    }
    /// Durable-граница перед асинхронным удалением. После возврата, отмены или
    /// ошибки новая попытка требует новой сверки ОС, даже без перезапуска helper.
    pub fn mark_cleanup(&mut self, ownership: Ownership, id: u64) -> Result<(), JournalError> {
        self.check(ownership)?;
        self.check_public_removal(id)?;
        let index = self
            .document
            .records
            .iter()
            .position(|record| record.id == id)
            .ok_or(JournalError::Missing)?;
        if !self.reconciled.contains(&id) {
            return Err(JournalError::ReconcileRequired);
        }
        let mut document = self.document.clone();
        document.records[index].state = RecordState::CleanupRemaining;
        self.persist(document)?;
        self.reconciled.remove(&id);
        Ok(())
    }
    /// Изменение существующего ресурса тоже требует durable intent. Отмена
    /// оставляет неизвестный старый/новый результат до независимой сверки ОС.
    pub fn mark_update(&mut self, ownership: Ownership, id: u64) -> Result<(), JournalError> {
        self.check(ownership)?;
        if self.document.public_policy.as_ref().is_some_and(|policy| {
            policy.id() == id && !matches!(policy.phase(), PublicPolicyPhase::Present { .. })
        }) {
            return Err(JournalError::Conflict);
        }
        let index = self
            .document
            .records
            .iter()
            .position(|record| record.id == id)
            .ok_or(JournalError::Missing)?;
        if self.document.records[index].state == RecordState::CleanupRemaining {
            return Err(JournalError::Conflict);
        }
        if !self.reconciled.contains(&id) {
            return Err(JournalError::ReconcileRequired);
        }
        let mut document = self.document.clone();
        document.records[index].state = RecordState::Intent;
        self.persist(document)?;
        self.reconciled.remove(&id);
        Ok(())
    }
    /// Callback удаляет только заново проверенный собственный ресурс, Ok —
    /// подтверждённое отсутствие. Err сохраняет остаток, остальные продолжаются.
    /// Неподтверждённые записи остаются, не мешая очистке подтверждённых.
    /// Публичная блокировка снимается только отдельным явным выбором PublicBlock.
    pub fn cleanup(
        &mut self,
        ownership: Ownership,
        scope: Scope,
        mut remove: impl FnMut(&Record) -> Result<(), CleanupFailed>,
    ) -> Result<CleanupReport, JournalError> {
        self.check(ownership)?;
        if scope == Scope::PublicBlock {
            if let Some(policy) = &self.document.public_policy {
                self.check_public_removal(policy.id())?;
            }
        }
        let ids: Vec<_> = self
            .document
            .records
            .iter()
            .filter(|record| record.scope == scope)
            .filter(|record| self.reconciled.contains(&record.id))
            .map(|record| record.id)
            .rev()
            .collect();
        if ids.is_empty() {
            if self
                .document
                .records
                .iter()
                .any(|record| record.scope == scope)
            {
                return Err(JournalError::ReconcileRequired);
            }
            return Ok(CleanupReport {
                removed: 0,
                remaining: 0,
            });
        }
        let mut document = self.document.clone();
        for record in &mut document.records {
            if record.scope == scope && self.reconciled.contains(&record.id) {
                record.state = RecordState::CleanupRemaining;
            }
        }
        self.persist(document)?;
        let mut removed = 0;
        let mut tun_children = BTreeMap::<u64, usize>::new();
        for record in &self.document.records {
            if let Some(tun_id) = record.resource.parent_tun_id() {
                *tun_children.entry(tun_id).or_default() += 1;
            }
        }
        for id in ids {
            let index = self
                .document
                .records
                .iter()
                .position(|record| record.id == id)
                .ok_or(JournalError::Missing)?;
            // Даже при unwind/cancellation следующая попытка требует новой сверки.
            self.reconciled.remove(&id);
            if matches!(self.document.records[index].resource, Resource::Tun { .. })
                && tun_children.get(&id).copied().unwrap_or(0) != 0
            {
                continue;
            }
            let resource = &self.document.records[index].resource;
            if let Some(table) = resource.route_table() {
                if self.document.records.iter().any(|record| {
                    matches!(record.resource, Resource::TunRule { table: used, .. } if used == table)
                        || resource.anchors_throw_route(&record.resource)
                }) {
                    continue;
                }
            }
            if remove(&self.document.records[index]).is_ok() {
                let mut document = self.document.clone();
                let removed_record = document.records.remove(index);
                if document
                    .public_policy
                    .as_ref()
                    .is_some_and(|policy| policy.id() == id)
                {
                    document.public_policy = None;
                }
                self.persist(document)?;
                if let Some(tun_id) = removed_record.resource.parent_tun_id() {
                    if let Some(count) = tun_children.get_mut(&tun_id) {
                        *count -= 1;
                    }
                }
                removed += 1;
            }
        }
        let remaining = self
            .document
            .records
            .iter()
            .filter(|record| record.scope == scope)
            .count();
        Ok(CleanupReport { removed, remaining })
    }
}
