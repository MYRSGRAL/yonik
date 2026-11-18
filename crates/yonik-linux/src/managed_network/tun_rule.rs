//! RPDB только для подтверждённых маршрутов собственного TUN.
use super::{TunError, TunExecutor, config, lease, write};
use crate::managed_network::{Journal, JournalError, Reconciled, RecordState, Resource, Scope};
use crate::{LinuxRule, LinuxTopology};

#[cfg(test)]
#[path = "tun_rule_tests.rs"]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TunRule {
    priority: u32,
    table: u32,
    mark: u32,
    ipv6: bool,
}
impl TunRule {
    pub fn new(priority: u32, table: u32, mark: u32, ipv6: bool) -> Result<Self, TunError> {
        if !(1..32766).contains(&priority)
            || !(256..u32::MAX).contains(&table)
            || !(1..=i32::MAX as u32).contains(&mark)
        {
            return Err(TunError::Invalid);
        }
        Ok(Self {
            priority,
            table,
            mark,
            ipv6,
        })
    }
    pub fn priority(self) -> u32 {
        self.priority
    }
    pub fn table(self) -> u32 {
        self.table
    }
    pub fn mark(self) -> u32 {
        self.mark
    }
    pub fn ipv6(self) -> bool {
        self.ipv6
    }
    fn family(self) -> u8 {
        if self.ipv6 { 10 } else { 2 }
    }
}
impl std::fmt::Debug for TunRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TunRule(<скрыто>)")
    }
}
pub(super) fn rule_matches(value: &LinuxRule, expected: TunRule) -> bool {
    let unspecified = if expected.ipv6 {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    };
    value.family == expected.family()
        && value.destination.address == unspecified
        && value.destination.length == 0
        && value.source.address == unspecified
        && value.source.length == 0
        && value.tos == 0
        && value.table == expected.table
        && value.action == 1
        && value.flags == 2
        && value.priority == Some(expected.priority)
        && value.goto.is_none()
        && value.fwmark == Some(expected.mark)
        && value.fwmask == Some(u32::MAX)
        && value.protocol == Some(253)
        && value.uid_range.is_none()
        && value.input_interface.is_none()
        && value.output_interface.is_none()
        && value.ip_protocol.is_none()
        && value.source_ports.is_none()
        && value.destination_ports.is_none()
        // Kernel dump выражает отсутствие suppression значением -1.
        && value.suppress_prefix_len.is_none_or(|length| length == u32::MAX)
        && value.suppress_interface_group.is_none()
        && value.l3mdev.is_none()
        && value.unknown.is_empty()
}
fn observe_rule(topology: &LinuxTopology, expected: TunRule) -> Result<bool, TunError> {
    let mut found = topology
        .rules
        .iter()
        .filter(|r| r.family == expected.family() && r.priority == Some(expected.priority));
    let Some(value) = found.next() else {
        return Ok(false);
    };
    if found.next().is_some() || !rule_matches(value, expected) {
        return Err(TunError::Foreign);
    }
    Ok(true)
}
fn parent(
    executor: &TunExecutor,
    journal: &Journal,
    tun_id: u64,
    topology: &LinuxTopology,
    adding: bool,
) -> Result<u32, TunError> {
    let state = config::record_state(journal, tun_id)?;
    if state == RecordState::Intent || adding && state != RecordState::Confirmed {
        return Err(TunError::Evidence);
    }
    config::parent_index(executor, journal, tun_id, topology, adding)?.ok_or(TunError::Evidence)
}
fn owned_reference(
    topology: &LinuxTopology,
    journal: &Journal,
    index: u32,
    value: &LinuxRule,
) -> bool {
    journal.records().iter().any(|record| {
        let Resource::TunRule {
            tun_id,
            ifindex,
            priority,
            table,
            mark,
            ipv6,
        } = record.resource()
        else {
            return false;
        };
        if record.scope() != Scope::Session
            || record.state() == RecordState::Intent
            || *ifindex != index
        {
            return false;
        }
        let Ok(expected) = TunRule::new(*priority, *table, *mark, *ipv6) else {
            return false;
        };
        if !rule_matches(value, expected) {
            return false;
        }
        journal.records().iter().any(|record| {
            let Resource::Tun { name_id } = record.resource() else {
                return false;
            };
            record.id() == *tun_id
                && record.scope() == Scope::Session
                && record.state() != RecordState::Intent
                && super::alias(journal.ownership(), *tun_id)
                    .ok()
                    .is_some_and(|alias| {
                        super::observed(&topology.links, *name_id, &alias).ok() == Some(Some(index))
                    })
        })
    })
}
/// Все ссылки на таблицу проверяются независимо от семейства.
pub(super) fn check_references(
    topology: &LinuxTopology,
    journal: &Journal,
    index: u32,
    table: u32,
    current: Option<TunRule>,
) -> Result<(), TunError> {
    for value in topology.rules.iter().filter(|r| r.table == table) {
        if !current.is_some_and(|expected| rule_matches(value, expected))
            && !owned_reference(topology, journal, index, value)
        {
            return Err(TunError::Foreign);
        }
    }
    Ok(())
}
fn check_table(
    topology: &LinuxTopology,
    journal: &Journal,
    tun_id: u64,
    index: u32,
    expected: TunRule,
    require_default: bool,
) -> Result<(), TunError> {
    let mut default = false;
    let loopback = config::loopback_ifindex(topology);
    for value in topology.routes.iter().filter(|r| r.table == expected.table) {
        let owned = journal.records().iter().any(|record| {
            record.scope() == Scope::Session
                && (record.state() == RecordState::Confirmed
                    || !require_default && record.state() == RecordState::CleanupRemaining)
                && config::recorded_route(record.resource(), tun_id, index)
                    .is_some_and(|route| config::route_matches(value, index, loopback, route))
        });
        if !owned {
            return Err(TunError::Foreign);
        }
        if value.family == expected.family()
            && value.destination.length == 0
            && value.destination.address.is_unspecified()
        {
            default = true;
        }
    }
    if require_default && !default {
        return Err(TunError::Evidence);
    }
    Ok(())
}
impl TunExecutor {
    pub async fn ensure_rule(
        &mut self,
        journal: &mut Journal,
        tun_id: u64,
        id: u64,
        rule: TunRule,
    ) -> Result<(), TunError> {
        config::ownership(self, journal)?;
        if journal.records().iter().any(|record| record.id() == id) {
            // Даже отмена ожидания lease или ошибка первого dump отменяет
            // прежнее подтверждение: оно не описывает новую попытку сверки.
            journal.require_reconciliation(self.owner, id)?;
        }
        let operation = lease().await?;
        let before = self.configuration_snapshot().await?;
        let index = parent(self, journal, tun_id, &before, true)?;
        check_table(&before, journal, tun_id, index, rule, true)?;
        check_references(&before, journal, index, rule.table, None)?;
        // Проверка конфликта priority происходит до записи intent, но совпавший
        // чужой объект всё равно никогда не становится нашим.
        let present = observe_rule(&before, rule)?;
        let fresh = journal.intent(
            self.owner,
            Scope::Session,
            id,
            Resource::TunRule {
                tun_id,
                ifindex: index,
                priority: rule.priority,
                table: rule.table,
                mark: rule.mark,
                ipv6: rule.ipv6,
            },
        )?;
        let state = config::record_state(journal, id)?;
        journal.require_reconciliation(self.owner, id)?;
        if present && (fresh || state != RecordState::Confirmed) {
            return Err(TunError::Evidence);
        }
        let topology = self.configuration_snapshot().await?;
        if parent(self, journal, tun_id, &topology, true)? != index {
            return Err(TunError::Evidence);
        }
        check_table(&topology, journal, tun_id, index, rule, true)?;
        check_references(&topology, journal, index, rule.table, None)?;
        if observe_rule(&topology, rule)? {
            if fresh || state != RecordState::Confirmed {
                return Err(TunError::Evidence);
            }
        } else {
            if !fresh {
                return Err(TunError::Evidence);
            }
            self.check_namespace()?;
            write::run(write::Action::Rule { rule, add: true }, operation).await?;
            let topology = self.configuration_snapshot().await?;
            if parent(self, journal, tun_id, &topology, true)? != index
                || !observe_rule(&topology, rule)?
            {
                return Err(TunError::Evidence);
            }
            check_table(&topology, journal, tun_id, index, rule, true)?;
            check_references(&topology, journal, index, rule.table, Some(rule))?;
        }
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        Ok(())
    }
    pub async fn remove_rule(
        &mut self,
        journal: &mut Journal,
        tun_id: u64,
        id: u64,
    ) -> Result<(), TunError> {
        let operation = lease().await?;
        config::ownership(self, journal)?;
        let record = journal
            .records()
            .iter()
            .find(|r| r.id() == id)
            .ok_or(JournalError::Missing)?;
        let Resource::TunRule {
            tun_id: expected_tun,
            ifindex,
            priority,
            table,
            mark,
            ipv6,
        } = record.resource()
        else {
            return Err(TunError::Invalid);
        };
        if record.scope() != Scope::Session || *expected_tun != tun_id {
            return Err(TunError::Invalid);
        }
        let (index, state, rule) = (
            *ifindex,
            record.state(),
            TunRule::new(*priority, *table, *mark, *ipv6)?,
        );
        journal.require_reconciliation(self.owner, id)?;
        let topology = self.configuration_snapshot().await?;
        if !observe_rule(&topology, rule)? {
            journal.reconcile(self.owner, id, Reconciled::Absent)?;
            return Ok(());
        }
        if state == RecordState::Intent || parent(self, journal, tun_id, &topology, false)? != index
        {
            return Err(TunError::Evidence);
        }
        check_table(&topology, journal, tun_id, index, rule, false)?;
        check_references(&topology, journal, index, rule.table, Some(rule))?;
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        journal.mark_cleanup(self.owner, id)?;
        self.check_namespace()?;
        write::run(write::Action::Rule { rule, add: false }, operation).await?;
        if observe_rule(&self.configuration_snapshot().await?, rule)? {
            return Err(TunError::Evidence);
        }
        journal.reconcile(self.owner, id, Reconciled::Absent)?;
        Ok(())
    }
}
