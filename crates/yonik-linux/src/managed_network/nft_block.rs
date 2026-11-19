use super::*;
use crate::managed_network::firewall::{DHCP_RENEWAL_CHAIN, DHCP_RENEWAL_SET};
use sha2::{Digest, Sha256};

pub(super) fn block_table(
    owner: Ownership,
    id: u64,
    table_id: u64,
    policy: &PublicBlockPolicy,
) -> Table {
    let mut table = Table::new(owner, Scope::PublicBlock, id, table_id, NftFamily::Inet);
    let mut hash = Sha256::new();
    hash.update(b"yonik-public-block-v1\0");
    hash.update(table.name.as_bytes());
    hash.update(table.comment.as_bytes());
    hash.update(policy.digest());
    table.comment = format!("yonik:block:1:{:x}", hash.finalize());
    table
}

/// Снимаем только различия представления, не смысл match/verdict. nft может
/// убрать зависимость nfproto/l4proto, уже выраженную последующим payload.
fn normalize_rule(
    value: &mut Value,
    resolve: &impl Fn(&str) -> Result<u32, NftError>,
) -> Result<(), NftError> {
    let Some(expressions) = value.get_mut("expr").and_then(Value::as_array_mut) else {
        return Err(NftError::Evidence);
    };
    let protocols: Vec<String> = expressions
        .iter()
        .filter_map(|expr| {
            expr.pointer("/match/left/payload/protocol")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    expressions.retain(|expr| {
        let key = expr.pointer("/match/left/meta/key").and_then(Value::as_str);
        let right = expr.pointer("/match/right").and_then(Value::as_str);
        let dependency = match (key, right) {
            (Some("nfproto"), Some("ipv4")) => Some("ip"),
            (Some("nfproto"), Some("ipv6")) => Some("ip6"),
            (Some("l4proto"), Some("tcp")) => Some("tcp"),
            (Some("l4proto"), Some("udp")) => Some("udp"),
            (Some("l4proto"), Some("ipv6-icmp")) => Some("icmpv6"),
            _ => None,
        };
        !dependency.is_some_and(|protocol| {
            protocols.iter().any(|actual| actual == protocol)
                && expr == &json!({"match":{"op":"==","left":{"meta":{"key":key}},"right":right}})
        })
    });
    for expression in expressions {
        if expression
            .pointer("/match/left/payload/protocol")
            .and_then(Value::as_str)
            == Some("icmpv6")
            && expression
                .pointer("/match/left/payload/field")
                .and_then(Value::as_str)
                == Some("type")
        {
            let kind = match expression.pointer("/match/right").and_then(Value::as_str) {
                Some("nd-router-solicit") => Some(133),
                Some("nd-neighbor-solicit") => Some(135),
                Some("nd-neighbor-advert") => Some(136),
                _ => None,
            };
            if let Some(kind) = kind {
                expression["match"]["right"] = json!(kind);
            }
        }
        if expression
            .pointer("/match/left/meta/key")
            .and_then(Value::as_str)
            == Some("oif")
        {
            if let Some(name) = expression.pointer("/match/right").and_then(Value::as_str) {
                let index = match resolve(name) {
                    Ok(index) => index,
                    Err(error) => match name.parse::<std::num::NonZeroU32>() {
                        Ok(index) if index.to_string() == name => index.get(),
                        _ => return Err(error),
                    },
                };
                expression["match"]["right"] = json!(index);
            }
        }
        if let Some(prefix) = expression
            .pointer("/match/right/prefix")
            .and_then(Value::as_object)
        {
            if prefix.len() == 2 {
                let address = prefix
                    .get("addr")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok());
                if let Some(address) = address {
                    let width = if address.is_ipv4() { 32 } else { 128 };
                    if prefix.get("len").and_then(Value::as_u64) == Some(width) {
                        expression["match"]["right"] = json!(address.to_string());
                    }
                }
            }
        }
    }
    Ok(())
}

fn verify_rules(
    bytes: &[u8],
    table: &Table,
    policy: &PublicBlockPolicy,
    resolve: impl Fn(&str) -> Result<u32, NftError>,
) -> Result<(), NftError> {
    if bytes.len() > MAX_OUTPUT {
        return Err(NftError::OutputLimit);
    }
    let listing: Listing = serde_json::from_slice(bytes).map_err(|_| NftError::Evidence)?;
    let mut tables = Vec::new();
    let mut actual = Vec::new();
    for item in listing.nftables {
        let object = item.as_object().ok_or(NftError::Evidence)?;
        if object.len() != 1 {
            return Err(NftError::Evidence);
        }
        if let Some(meta) = object.get("metainfo") {
            if !meta.is_object() {
                return Err(NftError::Evidence);
            }
            continue;
        }
        if object.contains_key("table") {
            tables.push(item);
            continue;
        }
        let (kind, mut data) = if let Some(chain) = object.get("chain") {
            ("chain", chain.clone())
        } else if let Some(rule) = object.get("rule") {
            ("rule", rule.clone())
        } else if let Some(set) = object.get("set").filter(|set| {
            policy.has_dhcp_renewal_anchor()
                && set.get("name").and_then(Value::as_str) == Some(DHCP_RENEWAL_SET)
        }) {
            ("set", set.clone())
        } else {
            return Err(NftError::Evidence);
        };
        let data_object = data.as_object_mut().ok_or(NftError::Evidence)?;
        if data_object
            .remove("handle")
            .and_then(|v| v.as_u64())
            .filter(|id| *id != 0)
            .is_none()
        {
            return Err(NftError::Evidence);
        }
        if kind == "set"
            && data_object
                .get("elem")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        {
            data_object.remove("elem");
        }
        if kind == "rule" {
            normalize_rule(&mut data, &resolve)?;
        }
        actual.push(json!({kind: data}));
    }
    if tables.len() != 1
        || !matches!(
            observe_json(
                &serde_json::to_vec(&json!({"nftables":tables})).map_err(|_| NftError::Evidence)?,
                table
            )?,
            Observation::Owned(_)
        )
    {
        return Err(NftError::Foreign);
    }
    let mut expected = Vec::new();
    for command in policy.commands(&table.name) {
        let mut data = command.get("add").cloned().ok_or(NftError::Evidence)?;
        if let Some(rule) = data.get_mut("rule") {
            normalize_rule(rule, &resolve)?;
        }
        expected.push(data);
    }
    if policy.has_dhcp_renewal_anchor() {
        // Порядок объектов разных типов зависит от nft. Порядок правил
        // внутри output остаётся частью проверки.
        let rank = |item: &Value| {
            if item.get("set").is_some() {
                0
            } else if item.pointer("/chain/name").and_then(Value::as_str)
                == Some(DHCP_RENEWAL_CHAIN)
            {
                1
            } else {
                2
            }
        };
        actual.sort_by_key(rank);
        expected.sort_by_key(rank);
    }
    if actual != expected {
        return Err(NftError::Evidence);
    }
    Ok(())
}

impl NftExecutor {
    /// Обновляет согласованные исключения без окна между снятием старой и
    /// установкой новой защиты. При конфликте handle откатывается весь batch.
    pub(super) async fn replace_public_block(
        &mut self,
        journal: &mut Journal,
        id: u64,
        previous: &PublicBlockPolicy,
        next: &PublicBlockPolicy,
    ) -> Result<(), NftError> {
        if journal.ownership() != self.owner {
            return Err(NftError::Journal(JournalError::WrongOwnership));
        }
        let record = journal
            .records()
            .iter()
            .find(|r| r.id() == id && r.scope() == Scope::PublicBlock)
            .ok_or(NftError::Journal(JournalError::Missing))?;
        if record.state() == RecordState::CleanupRemaining {
            return Err(NftError::Journal(JournalError::Conflict));
        }
        let Resource::NftTable {
            table_id,
            family: NftFamily::Inet,
        } = *record.resource()
        else {
            return Err(NftError::Invalid);
        };
        let old = block_table(self.owner, id, table_id, previous);
        let new = block_table(self.owner, id, table_id, next);
        journal.require_reconciliation(self.owner, id)?;
        let Observation::Owned(handle) = self.observe(&old).await? else {
            return Err(NftError::Evidence);
        };
        self.verify_public_block(&old, previous).await?;
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        journal.mark_update(self.owner, id)?;
        self.run(Action::ReplaceBlock(&old, handle, &new, next))
            .await?;
        self.verify_public_block(&new, next).await?;
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        Ok(())
    }
    pub(super) async fn verify_public_block(
        &mut self,
        table: &Table,
        policy: &PublicBlockPolicy,
    ) -> Result<(), NftError> {
        let bytes = self.run(Action::ListTable(table)).await?;
        self.check_namespace()?;
        let socket = rustix::net::socket_with(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::DGRAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| NftError::Io)?;
        verify_rules(&bytes, table, policy, |name| {
            rustix::net::netdevice::name_to_index(&socket, name).map_err(|_| NftError::Evidence)
        })
    }

    /// Создание таблицы и всех правил — одна nft transaction. Повтор принимает
    /// только полное фактическое совпадение; имеющаяся таблица не flush-ится.
    pub(super) async fn ensure_public_block(
        &mut self,
        journal: &mut Journal,
        id: u64,
        table_id: u64,
        policy: &PublicBlockPolicy,
    ) -> Result<(), NftError> {
        journal.intent(
            self.owner,
            Scope::PublicBlock,
            id,
            Resource::NftTable {
                table_id,
                family: NftFamily::Inet,
            },
        )?;
        journal.require_reconciliation(self.owner, id)?;
        if journal
            .records()
            .iter()
            .any(|r| r.id() == id && r.state() == RecordState::CleanupRemaining)
        {
            return Err(NftError::Journal(JournalError::Conflict));
        }
        let table = block_table(self.owner, id, table_id, policy);
        if self.observe(&table).await? == Observation::Absent {
            self.run(Action::InstallBlock(&table, policy)).await?;
        }
        self.verify_public_block(&table, policy).await?;
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        Ok(())
    }

    /// Внешний helper обязан отдельно авторизовать Unlock. Удаление сессионных
    /// ресурсов и Drop executor этот метод не вызывают.
    pub(super) async fn remove_public_block(
        &mut self,
        journal: &mut Journal,
        id: u64,
        policy: &PublicBlockPolicy,
    ) -> Result<(), NftError> {
        if journal.ownership() != self.owner {
            return Err(NftError::Journal(JournalError::WrongOwnership));
        }
        let record = journal
            .records()
            .iter()
            .find(|r| r.id() == id && r.scope() == Scope::PublicBlock)
            .ok_or(NftError::Journal(JournalError::Missing))?;
        let Resource::NftTable {
            table_id,
            family: NftFamily::Inet,
        } = *record.resource()
        else {
            return Err(NftError::Invalid);
        };
        let table = block_table(self.owner, id, table_id, policy);
        journal.require_reconciliation(self.owner, id)?;
        let handle = match self.observe(&table).await? {
            Observation::Absent => {
                journal.reconcile(self.owner, id, Reconciled::Absent)?;
                return Ok(());
            }
            Observation::Owned(handle) => handle,
        };
        self.verify_public_block(&table, policy).await?;
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        journal.mark_cleanup(self.owner, id)?;
        self.run(Action::Delete(&table, handle)).await?;
        if self.observe(&table).await? != Observation::Absent {
            return Err(NftError::Evidence);
        }
        journal.reconcile(self.owner, id, Reconciled::Absent)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "nft_block_tests.rs"]
pub(super) mod tests;

#[cfg(test)]
mod numeric_oif_regression {
    use super::{NftError, normalize_rule};
    use serde_json::json;
    #[test]
    fn deleted_oif_numeric_and_real_numeric_ifname() {
        let mut rule =
            json!({"expr":[{"match":{"op":"==","left":{"meta":{"key":"oif"}},"right":"27"}}]});
        assert_eq!(
            normalize_rule(&mut rule, &|_| Err(NftError::Evidence)),
            Ok(())
        );
        assert_eq!(rule["expr"][0]["match"]["right"], 27);
        rule["expr"][0]["match"]["right"] = json!("27");
        normalize_rule(&mut rule, &|_| Ok(81)).unwrap();
        assert_eq!(rule["expr"][0]["match"]["right"], 81);
        for invalid in ["0", "00", "027", "+27", "-27", "4294967296", "vpn"] {
            rule["expr"][0]["match"]["right"] = json!(invalid);
            assert_eq!(
                normalize_rule(&mut rule, &|_| Err(NftError::Evidence)),
                Err(NftError::Evidence)
            );
        }
    }
}
