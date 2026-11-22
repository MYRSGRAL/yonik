//! Политика nftables для временной защиты адресов, выданных Fake DNS.
//!
//! Один пакет команд создаёт отдельную таблицу `inet` транзакционно. Таймеры
//! элементов сохраняют защиту после остановки helper и истекают в ядре.
//! Формат nft JSON использует целые секунды, поэтому дробные значения
//! отклоняются.

use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    time::Duration,
};

const MAX_TTL_MS: u64 = 120_000;
const MAX_PREFIXES: usize = 512;
const OUTPUT_CHAIN: &str = "output";
const IPV4_SET: &str = "reserved_v4";
const IPV6_SET: &str = "reserved_v6";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineError {
    Owner,
    Prefix,
    Interface,
    Ttl,
    Limit,
    Empty,
    MissingFamily,
}

impl fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Owner => "Некорректная nft-идентичность карантина",
            Self::Prefix => "Нужен канонический зарезервированный IP-префикс",
            Self::Interface => "Нужна пара индекса и имени проверенного TUN",
            Self::Ttl => "TTL карантина должен быть целым числом секунд до 120 секунд",
            Self::Limit => "Превышен лимит префиксов карантина",
            Self::Empty => "Нужен хотя бы один защищаемый префикс",
            Self::MissingFamily => "Карантин должен содержать IPv4 и IPv6 префиксы",
        })
    }
}

impl std::error::Error for QuarantineError {}

/// Имя таблицы и точная owner-метка, созданные доверенным helper.
///
/// Для этой пары нужен уникальный идентификатор ресурса.
/// Восстановление сверяет обе строки, семейство `inet` и атрибуты таблицы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineOwner {
    table: String,
    tag: String,
}

impl QuarantineOwner {
    pub fn new(table: impl Into<String>, tag: impl Into<String>) -> Result<Self, QuarantineError> {
        let table = table.into();
        let tag = tag.into();
        let valid_name = !table.is_empty()
            && table.starts_with("yonik_")
            && table.len() <= 31
            && table
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        let valid_tag = tag.starts_with("yonik:")
            && !tag.is_empty()
            && tag.len() <= 128
            && tag.bytes().all(|byte| byte.is_ascii_graphic());
        if !valid_name || !valid_tag || table == OUTPUT_CHAIN {
            return Err(QuarantineError::Owner);
        }
        Ok(Self { table, tag })
    }
}

/// Канонический IP-префикс. Адрес уже нормализован до начала сети.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct QuarantinePrefix {
    address: IpAddr,
    length: u8,
}

impl QuarantinePrefix {
    pub fn new(address: IpAddr, length: u8) -> Result<Self, QuarantineError> {
        let canonical = match address {
            IpAddr::V4(address) if (1..=32).contains(&length) => {
                let mask = u32::MAX.checked_shl(u32::from(32 - length)).unwrap_or(0);
                u32::from(address) & mask == u32::from(address)
            }
            IpAddr::V6(address) if (1..=128).contains(&length) => {
                let mask = u128::MAX.checked_shl(u32::from(128 - length)).unwrap_or(0);
                u128::from(address) & mask == u128::from(address)
            }
            _ => false,
        };
        if !canonical {
            return Err(QuarantineError::Prefix);
        }
        Ok(Self { address, length })
    }

    fn nft_prefix(self) -> Value {
        json!({"prefix":{"addr":self.address.to_string(),"len":self.length}})
    }

    fn range(self) -> AddressRange {
        match self.address {
            IpAddr::V4(address) => {
                let start = u32::from(address);
                let end = start | u32::MAX.checked_shr(u32::from(self.length)).unwrap_or(0);
                AddressRange::V4 {
                    start: Ipv4Addr::from(start),
                    end: Ipv4Addr::from(end),
                }
            }
            IpAddr::V6(address) => {
                let start = u128::from(address);
                let end = start | u128::MAX.checked_shr(u32::from(self.length)).unwrap_or(0);
                AddressRange::V6 {
                    start: Ipv6Addr::from(start),
                    end: Ipv6Addr::from(end),
                }
            }
        }
    }
}

/// Проверенная helper-пара: разрешение создаётся только при совпадении обоих
/// признаков выходного интерфейса, поэтому переиспользованный ifindex/name сам
/// по себе не даёт обхода карантина.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTun {
    ifindex: NonZeroU32,
    ifname: String,
}

impl VerifiedTun {
    pub fn new(ifindex: u32, ifname: impl Into<String>) -> Result<Self, QuarantineError> {
        let ifindex = NonZeroU32::new(ifindex).ok_or(QuarantineError::Interface)?;
        let ifname = ifname.into();
        if ifname.is_empty()
            || ifname.len() > 15
            || matches!(ifname.as_str(), "." | "..")
            || ifname
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || byte == b'/' || byte == b':')
        {
            return Err(QuarantineError::Interface);
        }
        Ok(Self { ifindex, ifname })
    }
}

/// Ожидаемые элементы readback. Интервальные set-ы ядро вправе сериализовать
/// как `prefix` или как включительный `range`; caller сравнивает адресные
/// границы после нормализации. nft сообщает `expires` в целых секундах,
/// verifier переводит значение в миллисекунды. Видимый нулевой countdown
/// остаётся `Active(0)`, пока элементы действительно не исчезли из обоих set-ов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressRange {
    V4 { start: Ipv4Addr, end: Ipv4Addr },
    V6 { start: Ipv6Addr, end: Ipv6Addr },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedSet {
    pub name: &'static str,
    pub nft_type: &'static str,
    pub flags: [&'static str; 2],
    /// Точный срок в миллисекундах. В nft JSON передаётся `timeout_ms / 1000`.
    pub timeout_ms: u64,
    pub intervals: Vec<AddressRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedReadback {
    pub family: &'static str,
    pub table: String,
    pub owner_tag: String,
    pub chain: &'static str,
    pub chain_type: &'static str,
    pub hook: &'static str,
    pub priority: i32,
    pub chain_policy: &'static str,
    pub tun: Option<VerifiedTun>,
    pub sets: [ExpectedSet; 2],
    /// Канонические выражения из `nft -j list chain`; handles и counters
    /// зависят от runtime и не участвуют в сравнении.
    pub rules: Vec<Vec<Value>>,
    pub ttl_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineStatus {
    Active(Duration),
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineVerifyError {
    InvalidJson,
    ForeignOrUnexpectedObject,
    TableMismatch,
    ChainMismatch,
    RulesMismatch,
    SetsMismatch,
    PartialExpiry,
}

impl fmt::Display for QuarantineVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidJson => "Некорректный JSON readback nft",
            Self::ForeignOrUnexpectedObject => "В таблице карантина есть неизвестный nft объект",
            Self::TableMismatch => "Не совпала owner-метка nft-таблицы",
            Self::ChainMismatch => "Не совпали параметры base output chain",
            Self::RulesMismatch => "Не совпал порядок или выражения правил карантина",
            Self::SetsMismatch => "Не совпали параметры или префиксы timed set-ов",
            Self::PartialExpiry => "TTL-наборы карантина частично истекли или повреждены",
        })
    }
}

impl std::error::Error for QuarantineVerifyError {}

/// Проверяемая установка со стабильным compile result и install batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeQuarantine {
    owner: QuarantineOwner,
    ttl_ms: u64,
    tun: Option<VerifiedTun>,
    ipv4: Vec<QuarantinePrefix>,
    ipv6: Vec<QuarantinePrefix>,
}

impl FakeQuarantine {
    pub fn new(
        owner: QuarantineOwner,
        ttl: Duration,
        tun: Option<VerifiedTun>,
        prefixes: impl IntoIterator<Item = QuarantinePrefix>,
    ) -> Result<Self, QuarantineError> {
        let ttl_nanos = ttl.as_nanos();
        if ttl_nanos == 0 || ttl_nanos % 1_000_000_000 != 0 {
            return Err(QuarantineError::Ttl);
        }
        let ttl_ms = u64::try_from(ttl_nanos / 1_000_000).map_err(|_| QuarantineError::Ttl)?;
        if ttl_ms > MAX_TTL_MS {
            return Err(QuarantineError::Ttl);
        }

        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for prefix in prefixes {
            match prefix.address {
                IpAddr::V4(_) => ipv4.push(prefix),
                IpAddr::V6(_) => ipv6.push(prefix),
            }
            if ipv4.len() + ipv6.len() > MAX_PREFIXES {
                return Err(QuarantineError::Limit);
            }
        }
        ipv4.sort_unstable();
        ipv4.dedup();
        ipv6.sort_unstable();
        ipv6.dedup();
        if ipv4.is_empty() && ipv6.is_empty() {
            return Err(QuarantineError::Empty);
        }
        if ipv4.is_empty() || ipv6.is_empty() {
            return Err(QuarantineError::MissingFamily);
        }
        Ok(Self {
            owner,
            ttl_ms,
            tun,
            ipv4,
            ipv6,
        })
    }

    pub fn expected_readback(&self) -> ExpectedReadback {
        ExpectedReadback {
            family: "inet",
            table: self.owner.table.clone(),
            owner_tag: self.owner.tag.clone(),
            chain: OUTPUT_CHAIN,
            chain_type: "filter",
            hook: "output",
            priority: 0,
            chain_policy: "accept",
            tun: self.tun.clone(),
            sets: [
                ExpectedSet {
                    name: IPV4_SET,
                    nft_type: "ipv4_addr",
                    flags: ["interval", "timeout"],
                    timeout_ms: self.ttl_ms,
                    intervals: merged_ranges(&self.ipv4),
                },
                ExpectedSet {
                    name: IPV6_SET,
                    nft_type: "ipv6_addr",
                    flags: ["interval", "timeout"],
                    timeout_ms: self.ttl_ms,
                    intervals: merged_ranges(&self.ipv6),
                },
            ],
            rules: self.expected_rules(),
            ttl_ms: self.ttl_ms,
        }
    }

    /// Строго сверяет `nft -j -n list table inet <name>` с ожидаемым
    /// owner-tag, base chain, выражениями правил и обоими timed interval set-ами.
    /// Возвращает минимум `expires` по обеим семьям; только обе пустые сети
    /// означают истёкший карантин, а частично пустое состояние является ошибкой.
    pub fn verify_readback(&self, bytes: &[u8]) -> Result<QuarantineStatus, QuarantineVerifyError> {
        const MAX_READBACK_BYTES: usize = 1024 * 1024;
        if bytes.is_empty() || bytes.len() > MAX_READBACK_BYTES {
            return Err(QuarantineVerifyError::InvalidJson);
        }
        let root: Value =
            serde_json::from_slice(bytes).map_err(|_| QuarantineVerifyError::InvalidJson)?;
        if root
            .as_object()
            .map(|object| object.len() != 1 || !object.contains_key("nftables"))
            .unwrap_or(true)
        {
            return Err(QuarantineVerifyError::InvalidJson);
        }
        let items = root
            .get("nftables")
            .and_then(Value::as_array)
            .ok_or(QuarantineVerifyError::InvalidJson)?;
        let mut table_seen = false;
        let mut chain_seen = false;
        let mut rules = Vec::new();
        let mut sets = BTreeMap::new();
        for item in items {
            let object = item
                .as_object()
                .ok_or(QuarantineVerifyError::ForeignOrUnexpectedObject)?;
            if object.len() != 1 {
                return Err(QuarantineVerifyError::ForeignOrUnexpectedObject);
            }
            if object.contains_key("metainfo") {
                continue;
            }
            if let Some(table) = object.get("table") {
                if table_seen || !verify_table(table, &self.owner) {
                    return Err(QuarantineVerifyError::TableMismatch);
                }
                table_seen = true;
            } else if let Some(chain) = object.get("chain") {
                if chain_seen || !verify_chain(chain, &self.owner) {
                    return Err(QuarantineVerifyError::ChainMismatch);
                }
                chain_seen = true;
            } else if let Some(rule) = object.get("rule") {
                rules.push(verify_rule_shape(rule, &self.owner)?);
            } else if let Some(set) = object.get("set") {
                let name = set
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(QuarantineVerifyError::SetsMismatch)?;
                if sets.insert(name.to_owned(), set).is_some() {
                    return Err(QuarantineVerifyError::SetsMismatch);
                }
            } else {
                return Err(QuarantineVerifyError::ForeignOrUnexpectedObject);
            }
        }

        if !table_seen {
            return Err(QuarantineVerifyError::TableMismatch);
        }
        if !chain_seen {
            return Err(QuarantineVerifyError::ChainMismatch);
        }
        if let Some(tun) = &self.tun {
            normalize_interface_indexes(&mut rules, tun);
        }
        let expected = self.expected_readback();
        if rules != expected.rules {
            return Err(QuarantineVerifyError::RulesMismatch);
        }
        let v4 = sets
            .remove(IPV4_SET)
            .ok_or(QuarantineVerifyError::SetsMismatch)?;
        let v6 = sets
            .remove(IPV6_SET)
            .ok_or(QuarantineVerifyError::SetsMismatch)?;
        if !sets.is_empty() {
            return Err(QuarantineVerifyError::SetsMismatch);
        }
        let v4_expiry = verify_set(v4, &expected.sets[0], &self.owner)?;
        let v6_expiry = verify_set(v6, &expected.sets[1], &self.owner)?;
        match (v4_expiry, v6_expiry) {
            (None, None) => Ok(QuarantineStatus::Expired),
            (Some(v4), Some(v6)) => Ok(QuarantineStatus::Active(Duration::from_millis(v4.min(v6)))),
            _ => Err(QuarantineVerifyError::PartialExpiry),
        }
    }

    fn expected_rules(&self) -> Vec<Vec<Value>> {
        let mut rules = Vec::with_capacity(if self.tun.is_some() { 4 } else { 2 });
        for (protocol, set, prefixes) in
            [("ip", IPV4_SET, &self.ipv4), ("ip6", IPV6_SET, &self.ipv6)]
        {
            if prefixes.is_empty() {
                continue;
            }
            let destination = lookup_readback(protocol, "daddr", set);
            if let Some(tun) = &self.tun {
                rules.push(vec![
                    destination.clone(),
                    compare(
                        json!({"meta":{"key":"oif"}}),
                        json!(tun.ifindex.get().to_string()),
                    ),
                    compare(json!({"meta":{"key":"oifname"}}), json!(tun.ifname)),
                    json!({"accept":null}),
                ]);
            }
            rules.push(vec![destination, json!({"drop":null})]);
        }
        rules
    }

    /// Полный additive batch для первой установки. Все commands следует
    /// передавать одним nft JSON invocation, чтобы nft обработал их одной
    /// транзакцией; чужую существующую таблицу caller обязан отвергнуть.
    pub fn install_commands(&self) -> Vec<Value> {
        let mut commands = vec![json!({"add":{"table":{
            "family":"inet",
            "name":self.owner.table,
            "comment":self.owner.tag,
        }}})];
        commands.push(json!({"add":{"chain":{
            "family":"inet",
            "table":self.owner.table,
            "name":OUTPUT_CHAIN,
            "type":"filter",
            "hook":"output",
            "prio":0,
            "policy":"accept",
        }}}));
        commands.push(self.set_command(IPV4_SET, "ipv4_addr", &self.ipv4));
        commands.push(self.set_command(IPV6_SET, "ipv6_addr", &self.ipv6));
        commands.extend(self.rule_commands());
        commands
    }

    fn set_command(&self, name: &str, nft_type: &str, prefixes: &[QuarantinePrefix]) -> Value {
        let mut set = json!({
            "family":"inet",
            "table":self.owner.table,
            "name":name,
            "type":nft_type,
            "flags":["interval","timeout"],
            "timeout":self.ttl_ms / 1_000,
            "auto-merge":true,
        });
        let elements = self.elements(prefixes);
        if !elements.is_empty() {
            set["elem"] = json!(elements);
        }
        json!({"add":{"set":set}})
    }

    fn elements(&self, prefixes: &[QuarantinePrefix]) -> Vec<Value> {
        prefixes
            .iter()
            .map(|prefix| json!({"elem":{"val":prefix.nft_prefix(),"timeout":self.ttl_ms / 1_000}}))
            .collect()
    }

    fn rule_commands(&self) -> Vec<Value> {
        let mut commands = Vec::with_capacity(if self.tun.is_some() { 4 } else { 2 });
        for (protocol, set, prefixes) in
            [("ip", IPV4_SET, &self.ipv4), ("ip6", IPV6_SET, &self.ipv6)]
        {
            if prefixes.is_empty() {
                continue;
            }
            if let Some(tun) = &self.tun {
                commands.push(self.rule(vec![
                    lookup(protocol, "daddr", set),
                    compare(json!({"meta":{"key":"oif"}}), json!(tun.ifindex.get())),
                    compare(json!({"meta":{"key":"oifname"}}), json!(tun.ifname)),
                    json!({"accept":null}),
                ]));
            }
            commands.push(self.rule(vec![lookup(protocol, "daddr", set), json!({"drop":null})]));
        }
        commands
    }

    fn rule(&self, expr: Vec<Value>) -> Value {
        json!({"add":{"rule":{
            "family":"inet",
            "table":self.owner.table,
            "chain":OUTPUT_CHAIN,
            "expr":expr,
        }}})
    }
}

fn merged_ranges(prefixes: &[QuarantinePrefix]) -> Vec<AddressRange> {
    match prefixes.first().map(|prefix| prefix.address) {
        Some(IpAddr::V4(_)) => {
            let mut ranges = prefixes
                .iter()
                .filter_map(|prefix| match prefix.range() {
                    AddressRange::V4 { start, end } => Some((u32::from(start), u32::from(end))),
                    AddressRange::V6 { .. } => None,
                })
                .collect::<Vec<_>>();
            ranges.sort_unstable();
            let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
            for (start, end) in ranges {
                let merges_with_last = merged
                    .last()
                    .is_some_and(|last| start <= last.1.saturating_add(1));
                if merges_with_last {
                    if let Some(last) = merged.last_mut() {
                        last.1 = last.1.max(end);
                    }
                } else {
                    merged.push((start, end));
                }
            }
            merged
                .into_iter()
                .map(|(start, end)| AddressRange::V4 {
                    start: Ipv4Addr::from(start),
                    end: Ipv4Addr::from(end),
                })
                .collect()
        }
        Some(IpAddr::V6(_)) => {
            let mut ranges = prefixes
                .iter()
                .filter_map(|prefix| match prefix.range() {
                    AddressRange::V6 { start, end } => Some((u128::from(start), u128::from(end))),
                    AddressRange::V4 { .. } => None,
                })
                .collect::<Vec<_>>();
            ranges.sort_unstable();
            let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
            for (start, end) in ranges {
                let merges_with_last = merged
                    .last()
                    .is_some_and(|last| start <= last.1.saturating_add(1));
                if merges_with_last {
                    if let Some(last) = merged.last_mut() {
                        last.1 = last.1.max(end);
                    }
                } else {
                    merged.push((start, end));
                }
            }
            merged
                .into_iter()
                .map(|(start, end)| AddressRange::V6 {
                    start: Ipv6Addr::from(start),
                    end: Ipv6Addr::from(end),
                })
                .collect()
        }
        None => Vec::new(),
    }
}

fn verify_table(table: &Value, owner: &QuarantineOwner) -> bool {
    table.as_object().is_some_and(|object| {
        object
            .keys()
            .all(|key| matches!(key.as_str(), "family" | "name" | "comment" | "handle"))
            && table.get("family").and_then(Value::as_str) == Some("inet")
            && table.get("name").and_then(Value::as_str) == Some(owner.table.as_str())
            && table.get("comment").and_then(Value::as_str) == Some(owner.tag.as_str())
            && table
                .get("handle")
                .and_then(Value::as_u64)
                .is_some_and(|handle| handle != 0)
    })
}

fn verify_chain(chain: &Value, owner: &QuarantineOwner) -> bool {
    chain.as_object().is_some_and(|object| {
        object.keys().all(|key| {
            matches!(
                key.as_str(),
                "family" | "table" | "name" | "handle" | "type" | "hook" | "prio" | "policy"
            )
        }) && chain.get("family").and_then(Value::as_str) == Some("inet")
            && chain.get("table").and_then(Value::as_str) == Some(owner.table.as_str())
            && chain.get("name").and_then(Value::as_str) == Some(OUTPUT_CHAIN)
            && chain.get("type").and_then(Value::as_str) == Some("filter")
            && chain.get("hook").and_then(Value::as_str) == Some("output")
            && chain.get("prio").and_then(Value::as_i64) == Some(0)
            && chain.get("policy").and_then(Value::as_str) == Some("accept")
            && chain
                .get("handle")
                .and_then(Value::as_u64)
                .is_some_and(|handle| handle != 0)
    })
}

fn verify_rule_shape(
    rule: &Value,
    owner: &QuarantineOwner,
) -> Result<Vec<Value>, QuarantineVerifyError> {
    let object = rule
        .as_object()
        .ok_or(QuarantineVerifyError::RulesMismatch)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "family" | "table" | "chain" | "handle" | "expr"
        )
    }) || rule.get("family").and_then(Value::as_str) != Some("inet")
        || rule.get("table").and_then(Value::as_str) != Some(owner.table.as_str())
        || rule.get("chain").and_then(Value::as_str) != Some(OUTPUT_CHAIN)
        || rule
            .get("handle")
            .and_then(Value::as_u64)
            .is_none_or(|handle| handle == 0)
    {
        return Err(QuarantineVerifyError::RulesMismatch);
    }
    rule.get("expr")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(QuarantineVerifyError::RulesMismatch)
}

fn normalize_interface_indexes(rules: &mut [Vec<Value>], tun: &VerifiedTun) {
    let index = tun.ifindex.get().to_string();
    let mut verified_name = None;
    for expression in rules.iter_mut().flatten() {
        if expression
            .pointer("/match/left/meta/key")
            .and_then(Value::as_str)
            != Some("oif")
        {
            continue;
        }
        let right = &mut expression["match"]["right"];
        // nft может распечатать тот же индекс числом, строкой или именем.
        if right.as_u64() == Some(u64::from(tun.ifindex.get()))
            || (right.as_str() == Some(tun.ifname.as_str())
                && *verified_name.get_or_insert_with(|| interface_has_index(tun)))
        {
            *right = json!(index);
        }
    }
}

fn interface_has_index(tun: &VerifiedTun) -> bool {
    rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .and_then(|socket| rustix::net::netdevice::name_to_index(&socket, &tun.ifname))
    .is_ok_and(|index| index == tun.ifindex.get())
}

fn verify_set(
    set: &Value,
    expected: &ExpectedSet,
    owner: &QuarantineOwner,
) -> Result<Option<u64>, QuarantineVerifyError> {
    let object = set.as_object().ok_or(QuarantineVerifyError::SetsMismatch)?;
    // nft 1.0.9 опускает настройку объединения элементов при чтении JSON.
    // Установленные в ядре интервалы и их таймауты проверяются независимо.
    let auto_merge_matches = set
        .get("auto-merge")
        .is_none_or(|value| value.as_bool() == Some(true));
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "family"
                | "table"
                | "name"
                | "type"
                | "handle"
                | "flags"
                | "timeout"
                | "auto-merge"
                | "elem"
        )
    }) || set.get("family").and_then(Value::as_str) != Some("inet")
        || set.get("table").and_then(Value::as_str) != Some(owner.table.as_str())
        || set.get("name").and_then(Value::as_str) != Some(expected.name)
        || set.get("type").and_then(Value::as_str) != Some(expected.nft_type)
        || set
            .get("handle")
            .and_then(Value::as_u64)
            .is_none_or(|handle| handle == 0)
        || set.get("timeout").and_then(Value::as_u64) != Some(expected.timeout_ms / 1_000)
        || !auto_merge_matches
    {
        return Err(QuarantineVerifyError::SetsMismatch);
    }
    let mut flags = set
        .get("flags")
        .and_then(Value::as_array)
        .ok_or(QuarantineVerifyError::SetsMismatch)?
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or(QuarantineVerifyError::SetsMismatch)?;
    flags.sort_unstable();
    let mut expected_flags = expected.flags.to_vec();
    expected_flags.sort_unstable();
    if flags != expected_flags {
        return Err(QuarantineVerifyError::SetsMismatch);
    }

    let elements = match set.get("elem") {
        None => &[][..],
        Some(Value::Array(elements)) => elements.as_slice(),
        _ => return Err(QuarantineVerifyError::SetsMismatch),
    };
    if elements.len() > MAX_PREFIXES {
        return Err(QuarantineVerifyError::SetsMismatch);
    }
    let mut ranges = Vec::with_capacity(elements.len());
    let mut minimum_expiry = None;
    for element in elements {
        let wrapper = element
            .as_object()
            .filter(|object| object.len() == 1 && object.contains_key("elem"))
            .and_then(|_| element.get("elem"))
            .and_then(Value::as_object)
            .filter(|object| {
                object
                    .keys()
                    .all(|key| matches!(key.as_str(), "val" | "expires"))
            })
            .ok_or(QuarantineVerifyError::SetsMismatch)?;
        let value = wrapper
            .get("val")
            .ok_or(QuarantineVerifyError::SetsMismatch)?;
        let expires = wrapper
            .get("expires")
            .and_then(Value::as_u64)
            .ok_or(QuarantineVerifyError::SetsMismatch)?;
        if expires > expected.timeout_ms / 1_000 {
            return Err(QuarantineVerifyError::SetsMismatch);
        }
        ranges.push(parse_interval(value, expected.nft_type)?);
        let expires_ms = expires * 1_000;
        minimum_expiry =
            Some(minimum_expiry.map_or(expires_ms, |current: u64| current.min(expires_ms)));
    }
    if let Some(expiry) = minimum_expiry {
        let merged = merge_intervals(ranges)?;
        if merged != expected.intervals {
            return Err(QuarantineVerifyError::SetsMismatch);
        }
        Ok(Some(expiry))
    } else {
        Ok(None)
    }
}

fn parse_interval(value: &Value, nft_type: &str) -> Result<AddressRange, QuarantineVerifyError> {
    if let Some(prefix) = value.get("prefix") {
        if value
            .as_object()
            .map(|object| object.len() != 1)
            .unwrap_or(true)
        {
            return Err(QuarantineVerifyError::SetsMismatch);
        }
        if prefix
            .as_object()
            .map(|object| {
                object.len() != 2 || !object.contains_key("addr") || !object.contains_key("len")
            })
            .unwrap_or(true)
        {
            return Err(QuarantineVerifyError::SetsMismatch);
        }
        let address = prefix
            .get("addr")
            .and_then(Value::as_str)
            .and_then(|address| address.parse::<IpAddr>().ok())
            .ok_or(QuarantineVerifyError::SetsMismatch)?;
        let length = prefix
            .get("len")
            .and_then(Value::as_u64)
            .and_then(|length| u8::try_from(length).ok())
            .ok_or(QuarantineVerifyError::SetsMismatch)?;
        let prefix = QuarantinePrefix::new(address, length)
            .map_err(|_| QuarantineVerifyError::SetsMismatch)?;
        let family_matches = matches!(
            (nft_type, address),
            ("ipv4_addr", IpAddr::V4(_)) | ("ipv6_addr", IpAddr::V6(_))
        );
        if !family_matches {
            return Err(QuarantineVerifyError::SetsMismatch);
        }
        return Ok(prefix.range());
    }
    let range = value
        .as_object()
        .filter(|object| object.len() == 1 && object.contains_key("range"))
        .and_then(|_| value.get("range"))
        .and_then(Value::as_array)
        .filter(|range| range.len() == 2)
        .ok_or(QuarantineVerifyError::SetsMismatch)?;
    match nft_type {
        "ipv4_addr" => {
            let start = range[0]
                .as_str()
                .and_then(|address| address.parse::<Ipv4Addr>().ok())
                .ok_or(QuarantineVerifyError::SetsMismatch)?;
            let end = range[1]
                .as_str()
                .and_then(|address| address.parse::<Ipv4Addr>().ok())
                .ok_or(QuarantineVerifyError::SetsMismatch)?;
            if u32::from(start) > u32::from(end) {
                return Err(QuarantineVerifyError::SetsMismatch);
            }
            Ok(AddressRange::V4 { start, end })
        }
        "ipv6_addr" => {
            let start = range[0]
                .as_str()
                .and_then(|address| address.parse::<Ipv6Addr>().ok())
                .ok_or(QuarantineVerifyError::SetsMismatch)?;
            let end = range[1]
                .as_str()
                .and_then(|address| address.parse::<Ipv6Addr>().ok())
                .ok_or(QuarantineVerifyError::SetsMismatch)?;
            if u128::from(start) > u128::from(end) {
                return Err(QuarantineVerifyError::SetsMismatch);
            }
            Ok(AddressRange::V6 { start, end })
        }
        _ => Err(QuarantineVerifyError::SetsMismatch),
    }
}

fn merge_intervals(ranges: Vec<AddressRange>) -> Result<Vec<AddressRange>, QuarantineVerifyError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for range in ranges {
        match range {
            AddressRange::V4 { start, end } => v4.push((u32::from(start), u32::from(end))),
            AddressRange::V6 { start, end } => v6.push((u128::from(start), u128::from(end))),
        }
    }
    v4.sort_unstable();
    v6.sort_unstable();
    let mut merged = Vec::with_capacity(v4.len() + v6.len());
    for (start, end) in v4 {
        if let Some(AddressRange::V4 { end: previous, .. }) = merged.last_mut() {
            let previous_value = u32::from(*previous);
            if start <= previous_value.saturating_add(1) {
                *previous = Ipv4Addr::from(previous_value.max(end));
                continue;
            }
        }
        merged.push(AddressRange::V4 {
            start: Ipv4Addr::from(start),
            end: Ipv4Addr::from(end),
        });
    }
    let mut merged_v6: Vec<(u128, u128)> = Vec::with_capacity(v6.len());
    for (start, end) in v6 {
        if let Some((_, previous_end)) = merged_v6.last_mut() {
            if start <= previous_end.saturating_add(1) {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged_v6.push((start, end));
    }
    merged.extend(merged_v6.into_iter().map(|(start, end)| AddressRange::V6 {
        start: Ipv6Addr::from(start),
        end: Ipv6Addr::from(end),
    }));
    if merged
        .iter()
        .any(|range| matches!(range, AddressRange::V6 { .. }))
        && merged
            .iter()
            .any(|range| matches!(range, AddressRange::V4 { .. }))
    {
        return Err(QuarantineVerifyError::SetsMismatch);
    }
    Ok(merged)
}

fn lookup(protocol: &str, field: &str, set: &str) -> Value {
    json!({"match":{
        "op":"in",
        "left":{"payload":{"protocol":protocol,"field":field}},
        "right":format!("@{set}"),
    }})
}

fn lookup_readback(protocol: &str, field: &str, set: &str) -> Value {
    json!({"match":{
        "op":"==",
        "left":{"payload":{"protocol":protocol,"field":field}},
        "right":format!("@{set}"),
    }})
}

fn compare(left: Value, right: Value) -> Value {
    json!({"match":{"op":"==","left":left,"right":right}})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(address: &str, length: u8) -> QuarantinePrefix {
        QuarantinePrefix::new(address.parse().expect("Тестовый IP"), length)
            .expect("Тестовый префикс")
    }

    fn quarantine(tun: Option<VerifiedTun>) -> FakeQuarantine {
        FakeQuarantine::new(
            QuarantineOwner::new("yonik_q_fixture", "yonik:test:123").expect("Владелец"),
            Duration::from_millis(12_000),
            tun,
            [prefix("198.18.0.0", 15), prefix("2001:db8:1234::", 48)],
        )
        .expect("Карантин")
    }

    fn readback(policy: &FakeQuarantine, v4_expiry: Option<u64>, v6_expiry: Option<u64>) -> Value {
        let expected = policy.expected_readback();
        let mut items = vec![
            json!({"metainfo":{"version":"test","release_name":"test","json_schema_version":1}}),
            json!({"table":{"family":"inet","name":policy.owner.table,"handle":1,"comment":policy.owner.tag}}),
            json!({"chain":{
                "family":"inet","table":policy.owner.table,"name":"output","handle":2,
                "type":"filter","hook":"output","prio":0,"policy":"accept"
            }}),
        ];
        for (index, (set, prefixes, expires)) in [
            (&expected.sets[0], &policy.ipv4, v4_expiry),
            (&expected.sets[1], &policy.ipv6, v6_expiry),
        ]
        .into_iter()
        .enumerate()
        {
            let elements = expires
                .map(|expires| {
                    prefixes
                        .iter()
                        .map(|prefix| json!({"elem":{"val":prefix.nft_prefix(),"expires":expires}}))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            items.push(json!({"set":{
                "family":"inet","table":policy.owner.table,"name":set.name,"type":set.nft_type,
                "handle":index+3,"flags":["interval","timeout"],"timeout":policy.ttl_ms/1_000,
                "auto-merge":true,"elem":elements
            }}));
        }
        for (index, expression) in expected.rules.into_iter().enumerate() {
            items.push(json!({"rule":{
                "family":"inet","table":policy.owner.table,"chain":"output","handle":index+5,"expr":expression
            }}));
        }
        json!({"nftables":items})
    }

    #[test]
    fn accepts_nft_interface_name_only_when_the_current_index_matches() {
        let policy = quarantine(Some(VerifiedTun::new(1, "lo").expect("Тестовый интерфейс")));
        let mut data = readback(&policy, Some(9), Some(8));
        data["nftables"][5]["rule"]["expr"][1]["match"]["right"] = json!("lo");
        data["nftables"][7]["rule"]["expr"][1]["match"]["right"] = json!(1);
        assert_eq!(
            policy.verify_readback(data.to_string().as_bytes()),
            Ok(QuarantineStatus::Active(Duration::from_secs(8)))
        );

        let stale = quarantine(Some(VerifiedTun::new(99, "lo").expect("Устаревший индекс")));
        let mut data = readback(&stale, Some(9), Some(8));
        data["nftables"][5]["rule"]["expr"][1]["match"]["right"] = json!("lo");
        assert_eq!(
            stale.verify_readback(data.to_string().as_bytes()),
            Err(QuarantineVerifyError::RulesMismatch)
        );
    }

    #[test]
    fn emits_two_timed_interval_sets_and_drops_only_set_destinations() {
        let policy = quarantine(None);
        let commands = policy.install_commands();
        assert_eq!(commands[0]["add"]["table"]["comment"], "yonik:test:123");
        assert_eq!(commands[1]["add"]["chain"]["policy"], "accept");
        for (index, expected_type, expected_prefix) in [
            (2, "ipv4_addr", "198.18.0.0"),
            (3, "ipv6_addr", "2001:db8:1234::"),
        ] {
            let set = &commands[index]["add"]["set"];
            assert_eq!(set["type"], expected_type);
            assert_eq!(set["flags"], json!(["interval", "timeout"]));
            assert_eq!(set["timeout"], 12);
            assert_eq!(set["elem"][0]["elem"]["timeout"], 12);
            assert_eq!(
                set["elem"][0]["elem"]["val"]["prefix"]["addr"],
                expected_prefix
            );
        }
        let rules = &commands[4..];
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0]["add"]["rule"]["expr"][0]["match"]["right"],
            "@reserved_v4"
        );
        assert_eq!(rules[0]["add"]["rule"]["expr"][1], json!({"drop":null}));
        assert_eq!(
            rules[1]["add"]["rule"]["expr"][0]["match"]["right"],
            "@reserved_v6"
        );
        assert_eq!(rules[1]["add"]["rule"]["expr"][1], json!({"drop":null}));
        let expected = policy.expected_readback();
        assert_eq!(expected.sets[0].timeout_ms, 12_000);
        assert_eq!(expected.sets[0].flags, ["interval", "timeout"]);
        assert_eq!(expected.sets[0].intervals.len(), 1);
        assert_eq!(expected.rules.len(), 2);
        assert_eq!(expected.rules[0][0]["match"]["op"], "==");
        assert_eq!(expected.ttl_ms, 12_000);
    }

    #[test]
    fn tun_bypass_requires_both_verified_interface_identifiers_and_precedes_drop() {
        let tun = VerifiedTun::new(12, "yonik-tun0").expect("Проверенный TUN");
        let policy = quarantine(Some(tun));
        let commands = policy.install_commands();
        let rules = &commands[4..];
        assert_eq!(rules.len(), 4);
        let expr = rules[0]["add"]["rule"]["expr"]
            .as_array()
            .expect("Выражения");
        assert_eq!(expr[0]["match"]["right"], "@reserved_v4");
        assert_eq!(expr[1], compare(json!({"meta":{"key":"oif"}}), json!(12)));
        assert_eq!(
            expr[2],
            compare(json!({"meta":{"key":"oifname"}}), json!("yonik-tun0"))
        );
        assert_eq!(expr[3], json!({"accept":null}));
        assert_eq!(rules[1]["add"]["rule"]["expr"][1], json!({"drop":null}));
        assert_eq!(rules[2]["add"]["rule"]["expr"][3], json!({"accept":null}));
        assert_eq!(rules[3]["add"]["rule"]["expr"][1], json!({"drop":null}));
        let expected = policy.expected_readback();
        assert_eq!(expected.rules[0][1]["match"]["right"], "12");
        assert_eq!(expected.rules[0][2]["match"]["right"], "yonik-tun0");
    }

    #[test]
    fn validates_owner_prefix_tun_ttl_and_bounds() {
        assert!(QuarantineOwner::new("bad name", "yonik:owner").is_err());
        assert!(QuarantineOwner::new("table", "foreign").is_err());
        assert!(QuarantinePrefix::new(IpAddr::V4(Ipv4Addr::new(198, 18, 1, 0)), 15).is_err());
        assert!(QuarantinePrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).is_err());
        assert!(VerifiedTun::new(0, "tun0").is_err());
        assert!(VerifiedTun::new(2, "bad/name").is_err());

        let owner = QuarantineOwner::new("yonik_q", "yonik:owner").expect("Владелец");
        for ttl in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_millis(1_001),
            Duration::from_millis(120_001),
        ] {
            assert_eq!(
                FakeQuarantine::new(owner.clone(), ttl, None, [prefix("192.0.2.0", 24)]).err(),
                Some(QuarantineError::Ttl)
            );
        }
        assert_eq!(
            FakeQuarantine::new(owner, Duration::from_secs(1), None, []).err(),
            Some(QuarantineError::Empty)
        );
    }

    #[test]
    fn verifier_returns_minimum_remaining_ttl_and_requires_both_sets_to_expire() {
        let policy = quarantine(Some(VerifiedTun::new(12, "yonik-tun0").expect("TUN")));
        let active = readback(&policy, Some(9), Some(11));
        assert_eq!(
            policy.verify_readback(active.to_string().as_bytes()),
            Ok(QuarantineStatus::Active(Duration::from_secs(9)))
        );
        let expired = readback(&policy, None, None);
        assert_eq!(
            policy.verify_readback(expired.to_string().as_bytes()),
            Ok(QuarantineStatus::Expired)
        );
        let visible_zero_countdown = readback(&policy, Some(0), Some(0));
        assert_eq!(
            policy.verify_readback(visible_zero_countdown.to_string().as_bytes()),
            Ok(QuarantineStatus::Active(Duration::ZERO))
        );
        let partial = readback(&policy, None, Some(11));
        assert_eq!(
            policy.verify_readback(partial.to_string().as_bytes()),
            Err(QuarantineVerifyError::PartialExpiry)
        );
    }

    #[test]
    fn ubuntu_nftables_1_0_9_опускает_auto_merge_при_чтении_набора() {
        let policy = quarantine(None);
        let mut data = readback(&policy, Some(9), Some(8));
        for index in [3, 4] {
            data["nftables"][index]["set"]
                .as_object_mut()
                .expect("Набор")
                .remove("auto-merge");
        }
        assert_eq!(
            policy.verify_readback(data.to_string().as_bytes()),
            Ok(QuarantineStatus::Active(Duration::from_secs(8)))
        );

        let mut wrong_timeout = data.clone();
        wrong_timeout["nftables"][3]["set"]["timeout"] = json!(0);
        assert_eq!(
            policy.verify_readback(wrong_timeout.to_string().as_bytes()),
            Err(QuarantineVerifyError::SetsMismatch)
        );

        data["nftables"][3]["set"]["auto-merge"] = json!(false);
        assert_eq!(
            policy.verify_readback(data.to_string().as_bytes()),
            Err(QuarantineVerifyError::SetsMismatch)
        );
    }

    #[test]
    fn verifier_normalizes_prefix_ranges_and_rejects_owner_or_rule_drift() {
        let policy = quarantine(Some(VerifiedTun::new(12, "yonik-tun0").expect("TUN")));
        let mut range_form = readback(&policy, Some(9), Some(8));
        range_form["nftables"][3]["set"]["elem"][0]["elem"]["val"] =
            json!({"range":["198.18.0.0","198.19.255.255"]});
        range_form["nftables"][4]["set"]["elem"][0]["elem"]["val"] =
            json!({"range":["2001:db8:1234::","2001:db8:1234:ffff:ffff:ffff:ffff:ffff"]});
        assert_eq!(
            policy.verify_readback(range_form.to_string().as_bytes()),
            Ok(QuarantineStatus::Active(Duration::from_secs(8)))
        );

        let mut foreign_owner = readback(&policy, Some(9), Some(8));
        foreign_owner["nftables"][1]["table"]["comment"] = json!("yonik:other-owner");
        assert_eq!(
            policy.verify_readback(foreign_owner.to_string().as_bytes()),
            Err(QuarantineVerifyError::TableMismatch)
        );

        let mut changed_tun = readback(&policy, Some(9), Some(8));
        changed_tun["nftables"][5]["rule"]["expr"][1]["match"]["right"] = json!(99);
        assert_eq!(
            policy.verify_readback(changed_tun.to_string().as_bytes()),
            Err(QuarantineVerifyError::RulesMismatch)
        );
    }
}
