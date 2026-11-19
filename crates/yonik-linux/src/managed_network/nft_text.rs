//! Текстовая форма транзакции PublicBlock для nft без JSON socket cgroupv2.

use super::{MAX_OUTPUT, NftError};
use crate::managed_network::firewall::{
    DHCP_CGROUP_PATH as DHCP_CGROUP, DHCP_RENEWAL_CHAIN as DHCP_CHAIN,
    DHCP_RENEWAL_SET as DHCP_SET, DhcpRenewalKey,
};
use serde_json::Value;
use std::{fmt::Write as _, net::IpAddr};

const MAX_COMMANDS: usize = 1024;
const MAX_EXPRESSIONS: usize = 16;
const DHCP_SET_REFERENCE: &str = "@dhcp_renewal_leases";
const DHCP_KEY_TYPES: [&str; 4] = ["ipv4_addr", "ipv4_addr", "iface_index", "ifname"];
const DHCP_KEY_FIELDS: [&str; 4] = ["ip saddr", "ip daddr", "meta oif", "meta oifname"];

type Result<T> = std::result::Result<T, NftError>;

pub(super) fn dhcp_renewal(
    table: &str,
    element: Option<(&DhcpRenewalKey, u64)>,
) -> Result<Vec<u8>> {
    check_table_name(table)?;
    let mut script = format!("flush set inet {table} {DHCP_SET}\n");
    if let Some((key, timeout_ms)) = element {
        require((1..1000).contains(&timeout_ms) && safe_ifname(&key.ifname))?;
        write_fmt(writeln!(
            script,
            "add element inet {table} {DHCP_SET} {{ {} . {} . {} . \"{}\" timeout {timeout_ms}ms }}",
            key.address, key.server, key.ifindex, key.ifname
        ))?;
    }
    Ok(script.into_bytes())
}

pub(super) fn render(commands: &[Value]) -> Result<Vec<u8>> {
    if commands.is_empty() || commands.len() > MAX_COMMANDS {
        return Err(NftError::Invalid);
    }
    let mut script = String::new();
    for command in commands {
        render_command(&mut script, command)?;
        if script.len() > MAX_OUTPUT {
            return Err(NftError::Invalid);
        }
    }
    Ok(script.into_bytes())
}

fn render_command(script: &mut String, command: &Value) -> Result<()> {
    let (action, body) = single(command)?;
    let (kind, fields) = single(body)?;
    match (action, kind) {
        ("create", "table") => {
            let [family, name, comment] = exact(fields, ["family", "name", "comment"])?;
            require(text(family)? == "inet")?;
            let name = table_name(name)?;
            let comment = text(comment)?;
            require(
                !comment.is_empty()
                    && comment.len() <= 128
                    && comment
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b":_-".contains(&b)),
            )?;
            write_fmt(writeln!(
                script,
                "create table inet {name} {{ comment \"{comment}\"; }}"
            ))
        }
        ("delete", "table") => {
            let [family, handle] = exact(fields, ["family", "handle"])?;
            require(text(family)? == "inet")?;
            let handle = number(handle, 1, u64::MAX)?;
            write_fmt(writeln!(script, "delete table inet handle {handle}"))
        }
        ("add", "chain") if fields.get("type").is_none() => {
            let [family, table, name] = exact(fields, ["family", "table", "name"])?;
            require(text(family)? == "inet" && text(name)? == DHCP_CHAIN)?;
            let table = table_name(table)?;
            write_fmt(writeln!(script, "add chain inet {table} {DHCP_CHAIN}"))
        }
        ("add", "chain") => {
            let [family, table, name, ty, hook, prio, policy] = exact(
                fields,
                ["family", "table", "name", "type", "hook", "prio", "policy"],
            )?;
            require(
                text(family)? == "inet"
                    && text(name)? == "output"
                    && text(ty)? == "filter"
                    && text(hook)? == "output"
                    && prio.as_i64() == Some(0)
                    && text(policy)? == "drop",
            )?;
            let table = table_name(table)?;
            write_fmt(writeln!(
                script,
                "add chain inet {table} output {{ type filter hook output priority 0; policy drop; }}"
            ))
        }
        ("add", "set") => {
            let [family, table, name, ty, flags, size] =
                exact(fields, ["family", "table", "name", "type", "flags", "size"])?;
            require(
                text(family)? == "inet"
                    && text(name)? == DHCP_SET
                    && string_array(ty, &DHCP_KEY_TYPES)
                    && string_array(flags, &["timeout"])
                    && size.as_u64() == Some(16),
            )?;
            let table = table_name(table)?;
            write_fmt(writeln!(
                script,
                "add set inet {table} {DHCP_SET} {{ type ipv4_addr . ipv4_addr . iface_index . ifname; flags timeout; size 16; }}"
            ))
        }
        ("add", "rule") => render_rule(script, fields),
        _ => Err(NftError::Invalid),
    }
}

fn render_rule(script: &mut String, fields: &Value) -> Result<()> {
    let [family, table, chain, expr] = exact(fields, ["family", "table", "chain", "expr"])?;
    let chain = text(chain)?;
    require(text(family)? == "inet" && matches!(chain, "output" | DHCP_CHAIN))?;
    let table = table_name(table)?;
    let expr = expr.as_array().ok_or(NftError::Invalid)?;
    require(expr.len() <= MAX_EXPRESSIONS)?;
    let (last, matches) = expr.split_last().ok_or(NftError::Invalid)?;
    let (action, value) = single(last)?;
    let verdict = match (action, value.as_null()) {
        ("accept", Some(())) => "accept",
        ("drop", Some(())) => "drop",
        ("jump", None) if chain == "output" => {
            let [target] = exact(value, ["target"])?;
            require(text(target)? == DHCP_CHAIN)?;
            "jump dhcp_renewal"
        }
        _ => return Err(NftError::Invalid),
    };
    if chain == DHCP_CHAIN {
        require(verdict == "accept")?;
        require_dhcp_selectors(matches)?;
    } else {
        require((action == "jump") == matches.is_empty())?;
    }
    write_fmt(write!(script, "add rule inet {table} {chain}"))?;
    for expr in matches {
        let ("match", fields) = single(expr)? else {
            return Err(NftError::Invalid);
        };
        if chain == "output" {
            let [_, left, _] = exact(fields, ["op", "left", "right"])?;
            let (kind, _) = single(left)?;
            require(!matches!(kind, "socket" | "concat"))?;
        }
        script.push(' ');
        render_match(script, fields)?;
    }
    write_fmt(writeln!(script, " {verdict}"))
}

fn require_dhcp_selectors(expressions: &[Value]) -> Result<()> {
    let required = [
        "meta nfproto",
        "ip saddr",
        "ip daddr",
        "meta oif",
        "meta oifname",
        "meta skuid",
        "udp sport",
        "udp dport",
        "ip dscp",
        "meta mark",
        "socket",
        "concat",
    ];
    require(expressions.len() == required.len())?;
    for (expr, expected) in expressions.iter().zip(required) {
        let ("match", fields) = single(expr)? else {
            return Err(NftError::Invalid);
        };
        let [op, left, right] = exact(fields, ["op", "left", "right"])?;
        require(text(op)? == "==")?;
        if matches!(expected, "socket" | "concat") {
            require(single(left)?.0 == expected)?;
        } else {
            require(selector(left)? == expected)?;
        }
        require(match expected {
            "meta nfproto" => right.as_str() == Some("ipv4"),
            "ip saddr" | "ip daddr" => right.is_string(),
            "udp sport" => right.as_u64() == Some(68),
            "udp dport" => right.as_u64() == Some(67),
            _ => true,
        })?;
    }
    Ok(())
}

fn render_match(script: &mut String, fields: &Value) -> Result<()> {
    let [op, left, right] = exact(fields, ["op", "left", "right"])?;
    let op = text(op)?;
    require(matches!(op, "==" | "!="))?;
    let (kind, data) = single(left)?;
    match kind {
        "socket" => {
            let [name, level] = exact(data, ["key", "level"])?;
            require(op == "==" && text(name)? == "cgroupv2" && text(right)? == DHCP_CGROUP)?;
            let level = number(level, 2, 2)?;
            return write_fmt(write!(
                script,
                "socket cgroupv2 level {level} \"{DHCP_CGROUP}\""
            ));
        }
        "concat" => {
            let concat = data.as_array().ok_or(NftError::Invalid)?;
            require(
                op == "=="
                    && text(right)? == DHCP_SET_REFERENCE
                    && concat.len() == DHCP_KEY_FIELDS.len(),
            )?;
            for (part, expected) in concat.iter().zip(DHCP_KEY_FIELDS) {
                require(selector(part)? == expected)?;
            }
            return write_fmt(write!(
                script,
                "ip saddr . ip daddr . meta oif . meta oifname @{DHCP_SET}"
            ));
        }
        _ => {}
    }
    let selector = selector(left)?;
    require(op == "==" || matches!(selector, "ip daddr" | "ip6 daddr"))?;
    if matches!(selector, "rt ip nexthop" | "rt ip6 nexthop") {
        require(right.is_string())?;
    }
    script.push_str(selector);
    script.push_str(if op == "!=" { " != " } else { " " });
    match selector {
        "ip saddr" | "ip daddr" | "rt ip nexthop" => render_address(script, right, true),
        "ip6 saddr" | "ip6 daddr" | "rt ip6 nexthop" => render_address(script, right, false),
        "meta oif" => write_fmt(write!(script, "{}", number(right, 1, u32::MAX.into())?)),
        "meta skuid" | "meta mark" => {
            write_fmt(write!(script, "{}", number(right, 0, u32::MAX.into())?))
        }
        "meta nfproto" => keyword(script, right, &["ipv4", "ipv6"]),
        "meta l4proto" => keyword(script, right, &["tcp", "udp", "ipv6-icmp"]),
        "meta oifname" => {
            let name = text(right)?;
            require(safe_ifname(name))?;
            write_fmt(write!(script, "\"{name}\""))
        }
        "udp sport" | "udp dport" | "tcp dport" => {
            write_fmt(write!(script, "{}", number(right, 1, u16::MAX.into())?))
        }
        "ip dscp" => write_fmt(write!(script, "{}", number(right, 0, 63)?)),
        "ip6 hoplimit" | "icmpv6 type" | "icmpv6 code" => {
            write_fmt(write!(script, "{}", number(right, 0, u8::MAX.into())?))
        }
        _ => Err(NftError::Invalid),
    }
}

fn selector(value: &Value) -> Result<&'static str> {
    let (kind, data) = single(value)?;
    match kind {
        "meta" => {
            let [key] = exact(data, ["key"])?;
            match text(key)? {
                "oif" => Ok("meta oif"),
                "oifname" => Ok("meta oifname"),
                "nfproto" => Ok("meta nfproto"),
                "l4proto" => Ok("meta l4proto"),
                "skuid" => Ok("meta skuid"),
                "mark" => Ok("meta mark"),
                _ => Err(NftError::Invalid),
            }
        }
        "payload" => {
            let [protocol, field] = exact(data, ["protocol", "field"])?;
            match (text(protocol)?, text(field)?) {
                ("ip", "saddr") => Ok("ip saddr"),
                ("ip", "daddr") => Ok("ip daddr"),
                ("ip", "dscp") => Ok("ip dscp"),
                ("ip6", "saddr") => Ok("ip6 saddr"),
                ("ip6", "daddr") => Ok("ip6 daddr"),
                ("ip6", "hoplimit") => Ok("ip6 hoplimit"),
                ("tcp", "dport") => Ok("tcp dport"),
                ("udp", "sport") => Ok("udp sport"),
                ("udp", "dport") => Ok("udp dport"),
                ("icmpv6", "type") => Ok("icmpv6 type"),
                ("icmpv6", "code") => Ok("icmpv6 code"),
                _ => Err(NftError::Invalid),
            }
        }
        "rt" => {
            let [key, family] = exact(data, ["key", "family"])?;
            match (text(key)?, text(family)?) {
                ("nexthop", "ip") => Ok("rt ip nexthop"),
                ("nexthop", "ip6") => Ok("rt ip6 nexthop"),
                _ => Err(NftError::Invalid),
            }
        }
        _ => Err(NftError::Invalid),
    }
}

fn render_address(script: &mut String, right: &Value, ipv4: bool) -> Result<()> {
    let address = |value| -> Result<IpAddr> {
        let address = text(value)?
            .parse::<IpAddr>()
            .map_err(|_| NftError::Invalid)?;
        require(address.is_ipv4() == ipv4)?;
        Ok(address)
    };
    if right.is_string() {
        return write_fmt(write!(script, "{}", address(right)?));
    }
    let ("prefix", prefix) = single(right)? else {
        return Err(NftError::Invalid);
    };
    let [ip, length] = exact(prefix, ["addr", "len"])?;
    let ip = address(ip)?;
    let length = number(length, 1, if ipv4 { 32 } else { 128 })?;
    write_fmt(write!(script, "{ip}/{length}"))
}

fn exact<'a, const N: usize>(value: &'a Value, keys: [&str; N]) -> Result<[&'a Value; N]> {
    let object = value.as_object().ok_or(NftError::Invalid)?;
    require(object.len() == N)?;
    let mut result = [value; N];
    for (slot, key) in result.iter_mut().zip(keys) {
        *slot = object.get(key).ok_or(NftError::Invalid)?;
    }
    Ok(result)
}

fn single(value: &Value) -> Result<(&str, &Value)> {
    let object = value.as_object().ok_or(NftError::Invalid)?;
    require(object.len() == 1)?;
    object
        .iter()
        .next()
        .map(|(key, value)| (key.as_str(), value))
        .ok_or(NftError::Invalid)
}

fn table_name(value: &Value) -> Result<&str> {
    let name = text(value)?;
    check_table_name(name)?;
    Ok(name)
}

fn check_table_name(name: &str) -> Result<()> {
    let id = name.strip_prefix("yonik_").ok_or(NftError::Invalid)?;
    require(
        id.len() == 16
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )
}

fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or(NftError::Invalid)
}

fn safe_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+@".contains(&byte))
}

fn keyword(script: &mut String, value: &Value, allowed: &[&str]) -> Result<()> {
    let value = text(value)?;
    require(allowed.contains(&value))?;
    script.push_str(value);
    Ok(())
}

fn string_array(value: &Value, expected: &[&str]) -> bool {
    value.as_array().is_some_and(|array| {
        array.len() == expected.len()
            && array
                .iter()
                .zip(expected)
                .all(|(elem, name)| elem.as_str() == Some(name))
    })
}

fn number(value: &Value, min: u64, max: u64) -> Result<u64> {
    value
        .as_u64()
        .filter(|number| (min..=max).contains(number))
        .ok_or(NftError::Invalid)
}

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(NftError::Invalid)
    }
}

fn write_fmt(result: std::fmt::Result) -> Result<()> {
    result.map_err(|_| NftError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::{DHCP_CGROUP, DHCP_KEY_TYPES, DHCP_SET, DHCP_SET_REFERENCE, NftError, render};
    use serde_json::{Value, json};

    const TABLE: &str = "yonik_0000000000000001";

    fn add(kind: &str, fields: Value) -> Value {
        json!({"add":{kind:fields}})
    }

    fn rule(chain: &str, expr: Vec<Value>) -> Value {
        add(
            "rule",
            json!({"family":"inet","table":TABLE,"chain":chain,"expr":expr}),
        )
    }

    fn select(left: Value, right: Value) -> Value {
        json!({"match":{"op":"==","left":left,"right":right}})
    }

    fn payload(protocol: &str, field: &str) -> Value {
        json!({"payload":{"protocol":protocol,"field":field}})
    }

    fn meta(key: &str) -> Value {
        json!({"meta":{"key":key}})
    }

    fn child_rule() -> Value {
        rule(
            "dhcp_renewal",
            vec![
                select(meta("nfproto"), json!("ipv4")),
                select(payload("ip", "saddr"), json!("192.0.2.10")),
                select(payload("ip", "daddr"), json!("192.0.2.1")),
                select(meta("oif"), json!(7)),
                select(meta("oifname"), json!("veth-lan.2")),
                select(meta("skuid"), json!(998)),
                select(payload("udp", "sport"), json!(68)),
                select(payload("udp", "dport"), json!(67)),
                select(payload("ip", "dscp"), json!(32)),
                select(meta("mark"), json!(0)),
                select(
                    json!({"socket":{"key":"cgroupv2","level":2}}),
                    json!(DHCP_CGROUP),
                ),
                select(
                    json!({"concat":[payload("ip","saddr"),payload("ip","daddr"),meta("oif"),meta("oifname")]}),
                    json!(DHCP_SET_REFERENCE),
                ),
                json!({"accept":null}),
            ],
        )
    }

    #[test]
    fn renders_atomic_policy_with_dhcp_child_and_existing_rule_types() {
        let commands = [
            json!({"delete":{"table":{"family":"inet","handle":4}}}),
            json!({"create":{"table":{"family":"inet","name":TABLE,"comment":"yonik:block:1:abcd"}}}),
            add(
                "set",
                json!({"family":"inet","table":TABLE,"name":DHCP_SET,"type":DHCP_KEY_TYPES,"flags":["timeout"],"size":16}),
            ),
            add(
                "chain",
                json!({"family":"inet","table":TABLE,"name":"dhcp_renewal"}),
            ),
            add(
                "chain",
                json!({"family":"inet","table":TABLE,"name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}),
            ),
            rule(
                "output",
                vec![select(meta("oif"), json!(1)), json!({"accept":null})],
            ),
            rule(
                "output",
                vec![
                    select(
                        payload("ip6", "daddr"),
                        json!({"prefix":{"addr":"2001:db8::","len":32}}),
                    ),
                    json!({"drop":null}),
                ],
            ),
            rule("output", vec![json!({"jump":{"target":"dhcp_renewal"}})]),
            rule(
                "output",
                vec![
                    select(
                        json!({"rt":{"key":"nexthop","family":"ip"}}),
                        json!("192.0.2.1"),
                    ),
                    select(meta("oifname"), json!("veth-lan.2")),
                    json!({"match":{"op":"!=","left":payload("ip","daddr"),"right":"192.0.2.1"}}),
                    json!({"accept":null}),
                ],
            ),
            child_rule(),
        ];
        let script =
            String::from_utf8(render(&commands).expect("Точная транзакция")).expect("Текст nft");
        assert_eq!(
            script,
            format!(
                concat!(
                    "delete table inet handle 4\n",
                    "create table inet {} {{ comment \"yonik:block:1:abcd\"; }}\n",
                    "add set inet {} dhcp_renewal_leases {{ type ipv4_addr . ipv4_addr . iface_index . ifname; flags timeout; size 16; }}\n",
                    "add chain inet {} dhcp_renewal\n",
                    "add chain inet {} output {{ type filter hook output priority 0; policy drop; }}\n",
                    "add rule inet {} output meta oif 1 accept\n",
                    "add rule inet {} output ip6 daddr 2001:db8::/32 drop\n",
                    "add rule inet {} output jump dhcp_renewal\n",
                    "add rule inet {} output rt ip nexthop 192.0.2.1 meta oifname \"veth-lan.2\" ip daddr != 192.0.2.1 accept\n",
                    "add rule inet {} dhcp_renewal meta nfproto ipv4 ip saddr 192.0.2.10 ip daddr 192.0.2.1 meta oif 7 meta oifname \"veth-lan.2\" meta skuid 998 udp sport 68 udp dport 67 ip dscp 32 meta mark 0 socket cgroupv2 level 2 \"system.slice/systemd-networkd.service\" ip saddr . ip daddr . meta oif . meta oifname @dhcp_renewal_leases accept\n",
                ),
                TABLE, TABLE, TABLE, TABLE, TABLE, TABLE, TABLE, TABLE, TABLE
            )
        );
    }

    #[test]
    fn rejects_bad_shapes_and_tokens() {
        let cases = [
            json!({"create":{"table":{"family":"inet","name":TABLE,"comment":"tag\"; }\nflush ruleset"}}}),
            json!({"create":{"table":{"family":"inet","name":"yonik_0000000000000001\nflush ruleset","comment":"tag"}}}),
            add(
                "set",
                json!({"family":"inet","table":TABLE,"name":DHCP_SET,"type":DHCP_KEY_TYPES,"flags":["timeout"],"size":16,"elem":[]}),
            ),
            rule(
                "output",
                vec![
                    select(meta("oifname"), json!("lan*")),
                    json!({"accept":null}),
                ],
            ),
            rule(
                "output",
                vec![
                    select(payload("ip", "daddr"), json!("::1")),
                    json!({"drop":null}),
                ],
            ),
            rule(
                "output",
                vec![
                    select(meta("oif"), json!(4294967296u64)),
                    json!({"accept":null}),
                ],
            ),
            rule("output", vec![json!({"jump":{"target":"other"}})]),
        ];
        for command in cases {
            assert_eq!(render(&[command]), Err(NftError::Invalid));
        }
        let mut child = child_rule();
        child["add"]["rule"]["expr"][10]["match"]["left"]["socket"]["level"] = json!(3);
        assert_eq!(render(&[child]), Err(NftError::Invalid));
        let mut child = child_rule();
        child["add"]["rule"]["expr"][11]["match"]["right"] = json!("@different_set");
        assert_eq!(render(&[child]), Err(NftError::Invalid));
        let mut child = child_rule();
        child["add"]["rule"]["expr"][6]["match"]["right"] = json!(69);
        assert_eq!(render(&[child]), Err(NftError::Invalid));
        let mut child = child_rule();
        child["add"]["rule"]["expr"]
            .as_array_mut()
            .expect("Правило")
            .remove(11);
        assert_eq!(render(&[child]), Err(NftError::Invalid));
    }
}
