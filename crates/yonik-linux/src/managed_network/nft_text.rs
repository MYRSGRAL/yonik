//! Текстовая форма транзакции PublicBlock для nft без JSON socket cgroupv2.

use super::{MAX_OUTPUT, NftError};
use crate::managed_network::firewall::{
    CT_DIRECTION_REPLY, DHCP_CGROUP_PATH as DHCP_CGROUP, DHCP_RENEWAL_CHAIN as DHCP_CHAIN,
    DHCP_RENEWAL_SET as DHCP_SET, DHCPCD_CGROUP_PATH, DHCPCD_EGRESS_CHAIN, DHCPCD_ROUTE_CHAIN,
    DhcpRenewalKey, MAX_DHCP_RENEWALS, NM_DHCP_CGROUP_PATH,
};
use serde_json::Value;
use std::{
    fmt::Write as _,
    net::{IpAddr, Ipv4Addr},
};

const MAX_COMMANDS: usize = 1024;
const MAX_EXPRESSIONS: usize = 16;
const DHCP_SET_REFERENCE: &str = "@dhcp_renewal_leases";
const DHCP_KEY_TYPES: [&str; 4] = ["ipv4_addr", "ipv4_addr", "iface_index", "ifname"];
const DHCP_KEY_FIELDS: [&str; 4] = ["ip saddr", "ip daddr", "meta oif", "meta oifname"];

type Result<T> = std::result::Result<T, NftError>;
type ResolverCgroup = (u64, std::os::fd::RawFd);

pub(super) fn dhcp_renewal(
    table: &str,
    keys: &[DhcpRenewalKey],
    timeout_ms: u64,
) -> Result<Vec<u8>> {
    check_table_name(table)?;
    let mut script = format!("flush set inet {table} {DHCP_SET}\n");
    require(keys.len() <= MAX_DHCP_RENEWALS && (1..1000).contains(&timeout_ms))?;
    for key in keys {
        let key = dhcp_element_key(key)?;
        write_fmt(writeln!(
            script,
            "add element inet {table} {DHCP_SET} {{ {key} timeout {timeout_ms}ms }}"
        ))?;
    }
    Ok(script.into_bytes())
}

pub(super) fn delete_dhcp_renewals(table: &str, keys: &[&DhcpRenewalKey]) -> Result<Vec<u8>> {
    check_table_name(table)?;
    require(!keys.is_empty() && keys.len() <= MAX_DHCP_RENEWALS)?;
    let elements = keys
        .iter()
        .map(|key| dhcp_element_key(key))
        .collect::<Result<Vec<_>>>()?;
    Ok(format!(
        "delete element inet {table} {DHCP_SET} {{ {} }}\n",
        elements.join(", ")
    )
    .into_bytes())
}

fn dhcp_element_key(key: &DhcpRenewalKey) -> Result<String> {
    require(safe_ifname(&key.ifname))?;
    Ok(format!(
        "{} . {} . {} . \"{}\"",
        key.address, key.server, key.ifindex, key.ifname
    ))
}

pub(super) fn render(commands: &[Value], resolver: Option<ResolverCgroup>) -> Result<Vec<u8>> {
    if commands.is_empty() || commands.len() > MAX_COMMANDS {
        return Err(NftError::Invalid);
    }
    let mut script = String::new();
    for command in commands {
        render_command(&mut script, command, resolver)?;
        if script.len() > MAX_OUTPUT {
            return Err(NftError::Invalid);
        }
    }
    Ok(script.into_bytes())
}

fn render_command(
    script: &mut String,
    command: &Value,
    resolver: Option<ResolverCgroup>,
) -> Result<()> {
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
            require(text(family)? == "inet")?;
            let name = text(name)?;
            let (kind, kernel_hook, priority, verdict) = match name {
                "output" => ("filter", "output", 0, "drop"),
                DHCPCD_ROUTE_CHAIN => ("route", "output", -300, "accept"),
                DHCPCD_EGRESS_CHAIN => ("filter", "postrouting", 110, "accept"),
                _ => return Err(NftError::Invalid),
            };
            require(
                text(ty)? == kind
                    && text(hook)? == kernel_hook
                    && prio.as_i64() == Some(priority)
                    && text(policy)? == verdict,
            )?;
            let table = table_name(table)?;
            write_fmt(writeln!(
                script,
                "add chain inet {table} {name} {{ type {kind} hook {kernel_hook} priority {priority}; policy {verdict}; }}"
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
        ("add", "rule") => render_rule(script, fields, resolver),
        _ => Err(NftError::Invalid),
    }
}

fn render_rule(
    script: &mut String,
    fields: &Value,
    resolver: Option<ResolverCgroup>,
) -> Result<()> {
    let [family, table, chain, expr] = exact(fields, ["family", "table", "chain", "expr"])?;
    let chain = text(chain)?;
    require(
        text(family)? == "inet"
            && matches!(
                chain,
                "output" | DHCP_CHAIN | DHCPCD_ROUTE_CHAIN | DHCPCD_EGRESS_CHAIN
            ),
    )?;
    let table = table_name(table)?;
    let expr = expr.as_array().ok_or(NftError::Invalid)?;
    require(expr.len() <= MAX_EXPRESSIONS)?;
    if chain == DHCPCD_ROUTE_CHAIN {
        write_fmt(write!(script, "add rule inet {table} {chain}"))?;
        return render_dhcpcd_route(script, expr);
    }
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
    } else if chain == DHCPCD_EGRESS_CHAIN {
        let (header, extra) = matches.split_at_checked(6).ok_or(NftError::Invalid)?;
        require_renewal_matches(
            header.iter(),
            &[
                "meta nfproto",
                "ip saddr",
                "ip daddr",
                "udp sport",
                "udp dport",
                "meta mark",
            ],
        )?;
        let selectors: &[_] = if verdict == "accept" {
            &["ip dscp", "meta oif", "meta oifname", "concat"]
        } else {
            &[]
        };
        require_renewal_matches(extra.iter(), selectors)?;
        number(
            header[5].pointer("/match/right").ok_or(NftError::Invalid)?,
            1,
            u32::MAX.into(),
        )?;
    } else {
        require((action == "jump") == matches.is_empty())?;
    }
    let dot = chain == "output"
        && matches
            .iter()
            .any(|expr| expr.pointer("/match/left/socket").is_some());
    if dot {
        require(verdict == "accept")?;
        require_dot_selectors(matches)?;
    }
    write_fmt(write!(script, "add rule inet {table} {chain}"))?;
    for expr in matches {
        let ("match", fields) = single(expr)? else {
            return Err(NftError::Invalid);
        };
        if chain == "output" {
            let [_, left, _] = exact(fields, ["op", "left", "right"])?;
            let (kind, _) = single(left)?;
            require(kind != "concat" && (dot || kind != "socket"))?;
        }
        script.push(' ');
        render_match(script, fields, resolver)?;
    }
    write_fmt(writeln!(script, " {verdict}"))
}

fn match_fields(expr: &Value) -> Result<[&Value; 3]> {
    let ("match", fields) = single(expr)? else {
        return Err(NftError::Invalid);
    };
    exact(fields, ["op", "left", "right"])
}

fn require_renewal_matches<'a>(
    expressions: impl ExactSizeIterator<Item = &'a Value>,
    selectors: &[&str],
) -> Result<()> {
    require(expressions.len() == selectors.len())?;
    for (expr, &expected) in expressions.zip(selectors) {
        let [op, left, right] = match_fields(expr)?;
        require(text(op)? == "==")?;
        if matches!(expected, "socket" | "concat") {
            require(single(left)?.0 == expected)?;
        } else {
            require(selector(left)? == expected)?;
        }
        require(match expected {
            "meta nfproto" => right.as_str() == Some("ipv4"),
            "ip saddr" | "ip daddr" => right.is_string(),
            "meta skuid" => right.as_u64() == Some(0),
            "udp sport" => right.as_u64() == Some(68),
            "udp dport" => right.as_u64() == Some(67),
            "socket" => right.as_str() == Some(DHCPCD_CGROUP_PATH),
            _ => true,
        })?;
    }
    Ok(())
}

fn render_dhcpcd_route(script: &mut String, expressions: &[Value]) -> Result<()> {
    let [
        header @ ..,
        ciaddr,
        dscp,
        original_mark,
        socket,
        timed_key,
        source,
        escape_mark,
    ] = expressions
    else {
        return Err(NftError::Invalid);
    };
    require_renewal_matches(
        header.iter(),
        &[
            "meta nfproto",
            "meta oif",
            "ip saddr",
            "ip daddr",
            "meta skuid",
            "udp sport",
            "udp dport",
        ],
    )?;
    require_renewal_matches(
        [dscp, original_mark, socket, timed_key].into_iter(),
        &["ip dscp", "meta mark", "socket", "concat"],
    )?;

    let lease = mangle_value(source, "ip saddr")?;
    let lease_address = ipv4_address(lease)?;
    let escape_mark = number(mangle_value(escape_mark, "meta mark")?, 1, u32::MAX.into())?;
    require(
        original_mark
            .pointer("/match/right")
            .and_then(Value::as_u64)
            != Some(escape_mark),
    )?;

    let [op, left, right] = match_fields(ciaddr)?;
    let ("payload", payload) = single(left)? else {
        return Err(NftError::Invalid);
    };
    let [base, offset, len] = exact(payload, ["base", "offset", "len"])?;
    let ciaddr = u32::from(lease_address);
    require(
        text(op)? == "=="
            && text(base)? == "th"
            && offset.as_u64() == Some(160)
            && len.as_u64() == Some(32)
            && right.as_u64() == Some(ciaddr.into()),
    )?;

    let [_, left, right] = match_fields(timed_key)?;
    let (_, concat) = single(left)?;
    let Some([address, destination, ifindex, ifname]) = concat.as_array().map(Vec::as_slice) else {
        return Err(NftError::Invalid);
    };
    let ifname = text(ifname)?;
    require(
        address == lease
            && selector(destination)? == "ip daddr"
            && safe_ifname(ifname)
            && text(right)? == DHCP_SET_REFERENCE,
    )?;
    let ifindex = number(ifindex, 1, u32::MAX.into())?;
    require(header[1].pointer("/match/right").and_then(Value::as_u64) != Some(ifindex))?;

    for expr in header {
        script.push(' ');
        render_match(script, single(expr)?.1, None)?;
    }
    write_fmt(write!(script, " @th,160,32 {ciaddr}"))?;
    for expr in [dscp, original_mark, socket] {
        script.push(' ');
        render_match(script, single(expr)?.1, None)?;
    }
    write_fmt(writeln!(
        script,
        " {lease_address} . ip daddr . {ifindex} . \"{ifname}\" @{DHCP_SET} ip saddr set {lease_address} meta mark set {escape_mark}"
    ))
}

fn mangle_value<'a>(expr: &'a Value, expected: &str) -> Result<&'a Value> {
    let ("mangle", fields) = single(expr)? else {
        return Err(NftError::Invalid);
    };
    let [key, value] = exact(fields, ["key", "value"])?;
    require(selector(key)? == expected)?;
    Ok(value)
}

fn ipv4_address(value: &Value) -> Result<Ipv4Addr> {
    text(value)?.parse().map_err(|_| NftError::Invalid)
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
    let uid = expressions[5]
        .pointer("/match/right")
        .ok_or(NftError::Invalid)?;
    let root = number(uid, 0, u64::from(u32::MAX - 1))? == 0;
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
            "socket" => match right.as_str() {
                Some(NM_DHCP_CGROUP_PATH | DHCPCD_CGROUP_PATH) => root,
                Some(DHCP_CGROUP) => !root,
                _ => false,
            },
            _ => true,
        })?;
    }
    Ok(())
}

fn require_dot_selectors(expressions: &[Value]) -> Result<()> {
    let [family, destination, matches @ .., socket] = expressions else {
        return Err(NftError::Invalid);
    };
    let ("match", fields) = single(destination)? else {
        return Err(NftError::Invalid);
    };
    let [op, left, right] = exact(fields, ["op", "left", "right"])?;
    let protocol = match selector(left)? {
        "ip daddr" => "ipv4",
        "ip6 daddr" => "ipv6",
        _ => return Err(NftError::Invalid),
    };
    require(text(op)? == "==" && right.is_string())?;
    let ("match", fields) = single(family)? else {
        return Err(NftError::Invalid);
    };
    let [op, left, right] = exact(fields, ["op", "left", "right"])?;
    require(
        text(op)? == "==" && selector(left)? == "meta nfproto" && right.as_str() == Some(protocol),
    )?;
    let [_, _, transport, ..] = matches else {
        return Err(NftError::Invalid);
    };
    let port_selector = match transport.pointer("/match/right").and_then(Value::as_str) {
        Some("tcp") => "tcp dport",
        Some("udp") => "udp dport",
        _ => return Err(NftError::Invalid),
    };
    let expected = [
        "meta oif",
        "meta oifname",
        "meta l4proto",
        port_selector,
        "meta skuid",
        "meta mark",
    ];
    require(matches.len() == expected.len())?;
    for (expr, expected) in matches.iter().zip(expected) {
        let ("match", fields) = single(expr)? else {
            return Err(NftError::Invalid);
        };
        let [op, left, right] = exact(fields, ["op", "left", "right"])?;
        require(text(op)? == "==" && selector(left)? == expected)?;
        require(match expected {
            "meta skuid" => right
                .as_u64()
                .is_some_and(|uid| (1..u64::from(u32::MAX)).contains(&uid)),
            "meta mark" => right.as_u64() == Some(0),
            _ => true,
        })?;
    }
    let ("match", fields) = single(socket)? else {
        return Err(NftError::Invalid);
    };
    let [_, left, right] = exact(fields, ["op", "left", "right"])?;
    require(single(left)?.0 == "socket" && right.as_u64().is_some_and(|id| id != 0))
}

fn render_match(
    script: &mut String,
    fields: &Value,
    resolver: Option<ResolverCgroup>,
) -> Result<()> {
    let [op, left, right] = exact(fields, ["op", "left", "right"])?;
    let op = text(op)?;
    require(matches!(op, "==" | "!="))?;
    let (kind, data) = single(left)?;
    match kind {
        "socket" => {
            let [name, level] = exact(data, ["key", "level"])?;
            require(op == "==" && text(name)? == "cgroupv2")?;
            let level = number(level, 2, 2)?;
            return if let Some(path @ (DHCP_CGROUP | NM_DHCP_CGROUP_PATH | DHCPCD_CGROUP_PATH)) =
                right.as_str()
            {
                write_fmt(write!(script, "socket cgroupv2 level {level} \"{path}\""))
            } else {
                let id = number(right, 1, u64::MAX)?;
                let (expected, fd) = resolver.ok_or(NftError::Evidence)?;
                require(id == expected && fd >= 3)?;
                // Старый nft принимает только путь относительно /sys/fs/cgroup.
                // Этот путь открывает удерживаемый inode даже после замены каталога службы.
                write_fmt(write!(
                    script,
                    "socket cgroupv2 level {level} \"../../../proc/self/fd/{fd}\""
                ))
            };
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
        "ct direction" => {
            require(right.as_u64() == Some(CT_DIRECTION_REPLY.into()))?;
            script.push_str("reply");
            Ok(())
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
        "ct" => {
            let [key] = exact(data, ["key"])?;
            require(text(key)? == "direction")?;
            Ok("ct direction")
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

    #[test]
    fn разрешает_только_обратное_направление_conntrack() {
        let mut selector = json!({
            "op": "==",
            "left": {"ct": {"key": "direction"}},
            "right": super::CT_DIRECTION_REPLY
        });
        let mut rendered = String::new();
        super::render_match(&mut rendered, &selector, None).unwrap();
        assert_eq!(rendered, "ct direction reply");
        selector["right"] = json!(0);
        assert_eq!(
            super::render_match(&mut String::new(), &selector, None),
            Err(NftError::Invalid)
        );
    }

    #[test]
    fn deletion_targets_only_the_stale_dhcp_key() {
        let stale = super::DhcpRenewalKey {
            address: "192.0.2.20".parse().unwrap(),
            server: "192.0.2.1".parse().unwrap(),
            ifindex: std::num::NonZeroU32::new(9).unwrap(),
            ifname: "second-dhcp".into(),
        };
        assert_eq!(
            super::delete_dhcp_renewals(TABLE, &[&stale]).unwrap(),
            format!("delete element inet {TABLE} {DHCP_SET} {{ 192.0.2.20 . 192.0.2.1 . 9 . \"second-dhcp\" }}\n").into_bytes()
        );
        assert_eq!(
            super::delete_dhcp_renewals(TABLE, &[]),
            Err(NftError::Invalid)
        );
    }

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
    fn dhcpcd_requires_root_and_every_timed_renewal_selector() {
        let mut command = child_rule();
        let expressions = command["add"]["rule"]["expr"].as_array_mut().unwrap();
        expressions[5]["match"]["right"] = json!(0);
        expressions[10]["match"]["right"] = json!("system.slice/dhcpcd.service");
        let script =
            String::from_utf8(render(std::slice::from_ref(&command), None).unwrap()).unwrap();
        assert_eq!(
            script,
            format!(
                concat!(
                    "add rule inet {} dhcp_renewal meta nfproto ipv4 ip saddr 192.0.2.10 ",
                    "ip daddr 192.0.2.1 meta oif 7 meta oifname \"veth-lan.2\" meta skuid 0 ",
                    "udp sport 68 udp dport 67 ip dscp 32 meta mark 0 ",
                    "socket cgroupv2 level 2 \"system.slice/dhcpcd.service\" ",
                    "ip saddr . ip daddr . meta oif . meta oifname @dhcp_renewal_leases accept\n"
                ),
                TABLE
            )
        );

        let mut non_root = command.clone();
        non_root["add"]["rule"]["expr"][5]["match"]["right"] = json!(998);
        assert!(matches!(render(&[non_root], None), Err(NftError::Invalid)));
        let mut unknown_cgroup = command.clone();
        unknown_cgroup["add"]["rule"]["expr"][10]["match"]["right"] =
            json!("system.slice/dhcpcd@eth0.service");
        assert!(matches!(
            render(&[unknown_cgroup], None),
            Err(NftError::Invalid)
        ));
        command["add"]["rule"]["expr"]
            .as_array_mut()
            .unwrap()
            .remove(11);
        assert!(matches!(render(&[command], None), Err(NftError::Invalid)));
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
        let script = String::from_utf8(render(&commands, None).expect("Точная транзакция"))
            .expect("Текст nft");
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
            assert_eq!(render(&[command], None), Err(NftError::Invalid));
        }
        let mut child = child_rule();
        child["add"]["rule"]["expr"][10]["match"]["left"]["socket"]["level"] = json!(3);
        assert_eq!(render(&[child], None), Err(NftError::Invalid));
        let mut child = child_rule();
        child["add"]["rule"]["expr"][11]["match"]["right"] = json!("@different_set");
        assert_eq!(render(&[child], None), Err(NftError::Invalid));
        let mut child = child_rule();
        child["add"]["rule"]["expr"][6]["match"]["right"] = json!(69);
        assert_eq!(render(&[child], None), Err(NftError::Invalid));
        let mut child = child_rule();
        child["add"]["rule"]["expr"]
            .as_array_mut()
            .expect("Правило")
            .remove(11);
        assert_eq!(render(&[child], None), Err(NftError::Invalid));
    }
}
