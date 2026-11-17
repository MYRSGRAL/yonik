use super::graph::*;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use yonik_import::NativeProfile;
type Error = ProfileCompileError;
type Result<T> = std::result::Result<T, Error>;

// Положительные схемы конкретных native объектов. Неизвестное поле не проходит
// даже внутри выключенного транспорта: оно может получить эффект после upgrade.
fn object<'a>(v: &'a Value, fields: &[(&str, char)]) -> Result<&'a Map<String, Value>> {
    let o = v.as_object().ok_or(Error::Schema)?;
    for (k, v) in o {
        let kind = fields
            .iter()
            .find(|(name, _)| *name == k)
            .ok_or(Error::UnsupportedField)?
            .1;
        let valid = match kind {
            's' => v.is_string(),
            'b' => v.is_boolean(),
            'n' => v.as_u64().is_some(),
            'i' => v.as_i64().is_some(),
            'a' => v.is_array(),
            'o' => v.is_object(),
            _ => false,
        };
        if !valid {
            return Err(Error::Schema);
        }
    }
    Ok(o)
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str).ok_or(Error::Schema)
}
fn array<'a>(v: &'a Value, key: &str) -> Result<&'a [Value]> {
    match v.get(key) {
        None => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        _ => Err(Error::Schema),
    }
}
fn strings(v: &Value, key: &str) -> Result<Vec<String>> {
    array(v, key)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Schema))
        .collect()
}
fn choice(v: &Value, key: &str, allowed: &[&str]) -> Result<()> {
    if let Some(x) = v.get(key) {
        if !allowed.contains(&x.as_str().ok_or(Error::Schema)?) {
            return Err(Error::Schema);
        }
    }
    Ok(())
}
fn endpoint(v: &Value, protocol: TransportProtocol) -> Result<PhysicalEndpoint> {
    let host = text(v, "address")?;
    let port = v["port"]
        .as_u64()
        .filter(|p| (1..=65535).contains(p))
        .ok_or(Error::Schema)? as u16;
    if host.is_empty()
        || host.len() > 253
        || host.chars().any(|c| {
            c.is_control() || c.is_whitespace() || matches!(c, '/' | '@' | '\\' | '%' | '#')
        })
    {
        return Err(Error::Schema);
    }
    if host.parse::<std::net::IpAddr>().is_err() && url::Host::parse(host).is_err() {
        return Err(Error::Schema);
    }
    Ok(PhysicalEndpoint {
        host: host.to_owned(),
        port,
        protocol,
    })
}
fn ports(s: &str) -> Result<()> {
    for part in s.split(',') {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let a = a.parse::<u16>().map_err(|_| Error::Schema)?;
        let b = b.parse::<u16>().map_err(|_| Error::Schema)?;
        if a == 0 || a > b {
            return Err(Error::Schema);
        }
    }
    Ok(())
}
pub(super) fn resource(s: &str, ip: bool) -> Result<Option<OwnedResourceRequirement>> {
    use crate::resource_bundle::ResourceKind;
    // Native IP parser снимает все ! до распознавания DAT; domain parser этого
    // не делает. Инвертированные geoip пока не имеют owned representation.
    let matcher = if ip { s.trim_start_matches('!') } else { s };
    let external = if ip {
        &["ext:", "ext-ip:"][..]
    } else {
        &["ext:", "ext-domain:", "ext-site:"][..]
    };
    if external.iter().any(|prefix| matcher.starts_with(prefix))
        || (ip && matcher != s && matcher.starts_with("geoip:"))
    {
        return Err(Error::ResourceRequired);
    }
    let (prefix, kind) = if ip {
        ("geoip:", ResourceKind::Cidrs)
    } else {
        ("geosite:", ResourceKind::Domains)
    };
    if let Some(category) = matcher.strip_prefix(prefix) {
        if category.is_empty()
            || category.len() > 128
            || !category
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@!".contains(&b))
        {
            return Err(Error::Schema);
        }
        return Ok(Some(OwnedResourceRequirement {
            kind,
            category: category.to_owned(),
        }));
    }
    Ok(None)
}
fn mask(v: &Value) -> Result<()> {
    object(v, &[("tcp", 'a'), ("quicParams", 'o')]).map_err(|_| Error::UnsupportedMask)?;
    for mask in array(v, "tcp")? {
        object(mask, &[("type", 's'), ("settings", 'o')])?;
        if text(mask, "type")? != "header-custom" {
            return Err(Error::UnsupportedMask);
        }
        let settings = &mask["settings"];
        object(settings, &[("clients", 'a'), ("servers", 'a')])?;
        for key in ["clients", "servers"] {
            for sequence in array(settings, key)? {
                for item in sequence.as_array().ok_or(Error::Schema)? {
                    object(item, &[("type", 's'), ("packet", 's'), ("rand", 'n')])?;
                    if let Some(rand) = item.get("rand") {
                        if rand.as_u64().is_none_or(|n| n > 4096) || item.get("packet").is_some() {
                            return Err(Error::UnsupportedMask);
                        }
                    } else {
                        choice(item, "type", &["str", "hex", "base64"])?;
                        let packet = text(item, "packet")?;
                        match text(item, "type")? {
                            "hex"
                                if packet.len() % 2 != 0
                                    || !packet.bytes().all(|b| b.is_ascii_hexdigit()) =>
                            {
                                return Err(Error::UnsupportedMask);
                            }
                            "base64" => {
                                use base64::Engine;
                                base64::engine::general_purpose::STANDARD
                                    .decode(packet)
                                    .map_err(|_| Error::UnsupportedMask)?;
                            }
                            _ => (),
                        }
                    }
                }
            }
        }
    }
    if let Some(q) = v.get("quicParams") {
        object(
            q,
            &[
                ("congestion", 's'),
                ("bbrProfile", 's'),
                ("disablePathMTUDiscovery", 'b'),
            ],
        )?;
        choice(q, "congestion", &["", "bbr", "reno"]).map_err(|_| Error::UnsupportedCongestion)?;
        choice(
            q,
            "bbrProfile",
            &["", "conservative", "standard", "aggressive"],
        )
        .map_err(|_| Error::UnsupportedCongestion)?;
    }
    Ok(())
}
fn stream(v: &Value) -> Result<TransportProtocol> {
    object(
        v,
        &[
            ("network", 's'),
            ("security", 's'),
            ("tcpSettings", 'o'),
            ("grpcSettings", 'o'),
            ("xhttpSettings", 'o'),
            ("hysteriaSettings", 'o'),
            ("tlsSettings", 'o'),
            ("realitySettings", 'o'),
            ("finalmask", 'o'),
        ],
    )?;
    let network = v.get("network").and_then(Value::as_str).unwrap_or("tcp");
    if !["tcp", "grpc", "xhttp", "hysteria"].contains(&network) {
        return Err(Error::UnsupportedTransport);
    }
    for (key, expected) in [
        ("tcpSettings", "tcp"),
        ("grpcSettings", "grpc"),
        ("xhttpSettings", "xhttp"),
        ("hysteriaSettings", "hysteria"),
    ] {
        if v.get(key).is_some() && network != expected {
            return Err(Error::UnsupportedTransport);
        }
    }
    if let Some(t) = v.get("tcpSettings") {
        object(t, &[])?;
    }
    if let Some(g) = v.get("grpcSettings") {
        object(
            g,
            &[
                ("serviceName", 's'),
                ("authority", 's'),
                ("multiMode", 'b'),
                ("mode", 'b'),
            ],
        )?;
        // Pinned GRPCConfig не имеет mode. false — распознанный no-op;
        // true выражает неподдержанный intent, а не multiMode.
        if g.get("mode") == Some(&Value::Bool(true)) {
            return Err(Error::UnsupportedField);
        }
    }
    if let Some(x) = v.get("xhttpSettings") {
        object(
            x,
            &[("mode", 's'), ("host", 's'), ("path", 's'), ("extra", 'o')],
        )?;
        choice(x, "mode", &["auto", "stream-up", "stream-one", "packet-up"])?;
        if let Some(extra) = x.get("extra") {
            object(extra, &[("xmux", 'o')])?;
            if let Some(m) = extra.get("xmux") {
                object(m, &[("maxConnections", 'n')])?;
                if m["maxConnections"]
                    .as_u64()
                    .is_none_or(|n| n == 0 || n > 256)
                {
                    return Err(Error::Budget);
                }
            }
        }
    }
    if let Some(h) = v.get("hysteriaSettings") {
        object(h, &[("version", 'n'), ("auth", 's')])?;
        if h["version"] != 2 || text(h, "auth")?.is_empty() {
            return Err(Error::Schema);
        }
    }
    let security = v.get("security").and_then(Value::as_str).unwrap_or("none");
    choice(v, "security", &["none", "tls", "reality"])?;
    if (v.get("tlsSettings").is_some() && security != "tls")
        || (v.get("realitySettings").is_some() && security != "reality")
    {
        return Err(Error::Schema);
    }
    if security == "tls" {
        let t = &v["tlsSettings"];
        object(
            t,
            &[
                ("serverName", 's'),
                ("enableSessionResumption", 'b'),
                ("fingerprint", 's'),
                ("alpn", 'a'),
                ("allowInsecure", 'b'),
            ],
        )?;
        if t.get("allowInsecure") == Some(&Value::Bool(true)) {
            return Err(Error::Schema);
        }
        strings(t, "alpn")?;
        choice(
            t,
            "fingerprint",
            &[
                "chrome",
                "firefox",
                "safari",
                "edge",
                "ios",
                "android",
                "random",
                "randomized",
            ],
        )?;
    }
    if security == "reality" {
        let r = &v["realitySettings"];
        object(
            r,
            &[
                ("serverName", 's'),
                ("publicKey", 's'),
                ("shortId", 's'),
                ("fingerprint", 's'),
            ],
        )?;
        use base64::Engine;
        choice(
            r,
            "fingerprint",
            &[
                "chrome",
                "firefox",
                "safari",
                "edge",
                "ios",
                "android",
                "random",
                "randomized",
            ],
        )?;
        if base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text(r, "publicKey")?)
            .map_err(|_| Error::Schema)?
            .len()
            != 32
        {
            return Err(Error::Schema);
        }
        if let Some(id) = r.get("shortId") {
            let s = id.as_str().ok_or(Error::Schema)?;
            if s.len() > 16 || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Schema);
            }
        }
    }
    if let Some(m) = v.get("finalmask") {
        mask(m)?;
    }
    let xhttp_h3 = network == "xhttp"
        && v["security"] == "tls"
        && v["tlsSettings"]["alpn"]
            .as_array()
            .is_some_and(|alpn| alpn.len() == 1 && alpn[0] == "h3");
    Ok(if network == "hysteria" || xhttp_h3 {
        TransportProtocol::Udp
    } else {
        TransportProtocol::Tcp
    })
}
pub(super) fn validate(profile: &NativeProfile) -> Result<ValidatedGraph> {
    let source = profile.source().expose();
    // P1 уже проверил duplicate keys/depth; закрытый NativeProfile не позволяет
    // обойти это условие. Дополнительный compiler budget проверяется до Value.
    if source.len() > 64 * 1024 {
        return Err(Error::Budget);
    }
    let mut value: Value = serde_json::from_str(source).map_err(|_| Error::Schema)?;
    object(
        &value,
        &[
            ("remarks", 's'),
            ("meta", 'o'),
            ("log", 'o'),
            ("inbounds", 'a'),
            ("outbounds", 'a'),
            ("routing", 'o'),
            ("dns", 'o'),
            ("observatory", 'o'),
        ],
    )?;
    if let Some(log) = value.get("log") {
        object(log, &[("loglevel", 's')])?;
    }
    let outbounds = array(&value, "outbounds")?;
    if outbounds.is_empty() || outbounds.len() > 256 {
        return Err(Error::Budget);
    }
    let mut tags = Vec::new();
    let mut seen = HashSet::new();
    let mut endpoints = HashMap::new();
    let mut packet_endpoints = HashMap::new();
    let mut chains = Vec::new();
    let mut direct = Vec::new();
    for o in outbounds {
        object(
            o,
            &[
                ("tag", 's'),
                ("protocol", 's'),
                ("settings", 'o'),
                ("streamSettings", 'o'),
                ("mux", 'o'),
                ("proxySettings", 'o'),
            ],
        )?;
        let tag = text(o, "tag")?;
        if tag.is_empty()
            || tag.len() > 128
            || tag.starts_with("yonik-owned-")
            || tag == "system-tun"
            || !seen.insert(tag.to_owned())
        {
            return Err(Error::Reference);
        }
        tags.push(tag.to_owned());
        let transport = if let Some(s) = o.get("streamSettings") {
            stream(s)?
        } else {
            TransportProtocol::Tcp
        };
        if let Some(m) = o.get("mux") {
            object(
                m,
                &[
                    ("enabled", 'b'),
                    ("concurrency", 'i'),
                    ("xudpConcurrency", 'n'),
                    ("xudpProxyUDP443", 's'),
                ],
            )?;
            choice(m, "xudpProxyUDP443", &["", "reject", "allow", "skip"])?;
            if m.get("concurrency")
                .and_then(Value::as_i64)
                .is_some_and(|n| !(-1..=1024).contains(&n))
                || m.get("xudpConcurrency")
                    .and_then(Value::as_u64)
                    .is_some_and(|n| n > 1024)
            {
                return Err(Error::Budget);
            }
        }
        if let Some(p) = o.get("proxySettings") {
            object(p, &[("tag", 's'), ("transportLayer", 'b')])?;
            if p.get("transportLayer") != Some(&Value::Bool(true)) {
                return Err(Error::UnsupportedTransport);
            }
            chains.push((tag.to_owned(), text(p, "tag")?.to_owned()));
        }
        let empty = serde_json::json!({});
        let s = o.get("settings").unwrap_or(&empty);
        match text(o, "protocol")? {
            "vless" => {
                object(s, &[("vnext", 'a')])?;
                let next = array(s, "vnext")?;
                if next.len() != 1 {
                    return Err(Error::Schema);
                }
                object(&next[0], &[("address", 's'), ("port", 'n'), ("users", 'a')])?;
                let users = array(&next[0], "users")?;
                if users.len() != 1 {
                    return Err(Error::Schema);
                }
                object(
                    &users[0],
                    &[("id", 's'), ("encryption", 's'), ("flow", 's')],
                )?;
                let id = text(&users[0], "id")?;
                if id.len() != 36
                    || !id.bytes().enumerate().all(|(i, b)| {
                        if [8, 13, 18, 23].contains(&i) {
                            b == b'-'
                        } else {
                            b.is_ascii_hexdigit()
                        }
                    })
                {
                    return Err(Error::Schema);
                }
                choice(&users[0], "encryption", &["none"])?;
                choice(&users[0], "flow", &["", "xtls-rprx-vision"])?;
                endpoints.insert(tag.to_owned(), endpoint(&next[0], transport)?);
            }
            "shadowsocks" => {
                object(s, &[("servers", 'a')])?;
                let servers = array(s, "servers")?;
                if servers.len() != 1 {
                    return Err(Error::Schema);
                }
                let s = &servers[0];
                object(
                    s,
                    &[
                        ("address", 's'),
                        ("port", 'n'),
                        ("password", 's'),
                        ("method", 's'),
                        ("uot", 'b'),
                        ("UoTVersion", 'n'),
                    ],
                )?;
                choice(
                    s,
                    "method",
                    &[
                        "aes-128-gcm",
                        "aes-256-gcm",
                        "chacha20-poly1305",
                        "2022-blake3-aes-128-gcm",
                        "2022-blake3-aes-256-gcm",
                    ],
                )?;
                if text(s, "password")?.is_empty() {
                    return Err(Error::Schema);
                }
                let method = text(s, "method")?;
                if s.get("uot") == Some(&Value::Bool(true)) {
                    return Err(Error::UnsupportedField);
                }
                if s.get("UoTVersion")
                    .and_then(Value::as_u64)
                    .is_some_and(|n| n > 2)
                {
                    return Err(Error::Schema);
                }
                if method.starts_with("2022-") {
                    use base64::Engine;
                    let password = text(s, "password")?;
                    if password.split(':').count() > 32 {
                        return Err(Error::Budget);
                    }
                    // Pinned ParsePSKList/ParseKey проверяет каждый PSK отдельно;
                    // ошибка base64 допускает raw key нужной длины.
                    for part in password.split(':') {
                        let key = base64::engine::general_purpose::STANDARD
                            .decode(part)
                            .unwrap_or_else(|_| part.as_bytes().to_vec());
                        if key.len() != if method.ends_with("128-gcm") { 16 } else { 32 } {
                            return Err(Error::Schema);
                        }
                    }
                }
                endpoints.insert(tag.to_owned(), endpoint(s, transport)?);
                // UDP target обходит configured TCP transport selector. При
                // UDP carrier обе ветки имеют один physical endpoint.
                if transport != TransportProtocol::Udp {
                    packet_endpoints.insert(tag.to_owned(), endpoint(s, TransportProtocol::Udp)?);
                }
            }
            "hysteria" => {
                object(s, &[("address", 's'), ("port", 'n'), ("version", 'n')])?;
                if s["version"] != 2
                    || transport != TransportProtocol::Udp
                    || o["streamSettings"]["security"] != "tls"
                {
                    return Err(Error::Schema);
                }
                endpoints.insert(tag.to_owned(), endpoint(s, transport)?);
            }
            "freedom" => {
                object(s, &[("domainStrategy", 's')])?;
                choice(
                    s,
                    "domainStrategy",
                    &["AsIs", "UseIP", "UseIPv4", "UseIPv6"],
                )?;
                direct.push(tag.to_owned());
            }
            "blackhole" | "dns" => {
                object(s, &[])?;
            }
            _ => return Err(Error::UnsupportedProtocol),
        }
    }
    let next: HashMap<_, _> = chains
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let mut complete = HashSet::new();
    for (start, target) in &chains {
        if !seen.contains(target) || !endpoints.contains_key(target) {
            return Err(Error::Reference);
        }
        let mut cursor = start.as_str();
        let mut path = HashSet::new();
        while let Some(next) = next.get(cursor) {
            if complete.contains(cursor) {
                break;
            }
            if !path.insert(cursor) {
                return Err(Error::Cycle);
            }
            cursor = next;
        }
        complete.extend(path);
    }
    let mut resources = Vec::new();
    let mut probe = None;
    let mut selectors = Vec::new();
    let mut balancers = HashSet::new();
    if let Some(r) = value.get("routing") {
        object(
            r,
            &[("domainStrategy", 's'), ("rules", 'a'), ("balancers", 'a')],
        )?;
        choice(r, "domainStrategy", &["AsIs", "IPIfNonMatch", "IPOnDemand"])?;
        for b in array(r, "balancers")? {
            object(
                b,
                &[
                    ("tag", 's'),
                    ("selector", 'a'),
                    ("strategy", 'o'),
                    ("fallbackTag", 's'),
                ],
            )?;
            let tag = text(b, "tag")?;
            if !balancers.insert(tag.to_owned()) || seen.contains(tag) {
                return Err(Error::Reference);
            }
            object(&b["strategy"], &[("type", 's')])?;
            choice(
                &b["strategy"],
                "type",
                &["random", "roundRobin", "leastPing"],
            )?;
            let prefixes = strings(b, "selector")?;
            if prefixes.is_empty() || prefixes.iter().any(String::is_empty) {
                return Err(Error::Reference);
            }
            let matched: Vec<_> = tags
                .iter()
                .filter(|tag| prefixes.iter().any(|p| tag.starts_with(p)))
                .cloned()
                .collect();
            if matched.is_empty() {
                return Err(Error::Reference);
            }
            if let Some(f) = b.get("fallbackTag") {
                if !seen.contains(f.as_str().ok_or(Error::Schema)?) {
                    return Err(Error::Reference);
                }
            }
            selectors.push((tag.to_owned(), matched));
        }
        if array(r, "rules")?.len() > 2048 {
            return Err(Error::Budget);
        }
        for rule in array(r, "rules")? {
            object(
                rule,
                &[
                    ("type", 's'),
                    ("inboundTag", 'a'),
                    ("outboundTag", 's'),
                    ("balancerTag", 's'),
                    ("domain", 'a'),
                    ("ip", 'a'),
                    ("port", 's'),
                    ("network", 's'),
                ],
            )?;
            choice(rule, "type", &["field"])?;
            if rule.get("outboundTag").is_some() == rule.get("balancerTag").is_some() {
                return Err(Error::Reference);
            }
            if let Some(t) = rule.get("outboundTag") {
                if !seen.contains(t.as_str().ok_or(Error::Schema)?) {
                    return Err(Error::Reference);
                }
            }
            if let Some(t) = rule.get("balancerTag") {
                if !balancers.contains(t.as_str().ok_or(Error::Schema)?) {
                    return Err(Error::Reference);
                }
            }
            for key in ["domain", "ip"] {
                for s in strings(rule, key)? {
                    if let Some(r) = resource(&s, key == "ip")? {
                        if !resources.contains(&r) {
                            resources.push(r);
                        }
                    }
                }
            }
            strings(rule, "inboundTag")?;
            if let Some(port) = rule.get("port").and_then(Value::as_str) {
                ports(port)?;
            }
            choice(rule, "network", &["tcp", "udp", "tcp,udp"])?;
        }
    }
    if let Some(obs) = value.get("observatory") {
        object(
            obs,
            &[
                ("probeURL", 's'),
                ("probeUrl", 's'),
                ("probeInterval", 's'),
                ("subjectSelector", 'a'),
                ("enableConcurrency", 'b'),
            ],
        )?;
        if obs.get("probeURL").is_some() && obs.get("probeUrl").is_some() {
            return Err(Error::Schema);
        }
        let url = obs
            .get("probeURL")
            .or_else(|| obs.get("probeUrl"))
            .and_then(Value::as_str)
            .ok_or(Error::Schema)?;
        let u = url::Url::parse(url).map_err(|_| Error::Schema)?;
        if !["http", "https"].contains(&u.scheme())
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.fragment().is_some()
        {
            return Err(Error::Schema);
        }
        let prefixes = strings(obs, "subjectSelector")?;
        if let Some(interval) = obs.get("probeInterval").and_then(Value::as_str) {
            let multiplier = if interval.ends_with('s') {
                1
            } else if interval.ends_with('m') {
                60
            } else if interval.ends_with('h') {
                3600
            } else {
                return Err(Error::Schema);
            };
            let number = interval
                .get(..interval.len().saturating_sub(1))
                .ok_or(Error::Schema)?
                .parse::<u64>()
                .map_err(|_| Error::Schema)?;
            if number
                .checked_mul(multiplier)
                .is_none_or(|n| !(1..=86400).contains(&n))
            {
                return Err(Error::Budget);
            }
        }
        if prefixes.is_empty()
            || prefixes.iter().any(String::is_empty)
            || !tags
                .iter()
                .any(|t| prefixes.iter().any(|p| t.starts_with(p)))
        {
            return Err(Error::Reference);
        }
        probe = Some(ProbeRequirement {
            url: url.to_owned(),
            subjects: tags
                .iter()
                .filter(|t| prefixes.iter().any(|p| t.starts_with(p)))
                .cloned()
                .collect(),
        });
    } else if value["routing"]["balancers"]
        .as_array()
        .is_some_and(|bs| bs.iter().any(|b| b["strategy"]["type"] == "leastPing"))
    {
        return Err(Error::Reference);
    }
    let (resolvers, system_resolvers) = if let Some(dns) = value.get("dns") {
        dns_validate(dns, &mut resources)?
    } else {
        // core/xray.go устанавливает localdns.New при отсутствии DNS app.
        (
            Vec::new(),
            vec![SystemResolverRequirement {
                dns_ingress: DnsIngressIdentity::Untagged,
            }],
        )
    };
    let mut ingresses = Vec::new();
    let mut ingress_tags = HashSet::new();
    if array(&value, "inbounds")?.len() > 16 {
        return Err(Error::Budget);
    }
    for i in array(&value, "inbounds")? {
        object(
            i,
            &[
                ("tag", 's'),
                ("port", 'n'),
                ("listen", 's'),
                ("protocol", 's'),
                ("settings", 'o'),
                ("sniffing", 'o'),
            ],
        )?;
        let protocol = match text(i, "protocol")? {
            "socks" => ProviderIngressProtocol::Socks,
            "http" => ProviderIngressProtocol::Http,
            _ => return Err(Error::UnsupportedProtocol),
        };
        let tag = text(i, "tag")?;
        if tag.is_empty()
            || tag.len() > 128
            || tag.starts_with("yonik-owned-")
            || tag == "system-tun"
            || !ingress_tags.insert(tag.to_owned())
        {
            return Err(Error::Reference);
        }
        ingresses.push(IngressRequirement {
            tag: tag.to_owned(),
            protocol,
        });
        if let Some(s) = i.get("settings") {
            object(s, &[("udp", 'b'), ("auth", 's')])?;
            choice(s, "auth", &["noauth"])?;
        }
        if let Some(s) = i.get("sniffing") {
            object(
                s,
                &[("enabled", 'b'), ("routeOnly", 'b'), ("destOverride", 'a')],
            )?;
            if strings(s, "destOverride")?
                .iter()
                .any(|s| !["http", "tls", "quic"].contains(&s.as_str()))
            {
                return Err(Error::Schema);
            }
        }
    }
    let chained: HashSet<_> = chains.iter().map(|(s, _)| s.as_str()).collect();
    let subject_endpoints: Vec<_> = tags
        .iter()
        .flat_map(|tag| {
            endpoints
                .get(tag)
                .into_iter()
                .chain(packet_endpoints.get(tag))
                .map(|endpoint| (tag.clone(), endpoint.clone()))
        })
        .collect();
    let physical_bootstrap = subject_endpoints
        .iter()
        .filter(|(tag, endpoint)| !chained.contains(tag.as_str()) && endpoint.requires_bootstrap())
        .map(|(tag, endpoint)| PhysicalFirstHopBootstrap {
            subject: tag.clone(),
            endpoint: endpoint.clone(),
        })
        .collect();
    let mut physical = Vec::new();
    let mut unique = HashSet::new();
    for tag in &tags {
        if !chained.contains(tag.as_str()) {
            if let Some(e) = endpoints.remove(tag) {
                if unique.insert(e.clone()) {
                    physical.push(e);
                }
            }
            if let Some(e) = packet_endpoints.remove(tag) {
                if unique.insert(e.clone()) {
                    physical.push(e);
                }
            }
        }
    }
    if resources.len() > 16 {
        return Err(Error::Budget);
    }
    // Metadata не попадает в runtime и не используется для authority.
    if let Some(o) = value.as_object_mut() {
        o.remove("remarks");
        o.remove("meta");
    }
    Ok(ValidatedGraph {
        value,
        egress: EgressPlan {
            physical,
            chains,
            direct,
            resolvers,
            subject_endpoints,
            system_resolvers,
            physical_bootstrap,
        },
        tags,
        selectors,
        resources,
        probe,
        ingresses,
    })
}
fn dns_validate(
    dns: &Value,
    resources: &mut Vec<OwnedResourceRequirement>,
) -> Result<(Vec<ResolverRequirement>, Vec<SystemResolverRequirement>)> {
    let mut resolvers = Vec::new();
    let mut system_resolvers = Vec::new();
    object(
        dns,
        &[
            ("hosts", 'o'),
            ("servers", 'a'),
            ("queryStrategy", 's'),
            ("disableFallbackIfMatch", 'b'),
            ("disableFallback", 'b'),
            ("disableCache", 'b'),
            ("tag", 's'),
        ],
    )?;
    choice(dns, "queryStrategy", &["UseIP", "UseIPv4", "UseIPv6"])?;
    if let Some(h) = dns.get("hosts") {
        for (key, v) in h.as_object().ok_or(Error::Schema)? {
            if resource(key, false)?.is_some() {
                return Err(Error::ResourceRequired);
            }
            if v.as_str().is_none() {
                return Err(Error::Schema);
            }
        }
    }
    let servers = array(dns, "servers")?;
    if servers.is_empty() {
        // DNS app с пустым clients также включает NewLocalDNSClient.
        system_resolvers.push(SystemResolverRequirement {
            dns_ingress: DnsIngressIdentity::from_tag(dns.get("tag").and_then(Value::as_str)),
        });
    }
    for server in servers {
        let address = if let Some(s) = server.as_str() {
            s
        } else {
            object(
                server,
                &[
                    ("address", 's'),
                    ("tag", 's'),
                    ("domains", 'a'),
                    ("skipFallback", 'b'),
                    ("finalQuery", 'b'),
                    ("port", 'n'),
                ],
            )?;
            for d in strings(server, "domains")? {
                if let Some(r) = resource(&d, false)? {
                    if !resources.contains(&r) {
                        resources.push(r);
                    }
                }
            }
            text(server, "address")?
        };
        let dns_ingress = DnsIngressIdentity::from_tag(
            server
                .get("tag")
                .or_else(|| dns.get("tag"))
                .and_then(Value::as_str),
        );
        if address.eq_ignore_ascii_case("localhost") {
            system_resolvers.push(SystemResolverRequirement { dns_ingress });
            continue;
        }
        let (host, port, protocol) = if address.parse::<std::net::IpAddr>().is_err() {
            let u = url::Url::parse(address).map_err(|_| Error::Schema)?;
            if !["https", "tcp"].contains(&u.scheme())
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
            {
                return Err(Error::Schema);
            }
            (
                u.host_str().ok_or(Error::Schema)?.to_owned(),
                u.port_or_known_default().unwrap_or(53),
                if u.scheme() == "quic" {
                    TransportProtocol::Udp
                } else {
                    TransportProtocol::Tcp
                },
            )
        } else {
            (
                address.to_owned(),
                server
                    .get("port")
                    .and_then(Value::as_u64)
                    .unwrap_or(53)
                    .try_into()
                    .map_err(|_| Error::Schema)?,
                TransportProtocol::Udp,
            )
        };
        if port == 0 {
            return Err(Error::Schema);
        }
        resolvers.push(ResolverRequirement {
            endpoint: PhysicalEndpoint {
                host,
                port,
                protocol,
            },
            dns_ingress,
        });
    }
    Ok((resolvers, system_resolvers))
}
