use crate::{
    Credentials, Endpoint, Field, IssueCode, MAX_ENTRY_BYTES, ParsedServer, Protocol, ReviewFlag,
    SecretText, Security, Transport, decode, json, model::RecordError,
};
use percent_encoding::percent_decode_str;
use std::{collections::BTreeMap, net::IpAddr};
use url::{Host, Url};

const QUERY_KEYS: &[&str] = &[
    "encryption",
    "flow",
    "type",
    "security",
    "sni",
    "fp",
    "pbk",
    "sid",
    "alpn",
    "host",
    "path",
    "mode",
    "serviceName",
    "authority",
    "headerType",
    "seed",
    "quicSecurity",
    "key",
    "spx",
    "packetEncoding",
    "allowInsecure",
];

fn component(text: &str, field: Field) -> Result<String, RecordError> {
    let bytes = text.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return Err((IssueCode::InvalidEncoding, field));
        }
    }
    percent_decode_str(text)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| (IssueCode::InvalidEncoding, field))
}

fn credential(text: &str) -> Result<SecretText, RecordError> {
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err((IssueCode::InvalidCredentials, Field::Credentials));
    }
    Ok(SecretText::new(text.to_owned()))
}

fn uuid(text: &str) -> Result<SecretText, RecordError> {
    let valid = text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if !valid {
        return Err((IssueCode::InvalidCredentials, Field::Credentials));
    }
    Ok(SecretText::new(text.to_ascii_lowercase()))
}

fn host(text: &str) -> Result<String, RecordError> {
    // JSON хранит IPv6 literal без URI-скобок.
    if let Ok(address) = text.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    match Host::parse(text).map_err(|_| (IssueCode::InvalidHost, Field::Endpoint))? {
        // Host::parse уже выполнил IDNA: считаем октеты ASCII label.
        Host::Domain(name)
            if !name.is_empty() && name.split('.').all(|label| label.len() <= 63) =>
        {
            Ok(name)
        }
        Host::Ipv4(address) => Ok(address.to_string()),
        Host::Ipv6(address) => Ok(address.to_string()),
        _ => Err((IssueCode::InvalidHost, Field::Endpoint)),
    }
}

fn url(text: &str) -> Result<Url, RecordError> {
    Url::parse(text).map_err(|e| match e {
        url::ParseError::InvalidPort => (IssueCode::InvalidPort, Field::Endpoint),
        _ => (IssueCode::MalformedUri, Field::Source),
    })
}

fn endpoint(value: &Url, default_port: Option<u16>) -> Result<Endpoint, RecordError> {
    let port = value
        .port()
        .or(default_port)
        .filter(|p| *p != 0)
        .ok_or((IssueCode::InvalidPort, Field::Endpoint))?;
    Ok(Endpoint {
        host: host(
            value
                .host_str()
                .ok_or((IssueCode::InvalidHost, Field::Endpoint))?,
        )?,
        port,
    })
}

fn query(value: &Url) -> Result<BTreeMap<String, String>, RecordError> {
    let _ = component(value.query().unwrap_or_default(), Field::Parameters)?;
    let mut parameters = BTreeMap::new();
    for (key, value) in value.query_pairs() {
        if parameters
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err((IssueCode::DuplicateParameter, Field::Parameters));
        }
    }
    Ok(parameters)
}

fn transport(text: &str, flags: &mut Vec<ReviewFlag>) -> Transport {
    match text {
        "" | "tcp" | "raw" => Transport::Tcp,
        "ws" => Transport::WebSocket,
        "grpc" => Transport::Grpc,
        "xhttp" => Transport::Xhttp,
        "h2" | "http" => Transport::Http2,
        "quic" => Transport::Quic,
        _ => {
            flags.push(ReviewFlag::UnsupportedTransport);
            Transport::Unsupported
        }
    }
}

fn security(text: &str, flags: &mut Vec<ReviewFlag>) -> Security {
    match text {
        "" | "none" => Security::None,
        "tls" => Security::Tls,
        "reality" => Security::Reality,
        _ => {
            flags.push(ReviewFlag::UnsupportedSecurity);
            Security::Unsupported
        }
    }
}

fn shadow_credentials(
    method: &str,
    password: &str,
    flags: &mut Vec<ReviewFlag>,
    encoded: bool,
) -> Result<Credentials, RecordError> {
    // SIP002 запрещает Base64URL userinfo для AEAD-2022.
    if encoded && method.starts_with("2022-") {
        return Err((IssueCode::InvalidCredentials, Field::Credentials));
    }
    let method = credential(method)?;
    if ![
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ]
    .contains(&method.expose())
    {
        flags.push(ReviewFlag::UnsupportedCipher);
    }
    Ok(Credentials::Shadowsocks {
        method,
        password: credential(password)?,
    })
}

pub(crate) fn parse(text: &str) -> Result<ParsedServer, RecordError> {
    if text.len() > MAX_ENTRY_BYTES {
        return Err((IssueCode::TooLarge, Field::Source));
    }
    if text.chars().any(char::is_control) {
        return Err((IssueCode::MalformedUri, Field::Source));
    }
    let (scheme, body) = text
        .split_once("://")
        .ok_or((IssueCode::MalformedUri, Field::Source))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme == "vmess" {
        return vmess(text, body);
    }
    if scheme == "hysteria2" {
        return hysteria2(text, body);
    }
    if scheme == "ss" && !body.split('#').next().unwrap_or_default().contains('@') {
        return legacy_ss(text, body);
    }
    let protocol = match scheme.as_str() {
        "vless" => Protocol::Vless,
        "trojan" => Protocol::Trojan,
        "ss" => Protocol::Shadowsocks,
        "http" | "https" => Protocol::HttpConnect,
        "socks" | "socks5" => Protocol::Socks5,
        _ => return Err((IssueCode::UnsupportedProtocol, Field::Source)),
    };
    let value = url(text)?;
    let default_port = match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        "socks" | "socks5" => Some(1080),
        _ => None,
    };
    let endpoint = endpoint(&value, default_port)?;
    let parameters = query(&value)?;
    let mut flags = Vec::new();
    if parameters
        .keys()
        .any(|key| !QUERY_KEYS.contains(&key.as_str()))
    {
        flags.push(ReviewFlag::UnknownParameter);
    }
    if parameters.contains_key("allowInsecure")
        && !matches!(
            parameters.get("allowInsecure").map(String::as_str),
            Some("0" | "false")
        )
    {
        flags.push(ReviewFlag::UnsafeOption);
    }
    if (!value.path().is_empty() && value.path() != "/")
        || parameters.get("encryption").is_some_and(|v| v != "none")
        || parameters
            .get("flow")
            .is_some_and(|v| !v.is_empty() && v != "xtls-rprx-vision")
    {
        flags.push(ReviewFlag::UnsupportedOption);
    }
    let network = transport(
        parameters.get("type").map(String::as_str).unwrap_or("tcp"),
        &mut flags,
    );
    let tls_default = if scheme == "trojan" || scheme == "https" {
        "tls"
    } else {
        "none"
    };
    let tls = security(
        parameters
            .get("security")
            .map(String::as_str)
            .unwrap_or(tls_default),
        &mut flags,
    );
    if protocol == Protocol::HttpConnect
        && tls
            != if scheme == "https" {
                Security::Tls
            } else {
                Security::None
            }
    {
        return Err((IssueCode::ConflictingParameter, Field::Parameters));
    }
    let username = component(value.username(), Field::Credentials)?;
    let password = value
        .password()
        .map(|p| component(p, Field::Credentials))
        .transpose()?;
    let credentials = match protocol {
        Protocol::Vless => {
            if password.is_some() {
                return Err((IssueCode::InvalidCredentials, Field::Credentials));
            }
            Credentials::Uuid(uuid(&username)?)
        }
        Protocol::Trojan => Credentials::Password(credential(
            &password
                .map(|p| format!("{username}:{p}"))
                .unwrap_or(username),
        )?),
        Protocol::Shadowsocks => {
            if let Some(password) = password {
                shadow_credentials(&username, &password, &mut flags, false)?
            } else {
                let decoded = decode::base64_text(&username)
                    .map_err(|_| (IssueCode::InvalidEncoding, Field::Credentials))?;
                let (method, password) = decoded
                    .split_once(':')
                    .ok_or((IssueCode::InvalidCredentials, Field::Credentials))?;
                shadow_credentials(method, password, &mut flags, true)?
            }
        }
        Protocol::HttpConnect | Protocol::Socks5 => {
            if username.is_empty() && password.is_none() {
                Credentials::None
            } else {
                let password = password.unwrap_or_default();
                if username
                    .chars()
                    .chain(password.chars())
                    .any(char::is_control)
                {
                    return Err((IssueCode::InvalidCredentials, Field::Credentials));
                }
                Credentials::UserPassword {
                    username: SecretText::new(username),
                    password: SecretText::new(password),
                }
            }
        }
        Protocol::Vmess | Protocol::Hysteria2 => {
            return Err((IssueCode::MalformedUri, Field::Source));
        }
    };
    Ok(ParsedServer {
        protocol,
        endpoint,
        credentials,
        transport: network,
        security: tls,
        parameters: SecretText::new(value.query().unwrap_or_default().to_owned()),
        source: SecretText::new(text.to_owned()),
        review_flags: flags,
    })
}

fn hysteria2(text: &str, body: &str) -> Result<ParsedServer, RecordError> {
    let value = url(text)?;
    let authority = body.split(['/', '?', '#']).next().unwrap_or_default();
    let (auth, _) = authority
        .rsplit_once('@')
        .filter(|(auth, _)| !auth.contains('@'))
        .ok_or((IssueCode::InvalidCredentials, Field::Credentials))?;
    // Весь userinfo передаётся как одна строка HTTP-заголовка Hysteria-Auth.
    let auth = component(auth, Field::Credentials)?;
    if auth.starts_with(' ') || auth.ends_with(' ') {
        return Err((IssueCode::InvalidCredentials, Field::Credentials));
    }
    let credentials = Credentials::Password(credential(&auth)?);
    let parameters = query(&value)?;
    let mut flags = Vec::new();
    if parameters.keys().any(|key| key != "sni") {
        flags.push(ReviewFlag::UnknownParameter);
    }
    if !matches!(value.path(), "" | "/") {
        flags.push(ReviewFlag::UnsupportedOption);
    }
    Ok(ParsedServer {
        protocol: Protocol::Hysteria2,
        endpoint: endpoint(&value, Some(443))?,
        credentials,
        transport: Transport::Quic,
        security: Security::Tls,
        parameters: SecretText::new(value.query().unwrap_or_default().to_owned()),
        source: SecretText::new(text.to_owned()),
        review_flags: flags,
    })
}

fn legacy_ss(source: &str, body: &str) -> Result<ParsedServer, RecordError> {
    let decoded = decode::base64_text(body.split('#').next().unwrap_or_default())
        .map_err(|_| (IssueCode::InvalidEncoding, Field::Payload))?;
    let (auth, address) = decoded
        .rsplit_once('@')
        .ok_or((IssueCode::InvalidCredentials, Field::Credentials))?;
    let (method, password) = auth
        .split_once(':')
        .ok_or((IssueCode::InvalidCredentials, Field::Credentials))?;
    let mut flags = Vec::new();
    let credentials = shadow_credentials(method, password, &mut flags, true)?;
    let value = url(&format!("ss://{address}"))?;
    if !value.username().is_empty()
        || value.password().is_some()
        || value.query().is_some()
        || value.fragment().is_some()
        || !value.path().is_empty()
    {
        return Err((IssueCode::MalformedUri, Field::Endpoint));
    }
    Ok(ParsedServer {
        protocol: Protocol::Shadowsocks,
        endpoint: endpoint(&value, None)?,
        credentials,
        transport: Transport::Tcp,
        security: Security::None,
        parameters: SecretText::new(String::new()),
        source: SecretText::new(source.to_owned()),
        review_flags: flags,
    })
}

fn vmess(source: &str, body: &str) -> Result<ParsedServer, RecordError> {
    let decoded = decode::base64_text(body.split('#').next().unwrap_or_default())
        .map_err(|_| (IssueCode::InvalidEncoding, Field::Payload))?;
    decode::json_depth(&decoded).map_err(|_| (IssueCode::InvalidJson, Field::Payload))?;
    let object =
        json::unique_object(&decoded).map_err(|_| (IssueCode::InvalidJson, Field::Payload))?;
    let address = object
        .get("add")
        .and_then(serde_json::Value::as_str)
        .ok_or((IssueCode::InvalidHost, Field::Endpoint))?;
    let port = object
        .get("port")
        .and_then(integer16)
        .filter(|p| *p != 0)
        .ok_or((IssueCode::InvalidPort, Field::Endpoint))?;
    let id = object
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or((IssueCode::InvalidCredentials, Field::Credentials))?;
    let mut flags = Vec::new();
    let known = [
        "v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni",
        "alpn", "fp",
    ];
    if object.keys().any(|key| !known.contains(&key.as_str())) {
        flags.push(ReviewFlag::UnknownParameter);
    }
    if let Some(value) = object.get("aid") {
        let aid = integer16(value).ok_or((IssueCode::InvalidCredentials, Field::Parameters))?;
        if aid != 0 {
            flags.push(ReviewFlag::LegacyOption);
        }
    }
    let network = transport(optional_text(&object, "net", "tcp")?, &mut flags);
    let tls = security(optional_text(&object, "tls", "none")?, &mut flags);
    Ok(ParsedServer {
        protocol: Protocol::Vmess,
        endpoint: Endpoint {
            host: host(address)?,
            port,
        },
        credentials: Credentials::Uuid(uuid(id)?),
        transport: network,
        security: tls,
        parameters: SecretText::new(decoded),
        source: SecretText::new(source.to_owned()),
        review_flags: flags,
    })
}

fn optional_text<'a>(
    object: &'a BTreeMap<String, serde_json::Value>,
    key: &str,
    default: &'a str,
) -> Result<&'a str, RecordError> {
    object.get(key).map_or(Ok(default), |value| {
        value
            .as_str()
            .ok_or((IssueCode::InvalidJson, Field::Parameters))
    })
}

fn integer16(value: &serde_json::Value) -> Option<u16> {
    if let Some(text) = value.as_str() {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    } else {
        value.as_u64().and_then(|number| u16::try_from(number).ok())
    }
}
