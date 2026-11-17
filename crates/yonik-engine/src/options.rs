use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use yonik_import::{ParsedServer, Protocol, ReviewFlag, Security, Transport};

use crate::{CompileError, Engine};

#[derive(Default)]
pub(crate) struct Options {
    pub sni: String,
    pub fingerprint: String,
    pub alpn: Vec<String>,
    pub public_key: String,
    pub short_id: String,
    pub flow: String,
    pub host: String,
    pub path: String,
    pub mode: String,
    pub service: String,
    pub authority: String,
    pub spider_path: String,
    pub cipher: String,
}

type Parameters = BTreeMap<String, String>;

fn take(parameters: &mut Parameters, key: &str) -> String {
    parameters.remove(key).unwrap_or_default()
}

fn vmess_parameters(server: &ParsedServer) -> Result<Parameters, CompileError> {
    let value: Value = serde_json::from_str(server.parameters().expose())
        .map_err(|_| CompileError::InvalidParameter)?;
    let Value::Object(mut object) = value else {
        return Err(CompileError::InvalidParameter);
    };
    // Эти поля уже проверены импортом и представлены типизированными значениями.
    for key in ["ps", "add", "port", "id"] {
        object.remove(key);
    }
    if let Some(version) = object.remove("v") {
        if version != "2" && version != 2 {
            return Err(CompileError::UnsupportedOption);
        }
    }
    if let Some(aid) = object.remove("aid") {
        if aid != "0" && aid != 0 {
            return Err(CompileError::UnsupportedOption);
        }
    }
    let mut parameters = Parameters::new();
    for (key, value) in object {
        let text = value.as_str().ok_or(CompileError::InvalidParameter)?;
        let key = match key.as_str() {
            "net" => "type",
            "tls" => "security",
            "type" => "headerType",
            other => other,
        };
        if text.is_empty() {
            continue;
        }
        let key = if key == "path" && server.transport() == Transport::Grpc {
            "serviceName"
        } else {
            key
        };
        parameters.insert(key.to_owned(), text.to_owned());
    }
    Ok(parameters)
}

pub(crate) fn validate(server: &ParsedServer, engine: Engine) -> Result<Options, CompileError> {
    if server.review_flags().iter().any(|flag| {
        matches!(
            flag,
            ReviewFlag::UnknownParameter
                | ReviewFlag::UnsafeOption
                | ReviewFlag::UnsupportedOption
                | ReviewFlag::UnsupportedCipher
                | ReviewFlag::LegacyOption
        )
    }) {
        return Err(CompileError::UnsupportedOption);
    }
    let protocol = server.protocol();
    let transport = server.transport();
    let security = server.security();
    if !(matches!(
        transport,
        Transport::Tcp | Transport::WebSocket | Transport::Grpc
    ) || transport == Transport::Xhttp && engine == Engine::Xray)
    {
        return Err(CompileError::UnsupportedTransport);
    }
    if security == Security::Unsupported {
        return Err(CompileError::UnsupportedSecurity);
    }
    if !matches!(
        protocol,
        Protocol::Vless | Protocol::Vmess | Protocol::Trojan
    ) && transport != Transport::Tcp
    {
        return Err(CompileError::UnsupportedTransport);
    }
    if matches!(protocol, Protocol::Shadowsocks | Protocol::Socks5) && security != Security::None {
        return Err(CompileError::UnsupportedSecurity);
    }
    if protocol == Protocol::Trojan && security != Security::Tls {
        return Err(CompileError::UnsupportedSecurity);
    }
    // Xray 26.10.31 разрешает REALITY для RAW, gRPC и XHTTP.
    if security == Security::Reality
        && !(protocol == Protocol::Vless
            && (transport == Transport::Tcp
                || engine == Engine::Xray
                    && matches!(transport, Transport::Grpc | Transport::Xhttp)))
    {
        return Err(CompileError::UnsupportedSecurity);
    }
    // Xray 26.10.31 не допускает plaintext VLESS к публичному серверу.
    // Имена без TLS пока консервативно отклоняем: DNS не входит в компилятор.
    if engine == Engine::Xray && protocol == Protocol::Vless && security == Security::None {
        let private = server
            .endpoint()
            .host()
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| match ip.to_canonical() {
                std::net::IpAddr::V4(ip) => {
                    ip.is_loopback() || ip.is_private() || ip.is_link_local()
                }
                std::net::IpAddr::V6(ip) => {
                    ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
                }
            });
        if !private {
            return Err(CompileError::UnsupportedSecurity);
        }
    }
    let mut parameters = if protocol == Protocol::Vmess {
        vmess_parameters(server)?
    } else {
        url::form_urlencoded::parse(server.parameters().expose().as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    };
    // Значения этих двух полей уже определили enum в импорте.
    parameters.remove("type");
    parameters.remove("security");
    if let Some(insecure) = parameters.remove("allowInsecure") {
        if !matches!(insecure.as_str(), "false" | "0") {
            return Err(CompileError::UnsupportedOption);
        }
    }
    let encryption = take(&mut parameters, "encryption");
    if !encryption.is_empty() && (protocol != Protocol::Vless || encryption != "none") {
        return Err(CompileError::UnsupportedOption);
    }
    let header = take(&mut parameters, "headerType");
    if !matches!(header.as_str(), "" | "none") {
        return Err(CompileError::UnsupportedOption);
    }
    let mut options = Options {
        flow: take(&mut parameters, "flow"),
        ..Options::default()
    };
    if !options.flow.is_empty()
        && (options.flow != "xtls-rprx-vision"
            || protocol != Protocol::Vless
            || transport != Transport::Tcp
            || security == Security::None)
    {
        return Err(CompileError::UnsupportedOption);
    }
    if let Some(packet_encoding) = parameters.remove("packetEncoding") {
        // VLESS outbound в Xray 26.10.31 сам включает XUDP для UDP с Vision.
        // Оставляем нативную политику Vision для UDP/443 и не включаем отдельный mux.
        if packet_encoding != "xudp"
            || engine != Engine::Xray
            || security != Security::Reality
            || options.flow != "xtls-rprx-vision"
        {
            return Err(CompileError::UnsupportedOption);
        }
    }
    if security != Security::None {
        options.sni = take(&mut parameters, "sni");
        if options.sni.is_empty() {
            options.sni = server.endpoint().host().to_owned();
        }
        if options.sni.len() > 253
            || options
                .sni
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || options.sni.contains(['/', '\\', '@', '#', '?'])
        {
            return Err(CompileError::InvalidParameter);
        }
        options.fingerprint = take(&mut parameters, "fp");
        if !matches!(
            options.fingerprint.as_str(),
            "" | "chrome" | "firefox" | "safari" | "ios" | "android" | "edge"
        ) {
            return Err(CompileError::UnsupportedOption);
        }
        if security == Security::Tls {
            let alpn = take(&mut parameters, "alpn");
            if !alpn.is_empty() {
                for item in alpn.split(',') {
                    if item.is_empty()
                        || item.len() > 255
                        || !item.bytes().all(|b| b.is_ascii_graphic())
                    {
                        return Err(CompileError::InvalidParameter);
                    }
                    options.alpn.push(item.to_owned());
                }
            }
        } else {
            options.public_key = take(&mut parameters, "pbk");
            if URL_SAFE_NO_PAD
                .decode(&options.public_key)
                .map_or(true, |key| key.len() != 32)
                || options.fingerprint.is_empty()
            {
                return Err(CompileError::InvalidParameter);
            }
            options.spider_path = take(&mut parameters, "spx");
            if !options.spider_path.is_empty() && options.spider_path != "/" {
                if !options.spider_path.starts_with('/')
                    || options.spider_path.starts_with("//")
                    || options.spider_path.contains(['\\', '#'])
                    || options
                        .spider_path
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace())
                {
                    return Err(CompileError::InvalidParameter);
                }
                if engine == Engine::SingBox {
                    return Err(CompileError::UnsupportedOption);
                }
            }
            options.short_id = take(&mut parameters, "sid");
            if options.short_id.len() > 16
                || options.short_id.len() % 2 != 0
                || !options.short_id.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(CompileError::InvalidParameter);
            }
        }
    }
    match transport {
        Transport::WebSocket | Transport::Xhttp => {
            options.host = take(&mut parameters, "host");
            options.path = take(&mut parameters, "path");
            if options.path.is_empty() {
                options.path = "/".into();
            }
            if !options.path.starts_with('/')
                || options.path.chars().any(char::is_control)
                || options
                    .host
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(CompileError::InvalidParameter);
            }
            // sing-box трактует ?ed как ранний payload, Xray — как часть URI.
            if transport == Transport::WebSocket && options.path.contains('?') {
                return Err(CompileError::UnsupportedOption);
            }
            if transport == Transport::Xhttp {
                options.mode = take(&mut parameters, "mode");
                if options.mode.is_empty() {
                    options.mode = "auto".into();
                }
                if !matches!(
                    options.mode.as_str(),
                    "auto" | "packet-up" | "stream-up" | "stream-one"
                ) {
                    return Err(CompileError::UnsupportedOption);
                }
            }
        }
        Transport::Grpc => {
            // gun соответствует обычному gRPC обоих ядер; multiMode не подменяется.
            if parameters.remove("mode").is_some_and(|mode| mode != "gun") {
                return Err(CompileError::UnsupportedOption);
            }
            options.authority = take(&mut parameters, "authority");
            if !options.authority.is_empty() {
                if options.authority.contains(['/', '\\', '@', '#', '?', '%'])
                    || !options.authority.bytes().all(|b| b.is_ascii_graphic())
                    || url::Url::parse(&format!("https://{}/", options.authority))
                        .map_or(true, |url| url.host_str().is_none())
                {
                    return Err(CompileError::InvalidParameter);
                }
                if engine == Engine::SingBox {
                    return Err(CompileError::UnsupportedOption);
                }
            }
            options.service = take(&mut parameters, "serviceName");
            if options.service.chars().any(char::is_control) {
                return Err(CompileError::InvalidParameter);
            }
        }
        _ => {}
    }
    if protocol == Protocol::Vmess {
        options.cipher = take(&mut parameters, "scy");
        if options.cipher.is_empty() {
            options.cipher = "auto".into();
        }
        if !matches!(
            options.cipher.as_str(),
            "auto" | "aes-128-gcm" | "chacha20-poly1305"
        ) {
            return Err(CompileError::UnsupportedOption);
        }
    }
    if !parameters.is_empty() {
        return Err(CompileError::UnsupportedOption);
    }
    Ok(options)
}
