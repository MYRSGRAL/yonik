//! Строгий компилятор одного proxy outbound. Не запускает ядро и не меняет сеть.

mod dns;
pub mod native_profile;
pub use dns::{DnsContract, DnsMode, compile_native_dns, compile_policy_with_dns};
mod options;
pub mod platform_source;
pub mod policy_input;
pub mod private_dns;
mod routing;
mod source_selectors;
mod system_tun;
pub use routing::{
    PolicyCapability, PolicyCompileError, PolicyMode, ProbeAccess, ProbeCredentials, compile_policy,
};
pub use system_tun::{
    SystemTun, SystemTunAddress, compile_system, compile_system_bound_policy, compile_system_policy,
};

use std::{
    fmt,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU16,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use options::Options;
use serde_json::{Value, json};
use yonik_import::{Credentials, ParsedServer, Protocol, Security, Transport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Xray,
    SingBox,
}
impl Engine {
    pub fn version(self) -> &'static str {
        match self {
            Self::Xray => "26.10.31",
            Self::SingBox => "1.14.4",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileError {
    UnsupportedTransport,
    UnsupportedSecurity,
    UnsupportedOption,
    InvalidParameter,
    InvalidCredentials,
    ListenerConflict,
}
impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedTransport => "Транспорт не поддерживается выбранным ядром",
            Self::UnsupportedSecurity => "Сочетание протокола и защиты не поддерживается",
            Self::UnsupportedOption => "Есть неподдерживаемые или небезопасные параметры",
            Self::InvalidParameter => "Некорректный параметр конфигурации",
            Self::InvalidCredentials => "Некорректные учётные данные",
            Self::ListenerConflict => "Адрес сервера совпадает с локальным listener",
        })
    }
}
impl std::error::Error for CompileError {}

/// Содержит credentials. JSON доступен только явной записью в выбранный host writer.
pub struct CompiledConfig {
    value: Value,
    engine: Engine,
    port: NonZeroU16,
    probe_port: NonZeroU16,
    local_http_port: Option<NonZeroU16>,
    probe_access: ProbeAccess,
}
impl CompiledConfig {
    /// Только LocalSocks host вызывает это перед config-check; SystemTUN/worker не меняются.
    pub fn with_local_runtime_logging(mut self) -> Self {
        self.value["log"] = match self.engine {
            Engine::Xray => json!({"loglevel":"info", "access":"none"}),
            Engine::SingBox => json!({"disabled":false, "level":"info", "timestamp":false}),
        };
        self
    }

    pub fn engine(&self) -> Engine {
        self.engine
    }
    pub fn listen_port(&self) -> NonZeroU16 {
        self.port
    }
    pub fn probe_port(&self) -> NonZeroU16 {
        self.probe_port
    }
    pub fn local_http_port(&self) -> Option<NonZeroU16> {
        self.local_http_port
    }
    pub fn probe_auth(&self) -> Option<&ProbeCredentials> {
        self.probe_access.auth()
    }
    pub fn into_probe_access(self) -> ProbeAccess {
        self.probe_access
    }
    pub fn write_sensitive(&self, writer: impl Write) -> Result<(), serde_json::Error> {
        serde_json::to_writer(writer, &self.value)
    }

    /// Legacy writer проверяет capability повторно перед передачей JSON ядру.
    pub fn requires_xray_reality_h2(&self) -> bool {
        self.engine == Engine::Xray
            && self
                .value
                .pointer("/outbounds/0/streamSettings/realitySettings/alpn")
                .is_some()
    }
}
impl fmt::Debug for CompiledConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompiledConfig(<скрыто>)")
    }
}

/// Генерация не заменяет config-check закреплённым бинарником и проверку трафика.
/// Listener всегда 127.0.0.1, все его запросы направляются выбранному серверу.
pub fn compile(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
) -> Result<CompiledConfig, CompileError> {
    compile_server(server, engine, port, false)
}

mod xray_reality_h2;
pub use xray_reality_h2::{PendingXrayRealityH2, XrayRealityH2};

fn compile_server(
    server: &ParsedServer,
    engine: Engine,
    port: NonZeroU16,
    require_reality_h2: bool,
) -> Result<CompiledConfig, CompileError> {
    validate_listener(server, port)?;
    let options = options::validate(server, engine, require_reality_h2)?;
    validate_credentials(server, engine)?;
    let value = match engine {
        Engine::Xray => json!({
            "log":{"loglevel":"none"},
            "inbounds":[{"tag":"local","listen":"127.0.0.1","port":port.get(),
                "protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],
            "outbounds":[xray_outbound(server, &options)?],
        }),
        Engine::SingBox => json!({
            "log":{"disabled":true},
            "inbounds":[{"type":"socks","tag":"local","listen":"127.0.0.1","listen_port":port.get()}],
            "outbounds":[sing_outbound(server, &options)?],
            "route":{"final":"proxy"},
        }),
    };
    Ok(CompiledConfig {
        value,
        engine,
        port,
        probe_port: port,
        local_http_port: None,
        probe_access: ProbeAccess::default(),
    })
}

fn validate_listener(server: &ParsedServer, port: NonZeroU16) -> Result<(), CompileError> {
    let host = server.endpoint().host();
    let listener_address = host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.to_canonical() == IpAddr::V4(Ipv4Addr::LOCALHOST));
    if server.endpoint().port() == port.get() && listener_address {
        return Err(CompileError::ListenerConflict);
    }
    Ok(())
}

fn validate_credentials(server: &ParsedServer, engine: Engine) -> Result<(), CompileError> {
    match server.credentials() {
        Credentials::Shadowsocks { method, password } => {
            let method = method.expose();
            if method.starts_with("2022-") {
                let size = match method {
                    "2022-blake3-aes-128-gcm" => 16,
                    "2022-blake3-aes-256-gcm" => 32,
                    "2022-blake3-chacha20-poly1305" if engine == Engine::SingBox => 32,
                    _ => return Err(CompileError::UnsupportedOption),
                };
                // Multi-user identity chains требуют отдельной модели, не теряем их хвост.
                if STANDARD
                    .decode(password.expose())
                    .map_or(true, |key| key.len() != size)
                {
                    return Err(CompileError::InvalidCredentials);
                }
            }
        }
        Credentials::UserPassword { username, password }
            if server.protocol() == Protocol::Socks5
                && (username.expose().is_empty()
                    || password.expose().is_empty()
                    || username.expose().len() > 255
                    || password.expose().len() > 255) =>
        {
            return Err(CompileError::InvalidCredentials);
        }
        _ => {}
    }
    Ok(())
}

fn xray_outbound(server: &ParsedServer, options: &Options) -> Result<Value, CompileError> {
    let address = server.endpoint().host();
    let port = server.endpoint().port();
    let (protocol, settings) = match (server.protocol(), server.credentials()) {
        (Protocol::Vless, Credentials::Uuid(id)) => (
            "vless",
            json!({"vnext":[{"address":address,"port":port,"users":[{
            "id":id.expose(),"encryption":"none","flow":options.flow}]}]}),
        ),
        (Protocol::Vmess, Credentials::Uuid(id)) => (
            "vmess",
            json!({"vnext":[{"address":address,"port":port,"users":[{
            "id":id.expose(),"security":options.cipher}]}]}),
        ),
        (Protocol::Trojan, Credentials::Password(password)) => (
            "trojan",
            json!({"servers":[{"address":address,"port":port,"password":password.expose()}]}),
        ),
        (Protocol::Hysteria2, Credentials::Password(_)) => (
            "hysteria",
            json!({"version":2,"address":address,"port":port}),
        ),
        (Protocol::Shadowsocks, Credentials::Shadowsocks { method, password }) => (
            "shadowsocks",
            json!({"servers":[{
            "address":address,"port":port,"method":method.expose(),"password":password.expose()}]}),
        ),
        (Protocol::HttpConnect | Protocol::Socks5, credentials) => {
            let mut endpoint = json!({"address":address,"port":port});
            match credentials {
                Credentials::None => {}
                Credentials::UserPassword { username, password } => {
                    endpoint["users"] =
                        json!([{"user":username.expose(),"pass":password.expose()}]);
                }
                _ => return Err(CompileError::InvalidCredentials),
            }
            (
                if server.protocol() == Protocol::HttpConnect {
                    "http"
                } else {
                    "socks"
                },
                json!({"servers":[endpoint]}),
            )
        }
        _ => return Err(CompileError::InvalidCredentials),
    };
    let mut stream = json!({"network":match server.transport() {
        Transport::Tcp => "tcp", Transport::WebSocket => "ws", Transport::Grpc => "grpc", Transport::Xhttp => "xhttp",
        Transport::Quic if server.protocol() == Protocol::Hysteria2 => "hysteria",
        _ => return Err(CompileError::UnsupportedTransport),
    }, "security":match server.security() {
        Security::None => "none", Security::Tls => "tls", Security::Reality => "reality",
        _ => return Err(CompileError::UnsupportedSecurity),
    }});
    match server.security() {
        Security::Tls => {
            let mut tls =
                json!({"serverName":options.sni,"allowInsecure":false,"useSystemCA":true});
            if !options.fingerprint.is_empty() {
                tls["fingerprint"] = json!(options.fingerprint);
            }
            if !options.alpn.is_empty() {
                tls["alpn"] = json!(options.alpn);
            }
            if !options.flow.is_empty() {
                tls["minVersion"] = json!("1.3");
            }
            stream["tlsSettings"] = tls;
        }
        Security::Reality => {
            stream["realitySettings"] = json!({"serverName":options.sni,
            "fingerprint":options.fingerprint,"password":options.public_key,"shortId":options.short_id});
            if !options.spider_path.is_empty() && options.spider_path != "/" {
                stream["realitySettings"]["spiderX"] = json!(options.spider_path);
            }
        }
        _ => {}
    }
    match server.transport() {
        Transport::WebSocket => {
            stream["wsSettings"] = json!({"host":options.host,"path":options.path})
        }
        Transport::Grpc => {
            stream["grpcSettings"] = json!({"serviceName":options.service});
            if !options.authority.is_empty() {
                stream["grpcSettings"]["authority"] = json!(options.authority);
            }
        }
        Transport::Xhttp => {
            stream["xhttpSettings"] =
                json!({"host":options.host,"path":options.path,"mode":options.mode})
        }
        Transport::Quic => {
            let Credentials::Password(auth) = server.credentials() else {
                return Err(CompileError::InvalidCredentials);
            };
            stream["hysteriaSettings"] = json!({"version":2,"auth":auth.expose()});
        }
        _ => {}
    }
    let mut outbound =
        json!({"tag":"proxy","protocol":protocol,"settings":settings,"streamSettings":stream});
    if options.xudp_mux {
        // Положительная ёмкость включает XUDP. Один UDP-поток на worker
        // не разделяет соединение с другими потоками. UDP/443 остаётся на default Xray.
        outbound["mux"] = json!({"enabled":true,"concurrency":-1,"xudpConcurrency":1});
    }
    Ok(outbound)
}

fn sing_outbound(server: &ParsedServer, options: &Options) -> Result<Value, CompileError> {
    let protocol = match server.protocol() {
        Protocol::Vless => "vless",
        Protocol::Vmess => "vmess",
        Protocol::Trojan => "trojan",
        Protocol::Shadowsocks => "shadowsocks",
        Protocol::HttpConnect => "http",
        Protocol::Socks5 => "socks",
        Protocol::Hysteria2 => return Err(CompileError::UnsupportedTransport),
    };
    let mut value = json!({"type":protocol,"tag":"proxy","server":server.endpoint().host(),"server_port":server.endpoint().port()});
    match server.credentials() {
        Credentials::Uuid(id) => {
            value["uuid"] = json!(id.expose());
            if server.protocol() == Protocol::Vless {
                value["flow"] = json!(options.flow);
            } else {
                value["security"] = json!(options.cipher);
            }
        }
        Credentials::Password(password) => value["password"] = json!(password.expose()),
        Credentials::Shadowsocks { method, password } => {
            value["method"] = json!(method.expose());
            value["password"] = json!(password.expose());
        }
        Credentials::UserPassword { username, password } => {
            value["username"] = json!(username.expose());
            value["password"] = json!(password.expose());
        }
        Credentials::None => {}
    }
    if server.protocol() == Protocol::Socks5 {
        value["version"] = json!("5");
    }
    if server.security() != Security::None {
        let mut tls = json!({"enabled":true,"server_name":options.sni,"insecure":false});
        if !options.fingerprint.is_empty() {
            tls["utls"] = json!({"enabled":true,"fingerprint":options.fingerprint});
        }
        if !options.alpn.is_empty() {
            tls["alpn"] = json!(options.alpn);
        }
        if !options.flow.is_empty() {
            tls["min_version"] = json!("1.3");
        }
        if server.security() == Security::Reality {
            tls["reality"] =
                json!({"enabled":true,"public_key":options.public_key,"short_id":options.short_id});
        }
        value["tls"] = tls;
    }
    match server.transport() {
        Transport::WebSocket => {
            value["transport"] =
                json!({"type":"ws","path":options.path,"headers":{"Host":options.host}})
        }
        Transport::Grpc => {
            value["transport"] = json!({"type":"grpc","service_name":options.service})
        }
        Transport::Tcp => {}
        _ => return Err(CompileError::UnsupportedTransport),
    }
    Ok(value)
}

pub mod policy_wire;
pub mod presets;

pub mod external_rules;

pub mod resource_bundle;

pub mod resource_index;

pub mod transport;

pub mod dns_policy_plan;
