use std::fmt;

/// Содержимое доступно только явным expose; Debug не раскрывает исходники.
pub struct SecretText(String);

impl SecretText {
    pub(crate) fn new(text: String) -> Self {
        Self(text)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<скрыто>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    HttpConnect,
    Socks5,
    Hysteria2,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::HttpConnect => "http_connect",
            Self::Socks5 => "socks5",
            Self::Hysteria2 => "hysteria2",
        }
    }
}

pub struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
}
impl Endpoint {
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}
impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Endpoint(<скрыто>)")
    }
}

#[derive(Debug)]
pub enum Credentials {
    None,
    Uuid(SecretText),
    Password(SecretText),
    UserPassword {
        username: SecretText,
        password: SecretText,
    },
    Shadowsocks {
        method: SecretText,
        password: SecretText,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    WebSocket,
    Grpc,
    Xhttp,
    Http2,
    Quic,
    Unsupported,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    None,
    Tls,
    Reality,
    Unsupported,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewFlag {
    UnknownParameter,
    UnsupportedTransport,
    UnsupportedSecurity,
    UnsupportedCipher,
    UnsupportedOption,
    UnsafeOption,
    LegacyOption,
}

/// Только разобранные core-поля. Требуется отдельная capability/config-check проверка.
#[derive(Debug)]
pub struct ParsedServer {
    pub(crate) protocol: Protocol,
    pub(crate) endpoint: Endpoint,
    pub(crate) credentials: Credentials,
    pub(crate) transport: Transport,
    pub(crate) security: Security,
    pub(crate) parameters: SecretText,
    pub(crate) source: SecretText,
    pub(crate) review_flags: Vec<ReviewFlag>,
}
impl ParsedServer {
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }
    pub fn transport(&self) -> Transport {
        self.transport
    }
    pub fn security(&self) -> Security {
        self.security
    }
    /// Параметры остаются opaque до проверки конкретным engine adapter.
    pub fn parameters(&self) -> &SecretText {
        &self.parameters
    }
    pub fn source(&self) -> &SecretText {
        &self.source
    }
    pub fn review_flags(&self) -> &[ReviewFlag] {
        &self.review_flags
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueCode {
    MalformedUri,
    UnsupportedProtocol,
    InvalidPort,
    InvalidHost,
    InvalidCredentials,
    InvalidEncoding,
    InvalidJson,
    TooLarge,
    DuplicateParameter,
    ConflictingParameter,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Source,
    Endpoint,
    Credentials,
    Parameters,
    Payload,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Issue {
    pub line: usize,
    pub code: IssueCode,
    pub field: Field,
}

#[derive(Debug)]
pub struct ImportReport {
    pub servers: Vec<ParsedServer>,
    pub issues: Vec<Issue>,
    pub native_json: Option<SecretText>,
    pub base64_envelope: bool,
    pub(crate) original: SecretText,
}
impl ImportReport {
    pub fn original(&self) -> &SecretText {
        &self.original
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatalError {
    Io,
    TooLarge,
    TooManyRecords,
    InvalidEncoding,
    InvalidUtf8,
    Empty,
    InvalidJson,
    JsonTooDeep,
    UnsupportedFormat,
}
impl fmt::Display for FatalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Io => "Не удалось прочитать источник",
            Self::TooLarge => "Превышен размер импорта",
            Self::TooManyRecords => "Превышено число записей",
            Self::InvalidEncoding => "Некорректный Base64",
            Self::InvalidUtf8 => "Источник не является UTF-8",
            Self::Empty => "Пустой источник",
            Self::InvalidJson => "Некорректный JSON",
            Self::JsonTooDeep => "Превышена глубина JSON",
            Self::UnsupportedFormat => "Формат не распознан",
        })
    }
}
impl std::error::Error for FatalError {}

/// Фатальная ошибка сохраняет исходник для исправления/защищённого хранения host.
pub struct ImportFailure {
    pub(crate) kind: FatalError,
    pub(crate) input: Vec<u8>,
    pub(crate) complete: bool,
}
impl ImportFailure {
    pub fn kind(&self) -> FatalError {
        self.kind
    }
    /// Чувствительные байты; не отправлять в логи и обычный диагностический export.
    pub fn input(&self) -> &[u8] {
        &self.input
    }
    pub fn input_is_complete(&self) -> bool {
        self.complete
    }
}
impl fmt::Debug for ImportFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportFailure")
            .field("kind", &self.kind)
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for ImportFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}
impl std::error::Error for ImportFailure {}

pub(crate) type RecordError = (IssueCode, Field);
