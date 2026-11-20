//! Безопасный TCP bridge Fake-IP → доменное имя → локальный SOCKS ядра.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpStream, UdpSocket},
    time::{Instant, sleep_until, timeout},
};
use zeroize::Zeroizing;

use crate::Cancellation;
use yonik_engine::fake_dns::{DomainName, FakeMapping};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS_VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const METHOD_USER_PASS: u8 = 2;
const MAX_CREDENTIAL_LEN: usize = u8::MAX as usize;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_UDP_PACKET_LEN: usize = 4096;
const MAX_UDP_DESTINATIONS: usize = 64;
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const HMAC_CONTEXT: &[u8] = b"yonik-linux-fake-flow-auth-v1";

type HmacSha256 = Hmac<Sha256>;

/// Проверяемые credentials для обоих участков SOCKS-соединения.
pub struct SocksCredentials {
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
}

impl SocksCredentials {
    /// Создаёт credentials, совместимые с RFC 1929 (1–255 байт каждый).
    pub fn new(
        username: impl AsRef<[u8]>,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, FakeFlowError> {
        let username = username.as_ref();
        let password = password.as_ref();
        if username.is_empty()
            || username.len() > MAX_CREDENTIAL_LEN
            || password.is_empty()
            || password.len() > MAX_CREDENTIAL_LEN
        {
            return Err(FakeFlowError::InvalidConfiguration);
        }
        Ok(Self {
            username: Zeroizing::new(username.to_vec()),
            password: Zeroizing::new(password.to_vec()),
        })
    }

    fn matches(&self, username: &[u8], password: &[u8]) -> bool {
        let expected = credential_mac(&self.username, &self.password).finalize();
        let actual = credential_mac(username, password);
        actual.verify_slice(&expected.into_bytes()).is_ok()
    }
}

fn credential_mac(username: &[u8], password: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(HMAC_CONTEXT)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    mac.update(&(username.len() as u16).to_be_bytes());
    mac.update(username);
    mac.update(&(password.len() as u16).to_be_bytes());
    mac.update(password);
    mac
}

/// Ошибка bridge без адресов и секретов в сообщении.
#[derive(Debug)]
pub enum FakeFlowError {
    InvalidConfiguration,
    NonLoopback,
    Cancelled,
    Timeout,
    UnknownFakeIp,
    Protocol,
    UpstreamRejected,
    UdpPeerRejected,
    UdpMappingLimit,
    Io(io::Error),
}

impl std::fmt::Display for FakeFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "Некорректная конфигурация SOCKS bridge",
            Self::NonLoopback => "SOCKS bridge принимает только loopback соединения",
            Self::Cancelled => "SOCKS bridge отменён",
            Self::Timeout => "Превышен timeout SOCKS handshake",
            Self::UnknownFakeIp => "Fake-IP не найден в активном реестре",
            Self::Protocol => "Некорректный SOCKS протокол",
            Self::UpstreamRejected => "Локальное ядро отклонило SOCKS соединение",
            Self::UdpPeerRejected => "UDP пакет пришёл не от клиента этой SOCKS ассоциации",
            Self::UdpMappingLimit => "Исчерпан лимит назначений UDP ассоциации",
            Self::Io(_) => "Ошибка локального SOCKS соединения",
        })
    }
}

impl std::error::Error for FakeFlowError {}

impl From<io::Error> for FakeFlowError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Обрабатывает одно уже принятое клиентское соединение. Listener и лимит accept
/// сессий принадлежат вызывающему runtime.
pub async fn handle_tcp(
    mut incoming: TcpStream,
    upstream: SocketAddr,
    incoming_auth: &SocksCredentials,
    upstream_auth: &SocksCredentials,
    resolve_fake_ip: impl FnMut(IpAddr) -> Option<FakeMapping>,
    mut cancellation: Cancellation,
) -> Result<(), FakeFlowError> {
    validate_loopback(&incoming, upstream)?;
    let request = tokio::select! {
        result = timeout(HANDSHAKE_TIMEOUT, authenticate_request(&mut incoming, incoming_auth)) => result.map_err(|_| FakeFlowError::Timeout)??,
        () = cancellation.cancelled() => return Err(FakeFlowError::Cancelled),
    };
    if request.command != 1 {
        write_socks_failure(&mut incoming, 7).await?;
        return Err(FakeFlowError::Protocol);
    }
    handle_tcp_authenticated(
        incoming,
        request,
        upstream,
        upstream_auth,
        resolve_fake_ip,
        cancellation,
    )
    .await
}

/// Единый entry point SOCKS listener: один раз выбирает USERPASS и dispatch-ит
/// аутентифицированный CONNECT или UDP ASSOCIATE. Lookup возвращает исходную
/// аренду целиком для проверки её срока и поколения перед записью в сокет.
pub async fn handle_flow(
    mut incoming: TcpStream,
    upstream: SocketAddr,
    incoming_auth: &SocksCredentials,
    upstream_auth: &SocksCredentials,
    worker_isolation: Option<&WorkerOnlyLoopbackIsolation>,
    resolve_fake_ip: impl Fn(IpAddr) -> Option<FakeMapping> + Send + Sync,
    mut cancellation: Cancellation,
) -> Result<(), FakeFlowError> {
    validate_loopback(&incoming, upstream)?;
    let request = tokio::select! {
        result = timeout(HANDSHAKE_TIMEOUT, authenticate_request(&mut incoming, incoming_auth)) => result.map_err(|_| FakeFlowError::Timeout)??,
        () = cancellation.cancelled() => return Err(FakeFlowError::Cancelled),
    };
    match request.command {
        1 => {
            handle_tcp_authenticated(
                incoming,
                request,
                upstream,
                upstream_auth,
                resolve_fake_ip,
                cancellation,
            )
            .await
        }
        3 => {
            handle_udp_associate_authenticated(
                incoming,
                request,
                upstream,
                upstream_auth,
                worker_isolation,
                resolve_fake_ip,
                cancellation,
            )
            .await
        }
        _ => {
            write_socks_failure(&mut incoming, 7).await?;
            Err(FakeFlowError::Protocol)
        }
    }
}

async fn handle_tcp_authenticated(
    mut incoming: TcpStream,
    request: AuthenticatedRequest,
    upstream: SocketAddr,
    upstream_auth: &SocksCredentials,
    mut resolve_fake_ip: impl FnMut(IpAddr) -> Option<FakeMapping>,
    mut cancellation: Cancellation,
) -> Result<(), FakeFlowError> {
    let handshake = async {
        let target = read_tcp_target(&mut incoming, request).await?;
        let Some(mapping) =
            resolve_fake_ip(target.ip).filter(|mapping| mapping.address == target.ip)
        else {
            write_socks_failure(&mut incoming, 4).await?;
            return Err(FakeFlowError::UnknownFakeIp);
        };
        if mapping.name.as_str().is_empty()
            || mapping.name.as_str().len() > MAX_DOMAIN_LEN
            || target.port == 0
        {
            return Err(FakeFlowError::Protocol);
        }
        let mut core = TcpStream::connect(upstream).await?;
        if !core.local_addr()?.ip().is_loopback() || !core.peer_addr()?.ip().is_loopback() {
            return Err(FakeFlowError::NonLoopback);
        }
        let still_current = || resolve_fake_ip(target.ip).as_ref() == Some(&mapping);
        if let Err(error) = connect_core(
            &mut core,
            &mapping.name,
            target.port,
            upstream_auth,
            still_current,
        )
        .await
        {
            let reply = if matches!(error, FakeFlowError::UnknownFakeIp) {
                4
            } else {
                5
            };
            write_socks_failure(&mut incoming, reply).await?;
            return Err(error);
        }
        incoming
            .write_all(&[SOCKS_VERSION, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await?;
        Ok::<_, FakeFlowError>(core)
    };
    let mut core = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(FakeFlowError::Cancelled),
        result = timeout(HANDSHAKE_TIMEOUT, handshake) => result.map_err(|_| FakeFlowError::Timeout)??,
    };
    tokio::select! {
        result = copy_bidirectional(&mut incoming, &mut core) => { result?; Ok(()) },
        () = cancellation.cancelled() => Err(FakeFlowError::Cancelled),
    }
}

struct Target {
    ip: IpAddr,
    port: u16,
}

#[derive(Clone, Copy)]
struct AuthenticatedRequest {
    command: u8,
    address_type: u8,
}

fn validate_loopback(incoming: &TcpStream, upstream: SocketAddr) -> Result<(), FakeFlowError> {
    if !incoming.peer_addr()?.ip().is_loopback()
        || !incoming.local_addr()?.ip().is_loopback()
        || !upstream.ip().is_loopback()
        || upstream.port() == 0
    {
        return Err(FakeFlowError::NonLoopback);
    }
    Ok(())
}

async fn authenticate_request(
    stream: &mut TcpStream,
    credentials: &SocksCredentials,
) -> Result<AuthenticatedRequest, FakeFlowError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[1] == 0 {
        return Err(FakeFlowError::Protocol);
    }
    let methods = read_bounded(stream, usize::from(header[1])).await?;
    if !methods.contains(&METHOD_USER_PASS) {
        stream.write_all(&[SOCKS_VERSION, 0xff]).await?;
        return Err(FakeFlowError::Protocol);
    }
    stream.write_all(&[SOCKS_VERSION, METHOD_USER_PASS]).await?;
    let mut auth_head = [0u8; 2];
    stream.read_exact(&mut auth_head).await?;
    if auth_head[0] != AUTH_VERSION || auth_head[1] == 0 {
        return Err(FakeFlowError::Protocol);
    }
    let username = Zeroizing::new(read_bounded(stream, usize::from(auth_head[1])).await?);
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen).await?;
    if plen[0] == 0 {
        return Err(FakeFlowError::Protocol);
    }
    let password = Zeroizing::new(read_bounded(stream, usize::from(plen[0])).await?);
    if !credentials.matches(&username, &password) {
        stream.write_all(&[AUTH_VERSION, 1]).await?;
        return Err(FakeFlowError::Protocol);
    }
    stream.write_all(&[AUTH_VERSION, 0]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != SOCKS_VERSION || request[2] != 0 {
        return Err(FakeFlowError::Protocol);
    }
    Ok(AuthenticatedRequest {
        command: request[1],
        address_type: request[3],
    })
}

async fn read_tcp_target(
    stream: &mut TcpStream,
    request: AuthenticatedRequest,
) -> Result<Target, FakeFlowError> {
    let ip = match request.address_type {
        1 => IpAddr::from(
            <[u8; 4]>::try_from(read_bounded(stream, 4).await?)
                .map_err(|_| FakeFlowError::Protocol)?,
        ),
        4 => IpAddr::from(
            <[u8; 16]>::try_from(read_bounded(stream, 16).await?)
                .map_err(|_| FakeFlowError::Protocol)?,
        ),
        _ => {
            write_socks_failure(stream, 8).await?;
            return Err(FakeFlowError::Protocol);
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return Err(FakeFlowError::Protocol);
    }
    Ok(Target { ip, port })
}

async fn connect_core(
    stream: &mut TcpStream,
    domain: &DomainName,
    port: u16,
    credentials: &SocksCredentials,
    mut still_current: impl FnMut() -> bool,
) -> Result<(), FakeFlowError> {
    stream
        .write_all(&[SOCKS_VERSION, 1, METHOD_USER_PASS])
        .await?;
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await?;
    if method_reply != [SOCKS_VERSION, METHOD_USER_PASS] {
        return Err(FakeFlowError::UpstreamRejected);
    }
    stream
        .write_all(&[AUTH_VERSION, credentials.username.len() as u8])
        .await?;
    stream.write_all(&credentials.username).await?;
    stream
        .write_all(&[credentials.password.len() as u8])
        .await?;
    stream.write_all(&credentials.password).await?;
    let mut auth_reply = [0u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    if auth_reply != [AUTH_VERSION, 0] {
        return Err(FakeFlowError::UpstreamRejected);
    }
    let name = domain.as_str().as_bytes();
    let mut request = Vec::with_capacity(7 + name.len());
    request.extend_from_slice(&[SOCKS_VERSION, 1, 0, 3, name.len() as u8]);
    request.extend_from_slice(name);
    request.extend_from_slice(&port.to_be_bytes());
    let mut pending = request.as_slice();
    while !pending.is_empty() {
        stream.writable().await?;
        // Аутентификация и ожидание сокета могут пережить срок выдачи адреса.
        if !still_current() {
            return Err(FakeFlowError::UnknownFakeIp);
        }
        match stream.try_write(pending) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
            Ok(written) => pending = &pending[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
    }
    read_socks_reply(stream).await
}

async fn read_socks_reply(stream: &mut TcpStream) -> Result<(), FakeFlowError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err(FakeFlowError::Protocol);
    }
    let address_len = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            if len[0] == 0 {
                return Err(FakeFlowError::Protocol);
            }
            usize::from(len[0])
        }
        _ => return Err(FakeFlowError::Protocol),
    };
    let mut rest = vec![0; address_len + 2];
    stream.read_exact(&mut rest).await?;
    if header[1] != 0 {
        return Err(FakeFlowError::UpstreamRejected);
    }
    Ok(())
}

async fn write_socks_failure(stream: &mut TcpStream, reply: u8) -> Result<(), FakeFlowError> {
    stream
        .write_all(&[SOCKS_VERSION, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn read_bounded(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, FakeFlowError> {
    if len > 255 {
        return Err(FakeFlowError::Protocol);
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// Явное подтверждение caller, что loopback UDP доступен только процессу worker.
///
/// Передавайте этот token только после проверки caller, что bridge и engine находятся
/// в worker-only network namespace либо что эквивалентная изоляция запрещает чужим
/// локальным процессам отправлять UDP на relay. Одного bind на loopback недостаточно.
pub struct WorkerOnlyLoopbackIsolation(());

impl WorkerOnlyLoopbackIsolation {
    /// Создаёт token только если caller подтвердил изоляцию по собственному источнику.
    ///
    /// Проверка должна доказать изоляцию всех процессов, имеющих доступ к loopback
    /// namespace, а не только проверить адрес bind или наличие UDP-порта. Практический
    /// check: сравнить inode `/proc/<pid>/ns/net` у bridge и engine, убедиться, что это
    /// выделенный namespace только этих доверенных worker-процессов, проверить полный
    /// список процессов в нём и не передавать namespace fd/`setns` права host-процессам.
    pub fn verified_by(check: impl FnOnce() -> bool) -> Result<Self, FakeFlowError> {
        if check() {
            Ok(Self(()))
        } else {
            Err(FakeFlowError::InvalidConfiguration)
        }
    }
}

struct UdpAssociationRequest {
    exact_client: Option<SocketAddr>,
    client_ip: IpAddr,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct FakeDestination {
    address: IpAddr,
    port: u16,
}

struct UpstreamUdpAssociation {
    control: TcpStream,
    relay: UdpSocket,
}

enum UdpEvent {
    Client(usize, SocketAddr),
    Upstream(usize),
    ClientControl(usize),
    UpstreamControl(usize),
    Idle,
    Cancelled,
}

/// Обрабатывает одну RFC 1928 UDP ASSOCIATE с Fake-IP → domain reinject.
///
/// Unknown/invalid datagrams отбрасываются. Если клиент не указал source port
/// (обычно `0.0.0.0:0`, иногда loopback IP с портом `0`), требуется
/// `worker_isolation`; первый валидный пакет привязывает полный
/// source IP:port этой ассоциации. Другие UDP источники никогда не меняют peer.
/// На одну ассоциацию разрешено до 64 уникальных `(fake IP, port)`, но неоднозначные
/// ответы для одного `(domain, port)` с разными Fake-IP отбрасываются.
pub async fn handle_udp_associate(
    mut incoming_control: TcpStream,
    upstream: SocketAddr,
    incoming_auth: &SocksCredentials,
    upstream_auth: &SocksCredentials,
    worker_isolation: Option<&WorkerOnlyLoopbackIsolation>,
    resolve_fake_ip: impl Fn(IpAddr) -> Option<FakeMapping> + Send + Sync,
    mut cancellation: Cancellation,
) -> Result<(), FakeFlowError> {
    if !incoming_control.peer_addr()?.ip().is_loopback()
        || !incoming_control.local_addr()?.ip().is_loopback()
        || !upstream.ip().is_loopback()
        || upstream.port() == 0
    {
        return Err(FakeFlowError::NonLoopback);
    }
    let request = tokio::select! {
        result = timeout(HANDSHAKE_TIMEOUT, authenticate_request(&mut incoming_control, incoming_auth)) => result.map_err(|_| FakeFlowError::Timeout)??,
        () = cancellation.cancelled() => return Err(FakeFlowError::Cancelled),
    };
    if request.command != 3 {
        write_socks_failure(&mut incoming_control, 7).await?;
        return Err(FakeFlowError::Protocol);
    }
    handle_udp_associate_authenticated(
        incoming_control,
        request,
        upstream,
        upstream_auth,
        worker_isolation,
        resolve_fake_ip,
        cancellation,
    )
    .await
}

async fn handle_udp_associate_authenticated(
    mut incoming_control: TcpStream,
    authenticated_request: AuthenticatedRequest,
    upstream: SocketAddr,
    upstream_auth: &SocksCredentials,
    worker_isolation: Option<&WorkerOnlyLoopbackIsolation>,
    resolve_fake_ip: impl Fn(IpAddr) -> Option<FakeMapping> + Send + Sync,
    mut cancellation: Cancellation,
) -> Result<(), FakeFlowError> {
    if !incoming_control.peer_addr()?.ip().is_loopback()
        || !incoming_control.local_addr()?.ip().is_loopback()
        || !upstream.ip().is_loopback()
        || upstream.port() == 0
    {
        return Err(FakeFlowError::NonLoopback);
    }
    let peer_ip = incoming_control.peer_addr()?.ip();
    let local_ip = incoming_control.local_addr()?.ip();
    let setup = async {
        let request =
            read_udp_client_request(&mut incoming_control, peer_ip, authenticated_request).await?;
        if request.exact_client.is_none() && worker_isolation.is_none() {
            incoming_control
                .write_all(&[SOCKS_VERSION, 2, 0, 1, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(FakeFlowError::UdpPeerRejected);
        }
        let client_relay = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
        if !client_relay.local_addr()?.ip().is_loopback() {
            return Err(FakeFlowError::NonLoopback);
        }
        let relay_addr = client_relay.local_addr()?;
        write_udp_associate_reply(&mut incoming_control, relay_addr).await?;
        Ok::<_, FakeFlowError>((request, client_relay))
    };
    let (request, client_relay) = tokio::select! {
        result = timeout(HANDSHAKE_TIMEOUT, setup) => result.map_err(|_| FakeFlowError::Timeout)??,
        () = cancellation.cancelled() => return Err(FakeFlowError::Cancelled),
    };

    let mut expected_client = request.exact_client;
    let mut upstream_assoc: Option<UpstreamUdpAssociation> = None;
    let mut by_fake = HashMap::<FakeDestination, FakeMapping>::new();
    let mut by_domain = HashMap::<(String, u16), FakeDestination>::new();
    let mut idle_deadline = Instant::now() + UDP_IDLE_TIMEOUT;
    let mut client_buffer = [0u8; MAX_UDP_PACKET_LEN + 1];
    let mut upstream_buffer = [0u8; MAX_UDP_PACKET_LEN + 1];
    let mut encoded = Vec::with_capacity(MAX_UDP_PACKET_LEN);
    let mut client_control_byte = [0u8; 1];
    let mut upstream_control_byte = [0u8; 1];

    loop {
        let (upstream_control, upstream_relay) = match &mut upstream_assoc {
            Some(association) => (Some(&mut association.control), Some(&mut association.relay)),
            None => (None, None),
        };
        let event = tokio::select! {
            packet = client_relay.recv_from(&mut client_buffer) => {
                let (len, source) = packet?;
                UdpEvent::Client(len, source)
            }
            packet = recv_upstream_packet(upstream_relay, &mut upstream_buffer), if upstream_relay.is_some() => {
                UdpEvent::Upstream(packet?)
            }
            result = incoming_control.read(&mut client_control_byte) => {
                UdpEvent::ClientControl(result?)
            }
            result = read_upstream_control(upstream_control, &mut upstream_control_byte), if upstream_control.is_some() => {
                UdpEvent::UpstreamControl(result?)
            }
            () = sleep_until(idle_deadline) => UdpEvent::Idle,
            () = cancellation.cancelled() => UdpEvent::Cancelled,
        };

        match event {
            UdpEvent::ClientControl(0) | UdpEvent::UpstreamControl(0) => return Ok(()),
            UdpEvent::ClientControl(_) | UdpEvent::UpstreamControl(_) => {
                return Err(FakeFlowError::Protocol);
            }
            UdpEvent::Idle => return Err(FakeFlowError::Timeout),
            UdpEvent::Cancelled => return Err(FakeFlowError::Cancelled),
            UdpEvent::Client(len, source) => {
                if !source.ip().is_loopback()
                    || source.ip() != request.client_ip
                    || expected_client.is_some_and(|expected| expected != source)
                {
                    continue;
                }
                let Some((fake, port, payload)) = parse_client_udp(&client_buffer[..len]) else {
                    continue;
                };
                let Some(mapping) =
                    resolve_fake_ip(fake.address).filter(|mapping| mapping.address == fake.address)
                else {
                    continue;
                };
                if mapping.name.as_str().is_empty() || mapping.name.as_str().len() > MAX_DOMAIN_LEN
                {
                    continue;
                }
                let within_limit = by_fake.len() < MAX_UDP_DESTINATIONS;
                let mapping = match by_fake.entry(fake) {
                    std::collections::hash_map::Entry::Occupied(entry) => {
                        if entry.get() != &mapping {
                            return Err(FakeFlowError::UnknownFakeIp);
                        }
                        entry.into_mut()
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let reverse_key = (mapping.name.as_str().to_owned(), port);
                        if by_domain.contains_key(&reverse_key) {
                            continue;
                        }
                        if !within_limit {
                            return Err(FakeFlowError::UdpMappingLimit);
                        }
                        by_domain.insert(reverse_key, fake);
                        entry.insert(mapping)
                    }
                };
                let domain = mapping.name.as_str();
                if expected_client.is_none() {
                    expected_client = Some(source);
                }
                if upstream_assoc.is_none() {
                    let connect =
                        timeout(HANDSHAKE_TIMEOUT, connect_core_udp(upstream, upstream_auth));
                    let association = tokio::select! {
                        result = connect => result.map_err(|_| FakeFlowError::Timeout)??,
                        result = incoming_control.read(&mut client_control_byte) => {
                            if result? == 0 { return Ok(()); }
                            return Err(FakeFlowError::Protocol);
                        }
                        () = cancellation.cancelled() => return Err(FakeFlowError::Cancelled),
                    };
                    upstream_assoc = Some(association);
                }
                if 7 + domain.len() + payload.len() > MAX_UDP_PACKET_LEN {
                    continue;
                }
                encoded.clear();
                encoded.extend_from_slice(&[0, 0, 0, 3, domain.len() as u8]);
                encoded.extend_from_slice(domain.as_bytes());
                encoded.extend_from_slice(&port.to_be_bytes());
                encoded.extend_from_slice(payload);
                let Some(association) = upstream_assoc.as_mut() else {
                    return Err(FakeFlowError::UpstreamRejected);
                };
                if send_udp_for_mapping(&association.relay, mapping, &resolve_fake_ip, || {
                    association.relay.try_send(&encoded)
                })
                .await?
                {
                    idle_deadline = Instant::now() + UDP_IDLE_TIMEOUT;
                }
            }
            UdpEvent::Upstream(len) => {
                let Some((domain, port, payload)) = parse_upstream_udp(&upstream_buffer[..len])
                else {
                    continue;
                };
                let key = (domain, port);
                let Some(fake) = by_domain.get(&key).copied() else {
                    continue;
                };
                let mapping = by_fake.get(&fake).ok_or(FakeFlowError::UnknownFakeIp)?;
                let Some(source) = expected_client else {
                    continue;
                };
                let header_len = if fake.address.is_ipv4() { 10 } else { 22 };
                if header_len + payload.len() > MAX_UDP_PACKET_LEN {
                    continue;
                }
                encoded.clear();
                encode_fake_ip(&mut encoded, fake.address);
                encoded.extend_from_slice(&fake.port.to_be_bytes());
                encoded.extend_from_slice(payload);
                if send_udp_for_mapping(&client_relay, mapping, &resolve_fake_ip, || {
                    client_relay.try_send_to(&encoded, source)
                })
                .await?
                {
                    idle_deadline = Instant::now() + UDP_IDLE_TIMEOUT;
                }
            }
        }
    }
}

async fn send_udp_for_mapping(
    socket: &UdpSocket,
    mapping: &FakeMapping,
    resolve_fake_ip: impl Fn(IpAddr) -> Option<FakeMapping>,
    send: impl Fn() -> io::Result<usize>,
) -> Result<bool, FakeFlowError> {
    loop {
        socket.writable().await?;
        // Срок аренды проверяем после ожидания, перед каждой попыткой записи.
        match resolve_fake_ip(mapping.address) {
            None => return Ok(false),
            Some(current) if &current != mapping => return Err(FakeFlowError::UnknownFakeIp),
            Some(_) => {}
        }
        match send() {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
    }
}

async fn read_udp_client_request(
    stream: &mut TcpStream,
    peer_ip: IpAddr,
    request: AuthenticatedRequest,
) -> Result<UdpAssociationRequest, FakeFlowError> {
    let requested_ip = match request.address_type {
        1 => IpAddr::from(
            <[u8; 4]>::try_from(read_bounded(stream, 4).await?)
                .map_err(|_| FakeFlowError::Protocol)?,
        ),
        4 => IpAddr::from(
            <[u8; 16]>::try_from(read_bounded(stream, 16).await?)
                .map_err(|_| FakeFlowError::Protocol)?,
        ),
        _ => {
            write_socks_failure(stream, 8).await?;
            return Err(FakeFlowError::Protocol);
        }
    };
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let requested_port = u16::from_be_bytes(port_bytes);
    let source_unknown = requested_port == 0;
    let exact_client = if source_unknown {
        if !requested_ip.is_unspecified()
            && (!requested_ip.is_loopback() || requested_ip != peer_ip)
        {
            write_socks_failure(stream, 2).await?;
            return Err(FakeFlowError::UdpPeerRejected);
        }
        None
    } else {
        if !requested_ip.is_loopback() || requested_ip != peer_ip {
            stream
                .write_all(&[SOCKS_VERSION, 2, 0, 1, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(FakeFlowError::UdpPeerRejected);
        }
        Some(SocketAddr::new(requested_ip, requested_port))
    };
    Ok(UdpAssociationRequest {
        exact_client,
        client_ip: peer_ip,
    })
}

async fn write_udp_associate_reply(
    stream: &mut TcpStream,
    relay: SocketAddr,
) -> Result<(), FakeFlowError> {
    if !relay.ip().is_loopback() || relay.port() == 0 {
        return Err(FakeFlowError::NonLoopback);
    }
    let mut reply = vec![SOCKS_VERSION, 0, 0];
    encode_ip(&mut reply, relay.ip());
    reply.extend_from_slice(&relay.port().to_be_bytes());
    stream.write_all(&reply).await?;
    Ok(())
}

async fn connect_core_udp(
    upstream: SocketAddr,
    credentials: &SocksCredentials,
) -> Result<UpstreamUdpAssociation, FakeFlowError> {
    if !upstream.ip().is_loopback() || upstream.port() == 0 {
        return Err(FakeFlowError::NonLoopback);
    }
    let mut control = TcpStream::connect(upstream).await?;
    let local_addr = control.local_addr()?;
    let peer_addr = control.peer_addr()?;
    if !local_addr.ip().is_loopback() || !peer_addr.ip().is_loopback() {
        return Err(FakeFlowError::NonLoopback);
    }
    let udp = UdpSocket::bind(SocketAddr::new(local_addr.ip(), 0)).await?;
    let udp_source = udp.local_addr()?;
    if !udp_source.ip().is_loopback() || udp_source.port() == 0 {
        return Err(FakeFlowError::NonLoopback);
    }
    control
        .write_all(&[SOCKS_VERSION, 1, METHOD_USER_PASS])
        .await?;
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await?;
    if method != [SOCKS_VERSION, METHOD_USER_PASS] {
        return Err(FakeFlowError::UpstreamRejected);
    }
    control
        .write_all(&[AUTH_VERSION, credentials.username.len() as u8])
        .await?;
    control.write_all(&credentials.username).await?;
    control
        .write_all(&[credentials.password.len() as u8])
        .await?;
    control.write_all(&credentials.password).await?;
    let mut auth = [0u8; 2];
    control.read_exact(&mut auth).await?;
    if auth != [AUTH_VERSION, 0] {
        return Err(FakeFlowError::UpstreamRejected);
    }
    let mut request = vec![SOCKS_VERSION, 3, 0];
    encode_ip(&mut request, udp_source.ip());
    request.extend_from_slice(&udp_source.port().to_be_bytes());
    control.write_all(&request).await?;
    let relay = read_udp_associate_reply(&mut control).await?;
    udp.connect(relay).await?;
    Ok(UpstreamUdpAssociation {
        control,
        relay: udp,
    })
}

async fn read_udp_associate_reply(stream: &mut TcpStream) -> Result<SocketAddr, FakeFlowError> {
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != SOCKS_VERSION || reply[2] != 0 {
        return Err(FakeFlowError::Protocol);
    }
    if reply[1] != 0 {
        return Err(FakeFlowError::UpstreamRejected);
    }
    let ip = match reply[3] {
        1 => IpAddr::from(
            <[u8; 4]>::try_from(read_bounded(stream, 4).await?)
                .map_err(|_| FakeFlowError::Protocol)?,
        ),
        4 => IpAddr::from(
            <[u8; 16]>::try_from(read_bounded(stream, 16).await?)
                .map_err(|_| FakeFlowError::Protocol)?,
        ),
        _ => return Err(FakeFlowError::Protocol),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let relay = SocketAddr::new(ip, u16::from_be_bytes(port));
    if !relay.ip().is_loopback() || relay.ip().is_unspecified() || relay.port() == 0 {
        return Err(FakeFlowError::NonLoopback);
    }
    Ok(relay)
}

async fn recv_upstream_packet(
    relay: Option<&mut UdpSocket>,
    buffer: &mut [u8],
) -> io::Result<usize> {
    match relay {
        Some(relay) => relay.recv(buffer).await,
        None => std::future::pending().await,
    }
}

async fn read_upstream_control(
    control: Option<&mut TcpStream>,
    buffer: &mut [u8; 1],
) -> io::Result<usize> {
    match control {
        Some(control) => control.read(buffer).await,
        None => std::future::pending().await,
    }
}

fn parse_client_udp(packet: &[u8]) -> Option<(FakeDestination, u16, &[u8])> {
    if packet.len() < 10
        || packet.len() > MAX_UDP_PACKET_LEN
        || packet[..2] != [0, 0]
        || packet[2] != 0
    {
        return None;
    }
    let (address, offset) = match packet[3] {
        1 => {
            let bytes: [u8; 4] = packet.get(4..8)?.try_into().ok()?;
            (IpAddr::from(bytes), 8)
        }
        4 => {
            let bytes: [u8; 16] = packet.get(4..20)?.try_into().ok()?;
            (IpAddr::from(bytes), 20)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(packet.get(offset..offset + 2)?.try_into().ok()?);
    if port == 0 {
        return None;
    }
    Some((
        FakeDestination { address, port },
        port,
        &packet[offset + 2..],
    ))
}

fn parse_upstream_udp(packet: &[u8]) -> Option<(String, u16, &[u8])> {
    if packet.len() < 7
        || packet.len() > MAX_UDP_PACKET_LEN
        || packet[..2] != [0, 0]
        || packet[2] != 0
        || packet[3] != 3
    {
        return None;
    }
    let name_len = usize::from(*packet.get(4)?);
    if name_len == 0 || name_len > MAX_DOMAIN_LEN {
        return None;
    }
    let name_end = 5usize.checked_add(name_len)?;
    let name = std::str::from_utf8(packet.get(5..name_end)?).ok()?;
    if name.bytes().any(|byte| !byte.is_ascii()) {
        return None;
    }
    let port = u16::from_be_bytes(packet.get(name_end..name_end + 2)?.try_into().ok()?);
    if port == 0 {
        return None;
    }
    Some((name.to_ascii_lowercase(), port, &packet[name_end + 2..]))
}

fn encode_ip(output: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
    }
}

fn encode_fake_ip(output: &mut Vec<u8>, ip: IpAddr) {
    output.extend_from_slice(&[0, 0, 0]);
    encode_ip(output, ip);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicU8, AtomicUsize, Ordering},
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use yonik_engine::fake_dns::DnsEpoch;

    fn credentials() -> SocksCredentials {
        SocksCredentials::new(b"user", b"secret").unwrap_or_else(|_| unreachable!())
    }

    fn mapping(address: IpAddr, name: &str, expires_at: u64) -> Option<FakeMapping> {
        Some(FakeMapping {
            address,
            name: DomainName::from_str(name).ok()?,
            epoch: DnsEpoch::default(),
            expires_at,
        })
    }

    async fn start_handler(
        upstream: SocketAddr,
        resolver: impl Fn(IpAddr) -> Option<FakeMapping> + Send + Sync + 'static,
    ) -> (
        TcpStream,
        tokio::task::JoinHandle<Result<(), FakeFlowError>>,
    ) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming_auth = credentials();
        let upstream_auth =
            SocksCredentials::new(b"core-user", b"core-secret").unwrap_or_else(|_| unreachable!());
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let (_sender, cancellation) = Cancellation::new();
            handle_flow(
                stream,
                upstream,
                &incoming_auth,
                &upstream_auth,
                None,
                resolver,
                cancellation,
            )
            .await
        });
        let client = TcpStream::connect(addr).await.unwrap();
        (client, task)
    }

    async fn authenticate_and_request(
        client: &mut TcpStream,
        password: &[u8],
        ip: IpAddr,
        port: u16,
    ) -> [u8; 2] {
        client.write_all(&[5, 1, METHOD_USER_PASS]).await.unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, METHOD_USER_PASS]);
        client.write_all(&[1, 4]).await.unwrap();
        client.write_all(b"user").await.unwrap();
        client.write_all(&[password.len() as u8]).await.unwrap();
        client.write_all(password).await.unwrap();
        client.read_exact(&mut reply).await.unwrap();
        if reply != [1, 0] {
            return reply;
        }
        let mut request = vec![5, 1, 0];
        match ip {
            IpAddr::V4(value) => {
                request.push(1);
                request.extend_from_slice(&value.octets());
            }
            IpAddr::V6(value) => {
                request.push(4);
                request.extend_from_slice(&value.octets());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut result = [0; 2];
        client.read_exact(&mut result).await.unwrap();
        if result == [SOCKS_VERSION, 0] {
            let mut bind_reply_tail = [0; 8];
            client.read_exact(&mut bind_reply_tail).await.unwrap();
        }
        result
    }

    #[tokio::test]
    async fn connects_using_fake_domain_and_copies_both_directions() {
        let core_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let core_addr = core_listener.local_addr().unwrap();
        let core = tokio::spawn(async move {
            let (mut stream, _) = core_listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0; 2];
            stream.read_exact(&mut auth).await.unwrap();
            let mut username = vec![0; usize::from(auth[1])];
            stream.read_exact(&mut username).await.unwrap();
            let mut password_len = [0; 1];
            stream.read_exact(&mut password_len).await.unwrap();
            let mut password = vec![0; usize::from(password_len[0])];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"core-user");
            assert_eq!(password, b"core-secret");
            stream.write_all(&[1, 0]).await.unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 3]);
            let mut domain = vec![0; usize::from(request[4])];
            stream.read_exact(&mut domain).await.unwrap();
            let mut port = [0; 2];
            stream.read_exact(&mut port).await.unwrap();
            assert_eq!(domain, b"example.org");
            assert_eq!(u16::from_be_bytes(port), 8443);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut from_client = [0; 4];
            stream.read_exact(&mut from_client).await.unwrap();
            assert_eq!(&from_client, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let (mut client, handler) = start_handler(core_addr, |ip| {
            (ip == IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7)))
                .then(|| mapping(ip, "example.org", 10))
                .flatten()
        })
        .await;
        assert_eq!(
            authenticate_and_request(
                &mut client,
                b"secret",
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7)),
                8443
            )
            .await,
            [5, 0]
        );
        client.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        core.await.unwrap();
        drop(client);
        assert!(handler.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn истекший_при_аутентификации_fake_ip_не_отправляет_connect() {
        проверить_истечение_при_аутентификации(false).await;
    }

    #[tokio::test]
    async fn повторная_выдача_того_же_fake_ip_не_оживляет_connect() {
        проверить_истечение_при_аутентификации(true).await;
    }

    async fn проверить_истечение_при_аутентификации(
        перевыдать: bool,
    ) {
        use std::sync::{Mutex, atomic::AtomicU64};
        use yonik_engine::fake_dns::{FakeIpFamily, FakeIpLeaseTable};

        let fake_ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7));
        let epoch = DnsEpoch {
            network: 1,
            engine: 1,
            resolver: 1,
        };
        let mut leases = FakeIpLeaseTable::new([fake_ip]).unwrap();
        leases
            .issue(
                DomainName::from_str("example.org").unwrap(),
                FakeIpFamily::V4,
                epoch,
                1,
                10,
            )
            .unwrap();
        let leases = Mutex::new(leases);
        let now = Arc::new(AtomicU64::new(1));

        let core_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let core_addr = core_listener.local_addr().unwrap();
        let core_clock = Arc::clone(&now);
        let core = tokio::spawn(async move {
            let (mut stream, _) = core_listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).await.unwrap();
            let expected = b"\x01\x09core-user\x0bcore-secret";
            let mut auth = [0; 23];
            stream.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, expected);
            core_clock.store(11, Ordering::SeqCst);
            stream.write_all(&[1, 0]).await.unwrap();
            let mut connect = [0; 1];
            let length = stream.read(&mut connect).await.unwrap();
            assert_eq!(length, 0, "Движок получил CONNECT с истёкшим Fake-IP");
        });
        let (mut client, handler) = start_handler(core_addr, move |address| {
            let mut leases = leases.lock().unwrap();
            let tick = now.load(Ordering::SeqCst);
            if перевыдать && tick == 11 {
                let grant = leases
                    .issue(
                        DomainName::from_str("example.org").unwrap(),
                        FakeIpFamily::V4,
                        epoch,
                        tick,
                        10,
                    )
                    .unwrap();
                assert_eq!(grant.address, address);
                assert_eq!(grant.expires_at, 21);
            }
            leases.lookup(address, epoch, tick).unwrap()
        })
        .await;
        let response = authenticate_and_request(&mut client, b"secret", fake_ip, 443).await;
        core.await.unwrap();
        assert_eq!(response, [SOCKS_VERSION, 4]);
        assert!(matches!(
            handler.await.unwrap(),
            Err(FakeFlowError::UnknownFakeIp)
        ));
    }

    #[tokio::test]
    async fn unknown_mapping_does_not_connect_upstream() {
        let fake_ipv6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7));
        let core_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let core_addr = core_listener.local_addr().unwrap();
        let (mut client, handler) = start_handler(core_addr, move |ip| {
            assert_eq!(ip, fake_ipv6);
            None
        })
        .await;
        let response = authenticate_and_request(&mut client, b"secret", fake_ipv6, 443).await;
        assert_eq!(response[0], SOCKS_VERSION);
        assert_eq!(response[1], 4);
        assert!(matches!(
            handler.await.unwrap(),
            Err(FakeFlowError::UnknownFakeIp)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(30), core_listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_wrong_client_password_without_upstream_connect() {
        let core_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let core_addr = core_listener.local_addr().unwrap();
        let (mut client, handler) =
            start_handler(core_addr, |ip| mapping(ip, "example.org", 10)).await;
        assert_eq!(
            authenticate_and_request(&mut client, b"wrong", IpAddr::V4(Ipv4Addr::LOCALHOST), 443)
                .await,
            [1, 1]
        );
        assert!(matches!(
            handler.await.unwrap(),
            Err(FakeFlowError::Protocol)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(30), core_listener.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn credentials_reject_empty_or_oversized_fields() {
        assert!(SocksCredentials::new([], b"secret").is_err());
        assert!(SocksCredentials::new(vec![b'a'; 256], b"secret").is_err());
    }

    async fn udp_client_handshake(
        control: &mut TcpStream,
        udp_source: SocketAddr,
        password: &[u8],
    ) -> Result<SocketAddr, u8> {
        control.write_all(&[5, 1, METHOD_USER_PASS]).await.unwrap();
        let mut reply = [0; 2];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, METHOD_USER_PASS]);
        control.write_all(&[1, 4]).await.unwrap();
        control.write_all(b"user").await.unwrap();
        control.write_all(&[password.len() as u8]).await.unwrap();
        control.write_all(password).await.unwrap();
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 0]);
        let mut request = vec![5, 3, 0];
        encode_ip(&mut request, udp_source.ip());
        request.extend_from_slice(&udp_source.port().to_be_bytes());
        control.write_all(&request).await.unwrap();
        let mut header = [0; 4];
        control.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], SOCKS_VERSION);
        if header[1] != 0 {
            let address_len = match header[3] {
                1 => 4,
                4 => 16,
                _ => panic!("ошибка SOCKS должна иметь IP bind адрес"),
            };
            let _ = read_bounded(control, address_len).await.unwrap();
            let mut port = [0; 2];
            control.read_exact(&mut port).await.unwrap();
            return Err(header[1]);
        }
        assert_eq!(header[2], 0);
        let address = match header[3] {
            1 => {
                IpAddr::from(<[u8; 4]>::try_from(read_bounded(control, 4).await.unwrap()).unwrap())
            }
            4 => IpAddr::from(
                <[u8; 16]>::try_from(read_bounded(control, 16).await.unwrap()).unwrap(),
            ),
            _ => panic!("relay должен иметь IP адрес"),
        };
        let mut port = [0; 2];
        control.read_exact(&mut port).await.unwrap();
        let relay = SocketAddr::new(address, u16::from_be_bytes(port));
        assert!(relay.ip().is_loopback());
        assert_ne!(relay.port(), 0);
        Ok(relay)
    }

    fn socks_udp_packet(fake_ip: IpAddr, port: u16, frag: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0, 0, frag];
        encode_ip(&mut packet, fake_ip);
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    #[tokio::test]
    async fn udp_relay_maps_domain_rejects_injection_and_tracks_controls() {
        проверить_udp_после_смены_аренды("replacement.example", false).await;
    }

    #[tokio::test]
    async fn повторная_выдача_fake_ip_не_оживляет_udp_ассоциацию() {
        проверить_udp_после_смены_аренды("example.org", false).await;
    }

    #[tokio::test]
    async fn повторная_выдача_fake_ip_отбрасывает_запоздалый_udp_ответ() {
        проверить_udp_после_смены_аренды("example.org", true).await;
    }

    async fn проверить_udp_после_смены_аренды(
        имя: &'static str,
        поздний_ответ: bool,
    ) {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_relay_addr = upstream_udp.local_addr().unwrap();
        let (ответить, ждать_ответа) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut control, _) = upstream_listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, METHOD_USER_PASS]);
            control.write_all(&[5, METHOD_USER_PASS]).await.unwrap();
            let mut auth_header = [0; 2];
            control.read_exact(&mut auth_header).await.unwrap();
            let mut username = vec![0; usize::from(auth_header[1])];
            control.read_exact(&mut username).await.unwrap();
            let mut password_len = [0; 1];
            control.read_exact(&mut password_len).await.unwrap();
            let mut password = vec![0; usize::from(password_len[0])];
            control.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"core-user");
            assert_eq!(password, b"core-secret");
            control.write_all(&[1, 0]).await.unwrap();
            let mut request = [0; 10];
            control.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 3, 0, 1]);
            assert_eq!(&request[4..8], &[127, 0, 0, 1]);
            assert_ne!(&request[8..], &[0, 0]);
            let mut reply = vec![5, 0, 0];
            encode_ip(&mut reply, upstream_relay_addr.ip());
            reply.extend_from_slice(&upstream_relay_addr.port().to_be_bytes());
            control.write_all(&reply).await.unwrap();

            let mut packet = [0; MAX_UDP_PACKET_LEN + 1];
            let (length, client) = upstream_udp.recv_from(&mut packet).await.unwrap();
            let (domain, port, payload) = parse_upstream_udp(&packet[..length]).unwrap();
            assert_eq!(domain, "example.org");
            assert_eq!(port, 5353);
            assert_eq!(payload, b"request");

            let bridge_source = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    request[4], request[5], request[6], request[7],
                )),
                u16::from_be_bytes([request[8], request[9]]),
            );
            let rogue_relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let wrong_peer = {
                let mut response = vec![0, 0, 0, 3, 11];
                response.extend_from_slice(b"example.org");
                response.extend_from_slice(&5353u16.to_be_bytes());
                response.extend_from_slice(b"wrong-peer");
                response
            };
            rogue_relay
                .send_to(&wrong_peer, bridge_source)
                .await
                .unwrap();

            let forged = {
                let mut response = vec![0, 0, 0, 3, 11];
                response.extend_from_slice(b"attacker.io");
                response.extend_from_slice(&5353u16.to_be_bytes());
                response.extend_from_slice(b"forged");
                response
            };
            upstream_udp.send_to(&forged, client).await.unwrap();
            let valid = {
                let mut response = vec![0, 0, 0, 3, 11];
                response.extend_from_slice(b"example.org");
                response.extend_from_slice(&5353u16.to_be_bytes());
                response.extend_from_slice(b"answer");
                response
            };
            upstream_udp.send_to(&valid, client).await.unwrap();
            if поздний_ответ {
                ждать_ответа.await.unwrap();
                upstream_udp.send_to(&valid, client).await.unwrap();
            }
            let mut unexpected = [0; MAX_UDP_PACKET_LEN + 1];
            let mut eof = [0; 1];
            let length = timeout(Duration::from_secs(2), control.read(&mut eof))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(length, 0);
            assert!(
                timeout(
                    Duration::from_millis(30),
                    upstream_udp.recv_from(&mut unexpected)
                )
                .await
                .is_err(),
                "Движок получил UDP-пакет после смены аренды Fake-IP"
            );
        });

        let bridge_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let bridge_addr = bridge_listener.local_addr().unwrap();
        let incoming_auth = credentials();
        let upstream_auth =
            SocksCredentials::new(b"core-user", b"core-secret").unwrap_or_else(|_| unreachable!());
        let isolation = WorkerOnlyLoopbackIsolation::verified_by(|| true).unwrap();
        let fake_ip = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 55));
        let mapping_mode = Arc::new(AtomicU8::new(0));
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let resolver_mode = Arc::clone(&mapping_mode);
        let resolver_calls_inner = Arc::clone(&resolver_calls);
        let bridge = tokio::spawn(async move {
            let (control, _) = bridge_listener.accept().await?;
            let (_sender, cancellation) = Cancellation::new();
            handle_flow(
                control,
                upstream_addr,
                &incoming_auth,
                &upstream_auth,
                Some(&isolation),
                move |ip| {
                    if ip != fake_ip {
                        return None;
                    }
                    resolver_calls_inner.fetch_add(1, Ordering::SeqCst);
                    match resolver_mode.load(Ordering::SeqCst) {
                        0 => mapping(ip, "example.org", 10),
                        1 => None,
                        _ => mapping(ip, имя, 20),
                    }
                },
                cancellation,
            )
            .await
        });
        let mut client_control = TcpStream::connect(bridge_addr).await.unwrap();
        let client_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let relay = udp_client_handshake(
            &mut client_control,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            b"secret",
        )
        .await
        .unwrap();

        let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client_udp
            .send_to(
                &socks_udp_packet(
                    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 99)),
                    5353,
                    0,
                    b"unknown-fake-ip",
                ),
                relay,
            )
            .await
            .unwrap();
        client_udp
            .send_to(&socks_udp_packet(fake_ip, 5353, 1, b"fragmented"), relay)
            .await
            .unwrap();
        client_udp
            .send_to(&socks_udp_packet(fake_ip, 5353, 0, b"request"), relay)
            .await
            .unwrap();
        let mut response = [0; MAX_UDP_PACKET_LEN + 1];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, relay);
        let expected = socks_udp_packet(fake_ip, 5353, 0, b"answer");
        assert_eq!(&response[..length], expected);
        mapping_mode.store(1, Ordering::SeqCst);
        client_udp
            .send_to(
                &socks_udp_packet(fake_ip, 5353, 0, b"expired-mapping"),
                relay,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while resolver_calls.load(Ordering::SeqCst) < 4 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(!bridge.is_finished());
        assert!(
            tokio::time::timeout(
                Duration::from_millis(30),
                client_udp.recv_from(&mut response)
            )
            .await
            .is_err()
        );
        mapping_mode.store(2, Ordering::SeqCst);
        if поздний_ответ {
            ответить.send(()).unwrap();
        } else {
            client_udp
                .send_to(
                    &socks_udp_packet(fake_ip, 5353, 0, b"replaced-mapping"),
                    relay,
                )
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while resolver_calls.load(Ordering::SeqCst) < 5 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(30),
                client_udp.recv_from(&mut response)
            )
            .await
            .is_err()
        );
        attacker
            .send_to(
                &socks_udp_packet(
                    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 55)),
                    5353,
                    0,
                    b"late-injection",
                ),
                relay,
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), attacker.recv(&mut response))
                .await
                .is_err()
        );
        drop(client_control);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), bridge)
                .await
                .unwrap()
                .unwrap(),
            Err(FakeFlowError::UnknownFakeIp)
        ));
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn udp_rejects_unspecified_source_without_isolation_proof() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let bridge_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let bridge_addr = bridge_listener.local_addr().unwrap();
        let incoming_auth = credentials();
        let upstream_auth =
            SocksCredentials::new(b"core-user", b"core-secret").unwrap_or_else(|_| unreachable!());
        let bridge = tokio::spawn(async move {
            let (control, _) = bridge_listener.accept().await?;
            let (_sender, cancellation) = Cancellation::new();
            handle_udp_associate(
                control,
                upstream_addr,
                &incoming_auth,
                &upstream_auth,
                None,
                |ip| mapping(ip, "example.org", 10),
                cancellation,
            )
            .await
        });
        let mut client_control = TcpStream::connect(bridge_addr).await.unwrap();
        assert_eq!(
            udp_client_handshake(
                &mut client_control,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                b"secret",
            )
            .await,
            Err(2)
        );
        drop(client_control);
        assert!(matches!(
            bridge.await.unwrap(),
            Err(FakeFlowError::UdpPeerRejected)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(30), upstream_listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn udp_association_ends_when_control_closes() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let bridge_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let bridge_addr = bridge_listener.local_addr().unwrap();
        let incoming_auth = credentials();
        let upstream_auth =
            SocksCredentials::new(b"core-user", b"core-secret").unwrap_or_else(|_| unreachable!());
        let isolation = WorkerOnlyLoopbackIsolation::verified_by(|| true).unwrap();
        let bridge = tokio::spawn(async move {
            let (control, _) = bridge_listener.accept().await?;
            let (_sender, cancellation) = Cancellation::new();
            handle_udp_associate(
                control,
                upstream_addr,
                &incoming_auth,
                &upstream_auth,
                Some(&isolation),
                |_| None,
                cancellation,
            )
            .await
        });
        let mut client_control = TcpStream::connect(bridge_addr).await.unwrap();
        let client_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let _relay = udp_client_handshake(
            &mut client_control,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            b"secret",
        )
        .await
        .unwrap();
        drop(client_control);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), bridge)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), upstream_listener.accept())
                .await
                .is_err()
        );
        drop(client_udp);
    }
}
