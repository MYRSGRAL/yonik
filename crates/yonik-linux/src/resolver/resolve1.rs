//! Read-only adapter and narrowly scoped per-link writes for systemd-resolved.
//!
//! Before preparation and again before apply, the caller must verify that the
//! ifindex still identifies its own TUN interface. If an apply result has
//! `cleanup_required`, the caller must destroy that TUN lifetime; this module
//! never calls RevertLink or repeats an ambiguous mutation. The caller must keep
//! its interface-owner guard alive across apply and arrange the same cleanup if
//! its task is cancelled or dropped. D-Bus has no compare-and-set for link DNS,
//! so another network manager can still race between the last read and a write.

use super::ResolverError;
use crate::{
    Cancellation,
    helper::systemd_network_service::{Daemon, bind_resolved},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use zbus::{
    Connection, Proxy,
    zvariant::{OwnedObjectPath, OwnedValue},
};

const SERVICE: &str = "org.freedesktop.resolve1";
const PATH: &str = "/org/freedesktop/resolve1";
const MANAGER: &str = "org.freedesktop.resolve1.Manager";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const LINK: &str = "org.freedesktop.resolve1.Link";
const MAX_ENTRIES: usize = 4096;
const MAX_ROUTE_DOMAINS: usize = 256;
const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
type ManagerDnsServerEx = (i32, i32, Vec<u8>, u16, String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resolve1Scope {
    Global,
    Link(u32),
}

#[derive(Clone, PartialEq, Eq)]
pub struct Resolve1Endpoint {
    /// `Global` соответствует D-Bus ifindex=0; `Link` сохраняет исходный ifindex.
    pub scope: Resolve1Scope,
    pub address: IpAddr,
    /// При отсутствии явного порта используется 53 для DNS или 853 для TLS.
    pub port: u16,
    pub port_inferred: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Resolve1Domain {
    pub scope: Resolve1Scope,
    pub name: String,
    pub route_only: bool,
}

impl std::fmt::Debug for Resolve1Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolve1Endpoint(<скрыто>)")
    }
}
impl std::fmt::Debug for Resolve1Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolve1Domain(<скрыто>)")
    }
}

/// Неатомарное чтение свойств Manager: systemd может менять DNS между Get-вызовами.
#[derive(Clone, PartialEq, Eq)]
pub struct Resolve1Snapshot {
    pub endpoints: Vec<Resolve1Endpoint>,
    pub domains: Vec<Resolve1Domain>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resolve1TunSnapshot {
    pub(crate) config: Resolve1Snapshot,
    pub(crate) fallback_only: bool,
    pub(crate) global_transport: Option<Resolve1Transport>,
    /// По одному элементу на config.endpoints, включая глобальные DNS с %ifindex.
    pub(crate) sockets: Vec<Resolve1Socket>,
    pub(crate) daemon: Option<Daemon>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resolve1Transport {
    Plain,
    StrictTls,
    OpportunisticTls,
}

impl Resolve1Transport {
    fn parse(value: &str) -> Result<Self, ResolverError> {
        match value {
            "no" => Ok(Self::Plain),
            "yes" => Ok(Self::StrictTls),
            "opportunistic" => Ok(Self::OpportunisticTls),
            _ => Err(ResolverError::Unsupported),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Resolve1Socket {
    pub(crate) route_link: Option<u32>,
    pub(crate) transport: Resolve1Transport,
    // Учитываем изменение SNI при сверке, даже если IP и порт совпадают.
    server_name: Option<String>,
}

impl std::fmt::Debug for Resolve1Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolve1Socket(<скрыто>)")
    }
}
impl std::fmt::Debug for Resolve1Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolve1Snapshot")
            .field("endpoint_count", &self.endpoints.len())
            .field("domain_count", &self.domains.len())
            .finish()
    }
}

/// Читает системную D-Bus шину. Наличие resolve1 на ней само по себе не доказывает,
/// что системные приложения направляют DNS через этот daemon.
pub async fn read_resolve1_snapshot(
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<Resolve1Snapshot, ResolverError> {
    Ok(read_snapshot(cancel, timeout, SnapshotScope::Configured)
        .await?
        .config)
}

pub(crate) async fn read_resolve1_tun_snapshot(
    cancel: &mut Cancellation,
    timeout: Duration,
    own_link: Option<u32>,
) -> Result<Resolve1TunSnapshot, ResolverError> {
    read_snapshot(cancel, timeout, SnapshotScope::Tun { own_link }).await
}

#[derive(Clone, Copy)]
enum SnapshotScope {
    Configured,
    Tun { own_link: Option<u32> },
}

async fn read_snapshot(
    cancel: &mut Cancellation,
    timeout: Duration,
    scope: SnapshotScope,
) -> Result<Resolve1TunSnapshot, ResolverError> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(ResolverError::Limit);
    }
    tokio::time::timeout(timeout, async {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ResolverError::Cancelled),
            result = async {
                let connection = Connection::system().await.map_err(bus_error)?;
                let mut snapshot = read_connection(&connection, scope).await?;
                if snapshot.sockets.iter().any(|socket| socket.transport == Resolve1Transport::StrictTls) {
                    let (verified, daemon) = bind_resolved(async |connection, expected_owner| {
                        read_connection_for_owner(connection, scope, expected_owner).await
                    }).await?;
                    if verified != snapshot {
                        return Err(ResolverError::NetworkChanged);
                    }
                    snapshot.daemon = Some(daemon);
                }
                Ok(snapshot)
            } => result,
        }
    })
    .await
    .map_err(|_| ResolverError::Timeout)?
}

async fn read_connection(
    connection: &Connection,
    scope: SnapshotScope,
) -> Result<Resolve1TunSnapshot, ResolverError> {
    let owner_name = owner(connection).await?;
    read_connection_for_owner(connection, scope, &owner_name).await
}

async fn read_connection_for_owner(
    connection: &Connection,
    scope: SnapshotScope,
    owner_name: &str,
) -> Result<Resolve1TunSnapshot, ResolverError> {
    let proxy = Proxy::new(connection, owner_name, PATH, PROPERTIES)
        .await
        .map_err(bus_error)?;
    let domains = property::<Vec<(i32, String, bool)>>(&proxy, "Domains").await?;
    let mut snapshot = match scope {
        SnapshotScope::Configured => decode(property(&proxy, "DNS").await?, domains)?,
        SnapshotScope::Tun { .. } => decode(Vec::new(), domains)?,
    };
    let mut fallback_only = false;
    let mut global_transport = None;
    let mut sockets = Vec::new();
    if let SnapshotScope::Tun { own_link } = scope {
        let rows = property::<Vec<ManagerDnsServerEx>>(&proxy, "DNSEx").await?;
        let transport = Resolve1Transport::parse(&property::<String>(&proxy, "DNSOverTLS").await?)?;
        global_transport = Some(transport);
        (snapshot.endpoints, sockets) =
            read_tun_endpoints(connection, owner_name, rows, own_link, transport).await?;
        if let Some(index) = own_link {
            let scope = Resolve1Scope::Link(index);
            snapshot.domains.retain(|domain| domain.scope != scope);
        }
        if !has_default_dns(connection, owner_name, &snapshot).await? {
            let fallback = property::<Vec<ManagerDnsServerEx>>(&proxy, "FallbackDNSEx").await?;
            if !fallback.is_empty() {
                fallback_only = snapshot.endpoints.is_empty();
                if fallback.len() > MAX_ENTRIES {
                    return Err(ResolverError::Limit);
                }
                for row in fallback {
                    if row.0 != 0 {
                        if fallback_only {
                            return Err(ResolverError::Unsupported);
                        }
                        continue;
                    }
                    let mut endpoint = decode_ex_endpoint(&row)?;
                    sockets.push(tun_socket(&mut endpoint, None, transport, row.4));
                    snapshot.endpoints.push(endpoint);
                }
            }
        }
    }
    if owner(connection).await? != owner_name {
        return Err(ResolverError::NetworkChanged);
    }
    Ok(Resolve1TunSnapshot {
        config: snapshot,
        fallback_only,
        global_transport,
        sockets,
        daemon: None,
    })
}

async fn has_default_dns(
    connection: &Connection,
    owner: &str,
    snapshot: &Resolve1Snapshot,
) -> Result<bool, ResolverError> {
    let mut links = HashSet::new();
    for endpoint in &snapshot.endpoints {
        let Resolve1Scope::Link(index) = endpoint.scope else {
            return Ok(true);
        };
        links.insert(index);
    }
    for index in links {
        let path = get_link_path(connection, owner, index).await?;
        let proxy = Proxy::new(connection, owner, path.as_str(), PROPERTIES)
            .await
            .map_err(bus_error)?;
        if property_for::<bool>(&proxy, LINK, "DefaultRoute").await? {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn read_tun_endpoints(
    connection: &Connection,
    owner: &str,
    rows: Vec<ManagerDnsServerEx>,
    own_link: Option<u32>,
    global_transport: Resolve1Transport,
) -> Result<(Vec<Resolve1Endpoint>, Vec<Resolve1Socket>), ResolverError> {
    if rows.len() > MAX_ENTRIES {
        return Err(ResolverError::Limit);
    }
    let mut interfaces = HashMap::new();
    let mut endpoints = Vec::with_capacity(rows.len());
    let mut sockets = Vec::with_capacity(rows.len());
    for row in rows {
        let mut endpoint = decode_ex_endpoint(&row)?;
        let physical_link = match endpoint.scope {
            Resolve1Scope::Global => None,
            Resolve1Scope::Link(index) => Some(index),
        };
        if physical_link.is_some() && physical_link == own_link {
            continue;
        }
        // Manager.DNSEx сообщает ifindex даже для глобальной записи DNS=…%link.
        // Только сервер из Link.DNSEx использует транспорт этого линка.
        let (_, family, bytes, port, name) = row;
        let mut transport = global_transport;
        let key = (family, bytes, port, name);
        if let Some(index) = physical_link {
            if let std::collections::hash_map::Entry::Vacant(slot) = interfaces.entry(index) {
                let path = get_link_path(connection, owner, index).await?;
                let proxy = Proxy::new(connection, owner, path.as_str(), PROPERTIES)
                    .await
                    .map_err(bus_error)?;
                let entries = property_for::<Vec<LinkDnsServerEx>>(&proxy, LINK, "DNSEx").await?;
                if entries.len() > MAX_ENTRIES {
                    return Err(ResolverError::Limit);
                }
                let mode = property_for::<String>(&proxy, LINK, "DNSOverTLS").await?;
                slot.insert((
                    entries.into_iter().collect::<HashSet<_>>(),
                    Resolve1Transport::parse(&mode)?,
                ));
            }
            let (entries, link_transport) =
                interfaces.get_mut(&index).ok_or(ResolverError::Malformed)?;
            if entries.remove(&key) {
                transport = *link_transport;
            } else {
                endpoint.scope = Resolve1Scope::Global;
            }
        }
        sockets.push(tun_socket(&mut endpoint, physical_link, transport, key.3));
        endpoints.push(endpoint);
    }
    // Чтения неатомарны: остаточная запись на линке означает, что
    // список Manager и список Link не описывают одну и ту же конфигурацию.
    if interfaces.values().any(|(entries, _)| !entries.is_empty()) {
        return Err(ResolverError::NetworkChanged);
    }
    Ok((endpoints, sockets))
}

fn tun_socket(
    endpoint: &mut Resolve1Endpoint,
    route_link: Option<u32>,
    transport: Resolve1Transport,
    name: String,
) -> Resolve1Socket {
    let tls = transport != Resolve1Transport::Plain;
    if tls && endpoint.port_inferred {
        endpoint.port = DOT_PORT;
    }
    Resolve1Socket {
        route_link,
        transport,
        server_name: (tls && !name.is_empty()).then_some(name),
    }
}

fn decode_ex_endpoint(row: &ManagerDnsServerEx) -> Result<Resolve1Endpoint, ResolverError> {
    let (index, family, bytes, port, name) = row;
    // TLS-соединение открывает resolved. Имя нужно только для сверки снимков.
    if name.len() > MAX_DOMAIN_LENGTH + 1 || name.as_bytes().contains(&0) {
        return Err(ResolverError::Malformed);
    }
    decode_endpoint(*index, *family, bytes, *port)
}

async fn owner(connection: &Connection) -> Result<String, ResolverError> {
    let reply = connection
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetNameOwner",
            &(SERVICE,),
        )
        .await
        .map_err(bus_error)?;
    let value: String = reply
        .body()
        .deserialize()
        .map_err(|_| ResolverError::Malformed)?;
    if zbus::names::UniqueName::try_from(value.as_str()).is_err() {
        return Err(ResolverError::Untrusted);
    }
    Ok(value)
}

async fn property<T>(proxy: &Proxy<'_>, name: &str) -> Result<T, ResolverError>
where
    T: TryFrom<OwnedValue>,
{
    let value: OwnedValue = proxy
        .call("Get", &(MANAGER, name))
        .await
        .map_err(bus_error)?;
    T::try_from(value).map_err(|_| ResolverError::Malformed)
}

fn decode(
    dns: Vec<(i32, i32, Vec<u8>)>,
    domains: Vec<(i32, String, bool)>,
) -> Result<Resolve1Snapshot, ResolverError> {
    if dns.len() > MAX_ENTRIES || domains.len() > MAX_ENTRIES {
        return Err(ResolverError::Limit);
    }
    let endpoints = dns
        .into_iter()
        .map(|(index, family, bytes)| decode_endpoint(index, family, &bytes, 0))
        .collect::<Result<Vec<_>, _>>()?;
    let mut output_domains = Vec::with_capacity(domains.len());
    for (index, name, route_only) in domains {
        let scope = decode_scope(index)?;
        if name.is_empty() || name.len() > 1024 || name.as_bytes().contains(&0) {
            return Err(ResolverError::Malformed);
        }
        output_domains.push(Resolve1Domain {
            scope,
            name,
            route_only,
        });
    }
    Ok(Resolve1Snapshot {
        endpoints,
        domains: output_domains,
    })
}

fn decode_endpoint(
    index: i32,
    family: i32,
    bytes: &[u8],
    port: u16,
) -> Result<Resolve1Endpoint, ResolverError> {
    let address = match (family, bytes) {
        (2, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        (10, bytes) if bytes.len() == 16 => {
            let address: [u8; 16] = bytes.try_into().map_err(|_| ResolverError::Malformed)?;
            IpAddr::V6(Ipv6Addr::from(address))
        }
        _ => return Err(ResolverError::Malformed),
    };
    Ok(Resolve1Endpoint {
        scope: decode_scope(index)?,
        address,
        port: if port == 0 { DNS_PORT } else { port },
        port_inferred: port == 0,
    })
}

fn decode_scope(index: i32) -> Result<Resolve1Scope, ResolverError> {
    match index {
        0 => Ok(Resolve1Scope::Global),
        value if value > 0 => Ok(Resolve1Scope::Link(value as u32)),
        _ => Err(ResolverError::Malformed),
    }
}

fn bus_error(error: zbus::Error) -> ResolverError {
    match error {
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied" =>
        {
            ResolverError::PermissionDenied
        }
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.NameHasNoOwner" =>
        {
            ResolverError::Unavailable
        }
        zbus::Error::MethodError(_, _, _) => ResolverError::Malformed,
        _ => ResolverError::Unavailable,
    }
}

/// Read-only этап. Принимает только новую для resolve1 per-link конфигурацию:
/// существующие DNS/domain настройки считаются чужими и не перезаписываются.
/// Caller предварительно обязан подтвердить, что `ifindex` принадлежит его TUN.
/// Экспорт из `resolver.rs` отложен до интеграции caller.
pub async fn prepare_link_dns(
    ifindex: u32,
    marker: IpAddr,
    route_domains: &[String],
    timeout: Duration,
) -> Result<Resolve1Prepared, ResolverError> {
    let domains = Resolve1DomainPublication::scoped(route_domains);
    prepare_dns_on_owned_link(
        ifindex,
        &[SocketAddr::new(marker, DNS_PORT)],
        domains,
        false,
        timeout,
    )
    .await
}

/// В режиме FallbackDNS переносим выбор сервера на собственный TUN, иначе
/// старый resolved перестаёт обслуживать обычные имена при появлении DNS линка.
pub(crate) async fn prepare_fallback_link_dns(
    ifindex: u32,
    servers: &[SocketAddr],
    route_domains: &[String],
    original_domains: &[Resolve1Domain],
    timeout: Duration,
) -> Result<Resolve1Prepared, ResolverError> {
    let domains = Resolve1DomainPublication::fallback(route_domains, original_domains);
    prepare_dns_on_owned_link(ifindex, servers, domains, true, timeout).await
}

type LinkDomain = (String, bool);

struct Resolve1DomainPublication {
    link: Vec<LinkDomain>,
    mirrored_global: Option<Vec<LinkDomain>>,
}

impl Resolve1DomainPublication {
    fn scoped(route_domains: &[String]) -> Self {
        Self {
            link: route_domains
                .iter()
                .cloned()
                .map(|name| (name, true))
                .collect(),
            mirrored_global: None,
        }
    }

    fn fallback(route_domains: &[String], original: &[Resolve1Domain]) -> Self {
        let global = original
            .iter()
            .filter(|domain| domain.scope == Resolve1Scope::Global)
            .map(|domain| (domain.name.clone(), domain.route_only))
            .collect::<Vec<_>>();
        // Порядок и флаги определяют поиск коротких имён. Копируем только
        // существующие настройки, в том числе ~. лишь при наличии у resolved.
        Self {
            link: global
                .iter()
                .cloned()
                .chain(route_domains.iter().cloned().map(|name| (name, true)))
                .collect(),
            mirrored_global: Some(global),
        }
    }
}

async fn prepare_dns_on_owned_link(
    ifindex: u32,
    servers: &[SocketAddr],
    domains: Resolve1DomainPublication,
    default_route: bool,
    timeout: Duration,
) -> Result<Resolve1Prepared, ResolverError> {
    validate_link_request(ifindex, &domains.link)?;
    if servers.is_empty() || servers.len() > MAX_ENTRIES {
        return Err(ResolverError::Limit);
    }
    for server in servers {
        validate_marker(server.ip())?;
        if server.port() == 0 {
            return Err(ResolverError::Malformed);
        }
    }
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(ResolverError::Limit);
    }
    tokio::time::timeout(timeout, async {
        let connection = Connection::system().await.map_err(bus_error)?;
        prepare_on_connection(connection, ifindex, servers, domains, default_route).await
    })
    .await
    .map_err(|_| ResolverError::Timeout)?
}

/// Apply errors after dispatching the first write require dropping the caller-owned TUN
/// interface. That interface lifetime is the cleanup mechanism for ambiguous and
/// partial outcomes; this module deliberately never calls RevertLink or retries.
/// Экспорт из `resolver.rs` отложен до интеграции caller.
pub async fn apply_link_dns(
    prepared: &Resolve1Prepared,
    timeout: Duration,
) -> Result<(), Resolve1ApplyError> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(Resolve1ApplyError {
            error: ResolverError::Limit,
            cleanup_required: false,
        });
    }
    let mut mutation_started = false;
    let result =
        tokio::time::timeout(timeout, apply_prepared(prepared, &mut mutation_started)).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(Resolve1ApplyError {
            error,
            cleanup_required: mutation_started,
        }),
        Err(_) => Err(Resolve1ApplyError {
            error: ResolverError::Timeout,
            cleanup_required: mutation_started,
        }),
    }
}

pub struct Resolve1Prepared {
    connection: Connection,
    owner: String,
    ifindex: i32,
    link_path: OwnedObjectPath,
    dns_ex: Vec<LinkDnsServerEx>,
    default_route: bool,
    initial_transport: Resolve1Transport,
    domains: Resolve1DomainPublication,
}

impl Resolve1Prepared {
    pub(crate) async fn verify_active(&self) -> Result<(), ResolverError> {
        let connection = &self.connection;
        verify_owner(connection, &self.owner).await?;
        let path = get_link_path(connection, &self.owner, self.ifindex as u32).await?;
        if path != self.link_path {
            return Err(ResolverError::NetworkChanged);
        }
        let expected = Resolve1LinkConfig {
            dns: self.legacy_dns(),
            dns_ex: self.dns_ex.clone(),
            default_route: self.default_route,
            transport: Resolve1Transport::Plain,
            domains: self.domains.link.clone(),
        };
        if read_link_config(connection, &self.owner, &path).await? != expected {
            return Err(ResolverError::NetworkChanged);
        }
        ensure_manager_domains(
            &manager_domains(connection, &self.owner).await?,
            self.ifindex as u32,
            &self.domains,
            true,
        )?;
        verify_owner(connection, &self.owner).await
    }

    fn legacy_dns(&self) -> Vec<(i32, Vec<u8>)> {
        self.dns_ex
            .iter()
            .map(|(family, bytes, _, _)| (*family, bytes.clone()))
            .collect()
    }
}

impl std::fmt::Debug for Resolve1Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolve1Prepared")
            .field("ifindex", &self.ifindex)
            .field("domain_count", &self.domains.link.len())
            .field("dns_count", &self.dns_ex.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolve1ApplyError {
    pub error: ResolverError,
    /// Caller обязан уничтожить свой TUN lifetime, чтобы resolve1 удалил link config.
    pub cleanup_required: bool,
}

async fn prepare_on_connection(
    connection: Connection,
    ifindex: u32,
    servers: &[SocketAddr],
    domains: Resolve1DomainPublication,
    default_route: bool,
) -> Result<Resolve1Prepared, ResolverError> {
    validate_link_request(ifindex, &domains.link)?;
    let owner = owner(&connection).await?;
    let link_path = get_link_path(&connection, &owner, ifindex).await?;
    let state = read_link_config(&connection, &owner, &link_path).await?;
    if !state.dns.is_empty() || !state.dns_ex.is_empty() || !state.domains.is_empty() {
        return Err(ResolverError::Untrusted);
    }
    ensure_manager_domains(
        &manager_domains(&connection, &owner).await?,
        ifindex,
        &domains,
        false,
    )?;
    verify_owner(&connection, &owner).await?;
    Ok(Resolve1Prepared {
        connection,
        owner,
        ifindex: i32::try_from(ifindex).map_err(|_| ResolverError::Limit)?,
        link_path,
        dns_ex: servers
            .iter()
            .map(|server| {
                let (family, bytes) = encode_address(server.ip());
                let port = if server.port() == DNS_PORT {
                    0
                } else {
                    server.port()
                };
                (family, bytes, port, String::new())
            })
            .collect(),
        default_route,
        initial_transport: state.transport,
        domains,
    })
}

async fn apply_prepared(
    prepared: &Resolve1Prepared,
    mutation_started: &mut bool,
) -> Result<(), ResolverError> {
    let connection = &prepared.connection;
    verify_owner(connection, &prepared.owner).await?;
    let link_path = get_link_path(connection, &prepared.owner, prepared.ifindex as u32).await?;
    if link_path != prepared.link_path {
        return Err(ResolverError::NetworkChanged);
    }
    let current = read_link_config(connection, &prepared.owner, &link_path).await?;
    if !current.dns.is_empty() || !current.dns_ex.is_empty() || !current.domains.is_empty() {
        return Err(ResolverError::Untrusted);
    }
    if current.transport != prepared.initial_transport {
        return Err(ResolverError::NetworkChanged);
    }
    ensure_manager_domains(
        &manager_domains(connection, &prepared.owner).await?,
        prepared.ifindex as u32,
        &prepared.domains,
        false,
    )?;

    let manager = Proxy::new(connection, prepared.owner.as_str(), PATH, MANAGER)
        .await
        .map_err(bus_error)?;
    let expected_domains = &prepared.domains.link;
    // Routing is installed first, before this interface receives DNS queries.
    *mutation_started = true;
    if current.transport != Resolve1Transport::Plain {
        // Маркер DNS обслуживается локально по обычному DNS. Настройка
        // касается только собственного TUN, остальные области сохраняют TLS.
        let _: () = manager
            .call("SetLinkDNSOverTLS", &(prepared.ifindex, "no"))
            .await
            .map_err(bus_error)?;
    }
    let _: () = manager
        .call(
            "SetLinkDefaultRoute",
            &(prepared.ifindex, prepared.default_route),
        )
        .await
        .map_err(bus_error)?;
    let _: () = manager
        .call("SetLinkDomains", &(prepared.ifindex, expected_domains))
        .await
        .map_err(bus_error)?;

    verify_owner(connection, &prepared.owner).await?;
    let after_domains = read_link_config(connection, &prepared.owner, &link_path).await?;
    if !after_domains.dns.is_empty()
        || !after_domains.dns_ex.is_empty()
        || after_domains.default_route != prepared.default_route
        || after_domains.transport != Resolve1Transport::Plain
        || &after_domains.domains != expected_domains
    {
        return Err(ResolverError::NetworkChanged);
    }
    ensure_manager_domains(
        &manager_domains(connection, &prepared.owner).await?,
        prepared.ifindex as u32,
        &prepared.domains,
        true,
    )?;

    // Mutation outcomes may be ambiguous at timeout/disconnect; never retry.
    if prepared.dns_ex.iter().any(|(_, _, port, _)| *port != 0) {
        let _: () = manager
            .call("SetLinkDNSEx", &(prepared.ifindex, &prepared.dns_ex))
            .await
            .map_err(bus_error)?;
    } else {
        let _: () = manager
            .call("SetLinkDNS", &(prepared.ifindex, prepared.legacy_dns()))
            .await
            .map_err(bus_error)?;
    }

    prepared.verify_active().await
}

impl std::fmt::Display for Resolve1ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for Resolve1ApplyError {}

type LinkDnsServerEx = (i32, Vec<u8>, u16, String);

#[derive(PartialEq, Eq)]
struct Resolve1LinkConfig {
    dns: Vec<(i32, Vec<u8>)>,
    dns_ex: Vec<LinkDnsServerEx>,
    default_route: bool,
    transport: Resolve1Transport,
    domains: Vec<(String, bool)>,
}

async fn get_link_path(
    connection: &Connection,
    owner: &str,
    ifindex: u32,
) -> Result<OwnedObjectPath, ResolverError> {
    let ifindex = i32::try_from(ifindex).map_err(|_| ResolverError::Limit)?;
    let manager = Proxy::new(connection, owner, PATH, MANAGER)
        .await
        .map_err(bus_error)?;
    let path: OwnedObjectPath = manager
        .call("GetLink", &(ifindex,))
        .await
        .map_err(bus_error)?;
    let expected = link_object_path(ifindex);
    if path.as_str() != expected {
        return Err(ResolverError::Untrusted);
    }
    Ok(path)
}

async fn read_link_config(
    connection: &Connection,
    owner: &str,
    path: &OwnedObjectPath,
) -> Result<Resolve1LinkConfig, ResolverError> {
    let proxy = Proxy::new(connection, owner, path.as_str(), PROPERTIES)
        .await
        .map_err(bus_error)?;
    let dns = property_for::<Vec<(i32, Vec<u8>)>>(&proxy, LINK, "DNS").await?;
    let dns_ex = property_for::<Vec<LinkDnsServerEx>>(&proxy, LINK, "DNSEx").await?;
    let default_route = property_for::<bool>(&proxy, LINK, "DefaultRoute").await?;
    let transport =
        Resolve1Transport::parse(&property_for::<String>(&proxy, LINK, "DNSOverTLS").await?)?;
    let domains = property_for::<Vec<(String, bool)>>(&proxy, LINK, "Domains").await?;
    if dns.len() > MAX_ENTRIES || dns_ex.len() > MAX_ENTRIES || domains.len() > MAX_ENTRIES {
        return Err(ResolverError::Limit);
    }
    for (family, bytes) in &dns {
        match (*family, bytes.len()) {
            (2, 4) | (10, 16) => {}
            _ => return Err(ResolverError::Malformed),
        }
    }
    for (family, bytes, _port, name) in &dns_ex {
        match (*family, bytes.len()) {
            (2, 4) | (10, 16) => {}
            _ => return Err(ResolverError::Malformed),
        }
        if name.len() > MAX_DOMAIN_LENGTH || name.as_bytes().contains(&0) {
            return Err(ResolverError::Malformed);
        }
    }
    if domains.iter().any(|(name, _)| !valid_domain(name)) {
        return Err(ResolverError::Malformed);
    }
    Ok(Resolve1LinkConfig {
        dns,
        dns_ex,
        default_route,
        transport,
        domains,
    })
}

async fn manager_domains(
    connection: &Connection,
    owner: &str,
) -> Result<Vec<(i32, String, bool)>, ResolverError> {
    let proxy = Proxy::new(connection, owner, PATH, PROPERTIES)
        .await
        .map_err(bus_error)?;
    let domains = property::<Vec<(i32, String, bool)>>(&proxy, "Domains").await?;
    if domains.len() > MAX_ENTRIES {
        return Err(ResolverError::Limit);
    }
    if domains.iter().any(|(_, name, _)| !valid_domain(name)) {
        return Err(ResolverError::Malformed);
    }
    Ok(domains)
}

fn ensure_manager_domains(
    current: &[(i32, String, bool)],
    ifindex: u32,
    publication: &Resolve1DomainPublication,
    must_be_present: bool,
) -> Result<(), ResolverError> {
    if let Some(global) = &publication.mirrored_global {
        let actual_global = current
            .iter()
            .filter(|(index, _, _)| *index == 0)
            .map(|(_, name, route_only)| (name, route_only));
        if actual_global.ne(global.iter().map(|(name, route_only)| (name, route_only))) {
            return Err(ResolverError::NetworkChanged);
        }
    } else if !publication.link.is_empty()
        && current
            .iter()
            .any(|(index, name, _)| *index == 0 && name == ".")
    {
        return Err(ResolverError::Untrusted);
    }
    let owned_index = ifindex as i32;
    let names = publication
        .link
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    if current.iter().any(|(index, name, _)| {
        *index != owned_index
            && (*index != 0 || publication.mirrored_global.is_none())
            && names.contains(&name.to_ascii_lowercase())
    }) {
        return Err(ResolverError::Untrusted);
    }
    let expected_link = if must_be_present {
        publication.link.as_slice()
    } else {
        &[]
    };
    let actual_link = current
        .iter()
        .filter(|(index, _, _)| *index == owned_index)
        .map(|(_, name, route_only)| (name, route_only));
    if actual_link.ne(expected_link
        .iter()
        .map(|(name, route_only)| (name, route_only)))
    {
        return Err(ResolverError::NetworkChanged);
    }
    Ok(())
}

async fn verify_owner(connection: &Connection, expected: &str) -> Result<(), ResolverError> {
    if owner(connection).await? == expected {
        Ok(())
    } else {
        Err(ResolverError::NetworkChanged)
    }
}

async fn property_for<T>(proxy: &Proxy<'_>, interface: &str, name: &str) -> Result<T, ResolverError>
where
    T: TryFrom<OwnedValue>,
{
    let value: OwnedValue = proxy
        .call("Get", &(interface, name))
        .await
        .map_err(bus_error)?;
    T::try_from(value).map_err(|_| ResolverError::Malformed)
}

fn encode_address(address: IpAddr) -> (i32, Vec<u8>) {
    match address {
        IpAddr::V4(address) => (2, address.octets().to_vec()),
        IpAddr::V6(address) => (10, address.octets().to_vec()),
    }
}

fn link_object_path(ifindex: i32) -> String {
    let decimal = ifindex.to_string();
    let mut component = format!("_{:02X}", decimal.as_bytes()[0]);
    component.push_str(&decimal[1..]);
    format!("{PATH}/link/{component}")
}

fn validate_link_request(ifindex: u32, domains: &[LinkDomain]) -> Result<(), ResolverError> {
    if ifindex == 0 || i32::try_from(ifindex).is_err() || domains.len() > MAX_ROUTE_DOMAINS {
        return Err(ResolverError::Limit);
    }
    let mut seen = HashSet::with_capacity(domains.len());
    for (domain, route_only) in domains {
        if !valid_domain(domain)
            || (domain == "." && !route_only)
            || !seen.insert(domain.to_ascii_lowercase())
        {
            return Err(ResolverError::Malformed);
        }
    }
    Ok(())
}

fn validate_marker(marker: IpAddr) -> Result<(), ResolverError> {
    if marker.is_unspecified() || marker.is_multicast() || marker.is_loopback() {
        return Err(ResolverError::Malformed);
    }
    Ok(())
}

fn valid_domain(domain: &str) -> bool {
    if domain == "." {
        return true;
    }
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_LENGTH
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PrivateBus(std::process::Child, String);
    impl PrivateBus {
        fn new() -> Self {
            use std::io::BufRead;
            let mut child = std::process::Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--print-address=1"])
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut address = String::new();
            std::io::BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut address)
                .unwrap();
            Self(child, address.trim().to_owned())
        }
        async fn connect(&self) -> Connection {
            zbus::connection::Builder::address(self.1.as_str())
                .unwrap()
                .build()
                .await
                .unwrap()
        }
    }
    impl Drop for PrivateBus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct ManagerFixture {
        dns: Vec<(i32, i32, Vec<u8>)>,
        domains: Vec<(i32, String, bool)>,
        tls: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    #[zbus::interface(name = "org.freedesktop.resolve1.Manager")]
    impl ManagerFixture {
        fn get_link(&self, index: i32) -> OwnedObjectPath {
            OwnedObjectPath::try_from(link_object_path(index)).unwrap()
        }

        #[zbus(property, name = "DNS")]
        fn dns(&self) -> Vec<(i32, i32, Vec<u8>)> {
            self.dns.clone()
        }
        #[zbus(property, name = "DNSEx")]
        fn dns_ex(&self) -> Vec<ManagerDnsServerEx> {
            self.dns
                .iter()
                .map(|(index, family, bytes)| {
                    let port = if *index == 7 { 1053 } else { 0 };
                    let name = if *index == 7 { "dns.example." } else { "" };
                    (*index, *family, bytes.clone(), port, name.into())
                })
                .collect()
        }
        #[zbus(property, name = "Domains")]
        fn domains(&self) -> Vec<(i32, String, bool)> {
            self.domains.clone()
        }
        #[zbus(property, name = "FallbackDNSEx")]
        fn fallback_dns_ex(&self) -> Vec<ManagerDnsServerEx> {
            vec![
                (0, 2, vec![192, 0, 2, 11], 0, String::new()),
                (0, 2, vec![192, 0, 2, 12], 53, String::new()),
                (0, 2, vec![192, 0, 2, 13], 1054, String::new()),
                (0, 2, vec![192, 0, 2, 14], 0, "tls.test".into()),
            ]
        }
        #[zbus(property, name = "DNSOverTLS")]
        fn dns_over_tls(&self) -> &str {
            if self.tls.load(std::sync::atomic::Ordering::Relaxed) {
                "yes"
            } else {
                "no"
            }
        }
    }

    #[derive(Default)]
    struct DefaultDnsRoute(
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    );

    #[zbus::interface(name = "org.freedesktop.resolve1.Link")]
    impl DefaultDnsRoute {
        #[zbus(property, name = "DefaultRoute")]
        fn default_route(&self) -> bool {
            self.0.load(std::sync::atomic::Ordering::Relaxed)
        }
        #[zbus(property, name = "DNSOverTLS")]
        fn dns_over_tls(&self) -> &str {
            if self.1.load(std::sync::atomic::Ordering::Relaxed) {
                "yes"
            } else {
                "no"
            }
        }
        #[zbus(property, name = "DNSEx")]
        fn dns_ex(&self) -> Vec<LinkDnsServerEx> {
            if self.2.load(std::sync::atomic::Ordering::Relaxed) {
                Vec::new()
            } else {
                vec![(2, vec![192, 0, 2, 7], 1053, "dns.example.".into())]
            }
        }
    }

    const TEST_IFINDEX: i32 = 13;
    const TEST_LINK_PATH: &str = "/org/freedesktop/resolve1/link/_313";

    #[derive(Default)]
    struct MutationState {
        dns: Vec<(i32, Vec<u8>)>,
        dns_ex: Vec<LinkDnsServerEx>,
        default_route: bool,
        domains: Vec<(String, bool)>,
        foreign_domains: Vec<(i32, String, bool)>,
        set_dns_calls: usize,
        set_domains_calls: usize,
        fail_dns: bool,
        fail_domains: bool,
        uses_tls: bool,
        ignore_plain_request: bool,
        inject_conflict_after_domains: bool,
        flip_global_flag_after_domains: bool,
        hide_dns_ex_after_domains: bool,
        events: Vec<&'static str>,
    }

    struct MutationManager(std::sync::Arc<std::sync::Mutex<MutationState>>);
    impl MutationManager {
        fn publish_dns(&self, ifindex: i32, dns_ex: Vec<LinkDnsServerEx>) -> zbus::fdo::Result<()> {
            assert_eq!(ifindex, TEST_IFINDEX);
            let mut state = self.0.lock().unwrap();
            state.set_dns_calls += 1;
            state.events.push("dns");
            if state.fail_dns {
                return Err(zbus::fdo::Error::Failed(
                    "fixture DNS failure after domains".into(),
                ));
            }
            state.dns = dns_ex
                .iter()
                .map(|(family, bytes, _, _)| (*family, bytes.clone()))
                .collect();
            state.dns_ex = dns_ex;
            Ok(())
        }
    }
    #[zbus::interface(name = "org.freedesktop.resolve1.Manager")]
    impl MutationManager {
        #[zbus(name = "GetLink")]
        fn get_link(&self, ifindex: i32) -> zbus::zvariant::OwnedObjectPath {
            assert_eq!(ifindex, TEST_IFINDEX);
            TEST_LINK_PATH.try_into().unwrap()
        }
        #[zbus(property, name = "Domains")]
        fn domains(&self) -> Vec<(i32, String, bool)> {
            let state = self.0.lock().unwrap();
            state
                .foreign_domains
                .iter()
                .cloned()
                .chain(
                    state
                        .domains
                        .iter()
                        .cloned()
                        .map(|(name, route_only)| (TEST_IFINDEX, name, route_only)),
                )
                .collect()
        }
        #[zbus(name = "SetLinkDNS")]
        fn set_link_dns(&self, ifindex: i32, dns: Vec<(i32, Vec<u8>)>) -> zbus::fdo::Result<()> {
            self.publish_dns(
                ifindex,
                dns.into_iter()
                    .map(|(family, bytes)| (family, bytes, 0, String::new()))
                    .collect(),
            )
        }

        #[zbus(name = "SetLinkDNSEx")]
        fn set_link_dns_ex(
            &self,
            ifindex: i32,
            entries: Vec<LinkDnsServerEx>,
        ) -> zbus::fdo::Result<()> {
            self.publish_dns(ifindex, entries)
        }

        #[zbus(name = "SetLinkDefaultRoute")]
        fn set_link_default_route(&self, ifindex: i32, default_route: bool) {
            assert_eq!(ifindex, TEST_IFINDEX);
            let mut state = self.0.lock().unwrap();
            state.events.push("default_route");
            state.default_route = default_route;
        }
        #[zbus(name = "SetLinkDNSOverTLS")]
        fn set_link_dns_over_tls(&self, ifindex: i32, mode: &str) {
            assert_eq!(ifindex, TEST_IFINDEX);
            assert_eq!(mode, "no");
            let mut state = self.0.lock().unwrap();
            state.events.push("plain");
            if !state.ignore_plain_request {
                state.uses_tls = false;
            }
        }
        #[zbus(name = "SetLinkDomains")]
        fn set_link_domains(
            &self,
            ifindex: i32,
            domains: Vec<(String, bool)>,
        ) -> zbus::fdo::Result<()> {
            assert_eq!(ifindex, TEST_IFINDEX);
            let mut state = self.0.lock().unwrap();
            state.set_domains_calls += 1;
            state.events.push("domains");
            if state.fail_domains {
                return Err(zbus::fdo::Error::Failed("fixture partial failure".into()));
            }
            state.domains = domains;
            if state.inject_conflict_after_domains {
                state.foreign_domains.push((0, "corp.example".into(), true));
            }
            if state.flip_global_flag_after_domains {
                state.foreign_domains[0].2 = true;
            }
            Ok(())
        }
    }

    struct MutationLink(std::sync::Arc<std::sync::Mutex<MutationState>>);
    #[zbus::interface(name = "org.freedesktop.resolve1.Link")]
    impl MutationLink {
        #[zbus(property, name = "DNSOverTLS")]
        fn dns_over_tls(&self) -> &str {
            if self.0.lock().unwrap().uses_tls {
                "yes"
            } else {
                "no"
            }
        }
        #[zbus(property, name = "DefaultRoute")]
        fn default_route(&self) -> bool {
            self.0.lock().unwrap().default_route
        }
        #[zbus(property, name = "DNS")]
        fn dns(&self) -> Vec<(i32, Vec<u8>)> {
            self.0.lock().unwrap().dns.clone()
        }
        #[zbus(property, name = "DNSEx")]
        fn dns_ex(&self) -> zbus::fdo::Result<Vec<LinkDnsServerEx>> {
            let state = self.0.lock().unwrap();
            if state.hide_dns_ex_after_domains && !state.domains.is_empty() {
                return Err(zbus::fdo::Error::Failed("fixture DNSEx unavailable".into()));
            }
            Ok(state.dns_ex.clone())
        }
        #[zbus(property, name = "Domains")]
        fn domains(&self) -> Vec<(String, bool)> {
            self.0.lock().unwrap().domains.clone()
        }
    }

    async fn mutation_fixture(
        state: std::sync::Arc<std::sync::Mutex<MutationState>>,
    ) -> (PrivateBus, Connection, Connection) {
        let bus = PrivateBus::new();
        let server = zbus::connection::Builder::address(bus.1.as_str())
            .unwrap()
            .name(SERVICE)
            .unwrap()
            .serve_at(PATH, MutationManager(state.clone()))
            .unwrap()
            .serve_at(TEST_LINK_PATH, MutationLink(state))
            .unwrap()
            .build()
            .await
            .unwrap();
        let client = bus.connect().await;
        (bus, server, client)
    }

    #[tokio::test]
    async fn локальный_dns_отключает_tls_до_публикации_и_следит_за_режимом() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            uses_tls: true,
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let prepared = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["198.18.0.2:53".parse().unwrap()],
            Resolve1DomainPublication::scoped(&["example.test".into()]),
            false,
        )
        .await
        .unwrap();
        apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap();
        {
            let mut state = state.lock().unwrap();
            assert_eq!(state.events, ["plain", "default_route", "domains", "dns"]);
            state.uses_tls = true;
        }
        assert_eq!(
            prepared.verify_active().await,
            Err(ResolverError::NetworkChanged)
        );
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn локальный_dns_не_публикуется_если_tls_остался_включён() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            uses_tls: true,
            ignore_plain_request: true,
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let prepared = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["198.18.0.2:53".parse().unwrap()],
            Resolve1DomainPublication::scoped(&["example.test".into()]),
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            apply_link_dns(&prepared, Duration::from_secs(1)).await,
            Err(Resolve1ApplyError {
                error: ResolverError::NetworkChanged,
                cleanup_required: true
            }),
        );
        assert_eq!(state.lock().unwrap().set_dns_calls, 0);
        server.close().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "Требует одноразовую VM, строгий DNSOverTLS и отдельный тестовый TUN"]
    async fn resolved_сохраняет_tls_для_исходных_серверов_при_публикации_локального_dns() {
        assert_eq!(
            std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
                .unwrap()
                .trim(),
            "QEMU"
        );
        assert_eq!(
            std::fs::read_to_string("/etc/yonik-production-helper-vm")
                .unwrap()
                .trim(),
            "yonik-production-helper-disposable-v1"
        );
        assert_eq!(
            std::fs::read_to_string("/run/yonik-vm-gate")
                .unwrap()
                .trim(),
            "yonik-disposable-systemd-gate-v1"
        );
        let index = std::fs::read_to_string("/sys/class/net/tofudotproof/ifindex")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let connection = Connection::system().await.unwrap();
        let scope = SnapshotScope::Tun {
            own_link: Some(index),
        };
        let before = read_connection(&connection, scope).await.unwrap();
        assert_eq!(before.global_transport, Some(Resolve1Transport::StrictTls));
        assert!(
            before
                .sockets
                .iter()
                .any(|socket| socket.transport == Resolve1Transport::StrictTls)
        );

        let (_operation, mut cancel) = Cancellation::new();
        let trusted = read_resolve1_tun_snapshot(&mut cancel, Duration::from_secs(4), Some(index))
            .await
            .unwrap();
        let daemon = trusted.daemon.as_ref().expect("Личность systemd-resolved");
        assert_ne!(daemon.uid, 0);
        assert_ne!(daemon.pid, 1);
        assert_eq!(daemon.owner.as_str(), owner(&connection).await.unwrap());

        let prepared = prepare_link_dns(
            index,
            "198.18.0.2".parse().unwrap(),
            &["yonik-dot-proof.test".into()],
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(prepared.initial_transport, Resolve1Transport::StrictTls);
        apply_link_dns(&prepared, Duration::from_secs(3))
            .await
            .unwrap();
        prepared.verify_active().await.unwrap();
        assert_eq!(read_connection(&connection, scope).await.unwrap(), before);
        assert_eq!(
            read_resolve1_tun_snapshot(&mut cancel, Duration::from_secs(4), Some(index))
                .await
                .unwrap(),
            trusted
        );
    }

    #[tokio::test]
    async fn reads_typed_manager_properties_from_private_bus() {
        let bus = PrivateBus::new();
        let server = zbus::connection::Builder::address(bus.1.as_str())
            .unwrap()
            .name(SERVICE)
            .unwrap()
            .serve_at(
                PATH,
                ManagerFixture {
                    dns: vec![
                        (2, 2, vec![9, 9, 9, 9]),
                        (7, 10, vec![0; 15].into_iter().chain([1]).collect()),
                    ],
                    domains: vec![(2, "lan".into(), false), (7, "~corp".into(), true)],
                    tls: Default::default(),
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        let client = bus.connect().await;
        let owner_name = owner(&client).await.expect("private fixture service owner");
        let properties = Proxy::new(&client, owner_name.as_str(), PATH, PROPERTIES)
            .await
            .unwrap();
        property::<Vec<(i32, i32, Vec<u8>)>>(&properties, "DNS")
            .await
            .expect("DNS property shape");
        property::<Vec<(i32, String, bool)>>(&properties, "Domains")
            .await
            .expect("Domains property shape");
        let snapshot = read_connection(&client, SnapshotScope::Configured)
            .await
            .unwrap_or_else(|error| panic!("fixture read failed: {error:?}"))
            .config;
        assert_eq!(snapshot.endpoints.len(), 2);
        assert_eq!(
            snapshot
                .domains
                .iter()
                .filter(|domain| domain.route_only)
                .count(),
            1
        );
        assert_eq!(
            snapshot.endpoints[0].address,
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn туннельный_dns_не_скрывает_резервные_серверы() {
        let bus = PrivateBus::new();
        let route = DefaultDnsRoute::default();
        let is_default = std::sync::Arc::clone(&route.0);
        let uses_tls = std::sync::Arc::clone(&route.1);
        let no_link_dns = std::sync::Arc::clone(&route.2);
        let global_tls = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = zbus::connection::Builder::address(bus.1.as_str())
            .unwrap()
            .name(SERVICE)
            .unwrap()
            .serve_at(
                PATH,
                ManagerFixture {
                    dns: vec![(13, 2, vec![198, 18, 0, 2]), (7, 2, vec![192, 0, 2, 7])],
                    domains: vec![(13, "fake.test".into(), true)],
                    tls: global_tls.clone(),
                },
            )
            .unwrap()
            .serve_at(link_object_path(7), route)
            .unwrap()
            .build()
            .await
            .unwrap();
        let client = bus.connect().await;
        let snapshot = read_connection(&client, SnapshotScope::Tun { own_link: Some(13) })
            .await
            .unwrap();
        let addresses: Vec<_> = snapshot
            .config
            .endpoints
            .iter()
            .map(|endpoint| endpoint.address)
            .collect();
        assert_eq!(
            addresses,
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 14)),
            ]
        );
        assert_eq!(
            snapshot
                .config
                .endpoints
                .iter()
                .map(|endpoint| endpoint.port)
                .collect::<Vec<_>>(),
            [1053, 53, 53, 1054, 53]
        );
        assert!(snapshot.config.domains.is_empty());
        assert!(!snapshot.fallback_only);
        is_default.store(true, std::sync::atomic::Ordering::Relaxed);
        let updated = read_connection(&client, SnapshotScope::Tun { own_link: Some(13) })
            .await
            .unwrap();
        assert_eq!(updated.config.endpoints, snapshot.config.endpoints[..1]);
        uses_tls.store(true, std::sync::atomic::Ordering::Relaxed);
        let link_tls = read_connection(&client, SnapshotScope::Tun { own_link: Some(13) })
            .await
            .unwrap();
        assert_eq!(link_tls.config.endpoints[0].scope, Resolve1Scope::Link(7));
        assert_eq!(link_tls.config.endpoints[0].port, 1053);
        assert_eq!(link_tls.sockets[0].transport, Resolve1Transport::StrictTls);
        assert_eq!(
            link_tls.sockets[0].server_name.as_deref(),
            Some("dns.example.")
        );
        assert_eq!(link_tls.global_transport, Some(Resolve1Transport::Plain));
        // Тот же ifindex может относиться к глобальной записи DNS=…%link.
        no_link_dns.store(true, std::sync::atomic::Ordering::Relaxed);
        let pinned_global = read_connection(&client, SnapshotScope::Tun { own_link: Some(13) })
            .await
            .unwrap();
        assert_eq!(
            pinned_global.config.endpoints[0].scope,
            Resolve1Scope::Global
        );
        assert_eq!(pinned_global.sockets[0].route_link, Some(7));
        assert_eq!(pinned_global.sockets[0].transport, Resolve1Transport::Plain);
        uses_tls.store(false, std::sync::atomic::Ordering::Relaxed);
        global_tls.store(true, std::sync::atomic::Ordering::Relaxed);
        let global = read_connection(&client, SnapshotScope::Tun { own_link: Some(13) })
            .await
            .unwrap();
        assert_eq!(global.sockets[0].transport, Resolve1Transport::StrictTls);
        assert_eq!(global.global_transport, Some(Resolve1Transport::StrictTls));
        server.close().await.unwrap();
    }

    #[test]
    fn транспорт_resolved_задаёт_только_неявный_порт() {
        for (transport, default_port) in [
            (Resolve1Transport::Plain, 53),
            (Resolve1Transport::StrictTls, 853),
            (Resolve1Transport::OpportunisticTls, 853),
        ] {
            for (port, expected) in [(0, default_port), (53, 53), (1853, 1853)] {
                let row = (0, 2, vec![192, 0, 2, 53], port, "resolver.test".into());
                let mut endpoint = decode_ex_endpoint(&row).unwrap();
                let socket = tun_socket(&mut endpoint, None, transport, row.4);
                assert_eq!(endpoint.port, expected);
                assert_eq!(endpoint.port_inferred, port == 0);
                assert_eq!(
                    socket.server_name.as_deref(),
                    (transport != Resolve1Transport::Plain).then_some("resolver.test")
                );
            }
        }
    }

    #[tokio::test]
    async fn публикует_резервные_серверы_на_tun_в_исходном_порядке() {
        let original = vec![
            (0, "second.test".into(), false),
            (0, "first.test".into(), false),
            (0, ".".into(), true),
        ];
        let domains = decode(Vec::new(), original.clone()).unwrap().domains;
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            foreign_domains: original.clone(),
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let servers = [
            "192.0.2.11:1053".parse::<SocketAddr>().unwrap(),
            "[2001:db8::12]:2053".parse().unwrap(),
            "192.0.2.10:53".parse().unwrap(),
        ];
        let prepared = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &servers,
            Resolve1DomainPublication::fallback(&["fake.test".into()], &domains),
            true,
        )
        .await
        .unwrap();
        apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap();
        {
            let state = state.lock().unwrap();
            assert_eq!(state.dns, servers.map(|server| encode_address(server.ip())));
            assert_eq!(
                state.dns_ex.iter().map(|entry| entry.2).collect::<Vec<_>>(),
                [1053, 2053, 0]
            );
            assert_eq!(
                state.domains,
                [
                    ("second.test".into(), false),
                    ("first.test".into(), false),
                    (".".into(), true),
                    ("fake.test".into(), true),
                ]
            );
            assert_eq!(state.foreign_domains, original);
            assert!(state.default_route);
        }
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn изменение_поискового_домена_прерывает_публикацию_резервных_dns() {
        let original = vec![(0, "corp.test".into(), false)];
        let domains = decode(Vec::new(), original.clone()).unwrap().domains;
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            foreign_domains: original,
            flip_global_flag_after_domains: true,
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let request = Resolve1DomainPublication::fallback(&["fake.test".into()], &domains);
        let prepared = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["192.0.2.11:53".parse().unwrap()],
            request,
            true,
        )
        .await
        .unwrap();
        let failure = apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ResolverError::NetworkChanged);
        assert!(failure.cleanup_required);
        assert_eq!(state.lock().unwrap().set_dns_calls, 0);
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn applies_exact_wire_values_and_readback_per_link() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState::default()));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let domains = vec!["corp.example".to_owned(), ".".to_owned()];
        let prepared = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["198.18.0.1:53".parse().unwrap()],
            Resolve1DomainPublication::scoped(&domains),
            false,
        )
        .await
        .unwrap();
        assert_eq!(state.lock().unwrap().set_dns_calls, 0);
        apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap();
        {
            let state = state.lock().unwrap();
            assert_eq!(state.dns, vec![(2, vec![198, 18, 0, 1])]);
            assert_eq!(
                state.dns_ex,
                vec![(2, vec![198, 18, 0, 1], 0, String::new())]
            );
            assert_eq!(
                state.domains,
                vec![("corp.example".into(), true), (".".into(), true)]
            );
            assert_eq!(state.set_dns_calls, 1);
            assert_eq!(state.set_domains_calls, 1);
            assert_eq!(state.events, vec!["default_route", "domains", "dns"]);
        }
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn refuses_preexisting_foreign_link_dns_without_mutation() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            dns: vec![(2, vec![10, 0, 0, 53])],
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let result = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["198.18.0.1:53".parse().unwrap()],
            Resolve1DomainPublication::scoped(&[]),
            false,
        )
        .await;
        assert_eq!(result.err(), Some(ResolverError::Untrusted));
        {
            let state = state.lock().unwrap();
            assert_eq!(state.set_dns_calls, 0);
            assert_eq!(state.set_domains_calls, 0);
            assert_eq!(state.dns, vec![(2, vec![10, 0, 0, 53])]);
        }
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn refuses_equal_suffix_or_global_root_before_mutation() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            foreign_domains: vec![(0, "corp.example".into(), true)],
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let result = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["198.18.0.1:53".parse().unwrap()],
            Resolve1DomainPublication::scoped(&["corp.example".into()]),
            false,
        )
        .await;
        assert_eq!(result.err(), Some(ResolverError::Untrusted));
        {
            let state = state.lock().unwrap();
            assert_eq!(state.set_domains_calls, 0);
            assert_eq!(state.set_dns_calls, 0);
        }
        server.close().await.unwrap();

        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            foreign_domains: vec![(0, ".".into(), true)],
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let result = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["198.18.0.1:53".parse().unwrap()],
            Resolve1DomainPublication::scoped(&["corp.example".into()]),
            false,
        )
        .await;
        assert_eq!(result.err(), Some(ResolverError::Untrusted));
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn detects_cross_link_conflict_after_domains_and_skips_dns_write() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            inject_conflict_after_domains: true,
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let prepared = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["198.18.0.1:53".parse().unwrap()],
            Resolve1DomainPublication::scoped(&["corp.example".into()]),
            false,
        )
        .await
        .unwrap();
        let failure = apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ResolverError::Untrusted);
        assert!(failure.cleanup_required);
        {
            let state = state.lock().unwrap();
            assert_eq!(state.set_domains_calls, 1);
            assert_eq!(state.set_dns_calls, 0);
            assert_eq!(state.events, vec!["default_route", "domains"]);
        }
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn missing_dns_ex_readback_after_first_write_requires_cleanup() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            hide_dns_ex_after_domains: true,
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let prepared = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["198.18.0.1:53".parse().unwrap()],
            Resolve1DomainPublication::scoped(&["corp.example".into()]),
            false,
        )
        .await
        .unwrap();
        let failure = apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ResolverError::Malformed);
        assert!(failure.cleanup_required);
        {
            let state = state.lock().unwrap();
            assert_eq!(state.set_domains_calls, 1);
            assert_eq!(state.set_dns_calls, 0);
        }
        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn reports_partial_mutation_for_tun_lifetime_cleanup_without_retry() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            fail_dns: true,
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let prepared = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            &["198.18.0.1:53".parse().unwrap()],
            Resolve1DomainPublication::scoped(&["corp.example".into()]),
            false,
        )
        .await
        .unwrap();
        let failure = apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ResolverError::Malformed);
        assert!(failure.cleanup_required);
        {
            let state = state.lock().unwrap();
            assert!(state.dns.is_empty());
            assert_eq!(state.domains, vec![("corp.example".into(), true)]);
            assert_eq!(state.set_dns_calls, 1);
            assert_eq!(state.set_domains_calls, 1);
            assert_eq!(state.events, vec!["default_route", "domains", "dns"]);
        }
        server.close().await.unwrap();
    }

    #[test]
    fn route_domains_are_validated_and_root_requires_explicit_dot() {
        assert!(
            validate_link_request(13, &[("corp.example".into(), false), (".".into(), true)])
                .is_ok()
        );
        assert_eq!(
            validate_link_request(13, &[("".into(), false)]),
            Err(ResolverError::Malformed)
        );
        assert_eq!(
            validate_link_request(13, &[("~corp.example".into(), true)]),
            Err(ResolverError::Malformed)
        );
        assert_eq!(validate_link_request(0, &[]), Err(ResolverError::Limit));
        assert_eq!(
            validate_link_request(
                13,
                &[
                    ("corp.example".into(), false),
                    ("CORP.EXAMPLE".into(), true)
                ]
            ),
            Err(ResolverError::Malformed)
        );
        assert_eq!(
            validate_marker("0.0.0.0".parse().unwrap()),
            Err(ResolverError::Malformed)
        );
        assert_eq!(
            validate_marker("127.0.0.1".parse().unwrap()),
            Err(ResolverError::Malformed)
        );
        assert_eq!(
            validate_marker("224.0.0.1".parse().unwrap()),
            Err(ResolverError::Malformed)
        );
    }

    #[test]
    fn link_paths_use_sd_bus_canonical_decimal_escape() {
        assert_eq!(link_object_path(2), format!("{PATH}/link/_32"));
        assert_eq!(link_object_path(13), format!("{PATH}/link/_313"));
        assert_eq!(link_object_path(42), format!("{PATH}/link/_342"));
    }

    #[test]
    fn decodes_v4_v6_and_route_only_domains() {
        let snapshot = decode(
            vec![
                (2, 2, vec![1, 1, 1, 1]),
                (7, 10, vec![0; 15].into_iter().chain([1]).collect()),
            ],
            vec![(2, "lan".into(), false), (7, "~corp".into(), true)],
        )
        .unwrap();
        assert_eq!(
            snapshot.endpoints[0].address,
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(snapshot.endpoints[1].scope, Resolve1Scope::Link(7));
        assert!(snapshot.endpoints[0].port_inferred);
        assert!(snapshot.domains[1].route_only);
        assert_eq!(snapshot.domains[1].name, "~corp");
    }

    #[test]
    fn global_ifindex_zero_is_preserved_as_global_scope() {
        let snapshot = decode(
            vec![(0, 2, vec![127, 0, 0, 1])],
            vec![(0, ".".into(), true)],
        )
        .unwrap();
        assert_eq!(snapshot.endpoints[0].scope, Resolve1Scope::Global);
        assert_eq!(snapshot.domains[0].scope, Resolve1Scope::Global);
    }

    #[test]
    fn rejects_invalid_shapes_and_oversized_properties() {
        assert_eq!(
            decode(vec![(1, 2, vec![1, 2, 3])], vec![]),
            Err(ResolverError::Malformed)
        );
        assert_eq!(
            decode(vec![(-1, 2, vec![1; 4])], vec![]),
            Err(ResolverError::Malformed)
        );
        assert_eq!(
            decode(vec![], vec![(1, "".into(), false)]),
            Err(ResolverError::Malformed)
        );
        assert_eq!(
            decode(vec![(1, 2, vec![1; 4]); MAX_ENTRIES + 1], vec![]),
            Err(ResolverError::Limit)
        );
    }
}
