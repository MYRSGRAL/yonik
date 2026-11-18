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
use crate::Cancellation;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolve1Scope {
    Global,
    Link(u32),
}

#[derive(Clone, PartialEq, Eq)]
pub struct Resolve1Endpoint {
    /// `Global` соответствует D-Bus ifindex=0; `Link` сохраняет исходный ifindex.
    pub scope: Resolve1Scope,
    pub address: IpAddr,
    /// Значение 53 выведено из старого Manager.DNS, который порт не передаёт.
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
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(ResolverError::Limit);
    }
    tokio::time::timeout(timeout, async {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ResolverError::Cancelled),
            result = read_inner() => result,
        }
    })
    .await
    .map_err(|_| ResolverError::Timeout)?
}

async fn read_inner() -> Result<Resolve1Snapshot, ResolverError> {
    let connection = Connection::system().await.map_err(bus_error)?;
    read_connection(&connection).await
}

async fn read_connection(connection: &Connection) -> Result<Resolve1Snapshot, ResolverError> {
    let owner_name = owner(connection).await?;
    let proxy = Proxy::new(connection, owner_name.as_str(), PATH, PROPERTIES)
        .await
        .map_err(bus_error)?;
    let dns = property::<Vec<(i32, i32, Vec<u8>)>>(&proxy, "DNS").await?;
    let domains = property::<Vec<(i32, String, bool)>>(&proxy, "Domains").await?;
    let snapshot = decode(dns, domains)?;
    if owner(connection).await? != owner_name {
        return Err(ResolverError::NetworkChanged);
    }
    Ok(snapshot)
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
    let mut endpoints = Vec::with_capacity(dns.len());
    for (index, family, bytes) in dns {
        let scope = decode_scope(index)?;
        let address = match (family, bytes.as_slice()) {
            (2, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
            (10, bytes) if bytes.len() == 16 => {
                let address: [u8; 16] = bytes.try_into().map_err(|_| ResolverError::Malformed)?;
                IpAddr::V6(Ipv6Addr::from(address))
            }
            _ => return Err(ResolverError::Malformed),
        };
        endpoints.push(Resolve1Endpoint {
            scope,
            address,
            port: 53,
            port_inferred: true,
        });
    }
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
#[allow(dead_code)]
pub async fn prepare_link_dns(
    ifindex: u32,
    marker: IpAddr,
    route_domains: &[String],
    timeout: Duration,
) -> Result<Resolve1Prepared, ResolverError> {
    validate_link_request(ifindex, route_domains)?;
    validate_marker(marker)?;
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(ResolverError::Limit);
    }
    tokio::time::timeout(timeout, async {
        let connection = Connection::system().await.map_err(bus_error)?;
        prepare_on_connection(connection, ifindex, marker, route_domains).await
    })
    .await
    .map_err(|_| ResolverError::Timeout)?
}

/// Apply errors after dispatching SetLinkDomains require dropping the caller-owned TUN
/// interface. That interface lifetime is the cleanup mechanism for ambiguous and
/// partial outcomes; this module deliberately never calls RevertLink or retries.
/// Экспорт из `resolver.rs` отложен до интеграции caller.
#[allow(dead_code)]
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
    marker: IpAddr,
    route_domains: Vec<String>,
}

impl std::fmt::Debug for Resolve1Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolve1Prepared")
            .field("ifindex", &self.ifindex)
            .field("route_domain_count", &self.route_domains.len())
            .field("dns_marker", &"<скрыто>")
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
    marker: IpAddr,
    route_domains: &[String],
) -> Result<Resolve1Prepared, ResolverError> {
    validate_link_request(ifindex, route_domains)?;
    validate_marker(marker)?;
    let owner = owner(&connection).await?;
    let link_path = get_link_path(&connection, &owner, ifindex).await?;
    let state = read_link_config(&connection, &owner, &link_path).await?;
    if !state.dns.is_empty() || !state.dns_ex.is_empty() || !state.domains.is_empty() {
        return Err(ResolverError::Untrusted);
    }
    ensure_manager_domains(
        &manager_domains(&connection, &owner).await?,
        ifindex,
        route_domains,
        false,
    )?;
    verify_owner(&connection, &owner).await?;
    Ok(Resolve1Prepared {
        connection,
        owner,
        ifindex: i32::try_from(ifindex).map_err(|_| ResolverError::Limit)?,
        link_path,
        marker,
        route_domains: route_domains.to_vec(),
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
    ensure_manager_domains(
        &manager_domains(connection, &prepared.owner).await?,
        prepared.ifindex as u32,
        &prepared.route_domains,
        false,
    )?;

    let manager = Proxy::new(connection, prepared.owner.as_str(), PATH, MANAGER)
        .await
        .map_err(bus_error)?;
    let (family, bytes) = encode_address(prepared.marker);
    let expected_dns = vec![(family, bytes.clone())];
    // DNSEx stores raw s->port; zero means no override and resolves to port 53.
    let expected_dns_ex = vec![(family, bytes, 0, String::new())];
    let expected_domains = prepared
        .route_domains
        .iter()
        .cloned()
        .map(|domain| (domain, true))
        .collect::<Vec<_>>();
    // Routing is installed first, before this interface receives DNS queries.
    *mutation_started = true;
    let _: () = manager
        .call(
            "SetLinkDomains",
            &(prepared.ifindex, expected_domains.clone()),
        )
        .await
        .map_err(bus_error)?;

    verify_owner(connection, &prepared.owner).await?;
    let after_domains = read_link_config(connection, &prepared.owner, &link_path).await?;
    if !after_domains.dns.is_empty()
        || !after_domains.dns_ex.is_empty()
        || after_domains.domains != expected_domains
    {
        return Err(ResolverError::NetworkChanged);
    }
    ensure_manager_domains(
        &manager_domains(connection, &prepared.owner).await?,
        prepared.ifindex as u32,
        &prepared.route_domains,
        true,
    )?;

    // Mutation outcomes may be ambiguous at timeout/disconnect; never retry.
    let _: () = manager
        .call("SetLinkDNS", &(prepared.ifindex, expected_dns.clone()))
        .await
        .map_err(bus_error)?;

    verify_owner(connection, &prepared.owner).await?;
    let readback = read_link_config(connection, &prepared.owner, &link_path).await?;
    if readback.dns != expected_dns
        || readback.dns_ex != expected_dns_ex
        || readback.domains != expected_domains
    {
        return Err(ResolverError::NetworkChanged);
    }
    ensure_manager_domains(
        &manager_domains(connection, &prepared.owner).await?,
        prepared.ifindex as u32,
        &prepared.route_domains,
        true,
    )?;
    verify_owner(connection, &prepared.owner).await
}

impl std::fmt::Display for Resolve1ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for Resolve1ApplyError {}

struct Resolve1LinkConfig {
    dns: Vec<(i32, Vec<u8>)>,
    dns_ex: Vec<(i32, Vec<u8>, u16, String)>,
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
    let dns_ex = property_for::<Vec<(i32, Vec<u8>, u16, String)>>(&proxy, LINK, "DNSEx").await?;
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
    requested: &[String],
    must_be_present: bool,
) -> Result<(), ResolverError> {
    if !requested.is_empty()
        && current
            .iter()
            .any(|(index, name, _)| *index == 0 && name == ".")
    {
        return Err(ResolverError::Untrusted);
    }
    for expected in requested {
        let matching = current
            .iter()
            .filter(|(_, name, _)| name.eq_ignore_ascii_case(expected))
            .collect::<Vec<_>>();
        if must_be_present {
            if matching.len() != 1 || matching[0].0 != ifindex as i32 || !matching[0].2 {
                return Err(
                    if matching
                        .iter()
                        .any(|(index, _, _)| *index != ifindex as i32)
                    {
                        ResolverError::Untrusted
                    } else {
                        ResolverError::NetworkChanged
                    },
                );
            }
        } else if !matching.is_empty() {
            return Err(ResolverError::Untrusted);
        }
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

fn validate_link_request(ifindex: u32, domains: &[String]) -> Result<(), ResolverError> {
    if ifindex == 0 || i32::try_from(ifindex).is_err() || domains.len() > MAX_ROUTE_DOMAINS {
        return Err(ResolverError::Limit);
    }
    let mut seen = HashSet::with_capacity(domains.len());
    for domain in domains {
        if !valid_domain(domain) || !seen.insert(domain.to_ascii_lowercase()) {
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
    }
    #[zbus::interface(name = "org.freedesktop.resolve1.Manager")]
    impl ManagerFixture {
        #[zbus(property, name = "DNS")]
        fn dns(&self) -> Vec<(i32, i32, Vec<u8>)> {
            self.dns.clone()
        }
        #[zbus(property, name = "Domains")]
        fn domains(&self) -> Vec<(i32, String, bool)> {
            self.domains.clone()
        }
    }

    const TEST_IFINDEX: i32 = 13;
    const TEST_LINK_PATH: &str = "/org/freedesktop/resolve1/link/_313";

    #[derive(Default)]
    struct MutationState {
        dns: Vec<(i32, Vec<u8>)>,
        dns_ex: Vec<(i32, Vec<u8>, u16, String)>,
        domains: Vec<(String, bool)>,
        foreign_domains: Vec<(i32, String, bool)>,
        set_dns_calls: usize,
        set_domains_calls: usize,
        fail_dns: bool,
        fail_domains: bool,
        inject_conflict_after_domains: bool,
        hide_dns_ex_after_domains: bool,
        events: Vec<&'static str>,
    }

    struct MutationManager(std::sync::Arc<std::sync::Mutex<MutationState>>);
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
            assert_eq!(ifindex, TEST_IFINDEX);
            let mut state = self.0.lock().unwrap();
            state.set_dns_calls += 1;
            state.events.push("dns");
            if state.fail_dns {
                return Err(zbus::fdo::Error::Failed(
                    "fixture DNS failure after domains".into(),
                ));
            }
            state.dns = dns;
            state.dns_ex = state
                .dns
                .iter()
                .cloned()
                .map(|(family, bytes)| (family, bytes, 0, String::new()))
                .collect();
            Ok(())
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
            Ok(())
        }
    }

    struct MutationLink(std::sync::Arc<std::sync::Mutex<MutationState>>);
    #[zbus::interface(name = "org.freedesktop.resolve1.Link")]
    impl MutationLink {
        #[zbus(property, name = "DNS")]
        fn dns(&self) -> Vec<(i32, Vec<u8>)> {
            self.0.lock().unwrap().dns.clone()
        }
        #[zbus(property, name = "DNSEx")]
        fn dns_ex(&self) -> zbus::fdo::Result<Vec<(i32, Vec<u8>, u16, String)>> {
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
        let snapshot = read_connection(&client)
            .await
            .unwrap_or_else(|error| panic!("fixture read failed: {error:?}"));
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
    async fn applies_exact_wire_values_and_readback_per_link() {
        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState::default()));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let domains = vec!["corp.example".to_owned(), ".".to_owned()];
        let prepared = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            "198.18.0.1".parse().unwrap(),
            &domains,
        )
        .await
        .unwrap();
        assert_eq!(state.lock().unwrap().set_dns_calls, 0);
        apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap();
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
        assert_eq!(state.events, vec!["domains", "dns"]);
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
            "198.18.0.1".parse().unwrap(),
            &[],
        )
        .await;
        assert_eq!(result.err(), Some(ResolverError::Untrusted));
        let state = state.lock().unwrap();
        assert_eq!(state.set_dns_calls, 0);
        assert_eq!(state.set_domains_calls, 0);
        assert_eq!(state.dns, vec![(2, vec![10, 0, 0, 53])]);
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
            "198.18.0.1".parse().unwrap(),
            &["corp.example".into()],
        )
        .await;
        assert_eq!(result.err(), Some(ResolverError::Untrusted));
        let state = state.lock().unwrap();
        assert_eq!(state.set_domains_calls, 0);
        assert_eq!(state.set_dns_calls, 0);
        server.close().await.unwrap();

        let state = std::sync::Arc::new(std::sync::Mutex::new(MutationState {
            foreign_domains: vec![(0, ".".into(), true)],
            ..MutationState::default()
        }));
        let (_bus, server, client) = mutation_fixture(state.clone()).await;
        let result = prepare_on_connection(
            client,
            TEST_IFINDEX as u32,
            "198.18.0.1".parse().unwrap(),
            &["corp.example".into()],
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
            "198.18.0.1".parse().unwrap(),
            &["corp.example".into()],
        )
        .await
        .unwrap();
        let failure = apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ResolverError::Untrusted);
        assert!(failure.cleanup_required);
        let state = state.lock().unwrap();
        assert_eq!(state.set_domains_calls, 1);
        assert_eq!(state.set_dns_calls, 0);
        assert_eq!(state.events, vec!["domains"]);
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
            "198.18.0.1".parse().unwrap(),
            &["corp.example".into()],
        )
        .await
        .unwrap();
        let failure = apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ResolverError::Malformed);
        assert!(failure.cleanup_required);
        let state = state.lock().unwrap();
        assert_eq!(state.set_domains_calls, 1);
        assert_eq!(state.set_dns_calls, 0);
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
            "198.18.0.1".parse().unwrap(),
            &["corp.example".into()],
        )
        .await
        .unwrap();
        let failure = apply_link_dns(&prepared, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ResolverError::Malformed);
        assert!(failure.cleanup_required);
        let state = state.lock().unwrap();
        assert!(state.dns.is_empty());
        assert_eq!(state.domains, vec![("corp.example".into(), true)]);
        assert_eq!(state.set_dns_calls, 1);
        assert_eq!(state.set_domains_calls, 1);
        assert_eq!(state.events, vec!["domains", "dns"]);
        server.close().await.unwrap();
    }

    #[test]
    fn route_domains_are_validated_and_root_requires_explicit_dot() {
        assert!(validate_link_request(13, &["corp.example".into(), ".".into()]).is_ok());
        assert_eq!(
            validate_link_request(13, &["".into()]),
            Err(ResolverError::Malformed)
        );
        assert_eq!(
            validate_link_request(13, &["~corp.example".into()]),
            Err(ResolverError::Malformed)
        );
        assert_eq!(validate_link_request(0, &[]), Err(ResolverError::Limit));
        assert_eq!(
            validate_link_request(13, &["corp.example".into(), "CORP.EXAMPLE".into()]),
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
