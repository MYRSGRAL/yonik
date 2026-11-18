//! Read-only совместимый источник per-link DNS через system bus.

use super::ResolverError;
use crate::Cancellation;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use zbus::{Connection, Proxy, zvariant::OwnedValue};

const SERVICE: &str = "org.freedesktop.resolve1";
const PATH: &str = "/org/freedesktop/resolve1";
const MANAGER: &str = "org.freedesktop.resolve1.Manager";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const MAX_ENTRIES: usize = 4096;
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
