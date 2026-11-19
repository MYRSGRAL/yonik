//! Журналируемое правило RPDB для точного TCP-сокета системного резолвера.
use super::{TunError, TunExecutor, config, lease, rule, write};
use crate::managed_network::{
    Journal, JournalError, Ownership, Reconciled, RecordState, Resource, Scope,
};
use crate::{LinuxRule, LinuxTopology};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

const RULE_PROTOCOL: u8 = 253;
const TCP: u8 = 6;
const FRA_DPORT_MASK: u16 = 29;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResolverRouteRule {
    priority: u32,
    table: u32,
    uid: u32,
    endpoint: SocketAddr,
    mark: u32,
}

impl ResolverRouteRule {
    pub fn new(
        priority: u32,
        table: u32,
        uid: u32,
        endpoint: SocketAddr,
    ) -> Result<Self, TunError> {
        let address = endpoint.ip();
        if !(1..32766).contains(&priority)
            || !(1..u32::MAX).contains(&table)
            || table == 255
            || !(1..u32::MAX).contains(&uid)
            || endpoint.port() == 0
            || address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || match endpoint {
                SocketAddr::V4(addr) => addr.ip().is_broadcast() || addr.ip().is_link_local(),
                SocketAddr::V6(addr) => {
                    addr.scope_id() != 0
                        || addr.flowinfo() != 0
                        || addr.ip().is_unicast_link_local()
                        || addr.ip().to_ipv4().is_some()
                }
            }
        {
            return Err(TunError::Invalid);
        }
        Ok(Self {
            priority,
            table,
            uid,
            endpoint,
            mark: 0,
        })
    }

    pub fn priority(self) -> u32 {
        self.priority
    }
    pub fn table(self) -> u32 {
        self.table
    }
    pub fn uid(self) -> u32 {
        self.uid
    }
    pub fn endpoint(self) -> SocketAddr {
        self.endpoint
    }

    pub(super) fn mark(self) -> u32 {
        self.mark
    }

    pub(super) fn with_owner(mut self, owner: Ownership, id: u64) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"Yonik Resolver RPDB owner v1\0");
        hash.update(owner.owner_uid().to_be_bytes());
        hash.update(owner.session().to_be_bytes());
        hash.update(owner.generation().to_be_bytes());
        let (device, inode) = owner.namespace();
        hash.update(device.to_be_bytes());
        hash.update(inode.to_be_bytes());
        hash.update(id.to_be_bytes());
        let [a, b, c, d, ..] = <[u8; 32]>::from(hash.finalize());
        self.mark = u32::from_be_bytes([a, b, c, d]).max(1);
        self
    }

    fn family(self) -> u8 {
        if self.endpoint.is_ipv4() { 2 } else { 10 }
    }

    fn journal_resource(self, tun_id: u64, ifindex: u32) -> Resource {
        Resource::ResolverRule {
            tun_id,
            ifindex,
            priority: self.priority,
            ipv6: self.endpoint.is_ipv6(),
            digest: self.digest(),
        }
    }

    pub(crate) fn expected_resource(
        self,
        owner: Ownership,
        id: u64,
        tun_id: u64,
        ifindex: u32,
    ) -> Resource {
        self.with_owner(owner, id).journal_resource(tun_id, ifindex)
    }

    fn digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"Yonik Resolver RPDB v2\0");
        hash.update([self.family(), RULE_PROTOCOL, TCP]);
        hash.update(self.priority.to_be_bytes());
        hash.update(self.table.to_be_bytes());
        hash.update(self.uid.to_be_bytes());
        hash.update(self.mark.to_be_bytes());
        match self.endpoint.ip() {
            IpAddr::V4(ip) => hash.update(ip.octets()),
            IpAddr::V6(ip) => hash.update(ip.octets()),
        }
        hash.update(self.endpoint.port().to_be_bytes());
        hash.finalize().into()
    }

    fn from_kernel(value: &LinuxRule) -> Option<Self> {
        let ip = value.destination.address;
        let (uid, last_uid) = value.uid_range?;
        let (port, last_port) = value.destination_ports?;
        let mut expected =
            Self::new(value.priority?, value.table, uid, SocketAddr::new(ip, port)).ok()?;
        expected.mark = value.fwmark.filter(|mark| *mark != 0)?;
        // Новые ядра дополняют точный диапазон порта полной маской.
        let expected_mask = match value.unknown.as_slice() {
            [] => true,
            [attribute] => {
                attribute.kind == FRA_DPORT_MASK && attribute.value == u16::MAX.to_ne_bytes()
            }
            _ => false,
        };
        (value.family == expected.family()
            && value.destination.length == if ip.is_ipv4() { 32 } else { 128 }
            && value.source.length == 0
            && value.source.address.is_unspecified()
            && value.source.address.is_ipv4() == ip.is_ipv4()
            && value.tos == 0
            && value.action == 1
            && value.flags == 0
            && value.goto.is_none()
            && value.fwmask == Some(0)
            && last_uid == uid
            && last_port == port
            && value.input_interface.is_none()
            && value.output_interface.is_none()
            && value.protocol == Some(RULE_PROTOCOL)
            && value.ip_protocol == Some(TCP)
            && value.source_ports.is_none()
            && value
                .suppress_prefix_len
                .is_none_or(|length| length == u32::MAX)
            && value.suppress_interface_group.is_none()
            && value.l3mdev.is_none()
            && expected_mask)
            .then_some(expected)
    }
}

impl fmt::Debug for ResolverRouteRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResolverRouteRule(<скрыто>)")
    }
}

pub(super) fn matches_digest(value: &LinuxRule, digest: &[u8; 32]) -> bool {
    ResolverRouteRule::from_kernel(value).is_some_and(|rule| &rule.digest() == digest)
}

fn observe(
    topology: &LinuxTopology,
    priority: u32,
    family: u8,
    digest: &[u8; 32],
) -> Result<Option<ResolverRouteRule>, TunError> {
    let mut matches = topology
        .rules
        .iter()
        .filter(|rule| rule.family == family && rule.priority == Some(priority));
    let Some(value) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(TunError::Foreign);
    }
    ResolverRouteRule::from_kernel(value)
        .filter(|rule| &rule.digest() == digest)
        .map(Some)
        .ok_or(TunError::Foreign)
}

impl TunExecutor {
    /// Caller отдельно подтверждает исходный физический маршрут и ограничение nft.
    pub async fn ensure_resolver_rule(
        &mut self,
        journal: &mut Journal,
        tun_id: u64,
        id: u64,
        selector: ResolverRouteRule,
    ) -> Result<(), TunError> {
        config::ownership(self, journal)?;
        let selector = selector.with_owner(self.owner, id);
        if journal.records().iter().any(|record| record.id() == id) {
            journal.require_reconciliation(self.owner, id)?;
        }
        let operation = lease().await?;
        let topology = self.configuration_snapshot().await?;
        let index = rule::parent(self, journal, tun_id, &topology, true)?;
        if journal.records().iter().any(|record| {
            record.scope() == Scope::Session
                && record.resource().route_table() == Some(selector.table())
        }) {
            return Err(TunError::Invalid);
        }
        let digest = selector.digest();
        let present = observe(&topology, selector.priority, selector.family(), &digest)?.is_some();
        if present && !journal.records().iter().any(|record| record.id() == id) {
            return Err(TunError::Foreign);
        }
        let fresh = journal.intent(
            self.owner,
            Scope::Session,
            id,
            selector.journal_resource(tun_id, index),
        )?;
        let state = config::record_state(journal, id)?;
        journal.require_reconciliation(self.owner, id)?;
        let topology = self.configuration_snapshot().await?;
        if rule::parent(self, journal, tun_id, &topology, true)? != index {
            return Err(TunError::Evidence);
        }
        if observe(&topology, selector.priority, selector.family(), &digest)?.is_some() {
            if fresh || state == RecordState::CleanupRemaining {
                return Err(TunError::Evidence);
            }
        } else {
            if !fresh {
                return Err(TunError::Evidence);
            }
            self.check_namespace()?;
            write::run(
                write::Action::ResolverRule {
                    rule: selector,
                    add: true,
                },
                operation,
            )
            .await?;
            let topology = self.configuration_snapshot().await?;
            if rule::parent(self, journal, tun_id, &topology, true)? != index
                || observe(&topology, selector.priority, selector.family(), &digest)?.is_none()
            {
                return Err(TunError::Evidence);
            }
        }
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        Ok(())
    }

    pub async fn remove_resolver_rule(
        &mut self,
        journal: &mut Journal,
        tun_id: u64,
        id: u64,
    ) -> Result<(), TunError> {
        let operation = lease().await?;
        config::ownership(self, journal)?;
        let record = journal
            .records()
            .iter()
            .find(|record| record.id() == id)
            .ok_or(JournalError::Missing)?;
        let Resource::ResolverRule {
            tun_id: parent,
            ifindex,
            priority,
            ipv6,
            digest,
        } = *record.resource()
        else {
            return Err(TunError::Invalid);
        };
        if record.scope() != Scope::Session || parent != tun_id {
            return Err(TunError::Invalid);
        }
        let family = if ipv6 { 10 } else { 2 };
        journal.require_reconciliation(self.owner, id)?;
        let topology = self.configuration_snapshot().await?;
        let Some(selector) = observe(&topology, priority, family, &digest)? else {
            journal.reconcile(self.owner, id, Reconciled::Absent)?;
            return Ok(());
        };
        if rule::parent(self, journal, tun_id, &topology, false)? != ifindex {
            return Err(TunError::Evidence);
        }
        journal.reconcile(self.owner, id, Reconciled::Owned)?;
        journal.mark_cleanup(self.owner, id)?;
        self.check_namespace()?;
        write::run(
            write::Action::ResolverRule {
                rule: selector,
                add: false,
            },
            operation,
        )
        .await?;
        if observe(
            &self.configuration_snapshot().await?,
            priority,
            family,
            &digest,
        )?
        .is_some()
        {
            return Err(TunError::Evidence);
        }
        journal.reconcile(self.owner, id, Reconciled::Absent)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IpPrefix, NetworkAttribute};

    fn observed_rule(selector: ResolverRouteRule) -> LinuxRule {
        let address = selector.endpoint().ip();
        LinuxRule {
            family: selector.family(),
            destination: IpPrefix {
                address,
                length: if address.is_ipv4() { 32 } else { 128 },
            },
            source: IpPrefix {
                address: if address.is_ipv4() { "0.0.0.0" } else { "::" }
                    .parse()
                    .unwrap(),
                length: 0,
            },
            tos: 0,
            table: selector.table(),
            action: 1,
            flags: 0,
            priority: Some(selector.priority()),
            goto: None,
            fwmark: Some(selector.mark()),
            fwmask: Some(0),
            uid_range: Some((selector.uid(), selector.uid())),
            input_interface: None,
            output_interface: None,
            protocol: Some(RULE_PROTOCOL),
            ip_protocol: Some(TCP),
            source_ports: None,
            destination_ports: Some((selector.endpoint().port(), selector.endpoint().port())),
            suppress_prefix_len: Some(u32::MAX),
            suppress_interface_group: None,
            l3mdev: None,
            unknown: vec![],
        }
    }

    #[test]
    fn отпечаток_проверяет_точное_правило_обоих_семейств() {
        for endpoint in ["192.0.2.53:1853", "[2001:db8::53]:1853"] {
            let owner = Ownership::new(1000, 7, 9, 1, 2).unwrap();
            let selector = ResolverRouteRule::new(16999, 254, 991, endpoint.parse().unwrap())
                .unwrap()
                .with_owner(owner, 2);
            let digest = selector.digest();
            let kernel = observed_rule(selector);
            assert!(matches_digest(&kernel, &digest));
            let changes: [fn(&mut LinuxRule); 12] = [
                |rule| rule.destination.length -= 1,
                |rule| rule.table = 253,
                |rule| rule.uid_range = Some((990, 990)),
                |rule| rule.uid_range = Some((991, 992)),
                |rule| rule.ip_protocol = Some(17),
                |rule| rule.destination_ports = Some((1854, 1854)),
                |rule| rule.destination_ports = Some((1853, 1854)),
                |rule| rule.protocol = Some(4),
                |rule| rule.fwmark = rule.fwmark.map(|mark| mark ^ 1),
                |rule| rule.fwmask = Some(u32::MAX),
                |rule| rule.output_interface = Some(b"eth0".to_vec()),
                |rule| rule.flags = 2,
            ];
            for change in changes {
                let mut foreign = kernel.clone();
                change(&mut foreign);
                assert!(!matches_digest(&foreign, &digest));
            }
            let mut with_mask = kernel;
            with_mask.unknown.push(NetworkAttribute {
                kind: FRA_DPORT_MASK,
                value: u16::MAX.to_ne_bytes().to_vec(),
            });
            assert!(matches_digest(&with_mask, &digest));
            with_mask.unknown[0].value = 0xff00_u16.to_ne_bytes().to_vec();
            assert!(!matches_digest(&with_mask, &digest));
        }
    }

    #[tokio::test]
    #[ignore = "Требует отдельную network namespace и приватный каталог журнала"]
    async fn реальный_журнал_защищает_чужое_правило_при_очистке() {
        use std::os::unix::fs::DirBuilderExt;
        let namespace = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
        let (device, inode) = super::super::namespace(&namespace).unwrap();
        let owner =
            Ownership::new(rustix::process::getuid().as_raw(), 7, 9, device, inode).unwrap();
        let mut executor = TunExecutor::isolated_fixture(owner).unwrap();
        let area = std::env::temp_dir().join(format!("yonik-resolver-rpdb-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&area)
            .unwrap();
        let state_path = area.join("state");
        let mut journal = Journal::open(&state_path, owner).unwrap();
        executor.ensure_tun(&mut journal, 1, 7).await.unwrap();
        let v4 =
            ResolverRouteRule::new(16999, 254, 991, "192.0.2.53:1853".parse().unwrap()).unwrap();
        let v6 = ResolverRouteRule::new(16999, 254, 991, "[2001:db8::53]:1853".parse().unwrap())
            .unwrap();
        executor
            .ensure_resolver_rule(&mut journal, 1, 2, v4)
            .await
            .unwrap();
        let v4 = v4.with_owner(owner, 2);
        let v6 = v6.with_owner(owner, 3);
        let snapshot = executor.configuration_snapshot().await.unwrap();
        let index = rule::parent(&executor, &journal, 1, &snapshot, true).unwrap();
        assert!(
            journal
                .intent(owner, Scope::Session, 3, v6.journal_resource(1, index))
                .unwrap()
        );
        write::run(
            write::Action::ResolverRule {
                rule: v6,
                add: true,
            },
            lease().await.unwrap(),
        )
        .await
        .unwrap();
        // Моделируем остановку после ACK ядра до фиксации Confirmed.
        drop(journal);
        let mut journal = Journal::open(&state_path, owner).unwrap();
        assert_eq!(
            config::record_state(&journal, 3).unwrap(),
            RecordState::Intent
        );
        assert!(executor.remove_tun(&mut journal, 1).await.is_err());
        executor
            .remove_resolver_rule(&mut journal, 1, 3)
            .await
            .unwrap();

        let foreign = v4.with_owner(owner, 4);
        assert_ne!(foreign.mark(), v4.mark());
        write::run(
            write::Action::ResolverRule {
                rule: v4,
                add: false,
            },
            lease().await.unwrap(),
        )
        .await
        .unwrap();
        write::run(
            write::Action::ResolverRule {
                rule: foreign,
                add: true,
            },
            lease().await.unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            executor.remove_resolver_rule(&mut journal, 1, 2).await,
            Err(TunError::Foreign)
        );
        let snapshot = executor.configuration_snapshot().await.unwrap();
        assert_eq!(
            observe(
                &snapshot,
                foreign.priority(),
                foreign.family(),
                &foreign.digest()
            ),
            Ok(Some(foreign))
        );
        assert!(journal.records().iter().any(|record| record.id() == 2));
        write::run(
            write::Action::ResolverRule {
                rule: foreign,
                add: false,
            },
            lease().await.unwrap(),
        )
        .await
        .unwrap();
        executor
            .remove_resolver_rule(&mut journal, 1, 2)
            .await
            .unwrap();
        executor.remove_tun(&mut journal, 1).await.unwrap();
        assert!(journal.records().is_empty());
        drop(journal);
        std::fs::remove_dir_all(area).unwrap();
    }
}
