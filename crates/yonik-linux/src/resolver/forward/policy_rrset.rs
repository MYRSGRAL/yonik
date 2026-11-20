//! Подтверждённый ответ для выбора маршрута по реальному адресу.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    net::IpAddr,
    time::{Duration, Instant},
};

use super::{
    ForwardResponse, ResolverError, ResourceRecord, boottime_now, decode_name, parse_question,
    read_record, read_u16, read_u32, section_counts,
};

const MAX_ADDRESSES: usize = 64;
const MAX_TTL: u32 = i32::MAX as u32;

#[derive(Debug, PartialEq, Eq)]
pub struct PolicyRrset {
    addresses: Vec<IpAddr>,
    valid_until: Instant,
    boot_valid_until: Duration,
    terminal: Vec<u8>,
}

impl PolicyRrset {
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }

    pub fn boot_valid_until(&self) -> Duration {
        self.boot_valid_until
    }
}

impl ForwardResponse {
    pub(super) fn verify_policy_status(&self) -> Result<(), ResolverError> {
        let flags = read_u16(&self.packet, 2)?;
        if self.truncated
            || self.question.opcode != 0
            || !matches!(self.question.qtype, 1 | 28)
            || flags & 0x024f != 0
        {
            return Err(ResolverError::Untrusted);
        }
        Ok(())
    }

    /// Объединяет ответы A и AAAA на одно имя от одного узла.
    /// UDP и TCP к одному узлу считаются одним путём обычного DNS.
    /// Вызывающая сторона сохраняет связь с текущим снимком резолвера.
    pub fn policy_address_pair(&self, aaaa: &Self) -> Result<PolicyRrset, ResolverError> {
        if self.question.qtype != 1
            || aaaa.question.qtype != 28
            || self.question.name != aaaa.question.name
            || self.peer != aaaa.peer
        {
            return Err(ResolverError::Untrusted);
        }
        let mut v4 = self.policy_rrset()?;
        let v6 = aaaa.policy_rrset()?;
        if v4.terminal != v6.terminal {
            return Err(ResolverError::Untrusted);
        }
        let count = v4.addresses.len() + v6.addresses.len();
        if count == 0 {
            return Err(ResolverError::Unavailable);
        }
        if count > MAX_ADDRESSES {
            return Err(ResolverError::Limit);
        }
        v4.valid_until = v4.valid_until.min(v6.valid_until);
        v4.boot_valid_until = v4.boot_valid_until.min(v6.boot_valid_until);
        if v4.valid_until <= Instant::now()
            || v4.boot_valid_until <= boottime_now().ok_or(ResolverError::Unavailable)?
        {
            return Err(ResolverError::Unavailable);
        }
        v4.addresses.extend(v6.addresses);
        Ok(v4)
    }

    /// Возвращает только адреса конечного владельца из секции Answer.
    /// Пустой набор означает NODATA с SOA зоны конечного имени.
    pub fn policy_rrset(&self) -> Result<PolicyRrset, ResolverError> {
        self.verify_policy_status()?;
        let packet = &self.packet;
        let (question, mut offset) = parse_question(packet, true)?;
        if question != self.question {
            return Err(ResolverError::Untrusted);
        }

        let mut aliases = BTreeMap::<Vec<u8>, (Vec<u8>, u32)>::new();
        let mut addresses = BTreeSet::new();
        let mut address_owner = None;
        let mut address_ttl = MAX_TTL;
        let mut negative_zones = Vec::new();
        let mut has_opt = false;
        for (section, count) in section_counts(packet)?.into_iter().enumerate() {
            for _ in 0..count {
                let record = read_record(packet, &mut offset)?;
                if record.kind == 41 {
                    if section != 2 || has_opt || record.owner != [0] || record.ttl >> 16 != 0 {
                        return Err(ResolverError::Untrusted);
                    }
                    has_opt = true;
                    continue;
                }
                match (section, record.class, record.kind) {
                    (0, 1, 5) => insert_alias(packet, record, &mut aliases)?,
                    (0, 1, kind) if kind == question.qtype => {
                        let address = record.address(packet)?.ok_or(ResolverError::Malformed)?;
                        match &address_owner {
                            None => address_owner = Some(record.owner),
                            Some(owner) if owner != &record.owner => {
                                return Err(ResolverError::Untrusted);
                            }
                            Some(_) => {}
                        }
                        address_ttl = address_ttl.min(positive_ttl(record.ttl)?);
                        addresses.insert(address);
                        if addresses.len() > MAX_ADDRESSES {
                            return Err(ResolverError::Limit);
                        }
                    }
                    (0, 1, 46) => {} // RRSIG не является адресом или путём CNAME.
                    (0, _, _) => return Err(ResolverError::Untrusted),
                    (1, 1, 6) => negative_zones.push(record),
                    _ => {}
                }
            }
        }
        if offset != packet.len() {
            return Err(ResolverError::Malformed);
        }

        let mut terminal = question.name;
        let mut visited = BTreeSet::new();
        let mut ttl = MAX_TTL;
        while let Some((next, alias_ttl)) = aliases.remove(&terminal) {
            if address_owner.as_ref() == Some(&terminal) {
                return Err(ResolverError::Untrusted);
            }
            visited.insert(terminal);
            terminal = next;
            ttl = ttl.min(alias_ttl);
        }
        if !aliases.is_empty() || visited.contains(&terminal) {
            return Err(ResolverError::Untrusted);
        }
        let terminal_ttl = match address_owner {
            Some(owner) if owner == terminal => address_ttl,
            Some(_) => return Err(ResolverError::Untrusted),
            None => {
                let mut authority = negative_zones
                    .iter()
                    .filter(|record| covers_name(&record.owner, &terminal));
                let first = authority.next().ok_or(ResolverError::Unavailable)?;
                authority.try_fold(negative_ttl(packet, first)?, |ttl, record| {
                    Ok(ttl.min(negative_ttl(packet, record)?))
                })?
            }
        };
        let valid_until = self
            .received_at
            .checked_add(Duration::from_secs(u64::from(ttl.min(terminal_ttl))))
            .filter(|&until| until > Instant::now())
            .ok_or(ResolverError::Unavailable)?;
        let now_boottime = boottime_now().ok_or(ResolverError::Unavailable)?;
        let boot_valid_until = self
            .received_boottime
            .checked_add(Duration::from_secs(u64::from(ttl.min(terminal_ttl))))
            .filter(|&until| until > now_boottime)
            .ok_or(ResolverError::Unavailable)?;
        Ok(PolicyRrset {
            addresses: addresses.into_iter().collect(),
            valid_until,
            boot_valid_until,
            terminal,
        })
    }
}

fn insert_alias(
    packet: &[u8],
    record: ResourceRecord,
    aliases: &mut BTreeMap<Vec<u8>, (Vec<u8>, u32)>,
) -> Result<(), ResolverError> {
    let (target, end) = decode_name(packet, record.data.start, true)?;
    if end != record.data.end || target == [0] {
        return Err(ResolverError::Malformed);
    }
    let ttl = positive_ttl(record.ttl)?;
    match aliases.entry(record.owner) {
        Entry::Vacant(entry) => {
            entry.insert((target, ttl));
        }
        Entry::Occupied(mut entry) if entry.get().0 == target => {
            let kept_ttl = &mut entry.get_mut().1;
            *kept_ttl = (*kept_ttl).min(ttl);
        }
        Entry::Occupied(_) => return Err(ResolverError::Untrusted),
    }
    Ok(())
}

fn positive_ttl(ttl: u32) -> Result<u32, ResolverError> {
    (1..=MAX_TTL)
        .contains(&ttl)
        .then_some(ttl)
        .ok_or(ResolverError::Unavailable)
}

fn negative_ttl(packet: &[u8], record: &ResourceRecord) -> Result<u32, ResolverError> {
    let (_, end_mname) = decode_name(packet, record.data.start, true)?;
    let (_, end_rname) = decode_name(packet, end_mname, true)?;
    if end_rname + 20 != record.data.end {
        return Err(ResolverError::Malformed);
    }
    let ttl = positive_ttl(record.ttl)?;
    positive_ttl(ttl.min(read_u32(packet, end_rname + 16)?))
}

fn covers_name(zone: &[u8], mut name: &[u8]) -> bool {
    loop {
        if name == zone {
            return true;
        }
        if name[0] == 0 {
            return false;
        }
        name = &name[1 + usize::from(name[0])..];
    }
}

#[cfg(test)]
mod tests {
    use super::super::ForwardPeer;
    use super::*;
    use crate::{
        Cancellation,
        resolver::{
            dot::{DotPeer, DotPolicy},
            forward::forward_udp,
        },
    };
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};
    use tokio::net::UdpSocket;
    use yonik_engine::{
        fake_dns::{DnsEpoch, FakeMapping},
        resource_bundle::{
            Action, AnswerSet, Conditions, Destination, DestinationFlow, Evaluation,
            EvaluationContext, Policy, Resolution, ResolverPath, Route, Rule,
        },
    };

    const HOST: &[u8] = b"\x04host\x04test\x00";
    const ALIAS: &[u8] = b"\x05alias\x04test\x00";
    const ZONE: &[u8] = b"\x04test\x00";
    const HOST_POINTER: &[u8] = &[0xc0, 0x0c];

    fn record(owner: &[u8], kind: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
        let mut result = owner.to_vec();
        result.extend_from_slice(&kind.to_be_bytes());
        result.extend_from_slice(&1u16.to_be_bytes());
        result.extend_from_slice(&ttl.to_be_bytes());
        result.extend_from_slice(&(data.len() as u16).to_be_bytes());
        result.extend_from_slice(data);
        result
    }

    fn soa(owner: &[u8]) -> Vec<u8> {
        let mut data = Vec::from(ZONE);
        data.extend_from_slice(ZONE);
        for value in [1u32, 3600, 600, 86_400, 17] {
            data.extend_from_slice(&value.to_be_bytes());
        }
        record(owner, 6, 30, &data)
    }

    async fn exchange(
        qtype: u16,
        flags: u16,
        answers: &[Vec<u8>],
        authority: &[Vec<u8>],
        additional: &[Vec<u8>],
    ) -> ForwardResponse {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        exchange_from(&server, qtype, flags, answers, authority, additional).await
    }

    async fn exchange_from(
        server: &UdpSocket,
        qtype: u16,
        flags: u16,
        answers: &[Vec<u8>],
        authority: &[Vec<u8>],
        additional: &[Vec<u8>],
    ) -> ForwardResponse {
        let peer = server.local_addr().unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.connect(peer).await.unwrap();
        let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(HOST);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        let send = async {
            let mut packet = [0; 4096];
            let (len, address) = server.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[2..len], &query[2..]);
            let mut response = packet[..len].to_vec();
            response[2..4].copy_from_slice(&flags.to_be_bytes());
            for (index, records) in [answers, authority, additional].into_iter().enumerate() {
                let count = records.len() as u16;
                let offset = 6 + index * 2;
                response[offset..offset + 2].copy_from_slice(&count.to_be_bytes());
                for record in records {
                    response.extend_from_slice(record);
                }
            }
            server.send_to(&response, address).await.unwrap();
        };
        let (_owner, mut cancel) = Cancellation::new();
        let (response, ()) = tokio::join!(
            forward_udp(&client, peer, &query, Duration::from_secs(2), &mut cancel),
            async {
                tokio::time::timeout(Duration::from_secs(2), send)
                    .await
                    .unwrap()
            }
        );
        response.unwrap()
    }

    #[tokio::test]
    async fn cname_ограничивает_адреса_и_ttl() {
        let reply = exchange(
            1,
            0x8180,
            &[
                record(ALIAS, 1, 60, &[192, 0, 2, 2]),
                record(HOST_POINTER, 5, 13, ALIAS),
            ],
            &[],
            &[record(ZONE, 1, 120, &[203, 0, 113, 2])],
        )
        .await;
        let result = reply.policy_rrset().unwrap();
        assert_eq!(result.addresses(), &[IpAddr::from([192, 0, 2, 2])]);
        assert_eq!(
            result.valid_until(),
            reply.received_at + Duration::from_secs(13)
        );
    }

    #[tokio::test]
    async fn nodata_требует_soa_для_зоны_имени() {
        let good = exchange(28, 0x8180, &[], &[soa(ZONE)], &[]).await;
        let result = good.policy_rrset().unwrap();
        assert!(result.addresses().is_empty());
        assert_eq!(
            result.valid_until(),
            good.received_at + Duration::from_secs(17)
        );
        for authority in [vec![], vec![soa(b"\x05other\x00")]] {
            let incomplete = exchange(28, 0x8180, &[], &authority, &[]).await;
            assert!(incomplete.policy_rrset().is_err());
        }
    }

    #[tokio::test]
    async fn неверный_ответ_не_даёт_адрес_для_политики() {
        let address = record(HOST_POINTER, 1, 60, &[192, 0, 2, 2]);
        for flags in [0x8182, 0x8380] {
            let reply = exchange(1, flags, std::slice::from_ref(&address), &[], &[]).await;
            assert!(reply.policy_rrset().is_err());
        }
        let opt = record(&[0], 41, 0x01000000, &[]);
        let extended_error = exchange(1, 0x8180, &[address], &[], &[opt]).await;
        assert!(extended_error.policy_rrset().is_err());
        for answers in [
            vec![record(ALIAS, 1, 60, &[192, 0, 2, 2])],
            vec![
                record(HOST_POINTER, 5, 60, ALIAS),
                record(ALIAS, 5, 60, HOST_POINTER),
            ],
            vec![
                record(HOST_POINTER, 5, 60, ALIAS),
                record(HOST_POINTER, 5, 60, ZONE),
            ],
        ] {
            let reply = exchange(1, 0x8180, &answers, &[soa(ZONE)], &[]).await;
            assert!(reply.policy_rrset().is_err());
        }
    }

    #[tokio::test]
    async fn aaaa_сохраняет_срок_от_момента_получения() {
        let ip = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42);
        let mut reply = exchange(
            28,
            0x8180,
            &[record(HOST_POINTER, 28, 5, &ip.octets())],
            &[],
            &[],
        )
        .await;
        let result = reply.policy_rrset().unwrap();
        assert_eq!(result.addresses(), &[IpAddr::V6(ip)]);
        assert_eq!(
            result.valid_until(),
            reply.received_at + Duration::from_secs(5)
        );
        reply.received_at -= Duration::from_secs(5);
        assert_eq!(reply.policy_rrset(), Err(ResolverError::Unavailable));
    }

    #[tokio::test]
    async fn срок_dns_истекает_во_время_suspended_системы() {
        let mut response = exchange(
            1,
            0x8180,
            &[record(HOST_POINTER, 1, 5, &[192, 0, 2, 2])],
            &[],
            &[],
        )
        .await;
        response.received_boottime -= Duration::from_secs(6);
        assert_eq!(
            response.policy_rrset(),
            Err(ResolverError::Unavailable),
            "ответ с истёкшим сроком должен отклоняться по часам, учитывающим suspend"
        );
    }

    #[tokio::test]
    async fn истечение_одной_семьи_отвергает_всю_пару() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut a = exchange_from(
            &server,
            1,
            0x8180,
            &[record(HOST_POINTER, 1, 5, &[192, 0, 2, 2])],
            &[],
            &[],
        )
        .await;
        let aaaa = exchange_from(
            &server,
            28,
            0x8180,
            &[record(
                HOST_POINTER,
                28,
                30,
                &"2001:db8::42"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            )],
            &[],
            &[],
        )
        .await;
        a.received_boottime -= Duration::from_secs(6);
        assert_eq!(
            a.policy_address_pair(&aaaa),
            Err(ResolverError::Unavailable)
        );
    }

    #[tokio::test]
    async fn пара_требует_один_узел_и_ограничена_ближайшим_ttl() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let a = exchange_from(
            &server,
            1,
            0x8180,
            &[record(HOST_POINTER, 1, 60, &[192, 0, 2, 2])],
            &[],
            &[],
        )
        .await;
        let nodata = exchange_from(&server, 28, 0x8180, &[], &[soa(ZONE)], &[]).await;
        let set = a.policy_address_pair(&nodata).unwrap();
        assert_eq!(set.addresses(), &[IpAddr::from([192, 0, 2, 2])]);
        assert_eq!(
            set.valid_until(),
            nodata.received_at + Duration::from_secs(17)
        );
        let wrong_peer = exchange(28, 0x8180, &[], &[soa(ZONE)], &[]).await;
        assert_eq!(
            a.policy_address_pair(&wrong_peer),
            Err(ResolverError::Untrusted)
        );
        assert_eq!(a.policy_address_pair(&a), Err(ResolverError::Untrusted));
        let wrong_terminal = exchange_from(
            &server,
            28,
            0x8180,
            &[record(HOST_POINTER, 5, 60, ALIAS)],
            &[soa(ZONE)],
            &[],
        )
        .await;
        assert_eq!(
            a.policy_address_pair(&wrong_terminal),
            Err(ResolverError::Untrusted)
        );
        let failed = exchange_from(&server, 28, 0x8182, &[], &[], &[]).await;
        assert!(a.policy_address_pair(&failed).is_err());
        let address = server.local_addr().unwrap();
        let peer = |name| {
            Arc::new(
                DotPeer::new(
                    DotPolicy::opportunistic().unwrap(),
                    address.ip(),
                    Some(name),
                )
                .unwrap(),
            )
        };
        let mut switched_transport = nodata;
        let tls = ForwardPeer::Tls(address, peer("one.test"));
        switched_transport.peer = tls.clone();
        assert_eq!(
            a.policy_address_pair(&switched_transport),
            Err(ResolverError::Untrusted)
        );
        let mut a_tls = a;
        a_tls.peer = tls;
        assert!(a_tls.policy_address_pair(&switched_transport).is_ok());
        switched_transport.peer = ForwardPeer::Tls(address, peer("other.test"));
        assert_eq!(
            a_tls.policy_address_pair(&switched_transport),
            Err(ResolverError::Untrusted)
        );
    }

    #[tokio::test]
    async fn сетевые_a_и_aaaa_участвуют_в_выборе_маршрута_fake_ip() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let ip4 = IpAddr::from([192, 0, 2, 2]);
        let ip6: std::net::Ipv6Addr = "2001:db8::42".parse().unwrap();
        let a = exchange_from(
            &server,
            1,
            0x8180,
            &[record(HOST_POINTER, 1, 40, &[192, 0, 2, 2])],
            &[],
            &[],
        )
        .await;
        let aaaa = exchange_from(
            &server,
            28,
            0x8180,
            &[record(HOST_POINTER, 28, 10, &ip6.octets())],
            &[],
            &[],
        )
        .await;
        let verified = a.policy_address_pair(&aaaa).unwrap();
        assert_eq!(verified.addresses(), &[ip4, IpAddr::V6(ip6)]);
        assert_eq!(
            verified.valid_until(),
            aaaa.received_at + Duration::from_secs(10)
        );
        let epoch = DnsEpoch::default();
        let deadline = u64::try_from(
            verified
                .valid_until()
                .duration_since(a.received_at)
                .as_nanos(),
        )
        .unwrap();
        let mapping = FakeMapping {
            address: "198.18.0.2".parse().unwrap(),
            name: "host.test".parse().unwrap(),
            epoch,
            expires_at: Duration::from_secs(30).as_nanos() as u64,
        };
        let flow = DestinationFlow {
            executable: None,
            destination: Destination::Fake {
                address: mapping.address,
                mapping: Some(&mapping),
                resolution: Resolution::Answer(AnswerSet {
                    addresses: verified.addresses(),
                    complete: true,
                    expires_at: deadline,
                    epoch,
                    path: ResolverPath::Policy,
                }),
            },
        };
        let policy = Policy {
            user_rules: vec![Rule {
                id: 1,
                enabled: true,
                action: Action::Proxy,
                conditions: Conditions {
                    destinations: vec!["2001:db8::/32".parse().unwrap()],
                    ..Default::default()
                },
            }],
            default_action: Action::Block,
            ..Default::default()
        };
        let pools = ["198.18.0.0/15".parse().unwrap()];
        let mut context = EvaluationContext {
            now: 1,
            epoch,
            fake_pools: &pools,
        };
        assert!(matches!(
            policy.evaluate_destination(&flow, &context),
            Evaluation::Decided {
                decision,
                selected_address: Some(address),
                ..
            } if decision.action == Route::Proxy && address == IpAddr::V6(ip6)
        ));
        context.now = deadline;
        assert_eq!(
            policy.evaluate_destination(&flow, &context),
            Evaluation::NeedResolution(ResolverPath::Policy)
        );
    }
}
