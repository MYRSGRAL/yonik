//! Ограниченный DNS wire-адаптер для синтетических A/AAAA ответов.

use std::{net::IpAddr, str::FromStr};

use yonik_domain::FakeIpError;

pub use yonik_domain::{DnsEpoch, DomainName, FakeIpFamily, FakeIpLeaseTable, FakeMapping};

const HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
pub const MAX_DNS_PACKET: usize = 4096;
const MAX_EDNS_UDP_SIZE: u16 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeDnsError {
    Malformed,
    Unsupported,
    DnssecRequested,
    LeaseExpired,
    Lease(FakeIpError),
}

impl From<FakeIpError> for FakeDnsError {
    fn from(value: FakeIpError) -> Self {
        Self::Lease(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuestionKind {
    A,
    Aaaa,
    Unsupported(u16),
}

/// Проверенный единичный DNS вопрос. Имя и исходный wire вопрос сохранены отдельно.
#[derive(Clone, PartialEq, Eq)]
pub struct FakeDnsQuestion {
    id: u16,
    recursion_desired: bool,
    checking_disabled: bool,
    name: DomainName,
    wire_name: Vec<u8>,
    qtype: u16,
    kind: QuestionKind,
    edns: bool,
}

impl std::fmt::Debug for FakeDnsQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeDnsQuestion")
            .field("qtype", &self.qtype)
            .field("edns", &self.edns)
            .finish_non_exhaustive()
    }
}

impl FakeDnsQuestion {
    /// Корректный DNS-ответ без адреса для запроса, отклонённого политикой.
    pub fn refused(&self) -> Vec<u8> {
        self.error_response(5)
    }

    /// Ошибка подготовленного маршрута или отсутствие подходящего DNS backend.
    pub fn unavailable(&self) -> Vec<u8> {
        self.error_response(2)
    }

    /// Разбирает ровно один IN вопрос и не более одной корректной EDNS v0 OPT.
    pub fn parse(packet: &[u8]) -> Result<Self, FakeDnsError> {
        if packet.len() < HEADER_LEN || packet.len() > MAX_DNS_PACKET {
            return Err(FakeDnsError::Malformed);
        }
        let flags = read_u16(packet, 2)?;
        let qd = read_u16(packet, 4)?;
        let an = read_u16(packet, 6)?;
        let ns = read_u16(packet, 8)?;
        let ar = read_u16(packet, 10)?;
        if flags & 0xfecf != 0 || qd != 1 || an != 0 || ns != 0 || ar > 1 {
            return Err(FakeDnsError::Malformed);
        }
        let mut offset = HEADER_LEN;
        let start = offset;
        let mut labels = Vec::new();
        let mut wire_name_len = 1usize;
        loop {
            let label_len = *packet.get(offset).ok_or(FakeDnsError::Malformed)? as usize;
            offset += 1;
            if label_len == 0 {
                break;
            }
            if label_len & 0xc0 != 0
                || label_len > 63
                || offset
                    .checked_add(label_len)
                    .is_none_or(|end| end > packet.len())
            {
                return Err(FakeDnsError::Malformed);
            }
            wire_name_len = wire_name_len
                .checked_add(label_len + 1)
                .ok_or(FakeDnsError::Malformed)?;
            if wire_name_len > 255 {
                return Err(FakeDnsError::Malformed);
            }
            let label = std::str::from_utf8(&packet[offset..offset + label_len])
                .map_err(|_| FakeDnsError::Malformed)?;
            if !label.is_ascii() || label.as_bytes().contains(&b'.') {
                return Err(FakeDnsError::Malformed);
            }
            labels.push(label);
            offset += label_len;
        }
        if labels.is_empty() {
            return Err(FakeDnsError::Malformed);
        }
        let name = DomainName::from_str(&labels.join(".")).map_err(|_| FakeDnsError::Malformed)?;
        let question_end = offset.checked_add(4).ok_or(FakeDnsError::Malformed)?;
        if question_end > packet.len() {
            return Err(FakeDnsError::Malformed);
        }
        let qtype = read_u16(packet, offset)?;
        let qclass = read_u16(packet, offset + 2)?;
        if qclass != CLASS_IN {
            return Err(FakeDnsError::Unsupported);
        }
        offset = question_end;
        let edns = ar == 1;
        if edns {
            if packet.len().saturating_sub(offset) < 11
                || packet[offset] != 0
                || read_u16(packet, offset + 1)? != TYPE_OPT
            {
                return Err(FakeDnsError::Malformed);
            }
            let udp_size = read_u16(packet, offset + 3)?;
            let ttl = read_u32(packet, offset + 5)?;
            let rdlen = usize::from(read_u16(packet, offset + 9)?);
            let end = offset
                .checked_add(11)
                .and_then(|n| n.checked_add(rdlen))
                .ok_or(FakeDnsError::Malformed)?;
            if !(512..=MAX_EDNS_UDP_SIZE).contains(&udp_size)
                || ttl >> 24 != 0
                || ((ttl >> 16) & 0xff) != 0
                || end != packet.len()
            {
                return Err(FakeDnsError::Malformed);
            }
            if ttl & 0x8000 != 0 {
                return Err(FakeDnsError::DnssecRequested);
            }
            if ttl & 0x7fff != 0 {
                return Err(FakeDnsError::Malformed);
            }
            let mut option_offset = offset + 11;
            while option_offset < end {
                let option_len = usize::from(read_u16(packet, option_offset + 2)?);
                option_offset = option_offset
                    .checked_add(4)
                    .and_then(|n| n.checked_add(option_len))
                    .filter(|n| *n <= end)
                    .ok_or(FakeDnsError::Malformed)?;
            }
            offset = end;
        }
        if offset != packet.len() {
            return Err(FakeDnsError::Malformed);
        }
        let wire_name = packet[start..question_end - 4].to_vec();
        let kind = match qtype {
            TYPE_A => QuestionKind::A,
            TYPE_AAAA => QuestionKind::Aaaa,
            other => QuestionKind::Unsupported(other),
        };
        Ok(Self {
            id: read_u16(packet, 0)?,
            recursion_desired: flags & 0x0100 != 0,
            checking_disabled: flags & 0x0010 != 0,
            name,
            wire_name,
            qtype,
            kind,
            edns,
        })
    }

    pub fn name(&self) -> &DomainName {
        &self.name
    }
    pub fn qtype(&self) -> u16 {
        self.qtype
    }
    pub fn is_supported(&self) -> bool {
        matches!(self.kind, QuestionKind::A | QuestionKind::Aaaa)
    }
}

/// Выдаёт lease только после внешней policy-проверки. `now_ns` должен быть единым
/// монотонным источником; TTL аргумент и все тики измеряются в наносекундах.
pub fn answer_approved(
    question: &FakeDnsQuestion,
    leases: &mut FakeIpLeaseTable,
    epoch: DnsEpoch,
    ttl_seconds: u32,
    mut now_ns: impl FnMut() -> u64,
) -> Result<Vec<u8>, FakeDnsError> {
    let family = match question.kind {
        QuestionKind::A => FakeIpFamily::V4,
        QuestionKind::Aaaa => FakeIpFamily::V6,
        QuestionKind::Unsupported(_) => return Err(FakeDnsError::Unsupported),
    };
    let request_ns = now_ns();
    let ttl_ns = u64::from(ttl_seconds)
        .checked_mul(1_000_000_000)
        .ok_or(FakeDnsError::Malformed)?;
    let grant = match leases.issue(question.name.clone(), family, epoch, request_ns, ttl_ns) {
        Ok(grant) => grant,
        Err(FakeIpError::CapacityExhausted) => return Ok(question.error_response(2)),
        Err(error) => return Err(error.into()),
    };
    let publish_ns = now_ns();
    if publish_ns < request_ns {
        return Err(FakeDnsError::Lease(FakeIpError::ClockMovedBackwards));
    }
    let remaining = grant
        .expires_at
        .checked_sub(publish_ns)
        .filter(|remaining| *remaining > 0)
        .ok_or(FakeDnsError::LeaseExpired)?;
    let ttl =
        u32::try_from((remaining / 1_000_000_000).min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
    let address = grant.address;
    let mut response = question.base_response(0);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&question.qtype.to_be_bytes());
    response.extend_from_slice(&CLASS_IN.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    match address {
        IpAddr::V4(ip) => {
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            response.extend_from_slice(&16u16.to_be_bytes());
            response.extend_from_slice(&ip.octets());
        }
    }
    if question.edns {
        append_opt(&mut response);
    }
    set_counts(&mut response, 1, 0, u16::from(question.edns));
    Ok(response)
}

impl FakeDnsQuestion {
    fn base_response(&self, rcode: u16) -> Vec<u8> {
        let mut flags = 0x8000 | (rcode & 0xf);
        if self.recursion_desired {
            flags |= 0x0100;
        }
        if self.checking_disabled {
            flags |= 0x0010;
        }
        let mut response = Vec::with_capacity(64);
        response.extend_from_slice(&self.id.to_be_bytes());
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&self.wire_name);
        response.extend_from_slice(&self.qtype.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response
    }
    fn error_response(&self, rcode: u16) -> Vec<u8> {
        let mut response = self.base_response(rcode);
        if self.edns {
            append_opt(&mut response);
            set_counts(&mut response, 0, 0, 1);
        }
        response
    }
}

fn append_opt(packet: &mut Vec<u8>) {
    packet.extend_from_slice(&[0, 0, TYPE_OPT as u8, 0x10, 0, 0, 0, 0, 0, 0, 0]);
}
fn set_counts(packet: &mut [u8], answers: u16, authority: u16, additional: u16) {
    packet[6..8].copy_from_slice(&answers.to_be_bytes());
    packet[8..10].copy_from_slice(&authority.to_be_bytes());
    packet[10..12].copy_from_slice(&additional.to_be_bytes());
}
fn read_u16(packet: &[u8], offset: usize) -> Result<u16, FakeDnsError> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or(FakeDnsError::Malformed)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
fn read_u32(packet: &[u8], offset: usize) -> Result<u32, FakeDnsError> {
    let bytes = packet
        .get(offset..offset + 4)
        .ok_or(FakeDnsError::Malformed)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn query(qtype: u16, labels: &[&str]) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in labels {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.extend_from_slice(&[0, (qtype >> 8) as u8, qtype as u8, 0, 1]);
        packet
    }
    fn leases() -> FakeIpLeaseTable {
        FakeIpLeaseTable::new([
            "198.18.0.1".parse::<IpAddr>().expect("ip"),
            "fd00::1".parse::<IpAddr>().expect("ip"),
        ])
        .expect("pool")
    }
    fn epoch() -> DnsEpoch {
        DnsEpoch {
            network: 1,
            engine: 2,
            resolver: 3,
        }
    }

    #[test]
    fn synthesizes_a_aaaa_and_reuses_same_lease_without_extending_ttl() {
        let mut table = leases();
        let a = FakeDnsQuestion::parse(&query(TYPE_A, &["Example", "com"])).expect("question");
        let response =
            answer_approved(&a, &mut table, epoch(), 20, || 1_000_000_000).expect("answer");
        assert_eq!(read_u16(&response, 6), Ok(1));
        assert_eq!(&response[response.len() - 4..], &[198, 18, 0, 1]);
        let again =
            answer_approved(&a, &mut table, epoch(), 100, || 3_000_000_000).expect("repeat");
        assert_eq!(read_u32(&again, again.len() - 10), Ok(18));
        let aaaa = FakeDnsQuestion::parse(&query(TYPE_AAAA, &["v6", "example"])).expect("question");
        let response =
            answer_approved(&aaaa, &mut table, epoch(), 5, || 4_000_000_000).expect("answer");
        assert_eq!(
            &response[response.len() - 16..],
            &"fd00::1"
                .parse::<IpAddr>()
                .expect("ip")
                .to_string()
                .parse::<std::net::Ipv6Addr>()
                .expect("v6")
                .octets()
        );
    }

    #[test]
    fn malformed_names_trailing_bytes_and_dnssec_are_rejected() {
        let compressed = [
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1,
        ];
        assert_eq!(
            FakeDnsQuestion::parse(&compressed),
            Err(FakeDnsError::Malformed)
        );
        assert_eq!(
            FakeDnsQuestion::parse(&query(TYPE_A, &["a.example"])),
            Err(FakeDnsError::Malformed)
        );
        let mut trailing = query(TYPE_A, &["a", "example"]);
        trailing.push(0);
        assert_eq!(
            FakeDnsQuestion::parse(&trailing),
            Err(FakeDnsError::Malformed)
        );
        let mut opt_query = query(TYPE_A, &["a", "example"]);
        opt_query[10..12].copy_from_slice(&1u16.to_be_bytes());
        opt_query.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0]);
        assert_eq!(
            FakeDnsQuestion::parse(&opt_query),
            Err(FakeDnsError::DnssecRequested)
        );
    }

    #[test]
    fn publication_ttl_rounds_down_and_valid_edns_is_echoed() {
        let mut packet = query(TYPE_A, &["a", "example"]);
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        let question = FakeDnsQuestion::parse(&packet).expect("EDNS question");
        let mut ticks = [0, 1_500_000_000].into_iter();
        let response = answer_approved(&question, &mut leases(), epoch(), 2, || {
            ticks.next().expect("two clock reads")
        })
        .expect("answer");
        assert_eq!(read_u16(&response, 10), Ok(1));
        assert_eq!(response.len(), packet.len() + 16);
        assert_eq!(read_u32(&response, response.len() - 21), Ok(0));
        assert_eq!(
            &response[response.len() - 11..],
            &[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn rejects_lease_that_expires_before_publication() {
        let question = FakeDnsQuestion::parse(&query(TYPE_A, &["a", "example"])).expect("question");
        let mut ticks = [0, 1_000_000_000].into_iter();
        assert_eq!(
            answer_approved(&question, &mut leases(), epoch(), 1, || {
                ticks.next().expect("two clock reads")
            }),
            Err(FakeDnsError::LeaseExpired)
        );
    }

    #[test]
    fn unsupported_types_and_pool_exhaustion_are_explicit() {
        let parsed =
            FakeDnsQuestion::parse(&query(15, &["mail", "example"])).expect("parsed unsupported");
        assert!(!parsed.is_supported());
        assert_eq!(
            answer_approved(&parsed, &mut leases(), epoch(), 4, || 0),
            Err(FakeDnsError::Unsupported)
        );
        let mut table = FakeIpLeaseTable::new(["198.18.0.1".parse().expect("ip")]).expect("pool");
        let first = FakeDnsQuestion::parse(&query(TYPE_A, &["a", "example"])).expect("question");
        answer_approved(&first, &mut table, epoch(), 20, || 0).expect("first");
        let second = FakeDnsQuestion::parse(&query(TYPE_A, &["b", "example"])).expect("question");
        let response = answer_approved(&second, &mut table, epoch(), 20, || 1).expect("servfail");
        assert_eq!(read_u16(&response, 2).map(|flags| flags & 0xf), Ok(2));
        assert_eq!(read_u16(&response, 6), Ok(0));
    }
}
