//! Ограниченный реестр Fake-IP. Пул передаётся готовым списком адресов:
//! модуль не разворачивает CIDR и не делает предположений о его размере.

use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
};

use crate::{DnsEpoch, DomainName, FakeMapping};

const MAX_POOL_ADDRESSES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeIpError {
    EmptyPool,
    PoolTooLarge,
    DuplicateAddress,
    InvalidAddress,
    ZeroTtl,
    CapacityExhausted,
    StaleEpoch,
    ClockMovedBackwards,
    TimeOverflow,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FakeIpGrant {
    pub address: IpAddr,
    /// Остаток исходного lease; повторный запрос TTL не продлевает.
    pub remaining_ttl: u64,
    pub expires_at: u64,
    pub reused: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FakeIpFamily {
    V4,
    V6,
}

impl FakeIpFamily {
    fn index(self) -> usize {
        match self {
            Self::V4 => 0,
            Self::V6 => 1,
        }
    }
}

#[derive(Debug)]
struct Lease {
    name: DomainName,
    epoch: DnsEpoch,
    expires_at: u64,
}

/// `now`, TTL и expiry — тики одного монотонного источника времени.
/// Адаптер DNS должен округлить остаток вниз в секунды непосредственно перед
/// отправкой ответа; задержка wire-кодирования не должна продлевать TTL.
/// Доступ к таблице должен быть сериализован владельцем; методы изменяют
/// forward и reverse индексы через эксклюзивный `&mut self`.
pub struct FakeIpLeaseTable {
    free: [BTreeSet<IpAddr>; 2],
    leases: HashMap<IpAddr, Lease>,
    by_name: [HashMap<String, IpAddr>; 2],
    expirations: BTreeSet<(u64, IpAddr)>,
    current_epoch: Option<DnsEpoch>,
    last_now: Option<u64>,
}

impl FakeIpLeaseTable {
    /// Принимает только конечный, уже ограниченный набор адресов; размер
    /// входа одновременно является жёсткой верхней границей активных leases.
    pub fn new(addresses: impl IntoIterator<Item = IpAddr>) -> Result<Self, FakeIpError> {
        let mut free = [BTreeSet::new(), BTreeSet::new()];
        for (count, address) in addresses.into_iter().enumerate() {
            if count >= MAX_POOL_ADDRESSES {
                return Err(FakeIpError::PoolTooLarge);
            }
            if invalid_fake_address(address) {
                return Err(FakeIpError::InvalidAddress);
            }
            if !free[address_index(address)].insert(address) {
                return Err(FakeIpError::DuplicateAddress);
            }
        }
        if free.iter().all(BTreeSet::is_empty) {
            return Err(FakeIpError::EmptyPool);
        }
        Ok(Self {
            free,
            leases: HashMap::new(),
            by_name: [HashMap::new(), HashMap::new()],
            expirations: BTreeSet::new(),
            current_epoch: None,
            last_now: None,
        })
    }

    /// Обновляет epoch: старые записи перестают находиться сразу, но их IP
    /// остаются заняты до исходного expiry.
    pub fn advance_epoch(&mut self, epoch: DnsEpoch, now: u64) -> Result<(), FakeIpError> {
        self.observe_time(now)?;
        self.expire(now);
        if self.current_epoch != Some(epoch) {
            self.by_name.iter_mut().for_each(HashMap::clear);
            self.current_epoch = Some(epoch);
        }
        Ok(())
    }

    /// Выдаёт адрес на TTL. Повтор того же имени в текущем epoch возвращает
    /// прежний адрес и остаток lease без продления срока.
    pub fn issue(
        &mut self,
        name: DomainName,
        family: FakeIpFamily,
        epoch: DnsEpoch,
        now: u64,
        ttl: u64,
    ) -> Result<FakeIpGrant, FakeIpError> {
        if ttl == 0 {
            return Err(FakeIpError::ZeroTtl);
        }
        let expires_at = now.checked_add(ttl).ok_or(FakeIpError::TimeOverflow)?;
        self.observe_time(now)?;
        self.expire(now);
        if self.current_epoch.is_some_and(|current| current != epoch) {
            return Err(FakeIpError::StaleEpoch);
        }
        if self.current_epoch.is_none() {
            self.current_epoch = Some(epoch);
        }

        let index = family.index();
        let by_name = &mut self.by_name[index];
        if let Some(address) = by_name.get(name.as_str()).copied() {
            if let Some(lease) = self.leases.get(&address) {
                let remaining_ttl = lease.expires_at.saturating_sub(now);
                if remaining_ttl > 0 && lease.epoch == epoch {
                    return Ok(FakeIpGrant {
                        address,
                        remaining_ttl,
                        expires_at: lease.expires_at,
                        reused: true,
                    });
                }
            }
            by_name.remove(name.as_str());
        }

        let address = self.free[index]
            .pop_first()
            .ok_or(FakeIpError::CapacityExhausted)?;
        by_name.insert(name.as_str().to_owned(), address);
        self.leases.insert(
            address,
            Lease {
                name,
                epoch,
                expires_at,
            },
        );
        self.expirations.insert((expires_at, address));
        Ok(FakeIpGrant {
            address,
            remaining_ttl: ttl,
            expires_at,
            reused: false,
        })
    }

    /// Обратный lookup доступен только для активной записи текущего epoch.
    pub fn lookup(
        &mut self,
        address: IpAddr,
        epoch: DnsEpoch,
        now: u64,
    ) -> Result<Option<FakeMapping>, FakeIpError> {
        self.observe_time(now)?;
        self.expire(now);
        if self.current_epoch != Some(epoch) {
            return Ok(None);
        }
        Ok(self.leases.get(&address).and_then(|lease| {
            (lease.epoch == epoch
                && lease.expires_at > now
                && self.by_name[address_index(address)].get(lease.name.as_str()) == Some(&address))
            .then(|| FakeMapping {
                address,
                name: lease.name.clone(),
                epoch: lease.epoch,
                expires_at: lease.expires_at,
            })
        }))
    }

    fn observe_time(&mut self, now: u64) -> Result<(), FakeIpError> {
        if self.last_now.is_some_and(|last| now < last) {
            return Err(FakeIpError::ClockMovedBackwards);
        }
        self.last_now = Some(now);
        Ok(())
    }

    fn expire(&mut self, now: u64) {
        while let Some(&(expires_at, address)) = self.expirations.first() {
            if expires_at > now {
                break;
            }
            self.expirations.pop_first();
            if let Some(lease) = self.leases.remove(&address) {
                let index = address_index(address);
                let by_name = &mut self.by_name[index];
                if by_name.get(lease.name.as_str()) == Some(&address) {
                    by_name.remove(lease.name.as_str());
                }
                self.free[index].insert(address);
            }
        }
    }
}

fn address_index(address: IpAddr) -> usize {
    usize::from(address.is_ipv6())
}

fn invalid_fake_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_loopback()
                || address.is_link_local()
        }
        IpAddr::V6(address) => {
            address.is_unspecified()
                || address.is_multicast()
                || address.to_ipv4_mapped().is_some()
                || address.is_loopback()
                || address.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use super::*;

    fn name(value: &str) -> DomainName {
        DomainName::from_str(value).expect("valid domain")
    }
    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid IP")
    }
    fn epoch(engine: u64) -> DnsEpoch {
        DnsEpoch {
            network: 1,
            engine,
            resolver: 1,
        }
    }

    #[test]
    fn one_address_is_quarantined_until_ttl_expiry() {
        let mut table = FakeIpLeaseTable::new([ip("198.18.0.1")]).expect("pool");
        let first = table
            .issue(name("a.example"), FakeIpFamily::V4, epoch(1), 10, 30)
            .expect("issue A");
        assert_eq!(
            table.issue(name("b.example"), FakeIpFamily::V4, epoch(1), 39, 30),
            Err(FakeIpError::CapacityExhausted)
        );
        assert_eq!(
            table
                .lookup(first.address, epoch(1), 39)
                .expect("lookup")
                .unwrap()
                .name,
            name("a.example")
        );
        let second = table
            .issue(name("b.example"), FakeIpFamily::V4, epoch(1), 40, 30)
            .expect("issue after expiry");
        assert_eq!(second.address, first.address);
    }

    #[test]
    fn duplicate_does_not_extend_lease_and_epoch_rollover_keeps_quarantine() {
        let mut table = FakeIpLeaseTable::new([ip("198.18.0.1")]).expect("pool");
        let first = table
            .issue(name("a.example"), FakeIpFamily::V4, epoch(1), 5, 10)
            .expect("issue");
        let repeat = table
            .issue(name("a.example"), FakeIpFamily::V4, epoch(1), 8, 100)
            .expect("repeat");
        assert!(repeat.reused);
        assert_eq!(repeat.remaining_ttl, 7);
        assert_eq!(repeat.expires_at, first.expires_at);
        table.advance_epoch(epoch(2), 9).expect("rollover");
        assert!(
            table
                .lookup(first.address, epoch(2), 9)
                .expect("new epoch lookup")
                .is_none()
        );
        assert_eq!(
            table.issue(name("b.example"), FakeIpFamily::V4, epoch(2), 9, 10),
            Err(FakeIpError::CapacityExhausted)
        );
        assert!(
            table
                .lookup(first.address, epoch(1), 9)
                .expect("old epoch lookup")
                .is_none()
        );
        assert_eq!(
            table
                .issue(name("b.example"), FakeIpFamily::V4, epoch(2), 15, 10)
                .expect("after expiry")
                .address,
            first.address
        );
    }

    #[test]
    fn reverse_lookup_does_not_resurrect_an_aba_lease() {
        let first_address = ip("198.18.0.1");
        let second_address = ip("198.18.0.2");
        let third_address = ip("198.18.0.3");
        let mut table =
            FakeIpLeaseTable::new([first_address, second_address, third_address]).expect("pool");
        let old = table
            .issue(name("a.example"), FakeIpFamily::V4, epoch(1), 0, 100)
            .expect("old A");
        table.advance_epoch(epoch(2), 1).expect("epoch B");
        table
            .issue(name("b.example"), FakeIpFamily::V4, epoch(2), 1, 100)
            .expect("B mapping");
        table.advance_epoch(epoch(1), 2).expect("epoch A again");
        let new = table
            .issue(name("a.example"), FakeIpFamily::V4, epoch(1), 2, 100)
            .expect("new A");
        assert_ne!(old.address, new.address);
        assert!(
            table
                .lookup(old.address, epoch(1), 2)
                .expect("old reverse lookup")
                .is_none()
        );
        assert_eq!(
            table
                .lookup(new.address, epoch(1), 2)
                .expect("current reverse lookup")
                .expect("current mapping")
                .name,
            name("a.example")
        );
    }

    #[test]
    fn rejects_family_conflicts_and_invalid_constraints() {
        assert!(matches!(
            FakeIpLeaseTable::new(std::iter::empty::<IpAddr>()),
            Err(FakeIpError::EmptyPool)
        ));
        assert!(matches!(
            FakeIpLeaseTable::new([ip("198.18.0.1"), ip("198.18.0.1")]),
            Err(FakeIpError::DuplicateAddress)
        ));
        assert!(matches!(
            FakeIpLeaseTable::new([ip("0.0.0.0")]),
            Err(FakeIpError::InvalidAddress)
        ));
        for invalid in ["127.0.0.1", "169.254.0.1", "::1", "fe80::1"] {
            assert!(matches!(
                FakeIpLeaseTable::new([ip(invalid)]),
                Err(FakeIpError::InvalidAddress)
            ));
        }
        let too_many = (1..=MAX_POOL_ADDRESSES + 1).map(|n| {
            let offset = u32::try_from(n).expect("bounded test range");
            IpAddr::V4(std::net::Ipv4Addr::from(0xc612_0000 + offset))
        });
        assert!(matches!(
            FakeIpLeaseTable::new(too_many),
            Err(FakeIpError::PoolTooLarge)
        ));
        let mut table = FakeIpLeaseTable::new([
            ip("198.18.0.1"),
            ip("198.18.0.2"),
            ip("fd00::1"),
            ip("fd00::2"),
        ])
        .expect("mixed-family pool");
        let v4 = table
            .issue(name("v4.example"), FakeIpFamily::V4, epoch(1), 0, 4)
            .expect("IPv4");
        let v6 = table
            .issue(name("v6.example"), FakeIpFamily::V6, epoch(1), 0, 4)
            .expect("IPv6");
        assert_ne!(v4.address.is_ipv4(), v6.address.is_ipv4());
        let a = table
            .issue(name("same.example"), FakeIpFamily::V4, epoch(1), 0, 4)
            .expect("A");
        let aaaa = table
            .issue(name("same.example"), FakeIpFamily::V6, epoch(1), 0, 4)
            .expect("AAAA");
        assert!(a.address.is_ipv4());
        assert!(aaaa.address.is_ipv6());
        assert_eq!(
            table.issue(name("zero.example"), FakeIpFamily::V4, epoch(1), 0, 0),
            Err(FakeIpError::ZeroTtl)
        );
    }

    #[test]
    fn rejects_backwards_clock_and_expiry_overflow_without_mutation() {
        let mut table = FakeIpLeaseTable::new([ip("198.18.0.1")]).expect("pool");
        assert_eq!(
            table.issue(name("a.example"), FakeIpFamily::V4, epoch(1), u64::MAX, 1),
            Err(FakeIpError::TimeOverflow)
        );
        assert!(
            table
                .issue(name("a.example"), FakeIpFamily::V4, epoch(1), 4, 1)
                .is_ok()
        );
        assert!(matches!(
            table.lookup(ip("198.18.0.1"), epoch(1), 3),
            Err(FakeIpError::ClockMovedBackwards)
        ));
    }
}
