use std::{fmt, net::IpAddr, str::FromStr};

/// Каноническая подсеть: биты адреса хоста обязательно обнулены.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCidr;

impl fmt::Display for InvalidCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ожидается каноническая IPv4/IPv6-подсеть")
    }
}

impl std::error::Error for InvalidCidr {}

impl FromStr for Cidr {
    type Err = InvalidCidr;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or(InvalidCidr)?;
        let network = address.parse::<IpAddr>().map_err(|_| InvalidCidr)?;
        if matches!(network, IpAddr::V6(address) if address.to_ipv4_mapped().is_some()) {
            return Err(InvalidCidr);
        }
        let prefix = prefix.parse::<u8>().map_err(|_| InvalidCidr)?;
        let valid = match network {
            IpAddr::V4(address) if prefix <= 32 => u32::from(address) & !mask_v4(prefix) == 0,
            IpAddr::V6(address) if prefix <= 128 => u128::from(address) & !mask_v6(prefix) == 0,
            _ => false,
        };
        if !valid {
            return Err(InvalidCidr);
        }
        Ok(Self { network, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl Cidr {
    pub fn network(self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                u32::from(address) & mask_v4(self.prefix) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                u128::from(address) & mask_v6(self.prefix) == u128::from(network)
            }
            _ => false,
        }
    }
}

fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}
