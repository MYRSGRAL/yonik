//! Сверка числовых операндов socket cgroupv2, которые теряются в JSON nft.

use super::{
    NetworkNamespace, NetworkReadError as Error,
    read::{NetlinkReader, ReadOperation, attributes},
};
use crate::Cancellation;
use std::{collections::BTreeSet, ffi::CStr, num::NonZeroU64, time::Duration};
use tokio::time::Instant;

const NFPROTO_INET: u8 = 1;
const SOCKET_CGROUPV2: u32 = 3;
const CMP_EQ: u32 = 0;
const ATTR_TYPE_MASK: u16 = 0x3fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftSocketCgroupMatch {
    pub rule_handle: NonZeroU64,
    pub level: u8,
    pub cgroup_id: NonZeroU64,
}

/// Читает равенства socket cgroupv2 в одной цепочке inet через NETLINK_NETFILTER.
/// Остальные выражения требуют отдельной сверки. Вызов требует CAP_NET_ADMIN
/// в текущем network namespace и не изменяет правила.
pub async fn read_nft_socket_cgroup_matches(
    table: &str,
    chain: &str,
    cancel: &mut Cancellation,
    timeout: Duration,
) -> Result<(NetworkNamespace, Vec<NftSocketCgroupMatch>), Error> {
    if timeout.is_zero() || timeout > Duration::from_secs(5) {
        return Err(Error::Limit);
    }
    cancel.check().map_err(|_| Error::Cancelled)?;
    let deadline = Instant::now() + timeout;
    let mut request = vec![NFPROTO_INET, 0, 0, 0];
    add_name(&mut request, 1, table)?; // NFTA_RULE_TABLE.
    add_name(&mut request, 2, chain)?; // NFTA_RULE_CHAIN.
    let mut reader = NetlinkReader::open_netfilter()?;
    let replies = reader
        .request(ReadOperation::NftRules, &request, cancel, deadline)
        .await?;
    let mut result = Vec::new();
    let mut handles = BTreeSet::new();
    for reply in replies {
        let rule = reply.payload.get(4..).ok_or(Error::Malformed)?;
        if reply.payload[..2] != [NFPROTO_INET, 0] {
            return Err(Error::Malformed);
        }
        let fields = attributes(rule)?;
        if string_value(required(&fields, 1)?)? != table.as_bytes()
            || string_value(required(&fields, 2)?)? != chain.as_bytes()
        {
            return Err(Error::Malformed);
        }
        let handle = u64::from_be_bytes(fixed(required(&fields, 3)?)?);
        let handle = NonZeroU64::new(handle).ok_or(Error::Malformed)?;
        if !handles.insert(handle) {
            return Err(Error::Malformed);
        }
        for (level, cgroup_id) in decode_expressions(required(&fields, 4)?)? {
            result.push(NftSocketCgroupMatch {
                rule_handle: handle,
                level,
                cgroup_id: NonZeroU64::new(cgroup_id).ok_or(Error::Malformed)?,
            });
        }
    }
    reader.finish(cancel, deadline)?;
    Ok((reader.namespace(), result))
}

fn add_name(request: &mut Vec<u8>, kind: u16, name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(Error::Malformed);
    }
    let length = name.len() as u16 + 5;
    request.extend_from_slice(&length.to_ne_bytes());
    request.extend_from_slice(&kind.to_ne_bytes());
    request.extend_from_slice(name.as_bytes());
    request.push(0);
    request.resize((request.len() + 3) & !3, 0);
    Ok(())
}

fn decode_expressions(bytes: &[u8]) -> Result<Vec<(u8, u64)>, Error> {
    let expressions = attributes(bytes)?;
    let mut result = Vec::new();
    let mut entries = expressions.into_iter();
    while let Some(entry) = entries.next() {
        let (name, data) = decode_expression(entry)?;
        if name != b"socket" {
            continue;
        }
        let socket = attributes(data)?;
        if u32::from_be_bytes(fixed(required(&socket, 1)?)?) != SOCKET_CGROUPV2 {
            continue;
        }
        let register = required(&socket, 2)?;
        let level = u32::from_be_bytes(fixed(required(&socket, 3)?)?);
        let level = u8::try_from(level).map_err(|_| Error::Malformed)?;
        if socket.len() != 3 || register.len() != 4 {
            return Err(Error::Malformed);
        }
        let (name, data) = decode_expression(entries.next().ok_or(Error::Malformed)?)?;
        if name != b"cmp" {
            return Err(Error::Unsupported);
        }
        let cmp = attributes(data)?;
        if cmp.len() != 3 || required(&cmp, 1)? != register {
            return Err(Error::Malformed);
        }
        if u32::from_be_bytes(fixed(required(&cmp, 2)?)?) != CMP_EQ {
            return Err(Error::Unsupported);
        }
        let value = attributes(required(&cmp, 3)?)?;
        if value.len() != 1 {
            return Err(Error::Malformed);
        }
        // Ядро записывает cgroup_id в регистр в native endian.
        let id = u64::from_ne_bytes(fixed(required(&value, 1)?)?);
        result.push((level, id));
    }
    Ok(result)
}

fn decode_expression((kind, value): (u16, &[u8])) -> Result<(&[u8], &[u8]), Error> {
    if kind & ATTR_TYPE_MASK != 1 {
        return Err(Error::Malformed);
    }
    let fields = attributes(value)?;
    let name = string_value(required(&fields, 1)?)?;
    Ok((name, required(&fields, 2)?))
}

fn required<'a>(fields: &[(u16, &'a [u8])], kind: u16) -> Result<&'a [u8], Error> {
    let mut matches = fields
        .iter()
        .filter(|(raw, _)| raw & ATTR_TYPE_MASK == kind);
    let (_, value) = matches.next().ok_or(Error::Malformed)?;
    if matches.next().is_some() {
        return Err(Error::Malformed);
    }
    Ok(value)
}

fn string_value(value: &[u8]) -> Result<&[u8], Error> {
    Ok(CStr::from_bytes_with_nul(value)
        .map_err(|_| Error::Malformed)?
        .to_bytes())
}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], Error> {
    value.try_into().map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::{Error, decode_expressions};

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let len = (value.len() + 4) as u16;
        let mut bytes = len.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    fn expression(name: &[u8], data: Vec<Vec<u8>>) -> Vec<u8> {
        let value = [attribute(1, name), attribute(0x8002, &data.concat())].concat();
        attribute(0x8001, &value)
    }

    #[test]
    fn decodes_cgroup_level_inode_and_register() {
        let inode = 0x1_0000_0421u64;
        let socket = expression(
            b"socket\0",
            vec![
                attribute(1, &3u32.to_be_bytes()),
                attribute(2, &8u32.to_be_bytes()),
                attribute(3, &2u32.to_be_bytes()),
            ],
        );
        let compare = |register: u32| {
            expression(
                b"cmp\0",
                vec![
                    attribute(1, &register.to_be_bytes()),
                    attribute(2, &0u32.to_be_bytes()),
                    attribute(0x8003, &attribute(1, &inode.to_ne_bytes())),
                ],
            )
        };
        assert_eq!(
            decode_expressions(&[socket.clone(), compare(8)].concat()),
            Ok(vec![(2, inode)])
        );
        assert_eq!(
            decode_expressions(&[socket, compare(9)].concat()),
            Err(Error::Malformed)
        );
    }
}
