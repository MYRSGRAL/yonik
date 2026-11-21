use std::{
    io,
    net::Ipv4Addr,
    os::fd::OwnedFd,
    str::{FromStr, from_utf8},
};

use rustix::net::{SendFlags, send};
use tokio::{
    io::{AsyncRead, AsyncReadExt, Interest},
    net::UnixStream,
    time::{Instant, timeout_at},
};

use crate::NetworkReadError as Error;

const MAX_INTERFACE_NAME: usize = 15;
const MAX_RECORD_BYTES: usize = 16_384;
const MAX_LEASE_SECONDS: u32 = 365 * 24 * 60 * 60;

#[derive(Debug)]
pub(super) struct ControlLease {
    pub(super) peer_pid: u32,
    pub(super) peer_pidfd: OwnedFd,
    pub(super) address: Ipv4Addr,
    pub(super) server: Ipv4Addr,
    pub(super) prefix: u8,
    pub(super) duration: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct LeaseData {
    address: Ipv4Addr,
    server: Ipv4Addr,
    prefix: u8,
    duration: u32,
}

pub(super) async fn read_lease(ifname: &str, deadline: Instant) -> Result<ControlLease, Error> {
    if !valid_interface_name(ifname) {
        return Err(Error::Malformed);
    }
    before_deadline(deadline, read_candidates(ifname)).await
}

fn valid_interface_name(ifname: &str) -> bool {
    // Имя передаётся и как часть пути, и как аргумент getopt.
    !ifname.is_empty()
        && ifname.len() <= MAX_INTERFACE_NAME
        && !ifname.starts_with('-')
        && !matches!(ifname, "." | "..")
        && ifname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+@".contains(&byte))
}

async fn before_deadline<T>(
    deadline: Instant,
    future: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    if Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    let result = timeout_at(deadline, future)
        .await
        .map_err(|_| Error::Timeout)?;
    if Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    result
}

async fn read_candidates(ifname: &str) -> Result<ControlLease, Error> {
    let ipv4 = format!("/run/dhcpcd/{ifname}-4.unpriv.sock");
    let dual_stack = format!("/run/dhcpcd/{ifname}.unpriv.sock");
    let mut lease = None;
    for path in ["/run/dhcpcd/unpriv.sock", &ipv4, &dual_stack] {
        let Some(candidate) = read_candidate(path, ifname).await? else {
            continue;
        };
        if lease.replace(candidate).is_some() {
            return Err(Error::Changed);
        }
    }
    lease.ok_or(Error::Unavailable)
}

async fn read_candidate(path: &str, ifname: &str) -> Result<Option<ControlLease>, Error> {
    let stream = match UnixStream::connect(path).await {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(_) => return Err(Error::Unavailable),
    };
    let peer = stream.peer_cred().map_err(|_| Error::Unavailable)?;
    if peer.uid() != 0 {
        return Err(Error::Unavailable);
    }
    let peer_pid = peer
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or(Error::Unavailable)?;
    let peer_pidfd =
        yonik_nsfs::socket_namespace::unix_peer_pidfd(&stream).map_err(|_| Error::Unavailable)?;

    let request = [b"dhcpcd\0-4\0-U\0", ifname.as_bytes(), b"\0"].concat();
    // dhcpcd разбирает аргументы из одного read(). Частичную запись не продолжаем.
    let sent = stream
        .async_io(Interest::WRITABLE, || {
            send(&stream, &request, SendFlags::NOSIGNAL).map_err(Into::into)
        })
        .await
        .map_err(|_| Error::Unavailable)?;
    if sent != request.len() {
        return Err(Error::Truncated);
    }
    Ok(read_reply(stream, ifname).await?.map(|lease| ControlLease {
        peer_pid,
        peer_pidfd,
        address: lease.address,
        server: lease.server,
        prefix: lease.prefix,
        duration: lease.duration,
    }))
}

async fn read_reply(
    mut stream: impl AsyncRead + Unpin,
    ifname: &str,
) -> Result<Option<LeaseData>, Error> {
    let mut word = [0; size_of::<usize>()];
    stream.read_exact(&mut word).await.map_err(read_error)?;
    match usize::from_ne_bytes(word) {
        0 => return Ok(None),
        1 => {}
        _ => return Err(Error::Malformed),
    }
    stream.read_exact(&mut word).await.map_err(read_error)?;
    let length = usize::from_ne_bytes(word);
    if length == 0 {
        return Err(Error::Malformed);
    }
    if length > MAX_RECORD_BYTES {
        return Err(Error::Limit);
    }
    let mut record = vec![0; length];
    stream.read_exact(&mut record).await.map_err(read_error)?;
    parse_lease(&record, ifname).map(Some)
}

fn read_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        Error::Truncated
    } else {
        Error::Unavailable
    }
}

fn parse_lease(record: &[u8], ifname: &str) -> Result<LeaseData, Error> {
    let [
        mut interface,
        mut protocol,
        mut reason,
        mut address,
        mut server,
        mut prefix,
        mut kind,
        mut duration,
    ] = [None; 8];
    let record = record.strip_suffix(b"\0").ok_or(Error::Malformed)?;
    for entry in record.split(|byte| *byte == 0) {
        let separator = entry
            .iter()
            .position(|byte| *byte == b'=')
            .filter(|separator| *separator != 0)
            .ok_or(Error::Malformed)?;
        let field = match &entry[..separator] {
            b"interface" => &mut interface,
            b"protocol" => &mut protocol,
            b"reason" => &mut reason,
            b"new_ip_address" => &mut address,
            b"new_dhcp_server_identifier" => &mut server,
            b"new_subnet_cidr" => &mut prefix,
            b"new_dhcp_message_type" => &mut kind,
            b"new_dhcp_lease_time" => &mut duration,
            _ => continue,
        };
        if field.replace(&entry[separator + 1..]).is_some() {
            return Err(Error::Malformed);
        }
    }
    if interface != Some(ifname.as_bytes()) {
        return Err(Error::Malformed);
    }
    if protocol != Some(b"dhcp")
        || !matches!(reason, Some(b"BOUND" | b"RENEW" | b"REBIND"))
        || kind != Some(b"5")
    {
        return Err(Error::Unsupported);
    }
    let prefix = decimal(prefix.ok_or(Error::Malformed)?)?;
    let duration = decimal(duration.ok_or(Error::Malformed)?)?;
    if prefix > 32 || !(1..=MAX_LEASE_SECONDS).contains(&duration) {
        return Err(Error::Malformed);
    }
    Ok(LeaseData {
        address: unicast(address.ok_or(Error::Malformed)?)?,
        server: unicast(server.ok_or(Error::Malformed)?)?,
        prefix,
        duration,
    })
}

fn decimal<T: FromStr>(value: &[u8]) -> Result<T, Error> {
    if !value.iter().all(u8::is_ascii_digit) {
        return Err(Error::Malformed);
    }
    from_utf8(value)
        .map_err(|_| Error::Malformed)?
        .parse()
        .map_err(|_| Error::Malformed)
}

fn unicast(value: &[u8]) -> Result<Ipv4Addr, Error> {
    let address: Ipv4Addr = from_utf8(value)
        .map_err(|_| Error::Malformed)?
        .parse()
        .map_err(|_| Error::Malformed)?;
    match address.octets()[0] {
        1..=126 | 128..=223 => Ok(address),
        _ => Err(Error::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::AsyncWriteExt,
        time::{Duration, Instant},
    };

    const RECORD: &[u8] = concat!(
        "interface=eth0\0protocol=dhcp\0reason=BOUND\0",
        "new_ip_address=10.234.16.10\0new_subnet_cidr=24\0",
        "new_dhcp_server_identifier=10.234.16.1\0",
        "new_dhcp_message_type=5\0new_dhcp_lease_time=42\0",
        "new_domain_search=a=b\0"
    )
    .as_bytes();

    fn expected() -> LeaseData {
        LeaseData {
            address: Ipv4Addr::new(10, 234, 16, 10),
            server: Ipv4Addr::new(10, 234, 16, 1),
            prefix: 24,
            duration: 42,
        }
    }

    #[test]
    fn parses_bound_renewed_and_rebound_ack() {
        for reason in ["BOUND", "RENEW", "REBIND"] {
            let record = std::str::from_utf8(RECORD)
                .unwrap()
                .replace("BOUND", reason);
            assert_eq!(parse_lease(record.as_bytes(), "eth0"), Ok(expected()));
        }
    }

    #[test]
    fn requires_exact_interface_protocol_state_and_ack() {
        for (from, to, error) in [
            ("interface=eth0", "interface=eth0.1", Error::Malformed),
            ("protocol=dhcp", "protocol=dhcp6", Error::Unsupported),
            ("reason=BOUND", "reason=REBOOT", Error::Unsupported),
            (
                "new_dhcp_message_type=5",
                "new_dhcp_message_type=2",
                Error::Unsupported,
            ),
        ] {
            let record = std::str::from_utf8(RECORD).unwrap().replace(from, to);
            assert_eq!(parse_lease(record.as_bytes(), "eth0"), Err(error), "{to}");
        }
    }

    #[test]
    fn rejects_invalid_addresses_prefix_and_duration() {
        for (from, to) in [
            ("10.234.16.10", "127.0.0.1"),
            ("10.234.16.1\0", "0.0.0.0\0"),
            ("10.234.16.10", "10.234.016.10"),
            ("10.234.16.1\0", "224.0.0.1\0"),
            ("cidr=24", "cidr=33"),
            ("cidr=24", "cidr=+24"),
            ("time=42", "time=0"),
            ("time=42", "time=4294967295"),
        ] {
            let record = std::str::from_utf8(RECORD).unwrap().replace(from, to);
            assert_eq!(
                parse_lease(record.as_bytes(), "eth0"),
                Err(Error::Malformed),
                "{to}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_relevant_entries_and_broken_records() {
        for suffix in [b"interface=eth0\0".as_slice(), b"unframed\0", b"\0"] {
            let record = [RECORD, suffix].concat();
            assert_eq!(parse_lease(&record, "eth0"), Err(Error::Malformed));
        }
        assert_eq!(
            parse_lease(&RECORD[..RECORD.len() - 1], "eth0"),
            Err(Error::Malformed)
        );
    }

    #[tokio::test]
    async fn reads_native_size_and_payload_across_fragments() {
        let (reader, mut writer) = tokio::io::duplex(3);
        let response = [&1_usize.to_ne_bytes(), &RECORD.len().to_ne_bytes(), RECORD].concat();
        let (result, write) = tokio::join!(read_reply(reader, "eth0"), writer.write_all(&response));
        assert_eq!(result, Ok(Some(expected())));
        assert!(write.is_ok());
    }

    #[tokio::test]
    async fn rejects_oversize_invalid_and_truncated_frames() {
        let two_records = 2_usize.to_ne_bytes();
        let no_payload = [1_usize.to_ne_bytes(), 0_usize.to_ne_bytes()].concat();
        let oversized = [1_usize.to_ne_bytes(), 16_385_usize.to_ne_bytes()].concat();
        let short = [
            &1_usize.to_ne_bytes(),
            &2_usize.to_ne_bytes(),
            b"a".as_slice(),
        ]
        .concat();
        for (frame, error) in [
            (two_records.as_slice(), Error::Malformed),
            (&no_payload, Error::Malformed),
            (&oversized, Error::Limit),
            (&short, Error::Truncated),
        ] {
            assert_eq!(read_reply(frame, "eth0").await, Err(error));
        }
        assert_eq!(
            read_reply(0_usize.to_ne_bytes().as_slice(), "eth0").await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn partial_frame_cannot_exceed_operation_deadline() {
        let (reader, mut writer) = tokio::io::duplex(3);
        writer.write_all(&[1]).await.unwrap();
        assert_eq!(
            before_deadline(
                Instant::now() + Duration::from_millis(10),
                read_reply(reader, "eth0"),
            )
            .await,
            Err(Error::Timeout)
        );
    }

    #[tokio::test]
    async fn rejects_invalid_names_before_contacting_the_daemon() {
        let deadline = Instant::now() + Duration::from_secs(1);
        for invalid in ["", "-N", "../eth0", "eth0\0", ".", "eth0123456789012"] {
            assert_eq!(
                read_lease(invalid, deadline).await.unwrap_err(),
                Error::Malformed
            );
        }
    }

    #[tokio::test]
    async fn expired_deadline_rejects_even_a_ready_result() {
        assert_eq!(
            before_deadline(Instant::now(), async { Ok(()) }).await,
            Err(Error::Timeout)
        );
    }
}
