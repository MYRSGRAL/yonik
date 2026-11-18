//! Общий транспорт только для чтения kernel-снимков через netlink.

use super::super::Cancellation;
use rustix::net::{
    self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink::SocketAddrNetlink,
};
use std::{
    fmt, io,
    net::IpAddr,
    os::{fd::OwnedFd, unix::fs::MetadataExt},
};
use tokio::{io::unix::AsyncFd, time::Instant};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkReadError {
    Unavailable,
    Cancelled,
    Timeout,
    Changed,
    Interrupted,
    Truncated,
    Loss,
    Limit,
    Malformed,
    Unsupported,
    Kernel(i32),
}
impl fmt::Display for NetworkReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "Недоступен netlink",
            Self::Cancelled => "Чтение отменено",
            Self::Timeout => "Истёк срок чтения сети",
            Self::Changed => "Сеть изменилась во время чтения",
            Self::Interrupted => "Ядро прервало согласованное чтение",
            Self::Truncated => "Обрезан сетевой ответ",
            Self::Loss => "Потеряны сетевые сообщения",
            Self::Limit => "Превышен лимит снимка сети",
            Self::Malformed => "Повреждён сетевой ответ",
            Self::Unsupported => "Неподдержанные сетевые данные",
            Self::Kernel(_) => "Ядро отклонило сетевой запрос",
        })
    }
}
impl std::error::Error for NetworkReadError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkNamespace {
    pub device: u64,
    pub inode: u64,
}

/// Неинтерпретированный атрибут нельзя молча считать поддержанным.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkAttribute {
    pub kind: u16,
    pub value: Vec<u8>,
}
impl fmt::Debug for NetworkAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkAttribute")
            .field("kind", &self.kind)
            .field("bytes", &self.value.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub(super) enum ReadOperation {
    Links,
    Addresses,
    Routes,
    Rules,
    Nexthops,
    RouteGet,
    WireGuardFamily,
    WireGuardDevice(u16),
}

impl ReadOperation {
    fn kind(self) -> u16 {
        match self {
            Self::Links => 18,
            Self::Addresses => 22,
            Self::Routes | Self::RouteGet => 26,
            Self::Rules => 34,
            Self::Nexthops => 106,
            Self::WireGuardFamily => 16, // GENL_ID_CTRL.
            Self::WireGuardDevice(family) => family,
        }
    }
    fn dump(self) -> bool {
        !matches!(self, Self::RouteGet | Self::WireGuardFamily)
    }
    fn response_kind(self) -> u16 {
        if self.generic() {
            self.kind()
        } else {
            self.kind() - 2
        }
    }
    fn generic(self) -> bool {
        matches!(self, Self::WireGuardFamily | Self::WireGuardDevice(_))
    }
}

pub(super) struct Message {
    pub payload: Vec<u8>,
}

fn copy_message(payload: &[u8]) -> Result<Message, NetworkReadError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(payload.len())
        .map_err(|_| NetworkReadError::Limit)?;
    bytes.extend_from_slice(payload);
    Ok(Message { payload: bytes })
}

const DATAGRAM_LIMIT: usize = 65_536;
const BYTE_LIMIT: usize = 16 * 1024 * 1024;
const RECORD_LIMIT: usize = 32_768;

#[derive(Default)]
struct Budget {
    bytes: usize,
    records: usize,
}

struct Exchange<T> {
    operation: ReadOperation,
    sequence: u32,
    port: u32,
    done: bool,
    decode: fn(&[u8]) -> Result<T, NetworkReadError>,
    messages: Vec<T>,
}
impl Exchange<Message> {
    fn new(operation: ReadOperation, sequence: u32, port: u32) -> Self {
        Self::decoded(operation, sequence, port, copy_message)
    }
}

impl<T> Exchange<T> {
    fn decoded(
        operation: ReadOperation,
        sequence: u32,
        port: u32,
        decode: fn(&[u8]) -> Result<T, NetworkReadError>,
    ) -> Self {
        Self {
            operation,
            sequence,
            port,
            done: false,
            decode,
            messages: Vec::new(),
        }
    }
    fn accept(
        &mut self,
        bytes: &[u8],
        length: usize,
        sender: u32,
        groups: u32,
        budget: &mut Budget,
    ) -> Result<(), NetworkReadError> {
        if length > DATAGRAM_LIMIT || length != bytes.len() {
            return Err(NetworkReadError::Truncated);
        }
        budget.bytes = budget
            .bytes
            .checked_add(length)
            .ok_or(NetworkReadError::Limit)?;
        if budget.bytes > BYTE_LIMIT {
            return Err(NetworkReadError::Limit);
        }
        // sockaddr_netlink из recvfrom удостоверяет kernel, не nlmsg_pid.
        if sender != 0 {
            return Ok(());
        }
        if bytes.is_empty() {
            return Err(NetworkReadError::Malformed);
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            if rest.len() < 16 {
                return Err(NetworkReadError::Malformed);
            }
            let length = u32_value(&rest[..4])? as usize;
            if length < 16 || length > rest.len() {
                return Err(NetworkReadError::Malformed);
            }
            let kind = u16_value(&rest[4..6])?;
            let flags = u16_value(&rest[6..8])?;
            let sequence = u32_value(&rest[8..12])?;
            let port = u32_value(&rest[12..16])?;
            let payload = &rest[16..length];
            if kind == 4 {
                return Err(NetworkReadError::Loss);
            }
            if flags & 0x10 != 0 {
                return Err(NetworkReadError::Interrupted);
            }
            if groups != 0
                || (!self.operation.generic()
                    && sequence == 0
                    && matches!(
                        kind,
                        16 | 17 | 20 | 21 | 24 | 25 | 32 | 33 | 104 | 105 | 108 | 109
                    ))
            {
                return Err(NetworkReadError::Changed);
            }
            if sequence != self.sequence || (port != self.port && port != 0) {
                return Err(NetworkReadError::Malformed);
            }
            if self.done {
                return Err(NetworkReadError::Malformed);
            }
            budget.records = budget
                .records
                .checked_add(1)
                .ok_or(NetworkReadError::Limit)?;
            if budget.records > RECORD_LIMIT {
                return Err(NetworkReadError::Limit);
            }
            match kind {
                1 => {} // NLMSG_NOOP не завершает запрос.
                2 => {
                    if payload.len() < 20 {
                        return Err(NetworkReadError::Malformed);
                    }
                    kernel_status(&payload[..4])?;
                    // ACK=0 — подтверждение, а не искомый результат.
                }
                3 if self.operation.dump() => {
                    if !payload.is_empty() {
                        if payload.len() < 4 {
                            return Err(NetworkReadError::Malformed);
                        }
                        kernel_status(&payload[..4])?;
                        if payload.len() > 4 {
                            if flags & 0x200 == 0 {
                                return Err(NetworkReadError::Malformed);
                            }
                            attributes(&payload[4..])?;
                        }
                    }
                    self.done = true;
                }
                kind if kind == self.operation.response_kind() => {
                    if (flags & 2 != 0) != self.operation.dump() {
                        return Err(NetworkReadError::Malformed);
                    }
                    self.messages.push((self.decode)(payload)?);
                    self.done = !self.operation.dump();
                }
                _ => return Err(NetworkReadError::Malformed),
            }
            rest = if length == rest.len() {
                &[]
            } else {
                rest.get((length + 3) & !3..)
                    .ok_or(NetworkReadError::Malformed)?
            };
        }
        Ok(())
    }
}

fn kernel_status(bytes: &[u8]) -> Result<(), NetworkReadError> {
    let status = i32::from_ne_bytes(bytes.try_into().map_err(|_| NetworkReadError::Malformed)?);
    match status {
        0 => Ok(()),
        n if n < 0 => Err(NetworkReadError::Kernel(
            n.checked_neg().ok_or(NetworkReadError::Malformed)?,
        )),
        _ => Err(NetworkReadError::Malformed),
    }
}

pub(super) struct NetlinkReader {
    socket: AsyncFd<OwnedFd>,
    namespace: NetworkNamespace,
    port: u32,
    sequence: u32,
    generic: bool,
    budget: Budget,
}
impl NetlinkReader {
    pub fn open() -> Result<Self, NetworkReadError> {
        Self::open_socket(false)
    }
    pub fn open_generic() -> Result<Self, NetworkReadError> {
        Self::open_socket(true)
    }
    fn open_socket(generic: bool) -> Result<Self, NetworkReadError> {
        tokio::runtime::Handle::try_current().map_err(|_| NetworkReadError::Unavailable)?;
        // Нет await между идентификацией namespace и созданием его socket.
        let ns = std::fs::metadata("/proc/thread-self/ns/net")
            .map_err(|_| NetworkReadError::Unavailable)?;
        let socket = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            generic.then_some(net::netlink::GENERIC),
        )
        .map_err(io_error)?;
        let groups = if generic { 0 } else { super::route::GROUPS };
        net::bind(&socket, &SocketAddrNetlink::new(0, groups)).map_err(io_error)?;
        let address = net::getsockname(&socket).map_err(io_error)?;
        let port = SocketAddrNetlink::try_from(address)
            .map_err(|_| NetworkReadError::Unavailable)?
            .pid();
        let mut sequence = [0; 4];
        getrandom::getrandom(&mut sequence).map_err(|_| NetworkReadError::Unavailable)?;
        // OwnedFd остаётся владельцем fd; замена register требует запрещённый unsafe.
        #[allow(deprecated)]
        let socket = AsyncFd::new(socket).map_err(|_| NetworkReadError::Unavailable)?;
        Ok(Self {
            socket,
            namespace: NetworkNamespace {
                device: ns.dev(),
                inode: ns.ino(),
            },
            port,
            sequence: u32::from_ne_bytes(sequence).max(1),
            generic,
            budget: Budget::default(),
        })
    }
    pub fn namespace(&self) -> NetworkNamespace {
        self.namespace
    }
    /// Последний drain после разбора DTO. Не превращает результат в lease ОС.
    pub fn finish(
        &mut self,
        cancel: &Cancellation,
        deadline: Instant,
    ) -> Result<(), NetworkReadError> {
        let mut exchange = Exchange::new(ReadOperation::Links, self.sequence, self.port);
        exchange.done = true;
        self.drain(
            &mut exchange,
            &mut Zeroizing::new(vec![0; DATAGRAM_LIMIT]),
            deadline,
            cancel,
        )
    }
    pub async fn request(
        &mut self,
        operation: ReadOperation,
        payload: &[u8],
        cancel: &mut Cancellation,
        deadline: Instant,
    ) -> Result<Vec<Message>, NetworkReadError> {
        if operation.generic() {
            return Err(NetworkReadError::Unsupported);
        }
        self.request_decoded(operation, payload, cancel, deadline, copy_message)
            .await
    }
    pub async fn request_decoded<T>(
        &mut self,
        operation: ReadOperation,
        payload: &[u8],
        cancel: &mut Cancellation,
        deadline: Instant,
        decode: fn(&[u8]) -> Result<T, NetworkReadError>,
    ) -> Result<Vec<T>, NetworkReadError> {
        if operation.generic() != self.generic {
            return Err(NetworkReadError::Unsupported);
        }
        cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
        if Instant::now() >= deadline {
            return Err(NetworkReadError::Timeout);
        }
        if payload.len() > DATAGRAM_LIMIT - 16 {
            return Err(NetworkReadError::Limit);
        }
        let operation_cancel = cancel.clone();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(NetworkReadError::Cancelled),
            result = tokio::time::timeout_at(deadline, self.exchange(operation,payload,deadline,&operation_cancel,decode)) => result.map_err(|_| NetworkReadError::Timeout)?,
        }
    }
    async fn exchange<T>(
        &mut self,
        operation: ReadOperation,
        payload: &[u8],
        deadline: Instant,
        cancel: &Cancellation,
        decode: fn(&[u8]) -> Result<T, NetworkReadError>,
    ) -> Result<Vec<T>, NetworkReadError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(NetworkReadError::Limit)?;
        let mut exchange = Exchange::decoded(operation, self.sequence, self.port, decode);
        // WireGuard GET может вернуть private/preshared keys в том же сообщении.
        let mut buffer = Zeroizing::new(vec![0; DATAGRAM_LIMIT]);
        // Остаток предыдущего запроса/новое multicast-событие не скрывается.
        self.drain(&mut exchange, &mut buffer, deadline, cancel)?;
        let mut bytes = Vec::with_capacity(payload.len() + 16);
        bytes.extend_from_slice(&((payload.len() + 16) as u32).to_ne_bytes());
        bytes.extend_from_slice(&operation.kind().to_ne_bytes());
        bytes.extend_from_slice(&(if operation.dump() { 0x301u16 } else { 1u16 }).to_ne_bytes());
        bytes.extend_from_slice(&self.sequence.to_ne_bytes());
        bytes.extend_from_slice(&self.port.to_ne_bytes());
        bytes.extend_from_slice(payload);
        loop {
            cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
            if Instant::now() >= deadline {
                return Err(NetworkReadError::Timeout);
            }
            let mut ready = self
                .socket
                .writable()
                .await
                .map_err(|_| NetworkReadError::Unavailable)?;
            match ready.try_io(|fd| {
                net::sendto(
                    fd.get_ref(),
                    &bytes,
                    SendFlags::empty(),
                    &SocketAddrNetlink::new(0, 0),
                )
                .map_err(io::Error::from)
            }) {
                Err(_) => continue,
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(io_error(error)),
                Ok(Ok(sent)) if sent == bytes.len() => break,
                Ok(Ok(_)) => return Err(NetworkReadError::Truncated),
            }
        }
        loop {
            cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
            if Instant::now() >= deadline {
                return Err(NetworkReadError::Timeout);
            }
            let mut ready = self
                .socket
                .readable()
                .await
                .map_err(|_| NetworkReadError::Unavailable)?;
            let result = ready.try_io(|fd| receive(fd.get_ref(), &mut buffer));
            match result {
                Err(_) => continue,
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(io_error(error)),
                Ok(Ok((length, sender, groups))) => exchange.accept(
                    &buffer[..length.min(buffer.len())],
                    length,
                    sender,
                    groups,
                    &mut self.budget,
                )?,
            }
            if exchange.done {
                self.drain(&mut exchange, &mut buffer, deadline, cancel)?;
                return Ok(exchange.messages);
            }
        }
    }
    fn drain<T>(
        &mut self,
        exchange: &mut Exchange<T>,
        buffer: &mut [u8],
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<(), NetworkReadError> {
        loop {
            cancel.check().map_err(|_| NetworkReadError::Cancelled)?;
            if Instant::now() >= deadline {
                return Err(NetworkReadError::Timeout);
            }
            match receive(self.socket.get_ref(), buffer) {
                Ok((length, sender, groups)) => exchange.accept(
                    &buffer[..length.min(buffer.len())],
                    length,
                    sender,
                    groups,
                    &mut self.budget,
                )?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error(error)),
            }
        }
    }
}

fn receive(socket: &OwnedFd, bytes: &mut [u8]) -> io::Result<(usize, u32, u32)> {
    let (_, length, address) = net::recvfrom(socket, bytes, RecvFlags::TRUNC)?;
    let sender = address
        .and_then(|a| SocketAddrNetlink::try_from(a).ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok((length, sender.pid(), sender.groups()))
}
fn io_error(error: impl Into<io::Error>) -> NetworkReadError {
    let error = error.into();
    if error.raw_os_error() == Some(rustix::io::Errno::NOBUFS.raw_os_error()) {
        NetworkReadError::Loss
    } else {
        NetworkReadError::Unavailable
    }
}

pub(super) fn attributes(bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, NetworkReadError> {
    super::route::attributes(bytes).map_err(|_| NetworkReadError::Malformed)
}
pub(super) fn u16_value(bytes: &[u8]) -> Result<u16, NetworkReadError> {
    Ok(u16::from_ne_bytes(
        bytes.try_into().map_err(|_| NetworkReadError::Malformed)?,
    ))
}
pub(super) fn u32_value(bytes: &[u8]) -> Result<u32, NetworkReadError> {
    Ok(u32::from_ne_bytes(
        bytes.try_into().map_err(|_| NetworkReadError::Malformed)?,
    ))
}
pub(super) fn ip_value(family: u8, bytes: &[u8]) -> Result<IpAddr, NetworkReadError> {
    match family {
        2 => Ok(IpAddr::V4(
            <[u8; 4]>::try_from(bytes)
                .map_err(|_| NetworkReadError::Malformed)?
                .into(),
        )),
        10 => Ok(IpAddr::V6(
            <[u8; 16]>::try_from(bytes)
                .map_err(|_| NetworkReadError::Malformed)?
                .into(),
        )),
        _ => Err(NetworkReadError::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "Только новый network namespace с YONIK_HOST_NETWORK_NS"]
    async fn native_queued_changes_invalidate_reader_and_final_fence() {
        use std::{os::fd::AsRawFd, process::Command};
        let host = std::env::var("YONIK_HOST_NETWORK_NS")
            .expect("Явный host namespace")
            .parse::<u64>()
            .expect("inode");
        let namespace = std::fs::metadata("/proc/thread-self/ns/net").expect("namespace");
        assert_ne!(namespace.ino(), host, "Запрещены изменения host namespace");
        let links = Command::new("ip")
            .args(["-j", "link", "show"])
            .output()
            .expect("read-only links");
        assert!(links.status.success());
        let links: serde_json::Value = serde_json::from_slice(&links.stdout).expect("links JSON");
        let links = links.as_array().expect("links array");
        assert_eq!(links.len(), 1, "Только новый пустой namespace");
        assert_eq!(links[0]["ifname"], "lo");
        let mut reader = NetlinkReader::open().expect("reader");
        assert_eq!(reader.namespace().inode, namespace.ino());
        let owned_fd = reader.socket.get_ref().as_raw_fd();
        assert!(
            Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .expect("Свой lo")
                .success()
        );
        let (_source, mut cancel) = Cancellation::new();
        let result = reader
            .request(
                ReadOperation::Links,
                &[0; 16],
                &mut cancel,
                Instant::now() + std::time::Duration::from_secs(2),
            )
            .await;
        assert_eq!(result.err(), Some(NetworkReadError::Changed));
        drop(reader);
        assert!(
            !std::path::Path::new(&format!("/proc/self/fd/{owned_fd}")).exists(),
            "Owned socket закрыт"
        );
        let mut reader = NetlinkReader::open().expect("новый reader");
        let links = reader
            .request(
                ReadOperation::Links,
                &[0; 16],
                &mut cancel,
                Instant::now() + std::time::Duration::from_secs(2),
            )
            .await
            .expect("стабильный dump");
        assert_eq!(links.len(), 1);
        assert!(
            Command::new("ip")
                .args(["route", "add", "198.51.100.0/24", "dev", "lo"])
                .status()
                .expect("Свой route")
                .success()
        );
        assert_eq!(
            reader.finish(&cancel, Instant::now() + std::time::Duration::from_secs(2)),
            Err(NetworkReadError::Changed)
        );
        let (source, mut cancelled) = Cancellation::new();
        source.send_replace(true);
        assert_eq!(
            reader
                .request(
                    ReadOperation::Links,
                    &[0; 16],
                    &mut cancelled,
                    Instant::now() + std::time::Duration::from_secs(2)
                )
                .await
                .err(),
            Some(NetworkReadError::Cancelled)
        );
        assert_eq!(
            reader
                .request(ReadOperation::Links, &[0; 16], &mut cancel, Instant::now())
                .await
                .err(),
            Some(NetworkReadError::Timeout)
        );
    }
    fn message(kind: u16, flags: u16, seq: u32, port: u32, data: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::from(((data.len() + 16) as u32).to_ne_bytes());
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(flags.to_ne_bytes());
        bytes.extend(seq.to_ne_bytes());
        bytes.extend(port.to_ne_bytes());
        bytes.extend(data);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }
    fn accept(
        state: &mut Exchange<Message>,
        bytes: &[u8],
        budget: &mut Budget,
    ) -> Result<(), NetworkReadError> {
        state.accept(bytes, bytes.len(), 0, 0, budget)
    }
    #[test]
    fn multipart_requires_done_and_preserves_each_record() {
        let mut state = Exchange::new(ReadOperation::Links, 42, 777);
        let mut budget = Budget::default();
        accept(&mut state, &message(16, 2, 42, 777, &[1]), &mut budget).unwrap();
        assert!(!state.done);
        accept(&mut state, &message(16, 2, 42, 777, &[2]), &mut budget).unwrap();
        accept(
            &mut state,
            &message(3, 2, 42, 777, &0i32.to_ne_bytes()),
            &mut budget,
        )
        .unwrap();
        assert!(state.done);
        assert_eq!(state.messages.len(), 2);
        assert_eq!(state.messages[0].payload, vec![1]);
        assert_eq!(state.messages[1].payload, vec![2]);
    }
    #[test]
    fn dump_interrupt_on_done_never_returns_partial_success() {
        let mut state = Exchange::new(ReadOperation::Routes, 42, 777);
        let mut budget = Budget::default();
        accept(&mut state, &message(24, 2, 42, 777, &[1]), &mut budget).unwrap();
        assert_eq!(
            accept(&mut state, &message(3, 0x12, 42, 777, &[0; 4]), &mut budget),
            Err(NetworkReadError::Interrupted)
        );
    }
    #[test]
    fn error_ack_zero_is_not_a_dump_or_route_result() {
        let mut state = Exchange::new(ReadOperation::Routes, 42, 777);
        let mut budget = Budget::default();
        accept(&mut state, &message(2, 0, 42, 777, &[0; 20]), &mut budget).unwrap();
        assert!(!state.done);
        assert!(state.messages.is_empty());
        let mut error = vec![0; 20];
        error[..4].copy_from_slice(&(-101i32).to_ne_bytes());
        assert_eq!(
            accept(&mut state, &message(2, 0, 42, 777, &error), &mut budget),
            Err(NetworkReadError::Kernel(101))
        );
    }
    #[test]
    fn multicast_changes_and_overrun_are_not_snapshot_records() {
        let mut state = Exchange::new(ReadOperation::Routes, 42, 777);
        let mut budget = Budget::default();
        assert_eq!(
            accept(&mut state, &message(24, 0, 0, 0, &[0; 12]), &mut budget),
            Err(NetworkReadError::Changed)
        );
        assert_eq!(
            accept(&mut state, &message(4, 0, 42, 777, &[]), &mut budget),
            Err(NetworkReadError::Loss)
        );
    }
    #[test]
    fn multicast_group_overrides_originating_request_sequence_and_pid_header() {
        let mut state = Exchange::new(ReadOperation::Links, 42, 777);
        state.done = true;
        let mut budget = Budget::default();
        let route = message(24, 0, 99_999, 123_456, &[0; 12]);
        assert_eq!(
            state.accept(&route, route.len(), 0, 1 << 6, &mut budget),
            Err(NetworkReadError::Changed)
        );
        assert!(state.messages.is_empty());
    }
    #[test]
    fn untrusted_sender_is_ignored_but_wrong_kernel_sequence_or_port_is_failure() {
        let mut state = Exchange::new(ReadOperation::Links, 42, 777);
        let mut budget = Budget::default();
        let data = message(3, 2, 42, 777, &[0; 4]);
        state
            .accept(&data, data.len(), 123, 0, &mut budget)
            .unwrap();
        assert!(!state.done);
        assert_eq!(
            accept(&mut state, &message(3, 2, 43, 777, &[0; 4]), &mut budget),
            Err(NetworkReadError::Malformed)
        );
        assert_eq!(
            accept(&mut state, &message(3, 2, 42, 778, &[0; 4]), &mut budget),
            Err(NetworkReadError::Malformed)
        );
    }
    #[test]
    fn truncation_and_invalid_frames_are_explicit_errors() {
        let mut state = Exchange::new(ReadOperation::Links, 42, 777);
        let mut budget = Budget::default();
        assert_eq!(
            state.accept(&[0; 16], DATAGRAM_LIMIT + 1, 0, 0, &mut budget),
            Err(NetworkReadError::Truncated)
        );
        assert_eq!(
            accept(&mut state, &[0; 15], &mut budget),
            Err(NetworkReadError::Malformed)
        );
        assert_eq!(
            accept(&mut state, &message(16, 0, 42, 777, &[1]), &mut budget),
            Err(NetworkReadError::Malformed)
        );
    }
    #[test]
    fn single_lookup_requires_one_matching_nonmultipart_record() {
        let mut state = Exchange::new(ReadOperation::RouteGet, 42, 777);
        let mut budget = Budget::default();
        accept(&mut state, &message(24, 0, 42, 777, &[1]), &mut budget).unwrap();
        assert!(state.done);
        assert_eq!(state.messages.len(), 1);
        assert_eq!(
            accept(&mut state, &message(24, 0, 42, 777, &[2]), &mut budget),
            Err(NetworkReadError::Malformed)
        );
    }
    #[test]
    fn shared_budget_bounds_all_dump_classes_without_silent_eviction() {
        let mut state = Exchange::new(ReadOperation::Links, 42, 777);
        let data = message(16, 2, 42, 777, &[1]);
        let mut bytes = Budget {
            bytes: BYTE_LIMIT,
            records: 0,
        };
        assert_eq!(
            accept(&mut state, &data, &mut bytes),
            Err(NetworkReadError::Limit)
        );
        let mut records = Budget {
            bytes: 0,
            records: RECORD_LIMIT,
        };
        assert_eq!(
            accept(&mut state, &data, &mut records),
            Err(NetworkReadError::Limit)
        );
    }
}
