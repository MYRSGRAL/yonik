use super::{
    DEADLINE, Flow, Instant, IoSliceMut, Lookup, OwnerSnapshot, Process, RecvAncillaryBuffer,
    RecvFlags, ReturnFlags, TrustedContext, Unavailable, fs, namespaces, recvmsg,
};
use rustix::net::{
    AddressFamily, SendFlags, SocketFlags, SocketType,
    netlink::{SOCK_DIAG, SocketAddrNetlink},
    socket_with,
};
use std::{
    os::unix::fs::MetadataExt,
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(test)]
thread_local! {static WITNESSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };}

const MAX_PROCESSES: usize = 256;
const MAX_TASKS: usize = 256;
const MAX_FDS_PER_TASK: usize = 256;
const MAX_DIAG_RECORDS: usize = 65536;

fn u32n(b: &[u8]) -> Result<u32, Unavailable> {
    Ok(u32::from_ne_bytes(
        b.try_into().map_err(|_| Unavailable::Malformed)?,
    ))
}

/// Независимый listener census. Не owner lookup и не proof доверенного unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Listener {
    pub family: u8,
    pub protocol: u8,
    pub state: u8,
    pub local: [u8; 16],
    pub remote: [u8; 16],
    pub port: u16,
    pub remote_port: u16,
    pub interface: u32,
    pub uid: u32,
    pub inode: u32,
    pub cookie: u64,
    pub cgroup: u64,
    pub v6only: bool,
}
pub(crate) struct ListenerSet {
    rows: [Option<Listener>; 64],
    count: usize,
}
impl ListenerSet {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Listener> {
        self.rows[..self.count].iter().filter_map(Option::as_ref)
    }
    #[cfg(test)]
    pub(crate) fn fixture(rows: &[Listener]) -> Self {
        assert!(rows.len() <= 64);
        let mut result = Self {
            rows: [None; 64],
            count: rows.len(),
        };
        for (out, row) in result.rows.iter_mut().zip(rows) {
            *out = Some(*row);
        }
        result
    }
}
/// Fixed storage оплачивается capture caller до socket/recv. Обе families
/// обязательны; EOF/ошибка отравляют capture, partial set наружу не выходит.
pub(crate) struct ListenerDump {
    protocol: u8,
    port: u16,
    family: u8,
    sequence: u32,
    done: [bool; 2],
    scanned: usize,
    poisoned: bool,
    rows: ListenerSet,
}
impl ListenerDump {
    pub(crate) fn new(protocol: u8, port: u16) -> Result<Self, Unavailable> {
        if !matches!(protocol, 6 | 17) || port == 0 {
            return Err(Unavailable::Malformed);
        }
        Ok(Self {
            protocol,
            port,
            family: 2,
            sequence: 1,
            done: [false; 2],
            scanned: 0,
            poisoned: false,
            rows: ListenerSet {
                rows: [None; 64],
                count: 0,
            },
        })
    }
    pub(crate) fn begin_v6(&mut self) -> Result<(), Unavailable> {
        if self.poisoned || !self.done[0] || self.done[1] || self.family != 2 {
            self.poisoned = true;
            return Err(Unavailable::Coverage);
        }
        self.family = 10;
        self.sequence = 2;
        Ok(())
    }
    pub(crate) fn request(&self) -> [u8; 72] {
        let mut b = [0; 72];
        b[..4].copy_from_slice(&72u32.to_ne_bytes());
        b[4..6].copy_from_slice(&20u16.to_ne_bytes());
        b[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
        b[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
        b[16] = self.family;
        b[17] = self.protocol;
        let states = if self.protocol == 6 {
            1u32 << 10
        } else {
            u32::MAX
        };
        b[20..24].copy_from_slice(&states.to_ne_bytes());
        // Ни адрес, ни interface/cookie/UID не фильтруют wildcard/reuseport.
        b[64..72].fill(255);
        b
    }
    pub(crate) fn consume(
        &mut self,
        bytes: &[u8],
        flags: ReturnFlags,
        kernel_sender: bool,
    ) -> Result<bool, Unavailable> {
        if self.poisoned {
            return Err(Unavailable::Revoked);
        }
        let result = self.consume_inner(bytes, flags, kernel_sender);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn consume_inner(
        &mut self,
        bytes: &[u8],
        flags: ReturnFlags,
        kernel_sender: bool,
    ) -> Result<bool, Unavailable> {
        let index = usize::from(self.family == 10);
        if !kernel_sender
            || self.done[index]
            || bytes.is_empty()
            || flags.intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        {
            return Err(Unavailable::Coverage);
        }
        let mut offset = 0usize;
        while offset < bytes.len() {
            let h = bytes
                .get(offset..offset + 16)
                .ok_or(Unavailable::Malformed)?;
            let len = u32n(&h[..4])? as usize;
            let end = offset.checked_add(len).ok_or(Unavailable::Limit)?;
            if len < 16 || end > bytes.len() || u32n(&h[8..12])? != self.sequence {
                return Err(Unavailable::Malformed);
            }
            let nflags = u16::from_ne_bytes([h[6], h[7]]);
            if nflags & 0x30 != 0 || nflags & 2 == 0 {
                return Err(Unavailable::Coverage);
            }
            let kind = u16::from_ne_bytes([h[4], h[5]]);
            let body = &bytes[offset + 16..end];
            let aligned = (len + 3) & !3;
            if kind == 3 {
                if body.len() != 4 || u32n(body)? != 0 || offset + aligned != bytes.len() {
                    return Err(Unavailable::Coverage);
                }
                self.done[index] = true;
                return Ok(true);
            }
            if kind == 2 || kind == 4 {
                return Err(Unavailable::ReceiveOverflow);
            }
            if kind != 20 || body.len() < 72 || body[0] != self.family {
                return Err(Unavailable::Malformed);
            }
            self.scanned += 1;
            if self.scanned > MAX_DIAG_RECORDS {
                return Err(Unavailable::Limit);
            }
            let port = u16::from_be_bytes([body[4], body[5]]);
            if port == self.port && self.protocol == 6 && body[1] != 10 {
                return Err(Unavailable::Coverage);
            }
            if port == self.port && (self.protocol == 17 || body[1] == 10) {
                if self.rows.count == 64 {
                    return Err(Unavailable::Limit);
                }
                let mut cgroup = None;
                let mut v6only = None;
                let mut at = 72;
                while at < body.len() {
                    let h = body.get(at..at + 4).ok_or(Unavailable::Malformed)?;
                    let n = usize::from(u16::from_ne_bytes([h[0], h[1]]));
                    let tag = u16::from_ne_bytes([h[2], h[3]]);
                    if n < 4 || at + n > body.len() {
                        return Err(Unavailable::Malformed);
                    }
                    let value = &body[at + 4..at + n];
                    match tag {
                        21 => {
                            if value.len() != 8 || cgroup.is_some() {
                                return Err(Unavailable::Coverage);
                            }
                            cgroup = Some(u64::from_ne_bytes(
                                value.try_into().map_err(|_| Unavailable::Malformed)?,
                            ));
                        }
                        11 => {
                            if value.len() != 1 || value[0] > 1 || v6only.is_some() {
                                return Err(Unavailable::Coverage);
                            }
                            v6only = Some(value[0] != 0);
                        }
                        _ => {}
                    }
                    at += (n + 3) & !3;
                    if at > body.len() {
                        return Err(Unavailable::Malformed);
                    }
                }
                let mut local = [0; 16];
                local.copy_from_slice(&body[8..24]);
                let mut remote = [0; 16];
                remote.copy_from_slice(&body[24..40]);
                if self.family == 2
                    && (local[4..].iter().any(|b| *b != 0) || remote[4..].iter().any(|b| *b != 0))
                {
                    return Err(Unavailable::Malformed);
                }
                let cookie =
                    u64::from(u32n(&body[44..48])?) | (u64::from(u32n(&body[48..52])?) << 32);
                let group = cgroup.ok_or(Unavailable::Coverage)?;
                if group == 0 || cookie == 0 || cookie == u64::MAX {
                    return Err(Unavailable::Coverage);
                }
                let row = Listener {
                    family: self.family,
                    protocol: self.protocol,
                    state: body[1],
                    local,
                    remote,
                    port,
                    remote_port: u16::from_be_bytes([body[6], body[7]]),
                    interface: u32n(&body[40..44])?,
                    uid: u32n(&body[64..68])?,
                    inode: u32n(&body[68..72])?,
                    cookie,
                    cgroup: group,
                    v6only: if self.family == 10 {
                        v6only.ok_or(Unavailable::Coverage)?
                    } else {
                        false
                    },
                };
                self.rows.rows[self.rows.count] = Some(row);
                self.rows.count += 1;
            }
            offset += aligned;
            if offset > bytes.len() {
                return Err(Unavailable::Malformed);
            }
        }
        Ok(false)
    }
    pub(crate) fn finish(self) -> Result<ListenerSet, Unavailable> {
        if self.poisoned || self.done != [true; 2] {
            return Err(Unavailable::Coverage);
        }
        Ok(self.rows)
    }
}

#[cfg(test)]
mod listener_pure_tests {
    use super::*;
    fn message(family: u8, port: u16, cookie: u64) -> Vec<u8> {
        let size = 16 + 72 + 12 + usize::from(family == 10) * 8;
        let mut b = vec![0; size];
        b[..4].copy_from_slice(&(size as u32).to_ne_bytes());
        b[4..6].copy_from_slice(&20u16.to_ne_bytes());
        b[6..8].copy_from_slice(&2u16.to_ne_bytes());
        b[8..12].copy_from_slice(&(if family == 2 { 1u32 } else { 2u32 }).to_ne_bytes());
        let d = &mut b[16..];
        d[0] = family;
        d[1] = 7;
        d[4..6].copy_from_slice(&port.to_be_bytes());
        if family == 2 {
            d[8..12].copy_from_slice(&[127, 0, 0, 53]);
        } else {
            d[23] = 1;
        }
        d[44..48].copy_from_slice(&(cookie as u32).to_ne_bytes());
        d[48..52].copy_from_slice(&((cookie >> 32) as u32).to_ne_bytes());
        d[64..68].copy_from_slice(&991u32.to_ne_bytes());
        d[68..72].copy_from_slice(&100u32.to_ne_bytes());
        d[72..74].copy_from_slice(&12u16.to_ne_bytes());
        d[74..76].copy_from_slice(&21u16.to_ne_bytes());
        d[76..84].copy_from_slice(&42u64.to_ne_bytes());
        if family == 10 {
            d[84..86].copy_from_slice(&5u16.to_ne_bytes());
            d[86..88].copy_from_slice(&11u16.to_ne_bytes());
            d[88] = 1;
        }
        b
    }
    fn done(seq: u32) -> Vec<u8> {
        let mut b = vec![0; 20];
        b[..4].copy_from_slice(&20u32.to_ne_bytes());
        b[4..6].copy_from_slice(&3u16.to_ne_bytes());
        b[6..8].copy_from_slice(&2u16.to_ne_bytes());
        b[8..12].copy_from_slice(&seq.to_ne_bytes());
        b
    }
    #[test]
    fn listener_pure_requires_both_complete_families_and_keeps_kernel_fields() {
        let mut dump = ListenerDump::new(17, 53).unwrap();
        assert!(
            !dump
                .consume(&message(2, 53, 11), ReturnFlags::empty(), true)
                .unwrap()
        );
        assert!(dump.consume(&done(1), ReturnFlags::empty(), true).unwrap());
        dump.begin_v6().unwrap();
        dump.consume(&message(10, 53, 12), ReturnFlags::empty(), true)
            .unwrap();
        dump.consume(&done(2), ReturnFlags::empty(), true).unwrap();
        let rows = dump.finish().unwrap();
        let rows = rows.iter().collect::<Vec<_>>();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].uid, rows[0].cgroup, rows[0].cookie), (991, 42, 11));
        assert!(rows[1].v6only);
        let mut incomplete = ListenerDump::new(17, 53).unwrap();
        incomplete
            .consume(&done(1), ReturnFlags::empty(), true)
            .unwrap();
        assert!(incomplete.finish().is_err());
    }
    #[test]
    fn listener_pure_malformed_partial_foreign_and_sticky_errors() {
        let valid = message(2, 53, 11);
        for len in 0..valid.len() {
            let mut d = ListenerDump::new(17, 53).unwrap();
            assert!(
                d.consume(&valid[..len], ReturnFlags::empty(), true)
                    .is_err()
            );
            assert!(d.finish().is_err());
        }
        for mutation in 0..6 {
            let mut b = valid.clone();
            match mutation {
                0 => b[6] |= 0x10,
                1 => b[6] |= 0x20,
                2 => b[8] = 9,
                3 => b[16] = 10,
                4 => b[16 + 74] = 0,
                _ => b[16 + 76..16 + 84].fill(0),
            }
            let mut d = ListenerDump::new(17, 53).unwrap();
            assert!(d.consume(&b, ReturnFlags::empty(), true).is_err());
            assert!(matches!(
                d.consume(&valid, ReturnFlags::empty(), true),
                Err(Unavailable::Revoked)
            ));
        }
        for flags in [ReturnFlags::TRUNC, ReturnFlags::CTRUNC] {
            let mut d = ListenerDump::new(17, 53).unwrap();
            assert!(d.consume(&valid, flags, true).is_err());
        }
        let mut d = ListenerDump::new(17, 53).unwrap();
        assert!(d.consume(&valid, ReturnFlags::empty(), false).is_err());
    }
    #[test]
    fn listener_pure_cgroup_v6only_duplicate_attributes_and_candidate_cap() {
        let mut d = ListenerDump::new(17, 53).unwrap();
        d.consume(&done(1), ReturnFlags::empty(), true).unwrap();
        d.begin_v6().unwrap();
        let mut b = message(10, 53, 1);
        b.truncate(16 + 84);
        let n = b.len() as u32;
        b[..4].copy_from_slice(&n.to_ne_bytes());
        assert!(d.consume(&b, ReturnFlags::empty(), true).is_err());
        let mut duplicate = message(2, 53, 1);
        let attr = duplicate[88..100].to_vec();
        duplicate.extend(attr);
        let n = duplicate.len() as u32;
        duplicate[..4].copy_from_slice(&n.to_ne_bytes());
        assert!(
            ListenerDump::new(17, 53)
                .unwrap()
                .consume(&duplicate, ReturnFlags::empty(), true)
                .is_err()
        );
        let mut d = ListenerDump::new(17, 53).unwrap();
        for i in 1..=64 {
            d.consume(&message(2, 53, i), ReturnFlags::empty(), true)
                .unwrap();
        }
        assert!(matches!(
            d.consume(&message(2, 53, 65), ReturnFlags::empty(), true),
            Err(Unavailable::Limit)
        ));
    }
    #[test]
    fn listener_pure_scan_budget_is_shared_across_families() {
        let mut d = ListenerDump::new(17, 53).unwrap();
        let unrelated = message(2, 54, 1);
        for _ in 0..65536 {
            d.consume(&unrelated, ReturnFlags::empty(), true).unwrap();
        }
        d.consume(&done(1), ReturnFlags::empty(), true).unwrap();
        d.begin_v6().unwrap();
        assert!(matches!(
            d.consume(&message(10, 53, 2), ReturnFlags::empty(), true),
            Err(Unavailable::Limit)
        ));
    }
}

/// Compile-only OS producer: caller заранее держит common FD/byte credits и
/// independently retained netns identity. Ошибка не возвращает partial census.
pub(crate) fn listener_census(
    protocol: u8,
    port: u16,
    namespace: (u64, u64),
    deadline: Instant,
    cancel: &AtomicBool,
    _credit: &crate::helper::resolver_stub::CaptureCredits,
) -> Result<ListenerSet, Unavailable> {
    if cancel.load(Ordering::Acquire) {
        return Err(Unavailable::Cancelled);
    }
    let begun = Instant::now();
    if begun >= deadline || namespace == (0, 0) {
        return Err(Unavailable::Timeout);
    }
    let deadline = deadline.min(begun + DEADLINE);
    let mut dump = ListenerDump::new(protocol, port)?;
    let socket = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        Some(SOCK_DIAG),
    )
    .map_err(diag_error)?;
    let ns = std::fs::File::from(
        yonik_nsfs::socket_namespace::socket_namespace(&socket)
            .map_err(|_| Unavailable::Coverage)?,
    );
    let m = ns.metadata().map_err(|_| Unavailable::Coverage)?;
    if (m.dev(), m.ino()) != namespace {
        return Err(Unavailable::Authority);
    }
    rustix::net::sockopt::set_socket_recv_buffer_size(&socket, 32768).map_err(diag_error)?;
    for family in 0..2 {
        if family == 1 {
            dump.begin_v6()?;
        }
        if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(Unavailable::Timeout);
        }
        rustix::net::sendto(
            &socket,
            &dump.request(),
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )
        .map_err(diag_error)?;
        loop {
            if cancel.load(Ordering::Acquire) {
                return Err(Unavailable::Cancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Unavailable::Timeout);
            }
            let mut bytes = [0; 32768];
            let mut space = [];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            let msg = match recvmsg(
                &socket,
                &mut [IoSliceMut::new(&mut bytes)],
                &mut ancillary,
                RecvFlags::DONTWAIT,
            ) {
                Ok(msg) => msg,
                Err(rustix::io::Errno::AGAIN) => {
                    std::thread::park_timeout(
                        (deadline - now).min(std::time::Duration::from_millis(1)),
                    );
                    continue;
                }
                Err(e) => return Err(diag_error(e)),
            };
            let sender = msg
                .address
                .as_ref()
                .and_then(|a| SocketAddrNetlink::try_from(a.clone()).ok());
            let trusted = sender.is_some_and(|a| a.pid() == 0 && a.groups() == 0);
            if dump.consume(&bytes[..msg.bytes], msg.flags, trusted)? {
                break;
            }
        }
    }
    dump.finish()
}
/// Полный bounded SOCK_DIAG dump: DUMP_INTR, truncation и overflow запрещают proof.
fn witness(
    flow: Flow,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Option<(u64, u64)>, Unavailable> {
    #[cfg(test)]
    WITNESSES.with(|count| count.set(count.get() + 1));
    witness_dump::<true>(flow, deadline, cancelled)
}

fn witness_dump<const FILTER_PORTS: bool>(
    flow: Flow,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Option<(u64, u64)>, Unavailable> {
    #[cfg(test)]
    let phase_start = Instant::now();
    let socket = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        Some(SOCK_DIAG),
    )
    .map_err(|_| Unavailable::Coverage)?;
    rustix::net::sockopt::set_socket_recv_buffer_size(&socket, 32768)
        .map_err(|_| Unavailable::Coverage)?;
    rustix::net::sockopt::set_socket_send_buffer_size(&socket, 4096)
        .map_err(|_| Unavailable::Coverage)?;
    let mut request = [0u8; 72];
    request[..4].copy_from_slice(&72u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20u16.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[16] = flow.family;
    request[17] = flow.protocol;
    request[20..24].fill(255);
    request[64..72].fill(255);
    // Linux tcp_diag_dump/udp_diag_dump сравнивают ненулевые порты на равенство.
    // Это необходимое условие userspace match, без выбора одного socket/interface.
    // Адреса и cookie по-прежнему проверяются после полного dump до DONE.
    if FILTER_PORTS {
        request[24..26].copy_from_slice(&flow.local_port.to_be_bytes());
        request[26..28].copy_from_slice(&flow.remote_port.to_be_bytes());
    }
    rustix::net::sendto(
        &socket,
        &request,
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )
    .map_err(|_| Unavailable::Coverage)?;
    #[cfg(test)]
    let sent_at = Instant::now();
    #[cfg(test)]
    let mut receives = 0usize;
    #[cfg(test)]
    let mut again = 0usize;
    let mut dump = DiagDump {
        flow,
        found: None,
        count: 0,
    };
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(Unavailable::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(Unavailable::Timeout);
        }
        let mut b = [0u8; 32768];
        let mut space = [];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let msg = match recvmsg(
            &socket,
            &mut [IoSliceMut::new(&mut b)],
            &mut ancillary,
            RecvFlags::DONTWAIT,
        ) {
            Ok(m) => m,
            Err(rustix::io::Errno::AGAIN) => {
                #[cfg(test)]
                {
                    again += 1;
                }
                std::thread::yield_now();
                continue;
            }
            Err(error) => return Err(diag_error(error)),
        };
        #[cfg(test)]
        {
            receives += 1;
        }
        let sender = msg
            .address
            .as_ref()
            .and_then(|a| SocketAddrNetlink::try_from(a.clone()).ok())
            .ok_or(Unavailable::Coverage)?;
        if sender.pid() != 0 || sender.groups() != 0 {
            return Err(Unavailable::Authority);
        }
        if let DumpProgress::Complete(result) = dump.consume(&b[..msg.bytes], msg.flags)? {
            #[cfg(test)]
            eprintln!(
                "diag phases send={:?} receive_done={:?} records={} receives={receives} again={again}",
                sent_at.duration_since(phase_start),
                sent_at.elapsed(),
                dump.count
            );
            return Ok(result);
        }
    }
}

fn diag_error(error: rustix::io::Errno) -> Unavailable {
    if error == rustix::io::Errno::NOBUFS {
        Unavailable::ReceiveOverflow
    } else {
        Unavailable::Coverage
    }
}
type SocketWitness = (u64, u64);
enum DumpProgress {
    Pending,
    Complete(Option<SocketWitness>),
}
struct DiagDump {
    flow: Flow,
    found: Option<(u64, u64)>,
    count: usize,
}
impl DiagDump {
    fn consume(&mut self, bytes: &[u8], flags: ReturnFlags) -> Result<DumpProgress, Unavailable> {
        if flags.intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC) {
            return Err(Unavailable::Coverage);
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let h = bytes
                .get(offset..offset + 16)
                .ok_or(Unavailable::Malformed)?;
            let len = u32n(&h[..4])? as usize;
            if len < 16 || offset + len > bytes.len() || u32n(&h[8..12])? != 1 {
                return Err(Unavailable::Malformed);
            }
            let flags = u16::from_ne_bytes([h[6], h[7]]);
            if flags & 0x10 != 0 {
                return Err(Unavailable::Coverage);
            }
            let kind = u16::from_ne_bytes([h[4], h[5]]);
            let body = &bytes[offset + 16..offset + len];
            if kind == 4 {
                return Err(Unavailable::ReceiveOverflow);
            }
            if kind == 2 {
                let code = u32n(body.get(..4).ok_or(Unavailable::Malformed)?)? as i32;
                return Err(if code == -rustix::io::Errno::NOBUFS.raw_os_error() {
                    Unavailable::ReceiveOverflow
                } else {
                    Unavailable::Coverage
                });
            }
            if kind == 3 {
                if body.len() < 4 || offset + ((len + 3) & !3) != bytes.len() {
                    return Err(Unavailable::Malformed);
                }
                if u32n(&body[..4])? != 0 {
                    return Err(Unavailable::Coverage);
                }
                return Ok(DumpProgress::Complete(self.found));
            }
            if kind != 20 || body.len() < 72 {
                return Err(Unavailable::Coverage);
            }
            self.count += 1;
            if self.count > MAX_DIAG_RECORDS {
                return Err(Unavailable::Limit);
            }
            let cookie = u64::from(u32n(&body[44..48])?) | (u64::from(u32n(&body[48..52])?) << 32);
            if body[0] == self.flow.family
                && body[4..6] == self.flow.local_port.to_be_bytes()
                && body[6..8] == self.flow.remote_port.to_be_bytes()
                && body[8..24] == self.flow.local
                && body[24..40] == self.flow.remote
                && self.flow.cookie.is_none_or(|c| c == cookie)
            {
                if self.found.is_some() {
                    return Err(Unavailable::AmbiguousSocket);
                }
                self.found = Some((u64::from(u32n(&body[68..72])?), cookie));
            }
            offset += (len + 3) & !3;
        }
        Ok(DumpProgress::Pending)
    }
}

pub(super) fn lookup(context: &TrustedContext, flow: Flow) -> Lookup {
    match capture(context, flow) {
        Ok(Some(s)) => Lookup::KnownOwner(s),
        Ok(None) => Lookup::UnknownFlow,
        Err(e) => Lookup::MechanismUnavailable(e),
    }
}
fn capture(context: &TrustedContext, flow: Flow) -> Result<Option<OwnerSnapshot>, Unavailable> {
    if context.revoked {
        return Err(Unavailable::Revoked);
    }
    if context.cancelled.load(Ordering::Acquire) {
        return Err(Unavailable::Cancelled);
    }
    context.worker.validate()?;
    context.validate_scope()?;
    if ![2, 10].contains(&flow.family) || ![6, 17].contains(&flow.protocol) {
        return Err(Unavailable::Malformed);
    }
    if flow.remote_port == 0 || flow.remote.iter().all(|v| *v == 0) {
        return Ok(None);
    }
    let begun = Instant::now();
    let deadline = begun + DEADLINE;
    let Some((inode, cookie)) = witness(flow, deadline, &context.cancelled)? else {
        return Ok(None);
    };
    let mut owner = None;
    let entries = fs::read_dir("/proc").map_err(|_| Unavailable::Coverage)?;
    let mut pids = 0;
    let mut task_count = 0;
    for entry in entries {
        if context.cancelled.load(Ordering::Acquire) {
            return Err(Unavailable::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(Unavailable::Timeout);
        }
        let entry = entry.map_err(|_| Unavailable::Coverage)?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        pids += 1;
        if pids > MAX_PROCESSES {
            return Err(Unavailable::Limit);
        }
        let leader_uid = entry.metadata().map_err(|_| Unavailable::Coverage)?.uid();
        let proof = if leader_uid == context.target_uid {
            let process = Process::capture(pid, context.target_uid)?;
            let exe =
                fs::File::open(format!("/proc/{pid}/exe")).map_err(|_| Unavailable::Coverage)?;
            let before = exe.metadata().map_err(|_| Unavailable::Coverage)?;
            Some((process, exe, before))
        } else {
            None
        };
        // Метаданные task проверяются и у foreign leader: UID task может отличаться.
        let tasks = fs::read_dir(format!("/proc/{pid}/task")).map_err(|_| Unavailable::Coverage)?;
        let mut candidate = None;
        for task in tasks {
            task_count += 1;
            if task_count > MAX_TASKS {
                return Err(Unavailable::Limit);
            }
            if context.cancelled.load(Ordering::Acquire) {
                return Err(Unavailable::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Unavailable::Timeout);
            }
            let task = task.map_err(|_| Unavailable::Coverage)?;
            if task.metadata().map_err(|_| Unavailable::Coverage)?.uid() != context.target_uid {
                continue;
            }
            let tid = task
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or(Unavailable::Coverage)?;
            // Разные credentials или namespace у task требуют отдельного authority.
            if fs::metadata(format!("/proc/{pid}"))
                .map_err(|_| Unavailable::Coverage)?
                .uid()
                != context.target_uid
                || namespaces(tid)? != context.lookup_view.namespaces
            {
                return Err(Unavailable::Coverage);
            }
            let task_start = super::start(tid)?;
            for (n, fd) in fs::read_dir(task.path().join("fd"))
                .map_err(|_| Unavailable::Coverage)?
                .enumerate()
            {
                if n >= MAX_FDS_PER_TASK {
                    return Err(Unavailable::Limit);
                }
                if context.cancelled.load(Ordering::Acquire) {
                    return Err(Unavailable::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(Unavailable::Timeout);
                }
                let fd = fd.map_err(|_| Unavailable::Coverage)?;
                let number = fd
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .ok_or(Unavailable::Coverage)?;
                if fs::read_link(fd.path())
                    .map_err(|_| Unavailable::Coverage)?
                    .as_os_str()
                    == format!("socket:[{inode}]").as_str()
                {
                    candidate = Some((tid, task_start, number));
                }
            }
            if task.metadata().map_err(|_| Unavailable::Coverage)?.uid() != context.target_uid
                || super::start(tid)? != task_start
                || namespaces(tid)? != context.lookup_view.namespaces
            {
                return Err(Unavailable::Coverage);
            }
        }
        let Some((task_id, task_start, fd_number)) = candidate else {
            continue;
        };
        let (process, exe, before) = proof.ok_or(Unavailable::Coverage)?;
        process.validate()?;
        let after = fs::metadata(format!("/proc/{pid}/exe")).map_err(|_| Unavailable::Coverage)?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(Unavailable::Coverage);
        }
        {
            if owner.is_some() {
                return Ok(None);
            }
            #[cfg(test)]
            capture_hook();
            owner = Some(OwnerSnapshot {
                socket_inode: inode,
                task_id,
                task_start,
                socket_fd: fd_number,
                pidfd: process.pidfd,
                executable_fd: exe,
                observed_from: begun,
                observed_until: Instant::now(),
                pid,
                start_time: process.start,
                executable: (before.dev(), before.ino()),
                cookie,
                epoch: context.epoch,
            });
        }
    }
    if witness(flow, deadline, &context.cancelled)? != Some((inode, cookie)) {
        return Ok(None);
    }
    context.worker.validate()?;
    if context.cancelled.load(Ordering::Acquire) {
        return Err(Unavailable::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(Unavailable::Timeout);
    }
    if let Some(snapshot) = owner.as_mut() {
        snapshot.observed_until = Instant::now();
    }
    Ok(owner)
}

/// Cache хранит прежний observation interval; каждый hit вновь проверяет owner/exe.
pub(super) fn duplicate(s: &OwnerSnapshot) -> Result<OwnerSnapshot, Unavailable> {
    Ok(OwnerSnapshot {
        socket_inode: s.socket_inode,
        task_id: s.task_id,
        task_start: s.task_start,
        socket_fd: s.socket_fd,
        pidfd: s.pidfd.try_clone().map_err(|_| Unavailable::Limit)?,
        executable_fd: s
            .executable_fd
            .try_clone()
            .map_err(|_| Unavailable::Limit)?,
        pid: s.pid,
        start_time: s.start_time,
        executable: s.executable,
        cookie: s.cookie,
        epoch: s.epoch,
        observed_from: s.observed_from,
        observed_until: s.observed_until,
    })
}
pub(super) fn revalidate(
    context: &TrustedContext,
    flow: Flow,
    s: &OwnerSnapshot,
) -> Result<OwnerSnapshot, Unavailable> {
    if s.epoch != context.epoch || s.observed_from.elapsed() >= DEADLINE {
        return Err(Unavailable::Timeout);
    }
    context.worker.validate()?;
    context.validate_scope()?;
    let process = Process::capture(s.pid, context.target_uid)?;
    if process.start != s.start_time || process.namespaces != context.lookup_view.namespaces {
        return Err(Unavailable::Authority);
    }
    let exe = fs::metadata(format!("/proc/{}/exe", s.pid)).map_err(|_| Unavailable::Coverage)?;
    if (exe.dev(), exe.ino()) != s.executable {
        return Err(Unavailable::Authority);
    }
    if super::start(s.task_id)? != s.task_start
        || namespaces(s.task_id)? != context.lookup_view.namespaces
    {
        return Err(Unavailable::Authority);
    }
    let target = fs::read_link(format!(
        "/proc/{}/task/{}/fd/{}",
        s.pid, s.task_id, s.socket_fd
    ))
    .map_err(|_| Unavailable::Coverage)?;
    if target.as_os_str() != format!("socket:[{}]", s.socket_inode).as_str() {
        return Err(Unavailable::Authority);
    }
    if witness(flow, s.observed_from + DEADLINE, &context.cancelled)?
        != Some((s.socket_inode, s.cookie))
    {
        return Err(Unavailable::Coverage);
    }
    process.validate()?;
    let after = fs::metadata(format!("/proc/{}/exe", s.pid)).map_err(|_| Unavailable::Coverage)?;
    if (after.dev(), after.ino()) != s.executable {
        return Err(Unavailable::Authority);
    }
    if s.observed_from.elapsed() >= DEADLINE {
        return Err(Unavailable::Timeout);
    }
    let mut result = duplicate(s)?;
    result.observed_until = Instant::now();
    Ok(result)
}
#[cfg(test)]
thread_local! {static CAPTURE_HOOK:std::cell::RefCell<Option<Box<dyn FnOnce()>>>=std::cell::RefCell::new(None);}
#[cfg(test)]
fn capture_hook() {
    CAPTURE_HOOK.with(|h| {
        if let Some(hook) = h.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{Flow, Unavailable};
    fn witness(
        flow: Flow,
        deadline: std::time::Instant,
    ) -> Result<Option<(u64, u64)>, Unavailable> {
        super::witness(flow, deadline, &std::sync::atomic::AtomicBool::new(false))
    }
    use std::{
        net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
        time::{Duration, Instant},
    };
    fn flow(local: SocketAddr, remote: SocketAddr, protocol: u8) -> Flow {
        let mut a = [0; 16];
        let mut b = [0; 16];
        let family = match (local, remote) {
            (SocketAddr::V4(l), SocketAddr::V4(r)) => {
                a[..4].copy_from_slice(&l.ip().octets());
                b[..4].copy_from_slice(&r.ip().octets());
                2
            }
            (SocketAddr::V6(l), SocketAddr::V6(r)) => {
                a = l.ip().octets();
                b = r.ip().octets();
                10
            }
            _ => panic!("семейства fixture должны совпадать"),
        };
        Flow {
            family,
            protocol,
            local_port: local.port(),
            remote_port: remote.port(),
            local: a,
            remote: b,
            cookie: None,
        }
    }
    #[test]
    fn cancellation_during_actual_capture_releases_partial_proof() {
        if std::env::var_os("YONIK_BROKER_GATES").is_none() {
            return;
        }
        use crate::attribution::broker::{Broker, Lookup, TrustedContext};
        use std::{net::UdpSocket, sync::mpsc, time::Duration};
        let fds = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let baseline = fds();
        let begun = Instant::now();
        {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.connect(peer.local_addr().unwrap()).unwrap();
            let uid = rustix::process::getuid().as_raw();
            let mut b = Broker::new(
                TrustedContext::from_host(std::process::id(), uid, uid, 7, [1; 32], [2; 32])
                    .unwrap(),
            )
            .unwrap();
            let cancel = b.cancellation();
            let (go, ready) = mpsc::channel();
            let (ack, done) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                ready.recv_timeout(Duration::from_secs(1)).unwrap();
                cancel.cancel();
                ack.send(()).unwrap();
            });
            super::CAPTURE_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    go.send(()).unwrap();
                    done.recv_timeout(Duration::from_secs(1)).unwrap();
                }))
            });
            let result = b.lookup(flow(
                socket.local_addr().unwrap(),
                socket.peer_addr().unwrap(),
                17,
            ));
            worker.join().unwrap();
            assert!(matches!(
                result,
                Lookup::MechanismUnavailable(Unavailable::Cancelled)
            ));
            assert!(b.cache.is_empty());
        }
        assert_eq!(fds(), baseline);
        assert!(begun.elapsed() < Duration::from_secs(1));
        eprintln!("in-flight cancel+teardown {:?}", begun.elapsed());
    }
    #[test]
    fn retained_projection_positive_and_stale_replaced_deleted_epoch() {
        retained_projection_retry(
            Instant::now() + Duration::from_secs(1),
            retained_projection_attempt,
        )
        .unwrap();
    }
    fn retained_projection_retry(
        deadline: Instant,
        mut observe: impl FnMut(Instant) -> Result<(), Unavailable>,
    ) -> Result<(), Unavailable> {
        let begun = Instant::now();
        for attempt in 1..=3 {
            if Instant::now() >= deadline {
                return Err(Unavailable::Timeout);
            }
            let result = observe(deadline);
            eprintln!(
                "retained attempt={attempt}, elapsed={:?}, result={result:?}",
                begun.elapsed()
            );
            match result {
                Ok(()) if Instant::now() <= deadline => return Ok(()),
                Ok(()) => return Err(Unavailable::Timeout),
                Err(Unavailable::Timeout) if attempt < 3 => {}
                other => return other,
            }
        }
        Err(Unavailable::Timeout)
    }
    #[test]
    fn retained_retry_is_bounded_and_only_timeout_is_retryable() {
        let mut calls = 0;
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            retained_projection_retry(deadline, |_| {
                calls += 1;
                Err(Unavailable::Timeout)
            }),
            Err(Unavailable::Timeout)
        );
        assert_eq!(calls, 3);
        calls = 0;
        assert_eq!(
            retained_projection_retry(deadline, |_| {
                calls += 1;
                Err(Unavailable::Authority)
            }),
            Err(Unavailable::Authority)
        );
        assert_eq!(calls, 1);
        calls = 0;
        assert_eq!(
            retained_projection_retry(Instant::now(), |_| {
                calls += 1;
                Ok(())
            }),
            Err(Unavailable::Timeout)
        );
        assert_eq!(calls, 0);
    }
    fn observe(
        client: &impl std::os::fd::AsRawFd,
        f: Flow,
        epoch: u64,
        deadline: Instant,
    ) -> Result<super::OwnerSnapshot, Unavailable> {
        use std::os::unix::fs::MetadataExt;
        let observed_from = Instant::now();
        let pid = std::process::id();
        let uid = rustix::process::getuid().as_raw();
        let process = super::Process::capture(pid, uid).unwrap();
        let exe = std::fs::File::open("/proc/self/exe").unwrap();
        let m = exe.metadata().unwrap();
        let result = witness(f, (observed_from + super::DEADLINE).min(deadline));
        eprintln!(
            "retained capture/witness elapsed={:?}, result={result:?}",
            observed_from.elapsed()
        );
        let (inode, cookie) = result?.expect("socket fixture должен присутствовать");
        assert_eq!(
            std::fs::read_link(format!("/proc/{pid}/task/{pid}/fd/{}", client.as_raw_fd()))
                .unwrap()
                .to_str()
                .unwrap(),
            format!("socket:[{inode}]")
        );
        process.validate().unwrap();
        Ok(super::OwnerSnapshot {
            pidfd: process.pidfd,
            executable_fd: exe,
            pid,
            start_time: process.start,
            executable: (m.dev(), m.ino()),
            cookie,
            epoch,
            socket_inode: inode,
            task_id: pid,
            task_start: process.start,
            socket_fd: client.as_raw_fd() as u32,
            observed_from,
            observed_until: Instant::now(),
        })
    }
    fn retained_projection_attempt(deadline: Instant) -> Result<(), Unavailable> {
        use super::super::{Broker, TrustedContext};
        use std::{collections::VecDeque, fs, os::unix::fs::MetadataExt};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client =
            std::sync::Arc::new(TcpStream::connect(listener.local_addr().unwrap()).unwrap());
        let (_peer, _) = listener.accept().unwrap();
        let f = flow(client.local_addr().unwrap(), client.peer_addr().unwrap(), 6);
        let pid = std::process::id();
        let uid = rustix::process::getuid().as_raw();
        let context = TrustedContext::from_host(pid, uid, uid, 7, [1; 32], [2; 32]).unwrap();
        let mut snapshot = observe(&*client, f, 7, deadline)?;
        let mut broker = Broker {
            context,
            cache: VecDeque::new(),
            last_cold: None,
        };
        let projected = broker.project(f, &snapshot, 7);
        eprintln!(
            "retained direct project elapsed={:?}, result={:?}",
            snapshot.observed_from.elapsed(),
            projected.as_ref().map(|(_, _, ttl)| ttl)
        );
        let (_, path, ttl) = projected?;
        assert_eq!(
            path,
            fs::read_link("/proc/self/exe").unwrap().to_str().unwrap()
        );
        assert!(ttl > Duration::ZERO && ttl <= Duration::from_millis(20));
        // Мутации после выбора candidate обязаны достигать final validator.
        for mutation in 0..7 {
            let candidate = observe(&*client, f, 7, deadline)?;
            broker.cache = VecDeque::from([(f, candidate)]);
            super::super::CANDIDATE_HOOK.with(|h| {
                *h.borrow_mut() = Some(Box::new(move |s| match mutation {
                    0 => s.start_time ^= 1,
                    1 => s.socket_fd = u32::MAX,
                    2 => s.cookie ^= 1,
                    3 => s.executable.1 ^= 1,
                    4 => s.epoch ^= 1,
                    5 => s.observed_from -= Duration::from_millis(21),
                    _ => s.executable_fd = std::fs::File::open("/dev/null").unwrap(),
                }))
            });
            assert!(
                matches!(
                    broker.lookup_and_project(f, 7),
                    super::super::ProjectedLookup::Unavailable(_)
                ),
                "mutation {mutation}"
            );
            assert!(broker.cache.is_empty());
        }
        let candidate = observe(&*client, f, 7, deadline)?;
        broker.cache = VecDeque::from([(f, candidate)]);
        super::WITNESSES.with(|n| n.set(0));
        let result = broker.lookup_and_project(f, 7);
        assert!(matches!(result, super::super::ProjectedLookup::Known(_)));
        assert_eq!(super::WITNESSES.with(|n| n.get()), 1);
        eprintln!("single RPC cache-hit witnesses=1");
        let candidate = observe(&*client, f, 7, deadline)?;
        let mut wrong = f;
        wrong.remote_port ^= 1;
        broker.cache = VecDeque::from([(wrong, candidate)]);
        assert!(matches!(
            broker.lookup_and_project(wrong, 7),
            super::super::ProjectedLookup::Unavailable(_)
        ));
        let candidate = observe(&*client, f, 7, deadline)?;
        broker.cache = VecDeque::from([(f, candidate)]);
        assert!(matches!(
            broker.lookup_and_project(f, 8),
            super::super::ProjectedLookup::Unavailable(Unavailable::Authority)
        ));
        broker
            .context
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(matches!(
            broker.lookup_and_project(f, 7),
            super::super::ProjectedLookup::Unavailable(Unavailable::Cancelled)
        ));
        assert!(broker.cache.is_empty());
        broker
            .context
            .cancelled
            .store(false, std::sync::atomic::Ordering::Release);
        let closing = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_closing_peer, _) = listener.accept().unwrap();
        let closing_flow = flow(
            closing.local_addr().unwrap(),
            closing.peer_addr().unwrap(),
            6,
        );
        let candidate = observe(&closing, closing_flow, 7, deadline)?;
        broker.cache = VecDeque::from([(closing_flow, candidate)]);
        super::super::CANDIDATE_HOOK
            .with(|h| *h.borrow_mut() = Some(Box::new(move |_| drop(closing))));
        assert!(matches!(
            broker.lookup_and_project(closing_flow, 7),
            super::super::ProjectedLookup::Unavailable(_)
        ));
        assert!(broker.cache.is_empty());
        let wire_client = std::sync::Arc::clone(&client);
        let wire_broker = Broker {
            context: TrustedContext::from_host(pid, uid, uid, 1, [3; 32], [2; 32]).unwrap(),
            cache: VecDeque::new(),
            last_cold: None,
        };
        crate::attribution::native_session::known_roundtrip(
            wire_broker,
            move |broker| {
                let snapshot = observe(&*wire_client, f, 1, deadline)?;
                // Candidate проверяется единственным final validator внутри RPC.
                broker.cache = VecDeque::from([(f, snapshot)]);
                Ok(())
            },
            f,
            deadline,
        )?;

        let stale = super::duplicate(&snapshot).unwrap();
        std::thread::sleep(super::DEADLINE.saturating_sub(stale.observed_from.elapsed()));
        assert!(matches!(
            broker.project(f, &stale, 7),
            Err(Unavailable::Timeout)
        ));
        snapshot = observe(&*client, f, 7, deadline)?;
        assert!(broker.project(f, &snapshot, 8).is_err());
        snapshot = observe(&*client, f, 7, deadline)?;
        snapshot.executable.1 ^= 1;
        assert!(broker.project(f, &snapshot, 7).is_err());
        snapshot = observe(&*client, f, 7, deadline)?;
        let path = std::env::temp_dir().join(format!("yonik-deleted-exe-{}", pid));
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        snapshot.executable_fd = file;
        // Реально заменённый retained FD не соответствует исходному executable.
        assert!(broker.project(f, &snapshot, 7).is_err());
        snapshot = observe(&*client, f, 7, deadline)?;
        snapshot.executable_fd = fs::File::open(&path).unwrap();
        let metadata = snapshot.executable_fd.metadata().unwrap();
        snapshot.executable = (metadata.dev(), metadata.ino());
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            broker.project(f, &snapshot, 7),
            Err(Unavailable::Coverage)
        ));
        snapshot = observe(&*client, f, 7, deadline)?;
        broker.revoke();
        assert!(matches!(
            broker.lookup_and_project(f, 7),
            super::super::ProjectedLookup::Unavailable(Unavailable::Revoked)
        ));
        assert!(broker.project(f, &snapshot, 7).is_err());
        Ok(())
    }
    #[test]
    fn single_rpc_cookieless_tcp_udp_v4_v6() {
        use super::super::{Broker, TrustedContext};
        use std::{collections::VecDeque, os::fd::OwnedFd};
        for address in ["127.0.0.1:0", "[::1]:0"] {
            for protocol in [6, 17] {
                let deadline = Instant::now() + Duration::from_secs(1);
                retained_projection_retry(deadline, |deadline| {
                    let (client, _peer, f): (OwnedFd, OwnedFd, Flow) = if protocol == 6 {
                        let listener = TcpListener::bind(address).unwrap();
                        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                        let (peer, _) = listener.accept().unwrap();
                        let f = flow(
                            client.local_addr().unwrap(),
                            client.peer_addr().unwrap(),
                            protocol,
                        );
                        (client.into(), peer.into(), f)
                    } else {
                        let client = UdpSocket::bind(address).unwrap();
                        let peer = UdpSocket::bind(address).unwrap();
                        client.connect(peer.local_addr().unwrap()).unwrap();
                        let f = flow(
                            client.local_addr().unwrap(),
                            peer.local_addr().unwrap(),
                            protocol,
                        );
                        (client.into(), peer.into(), f)
                    };
                    let client = std::sync::Arc::new(client);
                    let retained = std::sync::Arc::clone(&client);
                    assert!(f.cookie.is_none());
                    let pid = std::process::id();
                    let uid = rustix::process::getuid().as_raw();
                    let broker = Broker {
                        context: TrustedContext::from_host(pid, uid, uid, 1, [3; 32], [2; 32])
                            .unwrap(),
                        cache: VecDeque::new(),
                        last_cold: None,
                    };
                    crate::attribution::native_session::known_roundtrip(
                        broker,
                        move |broker| {
                            let snapshot = observe(&*client, f, 1, deadline)?;
                            broker.cache = VecDeque::from([(f, snapshot)]);
                            // Сокет должен жить до завершения RPC, включая final witness.
                            let _ = &client;
                            Ok(())
                        },
                        f,
                        deadline,
                    )?;
                    let mut cold = Broker {
                        context: TrustedContext::from_host(pid, uid, uid, 1, [3; 32], [2; 32])
                            .unwrap(),
                        cache: VecDeque::new(),
                        last_cold: None,
                    };
                    super::WITNESSES.with(|n| n.set(0));
                    let cold_result = cold.lookup_and_project(f, 1);
                    let count = super::WITNESSES.with(|n| n.get());
                    match cold_result {
                        super::super::ProjectedLookup::Known(_) => {
                            assert_eq!(count, 3);
                            eprintln!("cold Known witnesses={count}");
                        }
                        super::super::ProjectedLookup::Unavailable(reason) => eprintln!(
                            "cold unavailable={reason:?} witnesses={count}; cold Known не доказан"
                        ),
                        _ => panic!("существующий connected socket должен иметь candidate"),
                    }
                    drop(retained);
                    eprintln!("cookieless Known family={} protocol={protocol}", f.family);
                    Ok(())
                })
                .unwrap();
            }
        }
    }
    #[test]
    fn cookieless_retry_recovers_after_callback_timeout() {
        use super::super::{Broker, TrustedContext};
        use std::collections::VecDeque;
        let mut attempts = 0;
        retained_projection_retry(Instant::now() + Duration::from_secs(1), |deadline| {
            attempts += 1;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (_peer, _) = listener.accept().unwrap();
            let f = flow(client.local_addr().unwrap(), client.peer_addr().unwrap(), 6);
            let uid = rustix::process::getuid().as_raw();
            let broker = Broker {
                context: TrustedContext::from_host(
                    std::process::id(),
                    uid,
                    uid,
                    1,
                    [3; 32],
                    [2; 32],
                )
                .unwrap(),
                cache: VecDeque::new(),
                last_cold: None,
            };
            let retained = std::sync::Arc::new(client);
            let client = std::sync::Arc::clone(&retained);
            let force_timeout = attempts == 1;
            crate::attribution::native_session::known_roundtrip(
                broker,
                move |broker| {
                    // Управляемая ошибка callback проверяет retry, не причину задержки CI.
                    if force_timeout {
                        return Err(Unavailable::Timeout);
                    }
                    broker.cache = VecDeque::from([(f, observe(&*client, f, 1, deadline)?)]);
                    Ok(())
                },
                f,
                deadline,
            )
        })
        .unwrap();
        assert!((2..=3).contains(&attempts));
    }
    #[test]
    fn cache_rejects_reuse_executable_and_epoch_without_churn() {
        use super::{OwnerSnapshot, Process, TrustedContext, revalidate};
        use std::{fs, os::unix::fs::MetadataExt};
        let pid = std::process::id();
        let uid = rustix::process::getuid().as_raw();
        let context = TrustedContext::from_host(pid, uid, uid, 7, [1; 32], [2; 32]).unwrap();
        let process = Process::capture(pid, uid).unwrap();
        let exe = fs::File::open(format!("/proc/{pid}/exe")).unwrap();
        let m = exe.metadata().unwrap();
        let mut s = OwnerSnapshot {
            pidfd: process.pidfd,
            executable_fd: exe,
            pid,
            start_time: process.start,
            executable: (m.dev(), m.ino()),
            cookie: 1,
            epoch: 7,
            socket_inode: 1,
            task_id: pid,
            task_start: process.start,
            socket_fd: 0,
            observed_from: Instant::now(),
            observed_until: Instant::now(),
        };
        let f = Flow {
            family: 2,
            protocol: 6,
            local_port: 1,
            remote_port: 2,
            local: [0; 16],
            remote: [0; 16],
            cookie: None,
        };
        s.start_time = s.start_time.wrapping_add(1);
        assert!(matches!(
            revalidate(&context, f, &s),
            Err(Unavailable::Authority)
        ));
        s.start_time = process.start;
        s.executable.1 ^= 1;
        assert!(matches!(
            revalidate(&context, f, &s),
            Err(Unavailable::Authority)
        ));
        s.executable.1 ^= 1;
        s.epoch = 8;
        assert!(matches!(
            revalidate(&context, f, &s),
            Err(Unavailable::Timeout)
        ));
    }
    #[test]
    fn cookieless_dump_keeps_bound_interfaces_ambiguous() {
        let f = flow(
            "127.0.0.1:42000".parse().unwrap(),
            "127.0.0.1:42001".parse().unwrap(),
            17,
        );
        let mut dump = super::DiagDump {
            flow: f,
            found: None,
            count: 0,
        };
        for interface in [1u32, 2] {
            let mut message = vec![0; 88];
            message[..4].copy_from_slice(&88u32.to_ne_bytes());
            message[4..6].copy_from_slice(&20u16.to_ne_bytes());
            message[8..12].copy_from_slice(&1u32.to_ne_bytes());
            let body = &mut message[16..];
            body[0] = f.family;
            body[4..6].copy_from_slice(&f.local_port.to_be_bytes());
            body[6..8].copy_from_slice(&f.remote_port.to_be_bytes());
            body[8..24].copy_from_slice(&f.local);
            body[24..40].copy_from_slice(&f.remote);
            body[40..44].copy_from_slice(&interface.to_ne_bytes());
            body[44..48].copy_from_slice(&interface.to_ne_bytes());
            body[68..72].copy_from_slice(&interface.to_ne_bytes());
            let result = dump.consume(&message, rustix::net::ReturnFlags::empty());
            if interface == 1 {
                assert!(matches!(result, Ok(super::DumpProgress::Pending)));
            } else {
                assert!(matches!(result, Err(Unavailable::AmbiguousSocket)));
            }
        }
    }
    #[test]
    fn actual_udp_reuseport_dump_preserves_ambiguity() {
        use rustix::net::{AddressFamily, SocketType, bind, socket, sockopt::set_socket_reuseport};
        let cancel = std::sync::atomic::AtomicBool::new(false);
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let peer = UdpSocket::bind(address).unwrap();
            let family = if peer.local_addr().unwrap().is_ipv4() {
                AddressFamily::INET
            } else {
                AddressFamily::INET6
            };
            let a = socket(family, SocketType::DGRAM, None).unwrap();
            set_socket_reuseport(&a, true).unwrap();
            let local: SocketAddr = address.parse().unwrap();
            bind(&a, &local).unwrap();
            let a = UdpSocket::from(a);
            let b = socket(family, SocketType::DGRAM, None).unwrap();
            set_socket_reuseport(&b, true).unwrap();
            bind(&b, &a.local_addr().unwrap()).unwrap();
            let b = UdpSocket::from(b);
            a.connect(peer.local_addr().unwrap()).unwrap();
            b.connect(peer.local_addr().unwrap()).unwrap();
            let f = flow(a.local_addr().unwrap(), a.peer_addr().unwrap(), 17);
            for result in [
                super::witness_dump::<false>(f, Instant::now() + Duration::from_secs(1), &cancel),
                super::witness_dump::<true>(f, Instant::now() + Duration::from_secs(1), &cancel),
            ] {
                assert_eq!(result, Err(Unavailable::AmbiguousSocket));
            }
            let mut selected = f;
            selected.cookie = Some(rustix::net::sockopt::socket_cookie(&a).unwrap());
            let expected = super::witness_dump::<false>(
                selected,
                Instant::now() + Duration::from_secs(1),
                &cancel,
            )
            .unwrap();
            assert!(expected.is_some());
            assert_eq!(
                witness(selected, Instant::now() + Duration::from_secs(1)),
                Ok(expected)
            );
            selected.remote[0] ^= 1;
            assert_eq!(
                witness(selected, Instant::now() + Duration::from_secs(1)),
                Ok(None)
            );
        }
    }
    #[test]
    fn diag_tcp_udp_v4_v6_cookie_and_deadline() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address).unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (_peer, _) = listener.accept().unwrap();
            let tcp = flow(client.local_addr().unwrap(), client.peer_addr().unwrap(), 6);
            let proof = witness(tcp, Instant::now() + Duration::from_secs(1))
                .unwrap()
                .unwrap();
            assert_ne!(proof.0, 0);
            let unfiltered = super::witness_dump::<false>(
                tcp,
                Instant::now() + Duration::from_secs(1),
                &std::sync::atomic::AtomicBool::new(false),
            );
            assert_eq!(unfiltered, Ok(Some(proof)));
            let mut wrong_tuple = tcp;
            wrong_tuple.remote_port ^= 1;
            assert_eq!(
                witness(wrong_tuple, Instant::now() + Duration::from_secs(1)),
                Ok(None)
            );
            let mut wrong = tcp;
            wrong.cookie = Some(proof.1.wrapping_add(1));
            assert_eq!(
                witness(wrong, Instant::now() + Duration::from_secs(1)),
                Ok(None)
            );
            let a = UdpSocket::bind(address).unwrap();
            let b = UdpSocket::bind(address).unwrap();
            a.connect(b.local_addr().unwrap()).unwrap();
            let udp = flow(a.local_addr().unwrap(), b.local_addr().unwrap(), 17);
            let proof = witness(udp, Instant::now() + Duration::from_secs(1))
                .unwrap()
                .unwrap();
            assert_eq!(
                super::witness_dump::<false>(
                    udp,
                    Instant::now() + Duration::from_secs(1),
                    &std::sync::atomic::AtomicBool::new(false)
                ),
                Ok(Some(proof))
            );
            let mut wrong = udp;
            wrong.cookie = Some(proof.1.wrapping_add(1));
            assert_eq!(
                witness(wrong, Instant::now() + Duration::from_secs(1)),
                Ok(None)
            );
            wrong = udp;
            wrong.remote_port ^= 1;
            assert_eq!(
                witness(wrong, Instant::now() + Duration::from_secs(1)),
                Ok(None)
            );
            assert_eq!(witness(udp, Instant::now()), Err(Unavailable::Timeout));
        }
    }
}

#[cfg(test)]
#[path = "diag_tests.rs"]
mod diag_tests;

#[cfg(test)]
#[path = "cold_tests.rs"]
mod cold_tests;

#[cfg(test)]
pub(in crate::attribution) fn report_cold_witnesses() {
    {
        let count = WITNESSES.with(|n| n.get());
        assert_eq!(count, 3, "cold wire требует три настоящих witness");
        eprintln!("cold wire witnesses={count}");
    }
}
