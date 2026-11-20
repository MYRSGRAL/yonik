//! Не ptrace и не generic ioctl: actual socket → retained network namespace FD.
use std::{
    io,
    num::NonZeroU32,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};
trait Ops<S> {
    type Namespace;
    fn socket(&self, fd: &S) -> io::Result<()>;
    fn acquire(&self, fd: &S) -> io::Result<Self::Namespace>;
    fn validate(&self, fd: &Self::Namespace) -> io::Result<()>;
    fn cloexec(&self, fd: &Self::Namespace) -> io::Result<()>;
}
fn checked<S, O: Ops<S>>(ops: &O, fd: &S) -> io::Result<O::Namespace> {
    ops.socket(fd)?;
    let namespace = ops.acquire(fd)?;
    ops.validate(&namespace)?;
    ops.cloexec(&namespace)?;
    Ok(namespace)
}
struct Kernel;
impl Ops<BorrowedFd<'_>> for Kernel {
    type Namespace = OwnedFd;
    fn socket(&self, fd: &BorrowedFd<'_>) -> io::Result<()> {
        if rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(fd)?.st_mode)
            != rustix::fs::FileType::Socket
        {
            return Err(io::Error::from_raw_os_error(libc::ENOTSOCK));
        }
        Ok(())
    }
    fn acquire(&self, fd: &BorrowedFd<'_>) -> io::Result<OwnedFd> {
        raw::namespace(*fd).map_err(Into::into)
    }
    fn validate(&self, fd: &OwnedFd) -> io::Result<()> {
        if crate::namespace_type(fd)? != crate::NamespaceType::Net {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(())
    }
    fn cloexec(&self, fd: &OwnedFd) -> io::Result<()> {
        let flags = rustix::io::fcntl_getfd(fd)?;
        rustix::io::fcntl_setfd(fd, flags | rustix::io::FdFlags::CLOEXEC)?;
        Ok(())
    }
}
/// Ошибки доступа не обходятся сменой uid/capabilities. Returned FD имеет
/// CLOEXEC; caller отдельно сравнивает nsfs dev/inode с trusted retained stamp.
pub fn socket_namespace(socket: impl AsFd) -> io::Result<OwnedFd> {
    checked(&Kernel, &socket.as_fd())
}
/// Только чтение SO_MARK actual profile socket; не general getsockopt API.
pub fn profile_socket_mark(socket: impl AsFd) -> io::Result<u32> {
    udp_raw::mark(socket.as_fd())
}
/// Устанавливает и перечитывает SO_MARK нового IP-сокета до connect.
pub fn mark_unconnected_dns_socket(socket: impl AsFd, mark: NonZeroU32) -> io::Result<()> {
    let fd = socket.as_fd();
    ensure_unconnected(fd)?;
    udp_raw::mark_dns(fd, mark)
}

/// Привязывает новый DNS-сокет к подтверждённому индексу интерфейса.
/// Существующая привязка и метка не могут быть заменены.
/// При ошибке вызывающий закрывает сокет.
pub fn bind_unconnected_private_dns_socket(
    socket: impl AsFd,
    ifindex: NonZeroU32,
    mark: u32,
) -> io::Result<()> {
    let fd = socket.as_fd();
    ensure_unconnected(fd)?;
    udp_raw::bind_private_dns(fd, ifindex, mark)
}

fn ensure_unconnected(fd: BorrowedFd<'_>) -> io::Result<()> {
    match rustix::net::getpeername(fd) {
        Ok(None) | Err(rustix::io::Errno::NOTCONN) => Ok(()),
        Ok(Some(_)) => Err(io::ErrorKind::AlreadyExists.into()),
        Err(error) => Err(error.into()),
    }
}
/// Consuming close ровно двух retained handles. Даже EINTR не повторяется:
/// numeric FD после close больше не принадлежит caller. Ошибка означает Unknown.
pub fn close_profile_socket(socket: OwnedFd, namespace: OwnedFd) -> io::Result<()> {
    close_pair(socket, namespace, raw::consume_close)
}
fn close_pair<T>(
    socket: T,
    namespace: T,
    mut close: impl FnMut(T) -> io::Result<()>,
) -> io::Result<()> {
    let first = close(socket);
    let second = close(namespace);
    first.and(second)
}

#[cfg(test)]
mod consuming_close_tests {
    #[test]
    fn consuming_close_pair_never_retries_uncertain_handle_and_consumes_neighbor() {
        for fail in [None, Some(1), Some(2)] {
            let mut seen = Vec::new();
            let result = super::close_pair(1, 2, |fd| {
                seen.push(fd);
                if fail == Some(fd) {
                    Err(std::io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            });
            assert_eq!(seen, [1, 2]);
            assert_eq!(result.is_ok(), fail.is_none());
        }
    }
}

/// Только fixed IPv4 UDP profile socket; не general setsockopt/recvmsg API.
pub struct UdpPeek {
    pub bytes: usize,
    pub address: [u8; 4],
    pub port: u16,
    pub flags: u16,
    pub overflow: u32,
}
pub fn prepare_profile_udp(socket: impl AsFd) -> io::Result<()> {
    udp_raw::prepare(socket.as_fd())
}
pub fn inspect_profile_udp(socket: impl AsFd) -> io::Result<()> {
    udp_raw::inspect(socket.as_fd())
}
pub fn peek_profile_udp(
    socket: impl AsFd,
    buffer: &mut [u8; 65536],
) -> io::Result<Option<UdpPeek>> {
    udp_raw::peek(socket.as_fd(), buffer)
}
fn udp_ancillary(bytes: &[u8]) -> io::Result<u32> {
    let width = std::mem::size_of::<usize>();
    let header = width + 8;
    let mut offset = 0;
    let mut found = None;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        if rest.len() < header {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut native = [0; std::mem::size_of::<usize>()];
        native.copy_from_slice(&rest[..width]);
        let length = usize::from_ne_bytes(native);
        let mut number = [0; 4];
        number.copy_from_slice(&rest[width..width + 4]);
        let level = i32::from_ne_bytes(number);
        number.copy_from_slice(&rest[width + 4..header]);
        let kind = i32::from_ne_bytes(number);
        if length != header + 4
            || length > rest.len()
            || level != libc::SOL_SOCKET
            || kind != libc::SO_RXQ_OVFL
            || found.is_some()
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        number.copy_from_slice(&rest[header..length]);
        found = Some(u32::from_ne_bytes(number));
        let end = offset + length;
        if end == bytes.len() {
            break;
        }
        offset = (end + width - 1) & !(width - 1);
        if offset > bytes.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(found.unwrap_or(0))
}
#[allow(unsafe_code)]
mod udp_raw {
    use super::{NonZeroU32, UdpPeek, io, udp_ancillary};
    use std::os::fd::{AsRawFd, BorrowedFd};
    fn option(fd: BorrowedFd<'_>, level: i32, name: i32) -> io::Result<i32> {
        let mut value = 0i32;
        let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: fixed int option, writable int/length живут до возврата syscall.
        let result = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                level,
                name,
                (&mut value as *mut i32).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of::<i32>() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(value)
    }
    pub(super) fn mark(fd: BorrowedFd<'_>) -> io::Result<u32> {
        Ok(option(fd, libc::SOL_SOCKET, libc::SO_MARK)? as u32)
    }
    fn set(fd: BorrowedFd<'_>, level: i32, name: i32, value: i32) -> io::Result<()> {
        // SAFETY: private fixed options, readonly int; generic API не экспортируется.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                name,
                (&value as *const i32).cast(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn validate_dns_socket(fd: BorrowedFd<'_>) -> io::Result<()> {
        let domain = option(fd, libc::SOL_SOCKET, libc::SO_DOMAIN)?;
        let socket_type = option(fd, libc::SOL_SOCKET, libc::SO_TYPE)?;
        let protocol = option(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL)?;
        if !matches!(domain, libc::AF_INET | libc::AF_INET6)
            || !matches!(
                (socket_type, protocol),
                (libc::SOCK_DGRAM, libc::IPPROTO_UDP) | (libc::SOCK_STREAM, libc::IPPROTO_TCP)
            )
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
    pub(super) fn mark_dns(fd: BorrowedFd<'_>, value: NonZeroU32) -> io::Result<()> {
        validate_dns_socket(fd)?;
        set_dns_mark(fd, value.get())
    }
    fn set_dns_mark(fd: BorrowedFd<'_>, value: u32) -> io::Result<()> {
        let current = mark(fd)?;
        if current != 0 && current != value {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if value == 0 {
            return Ok(());
        }
        set(fd, libc::SOL_SOCKET, libc::SO_MARK, value as i32)?;
        if mark(fd)? != value {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    pub(super) fn bind_private_dns(
        fd: BorrowedFd<'_>,
        ifindex: NonZeroU32,
        value: u32,
    ) -> io::Result<()> {
        // Linux UAPI asm-generic/socket.h и отдельный UAPI SPARC.
        #[cfg(not(any(target_arch = "sparc", target_arch = "sparc64")))]
        const SO_BINDTOIFINDEX: i32 = 62;
        #[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
        const SO_BINDTOIFINDEX: i32 = 0x0041;
        validate_dns_socket(fd)?;
        let index = i32::try_from(ifindex.get()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let current_mark = mark(fd)?;
        if current_mark != 0 && current_mark != value {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        match option(fd, libc::SOL_SOCKET, SO_BINDTOIFINDEX)? {
            0 => set(fd, libc::SOL_SOCKET, SO_BINDTOIFINDEX, index)?,
            current if current == index => {}
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        }
        if option(fd, libc::SOL_SOCKET, SO_BINDTOIFINDEX)? != index {
            return Err(io::ErrorKind::InvalidData.into());
        }
        set_dns_mark(fd, value)
    }
    fn socket(fd: BorrowedFd<'_>) -> io::Result<()> {
        if option(fd, libc::SOL_SOCKET, libc::SO_TYPE)? != libc::SOCK_DGRAM
            || option(fd, libc::SOL_SOCKET, libc::SO_DOMAIN)? != libc::AF_INET
            || option(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL)? != libc::IPPROTO_UDP
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
    pub(super) fn prepare(fd: BorrowedFd<'_>) -> io::Result<()> {
        socket(fd)?;
        set(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 65536)?;
        set(fd, libc::SOL_SOCKET, libc::SO_RXQ_OVFL, 1)?;
        set(fd, libc::IPPROTO_UDP, libc::UDP_GRO, 0)?;
        inspect(fd)
    }
    pub(super) fn inspect(fd: BorrowedFd<'_>) -> io::Result<()> {
        socket(fd)?;
        if !(65536..=131072).contains(&option(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)?)
            || option(fd, libc::SOL_SOCKET, libc::SO_RXQ_OVFL)? != 1
            || option(fd, libc::IPPROTO_UDP, libc::UDP_GRO)? != 0
        {
            return Err(io::ErrorKind::Unsupported.into());
        }
        Ok(())
    }
    pub(super) fn peek(
        fd: BorrowedFd<'_>,
        buffer: &mut [u8; 65536],
    ) -> io::Result<Option<UdpPeek>> {
        inspect(fd)?;
        let mut address = libc::sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let mut ancillary = [0usize; 16];
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        // SAFETY: zero — корректное начальное состояние msghdr; все используемые
        // pointers/lengths устанавливаются ниже и живут до завершения syscall.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut address as *mut libc::sockaddr_in).cast();
        message.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&ancillary);
        // SAFETY: fixed IPv4 UDP-only peek, valid bounded buffers, no FD reception
        // (SCM_RIGHTS существует только для AF_UNIX, который socket() отвергает).
        let count = unsafe {
            libc::recvmsg(
                fd.as_raw_fd(),
                &mut message,
                libc::MSG_PEEK | libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if message.msg_namelen as usize != std::mem::size_of::<libc::sockaddr_in>()
            || address.sin_family as i32 != libc::AF_INET
            || message.msg_controllen > std::mem::size_of_val(&ancillary)
            || message.msg_flags & !(libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: kernel-written initialized ancillary bytes внутри aligned array;
        // length отдельно проверена. Parser не следует pointers из control data.
        let control = unsafe {
            std::slice::from_raw_parts(ancillary.as_ptr().cast::<u8>(), message.msg_controllen)
        };
        let overflow = udp_ancillary(control)?;
        Ok(Some(UdpPeek {
            bytes: count as usize,
            address: address.sin_addr.s_addr.to_ne_bytes(),
            port: u16::from_be(address.sin_port),
            flags: u16::from(message.msg_flags & libc::MSG_TRUNC != 0)
                | (u16::from(message.msg_flags & libc::MSG_CTRUNC != 0) << 1),
            overflow,
        }))
    }
}
#[allow(unsafe_code)]
mod raw {
    use rustix::ioctl::{Ioctl, IoctlOutput, Opcode};
    use std::{
        ffi::c_void,
        os::fd::{BorrowedFd, FromRawFd, IntoRawFd, OwnedFd},
    };
    struct SocketNamespace;
    pub(super) fn consume_close(fd: OwnedFd) -> std::io::Result<()> {
        let raw = fd.into_raw_fd();
        // SAFETY: owned handle consumed exactly once; no retry even on EINTR.
        if unsafe { libc::close(raw) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    // SAFETY: SIOCGSKNS=0x894c, arg=NULL, result — новый kernel-owned FD.
    // Никаких user pointers, setns или caller-provided ioctl numbers.
    unsafe impl Ioctl for SocketNamespace {
        type Output = OwnedFd;
        const IS_MUTATING: bool = false;
        fn opcode(&self) -> Opcode {
            rustix::ioctl::opcode::none(0x89, 0x4c)
        }
        fn as_ptr(&mut self) -> *mut c_void {
            std::ptr::null_mut()
        }
        unsafe fn output_from_ptr(out: IoctlOutput, _: *mut c_void) -> rustix::io::Result<OwnedFd> {
            // SAFETY: вызывается rustix только после успешного fixed ioctl;
            // результат передаёт единственное владение новым FD.
            Ok(unsafe { OwnedFd::from_raw_fd(out) })
        }
    }
    pub(super) fn namespace(fd: BorrowedFd<'_>) -> rustix::io::Result<OwnedFd> {
        // SAFETY: fixed no-pointer ioctl, borrowed socket сохраняет lifetime.
        unsafe { rustix::ioctl::ioctl(fd, SocketNamespace) }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};
    #[test]
    fn udp_v2_ancillary_whitelist_bounds_duplicates_and_overflow() {
        assert_eq!(udp_ancillary(&[]).unwrap(), 0);
        let width = std::mem::size_of::<usize>();
        let header = width + 8;
        let mut c = (header + 4).to_ne_bytes().to_vec();
        c.extend_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
        c.extend_from_slice(&libc::SO_RXQ_OVFL.to_ne_bytes());
        c.extend_from_slice(&3u32.to_ne_bytes());
        assert_eq!(udp_ancillary(&c).unwrap(), 3);
        for n in 1..c.len() {
            assert!(udp_ancillary(&c[..n]).is_err());
        }
        let mut bad = c.clone();
        bad[width + 4] ^= 1;
        assert!(udp_ancillary(&bad).is_err());
        let mut twice = c.clone();
        twice.resize((c.len() + width - 1) & !(width - 1), 0);
        twice.extend_from_slice(&c);
        assert!(udp_ancillary(&twice).is_err());
    }
    struct Handle(Rc<Cell<usize>>);
    impl Drop for Handle {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    struct Fake {
        fail: u8,
        calls: Cell<u8>,
        drops: Rc<Cell<usize>>,
    }
    impl Fake {
        fn step(&self, n: u8) -> io::Result<()> {
            self.calls.set(n);
            if self.fail == n {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            } else {
                Ok(())
            }
        }
    }
    impl Ops<()> for Fake {
        type Namespace = Handle;
        fn socket(&self, _: &()) -> io::Result<()> {
            self.step(1)
        }
        fn acquire(&self, _: &()) -> io::Result<Handle> {
            self.step(2)?;
            Ok(Handle(Rc::clone(&self.drops)))
        }
        fn validate(&self, _: &Handle) -> io::Result<()> {
            self.step(3)
        }
        fn cloexec(&self, _: &Handle) -> io::Result<()> {
            self.step(4)
        }
    }
    #[test]
    fn fixed_socket_namespace_controls_fail_closed_and_close_acquired_handle() {
        for fail in 0..=4 {
            let drops = Rc::new(Cell::new(0));
            let ops = Fake {
                fail,
                calls: Cell::new(0),
                drops: Rc::clone(&drops),
            };
            let result = checked(&ops, &());
            assert_eq!(result.is_ok(), fail == 0);
            assert_eq!(ops.calls.get(), if fail == 0 { 4 } else { fail });
            drop(result);
            assert_eq!(drops.get(), usize::from(fail == 0 || fail >= 3));
        }
    }
}
