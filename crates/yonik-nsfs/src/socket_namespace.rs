//! Не ptrace и не generic ioctl: actual socket → retained network namespace FD.
use std::{
    io,
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
#[allow(unsafe_code)]
mod raw {
    use rustix::ioctl::{Ioctl, IoctlOutput, Opcode};
    use std::{
        ffi::c_void,
        os::fd::{BorrowedFd, FromRawFd, OwnedFd},
    };
    struct SocketNamespace;
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
