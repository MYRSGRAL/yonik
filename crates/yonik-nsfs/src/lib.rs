//! Узкие safe nsfs/TUN API. Нет raw FD, generic ioctl или setns API.
#![cfg(target_os = "linux")]
// Байты c083 сохраняются для аудита; изменяется только безопасный protocol layer.
#[rustfmt::skip]
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64", target_env = "gnu"))]
pub mod fixed_self_fence;
pub mod kernel_probe;
pub mod kernel_probe_v2;
/// Fixed parent-death adapter локального sealed core; отдельное unsafe approval.
pub mod local_parent_death;
use std::{io, os::fd::AsFd};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    Net,
    Pid,
    Mount,
}

pub fn namespace_type(fd: impl AsFd) -> io::Result<NamespaceType> {
    let fd = fd.as_fd();
    if rustix::fs::fstatfs(fd)?.f_type as i64 != 0x6e736673 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "FD не nsfs"));
    }
    match kernel::get_type(fd)? {
        0x40000000 => Ok(NamespaceType::Net),
        0x20000000 => Ok(NamespaceType::Pid),
        0x00020000 => Ok(NamespaceType::Mount),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Неожиданный namespace type",
        )),
    }
}

// Единственное разрешённое unsafe-исключение, без generic public syscall API.
#[allow(unsafe_code)]
mod kernel {
    use rustix::ioctl::{Ioctl, IoctlOutput, Opcode};
    use std::{ffi::c_void, os::fd::BorrowedFd};
    struct GetNamespaceType;
    // SAFETY: _IO(0xb7,3) не читает/пишет userspace memory. Arg=NULL;
    // return value — integer CLONE_NEW*. Caller заранее проверил nsfs magic.
    unsafe impl Ioctl for GetNamespaceType {
        type Output = IoctlOutput;
        const IS_MUTATING: bool = false;
        fn opcode(&self) -> Opcode {
            rustix::ioctl::opcode::none(0xb7, 3)
        }
        fn as_ptr(&mut self) -> *mut c_void {
            std::ptr::null_mut()
        }
        unsafe fn output_from_ptr(
            out: IoctlOutput,
            _: *mut c_void,
        ) -> rustix::io::Result<Self::Output> {
            Ok(out)
        }
    }
    pub(super) fn get_type(fd: BorrowedFd<'_>) -> rustix::io::Result<IoctlOutput> {
        // SAFETY: fixed request, nsfs FD и lifetime проверены safe API выше;
        // нет pointer/out-buffer или передачи владения FD.
        unsafe { rustix::ioctl::ioctl(fd, GetNamespaceType) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    #[test]
    fn actual_kernel_namespace_types_and_non_nsfs_rejection() {
        for (name, kind) in [
            ("net", NamespaceType::Net),
            ("pid", NamespaceType::Pid),
            ("mnt", NamespaceType::Mount),
        ] {
            let fd = File::open(format!("/proc/self/ns/{name}")).unwrap();
            assert_eq!(namespace_type(&fd).unwrap(), kind);
        }
        assert_eq!(
            namespace_type(File::open("/dev/null").unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            namespace_type(File::open("/proc/self/ns/uts").unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}

/// Механическая очередь Linux TUN; не admission authority.
pub mod tun;
