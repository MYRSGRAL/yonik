//! Передача nft закреплённых дескрипторов.

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use std::{
    io,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::Command,
};

/// Закрепляет FD каталога cgroup или файла с flock в новом процессе nft.
/// В родительском процессе сохраняется CLOEXEC.
#[allow(unsafe_code)]
pub fn inherit_nft_fd(command: &mut Command, fd: OwnedFd) -> io::Result<()> {
    let flags = fcntl_getfd(&fd)?;
    if fd.as_raw_fd() < 3 || !flags.contains(FdFlags::CLOEXEC) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: callback владеет FD. После fork вызывает только fcntl F_SETFD
    // с Copy flags. Преобразование Errno в io::Error не выделяет память.
    unsafe {
        command.pre_exec(move || fcntl_setfd(&fd, flags - FdFlags::CLOEXEC).map_err(Into::into));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn каталог_доступен_только_целевой_команде() {
        let directory = File::open("/proc").unwrap();
        let locator = format!("/proc/self/fd/{}", directory.as_raw_fd());
        let probe = || {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "test \"$1\" -ef /proc", "nft-cgroup-test", &locator]);
            command
        };
        let mut target = probe();
        inherit_nft_fd(&mut target, directory.into()).unwrap();
        assert!(!probe().status().unwrap().success());
        assert!(target.status().unwrap().success());
        assert!(!probe().status().unwrap().success());
    }

    #[test]
    fn дочерний_процесс_держит_блокировку_после_закрытия_fd_родителя() {
        use rustix::fs::{FlockOperation, MemfdFlags, flock, memfd_create};
        use std::process::Stdio;

        let writer = memfd_create("yonik-nft-lock-test", MemfdFlags::CLOEXEC).unwrap();
        let observer = File::open(format!("/proc/self/fd/{}", writer.as_raw_fd())).unwrap();
        flock(&writer, FlockOperation::LockExclusive).unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "read -r _ || :"]).stdin(Stdio::piped());
        inherit_nft_fd(&mut command, writer).unwrap();
        let mut child = command.spawn().unwrap();
        drop(command);
        assert_eq!(
            flock(&observer, FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        flock(&observer, FlockOperation::NonBlockingLockExclusive).unwrap();
    }
}
