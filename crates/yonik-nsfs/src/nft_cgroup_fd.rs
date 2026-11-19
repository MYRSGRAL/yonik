//! Передача nft одного каталога cgroup для сравнения по удерживаемому inode.

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use std::{
    io,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::Command,
};

/// Сохраняет каталог в новом процессе nft под исходным номером дескриптора.
/// В родительском процессе сохраняется CLOEXEC.
#[allow(unsafe_code)]
pub fn install_nft_cgroup_fd(command: &mut Command, directory: OwnedFd) -> io::Result<()> {
    let flags = fcntl_getfd(&directory)?;
    if directory.as_raw_fd() < 3 || !flags.contains(FdFlags::CLOEXEC) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: callback владеет FD. После fork вызывает только fcntl F_SETFD
    // с Copy flags. Преобразование Errno в io::Error не выделяет память.
    unsafe {
        command.pre_exec(move || {
            fcntl_setfd(&directory, flags - FdFlags::CLOEXEC).map_err(Into::into)
        });
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
        install_nft_cgroup_fd(&mut target, directory.into()).unwrap();
        assert!(!probe().status().unwrap().success());
        assert!(target.status().unwrap().success());
        assert!(!probe().status().unwrap().success());
    }
}
