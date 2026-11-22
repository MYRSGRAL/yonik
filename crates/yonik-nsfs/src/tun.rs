//! Только три согласованных fixed ioctl. Queue не передаёт owning FD и не реализует Clone.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_pointer_width = "64",
    target_endian = "little",
    target_env = "gnu"
)))]
compile_error!("TUN wrapper требует проверенный Linux GNU ABI x86_64 или AArch64");
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
};
type Result<T> = io::Result<T>;
fn reject<T>() -> Result<T> {
    Err(io::Error::other("Не совпадает контракт TUN"))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    Plain,
    Vnet10,
}
impl Framing {
    fn flags(self) -> u16 {
        match self {
            Self::Plain => 0x1001,
            Self::Vnet10 => 0x5001,
        }
    }
}
/// Единственный owning File. Drop закрывает очередь, включая любой error path.
pub struct Queue {
    file: File,
    name: String,
    framing: Framing,
}
impl Queue {
    /// Не проверяет Journal и не выдаёт authority. Эти проверки принадлежат helper.
    pub fn open(name: &str, framing: Framing) -> Result<Self> {
        kernel::validate_name(name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open("/dev/net/tun")?;
        kernel::attach(&file, name, framing)?;
        kernel::inspect(&file, name, framing)?;
        Ok(Self {
            file,
            name: name.into(),
            framing,
        })
    }
    /// Заимствование очереди не передаёт владение и не создаёт authority.
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.file)
    }
    /// Только non-default fixture: два typed owner удерживают ту же kernel queue.
    #[cfg(feature = "test-support")]
    pub fn test_duplicate(&self) -> Result<Self> {
        self.verify()?;
        let duplicate = Self {
            file: self.file.try_clone()?,
            name: self.name.clone(),
            framing: self.framing,
        };
        duplicate.verify()?;
        Ok(duplicate)
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn verify(&self) -> Result<()> {
        kernel::inspect(&self.file, &self.name, self.framing)
    }
}
// Allow ограничен private FFI boundary, остальной crate остаётся deny unsafe.
#[allow(unsafe_code)]
mod kernel {
    use super::{File, Framing, Result, io, reject};
    use std::os::fd::AsRawFd;
    pub(super) fn validate_name(name: &str) -> Result<()> {
        Ifreq::new(name).map(|_| ())
    }
    #[repr(C, align(8))]
    struct Ifreq {
        name: [u8; 16],
        data: [u8; 24],
    }
    const _: () = {
        assert!(std::mem::size_of::<Ifreq>() == 40);
        assert!(std::mem::align_of::<Ifreq>() == 8);
        assert!(std::mem::offset_of!(Ifreq, data) == 16);
        assert!(std::mem::size_of::<i32>() == 4);
    };
    impl Ifreq {
        fn new(name: &str) -> Result<Self> {
            if name.is_empty()
                || name.len() > 15
                || !name.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                return reject();
            }
            let mut r = Self {
                name: [0; 16],
                data: [0; 24],
            };
            r.name[..name.len()].copy_from_slice(name.as_bytes());
            Ok(r)
        }
    }
    // Единственные новые unsafe: фиксированные запросы, локальный initialized ifreq,
    // живой borrowed File. Ни request number, ни указатель не поступают от вызывающего.
    pub(super) fn attach(queue: &File, name: &str, framing: Framing) -> Result<()> {
        let mut r = Ifreq::new(name)?;
        r.data[..2].copy_from_slice(&framing.flags().to_ne_bytes());
        // SAFETY: на поддерживаемых ABI Linux ifreq занимает 40 байт.
        // Указатель доступен для записи и живёт до возврата ioctl.
        if unsafe { libc::ioctl(queue.as_raw_fd(), 0x400454ca, &mut r) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub(super) fn inspect(queue: &File, name: &str, framing: Framing) -> Result<()> {
        let mut r = Ifreq {
            name: [0; 16],
            data: [0; 24],
        };
        // SAFETY: TUNGETIFF writes only initialized 40-byte ifreq, no nested pointers.
        if unsafe { libc::ioctl(queue.as_raw_fd(), 0x800454d2u64, &mut r) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let expected = Ifreq::new(name)?;
        // IFF_PERSIST — единственный допустимый дополнительный read-only флаг.
        if r.name != expected.name
            || u16::from_ne_bytes([r.data[0], r.data[1]]) != framing.flags() | 0x0800
        {
            return reject();
        }
        if matches!(framing, Framing::Vnet10) {
            let mut size = 0i32;
            // SAFETY: фиксированный TUNGETVNETHDRSZ пишет один живой i32.
            if unsafe { libc::ioctl(queue.as_raw_fd(), 0x800454d7u64, &mut size) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if size != 10 {
                return reject();
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_names_rejected_before_open() {
        for name in ["", "../tun", "1234567890123456", "tun%0", "tun\0"] {
            assert!(Queue::open(name, Framing::Plain).is_err());
        }
    }
    #[test]
    #[ignore = "Только отдельный user/net namespace с YONIK_NFT_TEST_HOST_NETNS"]
    fn real_queue_cloexec_and_close_on_error() {
        use std::os::unix::fs::MetadataExt;
        let ns = std::fs::metadata("/proc/thread-self/ns/net").unwrap();
        assert_ne!(
            format!("{}:{}", ns.dev(), ns.ino()),
            std::env::var("YONIK_NFT_TEST_HOST_NETNS").unwrap()
        );
        let ip = |args: &[&str]| {
            assert!(
                std::process::Command::new("/usr/bin/ip")
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            )
        };
        ip(&["tuntap", "add", "dev", "custody0", "mode", "tun"]);
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let baseline = count();
        let queue = Queue::open("custody0", Framing::Plain).unwrap();
        assert!(
            rustix::io::fcntl_getfd(&queue.file)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(Queue::open("custody0", Framing::Plain).is_err());
        assert_eq!(count(), baseline + 1);
        drop(queue);
        assert_eq!(count(), baseline);
        let file = File::open("/dev/net/tun").unwrap();
        assert!(kernel::inspect(&file, "custody0", Framing::Plain).is_err());
        drop(file);
        assert_eq!(count(), baseline);
        ip(&["tuntap", "del", "dev", "custody0", "mode", "tun"]);
    }
}
