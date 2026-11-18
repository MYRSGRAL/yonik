//! Закрепляет системные команды по FD до исполнения в helper.
use rustix::{
    fs::{self, FileType, Mode, OFlags},
    io::Errno,
};
use std::fs::File;

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const EXECUTABLE: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);

pub(super) enum NetworkTool {
    Ip,
    Nft,
}
impl NetworkTool {
    pub(super) fn open(self) -> Result<File, Errno> {
        let root = File::from(fs::open("/", DIRECTORY, Mode::empty())?);
        self.open_from(root)
    }

    fn open_from(self, root: File) -> Result<File, Errno> {
        let name = match self {
            Self::Ip => "ip",
            Self::Nft => "nft",
        };
        check(&root, FileType::Directory)?;
        let usr = File::from(fs::openat(&root, "usr", DIRECTORY, Mode::empty())?);
        check(&usr, FileType::Directory)?;
        // Arch использует bin, Debian размещает nft в sbin. Повреждённый
        // или недоверенный первый кандидат останавливает поиск.
        for component in ["bin", "sbin"] {
            let directory = match fs::openat(&usr, component, DIRECTORY, Mode::empty()) {
                Ok(fd) => File::from(fd),
                Err(Errno::NOENT) => continue,
                Err(error) => return Err(error),
            };
            check(&directory, FileType::Directory)?;
            let file = match fs::openat(&directory, name, EXECUTABLE, Mode::empty()) {
                Ok(fd) => File::from(fd),
                Err(Errno::NOENT) => continue,
                Err(error) => return Err(error),
            };
            check(&file, FileType::RegularFile)?;
            return Ok(file);
        }
        Err(Errno::NOENT)
    }
}

fn check(file: &File, kind: FileType) -> Result<(), Errno> {
    let stat = fs::fstat(file)?;
    if stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || FileType::from_raw_mode(stat.st_mode) != kind
        || kind == FileType::RegularFile
            && (stat.st_nlink != 1 || stat.st_mode & 0o111 == 0 || stat.st_mode & 0o6000 != 0)
    {
        return Err(Errno::PERM);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::PathBuf,
    };

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[ignore = "Требуется root внутри отдельного user namespace"]
    fn root_owned_search_accepts_sbin_and_rejects_untrusted_bin() {
        assert!(rustix::process::geteuid().is_root());
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let location = std::env::temp_dir().join(format!(
            "yonik-tool-search-{:016x}",
            u64::from_ne_bytes(nonce)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&location)
            .unwrap();
        let fixture = Fixture(location);
        let usr = fixture.0.join("usr");
        let bin = usr.join("bin");
        let sbin = usr.join("sbin");
        for dir in [&usr, &bin, &sbin] {
            std::fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
        }
        let root = || File::open(&fixture.0).unwrap();
        for (tool, name) in [(NetworkTool::Nft, "nft"), (NetworkTool::Ip, "ip")] {
            let installed = sbin.join(name);
            std::fs::write(&installed, b"sbin").unwrap();
            std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755)).unwrap();
            let mut result = String::new();
            tool.open_from(root())
                .unwrap()
                .read_to_string(&mut result)
                .unwrap();
            assert_eq!(result, "sbin");
        }
        let preferred = bin.join("nft");
        std::os::unix::fs::symlink("../sbin/nft", &preferred).unwrap();
        assert!(NetworkTool::Nft.open_from(root()).is_err());
        std::fs::remove_file(&preferred).unwrap();
        std::fs::write(&preferred, b"bin").unwrap();
        std::fs::set_permissions(&preferred, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(NetworkTool::Nft.open_from(root()).is_err());
        std::fs::set_permissions(&preferred, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut result = String::new();
        NetworkTool::Nft
            .open_from(root())
            .unwrap()
            .read_to_string(&mut result)
            .unwrap();
        assert_eq!(result, "bin");
    }
}
