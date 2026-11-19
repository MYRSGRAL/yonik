//! Файловая изоляция автономного worker после unshare и до смены UID.

use super::WorkerSupervisorError as Error;
use crate::worker::WorkerMode;
use rustix::fs::{CWD, FileType, Mode, makedev, mknodat};
use std::{
    fs::{self, File, Permissions},
    io::{self, BufRead, BufReader},
    os::unix::fs::{PermissionsExt, symlink},
    process::{Command, Stdio},
};

type Result<T> = std::result::Result<T, Error>;
const DEVICES: [(&str, u32); 5] = [
    ("null", 3),
    ("zero", 5),
    ("full", 7),
    ("random", 8),
    ("urandom", 9),
];
const PRIVATE_TMP: &str = "nosuid,nodev,noexec,mode=1777,size=64M,nr_inodes=128";
const EMPTY_DIR: &str = "ro,nosuid,nodev,noexec,mode=000,size=4K,nr_inodes=2";

pub(super) fn setup(mode: WorkerMode) -> Result<()> {
    // Все операции применяются только в private mount namespace.
    verify_mounts(false)?;
    let null = File::open("/dev/null").map_err(unavailable)?;
    mount(
        &null,
        [
            "-o",
            "remount,bind,ro=recursive,nosuid=recursive,nodev=recursive",
            "/",
            "/",
        ],
    )?;
    // Старый mount(2) может проигнорировать суффикс recursive.
    verify_mounts(true)?;

    for path in ["/home", "/root", "/run/user"] {
        if directory_present(path)? {
            tmpfs(&null, path, EMPTY_DIR)?;
        }
    }
    for path in ["/tmp", "/var/tmp"] {
        if directory_present(path)? {
            tmpfs(&null, path, PRIVATE_TMP)?;
        }
    }

    if !directory_present("/dev")? {
        return Err(Error::Untrusted);
    }
    tmpfs(
        &null,
        "/dev",
        "dev,nosuid,noexec,mode=0755,size=1M,nr_inodes=32",
    )?;
    for (name, minor) in DEVICES {
        character_device(&format!("/dev/{name}"), 1, minor)?;
    }
    if mode == WorkerMode::Run {
        fs::create_dir("/dev/net").map_err(unavailable)?;
        fs::set_permissions("/dev/net", Permissions::from_mode(0o755)).map_err(unavailable)?;
        character_device("/dev/net/tun", 10, 200)?;
    }
    for (name, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
    ] {
        symlink(target, name).map_err(unavailable)?;
    }
    fs::create_dir("/dev/shm").map_err(unavailable)?;
    tmpfs(&null, "/dev/shm", PRIVATE_TMP)
}

fn directory_present(path: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(Error::Untrusted),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(unavailable(error)),
    }
}

fn character_device(path: &str, major: u32, minor: u32) -> Result<()> {
    mknodat(
        CWD,
        path,
        FileType::CharacterDevice,
        Mode::RUSR,
        makedev(major, minor),
    )
    .map_err(unavailable)?;
    fs::set_permissions(path, Permissions::from_mode(0o666)).map_err(unavailable)
}

fn tmpfs(null: &File, path: &str, options: &str) -> Result<()> {
    mount(null, ["-t", "tmpfs", "-o", options, "tmpfs", path])
}

fn mount<const N: usize>(null: &File, arguments: [&str; N]) -> Result<()> {
    let status = Command::new("/usr/bin/mount")
        .env_clear()
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::from(null.try_clone().map_err(unavailable)?))
        .args(["--internal-only", "--no-mtab", "--no-canonicalize"])
        .args(arguments)
        .status()
        .map_err(unavailable)?;
    if !status.success() {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn verify_mounts(read_only: bool) -> Result<()> {
    let mounts = BufReader::new(File::open("/proc/self/mountinfo").map_err(unavailable)?);
    let mut root_seen = false;
    for line in mounts.lines() {
        let line = line.map_err(unavailable)?;
        let mut fields = line.split_ascii_whitespace().skip(4);
        let target = fields.next().ok_or(Error::Untrusted)?;
        let options = fields.next().ok_or(Error::Untrusted)?;
        root_seen |= target == "/";
        if fields.take_while(|field| *field != "-").any(|field| {
            field.starts_with("shared:")
                || field.starts_with("master:")
                || field.starts_with("propagate_from:")
        }) {
            return Err(Error::Untrusted);
        }
        if read_only
            && ["ro", "nosuid", "nodev"]
                .into_iter()
                .any(|required| !options.split(',').any(|option| option == required))
        {
            return Err(Error::Untrusted);
        }
    }
    if !root_seen {
        return Err(Error::Untrusted);
    }
    Ok(())
}

fn unavailable<T>(_: T) -> Error {
    Error::Unavailable
}
