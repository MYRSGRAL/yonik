//! Проверка локальных файлов worker и его отдельной области cgroup v2.

use super::WorkerSupervisorError;
use rustix::fs::{Mode, OFlags, fstatfs, open, openat};
use std::{
    fs::File,
    io::Read,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

type Result<T> = std::result::Result<T, WorkerSupervisorError>;
const CGROUP2_MAGIC: u64 = 0x6367_7270;
const MAX_FILE_BYTES: u64 = 16 * 1024;
pub(super) const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
const DIR_FLAGS: OFlags = FILE_FLAGS.union(OFlags::DIRECTORY);

fn unavailable<T>(_: T) -> WorkerSupervisorError {
    WorkerSupervisorError::Unavailable
}

pub(super) fn trusted(file: &File, directory: bool) -> Result<()> {
    let metadata = file.metadata().map_err(unavailable)?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}

pub(super) fn child(parent: &File, name: &str) -> Result<File> {
    let file = File::from(openat(parent, name, DIR_FLAGS, Mode::empty()).map_err(unavailable)?);
    trusted(&file, true)?;
    Ok(file)
}

pub(super) fn root() -> Result<File> {
    let file = File::from(open("/", DIR_FLAGS, Mode::empty()).map_err(unavailable)?);
    trusted(&file, true)?;
    Ok(file)
}

pub(super) fn read_bounded(file: File) -> Result<String> {
    let mut contents = String::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(unavailable)?;
    if contents.len() as u64 > MAX_FILE_BYTES {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(contents)
}

pub(super) struct WorkerCgroups {
    mount: File,
    mount_id: u64,
    parent: File,
    parent_name: String,
}

impl WorkerCgroups {
    pub(super) fn open(parent_name: &str) -> Result<Self> {
        let mut mount = root()?;
        for component in ["sys", "fs", "cgroup"] {
            mount = child(&mount, component)?;
        }
        if fstatfs(&mount).map_err(unavailable)?.f_type as u64 != CGROUP2_MAGIC {
            return Err(WorkerSupervisorError::Untrusted);
        }
        let mount_id = mount_identity(&mount)?;
        let parent = directory_in_mount(&mount, parent_name, mount_id)?
            .ok_or(WorkerSupervisorError::Unavailable)?;
        trusted(&parent, true)?;
        Ok(Self {
            mount,
            mount_id,
            parent,
            parent_name: parent_name.to_owned(),
        })
    }

    /// Вызывающий запрещает повторный запуск worker до очистки сети.
    pub(super) fn empty(&self, name: &str) -> Result<bool> {
        let group = directory_in_mount(&self.parent, name, self.mount_id)?;
        if let Some(group) = &group {
            trusted(group, true)?;
            let events = File::from(
                openat(group, "cgroup.events", FILE_FLAGS, Mode::empty()).map_err(unavailable)?,
            );
            verify_mount(&events, self.mount_id)?;
            trusted(&events, false)?;
            if !empty_events(&read_bounded(events)?)? {
                return Ok(false);
            }
        }

        // systemd может удалить уже пустую область. Новый каталог по тому же
        // пути, как и замена родителя, требуют нового подтверждения.
        let current = directory_in_mount(&self.parent, name, self.mount_id)?;
        let current_parent = directory_in_mount(&self.mount, &self.parent_name, self.mount_id)?;
        if (current.is_some() && !same_directory(group.as_ref(), current.as_ref())?)
            || !same_directory(Some(&self.parent), current_parent.as_ref())?
        {
            return Err(WorkerSupervisorError::Stale);
        }
        Ok(true)
    }
}

pub(super) fn open_worker_directory(parent: &File, name: &str) -> Result<Option<File>> {
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.contains('/')
        || name.chars().any(char::is_control)
    {
        return Err(WorkerSupervisorError::Untrusted);
    }
    match openat(parent, name, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(unavailable(error)),
    }
}

fn directory_in_mount(parent: &File, name: &str, mount: u64) -> Result<Option<File>> {
    let directory = open_worker_directory(parent, name)?;
    if let Some(directory) = &directory {
        verify_mount(directory, mount)?;
    }
    Ok(directory)
}

fn mount_identity(file: &File) -> Result<u64> {
    // openat2 может быть недоступен в sandbox сервиса. Проверяем mnt_id
    // после openat по тому же дескриптору, до чтения содержимого.
    let info =
        File::open(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).map_err(unavailable)?;
    let contents = read_bounded(info)?;
    contents
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|id| *id != 0)
        .ok_or(WorkerSupervisorError::Untrusted)
}

fn verify_mount(file: &File, expected: u64) -> Result<()> {
    if mount_identity(file)? != expected {
        return Err(WorkerSupervisorError::Untrusted);
    }
    Ok(())
}

fn same_directory(old: Option<&File>, new: Option<&File>) -> Result<bool> {
    match (old, new) {
        (Some(old), Some(new)) => {
            trusted(new, true)?;
            let old = old.metadata().map_err(unavailable)?;
            let new = new.metadata().map_err(unavailable)?;
            Ok(old.dev() == new.dev() && old.ino() == new.ino())
        }
        (None, None) => Ok(true),
        _ => Ok(false),
    }
}

pub(super) fn empty_events(contents: &str) -> Result<bool> {
    if !contents.ends_with('\n') {
        return Err(WorkerSupervisorError::Untrusted);
    }
    let mut populated = None;
    for line in contents.lines() {
        let (name, value) = line
            .split_once(' ')
            .ok_or(WorkerSupervisorError::Untrusted)?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(WorkerSupervisorError::Untrusted);
        }
        if name == "populated" {
            if populated.is_some() {
                return Err(WorkerSupervisorError::Untrusted);
            }
            populated = Some(match value {
                "0" => true,
                "1" => false,
                _ => return Err(WorkerSupervisorError::Untrusted),
            });
        }
    }
    populated.ok_or(WorkerSupervisorError::Untrusted)
}
