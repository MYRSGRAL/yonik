//! Уведомления о замене файлов DNS. Настройки по-прежнему читает адаптер снимка.
use rustix::{
    fd::OwnedFd,
    fs::inotify::{self, CreateFlags, ReadFlags, Reader, WatchFlags},
};
use std::{ffi::OsString, io, mem::MaybeUninit, os::unix::ffi::OsStrExt, path::Path};
use tokio::io::unix::AsyncFd;

pub(crate) struct ResolverFileWatch {
    descriptor: AsyncFd<OwnedFd>,
    names: Vec<(i32, OsString)>,
}

impl ResolverFileWatch {
    pub(crate) fn new(paths: &[&Path]) -> io::Result<Self> {
        let descriptor = inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC)?;
        let flags = WatchFlags::ONLYDIR
            | WatchFlags::DONT_FOLLOW
            | WatchFlags::CREATE
            | WatchFlags::DELETE
            | WatchFlags::MOVE
            | WatchFlags::MODIFY
            | WatchFlags::CLOSE_WRITE
            | WatchFlags::ATTRIB
            | WatchFlags::MOVE_SELF
            | WatchFlags::DELETE_SELF;
        let mut names = Vec::with_capacity(paths.len());
        for path in paths {
            let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
            let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
            // DNS-менеджеры публикуют конфигурацию через rename. Наблюдение
            // за каталогом продолжает работать после замены inode файла.
            let watch = inotify::add_watch(&descriptor, parent, flags)?;
            names.push((watch, name.to_owned()));
        }
        Ok(Self {
            #[allow(deprecated)]
            descriptor: AsyncFd::new(descriptor)?,
            names,
        })
    }

    pub(crate) async fn changed(&self) -> io::Result<()> {
        loop {
            let mut ready = self.descriptor.readable().await?;
            let batch = ready.try_io(|fd| {
                let mut buffer = [MaybeUninit::<u8>::uninit(); 4096];
                let mut reader = Reader::new(fd.get_ref(), &mut buffer);
                let mut changed = false;
                loop {
                    let event = reader.next()?;
                    if event.events().intersects(
                        ReadFlags::IGNORED
                            | ReadFlags::QUEUE_OVERFLOW
                            | ReadFlags::MOVE_SELF
                            | ReadFlags::DELETE_SELF
                            | ReadFlags::UNMOUNT,
                    ) {
                        return Err(io::Error::other("Потеряно наблюдение за файлом DNS"));
                    }
                    changed |= event.file_name().is_some_and(|file| {
                        self.names.iter().any(|(watch, name)| {
                            event.wd() == *watch && file.to_bytes() == name.as_bytes()
                        })
                    });
                    if reader.is_buffer_empty() {
                        return Ok(changed);
                    }
                }
            });
            if let Ok(result) = batch {
                if result? {
                    return Ok(());
                }
            }
            // Шум в общем каталоге не должен занимать поток исполнителя.
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ResolverFileWatch;
    use std::{fs, path::PathBuf, time::Duration};

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let mut random = [0; 8];
            getrandom::getrandom(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "yonik-resolver-watch-{:x}",
                u64::from_ne_bytes(random)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[tokio::test]
    async fn observes_atomic_replacement_and_writes_to_the_new_inode() {
        let directory = Directory::new();
        let file = directory.0.join("resolv.conf");
        let temporary = directory.0.join("temporary");
        fs::write(&file, b"before").unwrap();
        let watch = ResolverFileWatch::new(&[&file]).unwrap();
        fs::write(&temporary, b"after").unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), watch.changed())
                .await
                .is_err()
        );
        fs::rename(&temporary, &file).unwrap();
        tokio::time::timeout(Duration::from_secs(1), watch.changed())
            .await
            .unwrap()
            .unwrap();
        fs::write(&file, b"another").unwrap();
        tokio::time::timeout(Duration::from_secs(1), watch.changed())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn moved_directory_invalidates_watch() {
        let directory = Directory::new();
        let source = directory.0.join("manager");
        fs::create_dir(&source).unwrap();
        let watch = ResolverFileWatch::new(&[&source.join("resolv.conf")]).unwrap();
        fs::rename(&source, directory.0.join("moved")).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), watch.changed())
                .await
                .unwrap()
                .is_err()
        );
    }
}
