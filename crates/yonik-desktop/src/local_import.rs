//! Подготовка локального импорта вне UI-потока. Ничего не сохраняет и не активирует.
use std::{fmt, fs::File, io::Read, path::PathBuf};
use tokio::sync::watch;
use yonik_import::{MAX_INPUT_BYTES, ProfileImportReport};

/// Без исходного текста, системной ошибки и пути выбранного файла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareError {
    Cancelled,
    TooLarge,
    InvalidInput,
    File,
    Worker,
}
impl fmt::Display for PrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "Импорт отменён",
            Self::TooLarge => "Превышен размер импорта",
            Self::InvalidInput => "Некорректный импорт",
            Self::File => "Не удалось прочитать обычный файл",
            Self::Worker => "Не удалось подготовить импорт",
        })
    }
}
impl std::error::Error for PrepareError {}

fn check(cancel: &watch::Receiver<bool>) -> Result<(), PrepareError> {
    if *cancel.borrow() || cancel.has_changed().is_err() {
        Err(PrepareError::Cancelled)
    } else {
        Ok(())
    }
}

fn parse(
    bytes: Vec<u8>,
    cancel: &watch::Receiver<bool>,
) -> Result<ProfileImportReport, PrepareError> {
    check(cancel)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(PrepareError::TooLarge);
    }
    let report = yonik_import::import_profiles(bytes).map_err(|_| PrepareError::InvalidInput)?;
    check(cancel)?;
    Ok(report)
}

/// Вызывать после ограничения размера сообщения bridge, до постановки в очередь.
pub async fn prepare_text(
    bytes: Vec<u8>,
    cancel: watch::Receiver<bool>,
) -> Result<ProfileImportReport, PrepareError> {
    check(&cancel)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(PrepareError::TooLarge);
    }
    tokio::task::spawn_blocking(move || parse(bytes, &cancel))
        .await
        .map_err(|_| PrepareError::Worker)?
}

/// Открытие, чтение и разбор выполняются одним blocking worker, который ожидается до конца.
pub async fn prepare_file(
    path: PathBuf,
    cancel: watch::Receiver<bool>,
) -> Result<ProfileImportReport, PrepareError> {
    check(&cancel)?;
    tokio::task::spawn_blocking(move || {
        let bytes = read_file(path, &cancel)?;
        parse(bytes, &cancel)
    })
    .await
    .map_err(|_| PrepareError::Worker)?
}

fn read_file(path: PathBuf, cancel: &watch::Receiver<bool>) -> Result<Vec<u8>, PrepareError> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
    check(cancel)?;
    // openat2 запрещает symlink во всех компонентах без TOCTOU. NONBLOCK не даёт
    // зависнуть при подмене выбранного файла FIFO перед проверкой metadata.
    let fd = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| PrepareError::File)?;
    let mut file = File::from(fd);
    let metadata = file.metadata().map_err(|_| PrepareError::File)?;
    if !metadata.is_file() {
        return Err(PrepareError::File);
    }
    if metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err(PrepareError::TooLarge);
    }
    // metadata — только предварительная проверка: файл может вырасти после неё.
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        check(cancel)?;
        let count = file.read(&mut chunk).map_err(|_| PrepareError::File)?;
        if count == 0 {
            break;
        }
        if count > MAX_INPUT_BYTES - bytes.len() {
            return Err(PrepareError::TooLarge);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    check(cancel)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    const INPUT: &[u8] = b"trojan://private-token@example.com:443#profile\n";

    #[tokio::test]
    async fn text_preserves_original_and_cancellation_is_closed() {
        let (sender, receiver) = watch::channel(false);
        let report = prepare_text(INPUT.to_vec(), receiver.clone())
            .await
            .expect("отчёт");
        assert_eq!(report.original().expose().as_bytes(), INPUT);
        assert_eq!(report.entries.len(), 1);
        sender.send_replace(true);
        assert_eq!(
            prepare_text(INPUT.to_vec(), receiver).await.err(),
            Some(PrepareError::Cancelled)
        );
        assert!(!format!("{:?}", PrepareError::File).contains("private-token"));
    }

    #[tokio::test]
    async fn full_json_preserves_roots_instead_of_flattening_outbounds() {
        let (_sender, receiver) = watch::channel(false);
        let input =
            br#"[{"remarks":"Auto","outbounds":[{"protocol":"vless"},{"protocol":"trojan"}]}]"#;
        let report = prepare_text(input.to_vec(), receiver)
            .await
            .expect("профиль");
        assert_eq!(report.original().expose().as_bytes(), input);
        assert_eq!(report.entries.len(), 1);
        let yonik_import::ProfileEntry::Xray(profile) = &report.entries[0] else {
            panic!("полный профиль не должен превращаться в серверы");
        };
        assert_eq!(profile.name(), "Auto");
        assert!(profile.source().expose().contains("trojan"));
    }

    #[tokio::test]
    async fn file_rejects_symlinks_directories_fifo_and_sparse_oversize() {
        let path = std::env::temp_dir().join(format!(
            "yonik-local-input-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("каталог теста");
        fs::write(path.join("input"), INPUT).expect("файл");
        symlink(path.join("input"), path.join("link")).expect("symlink");
        symlink(&path, path.join("parent")).expect("symlink каталога");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            path.join("fifo"),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .expect("FIFO");
        File::create(path.join("large"))
            .expect("sparse")
            .set_len(MAX_INPUT_BYTES as u64 + 1)
            .expect("размер");
        let (_sender, receiver) = watch::channel(false);
        for selected in [
            path.clone(),
            path.join("link"),
            path.join("parent/input"),
            path.join("fifo"),
        ] {
            assert_eq!(
                prepare_file(selected, receiver.clone()).await.err(),
                Some(PrepareError::File)
            );
        }
        assert_eq!(
            prepare_file(path.join("large"), receiver.clone())
                .await
                .err(),
            Some(PrepareError::TooLarge)
        );
        let report = prepare_file(path.join("input"), receiver)
            .await
            .expect("обычный файл");
        assert_eq!(report.original().expose().as_bytes(), INPUT);
        fs::remove_dir_all(path).expect("очистка собственного тестового каталога");
    }
}
