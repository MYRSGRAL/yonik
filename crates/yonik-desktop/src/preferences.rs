//! Ограниченные настройки без подписок и ключей; исходник ошибки не перезаписывается.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_BYTES: usize = 4096;
fn default_interval() -> u32 {
    86400
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Preferences {
    pub version: u8,
    /// Ревизия startup-настроек; остальные настройки не повышают её.
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub autostart_into_tray: bool,
    #[serde(default)]
    pub autoconnect: bool,
    #[serde(default)]
    pub autoconnect_target: Option<crate::startup_policy::Target>,
    #[serde(default)]
    pub repository_identity: Option<crate::startup_identity::Identity>,
    pub engine: String,
    pub port: Option<std::num::NonZeroU16>,
    pub probe_url: String,
    pub probe_status: u16,
    pub language: String,
    #[serde(default)]
    pub proxy_fetch_dns: Option<std::net::SocketAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_fake_dns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_fake_dns_policy_resolver: Option<std::net::SocketAddr>,
    #[serde(default = "default_interval")]
    pub subscription_interval_seconds: u32,
    #[serde(default)]
    pub subscription_background: bool,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            version: 3,
            revision: 0,
            autostart_into_tray: false,
            autoconnect: false,
            autoconnect_target: None,
            repository_identity: None,
            engine: "xray".into(),
            port: None,
            probe_url: super::backend::DEFAULT_PROBE_URL.into(),
            probe_status: 204,
            language: "ru".into(),
            proxy_fetch_dns: None,
            system_fake_dns: Vec::new(),
            system_fake_dns_policy_resolver: None,
            subscription_interval_seconds: default_interval(),
            subscription_background: false,
        }
    }
}

#[cfg(test)]
#[test]
fn system_fake_dns_suffixes_are_optional_and_validated_on_load() {
    let mut saved = serde_json::to_value(Preferences::default()).unwrap();
    saved.as_object_mut().unwrap().remove("system_fake_dns");
    assert!(valid(&serde_json::from_value(saved.clone()).unwrap()));
    saved["system_fake_dns"] = serde_json::json!(["example.test"]);
    assert!(valid(&serde_json::from_value(saved.clone()).unwrap()));
    saved["system_fake_dns"] = serde_json::json!(["127.0.0.1"]);
    assert!(!valid(&serde_json::from_value(saved).unwrap()));
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SaveOutcome {
    Durable,
    PublishedDurabilityUnknown,
}

/// Conflict содержит только проверенный снимок, прочитанный под writer lock.
/// Debug намеренно не раскрывает содержимое настроек/пути из I/O errors.
pub(crate) enum SaveError {
    Conflict(Box<Preferences>),
    Io(std::io::Error),
}
impl std::fmt::Debug for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(_) => f.write_str("PreferencesConflict"),
            Self::Io(error) => f.debug_tuple("PreferencesIo").field(&error.kind()).finish(),
        }
    }
}
impl From<std::io::Error> for SaveError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<serde_json::Error> for SaveError {
    fn from(error: serde_json::Error) -> Self {
        Self::Io(error.into())
    }
}

pub(crate) struct Store {
    path: PathBuf,
    original: Option<Vec<u8>>,
    blocked: bool,
    pub(crate) sync_directory: fn(&Path) -> std::io::Result<()>,
}
impl Store {
    pub fn open(directory: &Path) -> (Self, Preferences, bool) {
        let path = directory.join("preferences.json");
        let mut store = Self {
            path,
            original: None,
            blocked: false,
            sync_directory: |path| File::open(path)?.sync_all(),
        };
        let settings = match store.read() {
            Ok(None) => Some(Preferences::default()),
            Ok(Some(bytes)) => {
                let parsed = serde_json::from_slice::<Preferences>(&bytes)
                    .ok()
                    .filter(valid);
                store.original = Some(bytes);
                parsed.map(|mut settings| {
                    // Только read migration: original bytes остаются нетронутыми.
                    settings.version = 3;
                    settings
                })
            }
            Err(_) => None,
        };
        store.blocked = settings.is_none();
        let warning = store.blocked;
        (store, settings.unwrap_or_default(), warning)
    }
    pub(crate) fn directory(&self) -> &Path {
        self.path.parent().expect("каталог настроек")
    }
    fn read(&self) -> std::io::Result<Option<Vec<u8>>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&self.path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.len() > MAX_BYTES as u64
            || meta.uid() != rustix::process::getuid().as_raw()
            || meta.mode() & 0o777 != 0o600
        {
            return Err(std::io::Error::other("небезопасные настройки"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_BYTES {
            return Err(std::io::Error::other("лимит настроек"));
        }
        Ok(Some(bytes))
    }
    /// Общий lock всех writers; runtime-dir GUI не участвует в identity.
    /// Неблокирующий отказ ограничивает ожидание actor и сохраняет исходник.
    fn writer_lock(&self) -> std::io::Result<File> {
        let path = self.path.with_file_name("preferences.writer.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != rustix::process::getuid().as_raw()
            || meta.mode() & 0o7777 != 0o600
            || meta.nlink() != 1
        {
            return Err(std::io::Error::other("небезопасный lock настроек"));
        }
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        let current = fs::symlink_metadata(&path)?;
        if current.dev() != meta.dev()
            || current.ino() != meta.ino()
            || current.file_type().is_symlink()
        {
            return Err(std::io::Error::other("lock настроек заменён"));
        }
        Ok(file)
    }
    pub(crate) fn blocked(&self) -> bool {
        self.blocked
    }
    /// Только под common lock. Не принимает отсутствие/повреждение за defaults.
    fn conflict_locked(&mut self, current: Option<Vec<u8>>) -> SaveError {
        let Some(bytes) = current else {
            return SaveError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "настройки удалены извне",
            ));
        };
        let settings = serde_json::from_slice::<Preferences>(&bytes)
            .ok()
            .filter(valid);
        let Some(mut settings) = settings else {
            self.blocked = true;
            return SaveError::Io(std::io::Error::other(
                "неизвестный исходник настроек сохранён",
            ));
        };
        settings.version = 3;
        self.original = Some(bytes);
        SaveError::Conflict(Box::new(settings))
    }
    /// CAS под общим writer lock, который удерживается до directory fsync.
    #[allow(dead_code)]
    pub fn save_startup(
        &mut self,
        expected_revision: u64,
        autostart_into_tray: bool,
        autoconnect: bool,
        target: Option<crate::startup_policy::Target>,
    ) -> Result<(Preferences, SaveOutcome), SaveError> {
        let _lock = self.writer_lock()?;
        let mut settings = match &self.original {
            Some(bytes) => serde_json::from_slice::<Preferences>(bytes)?,
            None => Preferences::default(),
        };
        if self.blocked || !valid(&settings) {
            return Err(std::io::Error::other("запись настроек заблокирована").into());
        }
        if settings.revision != expected_revision {
            let current = self.read()?;
            return Err(self.conflict_locked(current));
        }
        settings.version = 3;
        settings.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("ревизия startup исчерпана"))?;
        settings.autostart_into_tray = autostart_into_tray;
        settings.autoconnect = autoconnect;
        settings.autoconnect_target = target;
        let outcome = self.save_locked(&settings)?;
        Ok((settings, outcome))
    }
    pub fn save(&mut self, settings: &Preferences) -> Result<SaveOutcome, SaveError> {
        let _lock = self.writer_lock()?;
        self.save_locked(settings)
    }
    fn save_locked(&mut self, settings: &Preferences) -> Result<SaveOutcome, SaveError> {
        let previous_revision = self
            .original
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<Preferences>(bytes).ok())
            .map_or(0, |settings| settings.revision);
        if self.blocked || !valid(settings) {
            return Err(
                std::io::Error::other("исходник настроек сохранён; запись заблокирована").into(),
            );
        }
        let current = self.read()?;
        if settings.revision < previous_revision || current != self.original {
            return Err(self.conflict_locked(current));
        }
        let bytes = serde_json::to_vec(settings)?;
        if bytes.len() > MAX_BYTES {
            return Err(std::io::Error::other("лимит настроек").into());
        }
        let temp = self
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            let current = self.read()?;
            if current != self.original {
                return Err(self.conflict_locked(current));
            }
            if self.original.is_none() {
                fs::hard_link(&temp, &self.path)?;
            } else {
                fs::rename(&temp, &self.path)?;
            }
            Ok::<(), SaveError>(())
        })();
        if temp.exists() {
            if let Err(error) = fs::remove_file(temp) {
                log::warn!("Не удалось убрать временный файл настроек: {error}");
            }
        }
        result?;
        // После публикации откат не обещаем: память должна принять видимый файл.
        self.original = Some(bytes);
        Ok(
            if (self.sync_directory)(self.path.parent().expect("каталог настроек")).is_ok()
            {
                SaveOutcome::Durable
            } else {
                SaveOutcome::PublishedDurabilityUnknown
            },
        )
    }
}
fn valid(p: &Preferences) -> bool {
    matches!(p.version, 1..=3)
        && (p.version == 3 || p.repository_identity.is_none())
        && (p.version != 1
            || (p.revision == 0
                && !p.autostart_into_tray
                && !p.autoconnect
                && p.autoconnect_target.is_none()))
        && p.autoconnect_target
            .as_ref()
            .is_none_or(crate::startup_policy::Target::valid)
        && p.subscription_interval_seconds >= default_interval()
        && p.proxy_fetch_dns.is_none_or(valid_proxy_fetch_dns)
        && valid_system_fake_dns(&p.system_fake_dns)
        && p.system_fake_dns_policy_resolver.is_none_or(|address| {
            yonik_linux::forward::PolicyProxyResolver::validate_upstream(address).is_ok()
        })
        && matches!(p.engine.as_str(), "xray" | "sing-box")
        && matches!(p.language.as_str(), "ru" | "en")
        && p.probe_url.len() <= 2048
        && !p.probe_url.contains(['@', '?', '#'])
        && yonik_linux::ProbeTarget::new(&p.probe_url, std::time::Duration::from_secs(5))
            .and_then(|t| t.with_expected_status(p.probe_status))
            .is_ok()
}

pub(crate) fn valid_system_fake_dns(suffixes: &[String]) -> bool {
    suffixes.len() <= 32
        && suffixes.iter().map(String::len).sum::<usize>() + suffixes.len().saturating_sub(1) * 2
            <= 1024
        && suffixes
            .iter()
            .all(|suffix| suffix.parse::<yonik_domain::DomainName>().is_ok())
}

/// Проверка тем же API, которое выполняет Proxy fetch; сетевых обращений нет.
pub(crate) fn valid_proxy_fetch_dns(address: std::net::SocketAddr) -> bool {
    yonik_linux::FetchHost::new(std::time::Duration::from_secs(30))
        .and_then(|host| host.with_socks_endpoint(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
        .and_then(|host| host.with_proxy_dns(address))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{SaveOutcome, Store, fs};
    #[test]
    fn интервал_legacy_границы_и_proxy_dns() {
        let preferences = super::Preferences::default();
        let mut value = serde_json::to_value(&preferences).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("subscription_interval_seconds");
        value
            .as_object_mut()
            .unwrap()
            .remove("subscription_background");
        let legacy: super::Preferences = serde_json::from_value(value).unwrap();
        assert_eq!(legacy.subscription_interval_seconds, 86400);
        assert!(!legacy.subscription_background);
        let mut p = legacy;
        p.subscription_interval_seconds = 86399;
        assert!(!super::valid(&p));
        p.subscription_interval_seconds = u32::MAX;
        assert!(super::valid(&p));
        p.proxy_fetch_dns = Some("127.0.0.1:5300".parse().unwrap());
        let reopened: super::Preferences =
            serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(reopened.proxy_fetch_dns, p.proxy_fetch_dns);
    }

    #[test]
    fn legacy_preferences_default_to_no_proxy_dns() {
        let mut json = serde_json::to_value(super::Preferences::default()).expect("JSON");
        json.as_object_mut()
            .expect("объект")
            .remove("proxy_fetch_dns");
        let legacy: super::Preferences = serde_json::from_value(json).expect("версия 1");
        assert!(legacy.proxy_fetch_dns.is_none());
        assert!(super::valid(&legacy));
    }

    #[test]
    fn directory_sync_failure_reports_publication_and_reopens_new_settings() {
        let dir =
            std::env::temp_dir().join(format!("yonik-preferences-sync-{}", std::process::id()));
        fs::create_dir(&dir).expect("fixture");
        let (mut store, mut preferences, _) = Store::open(&dir);
        store.save(&preferences).expect("начальное сохранение");
        store.sync_directory = |_| Err(std::io::Error::other("инъекция dir fsync"));
        preferences.language = "en".into();
        let result = store.save(&preferences);
        let (_, reopened, warning) = Store::open(&dir);
        assert!(!warning);
        assert_eq!(reopened.language, "en");
        assert_eq!(
            result.expect("опубликовано"),
            SaveOutcome::PublishedDurabilityUnknown
        );
        store.sync_directory = |path| super::File::open(path)?.sync_all();
        preferences.language = "ru".into();
        assert_eq!(
            store.save(&preferences).expect("повторная запись"),
            SaveOutcome::Durable
        );
        assert_eq!(Store::open(&dir).1.language, "ru");
        fs::remove_dir_all(dir).expect("очистка fixture");
    }

    #[test]
    fn foreign_temp_and_changed_file_are_preserved() {
        let dir =
            std::env::temp_dir().join(format!("yonik-preferences-foreign-{}", std::process::id()));
        fs::create_dir(&dir).expect("fixture");
        let (mut store, p, _) = Store::open(&dir);
        let temp = store
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&temp, b"foreign").expect("fixture");
        assert!(store.save(&p).is_err());
        assert_eq!(fs::read(&temp).expect("fixture"), b"foreign");
        fs::remove_file(&temp).expect("fixture");
        store.save(&p).expect("сохранение");
        fs::write(&store.path, b"changed").expect("fixture");
        assert!(store.save(&p).is_err());
        assert_eq!(fs::read(&store.path).expect("fixture"), b"changed");
        fs::remove_dir_all(dir).expect("очистка fixture");
    }

    #[test]
    fn reopen_and_preserve_invalid_truncated_unknown_and_symlink() {
        let dir = std::env::temp_dir().join(format!("yonik-preferences-{}", std::process::id()));
        fs::create_dir(&dir).expect("fixture");
        let (mut store, mut p, warning) = Store::open(&dir);
        assert!(!warning);
        p.language = "en".into();
        p.engine = "sing-box".into();
        store.save(&p).expect("сохранение");
        let original = fs::read(&store.path).expect("исходник");
        assert_eq!(Store::open(&dir).1.engine, "sing-box");
        assert_eq!(fs::read(&store.path).expect("после чтения"), original);
        assert_eq!(Store::open(&dir).1.language, "en");
        let mut unknown = serde_json::to_value(&p).expect("JSON");
        unknown["version"] = 99.into();
        let unknown = serde_json::to_vec(&unknown).expect("JSON");
        let oversized = vec![b' '; 4097];
        for raw in [
            b"{".as_slice(),
            b"invalid",
            unknown.as_slice(),
            oversized.as_slice(),
        ] {
            fs::write(&store.path, raw).expect("fixture");
            let (mut broken, _, warning) = Store::open(&dir);
            assert!(warning);
            assert!(broken.save(&p).is_err());
            assert_eq!(fs::read(&store.path).expect("исходник"), raw);
        }
        fs::remove_file(&store.path).expect("fixture");
        let victim = dir.join("victim");
        fs::write(&victim, "чужой файл".as_bytes()).expect("fixture");
        std::os::unix::fs::symlink(&victim, &store.path).expect("fixture");
        let (mut broken, _, warning) = Store::open(&dir);
        assert!(warning);
        assert!(broken.save(&p).is_err());
        assert_eq!(fs::read(&victim).expect("fixture"), "чужой файл".as_bytes());
        fs::remove_dir_all(dir).expect("очистка fixture");
    }
}

#[cfg(test)]
mod startup_tests {
    use super::{Preferences, SaveOutcome, Store, fs};
    #[test]
    fn lock_symlink_hardlink_и_неверные_права_не_трогаются() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("yonik-startup-lock-unsafe-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut store, p, _) = Store::open(&root);
        let lock = root.join("preferences.writer.lock");
        let victim = root.join("victim");
        fs::write(&victim, b"foreign").expect("fixture");
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).expect("fixture");
        std::os::unix::fs::symlink(&victim, &lock).expect("fixture");
        assert!(store.save(&p).is_err());
        fs::remove_file(&lock).expect("fixture");
        fs::hard_link(&victim, &lock).expect("fixture");
        assert!(store.save_startup(0, true, true, None).is_err());
        fs::remove_file(&lock).expect("fixture");
        fs::write(&lock, b"foreign").expect("fixture");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).expect("fixture");
        assert!(store.save(&p).is_err());
        assert_eq!(fs::read(&victim).expect("fixture"), b"foreign");
        assert!(!root.join("preferences.json").exists());
        fs::remove_dir_all(root).expect("fixture");
    }

    #[test]
    fn другой_процесс_с_другим_runtime_не_обходит_lock() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let root =
            std::env::temp_dir().join(format!("yonik-startup-process-lock-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut store, p, _) = Store::open(&root);
        store.save(&p).expect("seed");
        let mut child = Command::new("python3")
            .args(["-c", "import fcntl,sys; f=open(sys.argv[1], 'r+'); fcntl.flock(f, fcntl.LOCK_EX); print('held', flush=True); sys.stdin.read()"])
            .arg(root.join("preferences.writer.lock"))
            .env("XDG_RUNTIME_DIR", root.join("different-runtime"))
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("fixture lock owner");
        let mut ready = String::new();
        BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut ready)
            .expect("ready");
        assert_eq!(ready.trim(), "held");
        let original = fs::read(root.join("preferences.json")).expect("original");
        let ordinary = store.save(&p);
        let startup = store.save_startup(0, true, true, None);
        drop(child.stdin.take());
        assert!(child.wait().expect("child").success());
        assert!(ordinary.is_err());
        assert!(startup.is_err());
        assert_eq!(
            fs::read(root.join("preferences.json")).expect("preserved"),
            original
        );
        store.save_startup(0, true, false, None).expect("released");
        fs::remove_dir_all(root).expect("fixture");
    }

    #[test]
    fn общий_lock_блокирует_оба_writer_без_ожидания() {
        let root = std::env::temp_dir().join(format!("yonik-startup-lock-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut store, p, _) = Store::open(&root);
        let held = store.writer_lock().expect("lock");
        assert!(store.save(&p).is_err());
        assert!(store.save_startup(0, true, true, None).is_err());
        drop(held);
        store.save(&p).expect("lock освобождён");
        fs::remove_dir_all(root).expect("fixture");
    }

    #[test]
    fn миграция_и_четыре_комбинации() {
        let root = std::env::temp_dir().join(format!("yonik-startup-prefs-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut store, mut p, _) = Store::open(&root);
        assert_eq!(p.version, 3);
        assert!(!p.autostart_into_tray && !p.autoconnect);
        for (a, c) in [(false, false), (true, false), (false, true), (true, true)] {
            p = store.save_startup(p.revision, a, c, None).expect("CAS").0;
            let (_, reopened, warning) = Store::open(&root);
            assert!(!warning);
            assert_eq!((reopened.autostart_into_tray, reopened.autoconnect), (a, c));
        }
        assert!(store.save_startup(0, false, false, None).is_err());
        let mut legacy = serde_json::to_value(Preferences::default()).expect("json");
        legacy["version"] = 1.into();
        for key in [
            "revision",
            "autostart_into_tray",
            "autoconnect",
            "autoconnect_target",
        ] {
            legacy.as_object_mut().expect("object").remove(key);
        }
        let raw = serde_json::to_vec(&legacy).expect("json");
        fs::write(root.join("preferences.json"), &raw).expect("write");
        let (_, migrated, warning) = Store::open(&root);
        assert!(!warning);
        assert_eq!(migrated.version, 3);
        assert_eq!(migrated.revision, 0);
        assert!(!migrated.autostart_into_tray && !migrated.autoconnect);
        assert_eq!(fs::read(root.join("preferences.json")).expect("read"), raw);
        fs::remove_dir_all(root).expect("cleanup");
    }
    #[test]
    fn испорченный_исходник_выключен_и_заблокирован() {
        let root =
            std::env::temp_dir().join(format!("yonik-startup-invalid-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut store, p, _) = Store::open(&root);
        store.save(&p).expect("seed");
        for raw in [
            b"{".to_vec(),
            br#"{"version":99,"autoconnect":true}"#.to_vec(),
        ] {
            fs::write(root.join("preferences.json"), &raw).expect("fixture");
            let (mut store, p, warning) = Store::open(&root);
            assert!(warning);
            assert!(!p.autoconnect && !p.autostart_into_tray);
            assert!(store.save_startup(0, true, true, None).is_err());
            assert_eq!(fs::read(root.join("preferences.json")).expect("read"), raw);
        }
        fs::remove_dir_all(root).expect("cleanup");
    }
    #[test]
    fn stale_owner_и_durability_unknown() {
        let root = std::env::temp_dir().join(format!("yonik-startup-stale-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut store, old, _) = Store::open(&root);
        store.save(&old).expect("seed");
        let (mut other, _, _) = Store::open(&root);
        store.sync_directory = |_| Err(std::io::Error::other("fixture"));
        let (new, outcome) = store.save_startup(0, true, false, None).expect("published");
        assert_eq!(outcome, SaveOutcome::PublishedDurabilityUnknown);
        assert_eq!(new.revision, 1);
        assert!(store.save(&old).is_err());
        assert!(other.save_startup(0, false, true, None).is_err());
        assert!(Store::open(&root).1.autostart_into_tray);
        fs::remove_dir_all(root).expect("cleanup");
    }
    #[test]
    fn переполнение_сохраняет_исходник() {
        let root =
            std::env::temp_dir().join(format!("yonik-startup-overflow-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut store, mut p, _) = Store::open(&root);
        p.revision = u64::MAX;
        store.save(&p).expect("seed");
        let before = fs::read(root.join("preferences.json")).expect("read");
        assert!(store.save_startup(u64::MAX, true, true, None).is_err());
        assert_eq!(
            before,
            fs::read(root.join("preferences.json")).expect("read")
        );
        fs::remove_dir_all(root).expect("cleanup");
    }
}

#[cfg(test)]
mod startup_v3_tests {
    use super::*;
    #[test]
    fn v2_read_migration_preserves_bytes_and_old_reader_refuses_v3_field() {
        let root = std::env::temp_dir().join(format!("yonik-startup-v3-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut store, mut p, _) = Store::open(&root);
        p.version = 2;
        store.save(&p).expect("v2");
        let raw = fs::read(root.join("preferences.json")).expect("fixture");
        let (_, migrated, warning) = Store::open(&root);
        assert!(!warning);
        assert_eq!(migrated.version, 3);
        assert_eq!(
            fs::read(root.join("preferences.json")).expect("fixture"),
            raw
        );
        // Включение binding под старой версией отвергается до публикации.
        let mut value = serde_json::to_value(&p).expect("JSON");
        value["repository_identity"] = serde_json::json!({"path":"/fixture/subscriptions.sqlite","device":1,"inode":2,"directory_device":1,"directory_inode":3,"database":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]});
        let bound: Preferences = serde_json::from_value(value).expect("shape");
        assert!(!valid(&bound));
        assert!(store.save(&bound).is_err());
        fs::remove_dir_all(root).expect("fixture");
    }
}

#[cfg(test)]
mod old_reader_tests {
    use super::*;
    /// Строгая serde-форма L1 v2 без нового repository_identity.
    #[allow(dead_code)]
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OldV2 {
        version: u8,
        revision: u64,
        autostart_into_tray: bool,
        autoconnect: bool,
        autoconnect_target: Option<crate::startup_policy::Target>,
        engine: String,
        port: Option<std::num::NonZeroU16>,
        probe_url: String,
        probe_status: u16,
        language: String,
        proxy_fetch_dns: Option<std::net::SocketAddr>,
        subscription_interval_seconds: u32,
        subscription_background: bool,
    }
    #[test]
    fn closed_v2_reader_refuses_v3_without_downgrade() {
        let current = serde_json::to_vec(&Preferences::default()).expect("v3");
        assert!(serde_json::from_slice::<OldV2>(&current).is_err());
        let mut legacy: serde_json::Value = serde_json::from_slice(&current).expect("JSON");
        legacy
            .as_object_mut()
            .expect("object")
            .remove("repository_identity");
        legacy["version"] = 2.into();
        assert_eq!(
            serde_json::from_value::<OldV2>(legacy).expect("v2").version,
            2
        );
    }
}

#[cfg(test)]
mod conflict_tests {
    use super::*;
    #[test]
    fn два_store_conflict_refresh_и_следующий_явный_cas() {
        let root =
            std::env::temp_dir().join(format!("yonik-prefs-conflict-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut first, p, _) = Store::open(&root);
        first.save(&p).expect("seed");
        let (mut stale, _, _) = Store::open(&root);
        let (mut external, _) = first
            .save_startup(0, true, false, None)
            .expect("external CAS");
        external.language = "en".into();
        first.save(&external).expect("mixed external settings");
        let published = fs::read(root.join("preferences.json")).expect("read");
        let current = match stale.save_startup(0, false, true, None) {
            Err(SaveError::Conflict(current)) => *current,
            _ => panic!("ожидался typed conflict"),
        };
        assert_eq!(current.revision, 1);
        assert!(current.autostart_into_tray && !current.autoconnect);
        assert_eq!(current.language, "en");
        assert_eq!(stale.original.as_ref(), Some(&published));
        assert_eq!(
            fs::read(root.join("preferences.json")).expect("no retry"),
            published
        );
        let (updated, _) = stale
            .save_startup(current.revision, false, true, current.autoconnect_target)
            .expect("следующий явный CAS");
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.language, "en");
        assert!(!updated.autostart_into_tray && updated.autoconnect);
        fs::remove_dir_all(root).expect("fixture cleanup");
    }
    #[test]
    fn mixed_io_и_invalid_не_теряют_original_после_refresh() {
        let root = std::env::temp_dir().join(format!("yonik-prefs-mixed-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut first, p, _) = Store::open(&root);
        first.save(&p).expect("seed");
        let (mut stale, _, _) = Store::open(&root);
        first.save_startup(0, true, false, None).expect("external");
        let current = match stale.save_startup(0, false, true, None) {
            Err(SaveError::Conflict(current)) => *current,
            _ => panic!("conflict"),
        };
        let original = stale.original.clone();
        let temp = stale
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&temp, b"foreign temp").expect("fixture");
        assert!(matches!(stale.save(&current), Err(SaveError::Io(_))));
        assert_eq!(stale.original, original);
        assert_eq!(fs::read(&temp).expect("foreign preserved"), b"foreign temp");
        fs::remove_file(temp).expect("fixture");
        let invalid = br#"{"version":99,"private":"untouched"}"#;
        fs::write(&stale.path, invalid).expect("fixture");
        assert!(matches!(stale.save(&current), Err(SaveError::Io(_))));
        assert!(stale.blocked());
        assert_eq!(stale.original, original);
        assert_eq!(fs::read(&stale.path).expect("invalid preserved"), invalid);
        assert!(stale.save(&current).is_err());
        fs::remove_dir_all(root).expect("fixture cleanup");
    }
    #[test]
    fn symlink_не_становится_conflict_snapshot() {
        let root =
            std::env::temp_dir().join(format!("yonik-prefs-conflict-link-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let (mut store, p, _) = Store::open(&root);
        store.save(&p).expect("seed");
        let original = store.original.clone();
        fs::rename(&store.path, root.join("victim")).expect("fixture");
        std::os::unix::fs::symlink(root.join("victim"), &store.path).expect("fixture");
        assert!(matches!(store.save(&p), Err(SaveError::Io(_))));
        assert_eq!(store.original, original);
        assert_eq!(
            fs::read(root.join("victim")).expect("victim"),
            original.expect("seed")
        );
        fs::remove_dir_all(root).expect("fixture cleanup");
    }
}
