//! Безопасный снимок буквальных данных обычного `/etc/resolv.conf`.
//!
//! Это доказательство настроенных upstream/search-настроек, не доказательство
//! того, что NSS/libc или другие процессы действительно читают этот файл.
//! Обычный файл и известные пути DNS-менеджеров проверяются отдельно.

use super::{ResolvConfLayout, ResolverError};
use std::{
    collections::BTreeSet,
    fs::{self, File, Metadata},
    io::Read,
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

pub(crate) const SYSTEM_RESOLV_CONF: &str = "/etc/resolv.conf";
#[cfg(feature = "test-support")]
pub(crate) const FIXTURE_DNS_SOURCE: &str = "/run/yonik/fixture-dns-source";
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_LINE_BYTES: usize = 4096;
const GLIBC_MAX_NAMESERVERS: usize = 3;
const GLIBC_MAX_SEARCH_DOMAINS: usize = 6;
const GLIBC_MAX_SEARCH_BYTES: usize = 256;
const RESOLVED_STUB: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 53));

#[derive(Clone, PartialEq, Eq)]
pub struct PlainResolverSnapshot {
    nameservers: Vec<IpAddr>,
    search_domains: Vec<String>,
    search_configured: bool,
    options: ResolverOptions,
}

#[derive(Clone, Default, PartialEq, Eq)]
struct ResolverOptions {
    flags: BTreeSet<&'static str>,
    ndots: Option<u8>,
    timeout: Option<u8>,
    attempts: Option<u8>,
}

impl ResolverOptions {
    fn observe(&mut self, option: &str) -> Result<(), ResolverError> {
        const SUPPORTED_FLAGS: &[&str] = &[
            "edns0",
            "no-aaaa",
            "no-tld-query",
            "rotate",
            "single-request",
            "single-request-reopen",
            "trust-ad",
            "use-vc",
        ];
        if let Some(&flag) = SUPPORTED_FLAGS.iter().find(|flag| **flag == option) {
            self.flags.insert(flag);
            return Ok(());
        }
        let (name, value) = option.split_once(':').ok_or(ResolverError::Unsupported)?;
        let target = match name {
            "ndots" => (&mut self.ndots, 0..=15),
            "timeout" => (&mut self.timeout, 1..=30),
            "attempts" => (&mut self.attempts, 1..=5),
            _ => return Err(ResolverError::Unsupported),
        };
        let number = value
            .parse::<u8>()
            .ok()
            .filter(|number| {
                value.bytes().all(|byte| byte.is_ascii_digit()) && target.1.contains(number)
            })
            .ok_or(ResolverError::Unsupported)?;
        *target.0 = Some(number);
        Ok(())
    }
}

impl PlainResolverSnapshot {
    pub(crate) fn bootstrap_tcp_only(&self) -> bool {
        self.options.flags.contains("use-vc")
    }

    pub(crate) fn bootstrap_ipv6_enabled(&self) -> bool {
        !self.options.flags.contains("no-aaaa")
    }

    pub fn nameservers(&self) -> &[IpAddr] {
        &self.nameservers
    }

    pub fn search_domains(&self) -> &[String] {
        &self.search_domains
    }

    /// Отличает явный пустой search list от его отсутствия в файле.
    pub fn search_configured(&self) -> bool {
        self.search_configured
    }

    /// Единственный nameserver соответствует полному stub systemd-resolved.
    /// Доступность daemon проверяется отдельно.
    pub fn is_resolved_stub(&self) -> bool {
        self.nameservers.as_slice() == [RESOLVED_STUB]
    }
}

impl std::fmt::Debug for PlainResolverSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlainResolverSnapshot")
            .field("nameserver_count", &self.nameservers.len())
            .field("search_domain_count", &self.search_domains.len())
            .field("search_configured", &self.search_configured)
            .finish()
    }
}

/// Читает только обычный root-owned файл, не следуя по симлинкам.
pub fn read_system_resolv_conf() -> Result<PlainResolverSnapshot, ResolverError> {
    read_path(Path::new(SYSTEM_RESOLV_CONF), 0)
}

pub(crate) fn read_managed_resolv_conf(
    layout: ResolvConfLayout,
) -> Result<PlainResolverSnapshot, ResolverError> {
    let target = plain_resolver_path(layout)
        .filter(|target| *target != SYSTEM_RESOLV_CONF)
        .ok_or(ResolverError::Unsupported)?;
    read_known_link(Path::new(SYSTEM_RESOLV_CONF), Path::new(target), 0)
}

pub(crate) fn plain_resolver_path(layout: ResolvConfLayout) -> Option<&'static str> {
    match layout {
        ResolvConfLayout::RegularFile => Some(SYSTEM_RESOLV_CONF),
        ResolvConfLayout::NetworkManager => Some("/run/NetworkManager/resolv.conf"),
        ResolvConfLayout::Resolvconf => Some("/run/resolvconf/resolv.conf"),
        _ => None,
    }
}

fn read_known_link(
    link: &Path,
    target: &Path,
    trusted_uid: u32,
) -> Result<PlainResolverSnapshot, ResolverError> {
    let parents = parent_fence(link, trusted_uid)?;
    let identity = |path: &Path| -> Result<StatIdentity, ResolverError> {
        let metadata = fs::symlink_metadata(path).map_err(io_error)?;
        if !metadata.is_symlink() || metadata.uid() != trusted_uid || metadata.nlink() != 1 {
            return Err(ResolverError::Untrusted);
        }
        Ok(StatIdentity::from(&metadata))
    };
    let before = identity(link)?;
    if fs::canonicalize(link).map_err(io_error)? != target {
        return Err(ResolverError::Untrusted);
    }
    let parsed = read_path(target, trusted_uid)?;
    if identity(link)? != before
        || parent_fence(link, trusted_uid)? != parents
        || fs::canonicalize(link).map_err(io_error)? != target
    {
        return Err(ResolverError::NetworkChanged);
    }
    Ok(parsed)
}

#[cfg(feature = "test-support")]
pub(crate) fn read_fixture_dns_source() -> Result<PlainResolverSnapshot, ResolverError> {
    read_path(Path::new(FIXTURE_DNS_SOURCE), 0)
}

fn read_path(path: &Path, trusted_uid: u32) -> Result<PlainResolverSnapshot, ResolverError> {
    read_path_with_hooks(path, trusted_uid, || {}, || {})
}

fn read_path_with_hooks<BeforeOpen, AfterOpen>(
    path: &Path,
    trusted_uid: u32,
    before_open: BeforeOpen,
    after_open: AfterOpen,
) -> Result<PlainResolverSnapshot, ResolverError>
where
    BeforeOpen: FnOnce(),
    AfterOpen: FnOnce(),
{
    let initial_path_metadata = fs::symlink_metadata(path).map_err(io_error)?;
    validate_file_metadata(&initial_path_metadata, trusted_uid)?;
    let initial_identity = StatIdentity::from(&initial_path_metadata);
    let initial_parents = parent_fence(path, trusted_uid)?;

    before_open();
    let parent = open_parent(&initial_parents, trusted_uid)?;
    let descriptor = rustix::fs::openat(
        &parent,
        path.file_name().ok_or(ResolverError::Untrusted)?,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ResolverError::Untrusted)?;
    let mut file = File::from(descriptor);
    let opened_metadata = file.metadata().map_err(io_error)?;
    validate_file_metadata(&opened_metadata, trusted_uid)?;
    if StatIdentity::from(&opened_metadata) != initial_identity {
        return Err(ResolverError::NetworkChanged);
    }

    after_open();
    if opened_metadata.size() > MAX_FILE_BYTES {
        return Err(ResolverError::Limit);
    }
    let mut contents = Vec::with_capacity(opened_metadata.size() as usize);
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(io_error)?;
    if contents.len() as u64 > MAX_FILE_BYTES {
        return Err(ResolverError::Limit);
    }

    let final_fd_metadata = file.metadata().map_err(io_error)?;
    let final_path_metadata = fs::symlink_metadata(path).map_err(io_error)?;
    let final_parents = parent_fence(path, trusted_uid)?;
    if StatIdentity::from(&final_fd_metadata) != initial_identity
        || StatIdentity::from(&final_path_metadata) != initial_identity
        || final_parents != initial_parents
    {
        return Err(ResolverError::NetworkChanged);
    }
    validate_file_metadata(&final_fd_metadata, trusted_uid)?;
    validate_file_metadata(&final_path_metadata, trusted_uid)?;

    parse_resolv_conf(&contents)
}

fn open_parent(
    parents: &[(PathBuf, DirectoryIdentity)],
    trusted_uid: u32,
) -> Result<File, ResolverError> {
    use rustix::fs::{Mode, OFlags, open, openat};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut opened =
        File::from(open("/", flags, Mode::empty()).map_err(|_| ResolverError::Untrusted)?);
    for (index, (path, expected)) in parents.iter().enumerate() {
        if index != 0 {
            let name = path.file_name().ok_or(ResolverError::Untrusted)?;
            opened = File::from(
                openat(&opened, name, flags, Mode::empty())
                    .map_err(|_| ResolverError::Untrusted)?,
            );
        }
        let metadata = opened.metadata().map_err(io_error)?;
        if DirectoryIdentity::from(&metadata) != *expected {
            return Err(ResolverError::NetworkChanged);
        }
        validate_parent_metadata(&metadata, trusted_uid)?;
    }
    Ok(opened)
}

fn validate_file_metadata(metadata: &Metadata, trusted_uid: u32) -> Result<(), ResolverError> {
    let mode = metadata.mode();
    if !metadata.is_file()
        || metadata.uid() != trusted_uid
        || metadata.nlink() != 1
        || mode & 0o022 != 0
        || mode & 0o6000 != 0
    {
        return Err(ResolverError::Untrusted);
    }
    if metadata.size() > MAX_FILE_BYTES {
        return Err(ResolverError::Limit);
    }
    Ok(())
}

fn parent_fence(
    path: &Path,
    trusted_uid: u32,
) -> Result<Vec<(PathBuf, DirectoryIdentity)>, ResolverError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ResolverError::Untrusted);
    }
    let mut current = PathBuf::from("/");
    let root_metadata = fs::symlink_metadata(&current).map_err(io_error)?;
    validate_parent_metadata(&root_metadata, trusted_uid)?;
    let mut parents = vec![(current.clone(), DirectoryIdentity::from(&root_metadata))];
    let parent = path.parent().ok_or(ResolverError::Untrusted)?;
    for component in parent.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => current.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ResolverError::Untrusted);
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(io_error)?;
        validate_parent_metadata(&metadata, trusted_uid)?;
        parents.push((current.clone(), DirectoryIdentity::from(&metadata)));
    }
    Ok(parents)
}

fn validate_parent_metadata(metadata: &Metadata, trusted_uid: u32) -> Result<(), ResolverError> {
    let mode = metadata.mode();
    if !metadata.is_dir() || mode & 0o6000 != 0 {
        return Err(ResolverError::Untrusted);
    }
    if metadata.uid() == 0 {
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(ResolverError::Untrusted);
        }
    } else if metadata.uid() != trusted_uid || mode & 0o077 != 0 {
        return Err(ResolverError::Untrusted);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StatIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
}

impl From<&Metadata> for DirectoryIdentity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
        }
    }
}

impl From<&Metadata> for StatIdentity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            size: metadata.size(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

fn io_error(error: std::io::Error) -> ResolverError {
    match error.kind() {
        std::io::ErrorKind::NotFound => ResolverError::Unavailable,
        std::io::ErrorKind::PermissionDenied => ResolverError::PermissionDenied,
        _ => ResolverError::Untrusted,
    }
}

fn parse_resolv_conf(contents: &[u8]) -> Result<PlainResolverSnapshot, ResolverError> {
    if contents.is_empty() {
        return Err(ResolverError::Unsupported);
    }
    let mut nameservers = Vec::with_capacity(GLIBC_MAX_NAMESERVERS);
    let mut nameserver_lines = 0usize;
    let mut options = ResolverOptions::default();
    let mut search_domains = Vec::new();
    let mut search_configured = false;

    for line in contents.split(|byte| *byte == b'\n') {
        if line.len() > MAX_LINE_BYTES {
            return Err(ResolverError::Limit);
        }
        let line = strip_comment(line);
        let line = trim_ascii(line);
        if line.is_empty() {
            continue;
        }
        let line = std::str::from_utf8(line).map_err(|_| ResolverError::Malformed)?;
        let mut words = line.split_ascii_whitespace();
        let directive = words.next().ok_or(ResolverError::Malformed)?;
        let values = words.collect::<Vec<_>>();
        match directive {
            "nameserver" => {
                if values.len() != 1 {
                    return Err(ResolverError::Malformed);
                }
                nameserver_lines += 1;
                if nameserver_lines > GLIBC_MAX_NAMESERVERS {
                    return Err(ResolverError::Limit);
                }
                let address = if values[0] == "127.0.0.53" {
                    RESOLVED_STUB
                } else {
                    parse_nameserver(values[0])?
                };
                if !nameservers.contains(&address) {
                    nameservers.push(address);
                }
            }
            "search" => {
                search_domains = validate_search_domains(&values)?;
                search_configured = true;
            }
            "domain" => {
                if values.len() != 1 {
                    return Err(ResolverError::Malformed);
                }
                search_domains = validate_search_domains(&values)?;
                search_configured = true;
            }
            "options" if !values.is_empty() => {
                for option in values {
                    options.observe(option)?;
                }
            }
            _ => return Err(ResolverError::Unsupported),
        }
    }

    let stub_only = nameservers.as_slice() == [RESOLVED_STUB] && nameserver_lines == 1;
    if nameservers.is_empty() || nameservers.contains(&RESOLVED_STUB) && !stub_only {
        return Err(ResolverError::Unsupported);
    }
    Ok(PlainResolverSnapshot {
        nameservers,
        search_domains,
        search_configured,
        options,
    })
}

fn validate_search_domains(values: &[&str]) -> Result<Vec<String>, ResolverError> {
    if values.len() > GLIBC_MAX_SEARCH_DOMAINS {
        return Err(ResolverError::Limit);
    }
    let total_bytes = values
        .iter()
        .try_fold(values.len().saturating_sub(1), |sum, value| {
            sum.checked_add(value.len()).ok_or(ResolverError::Limit)
        })?;
    if total_bytes > GLIBC_MAX_SEARCH_BYTES {
        return Err(ResolverError::Limit);
    }
    if values.iter().any(|domain| !valid_domain(domain)) {
        return Err(ResolverError::Malformed);
    }
    Ok(values.iter().map(|domain| (*domain).to_owned()).collect())
}

fn valid_domain(domain: &str) -> bool {
    if domain == "." {
        return true;
    }
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() || domain.len() > 253 || domain.starts_with('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn parse_nameserver(value: &str) -> Result<IpAddr, ResolverError> {
    if value.contains('%') {
        return Err(ResolverError::Unsupported);
    }
    let address = value
        .parse::<IpAddr>()
        .map_err(|_| ResolverError::Malformed)?;
    let unsupported = match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_link_local()
                || address == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (octets[0] == 0xfe && octets[1] & 0xc0 == 0x80)
        }
    };
    if unsupported {
        return Err(ResolverError::Unsupported);
    }
    Ok(address)
}

fn strip_comment(line: &[u8]) -> &[u8] {
    line.iter()
        .enumerate()
        .find(|(index, byte)| {
            matches!(**byte, b'#' | b';') && (*index == 0 || line[*index - 1].is_ascii_whitespace())
        })
        .map_or(line, |(index, _)| &line[..index])
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct FixtureDirectory(PathBuf);
    impl FixtureDirectory {
        fn new() -> Self {
            let nonce = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("yonik-plain-{}-{nonce}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn file(&self, contents: &[u8]) -> PathBuf {
            let path = self.0.join("resolv.conf");
            write_file(&path, contents);
            path
        }
    }
    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn write_file(path: &Path, contents: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(path)
            .unwrap();
        std::io::Write::write_all(&mut file, contents).unwrap();
    }

    fn fixture_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn распознаёт_resolved_stub_в_обычном_файле_без_запасного_resolver() {
        let stub = b"# NetworkManager\nnameserver 127.0.0.53\noptions edns0 trust-ad\n";
        assert!(parse_resolv_conf(stub).unwrap().is_resolved_stub());
        let mixed = [stub.as_slice(), b"nameserver 192.0.2.1\n"].concat();
        assert_eq!(parse_resolv_conf(&mixed), Err(ResolverError::Unsupported));
        let unknown = [stub.as_slice(), b"options no-reload\n"].concat();
        assert_eq!(parse_resolv_conf(&unknown), Err(ResolverError::Unsupported));
    }

    #[test]
    fn parses_literal_nameservers_and_effective_search_domain_directives() {
        let snapshot = parse_resolv_conf(
            b"# managed\nnameserver 1.1.1.1\nnameserver 2001:4860:4860::8888\ndomain old.test\nsearch corp.test example.test. # note\n",
        )
        .unwrap();
        assert_eq!(
            snapshot.nameservers,
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "2001:4860:4860::8888".parse().unwrap()
            ]
        );
        assert_eq!(snapshot.search_domains, vec!["corp.test", "example.test."]);
        assert!(snapshot.search_configured);
        assert!(!format!("{snapshot:?}").contains("1.1.1.1"));
        assert!(!format!("{snapshot:?}").contains("corp.test"));
    }

    #[test]
    fn rejects_unsupported_upstream_and_directives_fail_closed() {
        for input in [
            &b"nameserver 127.0.0.54\n"[..],
            b"nameserver ::1\n",
            b"nameserver fe80::1%eth0\n",
            b"nameserver fe80::1\n",
            b"nameserver 169.254.1.1\n",
            b"nameserver 0.0.0.0\n",
            b"nameserver 224.0.0.1\n",
            b"nameserver 1.1.1.1\noptions timeout:31\n",
            b"nameserver 1.1.1.1\ninclude /etc/resolv.conf\n",
        ] {
            assert_eq!(parse_resolv_conf(input), Err(ResolverError::Unsupported));
        }
    }

    #[test]
    fn applies_glibc_nameserver_and_search_bounds() {
        assert_eq!(
            parse_resolv_conf(
                b"nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\nnameserver 4.2.2.2\n"
            ),
            Err(ResolverError::Limit)
        );
        assert_eq!(
            parse_resolv_conf(b"nameserver 1.1.1.1\nsearch a b c d e f g\n"),
            Err(ResolverError::Limit)
        );
        assert_eq!(
            parse_resolv_conf(b"# no configured nameservers\n"),
            Err(ResolverError::Unsupported)
        );
    }

    #[test]
    fn reads_common_options_for_literal_upstream_and_detects_option_changes() {
        let base =
            b"nameserver 192.0.2.1\noptions edns0 trust-ad rotate use-vc ndots:2 attempts:4\n";
        let snapshot = parse_resolv_conf(base).unwrap();
        assert_eq!(
            snapshot.nameservers(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(snapshot.options.ndots, Some(2));
        assert_eq!(snapshot.options.attempts, Some(4));
        assert!(snapshot.options.flags.contains("use-vc"));

        let changed = [base.as_slice(), b"options ndots:3\n"].concat();
        assert_ne!(parse_resolv_conf(&changed).unwrap(), snapshot);
        let unsupported = [base.as_slice(), b"options no-reload\n"].concat();
        assert_eq!(
            parse_resolv_conf(&unsupported),
            Err(ResolverError::Unsupported)
        );
    }

    #[test]
    fn rejects_symlink_and_non_root_or_writable_target_policy() {
        let fixture = FixtureDirectory::new();
        let target = fixture.0.join("target");
        write_file(&target, b"nameserver 1.1.1.1\n");
        let alias = fixture.0.join("resolv.conf");
        symlink(target, &alias).unwrap();
        assert_eq!(
            read_path(&alias, fixture_uid()),
            Err(ResolverError::Untrusted)
        );

        let file = fixture.0.join("ordinary");
        write_file(&file, b"nameserver 1.1.1.1\n");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            read_path(&file, fixture_uid()),
            Err(ResolverError::Untrusted)
        );
        let other_uid = if fixture_uid() == 0 { u32::MAX } else { 0 };
        assert_eq!(read_path(&file, other_uid), Err(ResolverError::Untrusted));
    }

    #[test]
    fn reads_a_managers_link_only_to_the_expected_path() {
        let fixture = FixtureDirectory::new();
        let expected = fixture.0.join("manager-dns");
        let other = fixture.0.join("other-dns");
        let link = fixture.0.join("os-dns");
        write_file(&expected, b"nameserver 192.0.2.1\n");
        write_file(&other, b"nameserver 192.0.2.2\n");
        symlink(&expected, &link).unwrap();
        let snapshot = read_known_link(&link, &expected, fixture_uid()).unwrap();
        assert_eq!(
            snapshot.nameservers(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            read_known_link(&link, &other, fixture_uid()),
            Err(ResolverError::Untrusted)
        );
        assert_eq!(fs::read_link(link).unwrap(), expected);
    }

    #[test]
    fn atomic_replacement_before_open_is_detected() {
        let fixture = FixtureDirectory::new();
        let path = fixture.file(b"nameserver 1.1.1.1\n");
        let replacement = fixture.0.join("next");
        write_file(&replacement, b"nameserver 8.8.8.8\n");
        let result = read_path_with_hooks(
            &path,
            fixture_uid(),
            || fs::rename(&replacement, &path).unwrap(),
            || {},
        );
        assert_eq!(result, Err(ResolverError::NetworkChanged));
    }

    #[test]
    fn atomic_replacement_after_open_is_detected_by_final_path_fence() {
        let fixture = FixtureDirectory::new();
        let path = fixture.file(b"nameserver 1.1.1.1\n");
        let replacement = fixture.0.join("next");
        write_file(&replacement, b"nameserver 8.8.8.8\n");
        let result = read_path_with_hooks(
            &path,
            fixture_uid(),
            || {},
            || fs::rename(&replacement, &path).unwrap(),
        );
        assert_eq!(result, Err(ResolverError::NetworkChanged));
    }

    #[test]
    fn reads_stable_root_owned_fixture_without_following_path_changes() {
        let fixture = FixtureDirectory::new();
        let path = fixture.file(b"nameserver 1.1.1.1\nsearch corp.test\n");
        let snapshot = read_path(&path, fixture_uid()).unwrap();
        assert_eq!(
            snapshot.nameservers,
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(snapshot.search_domains, vec!["corp.test"]);
    }
}
