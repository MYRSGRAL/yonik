//! Системный allowlist: пути и параметры запуска не поступают от клиента.

use std::{
    fs::{File, Metadata},
    io::Read,
    os::unix::fs::MetadataExt,
    str::FromStr,
    sync::{Mutex, Weak},
};

use rustix::fs::{Mode, OFlags, open, openat};
use serde::Deserialize;
use yonik_engine::Engine;

use super::memory::{ByteBudget, executable_budget};
use crate::host::{BinarySnapshot, HostError, Sha256, SharedImage};

const MAX_MANIFEST: u64 = 4096;
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
const DIR_FLAGS: OFlags = FILE_FLAGS.union(OFlags::DIRECTORY);

/// Ошибки не содержат исходные пути, содержимое файлов или ошибки ОС.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    Unavailable,
    UnsafeEntry,
    Manifest,
    Version,
    HashMismatch,
    InvalidBinary,
    Snapshot,
    MissingEngine,
    Capacity,
}
impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "Системный реестр ядер недоступен",
            Self::UnsafeEntry => "Недоверенная запись системного реестра",
            Self::Manifest => "Некорректный манифест системного реестра",
            Self::Version => "Версия ядра не соответствует контракту",
            Self::HashMismatch => "SHA-256 системного ядра не совпадает",
            Self::InvalidBinary => "Некорректный бинарник системного ядра",
            Self::Snapshot => "Не удалось создать неизменяемый снимок системного ядра",
            Self::Capacity => "Исчерпан бюджет памяти системных ядер",
            Self::MissingEngine => "Ядро отсутствует в системном реестре",
        })
    }
}
impl std::error::Error for RegistryError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    engines: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    engine: InstalledEngine,
    version: String,
    sha256: String,
    #[serde(default)]
    native_profile_producer: Option<ProducerRecord>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerRecord {
    contract: String,
    version: u32,
    source_commit: String,
    source_sha256: String,
    patch_sha256: String,
    builder_sha256: String,
    toolchain_sha256: String,
    build_inputs_sha256: String,
    elf_sha256: String,
    #[serde(default)]
    dns_release: Option<DnsReleaseRecord>,
    #[serde(default)]
    dns_wire: Option<DnsReleaseRecord>,
    #[serde(default)]
    bootstrap_source: Option<DnsReleaseRecord>,
    #[serde(default)]
    bootstrap_dns_wire: Option<DnsReleaseRecord>,
    #[serde(default)]
    bootstrap_dns_release: Option<DnsReleaseRecord>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsReleaseRecord {
    contract: String,
    version: u32,
    contract_sha256: String,
    schema_sha256: String,
}
// Root должен отдельно принять actual factory/Conn ownership и exact patch.
// Старый UDP pin не является DNS consuming-close/join authority.
const DNS_REVIEWED_PATCH: Option<&str> =
    Some("6e6abdbdcedae5b7c4548e9225ae4f8531a4489b8788141a2b6b4cf64a083c7e");
const DNS_WIRE_REVIEWED_PATCH: Option<&str> =
    Some("6e6abdbdcedae5b7c4548e9225ae4f8531a4489b8788141a2b6b4cf64a083c7e");
// Семантический contract отдельно от artifact pin. Новый DNS patchset должен
// пройти root source review и обновить allowlist до trusted install.
const PRODUCER_PATCH: &str = "6e6abdbdcedae5b7c4548e9225ae4f8531a4489b8788141a2b6b4cf64a083c7e";
// Отдельный review для CODEC4 отсутствует; Direct3 pin его не заменяет.
const DNS_CODEC4_REVIEWED_PATCH: Option<&str> = None;
const BOOTSTRAP_BUILD_REVIEWED_PATCH: Option<&str> = None;
const BOOTSTRAP_SOURCE_REVIEWED_PATCH: Option<&str> = None;
const BOOTSTRAP_DNS_WIRE_REVIEWED_PATCH: Option<&str> = None;
const BOOTSTRAP_DNS_RELEASE_REVIEWED_PATCH: Option<&str> = None;
const UDP_ADDITIONAL_REVIEWED_PATCH: Option<&str> = None;
const BOOTSTRAP_REVIEWED_PATCHES: [Option<&str>; 3] = [
    BOOTSTRAP_SOURCE_REVIEWED_PATCH,
    BOOTSTRAP_DNS_WIRE_REVIEWED_PATCH,
    BOOTSTRAP_DNS_RELEASE_REVIEWED_PATCH,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootstrapScope {
    Source,
    Wire,
    Release,
}
impl BootstrapScope {
    fn index(self) -> usize {
        match self {
            Self::Source => 0,
            Self::Wire => 1,
            Self::Release => 2,
        }
    }
    pub(crate) fn contract(self) -> &'static str {
        match self {
            Self::Source => "captured-netgo-bootstrap-parent-member-v1",
            Self::Wire => "bootstrap-direct-dns-bound-request-response-v1",
            Self::Release => "bootstrap-direct-dns-consuming-close-join-v1",
        }
    }
}
#[derive(Clone)]
struct BootstrapProvenance {
    scope: BootstrapScope,
    schema: [u8; 32],
    version: u32,
    contract: [u8; 32],
    patch: [u8; 32],
    reviewed: Option<[u8; 32]>,
}
impl BootstrapProvenance {
    fn decode(
        r: &DnsReleaseRecord,
        scope: BootstrapScope,
        patch: &str,
        review: Option<&str>,
    ) -> Result<Self, RegistryError> {
        use sha2::Digest;
        let contract: [u8; 32] =
            sha2::Sha256::digest(format!("{}\0", scope.contract()).as_bytes()).into();
        let schema = DnsSchema::Codec4.digest();
        let canonical = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if r.contract != scope.contract()
            || r.version != 1
            || Sha256::from_str(&r.contract_sha256).map(|v| v.0) != Ok(contract)
            || !canonical(&r.contract_sha256)
            || !canonical(&r.schema_sha256)
            || Sha256::from_str(&r.schema_sha256).map(|v| v.0) != Ok(schema)
        {
            return Err(RegistryError::Version);
        }
        let patch = Sha256::from_str(patch)
            .map_err(|_| RegistryError::Manifest)?
            .0;
        let reviewed = review
            .and_then(|s| Sha256::from_str(s).ok())
            .map(|v| v.0)
            .filter(|p| *p == patch);
        Ok(Self {
            scope,
            schema,
            version: 1,
            contract,
            patch,
            reviewed,
        })
    }
}
#[derive(Clone)]
pub(crate) struct BootstrapCapability {
    image: [u8; 32],
    proof: BootstrapProvenance,
}
impl BootstrapCapability {
    pub(crate) fn check(
        &self,
        image: [u8; 32],
        scope: BootstrapScope,
    ) -> Result<(), RegistryError> {
        use sha2::Digest;
        let contract: [u8; 32] =
            sha2::Sha256::digest(format!("{}\0", scope.contract()).as_bytes()).into();
        if self.image != image
            || self.proof.scope != scope
            || self.proof.version != 1
            || self.proof.contract != contract
            || self.proof.schema != DnsSchema::Codec4.digest()
            || DnsSchema::current()? != DnsSchema::Codec4
            || self.proof.reviewed != Some(self.proof.patch)
        {
            return Err(RegistryError::Version);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsSchema {
    Codec3,
    Codec4,
}
impl DnsSchema {
    fn digest(self) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(match self {
            Self::Codec3 => b"YONIK-DNS-V2-CODEC-3\0",
            Self::Codec4 => b"YONIK-DNS-V2-CODEC-4\0",
        })
        .into()
    }
    pub(crate) fn current() -> Result<Self, RegistryError> {
        use sha2::Digest;
        let hash: [u8; 32] = sha2::Sha256::digest(crate::profile_channel::dns_v2::SCHEMA).into();
        [Self::Codec3, Self::Codec4]
            .into_iter()
            .find(|s| s.digest() == hash)
            .ok_or(RegistryError::Version)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DnsContract {
    Release,
    Wire,
}
impl DnsContract {
    fn name(self) -> &'static str {
        match self {
            Self::Release => "direct-dns-consuming-close-join-v1",
            Self::Wire => "direct-dns-bound-request-response-v1",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DnsScope {
    DirectUserDns,
}
#[derive(Clone)]
struct DnsProvenance {
    schema: DnsSchema,
    contract: DnsContract,
    scope: DnsScope,
    source_patch: [u8; 32],
    reviewed_patch: Option<[u8; 32]>,
}
impl DnsProvenance {
    fn decode(
        record: &DnsReleaseRecord,
        contract: DnsContract,
        patch: &str,
        review3: Option<&str>,
        review4: Option<&str>,
    ) -> Result<Self, RegistryError> {
        use sha2::Digest;
        let contract_hash = format!(
            "{:x}",
            sha2::Sha256::digest(format!("{}\0", contract.name()).as_bytes())
        );
        if record.contract != contract.name()
            || record.version != 1
            || record.contract_sha256 != contract_hash
        {
            return Err(RegistryError::Version);
        }
        if record.schema_sha256.len() != 64
            || !record
                .schema_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(RegistryError::Version);
        }
        let schema = [DnsSchema::Codec3, DnsSchema::Codec4]
            .into_iter()
            .find(|s| Sha256::from_str(&record.schema_sha256).is_ok_and(|v| v.0 == s.digest()))
            .ok_or(RegistryError::Version)?;
        let source_patch = Sha256::from_str(patch)
            .map_err(|_| RegistryError::Manifest)?
            .0;
        let review = match schema {
            DnsSchema::Codec3 => review3,
            DnsSchema::Codec4 => review4,
        };
        let reviewed_patch = review.filter(|p| *p == patch).map(|_| source_patch);
        Ok(Self {
            schema,
            contract,
            scope: DnsScope::DirectUserDns,
            source_patch,
            reviewed_patch,
        })
    }
    fn check(&self, schema: DnsSchema, contract: DnsContract) -> Result<(), RegistryError> {
        if self.schema != schema
            || self.contract != contract
            || self.scope != DnsScope::DirectUserDns
            || self.reviewed_patch != Some(self.source_patch)
        {
            return Err(RegistryError::Version);
        }
        Ok(())
    }
}
/// Opaque retained contract/scope/schema; constructor только из checked record.
#[derive(Clone)]
pub(crate) struct DnsCapability {
    image: [u8; 32],
    proof: DnsProvenance,
}
impl DnsCapability {
    pub(crate) fn check_release(&self) -> Result<(), RegistryError> {
        self.proof
            .check(DnsSchema::current()?, DnsContract::Release)
    }
    pub(crate) fn check_wire(&self) -> Result<(), RegistryError> {
        self.proof.check(DnsSchema::current()?, DnsContract::Wire)
    }
    fn bound(
        &self,
        image: [u8; 32],
        schema: DnsSchema,
        contract: DnsContract,
    ) -> Result<(), RegistryError> {
        if self.image != image {
            return Err(RegistryError::HashMismatch);
        }
        self.proof.check(schema, contract)
    }
}
#[derive(Clone)]
pub(crate) struct ImageContract {
    bootstrap: [Option<BootstrapProvenance>; 3],
    image: [u8; 32],
    udp_reviewed: bool,
    dns_release: Option<DnsProvenance>,
    dns_wire: Option<DnsProvenance>,
}
impl ImageContract {
    pub(crate) fn bootstrap_channel(
        &self,
        image: [u8; 32],
        scope: BootstrapScope,
    ) -> Result<Option<BootstrapCapability>, RegistryError> {
        if self.image != image {
            return Err(RegistryError::HashMismatch);
        }
        let Some(proof) = self.bootstrap[scope.index()].as_ref() else {
            return Ok(None);
        };
        if proof.reviewed.is_none() {
            return Ok(None);
        }
        let capability = BootstrapCapability {
            image: self.image,
            proof: proof.clone(),
        };
        capability.check(image, scope)?;
        Ok(Some(capability))
    }
    #[cfg(test)]
    pub(crate) fn check_dns_wire(&self, image: [u8; 32]) -> Result<(), RegistryError> {
        self.dns_capability(image, DnsSchema::Codec3, DnsContract::Wire)
            .map(|_| ())
    }
    #[cfg(test)]
    pub(crate) fn check_dns(&self, image: [u8; 32]) -> Result<(), RegistryError> {
        self.dns_capability(image, DnsSchema::Codec3, DnsContract::Release)
            .map(|_| ())
    }
    pub(crate) fn dns_wire_channel(&self, image: [u8; 32]) -> Result<DnsCapability, RegistryError> {
        self.dns_capability(image, DnsSchema::current()?, DnsContract::Wire)
    }
    pub(crate) fn dns_release_channel(
        &self,
        image: [u8; 32],
    ) -> Result<DnsCapability, RegistryError> {
        self.dns_capability(image, DnsSchema::current()?, DnsContract::Release)
    }
    fn dns_capability(
        &self,
        image: [u8; 32],
        schema: DnsSchema,
        contract: DnsContract,
    ) -> Result<DnsCapability, RegistryError> {
        let proof = match contract {
            DnsContract::Release => &self.dns_release,
            DnsContract::Wire => &self.dns_wire,
        }
        .as_ref()
        .ok_or(RegistryError::Version)?
        .clone();
        let capability = DnsCapability {
            image: self.image,
            proof,
        };
        capability.bound(image, schema, contract)?;
        Ok(capability)
    }
    pub(crate) fn check(&self, image: [u8; 32]) -> Result<(), RegistryError> {
        if self.image != image {
            Err(RegistryError::HashMismatch)
        } else if !self.udp_reviewed {
            Err(RegistryError::Version)
        } else {
            Ok(())
        }
    }
}
impl ProducerRecord {
    fn validate(&self, image: Sha256) -> Result<ImageContract, RegistryError> {
        self.validate_dns_pin(image, DNS_REVIEWED_PATCH)
    }
    fn validate_dns_pin(
        &self,
        image: Sha256,
        reviewed_dns: Option<&str>,
    ) -> Result<ImageContract, RegistryError> {
        self.validate_dns_pins(image, reviewed_dns, DNS_WIRE_REVIEWED_PATCH)
    }
    fn validate_dns_pins(
        &self,
        image: Sha256,
        reviewed_dns: Option<&str>,
        reviewed_wire: Option<&str>,
    ) -> Result<ImageContract, RegistryError> {
        if self.contract != "yonik-xray-profile-udp-v2"
            || self.version != 1
            || self.source_commit != "a4a3dff5b20c2faae567b742c172c7b95e75c083"
            || self.patch_sha256 != PRODUCER_PATCH
                && Some(self.patch_sha256.as_str()) != BOOTSTRAP_BUILD_REVIEWED_PATCH
        {
            return Err(RegistryError::Version);
        }
        for value in [
            &self.source_sha256,
            &self.builder_sha256,
            &self.toolchain_sha256,
            &self.build_inputs_sha256,
            &self.elf_sha256,
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || value.bytes().all(|b| b == b'0')
            {
                return Err(RegistryError::Manifest);
            }
        }
        let actual = Sha256::from_str(&self.elf_sha256).map_err(|_| RegistryError::Manifest)?;
        if actual.0 != image.0 {
            return Err(RegistryError::HashMismatch);
        }
        let dns_release = self
            .dns_release
            .as_ref()
            .map(|r| {
                DnsProvenance::decode(
                    r,
                    DnsContract::Release,
                    &self.patch_sha256,
                    reviewed_dns,
                    DNS_CODEC4_REVIEWED_PATCH,
                )
            })
            .transpose()?;
        let dns_wire = self
            .dns_wire
            .as_ref()
            .map(|r| {
                DnsProvenance::decode(
                    r,
                    DnsContract::Wire,
                    &self.patch_sha256,
                    reviewed_wire,
                    DNS_CODEC4_REVIEWED_PATCH,
                )
            })
            .transpose()?;
        if let (Some(a), Some(b)) = (&dns_release, &dns_wire) {
            if a.schema != b.schema {
                return Err(RegistryError::Version);
            }
        }
        Ok(ImageContract {
            bootstrap: [
                (&self.bootstrap_source, BootstrapScope::Source),
                (&self.bootstrap_dns_wire, BootstrapScope::Wire),
                (&self.bootstrap_dns_release, BootstrapScope::Release),
            ]
            .map(|(r, scope)| {
                r.as_ref()
                    .map(|r| {
                        BootstrapProvenance::decode(
                            r,
                            scope,
                            &self.patch_sha256,
                            BOOTSTRAP_REVIEWED_PATCHES[scope.index()],
                        )
                    })
                    .transpose()
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| RegistryError::Manifest)?,
            image: image.0,
            udp_reviewed: self.patch_sha256 == PRODUCER_PATCH
                || Some(self.patch_sha256.as_str()) == UDP_ADDITIONAL_REVIEWED_PATCH,
            dns_release,
            dns_wire,
        })
    }
}

#[cfg(test)]
fn fake_dns_record(image: [u8; 32]) -> ProducerRecord {
    use sha2::Digest;
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in image {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    let value = serde_json::json!({"contract":"yonik-xray-profile-udp-v2","version":1,
        "source_commit":"a4a3dff5b20c2faae567b742c172c7b95e75c083",
        "source_sha256":"16".repeat(32),"patch_sha256":PRODUCER_PATCH,
        "builder_sha256":"12".repeat(32),"toolchain_sha256":"13".repeat(32),
        "build_inputs_sha256":"14".repeat(32),"elf_sha256":encoded,
        "dns_release":{"contract":"direct-dns-consuming-close-join-v1","version":1,
            "contract_sha256":format!("{:x}",sha2::Sha256::digest(b"direct-dns-consuming-close-join-v1\0")),
            "schema_sha256":format!("{:x}",sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-3\0"))}});
    serde_json::from_value(value).unwrap()
}
/// Отдельный synthetic CODEC4 source review. Не pin существующего Direct3/UDP.
#[cfg(test)]
pub(crate) fn fake_bootstrap_image(image: [u8; 32], scopes: &[BootstrapScope]) -> ImageContract {
    use sha2::Digest;
    let patch = "44".repeat(32);
    let bootstrap = [
        BootstrapScope::Source,
        BootstrapScope::Wire,
        BootstrapScope::Release,
    ]
    .map(|scope| {
        scopes.contains(&scope).then(|| {
            let r = DnsReleaseRecord {
                contract: scope.contract().into(),
                version: 1,
                contract_sha256: format!(
                    "{:x}",
                    sha2::Sha256::digest(format!("{}\0", scope.contract()).as_bytes())
                ),
                schema_sha256: format!("{:x}", sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-4\0")),
            };
            BootstrapProvenance::decode(&r, scope, &patch, Some(&patch)).unwrap()
        })
    });
    ImageContract {
        image,
        bootstrap,
        udp_reviewed: false,
        dns_release: None,
        dns_wire: None,
    }
}
/// Явный injected review отдельного synthetic source4 record; это не Direct3 pin.
#[cfg(test)]
pub(crate) fn fake_dns4_image(image: [u8; 32]) -> ImageContract {
    use sha2::Digest;
    let patch = "44".repeat(32);
    let record = |contract: DnsContract| {
        let value = serde_json::json!({"contract":contract.name(),"version":1,
            "contract_sha256":format!("{:x}",sha2::Sha256::digest(format!("{}\0",contract.name()).as_bytes())),
            "schema_sha256":format!("{:x}",sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-4\0"))});
        let record: DnsReleaseRecord = serde_json::from_value(value).unwrap();
        DnsProvenance::decode(&record, contract, &patch, None, Some(&patch)).unwrap()
    };
    ImageContract {
        bootstrap: [None, None, None],
        image,
        udp_reviewed: false,
        dns_release: Some(record(DnsContract::Release)),
        dns_wire: Some(record(DnsContract::Wire)),
    }
}
#[cfg(test)]
pub(crate) fn fake_dns_image(image: [u8; 32]) -> ImageContract {
    let record = fake_dns_record(image);
    assert!(
        record
            .validate_dns_pins(Sha256(image), None, None)
            .unwrap()
            .check_dns(image)
            .is_err()
    );
    record
        .validate_dns_pin(Sha256(image), Some(PRODUCER_PATCH))
        .unwrap()
}

#[cfg(test)]
pub(crate) fn fake_dns_wire_image(image: [u8; 32]) -> ImageContract {
    use sha2::Digest;
    let mut record = fake_dns_record(image);
    record.dns_wire = Some(DnsReleaseRecord {
        contract: "direct-dns-bound-request-response-v1".into(),
        version: 1,
        contract_sha256: format!(
            "{:x}",
            sha2::Sha256::digest(b"direct-dns-bound-request-response-v1\0")
        ),
        schema_sha256: format!("{:x}", sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-3\0")),
    });
    assert!(
        record
            .validate_dns_pins(Sha256(image), None, None)
            .unwrap()
            .check_dns_wire(image)
            .is_err()
    );
    record
        .validate_dns_pins(Sha256(image), Some(PRODUCER_PATCH), Some(PRODUCER_PATCH))
        .unwrap()
}

#[derive(Clone, Copy, Deserialize)]
enum InstalledEngine {
    #[serde(rename = "xray")]
    Xray,
    #[serde(rename = "sing-box")]
    SingBox,
}
impl InstalledEngine {
    fn engine(self) -> Engine {
        match self {
            Self::Xray => Engine::Xray,
            Self::SingBox => Engine::SingBox,
        }
    }
    fn filename(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::SingBox => "sing-box",
        }
    }
}

/// Манифест проверен целиком; бинарник проверяется при создании snapshot.
/// Один и тот же snapshot передаётся version/config-check/start без чтения пути.
/// Вызывающий код переиспользует один registry: живые snapshots делят sealed inode.
/// Разные registry могут хранить разные images, но используют общий процессный бюджет.
pub struct TrustedRegistry {
    directory: File,
    entries: Vec<InstalledEntry>,
}

struct InstalledEntry {
    engine: InstalledEngine,
    hash: Sha256,
    producer: Option<ImageContract>,
    cache: Mutex<Option<CachedImage>>,
}

struct CachedImage {
    source: SourceIdentity,
    image: Weak<SharedImage>,
}

#[derive(PartialEq, Eq)]
struct SourceIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
impl From<Metadata> for SourceIdentity {
    fn from(metadata: Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

impl std::fmt::Debug for TrustedRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedRegistry(<системный реестр>)")
    }
}
impl TrustedRegistry {
    pub(crate) fn producer_for_delivery(
        &self,
        delivery: &crate::worker::role_handoff::VerifiedExecDelivery,
        launch: crate::profile_channel::LaunchRecord,
    ) -> Result<ImageContract, RegistryError> {
        let actual = delivery
            .producer_image(launch)
            .map_err(|_| RegistryError::HashMismatch)?;
        let entry = self
            .entries
            .iter()
            .find(|e| e.engine.engine() == Engine::Xray)
            .ok_or(RegistryError::MissingEngine)?;
        if entry.hash.0 != actual {
            return Err(RegistryError::HashMismatch);
        }
        let proof = entry.producer.clone().ok_or(RegistryError::MissingEngine)?;
        proof.check(actual)?;
        Ok(proof)
    }
    /// Единственный production-корень: /usr/lib/yonik/engines, владелец root.
    pub fn system() -> Result<Self, RegistryError> {
        let mut directory = File::from(
            open("/", DIR_FLAGS, Mode::empty()).map_err(|_| RegistryError::Unavailable)?,
        );
        directory_metadata(&directory, 0)?;
        for component in ["usr", "lib", "yonik", "engines"] {
            directory = child(&directory, component, DIR_FLAGS)?;
            directory_metadata(&directory, 0)?;
        }
        Self::load(directory, 0)
    }

    /// Проверяет исходник; живой immutable snapshot переиспользуется при том же identity.
    pub fn snapshot(&self, engine: Engine) -> Result<BinarySnapshot, RegistryError> {
        self.snapshot_for_uid(engine, 0)
    }

    /// Native snapshot требует protected producer contract до чтения image.
    pub fn full_profile_snapshot(&self) -> Result<BinarySnapshot, RegistryError> {
        self.entries
            .iter()
            .find(|entry| entry.engine.engine() == Engine::Xray)
            .and_then(|entry| entry.producer.as_ref())
            .ok_or(RegistryError::MissingEngine)?;
        self.snapshot(Engine::Xray)
    }

    fn snapshot_for_uid(&self, engine: Engine, uid: u32) -> Result<BinarySnapshot, RegistryError> {
        self.snapshot_with_budget(engine, uid, executable_budget())
    }

    fn snapshot_with_budget(
        &self,
        engine: Engine,
        uid: u32,
        budget: &ByteBudget,
    ) -> Result<BinarySnapshot, RegistryError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.engine.engine() == engine)
            .ok_or(RegistryError::MissingEngine)?;
        // Один miss на запись: параллельные запросы разделяют уже sealed inode.
        let mut cache = entry.cache.lock().map_err(|_| RegistryError::Unavailable)?;
        directory_metadata(&self.directory, uid)?;
        let source = child(&self.directory, entry.engine.filename(), FILE_FLAGS)?;
        let metadata = source.metadata().map_err(|_| RegistryError::Unavailable)?;
        validate_regular_metadata(&metadata, uid, BinarySnapshot::MAX_SIZE, true)?;
        let identity = SourceIdentity::from(metadata);
        if let Some(cached) = cache.as_ref() {
            if cached.source == identity {
                if let Some(image) = cached.image.upgrade() {
                    return BinarySnapshot::from_image(image, entry.hash, engine)
                        .map(|snapshot| snapshot.with_producer(entry.producer.clone()))
                        .map_err(snapshot_error);
                }
            }
        }
        let lease = budget
            .reserve(identity.len as usize)
            .map_err(|_| RegistryError::Capacity)?;
        let snapshot = BinarySnapshot::load_budgeted(source, entry.hash, engine, lease)
            .map_err(snapshot_error)?;
        *cache = Some(CachedImage {
            source: identity,
            image: snapshot.weak_image(),
        });
        Ok(snapshot.with_producer(entry.producer.clone()))
    }

    fn load(directory: File, uid: u32) -> Result<Self, RegistryError> {
        directory_metadata(&directory, uid)?;
        let manifest_file = child(&directory, "registry.json", FILE_FLAGS)?;
        regular_metadata(&manifest_file, uid, MAX_MANIFEST, false)?;
        let mut bytes = Vec::new();
        manifest_file
            .take(MAX_MANIFEST + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RegistryError::Unavailable)?;
        if bytes.len() as u64 > MAX_MANIFEST {
            return Err(RegistryError::Manifest);
        }
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| RegistryError::Manifest)?;
        if ![1, 2].contains(&manifest.schema)
            || manifest.engines.is_empty()
            || manifest.engines.len() > 2
        {
            return Err(RegistryError::Manifest);
        }
        let mut entries: Vec<InstalledEntry> = Vec::with_capacity(manifest.engines.len());
        for entry in manifest.engines {
            let engine = entry.engine.engine();
            if entries.iter().any(|entry| entry.engine.engine() == engine) {
                return Err(RegistryError::Manifest);
            }
            if entry.version != engine.version() {
                return Err(RegistryError::Version);
            }
            let hash = Sha256::from_str(&entry.sha256).map_err(|_| RegistryError::Manifest)?;
            let producer = if let Some(record) = entry.native_profile_producer {
                if manifest.schema != 2 || engine != Engine::Xray {
                    return Err(RegistryError::Manifest);
                }
                Some(record.validate(hash)?)
            } else {
                None
            };
            entries.push(InstalledEntry {
                engine: entry.engine,
                hash,
                producer,
                cache: Mutex::new(None),
            });
        }
        Ok(Self { directory, entries })
    }

    /// Тесты передают уже открытый собственный корень, не ослабляя production walk.
    #[cfg(test)]
    fn for_test(directory: File, expected_uid: u32) -> Result<Self, RegistryError> {
        Self::load(directory, expected_uid)
    }
}

fn snapshot_error(error: HostError) -> RegistryError {
    match error {
        HostError::BinaryHash => RegistryError::HashMismatch,
        HostError::InvalidBinary => RegistryError::InvalidBinary,
        HostError::Snapshot => RegistryError::Snapshot,
        HostError::ResourceLimit => RegistryError::Capacity,
        _ => RegistryError::Unavailable,
    }
}

fn child(directory: &File, name: &str, flags: OFlags) -> Result<File, RegistryError> {
    openat(directory, name, flags, Mode::empty())
        .map(File::from)
        .map_err(|_| RegistryError::Unavailable)
}

fn directory_metadata(file: &File, uid: u32) -> Result<(), RegistryError> {
    let metadata = file.metadata().map_err(|_| RegistryError::Unavailable)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7022 != 0 {
        return Err(RegistryError::UnsafeEntry);
    }
    Ok(())
}

fn regular_metadata(
    file: &File,
    uid: u32,
    max_size: u64,
    executable: bool,
) -> Result<(), RegistryError> {
    let metadata = file.metadata().map_err(|_| RegistryError::Unavailable)?;
    validate_regular_metadata(&metadata, uid, max_size, executable)
}

fn validate_regular_metadata(
    metadata: &Metadata,
    uid: u32,
    max_size: u64,
    executable: bool,
) -> Result<(), RegistryError> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || metadata.len() > max_size
        || (executable && metadata.mode() & 0o111 == 0)
    {
        return Err(RegistryError::UnsafeEntry);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn dns_schema_provenance_scope_image_optional_and_review_are_independent() {
        use super::*;
        let image = [17; 32];
        let three = fake_dns_wire_image(image);
        assert!(three.check(image).is_ok());
        assert!(three.check_dns(image).is_ok());
        assert!(three.check_dns_wire(image).is_ok());
        assert!(three.dns_wire_channel(image).is_err());
        assert!(three.dns_release_channel(image).is_err());
        let four = fake_dns4_image(image);
        assert!(four.check(image).is_err());
        assert!(four.check_dns(image).is_err());
        let wire = four.dns_wire_channel(image).unwrap();
        assert!(wire.check_wire().is_ok());
        assert!(wire.check_release().is_err());
        assert!(
            four.dns_release_channel(image)
                .unwrap()
                .check_release()
                .is_ok()
        );
        assert!(four.dns_wire_channel([18; 32]).is_err());
        assert!(four.dns_release_channel([18; 32]).is_err());
        let mut optional = four.clone();
        optional.dns_release = None;
        assert!(optional.dns_wire_channel(image).is_ok());
        assert!(optional.dns_release_channel(image).is_err());
        optional.dns_release = four.dns_release.clone();
        optional.dns_wire = None;
        assert!(optional.dns_release_channel(image).is_ok());
        assert!(optional.dns_wire_channel(image).is_err());
        optional.dns_wire = optional.dns_release.clone();
        assert!(optional.dns_wire_channel(image).is_err());
        optional.dns_release.as_mut().unwrap().reviewed_patch = None;
        assert!(optional.dns_release_channel(image).is_err());
    }
    #[test]
    fn dns_schema_provenance_record4_without_review_mixed_unknown_and_hash_fail_closed() {
        use super::*;
        use sha2::Digest;
        let image = Sha256([17; 32]);
        let mut record = fake_dns_record(image.0);
        record.dns_release.as_mut().unwrap().schema_sha256 =
            format!("{:x}", sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-4\0"));
        let parsed = record.validate(image).unwrap();
        assert!(parsed.check(image.0).is_ok());
        assert!(parsed.dns_release_channel(image.0).is_err());
        let mut wire = record.dns_release.clone().unwrap();
        wire.contract = DnsContract::Wire.name().into();
        wire.contract_sha256 = format!(
            "{:x}",
            sha2::Sha256::digest(b"direct-dns-bound-request-response-v1\0")
        );
        wire.schema_sha256 = format!("{:x}", sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-3\0"));
        record.dns_wire = Some(wire);
        assert!(record.validate(image).is_err());
        record.dns_wire = None;
        for schema in [
            "00".repeat(32),
            format!("{:x}", sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-2\0")),
        ] {
            let mut bad = record.clone();
            bad.dns_release.as_mut().unwrap().schema_sha256 = schema;
            assert!(bad.validate(image).is_err());
        }
        for field in [0, 1, 2] {
            let mut bad = record.clone();
            let r = bad.dns_release.as_mut().unwrap();
            match field {
                0 => r.contract = "bootstrap-choice".into(),
                1 => r.version = 2,
                _ => r.contract_sha256 = "00".repeat(32),
            }
            assert!(bad.validate(image).is_err());
        }
    }
    #[test]
    fn reviewed_direct_dns_records_require_both_exact_contracts_and_patch() {
        use sha2::Digest;
        let image = super::Sha256([17; 32]);
        let mut record = super::fake_dns_record(image.0);
        let mut wire = record.dns_release.clone().unwrap();
        wire.contract = "direct-dns-bound-request-response-v1".into();
        wire.contract_sha256 = format!(
            "{:x}",
            sha2::Sha256::digest(b"direct-dns-bound-request-response-v1\0")
        );
        record.dns_wire = Some(wire);
        let checked = record.validate(image).unwrap();
        assert!(checked.check_dns(image.0).is_ok());
        assert!(checked.check_dns_wire(image.0).is_ok());
        let unreviewed = record.validate_dns_pins(image, None, None).unwrap();
        assert!(unreviewed.check_dns(image.0).is_err());
        assert!(unreviewed.check_dns_wire(image.0).is_err());
        let mut old = record.clone();
        old.patch_sha256 =
            "205b5337b8c38c608e4a341885dfe02174b33761e4dfda7724432359e84910c6".into();
        assert!(old.validate(image).is_err());
        record.dns_wire.as_mut().unwrap().schema_sha256 =
            format!("{:x}", sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-2\0"));
        assert!(record.validate(image).is_err());
    }
    #[test]
    fn dns_wire_contract_does_not_inherit_consuming_close_authority() {
        let image = [17; 32];
        assert!(super::fake_dns_image(image).check_dns_wire(image).is_err());
        let wire = super::fake_dns_wire_image(image);
        assert!(wire.check_dns_wire(image).is_ok());
        assert!(wire.check_dns_wire([18; 32]).is_err());
        let mut record = super::fake_dns_record(image);
        record.dns_wire = record.dns_release.clone();
        assert!(
            record
                .validate_dns_pins(
                    crate::host::Sha256(image),
                    Some(super::PRODUCER_PATCH),
                    Some(super::PRODUCER_PATCH)
                )
                .is_err()
        );
    }
    #[test]
    fn dns_release_record_schema_contract_image_and_separate_review_pin() {
        let image = crate::host::Sha256([17; 32]);
        let mut record = super::fake_dns_record(image.0);
        assert!(record.validate(image).unwrap().check_dns(image.0).is_ok());
        assert!(
            record
                .validate_dns_pins(image, None, None)
                .unwrap()
                .check_dns(image.0)
                .is_err()
        );
        assert!(
            record
                .validate_dns_pin(image, Some(super::PRODUCER_PATCH))
                .unwrap()
                .check_dns(image.0)
                .is_ok()
        );
        for field in [0, 1, 2, 3] {
            let mut bad = record.clone();
            let dns = bad.dns_release.as_mut().unwrap();
            match field {
                0 => dns.contract = "unknown".into(),
                1 => dns.version = 2,
                2 => dns.contract_sha256 = "11".repeat(32),
                _ => dns.schema_sha256 = "11".repeat(32),
            }
            assert!(
                bad.validate_dns_pin(image, Some(super::PRODUCER_PATCH))
                    .is_err()
            );
        }
        record.dns_release = None;
        assert!(
            record
                .validate_dns_pin(image, Some(super::PRODUCER_PATCH))
                .unwrap()
                .check_dns(image.0)
                .is_err()
        );
    }
    #[test]
    fn producer_pin_matches_reviewed_adapter_metadata() {
        let metadata: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../adapters/xray/v26.10.31/native-full-profile.json"
        ))
        .expect("закреплённый adapter metadata");
        assert_eq!(
            metadata["patch_sha256"].as_str(),
            Some(super::PRODUCER_PATCH)
        );
    }
    #[test]
    fn schema2_recognizes_optional_producer_without_legacy_authority() {
        let parsed = serde_json::from_value::<super::Manifest>(
            serde_json::json!({"schema":2,"engines":[{"engine":"xray","version":"26.10.31","sha256":"11".repeat(32),"native_profile_producer":null}]}),
        );
        assert!(parsed.is_ok());
    }
    #[test]
    fn bootstrap_record_slots_parse_without_promoting_direct3_or_udp() {
        use sha2::Digest;
        let mut value = serde_json::json!({"contract":"yonik-xray-profile-udp-v2","version":1,"source_commit":"a4a3dff5b20c2faae567b742c172c7b95e75c083","source_sha256":"16".repeat(32),"patch_sha256":super::PRODUCER_PATCH,"builder_sha256":"12".repeat(32),"toolchain_sha256":"13".repeat(32),"build_inputs_sha256":"14".repeat(32),"elf_sha256":"11".repeat(32)});
        for (slot, name) in [
            (
                "bootstrap_source",
                "captured-netgo-bootstrap-parent-member-v1",
            ),
            (
                "bootstrap_dns_wire",
                "bootstrap-direct-dns-bound-request-response-v1",
            ),
            (
                "bootstrap_dns_release",
                "bootstrap-direct-dns-consuming-close-join-v1",
            ),
        ] {
            value[slot] = serde_json::json!({"contract":name,"version":1,"contract_sha256":format!("{:x}",sha2::Sha256::digest(format!("{name}\0").as_bytes())),"schema_sha256":format!("{:x}",sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-4\0"))});
        }
        let record = serde_json::from_value::<super::ProducerRecord>(value);
        assert!(
            record.is_ok(),
            "три независимых optional slots должны разбираться"
        );
        let image = record
            .unwrap()
            .validate(crate::host::Sha256([17; 32]))
            .unwrap();
        assert!(image.check([17; 32]).is_ok());
        for scope in [
            super::BootstrapScope::Source,
            super::BootstrapScope::Wire,
            super::BootstrapScope::Release,
        ] {
            assert!(image.bootstrap_channel([17; 32], scope).unwrap().is_none());
        }
    }
    #[test]
    fn bootstrap_record_contract_schema_scope_and_review_do_not_alias() {
        use super::{BootstrapProvenance, BootstrapScope as S, DnsReleaseRecord};
        use sha2::Digest;
        let patch = "44".repeat(32);
        for (scope, hash) in [
            (
                S::Source,
                "3e7860519a0f3bd9d012ed5d739514ad45a387ecbd289c99a55d7761cf60004e",
            ),
            (
                S::Wire,
                "de8522b1473bd9a0c1cf6eb2ba6c0718baf4fd19a25ca8a02c4a5edde5c7d3b2",
            ),
            (
                S::Release,
                "ab218d837b1125c1f79cab94df388d8467e06e55a507338a348881da8b3382b4",
            ),
        ] {
            assert_eq!(
                format!(
                    "{:x}",
                    sha2::Sha256::digest(format!("{}\0", scope.contract()).as_bytes())
                ),
                hash
            );
            let r = DnsReleaseRecord {
                contract: scope.contract().into(),
                version: 1,
                contract_sha256: hash.into(),
                schema_sha256: format!("{:x}", sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-4\0")),
            };
            assert!(
                BootstrapProvenance::decode(&r, scope, &patch, None)
                    .unwrap()
                    .reviewed
                    .is_none()
            );
            for fault in 0..5 {
                let mut r = r.clone();
                match fault {
                    0 => r.contract = "unknown".into(),
                    1 => r.version = 2,
                    2 => r.contract_sha256 = "11".repeat(32),
                    3 => {
                        r.schema_sha256 =
                            format!("{:x}", sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-3\0"))
                    }
                    _ => r.schema_sha256 = r.schema_sha256.to_ascii_uppercase(),
                };
                assert!(BootstrapProvenance::decode(&r, scope, &patch, Some(&patch)).is_err());
            }
            let image = super::fake_bootstrap_image([17; 32], &[scope]);
            assert!(image.check([17; 32]).is_err());
            for wanted in [S::Source, S::Wire, S::Release] {
                assert_eq!(
                    image.bootstrap_channel([17; 32], wanted).unwrap().is_some(),
                    scope == wanted
                );
            }
            assert!(image.bootstrap_channel([18; 32], scope).is_err());
        }
    }
    #[test]
    fn producer_record_exact_image_launch_and_negative_controls() {
        let value = serde_json::json!({"contract":"yonik-xray-profile-udp-v2","version":1,"source_commit":"a4a3dff5b20c2faae567b742c172c7b95e75c083","patch_sha256":super::PRODUCER_PATCH,"builder_sha256":"12".repeat(32),"toolchain_sha256":"13".repeat(32),"build_inputs_sha256":"14".repeat(32),"elf_sha256":"11".repeat(32)});
        let mut value = value;
        value["source_sha256"] = serde_json::json!("16".repeat(32));
        let record: super::ProducerRecord = serde_json::from_value(value.clone()).unwrap();
        let proof = record.validate(crate::host::Sha256([17; 32])).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/xray-profile-channel-v3/system-proof-extension-v1.json"
        ))
        .unwrap();
        let hex = fixture["launch_hex"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|p| u8::from_str_radix(&hex[p..p + 2], 16).unwrap())
            .collect();
        let system = crate::profile_channel::LaunchRecord::decode(
            &bytes,
            crate::profile_channel::Mode::System,
        )
        .unwrap();
        for launch in [
            system,
            crate::profile_channel::LaunchRecord {
                mode: crate::profile_channel::Mode::Local,
                child_pid: 0,
                child_start: 0,
                ..system
            },
        ] {
            let mint = |image, config, manifest| {
                crate::helper::native_profile_channel::VerifiedUdpProducer::mint(
                    &proof, image, config, manifest, launch,
                )
            };
            let token = mint([17; 32], launch.binding.digest, launch.manifest).unwrap();
            assert_eq!(token.setup(launch).unwrap().2, 2);
            assert!(mint([18; 32], launch.binding.digest, launch.manifest).is_err());
            assert!(mint([17; 32], [18; 32], launch.manifest).is_err());
            assert!(mint([17; 32], launch.binding.digest, [18; 32]).is_err());
            let mut wrong = launch;
            wrong.nonce[0] ^= 1;
            assert!(token.setup(wrong).is_err());
        }
        for (field, replacement) in [
            ("contract", serde_json::json!("unknown")),
            ("version", serde_json::json!(2)),
            ("patch_sha256", serde_json::json!("22".repeat(32))),
            ("elf_sha256", serde_json::json!("22".repeat(32))),
            ("builder_sha256", serde_json::json!("00".repeat(32))),
        ] {
            let mut bad = value.clone();
            bad[field] = replacement;
            let record: super::ProducerRecord = serde_json::from_value(bad).unwrap();
            assert!(record.validate(crate::host::Sha256([17; 32])).is_err());
        }
        let duplicate =
            serde_json::to_string(&value)
                .unwrap()
                .replacen("{", "{\"contract\":\"other\",", 1);
        assert!(serde_json::from_str::<super::ProducerRecord>(&duplicate).is_err());
    }
    #[test]
    fn protected_record_legacy_modes_owner_and_nofollow_without_snapshot() {
        let fixture = Fixture::new();
        assert!(fixture.registry().unwrap().entries[0].producer.is_none());
        assert_eq!(
            fixture.registry().unwrap().full_profile_snapshot().err(),
            Some(RegistryError::MissingEngine)
        );
        fixture.manifest(&serde_json::json!({"schema":2,"engines":[entry("xray")]}));
        assert!(fixture.registry().unwrap().entries[0].producer.is_none());
        let mut installed = entry("xray");
        installed["native_profile_producer"] = serde_json::json!({"contract":"yonik-xray-profile-udp-v2","version":1,"source_commit":"a4a3dff5b20c2faae567b742c172c7b95e75c083","patch_sha256":super::PRODUCER_PATCH,"builder_sha256":"12".repeat(32),"toolchain_sha256":"13".repeat(32),"build_inputs_sha256":"14".repeat(32),"elf_sha256":installed["sha256"]});
        installed["native_profile_producer"]["source_sha256"] = serde_json::json!("16".repeat(32));
        fixture.manifest(&serde_json::json!({"schema":2,"engines":[installed.clone()]}));
        assert!(fixture.registry().unwrap().entries[0].producer.is_some());
        fixture.manifest(&serde_json::json!({"schema":1,"engines":[installed]}));
        assert_eq!(fixture.registry().err(), Some(RegistryError::Manifest));
        fixture.manifest(&serde_json::json!({"schema":2,"engines":[entry("xray")]}));
        assert_eq!(
            TrustedRegistry::for_test(fixture.directory(), fixture.uid().wrapping_add(1)).err(),
            Some(RegistryError::UnsafeEntry)
        );
        fixture.mode("registry.json", 0o666);
        assert_eq!(fixture.registry().err(), Some(RegistryError::UnsafeEntry));
        fs::remove_file(fixture.0.join("registry.json")).unwrap();
        symlink("xray", fixture.0.join("registry.json")).unwrap();
        assert!(fixture.registry().is_err());
    }
    use super::{
        BinarySnapshot, DIR_FLAGS, Engine, FILE_FLAGS, File, MAX_MANIFEST, Mode, Read,
        RegistryError, TrustedRegistry, child, directory_metadata, open, regular_metadata,
    };
    use sha2::{Digest, Sha256 as Hasher};
    use std::{
        fs::{self, Permissions},
        io::{Seek, SeekFrom, Write},
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const ELF: &[u8] = b"\x7fELFfixture: never execute";

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "yonik-registry-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
            let fixture = Self(path);
            fixture.binary("xray", ELF);
            fixture.binary("sing-box", ELF);
            fixture.manifest(&serde_json::json!({"schema":1,"engines":[entry("xray")]}));
            fixture
        }
        fn binary(&self, name: &str, bytes: &[u8]) {
            fs::write(self.0.join(name), bytes).unwrap();
            self.mode(name, 0o700);
        }
        fn mode(&self, name: &str, mode: u32) {
            fs::set_permissions(self.0.join(name), Permissions::from_mode(mode)).unwrap();
        }
        fn manifest(&self, value: &serde_json::Value) {
            fs::write(
                self.0.join("registry.json"),
                serde_json::to_vec(value).unwrap(),
            )
            .unwrap();
            self.mode("registry.json", 0o600);
        }
        fn directory(&self) -> File {
            File::from(open(&self.0, DIR_FLAGS, Mode::empty()).unwrap())
        }
        fn uid(&self) -> u32 {
            self.directory().metadata().unwrap().uid()
        }
        fn registry(&self) -> Result<TrustedRegistry, RegistryError> {
            TrustedRegistry::for_test(self.directory(), self.uid())
        }
        fn snapshot(&self) -> Result<BinarySnapshot, RegistryError> {
            self.registry()?.snapshot_for_uid(Engine::Xray, self.uid())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("Удалить собственный fixture");
        }
    }
    fn entry(name: &str) -> serde_json::Value {
        let engine = if name == "xray" {
            Engine::Xray
        } else {
            Engine::SingBox
        };
        serde_json::json!({"engine":name,"version":engine.version(),"sha256":format!("{:x}",Hasher::digest(ELF))})
    }
    fn bytes(snapshot: &mut BinarySnapshot) -> Vec<u8> {
        snapshot.file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        snapshot.file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn subset_and_both_engines_create_sealed_snapshots_without_execution() {
        let fixture = Fixture::new();
        let registry = fixture.registry().unwrap();
        assert_eq!(
            registry
                .snapshot_for_uid(Engine::SingBox, fixture.uid())
                .err(),
            Some(RegistryError::MissingEngine)
        );
        let mut image = registry
            .snapshot_for_uid(Engine::Xray, fixture.uid())
            .unwrap();
        assert_eq!(bytes(&mut image), ELF);
        assert!(image.file.write_all(b"replace").is_err());
        fixture
            .manifest(&serde_json::json!({"schema":1,"engines":[entry("xray"),entry("sing-box")]}));
        let registry = fixture.registry().unwrap();
        for engine in [Engine::Xray, Engine::SingBox] {
            assert_eq!(
                bytes(&mut registry.snapshot_for_uid(engine, fixture.uid()).unwrap()),
                ELF
            );
        }
    }

    #[test]
    fn weak_cache_reuses_inode_and_releases_the_last_lease() {
        let fixture = Fixture::new();
        let registry = fixture.registry().unwrap();
        let budget = crate::helper::memory::ByteBudget::new(ELF.len());
        let first = registry
            .snapshot_with_budget(Engine::Xray, fixture.uid(), &budget)
            .unwrap();
        let second = registry
            .snapshot_with_budget(Engine::Xray, fixture.uid(), &budget)
            .unwrap();
        assert_eq!(
            first.file.metadata().unwrap().ino(),
            second.file.metadata().unwrap().ino()
        );
        assert_eq!(
            first.file.metadata().unwrap().dev(),
            second.file.metadata().unwrap().dev()
        );
        assert_eq!(budget.used(), ELF.len());
        let weak = first.weak_image();
        drop(first);
        assert_eq!(budget.used(), ELF.len());
        drop(second);
        assert_eq!(budget.used(), 0);
        assert!(weak.upgrade().is_none());
        let third = registry
            .snapshot_with_budget(Engine::Xray, fixture.uid(), &budget)
            .unwrap();
        assert_eq!(budget.used(), ELF.len());
        drop(third);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn concurrent_cache_misses_allocate_one_image() {
        let fixture = Fixture::new();
        let registry = fixture.registry().unwrap();
        let budget = crate::helper::memory::ByteBudget::new(ELF.len());
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            let mut tasks = Vec::new();
            for _ in 0..8 {
                tasks.push(scope.spawn(|| {
                    barrier.wait();
                    registry
                        .snapshot_with_budget(Engine::Xray, fixture.uid(), &budget)
                        .unwrap()
                }));
            }
            let snapshots: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
            let first = snapshots[0].file.metadata().unwrap();
            for snapshot in &snapshots {
                let metadata = snapshot.file.metadata().unwrap();
                assert_eq!((metadata.dev(), metadata.ino()), (first.dev(), first.ino()));
            }
            assert_eq!(budget.used(), ELF.len());
        });
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn budget_is_shared_between_registries_and_rejects_before_copy() {
        let fixture = Fixture::new();
        let first_registry = fixture.registry().unwrap();
        let second_registry = fixture.registry().unwrap();
        let budget = crate::helper::memory::ByteBudget::new(ELF.len());
        let first = first_registry
            .snapshot_with_budget(Engine::Xray, fixture.uid(), &budget)
            .unwrap();
        assert_eq!(
            second_registry
                .snapshot_with_budget(Engine::Xray, fixture.uid(), &budget)
                .err(),
            Some(RegistryError::Capacity)
        );
        drop(first);
        assert_eq!(budget.used(), 0);
        assert!(
            second_registry
                .snapshot_with_budget(Engine::Xray, fixture.uid(), &budget)
                .is_ok()
        );
        let small = crate::helper::memory::ByteBudget::new(ELF.len() - 1);
        assert_eq!(
            first_registry
                .snapshot_with_budget(Engine::Xray, fixture.uid(), &small)
                .err(),
            Some(RegistryError::Capacity)
        );
        assert_eq!(small.used(), 0);
    }

    #[test]
    fn live_cache_never_bypasses_source_trust_or_replacement_hash() {
        let fixture = Fixture::new();
        let registry = fixture.registry().unwrap();
        let mut image = registry
            .snapshot_for_uid(Engine::Xray, fixture.uid())
            .unwrap();
        fixture.mode("xray", 0o722);
        assert_eq!(
            registry.snapshot_for_uid(Engine::Xray, fixture.uid()).err(),
            Some(RegistryError::UnsafeEntry)
        );
        fixture.mode("xray", 0o700);
        fixture.mode("", 0o770);
        assert_eq!(
            registry.snapshot_for_uid(Engine::Xray, fixture.uid()).err(),
            Some(RegistryError::UnsafeEntry)
        );
        fixture.mode("", 0o700);
        fs::rename(fixture.0.join("xray"), fixture.0.join("old")).unwrap();
        fixture.binary("xray", b"\x7fELFchanged");
        assert_eq!(
            registry.snapshot_for_uid(Engine::Xray, fixture.uid()).err(),
            Some(RegistryError::HashMismatch)
        );
        assert_eq!(bytes(&mut image), ELF);
        fixture.binary("xray", ELF);
        let replacement = registry
            .snapshot_for_uid(Engine::Xray, fixture.uid())
            .unwrap();
        assert_ne!(
            image.file.metadata().unwrap().ino(),
            replacement.file.metadata().unwrap().ino()
        );
        let mut changed = ELF.to_vec();
        *changed.last_mut().unwrap() ^= 1;
        fixture.binary("xray", &changed);
        assert_eq!(
            registry.snapshot_for_uid(Engine::Xray, fixture.uid()).err(),
            Some(RegistryError::HashMismatch)
        );
    }

    #[test]
    fn every_manifest_entry_is_strict_even_when_not_selected() {
        let fixture = Fixture::new();
        let good = entry("xray");
        let mut unknown_field = good.clone();
        unknown_field["argv"] = serde_json::json!(["--version"]);
        let mut wrong_version = entry("sing-box");
        wrong_version["version"] = serde_json::json!("0.0.0");
        let mut wrong_hash = entry("sing-box");
        wrong_hash["sha256"] = serde_json::json!("bad");
        for (manifest, error) in [
            (
                serde_json::json!({"schema":2,"engines":[good.clone()]}),
                RegistryError::Manifest,
            ),
            (
                serde_json::json!({"schema":1,"engines":[]}),
                RegistryError::Manifest,
            ),
            (
                serde_json::json!({"schema":1,"engines":[good.clone(),good.clone()]}),
                RegistryError::Manifest,
            ),
            (
                serde_json::json!({"schema":1,"engines":[good.clone()],"path":"/x"}),
                RegistryError::Manifest,
            ),
            (
                serde_json::json!({"schema":1,"engines":[unknown_field]}),
                RegistryError::Manifest,
            ),
            (
                serde_json::json!({"schema":1,"engines":[entry("unknown")]}),
                RegistryError::Manifest,
            ),
            (
                serde_json::json!({"schema":1,"engines":[good.clone(),wrong_version]}),
                RegistryError::Version,
            ),
            (
                serde_json::json!({"schema":1,"engines":[good,wrong_hash]}),
                RegistryError::Manifest,
            ),
        ] {
            fixture.manifest(&manifest);
            assert_eq!(fixture.registry().err(), Some(error));
        }
        for malformed in [
            "{",
            "{}",
            "{\"schema\":1,\"schema\":1,\"engines\":[]}",
            "{\"schema\":1,\"engines\":[{\"engine\":\"xray\",\"engine\":\"xray\"}]}",
        ] {
            fs::write(fixture.0.join("registry.json"), malformed).unwrap();
            assert_eq!(fixture.registry().err(), Some(RegistryError::Manifest));
        }
    }

    #[test]
    fn wrong_owner_modes_links_and_oversized_files_are_rejected() {
        let fixture = Fixture::new();
        assert_eq!(
            TrustedRegistry::for_test(fixture.directory(), fixture.uid().wrapping_add(1)).err(),
            Some(RegistryError::UnsafeEntry)
        );
        let binary = File::open(fixture.0.join("xray")).unwrap();
        assert_eq!(
            regular_metadata(
                &binary,
                fixture.uid().wrapping_add(1),
                BinarySnapshot::MAX_SIZE,
                true
            ),
            Err(RegistryError::UnsafeEntry)
        );
        let manifest = File::open(fixture.0.join("registry.json")).unwrap();
        assert_eq!(
            regular_metadata(
                &manifest,
                fixture.uid().wrapping_add(1),
                MAX_MANIFEST,
                false
            ),
            Err(RegistryError::UnsafeEntry)
        );
        for name in ["registry.json", "xray"] {
            for mode in [0o722, 0o770, 0o4700, 0o2700] {
                fixture.mode(name, mode);
                assert_eq!(fixture.snapshot().err(), Some(RegistryError::UnsafeEntry));
            }
            fixture.mode(name, 0o700);
            fs::hard_link(fixture.0.join(name), fixture.0.join("link")).unwrap();
            assert_eq!(fixture.snapshot().err(), Some(RegistryError::UnsafeEntry));
            fs::remove_file(fixture.0.join("link")).unwrap();
        }
        fixture.mode("", 0o770);
        assert_eq!(fixture.registry().err(), Some(RegistryError::UnsafeEntry));
        fixture.mode("", 0o1700);
        assert_eq!(
            directory_metadata(&fixture.directory(), fixture.uid()),
            Err(RegistryError::UnsafeEntry)
        );
        fixture.mode("", 0o700);
        fixture.mode("xray", 0o600);
        assert_eq!(fixture.snapshot().err(), Some(RegistryError::UnsafeEntry));
        fixture.mode("xray", 0o700);
        File::options()
            .write(true)
            .open(fixture.0.join("xray"))
            .unwrap()
            .set_len(BinarySnapshot::MAX_SIZE + 1)
            .unwrap();
        assert_eq!(fixture.snapshot().err(), Some(RegistryError::UnsafeEntry));
        File::options()
            .write(true)
            .open(fixture.0.join("registry.json"))
            .unwrap()
            .set_len(MAX_MANIFEST + 1)
            .unwrap();
        assert_eq!(fixture.registry().err(), Some(RegistryError::UnsafeEntry));
    }

    #[test]
    fn symlinks_directories_and_fifos_are_never_followed_or_read() {
        for name in ["registry.json", "xray"] {
            let fixture = Fixture::new();
            fs::rename(fixture.0.join(name), fixture.0.join("original")).unwrap();
            symlink("original", fixture.0.join(name)).unwrap();
            assert_eq!(fixture.snapshot().err(), Some(RegistryError::Unavailable));
            fs::remove_file(fixture.0.join(name)).unwrap();
            fs::create_dir(fixture.0.join(name)).unwrap();
            assert_eq!(fixture.snapshot().err(), Some(RegistryError::UnsafeEntry));
            fs::remove_dir(fixture.0.join(name)).unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                fixture.0.join(name),
                rustix::fs::FileType::Fifo,
                Mode::RUSR | Mode::WUSR,
                0,
            )
            .unwrap();
            assert_eq!(fixture.snapshot().err(), Some(RegistryError::UnsafeEntry));
        }
        let fixture = Fixture::new();
        fs::create_dir(fixture.0.join("directory")).unwrap();
        symlink("directory", fixture.0.join("alias")).unwrap();
        assert!(child(&fixture.directory(), "alias", DIR_FLAGS).is_err());
    }

    #[test]
    fn valid_manifest_does_not_claim_binary_verified_until_snapshot() {
        let fixture = Fixture::new();
        let registry = fixture.registry().unwrap();
        fixture.binary("xray", b"\x7fELFchanged");
        assert_eq!(
            registry.snapshot_for_uid(Engine::Xray, fixture.uid()).err(),
            Some(RegistryError::HashMismatch)
        );
        fixture.binary("xray", b"not an ELF");
        assert_eq!(fixture.snapshot().err(), Some(RegistryError::InvalidBinary));
        fs::remove_file(fixture.0.join("xray")).unwrap();
        assert_eq!(fixture.snapshot().err(), Some(RegistryError::Unavailable));
    }

    #[test]
    fn pinned_directory_and_source_fd_survive_path_replacement() {
        let fixture = Fixture::new();
        let registry = fixture.registry().unwrap();
        let uid = fixture.uid();
        let renamed = fixture.0.with_extension("renamed");
        fs::rename(&fixture.0, &renamed).unwrap();
        fs::create_dir(&fixture.0).unwrap();
        let mut image = registry.snapshot_for_uid(Engine::Xray, uid).unwrap();
        assert_eq!(bytes(&mut image), ELF);
        fs::remove_dir(&fixture.0).unwrap();
        fs::rename(&renamed, &fixture.0).unwrap();

        let source = child(&registry.directory, "xray", FILE_FLAGS).unwrap();
        regular_metadata(&source, uid, BinarySnapshot::MAX_SIZE, true).unwrap();
        fs::rename(fixture.0.join("xray"), fixture.0.join("old")).unwrap();
        fixture.binary("xray", b"\x7fELFreplacement");
        let mut from_fd =
            BinarySnapshot::load_file(source, registry.entries[0].hash, Engine::Xray).unwrap();
        assert_eq!(bytes(&mut from_fd), ELF);
        fixture.binary("old", b"\x7fELFafter snapshot");
        assert_eq!(bytes(&mut image), ELF);
        assert_eq!(bytes(&mut from_fd), ELF);
        assert_eq!(
            registry.snapshot_for_uid(Engine::Xray, uid).err(),
            Some(RegistryError::HashMismatch)
        );
    }
}
