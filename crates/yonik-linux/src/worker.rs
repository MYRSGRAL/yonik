//! Приватный протокол helper → worker: только sealed FD и типизированные метаданные.
use crate::{
    BinarySnapshot, Sha256,
    helper::{
        MAX_ARTIFACT_BYTES,
        memory::{ByteLease, config_budget, executable_budget},
    },
};
use rustix::{
    fs::{MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, memfd_create},
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
    },
};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    fs::File,
    io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    net::Shutdown,
    os::{
        fd::AsFd,
        unix::{fs::FileExt, net::UnixStream, process::CommandExt},
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use yonik_application::ConfigDigest;
use yonik_engine::{CompiledConfig, Engine};

#[cfg(test)]
mod output_transport;

// Frozen c083 receipt helper: форматирование не меняет проверенные байты.
#[rustfmt::skip]
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64", target_env = "gnu"))]
mod fixed_fence_receipt;
pub mod anchor_exchange;
#[cfg(all(
    target_arch = "x86_64",
    target_pointer_width = "64",
    target_env = "gnu"
))]
mod native_data;
pub mod role_handoff;

const TIMEOUT: Duration = Duration::from_secs(5);
fn remaining_budget(deadline: Instant) -> Result<Duration, WorkerError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(WorkerError::Timeout)
}
fn write_before(
    stream: &mut &UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), WorkerError> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining_budget(deadline)?))
            .map_err(|_| WorkerError::Io)?;
        let n = stream.write(bytes).map_err(|_| WorkerError::Io)?;
        if n == 0 {
            return Err(WorkerError::Io);
        }
        bytes = &bytes[n..];
    }
    Ok(())
}
fn read_before(
    stream: &mut &UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), WorkerError> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining_budget(deadline)?))
            .map_err(|_| WorkerError::Io)?;
        let n = stream.read(bytes).map_err(|_| WorkerError::Io)?;
        if n == 0 {
            return Err(WorkerError::Protocol);
        }
        bytes = &mut bytes[n..];
    }
    Ok(())
}
const HEADER_LEN: usize = 80;
const BUNDLE_HEADER_LEN: usize = 96;
#[derive(Clone, Copy)]
pub(crate) struct ResourceSession {
    pub session: u64,
    pub generation: u64,
}
impl ResourceSession {
    pub(crate) fn fresh() -> Result<Self, WorkerError> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| WorkerError::Io)?;
        Ok(Self {
            session: u64::from_be_bytes(nonce[..8].try_into().map_err(|_| WorkerError::Protocol)?)
                .max(1),
            generation: u64::from_be_bytes(
                nonce[8..].try_into().map_err(|_| WorkerError::Protocol)?,
            )
            .max(1),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerMode {
    Check,
    Run,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerStatus {
    Checked,
    Accepted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerAck {
    pub pid: u32,
    pub status: WorkerStatus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerError {
    Protocol,
    Peer,
    Io,
    Limit,
    Engine,
    Timeout,
    Check,
    Exec,
}
impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Protocol => "Некорректный протокол worker",
            Self::Peer => "Недопустимый отправитель worker",
            Self::Io => "Ошибка канала worker",
            Self::Limit => "Превышен лимит worker",
            Self::Engine => "Несовместимое ядро worker",
            Self::Timeout => "Истёк срок worker",
            Self::Check => "Ядро отклонило проверку worker",
            Self::Exec => "Не удалось запустить worker",
        })
    }
}
impl std::error::Error for WorkerError {}
struct Header {
    mode: WorkerMode,
    engine: Engine,
    length: usize,
    binary_hash: [u8; 32],
    config_hash: [u8; 32],
}
impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0; HEADER_LEN];
        b[..8].copy_from_slice(b"YNKWRK\0\x01");
        b[8] = match self.mode {
            WorkerMode::Check => 1,
            WorkerMode::Run => 2,
        };
        b[9] = match self.engine {
            Engine::Xray => 1,
            Engine::SingBox => 2,
        };
        b[12..16].copy_from_slice(&(self.length as u32).to_be_bytes());
        b[16..48].copy_from_slice(&self.binary_hash);
        b[48..80].copy_from_slice(&self.config_hash);
        b
    }
    fn decode(b: &[u8]) -> Result<Self, WorkerError> {
        if b.len() != HEADER_LEN || &b[..8] != b"YNKWRK\0\x01" || b[10..12] != [0, 0] {
            return Err(WorkerError::Protocol);
        }
        let mode = match b[8] {
            1 => WorkerMode::Check,
            2 => WorkerMode::Run,
            _ => return Err(WorkerError::Protocol),
        };
        let engine = match b[9] {
            1 => Engine::Xray,
            2 => Engine::SingBox,
            _ => return Err(WorkerError::Protocol),
        };
        let length =
            u32::from_be_bytes(b[12..16].try_into().map_err(|_| WorkerError::Protocol)?) as usize;
        if length == 0 || length > MAX_ARTIFACT_BYTES {
            return Err(WorkerError::Limit);
        }
        Ok(Self {
            mode,
            engine,
            length,
            binary_hash: b[16..48].try_into().map_err(|_| WorkerError::Protocol)?,
            config_hash: b[48..80].try_into().map_err(|_| WorkerError::Protocol)?,
        })
    }
}
const SEALS: SealFlags = SealFlags::WRITE
    .union(SealFlags::GROW)
    .union(SealFlags::SHRINK)
    .union(SealFlags::SEAL);
fn config_file() -> Result<File, WorkerError> {
    let file = File::from(
        memfd_create(
            "yonik-config",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .map_err(|_| WorkerError::Io)?,
    );
    rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
        .map_err(|_| WorkerError::Io)?;
    Ok(file)
}
fn sealed_config(bytes: &[u8]) -> Result<File, WorkerError> {
    let mut file = config_file()?;
    file.write_all(bytes).map_err(|_| WorkerError::Io)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| WorkerError::Io)?;
    fcntl_add_seals(&file, SEALS).map_err(|_| WorkerError::Io)?;
    Ok(file)
}
fn validate_file(file: &File, length: usize, expected: [u8; 32]) -> Result<(), WorkerError> {
    if !fcntl_get_seals(file)
        .map_err(|_| WorkerError::Protocol)?
        .contains(SEALS)
        || file.metadata().map_err(|_| WorkerError::Protocol)?.len() != length as u64
    {
        return Err(WorkerError::Protocol);
    }
    let mut hash = Hasher::new();
    let mut buffer = zeroize::Zeroizing::new([0; 65536]);
    let mut offset = 0;
    while offset < length {
        let n = file
            .read_at(&mut buffer[..65536.min(length - offset)], offset as u64)
            .map_err(|_| WorkerError::Protocol)?;
        if n == 0 {
            return Err(WorkerError::Protocol);
        }
        hash.update(&buffer[..n]);
        offset += n;
    }
    if <[u8; 32]>::from(hash.finalize()) != expected {
        return Err(WorkerError::Protocol);
    }
    Ok(())
}
struct BoundedConfig {
    file: File,
    hash: Hasher,
    length: usize,
}
impl BoundedConfig {
    fn new() -> Result<Self, WorkerError> {
        Ok(Self {
            file: config_file()?,
            hash: Hasher::new(),
            length: 0,
        })
    }
    fn finish(mut self) -> Result<(File, usize, [u8; 32]), WorkerError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| WorkerError::Io)?;
        fcntl_add_seals(&self.file, SEALS).map_err(|_| WorkerError::Io)?;
        Ok((self.file, self.length, self.hash.finalize().into()))
    }
}
impl Write for BoundedConfig {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() > MAX_ARTIFACT_BYTES.saturating_sub(self.length) {
            return Err(std::io::Error::other("Лимит конфигурации"));
        }
        self.file.write_all(b)?;
        self.hash.update(b);
        self.length += b.len();
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
pub struct WorkerPayload {
    binary: BinarySnapshot,
    config: File,
    header: Header,
    _lease: ByteLease,
    resources: Option<std::sync::Arc<crate::resource_fd_receiver::RebuiltBatch>>,
    resource_session: Option<ResourceSession>,
    _native_work: Option<crate::resource_fd_receiver::Reservation>,
    full_profile: Option<std::sync::Arc<crate::helper::profile_intent::PreparedFullProfile>>,
    native_payload: Option<native_resources::TrustedNativePayload>,
}
impl WorkerPayload {
    pub fn new(binary: BinarySnapshot, config: CompiledConfig) -> Result<Self, WorkerError> {
        Self::from_config(binary, &config)
    }
    fn from_config(binary: BinarySnapshot, config: &CompiledConfig) -> Result<Self, WorkerError> {
        if config.engine() != binary.engine {
            return Err(WorkerError::Engine);
        }
        let mut lease = config_budget()
            .reserve(MAX_ARTIFACT_BYTES)
            .map_err(|_| WorkerError::Limit)?;
        // Сериализация сразу в учтённый memfd: второй plaintext buffer не нужен.
        let mut bytes = BoundedConfig::new()?;
        config
            .write_sensitive(&mut bytes)
            .map_err(|_| WorkerError::Limit)?;
        let (config, length, config_hash) = bytes.finish()?;
        let header = Header {
            mode: WorkerMode::Check,
            engine: binary.engine,
            length,
            binary_hash: binary.trusted_hash(),
            config_hash,
        };
        validate_file(
            &binary.file,
            binary.file.metadata().map_err(|_| WorkerError::Io)?.len() as usize,
            header.binary_hash,
        )?;
        let retained = header
            .length
            .checked_mul(if binary.engine == Engine::SingBox {
                2
            } else {
                1
            })
            .ok_or(WorkerError::Limit)?;
        lease.resize(retained).map_err(|_| WorkerError::Limit)?;
        Ok(Self {
            binary,
            config,
            header,
            _lease: lease,
            resources: None,
            resource_session: None,
            _native_work: None,
            full_profile: None,
            native_payload: None,
        })
    }
    pub(crate) fn new_full_profile(
        binary: BinarySnapshot,
        profile: std::sync::Arc<crate::helper::profile_intent::PreparedFullProfile>,
        cancel: &crate::Cancellation,
    ) -> Result<Self, WorkerError> {
        if binary.engine != Engine::Xray {
            return Err(WorkerError::Engine);
        }
        profile
            .revalidate(cancel)
            .map_err(|_| WorkerError::Protocol)?;
        let native_payload = native_resources::TrustedNativePayload::capture(&profile, cancel)?;
        let mut payload = Self::from_config(binary, profile.retained().compiled().config())?;
        if payload.header.config_hash != *profile.retained().digest() {
            return Err(WorkerError::Protocol);
        }
        payload.resource_session = Some(ResourceSession::fresh()?);
        payload.full_profile = Some(profile);
        payload.native_payload = Some(native_payload);
        Ok(payload)
    }
    pub(crate) fn full_profile(
        &self,
    ) -> Option<&std::sync::Arc<crate::helper::profile_intent::PreparedFullProfile>> {
        self.full_profile.as_ref()
    }
    pub(crate) fn image_hash(&self) -> [u8; 32] {
        self.header.binary_hash
    }
    pub(crate) fn new_bundle(
        binary: BinarySnapshot,
        config: CompiledConfig,
        resources: std::sync::Arc<crate::resource_fd_receiver::RebuiltBatch>,
        session: ResourceSession,
    ) -> Result<Self, WorkerError> {
        use yonik_engine::resource_bundle::VerifiedCatalog;
        if resources.manifest().is_empty()
            || resources.manifest().len() > 16
            || resources
                .manifest()
                .iter()
                .any(|r| r.engine != binary.engine)
        {
            return Err(WorkerError::Protocol);
        }
        // Отдельный conservative credit на native JSON/protobuf parse + matcher IR;
        // удерживается вместе с payload до worker/cgroup-empty, не обещает RSS.
        let work = resources
            .manifest()
            .iter()
            .try_fold(8192u64, |sum, r| {
                sum.checked_add(r.records.checked_mul(1024)?)
            })
            .ok_or(WorkerError::Limit)?;
        let native_work = crate::resource_fd_receiver::Reservation::acquire(work)
            .map_err(|_| WorkerError::Limit)?;
        let mut payload = Self::new(binary, config)?;
        if session.session == 0 || session.generation == 0 {
            return Err(WorkerError::Protocol);
        }
        payload.resources = Some(resources);
        payload.resource_session = Some(session);
        payload._native_work = Some(native_work);
        Ok(payload)
    }
    pub fn digest(&self) -> ConfigDigest {
        ConfigDigest::new(self.header.config_hash)
    }
    pub fn retained_bytes(&self) -> usize {
        self._lease.bytes()
    }
    pub fn needs_tmpfs_assets(&self) -> bool {
        self.full_profile.is_some() || self.has_resources() && self.engine() == Engine::Xray
    }
    pub fn has_resources(&self) -> bool {
        self.resources.is_some()
            || self
                .native_payload
                .as_ref()
                .is_some_and(|p| !p.assets.is_empty())
    }
    pub fn engine(&self) -> Engine {
        self.header.engine
    }
    pub fn send(&self, stream: &UnixStream, mode: WorkerMode) -> Result<WorkerAck, WorkerError> {
        self.send_output(stream, mode, None)
    }
    pub(crate) fn send_output(
        &self,
        stream: &UnixStream,
        mode: WorkerMode,
        output: Option<crate::output_transport::ValidatedWriters>,
    ) -> Result<WorkerAck, WorkerError> {
        self.send_output_before(stream, mode, output, Instant::now() + TIMEOUT)
    }
    pub(crate) fn send_output_before(
        &self,
        stream: &UnixStream,
        mode: WorkerMode,
        output: Option<crate::output_transport::ValidatedWriters>,
        deadline: Instant,
    ) -> Result<WorkerAck, WorkerError> {
        #[cfg(test)]
        let started = Instant::now();
        if output.is_some() && mode != WorkerMode::Run {
            return Err(WorkerError::Protocol);
        }
        stream
            .set_read_timeout(Some(remaining_budget(deadline)?))
            .map_err(|_| WorkerError::Io)?;
        stream
            .set_write_timeout(Some(remaining_budget(deadline)?))
            .map_err(|_| WorkerError::Io)?;
        if self.needs_tmpfs_assets() {
            let mut preflight = b"YNKSHM\0\x01".to_vec();
            preflight.push(if mode == WorkerMode::Check { 1 } else { 2 });
            let mut channel = stream;
            write_before(&mut channel, &preflight, deadline)?;
            let mut proof = [0u8; 32];
            read_before(&mut channel, &mut proof, deadline)?;
            if &proof[..8] != b"YNKSHMOK"
                || proof[8..16] == [0; 8]
                || proof[16..24] == [0; 8]
                || proof[24..32] == [0; 8]
            {
                return Err(WorkerError::Protocol);
            }
        }
        let mut header = self.header.encode().to_vec();
        if let (Some(profile), Some(native)) = (&self.full_profile, &self.native_payload) {
            let session = self.resource_session.ok_or(WorkerError::Protocol)?;
            let descriptors = native
                .assets
                .iter()
                .map(|a| a.descriptor)
                .collect::<Vec<_>>();
            header = encode_native_header(
                &self.header,
                mode,
                session,
                &descriptors,
                profile.capsule_bytes(),
                output.is_some(),
            )?;
        }
        if let Some(resources) = &self.resources {
            use yonik_engine::resource_bundle::VerifiedCatalog;
            header[7] = 2;
            header[10] = resources.manifest().len() as u8;
            let session = self.resource_session.ok_or(WorkerError::Protocol)?;
            header.extend_from_slice(&session.session.to_be_bytes());
            header.extend_from_slice(&session.generation.to_be_bytes());
            for resource in resources.manifest() {
                encode_resource(&mut header, resource);
            }
        }
        if self.full_profile.is_none() {
            header[8] = match mode {
                WorkerMode::Check => 1,
                WorkerMode::Run => 2,
            };
        }
        if output.is_some() && self.full_profile.is_none() {
            let resources = header.split_off(BUNDLE_HEADER_LEN.min(header.len()));
            header.resize(112, 0);
            header[7] = 3;
            header[96..100].copy_from_slice(&[0, 2, 1, 2]);
            header.extend_from_slice(&resources);
        }
        let mut fds = vec![self.binary.file.as_fd(), self.config.as_fd()];
        if let Some(resources) = &self.resources {
            fds.extend(resources.artifacts.iter().map(|f| f.as_fd()));
        }
        if let Some(native) = &self.native_payload {
            fds.extend(native.assets.iter().map(|a| a.file.as_fd()));
        }
        if let Some(output) = &output {
            fds.extend([output.stdout.as_fd(), output.stderr.as_fd()]);
        }
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(20))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !ancillary.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(WorkerError::Protocol);
        }
        stream
            .set_write_timeout(Some(remaining_budget(deadline)?))
            .map_err(|_| WorkerError::Io)?;
        let n = sendmsg(
            stream,
            &[IoSlice::new(&header)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .map_err(|_| WorkerError::Io)?;
        let mut stream = stream;
        let mut remaining = &header[n..];
        while !remaining.is_empty() {
            stream
                .set_write_timeout(Some(remaining_budget(deadline)?))
                .map_err(|_| WorkerError::Io)?;
            let written = stream.write(remaining).map_err(|_| WorkerError::Io)?;
            if written == 0 {
                return Err(WorkerError::Io);
            }
            remaining = &remaining[written..];
        }
        stream
            .shutdown(Shutdown::Write)
            .map_err(|_| WorkerError::Io)?;
        stream
            .set_read_timeout(Some(remaining_budget(deadline)?))
            .map_err(|_| WorkerError::Io)?;
        let mut ack = [0; 9];
        let mut offset = 0;
        while offset < ack.len() {
            stream
                .set_read_timeout(Some(remaining_budget(deadline)?))
                .map_err(|_| WorkerError::Io)?;
            let read = stream.read(&mut ack[offset..]).map_err(|error| {
                #[cfg(test)]
                eprintln!(
                    "Ожидание worker Ack: kind={:?}, errno={:?}, elapsed={:?}",
                    error.kind(),
                    error.raw_os_error(),
                    started.elapsed()
                );
                #[cfg(not(test))]
                let _ = error;
                WorkerError::Io
            })?;
            if read == 0 {
                return Err(WorkerError::Protocol);
            }
            offset += read;
        }
        if &ack[..4] != b"YNKA" {
            return Err(WorkerError::Protocol);
        }
        let pid = u32::from_be_bytes(ack[4..8].try_into().map_err(|_| WorkerError::Protocol)?);
        let status = match (ack[8], mode) {
            (1, WorkerMode::Check) => WorkerStatus::Checked,
            (2, WorkerMode::Run) => WorkerStatus::Accepted,
            _ => return Err(WorkerError::Protocol),
        };
        if pid == 0 {
            return Err(WorkerError::Protocol);
        }
        Ok(WorkerAck { pid, status })
    }
}
struct NativeHeader<'a> {
    header: Header,
    session: ResourceSession,
    descriptors: Vec<native_resources::NativeDescriptor>,
    capsule: &'a [u8],
    output: bool,
}
fn encode_native_header(
    header: &Header,
    mode: WorkerMode,
    session: ResourceSession,
    descriptors: &[native_resources::NativeDescriptor],
    capsule: &[u8],
    output: bool,
) -> Result<Vec<u8>, WorkerError> {
    let length = 112usize
        .checked_add(
            descriptors
                .len()
                .checked_mul(88)
                .ok_or(WorkerError::Limit)?,
        )
        .and_then(|n| n.checked_add(capsule.len()))
        .filter(|n| *n <= 65536)
        .ok_or(WorkerError::Limit)?;
    native_resources::preflight_native(descriptors.iter().copied())?;
    let mut out = vec![0; 112];
    out[..8].copy_from_slice(b"YNKNPY01");
    out[8..12].copy_from_slice(&(length as u32).to_be_bytes());
    out[12..80].copy_from_slice(&header.encode()[12..80]);
    out[80] = if mode == WorkerMode::Run { 2 } else { 1 };
    out[81] = descriptors.len() as u8;
    out[82] = if output { 2 } else { 0 };
    out[84..92].copy_from_slice(&session.session.to_be_bytes());
    out[92..100].copy_from_slice(&session.generation.to_be_bytes());
    out[100..104].copy_from_slice(&(capsule.len() as u32).to_be_bytes());
    out.reserve_exact(length - 112);
    for d in descriptors {
        out.extend_from_slice(&d.encode()?);
    }
    out.extend_from_slice(capsule);
    decode_native_header(&out)?;
    Ok(out)
}
fn decode_native_header(bytes: &[u8]) -> Result<NativeHeader<'_>, WorkerError> {
    if !(112..=65536).contains(&bytes.len())
        || bytes[..8] != *b"YNKNPY01"
        || u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| WorkerError::Protocol)?) as usize
            != bytes.len()
        || bytes[83] != 0
        || bytes[104..112] != [0; 8]
    {
        return Err(WorkerError::Protocol);
    }
    let count = bytes[81] as usize;
    if count > 16
        || ![0, 2].contains(&bytes[82])
        || ![1, 2].contains(&bytes[80])
        || bytes[82] == 2 && bytes[80] != 2
    {
        return Err(WorkerError::Protocol);
    }
    let capsule_length = u32::from_be_bytes(
        bytes[100..104]
            .try_into()
            .map_err(|_| WorkerError::Protocol)?,
    ) as usize;
    let start = 112 + 88 * count;
    if start.checked_add(capsule_length) != Some(bytes.len()) {
        return Err(WorkerError::Protocol);
    }
    let mut old = [0; 80];
    old[..8].copy_from_slice(b"YNKWRK\0\x01");
    old[8] = bytes[80];
    old[9] = 1;
    old[12..80].copy_from_slice(&bytes[12..80]);
    let header = Header::decode(&old)?;
    let session = ResourceSession {
        session: u64::from_be_bytes(
            bytes[84..92]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ),
        generation: u64::from_be_bytes(
            bytes[92..100]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ),
    };
    if session.session == 0 || session.generation == 0 {
        return Err(WorkerError::Protocol);
    }
    let capsule = &bytes[start..];
    let decoded = crate::profile_channel::Capsule::decode(capsule, &header.config_hash)
        .map_err(|_| WorkerError::Protocol)?;
    if decoded.mode != crate::profile_channel::Mode::System {
        return Err(WorkerError::Protocol);
    }
    let mut descriptors = [None; 16];
    let mut refs = [(0, [0; 32], 0, [0; 32], 0); 16];
    for (i, row) in bytes[112..start].chunks_exact(88).enumerate() {
        let d = native_resources::NativeDescriptor::decode(row)?;
        refs[i] = (d.kind as u8, d.digest, d.bytes, d.source, d.flags);
        descriptors[i] = Some(d);
    }
    native_resources::preflight_native(descriptors[..count].iter().flatten().copied())?;
    decoded
        .validate_asset_refs(&refs[..count])
        .map_err(|_| WorkerError::Protocol)?;
    Ok(NativeHeader {
        header,
        session,
        descriptors: descriptors[..count].iter().flatten().copied().collect(),
        capsule,
        output: bytes[82] == 2,
    })
}
struct Received {
    binary: BinarySnapshot,
    config: File,
    resources: Vec<native_resources::OwnedResource>,
    resource_session: Option<ResourceSession>,
    output: Option<crate::output_transport::ValidatedWriters>,
    native_assets: Vec<native_resources::NativeAsset>,
    profile_capsule: Option<Vec<u8>>,
    _metadata: ByteLease,
}
#[cfg(test)]
fn receive(stream: &UnixStream, mode: WorkerMode) -> Result<(BinarySnapshot, File), WorkerError> {
    let received = receive_payload(stream, mode)?;
    if !received.resources.is_empty()
        || !received.native_assets.is_empty()
        || received.profile_capsule.is_some()
    {
        return Err(WorkerError::Protocol);
    }
    Ok((received.binary, received.config))
}
fn receive_payload(stream: &UnixStream, mode: WorkerMode) -> Result<Received, WorkerError> {
    if !rustix::net::sockopt::socket_peercred(stream)
        .map_err(|_| WorkerError::Peer)?
        .uid
        .is_root()
    {
        return Err(WorkerError::Peer);
    }
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|_| WorkerError::Io)?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|_| WorkerError::Io)?;
    let start = Instant::now();
    let metadata = config_budget()
        .reserve(2 * 65536)
        .map_err(|_| WorkerError::Limit)?;
    let mut bytes = Vec::with_capacity(65536);
    let mut fds = Vec::new();
    let mut shm_preflight = false;
    loop {
        stream
            .set_read_timeout(Some(
                TIMEOUT
                    .checked_sub(start.elapsed())
                    .ok_or(WorkerError::Timeout)?,
            ))
            .map_err(|_| WorkerError::Io)?;
        let mut part = [0; 65537];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(21))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let msg = recvmsg(
            stream,
            &mut [IoSliceMut::new(&mut part)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )
        .map_err(|_| WorkerError::Io)?;
        let mut malformed = msg
            .flags
            .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC);
        for message in ancillary.drain() {
            match message {
                RecvAncillaryMessage::ScmRights(rights) => {
                    for fd in rights {
                        if fds.len() < 20 && !malformed {
                            fds.push(fd);
                        } else {
                            malformed = true;
                            drop(fd);
                        }
                    }
                }
                _ => malformed = true,
            }
        }
        if malformed || bytes.len() + msg.bytes > 65536 {
            return Err(WorkerError::Protocol);
        }
        if msg.bytes == 0 {
            break;
        }
        bytes.extend_from_slice(&part[..msg.bytes]);
        if bytes.len() == 9 && bytes.get(..8) == Some(b"YNKSHM\0\x01") {
            if shm_preflight
                || !fds.is_empty()
                || bytes[8] != (if mode == WorkerMode::Check { 1 } else { 2 })
            {
                return Err(WorkerError::Protocol);
            }
            let proof = native_assets::check_base(mode)?;
            let mut reply = b"YNKSHMOK".to_vec();
            reply.extend_from_slice(&proof.mount.to_be_bytes());
            reply.extend_from_slice(&proof.dev.to_be_bytes());
            reply.extend_from_slice(&proof.ino.to_be_bytes());
            let mut channel = stream;
            channel.write_all(&reply).map_err(|_| WorkerError::Io)?;
            shm_preflight = true;
            bytes.clear();
        }
    }
    if bytes.get(..8) == Some(b"YNKNPY01") {
        if !shm_preflight {
            return Err(WorkerError::Protocol);
        }
        return receive_native_payload(&bytes, fds, mode, start, metadata);
    }
    let output_v3 = bytes.get(..8) == Some(b"YNKWRK\0\x03");
    let legacy = if output_v3 {
        decode_output_header(&bytes)?
    } else {
        bytes.clone()
    };
    let (header, manifest, resource_session) = decode_bundle_header(&legacy)?;
    if shm_preflight != (!manifest.is_empty() && header.engine == Engine::Xray) {
        return Err(WorkerError::Protocol);
    }
    if header.mode != mode || fds.len() != 2 + manifest.len() + if output_v3 { 2 } else { 0 } {
        return Err(WorkerError::Protocol);
    }
    let mut fds = fds.into_iter();
    let mut source = File::from(fds.next().ok_or(WorkerError::Protocol)?);
    let config = File::from(fds.next().ok_or(WorkerError::Protocol)?);
    let native_files = fds
        .by_ref()
        .take(manifest.len())
        .map(File::from)
        .collect::<Vec<_>>();
    let output = if output_v3 {
        Some(
            crate::output_transport::OutputWriters {
                roles: fds.collect(),
            }
            .validate()
            .map_err(|_| WorkerError::Protocol)?,
        )
    } else {
        None
    };
    let mut total = 0u64;
    for (file, resource) in native_files.iter().zip(&manifest) {
        native_resources::validate(file, resource)?;
        total = total
            .checked_add(
                resource
                    .bytes
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(8192))
                    .ok_or(WorkerError::Limit)?,
            )
            .ok_or(WorkerError::Limit)?;
    }
    let _physical =
        crate::resource_fd_receiver::Reservation::acquire(total).map_err(|_| WorkerError::Limit)?;
    let length = source.metadata().map_err(|_| WorkerError::Protocol)?.len();
    if length > BinarySnapshot::MAX_SIZE {
        return Err(WorkerError::Limit);
    }
    if !fcntl_get_seals(&source)
        .map_err(|_| WorkerError::Protocol)?
        .contains(SEALS | SealFlags::EXEC)
    {
        return Err(WorkerError::Protocol);
    }
    // load_budgeted одновременно копирует sealed ELF и проверяет закреплённый SHA-256.
    validate_file(&config, header.length, header.config_hash)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| WorkerError::Io)?;
    let lease = executable_budget()
        .reserve(length as usize)
        .map_err(|_| WorkerError::Limit)?;
    let binary =
        BinarySnapshot::load_budgeted(source, Sha256(header.binary_hash), header.engine, lease)
            .map_err(|_| WorkerError::Protocol)?;
    let mut resources = Vec::new();
    for (index, (file, descriptor)) in native_files.iter().zip(&manifest).enumerate() {
        resources.push(
            native_resources::copy_owned(file, descriptor, &|| start.elapsed() > TIMEOUT)?
                .into_slot(index)?,
        );
    }
    Ok(Received {
        binary,
        config,
        resources,
        resource_session,
        output,
        native_assets: Vec::new(),
        profile_capsule: None,
        _metadata: metadata,
    })
}
fn receive_native_payload(
    bytes: &[u8],
    fds: Vec<std::os::fd::OwnedFd>,
    mode: WorkerMode,
    start: Instant,
    metadata: ByteLease,
) -> Result<Received, WorkerError> {
    let native = decode_native_header(bytes)?;
    if native.header.mode != mode
        || fds.len() != 2 + native.descriptors.len() + if native.output { 2 } else { 0 }
    {
        return Err(WorkerError::Protocol);
    }
    let total = native
        .descriptors
        .iter()
        .try_fold(8192u64, |n, d| n.checked_add(d.bytes.checked_mul(2)?))
        .ok_or(WorkerError::Limit)?;
    let _reservation =
        crate::resource_fd_receiver::Reservation::acquire(total).map_err(|_| WorkerError::Limit)?;
    let mut fds = fds.into_iter();
    let mut source = File::from(fds.next().ok_or(WorkerError::Protocol)?);
    let config = File::from(fds.next().ok_or(WorkerError::Protocol)?);
    let length = source.metadata().map_err(|_| WorkerError::Protocol)?.len();
    if length > BinarySnapshot::MAX_SIZE
        || !fcntl_get_seals(&source)
            .map_err(|_| WorkerError::Protocol)?
            .contains(SEALS | SealFlags::EXEC)
    {
        return Err(WorkerError::Protocol);
    }
    validate_file(&config, native.header.length, native.header.config_hash)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| WorkerError::Io)?;
    let lease = executable_budget()
        .reserve(length as usize)
        .map_err(|_| WorkerError::Limit)?;
    let binary = BinarySnapshot::load_budgeted(
        source,
        Sha256(native.header.binary_hash),
        Engine::Xray,
        lease,
    )
    .map_err(|_| WorkerError::Protocol)?;
    let mut assets = Vec::with_capacity(native.descriptors.len());
    for descriptor in native.descriptors {
        let source = File::from(fds.next().ok_or(WorkerError::Protocol)?);
        assets.push(native_resources::copy_native(&source, descriptor, &|| {
            start.elapsed() > TIMEOUT
        })?);
    }
    let output = if native.output {
        Some(
            crate::output_transport::OutputWriters {
                roles: fds.collect(),
            }
            .validate()
            .map_err(|_| WorkerError::Protocol)?,
        )
    } else {
        None
    };
    Ok(Received {
        binary,
        config,
        resources: Vec::new(),
        resource_session: Some(native.session),
        output,
        native_assets: assets,
        profile_capsule: Some(native.capsule.to_vec()),
        _metadata: metadata,
    })
}
struct WorkerConfig {
    file: File,
    _lease: Option<ByteLease>,
}
#[cfg(test)]
mod profile_wire_tests {
    use super::*;
    fn bytes() -> Vec<u8> {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/system-chain-probe.json"
        ))
        .unwrap();
        let capsule = f["capsule_hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let reference = native_resources::NativeDescriptor {
            kind: native_resources::NativeKind::Resolver,
            digest: [9; 32],
            bytes: 120,
            records: 0,
            source: [8; 32],
            flags: 0,
        };
        encode_native_header(
            &Header {
                mode: WorkerMode::Run,
                engine: Engine::Xray,
                length: 64,
                binary_hash: [1; 32],
                config_hash: [3; 32],
            },
            WorkerMode::Run,
            ResourceSession {
                session: 5,
                generation: 6,
            },
            &[reference],
            &capsule,
            true,
        )
        .unwrap()
    }
    #[test]
    fn native_payload_has_exact_refs_and_rejects_bounds_before_fd_materialization() {
        let bytes = bytes();
        let decoded = decode_native_header(&bytes).unwrap();
        assert_eq!(decoded.descriptors.len(), 1);
        assert!(decoded.output);
        assert_eq!(decoded.session.session, 5);
        for end in 0..bytes.len() {
            assert!(decode_native_header(&bytes[..end]).is_err());
        }
        for (offset, value) in [
            (80, 0),
            (81, 17),
            (82, 1),
            (83, 1),
            (104, 1),
            (112, 4),
            (116, 0),
        ] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(decode_native_header(&bad).is_err(), "offset {offset}");
        }
        let mut wrong = bytes.clone();
        wrong[48] ^= 1;
        assert!(decode_native_header(&wrong).is_err());
        let mut no_asset = bytes.clone();
        no_asset[81] = 0;
        assert!(decode_native_header(&no_asset).is_err());
    }
}
fn worker_owned_config(
    source: &File,
    budget: &crate::helper::memory::ByteBudget,
) -> Result<WorkerConfig, WorkerError> {
    let metadata = source.metadata().map_err(|_| WorkerError::Protocol)?;
    let length = usize::try_from(metadata.len()).map_err(|_| WorkerError::Limit)?;
    if !metadata.is_file()
        || length == 0
        || length > MAX_ARTIFACT_BYTES
        || !fcntl_get_seals(source)
            .map_err(|_| WorkerError::Protocol)?
            .contains(SEALS)
    {
        return Err(WorkerError::Protocol);
    }
    let lease = budget.reserve(length).map_err(|_| WorkerError::Limit)?;
    let mut target = BoundedConfig::new()?;
    rustix::fs::fchmod(
        &target.file,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|_| WorkerError::Io)?;
    let mut buffer = zeroize::Zeroizing::new([0u8; 65536]);
    let mut offset = 0;
    while offset < length {
        let n = source
            .read_at(&mut buffer[..65536.min(length - offset)], offset as u64)
            .map_err(|_| WorkerError::Io)?;
        if n == 0 {
            return Err(WorkerError::Protocol);
        }
        target
            .write_all(&buffer[..n])
            .map_err(|_| WorkerError::Io)?;
        offset += n;
    }
    let (file, copied, hash) = target.finish()?;
    if copied != length {
        return Err(WorkerError::Protocol);
    }
    validate_file(source, length, hash)?;
    validate_file(&file, length, hash)?;
    Ok(WorkerConfig {
        file,
        _lease: Some(lease),
    })
}
fn command(binary: &BinarySnapshot) -> Command {
    use std::os::fd::AsRawFd;
    let mut command = Command::new(format!("/proc/self/fd/{}", binary.file.as_raw_fd()));
    command
        .env_clear()
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}
fn configured_assets(
    binary: &BinarySnapshot,
    config: &File,
    check: bool,
    assets: Option<&native_assets::Assets>,
) -> Result<Command, WorkerError> {
    let mut command = command(binary);
    if let Some(assets) = assets {
        if binary.engine != Engine::Xray {
            return Err(WorkerError::Protocol);
        }
        command.env("XRAY_LOCATION_ASSET", assets.path());
    }
    match binary.engine {
        Engine::Xray => {
            command.arg("run");
            if check {
                command.arg("-test");
            }
            command.args(["-c", "stdin:"]);
        }
        Engine::SingBox => {
            command
                .arg(if check { "check" } else { "run" })
                .args(["-c", "/dev/stdin"]);
        }
    }
    let mut input = config.try_clone().map_err(|_| WorkerError::Io)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|_| WorkerError::Io)?;
    command.stdin(Stdio::from(input));
    Ok(command)
}
async fn check_assets(
    binary: &BinarySnapshot,
    config: &File,
    assets: Option<&native_assets::Assets>,
) -> Result<(), WorkerError> {
    use tokio::io::AsyncReadExt;
    let operation = async {
        let mut version = command(binary);
        version.arg("version").stdout(Stdio::piped());
        let mut version = tokio::process::Command::from(version);
        version.kill_on_drop(true);
        let mut child = version.spawn().map_err(|_| WorkerError::Check)?;
        let output = child.stdout.take().ok_or(WorkerError::Check)?;
        let mut bytes = Vec::new();
        let mut output = output.take(4097);
        let (read, status) = tokio::join!(output.read_to_end(&mut bytes), child.wait());
        read.map_err(|_| WorkerError::Check)?;
        if !status.map_err(|_| WorkerError::Check)?.success() || bytes.len() > 4096 {
            return Err(WorkerError::Check);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| WorkerError::Check)?;
        let prefix = match binary.engine {
            Engine::Xray => "Xray 26.10.31",
            Engine::SingBox => "sing-box version 1.14.4",
        };
        let line = text.lines().next().ok_or(WorkerError::Check)?;
        if line != prefix
            && !line
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with(' '))
        {
            return Err(WorkerError::Check);
        }
        let mut check =
            tokio::process::Command::from(configured_assets(binary, config, true, assets)?);
        check.kill_on_drop(true);
        if !check
            .status()
            .await
            .map_err(|_| WorkerError::Check)?
            .success()
        {
            return Err(WorkerError::Check);
        }
        Ok(())
    };
    tokio::time::timeout(TIMEOUT, operation)
        .await
        .map_err(|_| WorkerError::Timeout)?
}
/// stdin должен быть listening socket, установленным StandardInput=socket.
pub async fn serve(mode: WorkerMode) -> Result<(), WorkerError> {
    let fd = rustix::net::accept_with(std::io::stdin().as_fd(), rustix::net::SocketFlags::CLOEXEC)
        .map_err(|_| WorkerError::Io)?;
    let stream = UnixStream::from(fd);
    serve_stream(stream, mode).await
}
async fn serve_stream(mut stream: UnixStream, mode: WorkerMode) -> Result<(), WorkerError> {
    let handoff = anchor_exchange::bootstrap(&stream, mode)?;
    let Received {
        binary,
        config,
        resources,
        resource_session,
        output,
        native_assets,
        profile_capsule,
        _metadata,
    } = receive_payload(&stream, mode)?;
    // Исходный FD уже проверен receive: type/seals/declared size/SHA-256.
    // Helper удерживает отдельный global reserve до подтверждённого пустого cgroup.
    let config = if binary.engine == Engine::SingBox {
        worker_owned_config(&config, config_budget())?
    } else {
        WorkerConfig {
            file: config,
            _lease: None,
        }
    };
    let mut assets = if profile_capsule.is_some() {
        Some(native_assets::Assets::create_profile(
            &native_assets,
            resource_session.ok_or(WorkerError::Protocol)?,
            mode,
        )?)
    } else if !resources.is_empty() && binary.engine == Engine::Xray {
        Some(native_assets::Assets::create(
            &resources,
            resource_session.ok_or(WorkerError::Protocol)?,
            mode,
        )?)
    } else {
        None
    };
    for resource in &resources {
        resource.inherit(true)?;
    }
    if let Some(assets) = assets.as_mut() {
        assets.issued();
    }
    if mode == WorkerMode::Check {
        check_assets(&binary, &config.file, assets.as_ref()).await?;
        // Check мог породить потомков: assets остаются issued до unit/cgroup-empty.
        // Drop удерживает их budget в quarantine; private mount убирает только PID1.
        for resource in &resources {
            resource.inherit(false)?;
        }
    }
    let mut ack = [0; 9];
    ack[..4].copy_from_slice(b"YNKA");
    ack[4..8].copy_from_slice(&std::process::id().to_be_bytes());
    ack[8] = match mode {
        WorkerMode::Check => 1,
        WorkerMode::Run => 2,
    };
    stream.write_all(&ack).map_err(|_| WorkerError::Io)?;
    if mode == WorkerMode::Run {
        drop(stream);
        let mut command = match configured_assets(&binary, &config.file, false, assets.as_ref()) {
            Ok(command) => command,
            Err(error) => {
                if let Some(assets) = assets.as_mut() {
                    assets.cleanup_after_failed_exec()?;
                }
                return Err(error);
            }
        };
        if let Some(output) = output {
            output.attach(&mut command);
        }
        if let Some(handoff) = handoff {
            let result = handoff.exec(
                &mut command,
                profile_capsule.as_deref(),
                &config.file,
                assets.as_ref().map(native_assets::Assets::root_fd),
            );
            if let Some(assets) = assets.as_mut() {
                assets.cleanup_after_failed_exec()?;
            }
            return result;
        }
        if profile_capsule.is_some() {
            return Err(WorkerError::Peer);
        }
        let _error = command.exec();
        // exec вернулся: новый child не создан, собственный ledger можно убрать.
        if let Some(assets) = assets.as_mut() {
            assets.cleanup_after_failed_exec()?;
        }
        return Err(WorkerError::Exec);
    }
    Ok(())
}

mod native_assets;
mod native_resources;

fn encode_resource(bytes: &mut Vec<u8>, r: &yonik_engine::resource_bundle::ExternalRef) {
    bytes.push(if r.engine == Engine::Xray { 1 } else { 2 });
    bytes.push(
        if r.kind == yonik_engine::resource_bundle::ResourceKind::Domains {
            1
        } else {
            2
        },
    );
    bytes.extend_from_slice(&r.format_version.to_be_bytes());
    bytes.extend_from_slice(&r.bytes.to_be_bytes());
    bytes.extend_from_slice(&r.records.to_be_bytes());
    bytes.extend_from_slice(&r.digest);
}
fn decode_bundle_header(
    bytes: &[u8],
) -> Result<
    (
        Header,
        Vec<yonik_engine::resource_bundle::ExternalRef>,
        Option<ResourceSession>,
    ),
    WorkerError,
> {
    use yonik_engine::resource_bundle::{ExternalRef, ResourceKind};
    if bytes.get(..8) == Some(b"YNKWRK\0\x01") {
        return Ok((Header::decode(bytes)?, Vec::new(), None));
    }
    if bytes.len() < BUNDLE_HEADER_LEN || bytes.get(..8) != Some(b"YNKWRK\0\x02") {
        return Err(WorkerError::Protocol);
    }
    let count = bytes[10] as usize;
    if count == 0 || count > 16 || bytes[11] != 0 || bytes.len() != BUNDLE_HEADER_LEN + count * 54 {
        return Err(WorkerError::Protocol);
    }
    let mut legacy = bytes[..HEADER_LEN].to_vec();
    legacy[7] = 1;
    legacy[10] = 0;
    let header = Header::decode(&legacy)?;
    let session = ResourceSession {
        session: u64::from_be_bytes(
            bytes[80..88]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ),
        generation: u64::from_be_bytes(
            bytes[88..96]
                .try_into()
                .map_err(|_| WorkerError::Protocol)?,
        ),
    };
    if session.session == 0 || session.generation == 0 {
        return Err(WorkerError::Protocol);
    }
    let mut manifest: Vec<ExternalRef> = Vec::with_capacity(count);
    let mut records = 0u64;
    for b in bytes[BUNDLE_HEADER_LEN..].chunks_exact(54) {
        let r = ExternalRef {
            engine: match b[0] {
                1 => Engine::Xray,
                2 => Engine::SingBox,
                _ => return Err(WorkerError::Protocol),
            },
            kind: match b[1] {
                1 => ResourceKind::Domains,
                2 => ResourceKind::Cidrs,
                _ => return Err(WorkerError::Protocol),
            },
            format_version: u32::from_be_bytes(
                b[2..6].try_into().map_err(|_| WorkerError::Protocol)?,
            ),
            bytes: u64::from_be_bytes(b[6..14].try_into().map_err(|_| WorkerError::Protocol)?),
            records: u64::from_be_bytes(b[14..22].try_into().map_err(|_| WorkerError::Protocol)?),
            digest: b[22..54].try_into().map_err(|_| WorkerError::Protocol)?,
        };
        r.validate().map_err(|_| WorkerError::Protocol)?;
        records = records
            .checked_add(r.records)
            .ok_or(WorkerError::Protocol)?;
        if records > 1_500_000 {
            return Err(WorkerError::Limit);
        }
        if r.engine != header.engine || manifest.iter().any(|old| old.digest == r.digest) {
            return Err(WorkerError::Protocol);
        }
        manifest.push(r);
    }
    Ok((header, manifest, Some(session)))
}

#[cfg(test)]
mod tests;

// V3 добавляет только закрытые stdout/stderr роли; resource decoder остаётся общим.
fn decode_output_header(bytes: &[u8]) -> Result<Vec<u8>, WorkerError> {
    if bytes.len() < 112 || bytes.get(..8) != Some(b"YNKWRK\0\x03") {
        return Err(WorkerError::Protocol);
    }
    let count = usize::from(bytes[10]);
    if count > 16
        || bytes.len() != 112 + 54 * count
        || bytes[8] != 2
        || bytes[96..100] != [0, 2, 1, 2]
        || bytes[100..112] != [0; 12]
    {
        return Err(WorkerError::Protocol);
    }
    let mut legacy = bytes[..96].to_vec();
    if count == 0 {
        if legacy[80..96] != [0; 16] {
            return Err(WorkerError::Protocol);
        }
        legacy.truncate(80);
        legacy[7] = 1;
    } else {
        legacy[7] = 2;
        legacy.extend_from_slice(&bytes[112..]);
    }
    decode_bundle_header(&legacy)?;
    Ok(legacy)
}

#[cfg(test)]
mod native_budget_tests {
    use super::*;
    #[test]
    fn expired_admission_never_receives_fresh_payload_budget() {
        assert!(matches!(
            remaining_budget(Instant::now()),
            Err(WorkerError::Timeout)
        ));
        let deadline = Instant::now() + Duration::from_millis(50);
        assert!(remaining_budget(deadline).unwrap() <= Duration::from_millis(50));
    }
    #[test]
    fn owned_ipc_expired_payload_read_does_not_wait_for_peer() {
        let (_peer, worker) = UnixStream::pair().unwrap();
        let mut stream = &worker;
        assert!(matches!(
            read_before(&mut stream, &mut [0; 1], Instant::now()),
            Err(WorkerError::Timeout)
        ));
    }
}
