//! Приватные DATA v4. Ни transport custody, ни применение namespace policy не доказаны.
#![allow(dead_code)]
use super::run_authorization::{RunAuthority, RunAuthorization, RunRevocationGuard};
use std::{sync::Mutex, time::Instant};

const FRAME: usize = 512;
const VECTOR: usize = 19;
// Source170: old3, затем interleaved unshare/legacy clone для known8.
const KNOWN8: [u32; 8] = [
    0x02000000, 0x08000000, 0x40000000, 0x00020000, 0x20000000, 0x10000000, 0x04000000, 0x80,
];

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Revoked,
    Expired,
    Transport,
    Protocol,
    Binding,
    Profile,
    EvidenceUnavailable,
    ObservationMismatch,
    IncompleteApplication,
    Consumed,
}

/// Нормализованные fixed16 DATA. Не proof и не профиль admission.
struct RuntimeData16 {
    pairs: [[u32; 2]; KNOWN8.len()],
}
impl RuntimeData16 {
    fn try_from_observations(
        observations: &[yonik_nsfs::kernel_probe_v2::Observation],
    ) -> Result<Self, Error> {
        if observations.len() != KNOWN8.len() {
            return Err(Error::ObservationMismatch);
        }
        let mut pairs = [[0; 2]; KNOWN8.len()];
        let mut seen = [false; KNOWN8.len()];
        for observation in observations {
            let flag = match observation.namespace {
                "cgroup" => 0x02000000,
                "ipc" => 0x08000000,
                "net" => 0x40000000,
                "mount" => 0x00020000,
                "pid" => 0x20000000,
                "user" => 0x10000000,
                "uts" => 0x04000000,
                "time" => 0x80,
                _ => return Err(Error::ObservationMismatch),
            };
            let index = KNOWN8
                .iter()
                .position(|known| *known == flag)
                .ok_or(Error::ObservationMismatch)?;
            if seen[index] {
                return Err(Error::ObservationMismatch);
            }
            seen[index] = true;
            pairs[index] = [
                checked_errno(observation.unshare_errno)?,
                checked_errno(observation.clone_selector_errno)?,
            ];
        }
        Ok(Self { pairs })
    }
}
fn checked_errno(value: i32) -> Result<u32, Error> {
    if !(1..=4095).contains(&value) {
        return Err(Error::Protocol);
    }
    Ok(value as u32)
}

struct RuntimeData {
    vector: [u32; VECTOR],
}
impl RuntimeData {
    fn from_reports(
        old3: &yonik_nsfs::kernel_probe::Report,
        fixed16: RuntimeData16,
    ) -> Result<Self, Error> {
        let mut vector = [0; VECTOR];
        vector[..3].copy_from_slice(&[
            checked_errno(old3.unshare)?,
            checked_errno(old3.setns)?,
            checked_errno(old3.clone3)?,
        ]);
        for (slot, pair) in vector[3..].chunks_exact_mut(2).zip(fixed16.pairs) {
            slot.copy_from_slice(&pair);
        }
        Ok(Self { vector })
    }
}

/// Отсутствие наблюдения не равно наблюдённому нулю. Не obligation профиля.
struct DiagnosticCounts {
    baseline: Option<u32>,
    current: Option<u32>,
}

/// Значения поступают из private pending context, никогда из report.
pub(super) struct Expected {
    pub(super) nonce: [u8; 32],
    pub(super) digest: [u8; 32],
    pub(super) session: [u8; 16],
    pub(super) generation: u64,
    pub(super) invocation: [u8; 16],
    pub(super) epoch: u64,
    pub(super) task_pid: u32,
    pub(super) task_start: u64,
    pub(super) server_pid: u32,
    pub(super) server_start: u64,
    pub(super) profile: [u8; 32],
    pub(super) observations: [u32; VECTOR],
}
struct ParsedReport {
    receipt_reference: Option<[u8; 32]>,
    baseline_filters: u32,
    current_filters: u32,
    observations: [u32; VECTOR],
}
impl ParsedReport {
    /// Полный supported-profile verifier отсутствует. Digest не превращается в proof.
    fn supported_profile(&self) -> Result<(), Error> {
        Err(Error::EvidenceUnavailable)
    }
}
fn bytes<const N: usize>(frame: &[u8; FRAME], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&frame[offset..offset + N]);
    value
}
fn u32_at(frame: &[u8; FRAME], offset: usize) -> u32 {
    u32::from_be_bytes(bytes(frame, offset))
}
fn u64_at(frame: &[u8; FRAME], offset: usize) -> u64 {
    u64::from_be_bytes(bytes(frame, offset))
}
fn decode(frame: &[u8], expected: &Expected) -> Result<ParsedReport, Error> {
    let frame: &[u8; FRAME] = frame.try_into().map_err(|_| Error::Transport)?;
    if &frame[..8] != b"YNKNS004"
        || [(124, 128), (140, 144), (228, 232), (308, 512)]
            .iter()
            .any(|&(a, b)| frame[a..b].iter().any(|&v| v != 0))
        || [88, 112, 128, 144].iter().any(|&o| u64_at(frame, o) == 0)
        || [120, 136].iter().any(|&o| u32_at(frame, o) == 0)
        || u32_at(frame, 216) != 2
    {
        return Err(Error::Protocol);
    }
    let observations = std::array::from_fn(|i| u32_at(frame, 232 + i * 4));
    if observations.iter().any(|v| !(1..=4095).contains(v)) {
        return Err(Error::Protocol);
    }
    if bytes::<32>(frame, 8) != expected.nonce
        || bytes::<32>(frame, 40) != expected.digest
        || bytes::<16>(frame, 72) != expected.session
        || u64_at(frame, 88) != expected.generation
        || bytes::<16>(frame, 96) != expected.invocation
        || u64_at(frame, 112) != expected.epoch
        || u32_at(frame, 120) != expected.task_pid
        || u64_at(frame, 128) != expected.task_start
        || u32_at(frame, 136) != expected.server_pid
        || u64_at(frame, 144) != expected.server_start
    {
        return Err(Error::Binding);
    }
    if bytes::<32>(frame, 152) != expected.profile {
        return Err(Error::Profile);
    }
    if observations != expected.observations {
        return Err(Error::ObservationMismatch);
    }
    let receipt = bytes(frame, 184);
    Ok(ParsedReport {
        receipt_reference: (receipt != [0; 32]).then_some(receipt),
        baseline_filters: u32_at(frame, 220),
        current_filters: u32_at(frame, 224),
        observations,
    })
}

/// Mutex сериализует только DATA consume. Нет Clone, публичного raw-конструктора или permit.
struct PendingReport<'a> {
    owner: &'a RunAuthority,
    authorization: RunAuthorization,
    expected: Expected,
    deadline: Instant,
    slot: Mutex<Option<RunRevocationGuard>>,
}
struct ConsumedRecord {
    data: ParsedReport,
    _guard: RunRevocationGuard,
    #[cfg(test)]
    custody: Option<crate::worker::anchor_exchange::NamespaceObservation>,
    #[cfg(test)]
    unit_profile: Option<UnitProfile>,
}
impl PendingReport<'_> {
    fn consume(&self, frame: &[u8]) -> Result<ConsumedRecord, Error> {
        let mut slot = self.slot.lock().map_err(|_| Error::Revoked)?;
        if slot.is_none() {
            return Err(Error::Consumed);
        }
        let result = (|| {
            self.authorization
                .validate_owner(self.owner)
                .map_err(|_| Error::Revoked)?;
            if Instant::now() >= self.deadline {
                return Err(Error::Expired);
            }
            let (nonce, session, generation) = self
                .authorization
                .challenge_context()
                .map_err(|_| Error::Revoked)?;
            if (nonce, session, generation)
                != (
                    self.expected.nonce,
                    self.expected.session,
                    self.expected.generation,
                )
            {
                return Err(Error::Binding);
            }
            let data = decode(frame, &self.expected)?;
            self.authorization
                .validate_owner(self.owner)
                .map_err(|_| Error::Revoked)?;
            if Instant::now() >= self.deadline {
                return Err(Error::Expired);
            }
            Ok(data)
        })();
        let guard = slot.take().ok_or(Error::Consumed)?;
        result.map(|data| ConsumedRecord {
            data,
            _guard: guard,
            #[cfg(test)]
            custody: None,
            #[cfg(test)]
            unit_profile: None,
        })
    }
}

#[cfg(test)]
impl PendingReport<'_> {
    /// Единый UNIT путь. Guard остаётся в pending на всём blocking exchange.
    fn receive_unit(
        &self,
        stream: &std::os::unix::net::UnixStream,
        uid: u32,
        profile: UnitProfile,
    ) -> Result<ConsumedRecord, Error> {
        let result = (|| {
            self.authorization
                .validate_owner(self.owner)
                .map_err(|_| Error::Revoked)?;
            if Instant::now() >= self.deadline {
                return Err(Error::Expired);
            }
            let challenge = crate::worker::anchor_exchange::Challenge::for_authorization(
                &self.authorization,
                self.expected.digest,
                self.expected.invocation,
            )
            .map_err(|_| Error::Binding)?;
            let transport =
                challenge.exchange_v4(stream, self.expected.task_pid, uid, self.deadline);
            self.authorization
                .validate_owner(self.owner)
                .map_err(|_| Error::Revoked)?;
            if Instant::now() >= self.deadline {
                return Err(Error::Expired);
            }
            let (custody, frame) = transport.map_err(|_| Error::Transport)?;
            let mut record = self.consume(&frame)?;
            profile.verify(&record.data, &self.expected)?;
            record.unit_profile = Some(profile);
            self.authorization
                .bind_custody(&custody)
                .map_err(|_| Error::Binding)?;
            self.authorization
                .validate_owner(self.owner)
                .map_err(|_| Error::Revoked)?;
            if Instant::now() >= self.deadline {
                return Err(Error::Expired);
            }
            record.custody = Some(custody);
            Ok(record)
        })();
        if result.is_err() {
            self.owner.revoke();
            self.slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
        result
    }
}

/// Закрытая UNIT модель retained formal obligations; не production allowlist.
#[cfg(test)]
enum UnitProfile {
    Unknown,
    Incomplete,
    Alternative {
        manifest: [u8; 32],
        formal_reference: [u8; 32],
    },
    Count {
        baseline: Option<u32>,
        maxima: Vec<u32>,
    },
}
#[cfg(test)]
impl UnitProfile {
    fn verify(&self, data: &ParsedReport, expected: &Expected) -> Result<(), Error> {
        // Ненулевой lookup key без independently retained record не принимается.
        if data.receipt_reference.is_some() {
            return Err(Error::EvidenceUnavailable);
        }
        match self {
            Self::Unknown => Err(Error::EvidenceUnavailable),
            Self::Incomplete => Err(Error::IncompleteApplication),
            Self::Alternative {
                manifest,
                formal_reference,
            } if *manifest == expected.profile && *formal_reference == [0x55; 32] => Ok(()),
            Self::Alternative { .. } => Err(Error::EvidenceUnavailable),
            Self::Count { baseline, maxima } => {
                let baseline = baseline.ok_or(Error::EvidenceUnavailable)?;
                let count = maxima
                    .iter()
                    .try_fold(baseline, |n, k| n.checked_add(*k))
                    .ok_or(Error::EvidenceUnavailable)?;
                if data.baseline_filters != baseline || data.current_filters != count {
                    return Err(Error::EvidenceUnavailable);
                }
                Ok(())
            }
        }
    }
}

/// Только типизированные UNIT observations. Не supported-profile registry/issuer.
#[cfg(test)]
struct UnitObservations {
    baseline: u32,
    current: u32,
    vector: [u32; VECTOR],
}
#[cfg(test)]
fn encode_unit(e: &Expected, observation: UnitObservations) -> Result<[u8; FRAME], Error> {
    encode_data_v4(
        e,
        &RuntimeData {
            vector: observation.vector,
        },
        DiagnosticCounts {
            baseline: Some(observation.baseline),
            current: Some(observation.current),
        },
    )
}

/// Чистый DATA encoder: context остаётся private, caller registration отсутствует.
/// Не вызывает probes, profile verifier или admission; receipt остаётся absent.
fn encode_data_v4(
    e: &Expected,
    data: &RuntimeData,
    counts: DiagnosticCounts,
) -> Result<[u8; FRAME], Error> {
    // В frozen layout нет тега unavailable. Не выдумываем значение или новый wire.
    let baseline = counts.baseline.ok_or(Error::EvidenceUnavailable)?;
    let current = counts.current.ok_or(Error::EvidenceUnavailable)?;
    let mut f = [0; FRAME];
    f[..8].copy_from_slice(b"YNKNS004");
    for (o, v) in [
        (8, e.nonce.as_slice()),
        (40, &e.digest),
        (72, &e.session),
        (96, &e.invocation),
        (152, &e.profile),
    ] {
        f[o..o + v.len()].copy_from_slice(v);
    }
    for (o, v) in [
        (88, e.generation),
        (112, e.epoch),
        (128, e.task_start),
        (144, e.server_start),
    ] {
        f[o..o + 8].copy_from_slice(&v.to_be_bytes());
    }
    for (o, v) in [
        (120, e.task_pid),
        (136, e.server_pid),
        (216, 2),
        (220, baseline),
        (224, current),
    ] {
        f[o..o + 4].copy_from_slice(&v.to_be_bytes());
    }
    for (i, v) in data.vector.iter().enumerate() {
        f[232 + i * 4..236 + i * 4].copy_from_slice(&v.to_be_bytes());
    }
    decode(&f, e)?;
    Ok(f)
}

/// Проверка покрытия после authenticated v4 transport и immutable producer validation.
/// Хеш ссылки не подпись: доверие producer проверяется отдельно до вызова.
pub(super) fn verify_fixed_report(frame: &[u8; FRAME], expected: &Expected) -> Result<(), Error> {
    use sha2::{Digest, Sha256};
    use yonik_nsfs::fixed_self_fence::{PROFILE_DIGEST, PROGRAM_SHA256};
    let data = decode(frame, expected)?;
    if expected.profile != PROFILE_DIGEST {
        return Err(Error::Profile);
    }
    let mut vector = [1; VECTOR];
    vector[2] = 38;
    if data.observations != vector {
        return Err(Error::ObservationMismatch);
    }
    if data.baseline_filters.checked_add(1) != Some(data.current_filters) {
        return Err(Error::IncompleteApplication);
    }
    let reference = data.receipt_reference.ok_or(Error::EvidenceUnavailable)?;
    let mut canonical = *frame;
    canonical[184..216].fill(0);
    let mut hash = Sha256::new();
    hash.update(b"yonik/fixed-self-fence/v2/local-delta1/receipt\0");
    hash.update(PROGRAM_SHA256);
    hash.update(PROFILE_DIGEST);
    hash.update(canonical);
    let computed: [u8; 32] = hash.finalize().into();
    if computed != reference {
        return Err(Error::Binding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn source16() -> Vec<yonik_nsfs::kernel_probe_v2::Observation> {
        [
            "time", "mount", "cgroup", "uts", "ipc", "user", "pid", "net",
        ]
        .into_iter()
        .enumerate()
        .map(|(i, namespace)| yonik_nsfs::kernel_probe_v2::Observation {
            namespace,
            unshare_errno: 4 + i as i32 * 2,
            clone_selector_errno: 5 + i as i32 * 2,
        })
        .collect()
    }
    fn runtime_data() -> RuntimeData {
        RuntimeData::from_reports(
            &yonik_nsfs::kernel_probe::Report {
                unshare: 1,
                setns: 2,
                clone3: 3,
            },
            RuntimeData16::try_from_observations(&source16()).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn pure_runtime_source_order_to_distinct_wire19() {
        let wire = [
            1, 2, 3, 8, 9, 12, 13, 18, 19, 6, 7, 16, 17, 14, 15, 10, 11, 4, 5,
        ];
        assert_eq!(runtime_data().vector, wire);
        let mut reordered = source16();
        reordered.reverse();
        let data = RuntimeData::from_reports(
            &yonik_nsfs::kernel_probe::Report {
                unshare: 1,
                setns: 2,
                clone3: 3,
            },
            RuntimeData16::try_from_observations(&reordered).unwrap(),
        )
        .unwrap();
        assert_eq!(data.vector, wire);
    }
    #[test]
    fn pure_runtime_rejects_missing_duplicate_unknown_and_errno() {
        let mut input = source16();
        input.pop();
        assert!(RuntimeData16::try_from_observations(&input).is_err());
        let mut input = source16();
        input.push(yonik_nsfs::kernel_probe_v2::Observation {
            namespace: "time",
            unshare_errno: 1,
            clone_selector_errno: 2,
        });
        assert!(RuntimeData16::try_from_observations(&input).is_err());
        let mut input = source16();
        input[7].namespace = "time";
        assert!(RuntimeData16::try_from_observations(&input).is_err());
        input[7].namespace = "unknown";
        assert!(RuntimeData16::try_from_observations(&input).is_err());
        for value in [i32::MIN, -1, 0, 4096, i32::MAX] {
            for field in 0..16 {
                let mut input = source16();
                if field % 2 == 0 {
                    input[field / 2].unshare_errno = value;
                } else {
                    input[field / 2].clone_selector_errno = value;
                }
                assert!(RuntimeData16::try_from_observations(&input).is_err());
            }
            for field in 0..3 {
                let mut report = yonik_nsfs::kernel_probe::Report {
                    unshare: 1,
                    setns: 2,
                    clone3: 3,
                };
                match field {
                    0 => report.unshare = value,
                    1 => report.setns = value,
                    _ => report.clone3 = value,
                }
                assert!(
                    RuntimeData::from_reports(
                        &report,
                        RuntimeData16::try_from_observations(&source16()).unwrap()
                    )
                    .is_err()
                );
            }
        }
        let input: Vec<_> = source16()
            .into_iter()
            .map(|mut o| {
                o.unshare_errno = 1;
                o.clone_selector_errno = 4095;
                o
            })
            .collect();
        assert!(RuntimeData16::try_from_observations(&input).is_ok());
    }
    #[test]
    fn pure_runtime_encoder_golden_and_unavailable_counts() {
        let mut e = expected();
        e.observations = runtime_data().vector;
        let counts = DiagnosticCounts {
            baseline: Some(0),
            current: Some(u32::MAX),
        };
        let f = encode_data_v4(&e, &runtime_data(), counts).unwrap();
        let mut golden = [0u8; FRAME];
        golden[..8].copy_from_slice(b"YNKNS004");
        for (a, b, value) in [
            (8, 40, 2),
            (40, 72, 3),
            (72, 88, 1),
            (96, 112, 4),
            (152, 184, 5),
        ] {
            golden[a..b].fill(value);
        }
        for (offset, value) in [(88, 1u64), (112, 9), (128, 11), (144, 13)] {
            golden[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [(120, 10u32), (136, 12), (216, 2), (224, u32::MAX)] {
            golden[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (i, value) in [
            1u32, 2, 3, 8, 9, 12, 13, 18, 19, 6, 7, 16, 17, 14, 15, 10, 11, 4, 5,
        ]
        .into_iter()
        .enumerate()
        {
            golden[232 + i * 4..236 + i * 4].copy_from_slice(&value.to_be_bytes());
        }
        assert_eq!(f, golden);
        let parsed = decode(&f, &e).unwrap();
        assert_eq!(parsed.baseline_filters, 0);
        assert_eq!(parsed.current_filters, u32::MAX);
        assert_eq!(parsed.receipt_reference, None);
        assert_eq!(parsed.supported_profile(), Err(Error::EvidenceUnavailable));
        for counts in [
            DiagnosticCounts {
                baseline: None,
                current: Some(0),
            },
            DiagnosticCounts {
                baseline: Some(0),
                current: None,
            },
            DiagnosticCounts {
                baseline: None,
                current: None,
            },
        ] {
            assert_eq!(
                encode_data_v4(&e, &runtime_data(), counts),
                Err(Error::EvidenceUnavailable)
            );
        }
        e.observations[0] = 99;
        assert_eq!(
            encode_data_v4(
                &e,
                &runtime_data(),
                DiagnosticCounts {
                    baseline: Some(0),
                    current: Some(0)
                }
            ),
            Err(Error::ObservationMismatch)
        );
    }
    fn expected() -> Expected {
        Expected {
            nonce: [2; 32],
            digest: [3; 32],
            session: [1; 16],
            generation: 1,
            invocation: [4; 16],
            epoch: 9,
            task_pid: 10,
            task_start: 11,
            server_pid: 12,
            server_start: 13,
            profile: [5; 32],
            observations: std::array::from_fn(|i| i as u32 + 1),
        }
    }
    fn frame(e: &Expected) -> [u8; FRAME] {
        encode_unit(
            e,
            UnitObservations {
                baseline: 0,
                current: 0,
                vector: e.observations,
            },
        )
        .unwrap()
    }

    fn pending(owner: &RunAuthority, deadline: Instant) -> PendingReport<'_> {
        let authorization = owner.authorize([2; 32]).unwrap();
        let guard = authorization.guard();
        PendingReport {
            owner,
            authorization,
            expected: expected(),
            deadline,
            slot: Mutex::new(Some(guard)),
        }
    }
    fn error(f: &[u8], e: &Expected) -> Error {
        decode(f, e).err().expect("отказ DATA")
    }
    #[test]
    fn unit_encode_transport_decode_consume_retains_custody() {
        use crate::worker::anchor_exchange::unit_v4_peer;
        for attack in [
            "valid",
            "short",
            "long",
            "old3",
            "nonce",
            "epoch",
            "profile",
            "vector",
            "uid",
            "unknown-profile",
            "incomplete",
            "count-missing",
            "count-overflow",
            "count-valid",
            "count-wrong",
            "alternative-counts",
            "receipt",
            "fd",
        ] {
            let owner = RunAuthority::new([1; 16], 1, 9).unwrap();
            let mut p = pending(&owner, Instant::now() + Duration::from_secs(1));
            p.expected.task_pid = std::process::id();
            let profile = match attack {
                "unknown-profile" => UnitProfile::Unknown,
                "incomplete" => UnitProfile::Incomplete,
                "count-missing" => UnitProfile::Count {
                    baseline: None,
                    maxima: vec![1],
                },
                "count-overflow" => UnitProfile::Count {
                    baseline: Some(u32::MAX),
                    maxima: vec![1],
                },
                "count-valid" | "count-wrong" => UnitProfile::Count {
                    baseline: Some(4),
                    maxima: vec![1, 2],
                },
                _ => UnitProfile::Alternative {
                    manifest: p.expected.profile,
                    formal_reference: [0x55; 32],
                },
            };
            let mut data = frame(&p.expected).to_vec();
            match attack {
                "short" => {
                    data.pop();
                }
                "long" => data.push(0),
                "old3" => {
                    data.truncate(128);
                    data[..8].copy_from_slice(b"YNKPR003");
                }
                "nonce" => data[8] ^= 1,
                "epoch" => data[119] ^= 1,
                "profile" => data[152] ^= 1,
                "vector" => data[235] ^= 1,
                "count-valid" | "count-wrong" => {
                    data[220..224].copy_from_slice(&4u32.to_be_bytes());
                    data[224..228].copy_from_slice(
                        &(if attack == "count-valid" { 7u32 } else { 6u32 }).to_be_bytes(),
                    );
                }
                "alternative-counts" => {
                    data[220..228].fill(255);
                }
                "receipt" => data[184..216].fill(7),
                _ => (),
            }
            let (helper, peer) = std::os::unix::net::UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || {
                unit_v4_peer(peer, |challenge| {
                    assert_eq!(&challenge[8..40], &[2; 32]);
                    (data, usize::from(attack == "fd"))
                })
            });
            let result = p.receive_unit(
                &helper,
                rustix::process::getuid().as_raw() + u32::from(attack == "uid"),
                profile,
            );
            if matches!(attack, "valid" | "count-valid" | "alternative-counts") {
                let record = result.unwrap();
                assert_eq!(
                    record.custody.as_ref().unwrap().retained_namespace_count(),
                    2
                );
                assert_eq!(
                    record.data.supported_profile(),
                    Err(Error::EvidenceUnavailable)
                );
                assert!(matches!(p.consume(&[]), Err(Error::Consumed)));
                drop(p);
                assert!(!owner.is_revoked());
                owner.revoke();
                assert_eq!(
                    record.custody.as_ref().unwrap().retained_namespace_count(),
                    0
                );
                drop(record);
            } else {
                assert!(result.is_err(), "{attack}");
                assert!(owner.is_revoked(), "{attack}");
            }
            drop(helper);
            worker.join().unwrap();
        }
    }
    #[test]
    fn unit_transport_late_and_cancelled_results_are_destroyed() {
        use crate::worker::anchor_exchange::unit_v4_peer;
        for cancelled in [false, true] {
            let owner = RunAuthority::new([1; 16], 1, 9).unwrap();
            let mut p = pending(&owner, Instant::now() + Duration::from_millis(60));
            p.expected.task_pid = std::process::id();
            let data = frame(&p.expected);
            let cancel = cancelled.then(|| p.authorization.guard());
            let (helper, peer) = std::os::unix::net::UnixStream::pair().unwrap();
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    unit_v4_peer(peer, |_| {
                        if cancelled {
                            drop(cancel);
                        } else {
                            std::thread::sleep(Duration::from_millis(90));
                        }
                        (data.to_vec(), 0)
                    })
                });
                let result = p.receive_unit(
                    &helper,
                    rustix::process::getuid().as_raw(),
                    UnitProfile::Alternative {
                        manifest: p.expected.profile,
                        formal_reference: [0x55; 32],
                    },
                );
                assert!(
                    matches!(result, Err(e) if e == if cancelled {Error::Revoked} else {Error::Expired})
                );
                assert!(owner.is_revoked());
                drop(helper);
                worker.join().unwrap();
            });
        }
    }
    #[test]
    fn framing_bounds_reserved_and_arbitrary() {
        let e = expected();
        let f = frame(&e);
        for len in 0..FRAME {
            assert_eq!(error(&f[..len], &e), Error::Transport);
        }
        assert_eq!(error(&[0; 513], &e), Error::Transport);
        for i in (124..128)
            .chain(140..144)
            .chain(228..232)
            .chain(308..512)
            .chain(0..8)
        {
            let mut bad = f;
            bad[i] ^= 1;
            assert_eq!(error(&bad, &e), Error::Protocol);
        }
        for offset in [88, 112, 120, 128, 136, 144] {
            let mut bad = f;
            let n = if offset == 120 || offset == 136 { 4 } else { 8 };
            bad[offset..offset + n].fill(0);
            assert_eq!(error(&bad, &e), Error::Protocol);
        }
        for i in 0..VECTOR {
            for v in [0u32, 4096, u32::MAX] {
                let mut bad = f;
                bad[232 + i * 4..236 + i * 4].copy_from_slice(&v.to_be_bytes());
                assert_eq!(error(&bad, &e), Error::Protocol);
            }
        }
        for seed in 0..=255u8 {
            assert_eq!(error(&[seed; 512], &e), Error::Protocol);
        }
    }
    #[test]
    fn every_binding_and_endian() {
        let e = expected();
        let f = frame(&e);
        for i in (8..124).chain(128..140).chain(144..152) {
            let mut bad = f;
            bad[i] ^= 0x40;
            assert_eq!(error(&bad, &e), Error::Binding, "offset {i}");
        }
        for i in 152..184 {
            let mut bad = f;
            bad[i] ^= 1;
            assert_eq!(error(&bad, &e), Error::Profile);
        }
        for i in 3..18 {
            let mut bad = f;
            bad[232 + i * 4..236 + i * 4].copy_from_slice(&e.observations[i + 1].to_be_bytes());
            assert_eq!(error(&bad, &e), Error::ObservationMismatch);
        }
        let mut upper = expected();
        upper.observations = [4095; VECTOR];
        assert!(decode(&frame(&upper), &upper).is_ok());
        let mut bad = f;
        bad[88..96].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(error(&bad, &e), Error::Binding);
        let mut bad = f;
        bad[232..236].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(error(&bad, &e), Error::ObservationMismatch);
    }
    #[test]
    fn optional_reference_never_admits() {
        let e = expected();
        let mut f = frame(&e);
        for receipt in [[0; 32], [7; 32]] {
            f[184..216].copy_from_slice(&receipt);
            let data = decode(&f, &e).unwrap();
            assert_eq!(
                data.receipt_reference,
                (receipt != [0; 32]).then_some(receipt)
            );
            assert_eq!(data.supported_profile(), Err(Error::EvidenceUnavailable));
        }
    }
    #[test]
    fn transfer_drop_replay_and_concurrent_winner() {
        let owner = RunAuthority::new([1; 16], 1, 9).unwrap();
        let p = pending(&owner, Instant::now() + Duration::from_secs(1));
        let f = frame(&p.expected);
        let record = std::thread::scope(|s| {
            let a = s.spawn(|| p.consume(&f));
            let b = s.spawn(|| p.consume(&f));
            let results = [a.join().unwrap(), b.join().unwrap()];
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
            assert!(results.iter().any(|r| matches!(r, Err(Error::Consumed))));
            results.into_iter().find_map(Result::ok).unwrap()
        });
        drop(p);
        assert!(!owner.is_revoked());
        assert_eq!(
            record.data.supported_profile(),
            Err(Error::EvidenceUnavailable)
        );
        drop(record);
        assert!(owner.is_revoked());
    }
    #[test]
    fn late_wrong_binding_and_retained_revocation() {
        let owner = RunAuthority::new([1; 16], 1, 9).unwrap();
        let p = pending(&owner, Instant::now() - Duration::from_secs(1));
        let mut f = frame(&p.expected);
        f[8] ^= 1;
        assert!(matches!(p.consume(&f), Err(Error::Expired)));
        assert!(matches!(p.consume(&f), Err(Error::Consumed)));
        let owner = RunAuthority::new([1; 16], 1, 9).unwrap();
        let p = pending(&owner, Instant::now() + Duration::from_secs(1));
        let record = p.consume(&frame(&p.expected)).unwrap();
        assert!(matches!(p.consume(&[]), Err(Error::Consumed)));
        owner.revoke();
        assert!(owner.is_revoked());
        drop(record);
    }
    #[test]
    fn trusted_revocation_expiry_and_cancel_precede_framing() {
        for revoke in [false, true] {
            let owner = RunAuthority::new([1; 16], 1, 9).unwrap();
            let p = pending(&owner, Instant::now());
            if revoke {
                owner.revoke();
            }
            assert!(
                matches!(p.consume(&[]),Err(e) if e==if revoke {Error::Revoked}else{Error::Expired})
            );
            assert!(owner.is_revoked());
        }
        let owner = RunAuthority::new([1; 16], 1, 9).unwrap();
        let p = pending(&owner, Instant::now() + Duration::from_secs(1));
        let cancel = p.authorization.guard();
        drop(cancel);
        assert!(matches!(p.consume(&[]), Err(Error::Revoked)));
        let owner = RunAuthority::new([1; 16], 1, 9).unwrap();
        drop(pending(&owner, Instant::now() + Duration::from_secs(1)));
        assert!(owner.is_revoked());
    }
}

#[cfg(test)]
mod fixed_coverage_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use yonik_nsfs::fixed_self_fence::{PROFILE_DIGEST, PROGRAM_SHA256};
    fn fixture() -> (Expected, [u8; 512]) {
        let mut observations = [1; 19];
        observations[2] = 38;
        let expected = Expected {
            nonce: [1; 32],
            digest: [2; 32],
            session: [3; 16],
            generation: 4,
            invocation: [5; 16],
            epoch: 6,
            task_pid: 7,
            task_start: 8,
            server_pid: 9,
            server_start: 10,
            profile: PROFILE_DIGEST,
            observations,
        };
        let mut frame = encode_data_v4(
            &expected,
            &RuntimeData {
                vector: observations,
            },
            DiagnosticCounts {
                baseline: Some(4),
                current: Some(5),
            },
        )
        .unwrap();
        seal(&mut frame);
        (expected, frame)
    }
    fn seal(frame: &mut [u8; 512]) {
        frame[184..216].fill(0);
        let mut hash = Sha256::new();
        hash.update(b"yonik/fixed-self-fence/v2/local-delta1/receipt\0");
        hash.update(PROGRAM_SHA256);
        hash.update(PROFILE_DIGEST);
        hash.update(*frame);
        frame[184..216].copy_from_slice(&hash.finalize());
    }
    #[test]
    fn pure_fixed_coverage_accepts_exact_complete_report_data() {
        let (expected, frame) = fixture();
        assert_eq!(verify_fixed_report(&frame, &expected), Ok(()));
    }
    #[test]
    fn pure_fixed_coverage_rejects_absent_and_forged_reference() {
        let (expected, mut frame) = fixture();
        frame[184..216].fill(0);
        assert_eq!(
            verify_fixed_report(&frame, &expected),
            Err(Error::EvidenceUnavailable)
        );
        frame[184..216].fill(1);
        assert_eq!(verify_fixed_report(&frame, &expected), Err(Error::Binding));
    }
    #[test]
    fn pure_fixed_coverage_rejects_delta_overflow_wrong_vector_and_binding() {
        for (baseline, current) in [(0u32, 0u32), (4, 6), (u32::MAX, 0)] {
            let (expected, mut frame) = fixture();
            frame[220..224].copy_from_slice(&baseline.to_be_bytes());
            frame[224..228].copy_from_slice(&current.to_be_bytes());
            seal(&mut frame);
            assert_eq!(
                verify_fixed_report(&frame, &expected),
                Err(Error::IncompleteApplication)
            );
        }
        let (mut expected, mut frame) = fixture();
        expected.observations[0] = 2;
        frame[232..236].copy_from_slice(&2u32.to_be_bytes());
        seal(&mut frame);
        assert_eq!(
            verify_fixed_report(&frame, &expected),
            Err(Error::ObservationMismatch)
        );
        let (expected, mut frame) = fixture();
        frame[8] ^= 1;
        seal(&mut frame);
        assert_eq!(verify_fixed_report(&frame, &expected), Err(Error::Binding));
    }
}
