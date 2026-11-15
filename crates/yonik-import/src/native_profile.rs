//! Ограниченные DATA: наличие профиля не разрешает запуск или сетевые эффекты.
use crate::{FatalError, ImportFailure, Issue, ParsedServer, SecretText};
use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt, io::Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileEngine {
    Xray,
}

/// Конструктор закрыт; исходник доступен только явным чувствительным доступом.
#[derive(Debug)]
pub struct NativeProfile {
    ordinal: usize,
    name: SecretText,
    root: SecretText,
}
impl NativeProfile {
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    /// Недоверенная подпись; не использовать как identity, authority или лог.
    pub fn name(&self) -> &str {
        self.name.expose()
    }
    pub fn engine(&self) -> ProfileEngine {
        ProfileEngine::Xray
    }
    pub fn source(&self) -> &SecretText {
        &self.root
    }
    pub fn write_sensitive(&self, mut writer: impl Write) -> Result<(), std::io::Error> {
        writer.write_all(self.root.expose().as_bytes())
    }
}

#[derive(Debug)]
pub enum ProfileEntry {
    Server(ParsedServer),
    Xray(NativeProfile),
}

#[derive(Debug)]
pub struct ProfileImportReport {
    pub entries: Vec<ProfileEntry>,
    pub issues: Vec<Issue>,
    pub base64_envelope: bool,
    original: SecretText,
}
impl ProfileImportReport {
    pub fn original(&self) -> &SecretText {
        &self.original
    }
}

struct Roots<'a>(Vec<&'a RawValue>);
impl<'de> Deserialize<'de> for Roots<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Array;
        impl<'de> Visitor<'de> for Array {
            type Value = Roots<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("Массив профилей")
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                let mut roots = Vec::new();
                while let Some(raw) = seq.next_element::<&RawValue>()? {
                    if roots.len() == crate::MAX_RECORDS {
                        return Err(S::Error::custom("Лимит профилей"));
                    }
                    roots.push(raw);
                }
                Ok(Roots(roots))
            }
        }
        d.deserialize_seq(Array)
    }
}

pub fn import_profiles(bytes: Vec<u8>) -> Result<ProfileImportReport, ImportFailure> {
    if bytes.len() > crate::MAX_INPUT_BYTES {
        return Err(ImportFailure {
            kind: FatalError::TooLarge,
            input: bytes,
            complete: true,
        });
    }
    let original = String::from_utf8(bytes).map_err(|e| ImportFailure {
        kind: FatalError::InvalidUtf8,
        input: e.into_bytes(),
        complete: true,
    })?;
    match parse(&original) {
        Ok((entries, issues, base64_envelope)) => Ok(ProfileImportReport {
            entries,
            issues,
            base64_envelope,
            original: SecretText::new(original),
        }),
        Err(kind) => Err(ImportFailure {
            kind,
            input: original.into_bytes(),
            complete: true,
        }),
    }
}

type Parsed = (Vec<ProfileEntry>, Vec<Issue>, bool);
fn parse(original: &str) -> Result<Parsed, FatalError> {
    let cleaned = original.trim_start_matches('\u{feff}').trim();
    if cleaned.is_empty() {
        return Err(FatalError::Empty);
    }
    let envelope = !cleaned.starts_with(['{', '[']) && !cleaned.contains("://");
    let decoded;
    let content = if envelope {
        decoded = crate::decode::base64_text(cleaned)?;
        decoded.trim_start_matches('\u{feff}').trim()
    } else {
        cleaned
    };
    if !content.starts_with(['{', '[']) {
        if !content.contains("://") {
            return Err(FatalError::UnsupportedFormat);
        }
        // Старый URI parser сохраняет прежние diagnostics и ограничения записей.
        let report = crate::import_bytes(content.as_bytes().to_vec()).map_err(|e| e.kind())?;
        return Ok((
            report
                .servers
                .into_iter()
                .map(ProfileEntry::Server)
                .collect(),
            report.issues,
            envelope,
        ));
    }
    crate::decode::json_depth(content)?;
    let checkpoint = crate::Checkpoint {
        proceed: &|| true,
        cancelled: std::cell::Cell::new(false),
    };
    crate::json::validate_unique(content, &checkpoint).map_err(|_| FatalError::InvalidJson)?;
    let roots = if content.starts_with('[') {
        serde_json::from_str::<Roots<'_>>(content)
            .map_err(|_| FatalError::TooManyRecords)?
            .0
    } else {
        vec![serde_json::from_str::<&RawValue>(content).map_err(|_| FatalError::InvalidJson)?]
    };
    if roots.is_empty() {
        return Err(FatalError::Empty);
    }
    let mut captured = 0usize;
    let mut entries = Vec::new();
    for (ordinal, raw) in roots.into_iter().enumerate() {
        captured = captured
            .checked_add(raw.get().len())
            .ok_or(FatalError::TooLarge)?;
        if raw.get().len() > crate::MAX_ENTRY_BYTES || captured > crate::MAX_DECODED_BYTES {
            return Err(FatalError::TooLarge);
        }
        let object: BTreeMap<String, &RawValue> =
            serde_json::from_str(raw.get()).map_err(|_| FatalError::UnsupportedFormat)?;
        let outbounds = object
            .get("outbounds")
            .ok_or(FatalError::UnsupportedFormat)?;
        let nodes = serde_json::from_str::<Roots<'_>>(outbounds.get())
            .map_err(|_| FatalError::UnsupportedFormat)?
            .0;
        if nodes.is_empty() {
            return Err(FatalError::UnsupportedFormat);
        }
        for node in nodes {
            let fields: BTreeMap<String, &RawValue> =
                serde_json::from_str(node.get()).map_err(|_| FatalError::UnsupportedFormat)?;
            if fields.contains_key("type")
                || !fields.get("protocol").is_some_and(|v| {
                    serde_json::from_str::<&str>(v.get()).is_ok_and(|s| !s.is_empty())
                })
            {
                return Err(FatalError::UnsupportedFormat);
            }
        }
        let name = object
            .get("remarks")
            .or_else(|| object.get("tag"))
            .and_then(|r| serde_json::from_str::<String>(r.get()).ok())
            .unwrap_or_default()
            .chars()
            .filter(|c| !c.is_control())
            .take(160)
            .collect();
        entries.push(ProfileEntry::Xray(NativeProfile {
            ordinal,
            name: SecretText::new(name),
            root: SecretText::new(raw.get().to_owned()),
        }));
    }
    Ok((entries, Vec::new(), envelope))
}
