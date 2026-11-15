//! Ограниченный импорт, не выполняющий загрузку, сохранение или активацию профилей.

mod decode;
mod identity;
mod intent;
mod json;
mod model;
mod native_profile;
mod singbox;
mod uri;
mod xray;

pub use identity::{IdentityError, SecretIdentity};
pub use intent::{IntentError, ServerIntent};
pub use model::{
    Credentials, Endpoint, FatalError, Field, ImportFailure, ImportReport, Issue, IssueCode,
    ParsedServer, Protocol, ReviewFlag, SecretText, Security, Transport,
};
pub use native_profile::{
    NativeProfile, ProfileEngine, ProfileEntry, ProfileImportReport, import_profiles,
};
use std::io::Read;

pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DECODED_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RECORDS: usize = 20_000;
pub const MAX_ENTRY_BYTES: usize = 64 * 1024;
pub const MAX_JSON_DEPTH: usize = 64;

pub fn import_reader(reader: impl Read) -> Result<ImportReport, ImportFailure> {
    let mut bytes = Vec::new();
    // Ошибка IO может содержать секретный URL/путь; наружу идёт только категория.
    if reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return Err(ImportFailure {
            kind: FatalError::Io,
            input: bytes,
            complete: false,
        });
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ImportFailure {
            kind: FatalError::TooLarge,
            input: bytes,
            complete: false,
        });
    }
    import_bytes(bytes)
}

/// Ошибка нового API: совместимый ImportFailure не меняет контракт.
#[derive(Debug)]
pub enum CancellableImportError {
    Cancelled,
    Import(ImportFailure),
}

impl std::fmt::Display for CancellableImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Импорт отменён"),
            Self::Import(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for CancellableImportError {}

pub(crate) struct Checkpoint<'a> {
    proceed: &'a dyn Fn() -> bool,
    cancelled: std::cell::Cell<bool>,
}
impl Checkpoint<'_> {
    pub(crate) fn check(&self) -> Result<(), FatalError> {
        if self.cancelled.get() || !(self.proceed)() {
            self.cancelled.set(true);
            Err(FatalError::Io)
        } else {
            Ok(())
        }
    }
}

/// Callback возвращает false при отмене. Отмена не публикует частичный отчёт.
pub fn import_bytes_cancellable(
    bytes: Vec<u8>,
    proceed: impl Fn() -> bool,
) -> Result<ImportReport, CancellableImportError> {
    let checkpoint = Checkpoint {
        proceed: &proceed,
        cancelled: std::cell::Cell::new(false),
    };
    let result = import_bytes_checked(bytes, &checkpoint);
    if checkpoint.cancelled.get() {
        Err(CancellableImportError::Cancelled)
    } else {
        result.map_err(CancellableImportError::Import)
    }
}

pub fn import_bytes(bytes: Vec<u8>) -> Result<ImportReport, ImportFailure> {
    import_bytes_checked(
        bytes,
        &Checkpoint {
            proceed: &|| true,
            cancelled: std::cell::Cell::new(false),
        },
    )
}

fn import_bytes_checked(
    bytes: Vec<u8>,
    checkpoint: &Checkpoint<'_>,
) -> Result<ImportReport, ImportFailure> {
    if checkpoint.check().is_err() {
        return Err(ImportFailure {
            kind: FatalError::Io,
            input: bytes,
            complete: true,
        });
    }

    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ImportFailure {
            kind: FatalError::TooLarge,
            input: bytes,
            complete: true,
        });
    }
    let original = String::from_utf8(bytes).map_err(|error| ImportFailure {
        kind: FatalError::InvalidUtf8,
        input: error.into_bytes(),
        complete: true,
    })?;
    match parse_text(&original, checkpoint) {
        Ok(parsed) => Ok(ImportReport {
            servers: parsed.servers,
            issues: parsed.issues,
            native_json: parsed.native_json,
            base64_envelope: parsed.base64_envelope,
            original: SecretText::new(original),
        }),
        Err(kind) => Err(ImportFailure {
            kind,
            input: original.into_bytes(),
            complete: true,
        }),
    }
}

struct ParsedBody {
    servers: Vec<ParsedServer>,
    issues: Vec<Issue>,
    native_json: Option<SecretText>,
    base64_envelope: bool,
}

fn parse_text(original: &str, checkpoint: &Checkpoint<'_>) -> Result<ParsedBody, FatalError> {
    checkpoint.check()?;
    let cleaned = original.trim_start_matches('\u{feff}').trim();
    if cleaned.is_empty() {
        return Err(FatalError::Empty);
    }
    let base64_envelope = !cleaned.contains("://") && !cleaned.starts_with(['{', '[']);
    let decoded;
    let content = if base64_envelope {
        decoded = decode::base64_text_checked(cleaned, checkpoint)?;
        decoded.trim_start_matches('\u{feff}')
    } else {
        original.trim_start_matches('\u{feff}')
    };
    if content.trim().is_empty() {
        return Err(FatalError::Empty);
    }
    let mut servers = Vec::new();
    let mut issues = Vec::new();
    let native_json = if content.trim_start().starts_with(['{', '[']) {
        decode::json_depth_checked(content, checkpoint)?;
        // RawValue проверяет синтаксис без построения произвольного дерева Value.
        serde_json::from_str::<&serde_json::value::RawValue>(content)
            .map_err(|_| FatalError::InvalidJson)?;
        json::validate_unique(content, checkpoint).map_err(|_| FatalError::InvalidJson)?;
        checkpoint.check()?;
        xray::extract(content, &mut servers, &mut issues, checkpoint)?;
        Some(SecretText::new(content.to_owned()))
    } else {
        if !content.contains("://") {
            return Err(FatalError::UnsupportedFormat);
        }
        let mut records = 0;
        for (index, line) in content.lines().enumerate() {
            checkpoint.check()?;
            let text = line.trim();
            if text.is_empty() {
                continue;
            }
            records += 1;
            if records > MAX_RECORDS {
                return Err(FatalError::TooManyRecords);
            }
            match uri::parse(text) {
                Ok(server) => servers.push(server),
                Err((code, field)) => issues.push(Issue {
                    line: index + 1,
                    code,
                    field,
                }),
            }
        }
        None
    };
    checkpoint.check()?;
    Ok(ParsedBody {
        servers,
        issues,
        native_json,
        base64_envelope,
    })
}
