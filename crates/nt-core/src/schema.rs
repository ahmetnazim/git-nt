use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::id::{generate_uuid_v7, is_valid_rfc3339_utc, is_valid_uuid_v7, now_rfc3339_utc};
use crate::jcs::{is_valid_sha256_digest, to_jcs_bytes};
use crate::path::{normalize_repo_path, normalize_repo_paths};
use crate::sanitize::{MAX_FIELD_SCALARS, sanitize_field};

/// Current canonical Negative-Space schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Strict byte ceiling for a single persisted canonical JCS tombstone (`< 1.5 KiB`).
pub const MAX_RECORD_BYTES: usize = 1_536;

/// Closed enumeration of Negative-Space failure classes (enforced on write and hydration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureClass {
    ConcurrencyDeadlock,
    NumericalInstability,
    MemorySafety,
    PerformanceRegression,
    SecurityBoundary,
    ApiContractViolation,
    ResourceLeak,
    DataCorruption,
}

impl FailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConcurrencyDeadlock => "CONCURRENCY_DEADLOCK",
            Self::NumericalInstability => "NUMERICAL_INSTABILITY",
            Self::MemorySafety => "MEMORY_SAFETY",
            Self::PerformanceRegression => "PERFORMANCE_REGRESSION",
            Self::SecurityBoundary => "SECURITY_BOUNDARY",
            Self::ApiContractViolation => "API_CONTRACT_VIOLATION",
            Self::ResourceLeak => "RESOURCE_LEAK",
            Self::DataCorruption => "DATA_CORRUPTION",
        }
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FailureClass {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CONCURRENCY_DEADLOCK" => Ok(Self::ConcurrencyDeadlock),
            "NUMERICAL_INSTABILITY" => Ok(Self::NumericalInstability),
            "MEMORY_SAFETY" => Ok(Self::MemorySafety),
            "PERFORMANCE_REGRESSION" => Ok(Self::PerformanceRegression),
            "SECURITY_BOUNDARY" => Ok(Self::SecurityBoundary),
            "API_CONTRACT_VIOLATION" => Ok(Self::ApiContractViolation),
            "RESOURCE_LEAK" => Ok(Self::ResourceLeak),
            "DATA_CORRUPTION" => Ok(Self::DataCorruption),
            other => Err(CoreError::UnknownFailureClass(other.to_owned())),
        }
    }
}

/// Lifecycle status of a Negative-Space tombstone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordStatus {
    Active,
    Retired,
}

impl RecordStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

impl fmt::Display for RecordStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RecordStatus {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "retired" => Ok(Self::Retired),
            other => Err(CoreError::UnknownRecordStatus(other.to_owned())),
        }
    }
}

/// Canonical Negative-Space tombstone record persisted at `.nt/ns/{id}.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeSpaceRecord {
    pub schema_version: u32,
    pub id: String,
    pub created_at: String,
    pub files: Vec<String>,
    pub target_symbol: String,
    pub failure_class: FailureClass,
    pub discarded_pattern: String,
    pub invariant: String,
    pub status: RecordStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_think_digest: Option<String>,
}

impl NegativeSpaceRecord {
    /// Constructs a new active, L2-sanitized, path-normalized tombstone with a fresh UUIDv7
    /// and UTC RFC 3339 timestamp, validating all invariants including the `< 1,536`-byte ceiling.
    pub fn new_sanitized<I, S>(
        files: I,
        target_symbol: &str,
        failure_class: FailureClass,
        discarded_pattern: &str,
        invariant: &str,
        supersedes: Option<String>,
        local_think_digest: Option<String>,
    ) -> Result<Self, CoreError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let record = Self {
            schema_version: SCHEMA_VERSION,
            id: generate_uuid_v7()?,
            created_at: now_rfc3339_utc()?,
            files: normalize_repo_paths(files)?,
            target_symbol: sanitize_field(target_symbol),
            failure_class,
            discarded_pattern: sanitize_field(discarded_pattern),
            invariant: sanitize_field(invariant),
            status: RecordStatus::Active,
            supersedes,
            local_think_digest,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates all structural, identifier, path, field-length, digest, and byte-ceiling invariants.
    pub fn validate(&self) -> Result<(), CoreError> {
        let _ = self.validate_and_encode()?;
        Ok(())
    }

    /// Validates and serializes this tombstone to deterministic RFC 8785 JCS UTF-8 bytes.
    pub fn to_jcs_bytes(&self) -> Result<Vec<u8>, CoreError> {
        self.validate_and_encode()
    }

    fn validate_and_encode(&self) -> Result<Vec<u8>, CoreError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CoreError::InvalidSchemaVersion {
                expected: SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        if !is_valid_uuid_v7(&self.id) {
            return Err(CoreError::InvalidUuid(self.id.clone()));
        }
        if !is_valid_rfc3339_utc(&self.created_at) {
            return Err(CoreError::InvalidTimestamp(self.created_at.clone()));
        }
        if self.files.is_empty() {
            return Err(CoreError::EmptyFiles);
        }
        for file in &self.files {
            let normalized = normalize_repo_path(file)?;
            if normalized != *file {
                return Err(CoreError::InvalidPath {
                    path: file.clone(),
                    reason: "path is not in normalized canonical form",
                });
            }
        }
        if !self.files.windows(2).all(|w| w[0] < w[1]) {
            return Err(CoreError::NonCanonicalFiles);
        }

        validate_text_field("target_symbol", &self.target_symbol)?;
        validate_text_field("discarded_pattern", &self.discarded_pattern)?;
        validate_text_field("invariant", &self.invariant)?;

        if let Some(ref sup) = self.supersedes {
            if !is_valid_uuid_v7(sup) {
                return Err(CoreError::InvalidUuid(sup.clone()));
            }
            if sup == &self.id {
                return Err(CoreError::SelfSupersedes(self.id.clone()));
            }
        }

        if let Some(ref digest) = self.local_think_digest
            && !is_valid_sha256_digest(digest)
        {
            return Err(CoreError::InvalidDigest(digest.clone()));
        }

        let jcs_bytes = to_jcs_bytes(self)?;
        if jcs_bytes.len() >= MAX_RECORD_BYTES {
            return Err(CoreError::RecordTooLarge {
                bytes: jcs_bytes.len(),
                max: MAX_RECORD_BYTES,
            });
        }

        Ok(jcs_bytes)
    }

    /// Strictly parses and validates a tombstone from JSON/JCS bytes, enforcing `< 1,536` bytes.
    pub fn from_jcs_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() >= MAX_RECORD_BYTES {
            return Err(CoreError::RecordTooLarge {
                bytes: bytes.len(),
                max: MAX_RECORD_BYTES,
            });
        }
        let record: Self = serde_json::from_slice(bytes)?;
        record.validate()?;
        Ok(record)
    }
}

fn validate_text_field(field: &'static str, value: &str) -> Result<(), CoreError> {
    if value.trim().is_empty() {
        return Err(CoreError::EmptyField(field));
    }
    let scalars = value.chars().count();
    if scalars > MAX_FIELD_SCALARS {
        return Err(CoreError::FieldTooLong {
            field,
            scalars,
            max: MAX_FIELD_SCALARS,
        });
    }
    Ok(())
}
