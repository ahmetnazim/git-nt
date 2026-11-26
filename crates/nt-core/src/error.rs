use thiserror::Error;

/// Errors returned by `nt-core` validation, canonicalization, and security primitives.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("unsupported schema_version: expected {expected}, got {actual}")]
    InvalidSchemaVersion { expected: u32, actual: u32 },

    #[error("invalid UUIDv7 identifier: '{0}'")]
    InvalidUuid(String),

    #[error("invalid RFC 3339 UTC timestamp: '{0}'")]
    InvalidTimestamp(String),

    #[error("invalid repo-relative path '{path}': {reason}")]
    InvalidPath { path: String, reason: &'static str },

    #[error("files array must contain at least one repo-relative path")]
    EmptyFiles,

    #[error("files array must be strictly sorted and deduplicated")]
    NonCanonicalFiles,

    #[error("required field '{0}' must not be empty")]
    EmptyField(&'static str),

    #[error("field '{field}' exceeds {max} Unicode scalar values (got {scalars})")]
    FieldTooLong {
        field: &'static str,
        scalars: usize,
        max: usize,
    },

    #[error("invalid sha256 digest format: '{0}'")]
    InvalidDigest(String),

    #[error("record '{0}' cannot supersede itself")]
    SelfSupersedes(String),

    #[error("canonical record size {bytes} bytes meets or exceeds {max}-byte ceiling")]
    RecordTooLarge { bytes: usize, max: usize },

    #[error("non-finite floating-point numbers (NaN/Infinity) are forbidden in RFC 8785 JCS")]
    NonFiniteNumber,

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("OS CSPRNG failure: {0}")]
    Randomness(String),

    #[error("unknown failure_class variant: '{0}'")]
    UnknownFailureClass(String),

    #[error("unknown record status: '{0}'")]
    UnknownRecordStatus(String),

    #[error("system clock precedes Unix epoch or exceeds year 9999")]
    ClockError,
}
