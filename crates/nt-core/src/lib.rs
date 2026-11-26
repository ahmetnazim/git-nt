#![forbid(unsafe_code)]

//! Core schema types, identifiers, RFC 8785 JCS canonicalization,
//! Layer 2 deterministic sanitizer, and Layer 3 CSPRNG Spotlighting for `git-nt`.

pub mod error;
pub mod id;
pub mod jcs;
pub mod path;
pub mod sanitize;
pub mod schema;
pub mod spotlight;

pub use error::CoreError;
pub use id::{
    format_rfc3339_utc, generate_uuid_v7, is_valid_rfc3339_utc, is_valid_uuid, is_valid_uuid_v7,
    now_rfc3339_utc,
};
pub use jcs::{
    format_jcs_f64, hex_encode_lower, is_valid_sha256_digest, sha256_digest, to_jcs_bytes,
    value_to_jcs_bytes,
};
pub use path::{normalize_repo_path, normalize_repo_paths};
pub use sanitize::{MAX_FIELD_SCALARS, contains_secret, sanitize_field};
pub use schema::{
    FailureClass, MAX_RECORD_BYTES, NegativeSpaceRecord, RecordStatus, SCHEMA_VERSION,
};
pub use spotlight::{SPOTLIGHT_HEADER, spotlight_wrap};
