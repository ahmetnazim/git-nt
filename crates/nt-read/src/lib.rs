#![forbid(unsafe_code)]

//! Strictly read-only Git tree reader (`RepoReader`), Layer 1 Trust Gate,
//! and Layers 1–3 Negative-Space hydration pipeline for `git-nt`.

pub mod config;
pub mod error;
pub mod hydrate;
pub mod reader;

pub use config::{TrustConfig, validate_commit_oid, validate_ref_name};
pub use error::ReadError;
pub use hydrate::{
    DEFAULT_MAX_RECORDS, HARD_MAX_RECORDS, HydrateOptions, HydrationRecord, HydrationResult,
    MAX_HYDRATED_BYTES, hydrate_file, hydrate_file_trusted_only, validate_target_file_path,
};
pub use reader::{NativeGitReader, RawTreeBlob, RepoReader, TrustedTreeSnapshot};
