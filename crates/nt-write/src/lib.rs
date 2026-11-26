#![forbid(unsafe_code)]

//! Lock-free atomic staging (`.git/nt-stage/`), atomic claim & diff-filtered promotion
//! (`.nt/ns/`), native `git commit` wrapper, tombstone retirement, and repository audit.

pub mod audit;
pub mod error;
pub mod promote;
pub mod repo;
pub mod retire;
pub mod stage;

pub use audit::{AuditFinding, AuditReport, audit_repository};
pub use error::WriteError;
pub use promote::{
    CommitOptions, CommitReport, PromoteOptions, PromoteReport, commit_with_options,
    commit_with_tombstones, promote_staged,
};
pub use repo::{RepoPaths, resolve_repo_paths};
pub use retire::{RetireMode, RetireOutcome, retire_tombstone};
pub use stage::{
    StageRequest, StagedArtifact, hash_think_file_streaming, list_staged_files,
    parse_stage_request_json, stage_record,
};
