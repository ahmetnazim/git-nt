use std::path::PathBuf;

use thiserror::Error;

/// Errors returned by `nt-write` staging, promotion, commit, retirement, and audit operations.
#[derive(Debug, Error)]
pub enum WriteError {
    #[error(transparent)]
    Core(#[from] nt_core::CoreError),

    #[error("I/O error at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("directory '{0}' is not inside a Git work tree")]
    NotAGitRepo(PathBuf),

    #[error("git command '{command}' failed (exit {code:?}): {stderr}")]
    GitCommandFailed {
        command: String,
        code: Option<i32>,
        stderr: String,
    },

    #[error(
        "secret pattern detected in field '{field}'; refusing to stage (pass --redact-secrets to override)"
    )]
    SecretDetected { field: &'static str },

    #[error("invalid JSON input for stage request: {0}")]
    InvalidStageJson(#[from] serde_json::Error),

    #[error("path '{path}' is not a regular file: {reason}")]
    NotARegularFile { path: PathBuf, reason: &'static str },

    #[error("tombstone '{0}' not found in .nt/ns/")]
    TombstoneNotFound(String),

    #[error("tombstone '{0}' is already retired")]
    AlreadyRetired(String),

    #[error("staged file '{path}' failed integrity check: {reason}")]
    CorruptStagedFile { path: PathBuf, reason: String },

    #[error("unsupported `git commit` arguments for `git nt commit`: {reason}")]
    UnsupportedCommitArgs { reason: String },

    #[error("native `git commit` exited with {code:?}; promoted tombstones rolled back: {stderr}")]
    CommitFailed { code: Option<i32>, stderr: String },
}

impl WriteError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
