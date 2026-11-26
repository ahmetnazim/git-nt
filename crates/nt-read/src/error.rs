use std::path::PathBuf;

use thiserror::Error;

/// Errors returned by strictly read-only `nt-read` operations.
#[derive(Debug, Error)]
pub enum ReadError {
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

    #[error("invalid Git reference '{ref_name}': {reason}")]
    InvalidRef {
        ref_name: String,
        reason: &'static str,
    },

    #[error("trusted ref '{0}' does not exist or does not resolve to a commit")]
    TrustedRefNotFound(String),

    #[error("symlink at '{path}' escapes repository root or is dangling")]
    SymlinkEscape { path: PathBuf },

    #[error("git read command '{command}' failed (exit {code:?}): {stderr}")]
    GitCommandFailed {
        command: String,
        code: Option<i32>,
        stderr: String,
    },
}

impl ReadError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
