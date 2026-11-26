use thiserror::Error;

/// Transport-level I/O errors returned by `nt-mcp`.
#[derive(Debug, Error)]
pub enum McpError {
    #[error("stdio read error: {0}")]
    ReadIo(#[source] std::io::Error),

    #[error("stdio write error: {0}")]
    WriteIo(#[source] std::io::Error),
}
