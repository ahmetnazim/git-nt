#![forbid(unsafe_code)]

//! Strictly read-only JSON-RPC 2.0 `stdio` Model Context Protocol (MCP) server (Layer 4).
//!
//! Compile-time isolation invariant: this crate depends ONLY on `nt-core` and `nt-read`
//! (never `nt-write`) and exposes strictly one tool: `nt_hydrate_file`.

pub mod error;
pub mod protocol;
pub mod server;

pub use error::McpError;
pub use protocol::{
    DEFAULT_PROTOCOL_VERSION, MAX_JSONRPC_LINE_BYTES, SUPPORTED_PROTOCOL_VERSIONS, TOOL_NAME,
    tool_definitions,
};
pub use server::{handle_raw_line, serve_stdio};
