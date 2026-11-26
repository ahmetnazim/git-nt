use nt_read::{DEFAULT_MAX_RECORDS, HARD_MAX_RECORDS};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The sole MCP tool exposed by `git-nt mcp` (Layer 4 read-only invariant).
pub const TOOL_NAME: &str = "nt_hydrate_file";

/// Hard ceiling (`64 KiB`) on a single incoming JSON-RPC 2.0 stdio line.
pub const MAX_JSONRPC_LINE_BYTES: usize = 64 * 1024;

/// Default MCP protocol version advertised when client requests an unrecognized version
/// (latest supported revision per MCP negotiation rules).
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-11-25";

/// MCP protocol revisions supported by this server.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];

/// Standard JSON-RPC 2.0 error codes.
pub const ERR_PARSE: i64 = -32700;
pub const ERR_INVALID_REQUEST: i64 = -32600;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
pub const ERR_INVALID_PARAMS: i64 = -32602;

/// Strict deserialization schema for `nt_hydrate_file` arguments (`deny_unknown_fields`
/// blocks untrusted overrides such as `include_untrusted` or `trusted_ref`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HydrateFileArgs {
    pub file_path: String,
    #[serde(default)]
    pub max_records: Option<usize>,
}

/// Outgoing JSON-RPC 2.0 response frame (serialized as single-line JSON + `\n`).
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// Returns the strictly read-only tool catalog (`len == 1`: `nt_hydrate_file` only).
pub fn tool_definitions() -> Vec<Value> {
    vec![json!({
        "name": TOOL_NAME,
        "description": "Read-only hydration of trusted mainline Negative-Space tombstones for a repo-relative file path, wrapped in a fresh 128-bit CSPRNG Spotlighting envelope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Repo-relative POSIX file path to hydrate (e.g. 'src/tile_cache.rs'). Absolute paths, '..', and symlink escapes are rejected."
                },
                "max_records": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": HARD_MAX_RECORDS,
                    "default": DEFAULT_MAX_RECORDS,
                    "description": "Optional maximum active tombstones to return (default 15, hard server ceiling 50)."
                }
            },
            "required": ["file_path"],
            "additionalProperties": false
        },
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": false,
            "openWorldHint": false
        }
    })]
}

/// Negotiates an MCP protocol version cleanly from the client's `initialize` params.
pub fn negotiate_protocol_version(params: Option<&Value>) -> &'static str {
    let requested = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str);

    if let Some(req) = requested {
        for &supported in SUPPORTED_PROTOCOL_VERSIONS {
            if supported == req {
                return supported;
            }
        }
    }

    DEFAULT_PROTOCOL_VERSION
}
