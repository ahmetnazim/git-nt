use std::io::{BufRead, ErrorKind, Write};

use nt_core::sanitize_field;
use nt_read::{RepoReader, hydrate_file_trusted_only};
use serde_json::{Value, json};

use crate::error::McpError;
use crate::protocol::{
    ERR_INVALID_PARAMS, ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, ERR_PARSE, HydrateFileArgs,
    JsonRpcResponse, MAX_JSONRPC_LINE_BYTES, TOOL_NAME, negotiate_protocol_version,
    tool_definitions,
};

enum LineRead {
    Eof,
    Line(Vec<u8>),
    Oversized,
}

/// Reads a single newline-delimited frame from `input` without ever allocating more than
/// `MAX_JSONRPC_LINE_BYTES`. Oversized lines are drained cleanly through the next `\n` (or EOF).
fn read_bounded_line<R: BufRead>(input: &mut R) -> Result<LineRead, McpError> {
    let mut buf = Vec::new();
    let mut oversized = false;

    loop {
        let available = match input.fill_buf() {
            Ok(slice) => slice,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(McpError::ReadIo(err)),
        };

        if available.is_empty() {
            if oversized {
                return Ok(LineRead::Oversized);
            }
            if buf.is_empty() {
                return Ok(LineRead::Eof);
            }
            return Ok(LineRead::Line(buf));
        }

        if let Some(nl_pos) = available.iter().position(|&b| b == b'\n') {
            if !oversized {
                let chunk = &available[..nl_pos];
                if buf.len().saturating_add(chunk.len()) > MAX_JSONRPC_LINE_BYTES {
                    oversized = true;
                    buf.clear();
                } else {
                    buf.extend_from_slice(chunk);
                }
            }
            input.consume(nl_pos + 1);
            if oversized {
                return Ok(LineRead::Oversized);
            }
            if buf.ends_with(b"\r") {
                buf.pop();
            }
            return Ok(LineRead::Line(buf));
        }

        let len = available.len();
        if !oversized {
            if buf.len().saturating_add(len) > MAX_JSONRPC_LINE_BYTES {
                oversized = true;
                buf.clear();
            } else {
                buf.extend_from_slice(available);
            }
        }
        input.consume(len);
    }
}

/// Runs the strictly read-only newline-delimited JSON-RPC 2.0 MCP server loop until EOF.
///
/// - Writes ONLY single-line JSON-RPC 2.0 responses to `output` and flushes after every frame.
/// - Writes ALL diagnostics strictly to `diag` (`stderr`), never to `output` (`stdout`).
/// - Never panics on malformed, oversized, or adversarial client messages.
pub fn serve_stdio<R, W, E>(
    reader: &dyn RepoReader,
    mut input: R,
    mut output: W,
    mut diag: E,
) -> Result<(), McpError>
where
    R: BufRead,
    W: Write,
    E: Write,
{
    loop {
        match read_bounded_line(&mut input)? {
            LineRead::Eof => return Ok(()),
            LineRead::Oversized => {
                let _ = writeln!(
                    diag,
                    "[nt-mcp] rejected oversized JSON-RPC frame (> {MAX_JSONRPC_LINE_BYTES} bytes)"
                );
                let resp = JsonRpcResponse::err(
                    Value::Null,
                    ERR_INVALID_REQUEST,
                    format!("request exceeds {MAX_JSONRPC_LINE_BYTES}-byte line limit"),
                );
                if !write_response(&mut output, &resp)? {
                    return Ok(());
                }
            }
            LineRead::Line(bytes) => {
                if bytes.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                if let Some(resp) = handle_raw_line(reader, &bytes, &mut diag)
                    && !write_response(&mut output, &resp)?
                {
                    return Ok(());
                }
            }
        }
    }
}

/// Writes a single newline-delimited JSON-RPC frame and flushes immediately.
/// Returns `Ok(false)` on `ErrorKind::BrokenPipe` so host disconnects terminate cleanly.
fn write_response<W: Write>(output: &mut W, resp: &JsonRpcResponse) -> Result<bool, McpError> {
    let encoded = serde_json::to_vec(resp).unwrap_or_else(|_| {
        br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"response serialization error"}}"#
            .to_vec()
    });
    for res in [
        output.write_all(&encoded),
        output.write_all(b"\n"),
        output.flush(),
    ] {
        match res {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::BrokenPipe => return Ok(false),
            Err(err) => return Err(McpError::WriteIo(err)),
        }
    }
    Ok(true)
}

/// Processes a single raw JSON-RPC 2.0 line and returns `Some(response)` for requests
/// or `None` for notifications (messages omitting `"id"`). Never panics.
pub fn handle_raw_line<E: Write>(
    reader: &dyn RepoReader,
    raw_line: &[u8],
    diag: &mut E,
) -> Option<JsonRpcResponse> {
    let Ok(text) = std::str::from_utf8(raw_line) else {
        let _ = writeln!(diag, "[nt-mcp] invalid UTF-8 in JSON-RPC request");
        return Some(JsonRpcResponse::err(
            Value::Null,
            ERR_PARSE,
            "Parse error: invalid UTF-8",
        ));
    };

    let value: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(err) => {
            let _ = writeln!(diag, "[nt-mcp] JSON parse error: {err}");
            return Some(JsonRpcResponse::err(
                Value::Null,
                ERR_PARSE,
                "Parse error: malformed JSON",
            ));
        }
    };

    let Some(obj) = value.as_object() else {
        return Some(JsonRpcResponse::err(
            Value::Null,
            ERR_INVALID_REQUEST,
            "Invalid Request: JSON-RPC message must be a JSON object",
        ));
    };

    // Per JSON-RPC 2.0 §4, `id` (when present) MUST be a String, integer Number, or Null.
    let maybe_id = match obj.get("id") {
        None => None,
        Some(id_val) if is_valid_jsonrpc_id(id_val) => Some(id_val.clone()),
        Some(_) => {
            return Some(JsonRpcResponse::err(
                Value::Null,
                ERR_INVALID_REQUEST,
                "Invalid Request: 'id' must be a string, integer, or null",
            ));
        }
    };

    let is_v2 = obj
        .get("jsonrpc")
        .and_then(Value::as_str)
        .is_some_and(|v| v == "2.0");
    if !is_v2 {
        return Some(JsonRpcResponse::err(
            maybe_id.unwrap_or(Value::Null),
            ERR_INVALID_REQUEST,
            "Invalid Request: 'jsonrpc' must be \"2.0\"",
        ));
    }

    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return Some(JsonRpcResponse::err(
            maybe_id.unwrap_or(Value::Null),
            ERR_INVALID_REQUEST,
            "Invalid Request: missing string 'method'",
        ));
    };

    let params = obj.get("params");

    // Notifications omit `"id"` and MUST NOT emit a response frame.
    let Some(id) = maybe_id else {
        if !matches!(
            method,
            "notifications/initialized" | "notifications/cancelled"
        ) {
            let _ = writeln!(
                diag,
                "[nt-mcp] ignored unknown notification '{}'",
                sanitize_field(method)
            );
        }
        return None;
    };

    match method {
        "initialize" => Some(handle_initialize(id, params)),
        "ping" => Some(JsonRpcResponse::ok(id, json!({}))),
        "tools/list" => Some(JsonRpcResponse::ok(
            id,
            json!({ "tools": tool_definitions() }),
        )),
        "tools/call" => Some(handle_tools_call(reader, id, params, diag)),
        other => {
            let _ = writeln!(
                diag,
                "[nt-mcp] method not found: '{}'",
                sanitize_field(other)
            );
            Some(JsonRpcResponse::err(
                id,
                ERR_METHOD_NOT_FOUND,
                format!("Method not found: {}", sanitize_field(other)),
            ))
        }
    }
}

fn is_valid_jsonrpc_id(v: &Value) -> bool {
    match v {
        Value::Null | Value::String(_) => true,
        Value::Number(n) => n.is_i64() || n.is_u64(),
        _ => false,
    }
}

fn handle_initialize(id: Value, params: Option<&Value>) -> JsonRpcResponse {
    if let Some(p) = params
        && !p.is_object()
    {
        return JsonRpcResponse::err(
            id,
            ERR_INVALID_PARAMS,
            "Invalid params: 'initialize' params must be an object",
        );
    }

    let protocol_version = negotiate_protocol_version(params);
    JsonRpcResponse::ok(
        id,
        json!({
            "protocolVersion": protocol_version,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "git-nt",
                "version": env!("CARGO_PKG_VERSION")
            }
        }),
    )
}

fn handle_tools_call<E: Write>(
    reader: &dyn RepoReader,
    id: Value,
    params: Option<&Value>,
    diag: &mut E,
) -> JsonRpcResponse {
    let Some(params_obj) = params.and_then(Value::as_object) else {
        return JsonRpcResponse::err(
            id,
            ERR_INVALID_PARAMS,
            "Invalid params: 'tools/call' requires an object params payload",
        );
    };

    let Some(tool_name) = params_obj.get("name").and_then(Value::as_str) else {
        return JsonRpcResponse::err(
            id,
            ERR_INVALID_PARAMS,
            "Invalid params: missing string 'name'",
        );
    };

    // Enforce Layer 4 single-tool surface strictly.
    if tool_name != TOOL_NAME {
        let safe_name = sanitize_field(tool_name);
        let _ = writeln!(diag, "[nt-mcp] rejected disallowed tool call '{safe_name}'");
        return JsonRpcResponse::err(
            id,
            ERR_INVALID_PARAMS,
            format!("Unknown or disallowed tool '{safe_name}'; only '{TOOL_NAME}' is registered"),
        );
    }

    let raw_args = match params_obj.get("arguments") {
        Some(v) if v.is_object() => v.clone(),
        _ => {
            return JsonRpcResponse::err(
                id,
                ERR_INVALID_PARAMS,
                "Invalid params: 'arguments' must be an object",
            );
        }
    };

    let args: HydrateFileArgs = match serde_json::from_value(raw_args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let safe_err = sanitize_field(&err.to_string());
            let _ = writeln!(diag, "[nt-mcp] invalid tool arguments: {safe_err}");
            return JsonRpcResponse::err(
                id,
                ERR_INVALID_PARAMS,
                format!("Invalid arguments for '{TOOL_NAME}': {safe_err}"),
            );
        }
    };

    if args.max_records == Some(0) {
        return JsonRpcResponse::err(
            id,
            ERR_INVALID_PARAMS,
            "Invalid arguments: 'max_records' must be >= 1",
        );
    }

    // Hardcoded trusted-tree-only hydration (`include_untrusted = false`, no ref override).
    match hydrate_file_trusted_only(reader, &args.file_path, args.max_records) {
        Ok(res) => JsonRpcResponse::ok(
            id,
            json!({
                "content": [
                    {
                        "type": "text",
                        "text": res.spotlighted_output
                    }
                ],
                "isError": false
            }),
        ),
        Err(err) => {
            let safe_err = sanitize_field(&err.to_string());
            let _ = writeln!(diag, "[nt-mcp] hydration error: {safe_err}");
            JsonRpcResponse::ok(
                id,
                json!({
                    "content": [
                        {
                            "type": "text",
                            "text": format!("error: {safe_err}")
                        }
                    ],
                    "isError": true
                }),
            )
        }
    }
}
