use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use nt_core::{FailureClass, NegativeSpaceRecord, contains_secret, hex_encode_lower};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::WriteError;
use crate::repo::{atomic_write_json_event, resolve_repo_paths};

/// Input payload for staging a new Negative-Space tombstone (via CLI flags or `--from-json`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageRequest {
    pub files: Vec<String>,
    pub target_symbol: String,
    pub failure_class: FailureClass,
    pub discarded_pattern: String,
    pub invariant: String,
    #[serde(default)]
    pub supersedes: Option<String>,
    #[serde(default)]
    pub think_file: Option<PathBuf>,
}

/// Result of atomically staging a Negative-Space tombstone in `.git/nt-stage/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedArtifact {
    pub record: NegativeSpaceRecord,
    pub staged_path: PathBuf,
}

/// Parses a single `StageRequest` JSON document (used by `git nt stage --from-json`).
pub fn parse_stage_request_json(json_bytes: &[u8]) -> Result<StageRequest, WriteError> {
    let req: StageRequest = serde_json::from_slice(json_bytes)?;
    Ok(req)
}

/// Computes a streaming `"sha256:<64 lowercase hex>"` digest over a local regular `<think>` file
/// in fixed 8 KiB chunks without ever loading or copying the raw file into Git storage.
pub fn hash_think_file_streaming(path: &Path) -> Result<String, WriteError> {
    let meta = fs::metadata(path).map_err(|e| WriteError::io(path, e))?;
    if !meta.file_type().is_file() {
        return Err(WriteError::NotARegularFile {
            path: path.to_path_buf(),
            reason: "think_file must be a regular file (FIFOs/devices/directories are forbidden)",
        });
    }

    let mut file = File::open(path).map_err(|e| WriteError::io(path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8 * 1024];

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(WriteError::io(path, err)),
        }
    }

    let digest = hasher.finalize();
    Ok(format!("sha256:{}", hex_encode_lower(&digest)))
}

/// Lock-free atomic staging writer:
/// 1. Fails closed if any free-text field contains an unredacted secret (unless `redact_secrets == true`).
/// 2. Optionally streams `--think-file` into a local SHA-256 digest (`local_think_digest`).
/// 3. Runs Layer 2 sanitization, path normalization, and RFC 8785 JCS canonicalization (`< 1,536` bytes).
/// 4. Writes `<stage_dir>/{id}.tmp` -> `sync_all()` -> atomic `rename(2)` -> `<stage_dir>/{id}.json` + `fsync(dir)`.
pub fn stage_record(
    repo_dir: &Path,
    req: &StageRequest,
    redact_secrets: bool,
) -> Result<StagedArtifact, WriteError> {
    if !redact_secrets {
        for (field, value) in [
            ("target_symbol", req.target_symbol.as_str()),
            ("discarded_pattern", req.discarded_pattern.as_str()),
            ("invariant", req.invariant.as_str()),
        ] {
            if contains_secret(value) {
                return Err(WriteError::SecretDetected { field });
            }
        }
    }

    let local_think_digest = match &req.think_file {
        Some(path) => Some(hash_think_file_streaming(path)?),
        None => None,
    };

    let record = NegativeSpaceRecord::new_sanitized(
        &req.files,
        &req.target_symbol,
        req.failure_class,
        &req.discarded_pattern,
        &req.invariant,
        req.supersedes.clone(),
        local_think_digest,
    )?;

    let jcs_bytes = record.to_jcs_bytes()?;
    let paths = resolve_repo_paths(repo_dir)?;
    let staged_path = atomic_write_json_event(&paths.stage_dir, &record.id, &jcs_bytes)?;

    Ok(StagedArtifact {
        record,
        staged_path,
    })
}

/// Lists all staged `*.json` files in `stage_dir` in strict lexicographical order,
/// ignoring temporary `*.tmp` and claimed `*.claimed-*` files.
pub fn list_staged_files(stage_dir: &Path) -> Result<Vec<PathBuf>, WriteError> {
    let read_dir = match fs::read_dir(stage_dir) {
        Ok(rd) => rd,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(WriteError::io(stage_dir, err)),
    };

    let mut entries = Vec::new();
    for entry_res in read_dir {
        let entry = entry_res.map_err(|e| WriteError::io(stage_dir, e))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".json") {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() {
            entries.push(path);
        }
    }

    entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    Ok(entries)
}
