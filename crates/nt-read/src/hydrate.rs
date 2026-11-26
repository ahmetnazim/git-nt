use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use nt_core::{
    FailureClass, NegativeSpaceRecord, RecordStatus, SPOTLIGHT_HEADER, normalize_repo_path,
    sanitize_field, spotlight_wrap,
};

use crate::config::validate_ref_name;
use crate::error::ReadError;
use crate::reader::{RawTreeBlob, RepoReader};

/// Default maximum hydrated records returned per file query.
pub const DEFAULT_MAX_RECORDS: usize = 15;

/// Hard server/CLI ceiling on hydrated records returned per query.
pub const HARD_MAX_RECORDS: usize = 50;

/// Hard byte ceiling (`16 KiB`) on the total Spotlighting-wrapped hydrated payload.
pub const MAX_HYDRATED_BYTES: usize = 16 * 1024;

/// Exact byte overhead of the Layer 3 CSPRNG Spotlighting envelope:
/// `{SPOTLIGHT_HEADER}\n<<<NT_DATA_{32-hex}<<<\n{body}\n>>>END_NT_DATA_{32-hex}>>>`.
const SPOTLIGHT_ENVELOPE_BYTES: usize = SPOTLIGHT_HEADER.len()
    + "\n<<<NT_DATA_".len()
    + 32
    + "<<<\n".len()
    + "\n>>>END_NT_DATA_".len()
    + 32
    + ">>>".len();

const MAX_BODY_BYTES: usize = MAX_HYDRATED_BYTES - SPOTLIGHT_ENVELOPE_BYTES;

/// Options for [`hydrate_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydrateOptions {
    pub file_path: String,
    pub max_records: Option<usize>,
    pub trusted_ref_override: Option<String>,
    /// CLI-only escape hatch (`--include-untrusted`). Strictly `false` for MCP callers.
    pub include_untrusted: bool,
}

/// Sanitized, trusted Negative-Space record surfaced during hydration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydrationRecord {
    pub id: String,
    pub failure_class: FailureClass,
    pub target_symbol: String,
    pub discarded_pattern: String,
    pub invariant: String,
    pub files: Vec<String>,
}

/// Result of running Layers 1–3 hydration for a target file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydrationResult {
    pub file_path: String,
    pub trusted_ref: String,
    pub records: Vec<HydrationRecord>,
    pub dropped_invalid: usize,
    pub dropped_unsigned: usize,
    pub spotlighted_output: String,
}

/// Validates that `raw_path` is a canonical repo-relative POSIX path and that no existing
/// path component inside `repo_root` is a symlink escaping `repo_root` (or dangling).
pub fn validate_target_file_path(repo_root: &Path, raw_path: &str) -> Result<String, ReadError> {
    let normalized = normalize_repo_path(raw_path)?;
    let canonical_root = fs::canonicalize(repo_root).map_err(|e| ReadError::io(repo_root, e))?;

    let mut cur = canonical_root.clone();
    for segment in normalized.split('/') {
        cur.push(segment);
        match fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    let resolved = fs::canonicalize(&cur)
                        .map_err(|_| ReadError::SymlinkEscape { path: cur.clone() })?;
                    if !resolved.starts_with(&canonical_root) {
                        return Err(ReadError::SymlinkEscape { path: cur });
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => break,
            Err(err) => return Err(ReadError::io(&cur, err)),
        }
    }

    Ok(normalized)
}

/// Strictly trusted-tree-only hydration entrypoint intended for Layer 4 (`nt-mcp`).
///
/// Hardcodes `include_untrusted = false` and ignores any ref overrides, always honoring
/// the repository's configured `nt.trustedRef` and `nt.requireSigned` policy.
pub fn hydrate_file_trusted_only(
    reader: &dyn RepoReader,
    file_path: &str,
    max_records: Option<usize>,
) -> Result<HydrationResult, ReadError> {
    hydrate_file(
        reader,
        &HydrateOptions {
            file_path: file_path.to_owned(),
            max_records,
            trusted_ref_override: None,
            include_untrusted: false,
        },
    )
}

/// Runs the full Layers 1–3 hydration pipeline for a single repo-relative file path.
pub fn hydrate_file(
    reader: &dyn RepoReader,
    opts: &HydrateOptions,
) -> Result<HydrationResult, ReadError> {
    let target_file = validate_target_file_path(reader.repo_root(), &opts.file_path)?;
    let cfg = reader.read_trust_config()?;

    let effective_ref = match &opts.trusted_ref_override {
        Some(r) => {
            validate_ref_name(r)?;
            r.clone()
        }
        None => cfg.trusted_ref.clone(),
    };

    let (resolved_commit, raw_blobs, mut dropped_invalid) = if opts.include_untrusted {
        let (blobs, skipped) = reader.read_worktree_ns_blobs()?;
        (None, blobs, skipped)
    } else {
        let snap = reader.read_trusted_ns_blobs(&effective_ref)?;
        (
            Some(snap.resolved_commit),
            snap.blobs,
            snap.skipped_oversized_or_non_canonical,
        )
    };

    // Parse all candidate blobs strictly through nt-core schema validation (closed enums,
    // UUIDv7 ID, path canonicality, < 1,536-byte ceiling). Silently drop malformed blobs.
    let mut parsed: Vec<(String, NegativeSpaceRecord)> = Vec::new();
    for RawTreeBlob { rel_path, bytes } in raw_blobs {
        let stem = rel_path
            .strip_prefix(".nt/ns/")
            .and_then(|s| s.strip_suffix(".json"));
        let Ok(record) = NegativeSpaceRecord::from_jcs_bytes(&bytes) else {
            dropped_invalid += 1;
            continue;
        };
        if stem != Some(record.id.as_str()) {
            dropped_invalid += 1;
            continue;
        }
        parsed.push((rel_path, record));
    }

    // Narrow to records relevant to `target_file`:
    // 1. Any record whose `files` array contains `target_file`.
    // 2. Any record whose `supersedes` points to an ID in set (1) (transitively),
    //    so retirement tombstones suppress matching records even if `files` differed.
    let mut relevant_ids: HashSet<String> = parsed
        .iter()
        .filter(|(_, rec)| rec.files.iter().any(|f| f == &target_file))
        .map(|(_, rec)| rec.id.clone())
        .collect();

    loop {
        let before = relevant_ids.len();
        for (_, rec) in &parsed {
            if let Some(ref sup) = rec.supersedes
                && relevant_ids.contains(sup)
            {
                relevant_ids.insert(rec.id.clone());
            }
        }
        if relevant_ids.len() == before {
            break;
        }
    }

    let relevant: Vec<(String, NegativeSpaceRecord)> = parsed
        .into_iter()
        .filter(|(_, rec)| relevant_ids.contains(&rec.id))
        .collect();

    // Layer 1 commit signature gate (when enabled & hydrating from a trusted Git tree).
    // Caches signature verification results per unique commit SHA within this invocation.
    let mut dropped_unsigned = 0usize;
    let verified: Vec<NegativeSpaceRecord> = if let Some(resolved_sha) = resolved_commit.as_deref()
        && !opts.include_untrusted
        && cfg.require_signed
    {
        let mut sig_cache: HashMap<String, char> = HashMap::new();
        let mut accepted = Vec::new();

        for (rel_path, rec) in relevant {
            let Some(touching_sha) = reader.last_touching_commit(resolved_sha, &rel_path)? else {
                dropped_unsigned += 1;
                continue;
            };
            let sig_char = match sig_cache.get(&touching_sha) {
                Some(&c) => c,
                None => {
                    let c = reader.verify_commit_signature(&touching_sha)?;
                    sig_cache.insert(touching_sha, c);
                    c
                }
            };
            let trusted_sig = sig_char == 'G' || (cfg.allow_untrusted_gpg_trust && sig_char == 'U');
            if trusted_sig {
                accepted.push(rec);
            } else {
                dropped_unsigned += 1;
            }
        }
        accepted
    } else {
        relevant.into_iter().map(|(_, rec)| rec).collect()
    };

    // Suppress retired records AND any active record superseded by a verified record.
    let superseded_ids: HashSet<String> = verified
        .iter()
        .filter_map(|r| r.supersedes.clone())
        .collect();

    let mut active_matching: Vec<NegativeSpaceRecord> = verified
        .into_iter()
        .filter(|r| {
            r.status == RecordStatus::Active
                && !superseded_ids.contains(&r.id)
                && r.files.iter().any(|f| f == &target_file)
        })
        .collect();

    // Deterministic ranking: newest UUIDv7 first (lexicographically descending).
    active_matching.sort_by(|a, b| b.id.cmp(&a.id));

    let max_records = opts
        .max_records
        .unwrap_or(DEFAULT_MAX_RECORDS)
        .min(HARD_MAX_RECORDS);

    // Layer 2 defense-in-depth re-sanitization + record/byte budget enforcement.
    let mut final_records = Vec::new();
    let mut body = String::new();

    for rec in active_matching.into_iter().take(max_records) {
        let sanitized = HydrationRecord {
            id: rec.id,
            failure_class: rec.failure_class,
            target_symbol: sanitize_field(&rec.target_symbol),
            discarded_pattern: sanitize_field(&rec.discarded_pattern),
            invariant: sanitize_field(&rec.invariant),
            files: rec.files,
        };

        let block = format_record_block(&sanitized);
        let separator_len = usize::from(!body.is_empty());
        if body.len() + separator_len + block.len() > MAX_BODY_BYTES {
            break;
        }
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(&block);
        final_records.push(sanitized);
    }

    if body.is_empty() {
        // Always pass echoed target_file through Layer 2 sanitization so an adversarial
        // non-existent path cannot inject delimiter/tag/Bidi payloads or exceed MAX_BODY_BYTES.
        let safe_target = sanitize_field(&target_file);
        body = format!("(no active trusted negative-space records for {safe_target})");
    }

    // Layer 3 fresh 128-bit OS CSPRNG Spotlighting envelope.
    let spotlighted_output = spotlight_wrap(&body)?;

    Ok(HydrationResult {
        file_path: target_file,
        trusted_ref: if opts.include_untrusted {
            "WORKTREE(UNTRUSTED)".to_owned()
        } else {
            effective_ref
        },
        records: final_records,
        dropped_invalid,
        dropped_unsigned,
        spotlighted_output,
    })
}

fn format_record_block(rec: &HydrationRecord) -> String {
    format!(
        "[{}] {} (id={})\n  discarded: {}\n  invariant: {}",
        rec.failure_class, rec.target_symbol, rec.id, rec.discarded_pattern, rec.invariant
    )
}
