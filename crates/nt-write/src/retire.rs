use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use nt_core::{
    CoreError, MAX_RECORD_BYTES, NegativeSpaceRecord, RecordStatus, SCHEMA_VERSION,
    contains_secret, generate_uuid_v7, is_valid_uuid_v7, now_rfc3339_utc, sanitize_field,
};

use crate::error::WriteError;
use crate::repo::{
    atomic_write_json_event, git_add_files, git_rm_file_force, hardened_git,
    read_regular_file_bounded, resolve_repo_paths,
};

/// Strategy used when retiring an obsolete Negative-Space tombstone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetireMode {
    /// Removed `.nt/ns/{id}.json` from the repository (`--delete`).
    Deleted,
    /// Created a new immutable `status: "retired"` tombstone superseding `target_id`.
    Superseded,
}

/// Outcome of `retire_tombstone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireOutcome {
    pub mode: RetireMode,
    pub affected_path: String,
    pub retired_record_id: Option<String>,
}

/// Retires an existing tombstone in `.nt/ns/{target_id}.json`.
///
/// - When `delete == true`, removes `.nt/ns/{target_id}.json` (using `git rm -f` if tracked,
///   even if freshly staged, modified, corrupt, or oversized).
/// - When `delete == false`, validates `existing.id == target_id` and materializes a new
///   immutable tombstone with `status: "retired"` and `supersedes: Some(target_id)` using
///   sanitized fields so near-ceiling tombstones do not overflow `< 1,536` bytes.
pub fn retire_tombstone(
    repo_dir: &Path,
    target_id: &str,
    delete: bool,
    reason: Option<&str>,
) -> Result<RetireOutcome, WriteError> {
    if !is_valid_uuid_v7(target_id) {
        return Err(WriteError::Core(CoreError::InvalidUuid(
            target_id.to_owned(),
        )));
    }

    let paths = resolve_repo_paths(repo_dir)?;
    let target_rel = format!(".nt/ns/{target_id}.json");
    let target_abs = paths.ns_dir.join(format!("{target_id}.json"));

    let meta = match fs::symlink_metadata(&target_abs) {
        Ok(m) => m,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(WriteError::TombstoneNotFound(target_id.to_owned()));
        }
        Err(err) => return Err(WriteError::io(&target_abs, err)),
    };

    if !meta.file_type().is_file() {
        return Err(WriteError::NotARegularFile {
            path: target_abs,
            reason: "target tombstone must be a regular file (symlinks are forbidden)",
        });
    }

    // Handle `--delete` BEFORE parsing `existing` so corrupt/oversized tombstones flagged by
    // `git nt audit` can always be cleanly deleted.
    if delete {
        let is_tracked = hardened_git(&paths.repo_root)
            .args(["ls-files", "--error-unmatch", "--", &target_rel])
            .output()
            .map_err(|e| WriteError::io(&paths.repo_root, e))?
            .status
            .success();

        if is_tracked {
            git_rm_file_force(&paths.repo_root, &target_rel)?;
        } else {
            fs::remove_file(&target_abs).map_err(|e| WriteError::io(&target_abs, e))?;
        }

        return Ok(RetireOutcome {
            mode: RetireMode::Deleted,
            affected_path: target_rel,
            retired_record_id: None,
        });
    }

    let raw = read_regular_file_bounded(&target_abs, MAX_RECORD_BYTES - 1)?.ok_or(
        WriteError::Core(CoreError::RecordTooLarge {
            bytes: meta.len() as usize,
            max: MAX_RECORD_BYTES,
        }),
    )?;
    let existing = NegativeSpaceRecord::from_jcs_bytes(&raw)?;

    if existing.id != target_id {
        return Err(WriteError::CorruptStagedFile {
            path: target_abs,
            reason: format!(
                "tombstone id '{}' does not match target filename id '{target_id}'",
                existing.id
            ),
        });
    }

    if existing.status == RecordStatus::Retired {
        return Err(WriteError::AlreadyRetired(target_id.to_owned()));
    }

    let reason_text = reason.unwrap_or("Retired obsolete tombstone");
    if contains_secret(reason_text) {
        return Err(WriteError::SecretDetected { field: "invariant" });
    }

    let new_id = generate_uuid_v7()?;
    // Sanitize `target_symbol` and use a compact sentinel for `discarded_pattern` so:
    // 1. Retiring a near-ceiling active tombstone does not exceed 1,536 bytes;
    // 2. Any secret present in a tampered legacy tombstone is never duplicated.
    let retired = NegativeSpaceRecord {
        schema_version: SCHEMA_VERSION,
        id: new_id.clone(),
        created_at: now_rfc3339_utc()?,
        files: existing.files,
        target_symbol: sanitize_field(&existing.target_symbol),
        failure_class: existing.failure_class,
        discarded_pattern: "Superseded obsolete tombstone".to_owned(),
        invariant: sanitize_field(reason_text),
        status: RecordStatus::Retired,
        supersedes: Some(target_id.to_owned()),
        local_think_digest: None,
    };

    let canonical_bytes = retired.to_jcs_bytes()?;
    let new_rel = format!(".nt/ns/{new_id}.json");
    let new_abs = atomic_write_json_event(&paths.ns_dir, &new_id, &canonical_bytes)?;

    if let Err(err) = git_add_files(&paths.repo_root, std::slice::from_ref(&new_rel)) {
        let _ = fs::remove_file(&new_abs);
        return Err(err);
    }

    Ok(RetireOutcome {
        mode: RetireMode::Superseded,
        affected_path: new_rel,
        retired_record_id: Some(new_id),
    })
}
