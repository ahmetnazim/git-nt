use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use nt_core::{
    MAX_RECORD_BYTES, NegativeSpaceRecord, RecordStatus, contains_secret, is_valid_uuid_v7,
};

use crate::error::WriteError;
use crate::repo::{head_tracked_files, read_regular_file_bounded, resolve_repo_paths};

/// Individual hygiene violation detected by `audit_repository`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditFinding {
    UnexpectedEntry {
        path: String,
        reason: String,
    },
    OversizedRecord {
        path: String,
        bytes: usize,
    },
    InvalidRecord {
        path: String,
        reason: String,
    },
    IdFilenameMismatch {
        path: String,
        expected_stem: String,
        actual_id: String,
    },
    NonCanonicalJcs {
        path: String,
    },
    UnredactedSecret {
        path: String,
        field: &'static str,
    },
    OrphanedPath {
        path: String,
        missing_repo_path: String,
    },
}

/// Summary report produced by `audit_repository`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub checked_files: usize,
    pub findings: Vec<AuditFinding>,
}

impl AuditReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Audits all files in `.nt/ns/` for:
/// 1. Non-symlink `.nt` and `.nt/ns` directory integrity (no symlink escapes).
/// 2. Canonical `{uuid7}.json` regular files (no stray files, subdirectories, or symlinks).
/// 3. Strict `< 1,536`-byte ceiling enforced before reading into memory.
/// 4. Valid `NegativeSpaceRecord` schema & closed enums (`FailureClass`, `RecordStatus`).
/// 5. Exact byte-for-byte RFC 8785 JCS canonicality.
/// 6. Zero unredacted secret patterns across free-text fields.
/// 7. Orphaned/renamed file references on non-superseded active tombstones (compared against `HEAD`).
pub fn audit_repository(repo_dir: &Path) -> Result<AuditReport, WriteError> {
    let paths = resolve_repo_paths(repo_dir)?;

    // Inspect `.nt` and `.nt/ns` with symlink_metadata so dangling or external symlinks
    // can never silently bypass audit or escape the repository.
    let nt_root = paths.repo_root.join(".nt");
    match fs::symlink_metadata(&nt_root) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => {
            return Ok(AuditReport {
                checked_files: 0,
                findings: vec![AuditFinding::UnexpectedEntry {
                    path: ".nt".to_owned(),
                    reason: "'.nt' must be a regular directory, not a symlink or file".to_owned(),
                }],
            });
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(AuditReport {
                checked_files: 0,
                findings: Vec::new(),
            });
        }
        Err(err) => return Err(WriteError::io(&nt_root, err)),
    }

    match fs::symlink_metadata(&paths.ns_dir) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => {
            return Ok(AuditReport {
                checked_files: 0,
                findings: vec![AuditFinding::UnexpectedEntry {
                    path: ".nt/ns".to_owned(),
                    reason: "'.nt/ns' must be a regular directory, not a symlink or file"
                        .to_owned(),
                }],
            });
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(AuditReport {
                checked_files: 0,
                findings: Vec::new(),
            });
        }
        Err(err) => return Err(WriteError::io(&paths.ns_dir, err)),
    }

    let head_files = head_tracked_files(&paths.repo_root)?;
    let mut dir_entries = Vec::new();
    for entry_res in fs::read_dir(&paths.ns_dir).map_err(|e| WriteError::io(&paths.ns_dir, e))? {
        let entry = entry_res.map_err(|e| WriteError::io(&paths.ns_dir, e))?;
        dir_entries.push(entry);
    }
    dir_entries.sort_by_key(|e| e.file_name());

    let mut checked_files = 0usize;
    let mut findings = Vec::new();
    let mut parsed_records: Vec<(String, NegativeSpaceRecord)> = Vec::new();
    let mut superseded_ids = BTreeSet::new();

    for entry in dir_entries {
        let abs_path = entry.path();
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let rel_path = format!(".nt/ns/{file_name}");

        let file_type = entry
            .file_type()
            .map_err(|e| WriteError::io(&abs_path, e))?;
        if !file_type.is_file() {
            findings.push(AuditFinding::UnexpectedEntry {
                path: rel_path,
                reason: "expected regular file inside .nt/ns/ (symlinks and dirs forbidden)"
                    .to_owned(),
            });
            continue;
        }

        checked_files += 1;

        let Some(stem) = file_name.strip_suffix(".json") else {
            findings.push(AuditFinding::UnexpectedEntry {
                path: rel_path,
                reason: "tombstone files must end with '.json'".to_owned(),
            });
            continue;
        };

        if !is_valid_uuid_v7(stem) {
            findings.push(AuditFinding::UnexpectedEntry {
                path: rel_path,
                reason: format!("filename stem '{stem}' is not a valid lowercase UUIDv7"),
            });
            continue;
        }

        let meta = fs::symlink_metadata(&abs_path).map_err(|e| WriteError::io(&abs_path, e))?;
        let Some(raw) = read_regular_file_bounded(&abs_path, MAX_RECORD_BYTES - 1)? else {
            findings.push(AuditFinding::OversizedRecord {
                path: rel_path,
                bytes: meta.len() as usize,
            });
            continue;
        };

        let record = match NegativeSpaceRecord::from_jcs_bytes(&raw) {
            Ok(rec) => rec,
            Err(err) => {
                findings.push(AuditFinding::InvalidRecord {
                    path: rel_path,
                    reason: err.to_string(),
                });
                continue;
            }
        };

        if record.id != stem {
            findings.push(AuditFinding::IdFilenameMismatch {
                path: rel_path.clone(),
                expected_stem: stem.to_owned(),
                actual_id: record.id.clone(),
            });
        }

        match record.to_jcs_bytes() {
            Ok(canonical) if canonical != raw => {
                findings.push(AuditFinding::NonCanonicalJcs {
                    path: rel_path.clone(),
                });
            }
            Ok(_) => {}
            Err(err) => {
                findings.push(AuditFinding::InvalidRecord {
                    path: rel_path,
                    reason: err.to_string(),
                });
                continue;
            }
        }

        for (field, value) in [
            ("target_symbol", record.target_symbol.as_str()),
            ("discarded_pattern", record.discarded_pattern.as_str()),
            ("invariant", record.invariant.as_str()),
        ] {
            if contains_secret(value) {
                findings.push(AuditFinding::UnredactedSecret {
                    path: rel_path.clone(),
                    field,
                });
            }
        }

        if let Some(ref sup) = record.supersedes {
            superseded_ids.insert(sup.clone());
        }
        parsed_records.push((rel_path, record));
    }

    if let Some(ref tracked) = head_files {
        for (rel_path, record) in parsed_records {
            if record.status == RecordStatus::Active && !superseded_ids.contains(&record.id) {
                for target_file in &record.files {
                    if !tracked.contains(target_file) {
                        findings.push(AuditFinding::OrphanedPath {
                            path: rel_path.clone(),
                            missing_repo_path: target_file.clone(),
                        });
                    }
                }
            }
        }
    }

    Ok(AuditReport {
        checked_files,
        findings,
    })
}
