use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use nt_core::{MAX_RECORD_BYTES, NegativeSpaceRecord, contains_secret, is_valid_uuid_v7};

use crate::error::WriteError;
use crate::repo::{
    RepoPaths, atomic_write_json_event, fsync_dir, git_add_files, git_unstage_files,
    modified_tracked_files, read_head_sha, read_regular_file_bounded, resolve_repo_paths,
    staged_index_files,
};
use crate::stage::list_staged_files;

static CLAIM_SEQ: AtomicU64 = AtomicU64::new(0);

/// Options controlling how staged tombstones are selected during promotion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PromoteOptions {
    /// When `false` (default), promote only tombstones whose `files` intersect the staged Git diff.
    /// When `true`, promote all staged tombstones regardless of staged diff overlap.
    pub promote_all: bool,
}

/// Options controlling `commit_with_options`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOptions {
    /// Promote all staged tombstones regardless of staged diff overlap.
    pub promote_all: bool,
    /// Inherit `stdin`/`stdout`/`stderr` for native `git commit` (required for interactive
    /// `$EDITOR`, TTY GPG/SSH pinentry, `-p`, and piped `-F -`). Defaults to `true`.
    pub inherit_stdio: bool,
}

impl Default for CommitOptions {
    fn default() -> Self {
        Self {
            promote_all: false,
            inherit_stdio: true,
        }
    }
}

/// Summary of a standalone `git nt promote` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromoteReport {
    pub promoted_ids: Vec<String>,
    pub promoted_paths: Vec<String>,
    pub skipped_unmatched: usize,
}

/// Summary of a `git nt commit -- <git args...>` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReport {
    pub promoted_ids: Vec<String>,
    pub promoted_paths: Vec<String>,
    pub skipped_unmatched: usize,
    pub head_sha: String,
}

struct ClaimedEntry {
    id: String,
    original_stage_path: PathBuf,
    claimed_path: PathBuf,
    materialized_ns_path: Option<PathBuf>,
    rel_ns_path: String,
}

struct ClaimBatch {
    entries: Vec<ClaimedEntry>,
}

impl ClaimBatch {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn finalize(self, stage_dir: &Path) -> Result<(), WriteError> {
        for entry in &self.entries {
            match fs::remove_file(&entry.claimed_path) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(WriteError::io(&entry.claimed_path, err)),
            }
        }
        if !self.entries.is_empty() {
            fsync_dir(stage_dir);
        }
        Ok(())
    }

    fn rollback(self, repo_root: &Path, stage_dir: &Path) {
        let rel_paths: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.materialized_ns_path.is_some())
            .map(|e| e.rel_ns_path.clone())
            .collect();

        // Only unlink working-tree `.nt/ns/{id}.json` if unstaging succeeded,
        // avoiding working-tree vs index desync under persistent lock failure.
        let unstaged_ok = if rel_paths.is_empty() {
            true
        } else {
            git_unstage_files(repo_root, &rel_paths).is_ok()
        };

        for entry in self.entries {
            if unstaged_ok && let Some(ns_path) = entry.materialized_ns_path {
                let _ = fs::remove_file(&ns_path);
            }
            let _ = fs::rename(&entry.claimed_path, &entry.original_stage_path);
        }
        fsync_dir(stage_dir);
    }
}

fn next_claim_path(stage_dir: &Path, id: &str) -> PathBuf {
    let pid = std::process::id();
    let seq = CLAIM_SEQ.fetch_add(1, Ordering::Relaxed);
    stage_dir.join(format!("{id}.claimed-{pid}-{seq}"))
}

fn record_has_secret(record: &NegativeSpaceRecord) -> Option<&'static str> {
    for (field, value) in [
        ("target_symbol", record.target_symbol.as_str()),
        ("discarded_pattern", record.discarded_pattern.as_str()),
        ("invariant", record.invariant.as_str()),
    ] {
        if contains_secret(value) {
            return Some(field);
        }
    }
    None
}

fn read_staged_bounded(path: &Path) -> Result<Option<Vec<u8>>, WriteError> {
    match read_regular_file_bounded(path, MAX_RECORD_BYTES - 1) {
        Ok(Some(bytes)) => Ok(Some(bytes)),
        Ok(None) => Err(WriteError::CorruptStagedFile {
            path: path.to_path_buf(),
            reason: format!("staged file meets or exceeds {MAX_RECORD_BYTES}-byte ceiling"),
        }),
        Err(WriteError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn claim_and_materialize(
    paths: &RepoPaths,
    candidate_diff: Option<&BTreeSet<String>>,
    promote_all: bool,
) -> Result<(ClaimBatch, usize), WriteError> {
    let staged_files = list_staged_files(&paths.stage_dir)?;
    let mut batch = ClaimBatch::new();
    let mut skipped_unmatched = 0usize;

    for stage_path in staged_files {
        let Some(stem) = stage_path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        if !is_valid_uuid_v7(&stem) {
            batch.rollback(&paths.repo_root, &paths.stage_dir);
            return Err(WriteError::CorruptStagedFile {
                path: stage_path,
                reason: "staged filename stem is not a valid lowercase UUIDv7".to_owned(),
            });
        }

        // Pre-check diff match before claiming so non-matching tombstones stay staged untouched.
        let Some(raw_preview) = (match read_staged_bounded(&stage_path) {
            Ok(opt) => opt,
            Err(err) => {
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(err);
            }
        }) else {
            // Another concurrent process already claimed this staged event.
            continue;
        };

        let preview_record = match NegativeSpaceRecord::from_jcs_bytes(&raw_preview) {
            Ok(rec) => rec,
            Err(err) => {
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(WriteError::CorruptStagedFile {
                    path: stage_path,
                    reason: err.to_string(),
                });
            }
        };

        if preview_record.id != stem {
            batch.rollback(&paths.repo_root, &paths.stage_dir);
            return Err(WriteError::CorruptStagedFile {
                path: stage_path,
                reason: format!(
                    "record id '{}' does not match filename stem '{stem}'",
                    preview_record.id
                ),
            });
        }

        if !promote_all {
            let matches_diff = candidate_diff
                .map(|diff| preview_record.files.iter().any(|f| diff.contains(f)))
                .unwrap_or(false);
            if !matches_diff {
                skipped_unmatched += 1;
                continue;
            }
        }

        // Atomically claim the staged event via POSIX rename(2). Only one process can win.
        let claimed_path = next_claim_path(&paths.stage_dir, &stem);
        match fs::rename(&stage_path, &claimed_path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {
                // Lost the race to a concurrent promoter/committer; skip cleanly.
                continue;
            }
            Err(err) => {
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(WriteError::io(&claimed_path, err));
            }
        }

        // Re-read & re-validate strictly from the exclusively owned claimed file (closes TOCTOU).
        let claimed_bytes = match read_regular_file_bounded(&claimed_path, MAX_RECORD_BYTES - 1) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                let _ = fs::rename(&claimed_path, &stage_path);
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(WriteError::CorruptStagedFile {
                    path: claimed_path,
                    reason: format!(
                        "claimed file meets or exceeds {MAX_RECORD_BYTES}-byte ceiling"
                    ),
                });
            }
            Err(err) => {
                let _ = fs::rename(&claimed_path, &stage_path);
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(err);
            }
        };

        let record = match NegativeSpaceRecord::from_jcs_bytes(&claimed_bytes) {
            Ok(rec) => rec,
            Err(err) => {
                let _ = fs::rename(&claimed_path, &stage_path);
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(WriteError::CorruptStagedFile {
                    path: claimed_path,
                    reason: err.to_string(),
                });
            }
        };

        if record.id != stem {
            let _ = fs::rename(&claimed_path, &stage_path);
            batch.rollback(&paths.repo_root, &paths.stage_dir);
            return Err(WriteError::CorruptStagedFile {
                path: claimed_path,
                reason: format!(
                    "claimed record id '{}' does not match filename stem '{stem}'",
                    record.id
                ),
            });
        }

        if let Some(field) = record_has_secret(&record) {
            let _ = fs::rename(&claimed_path, &stage_path);
            batch.rollback(&paths.repo_root, &paths.stage_dir);
            return Err(WriteError::SecretDetected { field });
        }

        if !promote_all {
            let matches_diff = candidate_diff
                .map(|diff| record.files.iter().any(|f| diff.contains(f)))
                .unwrap_or(false);
            if !matches_diff {
                let _ = fs::rename(&claimed_path, &stage_path);
                skipped_unmatched += 1;
                continue;
            }
        }

        let canonical_bytes = match record.to_jcs_bytes() {
            Ok(bytes) => bytes,
            Err(err) => {
                let _ = fs::rename(&claimed_path, &stage_path);
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(WriteError::Core(err));
            }
        };

        let rel_ns_path = format!(".nt/ns/{}.json", record.id);
        let existing_target = paths.ns_dir.join(format!("{}.json", record.id));
        // Use symlink_metadata so even a dangling symlink is detected and never clobbered.
        if existing_target.symlink_metadata().is_ok() {
            let _ = fs::rename(&claimed_path, &stage_path);
            batch.rollback(&paths.repo_root, &paths.stage_dir);
            return Err(WriteError::CorruptStagedFile {
                path: stage_path,
                reason: format!("target tombstone '{rel_ns_path}' already exists"),
            });
        }

        let ns_path = match atomic_write_json_event(&paths.ns_dir, &record.id, &canonical_bytes) {
            Ok(p) => p,
            Err(err) => {
                let _ = fs::rename(&claimed_path, &stage_path);
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(err);
            }
        };

        batch.entries.push(ClaimedEntry {
            id: record.id,
            original_stage_path: stage_path,
            claimed_path,
            materialized_ns_path: Some(ns_path),
            rel_ns_path,
        });
    }

    let rel_paths: Vec<String> = batch
        .entries
        .iter()
        .map(|e| e.rel_ns_path.clone())
        .collect();
    if let Err(err) = git_add_files(&paths.repo_root, &rel_paths) {
        batch.rollback(&paths.repo_root, &paths.stage_dir);
        return Err(err);
    }

    Ok((batch, skipped_unmatched))
}

/// Atomically claims matching staged tombstones from `.git/nt-stage/`, materializes them
/// into tracked `.nt/ns/{id}.json`, runs `git add`, and unlinks claimed staging files on success.
pub fn promote_staged(repo_dir: &Path, opts: PromoteOptions) -> Result<PromoteReport, WriteError> {
    let paths = resolve_repo_paths(repo_dir)?;
    let diff_set = if opts.promote_all {
        None
    } else {
        Some(staged_index_files(&paths.repo_root)?)
    };

    let (batch, skipped_unmatched) =
        claim_and_materialize(&paths, diff_set.as_ref(), opts.promote_all)?;

    let promoted_ids: Vec<String> = batch.entries.iter().map(|e| e.id.clone()).collect();
    let promoted_paths: Vec<String> = batch
        .entries
        .iter()
        .map(|e| e.rel_ns_path.clone())
        .collect();

    batch.finalize(&paths.stage_dir)?;

    Ok(PromoteReport {
        promoted_ids,
        promoted_paths,
        skipped_unmatched,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedCommitArgs {
    include_all_tracked: bool,
}

/// Validates `git commit` arguments before mutating `.git/nt-stage/`, `.nt/ns/`, or the Git index.
///
/// Fails closed on dry-run modes (`--dry-run`, `--short`, `--porcelain`) and partial/pathspec
/// commits (`-o`/`--only`, `--pathspec-from-file`, positional pathspecs) that would either skip
/// committing promoted `.nt/ns/` files or falsely finalize claimed staging files.
fn parse_git_commit_args(args: &[String]) -> Result<ParsedCommitArgs, WriteError> {
    let mut include_all_tracked = false;
    let mut skip_next = false;

    for (idx, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }

        if arg == "--" {
            if idx + 1 < args.len() {
                return Err(WriteError::UnsupportedCommitArgs {
                    reason: "pathspec arguments after '--' are unsupported by `git nt commit`; use `git nt promote` + native `git commit` for partial commits".to_owned(),
                });
            }
            break;
        }

        if matches!(arg.as_str(), "--dry-run" | "--short" | "--porcelain") {
            return Err(WriteError::UnsupportedCommitArgs {
                reason: format!(
                    "dry-run flag '{arg}' does not create a commit and is unsupported by `git nt commit`"
                ),
            });
        }

        if arg == "-o"
            || arg == "--only"
            || arg == "--pathspec-from-file"
            || arg.starts_with("--pathspec-from-file=")
            || arg == "--pathspec-file-nul"
        {
            return Err(WriteError::UnsupportedCommitArgs {
                reason: format!(
                    "partial commit option '{arg}' would omit promoted `.nt/ns/` tombstones; use `git nt promote` + native `git commit`"
                ),
            });
        }

        // Options that consume the next argv token as a mandatory value.
        // Note: `-S[<keyid>]` and `-u[<mode>]` take optional ATTACHED args only and NEVER consume next argv.
        if matches!(
            arg.as_str(),
            "-m" | "-F"
                | "-C"
                | "-c"
                | "-t"
                | "--message"
                | "--file"
                | "--reuse-message"
                | "--reedit-message"
                | "--fixup"
                | "--squash"
                | "--author"
                | "--date"
                | "--template"
                | "--cleanup"
                | "--trailer"
        ) {
            skip_next = true;
            continue;
        }

        if arg == "-a" || arg == "--all" {
            include_all_tracked = true;
            continue;
        }
        if arg == "--no-all" {
            include_all_tracked = false;
            continue;
        }

        if arg.starts_with("--") {
            // Other long flags (`--amend`, `--gpg-sign=...`, `--no-verify`, etc.).
            continue;
        }

        if arg.starts_with('-') && arg.len() > 1 {
            // Short option bundle (e.g. `-am`, `-sm`, `-Sa`, `-qm`).
            let flags = &arg[1..];
            let chars: Vec<char> = flags.chars().collect();
            for (pos, &ch) in chars.iter().enumerate() {
                match ch {
                    'o' => {
                        return Err(WriteError::UnsupportedCommitArgs {
                            reason: "partial commit flag '-o' would omit promoted `.nt/ns/` tombstones; use `git nt promote` + native `git commit`".to_owned(),
                        });
                    }
                    'a' => include_all_tracked = true,
                    // Optional attached argument: remainder of bundle is value; never consumes next argv.
                    'S' | 'u' => break,
                    // Required argument: if last char in bundle, consumes next argv; otherwise rest is inline value.
                    'm' | 'F' | 'C' | 'c' | 't' => {
                        if pos + 1 == chars.len() {
                            skip_next = true;
                        }
                        break;
                    }
                    _ => {}
                }
            }
            continue;
        }

        // Non-option positional argument (file pathspec).
        return Err(WriteError::UnsupportedCommitArgs {
            reason: format!(
                "positional pathspec '{arg}' implies a partial (`--only`) commit that omits promoted `.nt/ns/` tombstones; stage files and run `git nt commit` without pathspecs, or use `git nt promote`"
            ),
        });
    }

    Ok(ParsedCommitArgs {
        include_all_tracked,
    })
}

/// Promotes diff-matching staged tombstones into `.nt/ns/`, invokes native `git commit`
/// (preserving user hooks, GPG/SSH signing, TTY stdio, and subdirectory-relative paths),
/// and either finalizes claimed staging files on exit code `0` or rolls back cleanly on failure.
pub fn commit_with_tombstones(
    repo_dir: &Path,
    git_commit_args: &[String],
    promote_all: bool,
) -> Result<CommitReport, WriteError> {
    commit_with_options(
        repo_dir,
        git_commit_args,
        CommitOptions {
            promote_all,
            inherit_stdio: true,
        },
    )
}

/// Configurable version of [`commit_with_tombstones`] allowing callers/tests to choose
/// between inherited TTY stdio (`inherit_stdio = true`, CLI default) or captured output.
pub fn commit_with_options(
    repo_dir: &Path,
    git_commit_args: &[String],
    opts: CommitOptions,
) -> Result<CommitReport, WriteError> {
    // Fail closed on dry-run / pathspec / --only args BEFORE mutating staging or index.
    let parsed = parse_git_commit_args(git_commit_args)?;

    let paths = resolve_repo_paths(repo_dir)?;
    let diff_set = if opts.promote_all {
        None
    } else {
        let mut files = staged_index_files(&paths.repo_root)?;
        if parsed.include_all_tracked {
            files.extend(modified_tracked_files(&paths.repo_root)?);
        }
        Some(files)
    };

    let (batch, skipped_unmatched) =
        claim_and_materialize(&paths, diff_set.as_ref(), opts.promote_all)?;

    let promoted_ids: Vec<String> = batch.entries.iter().map(|e| e.id.clone()).collect();
    let promoted_paths: Vec<String> = batch
        .entries
        .iter()
        .map(|e| e.rel_ns_path.clone())
        .collect();

    // Native `git commit`: runs in `repo_dir` (preserving subdir-relative `-F`/`-t` paths)
    // and intentionally preserves user hooks and GPG/SSH signing (AGENTS.md §2.4).
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_dir)
        .arg("commit")
        .args(git_commit_args);

    let (success, code, stderr) = if opts.inherit_stdio {
        match cmd.status() {
            Ok(status) => (status.success(), status.code(), String::new()),
            Err(err) => {
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(WriteError::io(repo_dir, err));
            }
        }
    } else {
        match cmd.output() {
            Ok(out) => (
                out.status.success(),
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ),
            Err(err) => {
                batch.rollback(&paths.repo_root, &paths.stage_dir);
                return Err(WriteError::io(repo_dir, err));
            }
        }
    };

    if !success {
        batch.rollback(&paths.repo_root, &paths.stage_dir);
        return Err(WriteError::CommitFailed { code, stderr });
    }

    batch.finalize(&paths.stage_dir)?;
    let head_sha = read_head_sha(&paths.repo_root)?;

    Ok(CommitReport {
        promoted_ids,
        promoted_paths,
        skipped_unmatched,
        head_sha,
    })
}
