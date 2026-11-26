use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::error::WriteError;

/// Resolved Git repository and `git-nt` directory locations for a work tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPaths {
    pub repo_root: PathBuf,
    pub stage_dir: PathBuf,
    pub ns_dir: PathBuf,
}

/// Builds a hardened non-interactive native `git` command for read/index plumbing.
///
/// Explicitly disables `core.fsmonitor`, repository hooks (`core.hooksPath=/dev/null`),
/// terminal prompts, and locale-dependent stderr messages (`LC_ALL=C`).
/// Do NOT use this helper for user `git commit`, which MUST preserve user hooks and signing.
pub(crate) fn hardened_git(cwd: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ]);
    cmd
}

fn trim_single_trailing_newline(bytes: &[u8]) -> &[u8] {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    bytes.strip_suffix(b"\r").unwrap_or(bytes)
}

/// Resolves the repository root, per-worktree staging directory (`.git/nt-stage/`),
/// and tracked tombstone directory (`.nt/ns/`) for `repo_dir` in a single `git rev-parse` call.
pub fn resolve_repo_paths(repo_dir: &Path) -> Result<RepoPaths, WriteError> {
    let abs_cwd = fs::canonicalize(repo_dir).map_err(|e| WriteError::io(repo_dir, e))?;

    let out = hardened_git(&abs_cwd)
        .args(["rev-parse", "--show-toplevel", "--git-path", "nt-stage"])
        .output()
        .map_err(|e| WriteError::io(&abs_cwd, e))?;

    if !out.status.success() {
        return Err(WriteError::NotAGitRepo(repo_dir.to_path_buf()));
    }

    let trimmed = trim_single_trailing_newline(&out.stdout);
    let mut parts = trimmed.splitn(2, |&b| b == b'\n');
    let Some(top_bytes) = parts.next() else {
        return Err(WriteError::NotAGitRepo(repo_dir.to_path_buf()));
    };
    let Some(stage_bytes) = parts.next() else {
        return Err(WriteError::GitCommandFailed {
            command: "git rev-parse --show-toplevel --git-path nt-stage".to_owned(),
            code: out.status.code(),
            stderr: "unexpected single-line output from git rev-parse".to_owned(),
        });
    };

    let repo_root = PathBuf::from(OsStr::from_bytes(
        top_bytes.strip_suffix(b"\r").unwrap_or(top_bytes),
    ));
    let raw_stage = PathBuf::from(OsStr::from_bytes(
        stage_bytes.strip_suffix(b"\r").unwrap_or(stage_bytes),
    ));
    let stage_dir = if raw_stage.is_absolute() {
        raw_stage
    } else {
        abs_cwd.join(raw_stage)
    };

    let ns_dir = repo_root.join(".nt").join("ns");
    Ok(RepoPaths {
        repo_root,
        stage_dir,
        ns_dir,
    })
}

/// Returns repo-relative paths currently staged in the Git index (`git diff --cached --name-only -z`).
pub(crate) fn staged_index_files(repo_root: &Path) -> Result<BTreeSet<String>, WriteError> {
    run_git_nul_path_list(
        repo_root,
        &["diff", "--cached", "--name-only", "-z"],
        "git diff --cached --name-only -z",
    )
}

/// Returns tracked repo-relative paths modified in the working tree (`git diff --name-only -z`).
pub(crate) fn modified_tracked_files(repo_root: &Path) -> Result<BTreeSet<String>, WriteError> {
    run_git_nul_path_list(
        repo_root,
        &["diff", "--name-only", "-z"],
        "git diff --name-only -z",
    )
}

/// Returns tracked repo-relative paths present in `HEAD`, or `None` if `HEAD` is unborn.
pub(crate) fn head_tracked_files(repo_root: &Path) -> Result<Option<BTreeSet<String>>, WriteError> {
    let verify = hardened_git(repo_root)
        .args(["rev-parse", "--verify", "--quiet", "HEAD"])
        .output()
        .map_err(|e| WriteError::io(repo_root, e))?;

    if !verify.status.success() {
        return Ok(None);
    }

    let files = run_git_nul_path_list(
        repo_root,
        &["ls-tree", "-r", "-z", "--name-only", "HEAD"],
        "git ls-tree -r -z --name-only HEAD",
    )?;
    Ok(Some(files))
}

fn run_git_nul_path_list(
    repo_root: &Path,
    args: &[&str],
    label: &str,
) -> Result<BTreeSet<String>, WriteError> {
    let out = hardened_git(repo_root)
        .args(args)
        .output()
        .map_err(|e| WriteError::io(repo_root, e))?;

    if !out.status.success() {
        return Err(WriteError::GitCommandFailed {
            command: label.to_owned(),
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }

    let mut set = BTreeSet::new();
    for entry in out.stdout.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        let path = String::from_utf8_lossy(entry).into_owned();
        set.insert(path);
    }
    Ok(set)
}

/// Runs `git add -- <rel_paths...>` with bounded jittered retry on transient `.git/index.lock` contention.
pub(crate) fn git_add_files(repo_root: &Path, rel_paths: &[String]) -> Result<(), WriteError> {
    if rel_paths.is_empty() {
        return Ok(());
    }
    run_git_index_mutation_with_retry(repo_root, &["add", "--"], rel_paths, "git add")
}

/// Runs `git rm --cached -q --ignore-unmatch -- <rel_paths...>` (safe even on unborn `HEAD`).
pub(crate) fn git_unstage_files(repo_root: &Path, rel_paths: &[String]) -> Result<(), WriteError> {
    if rel_paths.is_empty() {
        return Ok(());
    }
    run_git_index_mutation_with_retry(
        repo_root,
        &["rm", "--cached", "-q", "--ignore-unmatch", "--"],
        rel_paths,
        "git rm --cached",
    )
}

/// Runs `git rm -f -q -- <rel_path>` with bounded retry on `index.lock` contention.
/// Uses `-f` so freshly staged or modified tombstones can be cleanly deleted via `retire --delete`.
pub(crate) fn git_rm_file_force(repo_root: &Path, rel_path: &str) -> Result<(), WriteError> {
    let paths = [rel_path.to_owned()];
    run_git_index_mutation_with_retry(repo_root, &["rm", "-f", "-q", "--"], &paths, "git rm -f")
}

fn run_git_index_mutation_with_retry(
    repo_root: &Path,
    prefix_args: &[&str],
    rel_paths: &[String],
    label: &str,
) -> Result<(), WriteError> {
    const MAX_ATTEMPTS: u32 = 40;
    const CHUNK_SIZE: usize = 256;
    let pid_jitter = u64::from(std::process::id() % 17);

    for chunk in rel_paths.chunks(CHUNK_SIZE) {
        let mut succeeded = false;
        for attempt in 0..MAX_ATTEMPTS {
            let out = hardened_git(repo_root)
                .args(prefix_args)
                .args(chunk)
                .output()
                .map_err(|e| WriteError::io(repo_root, e))?;

            if out.status.success() {
                succeeded = true;
                break;
            }

            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            let is_lock_contention = stderr.contains("index.lock")
                || stderr.contains("Another git process seems to be running");

            if is_lock_contention && attempt + 1 < MAX_ATTEMPTS {
                let base_ms = 10_u64.saturating_mul(u64::from(attempt + 1)).min(120);
                let jitter_ms = (pid_jitter.wrapping_mul(u64::from(attempt + 3))) % 29;
                thread::sleep(Duration::from_millis(base_ms + jitter_ms));
                continue;
            }

            return Err(WriteError::GitCommandFailed {
                command: label.to_owned(),
                code: out.status.code(),
                stderr,
            });
        }
        if !succeeded {
            unreachable!("loop always breaks or returns on final attempt");
        }
    }

    Ok(())
}

fn is_hex_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Fast-path loose-ref HEAD reader (`<git_dir>/HEAD` -> `<git_dir>/<ref>`), falling back to
/// `git rev-parse HEAD` for packed-refs, reftables, or linked worktree shared refs.
pub(crate) fn read_head_sha(repo_root: &Path, stage_dir: &Path) -> Result<String, WriteError> {
    if let Some(git_dir) = stage_dir.parent()
        && let Ok(head_raw) = fs::read_to_string(git_dir.join("HEAD"))
    {
        let head = head_raw.trim();
        if is_hex_oid(head) {
            return Ok(head.to_owned());
        }
        if let Some(ref_rel) = head.strip_prefix("ref: ")
            && !ref_rel.contains("..")
            && !ref_rel.starts_with('/')
            && let Ok(oid_raw) = fs::read_to_string(git_dir.join(ref_rel))
        {
            let oid = oid_raw.trim();
            if is_hex_oid(oid) {
                return Ok(oid.to_owned());
            }
        }
    }

    let out = hardened_git(repo_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| WriteError::io(repo_root, e))?;

    if !out.status.success() {
        return Err(WriteError::GitCommandFailed {
            command: "git rev-parse HEAD".to_owned(),
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }

    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Reads at most `max_bytes` from a regular non-symlink file, returning `Ok(None)` if the file
/// exceeds `max_bytes` without allocating unbounded memory.
pub(crate) fn read_regular_file_bounded(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, WriteError> {
    let meta = fs::symlink_metadata(path).map_err(|e| WriteError::io(path, e))?;
    if !meta.file_type().is_file() {
        return Err(WriteError::NotARegularFile {
            path: path.to_path_buf(),
            reason: "expected regular file (symlinks and special files are forbidden)",
        });
    }
    if meta.len() > max_bytes as u64 {
        return Ok(None);
    }

    let file = File::open(path).map_err(|e| WriteError::io(path, e))?;
    let mut reader = file.take((max_bytes as u64) + 1);
    let mut buf = Vec::with_capacity(meta.len() as usize);
    let mut chunk = [0u8; 4096];

    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(WriteError::io(path, err)),
        }
    }

    if buf.len() > max_bytes {
        return Ok(None);
    }
    Ok(Some(buf))
}

/// Atomically writes `bytes` to `<dir>/<id>.tmp`, calls `sync_all()`, renames via POSIX
/// `rename(2)` to `<dir>/<id>.json`, and best-effort `fsync`s `<dir>`.
pub(crate) fn atomic_write_json_event(
    dir: &Path,
    id: &str,
    bytes: &[u8],
) -> Result<PathBuf, WriteError> {
    fs::create_dir_all(dir).map_err(|e| WriteError::io(dir, e))?;

    let tmp_path = dir.join(format!("{id}.tmp"));
    let final_path = dir.join(format!("{id}.json"));

    // Create exclusively BEFORE registering cleanup so `AlreadyExists` never deletes
    // a `.tmp` file owned by another concurrent writer.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| WriteError::io(&tmp_path, e))?;

    let write_res = (|| -> Result<(), WriteError> {
        file.write_all(bytes)
            .map_err(|e| WriteError::io(&tmp_path, e))?;
        file.sync_all().map_err(|e| WriteError::io(&tmp_path, e))?;
        Ok(())
    })();

    drop(file);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, &final_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(WriteError::io(&final_path, err));
    }

    fsync_dir(dir);
    Ok(final_path)
}

/// Best-effort directory `fsync` to persist atomic rename directory entries on POSIX filesystems.
pub(crate) fn fsync_dir(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}
