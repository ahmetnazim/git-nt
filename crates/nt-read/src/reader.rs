use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use nt_core::{MAX_RECORD_BYTES, is_valid_uuid_v7};

use crate::config::{TrustConfig, validate_commit_oid, validate_ref_name};
use crate::error::ReadError;

/// A single `.nt/ns/{uuid7}.json` blob read from a Git tree or (CLI-only) working tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTreeBlob {
    pub rel_path: String,
    pub bytes: Vec<u8>,
}

/// Immutable snapshot of `.nt/ns/` blobs read from a single resolved commit on a trusted ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedTreeSnapshot {
    pub resolved_commit: String,
    pub blobs: Vec<RawTreeBlob>,
    pub skipped_oversized_or_non_canonical: usize,
}

/// Strictly read-only repository backend abstraction (allows swapping in an in-process
/// backend such as `gix` later without modifying `nt-core`, `nt-mcp`, or `git-nt`).
pub trait RepoReader {
    fn repo_root(&self) -> &Path;

    fn read_trust_config(&self) -> Result<TrustConfig, ReadError>;

    /// Reads regular `.nt/ns/{uuid7}.json` blobs (`< 1,536` bytes) strictly from the Git tree
    /// of `trusted_ref` (never from the working tree).
    fn read_trusted_ns_blobs(&self, trusted_ref: &str) -> Result<TrustedTreeSnapshot, ReadError>;

    /// Reads regular `.nt/ns/{uuid7}.json` blobs from the working tree (CLI `--include-untrusted` ONLY).
    fn read_worktree_ns_blobs(&self) -> Result<(Vec<RawTreeBlob>, usize), ReadError>;

    /// Returns the SHA of the commit on `resolved_commit` that last modified `rel_path`.
    fn last_touching_commit(
        &self,
        resolved_commit: &str,
        rel_path: &str,
    ) -> Result<Option<String>, ReadError>;

    /// Returns Git's `%G?` signature verification status char for `commit_sha`.
    fn verify_commit_signature(&self, commit_sha: &str) -> Result<char, ReadError>;
}

/// Hardened native `git` implementation of [`RepoReader`].
///
/// Every subprocess uses fixed argument arrays (no shell), `LC_ALL=C`, `GIT_TERMINAL_PROMPT=0`,
/// `-c core.fsmonitor=false`, and `-c core.hooksPath=/dev/null`.
#[derive(Debug, Clone)]
pub struct NativeGitReader {
    repo_root: PathBuf,
}

impl NativeGitReader {
    /// Opens the Git repository containing `repo_dir` in strictly read-only mode.
    pub fn open(repo_dir: &Path) -> Result<Self, ReadError> {
        let abs_cwd = fs::canonicalize(repo_dir).map_err(|e| ReadError::io(repo_dir, e))?;
        let out = hardened_git(&abs_cwd)
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .map_err(|e| ReadError::io(&abs_cwd, e))?;

        if !out.status.success() {
            return Err(ReadError::NotAGitRepo(repo_dir.to_path_buf()));
        }

        let top_bytes = trim_single_trailing_newline(&out.stdout);
        let raw_root = PathBuf::from(OsStr::from_bytes(top_bytes));
        let repo_root = fs::canonicalize(&raw_root).unwrap_or(raw_root);
        Ok(Self { repo_root })
    }

    fn parse_git_bool(key: &str, raw: Option<&str>) -> Result<bool, ReadError> {
        // In `git config -z`, a bare key with no value (`[nt]\n\trequireSigned`) means `true`.
        let Some(val) = raw else {
            return Ok(true);
        };
        match val.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Ok(true),
            "false" | "no" | "off" | "0" | "" => Ok(false),
            other => Err(ReadError::GitCommandFailed {
                command: format!("git config -z --get-regexp ({key})"),
                code: Some(128),
                stderr: format!("invalid boolean config value '{other}' for '{key}'"),
            }),
        }
    }

    fn fetch_blobs_batch(&self, items: &[(String, String)]) -> Result<Vec<RawTreeBlob>, ReadError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }

        let mut child = hardened_git(&self.repo_root)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ReadError::io(&self.repo_root, e))?;

        let mut child_stdin = child.stdin.take().ok_or_else(|| {
            ReadError::io(
                &self.repo_root,
                std::io::Error::other("failed to capture git cat-file stdin"),
            )
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            ReadError::io(
                &self.repo_root,
                std::io::Error::other("failed to capture git cat-file stdout"),
            )
        })?;
        let child_stderr = child.stderr.take().ok_or_else(|| {
            ReadError::io(
                &self.repo_root,
                std::io::Error::other("failed to capture git cat-file stderr"),
            )
        })?;

        // Stream OIDs on a scoped writer thread while reading stdout concurrently so large
        // `.nt/ns/` trees can never deadlock on OS pipe buffers.
        let (read_res, stderr_text) = thread::scope(|scope| {
            let writer_handle = scope.spawn(move || -> std::io::Result<()> {
                for (_, oid) in items {
                    child_stdin.write_all(oid.as_bytes())?;
                    child_stdin.write_all(b"\n")?;
                }
                child_stdin.flush()?;
                Ok(())
            });

            let stderr_handle = scope.spawn(move || -> String {
                let mut err_buf = String::new();
                let mut reader = BufReader::new(child_stderr);
                let _ = reader.read_to_string(&mut err_buf);
                err_buf
            });

            let mut reader = BufReader::new(child_stdout);
            let mut blobs = Vec::with_capacity(items.len());

            let loop_res: Result<(), ReadError> = (|| {
                for (rel_path, expected_oid) in items {
                    let mut header = String::new();
                    let n = reader
                        .read_line(&mut header)
                        .map_err(|e| ReadError::io(&self.repo_root, e))?;
                    if n == 0 {
                        return Err(ReadError::GitCommandFailed {
                            command: "git cat-file --batch".to_owned(),
                            code: None,
                            stderr: "unexpected EOF reading batch header".to_owned(),
                        });
                    }
                    let trimmed = header.trim_end_matches(['\r', '\n']);
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() != 3 || parts[0] != expected_oid.as_str() || parts[1] != "blob" {
                        return Err(ReadError::GitCommandFailed {
                            command: "git cat-file --batch".to_owned(),
                            code: None,
                            stderr: format!(
                                "unexpected cat-file header for {expected_oid}: '{trimmed}'"
                            ),
                        });
                    }
                    let size: usize =
                        parts[2].parse().map_err(|_| ReadError::GitCommandFailed {
                            command: "git cat-file --batch".to_owned(),
                            code: None,
                            stderr: format!("invalid blob size in header: '{trimmed}'"),
                        })?;

                    if size >= MAX_RECORD_BYTES {
                        // Drain oversized blob + trailing newline without retaining in memory.
                        let mut to_skip =
                            size.checked_add(1)
                                .ok_or_else(|| ReadError::GitCommandFailed {
                                    command: "git cat-file --batch".to_owned(),
                                    code: None,
                                    stderr: format!("blob size overflow in header: '{trimmed}'"),
                                })?;
                        let mut scratch = [0u8; 4096];
                        while to_skip > 0 {
                            let take = to_skip.min(scratch.len());
                            reader
                                .read_exact(&mut scratch[..take])
                                .map_err(|e| ReadError::io(&self.repo_root, e))?;
                            to_skip -= take;
                        }
                        continue;
                    }

                    let mut bytes = vec![0u8; size];
                    reader
                        .read_exact(&mut bytes)
                        .map_err(|e| ReadError::io(&self.repo_root, e))?;

                    // Consume and verify the single trailing LF emitted by `git cat-file --batch`.
                    let mut lf = [0u8; 1];
                    reader
                        .read_exact(&mut lf)
                        .map_err(|e| ReadError::io(&self.repo_root, e))?;
                    if lf[0] != b'\n' {
                        return Err(ReadError::GitCommandFailed {
                            command: "git cat-file --batch".to_owned(),
                            code: None,
                            stderr: format!("missing trailing LF after blob {expected_oid}"),
                        });
                    }

                    blobs.push(RawTreeBlob {
                        rel_path: rel_path.clone(),
                        bytes,
                    });
                }
                Ok(())
            })();

            let parse_result = match loop_res {
                Ok(()) => Ok(blobs),
                Err(err) => Err(err),
            };

            // Explicitly close stdout and terminate `git` on early parse error BEFORE joining
            // writer/stderr threads so kernel pipe buffers can never deadlock.
            drop(reader);
            if parse_result.is_err() {
                let _ = child.kill();
            }
            let _ = writer_handle.join();
            let err_str = stderr_handle.join().unwrap_or_default();
            (parse_result, err_str)
        });

        let status = child
            .wait()
            .map_err(|e| ReadError::io(&self.repo_root, e))?;
        // Preserve the original parse/protocol error instead of masking it with a SIGKILL exit status.
        let blobs = read_res?;
        if !status.success() {
            return Err(ReadError::GitCommandFailed {
                command: "git cat-file --batch".to_owned(),
                code: status.code(),
                stderr: stderr_text.trim().to_owned(),
            });
        }

        Ok(blobs)
    }
}

impl RepoReader for NativeGitReader {
    fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    fn read_trust_config(&self) -> Result<TrustConfig, ReadError> {
        let mut cfg = TrustConfig::default();

        // Fetch all nt.* trust settings in a single subprocess call (saves 2 git spawns per hydrate/MCP call).
        let out = hardened_git(&self.repo_root)
            .args([
                "config",
                "-z",
                "--get-regexp",
                r"^nt\.(trustedref|requiresigned|allowuntrustedgpgtrust)$",
            ])
            .output()
            .map_err(|e| ReadError::io(&self.repo_root, e))?;

        if !out.status.success() {
            // Exit code 1 means no nt.* keys are set; return defaults.
            if out.status.code() == Some(1) {
                return Ok(cfg);
            }
            return Err(ReadError::GitCommandFailed {
                command: "git config -z --get-regexp ^nt\\.".to_owned(),
                code: out.status.code(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }

        // Precedence order from Git is system -> global -> local; iterating forward makes last value win.
        for entry in out.stdout.split(|&b| b == 0) {
            if entry.is_empty() {
                continue;
            }
            let (key_bytes, val_opt) = match entry.iter().position(|&b| b == b'\n') {
                Some(pos) => (
                    &entry[..pos],
                    Some(String::from_utf8_lossy(&entry[pos + 1..]).into_owned()),
                ),
                None => (entry, None),
            };
            let key = String::from_utf8_lossy(key_bytes);
            match key.as_ref() {
                "nt.trustedref" => {
                    if let Some(ref_val) = val_opt {
                        let trimmed = ref_val.trim();
                        if !trimmed.is_empty() {
                            validate_ref_name(trimmed)?;
                            cfg.trusted_ref = trimmed.to_owned();
                        }
                    }
                }
                "nt.requiresigned" => {
                    cfg.require_signed =
                        Self::parse_git_bool("nt.requireSigned", val_opt.as_deref())?;
                }
                "nt.allowuntrustedgpgtrust" => {
                    cfg.allow_untrusted_gpg_trust =
                        Self::parse_git_bool("nt.allowUntrustedGpgTrust", val_opt.as_deref())?;
                }
                _ => {}
            }
        }

        Ok(cfg)
    }

    fn read_trusted_ns_blobs(&self, trusted_ref: &str) -> Result<TrustedTreeSnapshot, ReadError> {
        validate_ref_name(trusted_ref)?;

        // Resolve the trusted ref ONCE to an immutable commit OID so tree listing, blob reads,
        // and signature verification all inspect the exact same commit snapshot.
        let commit_spec = format!("{trusted_ref}^{{commit}}");
        let rev_out = hardened_git(&self.repo_root)
            .args(["rev-parse", "--verify", "--quiet", &commit_spec])
            .output()
            .map_err(|e| ReadError::io(&self.repo_root, e))?;

        if !rev_out.status.success() {
            return Err(ReadError::TrustedRefNotFound(trusted_ref.to_owned()));
        }
        let resolved_commit = String::from_utf8_lossy(&rev_out.stdout).trim().to_owned();

        let ls_out = hardened_git(&self.repo_root)
            .args([
                "ls-tree",
                "-r",
                "-l",
                "-z",
                &resolved_commit,
                "--",
                ".nt/ns",
            ])
            .output()
            .map_err(|e| ReadError::io(&self.repo_root, e))?;

        if !ls_out.status.success() {
            return Err(ReadError::GitCommandFailed {
                command: "git ls-tree -r -l -z".to_owned(),
                code: ls_out.status.code(),
                stderr: String::from_utf8_lossy(&ls_out.stderr).trim().to_owned(),
            });
        }

        let mut to_fetch: Vec<(String, String)> = Vec::new();
        let mut skipped = 0usize;

        for entry in ls_out.stdout.split(|&b| b == 0) {
            if entry.is_empty() {
                continue;
            }
            let Some(tab_pos) = entry.iter().position(|&b| b == b'\t') else {
                skipped += 1;
                continue;
            };
            let meta = String::from_utf8_lossy(&entry[..tab_pos]);
            let rel_path = String::from_utf8_lossy(&entry[tab_pos + 1..]).into_owned();

            let parts: Vec<&str> = meta.split_whitespace().collect();
            if parts.len() != 4 {
                skipped += 1;
                continue;
            }
            let (mode, obj_type, oid, size_str) = (parts[0], parts[1], parts[2], parts[3]);

            // Accept ONLY regular non-symlink blobs directly inside `.nt/ns/{uuid7}.json`.
            if !matches!(mode, "100644" | "100755") || obj_type != "blob" {
                skipped += 1;
                continue;
            }

            let Some(file_name) = rel_path.strip_prefix(".nt/ns/") else {
                skipped += 1;
                continue;
            };
            if file_name.contains('/') {
                skipped += 1;
                continue;
            }
            let Some(stem) = file_name.strip_suffix(".json") else {
                skipped += 1;
                continue;
            };
            if !is_valid_uuid_v7(stem) {
                skipped += 1;
                continue;
            }

            let Ok(size) = size_str.parse::<usize>() else {
                skipped += 1;
                continue;
            };
            if size >= MAX_RECORD_BYTES {
                skipped += 1;
                continue;
            }

            to_fetch.push((rel_path, oid.to_owned()));
        }

        let blobs = self.fetch_blobs_batch(&to_fetch)?;
        Ok(TrustedTreeSnapshot {
            resolved_commit,
            blobs,
            skipped_oversized_or_non_canonical: skipped,
        })
    }

    fn read_worktree_ns_blobs(&self) -> Result<(Vec<RawTreeBlob>, usize), ReadError> {
        let nt_root = self.repo_root.join(".nt");
        match fs::symlink_metadata(&nt_root) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Err(ReadError::SymlinkEscape { path: nt_root }),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(err) => return Err(ReadError::io(&nt_root, err)),
        }

        let ns_dir = nt_root.join("ns");
        match fs::symlink_metadata(&ns_dir) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Err(ReadError::SymlinkEscape { path: ns_dir }),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(err) => return Err(ReadError::io(&ns_dir, err)),
        }

        let mut entries: Vec<_> = fs::read_dir(&ns_dir)
            .map_err(|e| ReadError::io(&ns_dir, e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ReadError::io(&ns_dir, e))?;
        entries.sort_by_key(|e| e.file_name());

        let mut blobs = Vec::new();
        let mut skipped = 0usize;

        for entry in entries {
            let abs = entry.path();
            let Ok(ft) = entry.file_type() else {
                skipped += 1;
                continue;
            };
            if !ft.is_file() {
                skipped += 1;
                continue;
            }
            let Some(name) = abs.file_name().and_then(|n| n.to_str()) else {
                skipped += 1;
                continue;
            };
            let Some(stem) = name.strip_suffix(".json") else {
                skipped += 1;
                continue;
            };
            if !is_valid_uuid_v7(stem) {
                skipped += 1;
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(&abs) else {
                skipped += 1;
                continue;
            };
            if !meta.file_type().is_file() || meta.len() >= MAX_RECORD_BYTES as u64 {
                skipped += 1;
                continue;
            }

            let file = File::open(&abs).map_err(|e| ReadError::io(&abs, e))?;
            let mut reader = file.take(MAX_RECORD_BYTES as u64);
            let mut bytes = Vec::with_capacity(meta.len() as usize);
            reader
                .read_to_end(&mut bytes)
                .map_err(|e| ReadError::io(&abs, e))?;

            if bytes.len() >= MAX_RECORD_BYTES {
                skipped += 1;
                continue;
            }

            blobs.push(RawTreeBlob {
                rel_path: format!(".nt/ns/{name}"),
                bytes,
            });
        }

        Ok((blobs, skipped))
    }

    fn last_touching_commit(
        &self,
        resolved_commit: &str,
        rel_path: &str,
    ) -> Result<Option<String>, ReadError> {
        validate_commit_oid(resolved_commit)?;

        let out = hardened_git(&self.repo_root)
            .args([
                "log",
                "-n",
                "1",
                "--format=%H",
                resolved_commit,
                "--",
                rel_path,
            ])
            .output()
            .map_err(|e| ReadError::io(&self.repo_root, e))?;

        if !out.status.success() {
            return Err(ReadError::GitCommandFailed {
                command: format!("git log -n 1 --format=%H {resolved_commit} -- {rel_path}"),
                code: out.status.code(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }

        let sha = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if sha.is_empty() {
            Ok(None)
        } else {
            validate_commit_oid(&sha)?;
            Ok(Some(sha))
        }
    }

    fn verify_commit_signature(&self, commit_sha: &str) -> Result<char, ReadError> {
        validate_commit_oid(commit_sha)?;

        let out = hardened_git(&self.repo_root)
            .args(["log", "-n", "1", "--format=%G?", commit_sha, "--"])
            .output()
            .map_err(|e| ReadError::io(&self.repo_root, e))?;

        if !out.status.success() {
            return Err(ReadError::GitCommandFailed {
                command: format!("git log -n 1 --format=%G? {commit_sha} --"),
                code: out.status.code(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            });
        }

        let trimmed = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let Some(status_char) = trimmed.chars().next() else {
            return Err(ReadError::GitCommandFailed {
                command: format!("git log -n 1 --format=%G? {commit_sha} --"),
                code: out.status.code(),
                stderr: "empty signature status output from git log".to_owned(),
            });
        };
        Ok(status_char)
    }
}

fn hardened_git(cwd: &Path) -> Command {
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
