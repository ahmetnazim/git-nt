#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use nt_core::{
    FailureClass, MAX_RECORD_BYTES, NegativeSpaceRecord, RecordStatus, SCHEMA_VERSION,
    generate_uuid_v7, now_rfc3339_utc, sha256_digest,
};
use nt_write::{
    AuditFinding, CommitOptions, PromoteOptions, RetireMode, StageRequest, WriteError,
    audit_repository, commit_with_options, list_staged_files, parse_stage_request_json,
    promote_staged, resolve_repo_paths, retire_tombstone, stage_record,
};

/// Pure-`std` RAII guard for auxiliary temporary directories (e.g., linked worktrees).
struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(label: &str) -> Self {
        let id = generate_uuid_v7().expect("uuid v7");
        let path = std::env::temp_dir().join(format!("git-nt-tmp-{label}-{id}"));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Pure-`std` RAII temporary Git repository helper (no external `tempfile` dev-dependency).
struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    fn new(label: &str) -> Self {
        let id = generate_uuid_v7().expect("uuid v7");
        let dir = std::env::temp_dir().join(format!("git-nt-test-{label}-{id}"));
        fs::create_dir_all(&dir).expect("create temp repo dir");
        run_git(&dir, &["init", "-b", "main"]);
        run_git(&dir, &["config", "user.name", "git-nt-test"]);
        run_git(&dir, &["config", "user.email", "test@neurotiler.dev"]);
        run_git(&dir, &["config", "commit.gpgsign", "false"]);
        run_git(&dir, &["config", "core.hooksPath", ".git/hooks"]);
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write_file(&self, rel: &str, contents: &str) {
        let full = self.path.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&full, contents).expect("write repo file");
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn quiet_commit_opts(promote_all: bool) -> CommitOptions {
    CommitOptions {
        promote_all,
        inherit_stdio: false,
    }
}

fn sample_request(file: &str, sym: &str) -> StageRequest {
    StageRequest {
        files: vec![file.to_owned()],
        target_symbol: sym.to_owned(),
        failure_class: FailureClass::ConcurrencyDeadlock,
        discarded_pattern: "std::sync::RwLockWriteGuard held across async disk read".to_owned(),
        invariant: "Coalesce concurrent misses using per-key tokio::sync::OnceCell<Arc<Tile>>"
            .to_owned(),
        supersedes: None,
        think_file: None,
    }
}

#[test]
fn stage_from_json_fail_closed_secrets_and_streaming_think_hash() {
    let repo = TempRepo::new("stage-json");
    repo.write_file("src/tile_cache.rs", "pub fn load() {}\n");

    // 1. Fail-closed secret rejection by default
    let secret_json = br#"{
        "files": ["src/tile_cache.rs"],
        "target_symbol": "TileCache::get_or_load",
        "failure_class": "SECURITY_BOUNDARY",
        "discarded_pattern": "Hardcoded key sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        "invariant": "Load credentials exclusively from environment"
    }"#;
    let secret_req = parse_stage_request_json(secret_json).expect("valid stage request JSON");
    assert!(matches!(
        stage_record(repo.path(), &secret_req, false),
        Err(WriteError::SecretDetected {
            field: "discarded_pattern"
        })
    ));
    let paths = resolve_repo_paths(repo.path()).unwrap();
    assert!(list_staged_files(&paths.stage_dir).unwrap().is_empty());

    // 2. Explicit `--redact-secrets` override redacts before persisting
    let redacted =
        stage_record(repo.path(), &secret_req, true).expect("stage with redact override");
    assert!(!redacted.record.discarded_pattern.contains("sk-proj-"));
    assert!(
        redacted
            .record
            .discarded_pattern
            .contains("[REDACTED_SECRET]")
    );

    // 3. Streaming `--think-file` digest (raw reasoning trace stays local, never staged)
    let think_dir = repo.path().join(".nt-local");
    fs::create_dir_all(&think_dir).unwrap();
    let think_file = think_dir.join("attempt_01.think.log");
    let raw_think = "TOP SECRET RAW REASONING TRACE\n".repeat(1024);
    fs::write(&think_file, &raw_think).unwrap();
    let expected_digest = sha256_digest(raw_think.as_bytes());

    let mut req = sample_request("src/tile_cache.rs", "TileCache::get_or_load");
    req.think_file = Some(think_file);
    let staged = stage_record(repo.path(), &req, false).expect("stage with think file");
    assert_eq!(
        staged.record.local_think_digest.as_deref(),
        Some(expected_digest.as_str())
    );

    let staged_bytes = fs::read(&staged.staged_path).unwrap();
    let staged_text = std::str::from_utf8(&staged_bytes).unwrap();
    assert!(!staged_text.contains("TOP SECRET RAW REASONING TRACE"));
    assert_eq!(staged_bytes, staged.record.to_jcs_bytes().unwrap());

    // Reject directory passed as think_file
    let mut bad_think = sample_request("src/tile_cache.rs", "TileCache::get_or_load");
    bad_think.think_file = Some(think_dir);
    assert!(matches!(
        stage_record(repo.path(), &bad_think, false),
        Err(WriteError::NotARegularFile { .. })
    ));

    // Zero leftover .tmp files in stage dir
    let leftovers: Vec<_> = fs::read_dir(&paths.stage_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn resolve_repo_paths_works_from_subdirectory_and_linked_worktree() {
    let repo = TempRepo::new("worktree");
    repo.write_file("src/sub/mod.rs", "pub const X: u32 = 1;\n");
    run_git(repo.path(), &["add", "."]);
    run_git(repo.path(), &["commit", "-m", "initial"]);

    let root_paths = resolve_repo_paths(repo.path()).unwrap();
    let sub_paths = resolve_repo_paths(&repo.path().join("src/sub")).unwrap();
    assert_eq!(root_paths.repo_root, sub_paths.repo_root);
    assert!(root_paths.stage_dir.is_absolute());
    assert!(sub_paths.stage_dir.is_absolute());
    assert_eq!(
        fs::canonicalize(root_paths.stage_dir.parent().unwrap()).unwrap(),
        fs::canonicalize(sub_paths.stage_dir.parent().unwrap()).unwrap()
    );

    // Linked Git worktree gets its own isolated `.git/worktrees/<name>/nt-stage`
    let wt_guard = TempDirGuard::new("wt");
    run_git(
        repo.path(),
        &[
            "worktree",
            "add",
            "-b",
            "wt-branch",
            wt_guard.path().to_str().unwrap(),
        ],
    );

    let wt_paths = resolve_repo_paths(wt_guard.path()).unwrap();
    assert_ne!(wt_paths.stage_dir, root_paths.stage_dir);
    assert!(
        wt_paths.stage_dir.to_string_lossy().contains("worktrees"),
        "expected per-worktree stage dir, got {:?}",
        wt_paths.stage_dir
    );
}

#[test]
fn diff_filtered_commit_flag_parsing_and_subdir_relative_message_file() {
    let repo = TempRepo::new("diff-filter");
    repo.write_file("src/a.rs", "pub fn a() {}\n");
    repo.write_file("src/b.rs", "pub fn b() {}\n");
    run_git(repo.path(), &["add", "src/a.rs", "src/b.rs"]);
    run_git(repo.path(), &["commit", "-m", "init"]);

    // Stage tombstones for both src/a.rs and src/b.rs
    let art_a = stage_record(repo.path(), &sample_request("src/a.rs", "a::run"), false).unwrap();
    let art_b = stage_record(repo.path(), &sample_request("src/b.rs", "b::run"), false).unwrap();

    // Modify and stage ONLY src/a.rs, and verify dry-run / partial pathspec args fail closed
    repo.write_file("src/a.rs", "pub fn a() { /* fixed */ }\n");
    run_git(repo.path(), &["add", "src/a.rs"]);

    for bad_args in [
        vec!["--dry-run".to_owned(), "-m".to_owned(), "check".to_owned()],
        vec!["--short".to_owned()],
        vec!["--porcelain".to_owned()],
        vec!["-o".to_owned(), "-m".to_owned(), "x".to_owned()],
        vec!["--only".to_owned(), "-m".to_owned(), "x".to_owned()],
        vec!["-m".to_owned(), "x".to_owned(), "src/a.rs".to_owned()],
        vec![
            "-m".to_owned(),
            "x".to_owned(),
            "--".to_owned(),
            "src/a.rs".to_owned(),
        ],
        vec!["--pathspec-from-file=paths.txt".to_owned()],
    ] {
        let err = commit_with_options(repo.path(), &bad_args, quiet_commit_opts(false))
            .expect_err("unsupported commit args must fail closed");
        assert!(
            matches!(err, WriteError::UnsupportedCommitArgs { .. }),
            "expected UnsupportedCommitArgs for {bad_args:?}, got {err:?}"
        );
    }

    // Confirm zero mutation after rejected dry-run/pathspec attempts
    let paths = resolve_repo_paths(repo.path()).unwrap();
    assert_eq!(list_staged_files(&paths.stage_dir).unwrap().len(), 2);
    assert!(!paths.ns_dir.exists());

    // Commit from subdirectory `src/` using relative `-F msg.txt` AND `-sm "-a"`
    // (`-sm "-a"` must NOT trigger `--all` for unstaged tracked edits in src/b.rs)
    repo.write_file("src/b.rs", "pub fn b() { /* unstaged */ }\n");
    repo.write_file("src/msg.txt", "fix(a): apply invariant\n");

    let report = commit_with_options(
        &repo.path().join("src"),
        &["-s".to_owned(), "-F".to_owned(), "msg.txt".to_owned()],
        quiet_commit_opts(false),
    )
    .expect("commit from subdir with relative -F");

    assert_eq!(report.promoted_ids, vec![art_a.record.id.clone()]);
    assert_eq!(report.skipped_unmatched, 1);
    assert!(
        repo.path()
            .join(format!(".nt/ns/{}.json", art_a.record.id))
            .is_file()
    );
    assert!(
        !repo
            .path()
            .join(format!(".nt/ns/{}.json", art_b.record.id))
            .is_file()
    );

    // Now test `-u -a -m "fix(b)"` (`-u` must NOT swallow `-a`)
    let report_b = commit_with_options(
        repo.path(),
        &[
            "-u".to_owned(),
            "-a".to_owned(),
            "-m".to_owned(),
            "fix(b): tracked modification".to_owned(),
        ],
        quiet_commit_opts(false),
    )
    .expect("commit with -u -a should promote unstaged tracked src/b.rs tombstone");
    assert_eq!(report_b.promoted_ids, vec![art_b.record.id.clone()]);
    assert!(audit_repository(repo.path()).unwrap().is_clean());

    // Verify `-sm "-a"` does NOT treat commit message "-a" as `--all`, and `--no-all` overrides `-a`
    let art_c = stage_record(repo.path(), &sample_request("src/b.rs", "b::second"), false).unwrap();
    repo.write_file("src/b.rs", "pub fn b() { /* unstaged 2 */ }\n");
    repo.write_file("src/a.rs", "pub fn a() { /* staged 2 */ }\n");
    run_git(repo.path(), &["add", "src/a.rs"]);

    let report_sm = commit_with_options(
        repo.path(),
        &["-sm".to_owned(), "-a".to_owned()],
        quiet_commit_opts(false),
    )
    .expect("commit with -sm '-a'");
    assert!(
        report_sm.promoted_ids.is_empty(),
        "'-a' message after '-sm' must not enable --all"
    );
    assert_eq!(
        list_staged_files(&paths.stage_dir).unwrap(),
        vec![art_c.staged_path]
    );
}

#[test]
fn native_pre_commit_hook_and_ssh_commit_signing_work_with_rollback() {
    let repo = TempRepo::new("hook-signing");
    repo.write_file("src/lib.rs", "pub fn ok() {}\n");
    run_git(repo.path(), &["add", "src/lib.rs"]);
    run_git(repo.path(), &["commit", "-m", "initial"]);

    // Configure real ephemeral SSH signing key inside temp repo (zero global config mutation)
    let key_dir = TempDirGuard::new("ssh-key");
    fs::create_dir_all(key_dir.path()).unwrap();
    let key_path = key_dir.path().join("id_ed25519");
    let keygen = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "test@neurotiler.dev",
            "-f",
        ])
        .arg(&key_path)
        .status()
        .expect("run ssh-keygen");
    assert!(keygen.success(), "ssh-keygen must succeed");

    let pub_key = fs::read_to_string(key_dir.path().join("id_ed25519.pub")).unwrap();
    let allowed_signers = key_dir.path().join("allowed_signers");
    fs::write(
        &allowed_signers,
        format!("test@neurotiler.dev {}\n", pub_key.trim()),
    )
    .unwrap();

    run_git(repo.path(), &["config", "gpg.format", "ssh"]);
    run_git(
        repo.path(),
        &["config", "user.signingkey", key_path.to_str().unwrap()],
    );
    run_git(
        repo.path(),
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            allowed_signers.to_str().unwrap(),
        ],
    );
    run_git(repo.path(), &["config", "commit.gpgsign", "true"]);

    // Modify src/lib.rs and stage a tombstone
    repo.write_file("src/lib.rs", "pub fn ok() { /* v2 */ }\n");
    run_git(repo.path(), &["add", "src/lib.rs"]);
    let art = stage_record(repo.path(), &sample_request("src/lib.rs", "lib::ok"), false).unwrap();

    // Install a rejecting pre-commit hook first -> verify atomic rollback
    let hook_path = repo.path().join(".git/hooks/pre-commit");
    fs::write(
        &hook_path,
        "#!/bin/sh\necho 'hook rejected commit' >&2\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).unwrap();

    let err = commit_with_options(
        repo.path(),
        &["-m".to_owned(), "should fail".to_owned()],
        quiet_commit_opts(false),
    )
    .expect_err("rejecting pre-commit hook must fail commit");
    assert!(matches!(
        err,
        WriteError::CommitFailed { code: Some(1), .. }
    ));

    let ns_file = repo.path().join(format!(".nt/ns/{}.json", art.record.id));
    assert!(
        !ns_file.exists(),
        "rolled-back tombstone file must not exist"
    );
    let cached = run_git(repo.path(), &["diff", "--cached", "--name-only"]);
    assert!(
        !cached.contains(".nt/ns/"),
        "rolled-back tombstone must be unstaged"
    );

    let paths = resolve_repo_paths(repo.path()).unwrap();
    assert_eq!(
        list_staged_files(&paths.stage_dir).unwrap(),
        vec![art.staged_path.clone()]
    );
    let claimed_leftovers: Vec<_> = fs::read_dir(&paths.stage_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".claimed-"))
        .collect();
    assert!(claimed_leftovers.is_empty());

    // Replace hook with a passing hook writing a sentinel, then commit with `-S` SSH signing
    let sentinel = repo.path().join(".git/hook-ran");
    fs::write(
        &hook_path,
        format!("#!/bin/sh\necho ok > '{}'\nexit 0\n", sentinel.display()),
    )
    .unwrap();
    fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).unwrap();

    let ok_report = commit_with_options(
        repo.path(),
        &[
            "-S".to_owned(),
            "-m".to_owned(),
            "signed commit passes hook".to_owned(),
        ],
        quiet_commit_opts(false),
    )
    .expect("signed commit should succeed once hook passes");

    assert!(
        sentinel.is_file(),
        "native pre-commit hook must have executed"
    );
    assert_eq!(ok_report.promoted_ids, vec![art.record.id]);
    assert!(ns_file.is_file());
    assert!(list_staged_files(&paths.stage_dir).unwrap().is_empty());

    // Cryptographically verify the commit carries a valid 'G' SSH signature
    let sig_status = run_git(repo.path(), &["log", "-n", "1", "--format=%G?", "HEAD"]);
    assert_eq!(
        sig_status.trim(),
        "G",
        "expected verified good SSH signature ('G') on commit"
    );
}

#[test]
fn retire_handles_near_ceiling_staged_corrupt_symlinks_and_audit_detects_all_findings() {
    let repo = TempRepo::new("retire-audit");
    repo.write_file("src/cache.rs", "pub struct Cache;\n");
    run_git(repo.path(), &["add", "src/cache.rs"]);
    run_git(repo.path(), &["commit", "-m", "initial"]);

    // 1. Retiring a valid near-ceiling (~1,500 byte) active tombstone must NOT overflow 1,536 bytes
    let long_files: Vec<String> = (0..18)
        .map(|i| format!("src/cache_module_path_{i:02}.rs"))
        .collect();
    for f in &long_files {
        repo.write_file(f, "// file\n");
    }
    run_git(repo.path(), &["add", "src"]);
    run_git(repo.path(), &["commit", "-m", "add files"]);

    let near_ceiling = NegativeSpaceRecord {
        schema_version: SCHEMA_VERSION,
        id: generate_uuid_v7().unwrap(),
        created_at: now_rfc3339_utc().unwrap(),
        files: long_files,
        target_symbol: "a".repeat(200),
        failure_class: FailureClass::ConcurrencyDeadlock,
        discarded_pattern: "b".repeat(240),
        invariant: "c".repeat(200),
        status: RecordStatus::Active,
        supersedes: None,
        local_think_digest: Some(sha256_digest(b"think")),
    };
    let near_bytes = near_ceiling.to_jcs_bytes().unwrap();
    assert!(
        near_bytes.len() > 1_450 && near_bytes.len() < MAX_RECORD_BYTES,
        "expected near-ceiling tombstone (got {} bytes)",
        near_bytes.len()
    );
    fs::create_dir_all(repo.path().join(".nt/ns")).unwrap();
    fs::write(
        repo.path().join(format!(".nt/ns/{}.json", near_ceiling.id)),
        &near_bytes,
    )
    .unwrap();
    run_git(repo.path(), &["add", ".nt/ns"]);
    run_git(
        repo.path(),
        &["commit", "-m", "commit near-ceiling tombstone"],
    );

    let retired_near = retire_tombstone(
        repo.path(),
        &near_ceiling.id,
        false,
        Some("Replaced after refactor"),
    )
    .expect("retiring near-ceiling tombstone must fit under 1,536 bytes");
    assert_eq!(retired_near.mode, RetireMode::Superseded);
    let retired_near_id = retired_near.retired_record_id.unwrap();

    // 2. `retire --delete` works on a freshly staged (uncommitted) tombstone!
    let deleted_staged = retire_tombstone(repo.path(), &retired_near_id, true, None)
        .expect("retire --delete must succeed on freshly staged tombstone");
    assert_eq!(deleted_staged.mode, RetireMode::Deleted);
    assert!(
        !repo
            .path()
            .join(format!(".nt/ns/{retired_near_id}.json"))
            .exists()
    );

    // 3. `retire --delete` works even on a corrupt/oversized tombstone flagged by audit
    let corrupt_id = generate_uuid_v7().unwrap();
    let corrupt_rel = format!(".nt/ns/{corrupt_id}.json");
    fs::write(repo.path().join(&corrupt_rel), vec![b' '; MAX_RECORD_BYTES]).unwrap();
    run_git(repo.path(), &["add", &corrupt_rel]);
    let deleted_corrupt = retire_tombstone(repo.path(), &corrupt_id, true, None)
        .expect("retire --delete must delete oversized/corrupt tombstones");
    assert_eq!(deleted_corrupt.mode, RetireMode::Deleted);

    // 4. `retire` rejects symlinks in `.nt/ns/`
    let sym_id = generate_uuid_v7().unwrap();
    let sym_path = repo.path().join(format!(".nt/ns/{sym_id}.json"));
    symlink(repo.path().join("src/cache.rs"), &sym_path).unwrap();
    assert!(matches!(
        retire_tombstone(repo.path(), &sym_id, true, None),
        Err(WriteError::NotARegularFile { .. })
    ));
    fs::remove_file(&sym_path).unwrap();

    // 5. Audit catches: NonCanonicalJcs, OversizedRecord, UnredactedSecret, IdFilenameMismatch,
    //    InvalidRecord (unknown FailureClass), UnexpectedEntry (stray file), and OrphanedPath
    let art = stage_record(
        repo.path(),
        &sample_request("src/cache.rs", "Cache::get"),
        false,
    )
    .unwrap();
    promote_staged(repo.path(), PromoteOptions { promote_all: true }).unwrap();
    run_git(repo.path(), &["commit", "-m", "add cache tombstone"]);
    run_git(repo.path(), &["rm", "src/cache.rs"]);
    run_git(repo.path(), &["commit", "-m", "remove cache.rs"]);

    // Tamper: pretty-printed JSON (NonCanonicalJcs)
    let pretty_id = generate_uuid_v7().unwrap();
    let mut rec_pretty = art.record.clone();
    rec_pretty.id = pretty_id.clone();
    rec_pretty.status = RecordStatus::Retired;
    fs::write(
        repo.path().join(format!(".nt/ns/{pretty_id}.json")),
        serde_json::to_vec_pretty(&rec_pretty).unwrap(),
    )
    .unwrap();

    // Tamper: oversized (>= 1536 bytes)
    let oversized_id = generate_uuid_v7().unwrap();
    fs::write(
        repo.path().join(format!(".nt/ns/{oversized_id}.json")),
        vec![b' '; MAX_RECORD_BYTES],
    )
    .unwrap();

    // Tamper: unredacted secret directly written into `.nt/ns/`
    let secret_id = generate_uuid_v7().unwrap();
    let mut rec_secret = art.record.clone();
    rec_secret.id = secret_id.clone();
    rec_secret.status = RecordStatus::Retired;
    rec_secret.discarded_pattern = "leaked sk-proj-abcdefghijklmnopqrstuvwxyz123456".to_owned();
    fs::write(
        repo.path().join(format!(".nt/ns/{secret_id}.json")),
        rec_secret.to_jcs_bytes().unwrap(),
    )
    .unwrap();

    // Tamper: filename stem != record.id (IdFilenameMismatch)
    let mismatch_stem = generate_uuid_v7().unwrap();
    let mut rec_mismatch = art.record.clone();
    rec_mismatch.id = generate_uuid_v7().unwrap();
    rec_mismatch.status = RecordStatus::Retired;
    fs::write(
        repo.path().join(format!(".nt/ns/{mismatch_stem}.json")),
        rec_mismatch.to_jcs_bytes().unwrap(),
    )
    .unwrap();

    // Tamper: unknown FailureClass (InvalidRecord)
    let bad_enum_id = generate_uuid_v7().unwrap();
    let bad_enum_json = format!(
        r#"{{"created_at":"2026-11-18T14:22:09Z","discarded_pattern":"x","failure_class":"UNKNOWN_CLASS","files":["src/cache.rs"],"id":"{bad_enum_id}","invariant":"y","schema_version":1,"status":"active","target_symbol":"z"}}"#
    );
    fs::write(
        repo.path().join(format!(".nt/ns/{bad_enum_id}.json")),
        bad_enum_json,
    )
    .unwrap();

    // Tamper: stray non-JSON file (UnexpectedEntry)
    fs::write(repo.path().join(".nt/ns/README.txt"), "stray").unwrap();

    let report = audit_repository(repo.path()).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, AuditFinding::OrphanedPath { missing_repo_path, .. } if missing_repo_path == "src/cache.rs"))
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, AuditFinding::NonCanonicalJcs { .. }))
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, AuditFinding::OversizedRecord { .. }))
    );
    assert!(report.findings.iter().any(|f| matches!(
        f,
        AuditFinding::UnredactedSecret {
            field: "discarded_pattern",
            ..
        }
    )));
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, AuditFinding::IdFilenameMismatch { .. }))
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, AuditFinding::InvalidRecord { .. }))
    );
    assert!(report.findings.iter().any(
        |f| matches!(f, AuditFinding::UnexpectedEntry { path, .. } if path == ".nt/ns/README.txt")
    ));

    // 6. Audit catches dangling symlink at `.nt/ns` (must NOT silently report clean!)
    let sym_repo = TempRepo::new("audit-dangling-ns");
    fs::create_dir_all(sym_repo.path().join(".nt")).unwrap();
    symlink(
        sym_repo.path().join("does-not-exist"),
        sym_repo.path().join(".nt/ns"),
    )
    .unwrap();
    let sym_report = audit_repository(sym_repo.path()).unwrap();
    assert!(
        sym_report
            .findings
            .iter()
            .any(|f| matches!(f, AuditFinding::UnexpectedEntry { path, .. } if path == ".nt/ns")),
        "dangling symlink at .nt/ns must be flagged, got {:?}",
        sym_report.findings
    );
}

/// Multi-process worker entrypoint invoked by `multiprocess_stress_16x50_staging_and_promote_races`.
#[test]
#[ignore]
fn stress_worker_entry() {
    let mode = std::env::var("NT_STRESS_MODE").expect("NT_STRESS_MODE");
    let repo_dir = PathBuf::from(std::env::var("NT_STRESS_REPO").expect("NT_STRESS_REPO"));
    let worker_idx = std::env::var("NT_STRESS_WORKER_ID").expect("NT_STRESS_WORKER_ID");

    match mode.as_str() {
        "stage" => {
            let count: usize = std::env::var("NT_STRESS_COUNT").unwrap().parse().unwrap();
            for seq in 0..count {
                let req = sample_request("src/hot.rs", &format!("Worker{worker_idx}::event_{seq}"));
                stage_record(&repo_dir, &req, false).expect("concurrent stage_record");
            }
        }
        "promote" => {
            let report = promote_staged(&repo_dir, PromoteOptions { promote_all: true })
                .expect("concurrent promote_staged");
            for id in report.promoted_ids {
                println!("PROMOTED:{id}");
            }
        }
        other => panic!("unknown NT_STRESS_MODE: {other}"),
    }
}

#[test]
fn multiprocess_stress_16x50_staging_and_promote_races() {
    const STAGE_PROCS: usize = 16;
    const EVENTS_PER_PROC: usize = 50;
    const TOTAL_EVENTS: usize = STAGE_PROCS * EVENTS_PER_PROC;
    const PROMOTE_PROCS: usize = 8;

    let repo = TempRepo::new("stress-16x50");
    repo.write_file("src/hot.rs", "pub fn hot() {}\n");
    run_git(repo.path(), &["add", "src/hot.rs"]);
    run_git(repo.path(), &["commit", "-m", "initial"]);

    let exe = std::env::current_exe().expect("current test binary");

    // Phase A: 16 concurrent OS processes × 50 staging events = 800 total
    let mut children = Vec::with_capacity(STAGE_PROCS);
    for idx in 0..STAGE_PROCS {
        let child = Command::new(&exe)
            .args(["--exact", "--ignored", "--nocapture", "stress_worker_entry"])
            .env("NT_STRESS_MODE", "stage")
            .env("NT_STRESS_REPO", repo.path())
            .env("NT_STRESS_WORKER_ID", idx.to_string())
            .env("NT_STRESS_COUNT", EVENTS_PER_PROC.to_string())
            .spawn()
            .expect("spawn stage worker");
        children.push(child);
    }

    for child in children {
        let out = child.wait_with_output().expect("wait stage worker");
        assert!(
            out.status.success(),
            "stage worker failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let paths = resolve_repo_paths(repo.path()).unwrap();
    let staged = list_staged_files(&paths.stage_dir).unwrap();
    assert_eq!(
        staged.len(),
        TOTAL_EVENTS,
        "expected {TOTAL_EVENTS} staged JSON files, got {}",
        staged.len()
    );

    for entry in fs::read_dir(&paths.stage_dir)
        .unwrap()
        .filter_map(Result::ok)
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            name.ends_with(".json"),
            "unexpected leftover non-json file in stage dir: {name}"
        );
        let raw = fs::read(entry.path()).unwrap();
        let rec = NegativeSpaceRecord::from_jcs_bytes(&raw).expect("valid staged JCS");
        assert_eq!(raw, rec.to_jcs_bytes().unwrap());
    }

    // Phase B: 8 concurrent OS processes racing to claim & promote all 800 staged tombstones
    let mut promote_children = Vec::with_capacity(PROMOTE_PROCS);
    for idx in 0..PROMOTE_PROCS {
        let child = Command::new(&exe)
            .args(["--exact", "--ignored", "--nocapture", "stress_worker_entry"])
            .env("NT_STRESS_MODE", "promote")
            .env("NT_STRESS_REPO", repo.path())
            .env("NT_STRESS_WORKER_ID", idx.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn promote worker");
        promote_children.push(child);
    }

    let mut claimed_total = 0usize;
    let mut unique_ids = BTreeSet::new();
    for child in promote_children {
        let out = child.wait_with_output().expect("wait promote worker");
        assert!(
            out.status.success(),
            "promote worker failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(id) = line.strip_prefix("PROMOTED:") {
                claimed_total += 1;
                assert!(
                    unique_ids.insert(id.to_owned()),
                    "duplicate promotion of tombstone '{id}' across concurrent processes!"
                );
            }
        }
    }

    assert_eq!(claimed_total, TOTAL_EVENTS);
    assert_eq!(unique_ids.len(), TOTAL_EVENTS);

    // Zero leftover `.json`, `.tmp`, or `.claimed-*` files in `.git/nt-stage/`
    let remaining_stage_entries: Vec<_> = fs::read_dir(&paths.stage_dir)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        remaining_stage_entries.is_empty(),
        "expected empty stage dir after concurrent promote, found {:?}",
        remaining_stage_entries
    );

    // Verify all 800 tombstones are both present on disk AND staged in the Git index
    let cached_ns_count = run_git(repo.path(), &["diff", "--cached", "--name-only"])
        .lines()
        .filter(|line| line.starts_with(".nt/ns/") && line.ends_with(".json"))
        .count();
    assert_eq!(
        cached_ns_count, TOTAL_EVENTS,
        "expected all {TOTAL_EVENTS} promoted tombstones staged in Git index"
    );

    let audit = audit_repository(repo.path()).unwrap();
    assert_eq!(audit.checked_files, TOTAL_EVENTS);
    assert!(
        audit.is_clean(),
        "unexpected audit findings: {:?}",
        audit.findings
    );
}
