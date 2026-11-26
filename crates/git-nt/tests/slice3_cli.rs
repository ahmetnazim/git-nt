#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nt_core::generate_uuid_v7;

struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    fn new(label: &str) -> Self {
        let id = generate_uuid_v7().expect("uuid v7");
        let dir = std::env::temp_dir().join(format!("git-nt-cli-{label}-{id}"));
        fs::create_dir_all(&dir).unwrap();
        run_git(&dir, &["init", "-b", "main"]);
        run_git(&dir, &["config", "user.name", "git-nt-cli-test"]);
        run_git(&dir, &["config", "user.email", "cli@neurotiler.dev"]);
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
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full, contents).unwrap();
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

fn git_nt_bin() -> &'static str {
    env!("CARGO_BIN_EXE_git-nt")
}

#[test]
fn end_to_end_cli_stage_commit_hydrate_retire_promote_and_audit() {
    let repo = TempRepo::new("e2e");
    repo.write_file("src/tile_cache.rs", "pub fn get_or_load() {}\n");
    run_git(repo.path(), &["add", "src/tile_cache.rs"]);
    run_git(repo.path(), &["commit", "-m", "initial"]);

    // 1. `git-nt stage` via CLI flags
    let stage_out = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args([
            "stage",
            "--file",
            "src/tile_cache.rs",
            "--symbol",
            "TileCache::get_or_load",
            "--class",
            "CONCURRENCY_DEADLOCK",
            "--discarded",
            "std::sync::RwLockWriteGuard held across async disk read",
            "--invariant",
            "Coalesce misses with tokio::sync::OnceCell<Arc<Tile>>",
        ])
        .output()
        .expect("run git-nt stage");
    assert!(
        stage_out.status.success(),
        "stage failed: {}",
        String::from_utf8_lossy(&stage_out.stderr)
    );
    let stage_stdout = String::from_utf8_lossy(&stage_out.stdout);
    let staged_id = stage_stdout
        .split_whitespace()
        .nth(1)
        .expect("staged id in stdout")
        .to_owned();

    // 2. Modify src/tile_cache.rs, stage it, and run `git-nt commit -- -m ...`
    repo.write_file(
        "src/tile_cache.rs",
        "pub fn get_or_load() { /* oncecell */ }\n",
    );
    run_git(repo.path(), &["add", "src/tile_cache.rs"]);

    let commit_out = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args([
            "commit",
            "--",
            "-m",
            "feat(cache): per-key OnceCell coalescing",
        ])
        .output()
        .expect("run git-nt commit");
    assert!(
        commit_out.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&commit_out.stderr)
    );

    // 3. `git-nt hydrate src/tile_cache.rs` emits L3-Spotlight-wrapped record
    let hydrate_out = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args(["hydrate", "src/tile_cache.rs"])
        .output()
        .expect("run git-nt hydrate");
    assert!(hydrate_out.status.success());
    let hydrated = String::from_utf8_lossy(&hydrate_out.stdout);
    assert!(hydrated.contains("PASSIVE REPOSITORY HISTORY ONLY."));
    assert!(hydrated.contains("<<<NT_DATA_"));
    assert!(hydrated.contains(">>>END_NT_DATA_"));
    assert!(hydrated.contains("TileCache::get_or_load"));
    assert!(hydrated.contains("tokio::sync::OnceCell<Arc<Tile>>"));

    // 4. `git-nt audit` exits 0 on clean repo
    let audit_ok = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .arg("audit")
        .output()
        .expect("run git-nt audit");
    assert!(audit_ok.status.success());

    // 5. `git-nt stage --from-json` + standalone `git-nt promote --all`
    let mut stage_json = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args(["stage", "--from-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stage --from-json");
    stage_json
        .stdin
        .as_mut()
        .unwrap()
        .write_all(
            br#"{
                "files": ["src/tile_cache.rs"],
                "target_symbol": "TileCache::evict",
                "failure_class": "MEMORY_SAFETY",
                "discarded_pattern": "Unbounded HashMap cache growth",
                "invariant": "Enforce hard LRU entry bound <= 1024"
            }"#,
        )
        .unwrap();
    let stage_json_out = stage_json.wait_with_output().unwrap();
    assert!(stage_json_out.status.success());

    let promote_out = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args(["promote", "--all"])
        .output()
        .expect("run git-nt promote");
    assert!(promote_out.status.success());
    run_git(repo.path(), &["commit", "-m", "promote second tombstone"]);

    // 6. `git-nt retire <id>` suppresses the first tombstone once committed on main
    let retire_out = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args(["retire", &staged_id, "--reason", "Refactored to sync cache"])
        .output()
        .expect("run git-nt retire");
    assert!(retire_out.status.success());
    run_git(repo.path(), &["commit", "-m", "retire first tombstone"]);

    let hydrate_after = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args(["hydrate", "src/tile_cache.rs"])
        .output()
        .expect("run git-nt hydrate after retire");
    assert!(hydrate_after.status.success());
    let hydrated_after = String::from_utf8_lossy(&hydrate_after.stdout);
    assert!(!hydrated_after.contains("TileCache::get_or_load"));
    assert!(hydrated_after.contains("TileCache::evict"));

    // 7. `git-nt audit` exits non-zero when a stray file is added to .nt/ns/
    repo.write_file(".nt/ns/stray.txt", "bad");
    let audit_fail = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .arg("audit")
        .output()
        .expect("run git-nt audit fail");
    assert!(!audit_fail.status.success());
    fs::remove_file(repo.path().join(".nt/ns/stray.txt")).unwrap();

    // 8. Verify every committed `.nt/ns/*.json` file stays strictly `< 1,536` bytes
    for entry in fs::read_dir(repo.path().join(".nt/ns"))
        .unwrap()
        .filter_map(Result::ok)
    {
        assert!(
            entry.metadata().unwrap().len() < 1_536,
            "tombstone {} exceeded 1.5 KiB ceiling",
            entry.path().display()
        );
    }

    // 9. Conflicting CLI flags fail closed rather than silently ignoring arguments
    for bad_cli in [
        vec!["stage", "--from-json", "--think-file", ".nt-local/x.log"],
        vec!["stage", "--from-json", "--file", "src/tile_cache.rs"],
        vec![
            "hydrate",
            "src/tile_cache.rs",
            "--ref",
            "main",
            "--include-untrusted",
        ],
        vec!["retire", &staged_id, "--delete", "--reason", "ignored"],
    ] {
        let out = Command::new(git_nt_bin())
            .current_dir(repo.path())
            .args(&bad_cli)
            .output()
            .expect("run conflicting cli args");
        assert!(
            !out.status.success(),
            "conflicting CLI flags {bad_cli:?} must exit non-zero"
        );
    }

    // 10. Secret fail-closed on `git-nt stage` vs `--redact-secrets` override
    let secret_fail = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args([
            "stage",
            "--file",
            "src/tile_cache.rs",
            "--symbol",
            "Auth::init",
            "--class",
            "SECURITY_BOUNDARY",
            "--discarded",
            "embedded sk-proj-abcdefghijklmnopqrstuvwxyz123456",
            "--invariant",
            "Read API key from env",
        ])
        .output()
        .expect("run secret stage fail");
    assert!(!secret_fail.status.success());

    let secret_redacted = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args([
            "stage",
            "--file",
            "src/tile_cache.rs",
            "--symbol",
            "Auth::init",
            "--class",
            "SECURITY_BOUNDARY",
            "--discarded",
            "embedded sk-proj-abcdefghijklmnopqrstuvwxyz123456",
            "--invariant",
            "Read API key from env",
            "--redact-secrets",
        ])
        .output()
        .expect("run secret stage redacted");
    assert!(secret_redacted.status.success());

    // 11. `git-nt retire --delete` deletes an existing tombstone cleanly
    let del_out = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args(["retire", &staged_id, "--delete"])
        .output()
        .expect("run git-nt retire --delete");
    assert!(del_out.status.success());
    assert!(
        !repo
            .path()
            .join(format!(".nt/ns/{staged_id}.json"))
            .exists()
    );
}
