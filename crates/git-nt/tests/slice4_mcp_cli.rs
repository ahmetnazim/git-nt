#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nt_core::generate_uuid_v7;
use serde_json::{Value, json};

struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    fn new(label: &str) -> Self {
        let id = generate_uuid_v7().expect("uuid v7");
        let dir = std::env::temp_dir().join(format!("git-nt-mcp-cli-{label}-{id}"));
        fs::create_dir_all(&dir).unwrap();
        run_git(&dir, &["init", "-b", "main"]);
        run_git(&dir, &["config", "user.name", "git-nt-mcp-cli"]);
        run_git(&dir, &["config", "user.email", "mcp-cli@neurotiler.dev"]);
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

fn run_git(dir: &Path, args: &[&str]) {
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
}

fn git_nt_bin() -> &'static str {
    env!("CARGO_BIN_EXE_git-nt")
}

#[test]
fn live_git_nt_mcp_stdio_nonblocking_flushing_and_unique_nonces() {
    let repo = TempRepo::new("live-stdio");
    repo.write_file("src/engine.rs", "pub fn step() {}\n");
    run_git(repo.path(), &["add", "src/engine.rs"]);
    run_git(repo.path(), &["commit", "-m", "initial"]);

    // Stage & commit a trusted tombstone via CLI
    let stage = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args([
            "stage",
            "--file",
            "src/engine.rs",
            "--symbol",
            "Engine::step",
            "--class",
            "NUMERICAL_INSTABILITY",
            "--discarded",
            "Naive f32 summation drifts on long tiles",
            "--invariant",
            "Use Kahan compensated f64 accumulation",
        ])
        .status()
        .unwrap();
    assert!(stage.success());

    repo.write_file("src/engine.rs", "pub fn step() { /* kahan */ }\n");
    run_git(repo.path(), &["add", "src/engine.rs"]);
    let commit = Command::new(git_nt_bin())
        .current_dir(repo.path())
        .args(["commit", "--", "-m", "feat: kahan accumulation"])
        .status()
        .unwrap();
    assert!(commit.success());

    // Launch live `git-nt mcp --repo <path>` subprocess over pipes
    let mut child = Command::new(git_nt_bin())
        .args(["mcp", "--repo"])
        .arg(repo.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn git-nt mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let send_and_recv = |stdin: &mut std::process::ChildStdin,
                         stdout: &mut BufReader<std::process::ChildStdout>,
                         req: Value|
     -> Value {
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        let n = stdout.read_line(&mut line).unwrap();
        assert!(n > 0, "expected immediate flushed JSON-RPC response line");
        serde_json::from_str(&line).expect("valid JSON-RPC response")
    };

    // 1. initialize (interactive request-response while stdin stays open -> proves flushing!)
    let init = send_and_recv(
        &mut stdin,
        &mut stdout,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-03-26" }
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "git-nt");

    // 2. notifications/initialized (no response expected)
    writeln!(
        stdin,
        "{}",
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
    )
    .unwrap();
    stdin.flush().unwrap();

    // 3. tools/list asserts strictly 1 tool (`nt_hydrate_file`)
    let list = send_and_recv(
        &mut stdin,
        &mut stdout,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    );
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "nt_hydrate_file");

    // 4. Two consecutive `nt_hydrate_file` calls produce unique 128-bit Spotlighting nonces
    let call1 = send_and_recv(
        &mut stdin,
        &mut stdout,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "nt_hydrate_file", "arguments": { "file_path": "src/engine.rs" } }
        }),
    );
    let call2 = send_and_recv(
        &mut stdin,
        &mut stdout,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "nt_hydrate_file", "arguments": { "file_path": "src/engine.rs" } }
        }),
    );

    let text1 = call1["result"]["content"][0]["text"].as_str().unwrap();
    let text2 = call2["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text1.contains("Kahan compensated f64 accumulation"));
    assert!(text2.contains("Kahan compensated f64 accumulation"));
    assert_ne!(
        text1.lines().nth(1).unwrap(),
        text2.lines().nth(1).unwrap(),
        "consecutive MCP calls must emit distinct 128-bit CSPRNG Spotlighting nonces"
    );

    // Close stdin and verify clean exit 0 with empty stderr
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "git-nt mcp must exit 0 cleanly on stdin EOF (stderr={})",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "expected empty stderr on clean MCP session, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Startup error on a non-Git directory writes strictly to stderr (empty stdout, non-zero exit)
    let non_git =
        std::env::temp_dir().join(format!("git-nt-non-git-{}", generate_uuid_v7().unwrap()));
    fs::create_dir_all(&non_git).unwrap();
    let fail_out = Command::new(git_nt_bin())
        .args(["mcp", "--repo"])
        .arg(&non_git)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&non_git);
    assert!(!fail_out.status.success());
    assert!(
        fail_out.stdout.is_empty(),
        "stdout must remain empty on MCP startup failure"
    );
    assert!(
        !fail_out.stderr.is_empty(),
        "stderr must report MCP startup error"
    );
}
