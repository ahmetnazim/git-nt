#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use nt_core::FailureClass;
use nt_mcp::serve_stdio;
use nt_read::{HydrateOptions, NativeGitReader, hydrate_file};
use nt_write::{
    AuditFinding, PromoteOptions, RetireMode, StageRequest, audit_repository,
    commit_with_tombstones, parse_stage_request_json, promote_staged, retire_tombstone,
    stage_record,
};

const MAX_STDIN_JSON_BYTES: u64 = 64 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "git-nt",
    version,
    about = "Pure-Rust Negative-Space memory and prompt-injection-hardened context hydration for Git"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Atomically stage a Negative-Space tombstone into .git/nt-stage/
    Stage(StageArgs),
    /// Atomically claim diff-matching staged tombstones into .nt/ns/ and stage them in Git
    Promote(PromoteArgs),
    /// Promote diff-matching tombstones into .nt/ns/ and commit via native `git commit`
    Commit(CommitArgs),
    /// Hydrate trusted, L2-sanitized, L3-Spotlight-wrapped Negative-Space history for a file
    Hydrate(HydrateArgs),
    /// Retire an obsolete tombstone in .nt/ns/ (immutable supersession by default, or --delete)
    Retire(RetireArgs),
    /// Audit .nt/ns/ for RFC 8785 JCS validity, < 1.5 KiB ceiling, secret hygiene & orphaned paths
    Audit,
    /// Run the strictly read-only JSON-RPC 2.0 stdio MCP server (`nt_hydrate_file` only)
    Mcp(McpArgs),
}

#[derive(Debug, Args)]
struct StageArgs {
    /// Read a single StageRequest JSON document from stdin
    #[arg(
        long,
        conflicts_with_all = [
            "files",
            "symbol",
            "failure_class",
            "discarded",
            "invariant",
            "supersedes",
            "think_file"
        ]
    )]
    from_json: bool,

    /// Repo-relative file path(s) affected by this invariant (repeatable)
    #[arg(long = "file", required_unless_present = "from_json")]
    files: Vec<String>,

    /// Target symbol or module identifier
    #[arg(long, required_unless_present = "from_json")]
    symbol: Option<String>,

    /// Closed FailureClass variant (e.g., CONCURRENCY_DEADLOCK)
    #[arg(long = "class", required_unless_present = "from_json")]
    failure_class: Option<FailureClass>,

    /// Discarded pattern / failed approach
    #[arg(long, required_unless_present = "from_json")]
    discarded: Option<String>,

    /// Invariant future edits must preserve
    #[arg(long, required_unless_present = "from_json")]
    invariant: Option<String>,

    /// Optional UUIDv7 of an older tombstone superseded by this record
    #[arg(long)]
    supersedes: Option<String>,

    /// Optional local raw <think> file path (hashed via streaming SHA-256; never copied or staged)
    #[arg(long)]
    think_file: Option<PathBuf>,

    /// Redact detected secrets instead of failing closed
    #[arg(long)]
    redact_secrets: bool,
}

#[derive(Debug, Args)]
struct PromoteArgs {
    /// Promote all staged tombstones regardless of staged Git diff overlap
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct CommitArgs {
    /// Promote all staged tombstones regardless of staged Git diff overlap
    #[arg(long = "all", alias = "promote-all")]
    promote_all: bool,

    /// Arguments forwarded verbatim to native `git commit` (pass after `--`)
    #[arg(last = true, allow_hyphen_values = true)]
    git_args: Vec<String>,
}

#[derive(Debug, Args)]
struct HydrateArgs {
    /// Repo-relative file path to hydrate
    file_path: String,

    /// Maximum active tombstones returned (default 15, hard ceiling 50)
    #[arg(long)]
    max_records: Option<usize>,

    /// Override trusted ref (defaults to git config nt.trustedRef or refs/heads/main)
    #[arg(long = "ref", conflicts_with = "include_untrusted")]
    trusted_ref: Option<String>,

    /// Read directly from the local working tree instead of the trusted ref (UNSAFE; CLI only)
    #[arg(long)]
    include_untrusted: bool,
}

#[derive(Debug, Args)]
struct RetireArgs {
    /// UUIDv7 identifier of the tombstone in .nt/ns/{id}.json to retire
    id: String,

    /// Delete .nt/ns/{id}.json instead of writing an immutable retired superseding record
    #[arg(long)]
    delete: bool,

    /// Optional reason recorded on the superseding retired tombstone
    #[arg(long, conflicts_with = "delete")]
    reason: Option<String>,
}

#[derive(Debug, Args)]
struct McpArgs {
    /// Optional repository path (defaults to current working directory)
    #[arg(long)]
    repo: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("git-nt: error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    // Handle `mcp --repo <path>` before querying `current_dir()` so explicit `--repo`
    // works even if the caller's cwd is inaccessible or unlinked.
    if let Commands::Mcp(args) = cli.command {
        let repo_dir = match args.repo {
            Some(p) => p,
            None => {
                env::current_dir().map_err(|e| format!("failed to determine current dir: {e}"))?
            }
        };
        let reader = NativeGitReader::open(&repo_dir).map_err(|e| e.to_string())?;
        let stdin = io::stdin();
        let stdout = io::stdout();
        let stderr = io::stderr();
        serve_stdio(&reader, stdin.lock(), stdout.lock(), stderr.lock())
            .map_err(|e| e.to_string())?;
        return Ok(ExitCode::SUCCESS);
    }

    let cwd = env::current_dir().map_err(|e| format!("failed to determine current dir: {e}"))?;

    match cli.command {
        Commands::Stage(args) => {
            let req = if args.from_json {
                let mut buf = Vec::new();
                io::stdin()
                    .take(MAX_STDIN_JSON_BYTES + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| format!("failed to read stdin: {e}"))?;
                if (buf.len() as u64) > MAX_STDIN_JSON_BYTES {
                    return Err(format!(
                        "stdin JSON exceeds {MAX_STDIN_JSON_BYTES}-byte limit"
                    ));
                }
                parse_stage_request_json(&buf).map_err(|e| e.to_string())?
            } else {
                StageRequest {
                    files: args.files,
                    target_symbol: args.symbol.ok_or("missing --symbol")?,
                    failure_class: args.failure_class.ok_or("missing --class")?,
                    discarded_pattern: args.discarded.ok_or("missing --discarded")?,
                    invariant: args.invariant.ok_or("missing --invariant")?,
                    supersedes: args.supersedes,
                    think_file: args.think_file,
                }
            };

            let artifact =
                stage_record(&cwd, &req, args.redact_secrets).map_err(|e| e.to_string())?;
            println!(
                "staged {} -> {}",
                artifact.record.id,
                artifact.staged_path.display()
            );
            Ok(ExitCode::SUCCESS)
        }

        Commands::Promote(args) => {
            let report = promote_staged(
                &cwd,
                PromoteOptions {
                    promote_all: args.all,
                },
            )
            .map_err(|e| e.to_string())?;
            println!(
                "promoted {} tombstone(s) (skipped {} unmatched)",
                report.promoted_ids.len(),
                report.skipped_unmatched
            );
            for path in &report.promoted_paths {
                println!("  {path}");
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Commit(args) => {
            let report = commit_with_tombstones(&cwd, &args.git_args, args.promote_all)
                .map_err(|e| e.to_string())?;
            println!(
                "committed {} with {} promoted tombstone(s) (skipped {} unmatched)",
                report.head_sha,
                report.promoted_ids.len(),
                report.skipped_unmatched
            );
            Ok(ExitCode::SUCCESS)
        }

        Commands::Hydrate(args) => {
            let reader = NativeGitReader::open(&cwd).map_err(|e| e.to_string())?;
            let result = hydrate_file(
                &reader,
                &HydrateOptions {
                    file_path: args.file_path,
                    max_records: args.max_records,
                    trusted_ref_override: args.trusted_ref,
                    include_untrusted: args.include_untrusted,
                },
            )
            .map_err(|e| e.to_string())?;
            println!("{}", result.spotlighted_output);
            Ok(ExitCode::SUCCESS)
        }

        Commands::Retire(args) => {
            let outcome = retire_tombstone(&cwd, &args.id, args.delete, args.reason.as_deref())
                .map_err(|e| e.to_string())?;
            match outcome.mode {
                RetireMode::Deleted => println!("deleted {}", outcome.affected_path),
                RetireMode::Superseded => println!(
                    "retired {} via {} ({})",
                    args.id,
                    outcome.retired_record_id.as_deref().unwrap_or(""),
                    outcome.affected_path
                ),
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Audit => {
            let report = audit_repository(&cwd).map_err(|e| e.to_string())?;
            if report.is_clean() {
                println!(
                    "audit ok: {} tombstone file(s) verified",
                    report.checked_files
                );
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!(
                    "audit failed: {} finding(s) across {} checked file(s):",
                    report.findings.len(),
                    report.checked_files
                );
                for finding in &report.findings {
                    eprintln!("  - {}", format_audit_finding(finding));
                }
                Ok(ExitCode::FAILURE)
            }
        }

        Commands::Mcp(_) => unreachable!("handled prior to current_dir resolution"),
    }
}

fn format_audit_finding(finding: &AuditFinding) -> String {
    match finding {
        AuditFinding::UnexpectedEntry { path, reason } => format!("{path}: {reason}"),
        AuditFinding::OversizedRecord { path, bytes } => {
            format!("{path}: oversized ({bytes} bytes >= 1536 ceiling)")
        }
        AuditFinding::InvalidRecord { path, reason } => format!("{path}: invalid record: {reason}"),
        AuditFinding::IdFilenameMismatch {
            path,
            expected_stem,
            actual_id,
        } => format!("{path}: filename '{expected_stem}' != record id '{actual_id}'"),
        AuditFinding::NonCanonicalJcs { path } => format!("{path}: non-canonical RFC 8785 JCS"),
        AuditFinding::UnredactedSecret { path, field } => {
            format!("{path}: unredacted secret detected in '{field}'")
        }
        AuditFinding::OrphanedPath {
            path,
            missing_repo_path,
        } => format!("{path}: orphaned reference to missing/renamed path '{missing_repo_path}'"),
    }
}
