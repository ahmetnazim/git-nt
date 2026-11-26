# `git-nt`

**Pure-Rust Negative-Space memory and prompt-injection-hardened context hydration for Git.**

Standard Git stores only code that survived. Every failed AI attempt, Critic rejection, and discarded architectural dead end is overwritten and forgotten—forcing fresh coding-agent sessions to rediscover and repeat the same concurrency, safety, and contract regressions.

`git-nt` (Architecture Rev 4.1 / Crate `v0.1.0`) stores typed **Negative-Space tombstones** as immutable, per-event RFC 8785 JCS JSON files (`.nt/ns/{id}.json`) committed alongside code, then delivers them back to coding agents through a **4-Layer Indirect Prompt-Injection Defense** and a strictly read-only **Model Context Protocol (MCP)** server.

---

## Core Design Guarantees

* **Zero C Dependencies:** Compiles cleanly with `CC=/bin/false CXX=/bin/false cargo build --release`. No `libsqlite3-sys`, `libgit2-sys`, OpenSSL, or C build scripts.
* **Compact Single Binary:** Rust 2024 workspace (`#![forbid(unsafe_code)]`) targeting a stripped release binary under `6 MiB` (target: `< 3 MiB`).
* **Native Git & Rewrite Survival:** Stores tombstones as immutable per-event tracked files (`.nt/ns/{uuid7}.json`), so PR diff review, GPG/SSH commit signing, `git commit --amend`, `git rebase`, squash-merges, `git push`/`git pull`, and colocated Jujutsu (`jj`) all work natively with zero fragile note-sync hooks or reconcilers.
* **Lock-Free Parallel Staging:** Stages uncommitted events as immutable per-event files (`.git/nt-stage/<id>.tmp` -> `fsync` -> atomic POSIX `rename(2)`), then claims and promotes only diff-matching events on `git nt promote` or `git nt commit`.
* **Strict Repo Hygiene:** Raw Tier 3 `<think>` reasoning traces stay strictly local and Git-ignored (`.nt-local/`); only their `sha256:` digest enters `.nt/ns/{id}.json` (`< 1.5 KiB` each), and `git nt retire` / `git nt audit` prevent stale tombstones from rotting.

---

## Security: 4-Layer Indirect Prompt-Injection Firewall

Repository-resident agent memory is an indirect prompt-injection surface if untrusted branches or poisoned inputs can inject instructions into agent context. Every `git nt hydrate` and MCP `nt_hydrate_file` response passes sequentially through four barriers:

1. **Layer 1 — Trusted Tree & Signature Gate (`nt-read`):** Reads `.nt/ns/*.json` strictly from the trusted mainline ref's Git tree (default: `refs/heads/main`) — never from the local working tree — and optionally verifies the introducing commit's GPG/SSH signature when `nt.requireSigned=true`.
2. **Layer 2 — Deterministic Sanitizer (`nt-core`):** Enforces closed `FailureClass` and `RecordStatus` enums, strips Unicode control/Bidi/zero-width/Tag/Variation-Selector smuggling characters, preserves benign Rust/Python code syntax (`Vec<u8>`, `->`, `=>`, `<=`), neutralizes triple backticks and outer prompt/tool boundary tags, redacts URLs, shell pipes, and anchored credential tokens via linear-time `regex-lite`, and caps fields at `<= 240` Unicode scalar values (idempotently).
3. **Layer 3 — 128-Bit CSPRNG Spotlighting (`nt-core`):** Draws 16 fresh random bytes from the OS CSPRNG (`getrandom`) on every invocation to frame passive anti-context inside unguessable boundaries (`<<<NT_DATA_{hex}<<< ... >>>END_NT_DATA_{hex}>>>`).
4. **Layer 4 — Compile-Time Read-Only MCP (`nt-mcp`):** `nt-mcp` depends ONLY on `nt-core` and `nt-read` (never `nt-write`), speaks newline-delimited JSON-RPC 2.0 on `stdio` (diagnostics strictly to `stderr`), and registers **exactly one tool** (`nt_hydrate_file`) with repo-relative path validation, hard record/byte caps, and untrusted reads permanently disabled.

---

## Repository Structure

> **Status:** Architecture and guardrails complete (Phase 0). The `crates/` workspace packages below are scaffolded starting in Phase 2, Slice 1.

```text
git-nt/
├── AGENTS.md                     # Non-negotiable engineering invariants & CI gates
├── README.md                     # Project overview, setup, and usage
├── LICENSE                       # Apache License 2.0
├── Cargo.toml                    # Pure-Rust 2024 workspace manifest (scaffolded in Slice 1)
├── rust-toolchain.toml           # Pinned stable Rust toolchain + rustfmt/clippy
├── .github/workflows/ci.yml      # Zero-C build, -sys audit, L4 graph check, Clippy, tests, < 6 MiB gate
├── scripts/
│   └── setup-git-nt.sh           # Idempotent local trust-gate, staging & .nt-local setup
├── docs/
│   ├── SPEC_V4.md                # Canonical Negative-Space v1 schema, L1–L4 firewall & CLI/MCP spec
│   ├── ANTI_PATTERNS.md          # Negative-space ledger of banned architectures (AP-01..AP-10)
│   └── DEVELOPMENT_PHASES.md     # Phased vertical-slice roadmap & exit gates
└── crates/                       # Planned (Phase 2, Slices 1–4)
    ├── nt-core/                  # Schema types, UUIDv7, RFC 8785 JCS, SHA-256, L2/L3 security
    ├── nt-read/                  # Strictly read-only RepoReader (hardened git), L1 gate, query/ranking
    ├── nt-write/                 # Atomic ULID/UUIDv7 stager, claim/promote, native git commit, retire, audit
    ├── nt-mcp/                   # Strictly read-only JSON-RPC 2.0 stdio MCP server (nt-core + nt-read only)
    └── git-nt/                   # Unified CLI entrypoint (`git nt ...`)
```

---

## Quick Start

### 1. Build with Zero-C Verification (Once Slice 1+ Is Implemented)

```bash
CC=/bin/false CXX=/bin/false cargo build --release --bin git-nt
```

Place `target/release/git-nt` on your `PATH` (or install locally via `cargo install --path crates/git-nt`) so Git automatically dispatches `git nt <subcommand>`.

### 2. Configure Local Repository Defaults

Run the idempotent setup script inside any Git or colocated Jujutsu (`jj`) repository:

```bash
chmod +x scripts/setup-git-nt.sh
./scripts/setup-git-nt.sh

# Optional: require valid GPG/SSH commit signatures in Layer 1
./scripts/setup-git-nt.sh --require-signed

# Optional: hide .nt/ns/ from ripgrep searches via .rgignore
./scripts/setup-git-nt.sh --rgignore
```

This configures `nt.trustedRef` and `nt.requireSigned`, initializes `.git/nt-stage/`, and creates the Git-ignored `.nt-local/` directory (`chmod 700`) for private `<think>` traces. No Git push/rewrite hooks or custom fetch refspecs are required.

---

## CLI Usage

```bash
# 1. Stage a Critic rejection (atomic file in .git/nt-stage/; raw think file hashed locally only)
git nt stage \
  --file src/tile_cache.rs \
  --symbol TileCache::get_or_load \
  --class CONCURRENCY_DEADLOCK \
  --discarded "std::sync::RwLockWriteGuard held across async disk read" \
  --invariant "Coalesce concurrent misses using per-key tokio::sync::OnceCell<Arc<Tile>>" \
  --think-file .nt-local/attempt_01.think.log

# 1b. Or ingest programmatically over stdin (preferred for automated Critic/agent loops)
cat rejection.json | git nt stage --from-json

# 2a. Promote diff-matching staged tombstones into .nt/ns/ and commit via native git commit
git nt commit -- -m "feat(cache): per-key OnceCell miss coalescing"

# 2b. Or promote standalone before committing via plain `git commit`, IDE Git UI, or `jj commit`
git nt promote

# 3. Hydrate trusted, Spotlight-wrapped Negative-Space history for a file (from refs/heads/main)
git nt hydrate src/tile_cache.rs

# 4. Retire an obsolete tombstone after a refactor
git nt retire 019a97c4-8f20-7d3a-9b1c-4e5f6a7b8c9d

# 5. Audit .nt/ns/ for JCS validity, < 1.5 KiB ceiling, secret hygiene, and orphaned paths
git nt audit
```

### MCP Client Configuration (Read-Only)

Register `git-nt` as a local `stdio` MCP server in your coding agent configuration:

```json
{
  "mcpServers": {
    "git-nt": {
      "command": "git-nt",
      "args": ["mcp"]
    }
  }
}
```

Exposed tool: `nt_hydrate_file(file_path: String, max_records?: usize)` (read-only, trusted mainline tree only, hard cap `<= 50` records).

---

## Agentic Development Workflow & Verification Gates

This repository is built in gated vertical slices documented in [`docs/DEVELOPMENT_PHASES.md`](docs/DEVELOPMENT_PHASES.md) and governed by [`AGENTS.md`](AGENTS.md), [`docs/SPEC_V4.md`](docs/SPEC_V4.md), and [`docs/ANTI_PATTERNS.md`](docs/ANTI_PATTERNS.md).

Every pull request must pass all verification gates before Critic review:

```bash
cargo fmt --all -- --check
CC=/bin/false CXX=/bin/false cargo build --release
! (cargo tree --workspace --edges normal | grep -Eo '[A-Za-z0-9_-]+-sys[[:space:]]+v[0-9.]+' | grep -Ev '^(linux-raw-sys|windows-sys)\b')
! (cargo tree -p nt-mcp --edges normal | grep -q '\bnt-write\b')
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
