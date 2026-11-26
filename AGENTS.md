# AGENTS.md — Engineering Laws for `git-nt` (Arch Rev 4.1 / Crate `0.1.0`)

## 1. Mission & Scope
You are building **`git-nt`** (Architecture Rev 4.1, crate version `0.1.0`), a minimal, pure-Rust, zero-C-dependency Git subcommand and strictly read-only MCP server implementing:
1. Typed **Negative-Space Memory** stored as immutable per-event canonical JSON files (`.nt/ns/{id}.json`) committed alongside code, and
2. A **4-Layer Indirect Prompt-Injection Defense** for safe, mainline-trusted context hydration over CLI and read-only MCP `stdio`.

Optional **Agent Trace RFC v0.1.0** export/interop is deferred until after core Negative-Space Memory proves value in Phase 1 and Phase 3 dogfooding.

Read `docs/SPEC_V4.md`, `docs/ANTI_PATTERNS.md`, and `docs/DEVELOPMENT_PHASES.md` before writing code. These four Markdown files are the sole source of truth for this repository.

## 2. Non-Negotiable Architectural Invariants
1. **Zero C Dependencies:** The entire workspace MUST compile with `CC=/bin/false CXX=/bin/false cargo build --release`. Zero C/C++ build scripts or C-backed `*-sys` crates are permitted (no `libsqlite3-sys`, no `libgit2-sys`, no OpenSSL). Pure-Rust OS ABI crates (`linux-raw-sys`, `windows-sys`) are the sole exempt `-sys` entries.
2. **Toolchain, Safety & Footprint:** Rust 2024 edition (`#![forbid(unsafe_code)]` across all workspace crates). Keep the stripped release binary under `6 MiB` (`6,291,456` bytes; target: `< 3 MiB`). Target platforms: Linux and macOS.
3. **Compile-Time Read/Write Isolation:** Split VCS access into `nt-read` (strictly read-only) and `nt-write` (staging/promotion/commit). `nt-mcp` MUST depend ONLY on `nt-core` and `nt-read`, NEVER on `nt-write`.
4. **Hardened Native `git`, No Direct Object Synthesis:** Delegate reads to hardened native `git` (`-c core.fsmonitor=false -c core.hooksPath=/dev/null`, fixed argument arrays, no shell) behind `nt_read::RepoReader`, and delegate all commits to native `git commit` so GPG/SSH signing and user hooks remain intact. Never synthesize raw Git commits or loose blobs directly. (`gix` is deferred from v0.1; `RepoReader` allows dropping in an in-process backend later only if benchmarks require it.)
5. **Lock-Free Atomic Staging & Immutable Tracked Tombstones:**
   - Stage uncommitted tombstones strictly as immutable per-event files at `.git/nt-stage/{id}.tmp` (resolved via `git rev-parse --git-path nt-stage`), call `file.sync_all()`, atomically rename via POSIX `rename(2)` to `.git/nt-stage/{id}.json`, and `fsync` the staging directory.
   - On `git nt promote` / `git nt commit`, atomically claim matching files via `rename(2)` to `{id}.claimed-{pid}`, materialize diff-filtered tombstones into tracked `.nt/ns/{id}.json`, and unlink claimed staging files only after commit/promotion succeeds.
6. **Local-Only Raw Reasoning Traces:** Raw Tier 3 `<think>` traces remain strictly local and Git-ignored (`.nt-local/`). Only their `sha256:` digest (`local_think_digest`) may be persisted. Each persisted tombstone MUST remain `< 1.5 KiB` (`1,536` bytes) canonical JSON.
7. **True RFC 8785 JCS Canonicalization:** Serialize all persisted JSON deterministically using an explicit RFC 8785 serializer (UTF-16 code-unit key sorting, zero insignificant whitespace, minimal RFC 8785 string escaping, finite-number validation/forbidding NaN/Infinity). Never rely on `serde_json` struct declaration order or implicit `BTreeMap` behavior vulnerable to `preserve_order` feature unification.
8. **4-Layer Hydration Firewall:** Every hydration output MUST pass:
   - **L1 (Trusted Tree Gate):** Read `.nt/ns/` strictly from the trusted mainline ref's Git tree (default `refs/heads/main`) — NEVER from the working tree — and verify commit signatures when `nt.requireSigned=true`;
   - **L2 (Deterministic Sanitizer):** Closed `FailureClass` & `RecordStatus` enums; plain-Rust control + stealth Unicode stripping (Bidi, zero-width, Tags `U+E0000..=U+E007F`, Variation Selectors `U+FE00..=U+FE0F` / `U+E0100..=U+E01EF`); preserve benign code syntax (`<`, `>`, single backticks); neutralize triple backticks, outer LLM/tool XML boundary tags, and spotlight marker prefixes; anchored/bounded URL/shell/secret redaction via `regex-lite`; `<= 240` Unicode scalar cap; strictly idempotent;
   - **L3 (CSPRNG Spotlighting):** Fresh 128-bit OS CSPRNG delimiters (`getrandom`) per invocation;
   - **L4 (Read-Only MCP `stdio`):** `nt-mcp` registers **exactly one tool** (`nt_hydrate_file`), validates repo-relative paths, enforces hard record/byte caps, logs strictly to `stderr`, and never panics on untrusted input.

## 3. Pre-Approved Workspace Dependencies
Only these crates are pre-approved (no unapproved `[dev-dependencies]` either — use pure `std` RAII helpers for temporary test directories and RFC 3339 UTC formatting):
- `serde` (`derive`), `serde_json`, `sha2`, `clap` (`derive`), `thiserror`, `ulid`, `regex-lite`, `getrandom`

Do NOT add additional crates (including `gix`, `chrono`, `time`, `tempfile`, or any C-backed crate) without explicit maintainer approval.

## 4. Vertical Slice Discipline & Mandatory Verification Gate
- Work strictly on the **active slice** in `docs/DEVELOPMENT_PHASES.md`. Do not scaffold future slice logic prematurely (minimal empty crate stubs in Slice 1 are allowed only so the workspace manifest compiles).
- Never weaken, skip, or delete failing test assertions to achieve a green build.
- Before reporting any slice complete, run all five verification gates and report exact outputs:

```bash
cargo fmt --all -- --check
CC=/bin/false CXX=/bin/false cargo build --release
! (cargo tree --workspace --edges normal | grep -Eo '[A-Za-z0-9_-]+-sys[[:space:]]+v[0-9.]+' | grep -Ev '^(linux-raw-sys|windows-sys)\b')
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Additionally, from Slice 1 onward, verify compile-time L4 isolation:

```bash
! (cargo tree -p nt-mcp --edges normal | grep -q '\bnt-write\b')
```

Every completed slice MUST pass a separate Critic audit against `docs/ANTI_PATTERNS.md` before moving to the next slice.
