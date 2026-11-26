# `git-nt` Development Phases & Execution Runbook (Arch Rev 4.1 / Crate `v0.1.0`)

## Phase 0: Repository Initialization (Day 1)
**Goal:** Establish guardrails, toolchain, and zero-C CI checks before generating application code.
1. Initialize the Git repository properly (`git init`; if an empty `.git/` stub exists, run `git init` to populate it cleanly).
2. Install the Rust stable toolchain (`rustup`, Rust 2024 edition) matching `rust-toolchain.toml` so all local verification gates run.
3. Verify `AGENTS.md`, `docs/SPEC_V4.md`, `docs/ANTI_PATTERNS.md`, `docs/DEVELOPMENT_PHASES.md`, `LICENSE` (Apache-2.0), `.gitignore` (ignoring `/target/`, `.nt-local/`, `*.think.*`, `.nt-stage/` — while **never** ignoring tracked `.nt/ns/`), `scripts/setup-git-nt.sh`, and `.github/workflows/ci.yml`.
4. **Exit Gate:** Maintainer confirms zero contradictions across all four Markdown control files and `git status` + `cargo --version` succeed locally.

---

## Phase 1: Track C Falsification Pilot (Days 2–5 — Strongly Recommended Before Full Plumbing)
**Goal:** Empirically verify that Negative-Space hydration reduces repeat regressions before investing weeks in VCS/MCP plumbing.
1. In an isolated throwaway folder `experiments/pilot/` (kept outside the Rust workspace), collect `20–25` real bug-fix pairs where an initial naive implementation broke a non-obvious concurrency, numerical, memory, or API invariant.
2. Define "regression" operationally per task (automated unit/property test failure or blinded rubric violation) and run `>= 5` independent trials per task under two arms using a fresh, stateless coding agent:
   - **Control:** Codebase + existing tests + plain `git log`.
   - **Treatment:** Same context + the actual **L2-sanitized, L3-Spotlight-wrapped** Negative-Space block (`failure_class`, `discarded_pattern`, `invariant`).
3. Grade blind to arm and record both regression rate (with 95% confidence interval) and prompt token overhead.
4. **Go / Adjust / No-Go Gate:**
   - **GO:** Treatment reduces repeated anti-pattern regressions by `>= 25%` relative (with lower CI bound `> 0`) OR cuts CI/Critic retry cycles by `>= 30%`. Proceed immediately to Phase 2.
   - **ADJUST:** If Control already avoids regressions `> 85%` of the time, narrow or adjust `FailureClass` definitions in `docs/SPEC_V4.md` (e.g., adding `LOGIC_INVARIANT`) to focus strictly on non-obvious invariants not captured by tests, then re-test on a small held-out set.
   - **NO-GO:** If Treatment shows `<= 5%` improvement or increases regressions (anti-context distraction) across repeated runs, stop and pivot before investing in Phase 2.

---

## Phase 2: Contract-First Vertical Slices
Build strictly **one slice per branch/PR**. Every slice uses a **two-agent loop**: (1) Coder Agent implements the slice and tests, then (2) a fresh Critic Agent audits the diff against `AGENTS.md` and `docs/ANTI_PATTERNS.md` after all mandatory shell gates pass.

### Slice 1 — Workspace Scaffold & `nt-core` (Types, UUIDv7, RFC 8785 JCS, L2 Sanitizer, L3 Spotlighting)
- **Scope:** Root `Cargo.toml` workspace (5 members: `nt-core`, `nt-read`, `nt-write`, `nt-mcp`, `git-nt` with minimal compiling stubs for Slices 2–4) + complete `crates/nt-core`.
- **Deliverables:**
  - `NegativeSpaceRecord`, closed `FailureClass` & `RecordStatus` enums (`#[serde(deny_unknown_fields)]`), normalized repo-relative path validator, and RFC 9562 time-sortable UUIDv7 generator (via `getrandom` or `ulid` + `SystemTime`) + pure-`std` RFC 3339 UTC timestamp formatter.
  - True deterministic **RFC 8785 JCS serializer** (`to_jcs_bytes`) using explicit UTF-16 code-unit key sorting (immune to struct declaration order and `serde_json/preserve_order`) + SHA-256 hex digest helper (`sha256:<64-hex>`).
  - **Layer 2 deterministic sanitizer** (`sanitize_field` + `contains_secret` detector): plain-Rust control/Bidi/zero-width/Unicode-Tag/Variation-Selector stripping; preserves `<`, `>`, and single backticks; neutralizes triple backticks, outer LLM/tool XML boundary tags, and spotlight marker prefixes; anchored/bounded URL/shell/secret redaction via `regex-lite`; `<= 240` Unicode scalar cap; strictly idempotent.
  - **Layer 3 128-bit CSPRNG Spotlighting wrapper** (`spotlight_wrap`) via `getrandom`.
- **Exit Gate:**
  - Golden byte-identical RFC 8785 JCS vectors (including shuffled maps, non-ASCII UTF-16 key-order test, and number validation).
  - Rejection of unknown `FailureClass`, unknown `RecordStatus`, unknown struct fields, and invalid paths (`..`, `/abs`, NUL).
  - Structural adversarial tests pass `100%` (delimiter/fence breakouts, `</tool_result>`/`<system>` tags, Bidi `\u{202E}`, Unicode Tag smuggling `\u{E0041}`, Variation Selectors `\u{FE0F}`, shell pipes, URLs, anchored secrets).
  - `0%` false-positive corruption on benign Rust/Python identifiers, generics, operators, and hyphenated words (`Vec<u8>`, `Arc<Mutex<T>>`, `tokio::sync::OnceCell<Arc<Tile>>`, `->`, `=>`, `<= 240`, `task-queue`, `disk-cache`).
  - Idempotence test (`sanitize_field(&sanitize_field(x)) == sanitize_field(x)`) and unique 128-bit CSPRNG nonces across consecutive calls.
  - All five mandatory verification gates + `nt-mcp` isolation gate pass.

### Slice 2 — Lock-Free Atomic Staging, Promotion & Commit Wrapper (`nt-write`)
- **Scope:** `crates/nt-write`.
- **Deliverables:**
  - Per-worktree staging directory resolution (`git rev-parse --git-path nt-stage`).
  - Lock-free staging writer: `.git/nt-stage/{id}.tmp` -> `sync_all()` -> atomic `rename(2)` -> `.json` + directory `fsync`; pre-write L2 sanitization with fail-closed secret detection (`--redact-secrets` override); optional streaming SHA-256 hashing of `--think-file` (raw file never copied/staged); `--from-json` stdin ingestion.
  - Atomic claim (`{id}.claimed-{pid}` via `rename(2)`), diff-filtered promotion into `.nt/ns/{id}.json` + `git add`, native `git commit` subprocess wrapper with clean rollback on non-zero exit.
  - Tombstone retirement (`retire`) and repository audit (`audit`: JCS canonicality, `< 1.5 KiB` size ceiling, closed enums, secret scan, and orphaned/renamed path detection).
- **Exit Gate:** Multi-process stress test spawning `16` concurrent OS processes writing `50` events each (`800` total) + concurrent promote/claim races yields `0` lost/duplicated/corrupted files and `0` leftover `.tmp`/`.claimed-*` files; integration tests in temporary Git repos prove native hooks/signing work and failed commits roll back staged tombstones cleanly.

### Slice 3 — Read-Only Trusted Reader, L1 Gate & Core CLI (`nt-read` + `git-nt`)
- **Scope:** `crates/nt-read` + `crates/git-nt` (`stage`, `promote`, `commit`, `hydrate`, `retire`, `audit`).
- **Deliverables:**
  - `RepoReader` trait + hardened native `git` implementation (`-c core.fsmonitor=false -c core.hooksPath=/dev/null`) reading `.nt/ns/*.json` strictly from the trusted ref's Git tree (`refs/heads/main`), never from the working tree unless CLI `--include-untrusted` is explicitly passed.
  - Layer 1 optional commit signature verification (`nt.requireSigned=true`) with per-commit-SHA caching.
  - Retirement/supersession filtering, multi-file path matching, deterministic ranking, `max_records` cap (default `15`, ceiling `50`), and total byte ceiling (`16 KiB`).
  - Full CLI subcommands wired in `crates/git-nt`.
- **Exit Gate:** Integration tests in temporary Git (and optional colocated `jj`) repos prove working-tree / untrusted PR branch tombstones drop silently by default, GPG/SSH signature gate drops unsigned commits when enabled, retired/superseded tombstones are suppressed, promote/commit overhead `< 15 ms` median, and each `.nt/ns/{id}.json` stays `< 1.5 KiB`.

### Slice 4 — Strictly Read-Only MCP Server (`nt-mcp` + `git nt mcp`)
- **Scope:** `crates/nt-mcp` + `mcp` subcommand in `crates/git-nt`.
- **Deliverables:**
  - Lightweight newline-delimited JSON-RPC 2.0 `stdio` server (`initialize`, `notifications/initialized`, `tools/list`, `tools/call`), logging strictly to `stderr`.
  - Exposes **strictly one tool**: `nt_hydrate_file(file_path, max_records?)` with JSON Schema `inputSchema`, repo-relative + symlink-safe path validation, hard `max_records <= 50` cap, and `allow_untrusted = false` hardcoded.
  - Zero panics on malformed or adversarial JSON-RPC frames.
- **Exit Gate:** Protocol tests verify JSON-RPC framing, `stderr`-only logging, unique 128-bit Spotlighting nonces across consecutive calls, path-traversal/symlink rejection, `tools/list` asserting `len == 1` (`nt_hydrate_file`), and CI graph check proving `nt-mcp` has zero dependency on `nt-write`.

### Slice 5 (Optional / Post-Dogfood) — Agent Trace RFC v0.1.0 Interop & Optional `gix` Read Backend
- **Scope:** Deferred until after Phase 3 dogfooding proves need.
- **Deliverables (only if warranted by usage/benchmarks):**
  - `git nt export --format agent-trace` emitting compliant Agent Trace RFC v0.1.0 JSON (`id: uuid`, `tool`, `vcs`, `metadata["dev.neurotiler.negative_space.v1"]`).
  - Optional in-process `gix` implementation of `nt_read::RepoReader` if native `git` subprocess hydration ever exceeds the `50 ms` warm latency budget.

---

## Phase 3: Self-Dogfooding & Hardening (Immediately After Slice 4)
1. Register `git-nt mcp` inside your local agent configuration for the `git-nt` repository itself.
2. Record real Critic rejections encountered during hardening via `git nt stage` and `git nt commit` (or `git nt promote`).
3. Verify fresh agent sessions automatically hydrate trusted tombstones cleanly with `< 50 ms` warm MCP response latency and `git nt audit` stays green.

---

## Phase 4: Empirical Release Gate & v5.0 Unlock (Month 2+)
Before tagging `v0.1.0` or considering any federated v5.0 capabilities:
1. Run a synthetic `1,000`-commit replay benchmark on real Rust/Python OSS repositories (`ripgrep` / `tokio`) measuring promote/commit latency (`p50`, `p99`), repo growth (`< 1.5 KiB`/tombstone), `100%` rewrite survival across `200` mutations (`amend`, `rebase`, squash), and `P = 16` staging/promotion concurrency.
2. Run a red-team hydration suite (`500` adversarial notes + `500` benign technical notes) confirming:
   - `0%` untrusted working-tree / PR-branch pass-through in default mainline mode;
   - `100%` deterministic blocking of structural threats (delimiter/fence breakouts, stealth Unicode Bidi/Tag/Variation-Selector smuggling, shell/URL/secret patterns);
   - `0%` benign Rust/Python symbol/generic corruption;
   - Reported empirical semantic override Attack Success Rate (ASR) against a real frontier coding model.
3. **v5.0 Unlock Rule:** Only after `git-nt` `v0.1.0` passes all Phase 4 thresholds and proves daily value in real repositories may you open a separate milestone for federated Experience Capsules, Firecracker witness verification, transparency logs, or offline DPO LoRA compilation.
