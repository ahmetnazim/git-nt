#!/usr/bin/env bash
# =============================================================================
# scripts/setup-git-nt.sh — Idempotent Local Git Configuration for git-nt
# Configures:
#   1. Local Layer 1 trust gate defaults (nt.trustedRef, nt.requireSigned)
#   2. Local staging dir (.git/nt-stage/ per worktree) & private Tier 3 trace dir (.nt-local/)
#   3. Optional .rgignore entry so ripgrep skips tracked .nt/ns/ tombstones
#
# No custom Git push/rewrite hooks or notes refspecs are required because
# Negative-Space tombstones live as immutable per-event tracked files (.nt/ns/).
# Portable across Linux (GNU) and macOS (BSD) + Git worktrees / colocated jj.
# =============================================================================
set -euo pipefail

TRUSTED_REF="refs/heads/main"
REQUIRE_SIGNED="false"
ADD_RGIGNORE="false"

usage() {
  cat <<'EOF'
Usage: scripts/setup-git-nt.sh [OPTIONS]

Options:
  --trusted-ref <ref>     Mainline ref for Layer 1 Trust Gate (default: refs/heads/main)
  --require-signed        Require valid GPG/SSH commit signatures during hydration
  --rgignore              Add '.nt/ns/' to repo-root .rgignore so ripgrep skips tombstones
  -h, --help              Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --trusted-ref)
      TRUSTED_REF="${2:?Missing value for --trusted-ref}"
      shift 2
      ;;
    --require-signed)
      REQUIRE_SIGNED="true"
      shift
      ;;
    --rgignore)
      ADD_RGIGNORE="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: Unknown option '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# 1. Verify we are inside a Git work tree
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Error: Must be run inside a Git repository." >&2
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
STAGE_DIR="$(git rev-parse --git-path nt-stage)"
LOCAL_THINK_DIR="${REPO_ROOT}/.nt-local"

mkdir -p "$STAGE_DIR" "$LOCAL_THINK_DIR"
chmod 700 "$LOCAL_THINK_DIR"

# 2. Configure Layer 1 Trust Gate Defaults
git config --local nt.trustedRef "$TRUSTED_REF"
git config --local nt.requireSigned "$REQUIRE_SIGNED"
echo "[ok] Configured local nt.* trust gate (trustedRef=${TRUSTED_REF}, requireSigned=${REQUIRE_SIGNED})"

# 3. Optional ripgrep ignore for tracked .nt/ns/ tombstones
if [[ "$ADD_RGIGNORE" == "true" ]]; then
  RGIGNORE_FILE="${REPO_ROOT}/.rgignore"
  touch "$RGIGNORE_FILE"
  if ! grep -Fxq ".nt/ns/" "$RGIGNORE_FILE"; then
    printf '\n# git-nt tracked Negative-Space tombstones\n.nt/ns/\n' >> "$RGIGNORE_FILE"
    echo "[ok] Added .nt/ns/ to ${RGIGNORE_FILE}"
  else
    echo "[ok] .nt/ns/ already present in ${RGIGNORE_FILE}"
  fi
fi

echo ""
echo "git-nt repository setup complete."
echo "  Stage dir:      ${STAGE_DIR}"
echo "  Local <think>:  ${LOCAL_THINK_DIR} (mode 700, git-ignored)"
echo "  Trusted ref:    ${TRUSTED_REF} (requireSigned=${REQUIRE_SIGNED})"
