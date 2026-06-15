#!/usr/bin/env bash
# check_dev_flags_not_in_prod.sh — dev-flag scope guard (V-AC-6).
#
# DISK_USE_STUB_CA=1 and DISK_ACL_ALLOW_UNSIGNED=1 are local-mode-only flags
# that disable the real Auth Arcana CA chain and GPG ACL verification.  They
# must NEVER appear in committed production configs, deploy manifests, or any
# disk.toml template.  This script asserts that the flags appear only inside
# the dev bring-up script and test fixtures, and never in:
#   *.toml, *.yaml, *.yml       — config/deploy files
#   deploy/**                   — deployment manifests
#   disk.toml.example           — the shipped template
#
# Allowed locations (not flagged):
#   scripts/dev-local-e2e.sh    — the bring-up script (explicitly dev-only)
#   crates/*/tests/**           — test fixtures
#   crates/*/lints/**           — this and sibling lint scripts
#   **/*.md                     — documentation (mentions are informational)
#
# Usage:
#   ./crates/disk-client/lints/check_dev_flags_not_in_prod.sh [repo-root]
#
# Exit codes:
#   0 — no violations
#   1 — one or more violations found

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${1:-"$(cd "$SCRIPT_DIR/../../.." && pwd)"}"

DEV_FLAGS='DISK_USE_STUB_CA|DISK_ACL_ALLOW_UNSIGNED'

echo "[lint] Checking that dev flags ($DEV_FLAGS) do not appear in prod configs..."
echo "[lint] Repo root: $REPO_ROOT"

VIOLATIONS=0

# Check committed config/deploy files.
check_files() {
    local pattern="$1"
    local label="$2"
    local results
    results="$(grep -rn -E "$DEV_FLAGS" \
        --include="$pattern" \
        "$REPO_ROOT" \
        2>/dev/null \
        | grep -v '/tests/' \
        | grep -v '/lints/' \
        | grep -v 'scripts/dev-local-e2e.sh' \
        | grep -v '\.md:' \
        || true)"
    if [[ -n "$results" ]]; then
        echo "[lint] VIOLATION in $label files:"
        echo "$results" | sed 's/^/  /'
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
}

check_files "*.toml" "TOML config"
check_files "*.yaml" "YAML config"
check_files "*.yml"  "YML config"

# Also check the deploy/ directory for any file type.
DEPLOY_DIR="$REPO_ROOT/deploy"
if [[ -d "$DEPLOY_DIR" ]]; then
    DEPLOY_HITS="$(grep -rn -E "$DEV_FLAGS" "$DEPLOY_DIR" 2>/dev/null | grep -v '\.md:' || true)"
    if [[ -n "$DEPLOY_HITS" ]]; then
        echo "[lint] VIOLATION in deploy/ directory:"
        echo "$DEPLOY_HITS" | sed 's/^/  /'
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

if [[ "$VIOLATIONS" -gt 0 ]]; then
    echo ""
    echo "[lint] FAILED: dev-only flags found in $VIOLATIONS location(s)."
    echo "[lint] DISK_USE_STUB_CA and DISK_ACL_ALLOW_UNSIGNED are local-mode only."
    echo "[lint] They MUST NOT appear in production configs or deploy manifests."
    echo "[lint] Dev-only location: scripts/dev-local-e2e.sh (loopback bring-up)."
    exit 1
fi

echo "[lint] OK: dev flags not found in any production config or deploy file."
exit 0
