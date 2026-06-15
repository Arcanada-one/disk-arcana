#!/usr/bin/env bash
# no_branch_on_client_config.sh — P4a Step 10 CI lint
#
# Grep for server-side reads of `intended_direction` outside the `audit`
# module.  Any match triggers a non-zero exit (CI fail).
#
# Usage:
#   ./crates/disk-server/lints/no_branch_on_client_config.sh [repo-root]
#
# The optional argument is the repository root; defaults to the directory
# two levels above this script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The script lives at crates/disk-server/lints/ — three levels up is the repo root.
REPO_ROOT="${1:-"$(cd "$SCRIPT_DIR/../../.." && pwd)"}"
# Guard: fail loudly if the computed path does not contain disk-server/src.
if [[ ! -d "$REPO_ROOT/crates/disk-server/src" ]]; then
    echo "[lint] ERROR: disk-server/src not found under REPO_ROOT=$REPO_ROOT" >&2
    echo "[lint] Pass the repository root as the first argument, or run from inside the repo." >&2
    exit 2
fi
SERVER_SRC="$REPO_ROOT/crates/disk-server/src"

PATTERN='\.get\("intended_direction"\)'
AUDIT_MODULE="$SERVER_SRC/audit"

echo "[lint] Checking for server-side 'intended_direction' reads outside audit module…"
echo "[lint] Scanning: $SERVER_SRC"

# Find all Rust files in disk-server/src.
VIOLATIONS=0
while IFS= read -r -d '' file; do
    # Allow reads inside the audit module.
    if [[ "$file" == "$AUDIT_MODULE"* ]]; then
        continue
    fi

    # Grep for the forbidden pattern.
    if grep -qnE "$PATTERN" "$file"; then
        echo "[lint] VIOLATION in: $file"
        grep -nE "$PATTERN" "$file" | while IFS= read -r line; do
            echo "  $line"
        done
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done < <(find "$SERVER_SRC" -name "*.rs" -print0)

if [[ "$VIOLATIONS" -gt 0 ]]; then
    echo ""
    echo "[lint] FAILED: $VIOLATIONS file(s) contain server-side 'intended_direction' reads."
    echo "[lint] Only the audit module is permitted to read this field."
    echo "[lint] See: crates/disk-server/lints/no_branch_on_client_config.rs"
    exit 1
fi

echo "[lint] OK: no violations found."
exit 0
