#!/usr/bin/env bash
# check_loopback_bind.sh — R14 CI lint (defence-in-depth)
#
# Static fence preventing accidental non-loopback bind in the REST API
# module of disk-client. R7 already provides:
#   - runtime guard `assert_loopback_bind` (rest_api/mod.rs:170)
#   - integration test `it_rest_loopback_only.rs`
#
# This script is the third layer: a grep-time gate that catches a
# regression before it reaches the runtime (and before any human review
# is needed to spot a literal `0.0.0.0` or `Ipv4Addr::UNSPECIFIED`).
#
# Forbidden patterns inside `crates/disk-client/src/rest_api/`:
#   - literal "0.0.0.0"
#   - literal "[::]"           (IPv6 unspecified)
#   - `Ipv4Addr::UNSPECIFIED`
#   - `Ipv6Addr::UNSPECIFIED`
#
# Allowed exception: comments / module docs that mention the addresses
# for explanatory purposes (lines beginning with `//` or `//!`). The
# loopback-only invariant is part of the module's public contract, so
# the docs MUST be free to reference the addresses they reject.
#
# Usage:
#   ./crates/disk-client/lints/check_loopback_bind.sh [repo-root]
#
# Exit codes:
#   0 — no violations
#   1 — one or more violations found

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Default REPO_ROOT walks lints/ -> disk-client/ -> crates/ -> repo root.
REPO_ROOT="${1:-"$(cd "$SCRIPT_DIR/../../.." && pwd)"}"
REST_SRC="$REPO_ROOT/crates/disk-client/src/rest_api"

if [[ ! -d "$REST_SRC" ]]; then
    echo "[lint] ERROR: REST source directory not found: $REST_SRC"
    exit 2
fi

# Patterns that MUST NOT appear on non-comment lines.
# Use grep -E with alternation; -F won't help because we need anchoring.
PATTERN='(^|[^/])("0\.0\.0\.0"|"\[::\]"|Ipv4Addr::UNSPECIFIED|Ipv6Addr::UNSPECIFIED)'

echo "[lint] Checking REST module for non-loopback bind literals…"
echo "[lint] Scanning: $REST_SRC"

VIOLATIONS=0
while IFS= read -r -d '' file; do
    # Strip leading whitespace; drop pure-comment lines (// or //!).
    # `grep -nE` reports `line_no:content` — we filter via awk to ignore
    # lines whose first non-ws chars are //.
    matches=$(awk '
        {
            stripped = $0
            sub(/^[[:space:]]+/, "", stripped)
            if (stripped ~ /^\/\//) next
            if (stripped ~ /"0\.0\.0\.0"|"\[::\]"|Ipv4Addr::UNSPECIFIED|Ipv6Addr::UNSPECIFIED/) {
                print NR ":" $0
            }
        }
    ' "$file")
    if [[ -n "$matches" ]]; then
        echo "[lint] VIOLATION in: ${file#"$REPO_ROOT/"}"
        echo "$matches" | sed 's/^/  /'
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done < <(find "$REST_SRC" -name "*.rs" -print0)

if [[ "$VIOLATIONS" -gt 0 ]]; then
    echo ""
    echo "[lint] FAILED: $VIOLATIONS file(s) contain non-loopback bind literals."
    echo "[lint] The REST API daemon endpoint MUST bind to a loopback address."
    echo "[lint] See: crates/disk-client/src/rest_api/mod.rs:170 (assert_loopback_bind)"
    echo "[lint] See: crates/disk-client/tests/it_rest_loopback_only.rs (runtime IT)"
    exit 1
fi

echo "[lint] OK: no violations found."
exit 0
