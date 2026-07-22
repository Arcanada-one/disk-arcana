#!/usr/bin/env bash
# Self-tests for check_dev_flags_not_in_prod.sh (DISK-0059).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINT="$SCRIPT_DIR/check_dev_flags_not_in_prod.sh"

fail() {
  printf 'SELFTEST FAIL: %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'SELFTEST PASS: %s\n' "$1"
}

TMP="$(mktemp -d "${TMPDIR:-/tmp}/disk-dev-flags-lint.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/deploy/prod"

# AC-1: comment-only mention in deploy template must not fail.
cat >"$TMP/deploy/prod/env.example" <<'EOF'
# Production env — never set DISK_USE_STUB_CA=1 or DISK_ACL_ALLOW_UNSIGNED=1.
DISK_BIND_ADDR=0.0.0.0:9443
EOF

if ! bash "$LINT" "$TMP"; then
  fail "comment-only deploy line should be allowed"
fi
pass "comment-only deploy documentation allowed"

# AC-2: active assignment must still fail.
printf '%s\n' 'DISK_USE_STUB_CA=1' >>"$TMP/deploy/prod/env.example"

if bash "$LINT" "$TMP" 2>/dev/null; then
  fail "active DISK_USE_STUB_CA assignment must fail"
fi
pass "active dev flag assignment rejected"

printf 'SELFTEST OK (2/2)\n'
