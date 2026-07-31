#!/usr/bin/env bash
# INFRA-0370: exercise install-systemd-unit.sh against a throwaway directory.
#
# Covers the paths that would otherwise only ever run against production:
# dry-run leaves the target untouched, install writes the unit and takes a
# backup, install is idempotent, and a failing health check restores the backup.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
INSTALLER="$REPO_ROOT/scripts/install-systemd-unit.sh"
SOURCE_UNIT="$REPO_ROOT/deploy/linux/disk-arcana-server.service"
failures=0

WORK="$(mktemp -d "${TMPDIR:-/tmp}/disk-arcana-unit-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

UNIT="disk-arcana-server.service"

pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }

# Health stub: a file whose contents decide whether the "endpoint" is healthy.
HEALTH_FILE="$WORK/health.json"
run_installer() {
  DISK_ARCANA_UNIT_DIR="$WORK" \
  DISK_ARCANA_HEALTH_URL="file://$HEALTH_FILE" \
  DISK_ARCANA_HEALTH_RETRIES=2 \
    bash "$INSTALLER" "$@"
}

# ---------------------------------------------------------------- dry-run ---
printf '# dry-run against an absent unit\n'
if run_installer --dry-run | grep -q 'ABSENT'; then
  pass "dry-run reports an absent unit"
else
  fail "dry-run did not report the absent unit"
fi
if [[ ! -f "$WORK/$UNIT" ]]; then
  pass "dry-run created nothing"
else
  fail "dry-run wrote to the target directory"
fi

# ---------------------------------------------------------------- install ---
printf '\n# install onto a host carrying a stale unit\n'
# Simulate the real prod situation: an older unit with the restart-limit keys
# in the wrong section.
cp "$REPO_ROOT/deploy/linux/tests/fixtures/invalid-start-limit.service" "$WORK/$UNIT"
printf '{"status":"ok"}\n' >"$HEALTH_FILE"

if run_installer --install >"$WORK/install.log" 2>&1; then
  pass "install succeeded against a healthy endpoint"
else
  fail "install failed: $(tail -3 "$WORK/install.log")"
fi

if cmp -s "$SOURCE_UNIT" "$WORK/$UNIT"; then
  pass "installed unit matches the repo unit byte for byte"
else
  fail "installed unit differs from the repo unit"
fi

backup_count="$(find "$WORK" -maxdepth 1 -name "$UNIT.bak-*" | wc -l)"
if [[ "$backup_count" -eq 1 ]]; then
  pass "install took exactly one backup of the previous unit"
else
  fail "expected 1 backup, found $backup_count"
fi

backup_file="$(find "$WORK" -maxdepth 1 -name "$UNIT.bak-*" | head -1)"
if grep -q 'negative control' "$backup_file"; then
  pass "backup preserves the previous (stale) unit"
else
  fail "backup does not contain the previous unit"
fi

if grep -q 'Unknown key' "$WORK/install.log"; then
  fail "install log unexpectedly reports an unknown key"
else
  pass "install log is clean"
fi

# ------------------------------------------------------------- idempotent ---
printf '\n# re-install with the unit already correct\n'
# Redirect to a file rather than piping into grep: `grep -q` closes the pipe on
# first match, the installer dies with SIGPIPE, and `pipefail` would report 141
# for a run that actually succeeded.
run_installer --install >"$WORK/reinstall.log" 2>&1
if grep -q 'IDENTICAL' "$WORK/reinstall.log"; then
  pass "second install detects an identical unit"
else
  fail "second install did not detect an identical unit"
fi
if cmp -s "$SOURCE_UNIT" "$WORK/$UNIT"; then
  pass "second install leaves the unit correct"
else
  fail "second install corrupted the unit"
fi

# ---------------------------------------------------------------- rollback ---
printf '\n# install with a failing health endpoint must roll back\n'
rm -f "$WORK"/"$UNIT".bak-*
cp "$REPO_ROOT/deploy/linux/tests/fixtures/invalid-start-limit.service" "$WORK/$UNIT"
printf '{"status":"degraded"}\n' >"$HEALTH_FILE"

if run_installer --install >"$WORK/rollback.log" 2>&1; then
  fail "install reported success despite an unhealthy endpoint"
else
  pass "install exits non-zero when the service does not come healthy"
fi

if grep -q 'rolling back' "$WORK/rollback.log"; then
  pass "install announces the rollback"
else
  fail "install did not announce a rollback"
fi

if cmp -s "$REPO_ROOT/deploy/linux/tests/fixtures/invalid-start-limit.service" "$WORK/$UNIT"; then
  pass "rollback restored the previous unit"
else
  fail "rollback did NOT restore the previous unit — target left modified"
fi

printf '\n'
if [[ "$failures" -ne 0 ]]; then
  printf '%s install-unit check(s) failed\n' "$failures" >&2
  exit 1
fi

printf 'All install-unit checks passed\n'
