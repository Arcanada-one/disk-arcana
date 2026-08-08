#!/usr/bin/env bash
# INFRA-0370: fake-root cold-bootstrap durability contract.

set -euo pipefail
IFS=$'\n\t'

ROOT_REPO="$(git rev-parse --show-toplevel)"
INSTALLER="$ROOT_REPO/deploy/linux/install.sh"
UNIT="$ROOT_REPO/deploy/linux/disk-arcana-server.service"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
TESTS=0

pass() { TESTS=$((TESTS + 1)); printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

setup_case() {
  local name="$1"
  CASE="$TMP/$name"
  FAKE_ROOT="$CASE/root"
  JOURNAL_DIR="$CASE/audit"
  BINARY="$CASE/disk-arcana-server"
  OUTPUT="$CASE/output"
  FLAGS="$CASE/flags"
  SHIMS="$CASE/shims"
  install -d -m 0755 \
    "$FAKE_ROOT/usr/local/bin" "$FAKE_ROOT/etc/systemd/system" \
    "$FAKE_ROOT/etc/disk-arcana/tls" "$FAKE_ROOT/etc/disk-arcana/gpg" \
    "$FAKE_ROOT/var/lib" "$FAKE_ROOT/var/log" "$JOURNAL_DIR" "$FLAGS" "$SHIMS"
  chmod 0750 "$FAKE_ROOT/etc/disk-arcana" "$FAKE_ROOT/etc/disk-arcana/tls"
  chmod 0700 "$FAKE_ROOT/etc/disk-arcana/gpg" "$JOURNAL_DIR"
  printf 'DISK_TEST_SENTINEL=bootstrap-secret-0370\n' >"$FAKE_ROOT/etc/disk-arcana/env"
  chmod 0600 "$FAKE_ROOT/etc/disk-arcana/env"
  printf 'cold binary\n' >"$BINARY"
  chmod 0755 "$BINARY"

  cat >"$SHIMS/hostname" <<'SHIM'
#!/usr/bin/env bash
printf 'cold.example.internal\n'
SHIM
  cat >"$SHIMS/systemd-analyze" <<'SHIM'
#!/usr/bin/env bash
[[ "${1:-}" == verify && -f "${2:-}" ]]
SHIM
  cat >"$SHIMS/systemctl" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
flags="${DISK_TEST_FLAGS:?}"
case "${1:-}" in
  daemon-reload) exit 0 ;;
  enable) : >"$flags/enabled"; : >"$flags/active" ;;
  disable) rm -f "$flags/enabled" "$flags/active" ;;
  is-active) [[ -f "$flags/active" ]] ;;
  is-enabled) [[ -f "$flags/enabled" ]] ;;
  *) exit 2 ;;
esac
SHIM
  cat >"$SHIMS/curl" <<'SHIM'
#!/usr/bin/env bash
printf '{"status":"ok","detail":"%s"}\n' "${DISK_TEST_SENTINEL:?}"
SHIM
  chmod 0755 "$SHIMS"/*
}

run_installer() {
  env PATH="$SHIMS:$PATH" \
    DISK_ARCANA_INSTALL_TESTING=1 \
    DISK_TEST_FLAGS="$FLAGS" \
    DISK_TEST_SENTINEL=bootstrap-secret-0370 \
    "$@" \
    "$INSTALLER" --binary "$BINARY" --unit "$UNIT" \
      --journal-dir "$JOURNAL_DIR" --expected-hostname cold.example.internal \
      --root "$FAKE_ROOT" >"$OUTPUT" 2>&1
}

assert_cold_absent() {
  [[ ! -e "$FAKE_ROOT/usr/local/bin/disk-arcana-server" ]] || fail "rollback retained cold binary"
  [[ ! -e "$FAKE_ROOT/etc/systemd/system/disk-arcana-server.service" ]] || fail "rollback retained cold unit"
  [[ ! -e "$FAKE_ROOT/var/lib/disk-arcana" ]] || fail "rollback retained cold data directory"
  [[ ! -e "$FAKE_ROOT/var/log/disk-arcana" ]] || fail "rollback retained cold log directory"
}

setup_case success
run_installer || { sed -n '1,80p' "$OUTPUT" >&2; fail "valid cold bootstrap failed"; }
[[ -f "$FAKE_ROOT/usr/local/bin/disk-arcana-server" ]] || fail "cold binary was not installed"
[[ -f "$FAKE_ROOT/etc/systemd/system/disk-arcana-server.service" ]] || fail "cold unit was not installed"
grep -qF 'state=COMMITTED health=ok' "$OUTPUT" || fail "cold bootstrap did not commit"
! grep -qF 'bootstrap-secret-0370' "$OUTPUT" || fail "cold bootstrap leaked sentinel output"
pass "cold bootstrap installs, enables, starts and health-checks without secret output"

if ! run_installer; then
  sed -n '1,80p' "$OUTPUT" >&2
  fail "committed cold bootstrap did not verify idempotently"
fi
grep -qF 'state=COMMITTED recovered=true' "$OUTPUT" ||
  fail "committed cold bootstrap was not read back"
pass "committed cold bootstrap re-verifies hashes, active/enabled state and health"

setup_case existing-group
: >"$JOURNAL_DIR/test-group-exists"
run_installer || { sed -n '1,80p' "$OUTPUT" >&2; fail "bootstrap with existing service group failed"; }
[[ -f "$JOURNAL_DIR/test-group-exists" && -f "$JOURNAL_DIR/test-user-exists" ]] ||
  fail "bootstrap did not preserve the existing group while creating the user"
pass "cold bootstrap supports an existing service group without an existing user"

setup_case rollback
if run_installer DISK_ARCANA_INSTALL_TEST_FAIL_AT=HEALTH_VERIFIED; then
  fail "injected cold-bootstrap failure returned success"
fi
assert_cold_absent
[[ ! -e "$JOURNAL_DIR/test-user-exists" && ! -e "$JOURNAL_DIR/test-group-exists" ]] ||
  fail "rollback retained created service account"
grep -qF 'state=FAILED_RECOVERED' "$JOURNAL_DIR/install-current" ||
  fail "rollback did not persist recovered state"
pass "synchronous cold-bootstrap failure restores the absent baseline"

for state in INVENTORIED ACCOUNT_READY DIRECTORIES_READY FILES_INSTALLED SERVICE_ENABLED HEALTH_VERIFIED; do
  setup_case "crash-$state"
  if run_installer DISK_ARCANA_INSTALL_TEST_KILL_AFTER_STATE="$state"; then
    fail "SIGKILL injection after $state returned success"
  fi
  if run_installer; then
    fail "recovery after $state crash returned deployment success"
  fi
  assert_cold_absent
  grep -qF 'state=FAILED_RECOVERED' "$JOURNAL_DIR/install-current" ||
    fail "recovery after $state did not persist FAILED_RECOVERED"
  pass "fresh invocation restores the absent baseline after $state crash"
done

printf 'All cold-bootstrap checks passed (%d cases)\n' "$TESTS"
