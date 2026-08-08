#!/usr/bin/env bash
# INFRA-0370: fake-root contract for the crash-recoverable binary+unit deployer.

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(git rev-parse --show-toplevel)"
DEPLOYER="${DEPLOYER_OVERRIDE:-$REPO_ROOT/deploy/linux/deploy-server.sh}"
VALIDATOR="$REPO_ROOT/deploy/linux/validate-deploy-bundle.sh"
UNIT_SOURCE="$REPO_ROOT/deploy/linux/disk-arcana-server.service"
EXPECTED_COMMIT="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
EXPECTED_HOST="stage.example.internal"
TESTS=0

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

pass() {
  TESTS=$((TESTS + 1))
  printf 'PASS  %s\n' "$1"
}

fail() {
  printf 'FAIL  %s\n' "$1" >&2
  exit 1
}

sha() {
  sha256sum -- "$1" | awk '{print $1}'
}

write_old_unit() {
  local path="$1"
  install -d -m 0755 "$(dirname "$path")"
  sed 's/^Description=.*/Description=Disk Arcana prior test service/' "$UNIT_SOURCE" >"$path"
  chmod 0644 "$path"
}

write_shims() {
  local case_root="$1"
  local shim_dir="$case_root/shims"
  install -d -m 0755 "$shim_dir"

  cat >"$shim_dir/hostname" <<'SHIM'
#!/usr/bin/env bash
printf '%s\n' "${DISK_TEST_HOSTNAME:?}"
SHIM

  cat >"$shim_dir/systemd-analyze" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
if [[ -f "${DISK_TEST_FLAGS:?}/invalid-unit" ]]; then
  exit 1
fi
exit 0
SHIM

  cat >"$shim_dir/systemctl" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
flags="${DISK_TEST_FLAGS:?}"
cmd="${1:-}"
shift || true
case "$cmd" in
  is-active)
    [[ ! -f "$flags/inactive" ]]
    ;;
  is-enabled)
    [[ ! -f "$flags/disabled" ]]
    ;;
  daemon-reload)
    reload_count=0
    [[ -f "$flags/reload-count" ]] && reload_count="$(<"$flags/reload-count")"
    reload_count=$((reload_count + 1))
    printf '%s\n' "$reload_count" >"$flags/reload-count"
    if [[ -f "$flags/fail-recovery-reload" ]]; then
      exit 1
    fi
    if [[ -f "$flags/fail-reload" ]]; then
      rm -f "$flags/fail-reload"
      exit 1
    fi
    ;;
  restart)
    if [[ -f "$flags/fail-recovery-restart" ]]; then
      exit 1
    fi
    if [[ -f "$flags/fail-restart" ]]; then
      rm -f "$flags/fail-restart"
      exit 1
    fi
    restart_count=0
    [[ -f "$flags/restart-count" ]] && restart_count="$(<"$flags/restart-count")"
    restart_count=$((restart_count + 1))
    printf '%s\n' "$restart_count" >"$flags/restart-count"
    if [[ "$restart_count" -ge 2 ]]; then
      rm -f "$flags/unhealthy"
    fi
    ;;
  show)
    property=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == -p && $# -ge 2 ]]; then
        property="$2"
        shift 2
      else
        shift
      fi
    done
    case "$property" in
      StartLimitIntervalUSec)
        if [[ -f "$flags/bad-policy" ]]; then
          rm -f "$flags/bad-policy"
          printf '10s\n'
        else
          printf '2min\n'
        fi
        ;;
      StartLimitBurst)
        [[ -f "$flags/bad-policy" ]] && printf '3\n' || printf '5\n'
        ;;
      Restart)
        printf 'on-failure\n'
        ;;
      *)
        exit 2
        ;;
    esac
    ;;
  *)
    exit 2
    ;;
esac
SHIM

  cat >"$shim_dir/curl" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
flags="${DISK_TEST_FLAGS:?}"
if [[ -f "$flags/fail-recovery-health" && -f "$flags/reload-count" && "$(<"$flags/reload-count")" -ge 2 ]]; then
  printf '%s\n' "${DISK_TEST_SENTINEL:?}" >&2
  exit 22
fi
if [[ -f "$flags/unhealthy" && -f "$flags/restart-count" ]]; then
  printf '%s\n' "${DISK_TEST_SENTINEL:?}" >&2
  exit 22
fi
printf '{"status":"ok","detail":"%s"}\n' "${DISK_TEST_SENTINEL:?}"
SHIM

  chmod 0755 "$shim_dir"/*
}

setup_case() {
  local name="$1"
  CASE_ROOT="$TMP/$name"
  FAKE_ROOT="$CASE_ROOT/root"
  BUNDLE="$CASE_ROOT/bundle"
  FLAGS="$CASE_ROOT/flags"
  OUTPUT="$CASE_ROOT/output.log"
  install -d -m 0755 \
    "$FAKE_ROOT/usr/local/bin" \
    "$FAKE_ROOT/etc/systemd/system" \
    "$FAKE_ROOT/var/lib/disk-arcana-deploy/transactions" \
    "$FAKE_ROOT/var/lib/disk-arcana-deploy/backups" \
    "$FAKE_ROOT/run/lock" \
    "$FAKE_ROOT/etc/disk-arcana" \
    "$BUNDLE" "$FLAGS"
  chmod 0700 \
    "$FAKE_ROOT/var/lib/disk-arcana-deploy/transactions" \
    "$FAKE_ROOT/var/lib/disk-arcana-deploy/backups"
  install -d -m 0700 "$FAKE_ROOT/var/lib/disk-arcana-deploy/transactions/records"
  install -m 0600 /dev/null "$FAKE_ROOT/run/lock/disk-arcana-deploy.lock"

  printf 'old server binary\n' >"$FAKE_ROOT/usr/local/bin/disk-arcana-server"
  chmod 0755 "$FAKE_ROOT/usr/local/bin/disk-arcana-server"
  write_old_unit "$FAKE_ROOT/etc/systemd/system/disk-arcana-server.service"
  printf 'DISK_TEST_SECRET=%s\n' 'sentinel-env-0370' >"$FAKE_ROOT/etc/disk-arcana/env"
  chmod 0640 "$FAKE_ROOT/etc/disk-arcana/env"

  OLD_BINARY_SHA="$(sha "$FAKE_ROOT/usr/local/bin/disk-arcana-server")"
  OLD_UNIT_SHA="$(sha "$FAKE_ROOT/etc/systemd/system/disk-arcana-server.service")"

  printf 'new server binary\n' >"$BUNDLE/disk-arcana-server"
  chmod 0755 "$BUNDLE/disk-arcana-server"
  install -m 0644 "$UNIT_SOURCE" "$BUNDLE/disk-arcana-server.service"
  install -m 0755 "$DEPLOYER" "$BUNDLE/deploy-server.sh"
  install -m 0755 "$REPO_ROOT/deploy/linux/install.sh" "$BUNDLE/install.sh"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$BUNDLE/deploy-server-broker.sh"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$BUNDLE/provision-deploy-broker.sh"
  chmod 0755 "$BUNDLE/deploy-server-broker.sh" "$BUNDLE/provision-deploy-broker.sh"
  printf '%%disk-arcana-deploy ALL=(root) NOPASSWD: /usr/local/sbin/disk-arcana-deploy-broker *\n' \
    >"$BUNDLE/disk-arcana-deploy.sudoers"
  chmod 0440 "$BUNDLE/disk-arcana-deploy.sudoers"
  printf '%s\n' "$EXPECTED_COMMIT" >"$BUNDLE/commit"
  "$VALIDATOR" create --root "$BUNDLE" --commit "$EXPECTED_COMMIT" >/dev/null

  NEW_BINARY_SHA="$(sha "$BUNDLE/disk-arcana-server")"
  NEW_UNIT_SHA="$(sha "$BUNDLE/disk-arcana-server.service")"
  write_shims "$CASE_ROOT"
}

run_deploy() {
  local expected_host="${1:-$EXPECTED_HOST}"
  shift || true
  env \
    PATH="$CASE_ROOT/shims:$PATH" \
    DISK_ARCANA_DEPLOY_TESTING=1 \
    DISK_ARCANA_DEPLOY_TEST_ROOT="$FAKE_ROOT" \
    DISK_TEST_HOSTNAME="$EXPECTED_HOST" \
    DISK_TEST_FLAGS="$FLAGS" \
    DISK_TEST_SENTINEL='sentinel-health-0370' \
    "$@" \
    bash -c "set +e; \"\$@\"; rc=\$?; :; exit \"\$rc\"" _ \
      "$DEPLOYER" --bundle "$BUNDLE" \
      --expected-commit "$EXPECTED_COMMIT" \
      --expected-hostname "$expected_host" >"$OUTPUT" 2>&1
}

assert_old_installed() {
  [[ "$(sha "$FAKE_ROOT/usr/local/bin/disk-arcana-server")" == "$OLD_BINARY_SHA" ]] ||
    fail "old binary hash was not restored"
  [[ "$(sha "$FAKE_ROOT/etc/systemd/system/disk-arcana-server.service")" == "$OLD_UNIT_SHA" ]] ||
    fail "old unit hash was not restored"
  [[ -z "$(find "$FAKE_ROOT/usr/local/bin" "$FAKE_ROOT/etc/systemd/system" -maxdepth 1 -name '*.stage.*' -print -quit)" ]] ||
    fail "rollback retained a staged deployment file"
}

assert_new_installed() {
  [[ "$(sha "$FAKE_ROOT/usr/local/bin/disk-arcana-server")" == "$NEW_BINARY_SHA" ]] ||
    fail "new binary hash was not installed"
  [[ "$(sha "$FAKE_ROOT/etc/systemd/system/disk-arcana-server.service")" == "$NEW_UNIT_SHA" ]] ||
    fail "new unit hash was not installed"
  [[ -z "$(find "$FAKE_ROOT/usr/local/bin" "$FAKE_ROOT/etc/systemd/system" -maxdepth 1 -name '*.stage.*' -print -quit)" ]] ||
    fail "recovery retained a staged deployment file"
}

assert_no_sentinel_output() {
  if grep -qE 'sentinel-(env|health)-0370' "$OUTPUT"; then
    fail "secret sentinel leaked to deploy output"
  fi
}

[[ -x "$DEPLOYER" ]] || fail "deploy helper is missing or not executable: $DEPLOYER"

setup_case success
run_deploy || fail "healthy deploy returned non-zero"
assert_new_installed
grep -qF 'state=COMMITTED' "$OUTPUT" || fail "healthy deploy did not report COMMITTED"
assert_no_sentinel_output
pass "healthy deploy commits exact bundle binary and unit without secret output"

setup_case wrong-host
if run_deploy wrong.example.internal; then
  fail "wrong hostname was accepted"
fi
assert_old_installed
[[ ! -e "$FAKE_ROOT/var/lib/disk-arcana-deploy/transactions/current" ]] ||
  fail "failed precheck created a transaction journal"
pass "wrong hostname fails before target mutation"

setup_case manifest-mismatch
printf 'tampered\n' >>"$BUNDLE/disk-arcana-server"
if run_deploy; then
  fail "tampered manifest member was accepted"
fi
assert_old_installed
pass "manifest mismatch fails before target mutation"

setup_case active-lock
exec 8>"$FAKE_ROOT/run/lock/disk-arcana-deploy.lock"
flock -n 8 || fail "test could not acquire deploy lock"
if run_deploy; then
  fail "active deployment lock was ignored"
fi
flock -u 8
assert_old_installed
pass "active lock fails before target mutation"

setup_case unsafe-destination
mv "$FAKE_ROOT/etc/systemd/system/disk-arcana-server.service" "$CASE_ROOT/unit-real"
ln -s "$CASE_ROOT/unit-real" "$FAKE_ROOT/etc/systemd/system/disk-arcana-server.service"
if run_deploy; then
  fail "symlinked unit destination was accepted"
fi
[[ "$(sha "$CASE_ROOT/unit-real")" == "$OLD_UNIT_SHA" ]] || fail "symlink target was mutated"
pass "symlinked destination fails before target mutation"

setup_case symlinked-ancestor
mv "$FAKE_ROOT/usr/local" "$CASE_ROOT/local-real"
ln -s "$CASE_ROOT/local-real" "$FAKE_ROOT/usr/local"
if run_deploy; then
  fail "symlinked binary ancestor was accepted"
fi
[[ "$(sha "$CASE_ROOT/local-real/bin/disk-arcana-server")" == "$OLD_BINARY_SHA" ]] ||
  fail "symlink-ancestor target was mutated"
[[ ! -e "$FAKE_ROOT/var/lib/disk-arcana-deploy/transactions/current" ]] ||
  fail "symlink-ancestor precheck created a transaction journal"
pass "symlinked destination ancestor fails before target mutation"

setup_case wrong-mode
chmod 0666 "$FAKE_ROOT/etc/systemd/system/disk-arcana-server.service"
if run_deploy; then
  fail "unexpected current unit mode was accepted"
fi
[[ "$(sha "$FAKE_ROOT/usr/local/bin/disk-arcana-server")" == "$OLD_BINARY_SHA" ]] ||
  fail "wrong-mode precheck mutated binary"
pass "unexpected current mode fails before target mutation"

setup_case inactive-baseline
: >"$FLAGS/inactive"
if run_deploy; then
  fail "inactive service baseline was accepted"
fi
assert_old_installed
pass "missing active-service baseline fails before target mutation"

setup_case disabled-baseline
: >"$FLAGS/disabled"
if run_deploy; then
  fail "disabled service baseline was accepted"
fi
assert_old_installed
pass "disabled-service baseline fails before target mutation"

setup_case invalid-staged-unit
sed -i 's/^StartLimitBurst=5$/StartLimitBurst=6/' "$BUNDLE/disk-arcana-server.service"
rm -f "$BUNDLE/manifest.sha256"
"$VALIDATOR" create --root "$BUNDLE" --commit "$EXPECTED_COMMIT" >/dev/null
if run_deploy; then
  fail "invalid staged unit was accepted"
fi
assert_old_installed
pass "invalid staged unit fails before target mutation"

for failure in fail-reload fail-restart bad-policy unhealthy; do
  setup_case "sync-$failure"
  : >"$FLAGS/$failure"
  if run_deploy; then
    fail "$failure returned success"
  fi
  assert_old_installed
  grep -qF 'state=FAILED_RECOVERED' "$OUTPUT" ||
    fail "$failure did not prove recovered state"
  assert_no_sentinel_output
  pass "$failure restores both exact prior files and proves recovered health"
done

for failure in binary-activation unit-activation; do
  setup_case "activation-$failure"
  if run_deploy "$EXPECTED_HOST" DISK_ARCANA_DEPLOY_TEST_FAIL_AT="$failure"; then
    fail "$failure injection returned success"
  fi
  assert_old_installed
  grep -qF 'state=FAILED_RECOVERED' "$OUTPUT" ||
    fail "$failure did not prove recovered state"
  pass "$failure failure restores both exact prior files"
done

setup_case recovery-required
: >"$FLAGS/fail-restart"
: >"$FLAGS/fail-recovery-restart"
if run_deploy; then
  fail "rollback restart failure returned success"
fi
assert_old_installed
grep -qF 'state=FAILED_RECOVERY_REQUIRED' \
  "$FAKE_ROOT/var/lib/disk-arcana-deploy/transactions/current" ||
  fail "rollback failure did not retain FAILED_RECOVERY_REQUIRED journal"
pass "rollback failure is terminal FAILED_RECOVERY_REQUIRED"

for recovery_failure in reload restart health; do
  setup_case "recovery-required-$recovery_failure"
  : >"$FLAGS/fail-reload"
  : >"$FLAGS/fail-recovery-$recovery_failure"
  if run_deploy; then
    fail "recovery $recovery_failure failure returned success"
  fi
  grep -qF 'state=FAILED_RECOVERY_REQUIRED' \
    "$FAKE_ROOT/var/lib/disk-arcana-deploy/transactions/current" ||
    fail "recovery $recovery_failure failure did not retain terminal journal"
  pass "recovery $recovery_failure failure remains terminal"
done

for state in BACKUP_WRITTEN FILES_STAGED FILES_ACTIVATED DAEMON_RELOADED SERVICE_RESTARTED HEALTH_VERIFIED COMMITTED; do
  setup_case "crash-$state"
  if run_deploy "$EXPECTED_HOST" DISK_ARCANA_DEPLOY_TEST_KILL_AFTER_STATE="$state"; then
    fail "SIGKILL injection after $state returned success"
  fi
  if run_deploy; then
    :
  else
    fail "fresh invocation after $state crash did not recover and deploy"
  fi
  assert_new_installed
  grep -qF "recovered_from=$state" "$OUTPUT" ||
    fail "fresh invocation did not attest recovery from $state"
  assert_no_sentinel_output
  pass "fresh invocation recovers exact prior generation after $state crash"
done

setup_case crash-between-activation
if run_deploy "$EXPECTED_HOST" DISK_ARCANA_DEPLOY_TEST_KILL_AFTER_BINARY_ACTIVATION=1; then
  fail "SIGKILL injection between binary and unit activation returned success"
fi
run_deploy || fail "fresh invocation did not recover split activation"
assert_new_installed
grep -qF 'recovered_from=FILES_STAGED' "$OUTPUT" ||
  fail "split activation recovery did not use the persisted pre-activation state"
pass "fresh invocation recovers both files after crash between atomic activations"

setup_case idempotent
run_deploy || fail "first idempotence deploy failed"
backup_count_before="$(find "$FAKE_ROOT/var/lib/disk-arcana-deploy/backups" -mindepth 1 -maxdepth 1 -type d | wc -l)"
run_deploy || fail "second idempotence deploy failed"
backup_count_after="$(find "$FAKE_ROOT/var/lib/disk-arcana-deploy/backups" -mindepth 1 -maxdepth 1 -type d | wc -l)"
[[ "$backup_count_before" == "$backup_count_after" ]] || fail "idempotent reapply created a new backup"
grep -qF 'state=COMMITTED idempotent=true' "$OUTPUT" || fail "idempotent reapply not reported"
assert_new_installed
pass "identical reapply is a verified no-op"

printf 'All deploy-server checks passed (%d cases)\n' "$TESTS"
