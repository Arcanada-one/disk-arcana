#!/usr/bin/env bash
# INFRA-0370: fake-root contract for one-shot broker provisioning and import.

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(git rev-parse --show-toplevel)"
BROKER="$REPO_ROOT/deploy/linux/deploy-server-broker.sh"
PROVISIONER="$REPO_ROOT/deploy/linux/provision-deploy-broker.sh"
HELPER="$REPO_ROOT/deploy/linux/deploy-server.sh"
VALIDATOR="$REPO_ROOT/deploy/linux/validate-deploy-bundle.sh"
UNIT_SOURCE="$REPO_ROOT/deploy/linux/disk-arcana-server.service"
SUDOERS_SOURCE="$REPO_ROOT/deploy/linux/disk-arcana-deploy.sudoers"
EXPECTED_COMMIT="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
EXPECTED_HOST="broker.example.internal"
RUNNER_USER="$(id -un)"
RUNNER_GROUP="disk-arcana-deploy"
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

make_bundle() {
  local bundle="$1"
  install -d -m 0755 "$bundle"
  printf '%s\n' "$EXPECTED_COMMIT" >"$bundle/commit"
  printf 'server payload\n' >"$bundle/disk-arcana-server"
  chmod 0755 "$bundle/disk-arcana-server"
  install -m 0644 "$UNIT_SOURCE" "$bundle/disk-arcana-server.service"
  install -m 0755 "$HELPER" "$bundle/deploy-server.sh"
  install -m 0755 "$BROKER" "$bundle/deploy-server-broker.sh"
  install -m 0755 "$PROVISIONER" "$bundle/provision-deploy-broker.sh"
  install -m 0440 "$SUDOERS_SOURCE" "$bundle/disk-arcana-deploy.sudoers"
  "$VALIDATOR" create --root "$bundle" --commit "$EXPECTED_COMMIT" >/dev/null
}

write_shims() {
  local case_root="$1"
  local shims="$case_root/shims"
  install -d -m 0755 "$shims"
  cat >"$shims/hostname" <<'SHIM'
#!/usr/bin/env bash
printf '%s\n' "${DISK_TEST_HOSTNAME:?}"
SHIM
  cat >"$shims/visudo" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == -cf && -f "${2:-}" ]]
grep -qF '/usr/local/sbin/disk-arcana-deploy-broker' "$2"
! grep -qE '(^|[[:space:]])ALL[[:space:]]*($|,)' "$2"
SHIM
  cat >"$shims/systemd-analyze" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == verify && -f "${2:-}" ]]
SHIM
  chmod 0755 "$shims"/*
}

setup_case() {
  local name="$1"
  CASE_ROOT="$TMP/$name"
  FAKE_ROOT="$CASE_ROOT/root"
  DEPLOYMENT_ID="infra0370-${name//[^A-Za-z0-9]/-}"
  BOOTSTRAP="$FAKE_ROOT/var/lib/disk-arcana/bootstrap/$DEPLOYMENT_ID"
  BUNDLE="$BOOTSTRAP/bundle"
  AUTH="$BOOTSTRAP/authorization"
  IMPORT_ROOT="$CASE_ROOT/runner-temp"
  HELPER_LOG="$CASE_ROOT/helper.log"
  OUTPUT="$CASE_ROOT/output.log"
  install -d -m 0755 \
    "$FAKE_ROOT/etc/sudoers.d" \
    "$FAKE_ROOT/etc/disk-arcana" \
    "$FAKE_ROOT/usr/local/libexec/disk-arcana" \
    "$FAKE_ROOT/usr/local/sbin" \
    "$FAKE_ROOT/var/lib/disk-arcana/deploy-transactions" \
    "$BOOTSTRAP" "$IMPORT_ROOT"
  make_bundle "$BUNDLE"
  write_shims "$CASE_ROOT"
  write_authorization "$AUTH" "$BUNDLE" "$(( $(date +%s) + 600 ))" "nonce${name//[^A-Za-z0-9]/}0123456789abcdef"
}

write_authorization() {
  local auth="$1" bundle="$2" expiry="$3" nonce="$4" auth_dir
  auth_dir="$(dirname "$auth")"
  {
    printf 'deployment_id=%s\n' "$DEPLOYMENT_ID"
    printf 'run_id=123456789\n'
    printf 'commit=%s\n' "$EXPECTED_COMMIT"
    printf 'manifest_sha=%s\n' "$(sha "$bundle/manifest.sha256")"
    printf 'hostname=%s\n' "$EXPECTED_HOST"
    printf 'nonce=%s\n' "$nonce"
    printf 'expires=%s\n' "$expiry"
    printf 'runner_user=%s\n' "$RUNNER_USER"
    printf 'runner_group=%s\n' "$RUNNER_GROUP"
    printf 'import_root=%s\n' "$IMPORT_ROOT"
    printf 'bootstrap_root=%s\n' "$auth_dir"
  } >"$auth"
  chmod 0600 "$auth"
}

tree_digest() {
  (
    cd "$1"
    find . -printf '%y %m %P\n' | LC_ALL=C sort
    find . -type f -exec sha256sum -- {} + | LC_ALL=C sort
  ) | sha256sum | awk '{print $1}'
}

run_provisioner() {
  env \
    PATH="$CASE_ROOT/shims:$PATH" \
    DISK_ARCANA_PROVISION_TESTING=1 \
    DISK_ARCANA_PROVISION_TEST_ROOT="$FAKE_ROOT" \
    DISK_TEST_HOSTNAME="$EXPECTED_HOST" \
    "$@" \
    bash -c 'set +e; "$@"; rc=$?; :; exit "$rc"' _ \
    "$PROVISIONER" --bundle "$BUNDLE" --authorization "$AUTH" >"$OUTPUT" 2>&1
}

make_runner_bundle() {
  RUNNER_BUNDLE="$IMPORT_ROOT/bundle-$RANDOM"
  make_bundle "$RUNNER_BUNDLE"
}

run_broker() {
  local caller="${1:-$RUNNER_USER}"
  local bundle="${2:-$RUNNER_BUNDLE}"
  local commit="${3:-$EXPECTED_COMMIT}"
  local host="${4:-$EXPECTED_HOST}"
  env \
    PATH="$CASE_ROOT/shims:$PATH" \
    DISK_ARCANA_BROKER_TESTING=1 \
    DISK_ARCANA_BROKER_TEST_ROOT="$FAKE_ROOT" \
    DISK_ARCANA_BROKER_TEST_CALLER="$caller" \
    DISK_ARCANA_BROKER_TEST_HELPER_LOG="$HELPER_LOG" \
    DISK_TEST_HOSTNAME="$EXPECTED_HOST" \
    "$FAKE_ROOT/usr/local/sbin/disk-arcana-deploy-broker" \
      --deploy "$bundle" "$commit" "$host" >"$OUTPUT" 2>&1
}

assert_not_provisioned() {
  [[ ! -e "$FAKE_ROOT/usr/local/libexec/disk-arcana/deploy-server.sh" ]] ||
    fail "failed provision precheck installed helper"
  [[ ! -e "$FAKE_ROOT/usr/local/sbin/disk-arcana-deploy-broker" ]] ||
    fail "failed provision precheck installed broker"
  [[ ! -e "$FAKE_ROOT/etc/sudoers.d/disk-arcana-deploy" ]] ||
    fail "failed provision precheck installed sudoers"
}

[[ -x "$HELPER" ]] || fail "deploy helper is missing: $HELPER"
[[ -x "$BROKER" ]] || fail "deploy broker is missing: $BROKER"
[[ -x "$PROVISIONER" ]] || fail "broker provisioner is missing: $PROVISIONER"
[[ -f "$SUDOERS_SOURCE" ]] || fail "sudoers policy is missing: $SUDOERS_SOURCE"

setup_case provision
if ! run_provisioner; then
  sed -n '1,80p' "$OUTPUT" >&2
  fail "valid one-shot provisioning returned non-zero"
fi
[[ "$(stat -c '%a' "$FAKE_ROOT/usr/local/libexec/disk-arcana/deploy-server.sh")" == 755 ]] || fail "installed helper mode is not 0755"
[[ "$(stat -c '%a' "$FAKE_ROOT/usr/local/sbin/disk-arcana-deploy-broker")" == 755 ]] || fail "installed broker mode is not 0755"
[[ "$(stat -c '%a' "$FAKE_ROOT/etc/sudoers.d/disk-arcana-deploy")" == 440 ]] || fail "installed sudoers mode is not 0440"
[[ "$(stat -c '%a' "$FAKE_ROOT/etc/disk-arcana/deploy.conf")" == 600 ]] || fail "installed config mode is not 0600"
[[ "$(stat -c '%a' "$FAKE_ROOT/var/lib/disk-arcana/deploy-inbox")" == 700 ]] || fail "inbox mode is not 0700"
[[ -f "$FAKE_ROOT/var/lib/disk-arcana/deploy-transactions/test-group-exists" ]] || fail "deploy group was not reconciled"
[[ -f "$FAKE_ROOT/var/lib/disk-arcana/deploy-transactions/test-member-exists" ]] || fail "runner membership was not reconciled"
grep -qF 'state=COMMITTED' "$OUTPUT" || fail "provisioner did not report COMMITTED"
[[ ! -e "$BOOTSTRAP" ]] || fail "bootstrap authority path survived provisioning"
pass "one-shot provision installs exact restricted broker boundary and revokes bootstrap path"

installed_helper_sha="$(sha "$FAKE_ROOT/usr/local/libexec/disk-arcana/deploy-server.sh")"
install -d -m 0755 "$BOOTSTRAP"
make_bundle "$BUNDLE"
write_authorization "$AUTH" "$BUNDLE" "$(( $(date +%s) + 600 ))" 'nonceprovision0123456789abcdef'
if run_provisioner; then
  fail "consumed bootstrap nonce was replayed"
fi
[[ "$(sha "$FAKE_ROOT/usr/local/libexec/disk-arcana/deploy-server.sh")" == "$installed_helper_sha" ]] ||
  fail "nonce replay changed installed generation"
pass "consumed bootstrap authorization cannot be replayed"

make_runner_bundle
if ! run_broker; then
  sed -n '1,80p' "$OUTPUT" >&2
  fail "valid broker import returned non-zero"
fi
grep -qF -- "--bundle $FAKE_ROOT/var/lib/disk-arcana/deploy-inbox/" "$HELPER_LOG" ||
  fail "broker did not invoke installed helper on root-owned inbox"
grep -qF -- "--expected-commit $EXPECTED_COMMIT" "$HELPER_LOG" || fail "broker dropped expected commit"
grep -qF -- "--expected-hostname $EXPECTED_HOST" "$HELPER_LOG" || fail "broker dropped expected hostname"
pass "broker imports validated bundle and invokes only installed helper"

inbox_count="$(find "$FAKE_ROOT/var/lib/disk-arcana/deploy-inbox" -mindepth 1 -maxdepth 1 -type d | wc -l)"
if run_broker wrong-user; then
  fail "wrong broker caller was accepted"
fi
[[ "$(find "$FAKE_ROOT/var/lib/disk-arcana/deploy-inbox" -mindepth 1 -maxdepth 1 -type d | wc -l)" == "$inbox_count" ]] ||
  fail "wrong caller mutated inbox"
pass "wrong caller fails before inbox mutation"

outside="$CASE_ROOT/outside-bundle"
make_bundle "$outside"
if run_broker "$RUNNER_USER" "$outside"; then
  fail "bundle outside canonical runner temp was accepted"
fi
pass "bundle outside canonical runner temp fails before inbox mutation"

make_runner_bundle
printf '# mismatch\n' >>"$RUNNER_BUNDLE/deploy-server.sh"
rm -f "$RUNNER_BUNDLE/manifest.sha256"
"$VALIDATOR" create --root "$RUNNER_BUNDLE" --commit "$EXPECTED_COMMIT" >/dev/null
if run_broker; then
  fail "bundle helper hash mismatch was accepted"
fi
pass "bundle helper must match installed reviewed helper"

make_runner_bundle
if run_broker "$RUNNER_USER" "$RUNNER_BUNDLE" "$EXPECTED_COMMIT" wrong.example.internal; then
  fail "unexpected destination hostname was accepted"
fi
pass "unexpected destination fails before inbox mutation"

make_runner_bundle
sed -i 's/^User=disk-arcana$/User=root/' "$RUNNER_BUNDLE/disk-arcana-server.service"
rm -f "$RUNNER_BUNDLE/manifest.sha256"
"$VALIDATOR" create --root "$RUNNER_BUNDLE" --commit "$EXPECTED_COMMIT" >/dev/null
inbox_count="$(find "$FAKE_ROOT/var/lib/disk-arcana/deploy-inbox" -mindepth 1 -maxdepth 1 -type d | wc -l)"
if run_broker; then
  fail "weakened unit identity was accepted by broker"
fi
[[ "$(find "$FAKE_ROOT/var/lib/disk-arcana/deploy-inbox" -mindepth 1 -maxdepth 1 -type d | wc -l)" == "$inbox_count" ]] ||
  fail "weakened unit mutated root inbox"
pass "weakened unit contract fails before root inbox mutation"

setup_case rollback-existing
printf 'old helper\n' >"$FAKE_ROOT/usr/local/libexec/disk-arcana/deploy-server.sh"
printf 'old broker\n' >"$FAKE_ROOT/usr/local/sbin/disk-arcana-deploy-broker"
printf 'old sudoers\n' >"$FAKE_ROOT/etc/sudoers.d/disk-arcana-deploy"
printf 'old config\n' >"$FAKE_ROOT/etc/disk-arcana/deploy.conf"
chmod 0755 "$FAKE_ROOT/usr/local/libexec/disk-arcana/deploy-server.sh" \
  "$FAKE_ROOT/usr/local/sbin/disk-arcana-deploy-broker"
chmod 0440 "$FAKE_ROOT/etc/sudoers.d/disk-arcana-deploy"
chmod 0600 "$FAKE_ROOT/etc/disk-arcana/deploy.conf"
old_helper_sha="$(sha "$FAKE_ROOT/usr/local/libexec/disk-arcana/deploy-server.sh")"
old_broker_sha="$(sha "$FAKE_ROOT/usr/local/sbin/disk-arcana-deploy-broker")"
old_sudoers_sha="$(sha "$FAKE_ROOT/etc/sudoers.d/disk-arcana-deploy")"
old_config_sha="$(sha "$FAKE_ROOT/etc/disk-arcana/deploy.conf")"
if run_provisioner DISK_ARCANA_PROVISION_TEST_FAIL_AT=NARROW_RULE_VERIFIED; then
  fail "injected post-install provision failure returned success"
fi
[[ "$(sha "$FAKE_ROOT/usr/local/libexec/disk-arcana/deploy-server.sh")" == "$old_helper_sha" ]] || fail "rollback changed prior helper"
[[ "$(sha "$FAKE_ROOT/usr/local/sbin/disk-arcana-deploy-broker")" == "$old_broker_sha" ]] || fail "rollback changed prior broker"
[[ "$(sha "$FAKE_ROOT/etc/sudoers.d/disk-arcana-deploy")" == "$old_sudoers_sha" ]] || fail "rollback changed prior sudoers"
[[ "$(sha "$FAKE_ROOT/etc/disk-arcana/deploy.conf")" == "$old_config_sha" ]] || fail "rollback changed prior config"
grep -RqsF 'state=FAILED_RECOVERED' "$FAKE_ROOT/var/lib/disk-arcana/deploy-transactions" ||
  fail "provision rollback did not leave a durable recovered record"
[[ ! -e "$FAKE_ROOT/var/lib/disk-arcana/deploy-transactions/test-group-exists" ]] || fail "rollback retained created deploy group"
[[ ! -e "$FAKE_ROOT/var/lib/disk-arcana/deploy-transactions/test-member-exists" ]] || fail "rollback retained added runner membership"
pass "post-backup failure restores the exact prior broker generation"

for state in AUTHORITY_ISSUED BACKUP_WRITTEN INSTALLED NARROW_RULE_VERIFIED; do
  setup_case "crash-$state"
  if run_provisioner DISK_ARCANA_PROVISION_TEST_KILL_AFTER_STATE="$state"; then
    fail "SIGKILL injection after $state returned success"
  fi
  if run_provisioner; then
    fail "recovery reused authority after $state crash"
  fi
  assert_not_provisioned
  [[ ! -e "$BOOTSTRAP" ]] || fail "recovery retained bootstrap authority after $state"
  grep -RqsF 'state=FAILED_RECOVERED' "$FAKE_ROOT/var/lib/disk-arcana/deploy-transactions" ||
    fail "recovery after $state did not persist FAILED_RECOVERED"
  pass "fresh invocation restores prior generation and revokes authority after $state crash"
done

for state in BOOTSTRAP_REVOKED COMMITTED; do
  setup_case "crash-$state"
  if run_provisioner DISK_ARCANA_PROVISION_TEST_KILL_AFTER_STATE="$state"; then
    fail "SIGKILL injection after $state returned success"
  fi
  [[ ! -e "$BOOTSTRAP" ]] || fail "bootstrap was not revoked before $state crash"
  if run_provisioner; then
    fail "invocation with revoked bootstrap unexpectedly returned success"
  fi
  grep -RqsF 'state=COMMITTED' "$FAKE_ROOT/var/lib/disk-arcana/deploy-transactions" ||
    fail "next invocation did not roll forward $state to COMMITTED"
  pass "next invocation rolls forward a crash after $state"
done

setup_case expired
write_authorization "$AUTH" "$BUNDLE" "$(( $(date +%s) - 1 ))" 'expirednonce0123456789abcdef'
before_invalid="$(tree_digest "$FAKE_ROOT")"
if run_provisioner; then
  fail "expired authorization was accepted"
fi
assert_not_provisioned
[[ "$(tree_digest "$FAKE_ROOT")" == "$before_invalid" ]] || fail "expired authorization mutated fake root"
pass "expired bootstrap authorization fails before mutation"

setup_case broad-sudo
printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$RUNNER_USER" >"$FAKE_ROOT/etc/sudoers.d/broad-runner"
chmod 0440 "$FAKE_ROOT/etc/sudoers.d/broad-runner"
before_invalid="$(tree_digest "$FAKE_ROOT")"
if run_provisioner; then
  fail "broader passwordless sudo rule was accepted"
fi
assert_not_provisioned
[[ "$(tree_digest "$FAKE_ROOT")" == "$before_invalid" ]] || fail "broad-sudo rejection mutated fake root"
pass "broader passwordless sudo blocks provisioning"

printf 'All deploy-broker checks passed (%d cases)\n' "$TESTS"
