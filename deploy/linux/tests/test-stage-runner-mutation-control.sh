#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SUITE="$REPO_ROOT/deploy/linux/tests/test-stage-runner-provisioning.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

fail() {
  printf 'FAIL  %s\n' "$*" >&2
  exit 1
}

require_killed_mutant() {
  local label="$1" expected_marker="$2"
  shift 2
  local output status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || fail "$label mutant survived"
  [[ "$output" == *"$expected_marker"* ]] ||
    fail "$label mutant failed for the wrong reason: $output"
  printf 'PASS  %s mutant is killed by the behavioral suite\n' "$label"
}

host_mutant="$TMP/provision-stage-runner-host.sh"
sed '/actual_cloud_sha.*cloud_sha.*die 66/c true' \
  "$REPO_ROOT/deploy/linux/provision-stage-runner-host.sh" >"$host_mutant"
chmod 0755 "$host_mutant"
cmp -s "$host_mutant" "$REPO_ROOT/deploy/linux/provision-stage-runner-host.sh" &&
  fail 'host digest mutant was not applied'
require_killed_mutant 'cloud digest' 'wrong cloud digest is rejected before mutation status=0 expected=66' \
  env HOST_PROVISION_OVERRIDE="$host_mutant" bash "$SUITE"

guest_mutant="$TMP/bootstrap-stage-runner-guest.sh"
sed '/sha256sum.*runner_archive.*runner_digest/c true ||' \
  "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" >"$guest_mutant"
chmod 0755 "$guest_mutant"
cmp -s "$guest_mutant" "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" &&
  fail 'guest digest mutant was not applied'
require_killed_mutant 'guest runner digest' 'guest bootstrap rejects runner digest mismatch before mutation status=0 expected=66' \
  env GUEST_BOOTSTRAP_OVERRIDE="$guest_mutant" bash "$SUITE"

registration_mutant="$TMP/bootstrap-stage-runner-registration-mutant.sh"
sed 's/^runner_registration_attempted=true$/# registration cleanup arm removed/' \
  "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" >"$registration_mutant"
chmod 0755 "$registration_mutant"
cmp -s "$registration_mutant" "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" &&
  fail 'registration cleanup mutant was not applied'
require_killed_mutant 'registration cleanup arm' 'runner cleanup is not armed before the registration side effect' \
  env GUEST_BOOTSTRAP_OVERRIDE="$registration_mutant" bash "$SUITE"

bind_mutant="$TMP/bind-stage-runner-identity.sh"
sed '/api_id.*requested_runner_id.*api_name.*runner_name/c true ||' \
  "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" >"$bind_mutant"
chmod 0755 "$bind_mutant"
cmp -s "$bind_mutant" "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" &&
  fail 'identity binding mutant was not applied'
require_killed_mutant 'identity binding' 'identity binding rejects wrong runner ID before mutation status=0 expected=66' \
  env BIND_IDENTITY_OVERRIDE="$bind_mutant" bash "$SUITE"

teardown_mutant="$TMP/teardown-stage-runner-host.sh"
sed '/api_id.*runner_id.*api_name.*runner_name/c true ||' \
  "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" >"$teardown_mutant"
chmod 0755 "$teardown_mutant"
cmp -s "$teardown_mutant" "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" &&
  fail 'teardown identity mutant was not applied'
require_killed_mutant 'teardown identity' 'teardown rejects wrong runner ID before mutation status=0 expected=66' \
  env HOST_TEARDOWN_OVERRIDE="$teardown_mutant" bash "$SUITE"
