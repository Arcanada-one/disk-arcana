#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SUITE="$REPO_ROOT/deploy/linux/tests/test-stage-runner-provisioning.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/systemd"
cp "$REPO_ROOT/deploy/linux/systemd/disk-arcana-stage-vm.service.in" \
  "$TMP/systemd/disk-arcana-stage-vm.service.in"

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

bundle_mutant="$TMP/provision-stage-runner-bundle-mutant.sh"
sed '/actual_guest_bundle_sha.*guest_bundle_sha.*die 66/c true' \
  "$REPO_ROOT/deploy/linux/provision-stage-runner-host.sh" >"$bundle_mutant"
chmod 0755 "$bundle_mutant"
cmp -s "$bundle_mutant" "$REPO_ROOT/deploy/linux/provision-stage-runner-host.sh" &&
  fail 'guest bundle digest mutant was not applied'
require_killed_mutant 'guest bundle digest' \
  'unauthenticated cloud-init mutation is rejected before host mutation status=0 expected=66' \
  env HOST_PROVISION_OVERRIDE="$bundle_mutant" bash "$SUITE"

provision_commit_mutant="$TMP/provision-stage-runner-commit-mutant.sh"
sed 's/^write_phase COMMITTED$/# durable commit phase removed/' \
  "$REPO_ROOT/deploy/linux/provision-stage-runner-host.sh" >"$provision_commit_mutant"
chmod 0755 "$provision_commit_mutant"
cmp -s "$provision_commit_mutant" "$REPO_ROOT/deploy/linux/provision-stage-runner-host.sh" &&
  fail 'host provisioning commit mutant was not applied'
require_killed_mutant 'host provisioning commit' \
  'host provisioner did not commit durable state' \
  env HOST_PROVISION_OVERRIDE="$provision_commit_mutant" bash "$SUITE"

unit_mutant="$TMP/disk-arcana-stage-vm.service.in"
sed '/^PrivateTmp=yes$/a PrivateDevices=yes' \
  "$REPO_ROOT/deploy/linux/systemd/disk-arcana-stage-vm.service.in" >"$unit_mutant"
cmp -s "$unit_mutant" "$REPO_ROOT/deploy/linux/systemd/disk-arcana-stage-vm.service.in" &&
  fail 'KVM visibility mutant was not applied'
require_killed_mutant 'KVM device visibility' \
  'host unit hides /dev/kvm behind PrivateDevices=yes' \
  env UNIT_TEMPLATE_OVERRIDE="$unit_mutant" bash "$SUITE"

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

recovery_mutant="$TMP/bootstrap-stage-runner-recovery-mutant.sh"
# shellcheck disable=SC2016 # The sed program matches literal shell variables.
sed 's/^  if \[\[ "$journal_phase" != RUNNER_REVOKED && -n "$recovered_runner_id" \]\]; then$/  if false; then # API revocation removed/' \
  "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" >"$recovery_mutant"
chmod 0755 "$recovery_mutant"
cmp -s "$recovery_mutant" "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" &&
  fail 'bootstrap recovery mutant was not applied'
require_killed_mutant 'bootstrap crash recovery' \
  'bootstrap recovery did not execute fresh-authority API revocation' \
  env GUEST_BOOTSTRAP_OVERRIDE="$recovery_mutant" bash "$SUITE"

recovery_terminal_mutant="$TMP/bootstrap-stage-runner-terminal-mutant.sh"
sed '0,/^    write_phase RECOVERED$/s//    : # terminal recovery journal removed/' \
  "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" >"$recovery_terminal_mutant"
chmod 0755 "$recovery_terminal_mutant"
cmp -s "$recovery_terminal_mutant" "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" &&
  fail 'bootstrap terminal ordering mutant was not applied'
require_killed_mutant 'bootstrap terminal ordering' \
  'recovery interruption occurred before terminal journal durability' \
  env GUEST_BOOTSTRAP_OVERRIDE="$recovery_terminal_mutant" bash "$SUITE"

bootstrap_privileged_mutant="$TMP/bootstrap-stage-runner-privileged-mutant.sh"
# shellcheck disable=SC2016 # The sed program matches a literal shell variable.
sed 's|^bash "$bundle/install\.sh" \\|true \\|' \
  "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" >"$bootstrap_privileged_mutant"
chmod 0755 "$bootstrap_privileged_mutant"
cmp -s "$bootstrap_privileged_mutant" "$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh" &&
  fail 'privileged bootstrap mutant was not applied'
require_killed_mutant 'privileged bootstrap path' \
  'full bootstrap did not execute bundle-install' \
  env GUEST_BOOTSTRAP_OVERRIDE="$bootstrap_privileged_mutant" bash "$SUITE"

bind_mutant="$TMP/bind-stage-runner-identity.sh"
sed '/api_id.*requested_runner_id.*api_name.*runner_name/c true ||' \
  "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" >"$bind_mutant"
chmod 0755 "$bind_mutant"
cmp -s "$bind_mutant" "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" &&
  fail 'identity binding mutant was not applied'
require_killed_mutant 'identity binding' 'identity binding rejects wrong runner ID before mutation status=0 expected=66' \
  env BIND_IDENTITY_OVERRIDE="$bind_mutant" bash "$SUITE"

bind_boundary_mutant="$TMP/bind-stage-runner-boundary-mutant.sh"
sed "/^\[\[ \"\$api_status\" == online/,/GitHub runner boundary mismatch/c\true" \
  "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" >"$bind_boundary_mutant"
chmod 0755 "$bind_boundary_mutant"
cmp -s "$bind_boundary_mutant" "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" &&
  fail 'identity boundary mutant was not applied'
require_killed_mutant 'identity boundary' \
  'identity binding rejects offline busy wrong-label wrong-group runner status=0 expected=66' \
  env BIND_IDENTITY_OVERRIDE="$bind_boundary_mutant" bash "$SUITE"

bind_labels_mutant="$TMP/bind-stage-runner-labels-mutant.sh"
# shellcheck disable=SC2016 # The sed program matches a literal shell variable.
sed 's/"$api_labels_exact" == true/true == true/' \
  "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" >"$bind_labels_mutant"
chmod 0755 "$bind_labels_mutant"
cmp -s "$bind_labels_mutant" "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" &&
  fail 'identity labels mutant was not applied'
require_killed_mutant 'exact runner labels' \
  'identity binding rejects a runner without the exact workflow label set status=0 expected=66' \
  env BIND_IDENTITY_OVERRIDE="$bind_labels_mutant" bash "$SUITE"

bind_group_mutant="$TMP/bind-stage-runner-group-mutant.sh"
# shellcheck disable=SC2016 # The sed program matches literal shell variables.
sed 's/"$group_total_count" == 1 && "$group_returned_count" == 1 &&/true == true \&\&/' \
  "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" >"$bind_group_mutant"
chmod 0755 "$bind_group_mutant"
cmp -s "$bind_group_mutant" "$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh" &&
  fail 'identity singleton-group mutant was not applied'
require_killed_mutant 'singleton runner group' \
  'identity binding rejects a group containing a foreign runner status=0 expected=66' \
  env BIND_IDENTITY_OVERRIDE="$bind_group_mutant" bash "$SUITE"

teardown_mutant="$TMP/teardown-stage-runner-host.sh"
sed '/api_id.*runner_id.*api_name.*runner_name/c true ||' \
  "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" >"$teardown_mutant"
chmod 0755 "$teardown_mutant"
cmp -s "$teardown_mutant" "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" &&
  fail 'teardown identity mutant was not applied'
require_killed_mutant 'teardown identity' 'teardown rejects wrong runner ID before mutation status=0 expected=66' \
  env HOST_TEARDOWN_OVERRIDE="$teardown_mutant" bash "$SUITE"

teardown_resume_mutant="$TMP/teardown-stage-runner-resume-mutant.sh"
sed 's/^  write_phase UNIT_REMOVE_INTENT$/  : # unit-removal intent removed/' \
  "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" >"$teardown_resume_mutant"
chmod 0755 "$teardown_resume_mutant"
cmp -s "$teardown_resume_mutant" "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" &&
  fail 'teardown crash-resume mutant was not applied'
require_killed_mutant 'teardown crash resume' \
  'teardown did not persist unit-removal intent before deletion' \
  env HOST_TEARDOWN_OVERRIDE="$teardown_resume_mutant" bash "$SUITE"

teardown_delete_mutant="$TMP/teardown-stage-runner-delete-mutant.sh"
# shellcheck disable=SC2016 # The sed program matches a literal shell variable.
sed 's/^  if \[\[ "$api_status" == 200 \]\]; then$/  if false; then # runner API deletion removed/' \
  "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" >"$teardown_delete_mutant"
chmod 0755 "$teardown_delete_mutant"
cmp -s "$teardown_delete_mutant" "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" &&
  fail 'teardown runner deletion mutant was not applied'
require_killed_mutant 'teardown runner deletion' \
  'teardown did not call the exact runner deletion endpoint' \
  env HOST_TEARDOWN_OVERRIDE="$teardown_delete_mutant" bash "$SUITE"

teardown_unregistered_mutant="$TMP/teardown-stage-runner-unregistered-mutant.sh"
# shellcheck disable=SC2016 # The sed program matches a literal shell variable.
sed 's/^\[\[ "$runner_id" == UNREGISTERED || "$runner_id" =~ /[[ "$runner_id" =~ /' \
  "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" >"$teardown_unregistered_mutant"
chmod 0755 "$teardown_unregistered_mutant"
cmp -s "$teardown_unregistered_mutant" "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" &&
  fail 'teardown unregistered-host mutant was not applied'
require_killed_mutant 'unregistered host teardown' \
  'unregistered teardown rejects an identically named runner outside group 8 status=65 expected=66' \
  env HOST_TEARDOWN_OVERRIDE="$teardown_unregistered_mutant" bash "$SUITE"

teardown_preinstall_mutant="$TMP/teardown-stage-runner-preinstall-mutant.sh"
sed 's/^    preinstall_recovery=true$/    die 65 '\''preinstall recovery disabled'\''/' \
  "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" >"$teardown_preinstall_mutant"
chmod 0755 "$teardown_preinstall_mutant"
cmp -s "$teardown_preinstall_mutant" "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" &&
  fail 'teardown preinstall recovery mutant was not applied'
require_killed_mutant 'pre-unit-install host recovery' \
  'teardown recovers a host crash after state install but before unit install status=65 expected=0' \
  env HOST_TEARDOWN_OVERRIDE="$teardown_preinstall_mutant" bash "$SUITE"

teardown_symlink_mutant="$TMP/teardown-stage-runner-symlink-mutant.sh"
# shellcheck disable=SC2016 # The sed programs match literal shell variables.
sed -e '/assert_no_symlink_components "$diagnostics_root"/c\  true ||' \
  -e '/^  if \[\[ -e "$diagnostics_root" \]\]; then$/,/^  fi$/c\  : # preflight diagnostics metadata check removed' \
  -e '/^\[\[ -d "$diagnostics_root" && ! -L/,/die 65 '\''diagnostics root has unsafe metadata'\''/c\true' \
  "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" >"$teardown_symlink_mutant"
chmod 0755 "$teardown_symlink_mutant"
cmp -s "$teardown_symlink_mutant" "$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh" &&
  fail 'teardown diagnostics symlink mutant was not applied'
require_killed_mutant 'teardown diagnostics symlink' \
  'teardown rejects a diagnostics-root symlink before moving state status=0 expected=65' \
  env HOST_TEARDOWN_OVERRIDE="$teardown_symlink_mutant" bash "$SUITE"
