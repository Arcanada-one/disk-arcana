#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HOST_PROVISION="${HOST_PROVISION_OVERRIDE:-$REPO_ROOT/deploy/linux/provision-stage-runner-host.sh}"
GUEST_BOOTSTRAP="${GUEST_BOOTSTRAP_OVERRIDE:-$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh}"
HOST_TEARDOWN="${HOST_TEARDOWN_OVERRIDE:-$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh}"
BIND_IDENTITY="${BIND_IDENTITY_OVERRIDE:-$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh}"
DEPLOY_BUNDLE_VALIDATOR="$REPO_ROOT/deploy/linux/validate-deploy-bundle.sh"
export DISK_ARCANA_STAGE_BUNDLE_VALIDATOR="$DEPLOY_BUNDLE_VALIDATOR"

fail() {
  printf 'FAIL  %s\n' "$*" >&2
  exit 1
}

for required in \
  deploy/linux/provision-stage-runner-host.sh \
  deploy/linux/bootstrap-stage-runner-guest.sh \
  deploy/linux/bind-stage-runner-identity.sh \
  deploy/linux/teardown-stage-runner-host.sh \
  deploy/linux/systemd/disk-arcana-stage-vm.service.in; do
  [[ -f "$REPO_ROOT/$required" ]] || fail "missing $required"
done

printf 'PASS  stage runner provisioning artefacts exist\n'

run_expect() {
  local expected_status="$1" expected_marker="$2" label="$3"
  shift 3
  local output status

  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_status" ]]; then
    fail "$label status=$status expected=$expected_status output=$output"
  fi
  if [[ "$output" != *"$expected_marker"* ]]; then
    printf 'HARNESS_INVALID  %s missing marker=%s output=%s\n' \
      "$label" "$expected_marker" "$output" >&2
    exit 2
  fi
  printf 'PASS  %s\n' "$label"
}

run_expect 0 'control=positive' 'positive harness control' \
  bash -c 'printf "control=positive\n"'
run_expect 7 'control=negative' 'negative harness control' \
  bash -c 'printf "control=negative\n" >&2; exit 7'

fixture_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "$fixture_root"
}
trap cleanup EXIT

printf 'cloud image\n' >"$fixture_root/cloud.img"
printf 'runner archive\n' >"$fixture_root/runner.tar.gz"
mkdir "$fixture_root/bundle"
printf '#cloud-config\n' >"$fixture_root/bundle/user-data"
printf 'instance-id: disk-arcana-stage-test\nlocal-hostname: disk-arcana-stage\n' \
  >"$fixture_root/bundle/meta-data"
cloud_sha="$(sha256sum "$fixture_root/cloud.img" | awk '{print $1}')"
runner_sha="$(sha256sum "$fixture_root/runner.tar.gz" | awk '{print $1}')"
valid_root="/var/lib/disk-arcana-stage/test-${$}"

base_args=(
  --state-root "$valid_root"
  --cloud-image "$fixture_root/cloud.img"
  --cloud-image-sha256 "$cloud_sha"
  --guest-bundle "$fixture_root/bundle"
  --runner-archive "$fixture_root/runner.tar.gz"
  --runner-archive-sha256 "$runner_sha"
  --management-port 22446
  --validate-only
)

run_expect 64 'missing required option: --state-root' \
  'missing state root is rejected' \
  bash "$HOST_PROVISION" --validate-only

invalid_root_args=("${base_args[@]}")
invalid_root_args[1]='relative/state'
run_expect 65 'state root must be absolute' \
  'relative state root is rejected' \
  bash "$HOST_PROVISION" "${invalid_root_args[@]}"

invalid_digest_args=("${base_args[@]}")
invalid_digest_args[5]='not-a-digest'
run_expect 65 'cloud image SHA-256 must be 64 lowercase hex characters' \
  'malformed cloud digest is rejected' \
  bash "$HOST_PROVISION" "${invalid_digest_args[@]}"

mismatch_args=("${base_args[@]}")
mismatch_args[5]="$(printf '0%.0s' {1..64})"
run_expect 66 'cloud image digest mismatch' \
  'wrong cloud digest is rejected before mutation' \
  bash "$HOST_PROVISION" "${mismatch_args[@]}"
[[ ! -e "$valid_root" ]] || fail 'wrong digest created guest state'

runner_mismatch_args=("${base_args[@]}")
runner_mismatch_args[11]="$(printf '0%.0s' {1..64})"
run_expect 66 'runner archive digest mismatch' \
  'wrong runner digest is rejected before mutation' \
  bash "$HOST_PROVISION" "${runner_mismatch_args[@]}"
[[ ! -e "$valid_root" ]] || fail 'wrong runner digest created guest state'

traversal_args=("${base_args[@]}")
traversal_args[1]='/var/lib/disk-arcana-stage/guest/../foreign'
run_expect 65 'state root must not contain parent traversal' \
  'state root traversal is rejected' \
  bash "$HOST_PROVISION" "${traversal_args[@]}"

port_args=("${base_args[@]}")
port_args[13]='22'
run_expect 65 'management port must be between 1024 and 65535' \
  'privileged management port is rejected' \
  bash "$HOST_PROVISION" "${port_args[@]}"

ln -s "$fixture_root/cloud.img" "$fixture_root/cloud-link.img"
cloud_link_args=("${base_args[@]}")
cloud_link_args[3]="$fixture_root/cloud-link.img"
run_expect 65 'cloud image must be a regular non-symlink file' \
  'symlink cloud image is rejected' \
  bash "$HOST_PROVISION" "${cloud_link_args[@]}"

ln -s "$fixture_root/runner.tar.gz" "$fixture_root/runner-link.tar.gz"
runner_link_args=("${base_args[@]}")
runner_link_args[9]="$fixture_root/runner-link.tar.gz"
run_expect 65 'runner archive must be a regular non-symlink file' \
  'symlink runner archive is rejected' \
  bash "$HOST_PROVISION" "${runner_link_args[@]}"

ln -s "$fixture_root/bundle" "$fixture_root/bundle-link"
bundle_link_args=("${base_args[@]}")
bundle_link_args[7]="$fixture_root/bundle-link"
run_expect 65 'guest bundle must be a directory and not a symlink' \
  'symlink guest bundle is rejected' \
  bash "$HOST_PROVISION" "${bundle_link_args[@]}"

printf 'unexpected\n' >"$fixture_root/bundle/extra"
run_expect 65 'guest bundle inventory must be exactly user-data and meta-data' \
  'unexpected cloud-init bundle member is rejected' \
  bash "$HOST_PROVISION" "${base_args[@]}"
rm -f "$fixture_root/bundle/extra"

run_expect 0 'validation=ok' 'valid immutable inputs pass validation' \
  bash "$HOST_PROVISION" "${base_args[@]}"

unit_template="$REPO_ROOT/deploy/linux/systemd/disk-arcana-stage-vm.service.in"
for required_unit_text in \
  'ExecStart=/usr/bin/qemu-system-x86_64' \
  '-enable-kvm' \
  'file=@STATE_ROOT@/disk.qcow2' \
  'file=@STATE_ROOT@/seed.img' \
  'hostfwd=tcp:127.0.0.1:@MANAGEMENT_PORT@-:22' \
  '-no-reboot' \
  'NoNewPrivileges=yes' \
  'PrivateTmp=yes' \
  'ProtectSystem=strict' \
  'ReadWritePaths=@STATE_ROOT@'; do
  grep -F -- "$required_unit_text" "$unit_template" >/dev/null ||
    fail "host unit is missing $required_unit_text"
done
if grep -Ei -- '(docker\.sock|9p|virtfs|filesystem)' "$unit_template" >/dev/null; then
  fail 'host unit exposes a forbidden host filesystem or Docker seam'
fi
printf 'PASS  host unit is KVM-only with loopback management and no host mounts\n'

for directive in StartLimitIntervalSec StartLimitBurst; do
  directive_section="$(
    awk -v wanted="$directive" '
      /^\[[^]]+\]$/ {section=$0}
      $0 ~ "^" wanted "=" {print section}
    ' "$unit_template"
  )"
  [[ "$directive_section" == '[Unit]' ]] ||
    fail "$directive must occur exactly once under [Unit]"
done
printf 'PASS  host VM restart limits are placed under [Unit]\n'

bind_root="$fixture_root/bind/guest"
install -d -m 0700 "$fixture_root/bind"
install -d -m 0700 "$bind_root"
{
  printf 'guest_name=disk-arcana-stage\n'
  printf 'state_root=%s\n' "$bind_root"
  printf 'host_unit=disk-arcana-stage-vm.service\n'
  printf 'management_port=22446\n'
  printf 'cloud_image_sha256=%s\n' "$cloud_sha"
  printf 'runner_archive_sha256=%s\n' "$runner_sha"
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_id=UNREGISTERED\n'
} >"$bind_root/state.manifest"
chmod 0600 "$bind_root/state.manifest"
printf 'github-api-token-1234567890\n' >"$fixture_root/bind/token"
chmod 0600 "$fixture_root/bind/token"
printf '{"id":987654,"name":"disk-arcana-stage"}\n' \
  >"$fixture_root/bind/api-response.json"
run_expect 0 'validation=ok runner_id=987654 runner_name=disk-arcana-stage' \
  'identity binding validates the exact live runner before mutation' \
  env DISK_ARCANA_STAGE_BIND_TESTING=1 \
    DISK_ARCANA_STAGE_BIND_API_RESPONSE="$fixture_root/bind/api-response.json" \
    bash "$BIND_IDENTITY" \
      --state-root "$bind_root" \
      --runner-id 987654 \
      --github-token-file "$fixture_root/bind/token" \
      --validate-only
grep -Fx 'runner_id=UNREGISTERED' "$bind_root/state.manifest" >/dev/null ||
  fail 'identity validation mutated the unregistered manifest'
printf 'PASS  identity validation leaves the unregistered manifest unchanged\n'
bind_manifest_before="$(sha256sum "$bind_root/state.manifest" | awk '{print $1}')"
printf '{"id":987655,"name":"disk-arcana-stage"}\n' \
  >"$fixture_root/bind/api-response-wrong-id.json"
run_expect 66 'GitHub runner identity mismatch' \
  'identity binding rejects wrong runner ID before mutation' \
  env DISK_ARCANA_STAGE_BIND_TESTING=1 \
    DISK_ARCANA_STAGE_BIND_API_RESPONSE="$fixture_root/bind/api-response-wrong-id.json" \
    bash "$BIND_IDENTITY" \
      --state-root "$bind_root" \
      --runner-id 987654 \
      --github-token-file "$fixture_root/bind/token" \
      --validate-only
[[ "$(sha256sum "$bind_root/state.manifest" | awk '{print $1}')" == "$bind_manifest_before" ]] ||
  fail 'wrong live runner ID changed the host manifest'
printf 'PASS  identity mismatch leaves the host manifest byte-identical\n'

bootstrap_root="$fixture_root/bootstrap"
install -d -m 0700 "$bootstrap_root"
install -d -m 0700 "$bootstrap_root/bundle"
printf 'bootstrap server\n' >"$bootstrap_root/bundle/disk-arcana-server"
chmod 0755 "$bootstrap_root/bundle/disk-arcana-server"
install -m 0644 "$REPO_ROOT/deploy/linux/disk-arcana-server.service" \
  "$bootstrap_root/bundle/disk-arcana-server.service"
for executable in deploy-server.sh deploy-server-broker.sh install.sh \
  provision-deploy-broker.sh; do
  install -m 0755 "$REPO_ROOT/deploy/linux/$executable" \
    "$bootstrap_root/bundle/$executable"
done
install -m 0440 "$REPO_ROOT/deploy/linux/disk-arcana-deploy.sudoers" \
  "$bootstrap_root/bundle/disk-arcana-deploy.sudoers"
expected_commit='1111111111111111111111111111111111111111'
printf '%s\n' "$expected_commit" >"$bootstrap_root/bundle/commit"
bash "$DEPLOY_BUNDLE_VALIDATOR" create \
  --root "$bootstrap_root/bundle" --commit "$expected_commit" >/dev/null
install -m 0600 "$fixture_root/runner.tar.gz" "$bootstrap_root/runner.tar.gz"
bootstrap_runner_sha="$(sha256sum "$bootstrap_root/runner.tar.gz" | awk '{print $1}')"
printf '%s  runner.tar.gz\n' "$bootstrap_runner_sha" \
  >"$bootstrap_root/runner.tar.gz.sha256"
chmod 0600 "$bootstrap_root/runner.tar.gz.sha256"
registration_token='registration-token-1234567890'
removal_token='removal-token-123456789012345'
{
  printf 'runner_url=https://github.com/Arcanada-one\n'
  printf 'runner_group=disk-arcana-stage\n'
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_label=disk-arcana-stage\n'
  printf 'authority_run_id=31444643689\n'
  printf 'registration_token=%s\n' "$registration_token"
  printf 'removal_token=%s\n' "$removal_token"
} >"$bootstrap_root/registration.env"
chmod 0600 "$bootstrap_root/registration.env"

guest_base_args=(
  --bootstrap-root "$bootstrap_root"
  --expected-commit "$expected_commit"
  --expected-hostname disk-arcana-stage
  --validate-only
)

run_expect 64 'missing required option: --bootstrap-root' \
  'guest bootstrap requires a protected root' \
  env DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 bash "$GUEST_BOOTSTRAP" --validate-only

run_expect 0 'validation=ok' \
  'guest bootstrap accepts exact protected immutable inputs' \
  env DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 bash "$GUEST_BOOTSTRAP" \
    "${guest_base_args[@]}"

registration_arm_line="$(
  grep -nF 'runner_registration_attempted=true' "$GUEST_BOOTSTRAP" | cut -d: -f1 || true
)"
registration_call_line="$(
  grep -nF 'runuser -u disk-stage -- /opt/actions-runner/config.sh' "$GUEST_BOOTSTRAP" |
    tail -n 1 | cut -d: -f1
)"
[[ "$registration_arm_line" =~ ^[0-9]+$ && "$registration_call_line" =~ ^[0-9]+$ &&
   "$registration_arm_line" -lt "$registration_call_line" ]] ||
  fail 'runner cleanup is not armed before the registration side effect'
grep -F 'runner_registration_attempted" == true' "$GUEST_BOOTSTRAP" >/dev/null ||
  fail 'runner cleanup does not consume the pre-registration arm'
printf 'PASS  runner cleanup is armed before registration can partially succeed\n'

teardown_root="$fixture_root/teardown/guest"
install -d -m 0700 "$fixture_root/teardown"
install -d -m 0700 "$teardown_root"
runner_id=987654
{
  printf 'guest_name=disk-arcana-stage\n'
  printf 'state_root=%s\n' "$teardown_root"
  printf 'host_unit=disk-arcana-stage-vm.service\n'
  printf 'management_port=22446\n'
  printf 'cloud_image_sha256=%s\n' "$cloud_sha"
  printf 'runner_archive_sha256=%s\n' "$runner_sha"
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_id=%s\n' "$runner_id"
} >"$teardown_root/state.manifest"
chmod 0600 "$teardown_root/state.manifest"
printf 'github-api-token-1234567890\n' >"$fixture_root/teardown/token"
chmod 0600 "$fixture_root/teardown/token"
printf '{"id":%s,"name":"disk-arcana-stage"}\n' "$runner_id" \
  >"$fixture_root/teardown/api-response.json"

teardown_args=(
  --state-root "$teardown_root"
  --github-token-file "$fixture_root/teardown/token"
  --validate-only
)
run_expect 0 'validation=ok runner_id=987654 runner_name=disk-arcana-stage' \
  'teardown accepts exact manifest and live runner identity' \
  env DISK_ARCANA_STAGE_TEARDOWN_TESTING=1 \
    DISK_ARCANA_STAGE_TEARDOWN_API_RESPONSE="$fixture_root/teardown/api-response.json" \
    bash "$HOST_TEARDOWN" "${teardown_args[@]}"

teardown_before="$(
  find "$fixture_root/teardown" -type f -printf '%P %m ' -exec sha256sum {} \; |
    LC_ALL=C sort | sha256sum | awk '{print $1}'
)"
printf '{"id":987655,"name":"disk-arcana-stage"}\n' \
  >"$fixture_root/teardown/api-response-wrong-id.json"
run_expect 66 'GitHub runner identity mismatch' \
  'teardown rejects wrong runner ID before mutation' \
  env DISK_ARCANA_STAGE_TEARDOWN_TESTING=1 \
    DISK_ARCANA_STAGE_TEARDOWN_API_RESPONSE="$fixture_root/teardown/api-response-wrong-id.json" \
    bash "$HOST_TEARDOWN" "${teardown_args[@]}"
rm -f "$fixture_root/teardown/api-response-wrong-id.json"
teardown_after="$(
  find "$fixture_root/teardown" -type f -printf '%P %m ' -exec sha256sum {} \; |
    LC_ALL=C sort | sha256sum | awk '{print $1}'
)"
[[ "$teardown_before" == "$teardown_after" ]] ||
  fail 'wrong runner ID changed teardown state'
printf 'PASS  teardown identity mismatch leaves protected state byte-identical\n'

validation_output="$(
  DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 bash "$GUEST_BOOTSTRAP" \
    "${guest_base_args[@]}"
)"
[[ "$validation_output" != *"$registration_token"* && \
   "$validation_output" != *"$removal_token"* ]] ||
  fail 'guest validation exposed registration material'
printf 'PASS  guest validation does not expose registration material\n'

chmod 0644 "$bootstrap_root/registration.env"
run_expect 65 'registration file has unsafe metadata' \
  'world-readable registration material is rejected' \
  env DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 bash "$GUEST_BOOTSTRAP" \
    "${guest_base_args[@]}"
chmod 0600 "$bootstrap_root/registration.env"

printf '%s  runner.tar.gz\n' "$(printf '0%.0s' {1..64})" \
  >"$bootstrap_root/runner.tar.gz.sha256"
run_expect 66 'runner archive digest mismatch' \
  'guest bootstrap rejects runner digest mismatch before mutation' \
  env DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 bash "$GUEST_BOOTSTRAP" \
    "${guest_base_args[@]}"
