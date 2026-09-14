#!/usr/bin/env bash
set -euo pipefail

die() {
  local status="$1"
  shift
  printf 'ERROR: %s\n' "$*" >&2
  exit "$status"
}

require_value() {
  local option="$1" value="${2:-}"
  [[ -n "$value" && "$value" != --* ]] || die 64 "$option requires a value"
}

state_root=''
cloud_image=''
cloud_sha=''
guest_bundle=''
guest_bundle_sha=''
runner_archive=''
runner_sha=''
management_port=''
validate_only=false

while (($#)); do
  case "$1" in
    --state-root)
      require_value "$1" "${2:-}"
      state_root="$2"
      shift 2
      ;;
    --cloud-image)
      require_value "$1" "${2:-}"
      cloud_image="$2"
      shift 2
      ;;
    --cloud-image-sha256)
      require_value "$1" "${2:-}"
      cloud_sha="$2"
      shift 2
      ;;
    --guest-bundle)
      require_value "$1" "${2:-}"
      guest_bundle="$2"
      shift 2
      ;;
    --guest-bundle-sha256)
      require_value "$1" "${2:-}"
      guest_bundle_sha="$2"
      shift 2
      ;;
    --runner-archive)
      require_value "$1" "${2:-}"
      runner_archive="$2"
      shift 2
      ;;
    --runner-archive-sha256)
      require_value "$1" "${2:-}"
      runner_sha="$2"
      shift 2
      ;;
    --management-port)
      require_value "$1" "${2:-}"
      management_port="$2"
      shift 2
      ;;
    --validate-only)
      validate_only=true
      shift
      ;;
    *)
      die 64 "unknown option: $1"
      ;;
  esac
done

[[ -n "$state_root" ]] || die 64 'missing required option: --state-root'
[[ -n "$cloud_image" ]] || die 64 'missing required option: --cloud-image'
[[ -n "$cloud_sha" ]] || die 64 'missing required option: --cloud-image-sha256'
[[ -n "$guest_bundle" ]] || die 64 'missing required option: --guest-bundle'
[[ -n "$guest_bundle_sha" ]] || die 64 'missing required option: --guest-bundle-sha256'
[[ -n "$runner_archive" ]] || die 64 'missing required option: --runner-archive'
[[ -n "$runner_sha" ]] || die 64 'missing required option: --runner-archive-sha256'
[[ -n "$management_port" ]] || die 64 'missing required option: --management-port'

test_mode=false
expected_uid=0
expected_gid=0
state_parent='/var/lib/disk-arcana-stage'
unit_name='disk-arcana-stage-vm.service'
unit_path="/etc/systemd/system/$unit_name"
kvm_path='/dev/kvm'
if [[ "${DISK_ARCANA_STAGE_PROVISION_TESTING:-}" == 1 ]]; then
  [[ "$(id -u)" != 0 ]] || die 65 'host provisioning test mode is forbidden for root'
  [[ -n "${DISK_ARCANA_STAGE_PROVISION_STATE_PARENT:-}" &&
     -n "${DISK_ARCANA_STAGE_PROVISION_UNIT_PATH:-}" &&
     -n "${DISK_ARCANA_STAGE_PROVISION_KVM_PATH:-}" ]] ||
    die 65 'host provisioning test mode requires isolated paths'
  test_mode=true
  expected_uid="$(id -u)"
  expected_gid="$(id -g)"
  state_parent="$DISK_ARCANA_STAGE_PROVISION_STATE_PARENT"
  unit_path="$DISK_ARCANA_STAGE_PROVISION_UNIT_PATH"
  kvm_path="$DISK_ARCANA_STAGE_PROVISION_KVM_PATH"
else
  [[ -z "${DISK_ARCANA_STAGE_PROVISION_TESTING:-}" &&
     -z "${DISK_ARCANA_STAGE_PROVISION_STATE_PARENT:-}" &&
     -z "${DISK_ARCANA_STAGE_PROVISION_UNIT_PATH:-}" &&
     -z "${DISK_ARCANA_STAGE_PROVISION_KVM_PATH:-}" ]] ||
    die 65 'host provisioning test controls are forbidden in production'
fi

[[ "$state_root" == /* ]] || die 65 'state root must be absolute'
[[ "$state_root" != *'/../'* && "$state_root" != */.. ]] ||
  die 65 'state root must not contain parent traversal'
[[ "$(dirname "$state_root")" == "$state_parent" ]] ||
  die 65 'state root must be an immediate child of the state parent'
[[ ! -L "$state_root" ]] || die 65 'state root must not be a symlink'

sha_pattern='^[0-9a-f]{64}$'
[[ "$cloud_sha" =~ $sha_pattern ]] ||
  die 65 'cloud image SHA-256 must be 64 lowercase hex characters'
[[ "$runner_sha" =~ $sha_pattern ]] ||
  die 65 'runner archive SHA-256 must be 64 lowercase hex characters'
[[ "$guest_bundle_sha" =~ $sha_pattern ]] ||
  die 65 'guest bundle SHA-256 must be 64 lowercase hex characters'
[[ -f "$cloud_image" && ! -L "$cloud_image" ]] ||
  die 65 'cloud image must be a regular non-symlink file'
[[ -f "$runner_archive" && ! -L "$runner_archive" ]] ||
  die 65 'runner archive must be a regular non-symlink file'
[[ -d "$guest_bundle" && ! -L "$guest_bundle" ]] ||
  die 65 'guest bundle must be a directory and not a symlink'
mapfile -d '' -t guest_bundle_inventory < <(
  find "$guest_bundle" -mindepth 1 -maxdepth 1 -print0
)
[[ "${#guest_bundle_inventory[@]}" -eq 2 ]] ||
  die 65 'guest bundle inventory must be exactly user-data and meta-data'
if find "$guest_bundle" -mindepth 1 \( -type l -o \( ! -type f ! -type d \) \) \
    -print -quit | grep -q .; then
  die 65 'guest bundle must contain only regular files and directories'
fi
for seed_input in user-data meta-data; do
  [[ -f "$guest_bundle/$seed_input" && ! -L "$guest_bundle/$seed_input" ]] ||
    die 65 "guest bundle is missing regular $seed_input"
done
bundle_user_data_sha="$(sha256sum "$guest_bundle/user-data" | awk '{print $1}')"
bundle_meta_data_sha="$(sha256sum "$guest_bundle/meta-data" | awk '{print $1}')"
actual_guest_bundle_sha="$({
  printf '%s  user-data\n' "$bundle_user_data_sha"
  printf '%s  meta-data\n' "$bundle_meta_data_sha"
} | sha256sum | awk '{print $1}')"
[[ "$actual_guest_bundle_sha" == "$guest_bundle_sha" ]] || die 66 'guest bundle digest mismatch'
[[ "$management_port" =~ ^[0-9]+$ ]] || die 65 'management port must be numeric'
((management_port >= 1024 && management_port <= 65535)) ||
  die 65 'management port must be between 1024 and 65535'

actual_cloud_sha="$(sha256sum "$cloud_image" | awk '{print $1}')"
[[ "$actual_cloud_sha" == "$cloud_sha" ]] || die 66 'cloud image digest mismatch'
actual_runner_sha="$(sha256sum "$runner_archive" | awk '{print $1}')"
[[ "$actual_runner_sha" == "$runner_sha" ]] || die 66 'runner archive digest mismatch'

if [[ "$validate_only" == true ]]; then
  printf 'validation=ok\n'
  exit 0
fi

if [[ "$test_mode" != true ]]; then
  [[ "$(id -u)" == 0 ]] || die 77 'host provisioning requires root'
  [[ -c "$kvm_path" ]] || die 69 '/dev/kvm is unavailable'
else
  [[ -e "$kvm_path" && ! -L "$kvm_path" ]] || die 69 'test KVM marker is unavailable'
fi

unit_template="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/systemd/$unit_name.in"
readonly unit_template

[[ "$(basename "$state_root")" =~ ^[a-z0-9][a-z0-9.-]*$ ]] ||
  die 65 'state root basename contains unsafe characters'
[[ ! -e "$state_root" ]] || die 73 'state root already exists'
[[ ! -e "$unit_path" && ! -L "$unit_path" ]] || die 73 'host unit already exists'
[[ -f "$unit_template" && ! -L "$unit_template" ]] || die 69 'host unit template is unavailable'

for command_name in cloud-localds qemu-img qemu-system-x86_64 ss systemctl systemd-analyze; do
  command -v "$command_name" >/dev/null 2>&1 || die 69 "required command is unavailable: $command_name"
done

[[ ! -e "$state_parent" || -d "$state_parent" ]] || die 73 'state parent is not a directory'
[[ ! -L "$state_parent" ]] || die 73 'state parent must not be a symlink'
if [[ -e "$state_parent" ]]; then
  [[ "$(stat -c '%u:%g:%a' "$state_parent")" == "$expected_uid:$expected_gid:700" ]] ||
    die 73 'state parent ownership or mode is unsafe'
else
  if [[ "$test_mode" == true ]]; then
    install -d -m 0700 "$state_parent" || die 73 'could not create state parent'
  else
    install -d -o root -g root -m 0700 "$state_parent" || die 73 'could not create state parent'
  fi
fi
[[ "$(stat -c '%u:%g:%a' "$state_parent")" == "$expected_uid:$expected_gid:700" ]] ||
  die 73 'state parent ownership or mode is unsafe'

if ss -H -ltn "sport = :$management_port" 2>/dev/null | grep -q .; then
  die 73 'management port is already listening'
fi

staging_root="$(mktemp -d "$state_parent/.stage.XXXXXX")" ||
  die 73 'could not create private staging directory'
chmod 0700 "$staging_root" || die 73 'could not secure private staging directory'
state_installed=false
unit_installed=false
committed=false

write_phase() {
  local phase="$1" temporary="$staging_root/.phase.tmp"
  printf 'phase=%s\n' "$phase" >"$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$staging_root/phase"
}

rollback() {
  local rollback_status=0
  if [[ "$unit_installed" == true ]]; then
    systemctl disable --now "$unit_name" >/dev/null 2>&1 || rollback_status=1
    rm -f -- "$unit_path" || rollback_status=1
    systemctl daemon-reload >/dev/null 2>&1 || rollback_status=1
  fi
  if [[ "$state_installed" == true && -d "$state_root" && ! -L "$state_root" ]]; then
    rm -rf --one-file-system -- "$state_root" || rollback_status=1
  elif [[ -d "$staging_root" && ! -L "$staging_root" ]]; then
    rm -rf --one-file-system -- "$staging_root" || rollback_status=1
  fi
  return "$rollback_status"
}

on_exit() {
  local status=$?
  trap - EXIT INT TERM
  if ((status != 0)) && [[ "$committed" != true ]]; then
    rollback || printf 'ERROR: rollback was incomplete\n' >&2
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

write_phase INPUTS_VERIFIED

install -m 0600 "$cloud_image" "$staging_root/source.qcow2"
[[ "$(sha256sum "$staging_root/source.qcow2" | awk '{print $1}')" == "$cloud_sha" ]] ||
  die 66 'copied cloud image digest mismatch'
install -d -m 0700 "$staging_root/bundle"
cp -a -- "$guest_bundle/." "$staging_root/bundle/"
[[ -f "$staging_root/bundle/user-data" && ! -L "$staging_root/bundle/user-data" &&
   -f "$staging_root/bundle/meta-data" && ! -L "$staging_root/bundle/meta-data" ]] ||
  die 66 'copied guest bundle metadata is unsafe'
copied_guest_bundle_sha="$({
  sha256sum "$staging_root/bundle/user-data" | awk '{print $1 "  user-data"}'
  sha256sum "$staging_root/bundle/meta-data" | awk '{print $1 "  meta-data"}'
} | sha256sum | awk '{print $1}')"
[[ "$copied_guest_bundle_sha" == "$guest_bundle_sha" ]] ||
  die 66 'copied guest bundle digest mismatch'
install -m 0600 "$runner_archive" "$staging_root/runner.tar.gz"
[[ "$(sha256sum "$staging_root/runner.tar.gz" | awk '{print $1}')" == "$runner_sha" ]] ||
  die 66 'copied runner archive digest mismatch'
printf '%s  runner.tar.gz\n' "$runner_sha" >"$staging_root/runner.tar.gz.sha256"
chmod 0600 "$staging_root/runner.tar.gz.sha256"
write_phase INPUTS_COPIED

cloud_format="$(
  LC_ALL=C qemu-img info --force-share "$staging_root/source.qcow2" |
    awk -F': ' '$1 == "file format" {print $2}'
)"
[[ "$cloud_format" == qcow2 ]] || die 66 'cloud image format is not qcow2'
qemu-img convert -f qcow2 -O qcow2 "$staging_root/source.qcow2" "$staging_root/disk.qcow2"
qemu-img resize "$staging_root/disk.qcow2" 64G >/dev/null
rm -f -- "$staging_root/source.qcow2"
cloud-localds "$staging_root/seed.img" \
  "$staging_root/bundle/user-data" "$staging_root/bundle/meta-data"
chmod 0600 "$staging_root/disk.qcow2" "$staging_root/seed.img"
write_phase GUEST_MEDIA_CREATED

sed \
  -e "s|@STATE_ROOT@|$state_root|g" \
  -e "s|@MANAGEMENT_PORT@|$management_port|g" \
  "$unit_template" >"$staging_root/$unit_name"
chmod 0600 "$staging_root/$unit_name"
! grep -Eq '@(STATE_ROOT|MANAGEMENT_PORT)@' "$staging_root/$unit_name" ||
  die 69 'rendered unit retains a placeholder'
systemd-analyze verify "$staging_root/$unit_name" >/dev/null
write_phase UNIT_VALIDATED

cat >"$staging_root/state.manifest" <<EOF
guest_name=disk-arcana-stage
state_root=$state_root
host_unit=$unit_name
management_port=$management_port
cloud_image_sha256=$cloud_sha
guest_bundle_sha256=$guest_bundle_sha
runner_archive_sha256=$runner_sha
runner_name=disk-arcana-stage
runner_id=UNREGISTERED
EOF
chmod 0600 "$staging_root/state.manifest"
write_phase READY_TO_INSTALL

mv -- "$staging_root" "$state_root"
staging_root="$state_root"
state_installed=true
if [[ "$test_mode" == true ]]; then
  install -m 0644 "$state_root/$unit_name" "$unit_path"
else
  install -o root -g root -m 0644 "$state_root/$unit_name" "$unit_path"
fi
unit_installed=true
systemctl daemon-reload
systemctl enable --now "$unit_name"
[[ "$(systemctl is-enabled "$unit_name")" == enabled ]]
[[ "$(systemctl is-active "$unit_name")" == active ]]
write_phase COMMITTED
committed=true
printf 'provisioning=ok state_root=%s unit=%s management_port=%s\n' \
  "$state_root" "$unit_name" "$management_port"
