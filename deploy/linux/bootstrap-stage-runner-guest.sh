#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

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

bootstrap_root=''
expected_commit=''
expected_hostname=''
validate_only=false

while (($#)); do
  case "$1" in
    --bootstrap-root)
      require_value "$1" "${2:-}"
      bootstrap_root="$2"
      shift 2
      ;;
    --expected-commit)
      require_value "$1" "${2:-}"
      expected_commit="$2"
      shift 2
      ;;
    --expected-hostname)
      require_value "$1" "${2:-}"
      expected_hostname="$2"
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

[[ -n "$bootstrap_root" ]] || die 64 'missing required option: --bootstrap-root'
[[ -n "$expected_commit" ]] || die 64 'missing required option: --expected-commit'
[[ -n "$expected_hostname" ]] || die 64 'missing required option: --expected-hostname'
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || die 65 'expected commit must be 40 lowercase hex characters'
[[ "$expected_hostname" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] ||
  die 65 'expected hostname is invalid'
[[ "$bootstrap_root" == /* && "$bootstrap_root" != / && -d "$bootstrap_root" && ! -L "$bootstrap_root" ]] ||
  die 65 'bootstrap root is unsafe'

test_mode=false
expected_uid=0
expected_gid=0
if [[ "${DISK_ARCANA_STAGE_BOOTSTRAP_TESTING:-}" == 1 ]]; then
  [[ "$(id -u)" != 0 ]] || die 65 'guest bootstrap test mode is forbidden for root'
  [[ "$validate_only" == true ]] || die 65 'guest bootstrap test mode is validation-only'
  test_mode=true
  expected_uid="$(id -u)"
  expected_gid="$(id -g)"
else
  [[ -z "${DISK_ARCANA_STAGE_BOOTSTRAP_TESTING:-}" ]] || die 65 'invalid guest bootstrap test control'
  [[ "$(id -u)" == 0 ]] || die 77 'guest bootstrap requires root'
  [[ "$bootstrap_root" == /var/lib/disk-arcana-deploy/bootstrap/* ]] ||
    die 65 'bootstrap root is not canonical'
fi

assert_no_symlink_components() {
  local path="$1" current='' component
  local -a components=()
  [[ "$path" == /* ]] || return 1
  IFS=/ read -r -a components <<<"${path#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
    current="$current/$component"
    [[ ! -L "$current" ]] || return 1
  done
}

assert_no_symlink_components "$bootstrap_root" || die 65 'bootstrap path has a symlink component'
[[ "$(stat -c '%a:%u:%g' "$bootstrap_root")" == "700:$expected_uid:$expected_gid" ]] ||
  die 65 'bootstrap root has unsafe metadata'

bundle="$bootstrap_root/bundle"
runner_archive="$bootstrap_root/runner.tar.gz"
runner_digest_file="$bootstrap_root/runner.tar.gz.sha256"
registration_file="$bootstrap_root/registration.env"

[[ -d "$bundle" && ! -L "$bundle" && \
   "$(stat -c '%a:%u:%g' "$bundle")" == "700:$expected_uid:$expected_gid" ]] ||
  die 65 'bootstrap bundle has unsafe metadata'
for protected_file in "$runner_archive" "$runner_digest_file" "$registration_file"; do
  [[ -f "$protected_file" && ! -L "$protected_file" && \
     "$(stat -c '%a:%u:%g' "$protected_file")" == "600:$expected_uid:$expected_gid" ]] ||
    if [[ "$protected_file" == "$registration_file" ]]; then
      die 65 'registration file has unsafe metadata'
    else
      die 65 'runner input has unsafe metadata'
    fi
done

runner_digest=''
runner_digest_name=''
runner_digest_extra=''
IFS=' ' read -r runner_digest runner_digest_name runner_digest_extra <"$runner_digest_file" ||
  die 65 'runner digest file is malformed'
[[ -z "$runner_digest_extra" && "$runner_digest" =~ ^[0-9a-f]{64}$ && \
   "$runner_digest_name" == runner.tar.gz ]] || die 65 'runner digest file is malformed'
[[ "$(sha256sum "$runner_archive" | awk '{print $1}')" == "$runner_digest" ]] ||
  die 66 'runner archive digest mismatch'

validator=''
if [[ "$test_mode" == true ]]; then
  validator="${DISK_ARCANA_STAGE_BUNDLE_VALIDATOR:-}"
else
  [[ -z "${DISK_ARCANA_STAGE_BUNDLE_VALIDATOR:-}" ]] ||
    die 65 'bundle validator override is forbidden in production'
  validator="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/validate-deploy-bundle.sh"
fi
[[ -f "$validator" && ! -L "$validator" ]] || die 65 'deployment bundle validator is unavailable'
bash "$validator" verify --root "$bundle" --expected-commit "$expected_commit" >/dev/null ||
  die 66 'deployment bundle validation failed'

registration_token=''
removal_token=''
runner_url=''
runner_group=''
runner_name=''
runner_label=''
authority_run_id=''
registration_consumed=false
runner_configured=false
runner_service=''

cleanup_authority() {
  local status=0
  if [[ "$registration_consumed" != true && -f "$registration_file" && ! -L "$registration_file" ]]; then
    rm -f -- "$registration_file" || status=1
  fi
  if [[ "$runner_configured" == true && -n "$removal_token" && -x /opt/actions-runner/config.sh ]]; then
    if [[ -n "$runner_service" ]]; then
      systemctl stop "$runner_service" >/dev/null 2>&1 || status=1
    fi
    if [[ -x /opt/actions-runner/svc.sh ]]; then
      /opt/actions-runner/svc.sh uninstall >/dev/null 2>&1 || status=1
    fi
    runuser -u disk-stage -- /opt/actions-runner/config.sh remove \
      --unattended --token "$removal_token" >/dev/null 2>&1 || status=1
  fi
  return "$status"
}

on_exit() {
  local status=$?
  trap - EXIT INT TERM
  if ((status != 0)) && [[ "$test_mode" != true ]]; then
    cleanup_authority || printf 'ERROR: guest bootstrap cleanup was incomplete\n' >&2
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

declare -A seen_registration=()
while IFS='=' read -r key value; do
  [[ -n "$key" && -z "${seen_registration[$key]+present}" ]] ||
    die 65 'registration file contains an empty or duplicate key'
  seen_registration["$key"]=1
  case "$key" in
    runner_url) runner_url="$value" ;;
    runner_group) runner_group="$value" ;;
    runner_name) runner_name="$value" ;;
    runner_label) runner_label="$value" ;;
    authority_run_id) authority_run_id="$value" ;;
    registration_token) registration_token="$value" ;;
    removal_token) removal_token="$value" ;;
    *) die 65 'registration file contains an unknown key' ;;
  esac
done <"$registration_file"

[[ "$runner_url" == https://github.com/Arcanada-one ]] || die 65 'runner URL is not authorized'
[[ "$runner_group" == disk-arcana-stage ]] || die 65 'runner group is not authorized'
[[ "$runner_name" == disk-arcana-stage ]] || die 65 'runner name is not authorized'
[[ "$runner_label" == disk-arcana-stage ]] || die 65 'runner label is not authorized'
[[ "$authority_run_id" =~ ^[0-9]{1,20}$ ]] || die 65 'authority run ID is malformed'
[[ "$registration_token" =~ ^[A-Za-z0-9_-]{20,200}$ ]] || die 65 'registration token is malformed'
[[ "$removal_token" =~ ^[A-Za-z0-9_-]{20,200}$ ]] || die 65 'removal token is malformed'

if [[ "$validate_only" == true ]]; then
  registration_consumed=true
  printf 'validation=ok\n'
  exit 0
fi

[[ "$(hostname)" == "$expected_hostname" ]] || die 69 'guest hostname mismatch'
for command_name in apt-get getent groupadd useradd usermod loginctl systemctl runuser tar unshare; do
  command -v "$command_name" >/dev/null 2>&1 || die 69 "required command is unavailable: $command_name"
done
[[ ! -e /opt/actions-runner ]] || die 73 'runner installation already exists'
mapfile -t preexisting_runner_units < <(
  systemctl list-unit-files --type=service 'actions.runner.*' --no-legend --no-pager 2>/dev/null |
    awk '{print $1}'
)
[[ "${#preexisting_runner_units[@]}" -eq 0 ]] || die 73 'runner service already exists'
! id disk-stage >/dev/null 2>&1 || die 73 'runner user already exists'
! getent group disk-arcana-deploy >/dev/null 2>&1 || die 73 'runner group already exists'

rm -f -- "$registration_file"
registration_consumed=true

state_root='/var/lib/disk-arcana-stage-bootstrap'
install -d -o root -g root -m 0700 "$state_root"
state_journal="$state_root/bootstrap-current"
phase='AUTHORITY_CONSUMED'
write_phase() {
  local next="$1" temporary="$state_root/.bootstrap-current.$$"
  printf 'phase=%s\ncommit=%s\nrunner_name=%s\n' \
    "$next" "$expected_commit" "$runner_name" >"$temporary"
  chmod 0600 "$temporary"
  sync -f "$temporary" >/dev/null 2>&1
  mv -f -- "$temporary" "$state_journal"
  sync -f "$state_root" >/dev/null 2>&1
  phase="$next"
}
write_phase "$phase"

apt-get \
  -o Acquire::AllowInsecureRepositories=false \
  -o APT::Get::AllowUnauthenticated=false \
  update
DEBIAN_FRONTEND=noninteractive apt-get \
  -o Acquire::AllowInsecureRepositories=false \
  -o APT::Get::AllowUnauthenticated=false \
  install -y --no-install-recommends \
  ca-certificates curl fuse-overlayfs jq podman slirp4netns sudo uidmap
write_phase PACKAGES_INSTALLED

groupadd --system disk-arcana-deploy
useradd --create-home --shell /bin/bash disk-stage
usermod --append --groups disk-arcana-deploy disk-stage

subid_count() {
  local file="$1"
  awk -F: '$1 == "disk-stage" && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {total += $3}
    END {print total + 0}' "$file"
}
if (( $(subid_count /etc/subuid) < 65536 )); then
  usermod --add-subuids 200000:265535 disk-stage
fi
if (( $(subid_count /etc/subgid) < 65536 )); then
  usermod --add-subgids 200000:265535 disk-stage
fi
(( $(subid_count /etc/subuid) >= 65536 )) || die 69 'subordinate UID allocation failed'
(( $(subid_count /etc/subgid) >= 65536 )) || die 69 'subordinate GID allocation failed'
loginctl enable-linger disk-stage
runner_uid="$(id -u disk-stage)"
systemctl start "user@$runner_uid.service"
write_phase RUNNER_IDENTITY_CREATED

install -d -o disk-stage -g disk-stage -m 0750 /opt/actions-runner
install -o disk-stage -g disk-stage -m 0600 "$runner_archive" /opt/actions-runner/runner.tar.gz
runuser -u disk-stage -- tar -xzf /opt/actions-runner/runner.tar.gz -C /opt/actions-runner
rm -f -- /opt/actions-runner/runner.tar.gz
[[ -x /opt/actions-runner/config.sh && -x /opt/actions-runner/svc.sh ]] ||
  die 69 'runner archive did not install expected entrypoints'
runuser -u disk-stage -- /opt/actions-runner/config.sh \
  --unattended \
  --url "$runner_url" \
  --token "$registration_token" \
  --runnergroup "$runner_group" \
  --name "$runner_name" \
  --labels "$runner_label" \
  --work _work \
  --disableupdate
runner_configured=true
registration_token=''
/opt/actions-runner/svc.sh install disk-stage
mapfile -t installed_runner_units < <(
  systemctl list-unit-files --type=service 'actions.runner.*' --no-legend --no-pager 2>/dev/null |
    awk '{print $1}'
)
[[ "${#installed_runner_units[@]}" -eq 1 ]] || die 69 'runner service count is not exactly one'
runner_service="${installed_runner_units[0]}"
[[ "$runner_service" == actions.runner.*.disk-arcana-stage.service ]] ||
  die 69 'runner service identity is unexpected'
[[ "$(systemctl is-active "$runner_service" 2>/dev/null || true)" != active ]] ||
  die 69 'runner service started before readiness verification'
write_phase RUNNER_CONFIGURED

journal_dir='/var/lib/disk-arcana-install'
install -d -o root -g root -m 0700 "$journal_dir"
bash "$bundle/install.sh" \
  --binary "$bundle/disk-arcana-server" \
  --unit "$bundle/disk-arcana-server.service" \
  --journal-dir "$journal_dir" \
  --expected-hostname "$expected_hostname"
write_phase SERVER_INSTALLED

deployment_id="$(basename "$bootstrap_root")"
[[ "$deployment_id" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || die 65 'bootstrap deployment ID is invalid'
import_root='/var/lib/disk-arcana-deploy/import'
install -d -o root -g root -m 0700 "$import_root"
manifest_sha="$(sha256sum "$bundle/manifest.sha256" | awk '{print $1}')"
nonce="$(tr -d - < /proc/sys/kernel/random/uuid)$(date +%s)"
authorization_file="$bootstrap_root/authorization.env"
{
  printf 'deployment_id=%s\n' "$deployment_id"
  printf 'run_id=%s\n' "$authority_run_id"
  printf 'commit=%s\n' "$expected_commit"
  printf 'manifest_sha=%s\n' "$manifest_sha"
  printf 'hostname=%s\n' "$expected_hostname"
  printf 'nonce=%s\n' "$nonce"
  printf 'expires=%s\n' "$(( $(date +%s) + 900 ))"
  printf 'runner_user=disk-stage\n'
  printf 'runner_group=disk-arcana-deploy\n'
  printf 'import_root=%s\n' "$import_root"
  printf 'bootstrap_root=%s\n' "$bootstrap_root"
} >"$authorization_file"
chmod 0600 "$authorization_file"
bash "$bundle/provision-deploy-broker.sh" \
  --bundle "$bundle" --authorization "$authorization_file"
write_phase BROKER_INSTALLED

[[ "$(systemctl is-active disk-arcana-server.service)" == active ]]
[[ "$(systemctl show disk-arcana-server.service -p UnitFileState --value)" == enabled ]]
[[ "$(systemctl show disk-arcana-server.service -p Restart --value)" == on-failure ]]
[[ "$(systemctl show disk-arcana-server.service -p StartLimitIntervalUSec --value)" == 2min ]]
[[ "$(systemctl show disk-arcana-server.service -p StartLimitBurst --value)" == 5 ]]
curl --fail --silent --show-error --max-time 10 -o /dev/null \
  http://127.0.0.1:9446/health
command -v podman >/dev/null
runuser -u disk-stage -- unshare --user --map-root-user true
runuser -u disk-stage -- podman info --format '{{.Host.Security.Rootless}}' |
  grep -Fx true >/dev/null
[[ "$(loginctl show-user "$runner_uid" -p Linger --value)" == yes ]]
runuser -u disk-stage -- env \
  XDG_RUNTIME_DIR="/run/user/$runner_uid" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$runner_uid/bus" \
  systemctl --user show-environment >/dev/null
runuser -u disk-stage -- test ! -w /var/run/docker.sock

mapfile -t sudo_specs < <(
  runuser -u disk-stage -- sudo -n -l 2>/dev/null |
    awk '
      / may run the following commands on .*:$/ {in_specs=1; next}
      !in_specs {next}
      {
        spec=$0
        sub(/^[[:space:]]+/, "", spec)
        sub(/[[:space:]]+$/, "", spec)
        if (spec !~ /^\([^)]*\)([[:space:]]|$)/) next
        gsub(/[[:space:]]+/, " ", spec)
        gsub(/\([[:space:]]+/, "(", spec)
        gsub(/[[:space:]]+\)/, ")", spec)
        sub(/[[:space:]]*:[[:space:]]*/, ": ", spec)
        print spec
      }'
)
[[ "${#sudo_specs[@]}" -eq 1 && \
   "${sudo_specs[0]}" == '(root) NOPASSWD: /usr/local/sbin/disk-arcana-deploy-broker --deploy *' ]] ||
  die 69 'effective sudo policy is not broker-only'

systemctl start "$runner_service"
[[ "$(systemctl is-enabled "$runner_service")" == enabled ]]
[[ "$(systemctl is-active "$runner_service")" == active ]]
write_phase COMMITTED
runner_configured=false
removal_token=''
printf 'bootstrap=ok commit=%s runner_service=%s\n' "$expected_commit" "$runner_service"
