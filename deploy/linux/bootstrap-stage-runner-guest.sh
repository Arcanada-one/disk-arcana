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
github_token_file=''
validate_only=false
recover_only=false

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
    --github-token-file)
      require_value "$1" "${2:-}"
      github_token_file="$2"
      shift 2
      ;;
    --validate-only)
      validate_only=true
      shift
      ;;
    --recover-only)
      recover_only=true
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
[[ "$validate_only" != true || "$recover_only" != true ]] ||
  die 64 '--validate-only and --recover-only are mutually exclusive'
[[ "$recover_only" != true || -n "$github_token_file" ]] ||
  die 64 '--recover-only requires --github-token-file'
[[ "$recover_only" == true || -z "$github_token_file" ]] ||
  die 64 '--github-token-file is valid only with --recover-only'
[[ "$bootstrap_root" == /* && "$bootstrap_root" != / && -d "$bootstrap_root" && ! -L "$bootstrap_root" ]] ||
  die 65 'bootstrap root is unsafe'

test_mode=false
expected_uid=0
expected_gid=0
if [[ "${DISK_ARCANA_STAGE_BOOTSTRAP_TESTING:-}" == 1 ]]; then
  [[ "$(id -u)" != 0 ]] || die 65 'guest bootstrap test mode is forbidden for root'
  if [[ "$recover_only" == true ]]; then
    [[ -n "${DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT:-}" &&
       -n "${DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT:-}" ]] ||
      die 65 'guest bootstrap recovery test mode requires isolated roots'
  elif [[ "$validate_only" != true ]]; then
    [[ "${DISK_ARCANA_STAGE_BOOTSTRAP_FULL_TESTING:-}" == 1 &&
       -n "${DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT:-}" &&
       -n "${DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT:-}" &&
       -n "${DISK_ARCANA_STAGE_BOOTSTRAP_JOURNAL_ROOT:-}" &&
       -n "${DISK_ARCANA_STAGE_BOOTSTRAP_IMPORT_ROOT:-}" &&
       -n "${DISK_ARCANA_STAGE_BOOTSTRAP_SUBUID_FILE:-}" &&
       -n "${DISK_ARCANA_STAGE_BOOTSTRAP_SUBGID_FILE:-}" &&
       -n "${DISK_ARCANA_STAGE_BOOTSTRAP_DOCKER_SOCKET:-}" ]] ||
      die 65 'guest bootstrap full test mode requires isolated roots'
  fi
  test_mode=true
  expected_uid="$(id -u)"
  expected_gid="$(id -g)"
else
  [[ -z "${DISK_ARCANA_STAGE_BOOTSTRAP_TESTING:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_FULL_TESTING:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_JOURNAL_ROOT:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_IMPORT_ROOT:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_SUBUID_FILE:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_SUBGID_FILE:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_DOCKER_SOCKET:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_FAIL_AFTER_REGISTRATION:-}" &&
     -z "${DISK_ARCANA_STAGE_BOOTSTRAP_FAIL_AFTER_RECOVERED:-}" ]] ||
    die 65 'invalid guest bootstrap test control'
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

state_root="${DISK_ARCANA_STAGE_BOOTSTRAP_STATE_ROOT:-/var/lib/disk-arcana-stage-bootstrap}"
runner_install_root="${DISK_ARCANA_STAGE_BOOTSTRAP_RUNNER_ROOT:-/opt/actions-runner}"
journal_root="${DISK_ARCANA_STAGE_BOOTSTRAP_JOURNAL_ROOT:-/var/lib/disk-arcana-install}"
import_root="${DISK_ARCANA_STAGE_BOOTSTRAP_IMPORT_ROOT:-/var/lib/disk-arcana-deploy/import}"
subuid_file="${DISK_ARCANA_STAGE_BOOTSTRAP_SUBUID_FILE:-/etc/subuid}"
subgid_file="${DISK_ARCANA_STAGE_BOOTSTRAP_SUBGID_FILE:-/etc/subgid}"
docker_socket="${DISK_ARCANA_STAGE_BOOTSTRAP_DOCKER_SOCKET:-/var/run/docker.sock}"
state_journal="$state_root/bootstrap-current"
recovery_file="$state_root/recovery.env"

if [[ "$recover_only" == true ]]; then
  [[ "$github_token_file" == /* && -f "$github_token_file" && ! -L "$github_token_file" ]] ||
    die 65 'GitHub token file is unsafe'
  assert_no_symlink_components "$github_token_file" ||
    die 65 'GitHub token path has a symlink component'
  [[ "$(stat -c '%a:%u:%g' "$github_token_file")" == "600:$expected_uid:$expected_gid" ]] ||
    die 65 'GitHub token file has unsafe metadata'
fi

write_phase() {
  local next="$1" temporary="$state_root/.bootstrap-current.$$"
  printf 'phase=%s\ncommit=%s\nrunner_name=%s\n' \
    "$next" "$expected_commit" "${runner_name:-disk-arcana-stage}" >"$temporary"
  chmod 0600 "$temporary"
  sync -f "$temporary" >/dev/null 2>&1
  mv -f -- "$temporary" "$state_journal"
  sync -f "$state_root" >/dev/null 2>&1
}

if [[ "$recover_only" == true ]]; then
  [[ -d "$state_root" && ! -L "$state_root" &&
     "$(stat -c '%a:%u:%g' "$state_root")" == "700:$expected_uid:$expected_gid" ]] ||
    die 65 'bootstrap recovery state root has unsafe metadata'
  [[ -f "$state_journal" && ! -L "$state_journal" &&
     "$(stat -c '%a:%u:%g' "$state_journal")" == "600:$expected_uid:$expected_gid" ]] ||
    die 65 'bootstrap recovery journal has unsafe metadata'

  journal_phase=''
  journal_commit=''
  journal_runner_name=''
  declare -A recovery_journal_seen=()
  while IFS='=' read -r key value; do
    [[ -n "$key" && -z "${recovery_journal_seen[$key]+present}" ]] ||
      die 65 'bootstrap recovery journal is malformed'
    recovery_journal_seen["$key"]=1
    case "$key" in
      phase) journal_phase="$value" ;;
      commit) journal_commit="$value" ;;
      runner_name) journal_runner_name="$value" ;;
      *) die 65 'bootstrap recovery journal is malformed' ;;
    esac
  done <"$state_journal"
  [[ "${#recovery_journal_seen[@]}" -eq 3 && "$journal_commit" == "$expected_commit" &&
     "$journal_runner_name" == disk-arcana-stage ]] ||
    die 65 'bootstrap recovery journal identity mismatch'

  cleanup_recovery_inputs() {
    local protected_path
    for protected_path in "$bootstrap_root/registration.env" "$recovery_file"; do
      if [[ -e "$protected_path" || -L "$protected_path" ]]; then
        [[ -f "$protected_path" && ! -L "$protected_path" &&
           "$(stat -c '%a:%u:%g' "$protected_path")" == "600:$expected_uid:$expected_gid" ]] ||
          die 65 'terminal bootstrap authority has unsafe metadata'
        rm -f -- "$protected_path"
      fi
    done
    sync -f "$state_root" >/dev/null 2>&1
  }

  if [[ "$journal_phase" == COMMITTED || "$journal_phase" == RECOVERED ]]; then
    if [[ -e "$recovery_file" || -L "$recovery_file" ]]; then
      [[ -f "$recovery_file" && ! -L "$recovery_file" &&
         "$(stat -c '%a:%u:%g' "$recovery_file")" == "600:$expected_uid:$expected_gid" ]] ||
        die 65 'committed bootstrap recovery authority has unsafe metadata'
    fi
    cleanup_recovery_inputs
    if [[ "$journal_phase" == COMMITTED ]]; then
      printf 'recovery=already-committed runner_name=%s\n' "$journal_runner_name"
    else
      printf 'recovery=already-recovered runner_name=%s\n' "$journal_runner_name"
    fi
    exit 0
  fi
  case "$journal_phase" in
    AUTHORITY_STAGED|AUTHORITY_CONSUMED|PACKAGES_INSTALLED|RUNNER_IDENTITY_CREATED|REGISTRATION_INTENT|RUNNER_REGISTERED|RUNNER_CONFIGURED|SERVER_INSTALLED|BROKER_INSTALLED|RUNNER_REVOCATION_INTENT|RUNNER_REVOKED)
      ;;
    *) die 65 'bootstrap recovery journal phase is not recoverable' ;;
  esac
  [[ -f "$recovery_file" && ! -L "$recovery_file" &&
     "$(stat -c '%a:%u:%g' "$recovery_file")" == "600:$expected_uid:$expected_gid" ]] ||
    die 65 'bootstrap recovery authority has unsafe metadata'

  runner_url=''
  runner_group=''
  runner_name=''
  runner_label=''
  authority_run_id=''
  declare -A recovery_authority_seen=()
  while IFS='=' read -r key value; do
    [[ -n "$key" && -z "${recovery_authority_seen[$key]+present}" ]] ||
      die 65 'bootstrap recovery authority is malformed'
    recovery_authority_seen["$key"]=1
    case "$key" in
      runner_url) runner_url="$value" ;;
      runner_group) runner_group="$value" ;;
      runner_name) runner_name="$value" ;;
      runner_label) runner_label="$value" ;;
      authority_run_id) authority_run_id="$value" ;;
      *) die 65 'bootstrap recovery authority is malformed' ;;
    esac
  done <"$recovery_file"
  [[ "${#recovery_authority_seen[@]}" -eq 5 &&
     "$runner_url" == https://github.com/Arcanada-one &&
     "$runner_group" == disk-arcana-stage && "$runner_name" == disk-arcana-stage &&
     "$runner_label" == disk-arcana-stage &&
     "$authority_run_id" =~ ^[0-9]{1,20}$ ]] ||
    die 65 'bootstrap recovery authority identity mismatch'
  if [[ "$journal_phase" == AUTHORITY_STAGED || "$journal_phase" == AUTHORITY_CONSUMED ||
        "$journal_phase" == PACKAGES_INSTALLED || "$journal_phase" == RUNNER_IDENTITY_CREATED ]]; then
    write_phase RECOVERED
    if [[ "$test_mode" == true && "${DISK_ARCANA_STAGE_BOOTSTRAP_FAIL_AFTER_RECOVERED:-}" == 1 ]]; then
      die 99 'injected interruption after terminal recovery journal'
    fi
    cleanup_recovery_inputs
    printf 'recovery=ok runner_name=%s prior_phase=%s\n' "$runner_name" "$journal_phase"
    exit 0
  fi
  [[ -d "$runner_install_root" && ! -L "$runner_install_root" ]] ||
    die 65 'bootstrap recovery runner installation is unavailable'
  command -v curl >/dev/null 2>&1 || die 69 'curl is unavailable'
  command -v jq >/dev/null 2>&1 || die 69 'jq is unavailable'
  github_token="$(<"$github_token_file")"
  [[ "$github_token" =~ ^[^[:space:]]{20,500}$ ]] || die 65 'GitHub token is malformed'

  group_response="$(
    curl --fail --silent --show-error --max-time 20 \
      -H "Authorization: Bearer $github_token" \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' \
      'https://api.github.com/orgs/Arcanada-one/actions/runner-groups/8/runners?per_page=100'
  )" || die 69 'GitHub runner group recovery readback failed'
  org_response="$(
    curl --fail --silent --show-error --max-time 20 \
      -H "Authorization: Bearer $github_token" \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' \
      'https://api.github.com/orgs/Arcanada-one/actions/runners?per_page=100'
  )" || die 69 'GitHub organization runner recovery readback failed'
  group_total_count="$(jq -er '.total_count | select(type == "number")' \
    <<<"$group_response")" || die 66 'GitHub runner group recovery readback is malformed'
  group_returned_count="$(jq -er 'if (.runners | type) == "array" then (.runners | length) else error("runners") end' \
    <<<"$group_response")" || die 66 'GitHub runner group recovery readback is malformed'
  [[ "$group_total_count" == "$group_returned_count" &&
     ( "$group_total_count" == 0 || "$group_total_count" == 1 ) ]] ||
    die 66 'GitHub runner recovery group is not an exact singleton boundary'
  org_total_count="$(jq -er '.total_count | select(type == "number")' \
    <<<"$org_response")" || die 66 'GitHub organization runner recovery readback is malformed'
  org_returned_count="$(jq -er 'if (.runners | type) == "array" then (.runners | length) else error("runners") end' \
    <<<"$org_response")" || die 66 'GitHub organization runner recovery readback is malformed'
  org_name_match_count="$(jq -er --arg name "$runner_name" \
    '[.runners[]? | select(.name == $name)] | length' <<<"$org_response")" ||
    die 66 'GitHub organization runner recovery readback is malformed'
  [[ "$org_total_count" == "$org_returned_count" && "$org_total_count" -le 100 &&
     "$org_name_match_count" == "$group_total_count" ]] ||
    die 66 'GitHub organization runner recovery boundary is ambiguous'
  recovered_runner_id=''
  if [[ "$group_total_count" == 1 ]]; then
    recovered_runner_id="$(jq -er '.runners[0].id | select(type == "number")' \
      <<<"$group_response")" || die 66 'GitHub runner recovery identity is malformed'
    recovered_runner_name="$(jq -er '.runners[0].name | select(type == "string")' \
      <<<"$group_response")" || die 66 'GitHub runner recovery identity is malformed'
    recovered_runner_busy="$(jq -r 'if (.runners[0].busy | type) == "boolean" then (.runners[0].busy | tostring) else error("busy") end' \
      <<<"$group_response")" || die 66 'GitHub runner recovery identity is malformed'
    recovered_labels_exact="$(jq -r '([.runners[0].labels[]?.name] | sort) == (["self-hosted", "Linux", "X64", "disk-arcana-stage"] | sort) | tostring' \
      <<<"$group_response")" || die 66 'GitHub runner recovery identity is malformed'
    [[ "$recovered_runner_id" =~ ^[1-9][0-9]{0,19}$ &&
       "$recovered_runner_name" == "$runner_name" && "$recovered_runner_busy" == false &&
       "$recovered_labels_exact" == true ]] ||
      die 66 'GitHub runner recovery identity mismatch'
    org_runner_id="$(jq -er --arg name "$runner_name" \
      '.runners[] | select(.name == $name) | .id | select(type == "number")' \
      <<<"$org_response")" || die 66 'GitHub organization runner recovery identity is malformed'
    [[ "$org_runner_id" == "$recovered_runner_id" ]] ||
      die 66 'GitHub organization and group runner recovery identities differ'
  fi
  if [[ -e "$runner_install_root/.runner" || -L "$runner_install_root/.runner" ]]; then
    [[ -f "$runner_install_root/.runner" && ! -L "$runner_install_root/.runner" ]] ||
      die 65 'bootstrap recovery runner identity is unsafe'
    local_runner_id="$(jq -er '.agentId | select(type == "number")' \
      "$runner_install_root/.runner")" || die 66 'local runner recovery identity is malformed'
    local_runner_name="$(jq -er '.agentName | select(type == "string")' \
      "$runner_install_root/.runner")" || die 66 'local runner recovery identity is malformed'
    [[ "$local_runner_name" == "$runner_name" ]] || die 66 'local runner recovery identity mismatch'
    [[ -z "$recovered_runner_id" || "$local_runner_id" == "$recovered_runner_id" ]] ||
      die 66 'local and remote runner recovery identities differ'
  fi

  if [[ "$journal_phase" != RUNNER_REVOCATION_INTENT && "$journal_phase" != RUNNER_REVOKED ]]; then
    write_phase RUNNER_REVOCATION_INTENT
  fi
  if [[ "$journal_phase" != RUNNER_REVOKED && -n "$recovered_runner_id" ]]; then
    delete_status="$(
      curl --silent --show-error --max-time 20 -o /dev/null -w '%{http_code}' \
        -X DELETE \
        -H "Authorization: Bearer $github_token" \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        "https://api.github.com/orgs/Arcanada-one/actions/runners/$recovered_runner_id"
    )" || die 69 'GitHub runner recovery deregistration failed'
    [[ "$delete_status" == 204 ]] || die 69 'GitHub runner recovery deregistration was not acknowledged'
  fi
  write_phase RUNNER_REVOKED
  if [[ -x "$runner_install_root/svc.sh" && ! -L "$runner_install_root/svc.sh" ]]; then
    "$runner_install_root/svc.sh" uninstall >/dev/null
  fi
  rm -f -- "$runner_install_root/.runner" "$runner_install_root/.credentials" \
    "$runner_install_root/.credentials_rsaparams"
  write_phase RECOVERED
  if [[ "$test_mode" == true && "${DISK_ARCANA_STAGE_BOOTSTRAP_FAIL_AFTER_RECOVERED:-}" == 1 ]]; then
    die 99 'injected interruption after terminal recovery journal'
  fi
  cleanup_recovery_inputs
  printf 'recovery=ok runner_name=%s prior_phase=%s\n' "$runner_name" "$journal_phase"
  exit 0
fi

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
runner_registration_attempted=false
runner_service=''
authority_staged=false
mutating_bootstrap=false

cleanup_authority() {
  local status=0
  if [[ "$runner_registration_attempted" == true && -n "$removal_token" &&
        -x "$runner_install_root/config.sh" ]]; then
    if [[ -n "$runner_service" ]]; then
      systemctl stop "$runner_service" >/dev/null 2>&1 || status=1
    fi
    if [[ -x "$runner_install_root/svc.sh" ]]; then
      "$runner_install_root/svc.sh" uninstall >/dev/null 2>&1 || status=1
    fi
    runuser -u disk-stage -- "$runner_install_root/config.sh" remove \
      --unattended --token "$removal_token" >/dev/null 2>&1 || status=1
  fi
  if ((status == 0)) && [[ "$authority_staged" == true ]]; then
    write_phase RECOVERED || status=1
  fi
  if ((status == 0)); then
    if [[ "$registration_consumed" != true && -f "$registration_file" && ! -L "$registration_file" ]]; then
      rm -f -- "$registration_file" || status=1
    fi
    if [[ -f "$recovery_file" && ! -L "$recovery_file" ]]; then
      rm -f -- "$recovery_file" || status=1
    fi
    if [[ "$authority_staged" == true ]]; then
      sync -f "$state_root" >/dev/null 2>&1 || status=1
    fi
  fi
  return "$status"
}

on_exit() {
  local status=$?
  trap - EXIT INT TERM
  if ((status != 0)) && [[ "$mutating_bootstrap" == true ]]; then
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

mutating_bootstrap=true

[[ "$(hostname)" == "$expected_hostname" ]] || die 69 'guest hostname mismatch'
for command_name in apt-get getent groupadd useradd usermod loginctl systemctl runuser tar unshare; do
  command -v "$command_name" >/dev/null 2>&1 || die 69 "required command is unavailable: $command_name"
done
[[ ! -e "$runner_install_root" ]] || die 73 'runner installation already exists'
mapfile -t preexisting_runner_units < <(
  systemctl list-unit-files --type=service 'actions.runner.*' --no-legend --no-pager 2>/dev/null |
    awk '{print $1}'
)
[[ "${#preexisting_runner_units[@]}" -eq 0 ]] || die 73 'runner service already exists'
! id disk-stage >/dev/null 2>&1 || die 73 'runner user already exists'
! getent group disk-arcana-deploy >/dev/null 2>&1 || die 73 'runner group already exists'

if [[ "$test_mode" == true ]]; then
  for isolated_path in "$state_root" "$runner_install_root" "$journal_root" "$import_root" \
    "$subuid_file" "$subgid_file" "$docker_socket"; do
    [[ "$isolated_path" == /* && "$isolated_path" != / ]] ||
      die 65 'guest bootstrap full test path is unsafe'
    assert_no_symlink_components "$isolated_path" ||
      die 65 'guest bootstrap full test path has a symlink component'
  done
  install -d -m 0700 "$state_root"
else
  install -d -o root -g root -m 0700 "$state_root"
fi
recovery_temporary="$state_root/.recovery.env.$$"
{
  printf 'runner_url=%s\n' "$runner_url"
  printf 'runner_group=%s\n' "$runner_group"
  printf 'runner_name=%s\n' "$runner_name"
  printf 'runner_label=%s\n' "$runner_label"
  printf 'authority_run_id=%s\n' "$authority_run_id"
} >"$recovery_temporary"
chmod 0600 "$recovery_temporary"
sync -f "$recovery_temporary" >/dev/null 2>&1
mv -f -- "$recovery_temporary" "$recovery_file"
sync -f "$state_root" >/dev/null 2>&1
write_phase AUTHORITY_STAGED
authority_staged=true
rm -f -- "$registration_file"
registration_consumed=true
write_phase AUTHORITY_CONSUMED

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
if (( $(subid_count "$subuid_file") < 65536 )); then
  usermod --add-subuids 200000:265535 disk-stage
fi
if (( $(subid_count "$subgid_file") < 65536 )); then
  usermod --add-subgids 200000:265535 disk-stage
fi
(( $(subid_count "$subuid_file") >= 65536 )) || die 69 'subordinate UID allocation failed'
(( $(subid_count "$subgid_file") >= 65536 )) || die 69 'subordinate GID allocation failed'
loginctl enable-linger disk-stage
runner_uid="$(id -u disk-stage)"
systemctl start "user@$runner_uid.service"
write_phase RUNNER_IDENTITY_CREATED

if [[ "$test_mode" == true ]]; then
  install -d -m 0750 "$runner_install_root"
  install -m 0600 "$runner_archive" "$runner_install_root/runner.tar.gz"
else
  install -d -o disk-stage -g disk-stage -m 0750 "$runner_install_root"
  install -o disk-stage -g disk-stage -m 0600 "$runner_archive" "$runner_install_root/runner.tar.gz"
fi
runuser -u disk-stage -- tar -xzf "$runner_install_root/runner.tar.gz" -C "$runner_install_root"
rm -f -- "$runner_install_root/runner.tar.gz"
[[ -x "$runner_install_root/config.sh" && -x "$runner_install_root/svc.sh" ]] ||
  die 69 'runner archive did not install expected entrypoints'
runner_registration_attempted=true
write_phase REGISTRATION_INTENT
runuser -u disk-stage -- "$runner_install_root/config.sh" \
  --unattended \
  --url "$runner_url" \
  --token "$registration_token" \
  --runnergroup "$runner_group" \
  --name "$runner_name" \
  --labels "$runner_label" \
  --work _work \
  --disableupdate
registration_token=''
write_phase RUNNER_REGISTERED
if [[ "$test_mode" == true && "${DISK_ARCANA_STAGE_BOOTSTRAP_FAIL_AFTER_REGISTRATION:-}" == 1 ]]; then
  die 99 'injected interruption after runner registration'
fi
"$runner_install_root/svc.sh" install disk-stage
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

if [[ "$test_mode" == true ]]; then
  install -d -m 0700 "$journal_root"
else
  install -d -o root -g root -m 0700 "$journal_root"
fi
bash "$bundle/install.sh" \
  --binary "$bundle/disk-arcana-server" \
  --unit "$bundle/disk-arcana-server.service" \
  --journal-dir "$journal_root" \
  --expected-hostname "$expected_hostname"
write_phase SERVER_INSTALLED

deployment_id="$(basename "$bootstrap_root")"
[[ "$deployment_id" =~ ^[A-Za-z0-9._-]{1,80}$ ]] || die 65 'bootstrap deployment ID is invalid'
if [[ "$test_mode" == true ]]; then
  install -d -m 0700 "$import_root"
else
  install -d -o root -g root -m 0700 "$import_root"
fi
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
runuser -u disk-stage -- test ! -w "$docker_socket"

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
runner_registration_attempted=false
registration_token=''
removal_token=''
rm -f -- "$recovery_file"
sync -f "$state_root" >/dev/null 2>&1
printf 'bootstrap=ok commit=%s runner_service=%s\n' "$expected_commit" "$runner_service"
