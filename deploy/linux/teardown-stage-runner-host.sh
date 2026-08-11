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

state_root=''
github_token_file=''
validate_only=false
while (($#)); do
  case "$1" in
    --state-root)
      require_value "$1" "${2:-}"
      state_root="$2"
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
    *)
      die 64 "unknown option: $1"
      ;;
  esac
done

[[ -n "$state_root" ]] || die 64 'missing required option: --state-root'
[[ -n "$github_token_file" ]] || die 64 'missing required option: --github-token-file'
[[ "$state_root" == /* && "$state_root" != / && -d "$state_root" && ! -L "$state_root" ]] ||
  die 65 'state root is unsafe'
[[ -f "$github_token_file" && ! -L "$github_token_file" ]] || die 65 'GitHub token file is unsafe'

test_mode=false
expected_uid=0
expected_gid=0
if [[ "${DISK_ARCANA_STAGE_TEARDOWN_TESTING:-}" == 1 ]]; then
  [[ "$(id -u)" != 0 ]] || die 65 'teardown test mode is forbidden for root'
  [[ -n "${DISK_ARCANA_STAGE_TEARDOWN_API_RESPONSE:-}" ||
     "${DISK_ARCANA_STAGE_TEARDOWN_API_STATUS:-}" == 404 ]] ||
    die 65 'teardown test mode requires an API response fixture or 404 status'
  [[ -n "${DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH:-}" || "$validate_only" == true ]] ||
    die 65 'teardown mutating test mode requires a unit path'
  [[ -n "${DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT:-}" || "$validate_only" == true ]] ||
    die 65 'teardown mutating test mode requires a diagnostics root'
  test_mode=true
  expected_uid="$(id -u)"
  expected_gid="$(id -g)"
else
  [[ -z "${DISK_ARCANA_STAGE_TEARDOWN_TESTING:-}" &&
     -z "${DISK_ARCANA_STAGE_TEARDOWN_API_RESPONSE:-}" &&
     -z "${DISK_ARCANA_STAGE_TEARDOWN_API_STATUS:-}" &&
     -z "${DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH:-}" &&
     -z "${DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT:-}" &&
     -z "${DISK_ARCANA_STAGE_TEARDOWN_FAIL_AFTER_UNIT_REMOVE:-}" ]] ||
    die 65 'teardown test controls are forbidden in production'
  [[ "$(id -u)" == 0 ]] || die 77 'teardown requires root'
  [[ "$(dirname "$state_root")" == /var/lib/disk-arcana-stage ]] ||
    die 65 'state root is not canonical'
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

assert_no_symlink_components "$state_root" || die 65 'state path has a symlink component'
[[ "$(stat -c '%a:%u:%g' "$state_root")" == "700:$expected_uid:$expected_gid" ]] ||
  die 65 'state root has unsafe metadata'
[[ "$(stat -c '%a:%u:%g' "$github_token_file")" == "600:$expected_uid:$expected_gid" ]] ||
  die 65 'GitHub token file has unsafe metadata'

manifest="$state_root/state.manifest"
[[ -f "$manifest" && ! -L "$manifest" &&
   "$(stat -c '%a:%u:%g' "$manifest")" == "600:$expected_uid:$expected_gid" ]] ||
  die 65 'state manifest has unsafe metadata'

guest_name=''
manifest_state_root=''
host_unit=''
management_port=''
cloud_image_sha256=''
guest_bundle_sha256=''
runner_archive_sha256=''
runner_name=''
runner_id=''
declare -A manifest_seen=()
while IFS='=' read -r key value; do
  [[ -n "$key" && -z "${manifest_seen[$key]+present}" ]] ||
    die 65 'state manifest contains an empty or duplicate key'
  manifest_seen["$key"]=1
  case "$key" in
    guest_name) guest_name="$value" ;;
    state_root) manifest_state_root="$value" ;;
    host_unit) host_unit="$value" ;;
    management_port) management_port="$value" ;;
    cloud_image_sha256) cloud_image_sha256="$value" ;;
    guest_bundle_sha256) guest_bundle_sha256="$value" ;;
    runner_archive_sha256) runner_archive_sha256="$value" ;;
    runner_name) runner_name="$value" ;;
    runner_id) runner_id="$value" ;;
    *) die 65 'state manifest contains an unknown key' ;;
  esac
done <"$manifest"
[[ "${#manifest_seen[@]}" -eq 9 ]] || die 65 'state manifest is incomplete'
[[ "$guest_name" == disk-arcana-stage ]] || die 65 'guest identity mismatch'
[[ "$manifest_state_root" == "$state_root" ]] || die 65 'manifest state root mismatch'
[[ "$host_unit" == disk-arcana-stage-vm.service ]] || die 65 'host unit identity mismatch'
[[ "$management_port" =~ ^[0-9]+$ ]] || die 65 'manifest management port is invalid'
[[ "$cloud_image_sha256" =~ ^[0-9a-f]{64}$ && "$guest_bundle_sha256" =~ ^[0-9a-f]{64}$ &&
   "$runner_archive_sha256" =~ ^[0-9a-f]{64}$ ]] ||
  die 65 'manifest digest is invalid'
[[ "$runner_name" == disk-arcana-stage ]] || die 65 'runner name is invalid'
[[ "$runner_id" =~ ^[1-9][0-9]{0,19}$ ]] || die 65 'runner ID is invalid'
command -v jq >/dev/null 2>&1 || die 69 'jq is unavailable'

teardown_journal="$state_root/teardown-current"
teardown_phase='NEW'
if [[ -e "$teardown_journal" ]]; then
  [[ -f "$teardown_journal" && ! -L "$teardown_journal" &&
     "$(stat -c '%a:%u:%g' "$teardown_journal")" == "600:$expected_uid:$expected_gid" ]] ||
    die 65 'teardown journal has unsafe metadata'
  journal_phase=''
  journal_runner_id=''
  journal_runner_name=''
  journal_state_root=''
  declare -A journal_seen=()
  while IFS='=' read -r key value; do
    [[ -n "$key" && -z "${journal_seen[$key]+present}" ]] ||
      die 65 'teardown journal contains an empty or duplicate key'
    journal_seen["$key"]=1
    case "$key" in
      phase) journal_phase="$value" ;;
      runner_id) journal_runner_id="$value" ;;
      runner_name) journal_runner_name="$value" ;;
      state_root) journal_state_root="$value" ;;
      *) die 65 'teardown journal contains an unknown key' ;;
    esac
  done <"$teardown_journal"
  [[ "${#journal_seen[@]}" -eq 4 && "$journal_runner_id" == "$runner_id" &&
     "$journal_runner_name" == "$runner_name" && "$journal_state_root" == "$state_root" ]] ||
    die 65 'teardown journal identity mismatch'
  case "$journal_phase" in
    IDENTITY_VERIFIED|GUEST_STOPPED|RUNNER_DELETE_INTENT|RUNNER_DEREGISTERED|UNIT_REMOVE_INTENT|UNIT_REMOVED)
      teardown_phase="$journal_phase"
      ;;
    *) die 65 'teardown journal phase is unknown' ;;
  esac
fi

github_token="$(<"$github_token_file")"
[[ "$github_token" =~ ^[^[:space:]]{20,500}$ ]] || die 65 'GitHub token is malformed'

api_status=''
api_response=''
if [[ "$teardown_phase" == RUNNER_DEREGISTERED ||
      "$teardown_phase" == UNIT_REMOVE_INTENT || "$teardown_phase" == UNIT_REMOVED ]]; then
  api_status=404
elif [[ "$test_mode" == true && "${DISK_ARCANA_STAGE_TEARDOWN_API_STATUS:-}" == 404 ]]; then
  api_status=404
elif [[ "$test_mode" == true ]]; then
  api_response_file="$DISK_ARCANA_STAGE_TEARDOWN_API_RESPONSE"
  [[ -f "$api_response_file" && ! -L "$api_response_file" ]] ||
    die 65 'API response fixture is unsafe'
  api_response="$(<"$api_response_file")"
  api_status=200
else
  command -v curl >/dev/null 2>&1 || die 69 'curl is unavailable'
  api_wire="$(
    curl --silent --show-error --max-time 20 -w $'\n%{http_code}' \
      -H "Authorization: Bearer $github_token" \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' \
      "https://api.github.com/orgs/Arcanada-one/actions/runners/$runner_id"
  )" || die 69 'GitHub runner readback failed'
  [[ "$api_wire" == *$'\n'* ]] || die 69 'GitHub runner readback status is malformed'
  api_status="${api_wire##*$'\n'}"
  api_response="${api_wire%$'\n'*}"
fi

if [[ "$api_status" == 200 ]]; then
  api_id="$(jq -er '.id | select(type == "number")' <<<"$api_response")" ||
    die 66 'GitHub runner readback is malformed'
  api_name="$(jq -er '.name | select(type == "string")' <<<"$api_response")" ||
    die 66 'GitHub runner readback is malformed'
  [[ "$api_id" == "$runner_id" && "$api_name" == "$runner_name" ]] ||
    die 66 'GitHub runner identity mismatch'
elif [[ "$api_status" == 404 &&
        ( "$teardown_phase" == RUNNER_DELETE_INTENT ||
          "$teardown_phase" == RUNNER_DEREGISTERED ||
          "$teardown_phase" == UNIT_REMOVE_INTENT ||
          "$teardown_phase" == UNIT_REMOVED ) ]]; then
  :
else
  die 69 'GitHub runner readback did not return the recorded identity'
fi

if [[ "$validate_only" == true ]]; then
  [[ "$api_status" == 200 ]] || die 69 'validation requires a live exact runner identity'
  printf 'validation=ok runner_id=%s runner_name=%s\n' "$runner_id" "$runner_name"
  exit 0
fi

unit_path="${DISK_ARCANA_STAGE_TEARDOWN_UNIT_PATH:-/etc/systemd/system/$host_unit}"
if [[ "$teardown_phase" != UNIT_REMOVE_INTENT && "$teardown_phase" != UNIT_REMOVED ]]; then
  [[ -f "$unit_path" && ! -L "$unit_path" ]] || die 65 'recorded host unit is unsafe'
  grep -F -- "file=$state_root/disk.qcow2" "$unit_path" >/dev/null ||
    die 65 'recorded host unit does not target the recorded guest'
fi

write_phase() {
  local next="$1" temporary="$state_root/.teardown-current.$$"
  printf 'phase=%s\nrunner_id=%s\nrunner_name=%s\nstate_root=%s\n' \
    "$next" "$runner_id" "$runner_name" "$state_root" >"$temporary"
  chmod 0600 "$temporary"
  sync -f "$temporary" >/dev/null 2>&1
  mv -f -- "$temporary" "$teardown_journal"
  sync -f "$state_root" >/dev/null 2>&1
}

if [[ "$teardown_phase" == NEW ]]; then
  write_phase IDENTITY_VERIFIED
  teardown_phase=IDENTITY_VERIFIED
fi
if [[ "$teardown_phase" == IDENTITY_VERIFIED ]]; then
  if [[ "$test_mode" != true ]]; then
    systemctl disable --now "$host_unit"
  fi
  write_phase GUEST_STOPPED
  teardown_phase=GUEST_STOPPED
fi
if [[ "$teardown_phase" == GUEST_STOPPED ]]; then
  write_phase RUNNER_DELETE_INTENT
  teardown_phase=RUNNER_DELETE_INTENT
fi
if [[ "$teardown_phase" == RUNNER_DELETE_INTENT ]]; then
  if [[ "$api_status" == 200 ]]; then
    delete_status="$(
      curl --silent --show-error --max-time 20 -o /dev/null -w '%{http_code}' \
        -X DELETE \
        -H "Authorization: Bearer $github_token" \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        "https://api.github.com/orgs/Arcanada-one/actions/runners/$runner_id"
    )" || die 69 'GitHub runner deregistration failed'
    [[ "$delete_status" == 204 ]] || die 69 'GitHub runner deregistration was not acknowledged'
  fi
  write_phase RUNNER_DEREGISTERED
  teardown_phase=RUNNER_DEREGISTERED
fi
if [[ "$teardown_phase" == RUNNER_DEREGISTERED ]]; then
  write_phase UNIT_REMOVE_INTENT
  teardown_phase=UNIT_REMOVE_INTENT
fi
if [[ "$teardown_phase" == UNIT_REMOVE_INTENT ]]; then
  rm -f -- "$unit_path"
  if [[ "$test_mode" == true && "${DISK_ARCANA_STAGE_TEARDOWN_FAIL_AFTER_UNIT_REMOVE:-}" == 1 ]]; then
    die 99 'injected interruption after unit removal'
  fi
  if [[ "$test_mode" != true ]]; then
    systemctl daemon-reload
  fi
  write_phase UNIT_REMOVED
  teardown_phase=UNIT_REMOVED
fi

diagnostics_root="${DISK_ARCANA_STAGE_TEARDOWN_DIAGNOSTICS_ROOT:-/var/lib/disk-arcana-stage/diagnostics}"
if [[ "$test_mode" == true ]]; then
  install -d -m 0700 "$diagnostics_root"
else
  install -d -o root -g root -m 0700 "$diagnostics_root"
fi
diagnostic_target="$diagnostics_root/$(date -u +%Y%m%dT%H%M%SZ)-$runner_id"
[[ ! -e "$diagnostic_target" ]] || die 73 'diagnostic target already exists'
mv -- "$state_root" "$diagnostic_target"
printf 'teardown=ok runner_id=%s diagnostics=%s\n' "$runner_id" "$diagnostic_target"
